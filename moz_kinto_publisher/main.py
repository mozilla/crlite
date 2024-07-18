#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import math
import re
import tempfile
import time

from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path

import requests

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from kinto_http import Client
from kinto_http.exceptions import KintoException
from kinto_http.patch_type import BasicPatch

import glog as log

import workflow
import settings

CHANNEL_ALL = "all"
CHANNEL_SPECIFIED = "specified"
CHANNEL_PRIORITY = "priority"


class IntermediateRecordError(KintoException):
    pass


class TimeoutException(Exception):
    pass


class ConsistencyException(Exception):
    pass


class PublishedRunDB:
    def __init__(self, filter_bucket):
        self.filter_bucket = filter_bucket
        self.run_identifiers = workflow.get_run_identifiers(self.filter_bucket)
        self.cached_run_times = {}

    def __len__(self):
        return len(self.run_identifiers)

    def is_run_valid(self, run_id, channel):
        if channel == CHANNEL_ALL:
            mlbf_dir = "mlbf"
        elif channel == CHANNEL_SPECIFIED:
            mlbf_dir = "mlbf-specified"
        elif channel == CHANNEL_PRIORITY:
            mlbf_dir = "mlbf-priority"
        else:
            log.warning(f"Unrecognized channel ({channel}).")
            return False

        is_valid = (
            workflow.google_cloud_file_exists(
                self.filter_bucket, f"{run_id}/{mblf_dir}/filter"
            )
            and workflow.google_cloud_file_exists(
                self.filter_bucket, f"{run_id}/{mlbf_dir}/filter.stash"
            )
            and workflow.google_cloud_file_exists(
                self.filter_bucket, f"{run_id}/ct-logs.json"
            )
        )
        log.debug(f"{run_id} {'Is Valid' if is_valid else 'Is Not Valid'}")
        return is_valid

    def is_run_ready(self, run_id):
        is_ready = workflow.google_cloud_file_exists(
            self.filter_bucket, f"{run_id}/completed"
        )
        log.debug(f"{run_id}/completed {'is ready' if is_ready else 'is not ready'}")
        return is_ready

    def await_most_recent_run(self, *, timeout=timedelta(minutes=5)):
        run_id = self.most_recent_id()
        time_start = datetime.now()
        while not self.is_run_ready(run_id):
            time_waiting = datetime.now() - time_start
            if time_waiting >= timeout:
                raise TimeoutException(f"{time_waiting}")
            log.warning(
                f"{run_id}/completed not found, retrying (waiting={time_waiting}, "
                + f"deadline={timeout-time_waiting})"
            )
            time.sleep(30)

    def most_recent_id(self):
        return self.run_identifiers[-1]

    def get_run_timestamp(self, run_id):
        if run_id not in self.cached_run_times:
            byte_str = workflow.download_from_google_cloud_to_string(
                self.filter_bucket, f"{run_id}/timestamp"
            )
            self.cached_run_times[run_id] = datetime.fromisoformat(
                byte_str.decode("utf-8")
            ).replace(tzinfo=timezone.utc)

        return self.cached_run_times[run_id]


def asciiPemToBinaryDer(pem: str) -> bytes:
    matches = re.search(
        r"(?<=-----BEGIN CERTIFICATE-----).*?(?=-----END CERTIFICATE-----)",
        pem,
        flags=re.DOTALL,
    )
    return base64.b64decode(matches.group(0))


@lru_cache
def get_attachments_base_url(client):
    return client.server_info()["capabilities"]["attachments"]["base_url"]


class PublisherClient(Client):
    def attach_file(
        self,
        *,
        collection=None,
        filePath=None,
        fileName="file",
        fileContents=None,
        mimeType="application/octet-stream",
        recordId=None,
    ):
        if not ((filePath is None) ^ (fileContents is None)):
            raise Exception("Must specify either filePath or fileContents")

        if filePath:
            with open(filePath, "rb") as f:
                fileContents = f.read()

        attachmentEndpoint = "buckets/{}/collections/{}/records/{}/attachment".format(
            self.bucket_name, collection or self.collection_name, recordId
        )
        response = requests.post(
            self.session.server_url + attachmentEndpoint,
            files=[("attachment", (fileName, fileContents, mimeType))],
            auth=self.session.auth,
        )
        if response.status_code > 200:
            raise KintoException(
                f"Couldn't attach file at endpoint {self.session.server_url}{attachmentEndpoint}: "
                + f"{response.content.decode('utf-8')}"
            )

    def request_review_of_collection(self, *, collection=None):
        try:
            resp = self.get_collection(id=collection)
        except KintoException as e:
            log.error("Couldn't determine {collection} review status")
            raise e

        original = resp.get("data")
        if original is None:
            raise KintoException("Malformed response from Kinto")

        status = original.get("status")
        if status is None:
            raise KintoException("Malformed response from Kinto")

        if status != "work-in-progress":
            log.info(f"Collection {collection} is unchanged. Does not need review.")
            return

        try:
            resp = self.patch_collection(
                original=original, changes=BasicPatch({"status": "to-review"})
            )
        except KintoException as e:
            log.error("Couldn't request review of {collection}")
            raise e


class AttachedPem:
    def __init__(self, **kwargs):
        self.filename = kwargs["filename"]
        self.size = kwargs["size"]
        self.location = kwargs["location"]
        self.mimetype = kwargs["mimetype"]
        self.hash = kwargs["hash"]

    def _get_attributes(self):
        return {
            "filename": self.filename,
            "size": self.size,
            "location": self.location,
            "mimetype": self.mimetype,
            "hash": self.hash,
        }

    def __str__(self):
        return "{{PEM: {} [h={} s={}]}}".format(self.filename, self.hash, self.size)


def allIn(keys, record):
    return all(k in record for k in keys)


def exactlyOneIn(keys, record):
    return sum(k in record for k in keys) == 1


class Intermediate:
    cert: x509.Certificate
    crlite_enrolled: bool
    derHash: bytes
    kinto_id: str
    pemAttachment: AttachedPem
    pemData: str
    pemHash: str
    pubKeyHash: bytes
    subject: str
    subjectDN: bytes
    whitelist: bool

    def __init__(self, **kwargs):
        self.derHash = None
        self.kinto_id = None
        self.pemAttachment = None
        self.pemData = None
        self.pemHash = None
        self.subjectDN = None

        parseError = IntermediateRecordError(f"Malformed record: {kwargs}")

        # Local records have a "pem" field.
        # RemoteSettings records have "attachment".
        # TODO(jms): These should be versioned (See Issue 180).
        if not exactlyOneIn(["pem", "attachment"], kwargs):
            raise parseError

        if "pem" in kwargs and not allIn(
            [
                "enrolled",
                "pubKeyHash",
                "subject",
                "subjectDN",
                "whitelist",
            ],
            kwargs,
        ):
            raise parseError

        if "attachment" in kwargs and not allIn(
            [
                "crlite_enrolled",
                "derHash",
                "id",
                "pubKeyHash",
                "subject",
                "subjectDN",
                "whitelist",
            ],
            kwargs,
        ):
            raise parseError

        try:
            self.pubKeyHash = base64.b64decode(
                kwargs["pubKeyHash"], altchars="-_", validate=True
            )  # sha256 of the SPKI

            self.subjectDN = base64.b64decode(
                kwargs["subjectDN"], altchars="-_", validate=True
            )

            if "derHash" in kwargs:
                self.derHash = base64.b64decode(
                    kwargs["derHash"], altchars="-_", validate=True
                )
        except base64.binascii.Error:
            raise parseError

        if len(self.pubKeyHash) != 32:
            raise IntermediateRecordError(f"Invalid pubkey hash: {kwargs}")

        if self.derHash and len(self.derHash) != 32:
            raise IntermediateRecordError(f"Invalid DER hash. {kwargs}")

        self.subject = kwargs["subject"]
        self.whitelist = kwargs["whitelist"]

        if "pem" in kwargs:
            # The crlite_enrolled field is no longer used by CRLite. Set it to
            # False for local intermediates so that eventually the remote
            # intermediates will be stop being updated due to enrollment
            # changes.
            self.crlite_enrolled = False
            self.set_pem(kwargs["pem"])

        if "attachment" in kwargs:
            self.kinto_id = kwargs["id"]
            self.crlite_enrolled = kwargs["crlite_enrolled"]
            self.cert = None
            self.pemAttachment = AttachedPem(**kwargs["attachment"])
            self.pemHash = self.pemAttachment.hash
            if len(self.pemHash) != 64:  # sha256 hexdigest
                raise IntermediateRecordError(f"Invalid hash. {kwargs}")

    def __str__(self):
        return (
            f"{{Int: {self.subject} "
            + f"[h={base64.b85encode(self.pubKeyHash).decode('utf-8')}"
            + f" e={self.crlite_enrolled}]}}"
        )

    def unique_id(self):
        return (
            f"{base64.b85encode(self.pubKeyHash).decode('utf-8')}"
            + f"-{self.subject}-{self.derHash}"
        )

    def _get_attributes(self, *, complete=False):
        attributes = {
            "subject": self.subject,
            "subjectDN": base64.standard_b64encode(self.subjectDN).decode("utf-8"),
            "derHash": base64.standard_b64encode(self.derHash).decode("utf-8"),
            "pubKeyHash": base64.standard_b64encode(self.pubKeyHash).decode("utf-8"),
            "whitelist": self.whitelist,
            "crlite_enrolled": self.crlite_enrolled,
        }

        if complete and self.pemAttachment:
            attributes["attachment"] = self.pemAttachment._get_attributes()

        return attributes

    def _upload_pem(self, *, rw_client=None, kinto_id=None):
        rw_client.attach_file(
            collection=settings.KINTO_INTERMEDIATES_COLLECTION,
            fileContents=self.pemData,
            fileName=f"{base64.urlsafe_b64encode(self.pubKeyHash).decode('utf-8')}.pem",
            mimeType="text/plain",
            recordId=kinto_id or self.kinto_id,
        )

    def equals(self, *, remote_record=None):
        sameAttributes = self._get_attributes() == remote_record._get_attributes()
        sameAttachment = remote_record.derHash == self.derHash
        return sameAttributes and sameAttachment

    def set_pem(self, pem_data):
        self.pemData = pem_data
        self.pemHash = hashlib.sha256(pem_data.encode("utf-8")).hexdigest()
        derCert = asciiPemToBinaryDer(pem_data)
        self.derHash = hashlib.sha256(derCert).digest()
        try:
            self.cert = x509.load_pem_x509_certificate(
                pem_data.encode("utf-8"), default_backend()
            )
        except Exception as e:
            raise IntermediateRecordError("Cannot parse PEM data: {}".format(e))
        self.subjectDN = self.cert.subject.public_bytes(backend=default_backend())

    def download_pem(self, kinto_client):
        if not self.pemAttachment:
            raise Exception("pemAttachment not set")
        r = requests.get(
            f"{get_attachments_base_url(kinto_client)}{self.pemAttachment.location}"
        )
        r.raise_for_status()
        self.set_pem(r.text)

    def is_expired(self, kinto_client=None):
        if not self.cert:
            if not kinto_client:
                raise Exception("cannot download PEM without client")
            self.download_pem(kinto_client)
        return self.cert.not_valid_after <= datetime.utcnow()

    def delete_from_kinto(self, *, rw_client=None):
        if self.kinto_id is None:
            raise IntermediateRecordError(
                "Cannot delete a record not at Kinto: {}".format(self)
            )
        rw_client.delete_record(
            collection=settings.KINTO_INTERMEDIATES_COLLECTION,
            id=self.kinto_id,
        )

    def update_kinto(self, *, remote_record=None, rw_client=None):
        if self.pemData is None:
            raise IntermediateRecordError(
                "Cannot upload a record not local: {}".format(self)
            )
        if remote_record is None:
            raise IntermediateRecordError("Must provide a remote record")

        if remote_record.kinto_id is None:
            raise IntermediateRecordError(
                "No kinto ID available {}".format(remote_record)
            )

        if not remote_record.pemHash == self.pemHash:
            log.warning("Attachment update needed for {}".format(self))
            log.warning("New: {}".format(self.pemData))

            # TODO: Do we delete the record? Right now it'll get caught at the end but
            # not get fixed.
            raise IntermediateRecordError(
                "Attachment is incorrect for ID {}".format(remote_record.kinto_id)
            )

        # Make sure to put back the existing PEM attachment data
        self.pemAttachment = remote_record.pemAttachment

        rw_client.update_record(
            collection=settings.KINTO_INTERMEDIATES_COLLECTION,
            data=self._get_attributes(complete=True),
            id=remote_record.kinto_id,
        )

    def add_to_kinto(self, *, rw_client=None):
        if self.pemData is None:
            raise IntermediateRecordError(
                "Cannot upload a record not local: {}".format(self)
            )

        attributes = self._get_attributes()

        perms = {"read": ["system.Everyone"]}
        record = rw_client.create_record(
            collection=settings.KINTO_INTERMEDIATES_COLLECTION,
            data=attributes,
            permissions=perms,
        )
        self.kinto_id = record["data"]["id"]

        try:
            self._upload_pem(rw_client=rw_client)
        except KintoException as ke:
            log.error(
                "Failed to upload attachment. Removing stale intermediate record {}.".format(
                    self.kinto_id
                )
            )
            rw_client.delete_record(
                collection=settings.KINTO_INTERMEDIATES_COLLECTION,
                id=self.kinto_id,
            )
            log.error("Stale record deleted.")
            raise ke

    def details(self):
        return self._get_attributes()


def load_local_intermediates(*, intermediates_path):
    local_intermediates = {}
    with intermediates_path.open("r") as f:
        entries = json.load(f)
    for entry in entries:
        try:
            intObj = Intermediate(**entry)

            if intObj.unique_id() in local_intermediates:
                log.warning(
                    f"[{intObj.unique_id()}] Local collision: {intObj} with "
                    + f"{local_intermediates[intObj.unique_id()]}"
                )
                continue

            local_intermediates[intObj.unique_id()] = intObj
        except IntermediateRecordError:
            log.warning(
                "IntermediateRecordError: {} while importing from {}".format(
                    entry, f.name
                )
            )
            continue
        except Exception as e:
            log.error("Error importing file from {}: {}".format(f.name, e))
            log.error("Record: {}".format(entry))
            raise e
    return local_intermediates


def load_remote_intermediates(*, kinto_client):
    remote_intermediates = {}
    remote_error_records = []
    for record in kinto_client.get_records(
        collection=settings.KINTO_INTERMEDIATES_COLLECTION
    ):
        try:
            intObj = Intermediate(**record)
            intObj.download_pem(
                kinto_client
            )  # intObj.pemAttachment was set by constructor
            if intObj.unique_id() in remote_intermediates:
                log.warning(f"Will remove duplicate intermediate: {intObj}")
                remote_error_records.append(record)
            else:
                remote_intermediates[intObj.unique_id()] = intObj
        except IntermediateRecordError as ire:
            log.warning("Skipping broken intermediate record at Kinto: {}".format(ire))
            remote_error_records.append(record)
    return remote_intermediates, remote_error_records


def publish_intermediates(*, args, rw_client):
    if args.enrolled_json:
        # when using a local copy of enrolled.json we don't need to determine
        # the most recent run identifier.
        run_id = "local"
    else:
        run_identifiers = workflow.get_run_identifiers(args.filter_bucket)
        if not run_identifiers:
            log.warning("No run identifiers found")
            return
        run_id = run_identifiers[-1]

    run_id_path = args.download_path / Path(run_id)
    run_id_path.mkdir(parents=True, exist_ok=True)

    if args.enrolled_json:
        intermediates_path = Path(args.enrolled_json)
    else:
        intermediates_path = run_id_path / Path("enrolled.json")

        workflow.download_and_retry_from_google_cloud(
            args.filter_bucket,
            f"{run_id}/enrolled.json",
            intermediates_path,
            timeout=timedelta(minutes=5),
        )

    local_intermediates = load_local_intermediates(
        intermediates_path=intermediates_path
    )
    remote_intermediates, remote_error_records = load_remote_intermediates(
        kinto_client=rw_client
    )

    remote_only = set(remote_intermediates.keys()) - set(local_intermediates.keys())

    to_upload = set(local_intermediates.keys()) - set(remote_intermediates.keys())

    to_update = set()
    for i in set(local_intermediates.keys()) & set(remote_intermediates.keys()):
        if not local_intermediates[i].equals(remote_record=remote_intermediates[i]):
            to_update.add(i)

    remote_expired = set()
    for i in remote_only:
        try:
            if remote_intermediates[i].is_expired(kinto_client=rw_client):
                remote_expired.add(i)
        except Exception as e:
            log.warning(f"Failed to track expiration for {i}: {e}")

    log.info(f"Local intermediates: {len(local_intermediates)}")
    log.info(f"Remote intermediates: {len(remote_intermediates)}")
    log.info(f"- Expired: {len(remote_expired)}")
    log.info(f"- In error: {len(remote_error_records)}")
    log.info(f"To add: {len(to_upload)}")
    log.info(f"To update: {len(to_update)}")
    log.info(f"To delete: {len(remote_only)}")

    if args.noop:
        log.info("Noop flag set, exiting before any intermediate updates")
        return

    # All intermediates must be in the local list
    for unique_id in remote_only:
        record = remote_intermediates[unique_id]
        log.info(f"Removing deleted intermediate {record}")
        try:
            record.delete_from_kinto(rw_client=rw_client)
        except KintoException as ke:
            log.error(f"Couldn't delete record {record}: {ke}")

    # Delete any remote records that had errors
    # (note these "records" are just dictionaries)
    for raw_record in remote_error_records:
        log.info(f"Deleting remote record with error: {raw_record}")
        try:
            rw_client.delete_record(
                collection=settings.KINTO_INTERMEDIATES_COLLECTION,
                id=raw_record["id"],
            )
        except KintoException as ke:
            log.error(f"Couldn't delete record id {raw_record['id']}: {ke}")
        except KeyError:  # raw_record doesn't have "id"
            log.error(f"Couldn't delete record: {raw_record}")

    # New records
    for unique_id in to_upload:
        record = local_intermediates[unique_id]
        log.info(f"Adding new record: {record}")
        try:
            record.add_to_kinto(rw_client=rw_client)
        except KintoException as ke:
            log.error(f"Couldn't add record {record}: {ke}")

    # Updates
    for unique_id in to_update:
        local_int = local_intermediates[unique_id]
        remote_int = remote_intermediates[unique_id]
        log.info(f"Updating record: {remote_int} to {local_int}")
        try:
            local_int.update_kinto(
                rw_client=rw_client,
                remote_record=remote_int,
            )
        except KintoException as ke:
            log.error(
                f"Failed to update local={local_int} remote={remote_int} exception={ke}"
            )

    log.info("Verifying correctness...")
    verified_intermediates, verified_error_records = load_remote_intermediates(
        kinto_client=rw_client
    )
    if len(verified_error_records) > 0:
        raise KintoException(
            f"There are {len(verified_error_records)} broken intermediates. Re-run to fix."
        )

    # Every local intermediate should be in the remote list
    for unique_id, local_int in local_intermediates.items():
        if unique_id not in verified_intermediates:
            raise KintoException(f"Failed to upload {unique_id}")
        if not local_int.equals(remote_record=verified_intermediates[unique_id]):
            raise KintoException(
                "Local/Remote metadata mismatch for uniqueId={}".format(unique_id)
            )

    # Every remote intermediate should be in the local list
    for unique_id in verified_intermediates.keys():
        if unique_id not in local_intermediates:
            raise KintoException(f"Failed to remove {unique_id}")

    rw_client.request_review_of_collection(
        collection=settings.KINTO_INTERMEDIATES_COLLECTION
    )


def clear_crlite_filters(*, rw_client, noop, channel):
    if noop:
        log.info("Would clean up CRLite filters, but no-op set")
        return
    existing_records = rw_client.get_records(
        collection=settings.KINTO_CRLITE_COLLECTION
    )
    existing_records = [
        x for x in existing_records if x.get("channel", CHANNEL_ALL) == channel
    ]
    existing_filters = filter(lambda x: x["incremental"] is False, existing_records)
    for filter_record in existing_filters:
        log.info(f"Cleaning up stale filter record {filter_record['id']}.")
        rw_client.delete_record(
            collection=settings.KINTO_CRLITE_COLLECTION,
            id=filter_record["id"],
        )


def clear_crlite_stashes(*, rw_client, noop, channel):
    if noop:
        log.info("Would clean up CRLite stashes, but no-op set")
        return
    existing_records = rw_client.get_records(
        collection=settings.KINTO_CRLITE_COLLECTION
    )
    existing_records = [
        x for x in existing_records if x.get("channel", CHANNEL_ALL) == channel
    ]
    existing_stashes = filter(lambda x: x["incremental"] is True, existing_records)
    for stash in existing_stashes:
        log.info(f"Cleaning up stale stash record {stash['id']}.")
        rw_client.delete_record(
            collection=settings.KINTO_CRLITE_COLLECTION,
            id=stash["id"],
        )


def publish_crlite_record(
    *,
    attributes,
    attachment_path,
    attachment_name,
    rw_client,
    noop,
):
    if noop:
        log.info("NoOp mode enabled")
        return attributes["details"]["name"]

    channel = attributes.get("channel", CHANNEL_ALL)

    # You can test a filter expression relative to a mock context using the
    # Firefox browser console as follows.
    #   let {FilterExpressions} = ChromeUtils.importESModule("resource://gre/modules/components-utils/FilterExpressions.sys.mjs")
    #   let expression = "env.version|versionCompare('124.0a1') >= 0"
    #   let context = {env: {version:"130.0.1"}}
    #   await FilterExpressions.eval(expression, context)
    # See https://remote-settings.readthedocs.io/en/latest/target-filters.html
    # for the expression syntax and the definition of env.
    if channel == CHANNEL_ALL:
        # Users on Firefox < 130 don't have the security.pki.crlite_channel
        # pref, but we assign them to this channel by default.
        attributes[
            "filter_expression"
        ] = f"env.version|versionCompare('130') < 0 || '{channel}' == 'security.pki.crlite_channel'|preferenceValue('none')"
    else:
        attributes[
            "filter_expression"
        ] = f"env.version|versionCompare('130') >= 0 && '{channel}' == 'security.pki.crlite_channel'|preferenceValue('none')"

    record = rw_client.create_record(
        collection=settings.KINTO_CRLITE_COLLECTION,
        data=attributes,
        permissions={"read": ["system.Everyone"]},
    )
    recordid = record["data"]["id"]

    try:
        rw_client.attach_file(
            collection=settings.KINTO_CRLITE_COLLECTION,
            fileName=attachment_name,
            filePath=attachment_path,
            recordId=recordid,
        )
    except KintoException as ke:
        log.error(
            f"Failed to upload attachment. Removing stale CRLite record {recordid}: {ke}"
        )
        rw_client.delete_record(
            collection=settings.KINTO_CRLITE_COLLECTION,
            id=recordid,
        )
        log.error("Stale record deleted.")
        raise ke
    return recordid


def publish_crlite_main_filter(
    *, rw_client, filter_path, filename, timestamp, ctlogs, intermediates, noop, channel
):
    record_time = timestamp.isoformat(timespec="seconds")
    record_epoch_time_ms = math.floor(timestamp.timestamp() * 1000)
    identifier = f"{record_time}Z-full"

    # Each full filter has a `coverage` field which tells users which
    # certificates ct-fetch has downloaded from each CT log.
    #
    # The ct-fetch process tells us which CT logs it is monitoring, and for each log
    # it tells us
    #   (1) the contiguous range of indices of Merkle tree leaves that it downloaded,
    #   (2) the earliest timestamp it saw on those Merkle tree leaves, and
    #   (3) the latest timestamp it saw on those Merkle tree leaves.
    #
    # Communicating (1) to users directly is no good---users don't see leaf
    # indices. However (2) and (3) are useful, because users see timestamps in
    # embedded SCTs.
    #
    # The timestamp in an embedded SCT is a promise from a log that it will
    # assign an index in the next "maximum merge delay" (MMD) window. So if
    #   timestamp(Cert A) + MMD <= timestamp(Cert B)
    # then
    #   index(Cert A) < index(Cert B).
    #
    # It follows that if t0 is the time from (2) and t1 is the time from (3),
    # then a certificate has an index in (1) if
    #   t0 + MMD <= timestamp(certificate) <= t1 - MMD
    #
    # Note that this is an "if" not an "only if". In some special cases we can
    # extend the coverage beyond [t0 + MMD, t1 - MMD]. See below.
    #
    coverage = []
    for ctlog in ctlogs:
        if ctlog["LogID"] == "":
            # This indicates the metadata for this log was produced by an
            # old version of ct-fetch. It will get updated in a future run
            # if the log is still enrolled.
            continue

        if ctlog["MinEntry"] == 0:
            # MinTimestamp is guaranteed to be the smallest timestamp
            # in the log.
            minTimeCovered = ctlog["MinTimestamp"]
        else:
            minTimeCovered = ctlog["MinTimestamp"] + ctlog["MMD"]

        maxTimeCovered = ctlog["MaxTimestamp"] - ctlog["MMD"]

        if minTimeCovered >= maxTimeCovered:
            # No certificates are unambiguously covered.
            continue

        coverage += [
            {
                "logID": ctlog["LogID"],
                "minTimestamp": minTimeCovered,
                "maxTimestamp": maxTimeCovered,
            }
        ]

    enrolledIssuers = set()
    for issuer in intermediates:
        if issuer["enrolled"]:
            uid = base64.urlsafe_b64decode(issuer["uniqueID"])
            enrolledIssuers.add(base64.b64encode(uid).decode("utf-8"))
    enrolledIssuers = list(enrolledIssuers)

    attributes = {
        "details": {"name": identifier},
        "incremental": False,
        "effectiveTimestamp": record_epoch_time_ms,
        "coverage": coverage,
        "enrolledIssuers": enrolledIssuers,
        "channel": channel,
    }

    log.info(f"Publishing full filter {filter_path} {timestamp}")
    return publish_crlite_record(
        rw_client=rw_client,
        attributes=attributes,
        attachment_path=filter_path,
        attachment_name=filename,
        noop=noop,
    )


def publish_crlite_stash(
    *, rw_client, stash_path, filename, timestamp, previous_id, noop, channel
):
    record_time = timestamp.isoformat(timespec="seconds")
    record_epoch_time_ms = math.floor(timestamp.timestamp() * 1000)
    identifier = f"{record_time}Z-diff"

    attributes = {
        "details": {"name": identifier},
        "incremental": True,
        "effectiveTimestamp": record_epoch_time_ms,
        "parent": previous_id,
        "channel": channel,
    }

    log.info(
        f"Publishing incremental filter {stash_path} {timestamp} previous={previous_id}"
    )
    return publish_crlite_record(
        rw_client=rw_client,
        attributes=attributes,
        attachment_path=stash_path,
        attachment_name=filename,
        noop=noop,
    )


def timestamp_from_record(record):
    iso_string = record["details"]["name"].split("Z-")[0]
    return datetime.fromisoformat(iso_string).replace(tzinfo=timezone.utc)


def crlite_verify_record_consistency(*, existing_records, channel):
    # This function assumes that existing_records is sorted according to
    # record["details"]["name"], which is a "YYYY-MM-DDTHH:MM:SS+00:00Z"
    # timestamp.
    existing_records = [
        x for x in existing_records if x.get("channel", CHANNEL_ALL) == channel
    ]

    # It's OK if there are no records yet.
    if len(existing_records) == 0:
        return

    for r in existing_records:
        if not ("id" in r and "incremental" in r and "attachment" in r):
            raise ConsistencyException(f"Malformed record {r}.")
        if r["incremental"] and not "parent" in r:
            raise ConsistencyException(f"Malformed record {r}.")
        if not r["incremental"] and not "coverage" in r:
            raise ConsistencyException(f"Malformed record {r}.")
        if not r["incremental"] and not "enrolledIssuers" in r:
            raise ConsistencyException(f"Malformed record {r}.")

    # There must be exactly 1 full filter in the existing records.
    full_filters = [r for r in existing_records if not r["incremental"]]
    if len(full_filters) == 0:
        raise ConsistencyException("No full filters.")
    if len(full_filters) >= 2:
        raise ConsistencyException(f"Multiple full filters: {full_filters}")

    # Each incremental filter should be a descendent of the full filter
    ids = {r["id"]: r for r in existing_records}
    maxHeight = 0
    for r in existing_records:
        ptr = r["id"]
        height = 0
        while ids[ptr]["incremental"]:
            ptr = ids[ptr]["parent"]
            if ptr not in ids:
                raise ConsistencyException(f"Record {r['id']} has unknown parent {ptr}")
            height += 1
        maxHeight = max(height, maxHeight)

    # The incremental filters should form a chain (no branching), hence there's
    # an incremental filter len(existing_records)-1 steps away from the full
    # filter.
    if maxHeight != len(existing_records) - 1:
        raise ConsistencyException(f"Multiple filter descendents: {full_filters}")

    # There should be no long gaps between record timestamps
    allowed_delta = timedelta(hours=8)
    timestamps = [timestamp_from_record(r) for r in existing_records]
    for x, y in zip(timestamps, timestamps[1:]):
        if y - x > allowed_delta:
            raise ConsistencyException(f"Too-wide a delta: {y-x}")


def crlite_verify_run_id_consistency(*, run_db, identifiers_to_check, channel):
    # The runs should be complete.
    for r in identifiers_to_check:
        if not run_db.is_run_ready(r):
            raise ConsistencyException(f"Run is not ready: {r}")

    # Each run should have "filter", "filter.stash", and "ct-logs.json" files.
    for r in identifiers_to_check:
        if not run_db.is_run_valid(r, channel):
            raise ConsistencyException(f"Not a valid run: {r}")

    # When sorted by run ID, the runs should have increasing timestamps.
    identifiers_to_check.sort(key=lambda x: [int(y) for y in x.split("-")])
    ts = [run_db.get_run_timestamp(r) for r in identifiers_to_check]
    for x, y in zip(ts, ts[1:]):
        if x > y:
            raise ConsistencyException(f"Out-of-order timestamp: {ts}")

    # There should be no large gaps between run timestamps.
    allowed_delta = timedelta(hours=8)
    for x, y in zip(ts, ts[1:]):
        if y - x > allowed_delta:
            raise ConsistencyException(f"Too-wide a delta: {y-x}")


def crlite_determine_publish(*, existing_records, run_db, channel):
    assert len(run_db) > 0, "There must be run identifiers"

    # The default behavior is to clear all records and upload a full
    # filter based on the most recent run. We'll check if we can do
    # an incremental update instead.
    default = {"clear_all": True, "upload": [run_db.most_recent_id()]}

    # If there are no existing records, publish a full filter.
    if not existing_records:
        log.info("No existing records")
        return default

    # If the existing records are bad, publish a full filter.
    try:
        crlite_verify_record_consistency(
            existing_records=existing_records, channel=channel
        )
    except ConsistencyException as se:
        log.error(f"Failed to verify existing record consistency: {se}")
        return default

    # A run ID is a "YYYYMMDD" date and an index, e.g. "20210101-3".
    # The record["attachment"]["filename"] field of an existing record is
    # in the format "<run id>-filter" or "<run id>-filter.stash".
    record_run_ids = [
        record["attachment"]["filename"].rsplit("-", 1)[0]
        for record in existing_records
    ]
    record_run_dates = [
        datetime.strptime(id.split("-")[0], "%Y%m%d") for id in record_run_ids
    ]

    # If it's been 10 days since a full filter, publish a full filter.
    oldest_run_date = min(record_run_dates)
    if datetime.now() - oldest_run_date >= timedelta(days=10):
        log.info("Published full filter is >= 10 days old")
        return default

    # Get a list of run IDs that are newer than any existing record.
    # These are candidates for inclusion in an incremental update.
    old_run_ids = []
    new_run_ids = []
    cut_date, cut_idx = [int(x) for x in record_run_ids[-1].split("-")]
    for run_id in run_db.run_identifiers:
        run_date, run_idx = [int(x) for x in run_id.split("-")]
        if run_date < cut_date or (run_date == cut_date and run_idx <= cut_idx):
            old_run_ids.append(run_id)
        else:
            new_run_ids.append(run_id)

    # If we don't have data from old runs, publish a full filter.
    for run_id in record_run_ids:
        if run_id not in old_run_ids:
            log.error("We do not have data to support existing records.")
            return default

    # If the new runs fail a consistency check, publish a full filter.
    try:
        crlite_verify_run_id_consistency(
            run_db=run_db, identifiers_to_check=new_run_ids, channel=channel
        )
    except ConsistencyException as se:
        log.error(f"Failed to verify run ID consistency: {se}")
        return default

    return {"clear_all": False, "upload": new_run_ids}


def publish_crlite(*, args, rw_client, channel):
    # returns the run_id of a new full filter if one is published, otherwise None
    rv = None

    existing_records = rw_client.get_records(
        collection=settings.KINTO_CRLITE_COLLECTION
    )
    existing_records = [
        x for x in existing_records if x.get("channel", CHANNEL_ALL) == channel
    ]
    # Sort existing_records for crlite_verify_record_consistency,
    # which gets called in crlite_determine_publish.
    existing_records = sorted(existing_records, key=lambda x: x["details"]["name"])

    published_run_db = PublishedRunDB(args.filter_bucket)

    # Wait for the most recent run to finish.
    try:
        published_run_db.await_most_recent_run(timeout=timedelta(minutes=5))
    except TimeoutException as te:
        log.warning(f"The most recent run is not ready to be published (waited {te}).")
        return rv

    tasks = crlite_determine_publish(
        existing_records=existing_records, run_db=published_run_db, channel=channel
    )

    log.debug(f"crlite_determine_publish tasks={tasks}")

    if not tasks["upload"]:
        log.info("Nothing to do.")
        return rv

    args.download_path.mkdir(parents=True, exist_ok=True)

    final_run_id = tasks["upload"][-1]
    final_run_id_path = args.download_path / Path(final_run_id)
    final_run_id_path.mkdir(parents=True, exist_ok=True)

    filter_path = final_run_id_path / Path("filter")

    if channel == CHANNEL_ALL:
        mlbf_dir = "mlbf"
    elif channel == CHANNEL_SPECIFIED:
        mlbf_dir = "mlbf-specified"
    elif channel == CHANNEL_PRIORITY:
        mlbf_dir = "mlbf-priority"
    else:
        log.warning(f"Unrecognized channel ({channel}).")
        return rv

    workflow.download_and_retry_from_google_cloud(
        args.filter_bucket,
        f"{final_run_id}/{mlbf_dir}/filter",
        filter_path,
        timeout=timedelta(minutes=5),
    )

    if not tasks["clear_all"]:
        # We might upload a stash. But if the stashes are too big, we'll set
        # the `clear_all` flag and upload a full filter instead.
        new_stash_paths = []
        for run_id in tasks["upload"]:
            run_id_path = args.download_path / Path(run_id)
            run_id_path.mkdir(parents=True, exist_ok=True)
            stash_path = run_id_path / Path("stash")
            workflow.download_and_retry_from_google_cloud(
                args.filter_bucket,
                f"{run_id}/{mlbf_dir}/filter.stash",
                stash_path,
                timeout=timedelta(minutes=5),
            )
            new_stash_paths.append(stash_path)

        existing_stash_size = sum(
            x["attachment"]["size"] for x in existing_records if x["incremental"]
        )
        update_stash_size = sum(
            stash_path.stat().st_size for stash_path in new_stash_paths
        )

        total_stash_size = existing_stash_size + update_stash_size
        full_filter_size = filter_path.stat().st_size
        if total_stash_size > full_filter_size:
            tasks["clear_all"] = True
        else:
            log.info(f"New stash size: {total_stash_size} bytes")
            log.info(f"New filter size: {full_filter_size} bytes")

    if tasks["clear_all"]:
        log.info(f"Uploading a full filter based on {final_run_id}.")

        clear_crlite_filters(rw_client=rw_client, noop=args.noop, channel=channel)
        clear_crlite_stashes(rw_client=rw_client, noop=args.noop, channel=channel)

        ctlogs_path = args.download_path / Path(final_run_id) / Path("ct-logs.json")
        workflow.download_and_retry_from_google_cloud(
            args.filter_bucket,
            f"{final_run_id}/ct-logs.json",
            ctlogs_path,
            timeout=timedelta(minutes=5),
        )
        with open(ctlogs_path, "r") as f:
            ctlogs = json.load(f)

        enrolled_path = args.download_path / Path(final_run_id) / Path("enrolled.json")
        workflow.download_and_retry_from_google_cloud(
            args.filter_bucket,
            f"{final_run_id}/enrolled.json",
            enrolled_path,
            timeout=timedelta(minutes=5),
        )
        with open(enrolled_path, "r") as f:
            intermediates = json.load(f)

        assert filter_path.is_file(), "Missing local copy of filter"
        publish_crlite_main_filter(
            filter_path=filter_path,
            filename=f"{final_run_id}-{channel}-filter",
            rw_client=rw_client,
            timestamp=published_run_db.get_run_timestamp(final_run_id),
            ctlogs=ctlogs,
            intermediates=intermediates,
            channel=channel,
            noop=args.noop,
        )
        rv = final_run_id

    else:
        log.info("Uploading stashes.")
        previous_id = existing_records[-1]["id"]

        for run_id, stash_path in zip(tasks["upload"], new_stash_paths):
            assert stash_path.is_file(), "Missing local copy of stash"

            previous_id = publish_crlite_stash(
                stash_path=stash_path,
                filename=f"{run_id}-{channel}-filter.stash",
                rw_client=rw_client,
                previous_id=previous_id,
                timestamp=published_run_db.get_run_timestamp(run_id),
                channel=channel,
                noop=args.noop,
            )

    if not args.noop:
        rw_client.request_review_of_collection(
            collection=settings.KINTO_CRLITE_COLLECTION
        )

    return rv


def publish_ctlogs(*, args, rw_client):
    # Copy CT log metadata from google's v3 log_list to our kinto collection.
    # This will notify reviewers who can then manually enroll the log in CRLite.
    #
    # Schema for our ct-logs kinto collection:
    #   {
    #       "admissible": boolean
    #       "crlite_enrolled": boolean,
    #       "description": string,
    #       "key": string,
    #       "logID": string,
    #       "mmd": integer,
    #       "operator": string
    #       "url": string
    #   }
    #

    log_list_json = requests.get(
        "https://www.gstatic.com/ct/log_list/v3/log_list.json"
    ).json()

    # The "state" of a log determines whether its SCTs are admissible in policy checks.
    # We largely follow Chrome's behavior defined here:
    #    https://googlechrome.github.io/CertificateTransparency/log_states.html,
    # except we are not enforcing the restrictions on "retired" logs.
    admissible_states = ["qualified", "usable", "readonly", "retired"]

    # Google groups CT logs according to their operators, we want a flat list
    upstream_logs_raw = []
    for operator in log_list_json["operators"]:
        for ctlog in operator["logs"]:
            ctlog["operator"] = operator["name"]
            ctlog["admissible"] = any(
                state in ctlog["state"] for state in admissible_states
            )
            upstream_logs_raw.append(ctlog)

    # Translate |upstream_logs_raw| to our schema (and remove unused fields)
    upstream_logs = [
        {
            "admissible": ctlog["admissible"],
            "crlite_enrolled": False,
            "description": ctlog["description"],
            "key": ctlog["key"],
            "logID": ctlog["log_id"],
            "mmd": ctlog["mmd"],
            "operator": ctlog["operator"],
            "url": ctlog["url"],
        }
        for ctlog in upstream_logs_raw
    ]
    upstream_lut = {ctlog["logID"]: ctlog for ctlog in upstream_logs}

    if len(upstream_logs) != len(upstream_lut):
        raise ConsistencyException(
            "We expect the 'log_id' field to be unique in log_list.json"
        )

    # LogID is supposed to be a hash of the CT Log's key
    for upstream_log in upstream_logs:
        rfc6962_log_id = base64.b64encode(
            hashlib.sha256(base64.b64decode(upstream_log["key"])).digest()
        )
        if rfc6962_log_id != upstream_log["logID"].encode("utf8"):
            raise ConsistencyException(
                f"Google log list contains incorrectly computed logID {upstream_log}"
            )

    # Fetch our existing Kinto records
    known_logs = rw_client.get_records(collection=settings.KINTO_CTLOGS_COLLECTION)
    known_lut = {ctlog["logID"]: ctlog for ctlog in known_logs}

    if len(known_logs) != len(known_lut):
        raise ConsistencyException(
            "We expect the 'logID' field to be unique the ct-logs collection"
        )

    # Add new logs
    for upstream_id, upstream_log in upstream_lut.items():
        if upstream_id in known_lut:
            continue

        if args.noop:
            log.info(
                f"Noop enabled, skipping upload of \"{upstream_log['description']}\"."
            )
            continue

        log.info(f"Uploading new log {upstream_log}")
        try:
            rw_client.create_record(
                collection=settings.KINTO_CTLOGS_COLLECTION,
                data=upstream_log,
                permissions={"read": ["system.Everyone"]},
            )
        except KintoException as ke:
            log.error(f"Upload failed, {ke}")

    # Delete logs that have been removed from Google's list
    # (this probably doesn't happen)
    for known_id, known_log in known_lut.items():
        if known_id in upstream_lut:
            continue

        if args.noop:
            log.info(f"Noop enabled, skipping deletion of {known_log}.")
            continue

        log.info(
            f"Removing log {known_log}, which has been deleted from Google's list."
        )
        try:
            rw_client.delete_record(
                collection=settings.KINTO_CTLOGS_COLLECTION,
                id=known_log["id"],
            )
        except KintoException as ke:
            log.error(f"Deletion failed, {ke}")

    # Update logs if upstream metadata has changed.
    # (These will be unenrolled and manually reviewed.)
    for known_id, known_log in known_lut.items():
        if known_id not in upstream_lut:  # skip deletions
            continue

        upstream_log = upstream_lut[known_id]

        # This script is not responsible for updating crlite enrollment,
        # so preserve the existing value.
        upstream_log["crlite_enrolled"] = known_log["crlite_enrolled"]

        need_update = False
        for i in ["description", "key", "url", "mmd", "admissible", "operator"]:
            if upstream_log[i] != known_log.get(i, None):
                need_update = True

        if not need_update:
            continue

        if args.noop:
            log.info(f"Noop enabled, skipping update log with id {known_id}.")
            continue

        log.info(f"Changing {known_log} to {upstream_log}")
        try:
            rw_client.update_record(
                collection=settings.KINTO_CTLOGS_COLLECTION,
                data=upstream_log,
                id=known_log["id"],
            )
        except KintoException as ke:
            log.error(f"Update failed, {ke}")

    if not args.noop:
        rw_client.request_review_of_collection(
            collection=settings.KINTO_CTLOGS_COLLECTION
        )


def main():
    parser = argparse.ArgumentParser(
        description="Upload MLBF files to Kinto as records"
    )

    parser.add_argument("--noop", action="store_true", help="Don't update Kinto")

    parser.add_argument(
        "--download-path",
        type=Path,
        default=Path(tempfile.TemporaryDirectory().name),
        help="Path to temporarily store CRLite downloaded artifacts",
    )

    parser.add_argument("--filter-bucket", default="crlite_filters")
    parser.add_argument("--verbose", "-v", help="Be more verbose", action="store_true")
    parser.add_argument("--enrolled-json", help="Path to local copy of enrolled.json")

    args = parser.parse_args()

    if args.verbose:
        log.setLevel("DEBUG")

    if args.noop:
        log.info("The --noop flag is set, will not make changes.")

    if "KINTO_AUTH_USER" not in dir(settings):
        raise Exception("KINTO_AUTH_USER must be defined in settings.py")

    if "KINTO_AUTH_PASSWORD" not in dir(settings):
        raise Exception("KINTO_AUTH_PASSWORD must be defined in settings.py")

    auth = (
        None
        if args.noop
        else requests.auth.HTTPBasicAuth(
            settings.KINTO_AUTH_USER, settings.KINTO_AUTH_PASSWORD
        )
    )
    log.info(
        "Using username/password authentication. Username={}".format(
            settings.KINTO_AUTH_USER
        )
    )

    log.info(f"Connecting... {settings.KINTO_RW_SERVER_URL}")

    rw_client = PublisherClient(
        server_url=settings.KINTO_RW_SERVER_URL,
        auth=auth,
        bucket=settings.KINTO_BUCKET,
        retry=5,
    )

    try:
        log.info("Updating ct-logs collection")
        publish_ctlogs(args=args, rw_client=rw_client)

        log.info("Updating cert-revocations collection")
        publish_crlite(args=args, channel=CHANNEL_ALL, rw_client=rw_client)
        publish_crlite(args=args, channel=CHANNEL_SPECIFIED, rw_client=rw_client)
        publish_crlite(args=args, channel=CHANNEL_PRIORITY, rw_client=rw_client)

        log.info("Updating intermediates collection")
        publish_intermediates(args=args, rw_client=rw_client)
    except KintoException as ke:
        log.error("An exception at Kinto occurred: {}".format(ke))
        raise ke
    except Exception as e:
        log.error("A general exception occurred: {}".format(e))
        raise e


if __name__ == "__main__":
    main()
