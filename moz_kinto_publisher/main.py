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

    def is_run_valid(self, run_id):
        is_valid = workflow.google_cloud_file_exists(
            self.filter_bucket, f"{run_id}/mlbf/filter"
        ) and workflow.google_cloud_file_exists(
            self.filter_bucket, f"{run_id}/mlbf/filter.stash"
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
def get_attachments_base_url():
    return requests.get(settings.KINTO_RW_SERVER_URL).json()["capabilities"][
        "attachments"
    ]["base_url"]


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
            self._bucket_name, collection or self._collection_name, recordId
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
            self.crlite_enrolled = kwargs["enrolled"]
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
            + f"-{self.subject}-{self.pemHash}"
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
        sameAttachment = remote_record.pemHash == self.pemHash
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

    def download_pem(self):
        if not self.pemAttachment:
            raise Exception("pemAttachment not set")
        r = requests.get(f"{get_attachments_base_url()}{self.pemAttachment.location}")
        r.raise_for_status()
        self.set_pem(r.text)

    def is_expired(self):
        if not self.cert:
            self.download_pem()
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

    def unenroll_from_crlite_in_kinto(self, *, rw_client=None):
        if self.kinto_id is None:
            raise IntermediateRecordError(
                "Cannot unenroll a record not at Kinto: {}".format(self)
            )
        rw_client.patch_record(
            collection=settings.KINTO_INTERMEDIATES_COLLECTION,
            id=self.kinto_id,
            changes=BasicPatch({"crlite_enrolled": False}),
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
                "IntermediateRecordError: {} while importing from ".format(
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
            remote_intermediates[intObj.unique_id()] = intObj
        except IntermediateRecordError as ire:
            log.warning("Skipping broken intermediate record at Kinto: {}".format(ire))
            remote_error_records.append(record)
        except KeyError as ke:
            log.error("Critical error importing Kinto dataset: {}".format(ke))
            log.error("Record: {}".format(record))
            raise ke
    return remote_intermediates, remote_error_records


def publish_intermediates(*, args, rw_client):

    run_identifiers = workflow.get_run_identifiers(args.filter_bucket)
    if not run_identifiers:
        log.warning("No run identifiers found")
        return

    run_id = run_identifiers[-1]

    run_id_path = args.download_path / Path(run_id)
    run_id_path.mkdir(parents=True, exist_ok=True)
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

    remote_enrolled = set()
    for unique_id, record in remote_intermediates.items():
        if record.crlite_enrolled:
            remote_enrolled.add(unique_id)

    to_upload = set(local_intermediates.keys()) - set(remote_intermediates.keys())

    to_update = set()
    for i in set(local_intermediates.keys()) & set(remote_intermediates.keys()):
        if not local_intermediates[i].equals(remote_record=remote_intermediates[i]):
            to_update.add(i)

    remote_expired = set()
    for i in remote_only:
        try:
            if remote_intermediates[i].is_expired():
                remote_expired.add(i)
        except Exception as e:
            log.warning(f"Failed to track expiration for {i}: {e}")

    log.info(f"Remote intermediates: {len(remote_intermediates)}")
    log.info(f"- Enrolled: {len(remote_enrolled)}")
    log.info(f"- Expired: {len(remote_expired)}")
    log.info(f"- In error: {len(remote_error_records)}")
    log.info(f"To add: {len(to_upload)}")
    log.info(f"To update: {len(to_update)}")

    if args.noop:
        log.info("Noop flag set, exiting before any intermediate updates")
        return

    # Enrolled intermediates must be in the local list
    for unique_id in remote_only & remote_enrolled:
        record = remote_intermediates[unique_id]
        log.info(f"Unenrolling deleted {record} from CRLite")
        try:
            record.unenroll_from_crlite_in_kinto(rw_client=rw_client)
        except KintoException as ke:
            log.error(f"Couldn't unenroll record id {record}: {ke}")

    # Delete any remote records that had parsing errors
    for record in remote_error_records:
        log.info(f"Deleting remote record with parsing error: {record}")
        try:
            rw_client.delete_record(
                collection=settings.KINTO_INTERMEDIATES_COLLECTION,
                id=record["id"],
            )
        except KintoException as ke:
            log.error(f"Couldn't delete record id {record['id']}: {ke}")

    # Delete any expired remote records
    for unique_id in remote_expired:
        record = remote_intermediates[unique_id]
        log.info(f"Deleting expired remote record: {record}")
        try:
            rw_client.delete_record(
                collection=settings.KINTO_INTERMEDIATES_COLLECTION,
                id=record["id"],
            )
        except KintoException as ke:
            log.error(f"Couldn't delete record id {record['id']}: {ke}")

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
        log.info(f"Updating record: {local_int} to {remote_int}")
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

    num_verified_enrolled = sum(1 for v in verified_intermediates if v.crlite_enrolled)
    log.info(
        "{} intermediates locally, {} enrolled at Kinto of {} total.".format(
            len(local_intermediates), num_verified_enrolled, len(verified_intermediates)
        )
    )

    # Every local intermediate should be on remote
    for unique_id, local_int in local_intermediates.items():
        if unique_id not in verified_intermediates:
            raise KintoException(f"Failed to upload {unique_id}")
        if not local_int.equals(remote_record=verified_intermediates[unique_id]):
            raise KintoException(
                "Local/Remote metadata mismatch for uniqueId={}".format(unique_id)
            )

    # Every enrolled remote intermediate should be in the local list
    for unique_id, ver_int in verified_intermediates.items():
        if ver_int.crlite_enrolled and unique_id not in local_intermediates:
            raise KintoException(f"Failed to unenroll {unique_id}")


def clear_crlite_filters(*, rw_client, noop):
    if noop:
        log.info("Would clean up CRLite filters, but no-op set")
        return
    existing_records = rw_client.get_records(
        collection=settings.KINTO_CRLITE_COLLECTION
    )
    existing_filters = filter(lambda x: x["incremental"] is False, existing_records)
    for filter_record in existing_filters:
        log.info(f"Cleaning up stale filter record {filter_record['id']}.")
        rw_client.delete_record(
            collection=settings.KINTO_CRLITE_COLLECTION,
            id=filter_record["id"],
        )


def clear_crlite_stashes(*, rw_client, noop):
    if noop:
        log.info("Would clean up CRLite stashes, but no-op set")
        return
    existing_records = rw_client.get_records(
        collection=settings.KINTO_CRLITE_COLLECTION
    )
    existing_stashes = filter(lambda x: x["incremental"] is True, existing_records)
    for stash in existing_stashes:
        log.info(f"Cleaning up stale stash record {stash['id']}.")
        rw_client.delete_record(
            collection=settings.KINTO_CRLITE_COLLECTION,
            id=stash["id"],
        )


def publish_crlite_record(
    *, path, filename, timestamp, rw_client, incremental, noop, previous_id=None
):
    record_type = "diff" if incremental else "full"
    record_time = timestamp.isoformat(timespec="seconds")
    record_epoch_time_ms = math.floor(timestamp.timestamp() * 1000)
    identifier = f"{record_time}Z-{record_type}"

    attributes = {
        "details": {"name": identifier},
        "incremental": incremental,
        "effectiveTimestamp": record_epoch_time_ms,
    }
    perms = {"read": ["system.Everyone"]}
    if incremental:
        assert previous_id, "Incremental records must have a previous record ID"
        attributes["parent"] = previous_id

    log.info(
        f"Publishing {path} {timestamp} incremental={incremental} (previous={previous_id})"
    )
    if noop:
        log.info("NoOp mode enabled")

    if not noop:
        record = rw_client.create_record(
            collection=settings.KINTO_CRLITE_COLLECTION,
            data=attributes,
            permissions=perms,
        )
        recordid = record["data"]["id"]

        try:
            rw_client.attach_file(
                collection=settings.KINTO_CRLITE_COLLECTION,
                fileName=filename,
                filePath=path,
                recordId=recordid,
            )
        except KintoException as ke:
            log.error(
                f"Failed to upload attachment. Removing stale MLBF record {recordid}: {ke}"
            )
            rw_client.delete_record(
                collection=settings.KINTO_CRLITE_COLLECTION,
                id=recordid,
            )
            log.error("Stale record deleted.")
            raise ke
    else:
        recordid = "fake-noop-id"
        record = {"fake": True}

    log.info("Successfully uploaded MLBF record.")
    log.debug(json.dumps(record, indent=" "))
    return recordid


def publish_crlite_main_filter(*, filter_path, filename, rw_client, timestamp, noop):
    return publish_crlite_record(
        path=filter_path,
        filename=filename,
        timestamp=timestamp,
        rw_client=rw_client,
        noop=noop,
        incremental=False,
    )


def publish_crlite_stash(
    *, stash_path, filename, rw_client, previous_id, timestamp, noop
):
    return publish_crlite_record(
        path=stash_path,
        filename=filename,
        timestamp=timestamp,
        rw_client=rw_client,
        previous_id=previous_id,
        noop=noop,
        incremental=True,
    )


def timestamp_from_record(record):
    iso_string = record["details"]["name"].split("Z-")[0]
    return datetime.fromisoformat(iso_string).replace(tzinfo=timezone.utc)


def crlite_verify_record_consistency(*, existing_records):
    # This function assumes that existing_records is sorted according to
    # record["details"]["name"], which is a "YYYY-MM-DDTHH:MM:SS+00:00Z"
    # timestamp.

    # It's OK if there are no records yet.
    if len(existing_records) == 0:
        return

    for r in existing_records:
        if not ("id" in r and "incremental" in r and "attachment" in r):
            raise ConsistencyException(f"Malformed record {r}.")
        if r["incremental"] and not "parent" in r:
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


def crlite_verify_run_id_consistency(*, run_db, identifiers_to_check):
    # The runs should be complete.
    for r in identifiers_to_check:
        if not run_db.is_run_ready(r):
            raise ConsistencyException(f"Run is not ready: {r}")

    # Each run should have a "filter" and a "filter.stash" file.
    for r in identifiers_to_check:
        if not run_db.is_run_valid(r):
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


def crlite_determine_publish(*, existing_records, run_db):
    assert len(run_db) > 0, "There must be run identifiers"

    # The default behavior is to clear all records and upload a full
    # filter based on the most recent run. We'll check if we can do
    # an incremental update instead.
    default = {"clear_all": True, "upload": [run_db.most_recent_id()]}

    # If there are no existing records, publish a full filter.
    if not existing_records:
        return default

    # If the existing records are bad, publish a full filter.
    try:
        crlite_verify_record_consistency(existing_records=existing_records)
    except ConsistencyException as se:
        log.error(f"Failed to verify existing record consistency: {se}")
        return default

    # Get a list of run IDs that are newer than any existing record.
    # These are candidates for inclusion in an incremental update.

    # A run ID is a "YYYYMMDD" date and an index, e.g. "20210101-3".
    # The record["attachment"]["filename"] field of an existing record is
    # in the format "<run id>-filter" or "<run id>-filter.stash".
    old_run_ids = []
    new_run_ids = []
    cut = existing_records[-1]
    cut_date, cut_idx = [int(x) for x in cut["attachment"]["filename"].split("-")[:2]]
    for run_id in run_db.run_identifiers:
        run_date, run_idx = [int(x) for x in run_id.split("-")]
        if run_date < cut_date or (run_date == cut_date and run_idx <= cut_idx):
            old_run_ids.append(run_id)
        else:
            new_run_ids.append(run_id)

    # If we don't have data from old runs, publish a full filter.
    if not old_run_ids:
        log.error("We do not have data to support existing records.")
        return default

    # If it's been 10 days since a full filter, publish a full filter.
    min_run_id = min(run_id.split("-")[0] for run_id in old_run_ids)
    min_date = datetime.strptime(min_run_id, "%Y%m%d")
    if datetime.now() - min_date >= timedelta(days=10):
        return default

    # If the new runs fail a consistency check, publish a full filter.
    try:
        crlite_verify_run_id_consistency(
            run_db=run_db, identifiers_to_check=new_run_ids
        )
    except ConsistencyException as se:
        log.error(f"Failed to verify run ID consistency: {se}")
        return default

    return {"upload": new_run_ids}


def publish_crlite(*, args, rw_client):
    existing_records = rw_client.get_records(
        collection=settings.KINTO_CRLITE_COLLECTION
    )
    # Sort existing_records for crlite_verify_record_consistency,
    # which gets called in crlite_determine_publish.
    existing_records = sorted(existing_records, key=lambda x: x["details"]["name"])

    published_run_db = PublishedRunDB(args.filter_bucket)

    # Wait for the most recent run to finish.
    try:
        published_run_db.await_most_recent_run(timeout=timedelta(minutes=5))
    except TimeoutException as te:
        log.warning(f"The most recent run is not ready to be published (waited {te}).")

    tasks = crlite_determine_publish(
        existing_records=existing_records, run_db=published_run_db
    )

    log.debug(f"crlite_determine_publish tasks={tasks}")

    if not tasks["upload"]:
        log.info("Nothing to do.")
        return

    args.download_path.mkdir(parents=True, exist_ok=True)

    new_stash_paths = []
    for run_id in tasks["upload"]:
        run_id_path = args.download_path / Path(run_id)
        run_id_path.mkdir(parents=True, exist_ok=True)
        stash_path = run_id_path / Path("stash")
        workflow.download_and_retry_from_google_cloud(
            args.filter_bucket,
            f"{run_id}/mlbf/filter.stash",
            stash_path,
            timeout=timedelta(minutes=5),
        )
        new_stash_paths.append(stash_path)

    final_run_id = tasks["upload"][-1]
    filter_path = args.download_path / Path(final_run_id) / Path("filter")
    workflow.download_and_retry_from_google_cloud(
        args.filter_bucket,
        f"{final_run_id}/mlbf/filter",
        filter_path,
        timeout=timedelta(minutes=5),
    )

    existing_stash_size = sum(
        x["attachment"]["size"] for x in existing_records if x["incremental"]
    )
    update_stash_size = sum(stash_path.stat().st_size for stash_path in new_stash_paths)

    total_stash_size = existing_stash_size + update_stash_size
    full_filter_size = filter_path.stat().st_size

    log.info(f"New stash size: {total_stash_size} bytes")
    log.info(f"New filter size: {full_filter_size} bytes")

    if "clear_all" in tasks or total_stash_size > full_filter_size:
        log.info("Uploading a full filter based on {final_run_id}.")

        clear_crlite_filters(rw_client=rw_client, noop=args.noop)
        clear_crlite_stashes(rw_client=rw_client, noop=args.noop)

        assert filter_path.is_file(), "Missing local copy of filter"
        publish_crlite_main_filter(
            filter_path=filter_path,
            filename=f"{final_run_id}-filter",
            rw_client=rw_client,
            timestamp=published_run_db.get_run_timestamp(final_run_id),
            noop=args.noop,
        )

    else:
        log.info("Uploading stashes.")
        previous_id = existing_records[-1]["id"]

        for run_id, stash_path in zip(tasks["upload"], new_stash_paths):
            assert stash_path.is_file(), "Missing local copy of stash"

            previous_id = publish_crlite_stash(
                stash_path=stash_path,
                filename=f"{run_id}-filter.stash",
                rw_client=rw_client,
                previous_id=previous_id,
                timestamp=published_run_db.get_run_timestamp(run_id),
                noop=args.noop,
            )


def publish_ctlogs(*, args, rw_client):
    # Copy CT log metadata from google's v3 log_list to our kinto collection.
    # This will notify reviewers who can then manually enroll the log in CRLite.
    #
    # Schema for our ct-logs kinto collection:
    #   {
    #       "crlite_enrolled": boolean,
    #       "description": string,
    #       "key": string,
    #       "logID": string,
    #       "mmd": integer,
    #       "url": string
    #   }
    #

    log_list_json = requests.get(
        "https://www.gstatic.com/ct/log_list/v3/log_list.json"
    ).json()

    # Google groups CT logs according to their operators, we want a flat list
    upstream_logs_raw = [
        ctlog for operator in log_list_json["operators"] for ctlog in operator["logs"]
    ]

    # Translate |upstream_logs_raw| to our schema (and remove unused fields)
    upstream_logs = [
        {
            "crlite_enrolled": False,
            "description": ctlog["description"],
            "key": ctlog["key"],
            "logID": ctlog["log_id"],
            "url": ctlog["url"],
            "mmd": ctlog["mmd"],
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

        need_update = False
        for i in ["description", "key", "url", "mmd"]:
            if upstream_log[i] != known_log[i]:
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

    args = parser.parse_args()

    if args.verbose:
        log.setLevel("DEBUG")

    if args.noop:
        log.info("The --noop flag is set, will not make changes.")

    if "KINTO_AUTH_USER" not in dir(settings):
        raise Exception("KINTO_AUTH_USER must be defined in settings.py")

    if "KINTO_AUTH_PASSWORD" not in dir(settings):
        raise Exception("KINTO_AUTH_PASSWORD must be defined in settings.py")

    auth = requests.auth.HTTPBasicAuth(
        settings.KINTO_AUTH_USER, settings.KINTO_AUTH_PASSWORD
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
        publish_crlite(args=args, rw_client=rw_client)

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
