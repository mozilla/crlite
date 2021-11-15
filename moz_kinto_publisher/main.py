#!/usr/bin/env python3
import argparse
import base64
import glog as log
import hashlib
import json
import math
import re
import requests
import settings
import tempfile
import time
import workflow

from datetime import datetime, timedelta, timezone
from kinto_http import Client
from kinto_http.exceptions import KintoException
from kinto_http.patch_type import BasicPatch
from pathlib import Path
from requests.auth import HTTPBasicAuth
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class IntermediateRecordError(KintoException):
    pass


class TimeoutException(Exception):
    pass


class SanityException(Exception):
    pass


class PublishedRunDB(object):
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


def get_attachments_base_url():
    return requests.get(settings.KINTO_RO_SERVER_URL).json()["capabilities"][
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
        if not filePath and not fileContents:
            raise Exception("Must specify either filePath or fileContents")

        if filePath:
            files = [("attachment", (fileName, open(filePath, "rb"), mimeType))]
        elif fileContents:
            files = [("attachment", (fileName, fileContents, mimeType))]
        else:
            raise Exception("Unexpected state")

        attachmentEndpoint = "buckets/{}/collections/{}/records/{}/attachment".format(
            self._bucket_name, collection or self._collection_name, recordId
        )
        response = requests.post(
            self.session.server_url + attachmentEndpoint,
            files=files,
            auth=self.session.auth,
        )
        if response.status_code > 200:
            raise KintoException(
                f"Couldn't attach file at endpoint {self.session.server_url}{attachmentEndpoint}: "
                + f"{response.content.decode('utf-8')}"
            )

    def collection_check_state(self, *, collection=None, state):
        collectionEnd = "buckets/{}/collections/{}".format(
            self._bucket_name, collection or self._collection_name
        )

        response = requests.get(
            self.session.server_url + collectionEnd,
            auth=self.session.auth,
        )
        if response.status_code > 200:
            raise KintoException(
                f"Couldn't determine review status: {response.content.decode('utf-8')}"
            )

        status = response.json()["data"]["status"]
        log.debug(
            f"Collection review status: {status}, expecting {state} ({status==state})"
        )
        return status == state

    def collection_needs_review(self, *, collection=None):
        return self.collection_check_state(
            collection=collection, state="work-in-progress"
        )

    def collection_needs_sign(self, *, collection=None):
        return self.collection_check_state(collection=collection, state="to-review")

    def request_review_of_collection(self, *, collection=None):
        if not self.collection_needs_review(collection=collection):
            log.info("Collection does not require review. Skipping.")
            return

        collectionEnd = "buckets/{}/collections/{}".format(
            self._bucket_name, collection or self._collection_name
        )

        response = requests.patch(
            self.session.server_url + collectionEnd,
            json={"data": {"status": "to-review"}},
            auth=self.session.auth,
        )
        if response.status_code > 200:
            raise KintoException(
                f"Couldn't request review: {response.content.decode('utf-8')}"
            )

    def sign_collection(self, *, collection=None):
        if not self.collection_needs_sign(collection=collection):
            log.info("Collection does not require sign. Skipping.")
            return

        collectionEnd = "buckets/{}/collections/{}".format(
            self._bucket_name, collection or self._collection_name
        )
        response = requests.patch(
            self.session.server_url + collectionEnd,
            json={"data": {"status": "to-sign"}},
            auth=self.session.auth,
        )
        if response.status_code > 200:
            raise KintoException(f"Couldn't sign: {response.content.decode('utf-8')}")


def main():
    parser = argparse.ArgumentParser(
        description="Upload MLBF files to Kinto as records"
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--crlite", action="store_true", help="Perform a CRLite update")
    group.add_argument(
        "--intermediates", action="store_true", help="Perform an Intermediate CA update"
    )

    crlite_group = parser.add_argument_group("crlite", "crlite upload arguments")
    crlite_group.add_argument("--noop", action="store_true", help="Don't update Kinto")
    crlite_group.add_argument(
        "--download-path",
        type=Path,
        default=Path(tempfile.TemporaryDirectory().name),
        help="Path to temporarily store CRLite downloaded artifacts",
    )

    int_group = parser.add_argument_group(
        "intermediates", "intermediates upload arguments"
    )
    int_group.add_argument(
        "--debug", action="store_true", help="Enter a debugger during processing"
    )
    int_group.add_argument(
        "--delete", action="store_true", help="Delete entries that are now missing"
    )
    int_group.add_argument(
        "--export", help="Export intermediate set inspection files to this folder"
    )

    parser.add_argument("--filter-bucket", default="crlite_filters")
    parser.add_argument("--verbose", "-v", help="Be more verbose", action="store_true")

    signer_group = parser.add_mutually_exclusive_group()
    signer_group.add_argument(
        "--request-review",
        action="store_true",
        help="Mark the Kinto collection for signature when done",
    )
    signer_group.add_argument(
        "--approve-sign",
        action="store_true",
        help="Approve the Kinto collection for signing",
    )

    args = parser.parse_args()

    if args.verbose:
        log.setLevel("DEBUG")

    if args.noop:
        log.info("The --noop flag is set, will not make changes.")

    if "KINTO_AUTH_USER" not in dir(settings):
        raise Exception("KINTO_AUTH_USER must be defined in settings.py")

    if "KINTO_AUTH_PASSWORD" not in dir(settings):
        raise Exception("KINTO_AUTH_PASSWORD must be defined in settings.py")

    auth = HTTPBasicAuth(settings.KINTO_AUTH_USER, settings.KINTO_AUTH_PASSWORD)
    log.info(
        "Using username/password authentication. Username={}".format(
            settings.KINTO_AUTH_USER
        )
    )

    log.info(
        f"Connecting... RO={settings.KINTO_RO_SERVER_URL}, RW={settings.KINTO_RW_SERVER_URL}"
    )

    rw_client = PublisherClient(
        server_url=settings.KINTO_RW_SERVER_URL,
        auth=auth,
        bucket=settings.KINTO_BUCKET,
        retry=5,
    )

    ro_client = PublisherClient(
        server_url=settings.KINTO_RO_SERVER_URL,
        bucket=settings.KINTO_BUCKET,
        retry=5,
    )

    try:
        if args.approve_sign:
            if args.crlite:
                crlite_sign(args=args, rw_client=rw_client)
            elif args.intermediates:
                intermediates_sign(args=args, rw_client=rw_client)
            else:
                parser.print_help()
            return

        if args.crlite:
            publish_crlite(args=args, rw_client=rw_client, ro_client=ro_client)
            if not args.noop and args.request_review:
                log.info("Set for review")
                rw_client.request_review_of_collection(
                    collection=settings.KINTO_CRLITE_COLLECTION,
                )
            return

        if args.intermediates:
            publish_intermediates(args=args, rw_client=rw_client, ro_client=ro_client)
            return

        parser.print_help()

    except KintoException as ke:
        log.error("An exception at Kinto occurred: {}".format(ke))
        raise ke
    except Exception as e:
        log.error("A general exception occurred: {}".format(e))
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

    def verify(self, *, pemData=None):
        # TODO: move to Intermediate which has self.certHash handy
        localHash = hashlib.sha256(pemData.encode("utf-8")).hexdigest()
        if localHash != self.hash:
            return False
        return True


class Intermediate:
    subject: str
    kinto_id: str
    whitelist: bool
    crlite_enrolled: bool
    pemAttachment: AttachedPem
    cert: x509.Certificate
    certHash: str
    subjectDN: bytes
    derHash: bytes
    pubKeyHash: bytes

    def __init__(self, debug=False, **kwargs):
        self.pubKeyHash = base64.b64decode(
            kwargs["pubKeyHash"], altchars="-_", validate=True
        )  # sha256 of the SPKI
        self.subject = kwargs["subject"]
        self.whitelist = kwargs["whitelist"]

        self.pemData = None
        if "pem" in kwargs:
            self.pemData = kwargs["pem"]

        self.pemAttachment = None
        if "attachment" in kwargs:
            self.pemAttachment = AttachedPem(**kwargs["attachment"])

        if "enrolled" in kwargs:
            self.crlite_enrolled = kwargs["enrolled"]
        elif "crlite_enrolled" in kwargs:
            self.crlite_enrolled = kwargs["crlite_enrolled"]
        else:
            self.crlite_enrolled = False

        self.kinto_id = None
        if "id" in kwargs:
            self.kinto_id = kwargs["id"]

        if len(self.pubKeyHash) < 26:
            raise IntermediateRecordError(f"Invalid intermediate hash: {kwargs}")

        if self.pemAttachment:
            self.certHash = self.pemAttachment.hash
            if len(self.certHash) < 26:
                raise IntermediateRecordError(f"Invalid Cert hash. {kwargs}")
        elif self.pemData:
            self.certHash = hashlib.sha256(self.pemData.encode("utf-8")).hexdigest()
        else:
            raise IntermediateRecordError(f"No PEM data for this record: {kwargs}")

        # Added 2019-05 (Bug 1552304)
        self.subjectDN = None
        if "subjectDN" in kwargs:
            self.subjectDN = base64.b64decode(
                kwargs["subjectDN"], altchars="-_", validate=True
            )

        self.cert = None
        if self.pemData:
            self.set_pem(self.pemData)
            self.subjectDN = self.cert.subject.public_bytes(backend=default_backend())

        self.derHash = None  # Base64 of `openssl x509 -fingerprint -sha256`
        if "derHash" in kwargs:
            self.derHash = base64.b64decode(
                kwargs["derHash"], altchars="-_", validate=True
            )
            if len(self.derHash) < 26:
                raise IntermediateRecordError(f"Invalid DER hash. {kwargs}")
        elif self.pemData:
            self.derHash = hashlib.sha256(self._get_binary_der()).digest()

    def __str__(self):
        return (
            f"{{Int: {self.subject} "
            + f"[h={base64.b85encode(self.pubKeyHash).decode('utf-8')}"
            + f" e={self.crlite_enrolled}]}}"
        )

    def unique_id(self):
        return (
            f"{base64.b85encode(self.pubKeyHash).decode('utf-8')}"
            + f"-{self.subject}-{self.certHash}"
        )

    def _get_attributes(self, *, complete=False, new=False):
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

    def _get_binary_der(self) -> bytes:
        return asciiPemToBinaryDer(self.pemData)

    def equals(self, *, remote_record=None):
        sameAttributes = self._get_attributes() == remote_record._get_attributes()
        sameAttachment = remote_record.pemAttachment.verify(pemData=self.pemData)
        return sameAttributes and sameAttachment

    def set_pem(self, pem_data):
        self.pemData = pem_data
        try:
            self.cert = x509.load_pem_x509_certificate(
                pem_data.encode("utf-8"), default_backend()
            )
        except Exception as e:
            raise IntermediateRecordError("Cannot parse PEM data: {}".format(e))

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

        if not remote_record.pemAttachment.verify(pemData=self.pemData):
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

        attributes = self._get_attributes(new=True)

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


def publish_intermediates(*, args, ro_client, rw_client):
    local_intermediates = {}
    remote_intermediates = {}
    remote_error_records = []

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

    with intermediates_path.open("r") as f:
        for entry in json.load(f):
            try:
                intObj = Intermediate(**entry, debug=args.debug)

                if intObj.unique_id() in local_intermediates:
                    log.warning(
                        f"[{intObj.unique_id()}] Local collision: {intObj} with "
                        + f"{local_intermediates[intObj.unique_id()]}"
                    )
                    continue

                local_intermediates[intObj.unique_id()] = intObj
            except IntermediateRecordError as e:
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

    for record in ro_client.get_records(
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

    to_delete = set(remote_intermediates.keys()) - set(local_intermediates.keys())
    to_upload = set(local_intermediates.keys()) - set(remote_intermediates.keys())
    to_update = set()
    for i in set(local_intermediates.keys()) & set(remote_intermediates.keys()):
        if not local_intermediates[i].equals(remote_record=remote_intermediates[i]):
            to_update.add(i)

    expired = set()
    for i in to_delete:
        try:
            if remote_intermediates[i].is_expired():
                expired.add(i)
        except Exception as e:
            log.warning(f"Failed to track expiration for {i}: {e}")

    to_delete_not_expired = to_delete - expired

    delete_pubkeys = {remote_intermediates[i].pubKeyHash for i in to_delete}
    upload_pubkeys = {local_intermediates[i].pubKeyHash for i in to_upload}

    unenrollments = set()
    new_enrollments = set()
    update_other_than_enrollment = set()
    for i in to_update:
        if (
            local_intermediates[i].crlite_enrolled
            and not remote_intermediates[i].crlite_enrolled
        ):
            new_enrollments.add(i)
        elif (
            remote_intermediates[i].crlite_enrolled
            and not local_intermediates[i].crlite_enrolled
        ):
            unenrollments.add(i)
        else:
            update_other_than_enrollment.add(i)

    log.info(f"Total entries before update: {len(remote_intermediates)}")
    log.info(f"To delete: {len(to_delete)} (Deletion enabled: {args.delete})")
    log.info(f"- Expired: {len(expired)}")
    log.info(f"To add: {len(to_upload)}")
    log.info(
        f"Certificates updated (without a key change): {len(delete_pubkeys & upload_pubkeys)}"
    )
    log.info(f"Remote records in an error state: {len(remote_error_records)}")
    log.info(f"Total entries updated: {len(to_update)}")
    log.info(f"- New enrollments: {len(new_enrollments)}")
    log.info(f"- Unenrollments: {len(unenrollments)}")
    log.info(f"- Other: {len(update_other_than_enrollment)}")
    log.info(f"Total entries after update: {len(local_intermediates)}")

    if args.noop:
        log.info(f"Noop flag set, exiting before any intermediate updates")
        return

    # Don't accidentally use the ro_client beyond this point
    ro_client = None

    if len(remote_error_records) > 0:
        log.info(f"Cleaning {len(remote_error_records)} broken records")
        for record in remote_error_records:
            try:
                rw_client.delete_record(
                    collection=settings.KINTO_INTERMEDIATES_COLLECTION,
                    id=record["id"],
                )
            except KintoException as ke:
                log.warning(f"Couldn't delete record id {record['id']}: {ke}")

    if args.delete:
        for unique_id in to_delete:
            intermediate = remote_intermediates[unique_id]
            log.info(f"Deleting {intermediate} from Kinto")
            try:
                intermediate.delete_from_kinto(rw_client=rw_client)
            except KintoException as ke:
                log.warning(f"Couldn't delete record id {intermediate}: {ke}")
    else:
        # Locally deleted intermediates should be unenrolled from CRLite even
        # if we aren't performing deletions.
        for unique_id in to_delete:
            intermediate = remote_intermediates[unique_id]
            if not intermediate.crlite_enrolled:
                continue
            log.info(f"Unenrolling deleted {intermediate} from CRLite")
            try:
                intermediate.unenroll_from_crlite_in_kinto(rw_client=rw_client)
            except KintoException as ke:
                log.warning(f"Couldn't unenroll record id {intermediate}: {ke}")

    for unique_id in to_upload:
        intermediate = local_intermediates[unique_id]
        log.debug(f"Uploading {intermediate} to Kinto")
        intermediate.add_to_kinto(rw_client=rw_client)

    update_error_records = []
    for unique_id in to_update:
        local_int = local_intermediates[unique_id]
        remote_int = remote_intermediates[unique_id]
        if not local_int.equals(remote_record=remote_int):
            try:
                local_int.update_kinto(
                    rw_client=rw_client,
                    remote_record=remote_int,
                )
            except KintoException as ke:
                update_error_records.append((local_int, remote_int, ke))

    for (local_int, remote_int, ex) in update_error_records:
        log.warning(
            f"Failed to update local={local_int} remote={remote_int} exception={ex}"
        )

    log.info("Verifying correctness...")
    verified_intermediates = {}
    verification_error_records = []

    for record in rw_client.get_records(
        collection=settings.KINTO_INTERMEDIATES_COLLECTION
    ):
        try:
            intObj = Intermediate(**record)
            verified_intermediates[intObj.unique_id()] = intObj
        except IntermediateRecordError as ire:
            log.warning(
                "Verification found broken intermediate record at Kinto: {}".format(ire)
            )
            verification_error_records.append(record)
        except KeyError as ke:
            log.error("Critical error importing Kinto dataset: {}".format(ke))
            log.error("Record: {}".format(record))
            raise ke

    if len(verification_error_records) > 0:
        raise KintoException(
            "There were {} broken intermediates. Re-run to fix.".format(
                len(verification_error_records)
            )
        )

    log.info(
        "{} intermediates locally, {} at Kinto.".format(
            len(local_intermediates), len(verified_intermediates)
        )
    )

    if args.delete and set(local_intermediates.keys()) != set(
        verified_intermediates.keys()
    ):
        log.error("The verified intermediates do not match the local set. Differences:")
        missing_remote = set(local_intermediates.keys()) - set(
            verified_intermediates.keys()
        )
        missing_local = set(verified_intermediates.keys()) - set(
            local_intermediates.keys()
        )

        for d in missing_remote:
            log.error("{} does not exist at Kinto".format(d))
        for d in missing_local:
            log.error(
                "{} exists at Kinto but should have been deleted (not in local set)".format(
                    d
                )
            )
        raise KintoException("Local/Remote Verification Failed")

    elif not args.delete and set(local_intermediates.keys()) > set(
        verified_intermediates.keys()
    ):
        log.error("The verified intermediates do not match the local set. Differences:")
        missing_remote = set(local_intermediates.keys()) - set(
            verified_intermediates.keys()
        )
        for d in missing_remote:
            log.error("{} does not exist at Kinto".format(d))
        raise KintoException("Local/Remote Verification Failed")

    for unique_id in verified_intermediates.keys():
        remote_int = verified_intermediates[unique_id]

        if unique_id not in local_intermediates and not args.delete:
            log.info(
                "Remote {} has been deleted locally, but ignoring.".format(remote_int)
            )
            continue

        local_int = local_intermediates[unique_id]
        if not local_int.equals(remote_record=remote_int):
            if not remote_int.pemAttachment.verify(pemData=local_int.pemData):
                log.warning(
                    "PEM hash mismatch for {}; remote={} != local={}".format(
                        unique_id, remote_int, local_int
                    )
                )
                raise KintoException(
                    "Local/Remote PEM mismatch for uniqueId={}".format(unique_id)
                )
            else:
                log.warning(
                    f"Local/Remote metadata mismatch, uniqueID={unique_id}, "
                    + f"local={local_int.details()}, remote={remote_int.details()}"
                )
                raise KintoException(
                    "Local/Remote metadata mismatch for uniqueId={}".format(unique_id)
                )

    if to_update or to_upload or to_delete and not args.noop and args.request_review:
        log.info(
            f"Set for review, {len(to_update)} updates, {len(to_upload)} uploads, "
            + f"{len(to_delete)} deletions."
        )
        rw_client.request_review_of_collection(
            collection=settings.KINTO_INTERMEDIATES_COLLECTION,
        )
    else:
        log.info(f"No updates to do")


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

def crlite_verify_record_sanity(*, existing_records):
    # This function assumes that existing_records is sorted according to
    # record["details"]["name"], which is a "YYYY-MM-DDTHH:MM:SS+00:00Z"
    # timestamp.

    # It's OK if there are no records yet.
    if len(existing_records) == 0:
        return

    for r in existing_records:
        if not ("id" in r and "incremental" in r):
            raise SanityException(f"Malformed record {r}.")
        if r["incremental"] and not "parent" in r:
            raise SanityException(f"Malformed record {r}.")

    # There must be exactly 1 full filter in the existing records.
    full_filters = [r for r in existing_records if not r["incremental"]]
    if len(full_filters) == 0:
        raise SanityException(f"No full filters.")
    elif len(full_filters) >= 2:
        raise SanityException(f"Multiple full filters: {full_filters}")

    # Each incremental filter should be a descendent of the full filter
    ids = {r["id"]: r for r in existing_records}
    for r in existing_records:
        ptr = r["id"]
        while ids[ptr]["incremental"]:
            ptr = ids[ptr]["parent"]
            if ptr not in ids:
                raise SanityException(f"Record {r['id']} has unknown parent {ptr}")

    # There should be no long gaps between record timestamps
    allowed_delta = timedelta(hours=8)
    timestamps = [timestamp_from_record(r) for r in existing_records]
    for x, y in zip(timestamps, timestamps[1:]):
        if y - x > allowed_delta:
            raise SanityException(f"Too-wide a delta: {y-x}")


def crlite_verify_run_id_sanity(*, run_db, identifiers_to_check):
    # The runs should be complete.
    for r in identifiers_to_check:
        if not run_db.is_run_ready(r):
            raise SanityException(f"Run is not ready: {r}")

    # Each run should have a "filter" and a "filter.stash" file.
    for r in identifiers_to_check:
        if not run_db.is_run_valid(r):
            raise SanityException(f"Not a valid run: {r}")

    # When sorted by run ID, the runs should have increasing timestamps.
    identifiers_to_check.sort(key=lambda x: [int(y) for y in x.split("-")])
    ts = [run_db.get_run_timestamp(r) for r in identifiers_to_check]
    for x, y in zip(ts, ts[1:]):
        if x > y:
            raise SanityException(f"Out-of-order timestamp: {ts}")

    # There should be no large gaps between run timestamps.
    allowed_delta = timedelta(hours=8)
    for x, y in zip(ts, ts[1:]):
        if y - x > allowed_delta:
            raise SanityException(f"Too-wide a delta: {ts - last_timestamp}")


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
        crlite_verify_record_sanity(existing_records=existing_records)
    except SanityException as se:
        log.error(f"Failed to verify existing record sanity: {se}")
        return default

    # Get a list of run IDs that are newer than any existing record.
    # These are candidates for inclusion in an incremental update.

    # A run ID is a "YYYMMDD" date and an index, e.g. "20210101-3".
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
        log.error(f"We do not have data to support existing records.")
        return default

    # If it's been 10 days since a full filter, publish a full filter.
    min_run_id = min(run_id.split("-")[0] for run_id in old_run_ids)
    min_date = datetime.strptime(min_run_id, "%Y%m%d")
    if datetime.now() - min_date >= timedelta(days=10):
        return default

    # If the new runs fail a sanity check, publish a full filter.
    try:
        crlite_verify_run_id_sanity(run_db=run_db, identifiers_to_check=new_run_ids)
    except SanityException as se:
        log.error(f"Failed to verify run ID sanity: {se}")
        return default

    return {"upload": new_run_ids}


def publish_crlite(*, args, ro_client, rw_client):
    existing_records = ro_client.get_records(
        collection=settings.KINTO_CRLITE_COLLECTION
    )
    # Sort existing_records for crlite_verify_record_sanity
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

    # Don't accidentally use the ro_client beyond this point
    ro_client = None

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
        x["attachment"]["size"] for x in existing_stash_records if x["incremental"]
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


def crlite_sign(*, args, rw_client):
    log.info(f"Signing collection {settings.KINTO_CRLITE_COLLECTION}, noop={args.noop}")
    if args.noop:
        return
    rw_client.sign_collection(collection=settings.KINTO_CRLITE_COLLECTION)


def intermediates_sign(*, args, rw_client):
    log.info(
        f"Signing collection {settings.KINTO_INTERMEDIATES_COLLECTION}, noop={args.noop}"
    )
    if args.noop:
        return
    rw_client.sign_collection(collection=settings.KINTO_INTERMEDIATES_COLLECTION)


if __name__ == "__main__":
    main()
