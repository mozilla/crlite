#!/usr/bin/env python3
import argparse
import base64
import glog as log
import hashlib
import json
import re
import requests
import settings
import tempfile
import workflow

from datetime import datetime, timedelta
from kinto_http import Client
from kinto_http.exceptions import KintoException
from pathlib import Path
from requests.auth import HTTPBasicAuth
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class SanityException(Exception):
    pass


class BearerTokenAuth(requests.auth.AuthBase):
    def __init__(self, token):
        self.token = token

    def __call__(self, r):
        r.headers["Authorization"] = "Bearer " + self.token
        return r


def ensureNonBlank(settingNames):
    for setting in settingNames:
        if getattr(settings, setting) == "":
            raise Exception("{} must not be blank.".format(setting))


def asciiPemToBinaryDer(pem: str) -> bytes:
    matches = re.search(
        r"(?<=-----BEGIN CERTIFICATE-----).*?(?=-----END CERTIFICATE-----)",
        pem,
        flags=re.DOTALL,
    )
    return base64.b64decode(matches.group(0))


def get_attachments_base_url():
    return requests.get(settings.KINTO_SERVER_URL).json()["capabilities"][
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
                "Couldn't attach file at endpoint {}: {}".format(
                    self.session.server_url + attachmentEndpoint,
                    response.content.decode("utf-8"),
                )
            )

    def request_review_of_collection(self, *, collection=None):
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
                "Couldn't request review: {}".format(response.content.decode("utf-8"))
            )

    def sign_collection(self, *, collection=None):
        collectionEnd = "buckets/{}/collections/{}".format(
            self._bucket_name, collection or self._collection_name
        )
        response = requests.patch(
            self.session.server_url + collectionEnd,
            json={"data": {"status": "to-sign"}},
            auth=self.session.auth,
        )
        if response.status_code > 200:
            raise KintoException(
                "Couldn't sign: {}".format(response.content.decode("utf-8"))
            )


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
    crlite_group.add_argument("--filter-bucket", default="crlite_filters")
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

    parser.add_argument(
        "--request-review",
        action="store_true",
        help="Mark the Kinto collection for signature when done",
    )
    parser.add_argument("--verbose", "-v", help="Be more verbose", action="store_true")

    args = parser.parse_args()

    if args.verbose:
        log.setLevel("DEBUG")

    auth = {}
    try:
        ensureNonBlank(["KINTO_AUTH_TOKEN"])
        auth = BearerTokenAuth(settings.KINTO_AUTH_TOKEN)
        log.info("Using authentication bearer token")
    except Exception:
        ensureNonBlank(["KINTO_AUTH_USER", "KINTO_AUTH_PASSWORD"])
        auth = HTTPBasicAuth(settings.KINTO_AUTH_USER, settings.KINTO_AUTH_PASSWORD)
        log.info(
            "Using username/password authentication. Username={}".format(
                settings.KINTO_AUTH_USER
            )
        )

    log.info("Connecting to {}".format(settings.KINTO_SERVER_URL))

    client = PublisherClient(
        server_url=settings.KINTO_SERVER_URL,
        auth=auth,
        bucket=settings.KINTO_BUCKET,
        retry=5,
    )

    try:
        if args.crlite:
            publish_crlite(args=args, client=client)

        elif args.intermediates:
            publish_intermediates(args=args, client=client)

        else:
            parser.print_help()
    except KintoException as ke:
        log.error("An exception occurred: {}".format(ke))
        raise ke


class IntermediateRecordError(KintoException):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message


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

    def _upload_pem(self, *, client=None, kinto_id=None):
        client.attach_file(
            collection=settings.KINTO_INTERMEDIATES_COLLECTION,
            fileContents=self.pemData,
            fileName=f"{base64.urlsafe_b64encode(self.pubKeyHash).decode('utf-8')}.pem",
            mimeType="application/x-pem-file",
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
        self.cert = x509.load_pem_x509_certificate(
            pem_data.encode("utf-8"), default_backend()
        )

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

    def delete_from_kinto(self, *, client=None):
        if self.kinto_id is None:
            raise IntermediateRecordError(
                "Cannot delete a record not at Kinto: {}".format(self)
            )
        client.delete_record(
            collection=settings.KINTO_INTERMEDIATES_COLLECTION, id=self.kinto_id,
        )

    def update_kinto(self, *, remote_record=None, client=None):
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

        client.update_record(
            collection=settings.KINTO_INTERMEDIATES_COLLECTION,
            data=self._get_attributes(complete=True),
            id=remote_record.kinto_id,
        )

    def add_to_kinto(self, *, client=None):
        if self.pemData is None:
            raise IntermediateRecordError(
                "Cannot upload a record not local: {}".format(self)
            )

        attributes = self._get_attributes(new=True)

        perms = {"read": ["system.Everyone"]}
        record = client.create_record(
            collection=settings.KINTO_INTERMEDIATES_COLLECTION,
            data=attributes,
            permissions=perms,
        )
        self.kinto_id = record["data"]["id"]

        try:
            self._upload_pem(client=client)
        except KintoException as ke:
            log.error(
                "Failed to upload attachment. Removing stale intermediate record {}.".format(
                    self.kinto_id
                )
            )
            client.delete_record(
                collection=settings.KINTO_INTERMEDIATES_COLLECTION, id=self.kinto_id,
            )
            log.error("Stale record deleted.")
            raise ke

    def details(self):
        return self._get_attributes()


def export_intermediates(writer, keys, intermediates, *, old=None):
    for key in keys:
        details = intermediates[key].details()
        writer.write(
            "\n\t".join([f"{key} = {value}" for key, value in details.items()])
        )
        writer.write("\n\n")
        if old:
            details = old[key].details()
            writer.write("Previous state: \n")
            writer.write(
                "\n\t".join([f"{key} = {value}" for key, value in details.items()])
            )
            writer.write("\n---------------\n\n")


def publish_intermediates(*, args, client):
    local_intermediates = {}
    remote_intermediates = {}
    remote_error_records = []

    with open(args.intermediates_file, "r") as f:
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
            except Exception as e:
                log.error("Error importing file from {}: {}".format(args.inpath, e))
                log.error("Record: {}".format(entry))
                raise e

    for record in client.get_records(
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
        if remote_intermediates[i].is_expired():
            expired.add(i)

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

    print(f"Total entries before update: {len(remote_intermediates)}")
    print(f"To delete: {len(to_delete)} (Deletion enabled: {args.delete})")
    print(f"- Expired: {len(expired)}")
    print(f"To add: {len(to_upload)}")
    print(
        f"Certificates updated (without a key change): {len(delete_pubkeys & upload_pubkeys)}"
    )
    print(f"Total entries updated: {len(to_update)}")
    print(f"- New enrollments: {len(new_enrollments)}")
    print(f"- Unenrollments: {len(unenrollments)}")
    print(f"- Other: {len(update_other_than_enrollment)}")
    print(f"Total entries after update: {len(local_intermediates)}")
    print("")

    if args.export:
        with open(Path(args.export) / Path("to_delete"), "w") as df:
            export_intermediates(df, to_delete, remote_intermediates)
        with open(Path(args.export) / Path("to_delete_not_expired"), "w") as df:
            export_intermediates(df, to_delete_not_expired, remote_intermediates)
        with open(Path(args.export) / Path("expired"), "w") as df:
            export_intermediates(df, expired, remote_intermediates)
        with open(Path(args.export) / Path("to_upload"), "w") as df:
            export_intermediates(df, to_upload, local_intermediates)
        with open(Path(args.export) / Path("to_update"), "w") as df:
            export_intermediates(
                df, to_update, local_intermediates, old=remote_intermediates
            )
        with open(Path(args.export) / Path("unenrollments"), "w") as df:
            export_intermediates(
                df, unenrollments, local_intermediates, old=remote_intermediates
            )
        with open(Path(args.export) / Path("new_enrollments"), "w") as df:
            export_intermediates(
                df, new_enrollments, local_intermediates, old=remote_intermediates
            )
        with open(Path(args.export) / Path("update_other_than_enrollment"), "w") as df:
            export_intermediates(
                df,
                update_other_than_enrollment,
                local_intermediates,
                old=remote_intermediates,
            )

    if args.debug:
        print("Variables available:")
        print("  local_intermediates")
        print("  remote_intermediates")
        print("  remote_error_records")
        print("")
        print("  to_upload")
        print("  to_delete")
        print("  to_update")
        print("")
        print("  new_enrollments")
        print("  unenrollments")
        print("")
        print("  delete_pubkeys")
        print("  upload_pubkeys")
        print(
            "  delete_pubkeys & upload_pubkeys # certs updated without changing the key"
        )
        print("")
        print("  local_intermediates[to_update.pop()].cert # get cert object")
        print("")
        print("Use 'continue' to proceed")
        print("")
        breakpoint()

    if len(remote_error_records) > 0:
        log.info("Cleaning {} broken records".format(len(remote_error_records)))
        for record in remote_error_records:
            try:
                client.delete_record(
                    collection=settings.KINTO_INTERMEDIATES_COLLECTION, id=record["id"],
                )
            except KintoException as ke:
                log.warning("Couldn't delete record id {}: {}".format(record["id"], ke))

    for unique_id in to_delete:
        intermediate = remote_intermediates[unique_id]
        if args.delete:
            log.info("Deleting {} from Kinto".format(intermediate))
            intermediate.delete_from_kinto(client=client)

    for unique_id in to_upload:
        intermediate = local_intermediates[unique_id]
        log.debug("Uploading {} to Kinto".format(intermediate))
        intermediate.add_to_kinto(client=client)

    update_error_records = []
    for unique_id in to_update:
        local_int = local_intermediates[unique_id]
        remote_int = remote_intermediates[unique_id]
        if not local_int.equals(remote_record=remote_int):
            try:
                local_int.update_kinto(
                    client=client, remote_record=remote_int,
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
    for record in client.get_records(
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
                breakpoint()
                raise KintoException(
                    "Local/Remote metadata mismatch for uniqueId={}".format(unique_id)
                )

    if to_update or to_upload or to_delete and not args.noop and args.request_review:
        log.info(
            f"Set for review, {len(to_update)} updates, {len(to_upload)} uploads, "
            + f"{len(to_delete)} deletions."
        )
        client.request_review_of_collection(
            collection=settings.KINTO_INTERMEDIATES_COLLECTION,
        )
    else:
        log.info(f"No updates to do")

    # Todo - use different credentials, as editor cannot review.
    # log.info("Requesting signature")
    # client.sign_collection(
    #   collection = settings.KINTO_INTERMEDIATES_COLLECTION,
    # )


def clear_crlite_filters(*, client, noop):
    if noop:
        log.info("Would clean up CRLite filters, but no-op set")
        return
    existing_records = client.get_records(collection=settings.KINTO_CRLITE_COLLECTION)
    existing_filters = filter(lambda x: x["incremental"] is False, existing_records)
    for filter_record in existing_filters:
        log.info(f"Cleaning up stale filter record {filter_record['id']}.")
        client.delete_record(
            collection=settings.KINTO_CRLITE_COLLECTION, id=filter_record["id"],
        )


def clear_crlite_stashes(*, client, noop):
    if noop:
        log.info("Would clean up CRLite stashes, but no-op set")
        return
    existing_records = client.get_records(collection=settings.KINTO_CRLITE_COLLECTION)
    existing_stashes = filter(lambda x: x["incremental"] is True, existing_records)
    for stash in existing_stashes:
        log.info(f"Cleaning up stale stash record {stash['id']}.")
        client.delete_record(
            collection=settings.KINTO_CRLITE_COLLECTION, id=stash["id"],
        )


def publish_crlite_record(
    *, path, filename, timestamp, client, incremental, noop, previous_id=None
):
    record_type = "diff" if incremental else "full"
    record_time = timestamp.isoformat(timespec="seconds")
    identifier = f"{record_time}Z-{record_type}"

    attributes = {"details": {"name": identifier}, "incremental": incremental}
    perms = {"read": ["system.Everyone"]}
    if incremental:
        assert previous_id, "Incremental records must have a previous record ID"
        attributes["details"]["previous"] = previous_id

    log.info(
        f"Publishing {path} {timestamp} incremental={incremental} (previous={previous_id})"
    )
    if noop:
        log.info("NoOp mode enabled")

    if not noop:
        record = client.create_record(
            collection=settings.KINTO_CRLITE_COLLECTION,
            data=attributes,
            permissions=perms,
        )
        recordid = record["data"]["id"]

        try:
            client.attach_file(
                collection=settings.KINTO_CRLITE_COLLECTION,
                fileName=filename,
                filePath=path,
                recordId=recordid,
            )
        except KintoException as ke:
            log.error(
                f"Failed to upload attachment. Removing stale MLBF record {recordid}: {ke}"
            )
            client.delete_record(
                collection=settings.KINTO_CRLITE_COLLECTION, id=recordid,
            )
            log.error("Stale record deleted.")
            raise ke
    else:
        recordid = "fake-noop-id"
        record = {"fake": True}

    log.info("Successfully uploaded MLBF record.")
    log.debug(json.dumps(record, indent=" "))
    return recordid


def publish_crlite_main_filter(*, filter_path, filename, client, timestamp, noop):
    return publish_crlite_record(
        path=filter_path,
        filename=filename,
        timestamp=timestamp,
        client=client,
        noop=noop,
        incremental=False,
    )


def publish_crlite_stash(*, stash_path, filename, client, previous_id, timestamp, noop):
    return publish_crlite_record(
        path=stash_path,
        filename=filename,
        timestamp=timestamp,
        client=client,
        previous_id=previous_id,
        noop=noop,
        incremental=True,
    )


def timestamp_from_record(record):
    iso_string = record["details"]["name"].split("Z-")[0]
    return datetime.fromisoformat(iso_string)


def timestamp_from_run_id(run_id):
    parts = run_id.split("-")
    time_string = f"{parts[0]}-{int(parts[1])*6}"
    return datetime.strptime(time_string, "%Y%m%d-%H")


def timestamp_from_path(path):
    return timestamp_from_run_id(path.name)


def verify_unbroken_stash_chain(*, current_filter, current_stashes, stash_path):
    if current_filter is None:
        return False

    if current_filter["incremental"] is not False:
        raise ValueError(f"current filter should be non-incremental: {current_filter}")

    previous = current_filter
    for stash in reversed(current_stashes):
        if stash["details"]["previous"] != previous["id"]:
            log.warning(
                f"Stash {stash} does not reference the previous entry {previous}"
            )
            return False

        delta = timestamp_from_record(stash) - timestamp_from_record(previous)
        if delta < timedelta(0) or delta > timedelta(hours=24):
            log.warning(
                f"Stash chain has a time delta of {delta} between {previous} and {stash}"
            )
            return False

        previous = stash

    # Now confirm that the stash_path's filename is logically the next after previous
    previous_timestamp = timestamp_from_record(previous)
    stash_timestamp = timestamp_from_path(stash_path)

    delta = stash_timestamp - previous_timestamp

    log.debug(
        f"previous timestamp={previous_timestamp}, stash={stash_timestamp}, "
        + f"delta={delta}"
    )

    # TODO: use the {-1,2,3...} to try and get 6 hour resolution
    if delta < timedelta(0) or delta > timedelta(hours=24):
        log.warning(
            f"Stash is not recent enough compared to the previous (delta={delta})"
        )
        return False

    return True


def crlite_verify_record_sanity(*, existing_records):
    current_filters = list(
        filter(lambda x: x["incremental"] is False, existing_records)
    )
    if len(current_filters) == 0 and len(existing_records) > 0:
        raise SanityException(f"Only diff records")

    if len(current_filters) > 1:
        raise SanityException(f"More than one current filter: {current_filters}")

    allowed_delta = timedelta(hours=8)

    last_timestamp = None
    for r in existing_records:
        ts = timestamp_from_record(r)
        if last_timestamp:
            if ts < last_timestamp:
                raise SanityException(f"Out-of-order timestamp: {ts}")
            if ts - last_timestamp > allowed_delta:
                raise SanityException(f"Too-wide a delta: {ts - last_timestamp}")
        last_timestamp = ts


def crlite_verify_run_id_sanity(*, run_identifiers):
    allowed_delta = timedelta(hours=8)

    last_timestamp = None
    for r in run_identifiers:
        ts = timestamp_from_run_id(r)
        if last_timestamp:
            if ts < last_timestamp:
                raise SanityException(f"Out-of-order timestamp: {ts}")
            if ts - last_timestamp > allowed_delta:
                raise SanityException(f"Too-wide a delta: {ts - last_timestamp}")
        last_timestamp = ts


def crlite_determine_publish(*, existing_records, run_identifiers):
    assert len(run_identifiers) > 0, "There must be run identifiers"

    # First, if there are no existing records, then we upload the most recent
    # run.
    if not existing_records:
        return {"clear_all": True, "upload": [run_identifiers[-1]]}

    # First, match the most recent filter-or-stash with its run identifier.
    # If we don't find any published run identifiers, just upload the most
    # recent run.
    published_run_ids = []
    unpublished_run_ids = []

    for idx, run_id in enumerate(run_identifiers):
        if run_id in existing_records[-1]["attachment"]["filename"]:
            published_run_ids = run_identifiers[: idx + 1]
            unpublished_run_ids = run_identifiers[idx + 1 :]
            break

    if not published_run_ids:
        return {"clear_all": True, "upload": [run_identifiers[-1]]}

    # verify sanity of the run_identifiers
    try:
        crlite_verify_run_id_sanity(run_identifiers=unpublished_run_ids)
    except SanityException as se:
        log.error(f"Failed to verify run ID sanity: {se}")
        return {"clear_all": True, "upload": [run_identifiers[-1]]}

    return {"upload": unpublished_run_ids}


def publish_crlite(*, args, client):
    existing_records = client.get_records(collection=settings.KINTO_CRLITE_COLLECTION)
    run_identifiers = workflow.get_run_identifiers(args.filter_bucket)

    try:
        crlite_verify_record_sanity(existing_records=existing_records)
    except SanityException as se:
        log.error(f"Failed to verify existing record sanity: {se}")
        clear_crlite_filters(client=client, noop=args.noop)
        clear_crlite_stashes(client=client, noop=args.noop)

    result = crlite_determine_publish(
        existing_records=existing_records, run_identifiers=run_identifiers
    )

    log.debug(f"crlite_determine_publish results={result}")

    if not result["upload"]:
        log.info("Nothing to do.")
        return

    if "clear_all" in result:
        clear_crlite_filters(client=client, noop=args.noop)
        clear_crlite_stashes(client=client, noop=args.noop)

    args.download_path.mkdir()

    existing_stash_records = filter(lambda x: x["incremental"], existing_records)
    existing_stash_size = sum(
        map(lambda x: x["attachment"]["size"], existing_stash_records)
    )
    log.info(f"Total size of existing published records: {existing_stash_size} bytes")

    upload_size = 0

    for run_id in result["upload"]:
        run_id_path = args.download_path / Path(run_id)
        run_id_path.mkdir()
        timestamp_path = run_id_path / Path("timestamp")
        stash_path = run_id_path / Path("stash")

        workflow.download_and_retry_from_google_cloud(
            args.filter_bucket,
            f"{run_id}/mlbf/filter.stash",
            stash_path,
            timeout=timedelta(minutes=5),
        )

        try:
            workflow.download_from_google_cloud(
                args.filter_bucket, f"{run_id}/mlbf/timestamp", timestamp_path
            )
        except Exception:
            # If there's no timestamp, then we can derive it. This code should
            # not be necessary for release, remove it before then.
            timestamp_path.write_text(
                timestamp_from_run_id(run_id).isoformat(timespec="seconds")
            )
            pass

        upload_size += stash_path.stat().st_size

    total_size = existing_stash_size + upload_size

    log.info(
        f"Total size would be {total_size} bytes after uploading {upload_size} bytes of stashes: "
        + f"{result['upload']}"
    )

    final_run_id = result["upload"][-1]
    filter_path = args.download_path / Path(final_run_id) / Path("filter")
    workflow.download_and_retry_from_google_cloud(
        args.filter_bucket,
        f"{final_run_id}/mlbf/filter",
        filter_path,
        timeout=timedelta(minutes=5),
    )

    if total_size > filter_path.stat().st_size or not existing_records:
        if existing_records:
            log.info(
                f"Total size {total_size} > {filter_path} ({filter_path.stat().st_size}), "
                + "uploading a full filter."
            )

        clear_crlite_filters(client=client, noop=args.noop)
        clear_crlite_stashes(client=client, noop=args.noop)

        timestamp_path = args.download_path / Path(final_run_id) / Path("timestamp")

        publish_crlite_main_filter(
            filter_path=filter_path,
            filename=f"{final_run_id}-filter",
            client=client,
            timestamp=datetime.fromisoformat(timestamp_path.read_text()),
            noop=args.noop,
        )

    else:
        previous_id = existing_records[-1]["id"]
        for run_id in result["upload"]:
            run_id_path = args.download_path / Path(run_id)
            timestamp_path = run_id_path / Path("timestamp")
            stash_path = run_id_path / Path("stash")
            assert (
                timestamp_path.is_file() and stash_path.is_file()
            ), "files must have been downloaded"

            log.info(
                f"Adding this stash will increase {existing_stash_size} to {total_size}, "
                + f"uploading {stash_path}"
            )

            previous_id = publish_crlite_stash(
                stash_path=stash_path,
                filename=f"{final_run_id}-filter.stash",
                client=client,
                previous_id=previous_id,
                timestamp=datetime.fromisoformat(timestamp_path.read_text()),
                noop=args.noop,
            )

    if not args.noop and args.request_review:
        log.info("Set for review")
        client.request_review_of_collection(
            collection=settings.KINTO_CRLITE_COLLECTION,
        )


if __name__ == "__main__":
    main()
