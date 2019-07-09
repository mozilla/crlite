import argparse
import base64
import glog as log
import hashlib
import json
import os
import re
import requests
import settings

from datetime import datetime
from requests.auth import HTTPBasicAuth
from kinto_http import Client
from kinto_http.exceptions import KintoException
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class BearerTokenAuth(requests.auth.AuthBase):
    def __init__(self, token):
        self.token = token

    def __call__(self, r):
        r.headers['Authorization'] = 'Bearer ' + self.token
        return r

def ensureNonBlank(settingNames):
    for setting in settingNames:
        if getattr(settings, setting) == "":
            raise Exception("{} must not be blank.".format(setting))


def asciiPemToBinaryDer(pem: str) -> bytes:
    matches = re.search(r'(?<=-----BEGIN CERTIFICATE-----).*?(?=-----END CERTIFICATE-----)',
                        pem, flags=re.DOTALL)
    return base64.b64decode(matches.group(0))


class PublisherClient(Client):
    def attach_file(self, *, collection=None, filePath=None, fileName="file", fileContents=None,
                    mimeType="application/octet-stream", recordId=None):
        if not filePath and not fileContents:
            raise Exception("Must specify either filePath or fileContents")

        if filePath:
            files = [("attachment",
                      (fileName, open(filePath, "rb"), mimeType))]
        elif fileContents:
            files = [("attachment",
                      (fileName, fileContents, mimeType))]
        else:
            raise Exception("Unexpected state")

        attachmentEndpoint = "buckets/{}/collections/{}/records/{}/attachment".format(
            self._bucket_name, collection or self._collection_name, recordId)
        response = requests.post(self.session.server_url + attachmentEndpoint,
                                 files=files, auth=self.session.auth)
        if response.status_code > 200:
            raise KintoException("Couldn't attach file at endpoint {}: {}".format(
                self.session.server_url + attachmentEndpoint, response.content.decode("utf-8")))

    def request_review_of_collection(self, *, collection=None):
        collectionEnd = "buckets/{}/collections/{}".format(
            self._bucket_name, collection or self._collection_name)
        response = requests.patch(self.session.server_url + collectionEnd,
                                  json={"data": {"status": "to-review"}}, auth=self.session.auth)
        if response.status_code > 200:
            raise KintoException("Couldn't request review: {}".format(
                response.content.decode("utf-8")))

    def sign_collection(self, *, collection=None):
        collectionEnd = "buckets/{}/collections/{}".format(
            self._bucket_name, collection or self._collection_name)
        response = requests.patch(self.session.server_url + collectionEnd,
                                  json={"data": {"status": "to-sign"}}, auth=self.session.auth)
        if response.status_code > 200:
            raise KintoException("Couldn't sign: {}".format(response.content.decode("utf-8")))


def main():
    parser = argparse.ArgumentParser(description='Upload MLBF files to Kinto as records')
    parser.add_argument('--in', help="file to upload", dest="inpath", required=True)
    parser.add_argument('--crlite', action='store_true',
                        help="True if this is a CRLite update")
    parser.add_argument('--diff', action='store_true',
                        help="True if incremental (only valid for CRLite)")
    parser.add_argument('--intermediates', action='store_true',
                        help="True if this is an update of Intermediates")
    parser.add_argument('--debug', action='store_true',
                        help="Enter a debugger during processing (only valid for Intermediates)")
    parser.add_argument('--delete', action='store_true',
                        help="Delete entries that are now missing (only valid for Intermediates)")
    parser.add_argument('--verbose', '-v', help="Be more verbose", action='store_true')

    args = parser.parse_args()

    if not args.intermediates ^ args.crlite:
        parser.print_help()
        raise Exception("You must select either --intermediates or --crlite")

    if not os.path.exists(args.inpath):
        parser.print_help()
        raise Exception("You must provide an input file as the --in argument.")

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
        log.info("Using username/password authentication. Username={}".format(
          settings.KINTO_AUTH_USER))

    log.info("Connecting to {}".format(settings.KINTO_SERVER_URL))

    client = PublisherClient(
      server_url=settings.KINTO_SERVER_URL,
      auth=auth,
      bucket=settings.KINTO_BUCKET,
      retry=5,
    )

    try:
        if args.crlite:
            publish_crlite(args=args, auth=auth, client=client)

        elif args.intermediates:
            publish_intermediates(args=args, auth=auth, client=client)

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
        self.filename = kwargs['filename']
        self.size = kwargs['size']
        self.location = kwargs['location']
        self.mimetype = kwargs['mimetype']
        self.hash = kwargs['hash']

    def _get_attributes(self):
        return {
          'filename': self.filename,
          'size': self.size,
          'location': self.location,
          'mimetype': self.mimetype,
          'hash': self.hash,
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
    certHash: str
    subjectDN: bytes
    derHash: bytes
    pubKeyHash: bytes

    def __init__(self, debug=False, **kwargs):
        self.pubKeyHash = base64.b64decode(kwargs['pubKeyHash'], altchars="-_", validate=True)  # sha256 of the SPKI
        self.subject = kwargs['subject']
        self.whitelist = kwargs['whitelist']

        self.pemData = None
        if 'pem' in kwargs:
            self.pemData = kwargs['pem']

        self.pemAttachment = None
        if 'attachment' in kwargs:
            self.pemAttachment = AttachedPem(**kwargs['attachment'])

        if 'enrolled' in kwargs:
            self.crlite_enrolled = kwargs['enrolled']
        elif 'crlite_enrolled' in kwargs:
            self.crlite_enrolled = kwargs['crlite_enrolled']
        else:
            self.crlite_enrolled = False

        self.kinto_id = None
        if 'id' in kwargs:
            self.kinto_id = kwargs['id']

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
        if 'subjectDN' in kwargs:
            self.subjectDN = base64.b64decode(kwargs['subjectDN'], altchars="-_", validate=True)

        if self.pemData:
            self.cert = x509.load_pem_x509_certificate(self.pemData.encode("utf-8"),
                                                       default_backend())
            self.subjectDN = self.cert.subject.public_bytes(backend=default_backend())

        self.derHash = None  # Base64 of `openssl x509 -fingerprint -sha256`
        if 'derHash' in kwargs:
            self.derHash = base64.b64decode(kwargs['derHash'], altchars="-_", validate=True)
            if len(self.derHash) < 26:
                raise IntermediateRecordError(f"Invalid DER hash. {kwargs}")
        elif self.pemData:
            self.derHash = hashlib.sha256(self._get_binary_der()).digest()

    def __str__(self):
        return f"{{Int: {self.subject} [h={base64.b85encode(self.pubKeyHash).decode('utf-8')} e={self.crlite_enrolled}]}}"

    def unique_id(self):
        return f"{base64.b85encode(self.pubKeyHash).decode('utf-8')}-{self.subject}-{self.certHash}"

    def _get_attributes(self, *, complete=False, new=False):
        attributes = {
          'subject': self.subject,
          'subjectDN': base64.standard_b64encode(self.subjectDN).decode("utf-8"),
          'derHash': base64.standard_b64encode(self.derHash).decode("utf-8"),
          'pubKeyHash': base64.standard_b64encode(self.pubKeyHash).decode("utf-8"),
          'whitelist': self.whitelist,
          'crlite_enrolled': self.crlite_enrolled,
        }

        if complete and self.pemAttachment:
            attributes['attachment'] = self.pemAttachment._get_attributes()

        return attributes

    def _upload_pem(self, *, client=None, kinto_id=None):
        client.attach_file(
          collection=settings.KINTO_INTERMEDIATES_COLLECTION,
          fileContents=self.pemData,
          fileName=f"{base64.urlsafe_base64(self.pubKeyHash).decode('utf-8')}.pem",
          mimeType="application/x-pem-file",
          recordId=kinto_id or self.kinto_id,
        )

    def _get_binary_der(self) -> bytes:
        return asciiPemToBinaryDer(self.pemData)

    def equals(self, *, remote_record=None):
        sameAttributes = self._get_attributes() == remote_record._get_attributes()
        sameAttachment = remote_record.pemAttachment.verify(pemData=self.pemData)
        return sameAttributes and sameAttachment

    def delete_from_kinto(self, *, client=None):
        if self.kinto_id is None:
            raise IntermediateRecordError("Cannot delete a record not at Kinto: {}".format(self))
        client.delete_record(
          collection=settings.KINTO_INTERMEDIATES_COLLECTION,
          id=self.kinto_id,
        )

    def update_kinto(self, *, remote_record=None, client=None):
        if self.pemData is None:
            raise IntermediateRecordError("Cannot upload a record not local: {}".format(self))
        if remote_record is None:
            raise IntermediateRecordError("Must provide a remote record")

        if remote_record.kinto_id is None:
            raise IntermediateRecordError("No kinto ID available {}".format(remote_record))

        if not remote_record.pemAttachment.verify(pemData=self.pemData):
            log.warning("Attachment update needed for {}".format(self))
            log.warning("New: {}".format(self.pemData))

            # TODO: Do we delete the record? Right now it'll get caught at the end but
            # not get fixed.
            raise IntermediateRecordError(
                    "Attachment is incorrect for ID {}".format(remote_record.kinto_id))

        # Make sure to put back the existing PEM attachment data
        self.pemAttachment = remote_record.pemAttachment

        client.update_record(
          collection=settings.KINTO_INTERMEDIATES_COLLECTION,
          data=self._get_attributes(complete=True),
          id=remote_record.kinto_id,
        )

    def add_to_kinto(self, *, client=None):
        if self.pemData is None:
            raise IntermediateRecordError("Cannot upload a record not local: {}".format(self))

        attributes = self._get_attributes(new=True)

        perms = {"read": ["system.Everyone"]}
        record = client.create_record(
          collection=settings.KINTO_INTERMEDIATES_COLLECTION,
          data=attributes,
          permissions=perms,
        )
        self.kinto_id = record['data']['id']

        try:
            self._upload_pem(client=client)
        except KintoException as ke:
            log.error(
                "Failed to upload attachment. Removing stale intermediate record {}.".format(
                    self.kinto_id))
            client.delete_record(
              collection=settings.KINTO_INTERMEDIATES_COLLECTION,
              id=self.kinto_id,
            )
            log.error("Stale record deleted.")
            raise ke


def publish_intermediates(*, args=None, auth=None, client=None):
    local_intermediates = {}
    remote_intermediates = {}
    remote_error_records = []

    with open(args.inpath) as f:
        for entry in json.load(f):
            try:
                decodedSubjectBytes = base64.urlsafe_b64decode(entry['subject'])
                entry['subject'] = decodedSubjectBytes.decode("utf-8", "replace")
                intObj = Intermediate(**entry, debug=args.debug)

                if intObj.unique_id() in local_intermediates:
                    raise Exception("Local collision: {}".format(intObj))

                local_intermediates[intObj.unique_id()] = intObj
            except Exception as e:
                log.error("Error importing file from {}: {}".format(args.inpath, e))
                log.error("Record: {}".format(entry))
                raise e

    for record in client.get_records(collection=settings.KINTO_INTERMEDIATES_COLLECTION):
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

    delete_pubkeys = {remote_intermediates[i].pubKeyHash for i in to_delete}
    upload_pubkeys = {local_intermediates[i].pubKeyHash for i in to_upload}

    print(f"To delete: {len(to_delete)} (Deletion enabled: {args.delete})")
    print(f"To add: {len(to_upload)}")
    print(f"Certificates updated (without a key change): {len(delete_pubkeys & upload_pubkeys)}")
    print(f"Total entries updated: {len(to_update)}")
    print("")

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
        print("  delete_pubkeys")
        print("  upload_pubkeys")
        print("  delete_pubkeys & upload_pubkeys # certs updated without changing the key")
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
                  collection=settings.KINTO_INTERMEDIATES_COLLECTION,
                  id=record['id'],
                )
            except KintoException as ke:
                log.warning("Couldn't delete record id {}: {}".format(record['id'], ke))

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
                  client=client,
                  remote_record=remote_int,
                )
            except KintoException as ke:
                update_error_records.append((local_int, remote_int, ke))

    for (local_int, remote_int, ex) in update_error_records:
        log.warning(f"Failed to update local={local_int} remote={remote_int} exception={ex}")

    log.info("Verifying correctness...")
    verified_intermediates = {}
    verification_error_records = []
    for record in client.get_records(collection=settings.KINTO_INTERMEDIATES_COLLECTION):
        try:
            intObj = Intermediate(**record)
            verified_intermediates[intObj.unique_id()] = intObj
        except IntermediateRecordError as ire:
            log.warning("Verification found broken intermediate record at Kinto: {}".format(ire))
            verification_error_records.append(record)
        except KeyError as ke:
            log.error("Critical error importing Kinto dataset: {}".format(ke))
            log.error("Record: {}".format(record))
            raise ke

    if len(verification_error_records) > 0:
        raise KintoException(
            "There were {} broken intermediates. Re-run to fix.".format(
              len(verification_error_records)))

    log.info("{} intermediates locally, {} at Kinto.".format(
        len(local_intermediates), len(verified_intermediates)))

    if args.delete and set(local_intermediates.keys()) != set(verified_intermediates.keys()):
        log.error("The verified intermediates do not match the local set. Differences:")
        missing_remote = set(local_intermediates.keys()) - set(verified_intermediates.keys())
        missing_local = set(verified_intermediates.keys()) - set(local_intermediates.keys())

        for d in missing_remote:
            log.error("{} does not exist at Kinto".format(d))
        for d in missing_local:
            log.error(
              "{} exists at Kinto but should have been deleted (not in local set)".format(d))
        raise KintoException("Local/Remote Verification Failed")

    elif not args.delete and set(local_intermediates.keys()) > set(verified_intermediates.keys()):
        log.error("The verified intermediates do not match the local set. Differences:")
        missing_remote = set(local_intermediates.keys()) - set(verified_intermediates.keys())
        for d in missing_remote:
            log.error("{} does not exist at Kinto".format(d))
        raise KintoException("Local/Remote Verification Failed")

    for unique_id in verified_intermediates.keys():
        remote_int = verified_intermediates[unique_id]

        if unique_id not in local_intermediates and not args.delete:
            log.info("Remote {} has been deleted locally, but ignoring.".format(remote_int))
            continue

        local_int = local_intermediates[unique_id]
        if not local_int.equals(remote_record=remote_int):
            if not remote_int.pemAttachment.verify(pemData=local_int.pemData):
                log.warning("PEM hash mismatch for {}; remote={} != local={}".format(
                    unique_id, remote_int, local_int))
                raise KintoException("Local/Remote PEM mismatch for uniqueId={}".format(unique_id))
            else:
                breakpoint()
                raise KintoException(
                                "Local/Remote metadata mismatch for uniqueId={}".format(unique_id))

    log.info("Set for review")
    client.request_review_of_collection(
      collection=settings.KINTO_INTERMEDIATES_COLLECTION,
    )

    # Todo - use different credentials, as editor cannot review.
    # log.info("Requesting signature")
    # client.sign_collection(
    #   collection = settings.KINTO_INTERMEDIATES_COLLECTION,
    # )


def publish_crlite(*, args=None, auth=None, client=None):
    stale_records = []

    if not args.diff:
        # New base image, so we need to clear out the old records when we're done
        for record in client.get_records(collection=settings.KINTO_CRLITE_COLLECTION):
            stale_records.append(record['id'])
        log.info("New base image indicated.")
        log.info("The following MLBF records will be cleaned up at the end: {}".format(
                 stale_records))

    identifier = "{}Z-{}".format(
      datetime.utcnow().isoformat(timespec="seconds"),
      "diff" if args.diff else "full",
    )

    attributes = {
        'details': {'name': identifier},
        'incremental': args.diff
    }
    perms = {"read": ["system.Everyone"]}

    record = client.create_record(
      collection=settings.KINTO_CRLITE_COLLECTION,
      data=attributes,
      permissions=perms,
    )
    recordid = record['data']['id']

    try:
        client.attach_file(
          collection=settings.KINTO_CRLITE_COLLECTION,
          fileName=os.path.basename(args.inpath),
          filePath=args.inpath,
          recordId=recordid,
        )
    except KintoException as ke:
        log.error("Failed to upload attachment. Removing stale MLBF record {}.".format(recordid))
        client.delete_record(
          collection=settings.KINTO_CRLITE_COLLECTION,
          id=recordid,
        )
        log.error("Stale record deleted.")
        raise ke

    record = client.get_record(
      collection=settings.KINTO_CRLITE_COLLECTION,
      id=recordid,
    )
    log.info("Successfully uploaded MLBF record.")
    log.info(json.dumps(record, indent=" "))

    for recordid in stale_records:
        log.info("Cleaning up stale MLBF record {}.".format(recordid))
        client.delete_record(
          collection=settings.KINTO_CRLITE_COLLECTION,
          id=recordid,
        )

    log.info("Set for review")
    client.request_review_of_collection(
      collection=settings.KINTO_CRLITE_COLLECTION,
    )

    # Todo - use different credentials, as editor cannot review.
    # log.info("Requesting signature")
    # client.sign_collection(
    #   collection = settings.KINTO_CRLITE_COLLECTION,
    # )


if __name__ == "__main__":
    main()
