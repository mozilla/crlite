import argparse
import getpass
import glog as log
import json
import os
import requests
import settings
import sys
import uuid

from datetime import datetime
from requests.auth import HTTPBasicAuth
from kinto_http import Client
from kinto_http.exceptions import KintoException

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

class PublisherClient(Client):
  def attach_file(self, *, collection=None, filePath=None, recordId=None):
    files = [("attachment",
            (os.path.basename(filePath), open(filePath, "rb"),
              "application/octet-stream"))]
    attachmentEndpoint = "buckets/{}/collections/{}/records/{}/attachment".format(self._bucket_name, collection or self._collection_name, recordId)
    response = requests.post(self.session.server_url + attachmentEndpoint, files=files, auth=self.session.auth)
    if response.status_code > 200:
      raise KintoException("Couldn't attach file: {}".format(response.content.decode("utf-8")))

  def request_review_of_collection(self, *, collection=None):
    collectionEnd = "buckets/{}/collections/{}".format(self._bucket_name, collection or self._collection_name)
    response = requests.patch(self.session.server_url + collectionEnd, json={"data": {"status": "to-review"}}, auth=self.session.auth)
    if response.status_code > 200:
      raise KintoException("Couldn't request review: {}".format(response.content.decode("utf-8")))

  def sign_collection(self, *, collection=None):
    collectionEnd = "buckets/{}/collections/{}".format(self._bucket_name, collection or self._collection_name)
    response = requests.patch(self.session.server_url + collectionEnd, json={"data": {"status": "to-sign"}}, auth=self.session.auth)
    if response.status_code > 200:
      raise KintoException("Couldn't sign: {}".format(response.content.decode("utf-8")))

def main():
  parser = argparse.ArgumentParser(description='Upload MLBF files to Kinto as records')
  parser.add_argument('--in', help="file to upload", dest="inpath", required=True)
  parser.add_argument('--crlite', help="True if this is a CRLite update", action='store_true')
  parser.add_argument('--diff', help="True if incremental (only valid for CRLite)", action='store_true')
  parser.add_argument('--intermediates', help="True if this is an update of Intermediates", action='store_true')
  parser.add_argument('--debug', help="Enter a debugger during processing (only valid for Intermediates)", action='store_true')
  parser.add_argument('--clean-broken-records', help='Clean broken remote Intermediate records', action='store_true')
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
  except:
    ensureNonBlank(["KINTO_AUTH_USER", "KINTO_AUTH_PASSWORD"])
    auth = HTTPBasicAuth(settings.KINTO_AUTH_USER, settings.KINTO_AUTH_PASSWORD)
    log.info("Using username/password authentication. Username={}".format(settings.KINTO_AUTH_USER))

  log.info("Connecting to {}".format(settings.KINTO_SERVER_URL))

  client = PublisherClient(
    server_url = settings.KINTO_SERVER_URL,
    auth = auth,
    bucket = settings.KINTO_BUCKET,
    retry = 5,
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

class IntermediateRecordError(Exception):
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

  def verify(self, *, pemData=None):
    raise Exception("Not implemented a method to verify the attachment is correct")

class Intermediate:
  def __init__(self, **kwargs):
    self.pubKeyHash = kwargs['pubKeyHash']

    self.subject = kwargs['subject']
    self.whitelist = kwargs['whitelist']

    if 'pem' in kwargs:
      self.pemData = kwargs['pem']

    if 'attachment' in kwargs:
      self.pemAttachment = AttachedPem(**kwargs['attachment'])

    if 'enrolled' in kwargs:
      self.crlite_enrolled = kwargs['enrolled']
    elif 'crlite_enrolled' in kwargs:
      self.crlite_enrolled = kwargs['crlite_enrolled']
    else:
      self.crlite_enrolled = False

    if 'id' in kwargs:
      self.kinto_id = kwargs['id']

    if len(self.pubKeyHash) < 26:
      raise IntermediateRecordError("Invalid intermediate hash: {}".format(kwargs))

    if not self.pemData and not self.pemAttachment:
      raise IntermediateRecordError("No PEM data for this record: {}".format(kwargs))

  def __str__(self):
    return "{} e={}".format(self.pubKeyHash, self.crlite_enrolled)

  def delete_from_kinto(self, *, client=None):
    if self.kinto_id is None:
      raise IntermediateRecordError("Cannot delete a record not at Kinto: {}".format(self))
    client.delete_record(
      collection = settings.KINTO_INTERMEDIATES_COLLECTION,
      id = self.kinto_id,
    )

  def add_to_kinto(self, *, client=None):
    if self.pemData is None:
      raise IntermediateRecordError("Cannot upload a record not local: {}".format(self))
    pass

def publish_intermediates(*, args=None, auth=None, client=None):
  local_intermediates = {}
  remote_intermediates = {}
  remote_error_records = []

  with open(args.inpath) as f:
    for entry in json.load(f):
      try:
        local_intermediates[entry['pubKeyHash']] = Intermediate(**entry)
      except KeyError as ke:
        log.error("Error importing file from {}: {}".format(args.inpath, ke))
        log.error("Record: {}".format(entry))
        raise ke

  for record in client.get_records(collection = settings.KINTO_INTERMEDIATES_COLLECTION):
    try:
      remote_intermediates[record['pubKeyHash']] = Intermediate(**record)
    except IntermediateRecordError as ire:
      log.warning("Skipping broken intermediate record at Kinto: {}".format(ire))
      remote_error_records.append(record)
    except KeyError as ke:
      log.error("Critical error importing Kinto dataset: {}".format(ke))
      log.error("Record: {}".format(record))
      raise ke

  if len(remote_error_records) > 0:
    log.info("There are {} broken records remotely. Consider running with --clean-broken-records".format(len(remote_error_records)))
    if args.clean_broken_records:
      log.info("Cleaning broken records")
      for record in remote_error_records:
        try:
          client.delete_record(
            collection = settings.KINTO_INTERMEDIATES_COLLECTION,
            id = record['id'],
          )
        except KintoException as ke:
          log.warning("Couldn't delete record id {}: {}".format(record['id'], ke))

  to_delete = set(remote_intermediates.keys()) - set(local_intermediates.keys())
  to_upload = set(local_intermediates.keys()) - set(remote_intermediates.keys())

  if args.debug:
    print("Variables available:")
    print("  local_intermediates")
    print("  remote_intermediates")
    print("  remote_error_records")
    print("")
    print("  to_upload")
    print("  to_delete")
    print("")
    import pdb; pdb.set_trace()

  for pubKeyHash in to_delete:
    intermediate = remote_intermediates[pubKeyHash]
    log.debug("Deleting {} from Kinto".format(intermediate))
    intermediate.delete_from_kinto(client=client)

  for pubKeyHash in to_upload:
    intermediate = local_intermediates[pubKeyHash]
    log.debug("Uploading {} to Kinto".format(intermediate))
    intermediate.add_to_kinto(client=client)

def publish_crlite(*, args=None, auth=None, client=None):
  stale_records = []

  if not args.diff:
    # New base image, so we need to clear out the old records when we're done
    for record in client.get_records(collection = settings.KINTO_CRLITE_COLLECTION):
      stale_records.append(record['id'])
    log.info("New base image indicated. The following MLBF records will be cleaned up at the end: {}".format(stale_records))

  identifier = "{}Z-{}".format(
    datetime.utcnow().isoformat(timespec="seconds"),
    "diff" if args.diff else "full",
  )

  attributes = {
      'details': {'name': identifier },
      'incremental': args.diff
  }
  perms = {"read": ["system.Everyone"]}

  payload = {"data": json.dumps(attributes), "permissions": json.dumps(perms)}

  record = client.create_record(
    collection = settings.KINTO_CRLITE_COLLECTION,
    data = attributes,
    permissions = perms,
  )
  recordid = record['data']['id']

  try:
    client.attach_file(
      collection = settings.KINTO_CRLITE_COLLECTION,
      filePath = args.inpath,
      recordId = recordid,
    )
  except KintoException as ke:
    log.error("Failed to upload attachment. Removing stale MLBF record {}.".format(recordid))
    client.delete_record(id = recordid)
    log.error("Stale record deleted.")
    raise ke

  record = client.get_record(
    collection = settings.KINTO_CRLITE_COLLECTION,
    id = recordid,
  )
  log.info("Successfully uploaded MLBF record.")
  log.info(json.dumps(record, indent = " "))

  for recordid in stale_records:
    log.info("Cleaning up stale MLBF record {}.".format(recordid))
    client.delete_record(
      collection = settings.KINTO_CRLITE_COLLECTION,
      id = recordid,
    )

  log.info("Set for review")
  client.request_review_of_collection(
    collection = settings.KINTO_CRLITE_COLLECTION,
  )

  # Todo - use different credentials, as editor cannot review.
  log.info("Requesting signature")
  client.sign_collection(
    collection = settings.KINTO_CRLITE_COLLECTION,
  )

if __name__ == "__main__":
    main()