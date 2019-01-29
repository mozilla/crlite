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
  def attach_file(self, *, filePath=None, recordId=None):
    files = [("attachment",
            (os.path.basename(filePath), open(filePath, "rb"),
              "application/octet-stream"))]
    attachmentEndpoint = "buckets/{}/collections/{}/records/{}/attachment".format(self._bucket_name, self._collection_name, recordId)
    response = requests.post(self.session.server_url + attachmentEndpoint, files=files, auth=self.session.auth)
    response.raise_for_status()

  def request_review_of_collection(self):
    collectionEnd = "buckets/{}/collections/{}".format(self._bucket_name, self._collection_name)
    response = requests.patch(self.session.server_url + collectionEnd, json={"data": {"status": "to-review"}}, auth=self.session.auth)
    if response.status_code > 200:
      raise KintoException("Couldn't request review: {}".format(response.content.decode("utf-8")))

  def sign_collection(self):
    collectionEnd = "buckets/{}/collections/{}".format(self._bucket_name, self._collection_name)
    response = requests.patch(self.session.server_url + collectionEnd, json={"data": {"status": "to-sign"}}, auth=self.session.auth)
    if response.status_code > 200:
      raise KintoException("Couldn't sign: {}".format(response.content.decode("utf-8")))

def main():
  parser = argparse.ArgumentParser(description='Upload MLBF files to Kinto as records')
  parser.add_argument('--in', help="file to upload", dest="inpath", required=True)
  parser.add_argument('--intermediates', help="True if this is an update of intermediates", action='store_true')
  parser.add_argument('--crlite', help="True if this is a CRLite update", action='store_true')
  parser.add_argument('--diff', help="True if incremental (only valid for CRLite)", action='store_true')

  args = parser.parse_args()

  if not args.intermediates ^ args.crlite:
    parser.print_help()
    raise Exception("You must select either --intermediates or --crlite")

  if not os.path.exists(args.inpath):
    parser.print_help()
    raise Exception("You must provide an input file as the --in argument.")

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
    server_url=settings.KINTO_SERVER_URL,
    auth=auth,
    collection=settings.KINTO_COLLECTION,
    bucket=settings.KINTO_BUCKET,
    retry=5,
  )

  if args.crlite:
    publish_crlite(args=args, auth=auth, client=client)

  elif args.intermediates:
    publish_intermediates(args=args, auth=auth, client=client)

  else:
    parser.print_help()


def publish_intermediates(*, args=None, auth=None, client=None):
  raise Exception("Not implemented")

def publish_crlite(*, args=None, auth=None, client=None):
  stale_records=[]

  if not args.diff:
    # New base image, so we need to clear out the old records when we're done
    for record in client.get_records():
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
    data=attributes,
    permissions=perms,
  )
  recordid = record['data']['id']

  try:
    client.attach_file(filePath=args.inpath, recordId=recordid)
  except:
    log.error("Failed to upload attachment. Removing stale MLBF record {}.".format(recordid))
    client.delete_record(id=recordid)
    log.error("Stale record deleted.")
    sys.exit(1)

  record = client.get_record(id=recordid)
  log.info("Successfully uploaded MLBF record.")
  log.info(json.dumps(record, indent=" "))

  for recordid in stale_records:
    log.info("Cleaning up stale MLBF record {}.".format(recordid))
    client.delete_record(id=recordid)

  log.info("Set for review")
  try:
    client.request_review_of_collection()
  except KintoException as e:
    log.error("Failed to request signature: ", e)
    sys.exit(1)

  # Todo - use different credentials, as editor cannot review.
  log.info("Requesting signature")
  try:
    client.sign_collection()
  except KintoException as e:
    log.error("Failed to request signature: ", e)

if __name__ == "__main__":
    main()