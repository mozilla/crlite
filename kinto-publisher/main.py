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
from kinto_http import Client
from kinto_http.exceptions import KintoException

class BearerTokenAuth(requests.auth.AuthBase):
  def __init__(self, token):
    self.token = token

  def __call__(self, r):
    r.headers['Authorization'] = 'Bearer ' + self.token
    return r

parser = argparse.ArgumentParser(description='Upload MLBF files to Kinto as records')
parser.add_argument('--in', help="MLBF file", dest="mblfpath", required=True)
parser.add_argument('--diff', help="True if incremental", action='store_true')

args = parser.parse_args()

if not os.path.exists(args.mblfpath):
  raise Exception("You must provide an input MLBF file as the --in argument.")

auth = BearerTokenAuth(settings.KINTO_AUTH_TOKEN)

client = Client(
  server_url=settings.KINTO_SERVER_URL,
  auth=auth,
  collection=settings.KINTO_COLLECTION,
  bucket=settings.KINTO_BUCKET,
  retry=5,
)

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

files = [("attachment", (os.path.basename(args.mblfpath), open(args.mblfpath, "rb"), "application/octet-stream"))]
attachmentEnd = "buckets/{}/collections/{}/records/{}/attachment".format(settings.KINTO_BUCKET, settings.KINTO_COLLECTION, recordid)
try:
  response = requests.post(settings.KINTO_SERVER_URL + attachmentEnd, files=files, auth=auth)
  response.raise_for_status()
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

collectionEnd = "buckets/{}/collections/{}".format(settings.KINTO_BUCKET, settings.KINTO_COLLECTION)

log.info("Set for review")
response = requests.patch(settings.KINTO_SERVER_URL + collectionEnd, json={"data": {"status": "to-review"}}, auth=auth)
try:
  response.raise_for_status()
except:
  log.error("Failed to request signature.")
  log.error(response.text)
  sys.exit(1)

# Todo - use different credentials, as editor cannot review.
log.info("Requesting signature")
response = requests.patch(settings.KINTO_SERVER_URL + collectionEnd, json={"data": {"status": "to-sign"}}, auth=auth)
try:
  response.raise_for_status()
except:
  log.error("Failed to request signature")
  log.error(response.text)
