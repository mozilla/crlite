#!/usr/local/bin/python3

from collections import Counter
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from publicsuffixlist import PublicSuffixList
from progressbar import Bar, SimpleProgress, AdaptiveETA, Percentage, ProgressBar
from datetime import datetime
import argparse
# import boto3
import os
import pkioracle
import sys
import time
import threading
import queue
import geoip2.database

parser = argparse.ArgumentParser()
parser.add_argument("--path", help="Path to folder on disk to store certs")
# parser.add_argument("--s3bucket", help="S3 Bucket to store certs")
parser.add_argument("--psl", help="Path to effective_tld_names.dat")
parser.add_argument("--geoipDb", help="Path to GeoIP2-City.mmdb, if you want DNS resolutions")
parser.add_argument("--problems", default="problems", help="File to record errors")
parser.add_argument("--threads", help="Number of worker threads to use", default=4, type=int)
parser.add_argument("--outname", help="Name of output report files", default="oracle.out")
parser.add_argument('--assumedirty', help="Assume all folders are dirty", action="store_true")

# Progress Bar configuration
widgets = [Percentage(),
           ' ', Bar(),
           ' ', SimpleProgress(),
           ' ', AdaptiveETA()]

# I/O
args = parser.parse_args()

psl = PublicSuffixList()
if args.psl:
  with open(args.psl, "rb") as f:
    psl = PublicSuffixList(f)

# client = boto3.client('s3')
# s3 = boto3.resource('s3')

if args.problems:
  problemFd = open(args.problems, "w+")

geoDB = None
if args.geoipDb:
  geoDB = geoip2.database.Reader(args.geoipDb)

counter = Counter()

pbar_mutex = threading.RLock()
pbar = ProgressBar(widgets=widgets, maxval=0)
pbar.start()

work_queue = queue.Queue()

# Thread worker
def worker():
  while True:
    # Get a work task, if any
    dirty_folder = work_queue.get()
    if dirty_folder is None:
      break

    oracle = pkioracle.Oracle()
    if geoDB:
      oracle.geoDB = geoDB
    processFolder(oracle, dirty_folder)
    # save state out
    with open(os.path.join(dirty_folder, args.outname), "w") as outFd:
      outFd.write(oracle.serialize())

    # clear the dirty flag
    try:
      os.remove(os.path.join(dirty_folder, "dirty"))
    except:
      pass

    # All done
    work_queue.task_done()

def processFolder(oracle, path):
  if os.path.isdir(os.path.join(path, "state")):
    raise Exception("Should be called on subfolders, not the primary folder")

  file_queue = []

  for root, _, files in os.walk(path):
    for file in files:
      file_queue.append(os.path.join(root, file))

  with pbar_mutex:
    pbar.maxval += len(file_queue)

  for file_path in file_queue:
    try:
      with open(file_path, 'rb') as f:
        der_data = f.read()
        cert = x509.load_der_x509_certificate(der_data, default_backend())
        # This call is likely to block
        metaData = oracle.getMetadataForCert(psl, cert)
        oracle.recordCertMetadata(metaData)
        counter["Total Certificates Processed"] += 1
    except ValueError as e:
      problemFd.write("{}\t{}\n".format(file_path, e))
      counter["Certificate Parse Errors"] += 1

    with pbar_mutex:
      pbar.update(pbar.currval + 1)

  counter["Folders Processed"] += 1


def processDisk(path):
  if not os.path.isdir(os.path.join(path, "state")):
    raise Exception("This should be called on the primary folder")

  for item in os.listdir(path):
    # Skip the "state" folder
    if item == "state":
      continue

    entry = os.path.join(path, item)
    if not os.path.isdir(entry):
      # Not a folder, keep going
      continue

    # Is this expired (check by looking the path so we don't have to continue
    # to load)
    pathdate = datetime.strptime(item, "%Y-%m-%d").timetuple()
    now = time.gmtime()
    if (pathdate.tm_year < now.tm_year) or (pathdate.tm_year == now.tm_year and pathdate.tm_yday < now.tm_yday):
      counter["Folders Expired"] += 1
      continue

    # Does this folder have a dirty flag set?
    if args.assumedirty or os.path.isfile(os.path.join(entry, "dirty")):
      # Folder is dirty, add to the queue
      work_queue.put(entry)
      continue

    counter["Folders Up-to-date"] += 1

def main():
  if not args.path:
    parser.print_usage()
    sys.exit(0)

  threads = []
  for i in range(args.threads):
    t = threading.Thread(target=worker)
    t.start()
    threads.append(t)

  processDisk(args.path)

  work_queue.join()
  pbar.finish()

  print("Work queue completed.")

  for i in range(args.threads):
      work_queue.put(None)
  for t in threads:
      t.join()

  if problemFd:
    problemFd.close()

  print("All done. Process results: {}".format(counter))

if __name__ == "__main__":
  main()