#!/usr/local/bin/python3

from collections import Counter
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime
from progressbar import Bar, SimpleProgress, AdaptiveETA, Percentage, ProgressBar
from publicsuffixlist import PublicSuffixList
import argparse
import base64
import os
import pkioracle
import queue
import sys
import threading
import time

parser = argparse.ArgumentParser()
parser.add_argument("--path", help="Path to folder on disk to store certs")
parser.add_argument("--psl", help="Path to effective_tld_names.dat")
parser.add_argument("--problems", default="problems", help="File to record errors")
parser.add_argument("--limit", help="Number of folders to process", type=int)
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

if args.problems:
  problemFd = open(args.problems, "w+")

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

def processCer(oracle, path):
  """
  This method processes one single certificate, in DER-format
  """
  with open(file_path, 'rb') as f:
    der_data = f.read()
    cert = x509.load_der_x509_certificate(der_data, default_backend())
    metaData = oracle.getMetadataForCert(psl, cert)
    oracle.recordCertMetadata(metaData)
    counter["Total Certificates Processed"] += 1

def processPem(oracle, path):
  """
  This method processes a PEM file which may contain one or more PEM-formatted
  certificates.
  """
  fileSize = os.path.getsize(path)

  with pbar_mutex:
    pbar.maxval += fileSize

  with open(path, 'r') as pemFd:
    pem_buffer = ""
    buffer_len = 0

    for line in pemFd:
      # Record length always
      buffer_len += len(line)

      if line == "-----BEGIN CERTIFICATE-----\n":
        continue
      if line.startswith("LogID") or line.startswith("Recorded-at") or len(line)==0:
        continue
      if line.startswith("Seen-in-log"):
        continue
      if line == "-----END CERTIFICATE-----\n":
        # process the PEM
        der_data = base64.standard_b64decode(pem_buffer)
        cert = x509.load_der_x509_certificate(der_data, default_backend())
        metaData = oracle.getMetadataForCert(psl, cert)
        oracle.recordCertMetadata(metaData)
        counter["Total Certificates Processed"] += 1

        with pbar_mutex:
          pbar.update(pbar.currval + buffer_len)

        # clear the buffer
        pem_buffer = ""
        buffer_len = 0
        continue

      # Just a normal part of the base64, so add it to the buffer
      pem_buffer += line

def processFolder(oracle, path):
  if os.path.isdir(os.path.join(path, "state")):
    raise Exception("Should be called on subfolders, not the primary folder")

  file_queue = []

  for root, _, files in os.walk(path):
    for file in files:
      if file.endswith("cer") or file.endswith("pem"):
        file_queue.append(os.path.join(root, file))

  with pbar_mutex:
    pbar.maxval += len(file_queue)

  for file_path in file_queue:
    try:
      if file_path.endswith("cer"):
        processCer(oracle, file_path)
      elif file_path.endswith("pem"):
        processPem(oracle, file_path)
      else:
        raise Exception("Unknown type " + file_path)

    except ValueError as e:
      problemFd.write("{}\t{}\n".format(file_path, e))
      counter["Certificate Parse Errors"] += 1

    with pbar_mutex:
      pbar.update(pbar.currval + 1)

  counter["Folders Processed"] += 1


def processDisk(path):
  if not os.path.isdir(os.path.join(path, "state")):
    raise Exception("This should be called on the primary folder")

  count = 0

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
      count += 1
      if args.limit and args.limit <= count:
        return
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