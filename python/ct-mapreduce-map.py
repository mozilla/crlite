#!/usr/local/bin/python3

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from publicsuffixlist import PublicSuffixList
import argparse
import boto3
import datetime
import jsonpickle
import time
import os
import pkioracle

parser = argparse.ArgumentParser()
parser.add_argument("--path")
parser.add_argument("--s3bucket")
parser.add_argument("--psl")
parser.add_argument("--problems", default="problems")
parser.add_argument("--output")

# I/O
args = parser.parse_args()

psl = PublicSuffixList()
if args.psl:
  with open(args.psl, "rb") as f:
    psl = PublicSuffixList(f)

oracle = pkioracle.Oracle()
client = boto3.client('s3')
s3 = boto3.resource('s3')

def processDisk(path, errorFd):
  for root, _, files in os.walk(path):
    for file in files:
      file_path = os.path.join(root, file)
      try:
        with open(file_path, 'rb') as f:
          der_data = f.read()
          cert = x509.load_der_x509_certificate(der_data, default_backend())
          oracle.processCert(psl, cert)
      except ValueError as e:
        errorFd.write("{}\t{}\n".format(file_path, e))

def processS3(bucket, errorFd):
  # response = client.list_objects_v2(
  #   Bucket=bucket,
  #   MaxKeys=1024,
  #   # StartAfter='string',
  # )

  # print(response)
  # for obj in response['Contents']:
  #   print(obj)

  for obj in s3.Bucket(bucket).objects.filter(Prefix="cert/"):
    # print(obj)
    try:
      parts = obj.key.split("/")
      year = int(parts[1])
      dayOfYear = int(parts[2])

      # Is this expired by the path?
      now = time.gmtime()
      if year < now.tm_year:
        print("{} is < {}", year, now.tm_year)
        continue
      if year == now.tm_year and dayOfYear < now.tm_yday:
        print("{} is < {}", dayOfYear, now.tm_yday)
        continue

      # OK, not expired yet, fetch the body
      dlObj = obj.get()
      # print(dlObj)
      der_data = dlObj['Body'].read()
      cert = x509.load_der_x509_certificate(der_data, default_backend())
      oracle.processCert(psl, cert)
    except ValueError as e:
      errorFd.write("{}\t{}\t{}\n".format(obj.key, obj, e))

# Main
with open(args.problems, "w+") as problemFd:
  if args.path:
    processDisk(args.path, problemFd)
  elif args.s3bucket:
    processS3(args.s3bucket, problemFd)
  else:
    parser.print_usage()
    raise Exception("You have to give either path or s3bucket")

# Clean up the oracle and serialize it
del oracle.mutex
serializedOracle = jsonpickle.encode(oracle)

# Either go to file, or to stdout
if args.output:
  with open(args.output, "w") as outFd:
    outFd.write(serializedOracle)
else:
  # Pretty print it. Cheat using json module
  import json
  parsed = json.loads(serializedOracle)
  print(json.dumps(parsed, indent=4))