from collections import Counter
from datetime import datetime
from IPy import IP
from progressbar import Bar, SimpleProgress, AdaptiveETA, Percentage, ProgressBar
import argparse
import geoip2.database
import json
import jsonpickle
import os
import pkioracle
import queue
import socket
import sys
import threading

# Progress Bar configuration
widgets = [Percentage(),
           ' ', Bar(),
           ' ', SimpleProgress(),
           ' ', AdaptiveETA()]

parser = argparse.ArgumentParser()
parser.add_argument("input", nargs="*", help="Input reports (oracle.out files) from ct-mapreduce-map.py")
parser.add_argument("--problems", default="problems", help="File to record errors")
parser.add_argument("--geoipDb", help="Path to GeoIP2-City.mmdb, if you want DNS resolutions")
parser.add_argument("--output", help="File to place the output report")
parser.add_argument("--threads", help="Number of worker threads to use", default=32, type=int)
parser.add_argument("--path", help="Path to root folder on disk to store certs; if you specify this, don't specify specific input files")
parser.add_argument('--summary', help="Produce a human-readable summary report", action="store_true")
parser.add_argument("--expiredate", help="Expiration date to use (YYYY-MM-dd); if unset, will use the most recent UTC midnight")
parser.add_argument("--inname", help="Name of input report files", default="oracle.out")

args = parser.parse_args()
oracle = pkioracle.Oracle()

if not args.path and len(args.input) == 0:
  parser.print_usage()
  sys.exit(0)

expiredate = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
if args.expiredate:
  expiredate = datetime.strptime(args.expiredate, "%Y-%m-%d")

if not args.geoipDb:
  raise Exception("You must specify the GeoIP database for this operation")
geoDB = geoip2.database.Reader(args.geoipDb)

stats = Counter()

pbar_mutex = threading.RLock()
pbar = ProgressBar(widgets=widgets)
pbar.start()

work_queue = queue.Queue()

problemFd = None
if args.problems:
  problemFd = open(args.problems, "w+")

def worker():
  while True:
    # Get a work task, if any
    task = work_queue.get()
    if task is None:
      break

    try:
      # Get continent, country, city
      ipAddress = socket.gethostbyname(task["fqdn"])
      if IP(ipAddress).iptype() != "PRIVATE":
        result = geoDB.city(ipAddress)
        metaData = {
          "ipaddress": ipAddress,
          "continent": result.continent.name,
          "countrycode": result.country.iso_code
        }
        oracle.recordGeodata(task["aki"], metaData)
    except:
      pass

    with pbar_mutex:
      pbar.update(pbar.currval + 1)

    # All done
    work_queue.task_done()

# I/O
def main():
  process_queue = args.input

  if args.path:
    if not os.path.isdir(os.path.join(args.path, "state")):
      raise Exception("Should be called the primary folder, not subfolders")

    for root, _, files in os.walk(args.path):
      try:
        dir_date = datetime.strptime(os.path.basename(root), "%Y-%m-%d")
      except ValueError as e:
        continue

      if dir_date < expiredate:
        stats["Expired Directories"] += 1
        continue
      for file in files:
        if file == args.inname:
          process_queue.append(os.path.join(root, file))

  threads = []
  for i in range(args.threads):
    t = threading.Thread(target=worker)
    t.start()
    threads.append(t)

  for inFile in process_queue:
    try:
      with open(inFile, 'r') as f:
        oracle.merge(jsonpickle.decode(f.read()))
        stats["Number of Files Processed"] += 1
    except ValueError as e:
      if problemFd:
        problemFd.write("{}\t{}\n".format(inFile, e))

  for aki in oracle.certAuthorities:
    with pbar_mutex:
      pbar.maxval += len(oracle.certAuthorities[aki].fqdnSet)
    for fqdn in oracle.certAuthorities[aki].fqdnSet:
      work_queue.put({"fqdn": fqdn, "aki": aki})

  work_queue.join()
  for i in range(args.threads):
    work_queue.put(None)
  for t in threads:
    t.join()

  pbar.finish()

  if problemFd:
    problemFd.close()

  if args.output:
    with open(args.output, "w") as outFd:
      if len(process_queue) == 1:
        summary = oracle.summarize(stats)
        outFd.write(summary)
      else:
        serializedOracle = oracle.serialize()
        outFd.write(serializedOracle)

  else:
    if len(process_queue) == 1:
      summary = oracle.summarize(stats)
      print(json.dumps(summary, indent=4))
    else:
      serializedOracle = oracle.serialize()
      parsed = json.loads(serializedOracle)
      print(json.dumps(parsed, indent=4))

  print(stats)

if __name__ == "__main__":
  main()