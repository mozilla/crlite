import argparse
import json
import jsonpickle
import os
import pkioracle
import sys
import threading
import traceback
from datetime import datetime, timedelta
from collections import Counter
from progressbar import Bar, SimpleProgress, AdaptiveETA, Percentage, ProgressBar

# Progress Bar configuration
widgets = [Percentage(),
           ' ', Bar(),
           ' ', SimpleProgress(),
           ' ', AdaptiveETA()]

parser = argparse.ArgumentParser()
parser.add_argument("input", nargs="*", help="Input reports (oracle.out files) from ct-mapreduce-map.py")
parser.add_argument("--problems", default="problems", help="File to record errors")
parser.add_argument("--output", help="File to place the output report")
parser.add_argument("--path", help="Path to root folder on disk to store certs; if you specify this, don't specify specific input files")
parser.add_argument('--summary', help="Produce a human-readable summary report", action="store_true")
parser.add_argument("--expiredate", help="Expiration date to use (YYYY-MM-dd); if unset, will use the most recent UTC midnight")
parser.add_argument("--futuredays", help="Number of future days to process", type=int, default=90)


# I/O
def main():
  args = parser.parse_args()
  oracle = pkioracle.Oracle()
  stats = Counter()
  mutex = threading.RLock()

  if not args.path and len(args.input) == 0:
    parser.print_usage()
    sys.exit(0)

  expiredate = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
  if args.expiredate:
    expiredate = datetime.strptime(args.expiredate, "%Y-%m-%d")
  latestdate = expiredate + timedelta(days=args.futuredays)

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
      if dir_date >= latestdate:
        stats["Future Directories"] += 1
        continue
      for file in files:
        if file == "oracle.out":
          process_queue.append(os.path.join(root, file))

  with open(args.problems, "w") as problemFd:
    pbar = ProgressBar(widgets=widgets, maxval=len(process_queue), redirect_stderr=True)
    pbar.start()

    for idx, inFile in enumerate(process_queue):
      print("Processing {}".format(inFile), file=sys.stderr)
      try:
        oracle.loadAndMerge(inFile)
        stats["Number of Files Processed"] += 1
        pbar.update(idx)
      except ValueError as e:
        problemFd.write("{}\t{}\n".format(inFile, e))

    pbar.finish()

    print("Procesing complete...", file=sys.stderr)

    try:
      if len(args.input) == 1:
        print("Producing summary", file=sys.stderr)
        summarize(args.output, oracle, stats)
      else:
        print("Serializing state", file=sys.stderr)
        serialize(args.output, oracle, stats)
    except:
      problemFd.write("Exception writing output\t{}\n".format(traceback.format_exc()))
      print(traceback.format_exc(), file=sys.stderr)
      sys.exit(1)

    print(stats, file=sys.stderr)
    print("mapreduce-reduce completed", file=sys.stderr)
    sys.exit(0)

def summarize(output, oracle, stats):
  summary = oracle.summarize(stats)

  orgMap = {}
  for entry in summary.values():
    name = entry["organization"]
    if name not in orgMap:
      orgMap[name] = Counter({
        "certsIssuedByIssuanceDay": Counter(),
      })

    orgMap[name]["certsIssuedByIssuanceDay"] += entry["certsIssuedByIssuanceDay"]
    orgMap[name]["fqdns"] += entry["fqdns"]
    orgMap[name]["regDoms"] += entry["regDoms"]
    orgMap[name]["wildcards"] += entry["wildcards"]
    orgMap[name]["certsTotal"] += entry["certsTotal"]

  if output:
    with open(output, "w") as outFd:
      outFd.write(summary)
  else:
      print(json.dumps(summary, indent=4))
      print(json.dumps(orgMap, indent=4))

def serialize(output, oracle, stats):
  if output:
    with open(output, "wb") as outFd:
      oracle.serialize(outFd)
  else:
    oracle.serialize(sys.stdout, indent=4)


if __name__ == "__main__":
  main()