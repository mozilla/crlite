import argparse
import json
import jsonpickle
import os
import pkioracle
import sys
import threading
from datetime import datetime
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
        if file == "oracle.out":
          process_queue.append(os.path.join(root, file))

  with open(args.problems, "w") as problemFd:
    pbar = ProgressBar(widgets=widgets, maxval=len(process_queue))
    pbar.start()

    for idx, inFile in enumerate(process_queue):
      try:
        with open(inFile, 'r') as f:
          oracle.merge(jsonpickle.decode(f.read()))
          stats["Number of Files Processed"] += 1
          pbar.update(idx)
      except ValueError as e:
        problemFd.write("{}\t{}\n".format(inFile, e))

    pbar.finish()

  if args.output:
    with open(args.output, "w") as outFd:
      if len(args.input) == 1:
        summary = oracle.summarize(stats)
        outFd.write(summary)
      else:
        serializedOracle = oracle.serialize()
        outFd.write(serializedOracle)

  else:
    if len(args.input) == 1:
      summary = oracle.summarize(stats)
      print(json.dumps(summary, indent=4))
    else:
      serializedOracle = oracle.serialize()
      parsed = json.loads(serializedOracle)
      print(json.dumps(parsed, indent=4))

  print(stats)

if __name__ == "__main__":
  main()