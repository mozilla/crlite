import argparse
import json
import jsonpickle
import os
import pkioracle
import sys
from collections import Counter
from progressbar import Bar, SimpleProgress, AdaptiveETA, Percentage, ProgressBar

# Progress Bar configuration
widgets = [Percentage(),
           ' ', Bar(),
           ' ', SimpleProgress(),
           ' ', AdaptiveETA()]

parser = argparse.ArgumentParser()
parser.add_argument("input", nargs='*', help="Input reports (oracle.out files) from ct-mapreduce-map.py")
parser.add_argument("--problems", default="problems", help="File to record errors")
parser.add_argument("--output", help="File to place the output report")
parser.add_argument("--path", help="Path to root folder on disk to store certs; if you specify this, don't specify specific input files")

# I/O
args = parser.parse_args()
oracle = pkioracle.Oracle()

stats = Counter()

if not args.path and len(args.input) == 0:
  parser.print_usage()
  sys.exit(0)

process_queue = args.input

if args.path:
  if not os.path.isdir(os.path.join(args.path, "state")):
    raise Exception("Should be called the primary folder, not subfolders")

  for root, _, files in os.walk(args.path):
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
        stats["numFiles"] += 1
        pbar.update(idx)
    except ValueError as e:
      problemFd.write("{}\t{}\n".format(inFile, e))

  pbar.finish()

if args.output:
  with open(args.output, "w") as outFd:
    if len(args.input) == 1:
      summary = oracle.summarize()
      outFd.write(summary)
    else:
      serializedOracle = oracle.serialize()
      outFd.write(serializedOracle)

else:
  if len(args.input) == 1:
    summary = oracle.summarize()
    print(json.dumps(summary, indent=4))
  else:
    serializedOracle = oracle.serialize()
    parsed = json.loads(serializedOracle)
    print(json.dumps(parsed, indent=4))

print(stats)