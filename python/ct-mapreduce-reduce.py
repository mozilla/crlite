import argparse
import json
import jsonpickle
import os
import pkioracle
import sys

parser = argparse.ArgumentParser()
parser.add_argument("input", nargs='*', help="Input reports from ct-mapreduce-map.py")
parser.add_argument("--problems", default="problems", help="File to record errors")
parser.add_argument("--output", help="File to place the output report")

# I/O
args = parser.parse_args()
oracle = pkioracle.Oracle()

if len(args.input) == 0:
  parser.print_usage()
  sys.exit(0)

with open(args.problems, "w") as problemFd:
  for inFile in args.input:
    try:
      with open(inFile, 'r') as f:
        oracle.merge(jsonpickle.decode(f.read()))
    except ValueError as e:
      problemFd.write("{}\t{}\n".format(inFile, e))

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