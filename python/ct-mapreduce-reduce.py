import argparse
import jsonpickle
import os
import json
import pkioracle

parser = argparse.ArgumentParser()
parser.add_argument("input", nargs='*')
parser.add_argument("--problems", default="problems")
parser.add_argument("--output")

def serializeOracle(oracle):
  del oracle.mutex
  return jsonpickle.encode(oracle)

# I/O
args = parser.parse_args()
oracle = pkioracle.Oracle()

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
      serializedOracle = serializeOracle(oracle)
      outFd.write(serializedOracle)

else:
  if len(args.input) == 1:
    summary = oracle.summarize()
    print(json.dumps(summary, indent=4))
  else:
    serializedOracle = serializeOracle(oracle)
    parsed = json.loads(serializedOracle)
    print(json.dumps(parsed, indent=4))