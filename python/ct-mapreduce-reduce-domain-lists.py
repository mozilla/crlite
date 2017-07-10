import sys
import argparse
import jsonpickle
import pkioracle
import statisticstorage
from collections import Counter

parser = argparse.ArgumentParser()
parser.add_argument("input", help="Reduce report from ct-mapreduce-reduce.py")
parser.add_argument("--fqdns", help="Write FQDNs here")
parser.add_argument("--regdoms", help="Write RegDoms here")

# I/O
def main():
  args = parser.parse_args()
  if len(args.input) == 0 or (args.fqdns is None and args.regdoms is None):
    parser.print_usage()
    sys.exit(0)

  oracle = pkioracle.Oracle()
  stats = Counter()

  oracle.loadAndMerge(args.input)

  allFqdns = set()
  allRegDoms = set()

  for k in oracle.certAuthorities:
    allFqdns = allFqdns | oracle.certAuthorities[k].fqdnSet
    allRegDoms = allRegDoms | oracle.certAuthorities[k].regDomSet

  if args.fqdns:
    with open(args.fqdns, "w") as out:
      for fqdn in allFqdns:
        out.write("{}\n".format(fqdn))

  if args.regdoms:
    with open(args.regdoms, "w") as out:
      for rd in allRegDoms:
        out.write("{}\n".format(rd))

if __name__ == "__main__":
  main()