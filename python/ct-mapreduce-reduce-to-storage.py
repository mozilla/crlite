import sys
import argparse
import jsonpickle
import pkioracle
import statisticstorage
from collections import Counter

parser = argparse.ArgumentParser()
parser.add_argument("input", help="Reduce report from ct-mapreduce-reduce.py")
parser.add_argument("--db", help="Database file")
parser.add_argument("--today", help="Today's date YYYY-MM-DD")

# I/O
def main():
  args = parser.parse_args()
  if len(args.input) == 0 or args.db is None:
    parser.print_usage()
    sys.exit(0)

  storage = statisticstorage.StatisticStorage(dbPath=args.db)
  oracle = pkioracle.Oracle()
  stats = Counter()

  oracle.loadAndMerge(args.input)

  for aki, data in oracle.summarize(stats).items():
    # print(aki)
    # print(data)
    issuerId = storage.getIssuerID(aki=aki, name=data['organization'])
    # print(issuerId)

    for datestamp, issueCount in data['certsIssuedByIssuanceDay'].items():
      storage.updateCertTimeline(issuerID=issuerId, datestamp=datestamp, certsIssued=issueCount)

    print("Completed issuance count update. Today = {}".format(args.today))
    if args.today:
      storage.updateCertTimeline(issuerID=issuerId, datestamp=args.today, certsActive=data['certsTotal'],
                                 fqdnsActive=data['fqdns'], regDomainsActive=data['regDoms'],
                                 wildcardsActive=data['wildcards'])
      print("Updated cert timeline: {} {} {} {} {}".format(data['certsTotal'], data['fqdns'],
            data['regDoms'], len(data['certsIssuedByIssuanceDay']), data['wildcards']))


if __name__ == "__main__":
  main()

