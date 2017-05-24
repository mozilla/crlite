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

  with open(args.input, 'r') as f:
    oracle.merge(jsonpickle.decode(f.read()))

  for aki, data in oracle.summarize(stats).items():
    # print(aki)
    # print(data)
    issuerId = storage.getIssuerID(aki=aki, name=data['organization'])
    # print(issuerId)

    for datestamp, issueCount in data['certsIssuedByIssuanceDay'].items():
      if args.today == datestamp:
        storage.updateCertTimeline(issuerID=issuerId, datestamp=datestamp, certsIssued=issueCount,
                                   certsActive=data['certsTotal'], fqdnsActive=data['fqdns'],
                                   regDomainsActive=data['regDoms'])
      else:
        storage.updateCertTimeline(issuerID=issuerId, datestamp=datestamp, certsIssued=issueCount)

# #"datestamp date primary key, countTLS integer not null, countPageloads integer not null,"
# #                "timeAdded datetime not null)")
# storage.updatePageloadTLS(datestamp="2017-01-01", countTLS=44, countPageloads=55,
#                           timeAdded="2017-09-11 01:23:45")

if __name__ == "__main__":
  main()