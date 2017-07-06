import argparse
import logging
import requests
import statisticstorage
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from progressbar import Bar, SimpleProgress, AdaptiveETA, Percentage, ProgressBar

parser = argparse.ArgumentParser()
parser.add_argument("--db", help="Database file")
parser.add_argument("--window", help="Time window in days", type=int, default=30)

# Progress Bar configuration
widgets = [Percentage(),
           ' ', Bar(),
           ' ', SimpleProgress(),
           ' ', AdaptiveETA()]

class TelemetryService:
  def __init__(self):
    self.baseURL = "https://aggregates.telemetry.mozilla.org"

  def getVersions(self, channel):
    req = requests.get("{}/aggregates_by/submission_date/channels/{}/dates/".format(self.baseURL, channel))
    if req.status_code > 399:
      logging.debug("Failed to get version (status: {}) data: {}".format(req.status_code, req.text))
      return None
    return req.json()

  def getAggregates(self, measure, channel, dates, version):
    formatted_date_string = ",".join(dates)

    payload = {"version": version, "metric": measure, "dates": formatted_date_string }
    req = requests.get("{}/aggregates_by/submission_date/channels/{}".format(self.baseURL, channel), params=payload)
    if req.status_code > 399:
      logging.debug("Failed to get aggregate (status: {}) data: {}".format(req.status_code, req.text))
      return None
    return req.json()

class PageloadIsSSLPoint:
  def __init__(self):
    self.CountTLS = 0
    self.CountPageloads = 0

  def __repr__(self):
    percent = self.CountTLS / self.CountPageloads if self.CountPageloads > 0 else 0
    return "CountTLS: {} CountPageloads: {} Percentage: {:0.3f}".format(self.CountTLS, self.CountPageloads, percent)

# I/O
def main():
  args = parser.parse_args()
  if args.db is None:
    parser.print_usage()
    sys.exit(0)

  storage = statisticstorage.StatisticStorage(dbPath=args.db)
  stats = Counter()

  service = TelemetryService()

  versionList = service.getVersions("release")

  cutoff = datetime.now() - timedelta(days = args.window)
  recentVersions = list(filter(lambda item: datetime.strptime(item['date'], "%Y%m%d") > cutoff, versionList))

  # Convert a list of {date, version} tuples to a map of {version: [dates...]}
  versionMap = defaultdict(list)
  for item in recentVersions:
    versionMap[item['version']].append(item['date'])

  pbar = ProgressBar(widgets=widgets, max_value=len(versionMap))
  pbar.start()

  telemetryHistogramData = defaultdict(PageloadIsSSLPoint)

  for versionNumber, dateList in versionMap.items():
    data = service.getAggregates("HTTP_PAGELOAD_IS_SSL", "release", dateList, versionNumber)
    pbar.update(pbar.value + 1)

    if data is None:
      continue

    for entry in data['data']:
      datapoint = telemetryHistogramData[entry['date']]
      datapoint.CountTLS += entry['histogram'][1]
      datapoint.CountPageloads += entry['histogram'][0] + entry['histogram'][1]

  pbar.finish()

  for date, point in telemetryHistogramData.items():
    print("{}: {}".format(date, point))

  nowTime = datetime.now()
  for datestamp, point in telemetryHistogramData.items():
    formattedStamp = datetime.strptime(datestamp, "%Y%m%d").strftime("%Y-%m-%d")
    storage.updatePageloadTLS(datestamp=formattedStamp, countTLS=point.CountTLS,
                              countPageloads=point.CountPageloads, timeAdded=nowTime)


main()
