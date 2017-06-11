#!/usr/local/bin/python3

from datetime import datetime
from progressbar import Bar, SimpleProgress, AdaptiveETA, Percentage, ProgressBar
import argparse
import os
import shutil
import sys
import time

parser = argparse.ArgumentParser()
parser.add_argument("--path", help="Path to folder on disk to store certs")
parser.add_argument("--noop", "-n", help="Don't actually delete, just print", action="store_true")
parser.add_argument("--today", help="Today's date YYYY-MM-DD")

# Progress Bar configuration
widgets = [Percentage(),
           ' ', Bar(),
           ' ', SimpleProgress(),
           ' ', AdaptiveETA()]

def main():
  args = parser.parse_args()

  if not args.path:
    parser.print_usage()
    sys.exit(0)

  dirlist = os.listdir(args.path)

  if args.noop:
    print("No-op mode, not deleting anything...")

  pbar = ProgressBar(widgets=widgets, max_value=len(dirlist), redirect_stdout=True)
  pbar.start()

  for idx, item in enumerate(dirlist):
    pbar.update(idx)

    # Skip the "state" folder
    if item == "state":
      continue

    entry = os.path.join(args.path, item)
    if not os.path.isdir(entry):
      # Not a folder, keep going
      continue

    # Is this expired (check by looking the path so we don't have to continue
    # to load)
    pathdate = datetime.strptime(item, "%Y-%m-%d").timetuple()
    now = time.gmtime()
    if args.today:
      now = datetime.strptime(args.today, "%Y-%m-%d").timetuple()

    if (pathdate.tm_year < now.tm_year) or (pathdate.tm_year == now.tm_year and pathdate.tm_yday < now.tm_yday):
      print("Deleting: {}".format(entry))
      if not args.noop:
        shutil.rmtree(entry)

  pbar.finish()
  print("All done.")

if __name__ == "__main__":
  main()
