import os
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("in_pems", help="Set of PEMs")
parser.add_argument("--out_path", help="Path to folder on disk to store certs, or stdout if not set")
parser.add_argument("--idx", help="Index to retrieve, or none", type=int)


def splitPem(in_path, out_path=None, idx=None):
  """
  This method processes a PEM file which may contain one or more PEM-formatted
  certificates.
  """

  with open(in_path, 'r') as pem_fd:
    pem_buffer = ""
    buffer_len = 0
    offset = 0
    count = 0

    for line in pem_fd:
      # Record length always
      buffer_len += len(line)

      if line.startswith("Log") or line.startswith("Recorded-at") or len(line)<3:
        continue
      if line.startswith("Seen-in-log"):
        continue

      if idx is None or count == idx:
        # Just a normal part of the base64, so add it to the buffer
        pem_buffer += line

      if line == "-----END CERTIFICATE-----\n":
        # process the PEM
        if out_path is not None:
          try:
            outfile = os.path.join(out_path, "{}.pem".format(count))

            with open(outfile, 'w') as out_fd:
              out_fd.write(pem_buffer)

          except ValueError as e:
            print("{}:{}\t{}\n".format(path, offset, e))
        else:
          print(pem_buffer)

        # clear the buffer
        pem_buffer = ""
        offset += buffer_len
        buffer_len = 0
        count += 1

args = parser.parse_args()
splitPem(args.in_pems, idx=args.idx, out_path=args.out_path)
