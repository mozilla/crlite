import logging
import re
import time
from datetime import datetime, timedelta
from google.api_core import exceptions, page_iterator
from google.cloud import storage

kIdentifierFormat = re.compile(r"(\d{8}-\d+)/?")

log = logging.getLogger("workflow")


class FileNotFoundException(exceptions.NotFound):
    pass


def _item_to_value(iterator, item):
    return item


def list_google_storage_directories(bucket_name, *, prefix=None):
    extra_params = {"projection": "noAcl", "delimiter": "/"}

    if prefix is not None:
        if not prefix.endswith("/"):
            prefix += "/"
        extra_params["prefix"] = prefix

    gcs = storage.Client()

    path = "/b/" + bucket_name + "/o"

    iterator = page_iterator.HTTPIterator(
        client=gcs,
        api_request=gcs._connection.api_request,
        path=path,
        items_key="prefixes",
        item_to_value=_item_to_value,
        extra_params=extra_params,
    )

    return [x for x in iterator]


def normalize_identifier(s):
    """ The first part of the identifier is a date with no separators and is
        obvious to sort. The second part is a number which is generally a
        single digit, but in a degenerate case could end up with multiple, so
        we pad it here.
    """
    parts = s.rstrip("/").split("-")
    return f"{parts[0]}{int(parts[1]):06d}"


def get_run_identifiers(bucket_name):
    dirs = list_google_storage_directories(bucket_name)
    identifiers = filter(lambda x: kIdentifierFormat.match(x), dirs)
    identifiers = map(lambda x: kIdentifierFormat.match(x).group(1), identifiers)
    return sorted(identifiers, key=normalize_identifier)


def download_from_google_cloud(bucket_name, remote, local):
    gcs = storage.Client()
    bucket = gcs.get_bucket(bucket_name)

    blob = storage.blob.Blob(remote, bucket)
    if not blob.exists():
        raise FileNotFoundException(f"{remote} does not exist")
    with open(local, "wb") as file_obj:
        blob.download_to_file(file_obj)
        logging.info(f"Downloaded {blob.public_url} to {local}")


def download_and_retry_from_google_cloud(
    bucket_name, remote, local, *, timeout=timedelta(minutes=5)
):
    time_start = datetime.now()
    while True:
        try:
            return download_from_google_cloud(bucket_name, remote, local)
        except FileNotFoundException as fnfe:
            time_waiting = datetime.now() - time_start
            if time_waiting >= timeout:
                raise fnfe
            log.warning(
                f"File {remote} not found, retrying (wating={time_waiting}, "
                + f"deadline={timeout-time_waiting})"
            )
            time.sleep(30)
