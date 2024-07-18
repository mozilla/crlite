import main
import settings
import unittest
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path


def timestamp_from_run_id(run_id):
    parts = run_id.split("-")
    time_string = f"{parts[0]}-{int(parts[1])*6}"
    return datetime.strptime(time_string, "%Y%m%d-%H").replace(tzinfo=timezone.utc)


def make_record(run_id, *, parent, channel):
    timestamp = timestamp_from_run_id(run_id)
    record_type = "diff" if parent else "full"
    record_time = timestamp.isoformat(timespec="seconds")
    identifier = f"{record_time}Z-{record_type}"

    random_id = hashlib.sha256(run_id.encode("utf-8")).hexdigest()
    extension = "filter.stash" if parent else "filter"

    record = {
        "schema": 1,
        "details": {"name": identifier},
        "attachment": {
            "hash": "hash",
            "size": 0,
            "filename": f"{run_id}-{extension}",
            "location": "abc",
            "mimetype": "application/octet-stream",
        },
        "incremental": parent is not None,
        "id": random_id,
        "last_modified": 1,
        "channel": channel,
    }
    if parent:
        record["parent"] = hashlib.sha256(parent.encode("utf-8")).hexdigest()
    else:
        record["coverage"] = []
        record["enrolledIssuers"] = []
    return record


class MockRunDB(main.PublishedRunDB):
    def __init__(self, runs):
        self.run_identifiers = runs

    def get_run_timestamp(self, run_id):
        return timestamp_from_run_id(run_id)

    def is_run_valid(self, run_id, channel):
        return run_id in self.run_identifiers

    def is_run_ready(self, run_id):
        return True


class TestTimestampMethods(unittest.TestCase):
    def test_from_run_id(self):
        with self.assertRaises(ValueError):
            timestamp_from_run_id("20501240-1")

        with self.assertRaises(ValueError):
            timestamp_from_run_id("20500101-4")

        self.assertEqual(
            timestamp_from_run_id("20500101-3"),
            datetime(2050, 1, 1, 18, 0, 0, tzinfo=timezone.utc),
        )


class TestLoadIntermediates(unittest.TestCase):
    def test_load_local(self):
        intermediates_path = Path(__file__).parent / Path("example_enrolled.json")
        main.load_local_intermediates(intermediates_path=intermediates_path)

    def test_load_remote(self):
        ro_client = main.PublisherClient(
            server_url=settings.KINTO_RO_SERVER_URL,
            bucket=settings.KINTO_BUCKET,
            retry=5,
        )
        main.load_remote_intermediates(kinto_client=ro_client)


class TestPublishDecisions(unittest.TestCase):
    def test_consistency_okay(self):
        existing_records = [
            make_record("20491230-3", parent=None, channel="all"),
            make_record("20491231-0", parent="20491230-3", channel="all"),
            make_record("20491231-1", parent="20491231-0", channel="all"),
            make_record("20491231-2", parent="20491231-1", channel="all"),
            make_record("20491231-3", parent="20491231-2", channel="all"),
            make_record("20500101-0", parent="20491231-3", channel="all"),
        ]
        main.crlite_verify_record_consistency(
            existing_records=existing_records, channel="all"
        )

    def test_consistency_okay(self):
        existing_records = [
            make_record("20491230-3", parent=None, channel="all"),
            make_record("20491231-0", parent="20491230-3", channel="all"),
            make_record("20491231-1", parent="20491231-0", channel="all"),
            make_record("20491231-2", parent="20491231-1", channel="all"),
            make_record("20491231-3", parent="20491231-2", channel="all"),
            make_record("20500101-0", parent="20491231-3", channel="all"),
        ]
        main.crlite_verify_record_consistency(
            existing_records=existing_records, channel="all"
        )

    def test_consistency_multiple_channels(self):
        existing_records = [
            make_record("20491230-3", parent=None, channel="all"),
            make_record("20491231-0", parent="20491230-3", channel="all"),
            make_record("20491231-1", parent="20491231-0", channel="all"),
            make_record("20491231-2", parent=None, channel="specified"),
            make_record("20491231-3", parent="20491231-2", channel="specified"),
            make_record("20500101-0", parent="20491231-3", channel="specified"),
        ]
        main.crlite_verify_record_consistency(
            existing_records=existing_records, channel="specified"
        )

    def test_consistency_multiple_filters(self):
        existing_records = [
            make_record("20491230-3", parent=None, channel="all"),
            make_record("20491231-0", parent="20491230-3", channel="all"),
            make_record("20491231-1", parent="20491231-0", channel="all"),
            make_record("20491231-2", parent=None, channel="all"),
            make_record("20491231-3", parent="20491231-2", channel="all"),
            make_record("20500101-0", parent="20491231-3", channel="all"),
        ]
        with self.assertRaises(main.ConsistencyException):
            main.crlite_verify_record_consistency(
                existing_records=existing_records, channel="all"
            )

    def test_consistency_not_sequential(self):
        existing_records = [
            make_record("20491230-3", parent=None, channel="all"),
            make_record("20491231-0", parent="20491230-3", channel="all"),
            make_record("20491231-1", parent="20491231-0", channel="all"),
            make_record("20491231-3", parent="20491231-1", channel="all"),
            make_record("20500101-0", parent="20491231-3", channel="all"),
        ]
        with self.assertRaises(main.ConsistencyException):
            main.crlite_verify_record_consistency(
                existing_records=existing_records, channel="all"
            )

    def test_consistency_out_of_order(self):
        existing_records = [
            make_record("20491230-3", parent=None, channel="all"),
            make_record("20491231-1", parent="20491231-0", channel="all"),
            make_record("20491231-0", parent="20491230-3", channel="all"),
        ]
        with self.assertRaises(main.ConsistencyException):
            main.crlite_verify_record_consistency(
                existing_records=existing_records, channel="all"
            )

    def test_consistency_unknown_parent(self):
        existing_records = [
            make_record("20491230-3", parent=None, channel="all"),
            make_record("20491231-0", parent="20491230-2", channel="all"),
            make_record("20491231-1", parent="20491231-0", channel="all"),
        ]
        with self.assertRaises(main.ConsistencyException):
            main.crlite_verify_record_consistency(
                existing_records=existing_records, channel="all"
            )

    def test_consistency_nonlinear(self):
        existing_records = [
            make_record("20491230-3", parent=None, channel="all"),
            make_record("20491231-0", parent="20491230-3", channel="all"),
            make_record("20491231-1", parent="20491230-3", channel="all"),
        ]
        with self.assertRaises(main.ConsistencyException):
            main.crlite_verify_record_consistency(
                existing_records=existing_records, channel="all"
            )

    def test_run_id_consistency_not_sequential(self):
        with self.assertRaises(main.ConsistencyException):
            db = MockRunDB([])
            main.crlite_verify_run_id_consistency(
                run_db=db,
                identifiers_to_check=[
                    "20491230-3",
                    "20491231-0",
                    "20491231-1",
                    "20491231-3",
                    "20500101-0",
                ],
                channel="all",
            )

    def test_run_id_consistency_out_of_order(self):
        with self.assertRaises(main.ConsistencyException):
            db = MockRunDB([])
            main.crlite_verify_run_id_consistency(
                run_db=db,
                identifiers_to_check=["20491230-3", "20491231-1", "20491231-0"],
                channel="all",
            )

    def test_run_id_consistency_okay(self):
        identifiers = [
            "20491230-3",
            "20491231-0",
            "20491231-1",
            "20491231-2",
            "20491231-3",
            "20500101-0",
        ]
        db = MockRunDB(identifiers)
        main.crlite_verify_run_id_consistency(
            run_db=db, identifiers_to_check=identifiers, channel="all"
        )

    def test_run_id_consistency_empty(self):
        db = MockRunDB([])
        main.crlite_verify_run_id_consistency(
            run_db=db, identifiers_to_check=[], channel="all"
        )

    def test_initial_conditions(self):
        existing_records = []
        db = MockRunDB(["20500101-1"])
        result = main.crlite_determine_publish(
            existing_records=existing_records, run_db=db, channel="all"
        )
        self.assertEqual(result, {"clear_all": True, "upload": ["20500101-1"]})

    def test_no_overlap(self):
        existing_records = [
            make_record("20491231-2", parent=None, channel="all"),
            make_record("20491231-3", parent="20491231-2", channel="all"),
        ]
        db = MockRunDB(["20500101-0"])
        result = main.crlite_determine_publish(
            existing_records=existing_records, run_db=db, channel="all"
        )
        self.assertEqual(result, {"clear_all": True, "upload": ["20500101-0"]})

    def test_continue_with_single_stash(self):
        existing_records = [
            make_record("20491231-2", parent=None, channel="all"),
            make_record("20491231-3", parent="20491231-2", channel="all"),
        ]
        db = MockRunDB(["20491231-2", "20491231-3", "20500101-0"])
        result = main.crlite_determine_publish(
            existing_records=existing_records, run_db=db, channel="all"
        )
        self.assertEqual(result, {"clear_all": False, "upload": ["20500101-0"]})

    def test_continue_with_four_stashes(self):
        existing_records = [
            make_record("20491231-0", parent=None, channel="all"),
            make_record("20491231-1", parent="20491231-0", channel="all"),
            make_record("20491231-2", parent="20491231-1", channel="all"),
            make_record("20491231-3", parent="20491231-2", channel="all"),
        ]
        db = MockRunDB(
            [
                "20491231-0",
                "20491231-1",
                "20491231-2",
                "20491231-3",
                "20500101-0",
                "20500101-1",
                "20500101-2",
                "20500101-3",
            ]
        )
        result = main.crlite_determine_publish(
            existing_records=existing_records, run_db=db, channel="all"
        )
        self.assertEqual(
            result,
            {
                "clear_all": False,
                "upload": ["20500101-0", "20500101-1", "20500101-2", "20500101-3"],
            },
        )

    def test_up_to_date_single_entry(self):
        existing_records = [
            make_record("20491231-3", parent=None, channel="all"),
        ]
        db = MockRunDB(
            [
                "20491230-1",
                "20491230-2",
                "20491230-3",
                "20491231-0",
                "20491231-1",
                "20491231-2",
                "20491231-3",
            ]
        )
        result = main.crlite_determine_publish(
            existing_records=existing_records, run_db=db, channel="all"
        )
        self.assertEqual(result, {"clear_all": False, "upload": []})

    def test_up_to_date(self):
        existing_records = [
            make_record("20491231-0", parent=None, channel="all"),
            make_record("20491231-1", parent="20491231-0", channel="all"),
            make_record("20491231-2", parent="20491231-1", channel="all"),
            make_record("20491231-3", parent="20491231-2", channel="all"),
        ]
        db = MockRunDB(
            [
                "20491230-1",
                "20491230-2",
                "20491230-3",
                "20491231-0",
                "20491231-1",
                "20491231-2",
                "20491231-3",
            ]
        )
        result = main.crlite_determine_publish(
            existing_records=existing_records, run_db=db, channel="all"
        )
        self.assertEqual(result, {"clear_all": False, "upload": []})

    def test_rundb_data_loss(self):
        existing_records = [
            make_record("20491231-0", parent=None, channel="all"),
            make_record("20491231-1", parent="20491231-0", channel="all"),
            make_record("20491231-2", parent="20491231-1", channel="all"),
        ]
        db = MockRunDB(
            [
                "20491231-1",
                "20491231-2",
            ]
        )
        result = main.crlite_determine_publish(
            existing_records=existing_records, run_db=db, channel="all"
        )
        self.assertEqual(result, {"clear_all": True, "upload": ["20491231-2"]})

    def test_ten_day_old_full_filter(self):
        ids = []
        for i in [10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0]:
            date = (datetime.now() - timedelta(days=i)).strftime("%Y%m%d")
            for j in [0, 1, 2, 3]:
                ids += [f"{date}-{j}"]
        existing_records = [make_record(ids[0], parent=None, channel="all")]
        for i in range(1, len(ids)):
            existing_records += [make_record(ids[i], parent=ids[i - 1], channel="all")]
        db = MockRunDB(ids)
        result = main.crlite_determine_publish(
            existing_records=existing_records, run_db=db, channel="all"
        )
        self.assertEqual(result, {"clear_all": True, "upload": [ids[-1]]})

    def test_nine_day_old_full_filter(self):
        ids = []
        for i in [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]:
            date = (datetime.now() - timedelta(days=i)).strftime("%Y%m%d")
            for j in [0, 1, 2, 3]:
                ids += [f"{date}-{j}"]
        existing_records = [make_record(ids[0], parent=None, channel="all")]
        for i in range(1, len(ids)):
            existing_records += [make_record(ids[i], parent=ids[i - 1], channel="all")]
        db = MockRunDB(ids)
        result = main.crlite_determine_publish(
            existing_records=existing_records, run_db=db, channel="all"
        )
        self.assertEqual(result, {"clear_all": False, "upload": []})
