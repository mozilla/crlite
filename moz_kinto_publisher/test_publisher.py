import main
import unittest
import hashlib
from datetime import datetime, timezone


def make_record(run_id, *, parent):
    timestamp = main.timestamp_from_run_id(run_id)
    record_type = "diff" if parent else "full"
    record_time = timestamp.isoformat(timespec="seconds")
    identifier = f"{record_time}Z-{record_type}"

    random_id = hashlib.sha256(run_id.encode("utf-8")).hexdigest()

    record = {
        "schema": 1,
        "details": {"name": identifier},
        "attachment": {
            "hash": "hash",
            "size": 0,
            "filename": f"{run_id}",
            "location": "abc",
            "mimetype": "application/octet-stream",
        },
        "incremental": parent is not None,
        "id": random_id,
        "last_modified": 1,
    }
    if parent:
        record["parent"] = hashlib.sha256(parent.encode("utf-8")).hexdigest()
    return record


class MockRunDB(main.PublishedRunDB):
    def __init__(self, runs):
        self.run_identifiers = runs

    def get_timestamp_for_run_id(self, run_id):
        return main.timestamp_from_run_id(run_id)

    def is_run_valid(self, run_id):
        return run_id in self.run_identifiers


class TestTimestampMethods(unittest.TestCase):
    def test_from_run_id(self):
        with self.assertRaises(ValueError):
            main.timestamp_from_run_id("20501240-1")

        with self.assertRaises(ValueError):
            main.timestamp_from_run_id("20500101-4")

        self.assertEqual(
            main.timestamp_from_run_id("20500101-3"),
            datetime(2050, 1, 1, 18, 0, 0, tzinfo=timezone.utc),
        )


class TestPublishDecisions(unittest.TestCase):
    def test_sanity_okay(self):
        existing_records = [
            make_record("20491230-3", parent=None),
            make_record("20491231-0", parent="20491230-3"),
            make_record("20491231-1", parent="20491231-0"),
            make_record("20491231-2", parent="20491231-1"),
            make_record("20491231-3", parent="20491231-2"),
            make_record("20500101-0", parent="20491231-3"),
        ]
        main.crlite_verify_record_sanity(existing_records=existing_records)

    def test_sanity_multiple_filters(self):
        existing_records = [
            make_record("20491230-3", parent=None),
            make_record("20491231-0", parent="20491230-3"),
            make_record("20491231-1", parent="20491231-0"),
            make_record("20491231-2", parent=None),
            make_record("20491231-3", parent="20491231-2"),
            make_record("20500101-0", parent="20491231-3"),
        ]
        with self.assertRaises(main.SanityException):
            main.crlite_verify_record_sanity(existing_records=existing_records)

    def test_sanity_not_sequential(self):
        existing_records = [
            make_record("20491230-3", parent=None),
            make_record("20491231-0", parent="20491230-3"),
            make_record("20491231-1", parent="20491231-0"),
            make_record("20491231-3", parent="20491231-1"),
            make_record("20500101-0", parent="20491231-3"),
        ]
        with self.assertRaises(main.SanityException):
            main.crlite_verify_record_sanity(existing_records=existing_records)

    def test_sanity_out_of_order(self):
        existing_records = [
            make_record("20491230-3", parent=None),
            make_record("20491231-1", parent="20491231-0"),
            make_record("20491231-0", parent="20491230-3"),
        ]
        with self.assertRaises(main.SanityException):
            main.crlite_verify_record_sanity(existing_records=existing_records)

    def test_sanity_unknown_parent(self):
        existing_records = [
            make_record("20491230-3", parent=None),
            make_record("20491231-0", parent="20491230-2"),
            make_record("20491231-1", parent="20491231-0"),
        ]
        with self.assertRaises(main.SanityException):
            main.crlite_verify_record_sanity(existing_records=existing_records)

    def test_run_id_sanity_not_sequential(self):
        with self.assertRaises(main.SanityException):
            db = MockRunDB([])
            main.crlite_verify_run_id_sanity(
                run_db=db,
                identifiers_to_check=[
                    "20491230-3",
                    "20491231-0",
                    "20491231-1",
                    "20491231-3",
                    "20500101-0",
                ],
            )

    def test_run_id_sanity_out_of_order(self):
        with self.assertRaises(main.SanityException):
            db = MockRunDB([])
            main.crlite_verify_run_id_sanity(
                run_db=db,
                identifiers_to_check=["20491230-3", "20491231-1", "20491231-0"],
            )

    def test_run_id_sanity_okay(self):
        identifiers = [
            "20491230-3",
            "20491231-0",
            "20491231-1",
            "20491231-2",
            "20491231-3",
            "20500101-0",
        ]
        db = MockRunDB(identifiers)
        main.crlite_verify_run_id_sanity(
            run_db=db,
            identifiers_to_check=identifiers,
        )

    def test_run_id_sanity_empty(self):
        db = MockRunDB([])
        main.crlite_verify_run_id_sanity(run_db=db, identifiers_to_check=[])

    def test_initial_conditions(self):
        existing_records = []
        db = MockRunDB(["20500101-1"])
        result = main.crlite_determine_publish(
            existing_records=existing_records, run_db=db
        )
        self.assertEqual(result, {"clear_all": True, "upload": ["20500101-1"]})

    def test_no_overlap(self):
        existing_records = [
            make_record("20491231-2", parent=None),
            make_record("20491231-3", parent="20491231-2"),
        ]
        db = MockRunDB(["20500101-0"])
        result = main.crlite_determine_publish(
            existing_records=existing_records, run_db=db
        )
        self.assertEqual(result, {"clear_all": True, "upload": ["20500101-0"]})

    def test_continue_with_single_stash(self):
        existing_records = [
            make_record("20491231-2", parent=None),
            make_record("20491231-3", parent="20491231-2"),
        ]
        db = MockRunDB(["20491231-3", "20500101-0"])
        result = main.crlite_determine_publish(
            existing_records=existing_records, run_db=db
        )
        self.assertEqual(result, {"upload": ["20500101-0"]})

    def test_continue_with_four_stashes(self):
        existing_records = [
            make_record("20491231-0", parent=None),
            make_record("20491231-1", parent="20491231-0"),
            make_record("20491231-2", parent="20491231-1"),
            make_record("20491231-3", parent="20491231-2"),
        ]
        db = MockRunDB(
            ["20491231-3", "20500101-0", "20500101-1", "20500101-2", "20500101-3"]
        )
        result = main.crlite_determine_publish(
            existing_records=existing_records, run_db=db
        )
        self.assertEqual(
            result, {"upload": ["20500101-0", "20500101-1", "20500101-2", "20500101-3"]}
        )

    def test_up_to_date_single_entry(self):
        existing_records = [
            make_record("20491231-3", parent=None),
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
            existing_records=existing_records, run_db=db
        )
        self.assertEqual(result, {"upload": []})

    def test_up_to_date(self):
        existing_records = [
            make_record("20491231-0", parent=None),
            make_record("20491231-1", parent="20491231-0"),
            make_record("20491231-2", parent="20491231-1"),
            make_record("20491231-3", parent="20491231-2"),
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
            existing_records=existing_records, run_db=db
        )
        self.assertEqual(result, {"upload": []})
