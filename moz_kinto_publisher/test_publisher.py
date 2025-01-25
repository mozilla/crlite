import main
import settings
import unittest
import hashlib
import os
import pytest
import shutil
import workflow
from datetime import datetime, timedelta, timezone
from pathlib import Path

DEFAULT_CHANNEL = [x for x in main.CHANNELS if x.slug == main.CHANNEL_ALL][0]


def date(time):
    return datetime.strftime(time, "%Y%m%d")


class MockRunDB(main.PublishedRunDB):
    def __init__(self):
        self.time = datetime.now()
        self.run_ctr = 0
        os.mkdir(Path("db"))
        main.PublishedRunDB.__init__(self, workflow.kTestBucket + ":" + str(Path()))

    def next_run_id(self, delta=timedelta(hours=6)):
        # reset the run counter when the clock rolls over
        if date(self.time) != date(self.time + delta):
            self.run_ctr = 0
        self.time += delta
        run_id = date(self.time) + "-" + str(self.run_ctr)
        self.run_ctr += 1
        return run_id

    def add_run(
        self, *, completed=True, delta=timedelta(hours=6), filter_size=0, stash_size=0
    ):
        run_id = self.next_run_id(delta)
        rundir = Path("db") / run_id
        os.mkdir(rundir)
        (rundir / "ct-logs.json").write_text("{}")  # must be JSON
        (rundir / "enrolled.json").write_text("{}")  # must be JSON
        (rundir / "timestamp").write_text(
            self.time.isoformat(timespec="seconds"),
            encoding="utf-8",
        )
        for channel in main.CHANNELS:
            if (rundir / channel.dir).exists():
                # multiple channels can share the same mlbf_dir if one
                # uses stashes and one uses deltas.
                continue
            os.mkdir(rundir / channel.dir)
            (rundir / channel.dir / "filter").write_bytes(b"\x00" * filter_size)
            (rundir / channel.dir / "filter.stash").write_bytes(b"\x00" * stash_size)
            (rundir / channel.dir / "filter.delta").write_bytes(b"\x00" * stash_size)
        if completed:
            (rundir / "completed").touch()
        self.run_identifiers += [run_id]
        return run_id

    def complete_run(self, run_id):
        rundir = Path("db") / run_id
        (rundir / "completed").touch()

    def clear_runs(self):
        shutil.rmtree(Path("db"))
        os.mkdir(Path("db"))
        self.run_identifiers = []


class MockClient:
    def __init__(self):
        self.existing_records = []

    def attach_file(
        self,
        *args,
        **kwargs,
    ):
        for record in self.existing_records:
            if record["id"] == kwargs["recordId"]:
                record["attachment"] = {
                    "hash": hashlib.sha256(
                        Path(kwargs["filePath"]).read_bytes()
                    ).hexdigest(),
                    "size": Path(kwargs["filePath"]).stat().st_size,
                    "filename": kwargs["fileName"],
                    "location": kwargs["filePath"],
                    "mimetype": "application/octet-stream",
                }
                break

    def create_record(self, *args, **kwargs):
        record = kwargs["data"]
        record["id"] = hashlib.sha256(
            record["channel"].encode("utf-8")
            + record["details"]["name"].encode("utf-8")
        ).hexdigest()
        self.existing_records += [record]
        return {"data": record}

    def delete_record(self, *args, **kwargs):
        self.existing_records[:] = [
            x for x in self.existing_records if x["id"] != kwargs["id"]
        ]

    def get_records(self, *args, **kwargs):
        return self.existing_records

    def get_run_ids(self, *, channel=DEFAULT_CHANNEL):
        return [
            x["attachment"]["filename"].rsplit("-", 1)[0]
            for x in self.existing_records
            if x["channel"] == channel.slug
        ]

    def request_review_of_collection(self, *args, **kwargs):
        pass

    def update_record(self, *args, **kwargs):
        raise

    def publish(self, *, channel=DEFAULT_CHANNEL, timeout=timedelta(seconds=0)):
        return main.publish_crlite(
            args=Args(),
            channel=channel,
            rw_client=self,
            timeout=timeout,
        )


class TestLoadIntermediates(unittest.TestCase):
    def test_load_local(self):
        intermediates_path = Path(__file__).parent / Path("example_enrolled.json")
        intermediates = main.load_local_intermediates(
            intermediates_path=intermediates_path
        )
        self.assertEqual(len(intermediates), 1707)

    def test_load_remote(self):
        ro_client = main.PublisherClient(
            server_url=settings.KINTO_RO_SERVER_URL,
            bucket=settings.KINTO_BUCKET,
            retry=5,
        )
        (intermediates, errors) = main.load_remote_intermediates(kinto_client=ro_client)
        self.assertEqual(len(errors), 0)


class Args:
    def __init__(self):
        self.noop = False
        self.download_path = Path()
        self.filter_bucket = workflow.kTestBucket + ":" + str(Path())


class TestPublishDecisions(unittest.TestCase):
    # Create a new temporary directory and cd into it for each test.
    @pytest.fixture(autouse=True)
    def initdir(self, tmpdir, monkeypatch):
        monkeypatch.chdir(tmpdir)

    def test_record_consistency_unique_filter(self):
        # the list of published records should contain exactly one full filter
        rw_client = MockClient()
        db = MockRunDB()
        db_run_ids = [db.add_run()]
        self.assertEqual(db_run_ids[0], rw_client.publish())
        # duplicate the filter record
        rw_client.existing_records += rw_client.existing_records
        with self.assertRaisesRegex(main.ConsistencyException, "Multiple full filters"):
            main.crlite_verify_record_consistency(
                existing_records=rw_client.get_records(), channel=DEFAULT_CHANNEL
            )

    def test_record_consistency_unique_history(self):
        # no record should have more than one descendent
        rw_client = MockClient()
        db = MockRunDB()
        for _ in range(3):
            db.add_run()
            rw_client.publish()
        rw_client.existing_records[2]["parent"] = rw_client.existing_records[1][
            "parent"
        ]
        with self.assertRaisesRegex(
            main.ConsistencyException, "Multiple filter descendents"
        ):
            main.crlite_verify_record_consistency(
                existing_records=rw_client.get_records(), channel=DEFAULT_CHANNEL
            )

    def test_record_consistency_unknown_parent(self):
        # the parent field of a stash record should point to a known record
        rw_client = MockClient()
        db = MockRunDB()
        for _ in range(3):
            db.add_run()
            rw_client.publish()
        rw_client.existing_records[2]["parent"] = "unknown"
        with self.assertRaisesRegex(main.ConsistencyException, "unknown parent"):
            main.crlite_verify_record_consistency(
                existing_records=rw_client.get_records(), channel=DEFAULT_CHANNEL
            )

    def test_record_consistency_self_reference(self):
        # the "parent" entry for a stash record should not point to itself
        rw_client = MockClient()
        db = MockRunDB()
        for _ in range(3):
            db.add_run()
            rw_client.publish()
        rw_client.existing_records[1]["parent"] = rw_client.existing_records[1]["id"]
        with self.assertRaisesRegex(main.ConsistencyException, "cycle"):
            main.crlite_verify_record_consistency(
                existing_records=rw_client.get_records(), channel=DEFAULT_CHANNEL
            )

    def test_run_db_consistency_out_of_order_timestamps(self):
        # timestamps should increase monotonically with run db identifiers
        db = MockRunDB()
        db_run_ids = [db.add_run() for _ in range(3)]
        r1_path = Path("db") / db_run_ids[1] / "timestamp"
        r2_path = Path("db") / db_run_ids[2] / "timestamp"
        r1_data = r1_path.read_bytes()
        r2_data = r2_path.read_bytes()
        r1_path.write_bytes(r2_data)
        r2_path.write_bytes(r1_data)
        with self.assertRaisesRegex(main.ConsistencyException, "Out-of-order"):
            main.crlite_verify_run_id_consistency(
                run_db=db,
                identifiers_to_check=db_run_ids,
                channel=DEFAULT_CHANNEL,
            )

    def test_publish(self):
        # normal operation
        rw_client = MockClient()
        db = MockRunDB()
        # add full filter
        db_run_ids = [db.add_run()]
        self.assertEqual(db_run_ids[0], rw_client.publish())
        self.assertEqual(db_run_ids, rw_client.get_run_ids())
        # add stash
        db_run_ids += [db.add_run()]
        self.assertEqual(None, rw_client.publish())
        self.assertEqual(db_run_ids, rw_client.get_run_ids())
        # add stash
        db_run_ids += [db.add_run()]
        self.assertEqual(None, rw_client.publish())
        self.assertEqual(db_run_ids, rw_client.get_run_ids())

    def test_publish_channels(self):
        # normal operation with multiple channels
        rw_client = MockClient()
        db = MockRunDB()
        # add full filter
        db_run_ids = [db.add_run()]
        for channel in main.CHANNELS:
            self.assertEqual(db_run_ids[0], rw_client.publish(channel=channel))
            self.assertEqual(db_run_ids, rw_client.get_run_ids(channel=channel))
        # add stash
        db_run_ids += [db.add_run()]
        for channel in main.CHANNELS:
            self.assertEqual(None, rw_client.publish(channel=channel))
            self.assertEqual(db_run_ids, rw_client.get_run_ids(channel=channel))
        self.assertEqual(2 * len(main.CHANNELS), len(rw_client.get_records()))

    def test_publish_channels_with_error(self):
        # test that a consistency error while publishing one channel does not affect the others
        rw_client = MockClient()
        db = MockRunDB()
        # add full filter
        db_run_ids = [db.add_run()]
        for channel in main.CHANNELS:
            self.assertEqual(db_run_ids[0], rw_client.publish(channel=channel))
            self.assertEqual(db_run_ids, rw_client.get_run_ids(channel=channel))
        # add stash
        db_run_ids += [db.add_run()]
        for channel in main.CHANNELS:
            self.assertEqual(None, rw_client.publish(channel=channel))
            self.assertEqual(db_run_ids, rw_client.get_run_ids(channel=channel))
        # delete the filter record on one channel
        rw_client.existing_records[:] = [
            x
            for x in rw_client.existing_records
            if not (x["channel"] == DEFAULT_CHANNEL.slug and x["incremental"] == False)
        ]
        # the error should be detected and a new full filter should be published
        self.assertEqual(db_run_ids[-1], rw_client.publish(channel=DEFAULT_CHANNEL))
        self.assertEqual(
            [db_run_ids[-1]], rw_client.get_run_ids(channel=DEFAULT_CHANNEL)
        )
        # the other channels are not touched
        for channel in main.CHANNELS:
            if channel == DEFAULT_CHANNEL:
                continue
            self.assertEqual(db_run_ids, rw_client.get_run_ids(channel=channel))

    def test_publish_no_runs(self):
        # An empty run db is not an error
        rw_client = MockClient()
        db = MockRunDB()
        self.assertEqual(None, rw_client.publish())
        self.assertEqual([], rw_client.get_run_ids())

    def test_publish_not_completed(self):
        # runs are only published once the "completed" flag is set
        rw_client = MockClient()
        db = MockRunDB()
        db_run_ids = [db.add_run(completed=False)]
        self.assertEqual(None, rw_client.publish())
        self.assertEqual([], rw_client.get_run_ids())
        db.complete_run(db_run_ids[0])
        self.assertEqual(db_run_ids[0], rw_client.publish())
        self.assertEqual(db_run_ids, rw_client.get_run_ids())

    def test_publish_up_to_date(self):
        # normal operation with more publish jobs than runs
        rw_client = MockClient()
        db = MockRunDB()
        # add full filter
        db_run_ids = [db.add_run()]
        self.assertEqual(db_run_ids[0], rw_client.publish())
        self.assertEqual(db_run_ids, rw_client.get_run_ids())
        # running publisher again without a new run should noop
        self.assertEqual(None, rw_client.publish())
        self.assertEqual(db_run_ids, rw_client.get_run_ids())
        # add stash
        db_run_ids += [db.add_run()]
        self.assertEqual(None, rw_client.publish())
        self.assertEqual(db_run_ids, rw_client.get_run_ids())
        # running publisher again without a new run should noop
        self.assertEqual(None, rw_client.publish())
        self.assertEqual(db_run_ids, rw_client.get_run_ids())

    def test_publish_latest_run(self):
        # normal operation with multiple filters produced before publishing
        rw_client = MockClient()
        db = MockRunDB()
        # add runs but don't publish them
        db_run_ids = [db.add_run() for i in range(4)]
        # only the latest run should be published as a full filter
        self.assertEqual(db_run_ids[-1], rw_client.publish())
        self.assertEqual([db_run_ids[-1]], rw_client.get_run_ids())

    def test_publish_multiple_stashes(self):
        # normal operation with multiple stashes produced before publishing
        rw_client = MockClient()
        db = MockRunDB()
        # publish a full filter
        db_run_ids = [db.add_run()]
        self.assertEqual(db_run_ids[0], rw_client.publish())
        # add runs but don't publish them
        for i in range(4):
            db_run_ids += [db.add_run()]
        # The client should publish all of the stashes at once
        self.assertEqual(None, rw_client.publish())
        self.assertEqual(db_run_ids, rw_client.get_run_ids())

    def test_publish_delayed_run(self):
        rw_client = MockClient()
        db = MockRunDB()
        db_run_ids = [db.add_run()]
        self.assertEqual(db_run_ids[0], rw_client.publish())
        self.assertEqual(db_run_ids, rw_client.get_run_ids())
        # add a stash from a run that was delayed
        db_run_ids += [db.add_run(delta=timedelta(hours=12))]
        self.assertEqual(None, rw_client.publish())
        self.assertEqual(db_run_ids, rw_client.get_run_ids())
        # the next consistency check will fail, and a full filter will be published
        db_run_ids += [db.add_run()]
        self.assertEqual(db_run_ids[2], rw_client.publish())
        self.assertEqual([db_run_ids[2]], rw_client.get_run_ids())

    def test_publish_ten_day_old_filter(self):
        # a new filter should be published every 10 days
        rw_client = MockClient()
        db = MockRunDB()
        run_id = db.add_run()
        start = db.time
        self.assertEqual(run_id, rw_client.publish())
        while db.time - start + timedelta(hours=6) < timedelta(days=10):
            db.add_run()
            self.assertEqual(None, rw_client.publish())
        # A new filter should be published after 10 days
        run_id = db.add_run(delta=timedelta(hours=6))
        self.assertEqual(run_id, rw_client.publish())
        self.assertEqual([run_id], rw_client.get_run_ids())

    def test_publish_data_loss(self):
        # a new filter should be published if we lose the run db
        rw_client = MockClient()
        db = MockRunDB()
        db_run_ids = [db.add_run()]
        self.assertEqual(db_run_ids[0], rw_client.publish())
        db_run_ids += [db.add_run()]
        self.assertEqual(None, rw_client.publish())
        db_run_ids += [db.add_run()]
        self.assertEqual(None, rw_client.publish())
        # simulate loss of the run database
        db.clear_runs()
        # We'll publish a full filter instead of another stash
        db_run_ids += [db.add_run()]
        self.assertEqual(db_run_ids[-1], rw_client.publish())
        self.assertEqual([db_run_ids[-1]], rw_client.get_run_ids())
