#!/usr/bin/env python3
# MongoDB insert_many probe for the audit collector pipeline.
#
# Modes:
#   INFO=1   : print audit_events index list + stats (avgObjSize, count), then exit.
#   SAMPLE=1 : pull DOCS real docs from audit_events and replay insert_many of THOSE
#              exact docs (real shape/size) into bench_tmp. Best reproduction.
#   default  : synthetic 400B docs.
#
# Baseline / contention knobs: THREADS (concurrent writers), INDEX (0/1 unique index).
#
# Examples (run on 139 or 145):
#   INFO=1 python3 bench_insert.py
#   SAMPLE=1 THREADS=2 INDEX=1 python3 bench_insert.py
#   URI='mongodb://audit_collector:1@127.0.0.1:27017/ob_audit?authSource=ob_audit' INFO=1 python3 bench_insert.py

import os
import threading
import time

from pymongo import ASCENDING, MongoClient, WriteConcern

URI = os.environ.get(
    "URI",
    "mongodb://audit_collector:1@7.27.43.145:27017/ob_audit?authSource=ob_audit",
)
DB = os.environ.get("DB", "ob_audit")
SRC = os.environ.get("SRC", "audit_events")
DOCS = int(os.environ.get("DOCS", "542"))
ROUNDS = int(os.environ.get("ROUNDS", "20"))
PAD = int(os.environ.get("PAD", "400"))
THREADS = int(os.environ.get("THREADS", "1"))
INDEX = os.environ.get("INDEX", "0") == "1"
INFO = os.environ.get("INFO", "0") == "1"
SAMPLE = os.environ.get("SAMPLE", "0") == "1"
MOCK = os.environ.get("MOCK", "0") == "1"
SQLLEN = int(os.environ.get("SQLLEN", "100"))

COLL = "bench_tmp"


def mock_doc(base, i):
    # Mirror the compact append_event_doc(): numeric string keys assigned by the
    # external schema (audit_schema.json v2, perf fields excluded) plus the `sv`
    # schema-version marker. Redundant fields (*_raw, payload *_len,
    # trans_status_name, event/request_server_ip) are dropped so the BSON size
    # matches the collector's real docs (~400-460B each).
    d = {
        "sv": 2,
        "0": 0, "1": 1, "2": 0,
        "3": base + i, "4": 0, "5": 0,
        "6": 200001, "7": 1, "8": 1,
        "9": 3221487, "10": 0, "11": 500001,
        "12": 1, "13": 10, "14": 1234567890123,
        "15": base + i, "16": 1723000000000000,
        "17": 523, "18": 410,
        "19": SQLLEN, "20": 0,
        "21": 12345, "22": 12346, "23": 0,
        "24": 2, "25": "SELECT",
        "26": 1, "27": "LOCAL",
        "28": 0, "29": "INIT",
        "30": 0, "31": 0,
        "32": "7.27.43.100", "33": "7.27.43.100", "34": "7.27.43.100",
        "35": "A1B2C3D4E5F60718293A4B5C6D7E8F90",
        "36": "YB420A1B2C3D-0006123456789ABC-0-0",
        "37": "sbtest_u", "38": "", "39": "obt", "40": "test",
        "41": "x" * SQLLEN, "42": "",
        "43": "agent-ob1-7.27.43.136",
        "44": base + i, "45": 426, "46": (base + i) * 512,
    }
    return d


def print_info(client):
    db = client[DB]
    src = db[SRC]
    try:
        stats = db.command("collStats", SRC)
        print(
            f"[{SRC}] count={stats.get('count')} "
            f"avgObjSize={stats.get('avgObjSize')}B "
            f"size={stats.get('size')}B nindexes={stats.get('nindexes')}"
        )
        idx_sizes = stats.get("indexSizes", {})
        for name, spec in src.index_information().items():
            key = spec.get("key")
            uniq = spec.get("unique", False)
            print(f"    index {name}: key={key} unique={uniq} size={idx_sizes.get(name)}B")
    except Exception as exc:  # noqa: BLE001
        print(f"collStats/index_information failed: {exc}")


def synth_docs(n, base):
    pad = "x" * PAD
    # keys: 7=tenant_id, 34=server_ip, 3=event_seq (per audit_schema.json)
    return [
        {"7": 1, "34": "7.27.43.100", "3": base + i, "pad": pad}
        for i in range(n)
    ]


def load_real_docs(client):
    src = client[DB][SRC]
    docs = list(src.find({}, limit=DOCS))
    for d in docs:
        d.pop("_id", None)
    if not docs:
        raise SystemExit(f"no docs in {DB}.{SRC} to sample; run a test first")
    return docs


def make_batch(template, tid, r):
    # rewrite the unique-key fields so replayed docs never collide
    base = (tid * 100 + r + 1) * 1_000_000
    out = []
    for i, d in enumerate(template):
        doc = dict(d)
        doc["7"] = 1
        doc["34"] = "7.27.43.100"
        doc["3"] = base + i
        out.append(doc)
    return out


def gen_batch(template, tid, r):
    base = (tid * 100 + r + 1) * 1_000_000
    if MOCK:
        return [mock_doc(base, i) for i in range(DOCS)]
    if template:
        return make_batch(template, tid, r)
    return synth_docs(DOCS, base)


def worker(col, tid, template, out):
    lat = []
    for r in range(ROUNDS):
        batch = gen_batch(template, tid, r)
        start = time.perf_counter()
        col.insert_many(batch, ordered=False)
        lat.append((time.perf_counter() - start) * 1000.0)
    out[tid] = lat


def main():
    client = MongoClient(URI, w=1, wtimeoutMS=2000, maxPoolSize=THREADS + 2)

    if INFO:
        print_info(client)
        client.close()
        return

    template = load_real_docs(client) if SAMPLE else None
    n_docs = len(template) if template else DOCS

    col = client[DB].get_collection(COLL, write_concern=WriteConcern(w=1, wtimeout=2000))
    col.drop()
    if INDEX:
        col.create_index(
            [("7", ASCENDING), ("34", ASCENDING), ("3", ASCENDING)],
            unique=True,
            name="uniq_tenant_server_event_seq",
        )

    # report average BSON doc size for the chosen mode
    import bson
    sample_batch = gen_batch(template, 0, 0)
    avg_doc = sum(len(bson.encode(d)) for d in sample_batch) / len(sample_batch)

    # warmup
    col.insert_many(gen_batch(template, 99, 99), ordered=False)

    out = {}
    threads = [threading.Thread(target=worker, args=(col, t, template, out)) for t in range(THREADS)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()

    mode = "sample" if SAMPLE else ("mock" if MOCK else "synth")
    latencies = sorted(v for lat in out.values() for v in lat)
    n = len(latencies)
    print(
        f"mode={mode} threads={THREADS} index={int(INDEX)} "
        f"docs/batch={n_docs} avg_bson={avg_doc:.0f}B rounds={ROUNDS} samples={n} "
        f"median={latencies[n // 2]:.1f}ms p95={latencies[min(n - 1, int(n * 0.95))]:.1f}ms "
        f"min={latencies[0]:.1f}ms max={latencies[-1]:.1f}ms"
    )
    col.drop()
    client.close()


if __name__ == "__main__":
    main()
