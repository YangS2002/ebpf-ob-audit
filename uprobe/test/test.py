#!/usr/bin/env python3
# Standalone MongoDB insert_many latency probe.
# Isolates whether the collector's ~85ms insert_many is server / network / client.
#
# Run on collector host (139, goes over network to mongo):
#   python3 bench_insert.py
# Run on mongo host (145, loopback):
#   URI='mongodb://audit_collector:1@127.0.0.1:27017/ob_audit?authSource=ob_audit' python3 bench_insert.py
#
# Env overrides: URI, DOCS (per batch), ROUNDS, PAD (bytes of pad string).

import os
import time

from pymongo import MongoClient, WriteConcern

URI = os.environ.get(
    "URI",
    "mongodb://audit_collector:1@7.27.43.145:27017/ob_audit?authSource=ob_audit",
)
DOCS = int(os.environ.get("DOCS", "542"))
ROUNDS = int(os.environ.get("ROUNDS", "20"))
PAD = int(os.environ.get("PAD", "400"))


def make_docs(n, base):
    pad = "x" * PAD
    return [
        {"tenant_id": 1, "server_ip": 1, "event_seq": base + i, "pad": pad}
        for i in range(n)
    ]


def main():
    client = MongoClient(URI, w=1, wtimeoutMS=2000)
    col = client["ob_audit"].get_collection(
        "bench_tmp", write_concern=WriteConcern(w=1, wtimeout=2000)
    )
    col.drop()

    # warmup (also opens the connection / triggers server selection)
    col.insert_many(make_docs(DOCS, 0), ordered=False)

    latencies = []
    for r in range(ROUNDS):
        batch = make_docs(DOCS, (r + 1) * 1_000_000)
        start = time.perf_counter()
        col.insert_many(batch, ordered=False)
        latencies.append((time.perf_counter() - start) * 1000.0)

    latencies.sort()
    n = len(latencies)
    median = latencies[n // 2]
    p95 = latencies[min(n - 1, int(n * 0.95))]
    print(
        f"docs/batch={DOCS} rounds={ROUNDS} "
        f"median={median:.1f}ms p95={p95:.1f}ms "
        f"min={latencies[0]:.1f}ms max={latencies[-1]:.1f}ms"
    )
    col.drop()
    client.close()


if __name__ == "__main__":
    main()