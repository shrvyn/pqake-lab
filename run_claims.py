"""Run the claim-by-claim security matrix and dump machine-readable results."""
import json
import sys
import time

from lab import claims


def main():
    t0 = time.perf_counter()
    recs = claims.run_all(verbose=True)
    json.dump({"generated": time.strftime("%Y-%m-%d %H:%M:%S"),
               "python": sys.version.split()[0],
               "seconds": round(time.perf_counter() - t0, 1),
               "results": recs},
              open("claims.json", "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    tally = {}
    for r in recs:
        tally[r["verdict"]] = tally.get(r["verdict"], 0) + 1
    print("\n%d records in %.1fs: %s" % (len(recs), time.perf_counter() - t0,
                                         ", ".join("%s=%d" % kv for kv in sorted(tally.items()))))
    print("wrote claims.json")


if __name__ == "__main__":
    main()
