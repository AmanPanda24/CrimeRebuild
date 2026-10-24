# Created by: Aman Kumar Panda
"""Command-line helper:

    python cli.py demo insider            load a demo scenario into the database
    python cli.py samples                 (re)write sample_evidence/ files
    python cli.py collect --name "PC-01"  collect from this Windows machine into a new case
    python cli.py report 1 out.pdf        export the PDF report for case 1
"""
import argparse
import sys

import config
from crimerebuild import analysis, collector, db, demo, evidence
from crimerebuild.db import Store
from crimerebuild.report import build_pdf


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo"); d.add_argument("scenario", choices=list(demo.SCENARIOS))
    sub.add_parser("samples")
    c = sub.add_parser("collect"); c.add_argument("--name", default="Live collection"); c.add_argument("--days", type=int, default=14)
    r = sub.add_parser("report"); r.add_argument("case_id", type=int); r.add_argument("out")
    args = ap.parse_args(argv)
    store = Store(config.DATA_DIR)

    if args.cmd == "demo":
        case_id = demo.load_demo(store, args.scenario)
        with store.session() as conn:
            case = db.get_case(conn, case_id)
        print(f"Case {case_id} created: risk {case['risk_score']}/100 ({case['risk_level']})")
    elif args.cmd == "samples":
        demo.write_samples(f"{config.BASE_DIR}/sample_evidence")
        print("Sample evidence written to sample_evidence/")
    elif args.cmd == "collect":
        with store.session() as conn:
            case_id = db.create_case(conn, args.name, "cli")
        try:
            summary = collector.collect_into_case(store, case_id, args.days)
        except collector.CollectorUnavailable as exc:
            print(exc); return 1
        for w in summary["warnings"]:
            print("warning:", w)
        alerts, score, level = analysis.reanalyze(store, case_id)
        print(f"Case {case_id}: {len(summary['ingested'])} file(s) ingested, {len(alerts)} alert(s), risk {score} ({level})")
    elif args.cmd == "report":
        results = evidence.verify_case(store, args.case_id)
        with store.session() as conn:
            bundle = analysis.case_bundle(conn, args.case_id)
            custody = conn.execute("SELECT * FROM custody WHERE case_id=? ORDER BY id", (args.case_id,)).fetchall()
        with open(args.out, "wb") as fh:
            fh.write(build_pdf(bundle, results, custody))
        print("Report written to", args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
