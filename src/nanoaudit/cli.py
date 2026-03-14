from __future__ import annotations

import argparse
import json

from nanoaudit.config import load_config
from nanoaudit.data import ensure_demo_dataset
from nanoaudit.pipeline import NanoAuditPipeline


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="NanoLLM4Audit command line interface")
    parser.add_argument("--config", default="configs/default.toml", help="Path to project config")
    subparsers = parser.add_subparsers(dest="command", required=True)

    make_data_parser = subparsers.add_parser("make-data", help="Generate the bundled demo dataset")
    make_data_parser.add_argument("--force", action="store_true", help="Rebuild dataset even if it already exists")

    run_parser = subparsers.add_parser("run", help="Run the full local demo pipeline")
    run_parser.add_argument("--rebuild-data", action="store_true", help="Rebuild demo dataset before scoring")

    subparsers.add_parser("summary", help="Print metrics from the latest run")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    config = load_config(args.config)

    if args.command == "make-data":
        dataset = ensure_demo_dataset(config, force=args.force)
        print(f"dataset_ready rows={len(dataset)} path={config.paths.data_file}")
        return

    pipeline = NanoAuditPipeline(config)
    if args.command == "run":
        result = pipeline.run(rebuild_data=args.rebuild_data)
        print(
            "run_completed "
            f"events={len(result['scored'])} "
            f"candidates={result['metrics']['candidate_count']} "
            f"f1={result['metrics']['f1']:.3f} "
            f"dashboard={config.paths.dashboard_file}"
        )
        return

    if args.command == "summary":
        print(json.dumps(pipeline.summary(), ensure_ascii=False, indent=2))
        return


if __name__ == "__main__":
    main()
