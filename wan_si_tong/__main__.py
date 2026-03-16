"""
__main__.py — CLI entry point.

Usage (backward-compatible with old wan_si_tong.py monolith):
    python -m wan_si_tong --findings findings.json
    python -m wan_si_tong --findings findings.json --out path_suggestions.json

New flags:
    --tracker-report        Print engagement outcome statistics and exit
    --os linux|windows|macos|android
                            Override OS detection for collation filtering
    --design-path           Run the Path Designer and print the resulting phase queue
    --list                  List all registered methodologies and exit
    --min-score FLOAT       Minimum relevance score threshold (default: 0.3)
"""

import argparse
import sys


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wan_si_tong",
        description="Wan Si Tong — Attack Methodology Library for dig_champs",
    )
    p.add_argument("-f", "--findings",
                   help="Path to findings JSON (dig_champs report or raw findings list)")
    p.add_argument("-t", "--target", default="unknown",
                   help="Target identifier (for output metadata)")
    p.add_argument("-o", "--out", default="path_suggestions.json",
                   help="Output path for methodology suggestions JSON")
    p.add_argument("--list", action="store_true",
                   help="List all methodologies in the library and exit")
    p.add_argument("--min-score", type=float, default=0.3,
                   help="Minimum relevance score threshold (default: 0.3)")
    p.add_argument("--os", dest="os_tag",
                   choices=["linux", "windows", "macos", "android"],
                   default=None,
                   help="Override OS detection for methodology filtering")
    p.add_argument("--tracker-report", action="store_true",
                   help="Print engagement outcome statistics and exit")
    p.add_argument("--design-path", action="store_true",
                   help="Run Path Designer on findings and print recommended phase queue")
    p.add_argument("--mode", type=int, default=2, choices=[1, 2, 3, 4],
                   help="Engagement mode for Path Designer (1=Ghost, 4=BOSS; default: 2)")
    return p


def main() -> None:
    # Import here to ensure all methodology modules are registered
    from wan_si_tong.registry import MethodologyRegistry
    from wan_si_tong.tracker import EngagementTracker
    from wan_si_tong.output import run_collation

    args = _build_parser().parse_args()

    # ── --list: print all registered methodologies ────────────────────────────
    if args.list:
        registry = MethodologyRegistry.get()
        all_m = registry.all()
        print(f"\nWan Si Tong — {len(all_m)} methodologies registered\n")
        for m in sorted(all_m, key=lambda x: (x.category, x.id)):
            print(f"  [{m.id}]  {m.name}  "
                  f"(phase={m.phase}, opsec={m.opsec_level}/5, cat={m.category})")
        return

    # ── --tracker-report: print engagement stats ──────────────────────────────
    if args.tracker_report:
        tracker = EngagementTracker()
        tracker.print_report()
        return

    # ── All other modes require --findings ────────────────────────────────────
    if not args.findings:
        _build_parser().print_help()
        sys.exit(1)

    suggestions = run_collation(
        findings_path=args.findings,
        target=args.target,
        out_path=args.out,
        min_score=args.min_score,
        os_tag=args.os_tag,
    )

    # ── --design-path: run Path Designer ─────────────────────────────────────
    if args.design_path:
        from wan_si_tong.tracker import EngagementTracker
        from wan_si_tong.path_designer import TrajectoryPathDesigner
        tracker = EngagementTracker()
        designer = TrajectoryPathDesigner(
            trajectory={},
            suggestions=suggestions,
            mode=args.mode,
            tracker=tracker,
        )
        queue = designer.to_phase_queue()
        print(f"\nPath Designer — mode {args.mode} — recommended phase queue:")
        for i, phase in enumerate(queue, 1):
            print(f"  {i}. {phase}")
        print(f"\n{designer.explain()}")
        return

    # ── Default: show top suggestions ─────────────────────────────────────────
    print(f"\nTop suggestions for '{args.target}':")
    for s in suggestions[:5]:
        print(f"  [{s['id']}]  {s['name']}  score={s['relevance_score']}")


if __name__ == "__main__":
    main()
