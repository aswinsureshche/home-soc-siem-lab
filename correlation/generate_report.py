#!/usr/bin/env python3
"""
Renders incidents.json (from correlate.py) into a Markdown incident report,
optionally converted to PDF.

Usage:
    python3 generate_report.py --incidents incidents.json --out report.md
    python3 generate_report.py --incidents incidents.json --out report.md --pdf
"""
import argparse
import datetime as dt
import json
import sys
from pathlib import Path

import yaml
from jinja2 import Environment, FileSystemLoader


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--incidents", default="incidents.json")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--out", default="report.md")
    parser.add_argument("--pdf", action="store_true", help="Also render report.pdf (requires weasyprint + markdown2)")
    args = parser.parse_args()

    incidents_path = Path(args.incidents)
    if not incidents_path.exists():
        print(f"{incidents_path} not found — run correlate.py first.", file=sys.stderr)
        sys.exit(1)
    incidents = json.loads(incidents_path.read_text())

    config = {}
    config_path = Path(args.config)
    if config_path.exists():
        config = yaml.safe_load(config_path.read_text()) or {}
    org_name = config.get("report", {}).get("organization_name", "Home SOC Lab")

    env = Environment(loader=FileSystemLoader(str(Path(__file__).parent)))
    template = env.get_template("report_template.md.j2")
    markdown = template.render(
        incidents=incidents,
        organization_name=org_name,
        generated_at=dt.datetime.now().isoformat(timespec="seconds"),
    )

    out_path = Path(args.out)
    out_path.write_text(markdown)
    print(f"Wrote {out_path}")

    if args.pdf:
        try:
            import markdown2
            from weasyprint import HTML
        except ImportError:
            print(
                "PDF output requires markdown2 and weasyprint: "
                "pip install markdown2 weasyprint",
                file=sys.stderr,
            )
            sys.exit(1)

        html_body = markdown2.markdown(markdown, extras=["tables"])
        html_doc = f"""
        <html><head><style>
        body {{ font-family: sans-serif; margin: 2em; }}
        table {{ border-collapse: collapse; width: 100%; margin-bottom: 1.5em; }}
        th, td {{ border: 1px solid #ccc; padding: 4px 8px; font-size: 0.85em; }}
        th {{ background: #eee; }}
        h2 {{ border-bottom: 2px solid #333; padding-bottom: 4px; }}
        </style></head><body>{html_body}</body></html>
        """
        pdf_path = out_path.with_suffix(".pdf")
        HTML(string=html_doc).write_pdf(str(pdf_path))
        print(f"Wrote {pdf_path}")


if __name__ == "__main__":
    main()
