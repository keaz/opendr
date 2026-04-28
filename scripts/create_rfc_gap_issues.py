#!/usr/bin/env python3
"""Create GitHub issues from docs/LDAP_RFC_GAP_ISSUES.md.

Usage:
  python scripts/create_rfc_gap_issues.py --repo owner/name --dry-run
  GITHUB_TOKEN=... python scripts/create_rfc_gap_issues.py --repo owner/name
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path


ISSUE_SPLIT = re.compile(r"^## Issue (?P<num>\d+): (?P<title>.+)$", re.MULTILINE)


@dataclass
class IssueDraft:
    number: int
    title: str
    body: str


def parse_issue_drafts(markdown_path: Path) -> list[IssueDraft]:
    content = markdown_path.read_text(encoding="utf-8")
    matches = list(ISSUE_SPLIT.finditer(content))
    drafts: list[IssueDraft] = []
    for idx, match in enumerate(matches):
        start = match.end()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else content.find("## Recommended rollout plan")
        if end == -1:
            end = len(content)
        body = content[start:end].strip()
        body = re.sub(r"\n---\s*$", "", body, flags=re.MULTILINE).strip()
        drafts.append(
            IssueDraft(
                number=int(match.group("num")),
                title=match.group("title").strip(),
                body=body,
            )
        )
    return drafts


def create_issue(repo: str, token: str, title: str, body: str, labels: list[str]) -> dict:
    payload = json.dumps({"title": title, "body": body, "labels": labels}).encode("utf-8")
    req = urllib.request.Request(
        url=f"https://api.github.com/repos/{repo}/issues",
        data=payload,
        method="POST",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req) as response:  # noqa: S310
        return json.loads(response.read().decode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="GitHub repository slug, e.g. org/repo")
    parser.add_argument(
        "--source",
        default="docs/LDAP_RFC_GAP_ISSUES.md",
        help="Path to issue draft markdown source",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print parsed issues instead of creating them")
    parser.add_argument(
        "--labels",
        default="rfc-compliance,tests-required",
        help="Comma-separated labels to apply to each issue",
    )
    args = parser.parse_args()

    labels = [label.strip() for label in args.labels.split(",") if label.strip()]
    drafts = parse_issue_drafts(Path(args.source))
    if not drafts:
        print("No issue drafts found.", file=sys.stderr)
        return 1

    if args.dry_run:
        for draft in drafts:
            print(f"[DRY RUN] #{draft.number}: {draft.title}")
        print(f"Parsed {len(drafts)} issue drafts from {args.source}.")
        return 0

    token = os.getenv("GITHUB_TOKEN")
    if not token:
        print("GITHUB_TOKEN is required unless --dry-run is used.", file=sys.stderr)
        return 2

    created = 0
    for draft in drafts:
        issue_title = f"RFC gap: {draft.title}"
        issue_body = (
            "This issue was generated from `docs/LDAP_RFC_GAP_ISSUES.md`.\n\n"
            f"{draft.body}\n\n"
            "---\n"
            f"Source draft: Issue {draft.number}"
        )
        try:
            result = create_issue(args.repo, token, issue_title, issue_body, labels)
        except urllib.error.HTTPError as exc:
            error_body = exc.read().decode("utf-8", errors="replace")
            print(f"Failed to create issue for draft {draft.number}: HTTP {exc.code}\n{error_body}", file=sys.stderr)
            return 3
        except urllib.error.URLError as exc:
            print(f"Network error creating issue for draft {draft.number}: {exc}", file=sys.stderr)
            return 4

        created += 1
        print(f"Created issue #{result.get('number')}: {result.get('html_url')}")

    print(f"Created {created} issues in {args.repo}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
