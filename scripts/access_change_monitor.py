"""
access_change_monitor.py
Weekly scan of moovfinancial GitHub org for merged PRs that contain
access-related file changes. Posts findings to Slack via
Workflow Builder webhook - one message per PR.
"""

import os
import json
import requests
import time
from datetime import datetime, timedelta, timezone
from github import Github

# ── Configuration ─────────────────────────────────────────────────────────────
GH_TOKEN          = os.environ["GH_TOKEN"]
SLACK_WEBHOOK_URL = os.environ["SLACK_WEBHOOK_URL"]
ORG_NAME          = os.environ["ORG"]
LOOKBACK_DAYS     = 7

# ── File path patterns that indicate access provisioning ──────────────────────
ACCESS_PATTERNS = [
    "iam", "iam_binding", "iam_member", "iam_policy",
    "google_compute", "ssh_keys", "metadata",
    "jumpcloud", "user_group",
    "CODEOWNERS", "team", "members",
    "clusterrolebinding", "rolebinding", "serviceaccount",
    "vault_policy", "vault_auth",
    "twingate", "spacelift_stack",
    "access", "permission", "role", "privilege",
    "user_add", "add_user", "grant",
]

TRACKED_SYSTEMS = [
    "1password", "github", "gsuite", "gcp", "jumpcloud",
    "knowbe4", "postman", "slack", "linear", "gke", "vault",
    "twingate", "bigquery", "alloydb", "spanner", "compute",
]


def is_access_related(file_path: str) -> bool:
    path_lower = file_path.lower()
    return any(p.lower() in path_lower for p in ACCESS_PATTERNS)


def get_system_hint(file_path: str) -> str:
    path_lower = file_path.lower()
    for system in TRACKED_SYSTEMS:
        if system in path_lower:
            return system.upper()
    if ".tf" in path_lower:
        return "GCP/TERRAFORM"
    if "k8s" in path_lower or "kubernetes" in path_lower:
        return "KUBERNETES"
    return "UNKNOWN"


def get_merger_email(g, login: str) -> str:
    try:
        return g.get_user(login).email or ""
    except Exception:
        return ""


def scan_org(g, org_name: str, since: datetime) -> list:
    org = g.get_organization(org_name)
    findings = []

    for repo in org.get_repos(type="all"):
        try:
            pulls = repo.get_pulls(state="closed", sort="updated", direction="desc")
            for pr in pulls:
                if not pr.merged_at:
                    continue
                if pr.merged_at < since:
                    break
                access_files = []
                try:
                    for f in pr.get_files():
                        if is_access_related(f.filename):
                            access_files.append({
                                "path":        f.filename,
                                "status":      f.status,
                                "additions":   f.additions,
                                "deletions":   f.deletions,
                                "system_hint": get_system_hint(f.filename),
                            })
                except Exception:
                    continue
                if access_files:
                    merger       = pr.merged_by.login if pr.merged_by else "unknown"
                    merger_email = get_merger_email(g, merger)
                    findings.append({
                        "repo":            repo.full_name,
                        "pr_number":       pr.number,
                        "pr_title":        pr.title,
                        "pr_url":          pr.html_url,
                        "author":          pr.user.login,
                        "merged_by":       merger,
                        "merged_by_email": merger_email,
                        "merged_at":       pr.merged_at.strftime("%Y-%m-%d %H:%M UTC"),
                        "files":           access_files,
                    })
        except Exception as e:
            print(f"  Skipping {repo.name}: {e}")
            continue

    return findings


def post_to_slack(message: str) -> bool:
    payload  = {"message": message}
    headers  = {"Content-Type": "application/json"}
    response = requests.post(
        SLACK_WEBHOOK_URL,
        data=json.dumps(payload),
        headers=headers
    )
    print(f"Slack response: {response.status_code} {response.text}")
    return response.status_code == 200


def main():
    since = datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)
    now_str   = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    since_str = since.strftime("%Y-%m-%d")

    print(f"Scanning {ORG_NAME} for access-related PRs merged since {since.date()}...")

    g        = Github(GH_TOKEN)
    findings = scan_org(g, ORG_NAME, since)
    print(f"Found {len(findings)} PR(s) with access-related changes.")

    if not findings:
        post_to_slack(
            f"*Access Change Monitor — {now_str}*\n"
            f"No access-related PR changes detected between "
            f"{since_str} and {now_str}."
        )
        return

    # ── Post summary header ───────────────────────────────────────────────────
    post_to_slack(
        f"*ACCESS CHANGE MONITOR — {now_str}*\n"
        f"*{len(findings)} PR(s)* merged between {since_str} and {now_str} "
        f"contain access-related file changes requiring AAF review.\n\n"
        f"*Action required:* Confirm each change is reflected on the user's AAF. "
        f"If not, contact the security admin listed as *Merged by* and request "
        f"they update the AAF with the date access was implemented and their name."
    )
    time.sleep(1)

    # ── Post one message per finding ──────────────────────────────────────────
    for i, f in enumerate(findings, 1):
        email_note = f" ({f['merged_by_email']})" if f["merged_by_email"] else ""
        file_lines = "\n".join(
            f"  • `{fl['path']}` [{fl['system_hint']}] "
            f"({fl['status']}, +{fl['additions']}/-{fl['deletions']})"
            for fl in f["files"]
        )
        message = (
            f"*Finding {i} of {len(findings)}: PR #{f['pr_number']} — {f['pr_title']}*\n"
            f"*Repo:* {f['repo']}\n"
            f"*URL:* {f['pr_url']}\n"
            f"*Author:* {f['author']}\n"
            f"*Merged by (Security Admin):* {f['merged_by']}{email_note}\n"
            f"*Merged:* {f['merged_at']}\n"
            f"*Files changed:*\n{file_lines}"
        )
        post_to_slack(message)
        time.sleep(1)

    print("Done.")


if __name__ == "__main__":
    main()
