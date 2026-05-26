"""
access_change_monitor.py
Weekly scan of moovfinancial GitHub org for merged PRs that contain
access-related file changes. Emails a report to the compliance lead
and identifies the security admin who implemented the change.
"""

import os
import smtplib
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from github import Github

# ── Configuration ─────────────────────────────────────────────────────────────
GH_TOKEN       = os.environ["GH_TOKEN"]
GMAIL_USER     = os.environ["GMAIL_USER"]
GMAIL_PASSWORD = os.environ["GMAIL_APP_PASSWORD"]
NOTIFY_EMAIL   = os.environ["NOTIFY_EMAIL"]
ORG_NAME       = os.environ["ORG"]
LOOKBACK_DAYS  = 7

# ── File path patterns that indicate access provisioning ──────────────────────
# Any merged PR touching a file whose path contains one of these strings
# will be flagged for AAF review.
ACCESS_PATTERNS = [
    # GCP IAM / Terraform
    "iam", "iam_binding", "iam_member", "iam_policy",
    # Compute / VM access
    "google_compute", "ssh_keys", "metadata",
    # JumpCloud
    "jumpcloud", "user_group",
    # GitHub org / team membership
    "CODEOWNERS", "team", "members",
    # Kubernetes RBAC
    "clusterrolebinding", "rolebinding", "serviceaccount",
    # HashiCorp Vault
    "vault_policy", "vault_auth",
    # Twingate
    "twingate",
    # Spacelift
    "spacelift_stack",
    # Generic access keywords
    "access", "permission", "role", "privilege",
    "user_add", "add_user", "grant",
]

# Systems tracked on Moov access authorization forms (AAFs)
TRACKED_SYSTEMS = [
    "1password", "github", "gsuite", "gcp", "jumpcloud",
    "knowbe4", "postman", "slack", "linear", "gke", "vault",
    "twingate", "bigquery", "alloydb", "spanner", "compute",
]


def is_access_related(file_path: str) -> bool:
    """Return True if the file path suggests an access provisioning change."""
    path_lower = file_path.lower()
    return any(p.lower() in path_lower for p in ACCESS_PATTERNS)


def get_system_hint(file_path: str) -> str:
    """Infer which tracked system a file path relates to."""
    path_lower = file_path.lower()
    for system in TRACKED_SYSTEMS:
        if system in path_lower:
            return system.upper()
    if ".tf" in path_lower:
        return "GCP/TERRAFORM"
    if "k8s" in path_lower or "kubernetes" in path_lower:
        return "KUBERNETES"
    return "UNKNOWN — REVIEW MANUALLY"


def get_merger_email(g: Github, login: str) -> str:
    """Look up a GitHub user's public email. Returns empty string if not set."""
    try:
        return g.get_user(login).email or ""
    except Exception:
        return ""


def scan_org(g: Github, org_name: str, since: datetime) -> list:
    """
    Scan all org repos for merged PRs in the lookback window that touch
    access-related files. Returns a list of finding dicts.
    """
    org = g.get_organization(org_name)
    findings = []
    skipped = []

    for repo in org.get_repos(type="all"):
        try:
            pulls = repo.get_pulls(state="closed", sort="updated", direction="desc")
            for pr in pulls:
                if not pr.merged_at:
                    continue
                # PRs are sorted by updated_at desc — once we're past the window, stop
                if pr.merged_at < since:
                    break

                access_files = []
                try:
                    for f in pr.get_files():
                        if is_access_related(f.filename):
                            access_files.append({
                                "path":        f.filename,
                                "status":      f.status,       # added / modified / removed
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
            skipped.append(f"{repo.name}: {e}")
            continue

    if skipped:
        print(f"Skipped {len(skipped)} repo(s) due to errors:")
        for s in skipped:
            print(f"  {s}")

    return findings


def build_html_report(findings: list, since: datetime) -> str:
    """Build the HTML email body."""
    now_str   = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    since_str = since.strftime("%Y-%m-%d")

    if not findings:
        return f"""
        <html><body style="font-family:Arial,sans-serif;font-size:13px">
        <h2>✅ Access Change Monitor — {now_str}</h2>
        <p>No access-related PR changes detected in <strong>moovfinancial</strong>
        between <strong>{since_str}</strong> and <strong>{now_str}</strong>.</p>
        <p style="color:#666">Scan covered all org repos for IAM, JumpCloud, SSH, RBAC,
        Vault, Twingate, Compute, and GitHub membership changes.</p>
        </body></html>
        """

    # Build one table block per finding
    blocks = ""
    for f in findings:
        email_note = f"({f['merged_by_email']})" if f["merged_by_email"] else "(email not public on GitHub profile)"

        file_rows = "".join(
            f"""
            <tr>
              <td style="padding:5px 8px">{fl['path']}</td>
              <td style="padding:5px 8px;text-align:center">{fl['status']}</td>
              <td style="padding:5px 8px;text-align:center"><strong>{fl['system_hint']}</strong></td>
              <td style="padding:5px 8px;text-align:center">+{fl['additions']} / -{fl['deletions']}</td>
            </tr>
            """
            for fl in f["files"]
        )

        blocks += f"""
        <table border="1" cellpadding="0" cellspacing="0"
               style="border-collapse:collapse;width:100%;margin-bottom:24px;font-size:13px">

          <!-- PR header row -->
          <tr style="background:#1a1a2e;color:#fff">
            <td colspan="4" style="padding:10px 12px">
              <strong>
                <a href="{f['pr_url']}" style="color:#7ec8e3;text-decoration:none">
                  #{f['pr_number']} — {f['pr_title']}
                </a>
              </strong>
            </td>
          </tr>

          <!-- Meta row -->
          <tr style="background:#f0f4ff">
            <td colspan="4" style="padding:8px 12px;font-size:12px">
              <strong>Repo:</strong> {f['repo']} &nbsp;|&nbsp;
              <strong>PR Author:</strong> {f['author']} &nbsp;|&nbsp;
              <strong>Merged by (Security Admin):</strong>
                <span style="color:#c0392b">{f['merged_by']}</span> {email_note} &nbsp;|&nbsp;
              <strong>Merged:</strong> {f['merged_at']}
            </td>
          </tr>

          <!-- File header -->
          <tr style="background:#e8e8e8">
            <th style="padding:6px 8px;text-align:left">File Path</th>
            <th style="padding:6px 8px">Change Type</th>
            <th style="padding:6px 8px">System (Inferred)</th>
            <th style="padding:6px 8px">Lines +/-</th>
          </tr>

          {file_rows}
        </table>
        """

    return f"""
    <html><body style="font-family:Arial,sans-serif;font-size:13px;max-width:960px">

    <h2 style="color:#c0392b">🔐 Access Change Monitor — {now_str}</h2>

    <p>
      <strong>{len(findings)} PR(s)</strong> merged between
      <strong>{since_str}</strong> and <strong>{now_str}</strong>
      contain access-related file changes requiring AAF review.
    </p>

    <div style="background:#fff8e1;border-left:4px solid #f39c12;padding:12px 16px;margin-bottom:24px">
      <strong>⚠️ Action required for each finding below:</strong>
      <ol style="margin:8px 0 0 0">
        <li>Confirm the change is reflected on the user's Access Authorization Form (AAF).</li>
        <li>If the AAF has not been updated, contact the security admin listed under
            <em>"Merged by"</em> and request they update the AAF with:
          <ul>
            <li>Date access was implemented</li>
            <li>Their name as the implementing security admin</li>
          </ul>
        </li>
      </ol>
    </div>

    {blocks}

    <p style="color:#999;font-size:11px;margin-top:32px">
      Generated by access-change-monitor.yml · moovfinancial/.github ·
      Lookback: {LOOKBACK_DAYS} days · Run: {now_str}
    </p>

    </body></html>
    """


def send_email(subject: str, html_body: str):
    """Send the report via Gmail SMTP."""
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = GMAIL_USER
    msg["To"]      = NOTIFY_EMAIL
    msg.attach(MIMEText(html_body, "html"))

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(GMAIL_USER, GMAIL_PASSWORD)
        server.sendmail(GMAIL_USER, [NOTIFY_EMAIL], msg.as_string())

    print(f"Report emailed to {NOTIFY_EMAIL}")


def main():
    since = datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)
    print(f"Scanning {ORG_NAME} for access-related PRs merged since {since.date()}...")

    g        = Github(GH_TOKEN)
    findings = scan_org(g, ORG_NAME, since)

    print(f"Found {len(findings)} PR(s) with access-related changes.")

    subject = (
        f"[Access Monitor] {len(findings)} access change(s) require AAF review — "
        f"{datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
        if findings else
        f"[Access Monitor] ✅ No access changes detected — "
        f"{datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
    )

    html = build_html_report(findings, since)
    send_email(subject, html)


if __name__ == "__main__":
    main()
