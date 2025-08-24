#!/usr/bin/env python3
import json, argparse, datetime, html
from typing import List, Dict, Any

SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEV_SCORE = {"LOW": 1, "MEDIUM": 3, "HIGH": 7, "CRITICAL": 10}

def sev_max(a, b):
    return a if SEV_SCORE[a] >= SEV_SCORE[b] else b

def add_finding(findings, service, title, severity, detail, resource=None, remediation=None, control=None):
    findings.append({
        "service": service,
        "title": title,
        "severity": severity,
        "detail": detail,
        "resource": resource,
        "remediation": remediation,
        "control": control
    })

def check_s3(data, findings):
    for b in data.get("s3_buckets", []):
        name = b.get("name")
        public = bool(b.get("public", False))
        encryption = bool(b.get("encryption", False))
        versioning = bool(b.get("versioning", False))

        if public:
            add_finding(findings, "S3", "Public S3 bucket", "CRITICAL",
                        f"Bucket '{name}' is publicly accessible (ACL/Policy).",
                        resource=name,
                        remediation="Make bucket private; restrict access via IAM; use VPC endpoints.",
                        control="CIS AWS 2.1.1")
        if not encryption:
            add_finding(findings, "S3", "S3 without encryption", "HIGH",
                        f"Bucket '{name}' lacks default server-side encryption.",
                        resource=name,
                        remediation="Enable SSE-S3 or SSE-KMS.",
                        control="CIS AWS 2.1.5")
        if not versioning:
            add_finding(findings, "S3", "S3 without versioning", "MEDIUM",
                        f"Bucket '{name}' does not have object versioning enabled.",
                        resource=name,
                        remediation="Enable versioning to protect against accidental deletion/overwrite.",
                        control="Best Practice")

def is_wild(x):
    if isinstance(x, list):
        return any(is_wild(i) for i in x)
    return str(x).strip() in ("*", "*:*")

def check_iam(data, findings):
    for p in data.get("iam_policies", []):
        name = p.get("name")
        for st in p.get("statements", []):
            effect = (st.get("effect") or "").upper()
            action = st.get("action", [])
            resource = st.get("resource", [])
            if effect == "ALLOW" and (is_wild(action) or is_wild(resource)):
                add_finding(findings, "IAM", "Overly permissive IAM policy", "CRITICAL",
                            f"Policy '{name}' allows {action} on {resource}.",
                            resource=name,
                            remediation="Replace wildcards with least-privilege actions/resources.",
                            control="CIS AWS 1.22")
            elif effect == "ALLOW" and (("iam:*" in (action if isinstance(action, list) else [action]))):
                add_finding(findings, "IAM", "IAM FullAccess detected", "HIGH",
                            f"Policy '{name}' allows iam:* which is high risk.",
                            resource=name,
                            remediation="Scope down IAM permissions.",
                            control="Least Privilege")

def check_sg(data, findings):
    risky_ports = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "Postgres", 27017: "MongoDB"}
    for sg in data.get("security_groups", []):
        name = sg.get("name")
        for rule in sg.get("inbound", []):
            cidr = rule.get("cidr", "")
            port = int(rule.get("port", -1))
            proto = (rule.get("protocol") or "tcp").lower()
            if cidr == "0.0.0.0/0" and proto in ("tcp", "udp"):
                sev = "HIGH" if port in risky_ports else "MEDIUM"
                svc = risky_ports.get(port, "Any")
                add_finding(findings, "SecurityGroup", "Wide-open ingress", sev,
                            f"SG '{name}' allows {proto.upper()} {port} ({svc}) from 0.0.0.0/0.",
                            resource=name,
                            remediation="Restrict ingress to specific CIDRs or use bastion/VPN.",
                            control="CIS AWS 4.1")
            if cidr == "::/0":
                add_finding(findings, "SecurityGroup", "IPv6 wide-open ingress", "HIGH",
                            f"SG '{name}' allows IPv6 from ::/0 on port {port}.",
                            resource=name,
                            remediation="Restrict IPv6 ingress to trusted ranges.",
                            control="CIS AWS 4.1")

def check_kms(data, findings):
    kms = data.get("kms", {})
    if not kms.get("enabled", False):
        add_finding(findings, "KMS", "KMS encryption disabled", "HIGH",
                    "KMS not enabled for the account/services where required.",
                    remediation="Enable KMS and use CMKs for sensitive data.",
                    control="CIS AWS 3.3")

def check_cloudtrail(data, findings):
    ct = data.get("cloudtrail", {})
    if not ct.get("enabled", False):
        add_finding(findings, "CloudTrail", "CloudTrail disabled", "CRITICAL",
                    "CloudTrail is not enabled for auditing/forensics.",
                    remediation="Enable multi-region CloudTrail with log file validation.",
                    control="CIS AWS 3.1")

def check_rds(data, findings):
    for db in data.get("rds_instances", []):
        name = db.get("name")
        if db.get("public", False):
            add_finding(findings, "RDS", "Publicly accessible RDS", "HIGH",
                        f"RDS '{name}' is public.",
                        resource=name,
                        remediation="Disable public access; place in private subnets.",
                        control="CIS AWS 4.2")
        if not db.get("storage_encrypted", False):
            add_finding(findings, "RDS", "RDS storage not encrypted", "HIGH",
                        f"RDS '{name}' lacks storage encryption.",
                        resource=name,
                        remediation="Enable storage encryption at rest.",
                        control="CIS AWS 2.4")

CHECKS = [check_s3, check_iam, check_sg, check_kms, check_cloudtrail, check_rds]

def summarize(findings, min_sev):
    def sev_ok(s): return SEV_SCORE[s] >= SEV_SCORE[min_sev]
    filtered = [f for f in findings if sev_ok(f["severity"])]
    score = sum(SEV_SCORE[f["severity"]] for f in filtered)
    counts = {s: 0 for s in SEVERITIES}
    for f in filtered: counts[f["severity"]] += 1
    return filtered, score, counts

def render_html(findings, score, counts, min_sev, src_name):
    now = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d %H:%M UTC")
    rows = []
    for f in findings:
        rows.append(f"""<tr>
<td>{html.escape(f['service'])}</td>
<td><b>{html.escape(f['title'])}</b><br><small>{html.escape(f.get('detail',''))}</small></td>
<td><span class="sev {f['severity']}">{f['severity']}</span></td>
<td>{html.escape(f.get('resource','') or '-')}</td>
<td>{html.escape(f.get('remediation','') or '-')}</td>
<td>{html.escape(f.get('control','') or '-')}</td>
</tr>""")
    rows_html = "\n".join(rows) or "<tr><td colspan='6'>No findings at/above selected severity.</td></tr>"
    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Cloud Misconfiguration Report</title>
<style>
body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial; padding: 20px; }}
h1 {{ margin-bottom: 0; }}
.badge {{ display:inline-block; padding:4px 8px; border-radius:8px; background:#eee; margin-right:6px; }}
.sev {{ padding:2px 6px; border-radius:6px; font-weight:700; }}
.SEVERE {{ }}
.CRITICAL {{ background:#ffdddd; border:1px solid #ff4444; }}
.HIGH {{ background:#ffe8d6; border:1px solid #ff8844; }}
.MEDIUM {{ background:#fff6c4; border:1px solid #e6b800; }}
.LOW {{ background:#e8f5e9; border:1px solid #66bb6a; }}
table {{ width:100%; border-collapse: collapse; margin-top: 14px; }}
th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; }}
th {{ background: #f6f6f6; }}
.summary {{ margin-top: 12px; }}
</style>
</head>
<body>
<h1>Cloud Misconfiguration Report</h1>
<div class="summary">
<span class="badge"><b>Source:</b> {html.escape(src_name)}</span>
<span class="badge"><b>Generated:</b> {now}</span>
<span class="badge"><b>Min Severity:</b> {min_sev}</span>
<span class="badge"><b>Total Score:</b> {score}</span>
<span class="badge">CRITICAL: {counts.get('CRITICAL',0)}</span>
<span class="badge">HIGH: {counts.get('HIGH',0)}</span>
<span class="badge">MEDIUM: {counts.get('MEDIUM',0)}</span>
<span class="badge">LOW: {counts.get('LOW',0)}</span>
</div>
<table>
<thead><tr><th>Service</th><th>Finding</th><th>Severity</th><th>Resource</th><th>Remediation</th><th>Control</th></tr></thead>
<tbody>
{rows_html}
</tbody>
</table>
</body>
</html>"""

def main():
    ap = argparse.ArgumentParser(description="Cloud Misconfiguration Scanner (mock config)")
    ap.add_argument("config", help="Path to mocked cloud config JSON")
    ap.add_argument("--report", help="Write HTML report to file")
    ap.add_argument("--json", dest="json_out", help="Write findings JSON to file")
    ap.add_argument("--min-severity", choices=SEVERITIES, default="LOW", help="Filter findings by minimum severity")
    args = ap.parse_args()

    with open(args.config, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = []
    for check in CHECKS:
        try:
            check(data, findings)
        except Exception as e:
            add_finding(findings, "CORE", f"Checker {check.__name__} failed", "LOW", str(e))

    filtered, score, counts = summarize(findings, args.min_severity)

    if args.report:
        html_out = render_html(filtered, score, counts, args.min_severity, args.config)
        with open(args.report, "w", encoding="utf-8") as f:
            f.write(html_out)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump({"min_severity": args.min_severity, "score": score, "findings": filtered}, f, indent=2)

    if not args.report and not args.json_out:
        # print plaintext summary
        print(f"Findings (min severity: {args.min_severity}) - Score {score}")
        for f in filtered:
            print(f"[{f['severity']}] {f['service']}: {f['title']} - {f.get('resource','-')}")
            if f.get('detail'): print(f"  {f['detail']}")

if __name__ == "__main__":
    main()
