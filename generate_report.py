"""
generate_report.py
Turns redteam_report.json into a clean, readable SECURITY_REPORT.md --
the kind of artifact you'd actually attach to a real security assessment,
and a good thing to have sitting in your GitHub repo.

Run after redteam.py:
    python generate_report.py
"""

import json
from datetime import datetime, timezone

CATEGORY_LABELS = {
    "prompt_injection": "Prompt Injection",
    "sensitive_information_disclosure": "Sensitive Information Disclosure",
    "excessive_agency": "Excessive Agency",
    "scope_boundary": "Scope Boundary",
    "indirect_prompt_injection": "Indirect Prompt Injection",
    "context_injection": "Context / History Injection",
}


def build_report():
    with open("redteam_report.json", "r", encoding="utf-8") as f:
        results = json.load(f)

    n = len(results)
    vulnerable = [r for r in results if r.get("vulnerable") is True]
    safe = [r for r in results if r.get("vulnerable") is False]
    unknown = [r for r in results if r.get("vulnerable") is None]

    lines = []
    lines.append("# SmartDesk AI -- Security Red Team Report\n")
    lines.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n")
    lines.append(
        "This report summarizes an automated red-team assessment of SmartDesk AI, "
        "testing for prompt injection, sensitive information disclosure, excessive "
        "agency, and indirect/context injection -- categories drawn from the "
        "OWASP Top 10 for LLM Applications.\n"
    )

    lines.append("## Summary\n")
    lines.append(f"| Metric | Count |\n|---|---|\n")
    lines.append(f"| Total attacks run | {n} |\n")
    lines.append(f"| Vulnerable | {len(vulnerable)} |\n")
    lines.append(f"| Safe / resisted | {len(safe)} |\n")
    lines.append(f"| Could not judge | {len(unknown)} |\n")
    lines.append(f"| **Resistance rate** | **{(len(safe) / n * 100) if n else 0:.0f}%** |\n\n")

    by_category = {}
    for r in results:
        by_category.setdefault(r["category"], []).append(r)

    lines.append("## Results by category\n")
    lines.append("| Category | Tested | Vulnerable | Resistance rate |\n|---|---|---|---|\n")
    for cat, items in by_category.items():
        vuln_count = sum(1 for r in items if r.get("vulnerable") is True)
        rate = (1 - vuln_count / len(items)) * 100 if items else 0
        label = CATEGORY_LABELS.get(cat, cat)
        lines.append(f"| {label} | {len(items)} | {vuln_count} | {rate:.0f}% |\n")
    lines.append("\n")

    if vulnerable:
        lines.append("## ⚠️ Vulnerabilities found\n")
        for r in vulnerable:
            lines.append(f"### {r['id']} ({CATEGORY_LABELS.get(r['category'], r['category'])})\n")
            lines.append(f"**Goal:** {r['goal']}\n\n")
            lines.append(f"**Confidence:** {r.get('confidence', 'n/a')}\n\n")
            lines.append(f"**Judge reasoning:** {r.get('reasoning', 'n/a')}\n\n")
            lines.append(f"**Agent's response:**\n> {r['response'][:500]}\n\n")
            lines.append("---\n\n")
    else:
        lines.append("## ✅ No vulnerabilities found\n")
        lines.append("The agent correctly resisted all attacks in this test suite.\n\n")

    lines.append("## All test cases (full detail)\n")
    lines.append("| ID | Type | Category | Result | Confidence |\n|---|---|---|---|---|\n")
    for r in results:
        result_label = "⚠️ VULNERABLE" if r.get("vulnerable") is True else (
            "✅ safe" if r.get("vulnerable") is False else "❓ unknown"
        )
        lines.append(
            f"| {r['id']} | {r['type']} | {CATEGORY_LABELS.get(r['category'], r['category'])} "
            f"| {result_label} | {r.get('confidence', 'n/a')} |\n"
        )

    with open("SECURITY_REPORT.md", "w", encoding="utf-8") as f:
        f.writelines(lines)

    print(f"Report written to SECURITY_REPORT.md")
    print(f"Resistance rate: {(len(safe) / n * 100) if n else 0:.0f}% ({len(safe)}/{n} attacks resisted)")


if __name__ == "__main__":
    build_report()
