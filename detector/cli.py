import json
import sys
from pathlib import Path

# Safe encoding reconfiguration for Windows console
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure project root is in sys.path regardless of where this script is executed from
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from detector.detector import analyze_email


def read_multiline_input() -> str:
    """Read multiline email text from stdin until EOF or 'END' on an empty line."""
    if not sys.stdin.isatty():
        # Input is piped or redirected
        return sys.stdin.read()

    print("Paste your email text below.")
    print("When finished, type 'END' on a new line or press Ctrl+Z then Enter:")
    print("-" * 65)

    lines = []
    while True:
        try:
            line = input()
            if line.strip() == "END":
                break
            lines.append(line)
        except EOFError:
            break

    return "\n".join(lines)


def format_cli_output(text: str, findings: list) -> None:
    """Format and print email screening results nicely in the terminal."""
    total_chars = len(text)
    total_lines = len(text.splitlines()) if text else 0

    print("\n" + "=" * 70)
    print("                 [PHISHINGGUARD EMAIL DETECTOR]")
    print("=" * 70)
    print(f" Analyzed: {total_lines} line(s), {total_chars} character(s)")

    if not findings:
        print(" Result:   [OK] No suspicious patterns detected (Email appears clean).")
        print("=" * 70 + "\n")
        return

    print(f" Result:   [!] {len(findings)} suspicious pattern(s) flagged!")
    print("-" * 70)

    severity_badges = {
        "high": "[HIGH RISK]  ",
        "medium": "[MED RISK]   ",
        "low": "[LOW RISK]   ",
    }

    for idx, f in enumerate(findings, 1):
        sev = f.get("severity", "medium").lower()
        badge = severity_badges.get(sev, "[ALERT]      ")
        weight = f.get("weight", 0.0)
        warning = f.get("warning", "Suspicious pattern")
        matched = f.get("text", f.get("matched_text", ""))
        line_num = f.get("line_number", f.get("line", 1))
        line_context = f.get("line", "")
        explanation = f.get("explanation", "")

        print(f"\n[{idx}] {badge} {warning.upper()} (Score: {weight:.2f})")
        print(f"    - Line Number : {line_num}")
        print(f"    - Flagged Text: \"{matched}\"")
        if line_context and line_context != line_num:
            print(f"    - Line Context: {line_context.strip()}")
        print(f"    - Explanation : {explanation}")

    print("\n" + "=" * 70 + "\n")


def interactive_loop():
    """Run an interactive CLI session."""
    while True:
        email_content = read_multiline_input()
        if not email_content.strip():
            print("\n[!] Empty text received. Nothing to analyze.")
        else:
            findings = analyze_email(email_content)
            format_cli_output(email_content, findings)

        if not sys.stdin.isatty():
            # If input was piped, run once and exit
            break

        try:
            choice = input("Analyze another email? (y/n) [default: y]: ").strip().lower()
            if choice in ["n", "no", "exit", "quit", "q"]:
                print("\nGoodbye! Stay safe online.\n")
                break
            print("\n" + "-" * 70 + "\n")
        except (KeyboardInterrupt, EOFError):
            print("\n\nGoodbye!\n")
            break


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ["--json", "-j"]:
        raw_text = read_multiline_input()
        results = analyze_email(raw_text)
        print(json.dumps(results, indent=2))
    else:
        interactive_loop()
