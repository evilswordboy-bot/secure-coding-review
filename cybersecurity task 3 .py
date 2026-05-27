import re
from collections import defaultdict


class SecureCodeReviewer:

    def __init__(self):

        self.patterns = {
            "Hardcoded Password":
                r'password\s*=\s*[\'"].+[\'"]',

            "Possible SQL Injection":
                r'execute\s*\(.+\+.+\)',

            "Dangerous eval()":
                r'eval\s*\(',

            "Dangerous exec()":
                r'exec\s*\(',

            "OS Command Injection":
                r'os\.system\s*\(',

            "Debug Enabled":
                r'debug\s*=\s*True'
        }

        self.results = []

    def scan_file(self, file_path):

        print("\n[+] Scanning:", file_path)

        try:
            with open(file_path, "r", encoding="utf-8") as file:
                lines = file.readlines()

            for line_num, line in enumerate(lines, start=1):

                for vuln_name, pattern in self.patterns.items():

                    if re.search(pattern, line):

                        result = {
                            "line": line_num,
                            "issue": vuln_name,
                            "code": line.strip()
                        }

                        self.results.append(result)

                        print(f"[!] {vuln_name}")
                        print(f"    Line: {line_num}")
                        print(f"    Code: {line.strip()}\n")

        except FileNotFoundError:
            print("[ERROR] File not found")

        except Exception as e:
            print("[ERROR]", e)

    def summary(self):

        print("\n========== SUMMARY ==========")

        if not self.results:
            print("No major vulnerabilities detected.")
            return

        counts = defaultdict(int)

        for item in self.results:
            counts[item["issue"]] += 1

        for issue, count in counts.items():
            print(f"{issue}: {count}")

        print(f"\nTotal Issues: {len(self.results)}")


# MAIN

reviewer = SecureCodeReviewer()

path = input("Enter Python file path: ")

reviewer.scan_file(path)

reviewer.summary()
