import re
from collections import defaultdict
from tkinter import Tk, Button, Text, filedialog, END, Label

def analyze_logs(file_path, output_box):
    failed_logins = defaultdict(int)
    success_logins = defaultdict(int)

    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

    try:
        with open(file_path, "r") as file:
            for line in file:
                ip = re.findall(ip_pattern, line)

                if ip:
                    ip = ip[0]

                    # Failed login
                    if "Failed password" in line or "failed login" in line:
                        failed_logins[ip] += 1

                    # Successful login
                    if "Accepted password" in line or "login success" in line:
                        success_logins[ip] += 1

        output_box.delete(1.0, END)
        output_box.insert(END, "=== SOC Analysis Report ===\n\n")

        report_lines = []
        report_lines.append("=== SOC Analysis Report ===\n")

        for ip in failed_logins:
            failed = failed_logins[ip]
            success = success_logins[ip]

            if failed >= 3:
                # TP/FP Logic
                if success > 0:
                    status = "FALSE POSITIVE (User eventually logged in)"
                else:
                    status = "TRUE POSITIVE (Likely brute force attack)"

                msg = f"[ALERT] IP: {ip} | Failed: {failed} | Success: {success} | {status}\n"

                output_box.insert(END, msg)
                report_lines.append(msg)

        if len(report_lines) == 1:
            output_box.insert(END, "No suspicious activity detected.\n")
            report_lines.append("No suspicious activity detected.\n")

        # Save report
        with open("soc_report.txt", "w") as report:
            report.writelines(report_lines)

        output_box.insert(END, "\nReport saved as soc_report.txt\n")

    except Exception as e:
        output_box.insert(END, f"Error: {str(e)}\n")


def select_file():
    file_path = filedialog.askopenfilename(title="Select Log File")
    if file_path:
        analyze_logs(file_path, output_box)


# GUI
root = Tk()
root.title("SOC Analyzer - TP/FP Detection")
root.geometry("700x450")

Label(root, text="SOC Log Analyzer (TP/FP + Report)", font=("Arial", 16)).pack(pady=10)

Button(root, text="Import Log File", command=select_file).pack(pady=10)

output_box = Text(root, height=18, width=80)
output_box.pack(pady=10)

root.mainloop()