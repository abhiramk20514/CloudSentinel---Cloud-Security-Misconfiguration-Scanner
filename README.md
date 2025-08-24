# CloudSentinel – Cloud Security Misconfiguration Scanner

CloudSentinel is a Python-based security tool that audits cloud configurations for misconfigurations, exposed resources, and security risks. The tool generates detailed HTML reports highlighting potential vulnerabilities and remediation suggestions.

---

## Project Title
CloudSentinel – Cloud Security Misconfiguration Scanner

---

## Developed By
**K. SAI ABHIRAM**  
B.Tech Cyber Security  
VIT-AP University

---

## Objective
This project aims to detect common cloud misconfigurations that can lead to security breaches. The tool enables:

- Detection of publicly exposed storage buckets  
- Identification of IAM users with excessive privileges  
- Detection of unencrypted resources (storage/services)  
- Identification of overly permissive security groups (0.0.0.0/0)  
- Generation of HTML reports for analysis and documentation  

---

## Requirements
- Python 3.8 or higher  

---

## Install Dependencies
```bash
pip install -r requirements.txt
```
*(No external libraries required for core functionality if using only standard library)*  

---

## How to Run

**Step 1: Clone the Repository**
```bash
git clone <your-repo-url>
cd CloudSentinel
```

**Step 2: Run the Scanner**
```bash
python3 cloudscan.py sample_config.json --report report.html
```

**Optional Arguments:**
- `--json findings.json` → Export findings in JSON  
- `--min-severity MEDIUM` → Filter out low severity findings  

---

## Features
- Detects publicly exposed cloud storage buckets  
- Flags IAM roles/users with administrative privileges  
- Checks for missing encryption on resources  
- Detects overly permissive security groups  
- Generates detailed HTML reports with severity levels  

---

## Example Report
- Report is saved as `report.html` in the project directory  
- Open in any browser to view results  

*(Add screenshots in `screenshots/report.png` for GitHub preview)*  

---

## Tech Stack
- Python 3  
- JSON parsing  
- HTML report generation  

---

## Future Enhancements
- Direct integration with AWS, Azure, and GCP APIs  
- PDF report generation  
- CI/CD integration for continuous security audits  

---

## Project Structure
```
CloudSentinel/
├── cloudscan.py           # Core scanner logic
├── sample_config.json     # Example configuration with intentional misconfigs
├── report.html            # Example report after running scanner
├── README.md              # README FILE
```

---

## GitHub Repository
`<your-repo-url>`

---

## Final Output
A Python tool that audits cloud configurations for misconfigurations, generates prioritized reports, and suggests remediation steps.  

---

## Student Info
Name: K. SAI ABHIRAM  
University: VIT-AP University  

---

## Thank You

