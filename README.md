# Digital Forensics — Windows 11 Insider Investigation

A case study in host-based digital forensics: investigating a Windows 11 workstation
for evidence of unauthorized access and data exfiltration by a suspected insider, using
industry-standard methodology and open-source tooling.

> Scenario-based lab. The organization ("ABC Tech") and all data are fictional/synthetic.

## Scenario

Senior management suspected an employee had improperly accessed and exfiltrated
proprietary information in violation of the Acceptable Use Policy and NDA. Legal approved
a forensic examination of the employee's workstation. The objective: acquire the disk
image, recover deleted/hidden files, analyze logs and registry, examine browser activity,
and determine whether internal policy was violated — while preserving evidentiary integrity.

## Methodology

The investigation followed recognized forensic standards end-to-end:

1. **Acquisition & verification** — hash-verify the provided disk image before analysis to
   prove it was unaltered (integrity baseline for chain of custody).
2. **Case setup** — created a case in **Autopsy 4.22.0**, documented examiner, case number,
   and evidence location.
3. **Ingest & indexing** — loaded the `.001` raw image and ran Autopsy ingest modules.
4. **Artifact analysis** — systematically reviewed the artifact categories below.
5. **Timeline reconstruction** — correlated file, log, and registry timestamps to establish
   a sequence of events, including after-hours activity.
6. **Reporting** — generated an HTML evidence report and a written findings summary.

**Frameworks applied:** NIST SP 800-86 (integrating forensics into IR), NIST SP 800-61 Rev. 2
(incident handling), ISO/IEC 27037 (evidence handling). **Legal context:** Computer Fraud and
Abuse Act (CFAA) and Electronic Communications Privacy Act (ECPA).

## Artifacts examined (and why)

| # | Artifact | Location | Investigative value |
|---|---|---|---|
| 1 | Security event logs | `Windows/System32/winevt/Logs/Security.evtx` | Successful/failed logins, cached-credential use, spray attempts |
| 2 | System event log | `.../winevt/Logs/System.evtx` | Uptime, hardware/device activity, network changes |
| 3 | `todo.docx` | `Users/…/Documents` | Possible planning/intent document |
| 4 | `logger.exe` | `Users/…/Downloads` | Unauthorized executable — potential credential/keystroke logger |
| 5 | Correspondence `.txt` | `Users/…/Desktop` | Notes on how to send exfiltrated data |
| 6 | Browser cookies | `.../Edge/UserData/Default/Network` | Sites visited, logins, downloads |
| 7 | Browser history | `.../Chrome/User Data/Default` | Email / file-sharing / cloud access |
| 8 | Prefetch | `Windows/Prefetch` | Which executables ran, how often, resources touched |
| 9 | SetupAPI log | `Windows/INF` | Removable/USB hardware install history |
| 10 | Thumbnail cache | `.../Explorer` | Reconstruct recent (incl. deleted) file access |

## Findings

Recovered artifacts were consistent with **intentional unauthorized access and preparation
for exfiltration**: a deleted to-do list of information to gather, a correspondence file
describing how to send data out, browser artifacts showing access to file-sharing/anonymizing
resources, an unapproved executable, and timeline evidence of after-hours access and file
deletion. Direct exfiltration could not be confirmed without network logs, but the host
evidence clearly supported violations of the organization's data-security policy.

## What's in this repo

- `README.md` — this case study.
- `scripts/verify_and_timeline.py` — a Python tool that reproduces two core forensic steps
  on any evidence folder: (1) hash every file (MD5 + SHA-256) to build an integrity manifest,
  and (2) build a chronological access/modify timeline. Demonstrates the *concepts* the lab
  performed in Autopsy, in code.
- `scripts/sample_output.txt` — example run output.
- `docs/chain-of-custody-template.md` — a reusable evidence log.

## Running the tool

```bash
python3 scripts/verify_and_timeline.py ./sample_evidence --manifest manifest.csv --timeline timeline.csv
```

No third-party dependencies (standard library only).

## Skills demonstrated

Evidence acquisition & hash verification · Windows artifact analysis (event logs, prefetch,
registry, browser, USB) · timeline reconstruction · chain of custody · forensic reporting ·
mapping technical findings to legal/policy violations.
