# Check HTTPS Protocol

Scripts that audit a list of URLs for **obsolete cryptographic protocols**
(SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1) and generate a **tab-separated CSV report**.

---

## Scripts disponibles

| Script | Plateforme | Dépendances |
|--------|------------|-------------|
| `check_https_protocols.sh` | Linux / macOS | `bash`, `openssl`, `curl` |
| `check_https_protocols.ps1` | PowerShell 7+ | APIs .NET natives uniquement |

---

## Requirements

| Tool | Purpose |
|------|---------|
| `openssl` | SSL/TLS protocol testing |
| `curl` | HTTP response code retrieval |
| `bash` ≥ 4 | Script execution |

> `openssl` and `curl` are pre-installed on most Linux/macOS systems.

---

## Bash usage

```bash
chmod +x check_https_protocols.sh
./check_https_protocols.sh <url_file> [output_file]
```

| Argument | Description |
|----------|-------------|
| `url_file` | Text file with one URL per line (required) |
| `output_file` | Path for the CSV report (optional — defaults to `report_YYYYMMDD_HHMMSS.csv`) |

### Examples

```bash
# Use default output filename
./check_https_protocols.sh urls.txt

# Specify custom output filename
./check_https_protocols.sh urls.txt results.csv
```

---

## PowerShell usage

```powershell
pwsh -File ./check_https_protocols.ps1 <url_file> [output_file]
```

| Argument | Description |
|----------|-------------|
| `url_file` | Text file with one URL per line (required) |
| `output_file` | Path for the CSV report (optional — defaults to `report_YYYYMMDD_HHMMSS.csv`) |

### Examples

```powershell
# Use default output filename
pwsh -File ./check_https_protocols.ps1 .\urls.txt

# Specify custom output filename
pwsh -File ./check_https_protocols.ps1 .\urls.txt .\results.csv
```

The PowerShell script uses only native .NET / `System.Net` APIs and does not
require `openssl`, `curl`, or any other external tool.

---

## Input file format

One URL (or hostname) per line. Lines starting with `#` and blank lines are ignored.

```
# My servers
google.com
https://github.com
alma.uqtr.ca
192.0.2.1
```

A sample file is included: [`sample_urls.txt`](sample_urls.txt).

---

## CSV report format

The report uses **tab** as the column separator.

| Column | Description |
|--------|-------------|
| `URL` | Hostname extracted from the input |
| `SSL 2.0` | `TRUE` / `FALSE` / `N/A`* |
| `SSL 3.0` | `TRUE` / `FALSE` / `N/A`* |
| `TLS 1.0` | `TRUE` / `FALSE` / `N/A`* |
| `TLS 1.1` | `TRUE` / `FALSE` / `N/A`* |
| `SECURED` | `TRUE` if no obsolete protocol is accepted, `FALSE` otherwise |
| `REPONSE HTTP` | HTTP status code returned over HTTPS (e.g. `200`, `301`) |
| `ERREUR` | Error message if the host is unreachable or DNS fails |

\* `N/A` is reported when the local TLS stack cannot test that protocol
(common for obsolete protocols on modern systems).

### Example output

```
URL             SSL 2.0  SSL 3.0  TLS 1.0  TLS 1.1  SECURED  REPONSE HTTP  ERREUR
alma.uqtr.ca    TRUE     TRUE     FALSE    TRUE     FALSE    200
badhost.local   FALSE    FALSE    FALSE    FALSE    TRUE                   Le DNS ne résout pas
```

---

## Notes

- Only **port 443** is tested.
- The `SECURED` column is `TRUE` only when **all four** obsolete protocols are
  rejected by the server.
- Modern TLS stacks may refuse to negotiate obsolete protocols locally; those
  columns will show `N/A` in that case, meaning they cannot be tested from the
  current machine — not that the server supports them.
- Hosts that fail DNS resolution or TCP connection to port 443 are skipped for
  protocol tests; an error message is written to the `ERREUR` column.
