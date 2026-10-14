# B02 DEV/original SAST comparison

Target: `5658473cf8814459bf89000ce373b20ed0b4eb37`; Semgrep CE `1.174.0`.
Profile: `juice-shop-v2`; raw alerts/scope equivalent for agent and baseline: **True**.
Repeat-run parser diagnostics identical: **False** (timeouts may vary).

| Profile | TP | FP | FN | TN | Precision | Recall | Duplicates | Unresolved | Outside GT | Alerts | Parser diagnostics |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| a06_before | 1 | 0 | 19 | 2 | 1.0 | 0.05 | 1 | 0 | 73 | 75 | 61 |
| b02_agent | 7 | 0 | 13 | 2 | 1.0 | 0.35 | 3 | 0 | 88 | 98 | 61 |
| b02_baseline | 7 | 0 | 13 | 2 | 1.0 | 0.35 | 3 | 0 | 88 | 98 | 61 |

## Family cases: TP / FP / FN / TN

- `access-control`: a06_before 0/0/4/0; b02_agent 0/0/4/0
- `authentication`: a06_before 0/0/1/0; b02_agent 0/0/1/0
- `authorization`: a06_before 0/0/0/1; b02_agent 0/0/0/1
- `business-logic`: a06_before 0/0/2/0; b02_agent 0/0/2/0
- `code-evaluation`: a06_before 0/0/1/0; b02_agent 1/0/0/0
- `file-validation`: a06_before 0/0/1/0; b02_agent 0/0/1/0
- `nosql-injection`: a06_before 0/0/2/0; b02_agent 1/0/1/0
- `open-redirect`: a06_before 1/0/0/0; b02_agent 1/0/0/0
- `path-traversal`: a06_before 0/0/1/1; b02_agent 1/0/0/1
- `rate-limiting`: a06_before 0/0/1/0; b02_agent 0/0/1/0
- `sensitive-data-exposure`: a06_before 0/0/1/0; b02_agent 0/0/1/0
- `ssrf`: a06_before 0/0/1/0; b02_agent 1/0/0/0
- `weak-cryptography`: a06_before 0/0/1/0; b02_agent 1/0/0/0
- `xml-external-entities`: a06_before 0/0/1/0; b02_agent 1/0/0/0
- `xss`: a06_before 0/0/2/0; b02_agent 0/0/2/0

SAST alerts are detection candidates only; this report contains zero Evidence-backed confirmations.
The two DEV/original safe controls are included as negative cases. No holdout slice is scored.
Raw JSON and stderr are retained under `raw/`; parser warnings and partial parse coverage remain visible.
