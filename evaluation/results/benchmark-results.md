# Security Benchmark Report

**Generated:** 2026-08-28 00:06:29 UTC
**Scanner:** analyze_source (deterministic engine + Python AST parser)
**Benchmark root:** `/Users/oskrcjx/Appsec Projects/ai-security-assistant/evaluation/benchmark`

## Summary

- **Total cases:** 60
- **Vulnerable (positive):** 30
- **Safe (negative):** 30

## Overall metrics

| Metric | Value |
| --- | ---: |
| TP | 24 |
| TN | 26 |
| FP | 4 |
| FN | 6 |
| Precision | 0.857 |
| Recall | 0.800 |
| F1 | 0.828 |
| False-positive rate | 0.133 |
| Accuracy | 0.833 |

## Per-class metrics

| Class | TP | TN | FP | FN | Precision | Recall | F1 | FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| file_upload | 6 | 5 | 1 | 0 | 0.857 | 1.000 | 0.923 | 0.167 |
| idor | 5 | 6 | 0 | 1 | 1.000 | 0.833 | 0.909 | 0.000 |
| sql_injection | 6 | 6 | 0 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| ssrf | 5 | 4 | 2 | 1 | 0.714 | 0.833 | 0.769 | 0.333 |
| xss | 2 | 5 | 1 | 4 | 0.667 | 0.333 | 0.444 | 0.167 |

## Failures (FP / FN)

### xss-vuln_template_string (FN)

- **Expected vulnerable:** True
- **Expected issue type:** `xss`
- **Actual issue types:** `[]`
- **Primary issue:** `None`
- **Scanner rules/findings:** `[]`

### xss-vuln_markup_concat (FN)

- **Expected vulnerable:** True
- **Expected issue type:** `xss`
- **Actual issue types:** `[]`
- **Primary issue:** `None`
- **Scanner rules/findings:** `[]`

### xss-vuln_unescaped_variable (FN)

- **Expected vulnerable:** True
- **Expected issue type:** `xss`
- **Actual issue types:** `[]`
- **Primary issue:** `None`
- **Scanner rules/findings:** `[]`

### xss-vuln_url_in_html (FN)

- **Expected vulnerable:** True
- **Expected issue type:** `xss`
- **Actual issue types:** `[]`
- **Primary issue:** `None`
- **Scanner rules/findings:** `[]`

### xss-safe_markupsafe_escape (FP)

- **Expected vulnerable:** False
- **Expected issue type:** `None`
- **Actual issue types:** `['xss']`
- **Primary issue:** `xss`
- **Scanner rules/findings:** `['xss']`

### ssrf-vuln_session_url (FN)

- **Expected vulnerable:** True
- **Expected issue type:** `ssrf`
- **Actual issue types:** `[]`
- **Primary issue:** `None`
- **Scanner rules/findings:** `[]`

### ssrf-safe_allowlist_host (FP)

- **Expected vulnerable:** False
- **Expected issue type:** `None`
- **Actual issue types:** `['ssrf']`
- **Primary issue:** `ssrf`
- **Scanner rules/findings:** `['ssrf']`

### ssrf-safe_validated_scheme (FP)

- **Expected vulnerable:** False
- **Expected issue type:** `None`
- **Actual issue types:** `['ssrf']`
- **Primary issue:** `ssrf`
- **Scanner rules/findings:** `['ssrf']`

### file_upload-safe_reject_executable (FP)

- **Expected vulnerable:** False
- **Expected issue type:** `None`
- **Actual issue types:** `['file_upload']`
- **Primary issue:** `file_upload`
- **Scanner rules/findings:** `['file_upload']`

### idor-vuln_path_id (FN)

- **Expected vulnerable:** True
- **Expected issue type:** `idor`
- **Actual issue types:** `[]`
- **Primary issue:** `None`
- **Scanner rules/findings:** `[]`

_Deterministic benchmark — scanner rules were not modified for this run._
