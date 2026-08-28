# Security Benchmark Report

**Generated:** 2026-08-28 01:23:14 UTC
**Scanner:** analyze_source (deterministic engine + Python AST parser)
**Benchmark root:** `/Users/oskrcjx/Appsec Projects/ai-security-assistant/evaluation/holdout`

## Summary

- **Total cases:** 50
- **Vulnerable (positive):** 25
- **Safe (negative):** 25

## Overall metrics

| Metric | Value |
| --- | ---: |
| TP | 18 |
| TN | 23 |
| FP | 2 |
| FN | 7 |
| Precision | 0.900 |
| Recall | 0.720 |
| F1 | 0.800 |
| False-positive rate | 0.080 |
| Accuracy | 0.820 |

## Per-class metrics

| Class | TP | TN | FP | FN | Precision | Recall | F1 | FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| file_upload | 4 | 5 | 0 | 1 | 1.000 | 0.800 | 0.889 | 0.000 |
| idor | 4 | 5 | 0 | 1 | 1.000 | 0.800 | 0.889 | 0.000 |
| sql_injection | 4 | 4 | 1 | 1 | 0.800 | 0.800 | 0.800 | 0.200 |
| ssrf | 2 | 4 | 1 | 3 | 0.667 | 0.400 | 0.500 | 0.200 |
| xss | 4 | 5 | 0 | 1 | 1.000 | 0.800 | 0.889 | 0.000 |

## Failures (FP / FN)

### hold_sqli_v_join_fragments (FN)

- **Expected vulnerable:** True
- **Expected issue type:** `sql_injection`
- **Actual issue types:** `[]`
- **Primary issue:** `None`
- **Scanner rules/findings:** `[]`

### hold_sqli_s_orm_filter (FP)

- **Expected vulnerable:** False
- **Expected issue type:** `None`
- **Actual issue types:** `['idor']`
- **Primary issue:** `idor`
- **Scanner rules/findings:** `['idor']`

### hold_xss_v_multihop_reflect (FN)

- **Expected vulnerable:** True
- **Expected issue type:** `xss`
- **Actual issue types:** `[]`
- **Primary issue:** `None`
- **Scanner rules/findings:** `[]`

### hold_ssrf_v_indirect_variable (FN)

- **Expected vulnerable:** True
- **Expected issue type:** `ssrf`
- **Actual issue types:** `[]`
- **Primary issue:** `None`
- **Scanner rules/findings:** `[]`

### hold_ssrf_v_weak_scheme_only (FN)

- **Expected vulnerable:** True
- **Expected issue type:** `ssrf`
- **Actual issue types:** `[]`
- **Primary issue:** `None`
- **Scanner rules/findings:** `[]`

### hold_ssrf_v_urlopen_alias (FN)

- **Expected vulnerable:** True
- **Expected issue type:** `ssrf`
- **Actual issue types:** `[]`
- **Primary issue:** `None`
- **Scanner rules/findings:** `[]`

### hold_ssrf_s_user_url_in_html (FP)

- **Expected vulnerable:** False
- **Expected issue type:** `None`
- **Actual issue types:** `['xss']`
- **Primary issue:** `xss`
- **Scanner rules/findings:** `['xss']`

### hold_upload_v_path_join (FN)

- **Expected vulnerable:** True
- **Expected issue type:** `file_upload`
- **Actual issue types:** `[]`
- **Primary issue:** `None`
- **Scanner rules/findings:** `[]`

### hold_idor_v_json_body_id (FN)

- **Expected vulnerable:** True
- **Expected issue type:** `idor`
- **Actual issue types:** `[]`
- **Primary issue:** `None`
- **Scanner rules/findings:** `[]`

_Deterministic benchmark — scanner rules were not modified for this run._
