# Security Benchmark Report

**Generated:** 2026-08-28 03:53:56 UTC
**Scanner:** analyze_source (deterministic engine + Python AST parser)
**Benchmark root:** `/Users/oskrcjx/Appsec Projects/ai-security-assistant/evaluation/holdout4`

## Summary

- **Total cases:** 100
- **Vulnerable (positive):** 50
- **Safe (negative):** 50

## Overall metrics

| Metric | Value |
| --- | ---: |
| TP | 46 |
| TN | 47 |
| FP | 3 |
| FN | 4 |
| Precision | 0.939 |
| Recall | 0.920 |
| F1 | 0.929 |
| False-positive rate | 0.060 |
| Accuracy | 0.930 |

## Per-class metrics

| Class | TP | TN | FP | FN | Precision | Recall | F1 | FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| file_upload | 10 | 10 | 0 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| idor | 9 | 10 | 0 | 1 | 1.000 | 0.900 | 0.947 | 0.000 |
| sql_injection | 8 | 10 | 0 | 2 | 1.000 | 0.800 | 0.889 | 0.000 |
| ssrf | 10 | 10 | 0 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| xss | 9 | 8 | 2 | 1 | 0.818 | 0.900 | 0.857 | 0.200 |

## Failures (FP / FN)

### u4_sqli_v_conditional_fragment (FN)

- **Expected vulnerable:** True
- **Expected issue type:** `sql_injection`
- **Actual issue types:** `[]`
- **Primary issue:** `None`
- **Scanner rules/findings:** `[]`

### u4_sqli_v_alias_like_chain (FN)

- **Expected vulnerable:** True
- **Expected issue type:** `sql_injection`
- **Actual issue types:** `[]`
- **Primary issue:** `None`
- **Scanner rules/findings:** `[]`

### u4_xss_v_multihop_return_html (FN)

- **Expected vulnerable:** True
- **Expected issue type:** `xss`
- **Actual issue types:** `[]`
- **Primary issue:** `None`
- **Scanner rules/findings:** `[]`

### u4_xss_s_static_markup_banner (FP)

- **Expected vulnerable:** False
- **Expected issue type:** `None`
- **Actual issue types:** `['xss']`
- **Primary issue:** `xss`
- **Scanner rules/findings:** `['xss']`

### u4_xss_s_render_template_file (FP)

- **Expected vulnerable:** False
- **Expected issue type:** `None`
- **Actual issue types:** `['xss']`
- **Primary issue:** `xss`
- **Scanner rules/findings:** `['xss']`

### u4_idor_v_ticket_key_filter (FN)

- **Expected vulnerable:** True
- **Expected issue type:** `idor`
- **Actual issue types:** `[]`
- **Primary issue:** `None`
- **Scanner rules/findings:** `[]`

_Deterministic benchmark — scanner rules were not modified for this run._
