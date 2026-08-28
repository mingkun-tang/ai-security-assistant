# Security Benchmark Report

**Generated:** 2026-08-28 02:08:29 UTC
**Scanner:** analyze_source (deterministic engine + Python AST parser)
**Benchmark root:** `/Users/oskrcjx/Appsec Projects/ai-security-assistant/evaluation/holdout2`

## Summary

- **Total cases:** 100
- **Vulnerable (positive):** 50
- **Safe (negative):** 50

## Overall metrics

| Metric | Value |
| --- | ---: |
| TP | 39 |
| TN | 42 |
| FP | 8 |
| FN | 11 |
| Precision | 0.830 |
| Recall | 0.780 |
| F1 | 0.804 |
| False-positive rate | 0.160 |
| Accuracy | 0.810 |

## Per-class metrics

| Class | TP | TN | FP | FN | Precision | Recall | F1 | FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| file_upload | 5 | 9 | 1 | 5 | 0.833 | 0.500 | 0.625 | 0.100 |
| idor | 8 | 7 | 3 | 2 | 0.727 | 0.800 | 0.762 | 0.300 |
| sql_injection | 8 | 10 | 0 | 2 | 1.000 | 0.800 | 0.889 | 0.000 |
| ssrf | 9 | 6 | 4 | 1 | 0.692 | 0.900 | 0.783 | 0.400 |
| xss | 9 | 10 | 0 | 1 | 1.000 | 0.900 | 0.947 | 0.000 |

## Failures (FP / FN)

### u2_sqli_v_extra_where_list (FN)

- **Expected vulnerable:** True
- **Expected issue type:** `sql_injection`
- **Actual issue types:** `[]`
- **Primary issue:** `None`
- **Scanner rules/findings:** `[]`

### u2_sqli_v_loop_join_fragments (FN)

- **Expected vulnerable:** True
- **Expected issue type:** `sql_injection`
- **Actual issue types:** `[]`
- **Primary issue:** `None`
- **Scanner rules/findings:** `[]`

### u2_xss_v_list_join_tags (FN)

- **Expected vulnerable:** True
- **Expected issue type:** `xss`
- **Actual issue types:** `[]`
- **Primary issue:** `None`
- **Scanner rules/findings:** `[]`

### u2_ssrf_v_aiohttp_session (FN)

- **Expected vulnerable:** True
- **Expected issue type:** `ssrf`
- **Actual issue types:** `[]`
- **Primary issue:** `None`
- **Scanner rules/findings:** `[]`

### u2_ssrf_s_allowlist_netloc (FP)

- **Expected vulnerable:** False
- **Expected issue type:** `None`
- **Actual issue types:** `['ssrf']`
- **Primary issue:** `ssrf`
- **Scanner rules/findings:** `['ssrf']`

### u2_ssrf_s_https_only_scheme (FP)

- **Expected vulnerable:** False
- **Expected issue type:** `None`
- **Actual issue types:** `['ssrf']`
- **Primary issue:** `ssrf`
- **Scanner rules/findings:** `['ssrf']`

### u2_ssrf_s_block_private_ip (FP)

- **Expected vulnerable:** False
- **Expected issue type:** `None`
- **Actual issue types:** `['ssrf']`
- **Primary issue:** `ssrf`
- **Scanner rules/findings:** `['ssrf']`

### u2_ssrf_s_fixed_path_append (FP)

- **Expected vulnerable:** False
- **Expected issue type:** `None`
- **Actual issue types:** `['ssrf']`
- **Primary issue:** `ssrf`
- **Scanner rules/findings:** `['ssrf']`

### u2_upload_v_shutil_copy (FN)

- **Expected vulnerable:** True
- **Expected issue type:** `file_upload`
- **Actual issue types:** `[]`
- **Primary issue:** `None`
- **Scanner rules/findings:** `[]`

### u2_upload_v_open_write_bytes (FN)

- **Expected vulnerable:** True
- **Expected issue type:** `file_upload`
- **Actual issue types:** `[]`
- **Primary issue:** `None`
- **Scanner rules/findings:** `[]`

### u2_upload_v_pathlib_write (FN)

- **Expected vulnerable:** True
- **Expected issue type:** `file_upload`
- **Actual issue types:** `[]`
- **Primary issue:** `None`
- **Scanner rules/findings:** `[]`

### u2_upload_v_double_name_chain (FN)

- **Expected vulnerable:** True
- **Expected issue type:** `file_upload`
- **Actual issue types:** `[]`
- **Primary issue:** `None`
- **Scanner rules/findings:** `[]`

### u2_upload_v_join_webroot (FN)

- **Expected vulnerable:** True
- **Expected issue type:** `file_upload`
- **Actual issue types:** `[]`
- **Primary issue:** `None`
- **Scanner rules/findings:** `[]`

### u2_upload_s_outside_webroot (FP)

- **Expected vulnerable:** False
- **Expected issue type:** `None`
- **Actual issue types:** `['file_upload']`
- **Primary issue:** `file_upload`
- **Scanner rules/findings:** `['file_upload']`

### u2_idor_v_record_id_param (FN)

- **Expected vulnerable:** True
- **Expected issue type:** `idor`
- **Actual issue types:** `[]`
- **Primary issue:** `None`
- **Scanner rules/findings:** `[]`

### u2_idor_v_filter_username (FN)

- **Expected vulnerable:** True
- **Expected issue type:** `idor`
- **Actual issue types:** `[]`
- **Primary issue:** `None`
- **Scanner rules/findings:** `[]`

### u2_idor_s_guard_before_delete (FP)

- **Expected vulnerable:** False
- **Expected issue type:** `None`
- **Actual issue types:** `['idor']`
- **Primary issue:** `idor`
- **Scanner rules/findings:** `['idor']`

### u2_idor_s_get_with_owner_check (FP)

- **Expected vulnerable:** False
- **Expected issue type:** `None`
- **Actual issue types:** `['idor']`
- **Primary issue:** `idor`
- **Scanner rules/findings:** `['idor']`

### u2_idor_s_admin_role_gate (FP)

- **Expected vulnerable:** False
- **Expected issue type:** `None`
- **Actual issue types:** `['idor']`
- **Primary issue:** `idor`
- **Scanner rules/findings:** `['idor']`

_Deterministic benchmark — scanner rules were not modified for this run._
