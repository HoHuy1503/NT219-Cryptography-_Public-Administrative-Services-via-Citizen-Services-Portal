# RESULTS.md — Ket Qua Evaluation
# NT219 Topic 11

## Bang Metric Tong Hop
| Nhom  | Metric              | Eval  | Nguong    | Ket qua | Status |
|-------|---------------------|-------|-----------|---------|--------|
| Crypto| Plaintext leakage   | E-C1  | 0 byte    | 0 byte  | PASS   |
| Crypto| Nonce reuse         | E-C2  | 0         | 0       | PASS   |
| Crypto| Tamper detection    | E-C3  | 100%      | 100/100 | PASS   |
| AuthN | Login success rate  | E-N1  | >=99%     | 100%    | PASS   |
| AuthN | False-accept rate   | E-N1  | 0%        | 0%      | PASS   |
| AuthN | QR replay block     | E-N2  | 100%      | 50/50   | PASS   |
| AuthZ | Policy pass-rate    | E-Z1  | >=95%     | 100%    | PASS   |
| AuthZ | Token hardening     | E-Z2  | 100%      | 100%    | PASS   |
| Key   | Rotation time       | E-X1  | <=10 phut | 2s      | PASS   |
| Obs   | Explainability      | E-X2  | 100%      | 20/20   | PASS   |

## Ket Luan Invariants
| Invariant | Khang dinh                          | Dat? | Bang chung |
|-----------|-------------------------------------|------|------------|
| I1        | 0 byte plaintext ro ri              | PASS | EVIDENCE/pcaps/e-c1-capture.pcap |
| I2        | Tamper bi tu choi + co log          | PASS | EVAL/E-C/E-C3-result.json |
| I3        | Toan ven tai lieu sau ky            | PASS | EVAL/E-C/E-C3-result.json |
| I4        | AuthN false-accept = 0              | PASS | EVAL/E-N/E-N1-result.json |
| I5        | AuthZ explainable theo deny_reason  | PASS | EVAL/E-Z/E-Z1-result.json, EVAL/E-X/E-X2-result.json |
| I6        | Key rotate <= 10 phut               | PASS | EVAL/E-X/E-X1-result.json |
| I7        | QR nonce single-use                 | PASS | EVAL/E-N/E-N2-result.json |

## Ghi chu cap nhat
- Sau khi chay EVAL/run_all_evals.sh, thay cac muc TBD bang PASS/FAIL theo tung file JSON.
- Co the tong hop nhanh bang lenh: jq -r '.eval_id + ": " + .status' EVAL/E-*/E-*-result.json
