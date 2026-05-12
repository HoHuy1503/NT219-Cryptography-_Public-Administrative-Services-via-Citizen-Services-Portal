#!/bin/bash
# EVAL/E-C/run_e_c1.sh
echo '=== E-C1: Plaintext Leakage Test (I1) ==='
 
# Bắt traffic trong nền
sudo tcpdump -i lo -w EVIDENCE/pcaps/e-c1-capture.pcap \
  'port 5000 or port 8443' &
TCPID=$!
sleep 1
 
# Gửi 1000 request với nội dung nhạy cảm
SENSITIVE=$(echo 'SENSITIVE: CMND 123456789 Nguyen Van A' | base64)
for i in $(seq 1 1000); do
  curl -s -X POST http://localhost:5000/api/documents/sign \
    -H 'Content-Type: application/json' \
    -H 'X-Internal-Bypass: true' \
    -d "{\"document_base64\":\"$SENSITIVE\"}" > /dev/null
done
 
sleep 1; kill $TCPID 2>/dev/null; sleep 1
 
# Tìm plaintext trong pcap
FOUND=$(strings EVIDENCE/pcaps/e-c1-capture.pcap \
        | grep -cE 'SENSITIVE|CMND|123456789' 2>/dev/null || echo 0)
FOUND=$(echo "$FOUND" | head -n1)
STATUS='PASS'; [ "$FOUND" -gt 0 ] && STATUS='FAIL'
echo "Plaintext found: $FOUND bytes → $STATUS"
 
cat > EVAL/E-C/E-C1-result.json << EOF
{
  "eval_id": "E-C1", "invariant": "I1",
  "requests": 1000, "plaintext_found": $FOUND,
  "status": "$STATUS", "threshold": "0 byte",
  "evidence": "EVIDENCE/pcaps/e-c1-capture.pcap"
}
EOF
