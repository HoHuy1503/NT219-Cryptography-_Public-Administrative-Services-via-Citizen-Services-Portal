Demo local private key layout

pki/ca_key.pem, pki/ca_cert.pem
  PKI CA private key/cert used by doc_service through Docker mount.

officer_ca/ca_key.pem, officer_ca/ca_cert.pem
  Demo CA bucket for officer-side experiments. Not part of production PKI trust by default.

thirdparty_ca/ca_key.pem, thirdparty_ca/ca_cert.pem
  Demo CA bucket for thirdparty-side experiments. Not part of production PKI trust by default.

officers/<officer_id>/signing_private.pem
  Officer business signing private key used by the portal helper.

officers/<officer_id>/mtls_private.pem
  Officer mTLS private key generated during demo enrollment.

thirdparties/<thirdparty_id>/mtls_private.pem
  Thirdparty mTLS private key generated during demo enrollment.
