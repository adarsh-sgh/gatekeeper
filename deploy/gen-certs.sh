#!/usr/bin/env sh
# Self-signed CA + server + client certs for local mTLS. Usage: gen-certs.sh <outdir>
set -eu
out=${1:-certs}
mkdir -p "$out" && cd "$out"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
  -subj "/CN=gatekeeper-dev-ca" -keyout ca.key -out ca.crt 2>/dev/null
for name in server client; do
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj "/CN=$name" -keyout $name.key -out $name.csr 2>/dev/null
  printf "subjectAltName=IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=${name}Auth\n" > $name.ext
  openssl x509 -req -in $name.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 \
    -extfile $name.ext -out $name.crt 2>/dev/null
  rm $name.csr $name.ext
done
echo "wrote $out/{ca,server,client}.{crt,key}"
echo "run:  gatekeeper -dev-issuer -tls-cert $out/server.crt -tls-key $out/server.key -tls-client-ca $out/ca.crt"
echo "call: grpcurl -cacert $out/ca.crt -cert $out/client.crt -key $out/client.key -H 'authorization: Bearer \$TOKEN' 127.0.0.1:9090 list"
