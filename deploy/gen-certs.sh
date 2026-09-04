#!/usr/bin/env sh
# Self-signed CA + server + client certs for local mTLS. Usage: gen-certs.sh <outdir>
set -eu
out=${1:-certs}
mkdir -p "$out" && cd "$out"
# ecparam -genkey emits a named-curve key on both OpenSSL and LibreSSL; `req -newkey ec` may not.
for name in ca server client; do openssl ecparam -name prime256v1 -genkey -noout -out $name.key; done
openssl req -x509 -new -key ca.key -days 365 -subj "/CN=gatekeeper-dev-ca" -out ca.crt 2>/dev/null
for name in server client; do
  openssl req -new -key $name.key -subj "/CN=$name" -out $name.csr 2>/dev/null
  printf "subjectAltName=IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=${name}Auth\n" > $name.ext
  openssl x509 -req -in $name.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 \
    -extfile $name.ext -out $name.crt 2>/dev/null
  rm $name.csr $name.ext
done
echo "wrote $out/{ca,server,client}.{crt,key}"
echo "run:  gatekeeper -dev-issuer -tls-cert $out/server.crt -tls-key $out/server.key -tls-client-ca $out/ca.crt"
echo "call: grpcurl -cacert $out/ca.crt -cert $out/client.crt -key $out/client.key -H 'authorization: Bearer \$TOKEN' 127.0.0.1:9090 list"
