#!/bin/bash
# certs.sh DIR: a certificate authority of this machine's own, for the
# stand-in (registry.py). The VM is told to trust it (vm/provision.sh);
# nothing else is. Made once, kept out of the repository.
#
# certs.sh DIR OUT NAME...: a certificate for registry.npmjs.org and the
# NAMEs, signed by that authority, as OUT/leaf.pem and OUT/leaf.key: what one
# recording's stand-in serves with.
set -euo pipefail
dir=${1:?usage: certs.sh DIR [OUT NAME...]}
mkdir -p "$dir"
if [ ! -f "$dir/ca.pem" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=tangent-eval recording CA" \
    -keyout "$dir/ca.key" -out "$dir/ca.pem" 2>/dev/null
  chmod 600 "$dir/ca.key"
  echo "$dir/ca.pem: the VM trusts this"
fi
[ $# -ge 2 ] || exit 0
out=$2
shift 2
mkdir -p "$out"
san="DNS:registry.npmjs.org"
for name in "$@"; do san="$san,DNS:$name"; done
openssl req -newkey rsa:2048 -nodes -subj "/CN=registry.npmjs.org" -keyout "$out/leaf.key" -out "$out/leaf.csr" 2>/dev/null
printf 'subjectAltName=%s\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' "$san" > "$out/leaf.ext"
openssl x509 -req -in "$out/leaf.csr" -CA "$dir/ca.pem" -CAkey "$dir/ca.key" -CAcreateserial -days 30 \
  -extfile "$out/leaf.ext" -out "$out/leaf.pem" 2>/dev/null
rm "$out/leaf.csr" "$out/leaf.ext"
chmod 600 "$out/leaf.key"
