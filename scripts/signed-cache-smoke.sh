#!/usr/bin/env bash
set -euo pipefail

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

secret="$tmp/signing-secret.key"
public="$tmp/signing-public.key"
cache="$tmp/cache"
server_store="local?root=$tmp/server"
client_without_key="local?root=$tmp/client-without-key"
client_with_key="local?root=$tmp/client-with-key"

mkdir -p "$cache"
nix-store --generate-binary-cache-key drv-thru-smoke "$secret" "$public"
chmod 0600 "$secret"

cat >"$tmp/test.nix" <<'NIX'
derivation {
  name = "drv-thru-signed-cache-smoke";
  system = builtins.currentSystem;
  builder = "/bin/sh";
  args = [ "-c" "echo ok > $out" ];
  __noChroot = true;
}
NIX

path=$(nix-build --store "$server_store" --option sandbox false "$tmp/test.nix" --no-out-link)

nix copy --from "$server_store" --to "file://$cache?secret-key=$secret" "$path"
grep -R '^Sig:' "$cache"/*.narinfo >/dev/null

if nix copy --from "file://$cache" --to "$client_without_key" --option require-sigs true "$path"; then
  echo "signed cache unexpectedly imported without trusted public key" >&2
  exit 1
fi

public_key=$(<"$public")
nix copy --from "file://$cache" \
  --to "$client_with_key" \
  --option require-sigs true \
  --option trusted-public-keys "$public_key" \
  "$path"

nix --store "$client_with_key" path-info --json "$path" | grep -F 'drv-thru-smoke:' >/dev/null
printf 'signed cache smoke ok: %s\n' "$path"
