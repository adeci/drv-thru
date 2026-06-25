# drv-thru

<p align="center">
  <img src="./assets/drv-thru.jpg" alt="drv-thru" width="640">
</p>

P2P Nix builds!

Run `drv-thru` on a NixOS builder, create one time redeemable build tickets or set up persistent access. Anyone with a ticket can build on your machine without getting an account there. Missing inputs upload from their Nix store; finished outputs come back as signed Nix store paths.

<p align="center">
  <img src="./assets/demo.gif" alt="drv-thru demo showing a ticketed remote Nix build" width="720">
</p>

## Quickstart

You need one NixOS builder and one NixOS client. For ticket builds on a multi-user Nix client, the client must trust the builder's signing key through the drv-thru helper.

### 1. Start The Builder

Add the module on the machine that should run builds:

```nix
{ inputs, ... }:
{
  imports = [ inputs.drv-thru.nixosModules.default ];

  services.drv-thru.server.enable = true;
}
```

Rebuild, then print the builder's signing key:

```sh
sudo nixos-rebuild switch
sudo cat /var/lib/drv-thru/signing-public.key
```

Save that key. The client needs it in the next step.

Create a ticket on the builder:

```sh
drv-thru ticket create
```

Send the printed `drvthru...` ticket to the client.

### 2. Trust That Builder On The Client

Add the client module and allow the builder signing key:

```nix
{ inputs, ... }:
{
  imports = [ inputs.drv-thru.nixosModules.default ];

  services.drv-thru.client = {
    enable = true;

    ticketHelper.trustedBuilderPublicKeys = [
      "drv-thru:builder-signing-public-key"
    ];
  };
}
```

Rebuild the client:

```sh
sudo nixos-rebuild switch
```

### 3. Build With The Ticket

```sh
drv-thru build nixpkgs#hello --ticket "drvthru..."
```

That evaluates locally, uploads missing inputs to the builder, runs the build there, then imports the signed output back into the client's Nix store.

## Other Ways To Use It

### Long-Lived Trusted Client

Use this when one client should keep using the same builder without tickets.

On the client, print its Iroh key:

```sh
drv-thru key show
```

On the builder, allow that client:

```nix
services.drv-thru.server.trustedClients.alex = {
  publicKey = "client-iroh-endpoint-id";
  maxBuildTime = "30m";
  maxUploadBytes = "20G";
};
```

On the client, trust the builder's signing key:

```nix
services.drv-thru.client = {
  enable = true;
  trustedBuilders.leviathan.publicKey = "drv-thru:builder-signing-public-key";
};
```

Then save the builder address for your user:

```sh
mkdir -p ~/.config/drv-thru
cat > ~/.config/drv-thru/builders.json <<'EOF'
{
  "builders": {
    "leviathan": {
      "endpoint_id": "builder-iroh-endpoint-id",
      "relay_url": null
    }
  }
}
EOF
```

On the builder, `drv-thru status` prints the server endpoint id. Then build without a ticket:

```sh
drv-thru build nixpkgs#hello --builder leviathan
```

You can still pass the endpoint directly:

```sh
drv-thru build nixpkgs#hello --server "builder-iroh-endpoint-id"
```

### Run Without Installing First

```sh
nix run github:adeci/drv-thru#drv-thru -- build nixpkgs#hello --ticket "drvthru..."
```

This only runs the CLI. It does not install the local helper or change Nix trust settings.

## Ticket Commands

Create a ticket with custom limits:

```sh
drv-thru ticket create \
  --name friend \
  --expires 2h \
  --uses 1 \
  --max-build-time 30m \
  --max-upload-bytes 20G
```

Bind a ticket to one client endpoint:

```sh
drv-thru ticket create --bind-client "client-iroh-endpoint-id"
```

Inspect and manage tickets on the builder:

```sh
drv-thru ticket inspect "drvthru..."
drv-thru ticket list
drv-thru ticket reveal "ticket-id"
drv-thru ticket revoke "ticket-id"
```

Defaults: tickets expire after 2 hours, allow one use, allow 30 minutes of build time, and allow 20 GiB of input upload. `list` does not print bearer secrets; `reveal` does.

## Build Options

```sh
NIXPKGS_ALLOW_UNSUPPORTED_SYSTEM=1 drv-thru build . --impure --ticket "drvthru..."
drv-thru build . --refresh --ticket "drvthru..."
drv-thru build . --override-input nixpkgs github:NixOS/nixpkgs/nixos-unstable --ticket "drvthru..."
drv-thru build . --rebuild --ticket "drvthru..."
drv-thru build nixpkgs#hello --ticket "drvthru..." --no-nom
```

`--impure`, `--refresh`, and `--override-input` affect local evaluation before inputs upload. `--rebuild` asks the remote builder to rebuild and check the derivation. `--no-nom` uses plain logs.

If the requested outputs are already valid in the local Nix store, drv-thru skips the remote builder and prints the local output paths.

## Status

```sh
drv-thru status
drv-thru status --watch
```

Run these on the builder to see active builds and the waiting queue.

## What Gets Trusted

There are two separate trust decisions:

- who may spend CPU and disk on the builder
- whose build outputs may enter the client's Nix store

Tickets and `server.trustedClients.*` control builder access.

A builder endpoint id is an address, not an auth secret. Keep it local if you do not want people probing reachability, but access still requires a trusted client key or a ticket. Named builders can live in `/etc/drv-thru/builders.json` from the NixOS module or in `~/.config/drv-thru/builders.json` for one user; the user file overrides the system file.

Nix trusted users, `client.builders`, `client.trustedBuilders`, and `ticketHelper.trustedBuilderPublicKeys` control output import trust.

A ticket alone is not enough for an untrusted multi-user Nix client to import outputs from a new builder. One of these must also be true:

- the local user is a trusted Nix user
- the builder signing key is in `nix.settings.trusted-public-keys`
- the user can access the drv-thru import helper socket and the builder key is in the helper allowlist

The helper is a local root service. It only accepts allowlisted builder keys, loopback HTTP cache URLs, and exact `/nix/store/...` paths. It does not run arbitrary commands or arbitrary Nix options.

## How Output Import Works

Outputs move back through Nix's signed binary cache path:

- the builder signs `.narinfo` files
- the client mirrors the needed cache files over Iroh
- local Nix imports the paths after checking signatures

The server keeps a persistent signed cache under `/var/lib/drv-thru/cache`. First request for a large uncached closure may spend time filling cache entries; later builds reuse them.

Raw `nix-store --export` / `nix-store --import` is still used for server-side input upload. It is not used for client output import.

## NixOS Module Reference

```nix
services.drv-thru = {
  package = inputs.drv-thru.packages.${pkgs.stdenv.hostPlatform.system}.default;

  server = {
    enable = true;
    dataDir = "/var/lib/drv-thru";
    secretKeyFile = "/var/lib/drv-thru/secret.key";
    maxConcurrentBuilds = 1;
    outputCacheMaxParallelFills = null; # auto
    recentBuildsLimit = 20;

    trustedClients.alex = {
      publicKey = "client-iroh-endpoint-id";
      maxBuildTime = "30m";
      maxUploadBytes = "20G";
    };
  };

  client = {
    enable = true;
    narFetches = null; # auto

    builders.leviathan = {
      endpointId = null;
      endpointIdFile = "/run/secrets/drv-thru-leviathan-endpoint-id";
      relayUrl = null;
      publicKey = "drv-thru:builder-signing-public-key";
    };

    trustedBuilders.other.publicKey = "drv-thru:other-builder-signing-public-key";

    ticketHelper = {
      enable = true; # defaults to client.enable
      group = "wheel";
      trustedBuilderPublicKeys = [
        "drv-thru:ticket-only-builder-signing-public-key"
      ];
    };
  };
};
```

Module state lives in `/var/lib/drv-thru`. Wheel users can create and inspect tickets. The server Iroh secret key and signing secret key stay private to the `drv-thru` service user.
