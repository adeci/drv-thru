# drv-thru

<p align="center">
  <img src="./assets/drv-thru.jpg" alt="drv-thru" width="640">
</p>

Remote Nix builds over Iroh.

Run `drv-thru` on a NixOS builder, hand someone a ticket, and they can run a build on that machine. Inputs the builder is missing upload as normal Nix export streams. Outputs come back through a signed binary cache served over Iroh. No SSH account on the builder.

## Casual Setup

There are three common setups.

### 1. Builder Machine

Put this on the machine that will run builds.

```nix
{ inputs, ... }:
{
  imports = [ inputs.drv-thru.nixosModules.default ];

  services.drv-thru.server = {
    enable = true;

    # Optional long-lived clients. Tickets work without this.
    trustedClients.alex = {
      publicKey = "client-iroh-endpoint-id";
      maxBuildTime = "30m";
      maxUploadBytes = "20G";
    };
  };
}
```

Create a ticket on the builder:

```sh
drv-thru ticket create
```

Send the printed ticket to the client.

### 2. Regular Client For A Builder You Trust

Use this when the client should always trust outputs signed by a specific builder.

```nix
{ inputs, ... }:
{
  imports = [ inputs.drv-thru.nixosModules.default ];

  services.drv-thru.client = {
    enable = true;
    narFetches = null; # auto, based on CPU count; set e.g. 16 to tune

    trustedBuilders.leviathan = {
      publicKey = "drv-thru:builder-signing-public-key";
    };
  };
}
```

This adds the builder signing key to `nix.settings.trusted-public-keys`. After that, normal users on the client can import outputs signed by that builder.

Build with trusted-client auth:

```sh
drv-thru key show
# add the printed endpoint id to server.trustedClients on the builder

drv-thru build nixpkgs#hello --server "builder-iroh-endpoint-id"
```

If node-id-only dialing does not have address info yet, pass the relay URL:

```sh
drv-thru build nixpkgs#hello \
  --server "builder-iroh-endpoint-id" \
  --relay-url "https://use1-1.relay.n0.iroh.link./"
```

### 3. Ticket Helper With Local Builder Allowlist

Use this when you want ticket builds without making the local user a trusted Nix user and without saving builder keys in global Nix config. The helper still needs an explicit local allowlist of builder signing keys.

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

The helper defaults on with `client.enable`. It is a local root service. Its socket is group-gated to `wheel` by default, which is appropriate for admin machines because wheel users can already become root.

Important: helper-group membership is local import trust for allowed builder keys. Members can ask root to import exact signed store paths from loopback drv-thru cache URLs when the builder signing key is in `ticketHelper.trustedBuilderPublicKeys` or `client.trustedBuilders`. Use a narrower group only for users you trust with that local import power:

```nix
services.drv-thru.client.ticketHelper.group = "drv-thru";
users.users.alex.extraGroups = [ "drv-thru" ];
```

After changing groups, log out and back in.

Then build with a ticket:

```sh
drv-thru build nixpkgs#hello --ticket "drvthru..."
```

No `client.trustedBuilders` entry is needed for this mode. The helper validates a narrow request, checks the builder key against its local allowlist, and runs trusted `nix copy` locally for exact store paths from a loopback cache URL.

## Usage

Create a ticket with custom limits:

```sh
drv-thru ticket create \
  --name friend \
  --expires 2h \
  --uses 1 \
  --max-build-time 30m \
  --max-upload-bytes 20G

# Optional: bind the ticket to one client's endpoint id.
drv-thru ticket create --bind-client "client-iroh-endpoint-id"
```

By default, tickets are one-use, expire after 2 hours, allow 30 minutes of build time, and allow 20 GiB of input upload.

Inspect a ticket:

```sh
drv-thru ticket inspect "drvthru..."
```

Manage stored tickets on the builder:

```sh
drv-thru ticket list
drv-thru ticket reveal "ticket-id"
drv-thru ticket revoke "ticket-id"
```

`list` does not print bearer secrets. `reveal` is explicit because it prints the pasteable ticket.

Show local builder status:

```sh
drv-thru status
drv-thru status --watch
```

Build with a ticket:

```sh
drv-thru build nixpkgs#hello --ticket "drvthru..."
```

If the requested top-level outputs are already valid in the local Nix store, drv-thru skips the remote builder and prints the local output paths.

Use supported Nix flags:

```sh
NIXPKGS_ALLOW_UNSUPPORTED_SYSTEM=1 drv-thru build . --impure --ticket "drvthru..."
drv-thru build . --refresh --ticket "drvthru..."
drv-thru build . --override-input nixpkgs github:NixOS/nixpkgs/nixos-unstable --ticket "drvthru..."
drv-thru build . --rebuild --ticket "drvthru..."
```

`--impure`, `--refresh`, and `--override-input` affect client-side evaluation before inputs are uploaded. `--rebuild` asks the remote builder to rebuild and check the derivation.

Use plain logs instead of local `nom` rendering:

```sh
drv-thru build nixpkgs#hello --ticket "drvthru..." --no-nom
```

Run without installing the package first:

```sh
nix run github:adeci/drv-thru#drv-thru -- build nixpkgs#hello --ticket "drvthru..."
```

## What Gets Trusted

There are two separate trust decisions.

- Builder access: who may spend CPU and disk on the builder?
- Store import trust: whose binaries may enter the client's Nix store?

Tickets and `server.trustedClients.*` answer the first question. Nix signing keys and the local import helper answer the second.

A ticket alone does not make an untrusted multi-user Nix client accept outputs from a new builder. One of these must also be true:

- the local user is a trusted Nix user,
- the builder signing key is in `nix.settings.trusted-public-keys`, or
- the local user can access the drv-thru import helper socket and the builder key is in the helper allowlist.

## Output Cache

Outputs are imported through Nix binary-cache semantics:

- signed `.narinfo`
- matching NAR/NAR.zst file
- trusted public key, or a trusted local helper with that builder key in its allowlist

The server keeps a persistent signed cache under `/var/lib/drv-thru/cache`. Cache entries are generated on demand when the client asks for allowed `.narinfo` files, then reused across tickets and builds.

Raw `nix-store --export` / `nix-store --import` is still used for server-side input upload. It is not used for client output import.

## Limitations

- Both sides still need Nix. drv-thru moves where the build happens; it is not a Nix daemon replacement.
- One-off ticket builds for untrusted Nix users need the local helper and a helper builder-key allowlist entry. The NixOS client module enables the helper by default.
- First request for a large uncached closure still has to generate cache entries. Later builds reuse the persistent cache.
- The helper only accepts allowlisted builder keys, loopback HTTP cache URLs, and exact `/nix/store/...` paths. It does not run arbitrary commands or arbitrary Nix options.
- Tickets are bearer credentials. Whoever redeems a one-use ticket first gets the build.

## NixOS Module Reference

`package` defaults automatically from the flake. `server` configures the builder daemon. `client` installs the CLI, trusted builder keys, and the local ticket helper.

```nix
services.drv-thru = {
  server = {
    enable = true;
    dataDir = "/var/lib/drv-thru";
    secretKeyFile = "/var/lib/drv-thru/secret.key";
    maxConcurrentBuilds = 1;
    outputCacheMaxParallelFills = null; # auto, based on CPU count; set e.g. 8 to tune
    recentBuildsLimit = 20;

    trustedClients.alex = {
      publicKey = "client-iroh-endpoint-id";
      maxBuildTime = "30m";
      maxUploadBytes = "20G";
    };
  };

  client = {
    enable = true;

    trustedBuilders.leviathan = {
      publicKey = "drv-thru:builder-signing-public-key";
    };

    narFetches = null; # auto, based on CPU count; set e.g. 16 to tune

    ticketHelper = {
      enable = true; # defaults to client.enable
      group = "wheel"; # use a narrow group only for trusted local import users
      trustedBuilderPublicKeys = [
        "drv-thru:ticket-only-builder-signing-public-key"
      ];
    };
  };
};
```

Module state lives in `/var/lib/drv-thru`. Wheel users can create and inspect tickets; the server Iroh secret key and signing secret key stay private to the `drv-thru` service user.
