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
      endpointId = "builder-iroh-endpoint-id";
      publicKey = "drv-thru:builder-signing-public-key";
      relayUrl = "https://use1-1.relay.n0.iroh.link./";
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

### 3. Ticket-Only Client For One-Off Builders

Use this when you want to test one-time tickets from arbitrary builders without making the local user a trusted Nix user and without saving builder keys in global Nix config.

```nix
{ inputs, ... }:
{
  imports = [ inputs.drv-thru.nixosModules.default ];

  services.drv-thru.client.enable = true;
}
```

The helper defaults on with `client.enable`. It is a local root service. Its socket is group-gated to `wheel` by default, which is appropriate for admin machines because wheel users can already become root.

For delegated non-admin access, use a narrower group:

```nix
services.drv-thru.client.ticketHelper.group = "drv-thru";
users.users.alex.extraGroups = [ "drv-thru" ];
```

After changing groups, log out and back in.

Then build with a ticket:

```sh
drv-thru build nixpkgs#hello --ticket "drvthru..."
```

No trusted builder entry is needed for this mode. The helper validates a narrow request and runs trusted `nix copy` locally for exact store paths from a loopback cache URL.

## Usage

Create a ticket with custom limits:

```sh
drv-thru ticket create \
  --name friend \
  --expires 2h \
  --uses 1 \
  --max-build-time 30m \
  --max-upload-bytes 20G
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
- the local user can access the drv-thru import helper socket.

## Output Cache

Outputs are imported through Nix binary-cache semantics:

- signed `.narinfo`
- matching NAR/NAR.zst file
- trusted public key, or a trusted local helper doing the import

The server keeps a persistent signed cache under `/var/lib/drv-thru/cache`. Cache entries are generated on demand when the client asks for allowed `.narinfo` files, then reused across tickets and builds.

Raw `nix-store --export` / `nix-store --import` is still used for server-side input upload. It is not used for client output import.

## Limitations

- Both sides still need Nix. drv-thru moves where the build happens; it is not a Nix daemon replacement.
- One-off ticket builds for untrusted Nix users need the local helper. The NixOS client module enables it by default.
- `client.trustedBuilders.*.endpointId` and `relayUrl` record builder dialing info, but builds still pass `--server`/`--relay-url` or `--ticket` today.
- First request for a large uncached closure still has to generate cache entries. Later builds reuse the persistent cache.
- The helper only accepts loopback HTTP cache URLs and exact `/nix/store/...` paths. It does not run arbitrary commands or arbitrary Nix options.
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
      endpointId = "builder-iroh-endpoint-id";
      publicKey = "drv-thru:builder-signing-public-key";
      relayUrl = null;
    };

    narFetches = null; # auto, based on CPU count; set e.g. 16 to tune

    ticketHelper = {
      enable = true; # defaults to client.enable
      group = "wheel"; # set to "drv-thru" for delegated non-admin users
    };
  };
};
```

Module state lives in `/var/lib/drv-thru`. Wheel users can create and inspect tickets; the server Iroh secret key and signing secret key stay private to the `drv-thru` service user.
