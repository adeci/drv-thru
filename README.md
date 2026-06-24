# drv-thru

<p align="center">
  <img src="./assets/drv-thru.jpg" alt="drv-thru" width="640">
</p>

Remote Nix builds over Iroh.

Run `drv-thru` on a NixOS builder, give someone a ticket, and they can build on that machine. Missing inputs still upload as Nix export streams; requested outputs download through a signed binary cache over Iroh. No SSH user setup or network shenanigans needed.

## Quick Start

On the builder, either enable the NixOS module:

```nix
{ pkgs, inputs, ... }:
let
  drvThru = inputs.drv-thru.packages.${pkgs.stdenv.hostPlatform.system}.drv-thru;
in
{
  imports = [ inputs.drv-thru.nixosModules.default ];

  services.drv-thru = {
    package = drvThru;

    # Enable the builder daemon.
    server.enable = true;

    # Install the CLI for creating tickets on the builder.
    client.enable = true;
  };
}
```

Or run the package directly:

```sh
drv-thru serve
```

Create a ticket on the builder:

```sh
drv-thru ticket create
```

Send that ticket to a client. They build with:

```sh
drv-thru build nixpkgs#hello --ticket "your-ticket-here"
```

Or without installing:

```sh
nix run github:adeci/drv-thru#drv-thru -- build nixpkgs#hello --ticket "your-ticket-here"
```

By default, tickets are one-use, expire after 2 hours, allow 30 minutes of build time, and allow 20 GiB of input upload.

## NixOS Module

`package` is shared. `server` configures the builder daemon. `client` installs the CLI and declares builder cache keys this machine trusts for store imports.

```nix
services.drv-thru = {
  package = drvThru;

  server = {
    enable = true;
    dataDir = "/var/lib/drv-thru";
    secretKeyFile = "/var/lib/drv-thru/secret.key";
    maxConcurrentBuilds = 1;

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

    # Optional: lets normal users in this group use one-off tickets
    # from builders not already listed in trustedBuilders.
    ticketHelper = {
      enable = true;
      group = "drv-thru";
    };
  };
};
```

`client.trustedBuilders.*.publicKey` is appended to `nix.settings.trusted-public-keys`. `endpointId` and `relayUrl` record builder dialing info; builds still pass `--server`/`--relay-url` or `--ticket` today.

The ticket helper is optional. Users in `client.ticketHelper.group` can import signed paths from ticket builders through a local root helper, so treat that group as local import trust.

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

Inspect a ticket:

```sh
drv-thru ticket inspect "your-ticket-here"
```

Build with a ticket:

```sh
drv-thru build nixpkgs#hello --ticket "your-ticket-here"

# no install needed
nix run github:adeci/drv-thru#drv-thru -- build nixpkgs#hello --ticket "your-ticket-here"
```

Use plain logs instead of local `nom` rendering:

```sh
drv-thru build nixpkgs#hello --ticket "your-ticket-here" --no-nom
```

Trusted client access:

```sh
drv-thru key show
```

Add the printed endpoint id to the server allowlist, then build with:

```sh
drv-thru build nixpkgs#hello --server "server-endpoint-id"
```

If node-id-only dialing does not have address info yet, pass the relay URL printed by `serve`:

```sh
drv-thru build nixpkgs#hello \
  --server "server-endpoint-id" \
  --relay-url "https://use1-1.relay.n0.iroh.link./"
```

## Some Notes

- Server build access means permission to run a Nix build on the server. Grant it with tickets or `server.trustedClients.*`.
- Tickets are bearer credentials. Whoever redeems a one-use ticket first gets the build. Share them like passwords.
- Trusted client keys are long-lived server access. Use them for machines or people the builder owner already trusts.
- Client store import trust is separate: the client must run as root/a trusted Nix user, or the builder signing key must be in `nix.settings.trusted-public-keys`.
- Tickets work for trusted Nix users, clients that already trust the builder key, or users allowed to use the client import helper. Treat that helper group as local import trust.
- NixOS module state lives in `/var/lib/drv-thru`.
- Wheel users can create/admin tickets; the server secret key stays private to the `drv-thru` service user.
- Trusted-client builds use a persistent client key at `~/.config/drv-thru/secret.key`.
- Ticket builds use ephemeral Iroh client keys by default.
- Build logs render through local `nom --json` by default; use `--no-nom` for raw stderr logs.
