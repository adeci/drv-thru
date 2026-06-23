# drv-thru

<p align="center">
  <img src="./assets/drv-thru.jpg" alt="drv-thru" width="640">
</p>

Remote Nix builds over Iroh.

Run `drv-thru` on a NixOS builder, give someone a ticket, and they can build on that machine. Missing inputs and outputs move as normal Nix export/import streams. No SSH user setup or network shenanagins needed!

## Quick Start

On the builder, either enable the NixOS module:

```nix
{ pkgs, inputs, ... }:
let
  drvThru = inputs.drv-thru.packages.${pkgs.stdenv.hostPlatform.system}.drv-thru;
in
{
  imports = [ inputs.drv-thru.nixosModules.default ];

  # Enable the builder daemon.
  services.drv-thru = {
    enable = true;
    package = drvThru;
  };

  # Install the CLI for creating tickets on the builder.
  environment.systemPackages = [ drvThru ];
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

- Access means permission to run a Nix build on the server.
- Tickets are bearer credentials. Whoever redeems a one-use ticket first gets the build. Share them like passwords.
- Trusted client keys are long-lived access. Use them for machines or people the builder owner already trusts.
- NixOS module state lives in `/var/lib/drv-thru`.
- Wheel users can create/admin tickets; the server secret key stays private to the `drv-thru` service user.
- Trusted-client builds use a persistent client key at `~/.config/drv-thru/secret.key`.
- Ticket builds use ephemeral Iroh client keys by default.
- Build logs render through local `nom --json` by default; use `--no-nom` for raw stderr logs.
