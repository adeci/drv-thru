{ packageFor }:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.drv-thru;
  serverCfg = cfg.server;
  clientCfg = cfg.client;
  ticketHelperCfg = clientCfg.ticketHelper;
  inherit (cfg) package;
  json = pkgs.formats.json { };

  serverConfig = json.generate "drv-thru-server.json" {
    data_dir = serverCfg.dataDir;
    secret_key_file = serverCfg.secretKeyFile;
    max_concurrent_builds = serverCfg.maxConcurrentBuilds;
    output_cache_max_parallel_fills = serverCfg.outputCacheMaxParallelFills;
    recent_builds_limit = serverCfg.recentBuildsLimit;
    trusted_clients = lib.mapAttrs (_: client: {
      public_key = client.publicKey;
      max_build_time = client.maxBuildTime;
      max_upload_bytes = client.maxUploadBytes;
    }) serverCfg.trustedClients;
  };

  standaloneTrustedBuilderPublicKeys = lib.mapAttrsToList (
    _: builder: builder.publicKey
  ) clientCfg.trustedBuilders;
  namedBuilderPublicKeys = lib.mapAttrsToList (_: builder: builder.publicKey) clientCfg.builders;
  clientTrustedBuilderPublicKeys = lib.unique (
    standaloneTrustedBuilderPublicKeys ++ namedBuilderPublicKeys
  );
  helperTrustedBuilderPublicKeys = lib.unique (
    clientTrustedBuilderPublicKeys ++ ticketHelperCfg.trustedBuilderPublicKeys
  );
  helperTrustedPublicKeysFile = pkgs.writeText "drv-thru-import-helper-trusted-public-keys" ''
    ${lib.concatStringsSep "\n" helperTrustedBuilderPublicKeys}
  '';
  clientBuildersConfig = json.generate "drv-thru-builders.json" {
    builders = lib.mapAttrs (_: builder: {
      endpoint_id = builder.endpointId;
      endpoint_id_file = builder.endpointIdFile;
      relay_url = builder.relayUrl;
    }) clientCfg.builders;
  };
in
{
  options.services.drv-thru = {
    package = lib.mkOption {
      type = lib.types.package;
      default = packageFor pkgs.stdenv.hostPlatform.system;
      defaultText = lib.literalExpression "inputs.drv-thru.packages.${pkgs.stdenv.hostPlatform.system}.default";
      description = "Package providing the drv-thru binary.";
    };

    server = {
      enable = lib.mkEnableOption "drv-thru remote Nix builder";

      dataDir = lib.mkOption {
        type = lib.types.str;
        default = "/var/lib/drv-thru";
        description = "Directory for server state.";
      };

      secretKeyFile = lib.mkOption {
        type = lib.types.str;
        default = "${serverCfg.dataDir}/secret.key";
        description = "Path to the server Iroh secret key.";
      };

      maxConcurrentBuilds = lib.mkOption {
        type = lib.types.ints.positive;
        default = 1;
        description = "Maximum active builds processed at once.";
      };

      outputCacheMaxParallelFills = lib.mkOption {
        type = lib.types.nullOr lib.types.ints.positive;
        default = null;
        description = "Maximum signed cache entries generated in parallel. null uses an automatic CPU-based default.";
      };

      recentBuildsLimit = lib.mkOption {
        type = lib.types.ints.positive;
        default = 20;
        description = "Maximum recent builds retained in the local drv-thru status snapshot.";
      };

      trustedClients = lib.mkOption {
        default = { };
        description = "Declarative allowlist of long-lived client keys.";
        type = lib.types.attrsOf (
          lib.types.submodule {
            options = {
              publicKey = lib.mkOption {
                type = lib.types.str;
                description = "Client Iroh endpoint id.";
              };

              maxBuildTime = lib.mkOption {
                type = lib.types.str;
                default = "30m";
                description = "Wall-clock build timeout.";
              };

              maxUploadBytes = lib.mkOption {
                type = lib.types.str;
                default = "20G";
                description = "Maximum input upload size.";
              };
            };
          }
        );
      };
    };

    client = {
      enable = lib.mkEnableOption "drv-thru client CLI";

      narFetches = lib.mkOption {
        type = lib.types.nullOr lib.types.ints.positive;
        default = null;
        description = "Default parallel NAR payload fetches for local cache mirroring. null uses the CLI auto default.";
      };

      trustedBuilders = lib.mkOption {
        default = { };
        description = "Declarative builder signing keys trusted globally for client-side store imports.";
        type = lib.types.attrsOf (
          lib.types.submodule {
            options = {
              publicKey = lib.mkOption {
                type = lib.types.str;
                description = "Builder binary-cache signing public key.";
              };

            };
          }
        );
      };

      builders = lib.mkOption {
        default = { };
        description = "Named long-lived builders available to drv-thru build --builder <name>. These entries also trust the builder signing key globally for client-side store imports.";
        type = lib.types.attrsOf (
          lib.types.submodule {
            options = {
              endpointId = lib.mkOption {
                type = lib.types.nullOr lib.types.str;
                default = null;
                description = "Builder Iroh endpoint id. Use endpointIdFile instead to keep this out of the Nix store and git.";
              };

              endpointIdFile = lib.mkOption {
                type = lib.types.nullOr lib.types.str;
                default = null;
                description = "Runtime file containing the builder Iroh endpoint id. Useful with sops/agenix secrets.";
              };

              relayUrl = lib.mkOption {
                type = lib.types.nullOr lib.types.str;
                default = null;
                description = "Optional Iroh relay URL for this builder.";
              };

              publicKey = lib.mkOption {
                type = lib.types.str;
                description = "Builder binary-cache signing public key.";
              };
            };
          }
        );
      };

      ticketHelper = {
        enable = lib.mkOption {
          type = lib.types.bool;
          default = clientCfg.enable;
          defaultText = lib.literalExpression "services.drv-thru.client.enable";
          description = "Whether to run the drv-thru local ticket import helper.";
        };

        group = lib.mkOption {
          type = lib.types.str;
          default = "wheel";
          description = "Group allowed to use the local drv-thru import helper. Members can ask root to import exact signed store paths from loopback drv-thru cache URLs, but only for keys allowed by client.trustedBuilders or ticketHelper.trustedBuilderPublicKeys. Defaults to wheel because wheel users can already become root; use a narrow group only for users trusted with that local import power.";
        };

        trustedBuilderPublicKeys = lib.mkOption {
          type = lib.types.listOf lib.types.str;
          default = [ ];
          description = "Additional builder signing public keys the local import helper may trust without adding them to nix.settings.trusted-public-keys. Public keys from client.trustedBuilders are also accepted.";
        };
      };
    };
  };

  config = lib.mkMerge [
    {
      assertions = [
        {
          assertion = !(ticketHelperCfg.enable && !clientCfg.enable);
          message = "services.drv-thru.client.ticketHelper.enable requires services.drv-thru.client.enable.";
        }
        {
          assertion = lib.all (builder: (builder.endpointId != null) != (builder.endpointIdFile != null)) (
            lib.attrValues clientCfg.builders
          );
          message = "Each services.drv-thru.client.builders entry must set exactly one of endpointId or endpointIdFile.";
        }
      ];
    }

    (lib.mkIf (clientCfg.enable && clientTrustedBuilderPublicKeys != [ ]) {
      nix.settings.trusted-public-keys = lib.mkAfter clientTrustedBuilderPublicKeys;
    })

    (lib.mkIf (clientCfg.enable && clientCfg.builders != { }) {
      environment.etc."drv-thru/builders.json".source = clientBuildersConfig;
    })

    (lib.mkIf clientCfg.enable {
      environment.systemPackages = [ package ];
    })

    (lib.mkIf (clientCfg.enable && clientCfg.narFetches != null) {
      environment.sessionVariables.DRV_THRU_NAR_FETCHES = toString clientCfg.narFetches;
    })

    (lib.mkIf ticketHelperCfg.enable {
      users.groups.${ticketHelperCfg.group} = { };

      systemd.services.drv-thru-import-helper = {
        description = "drv-thru local ticket import helper";
        path = [ pkgs.nix ];
        wantedBy = [ "multi-user.target" ];
        after = [ "nix-daemon.service" ];

        serviceConfig = {
          ExecStart = "${lib.getExe package} import-helper serve --socket /run/drv-thru/import-helper.sock --trusted-public-key-file ${helperTrustedPublicKeysFile}";
          User = "root";
          Group = ticketHelperCfg.group;
          RuntimeDirectory = "drv-thru";
          RuntimeDirectoryMode = "0750";
          UMask = "0007";
          Restart = "on-failure";
        };
      };
    })

    (lib.mkIf serverCfg.enable {
      nix.settings.trusted-users = [ "drv-thru" ];

      users.groups.drv-thru = { };
      users.users.drv-thru = {
        isSystemUser = true;
        group = "drv-thru";
        home = serverCfg.dataDir;
        createHome = false;
      };

      system.activationScripts.drv-thru-state = lib.stringAfter [ "users" ] ''
        install -d -o drv-thru -g wheel -m 2770 ${serverCfg.dataDir}
        install -d -o drv-thru -g drv-thru -m 0750 ${serverCfg.dataDir}/cache

        if [ -e ${serverCfg.secretKeyFile} ]; then
          chown drv-thru:drv-thru ${serverCfg.secretKeyFile}
          chmod 0600 ${serverCfg.secretKeyFile}
        fi

        if [ -e ${serverCfg.dataDir}/signing-secret.key ]; then
          chown drv-thru:drv-thru ${serverCfg.dataDir}/signing-secret.key
          chmod 0600 ${serverCfg.dataDir}/signing-secret.key
        fi

        if [ -e ${serverCfg.dataDir}/signing-public.key ]; then
          chown drv-thru:drv-thru ${serverCfg.dataDir}/signing-public.key
          chmod 0644 ${serverCfg.dataDir}/signing-public.key
        fi

        for file in ${serverCfg.dataDir}/server-addr.json ${serverCfg.dataDir}/tickets.json ${serverCfg.dataDir}/status.json; do
          if [ -e "$file" ]; then
            chown drv-thru:wheel "$file"
            chmod 0660 "$file"
          fi
        done
      '';

      systemd.services.drv-thru = {
        description = "drv-thru remote Nix builder";
        path = [ pkgs.nix ];
        wantedBy = [ "multi-user.target" ];
        wants = [ "network-online.target" ];
        after = [
          "network-online.target"
          "nix-daemon.service"
        ];

        serviceConfig = {
          ExecStart = "${lib.getExe package} serve --config ${serverConfig}";
          Restart = "on-failure";
          User = "drv-thru";
          Group = "drv-thru";
          SupplementaryGroups = [ "wheel" ];
        };
      };
    })
  ];
}
