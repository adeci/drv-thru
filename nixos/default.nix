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
  package = cfg.package;
  json = pkgs.formats.json { };

  serverConfig = json.generate "drv-thru-server.json" {
    data_dir = serverCfg.dataDir;
    secret_key_file = serverCfg.secretKeyFile;
    max_concurrent_builds = serverCfg.maxConcurrentBuilds;
    output_cache_max_parallel_fills = serverCfg.outputCacheMaxParallelFills;
    trusted_clients = lib.mapAttrs (_: client: {
      public_key = client.publicKey;
      max_build_time = client.maxBuildTime;
      max_upload_bytes = client.maxUploadBytes;
    }) serverCfg.trustedClients;
  };

  trustedBuilderPublicKeys = lib.mapAttrsToList (
    _: builder: builder.publicKey
  ) clientCfg.trustedBuilders;
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
        description = "Declarative builder signing keys trusted for client-side store imports.";
        type = lib.types.attrsOf (
          lib.types.submodule {
            options = {
              endpointId = lib.mkOption {
                type = lib.types.str;
                description = "Builder Iroh endpoint id.";
              };

              publicKey = lib.mkOption {
                type = lib.types.str;
                description = "Builder binary-cache signing public key.";
              };

              relayUrl = lib.mkOption {
                type = lib.types.nullOr lib.types.str;
                default = null;
                description = "Optional builder Iroh relay URL.";
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
          description = "Group allowed to use the local drv-thru import helper. Members can import signed store paths from ticket builders. Defaults to wheel because wheel users can already become root; set this to a narrower group for delegated non-admin access.";
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
      ];
    }

    (lib.mkIf (clientCfg.enable && trustedBuilderPublicKeys != [ ]) {
      nix.settings.trusted-public-keys = lib.mkAfter trustedBuilderPublicKeys;
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
          ExecStart = "${lib.getExe package} import-helper serve --socket /run/drv-thru/import-helper.sock";
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

        for file in ${serverCfg.dataDir}/server-addr.json ${serverCfg.dataDir}/tickets.json; do
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
