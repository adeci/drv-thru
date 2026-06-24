{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.drv-thru;
  json = pkgs.formats.json { };
  serverConfig = json.generate "drv-thru-server.json" {
    data_dir = cfg.dataDir;
    secret_key_file = cfg.secretKeyFile;
    max_concurrent_builds = cfg.maxConcurrentBuilds;
    trusted_clients = lib.mapAttrs (_: client: {
      public_key = client.publicKey;
      max_build_time = client.maxBuildTime;
      max_upload_bytes = client.maxUploadBytes;
    }) cfg.trustedClients;
  };
in
{
  options.services.drv-thru = {
    enable = lib.mkEnableOption "drv-thru remote Nix builder";

    package = lib.mkOption {
      type = lib.types.nullOr lib.types.package;
      default = null;
      description = "Package providing the drv-thru binary.";
    };

    dataDir = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/drv-thru";
      description = "Directory for server state.";
    };

    secretKeyFile = lib.mkOption {
      type = lib.types.str;
      default = "${cfg.dataDir}/secret.key";
      description = "Path to the server Iroh secret key.";
    };

    maxConcurrentBuilds = lib.mkOption {
      type = lib.types.ints.positive;
      default = 1;
      description = "Maximum active builds processed at once.";
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

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.package != null;
        message = "services.drv-thru.package must be set until drv-thru is packaged.";
      }
    ];

    nix.settings.trusted-users = [ "drv-thru" ];

    users.groups.drv-thru = { };
    users.users.drv-thru = {
      isSystemUser = true;
      group = "drv-thru";
      home = cfg.dataDir;
      createHome = false;
    };

    system.activationScripts.drv-thru-state = lib.stringAfter [ "users" ] ''
      install -d -o drv-thru -g wheel -m 2770 ${cfg.dataDir}

      if [ -e ${cfg.secretKeyFile} ]; then
        chown drv-thru:drv-thru ${cfg.secretKeyFile}
        chmod 0600 ${cfg.secretKeyFile}
      fi

      if [ -e ${cfg.dataDir}/signing-secret.key ]; then
        chown drv-thru:drv-thru ${cfg.dataDir}/signing-secret.key
        chmod 0600 ${cfg.dataDir}/signing-secret.key
      fi

      if [ -e ${cfg.dataDir}/signing-public.key ]; then
        chown drv-thru:drv-thru ${cfg.dataDir}/signing-public.key
        chmod 0644 ${cfg.dataDir}/signing-public.key
      fi

      for file in ${cfg.dataDir}/server-addr.json ${cfg.dataDir}/tickets.json; do
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
        ExecStart = "${lib.getExe cfg.package} serve --config ${serverConfig}";
        Restart = "on-failure";
        User = "drv-thru";
        Group = "drv-thru";
        SupplementaryGroups = [ "wheel" ];
      };
    };
  };
}
