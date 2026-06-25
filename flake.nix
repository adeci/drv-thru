{
  description = "drv-thru: remote Nix builds over Iroh";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

    treefmt-nix.url = "github:numtide/treefmt-nix";
    treefmt-nix.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      treefmt-nix,
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      forAllSystems =
        f:
        nixpkgs.lib.genAttrs systems (
          system:
          f (
            import nixpkgs {
              inherit system;
            }
          )
        );

      packageFor =
        pkgs:
        pkgs.rustPlatform.buildRustPackage {
          pname = "drv-thru";
          version = self.shortRev or self.dirtyShortRev or "0.1.0";

          nativeBuildInputs = [ pkgs.makeWrapper ];

          src = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./Cargo.lock
              ./Cargo.toml
              ./crates
            ];
          };

          cargoLock.lockFile = ./Cargo.lock;

          postInstall = ''
            wrapProgram $out/bin/drv-thru \
              --prefix PATH : ${
                pkgs.lib.makeBinPath [
                  pkgs.nix
                  pkgs.nix-output-monitor
                ]
              }
          '';

          meta = {
            description = "Remote Nix builds over Iroh";
            license = pkgs.lib.licenses.mit;
            mainProgram = "drv-thru";
          };
        };

      formatterFor =
        pkgs:
        treefmt-nix.lib.mkWrapper pkgs {
          projectRootFile = "flake.nix";

          programs.nixfmt.enable = true;
          programs.rustfmt.enable = true;
          programs.taplo.enable = true;

          settings.global.excludes = [
            ".direnv/*"
            "target/*"
            "result"
            "result-*"
          ];
        };
    in
    {
      packages = forAllSystems (
        pkgs:
        let
          drvThru = packageFor pkgs;
        in
        {
          default = drvThru;
          drv-thru = drvThru;
        }
      );

      checks = nixpkgs.lib.genAttrs systems (system: {
        package-default = self.packages.${system}.default;
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            pkgs.cargo
            pkgs.cargo-watch
            pkgs.clippy
            pkgs.deadnix
            pkgs.nil
            pkgs.nix
            pkgs.nix-output-monitor
            pkgs.nixfmt
            pkgs.pkg-config
            pkgs.rust-analyzer
            pkgs.rustc
            pkgs.rustfmt
            pkgs.shellcheck
            pkgs.statix
            pkgs.taplo
          ];
        };
      });

      formatter = forAllSystems formatterFor;

      nixosModules = {
        default = import ./nixos {
          packageFor = system: self.packages.${system}.default;
        };
        drv-thru = self.nixosModules.default;
      };
    };
}
