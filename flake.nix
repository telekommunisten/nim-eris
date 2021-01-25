{
  description = "Encoding for Robust Immutable Storage";

  outputs = { self, nixpkgs, nimble }:
    let
      systems = [ "aarch64-linux" "x86_64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);
    in {

      defaultPackage = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          nimpkgs = nimble.packages.${system};
        in with pkgs;
        stdenv.mkDerivation {
          pname = "eris";
          version = "unstable-" + self.lastModifiedDate;
          src = self;
          nativeBuildInputs = [ nimpkgs.nim ];
        });

    };
}
