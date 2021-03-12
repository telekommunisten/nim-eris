{
  description = "Encoding for Robust Immutable Storage";
  outputs = { self, nimble }:
    let
      systems = [ "aarch64-linux" "x86_64-linux" ];
      forAllSystems = nimble.inputs.nixpkgs.lib.genAttrs systems;
    in {

      defaultPackage = forAllSystems (system:
        let nimpkgs = nimble.packages.${system};
        in nimpkgs.eris.overrideAttrs (attrs: {
          version = "unstable-" + self.lastModifiedDate;
          src = self;
        }));

    };
}
