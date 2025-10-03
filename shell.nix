let
  pkgs = import <nixpkgs> {};
in pkgs.mkShell {
  packages = with pkgs; [
    (python313.withPackages (python-pkgs: [
      python-pkgs.flask
    ]))
  ];
}

