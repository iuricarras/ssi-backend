{
  description = "SSI backend flake";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  };

  outputs = {
    self,
    nixpkgs,
  }: let
    system = "x86_64-linux";
    pkgs = nixpkgs.legacyPackages.${system};
  in {
    devShells.${system}.default = pkgs.mkShell {
      packages = with pkgs; [
        (python313.withPackages (python-pkgs: [
          python-pkgs.flask
          python-pkgs.flask-jwt-extended
          python-pkgs.flask-mail
          python-pkgs.flask-cors
          python-pkgs.flasgger
          python-pkgs.pymongo
          python-pkgs.python-dotenv
          python-pkgs.pyjwt
          python-pkgs.cryptography
        ]))
        mongodb-compass
        postman
      ];
      shellHook = ''
        export FLASK_APP=app
        export FLASK_ENV=development
      '';
    };
  };
}
