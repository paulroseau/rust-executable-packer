{ lib
, stdenv
, fetchFromGitHub
, rustPlatform
, cmake
}:

rustPlatform.buildRustPackage rec {
  pname = "ugdb";
  version = "0.1.11";

  src = fetchFromGitHub {
    owner = "ftilde";
    repo = pname;
    rev = "${version}";
    hash = "sha256-qImOMuMB4f+NQwn5pNYHGto+iZT1UxMsJs2fET3HFQg=";
  };

  nativeBuildInputs = [ cmake ];

  cargoHash = "sha256-j/bttlfvrbV5VgOuYgA3nZv22385129rHUDs9xyMUEs=";

  doCheck = false;

  meta = with lib; {
    description = "An unsegen based alternative TUI for gdb";
    homepage = "https://github.com/ftilde/ugdb";
    license = licenses.mit;
    mainProgram = "ugdb";
  };
}
