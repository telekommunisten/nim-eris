# Package

version       = "0.2.0"
author        = "Emery Hemingway"
description   = "Encoding for Robust Immutable Storage"
license       = "ISC"
srcDir        = "src"



# Dependencies

requires "nim >= 1.4.0", "base32 >= 0.1.3", "taps >= 0.2.0", "lmdb"

import distros
if detectOs(NixOS):
  foreignDep "lmdb"
