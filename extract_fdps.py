#!/usr/bin/env python3
"""Extract Cognition protobuf descriptors (*.fdp) from the jeopi-catalog npm
package for devin-shim's server.py. stdlib only — no node/npm/protobuf needed.

Usage: python3 extract-fdps.py [outdir]   (default: current directory)
"""
import base64
import io
import json
import os
import re
import sys
import tarfile
import urllib.request

PKG_URL = "https://registry.npmjs.org/jeopi-catalog/latest"


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "."
    meta = json.loads(urllib.request.urlopen(PKG_URL, timeout=30).read())
    tarball_url = meta["dist"]["tarball"]
    print(f"jeopi-catalog {meta['version']} -> {tarball_url}")
    blob = urllib.request.urlopen(tarball_url, timeout=60).read()

    n = 0
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
        for member in tf.getmembers():
            if not member.name.endswith(".ts"):
                continue
            src = tf.extractfile(member).read().decode("utf-8", "replace")
            gen = re.search(r"@generated from file (\S+\.proto)", src)
            desc = re.search(r'fileDesc\("([A-Za-z0-9+/=]+)"', src)
            if not gen or not desc:
                continue
            proto_path = gen.group(1)                      # e.g. exa/auth_pb/auth.proto
            name = os.path.basename(proto_path)[:-6]       # auth.proto -> auth
            if not name.endswith("_pb"):
                name += "_pb"                              # keep *_pb.fdp style
            name += ".fdp"
            payload = desc.group(1)
            payload += "=" * (-len(payload) % 4)
            with open(os.path.join(outdir, name), "wb") as fh:
                fh.write(base64.b64decode(payload))
            n += 1
            print(f"  {proto_path} -> {name}")
    print(f"wrote {n} .fdp files to {outdir}")
    if n == 0:
        sys.exit("no descriptors found — package layout may have changed")


if __name__ == "__main__":
    main()
