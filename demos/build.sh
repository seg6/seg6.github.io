#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
build="$here/.build"
out="$here/../public/wasm"
mkdir -p "$build" "$out"

for repo in byte raytracer pox; do
  if [ -d "$build/$repo/.git" ]; then
    git -C "$build/$repo" pull -q --ff-only
  else
    git clone -q --depth 1 "https://github.com/seg6/$repo" "$build/$repo"
  fi
done

python3 "$here/byte/asm.py" "$here/byte/plasma.s" "$build/plasma.bin" "$out/byte-plasma.json"
cargo build --quiet --release --target wasm32-unknown-unknown \
  --manifest-path "$here/byte/Cargo.toml" --target-dir "$build/target"
cp "$build/target/wasm32-unknown-unknown/release/byte_web.wasm" "$out/byte.wasm"

rt="$build/raytracer"
zig cc -target wasm32-wasi -O2 -s -mexec-model=reactor \
  -I"$rt/raytracer/include" -I"$rt/canvas/include" -I"$rt/linal/include" \
  "$here/raytracer/web.c" \
  "$rt"/raytracer/src/{scene,sphere,light,camera}.c "$rt"/canvas/src/*.c "$rt"/linal/src/*.c \
  -o "$out/raytracer.wasm"

python3 - "$build/pox" "$out/pox.json" <<'PY'
import json, pathlib, sys
root, out = pathlib.Path(sys.argv[1]), sys.argv[2]
files = {str(p.relative_to(root)): p.read_text() for p in sorted(root.glob('pox/**/*.py'))}
examples = {p.stem: p.read_text() for p in sorted(root.glob('examples/*.pox'))}
json.dump({'files': files, 'examples': examples}, open(out, 'w'))
PY

{
  printf '{'
  for repo in byte raytracer pox; do
    printf '"%s": "%s"' "$repo" "$(git -C "$build/$repo" rev-parse HEAD)"
    [ "$repo" = pox ] || printf ', '
  done
  printf '}\n'
} > "$out/versions.json"

ls -l "$out"
