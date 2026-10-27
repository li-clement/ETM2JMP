#!/usr/bin/env bash
# convert_all.sh — regenerate every shipped .jmp in output/ byte-for-byte
# from the trainers in input/ (plus the real SH4 default.xbe where needed).
# This is the canonical record of how each artifact was produced.
set -euo pipefail
cd "$(dirname "$0")"

python3 etm2jmp.py "input/Baldurs Gate - Dark Alliance 2.etm" \
  --game-title "Baldur's Gate - Dark Alliance 2" \
  --jmp "output/BGDA2_infinite_trainer_usa.jmp"

python3 etm2jmp.py "input/Baldurs Gate Dark Alliance 2 p16 ntsc.etm" \
  --game-title "Baldur's Gate - Dark Alliance 2" \
  --jmp "output/BGDA2_infinite_trainer_ntsc.jmp"

if [ -f input/default.xbe ]; then
  # safe subset (options 2-3 only; runtime-hook option excluded) — exact mode
  python3 etm2jmp.py "input/Silent Hill 4 [plus3] (NTSC).etm" \
    --xbe input/default.xbe \
    --jmp "output/Silent Hill 4 [plus3] (NTSC).jmp"

  # hardware-verified full build: hook handler relocated into header padding
  python3 etm2jmp.py "input/Silent Hill 4 [plus3] (NTSC).etm" \
    --xbe input/default.xbe --hook-cave \
    --game-title "Silent Hill 4: The Room" \
    --jmp "output/Silent Hill 4 [plus3] (NTSC)_verified.jmp"
else
  echo "note: input/default.xbe missing — skipping SH4 exact-mode patches" >&2
  python3 etm2jmp.py "input/Silent Hill 4 [plus3] (NTSC).etm" \
    --jmp "output/Silent Hill 4 [plus3] (NTSC).jmp"
fi

python3 etm2jmp.py "input/Silent Hill 4 p3 ntsc.etm" \
  --game-title "Silent Hill 4: The Room" \
  --jmp "output/Silent Hill 4 p3 ntsc.jmp"

echo
echo "== re-validating every generated patch =="
python3 validate_jmp.py output/*.jmp
