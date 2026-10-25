#!/usr/bin/env bash
# Run Tauri build with a live progress bar based on Cargo.lock crate count.
set -o pipefail
cd /home/cxarch/Downloads/Opencode-Stuff/iloader-src || exit 1

total=$(grep -c '^name = ' src-tauri/Cargo.lock 2>/dev/null || echo 1)
[ "$total" -lt 1 ] && total=1
done=0

bun run tauri build 2>&1 | while IFS= read -r line; do
  printf '%s\n' "$line"
  if [[ "$line" == Compiling* ]]; then
    done=$((done+1))
    pct=$((done*100/total))
    bar_len=40
    filled=$((pct*bar_len/100))
    empty=$((bar_len-filled))
    printf '\r['
    printf '%*s' "$filled" '' | tr ' ' '#'
    printf '%*s' "$empty" '' | tr ' ' '-'
    printf '] %d%% (%d/%d)\n' "$pct" "$done" "$total"
  fi
done
echo "Build finished."