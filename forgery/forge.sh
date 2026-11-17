#!/usr/bin/env bash
# Reproduce the UltraKeccakZK Libra forgery from FORGERY.md / REPORT.md §7 and
# the artifacts that demonstrate the boundary-opening fix.
#
# Inputs (all checked into the repo):
#   circuits/simple_circuit/target/simple_circuit.json — compiled Noir circuit
#   circuits/simple_circuit/target/zk/vk                — verification key
#   forgery/false_witness.gz                            — witness with x = y = 2
#                                                        (violates assert(x != y))
#   forgery/bb-libra-forgery.patch                       — prover forgery patch
#   forgery/bb-libra-boundary.patch                      — prover boundary fix
#
# Environment:
#   BB_PATCHED  path to the patched bb binary   (default: /tmp/bb-forged/bin/bb)
#   BB_STOCK    path to a stock bb v0.87.0       (default: ~/.bb/bin/bb)
#   NARGO       path to nargo 1.0.0-beta.9      (default: ~/.nargo/bin/nargo)
#
# Outputs (checked into the repo after a run):
#   forgery/false_honest/  control: stock prover, false witness — must NOT verify
#   forgery/stock_format/  honest stock-format proof — rejected by the fixed
#                          verifier (missing A(1) = 0 boundary opening)
#   forgery/fixed/         honest proof from the boundary-patched prover —
#                          accepted by the fixed verifier
#   forgery/forged_v2/     the forgery recipe replayed against the
#                          boundary-patched prover — rejected by the fixed
#                          verifier (the attack is dead at the source)
#
#   forgery/forged/        the original stock-format forgery is NOT regenerated
#                          here: it predates the boundary fix and needs a prover
#                          carrying only bb-libra-forgery.patch. It stays
#                          committed as the regression fixture for
#                          forged_zk_proof_is_rejected.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CIRCUIT_JSON="$ROOT/circuits/simple_circuit/target/simple_circuit.json"
VK="$ROOT/circuits/simple_circuit/target/zk/vk"
FALSE_WITNESS="$ROOT/forgery/false_witness.gz"
BB_PATCHED="${BB_PATCHED:-/tmp/bb-forged/bin/bb}"
BB_STOCK="${BB_STOCK:-$HOME/.bb/bin/bb}"
NARGO="${NARGO:-$HOME/.nargo/bin/nargo}"

prove() { # $1 bb binary, $2 out dir, $3 witness, $4 extra env
  mkdir -p "$2"
  env $4 "$1" prove \
    --scheme ultra_honk \
    --oracle_hash keccak \
    --zk \
    --bytecode_path "$CIRCUIT_JSON" \
    --witness_path "$3" \
    --output_path "$2" \
    --output_format bytes_and_fields >/dev/null
  cp "$VK" "$2/vk"
}

echo "[0/5] checking toolchain"
"$BB_STOCK" --version
"$BB_PATCHED" --version   # must report 0.87.0-libra-boundary
"$NARGO" --version

echo "[1/5] stock prover, false witness (control; the proof must NOT verify)"
prove "$BB_STOCK" "$ROOT/forgery/false_honest" "$FALSE_WITNESS" ""
if "$BB_STOCK" verify --scheme ultra_honk --oracle_hash keccak --zk \
     --proof_path "$ROOT/forgery/false_honest/proof" \
     --public_inputs_path "$ROOT/forgery/false_honest/public_inputs" \
     --vk_path "$VK" >/dev/null 2>&1; then
  echo "control proof unexpectedly verified" >&2
  exit 1
fi
echo "      rejected, as expected"

echo "[2/5] stock prover, honest witness (stock format; rejected by the fixed verifier)"
HONEST_WITNESS="$ROOT/circuits/simple_circuit/target/simple_circuit.gz"
if [[ ! -f "$HONEST_WITNESS" ]]; then
  (cd "$ROOT/circuits/simple_circuit" && "$NARGO" execute >/dev/null)
fi
prove "$BB_STOCK" "$ROOT/forgery/stock_format" "$HONEST_WITNESS" ""

echo "[3/5] boundary-patched prover, honest witness (fixed format; must verify)"
prove "$BB_PATCHED" "$ROOT/forgery/fixed" "$HONEST_WITNESS" ""
"$BB_PATCHED" verify --scheme ultra_honk --oracle_hash keccak --zk \
  --proof_path "$ROOT/forgery/fixed/proof" \
  --public_inputs_path "$ROOT/forgery/fixed/public_inputs" \
  --vk_path "$VK"

echo "[4/5] patched prover (BB_FORGE_LIBRA=1), false witness (forgery replay)"
prove "$BB_PATCHED" "$ROOT/forgery/forged_v2" "$FALSE_WITNESS" "BB_FORGE_LIBRA=1"
if "$BB_PATCHED" verify --scheme ultra_honk --oracle_hash keccak --zk \
     --proof_path "$ROOT/forgery/forged_v2/proof" \
     --public_inputs_path "$ROOT/forgery/forged_v2/public_inputs" \
     --vk_path "$VK" >/dev/null 2>&1; then
  echo "forged_v2 unexpectedly verified: the boundary fix is not effective" >&2
  exit 1
fi
echo "      rejected, as expected (the forgery is dead under the fix)"

echo "[5/5] done — check the rest with: cargo test -p ultrahonk_soroban_verifier --test forgery_test"
