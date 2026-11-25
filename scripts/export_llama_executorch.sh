#!/usr/bin/env bash
# Export Llama 3.2 1B Instruct -> ExecuTorch .pte (XNNPACK, 4-bit groupwise weights) and build the runner for Arm.
# Follows the official ExecuTorch Llama guide (https://github.com/pytorch/executorch/tree/main/examples/models/llama).
# Do the export on a laptop/PC (needs the HF-licensed checkpoint), then copy the .pte + tokenizer to the Pi/phone.
# NOTE: flags change between ExecuTorch releases - check the README of the version you install.
set -e
pip install executorch                     # or build from source for the latest runner
# 1) get weights (accept the Llama license on Hugging Face first):  huggingface-cli download meta-llama/Llama-3.2-1B-Instruct --local-dir llama32_1b
# 2) export
python -m examples.models.llama.export_llama \
  --checkpoint llama32_1b/original/consolidated.00.pth --params llama32_1b/original/params.json \
  -kv --use_sdpa_with_kv_cache -X --xnnpack-extended-ops -d fp32 \
  --quantization_mode 8da4w --group_size 32 --max_seq_length 512 --max_context_length 512 \
  --metadata '{"get_bos_id":128000,"get_eos_ids":[128009,128001]}' --output_name llama32_1b_q4.pte
# 3) build llama_main for the target (on the Pi itself, or cross-compile with the aarch64 toolchain)
#    cmake --preset llm  &&  cmake --build cmake-out -j4 --target llama_main     (see the ExecuTorch Llama README)
# 4) point Trinetra at it:
cat <<'ENV'
export TRINETRA_LLAMA_BIN=$HOME/executorch/cmake-out/examples/models/llama/llama_main
export TRINETRA_LLAMA_MODEL=$HOME/models/llama32_1b_q4.pte
export TRINETRA_LLAMA_TOKENIZER=$HOME/models/tokenizer.model
python app/server.py        # badge will switch to "Llama via ExecuTorch"
ENV
