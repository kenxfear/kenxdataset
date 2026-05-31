# Deep Eye Hacker — Model Training

Fine-tune Qwen2.5-Coder-7B (atau model lain) untuk penetration testing menggunakan Unsloth atau Axolotl.

## Prerequisites

**GPU minimal 8GB VRAM** (T4, RTX 3070+, A10G, dll).

## Quick Start (Google Colab - Free T4 GPU)

Buka notebook Colab yang sudah disiapkan:

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/zakirkun/deep-eye/blob/main/scripts/training/deep_eye_colab.ipynb)

Atau manual:
1. Buka https://colab.research.google.com/
2. Upload `scripts/training/deep_eye_colab.ipynb`
3. Runtime → Change runtime type → GPU T4
4. Jalankan sel-sel secara berurutan

## Unsloth Training (Recommended)

```bash
# 1. Install
pip install unsloth torch xformers datasets accelerate bitsandbytes
pip install ninja peft trl

# 2. Prepare dataset
python scripts/training/prepare_dataset.py

# 3. Train (8GB VRAM minimum)
python scripts/training/train_unsloth.py \
    --model "unsloth/qwen2.5-coder-7b-bnb-4bit" \
    --dataset "data/pentest_dataset.jsonl" \
    --output "models/deep-eye-hacker-7b" \
    --epochs 3 \
    --batch-size 2 \
    --lr 2e-4

# 4. Import ke OLLAMA
ollama create deep-eye-hacker -f models/deep-eye-hacker-7b-merged/Modelfile
ollama run deep-eye-hacker
```

## Axolotl Training (Alternative)

```bash
pip install axolotl
accelerate launch -m axolotl.cli.train scripts/training/train_axolotl.yml

# Export ke GGUF
python -m axolotl.cli.merge_lora scripts/training/train_axolotl.yml
python -m llama_cpp.convert_hf_to_gguf models/deep-eye-axolotl-merged \
    --outfile models/deep-eye-axolotl.gguf --outtype q8_0

# Import ke OLLAMA
echo "FROM models/deep-eye-axolotl.gguf" > Modelfile
ollama create deep-eye-hacker-axolotl -f Modelfile
```

## Training Effects

Setelah fine-tuning, model akan lebih baik dalam:

| Task | Sebelum | Sesudah |
|------|---------|---------|
| Generate SQLi payload | Generic | Context-aware, WAF bypass |
| Analisis false positive | Sering error | Akurat, sesuai pola CVE |
| Generate report | Verbose | Professional, severity tepat |
| CVE exploitation | Tidak tahu | Tahu vektor eksploitasi |

## Dataset Customization

Tambahkan data sendiri di `data/pentest_dataset.jsonl` dengan format:

```json
{"instruction": "Your pentest question", "output": "Expert answer"}
```

Kumpulkan dari:
- Payload yang Anda temukan sendiri saat pentest
- CVE writeups dari Exploit-DB
- Report/bug bounty writeup pribadi
