#!/usr/bin/env python3
"""
Fine-tune Qwen2.5-Coder (or any CodeLLM) for penetration testing using Unsloth.

Requirements:
    pip install unsloth torch xformers datasets accelerate bitsandbytes
    pip install ninja peft trl

Usage:
    python scripts/training/train_unsloth.py \\
        --model "unsloth/qwen2.5-coder-7b-bnb-4bit" \\
        --dataset "data/pentest_dataset.jsonl" \\
        --output "models/deep-eye-hacker-7b" \\
        --epochs 3

Output:
    - Adapter weights in --output dir
    - Merge + export to GGUF for OLLAMA: merge_and_export() step
"""

import json
import os
import sys
import argparse
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

os.environ["CUDA_VISIBLE_DEVICES"] = "0"


def parse_args():
    parser = argparse.ArgumentParser(description="Fine-tune LLM for pentesting with Unsloth")
    parser.add_argument("--model", default="unsloth/qwen2.5-coder-7b-bnb-4bit",
                        help="Base model on HuggingFace (4-bit quantized)")
    parser.add_argument("--dataset", default="data/pentest_dataset.jsonl",
                        help="Training dataset in JSONL format (instruction + output)")
    parser.add_argument("--output", default="models/deep-eye-hacker-7b",
                        help="Output directory for LoRA adapter")
    parser.add_argument("--epochs", type=int, default=3, help="Training epochs")
    parser.add_argument("--batch-size", type=int, default=2, help="Per-device batch size")
    parser.add_argument("--grad-accum", type=int, default=4, help="Gradient accumulation steps")
    parser.add_argument("--lr", type=float, default=2e-4, help="Learning rate")
    parser.add_argument("--lora-r", type=int, default=16, help="LoRA rank")
    parser.add_argument("--lora-alpha", type=int, default=32, help="LoRA alpha")
    parser.add_argument("--max-length", type=int, default=2048, help="Max sequence length")
    parser.add_argument("--export-gguf", action="store_true", default=True,
                        help="Export merged model to GGUF for OLLAMA")
    return parser.parse_args()


def format_prompt(example: dict) -> str:
    """Format instruction-response pair into chat template."""
    return f"### Instruction:\n{example['instruction']}\n\n### Response:\n{example['output']}"


def load_dataset(path: str):
    """Load JSONL dataset."""
    data = []
    with open(path) as f:
        for line in f:
            item = json.loads(line)
            data.append({"text": format_prompt(item)})
    return data


def train(args):
    print("[*] Loading Unsloth + model...")

    from unsloth import FastLanguageModel, is_bfloat16_supported
    from unsloth import unsloth_train
    from datasets import Dataset
    from transformers import TrainingArguments
    from trl import SFTTrainer

    # Load 4-bit quantized model
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=args.model,
        max_seq_length=args.max_length,
        dtype=None,
        load_in_4bit=True,
    )

    # Add LoRA adapters
    model = FastLanguageModel.get_peft_model(
        model,
        r=args.lora_r,
        target_modules=[
            "q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj",
        ],
        lora_alpha=args.lora_alpha,
        lora_dropout=0,
        bias="none",
        use_gradient_checkpointing="unsloth",
        random_state=42,
    )

    print(f"[*] Trainable parameters: {model.num_parameters(only_trainable=True):,}")

    # Load dataset
    raw_data = load_dataset(args.dataset)
    dataset = Dataset.from_list(raw_data)

    print(f"[*] Dataset size: {len(dataset)} examples")

    # Training arguments
    training_args = TrainingArguments(
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum,
        warmup_ratio=0.1,
        num_train_epochs=args.epochs,
        learning_rate=args.lr,
        fp16=not is_bfloat16_supported(),
        bf16=is_bfloat16_supported(),
        logging_steps=10,
        optim="adamw_8bit",
        weight_decay=0.01,
        lr_scheduler_type="cosine",
        seed=42,
        output_dir=args.output,
        report_to="none",
    )

    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=dataset,
        dataset_text_field="text",
        max_seq_length=args.max_length,
        dataset_num_proc=2,
        packing=True,
        args=training_args,
    )

    print("[*] Starting training...")
    trainer.train()

    # Save LoRA adapter
    model.save_pretrained(args.output)
    tokenizer.save_pretrained(args.output)
    print(f"[+] LoRA adapter saved to: {args.output}")

    # Merge and export to GGUF for OLLAMA
    if args.export_gguf:
        print("[*] Merging model and exporting to GGUF...")
        try:
            from unsloth import FastLanguageModel

            # Merge LoRA weights into base model
            merged_model = FastLanguageModel.merge_and_unload(model)
            print("[+] Model merged successfully")

            # Save full model in HuggingFace format
            merged_output = args.output + "-merged"
            merged_model.save_pretrained(merged_output, safe_serialization=True)
            tokenizer.save_pretrained(merged_output)
            print(f"[+] Merged model saved to: {merged_output}")

            # Convert to GGUF using llama.cpp
            print("[*] Converting to GGUF format (requires llama.cpp)...")
            import subprocess
            result = subprocess.run(
                ["python3", "-m", "llama_cpp.convert_hf_to_gguf",
                 merged_output,
                 "--outfile", f"{merged_output}/qwen2.5-deep-eye-hacker.gguf",
                 "--outtype", "q8_0"],
                capture_output=True, text=True, timeout=300,
            )
            if result.returncode == 0:
                print(f"[+] GGUF model: {merged_output}/qwen2.5-deep-eye-hacker.gguf")

                # Create OLLAMA Modelfile
                modelfile = f"""FROM {merged_output}/qwen2.5-deep-eye-hacker.gguf
TEMPLATE "### Instruction:\\n{{.Prompt}}\\n\\n### Response:\\n"
PARAMETER temperature 0.7
PARAMETER top_p 0.95
PARAMETER stop "### Instruction"
SYSTEM "You are Deep Eye Hacker, an AI assistant specialized in penetration testing, vulnerability detection, exploit development, and security assessment. Provide accurate, technical responses for security testing."
"""
                with open(f"{merged_output}/Modelfile", "w") as f:
                    f.write(modelfile)
                print(f"[+] OLLAMA Modelfile created at: {merged_output}/Modelfile")
                print(f"\n  -> Import ke OLLAMA:")
                print(f"     ollama create deep-eye-hacker -f {merged_output}/Modelfile")
            else:
                print(f"[!] GGUF conversion failed: {result.stderr}")
                print("    Install llama.cpp: pip install llama-cpp-python")
        except Exception as e:
            print(f"[!] Export skipped: {e}")
            print("    You can manually run converters later.")

    print("\n[DONE] Training complete!")


if __name__ == "__main__":
    args = parse_args()
    train(args)
