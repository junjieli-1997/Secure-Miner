# Improving Secure Code Generation for LLMs by Mining Secure Coding Practices

Secure-Miner mines secure practice from GitHub repositories to improve the secure code generation using LLMs.

![Figure 1](/data/mining_secure_practices/replication/figs/fig1.png)
 
*An Overview of Secure-Miner*

![Figure 2](/data/mining_secure_practices/replication/figs/fig2.png)

![Figure 3](/data/mining_secure_practices/replication/figs/fig3.png)
*Results of Secure-Miner*
## Setup
Install Python dependencies:
```console
pip install -r requirements.txt
``


## The pipeline of Secure-Miner
run regex agent 

```console
python3 ./src/regex_agent.py --cwe-details-path cwe_details.csv --output-file-path "regex.jsonl" --api-key sk-xxxx --num 5
```

run verification agent, `matched_regex.jsonl` stores the code snippets matched by regex

```console
python3 ./src/verification_agent.py  \
  --matched-regex-path matched_regex.jsonl  \
  --output-file-path batch_input.jsonl  \
  --api-key sk-xxxx
  ```

run refinement agent `secure-code-path.jsonl` is the code snippets that verified that are security for a specific CWE. 

```console
python3 ./src/refinement_agent.py  \
  --secure-code-path secure-code-path.jsonl  \
  --output-file-path refine_batch_input.jsonl  \
  --api-key sk-xxxx
  ```


## Model Fine-tuning & RAG
For the fine-tuning approach
```console
python3 ./src/finetuning/train.py \
--pretrain_name codellama-7b \
--model_dir ./codellama-7b-secure-miner \
--datasets ../data/mined_data/mined_data.jsonl  ../data/training_data/evol.jsonl \
--num_train_epochs 2 --lora 1
```

For the RAG appraoch
```console
python3 ./src/rag/Defense_Standard_with_mining.py \
  --vector_db_path ./embeddings/kng_rc_jina-embeddings-v3.faiss \
  --output_path ./datasets/def_std_all.json
```


## Evaluation
For CWEval, please follow the work CWEval to evaluate the generated code on docker. https://github.com/Co1lin/CWEval

For the newly created ones, 
```console
python3 ./src/evaluation/evaluation_cybersec.py \
        --analyze-path "/path/to/generated_{gen_num}/{lan}" \
        --results-path "/path/to/generated_{gen_num}/{lan}_results.json" \
        --gen-num gen_num
```

## Datasets
The mined data in this paper has stored it the folder `data/mined_data/mined_data.jsonl`.
The benchmark data  has stored in the folder `data/evaluation_dataset`.
The model weight in `data/models_weights`.