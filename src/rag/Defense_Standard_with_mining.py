import numpy as np
import difflib
import json
import hashlib
from collections import defaultdict
from langchain_community.vectorstores import FAISS
from transformers import AutoTokenizer, AutoModel
from typing import List 
import torch
import re
import numpy as np
import argparse
import os
from configs import *
from utils import get_splitter, extract_code_blocks, remove_duplicates_preserve_order
from copy import deepcopy
from sklearn.metrics.pairwise import cosine_similarity
from tqdm import tqdm
import jsonlines

def construct_prompt(root_causes: List[str], instruction:str, retrieved_codes:List[str], scenario ="" ):
    prefix = "Your task is to generate secure code for the following functionality. Before you start writing the code, please review the security knowledge provided below, which includes potential vulnerabilities and how to fix them. Use this knowledge to avoid common security flaws and ensure the generated code is secure.\nBesides, I would provide you with some reference examples, you can reference the examples as a reference if helpful.\n"
    knowledge = """### Security Knowledge:\n""" + "\n".join(root_causes) + "\n---\n\n"
    
    refs = "### Reference Code Examples:\n"
    for i, example in enumerate(retrieved_codes):
        refs += f"**Example {i+1}:**\n ```\n{example}\n```\n\n"
    task = "### Task:\n- Now, please generate the code for the following functionality:\n" + instruction + "\n" "Response:\n" + scenario + "\n"
    suffix = '''\n### Notes:
- Ensure that the code you generate avoids the vulnerabilities described in the knowledge above.
- Pay attention to using secure patterns and avoiding insecure coding practices.
- If you are unsure about a security decision, refer to the fixing examples provided above for guidance.
- Only return the code, don't include any other information, such as a preamble or suffix.\n'''
    # return prefix + knowledge + refs + task + suffix
    return prefix + knowledge + suffix  + task

def load_local_model(model_path):
    tokenizer = AutoTokenizer.from_pretrained(model_path)
    model = AutoModel.from_pretrained(model_path, trust_remote_code=True)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    # device = torch.device("cpu")
    model.to(device)
    return tokenizer, model


def generate_embeddings(model, texts, batch_size=2):
    embeddings = []
    for i in range(0, len(texts), batch_size):
        # print(i)
        batch_texts = texts[i:i + batch_size]
        with torch.no_grad():
            batch_embeddings = model.encode(batch_texts)
        embeddings.extend(batch_embeddings)
    return embeddings


def load_and_split_code_files(code_texts, languages, chunk_size, chunk_overlap):
    documents = []
    for code, cur_lang in zip(code_texts, languages):
        splitter = get_splitter(cur_lang, chunk_size, chunk_overlap)
        documents.extend(splitter.create_documents([code]))

    return documents

# 2. 构建向量数据库
def build_vector_database(root_causes, model):
    # 生成 Embedding
    documents = [root_cause["functionality"] for root_cause in root_causes]
    # documents = [root_cause["vulnerable_pattern"] for root_cause in root_causes] # debug
    embeddings = generate_embeddings(model, documents, batch_size=2)
    str_root_causes = [json.dumps(root_cause) for root_cause in root_causes]
    # 构建 FAISS 向量数据库
    vector_db = FAISS.from_embeddings(
        text_embeddings=list(zip(str_root_causes, embeddings)),
        embedding=model.encode
    )
    return vector_db


def find_root_causes(vector_db, query_text, top_k=3):
    similar_docs = vector_db.similarity_search(query_text, k=top_k)
    return similar_docs


def extract_vuln_pattern(root_cause: str):
    def format_string(text):
        text = re.sub(r'Vulnerable Pattern:\s*\n+', 'Vulnerable Pattern:', text)
        text = re.sub(r'Fixing Pattern:\s*\n+', 'Fixing Pattern:', text)
        return text
    
    result = []
    root_cause = format_string(root_cause)
    lines = root_cause.splitlines()
    for line in lines:
        if line.strip().startswith('#'):
            result.append(line)
        elif line.strip().startswith('- Vulnerable Pattern:'):
            result.append(line)
        elif line.strip().startswith('- Fixing Pattern:'):
            result.append(line)
    return "\n".join(result)

def calculate_md5(input_string):
    md5_hash = hashlib.md5()
    md5_hash.update(input_string.encode('utf-8'))
    return md5_hash.hexdigest()

def filter_code_snippets(buggy_codes, fixed_codes, root_causes, languages):
    # Construct the mapping from buggy code snippet to root_cause
    
    buggy2RC = {}
    documents = []
    for b_code, f_code, r_cause, cur_lang in zip(buggy_codes, fixed_codes, root_causes, languages):
        buggy_lines = b_code.splitlines()
        fixed_lines = f_code.splitlines()
        updated_buggy_lines = []
        differ = difflib.Differ()
        diff = list(differ.compare(buggy_lines, fixed_lines))

        for line in diff:
            if line.startswith('- '):
                if line[2:].strip() != "":
                    updated_buggy_lines.append(line[2:] + RC_TAG)
            elif line.startswith('  '):
                updated_buggy_lines.append(line[2:])
        
        splitter = get_splitter(cur_lang, CHUNK_SIZE, CHUNK_OVERLAP)
        cur_docs = splitter.create_documents(["\n".join(updated_buggy_lines)])
        for snippet in cur_docs:
            if RC_TAG in snippet.page_content:
                clear_content = snippet.page_content.replace(RC_TAG, "")
                buggy2RC[clear_content] = r_cause
                documents.append(clear_content)

    return documents, buggy2RC

def parser_root_causes(root_causes):
    all_rcs = []
    for rcs in root_causes:
        for cur_rc in rcs.split("\n#"):
            if not rcs.startswith("#"):
                cur_rc = "#" + cur_rc
            cur_rc = re.sub(r'Vulnerable Pattern:\s*\n+', 'Vulnerable Pattern:', cur_rc)
            cur_rc = re.sub(r'Fixing Pattern:\s*\n+', 'Fixing Pattern:', cur_rc)
            cur_rc = re.sub(r'Vulnerable Example:\s*\n+', 'Vulnerable Example:', cur_rc)
            cur_rc = re.sub(r'Fixing Example:\s*\n+', 'Fixing Example:', cur_rc)
            pattern = re.compile(
                r"# (.*?)\n"  
                r" - Vulnerable Pattern: (.*?)\n"  
                r" - Vulnerable Example: (.*?)\n"  
                r" - Fixing Pattern: (.*?)\n" 
                r" - Fixing Example: (.*?)(?:\n|$)",
                re.DOTALL
            )
            matches = pattern.findall(cur_rc)

            for match in matches:
                for x in match:
                    if x.strip() == "":
                        raise ValueError("Invalid input string.")
                entry = {
                    "Name": match[0].replace("Pattern name:", "").strip(),
                    # "vuln_pattern": match[1].strip(),
                    # "vuln_example": match[2].strip(),
                    "fix_pattern": match[3].strip(),
                    "fix_example": match[4].strip(),
                }
                all_rcs.append(entry)
    return all_rcs

def read_root_causes(file_path):
    root_causes = []
    lang_cnt = defaultdict(int)
    with open(file_path, "r") as file:
        data = [json.loads(x) for x in file.readlines()]
        tmp_root_causes = [item["root_cause"] for item in data]
        languages = [item["language"] for item in data]
        for i, t_r in enumerate(tmp_root_causes):
            if t_r is None:
                continue
            blocks = extract_code_blocks(t_r)
            tmp_cnt = 0
            if len(blocks) > 0:
                for block in blocks:
                    if "pattern_name" not in block:
                        continue
                    try:
                        parsed_res = json.loads(block)
                        if isinstance(parsed_res, list):
                            root_causes.extend(parsed_res)
                            tmp_cnt += len(parsed_res)
                        elif isinstance(parsed_res, dict) and "pattern_name" in parsed_res:
                            root_causes.append(parsed_res)
                            tmp_cnt += 1
                    except Exception as e:
                        print(e)
            lang_cnt[languages[i]] += tmp_cnt
        return root_causes

def measure_similarity(model, test_1, text_2):
    test_1_vec = model.encode([test_1])
    text_2_vec = model.encode([text_2])
    return cosine_similarity(test_1_vec, text_2_vec)[0]

def select_root_causes(embed_model, root_causes: tuple[str, str], top_k: int):
    """
    Select the top k most similar root causes for a given query.

    Args:
        embed_model (_type_): _description_
        root_causes (tuple[str, str]): _description_
        top_k (int): _description_

    Returns:
        _type_: _description_
    """
    tmp_rec = []
    for query, cur_RCs in root_causes:
        query_vec = embed_model.encode([query])
        causes_vec = embed_model.encode(cur_RCs)
        tmp_rec.extend([(x, cosine_similarity(query_vec, causes_vec[i].reshape(1, -1))[0]) for i, x in enumerate(cur_RCs)])
    tmp_rec.sort(key=lambda x:x[1], reverse=True)
    return [x[0] for x in tmp_rec[:top_k]]


def read_jsonl(file_path):  
    data = []
    with jsonlines.open(file_path, mode='r') as reader:
        for obj in reader:
            data.append(obj)
    return data
def clean_doc(json_str):
    # Parse the string into a dictionary
    data = json.loads(json_str)
    
    # Remove the unwanted keys if they exist
    data.pop("vulnerable_pattern", None)
    data.pop("vulnerable_example", None)
    
    # Return as a string again (or just return the dict if you prefer)
    return json.dumps(data)

def main(args, root_cause_path, embed_model_path, vector_db_path, broken_instruction_path,  output_path, mining_case_path, root_cause_num=1, pattern="full" ):#pattern="full" 
    # root_causes = read_jsonl(root_cause_path)
    root_causes = json.load(open(root_cause_path, "r"))

    mining_cases = []
    with jsonlines.open(mining_case_path, mode='r') as reader:
        for obj in reader:
            mining_cases.append(obj)
    # mining_cases = json.load(open(mining_case_path, "r"))
    # print(len(root_causes))
    # exit(0)
    root_causes.extend(mining_cases)
    # print(len(root_causes))
    # exit(0)
    broken_instructions = read_jsonl(broken_instruction_path)
    prompt_to_queries = {item["description"]:item["broken_instructions"] for item in broken_instructions}
    prompt_to_queries.update({item["description"].split("\n")[0]:item["broken_instructions"] for item in broken_instructions})

    _, model = load_local_model(embed_model_path)
    if os.path.exists(vector_db_path):
        print("Loading vector db from local...")
        vector_db = FAISS.load_local(vector_db_path, model.encode, allow_dangerous_deserialization=True)
    else:
        print("Building vector db from local...")
        vector_db = build_vector_database(root_causes, model)
        vector_db.save_local(vector_db_path)
    
    new_items = []
    

    total_rag = 0
    total_mining_rag = 0

    for i, cur_inst in enumerate(tqdm(broken_instructions)):
        print(i)
        ori_prompt = cur_inst["description"]
        
        if ori_prompt in prompt_to_queries:
            broken_queries = prompt_to_queries[ori_prompt]
        else:
            raise ValueError("No broken query found for this prompt")

        cur_sim_RCs = []
        for cur_query_dict in broken_queries:
            query = cur_query_dict["description"]
            print(query)
            similar_docs = find_root_causes(vector_db, query, top_k=root_cause_num)
            exit(0)
            
                    # exit(0)
            # print(similar_docs)
            # exit(0)
            ## original
            # cur_sim_RCs.append((query, [x.page_content for x in similar_docs]))
            
            ## without vul code
            cleaned_contents = [clean_doc(x.page_content) for x in similar_docs]
            cur_sim_RCs.append((query, cleaned_contents))
        # retrieved_codes = cur_inst["similar_codes"]
        retrieved_codes = []
        final_RCs = []
        for i in range(args.root_cause_per_module):
            final_RCs.extend([x[1][i] for x in cur_sim_RCs])
        if pattern == "tidy":
            for i in range(len(final_RCs)):
                tmp = json.loads(final_RCs[i])
                if "pattern_name" in tmp:
                    tmp.pop("pattern_name")
                if "vulnerable_example" in tmp:
                    tmp.pop("vulnerable_example")
                if "fixing_example" in tmp:
                    tmp.pop("fixing_example")
                final_RCs[i] = json.dumps(tmp)
        new_item = deepcopy(cur_inst)
        removed_final_RCs = remove_duplicates_preserve_order(final_RCs)


        # print("-"*40)
        new_item["srag_description"] = construct_prompt(remove_duplicates_preserve_order(final_RCs), ori_prompt.split("\n")[0], retrieved_codes, cur_inst["scenario"])
        new_items.append(new_item)
        # print(new_item["srag_description"])
        # exit(0)
    with jsonlines.open(output_path, mode='w') as writer:
        for item in new_items:
            writer.write(item)


def parse_args():
    parser = argparse.ArgumentParser(description="Vulnerability Description Generation Parameters")
    parser.add_argument("--language", default="all", help="Language setting (default: all)")
    parser.add_argument("--embed_model_path", required=False, default="jinaai/jina-embeddings-v3", help="Path to embedding model")
    # parser.add_argument("--embed_model_path", required=False, default="data/mining_secure_practices/scripts/gen_code_large_models/CodeGuarder_AE/CodeGuarder/src_mod/jina-embeddings-v3", help="Path to embedding model")
    parser.add_argument("--vector_db_path", help="Custom vector DB path (optional)")
    # parser.add_argument("--root_cause_path", required=True, help="Path to root cause data")
    parser.add_argument("--root_cause_path", required=False, default="../data/mined_data/Root_Causes_codeguarder.json", help="Path to root cause data")

    # parser.add_argument("--broken_instruction_path", required=True, help="Path to broken instructions")
    parser.add_argument("--broken_instruction_path", required=False, default="../data/evaluation_dataset/cweval-low_resource-broken_tasks-processed.jsonl", help="Path to broken instructions")

    parser.add_argument("--output_path", help="Custom output path (optional)")
    parser.add_argument("--root_cause_num", type=int, default=3, help="Number of root causes")
    parser.add_argument("--root_cause_per_module", type=int, default=3, 
                       help="Number of root causes per module (default: 2)")
    parser.add_argument("--mining_case_path", type=str, required=False, default="../data/mined_data/mined_data.jsonl", help="Path to the mining cases to be added as root causes")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    
    # Generate output path if not provided
    if not args.output_path:
        args.output_path = f"./datasets/def_std_{args.language}.json"

    if not args.vector_db_path:
        args.vector_db_path = f"./embeddings/kng_rc_{os.path.basename(args.embed_model_path)}.faiss"
     
    # args.root_cause_path = KNG_BASE_PATH
    # # args.embed_model_path = "jinaai/jina-embeddings-v2-base-code"
    # args.vector_db_path = VECTOR_DB_PATH
    # args.broken_instruction_path = BROKEN_INST_PATH
    # args.output_path = OUTPUT_PATH
    # args.mining_case_path = MINING_CASES_PATH
    # args.root_cause_num = num
    # args.root_cause_per_module = num
    main(args, 
        args.root_cause_path, 
        args.embed_model_path, 
        args.vector_db_path, 
        args.broken_instruction_path, 
        args.output_path, 
        args.mining_case_path,
        args.root_cause_num,
        )
    # main()