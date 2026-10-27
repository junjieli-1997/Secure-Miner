import os
import json
import argparse

# from safecoder.metric import FuncEval, SecEval, MMLUEval, TruthfulQAEval
import os
import yaml
import json
import numpy as np
from tabulate import tabulate
from collections import OrderedDict
import pandas as pd
import csv
from collections import defaultdict
from openai import OpenAI
import openai
import jsonlines


developer_msg = "You are an expert researcher in LLM-based AI agent."
verification_prompt = '''
You are a secure code reviewer. 
Assess if the <Language> code below is relevant to and securely mitigates 
CWE-{cwe_id1} ({cwe_id_name})
{cwe_id_des}

Code snippet:
```{lan}
{code_snippet}
```

Output format (strict):
{{
  "relevant_to_cwe": "Yes" | "No",
  "prevents_cwe": "Yes" | "No" | "None",
  "reason": "<concise justification in 1-3 sentences>"
}}

If "relevant_to_cwe" = "No", then set "prevents_cwe" to "None".
Keep the reason short and concrete; cite specific lines, APIs, or patterns from the snippet when possible.
Do not include remediation advice or step-by-step reasoning—just the conclusion.
'''

example_prompt = '''
Example (for illustration only; do not include in output):

CWE: CWE-79 — Cross-Site Scripting (XSS)
Code:
```js
res.send(`<div>${{req.query.name}}</div>`);
```

Expected output:
{{
  "relevant_to_cwe": "Yes",
  "prevents_cwe": "No",
  "reason": "User input is inserted into HTML without encoding or sanitization, enabling script injection."
}}
'''

def get_cwe_row(cwe_id):
    cwe_details_path = r"/data/mining_secure_practices/scripts/investigation_secure_patterns_in_different_datasets/scripts/data_synthesize/cwe-details.csv"
    df_cwe_details = pd.read_csv(cwe_details_path)
    cwe_id_remove0 = str(int(cwe_id))
    cwe_row = df_cwe_details[df_cwe_details['CWE-ID'].astype(str) == cwe_id_remove0]
    return cwe_row.iloc[0]


### verify
def generate_batch_file(matched_regex_path, output_file_path,  verification_prompt):
    """
    Generate a batch file for OpenAI Batch API from a CSV file.
    
    Args:
        matched_regex_path: Path to input jsonlines
        output_file_path: Path to output JSONL batch file
        prompt_id: Your prompt ID from OpenAI platform
    """
    with jsonlines.open(matched_regex_path, mode='r') as reader:
        matched_results = []
        for obj in reader:
            matched_results.append(obj)
    count = 0
    batch_list = []
    for matched_item in matched_results:
        # cwe_id = matched_item['cwe']
        
        # lan = matched_item['language']

        # cwe_id,lan = matched_item['key'].split('-')
        cwe_id = matched_item['cwe']
        lan = matched_item['language']
        cwe_row = get_cwe_row(cwe_id)
        # found_codes = matched_item['matched_codes']
        # print(f"Verifying CWE: {cwe_id} ({len(matched_results)}) in language: {lan}")




        prompt_input = verification_prompt.format(
            # cwe_id = cwe_description_process(target_cwe_des),
            cwe_id1= str(cwe_row['CWE-ID']),
            cwe_id_name= str(cwe_row['Name']),
            cwe_id_des= str(cwe_row['Description']),
            lan = lan,
            cwe_id2= str(cwe_row['CWE-ID']),
            code_snippet = matched_item['function'],
        )  +'\n' +  example_prompt
        # print(prompt_input)
        # exit(0)
        batch_request = {
        "custom_id": f"request-{count}",
        "method": "POST",
        "url": "/v1/responses",
        "body": {
            # "model": "gpt-5-mini-2025-08-07",
            "model": "gpt-5.1-codex",
            "input": [
                {
                    'role': 'user',
                    'content': prompt_input
                }
            ],
            "store": True
            }
        }
        count += 1

        batch_list.append(batch_request)

    with jsonlines.open(output_file_path, 'w') as batch_file:  
        for row in batch_list:
            batch_file.write(row) 
    
    print(f"Batch file created successfully: {output_file_path}")
    print(f"Total requests: {count}")


def upload_create_batch(jsonl_path, api_key):
    from openai import OpenAI
    api_key = api_key
    client = OpenAI(
        api_key = api_key
    )
    batch_input_file = client.files.create(
        file=open(jsonl_path, "rb"),
        purpose="batch"
    )
    print(batch_input_file)
    batch_input_file_id = batch_input_file.id
    msg_obj = client.batches.create(
        input_file_id=batch_input_file_id,
        endpoint="/v1/responses",
        completion_window="24h",
        metadata={
            "description": "codegen"
        }
    )
    print(msg_obj)

def run_verification_agent( api_key, matched_regex_path, output_file_path,verification_prompt = verification_prompt):
    generate_batch_file(matched_regex_path, output_file_path,  verification_prompt)
    upload_create_batch(output_file_path, api_key)

def parse_args():
    parser = argparse.ArgumentParser(
        description="Run verification agent: generate a batch file and upload/create the batch."
    )
    parser.add_argument(
        "--matched-regex-path",
        type=str,
        required=True,
        help="Path to the matched regex input file.",
    )
    parser.add_argument(
        "--output-file-path",
        type=str,
        required=True,
        help="Path to write the generated batch file.",
    )
    parser.add_argument(
        "--developer-msg",
        type=str,
        required=True,
        help="Developer/system message to include in the batch prompt.",
    )
    parser.add_argument(
        "--user-prompt",
        type=str,
        required=True,
        help="User prompt to include in the batch prompt.",
    )
    parser.add_argument(
        "--api-key",
        type=str,
        required=True,
        help="OpenAI API key. You can also set this via the OPENAI_API_KEY env var instead.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run_verification_agent(
        matched_regex_path=args.matched_regex_path,
        output_file_path=args.output_file_path,
        api_key=args.api_key,
    )