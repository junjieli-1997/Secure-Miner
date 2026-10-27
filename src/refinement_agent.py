import jsonlines
import os
from openai import OpenAI
import openai
import pandas as pd
import json
import numpy as np
import random 
import argparse

refine_prompt ='''
You are a secure code expert.

Distill the {lan} code below into a minimal snippet
that explicitly isolates the core mitigation for CWE-{cwe_id}:
{cwe_description}.
Constraint: Prioritize demonstrating the concrete security
pattern. Simplify all dependencies and remove extraneous
logic. Output only the refined code.
Code:
```{lan}
{function_code}
```

Justification: 
{reason}
'''

refine_prompt = """
Refinement Constraints (Concrete & Scientific):**
**Isolation:** Strip all external business logic. Keep only the data flow that interacts with the CWE-relevant sink.
**Primitive Focus:** Use standard library primitives where possible to ensure the secure pattern is self-evident.
**The "Before/After" Trace:** Ensure the code explicitly demonstrates the **mitigation mechanism** (e.g., parameterized queries, bounds checking, or explicit type casting).
"""


def get_cwe_row(cwe_id):
    cwe_details_path = r"/data/mining_secure_practices/scripts/investigation_secure_patterns_in_different_datasets/scripts/data_synthesize/cwe-details.csv"
    df_cwe_details = pd.read_csv(cwe_details_path)
    cwe_id_remove0 = str(int(cwe_id))
    cwe_row = df_cwe_details[df_cwe_details['CWE-ID'].astype(str) == cwe_id_remove0]
    return cwe_row.iloc[0]

developer_msg = "You are an expert researcher in LLM-based AI agent."


### refine
def generate_batch_file_all_refine(matched_regex_path, output_file_path,refine_prompt):
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
        # cwe_id,lan = matched_item['key'].split('-')
        cwe_id = matched_item['cwe']
        lan = matched_item['language']
        cwe_row = get_cwe_row(cwe_id)

        # found_codes = matched_item['matched_codes']
        function = matched_item['function']
        reason = matched_item['verification_response']['reason']
        # print(f"Verifying CWE: {cwe_id} ({len(matched_results)}) in language: {lan}")
        
        prompt_input = refine_prompt.format(
            # cwe_id = cwe_description_process(target_cwe_des),
            cwe_id= str(cwe_row['CWE-ID']),
            cwe_description= str(cwe_row['Name']),
            lan = lan,
            function_code = function,
            reason = reason,
        )
        # print(prompt_input)
        # exit(0)
        batch_request = {
        "custom_id": f"request-{count}",
        "method": "POST",
        "url": "/v1/responses",
        "body": {
            # "model": "gpt-5-mini-2025-08-07",
            "model": "gpt-5.1",
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




def run_refinement_agent(matched_regex_path, output_file_path, api_key, refine_prompt=refine_prompt):
    generate_batch_file_all_refine(matched_regex_path, output_file_path, refine_prompt)
    upload_create_batch(output_file_path, api_key)
def parse_args():
    parser = argparse.ArgumentParser(
        description="Run refinement agent: generate a refine batch file and upload/create the batch."
    )
    parser.add_argument(
        "--secure-code-path",
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
        "--api-key",
        type=str,
        required=True,
        help="OpenAI API key. You can also set this via the OPENAI_API_KEY env var instead.",
    )
    parser.add_argument(
        "--refine-prompt",
        type=str,
        default=None,
        help="Refine prompt text. If omitted, falls back to the default 'refine_prompt' defined in the code.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    kwargs = dict(
        matched_regex_path=args.secure_code_path,
        output_file_path=args.output_file_path,
        api_key=args.api_key,
    )
    # Only override the default refine_prompt if the user actually passed one
    if args.refine_prompt is not None:
        kwargs["refine_prompt"] = args.refine_prompt

    run_refinement_agent(**kwargs)
