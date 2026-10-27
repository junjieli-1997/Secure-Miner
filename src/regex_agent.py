import jsonlines
import pandas as pd
import jsonlines
import json
from anthropic.types.beta.message_create_params import MessageCreateParamsNonStreaming
from anthropic.types.beta.messages.batch_create_params import Request
import argparse

import jsonlines
import os
import time

from openai.types.chat import ChatCompletion


import json
import pandas as pd
import os
from openai import OpenAI



all_low_resource = ['329-py', '918-cpp', '326-py', '760-cpp', '326-c', '468-c', '327-js', '643-py', '943-c', '113-cpp', '326-go', '918-c', '117-js', 
                    '328-cpp', '760-py', '117-c', '208-js', '760-go', '095-js', '347-cpp', '643-cpp', '328-py', '643-js', '329-js', '326-js', '117-py', 
                    '326-cpp', '117-cpp', '377-c', '943-js', '113-js', '943-cpp', '760-js', '338-cpp', '1333-cpp', '943-py', '329-c', '327-py', '329-cpp', 
                    '113-c', '502-js', '329-go', '113-go', '377-py', '095-py', '113-py', '643-c', '760-c', '338-c', '327-go', '643-go', '117-go', '943-go', 
                    '327-cpp', '676-c', '170-c']



regex_prompt = """
Based on the cwe description and cwe code example below, \
generate a list of Python regular expressions specifically  \
designed to identify the secure, mitigated functions or patterns \
associated with preventing this CWE.

{cwe_id_des} in {language} code.
"""
lan_mapping = {
    'c': 'C',
    'cpp': 'C++',
    'go': 'Go',
    'js': 'JavaScript',
    'py': 'Python',
}



def gpt5_gen(client, inputs):

    resp = client.responses.create(
        model = "gpt-5",
        input=inputs
    )

    # print(resp.output_text)
    return resp.output_text

def cwe_description_process(target_row):
    # print(target_row)
    return 'CWE-' + str(target_row['CWE-ID']) + ': ' + target_row['Name']

def construct_prompt(prompt, target_cwe_des,lan):
    prompt_input = prompt.format(
        cwe_id_des = cwe_description_process(target_cwe_des),
        language = lan
    )
    return prompt_input

def gen_regex(cwe_details_path,output_file_path ,api_key, num):


    for i in range(num):
        results = []

        client = OpenAI(
            # api_key=os.environ.get("OPENAI_API_KEY"),
            api_key = api_key
        )
        df_cwe_details = pd.read_csv(cwe_details_path)

        for cwe_lan in all_low_resource:
            print(cwe_lan)


            cwe_id = cwe_lan.split('-')[0]
            cwe_id_remove0 = str(int(cwe_id))
            ## serach the row of df_cwe_details that the CWE is equal to cwe_id in

            cwe_row = df_cwe_details[df_cwe_details['CWE-ID'].astype(str) == cwe_id_remove0]
            if cwe_row.empty:
                raise ValueError(f"no row found for CWE {cwe_id}")
            # print(cwe_id_remove0)



            cwe_row = cwe_row.iloc[0]
            cwe_cat = cwe_row['Name']
            cwe_des = cwe_row['Description']

            lan = cwe_lan.split('-')[1]


            language_dic = {'java': 'Java','js': 'JavaScript', 'Ruby': 'ruby', 'go':'Go','py':'Python', 'c': 'C', 'cpp': 'C++'}
            prompt_input = construct_prompt(regex_prompt,cwe_row,language_dic[lan])
            ret = gpt5_gen(client, prompt_input)
            try:
                patterns_json = json.loads(ret)
                results_dict = {}
                results_dict['cwe'] = cwe_id
                results_dict['language'] = lan
                pattern_list = patterns_json['patterns']
                results_dict['patterns'] = pattern_list
                results.append(results_dict)
            except:
                patterns_json = []
                results_dict = {}
                results_dict['cwe'] = cwe_id
                results_dict['language'] = lan
                pattern_list = patterns_json
                results_dict['patterns'] = pattern_list
                results.append(results_dict)
                
        # save data:
        with jsonlines.open(output_file_path.format(i=i), mode='w') as writer:
            for item in results:
                writer.write(item)



def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate regex patterns for CWE categories using an OpenAI model."
    )
    parser.add_argument(
        "--cwe-details-path",
        type=str,
        # required=True,
        default="../data/cwe-details.csv",
        help="Path to the CSV file containing CWE details (must have 'CWE-ID', 'Name', 'Description' columns).",
    )
    parser.add_argument(
        "--output-file-path",
        type=str,
        required=True,
        help="Output path template for the jsonl results, e.g. 'results_{i}.jsonl'.",
    )
    parser.add_argument(
        "--api-key",
        type=str,
        required=True,
        help="OpenAI API key. You can also set this via the OPENAI_API_KEY env var instead.",
    )
    parser.add_argument(
        "--num",
        type=int,
        default=1,
        help="Number of iterations/output files to generate (default: 1).",
    )
    return parser.parse_args()
 
 
if __name__ == "__main__":
    args = parse_args()
    gen_regex(
        cwe_details_path=args.cwe_details_path,
        output_file_path=args.output_file_path,
        api_key=args.api_key,
        num=args.num,
    )
