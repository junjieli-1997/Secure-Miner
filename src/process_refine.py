import jsonlines
import json
import re 
import pandas as pd


def get_cwe_row(cwe_id):
    cwe_details_path = r"/data/mining_secure_practices/scripts/investigation_secure_patterns_in_different_datasets/scripts/data_synthesize/cwe-details.csv"
    df_cwe_details = pd.read_csv(cwe_details_path)
    cwe_id_remove0 = str(int(cwe_id))
    cwe_row = df_cwe_details[df_cwe_details['CWE-ID'].astype(str) == cwe_id_remove0]
    return cwe_row.iloc[0]

def write_refine_response(response_path, matched_regex_path,output_path):
    # response_path = r"/data/mining_secure_practices/scripts/pipelines_regex_verification/regex_verified_results_optimization/verification_{lan}_raw.jsonl"
    count = 0
    error_count = 0
    response_list = []
    with jsonlines.open(response_path, mode='r') as reader:
        
        for obj in reader:
            count +=1
            # if 'response' not in obj.keys() or obj['response'] == {}:
            #     print(f"Empty response found in language {lan} at index {count}")
            # print(obj['response']['body']['output'][1]['content'][0]['text'])
            
            ## get index of  a list that the element has content key under obj['response']['body']['output']
            obj_index = -1
            for idx, element in enumerate(obj['response']['body']['output']):
                if 'content' in element.keys():
                    obj_index = idx
                    break
            if obj_index == -1:
                print(f"No content found in response at index {count}")
                error_count+=1
                raise Exception("No content found in response")
            # print(obj['response']['body']['output'][obj_index]['content'][0]['text'])
            if '```' not in obj['response']['body']['output'][obj_index]['content'][0]['text']:

                refine_code = obj['response']['body']['output'][obj_index]['content'][0]['text']
            else:
                str_pattern = f'```{lan}\n(.*?)```'

                refine_codes = re.findall(str_pattern, obj['response']['body']['output'][obj_index]['content'][0]['text'], re.DOTALL)
                if len(refine_codes) != 0:
                    refine_code = refine_codes[0]
                else:    
                    refine_codes = re.findall(r'```(.*?)```', obj['response']['body']['output'][obj_index]['content'][0]['text'], re.DOTALL)
                    if len(refine_codes) != 0:
                        refine_code = refine_codes[0]
                    else:
                        refine_code = ""
                    
                
            if refine_code == "":
                error_count+=1
            response_list.append(refine_code)
            # print(json_obj)
            # exit(0)
    print(count)
    print(f"Total parse errors: {error_count}")


    with jsonlines.open(matched_regex_path, mode='r') as reader:
        matched_results = []
        for obj in reader:
            matched_results.append(obj)
    code_count = 0
    batch_list = []
    # results_list = []
    for ids, matched_item in enumerate(matched_results):

        matched_item['refined_code'] = response_list[code_count]
        

        code_count +=1


    with jsonlines.open(output_path, mode='w') as writer:
        for item in matched_results:
            writer.write(item)


response_path = r"/data/mining_secure_practices/scripts/pipelines_regex_verification/regex_verified_results_entire_data/processed_data/batch_request_refine/refine_{lan}_raw.jsonl"
sampled_path = r"/data/mining_secure_practices/scripts/pipelines_regex_verification/regex_verified_results_entire_data/processed_data/functions_{lan}.jsonl"
output_path = r"/data/mining_secure_practices/scripts/pipelines_regex_verification/regex_verified_results_entire_data/processed_data/refined_data/functions_{lan}.jsonl"

# for lan in ['c','cpp','go','js','py']:
#     write_refine_response(response_path.format(lan= lan), sampled_path.format(lan= lan),output_path.format(lan= lan))

def _fix_unescaped_quotes_in_strings(s: str) -> str:
    result = []
    in_string = False
    i = 0
    n = len(s)

    while i < n:
        ch = s[i]

        if ch == '"':
            # Count preceding backslashes to see if this " is already escaped
            backslash_count = 0
            j = i - 1
            while j >= 0 and s[j] == '\\':
                backslash_count += 1
                j -= 1
            escaped = (backslash_count % 2 == 1)

            if not escaped:
                if in_string:
                    #
                    # ---------------------------------------------------------
                    # SPECIAL CASE: escape occurrences of #" → #\"
                    # ---------------------------------------------------------
                    #
                    # Only trigger if:
                    #   - previous char is '#'
                    #   - this quote is not escaped (already ensured)
                    #
                    if i > 0 and s[i-1] == '#':
                        result.append('\\\"')
                        i += 1
                        continue
                    #
                    # ---------------------------------------------------------
                    #

                    # (Original heuristic)
                    k = i + 1
                    while k < n and s[k].isspace():
                        k += 1

                    if k >= n or s[k] in [',', '}', ']', ':']:
                        in_string = False
                        result.append(ch)
                    else:
                        result.append('\\\"')

                else:
                    # Start of JSON string
                    in_string = True
                    result.append(ch)

                i += 1
                continue

        # Normal character
        result.append(ch)
        i += 1

    return ''.join(result)

def safe_json_loads(s: str):
    orig_s = s
    try:
        return json.loads(s)
    except json.JSONDecodeError as e:
        # Only try to “auto-fix” if it's the invalid escape error
        # raise
        # if "Invalid \\escape" not in str(e) and "Expecting ','" not in str(e) and "Expecting property name enclosed" not in str(e):
        #     raise

        # Escape backslashes that are NOT followed by a valid JSON escape character
        # Valid ones are: " \ / b f n r t u
        if "Invalid \\escape" in str(e) or "Expecting property name enclosed" in str(e):
            # s = re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', s)
            # s = re.sub(r'(?<!\\)\\(?!["\\/bfnrtu])', r'\\\\', s)
            s = re.sub(
                r'((?<!\\)(?:\\\\)*)\\(?!["\\/bfnrtu])',
                r'\1\\\\',
                s
            )

        # --------------------------------------------------------------------
        # 3. If string ends without a closing brace, append it
        # --------------------------------------------------------------------
        if "Expecting ','" in str(e):
            s = _fix_unescaped_quotes_in_strings(s)
            s_stripped = s.rstrip()
            # Missing final closing brace
            if not s_stripped.endswith('}'):
                s += '}'

        try:
            return json.loads(s)
        except json.JSONDecodeError:
            # ------------------------------------------------------
            # 3. FINAL SALVAGE MODE:
            #    Extract Key1, Key2 from ORIGINAL text,
            #    force reason = "Parse error".
            # ------------------------------------------------------

            # Extract the key values without trusting JSON structure
            k1 = re.search(r'relevant_to_cwe\s*:\s*"([^"]*)"', orig_s)
            k2 = re.search(r'prevents_cwe"([^"]*)', orig_s)

            key1_val = k1.group(1) if k1 else ""
            key2_val = k2.group(1) if k2 else ""

            return {
                "relevant_to_cwe": key1_val,
                "prevents_cwe": key2_val,
                "reason": "Parse error"
            }
        
def write_verification_refine_response(verification_path, response_path, matched_regex_path,output_path):
    # response_path = r"/data/mining_secure_practices/scripts/pipelines_regex_verification/regex_verified_results_optimization/verification_{lan}_raw.jsonl"
    count = 0
    error_count = 0
    response_list = []

    matched_results = []

    with jsonlines.open(matched_regex_path, mode='r') as reader:    
        for obj in reader:
            matched_results.append(obj)


    with jsonlines.open(verification_path, mode='r') as reader:
        cweval_list = []
        for ids, obj in enumerate(reader):
            # matched_results[ids]['refined_response'] = obj

            obj_index = -1
            for idx, element in enumerate(obj['response']['body']['output']):
                if 'content' in element.keys():
                    obj_index = idx
                    break
            if obj_index == -1:
                print(f"No content found in response at index {count}")
                error_count+=1
                raise Exception("No content found in response")
            # print(obj['response']['body']['output'][obj_index]['content'][0]['text'])
            json_obj = safe_json_loads(obj['response']['body']['output'][obj_index]['content'][0]['text'])
            if json_obj['reason'] == "Parse error":
                error_count+=1
            # response_list.append(json_obj)

            matched_results[ids]['verification_response'] = json_obj
            

            # cweval_list.append(cweval_item)

    with jsonlines.open(response_path, mode='r') as reader:
        
        for ids,obj in enumerate(reader):
            count +=1
            # if 'response' not in obj.keys() or obj['response'] == {}:
            #     print(f"Empty response found in language {lan} at index {count}")
            # print(obj['response']['body']['output'][1]['content'][0]['text'])
            
            ## get index of  a list that the element has content key under obj['response']['body']['output']
            lan = matched_results[ids]['language']


            obj_index = -1
            for idx, element in enumerate(obj['response']['body']['output']):
                if 'content' in element.keys():
                    obj_index = idx
                    break
            if obj_index == -1:
                print(f"No content found in response at index {count}")
                error_count+=1
                raise Exception("No content found in response")
            # print(obj['response']['body']['output'][obj_index]['content'][0]['text'])
            if '```' not in obj['response']['body']['output'][obj_index]['content'][0]['text']:

                refine_code = obj['response']['body']['output'][obj_index]['content'][0]['text']
            else:
                str_pattern = f'```{lan}\n(.*?)```'

                refine_codes = re.findall(str_pattern, obj['response']['body']['output'][obj_index]['content'][0]['text'], re.DOTALL)
                if len(refine_codes) != 0:
                    refine_code = refine_codes[0]
                else:    
                    refine_codes = re.findall(r'```(.*?)```', obj['response']['body']['output'][obj_index]['content'][0]['text'], re.DOTALL)
                    if len(refine_codes) != 0:
                        refine_code = refine_codes[0]
                    else:
                        refine_code = ""
                    
                
            if refine_code == "":
                error_count+=1

            
            # response_list.append(refine_code)

            matched_results[ids]['refined_response'] = refine_code


            # print(json_obj)
            # exit(0)
    print(count)
    print(f"Total parse errors: {error_count}")

    results_list= []
    for row in matched_results:
        print(row.keys())
        if 'verification_response' not in row.keys():
            print(f"No verification response found for {row['cwe_id']} at index {count}")
            continue
        elif 'prevents_cwe' not in row['verification_response'].keys():
            print(f"No prevents_cwe found for {row['cwe_id']} at index {count}")
            continue
        print(row['verification_response']['prevents_cwe'])
        if row['verification_response']['prevents_cwe'] == 'Yes':
            results_list.append(row)




    with jsonlines.open(output_path, mode='w') as writer:
        for item in results_list:
            item['func_src_after'] = item['refined_response']
            writer.write(item)

verification_path = r"/data/mining_secure_practices/scripts/pipelines_regex_verification/regex_filter_results/round2/verification_batch/verified_response_raw.jsonl"
response_path = r"/data/mining_secure_practices/scripts/pipelines_regex_verification/regex_filter_results/round2/verification_batch/refined_response_raw.jsonl"
matched_regex_path = r"/data/mining_secure_practices/scripts/pipelines_regex_verification/regex_filter_results/round2/verification_batch/verified_data.jsonl"
output_path = r"/data/mining_secure_practices/scripts/pipelines_regex_verification/regex_filter_results/round2/verification_batch/fine_tuning_data_verified_refined.jsonl"

# write_verification_refine_response(verification_path, response_path, matched_regex_path,output_path)


def check_functions():
    path = r"/data/mining_secure_practices/scripts/pipelines_regex_verification/regex_filter_results/round2/verification_batch/fine_tuning_data_verified_refined.jsonl"
    with jsonlines.open(path, mode='r') as reader:
        for obj in reader:
            if obj['refined_response'] == '':

                print(obj['cwe'], obj['language'])
# check_functions()

def exclude_empty():
    path = r"/data/mining_secure_practices/scripts/pipelines_regex_verification/regex_filter_results/round2/verification_batch/fine_tuning_data_verified_refined_instruction.jsonl"
    output_path = r"/data/mining_secure_practices/scripts/pipelines_regex_verification/regex_filter_results/round2/verification_batch/fine_tuning_data_verified_refined_instruction_nonempty.jsonl"
    with jsonlines.open(path, mode='r') as reader:
        data = []
        for obj in reader:
            if obj['refined_response'].strip() != '':
                data.append(obj)
    with jsonlines.open(output_path, mode='w') as writer:
        writer.write_all(data)
exclude_empty()
# response_path = r"/data/mining_secure_practices/scripts/pipelines_regex_verification/regex_verified_results_optimization/response_raw3/verification_{lan}_raw.jsonl"
# matched_regex_path = r"/data/mining_secure_practices/scripts/pipelines_regex_verification/regex_matched_results_optimization/matched3/regex_matched_{lan}.jsonl"
# output_path = r"/data/mining_secure_practices/scripts/pipelines_regex_verification/regex_verified_results_optimization/processed_response3/verification_{lan}.jsonl"
# for lan in ['c','cpp','go','js','py']:
#     write_response(response_path.format(lan= lan), matched_regex_path.format(lan= lan),output_path.format(lan= lan))

