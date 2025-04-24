import pandas as pd
import json
import os

# output jsonl file path
output_jsonl_path = './test.jsonl'

commit_dict = { 'CVE_2018_0734': '8abfe72e8c1de1b95f50aa0d9134803b4d00070f',
                'CVE_2018_0735': '99540ec79491f59ed8b46b4edf130e17dc907f52',
                'CVE_2020_1967': 'a87f3fe01a5a894aa27ccd6a239155fd129988e4',
                'CVE_2021_23841': '8130d654d1de922ea224fa18ee3bc7262edc39c0'
}

# {"file": "CVE_2018_0734_post3_007efc4d.elf", "cve": "CVE_2018_0734", "commit": "a9cfb8c2aa7254a4aa6a1716909e3f8cb78049b66", "ground_truth": "patch", "project": "openssl"}

# 1. 지금 위치에 있는 모든 폴더를 list로 가져오기
# 1-1. CVE_2018_0734_post면, jsonl의 'cve'에 'CVE_2018_0734'를 넣어주기, 'project'에 'openssl'를 넣어주기, 'ground_truth'는 post가 들어가면 'patch'를 넣어주기/ pre가 들어가면 'vuln'을 넣어주기, 'commit'은 commit_dict에서 가져오기
# 2. 해당 폴더 밑에 있는 모든 파일 list로 가져오고 파일 이름을 jsonl의 'file'에 넣어주기
# 3. jsonl 파일로 저장하기, 포맷은 위의 주석 참고

# make the code
data = []
for root, dirs, files in os.walk('./'):
    for dir in dirs:
        if 'CVE_2018_0734_post' in dir:
            cve = 'CVE_2018_0734'
            project = 'openssl'
            ground_truth = 'patch'
            commit = commit_dict[cve]
        elif 'CVE_2018_0734_pre' in dir:
            cve = 'CVE_2018_0734'
            project = 'openssl'
            ground_truth = 'vuln'
            commit = commit_dict[cve]
        elif 'CVE_2018_0735_post' in dir:
            cve = 'CVE_2018_0735'
            project = 'openssl'
            ground_truth = 'patch'
            commit = commit_dict[cve]
        elif 'CVE_2018_0735_pre' in dir:
            cve = 'CVE_2018_0735'
            project = 'openssl'
            ground_truth = 'vuln'
            commit = commit_dict[cve]
        elif 'CVE_2020_1967_post' in dir:
            cve = 'CVE_2020_1967'
            project = 'openssl'
            ground_truth = 'patch'
            commit = commit_dict[cve]
        elif 'CVE_2020_1967_pre' in dir:
            cve = 'CVE_2020_1967'
            project = 'openssl'
            ground_truth = 'vuln'
            commit = commit_dict[cve]
        elif 'CVE_2021_23841_post' in dir:
            cve = 'CVE_2021_23841'
            project = 'openssl'
            ground_truth = 'patch'
            commit = commit_dict[cve]
        elif 'CVE_2021_23841_pre' in dir:
            cve = 'CVE_2021_23841'
            project = 'openssl'
            ground_truth = 'vuln'
            commit = commit_dict[cve]
        else:
            continue

        for root, dirs, files in os.walk(dir):
            for file in files:
                data.append({
                    'file': file,
                    'cve': cve,
                    'commit': commit,
                    'ground_truth': ground_truth,
                    'project': project
                })

# JSONL 파일로 저장
with open(output_jsonl_path, 'w') as jsonl_file:
    for row in data:
        json.dump(row, jsonl_file)
        jsonl_file.write('\n')