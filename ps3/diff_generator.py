import csv
import requests
import os

# 다운로드한 diff 파일을 저장할 디렉토리 생성
output_dir = "diff_files"
os.makedirs(output_dir, exist_ok=True)

# CSV 파일 경로
csv_file_path = "/mnt/data/diff.csv"

# CSV 파일 처리 및 diff 파일 다운로드
with open(csv_file_path, "r", encoding="utf-8") as csv_file:
    reader = csv.reader(csv_file)
    for idx, row in enumerate(reader):
        if len(row) < 2:
            continue  # CVE 번호와 URL이 없는 경우 건너뜀
        cve_number = row[1]  # 첫 번째 열에 CVE 번호가 있다고 가정
        url = row[-1]  # 마지막 열에 URL

        if not url:
            continue  # URL이 없는 경우 건너뜀

        # PR URL 처리
        if "/pull/" in url and url.endswith("/files"):
            url = url.replace("github.com", "patch-diff.githubusercontent.com/raw").replace("/files", ".diff")
        
        # Commit URL 처리
        if url.endswith("/commit/") or not url.endswith(".diff"):
            url += ".diff"  # URL에 .diff 추가

        try:
            print(f"Downloading {url}...")
            response = requests.get(url, timeout=10)
            response.raise_for_status()

            # 파일 저장 (CVE 번호를 사용하여 파일 이름 지정)
            diff_file_path = os.path.join(output_dir, f"{cve_number}.diff")
            with open(diff_file_path, "w", encoding="utf-8") as diff_file:
                diff_file.write(response.text)
            print(f"Saved: {diff_file_path}")
        except Exception as e:
            print(f"Failed to download {url}: {e}")
