import os
ROOT_PATH = os.path.abspath('../') # project root path
HDD_PATH = "/mnt/d/dataset" # hdd path

DATASET_PATH = os.path.join(ROOT_PATH, 'dataset') # dataset path
# BINARY_PATH = os.path.join(DATASET_PATH, 'binary')
# BINARY_PATH = os.path.join(DATASET_PATH, 'libs')
# BINARY_PATH = os.path.join(DATASET_PATH, 'ps3_original_binary')
# BINARY_PATH = os.path.join(HDD_PATH, 'binary')

# DIFF_PATH= os.path.join(HDD_PATH, 'diff')
DIFF_PATH= os.path.join(HDD_PATH, 'original_diff')
# TEST_FILE= os.path.join(DATASET_PATH, 'test.jsonl')
# TEST_FILE= os.path.join(DATASET_PATH, 'overlapped_test.jsonl')
# TEST_FILE= os.path.join(DATASET_PATH, 'overlapped_original_test.jsonl')
# TEST_FILE= os.path.join(DATASET_PATH, 'temp2.jsonl')
# TEST_FILE= os.path.join(DATASET_PATH, 'test_1976.jsonl')
# TEST_FILE= os.path.join(DATASET_PATH, 'test_real.jsonl')
# TEST_FILE= os.path.join(DATASET_PATH, 'test_test.jsonl')
TEST_FILE= os.path.join(HDD_PATH, 'original_test2.jsonl')
# TEST_FILE= os.path.join(DATASET_PATH, 'test_ps3_remain_openssl.jsonl')
# TEST_FILE= os.path.join(DATASET_PATH, 'test_tcpdump.jsonl')
# TEST_FILE= os.path.join(DATASET_PATH, 'test_FFmpeg.jsonl')

# temp log
# BINARY_PATH = os.path.join(HDD_PATH, 'ps3_original_binary')
# DIFF_PATH= os.path.join(HDD_PATH, 'original_diff')
# LOG_PATH = os.path.join(ROOT_PATH, "ps3", 'quick.txt')
# TEST_FILE= os.path.join(HDD_PATH, 'test_1976.jsonl')

# FFmpeg
# TEST_FILE= os.path.join(HDD_PATH, 'test_FFmpeg_new.jsonl')
# TEST_FILE= os.path.join(HDD_PATH, 'test_FFmpeg.jsonl')
BINARY_PATH = os.path.join(HDD_PATH, 'ps3_original_binary')
LOG_PATH = os.path.join(ROOT_PATH, "ps3",'log_all.txt')
SRC_PATH = os.path.join(HDD_PATH, 'source')
CVE_FILE = os.path.join(HDD_PATH, 'new_CVE_info.jsonl')

# tcpdump
# TEST_FILE= os.path.join(HDD_PATH, 'test_tcpdump_new.jsonl')
# BINARY_PATH = os.path.join(HDD_PATH, 'binary')
# LOG_PATH = os.path.join(ROOT_PATH, "ps3", 'log_tcpdump_new.txt')

# openssl
# TEST_FILE= os.path.join(HDD_PATH, 'test_openssl_new.jsonl')
# BINARY_PATH = os.path.join(HDD_PATH, 'binary')
# LOG_PATH = os.path.join(ROOT_PATH, "ps3", 'log_openssl_new.txt')

# dwg2dxf
# TEST_FILE= os.path.join(HDD_PATH, 'test_dwg2dxf.jsonl')
# BINARY_PATH = os.path.join(HDD_PATH, 'test')
# LOG_PATH = os.path.join(ROOT_PATH, "ps3", 'log_dwg2dxf.txt')




ADDR2LINE = 'addr2line'

REPO_PATH = "../dataset/repos"