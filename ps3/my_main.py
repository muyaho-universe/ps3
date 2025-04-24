import concurrent.futures
import time
from dataset_processer import Dataset, Evaluator, TestJson, TestResult
from debug_parser import DebugParser2
from diff_parser import DiffParser
from simulator import Generator, Signature, Test, valid_sig
from log import *
from settings import *
import psutil

logger = get_logger(__name__)
logger.setLevel(INFO)
file_handler = logging.FileHandler(LOG_PATH)
file_handler.setLevel(logging.INFO)
logger.addHandler(file_handler)

TEST_NUM = -1

min_time = 99999999
max_time = 0
max_project = ""

TIMEOUT_SECONDS = 300  # 5분 (300초)

def run_test_worker(binary_path, sigs):
    """멀티프로세싱에서 실행될 독립적인 함수"""
    testor = Test(sigs)  # 멀티프로세스에서 새로운 객체 생성
    return testor.test_path(binary_path)

def run_test_with_timeout(binary_path, sigs):
    """testor.test_path()를 실행하고 타임아웃을 초과하면 강제 종료하는 함수"""
    with concurrent.futures.ProcessPoolExecutor(max_workers=1) as executor:
        future = executor.submit(run_test_worker, binary_path, sigs)
        try:
            return future.result(timeout=TIMEOUT_SECONDS)  # 5분 제한
        except concurrent.futures.TimeoutError:
            logger.info(f"Timeout: {binary_path} execution took longer than {TIMEOUT_SECONDS} seconds")
            # 프로세스 강제 종료
            parent = psutil.Process(os.getpid())
            for child in parent.children(recursive=True):  # 자식 프로세스 종료
                child.terminate()
            executor.shutdown(wait=False)  # 실행 중인 프로세스 풀 종료
            return None
        except Exception as e:
            logger.error(f"Error in evaluating {binary_path}: {str(e)}")
            return None


def run_one(tests: list[TestJson]) -> list[TestResult]:
    global min_time, max_time, max_project
    test_results = []
    test = tests[0]

    vuln_name, patch_name = f"{test.cve}_vuln", f"{test.cve}_patch"
    vuln_path, patch_path = f"{BINARY_PATH}/{test.project}/{vuln_name}", f"{BINARY_PATH}/{test.project}/{patch_name}"

    # vuln_name, patch_name = f"{test.cve}_{test.commit[:6]}_vuln", f"{test.cve}_{test.commit[:6]}_patch"
    # vuln_path, patch_path = f"{BINARY_PATH}/{test.project}/{vuln_name}", f"{BINARY_PATH}/{test.project}/{patch_name}"

    diff_name = f"{test.cve}.diff"
    # diff_name = f"{test.cve}_{test.commit[:6]}.diff"
    diff_path = f"{DIFF_PATH}/{diff_name}"
    diffparser = DiffParser.from_file(diff_path)
    # print(f"diffparser result: {diffparser.parse_result}")
    funcnames = []
    for diffs in diffparser.parse_result:
        funcnames.extend(list(diffs['functions'].keys()))
    # print(funcnames)
    debugparser2 = DebugParser2.from_binary(vuln_path, patch_path, funcnames)
    # logger.info(f"debugparser2: {debugparser2.patch_parser}")
    # logger.info(f"debugparser2: {debugparser2.vuln_parser}")
    binary_diffs = diffparser.get_binarylevel_change(debugparser2)
    # logger.info(f"binary_diffs: {binary_diffs}")
    # print(f"binary_diffs: {binary_diffs}")
    signature_generator = Generator.from_binary(vuln_path, patch_path)
    sigs = {}
    # print(f'binary_diffs: {binary_diffs}')
    for diffs in binary_diffs:
        funcname = diffs.funcname
        sigs[funcname] = []
        # print(f'diffs.hunks: {len(diffs.hunks)}')
        # logger.info(f"diffs.hunks: {len(diffs.hunks)}")
        for hunk in diffs.hunks:
            # print(f'hunk: {hunk}')
            if hunk.type == "add":
                # logger.info(f"hunk.add: {hunk.add}")
                collect = signature_generator.generate(
                    funcname, hunk.add, "patch", hunk.add_pattern)
                if collect is None:
                    continue
                # logger.info(f"In add {test.cve} {funcname},\ncollect: {collect}")
                signature = Signature.from_add(
                    collect, funcname, "patch", hunk.add_pattern)
                sigs[funcname].append(signature)
                # logger.info(f"Ralo: {sigs[funcname]}")
            elif hunk.type == "remove":
                collect = signature_generator.generate(
                    funcname, hunk.remove, "vuln", hunk.remove_pattern)
                if collect is None:
                    continue
                # logger.info(f"In remove {test.cve} {funcname},\ncollect: {collect}")
                signature = Signature.from_remove(
                    collect, funcname, "vuln", hunk.remove_pattern)
                sigs[funcname].append(signature)
            elif hunk.type == "modify":
                collect_patch = signature_generator.generate(
                    funcname, hunk.add, "patch", hunk.add_pattern)
                collect_vuln = signature_generator.generate(
                    funcname, hunk.remove, "vuln", hunk.remove_pattern)
                # logger.info(f"{test.cve} {funcname},\ncollect_patch: {collect_patch}\ncollect_vuln: {collect_vuln}")
                if collect_patch is None and collect_vuln is None:
                    continue
                signature = Signature.from_modify(
                    collect_vuln, collect_patch, funcname, hunk.add_pattern, hunk.remove_pattern)
                sigs[funcname].append(signature)
            else:
                raise ValueError("hunk type error")
        # print(f"sig: {sigs[funcname]}")
        # print(f"len(sig): {len(sigs[funcname])}")
        if len(sigs[funcname]) == 0:
            logger.error(f"{test.cve} {funcname} No signature generated")
            sigs.pop(funcname)
    if len(sigs.keys()) == 0:
        logger.error(f"{test.cve} No signature generated")
        return None
        assert False

    # logger.info(f"sig: {len(sigs.keys())}")

    for funcname in sigs.keys():
        sig = sigs[funcname]

        if len(sig) > 1:
            pass
            sigs[funcname] = valid_sig(sig)
        # logger.info(f"sig[funcname] len: {len(sigs[funcname])}")

        for s in sigs[funcname]:
            s.show()
    testor = Test(sigs)

    if TEST_NUM >= 0:  # test specific number of tests
        if TEST_NUM == 0:
            return []
        for test in tests:
            if test.ground_truth == "patch":
                one_result = testor.test_path(
                    f"{BINARY_PATH}/{test.project}/{test.file}")
                if one_result is None:
                    continue
                logger.info(
                    f"{test.cve} {test.file} truth = {test.ground_truth} result = {one_result}")
                test_results.append(TestResult(test, one_result))
                if len(test_results) >= TEST_NUM:
                    break
        for test in tests:
            if test.ground_truth == "vuln":
                one_result = testor.test_path(
                    f"{BINARY_PATH}/{test.project}/{test.file}")
                if one_result is None:
                    continue
                logger.info(
                    f"{test.cve} {test.file} truth = {test.ground_truth} result = {one_result}")
                test_results.append(TestResult(test, one_result))
                if len(test_results) >= TEST_NUM * 2:
                    break
        return test_results
    for test in tests:  # test all tests
        start = time.time()
        logger.info(f"{test.file} truth is {test.ground_truth}")

        binary_path = f"{BINARY_PATH}/{test.project}/{test.file}"
        one_result = run_test_with_timeout(binary_path, sigs)  # 타임아웃 적용

        if one_result is None:
            with open("error_test.txt", "a") as f:
                f.write(f"{test} is not valid\n")
            continue

        logger.info(f"{test.cve} {test.file} truth = {test.ground_truth} result = {one_result}")
        test_results.append(TestResult(test, one_result))
        end = time.time()
        if end - start > max_time:
            max_time = end - start
            max_project = f"{test.project} {test.cve} {test.file}"
        if end - start < min_time:
            min_time = end - start

    return test_results


def run_all():
    dataset = Dataset.from_file()
    evaluate = Evaluator()
    test_all = []
    for cve_id in dataset.tests.keys():
        test_results = []
        logger.info(f"{cve_id}")
        project = dataset.tests[cve_id][0].project
        result = run_one(dataset.tests[cve_id])
        test_results.extend(result)
        logger.info(
            f"{project} {cve_id} {evaluate.precision_recall_f1(test_results)}")
        test_all.extend(test_results)
    logger.info(f"RQ1 {evaluate.precision_recall_f1(test_all)}")
    result = evaluate.evaulate_RQ2(test_all)
    logger.info(f"RQ2 {result}")

if __name__ == "__main__":
    dataset = Dataset.from_file()
    start = time.time()
    run_all()
    end = time.time()
    print("time: ", end - start)
    print("min_time: ", min_time)
    print("max_time: ", max_time)
    print("max_project: ", max_project)
