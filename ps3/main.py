import time
from dataset_processer import Dataset, Evaluator, TestJson, TestResult
from debug_parser import DebugParser2
from diff_parser import DiffParser
from simulator import Generator, Signature, Test, remove_duplicate, valid_sig
# from original_simulator import Generator, Signature, Test, valid_sig
from inspect_info import InspectInfo
from effect import Effect
from pyvex.expr import IRExpr, Binop, Const, Unop
from symbol_value import AnySymbol, RegSymbol, ReturnSymbol, MemSymbol
from log import *
from settings import *

logger = get_logger(__name__)
logger.setLevel(INFO)
file_handler = logging.FileHandler(LOG_PATH)
file_handler.setLevel(logging.INFO)
logger.addHandler(file_handler)

TEST_NUM = -1

min_time = 99999999
max_time = 0
max_project = ""


def run_one(tests: list[TestJson]) -> list[TestResult]:
    global min_time, max_time, max_project
    test_results = []
    test = tests[0]

    vuln_name, patch_name = f"{test.cve}_{test.commit[:6]}_vuln", f"{test.cve}_{test.commit[:6]}_patch"
    # vuln_name, patch_name = f"{test.cve}_vuln", f"{test.cve}_patch"
    vuln_path, patch_path = f"{BINARY_PATH}/{test.project}/{vuln_name}", f"{BINARY_PATH}/{test.project}/{patch_name}"

    diff_name = f"{test.cve}_{test.commit[:6]}.diff"
    # diff_name = f"{test.cve}.diff"
    diff_path = f"{DIFF_PATH}/{diff_name}"
    # print(diff_path)
   
    diffparser = DiffParser.from_file(diff_path)
    # print(diffparser.parse_result)
    # print(f"diffparser.parse_result {diffparser.parse_result}")
    funcnames = []
    for diffs in diffparser.parse_result:
        funcnames.extend(list(diffs['functions'].keys()))
    debugparser2 = DebugParser2.from_binary(vuln_path, patch_path, funcnames)
    # binary_diffs = diffparser.get_binarylevel_change(debugparser2, test.cve)
    binary_diffs = diffparser.get_binarylevel_change(debugparser2)
    # print(binary_diffs)
    signature_generator = Generator.from_binary(vuln_path, patch_path)
    sigs = {}

    for diffs in binary_diffs:
        funcname = diffs.funcname
        sigs[funcname] = []
        vuln_has_indirect_jump = None
        patch_has_indirect_jump = None
        has_indirect_jump = False
        for hunk in diffs.hunks:
            # print(f"{funcname} {hunk.type}")
            if hunk.type == "add":
                collect, patch_has_indirect_jump = signature_generator.generate(
                    funcname, hunk.add, "patch", hunk.add_pattern)
                if collect is None:
                    continue
                signature = Signature.from_add(
                    collect, funcname, "patch", hunk.add_pattern)
                sigs[funcname].append(signature)
                if patch_has_indirect_jump and not has_indirect_jump:
                    has_indirect_jump = True

            elif hunk.type == "remove":
                collect, vuln_has_indirect_jump = signature_generator.generate(
                    funcname, hunk.remove, "vuln", hunk.remove_pattern)
                if collect is None:
                    continue
                signature = Signature.from_remove(
                    collect, funcname, "vuln", hunk.remove_pattern)
                sigs[funcname].append(signature)
                if vuln_has_indirect_jump and not has_indirect_jump:
                    has_indirect_jump = True
            elif hunk.type == "modify":
                collect_patch, patch_has_indirect_jump = signature_generator.generate(
                    funcname, hunk.add, "patch", hunk.add_pattern)
                # exit(0)
                # print("=" * 20)
                collect_vuln, vuln_has_indirect_jump = signature_generator.generate(
                    funcname, hunk.remove, "vuln", hunk.remove_pattern)
                

                # print(f"before refine collect_patch: {collect_patch}")
                # print(f"before refine collect_vuln: {collect_vuln}")
                if collect_patch is None and collect_vuln is None:
                    continue
                # print(f"type_collect_patch: {type(collect_patch)}")
                # traverse_collect(collect_patch)
                
                # print(f"after refine collect_patch: {collect_patch}")
                # print(f"after refine collect_vuln: {collect_vuln}")
                
                signature = Signature.from_modify(
                    collect_vuln, collect_patch, funcname, hunk.add_pattern, hunk.remove_pattern)
                sigs[funcname].append(signature)
                if (patch_has_indirect_jump or vuln_has_indirect_jump) and not has_indirect_jump:
                    has_indirect_jump = True
                # print(f"signature: {signature}")
            else:
                raise ValueError("hunk type error")
        if len(sigs[funcname]) == 0:
            logger.error(f"{test.cve} {funcname} No signature generated")
            sigs.pop(funcname)
    if len(sigs.keys()) == 0:
        logger.error(f"{test.cve} No signature generated")
        assert False
    for funcname in sigs.keys():
        sig = sigs[funcname]
        if len(sig) > 1:
            sigs[funcname] = valid_sig(sig)
        sig = sigs[funcname]
        sigs[funcname] = remove_duplicate(sig)
        for s in sigs[funcname]:
            s.show()

    testor = Test(sigs)
    if TEST_NUM >= 0:  # test specific number of tests
        if TEST_NUM == 0:
            return []
        for test in tests:
            if test.ground_truth == "patch":
                one_result = testor.test_path(
                    f"{BINARY_PATH}/{test.project}/{test.file}", test.ground_truth, has_indirect_jump)
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
                    f"{BINARY_PATH}/{test.project}/{test.file}", test.ground_truth, has_indirect_jump)
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
        logger.info(f"\n{test.file} truth is {test.ground_truth}")
        one_result = testor.test_path(
            f"{BINARY_PATH}/{test.project}/{test.file}", test.ground_truth, has_indirect_jump)
        if one_result is None:
            with open("error_test.txt", "a") as f:
                f.write(f"{test} is not valid")
            continue
        logger.info(
            f"{test.cve} {test.file} truth = {test.ground_truth} result = {one_result}")
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
    logger.info(f"time: {end - start}")
    logger.info(f"min_time: {min_time}")
    logger.info(f"max_time: {max_time}")
    logger.info(f"max_project: {max_project}")
