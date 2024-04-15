import yara
import os

# Define fileset directories
filesets_dir = {
    'known-bad': 'fileset/known-bad/',
    'known-clean': 'fileset/known-clean/',
    'unclassified': 'fileset/unclassified/'
}

# Compile rules for each group
group2 = yara.compile(filepath='new-ruleset/group2-new.yara')
group5 = yara.compile(filepath='new-ruleset/group5-new.yara')  # Assuming you meant group5 here

# Function to scan directories and count matches
def scan_directory(directory_path, compiled_rules):
    matches = 0
    for file in os.listdir(directory_path):
        file_path = os.path.join(directory_path, file)
        if compiled_rules.match(file_path):
            matches += 1
    return matches

# Function to calculate various rates
def fp_rate(fp, tn):
    return fp / (fp + tn) if (fp + tn) > 0 else 0

def f1_score(tp, fp, fn):
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    return 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

def tp_rate(tp, fn):
    return tp / (tp + fn) if (tp + fn) > 0 else 0

# Evaluate groups and compile statistics
group_results = []
for group_name, rules in [('Group 2', group2), ('Group 5', group5)]:
    tp_count = scan_directory(filesets_dir['known-bad'], rules)
    known_bad_files = len(os.listdir(filesets_dir['known-bad']))
    fn_count = known_bad_files - tp_count

    fp_count = scan_directory(filesets_dir['known-clean'], rules)
    known_clean_files = len(os.listdir(filesets_dir['known-clean']))
    tn_count = known_clean_files - fp_count

    matches_unknown = scan_directory(filesets_dir['unclassified'], rules)

    precision = tp_count / (tp_count + fp_count) if (tp_count + fp_count) > 0 else 0
    expected_tps_unknown = precision * matches_unknown

    group_results.append({
        'group': group_name,
        'TP': tp_count,
        'FN': fn_count,
        'FP': fp_count,
        'TN': tn_count,
        'Matches Unknown': matches_unknown,
        'Expected TPs Unknown': expected_tps_unknown
    })

# Print results for each group
for result in group_results:
    print(f"{result['group']}:")
    print(f"  TP: {result['TP']}, FN: {result['FN']}, FP: {result['FP']}, TN: {result['TN']}")
    print(f"  Matches Unknown: {result['Matches Unknown']}, Expected TPs Unknown: {result['Expected TPs Unknown']:.3f}")
    print(f"  FP Rate: {fp_rate(result['FP'], result['TN']):.3f}, F1 Score: {f1_score(result['TP'], result['FP'], result['FN']):.3f}, TP Rate: {tp_rate(result['TP'], result['FN']):.3f}\n")
