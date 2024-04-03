import os
import random
import yara

# Assuming the rules directory and filesets directory paths are correctly set
rules_dir = 'ruleset/'
filesets_dir = {
    'known-bad': 'fileset/known-bad/',
    'known-clean': 'fileset/known-clean/',
    'unclassified': 'fileset/unclassified/'
}

# List all rule files and shuffle them to randomize selection
all_rule_files = os.listdir(rules_dir)
random.shuffle(all_rule_files)

# Create 10 groups with 4 random rules each
rule_groups = [random.sample(all_rule_files, 4) for _ in range(10)]

# Function to compile rules for a group
def compile_group_rules(group):
    return yara.compile(filepaths={rule: os.path.join(rules_dir, rule) for rule in group})

# Function to scan a directory with a compiled rule group
def scan_directory(directory_path, compiled_rules):
    matches = 0
    for file in os.listdir(directory_path):
        file_path = os.path.join(directory_path, file)
        if compiled_rules.match(file_path):
            matches += 1
    return matches

# Initialize a list to hold results for each group
group_results = []

# Evaluate each rule group
for group in rule_groups:
    compiled_rules = compile_group_rules(group)

    # Scan known-bad set (TP/FN)
    known_bad_files = len(os.listdir(filesets_dir['known-bad']))
    tp_count = scan_directory(filesets_dir['known-bad'], compiled_rules)
    fn_count = known_bad_files - tp_count

    # Scan known-clean set (FP/TN)
    known_clean_files = len(os.listdir(filesets_dir['known-clean']))
    fp_count = scan_directory(filesets_dir['known-clean'], compiled_rules)
    tn_count = known_clean_files - fp_count

    # Count matches in the unclassified set
    matches_unknown = scan_directory(filesets_dir['unclassified'], compiled_rules)

    # Calculate Precision and estimate expected TPs in the unclassified set
    precision = tp_count / (tp_count + fp_count) if (tp_count + fp_count) > 0 else 0
    expected_tps_unknown = precision * matches_unknown

    # Store results
    group_results.append({
        'group': group,
        'TP': tp_count,
        'FN': fn_count,
        'FP': fp_count,
        'TN': tn_count,
        'Matches Unknown': matches_unknown,
        'Expected TPs Unknown': expected_tps_unknown
    })

# Function to calculate FP rate
def fp_rate(fp, tn):
    return fp / (fp + tn) if (fp + tn) > 0 else 0

# Function to calculate F1 score
def f1_score(tp, fp, fn):
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    return 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

# Function to calculate TP rate
def tp_rate(tp, fn):
    return tp / (tp + fn) if (tp + fn) > 0 else 0

# Calculate metrics for each group
for result in group_results:
    result['FP Rate'] = fp_rate(result['FP'], result['TN'])
    result['F1 Score'] = f1_score(result['TP'], result['FP'], result['FN'])
    result['TP Rate'] = tp_rate(result['TP'], result['FN'])

# Select best groups for each use case
best_low_risk = min(group_results, key=lambda x: x['FP Rate'])
best_high_risk = max(group_results, key=lambda x: x['F1 Score'])
best_core_servers = max(group_results, key=lambda x: (x['TP Rate'], x['Expected TPs Unknown']))


# Print FP Rate, F1 Score, and TP Rate for each group
for i, result in enumerate(group_results, 1):  # Start counting groups from 1
    print(f"Group {i}:")
    print(f"  Rules: {', '.join(result['group'])}")
    print(f"  FP Rate: {result['FP Rate']:.2f}, F1 Score: {result['F1 Score']:.2f}, TP Rate: {result['TP Rate']:.2f}")
    print(f"  TP: {result['TP']}, FN: {result['FN']}, FP: {result['FP']}, TN: {result['TN']}")
    print(f"  Matches in Unknown: {result['Matches Unknown']}, Expected TPs in Unknown: {result['Expected TPs Unknown']:.2f}\n")

# Print recommendations
print(f"Recommended Group for Low Risk Employee Workstations: Group {group_results.index(best_low_risk) + 1} (Lowest FP Rate)")
print(f"Recommended Group for High Risk Employee Workstations: Group {group_results.index(best_high_risk) + 1} (Highest F1 Score)")
print(f"Recommended Group for Company Core Servers: Group {group_results.index(best_core_servers) + 1} (Highest TP Rate & Expected TPs in Unknown)")
