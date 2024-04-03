import os
import yara

# Paths
rules_dir = 'ruleset/'
filesets_dir = {
    'known-bad': 'fileset/known-bad/',
    'known-clean': 'fileset/known-clean/',
    'unclassified': 'fileset/unclassified/'
}

# Compile the first 10 Yara rules
rule_files = sorted(os.listdir(rules_dir))[:10]
compiled_rules = {}
for rule_file in rule_files:
    rule_path = os.path.join(rules_dir, rule_file)
    try:
        compiled_rules[rule_file] = yara.compile(filepath=rule_path)
    except yara.SyntaxError as e:
        print(f"Error compiling {rule_file}: {e}")

# Function to scan a directory with a rule
def scan_directory(directory_path, rule):
    matches = []
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            if rule.match(file_path):
                matches.append(file)
    return matches

# Initialize a dictionary to hold results
results = {rule_file: {'TP': 0, 'FP': 0, 'Unknown': 0} for rule_file in rule_files}

# Scan each directory with each rule and classify matches
for rule_name, rule in compiled_rules.items():
    # True Positives (known-bad)
    results[rule_name]['TP'] = len(scan_directory(filesets_dir['known-bad'], rule))

    # False Positives (known-clean)
    results[rule_name]['FP'] = len(scan_directory(filesets_dir['known-clean'], rule))

    # Matches among the Unknown
    results[rule_name]['Unknown'] = len(scan_directory(filesets_dir['unclassified'], rule))

# Print results
for rule, counts in results.items():
    print(f"Rule: {rule}")
    print(f"  True Positives: {counts['TP']}")
    print(f"  False Positives: {counts['FP']}")
    print(f"  Unknown Matches: {counts['Unknown']}\n")
