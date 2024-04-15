import os
import random
import yara
import matplotlib.pyplot as plt
import numpy as np

rules_dir = 'ruleset/'
filesets_dir = {
    'known-bad': 'fileset/known-bad/',
    'known-clean': 'fileset/known-clean/',
    'unclassified': 'fileset/unclassified/'
}

all_rule_files = os.listdir(rules_dir)
random.shuffle(all_rule_files)

rule_groups = [random.sample(all_rule_files, 4) for _ in range(10)]


def compile_group_rules(group):
    return yara.compile(filepaths={rule: os.path.join(rules_dir, rule) for rule in group})


def scan_directory(directory_path, compiled_rules):
    matches = 0
    for file in os.listdir(directory_path):
        file_path = os.path.join(directory_path, file)
        if compiled_rules.match(file_path):
            matches += 1
    return matches


group_results = []


for group in rule_groups:
    compiled_rules = compile_group_rules(group)

   
    known_bad_files = len(os.listdir(filesets_dir['known-bad']))
    tp_count = scan_directory(filesets_dir['known-bad'], compiled_rules)
    fn_count = known_bad_files - tp_count

   
    known_clean_files = len(os.listdir(filesets_dir['known-clean']))
    fp_count = scan_directory(filesets_dir['known-clean'], compiled_rules)
    tn_count = known_clean_files - fp_count

   
    matches_unknown = scan_directory(filesets_dir['unclassified'], compiled_rules)

    
    precision = tp_count / (tp_count + fp_count) if (tp_count + fp_count) > 0 else 0
    expected_tps_unknown = precision * matches_unknown


    group_results.append({
        'group': group,
        'TP': tp_count,
        'FN': fn_count,
        'FP': fp_count,
        'TN': tn_count,
        'Matches Unknown': matches_unknown,
        'Expected TPs Unknown': expected_tps_unknown
    })


def fp_rate(fp, tn):
    return fp / (fp + tn) if (fp + tn) > 0 else 0


def f1_score(tp, fp, fn):
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    return 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0


def tp_rate(tp, fn):
    return tp / (tp + fn) if (tp + fn) > 0 else 0

for result in group_results:
    result['FP Rate'] = fp_rate(result['FP'], result['TN'])
    result['F1 Score'] = f1_score(result['TP'], result['FP'], result['FN'])
    result['TP Rate'] = tp_rate(result['TP'], result['FN'])

best_low_risk = min(group_results, key=lambda x: x['FP Rate'])
best_high_risk = max(group_results, key=lambda x: x['F1 Score'])
best_core_servers = max(group_results, key=lambda x: (x['TP Rate'], x['Expected TPs Unknown']))


for i, result in enumerate(group_results, 1):  
    print(f"Group {i}:")
    print(f"  Rules: {', '.join(result['group'])}")
    print(f"  FP Rate: {result['FP Rate']:.2f}, F1 Score: {result['F1 Score']:.2f}, TP Rate: {result['TP Rate']:.2f}")
    print(f"  TP: {result['TP']}, FN: {result['FN']}, FP: {result['FP']}, TN: {result['TN']}")
    print(f"  Matches in Unknown: {result['Matches Unknown']}, Expected TPs in Unknown: {result['Expected TPs Unknown']:.2f}\n")

print(f"Recommended Group for Low Risk Employee Workstations: Group {group_results.index(best_low_risk) + 1} (Lowest FP Rate)")
print(f"Recommended Group for High Risk Employee Workstations: Group {group_results.index(best_high_risk) + 1} (Highest F1 Score)")
print(f"Recommended Group for Company Core Servers: Group {group_results.index(best_core_servers) + 1} (Highest TP Rate & Expected TPs in Unknown)")

groups = np.arange(1, 11)
fp_rates = [result['FP Rate'] for result in group_results]
f1_scores = [result['F1 Score'] for result in group_results]
tp_rates = [result['TP Rate'] for result in group_results]
expected_tps = [result['Expected TPs Unknown'] for result in group_results]

plt.figure(figsize=(10, 5))
plt.bar(groups, fp_rates, color='teal')
plt.xlabel('Group')
plt.ylabel('FP Rate')
plt.title('FP Rate by Group for Low Risk Employee Workstations')
plt.xticks(groups)
plt.show()


plt.figure(figsize=(10, 5))
plt.bar(groups, f1_scores, color='purple')
plt.xlabel('Group')
plt.ylabel('F1 Score')
plt.title('F1 Score by Group for High Risk Employee Workstations')
plt.xticks(groups)
plt.show()

fig, ax1 = plt.subplots(figsize=(10, 5))

color = 'tab:red'
ax1.set_xlabel('Group')
ax1.set_ylabel('TP Rate', color=color)
ax1.bar(groups, tp_rates, color=color)
ax1.tick_params(axis='y', labelcolor=color)
ax1.set_xticks(groups)

ax2 = ax1.twinx()  
color = 'tab:blue'
ax2.set_ylabel('Expected TPs', color=color)
ax2.plot(groups, expected_tps, color=color, marker='o', linestyle='dashed', linewidth=2, markersize=12)
ax2.tick_params(axis='y', labelcolor=color)

fig.tight_layout() 
plt.title('TP Rate and Expected TPs by Group for Company Core Servers')
plt.show()
