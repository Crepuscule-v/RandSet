from matplotlib import pyplot as plt
import csv
import sys
import os
import subprocess
import re
import numpy as np

def load_coverage(csv_file):
    coverage = []
    with open(csv_file, 'r') as fobj:
        reader = csv.reader(fobj)
        for row in reader:
            cov = row[7]
            cov = cov.strip()
            cov = cov[1:-1]
            if re.match(r'\d+\/\d+ \(\d+\%\)', cov) is not None:
                coverage.append(int(cov.split('/')[0]))
    return coverage

def coverage_avg(dir):
    cwd = os.getcwd()
    os.chdir(dir) 
    res = subprocess.run(
        ["find", "-name", "fuzzer_stats.csv"],
        shell=False,
        capture_output=True,
    )

    csv_files = res.stdout.decode().split("\n")[:-1]
    assert len(csv_files) > 0, "No fuzzer_stats.csv files found"

    coverages = []
    l = 3000
    for file in csv_files:
        coverage = load_coverage(file)
        coverages.append(coverage)
        l = min(l, len(coverage))
    
    for i in range(len(coverages)):
        coverage = coverages[i]
        coverage = coverage[:l]
        coverages[i] = coverage

    ar = np.stack(coverages)
    os.chdir(cwd)
    return np.average(ar, axis=0).tolist()

def main(argv):
    plt.ylabel('edges')
    plt.xlabel('minutes')
    for dir in argv[1:]:
        coverage = coverage_avg(dir)
        l = 1440 / len(coverage)
        timestamp = [l * i for i in range(len(coverage))]
        plt.plot(timestamp, coverage, label=dir)
        # plt.plot(coverage, label=dir)
    
    plt.legend()
    plt.savefig("coverage.png")
    plt.close()

if __name__ == "__main__":
    main(sys.argv)
