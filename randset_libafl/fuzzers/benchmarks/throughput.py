"""
Plot the throughput of the fuzzer over time.
"""
from matplotlib import pyplot as plt
import csv
import sys
import os
import subprocess
import re
import numpy as np

def load_throughput(csv_file):
    throughput = []
    with open(csv_file, 'r') as fobj:
        reader = csv.reader(fobj)
        for row in reader:
            cov = row[6]
            cov = cov.strip()
            try:
                cov = float(cov)
            except:
                cov = 0.0
            if cov > 1.0:
                throughput.append(cov)
    return throughput

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
    l = None
    for file in csv_files:
        coverage = load_throughput(file)
        coverages.append(coverage)
        if l is None:
            l = len(coverage)
        l = min(l, len(coverage))
    
    if l < 1200:
        print("In directory", dir, file=sys.stderr)
        print("Warning: some table may not be complete", file=sys.stderr)

    for i in range(len(coverages)):
        coverage = coverages[i]
        coverage = coverage[:l]
        coverages[i] = coverage

    ar = np.stack(coverages)
    os.chdir(cwd)
    return np.average(ar, axis=0).tolist()

def main(argv):
    plt.ylabel('throughput')
    plt.xlabel('minutes')
    for dir in argv[1:]:
        coverage = coverage_avg(dir)
        l = 1440 / len(coverage)
        timestamp = [l * i for i in range(len(coverage))]
        plt.plot(timestamp, coverage, label=dir)
    
    plt.legend()
    plt.savefig("throughput.png")
    plt.close()

if __name__ == "__main__":
    main(sys.argv)
