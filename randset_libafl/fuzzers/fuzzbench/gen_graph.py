#!/usr/bin/python3

import csv
import sys
import json
import os
import subprocess

if __name__ == "__main__":
  if len(sys.argv) != 2:
    print("ERROR: file prefix not given", file=sys.stderr)
    sys.exit(1)
  
  prefix = sys.argv[1]
  cfg_json = prefix + ".ll.cfg"
  cfg_csv = prefix + ".csv"

  if not os.path.exists(cfg_csv):
    print(f"ERROR: {cfg_csv} not found.", file = sys.stderr)
    sys.exit(1)
  if not os.path.exists(cfg_json):
    print(f"ERROR: {cfg_json} not found.", file = sys.stderr)
    sys.exit(1)

  # read the json graph
  with open(cfg_json, 'r') as fobj:
    cfg_obj:dict = json.load(fobj)

  # read the csv file
  with open(cfg_csv, 'r') as fobj:
    for line in fobj:
      leading: str = line
      break

  guards= [word.strip() for word in leading.split(',')]

  size_of_guards: dict = {}
  for guard in guards:
    size_of_guards[guard] = 0

  call_args = []
  with open(cfg_csv, 'r') as fobj:
    line_no = 0
    for line in fobj:
      if line_no != 0:
        words = [word.strip() for word in line.split(',')]
        call_args.append({
          "base": words[0], # base address
          "offset": int(words[1]) // 4,  # offset
        })
      line_no += 1

  calls, edges = cfg_obj['calls'], cfg_obj['edges']

  # compute the offset of guards based on call_args and calls.
  off = 0

  # try mapping guard to function
  guard_to_fn = {}
  for fn in calls.keys():
    args = call_args[off]
    call = calls[fn]
    guard_to_fn[args["base"]] = fn
    num_call = len(call.keys())
    size_of_guards[args['base']] = num_call
    off += num_call
    if off >= len(call_args):
      break

  #print(size_of_guards)
  #print(guard_to_fn)

  # compute the offset of each guard.
  guard_off = {}
  off = 0
  for guard in guards:
    guard_off[guard] = off
    off += size_of_guards[guard]

  output_edges = []
  for guard in guards:
    try:
      fn = guard_to_fn[guard]
    except:
      continue
    off = guard_off[guard]
    basic_blocks = edges[fn]
    num_basic_blocks = len(basic_blocks)

    for i in range(num_basic_blocks):
      for succ in basic_blocks[i]:
        output_edges.append([i + off, succ + off])
  
  result = subprocess.run(
f"""
  readelf -S {prefix} 2> /dev/null | grep \"sancov_pc\" -A 1 | tail -n 1 | sed -E \"s/0*([a-fA-F0-9]+).*/\\1/\"
""",
    shell=True,
    capture_output=True,
  )

  assert result.returncode == 0, "Something went wrong. Abort"
  n_edges = int(result.stdout.decode(), base=16)
  n_edges = n_edges // 16

  # ok, write output to cfg file.
  with open(prefix + "_cfg", 'w') as fobj:
    for edge in output_edges:
      fobj.write(f"{edge[0]} {edge[1]}\n")

    fobj.write(f"{n_edges} {n_edges}\n")
