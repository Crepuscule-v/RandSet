#!/usr/bin/python
import json
import os
import sys

class CFGLinker():
  """ Linker that links output of dump-cfg-pass into a single .cfg file """
  def __init__(self):
    self.calls = dict()
    self.edges = dict()
    self.entries = dict()

  def add_cfg_file(self, file_name):
    """ Add a cfg file """
    print("\033[01;92m[+]\033[0;m cfg-ld: linking", file_name, file=sys.stderr)
    if not os.path.exists(file_name):
      self.error(f"{file_name}: No such file or directory")
    try:
      with open(file_name, 'r') as fobj:
        obj = json.load(fobj)
        if obj is None:
          obj = {
            "calls": {},
            "edges": {},
            "entries": {},
          }
        self.add_object(obj)
      del obj
    except Exception as e:
      self.error(f"{file_name}: {e}.")
  
  def add_object(self, obj: dict):
    new_calls = obj['calls'] if 'calls' in obj.keys() else {}
    new_edges = obj['edges'] if 'edges' in obj.keys() else {}
    new_entries = obj['entries'] if 'entries' in obj.keys() else {}

    for key in new_calls:
      if key in self.calls.keys():
        print("cfg-ld: \033[01;33mWarning:\033[0;m duplicate key", key, "found in \'calls\'", file=sys.stderr)
        self.calls[key] = new_calls[key]
      else:
        self.calls[key] = new_calls[key]
    
    for key in new_edges:
      if key in self.edges.keys():
        # raise RuntimeError(f"duplicate key {key} found in \'edges\'")
        print("cfg-ld: \033[01;33mWarning:\033[0;m duplicate key", key, "found in \'edges\'", file=sys.stderr)
        self.edges[key] = new_edges[key]
      else:
        self.edges[key] = new_edges[key]
      
    for key in new_entries:
      if key in self.entries.keys():
        # raise RuntimeError(f"duplicate key {key} found in \'entries\'")
        pass
      else:
        self.entries[key] = new_entries[key]
    
    del new_calls
    del new_entries
    del new_edges
  
  def error(self, message: str):
    """ Print a error message and exit. """
    print("cfg-ld: \033[01;31merror:\033[0m", message, file=sys.stderr)
    raise RuntimeError("Further execution is not possible.")
  
  def output(self, file_name = "a.out.cfg"):
    """
    Print linker output to file_name.
    """
    obj = {
      "calls": self.calls,
      "edges": self.edges,
      "entries": self.entries,
    }
    with open(file_name, 'w') as fobj:
      json.dump(obj, fobj)
    del obj

CFG_EXTENSION = ".cfg"
OJBECT_EXTENSION = ".o"

if __name__ == "__main__":
  args = sys.argv[1:]
  print("\033[01;32m[*]\033[0;m cfg-ld", args, file=sys.stderr)
  linker: CFGLinker = CFGLinker()
  if len(args) == 0:
    print("cfg-ld: \033[01;31merror:\033[0;m cfg-ld", "No input files", file=sys.stderr)
    sys.exit(0)

  # filter args

  # parser args
  i = 0
  input_files = []
  output_file = "a.out.cfg"
  while i < len(args):
    if args[i] == "-o" or args[i] == "--output":
      output_file = args[i + 1]
      i += 2
    else:
      input_files.append(args[i])
      i += 1

  for input_file in input_files:
    linker.add_cfg_file(input_file)
  linker.output(file_name = output_file) 
  sys.exit(0)
