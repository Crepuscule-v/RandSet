import sys
from elftools.elf.elffile import ELFFile


def get_begin_sancov_addr(elf_file_path):
    with open(elf_file_path, 'rb') as f:
        elffile = ELFFile(f)
        for section in elffile.iter_sections():
            if section.name == "__sancov_guards":
                return section['sh_addr']
    return None

def get_sancov_cfg(elf_file_path, sancov_begin_addr, gap):
    cfg_dict_list = dict()
    
    # read from .cfg_log_section
    with open(elf_file_path, 'rb') as f:
        elffile = ELFFile(f)
        for section in elffile.iter_sections():
            if section.name == ".cfg_log_section":
                for i in range(0, section.data_size, 2 * gap):
                    sancov_addr = int.from_bytes(section.data()[i:i+8], byteorder='little')
                    pred_index = (sancov_addr-sancov_begin_addr)//4
                    succ_sancov_addr = int.from_bytes(section.data()[i+gap:i+gap+8], byteorder='little')
                    succ_index = (succ_sancov_addr-sancov_begin_addr)//4
                    if pred_index not in cfg_dict_list:
                        cfg_dict_list[pred_index] = []
                    cfg_dict_list[pred_index].append(succ_index)
    return cfg_dict_list
            
                    
if __name__ == '__main__': 
    elf_path = sys.argv[1]
    sancov_addr = get_begin_sancov_addr(elf_path)
    if not sancov_addr:
        print("No sancov section found")
        sys.exit(1)
    # we use struct, no need to get gap 
    gap = 8
    # from .cfg_log_section get sancov_addr(8 bytes) and corresponding succ's sancov_addr (8 bytes)
    cfg = get_sancov_cfg(elf_path, sancov_addr, gap)
    # print(cfg)
    with open("sancov_cfg", "w") as f:
        for pred_index in cfg:
            for succ_index in cfg[pred_index]:
                f.write(str(pred_index + 6) + " " + str(succ_index + 6) + "\n")
    