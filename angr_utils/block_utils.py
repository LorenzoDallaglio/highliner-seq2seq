import angr

def index_blocks(binary_path, rebase=True):
    proj = angr.Project(binary_path, main_opts={'arch': "amd64"}, load_options={'auto_load_libs': False})
    base_addr = proj.loader.main_object.min_addr if rebase else 0
    cfg = proj.analyses.CFGFast(normalize=True)
    function_manager = cfg.kb.functions
    block_index = {}
    for fun in function_manager.values():
        for block in fun.blocks:
            block_index[block.addr - base_addr] = block
        
    return block_index

def disasm_as_seq(block):
    seq = []
    for inst in block.disassembly.insns:
        inst_string = "{}: ".format(hex(inst.address))
        inst_string += "{} {}".format(inst.mnemonic, inst.op_str)
        seq.append(inst_string)
    return seq
