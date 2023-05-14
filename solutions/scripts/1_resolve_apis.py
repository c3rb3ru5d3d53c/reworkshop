#Resolve Workshop APIs
#@author @c3rb3ru5d3d53c
#@category APIs
#@keybinding 
#@menupath 
#@toolbar 

import pickle
from pprint import pprint
from hexdump import hexdump
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.lang import OperandType
from ghidra.program.flatapi import FlatProgramAPI

def search_memory(string, max_results=128):
    fpi = FlatProgramAPI(getCurrentProgram())
    return fpi.findBytes(currentProgram.getMinAddress(), ''.join(['.' if '?' in x else f'\\x{x}' for x in string.split()]), max_results)

def get_address(address: int):
	return currentProgram.getAddressFactory().getAddress(str(hex(address)))

def get_codeunit(address):
	return currentProgram.getListing().getCodeUnitAt(address)

def get_xrefs(address):
    return [x.getFromAddress() for x in getReferencesTo(address)]

def set_comment_eol(address, text, debug=False):
    cu = currentProgram.getListing().getCodeUnitAt(address)
    if debug is False: cu.setComment(CodeUnit.EOL_COMMENT, text)
    if debug is True: print(str(address) + ' | ' + text)

def get_params(address, max_insn=128):
    params = []
    start_address = address
    for i in range(0, max_insn):
        if len(params) >= 2: break
        cu = get_codeunit(address)
        if cu.getMnemonicString().lower() == 'push':
            params.append(cu.getScalar(0).getValue())
        address = cu.getPrevious().getAddress()
    if len(params) < 2: return None
    return {
        'address': start_address,
        'module_hash': params[0],
        'func_hash': params[1]
    }

def get_seed(max_insn=32):
    address = search_memory('55 8b ec 83 ec 0c c7 4? ?? ?? ?? ?? ?? c7 4? ?? 00 00 00 00 eb ?? 8b 4? ?? 83 c0 01 89 4? ?? 8b 4? ?? 3b 4? ?? 73 ?? 8b 5? ?? 03 5? ?? 8a 02 88 4? ?? 0f b6 4? ?? 03 4? ?? 89 4? ?? 8b 5? ?? c1 e2 08 33 5? ?? 89 5? ?? eb ?? 8b 4? ?? 8b e5 5d c3')[0]
    cu = get_codeunit(address)
    for i in range(0, max_insn):
        if cu.getMnemonicString().lower() == 'mov' and cu.getOperandType(1) == OperandType.SCALAR:
            return cu.getScalar(1).getValue() & 0xffffffff
        cu = cu.getNext()
    return None

def create_hash(data: bytes, seed=0xdeadbeef):
    data = bytearray(data)
    h = seed
    for i in range(0, len(data)):
        h = (data[i] + h) & 0xffffffff
        h ^= (h << 8) & 0xffffffff
    return h

def create_fhm(modules):
    h = {}
    seed = get_seed()
    for m in modules:
        for e in m['exports']:
            h[create_hash(e.encode(), seed=seed)] = e
    return h

modules = pickle.load(open(askFile('Choose API Picke File', 'Okay').toString(), 'rb'))

fhm = create_fhm(modules)

results = [get_params(a) for a in get_xrefs(search_memory('55 8b ec 83 ec 18 e8 ?? ?? ?? ?? 89 4? ?? 83 7? ?? 00 75 ?? 33 c0 e9 ?? ?? ?? ?? c7 4? ?? 00 00 00 00 c7 4? ?? 00 00 00 00 c7 4? ?? 00 00 00 00 c7 4? ?? 00 00 00 00 8b 4? ?? 8b 48 0c 89 4? ?? 8b 5? ?? 83 c2 14 89 5? ?? 8b 4? ?? 8b 08 89 4? ?? 8b 5? ?? 3b 5? ?? 74 ?? 8b 4? ?? 83 e8 08 89 4? ?? 8b 4? ?? 8b 51 30 52 e8 ?? ?? ?? ?? 83 c4 04 3b 4? ?? 75 ?? 8b 4? ?? 50 8b 4? ?? 8b 51 18 52 e8 ?? ?? ?? ?? 83 c4 08 89 4? ?? 83 7? ?? 00 75 ?? 33 c0 eb ?? 8b 4? ?? eb ?? 8b 4? ?? 8b 08 89 4? ?? eb ?? 33 c0 8b e5 5d c3')[0])]

for result in results: set_comment_eol(result['address'], fhm[result['func_hash']], debug=True)
