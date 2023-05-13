#Resolve Workshop APIs
#@author @c3rb3ru5d3d53c
#@category APIs
#@keybinding 
#@menupath 
#@toolbar 

from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.lang import OperandType
from hexdump import hexdump
from pprint import pprint
import pickle

g_resolve_api = 0x00401600
g_pickle_path = '/home/remnux/ghidra_scripts/apis.pickle'

def get_address(address: int):
	return currentProgram.getAddressFactory().getAddress(str(hex(address)))

def get_codeunit(address):
	return currentProgram.getListing().getCodeUnitAt(address)

def get_xrefs(address: int):
    return [x.getFromAddress() for x in getReferencesTo(get_address(address))]

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

def create_hash(data: bytes):
    data = bytearray(data)
    h = 0xdeadbeef
    for i in range(0, len(data)):
        h = (data[i] + h) & 0xffffffff
        h ^= (h << 8) & 0xffffffff
    return h

def create_fhm(modules):
    h = {}
    for m in modules:
        for e in m['exports']:
            h[create_hash(e.encode())] = e
    return h

modules = pickle.load(open(g_pickle_path, 'rb'))

fhm = create_fhm(modules)

results = [get_params(a) for a in get_xrefs(g_resolve_api)]

for result in results: set_comment_eol(result['address'], fhm[result['func_hash']], debug=True)
