#Decrypt Workshop Strings
#@author @c3rb3ru5d3d53c
#@category Strings
#@keybinding 
#@menupath 
#@toolbar 

from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.lang import OperandType
from ghidra.program.flatapi import FlatProgramAPI
from hexdump import hexdump
from pprint import pprint

def search_memory(string, max_results=128):
    fpi = FlatProgramAPI(getCurrentProgram())
    return fpi.findBytes(currentProgram.getMinAddress(), ''.join(['.' if '?' in x else f'\\x{x}' for x in string.split()]), max_results)

def get_address(address: int):
	return currentProgram.getAddressFactory().getAddress(str(hex(address)))

def get_codeunit(address):
	return currentProgram.getListing().getCodeUnitAt(address)

def set_comment_eol(address, text, debug=False):
    cu = currentProgram.getListing().getCodeUnitAt(address)
    if debug is False: cu.setComment(CodeUnit.EOL_COMMENT, text)
    if debug is True: print(str(address) + ' | ' + text)

def decrypt(data, key):
    key = bytearray(key)
    data = bytearray(data)
    for i in range(0, len(data)):
        data[i] ^= key[i % 32]
    return bytes(data)

def get_xrefs(address):
    return [x.getFromAddress() for x in getReferencesTo(address)]

def get_decrypt_key(max_insn=32):
    address = search_memory('55 8b ec 83 ec 20 8b 4? ?? 33 d2 56 8b 7? ?? c7 4? ?? ?? ?? ?? ?? c7 4? ?? ?? ?? ?? ?? c7 4? ?? ?? ?? ?? ?? c7 4? ?? ?? ?? ?? ?? c7 4? ?? ?? ?? ?? ?? c7 4? ?? ?? ?? ?? ?? c7 4? ?? ?? ?? ?? ?? c7 4? ?? ?? ?? ?? ?? 85 f6 74 ?? 0f 1f 44 00 00 8b ca 83 e1 1f 8a 4c ?? ?? 30 0c 02 42 3b d6 72 ?? 5e 8b e5 5d c3')[0]
    result = []
    cu = get_codeunit(address)
    for i in range(0, max_insn):
        if cu.getMnemonicString().lower() == 'jz': break
        if (cu.getMnemonicString().lower() == 'mov' and
            cu.getOperandType(1) == OperandType.SCALAR):
            result.append(cu.getScalar(1).getValue())
        cu = cu.getNext()
    return b''.join([c.to_bytes(4, 'little') for c in result])

def get_ciphertext(address, max_insn=128):
    ct = []
    for i in range(0, max_insn):
        cu = get_codeunit(address)
        if (cu.getMnemonicString().lower() == 'call' and
            i > 0):
            break
        if (cu.getMnemonicString().lower() == 'mov' and
            cu.getOperandType(1) == OperandType.SCALAR and
            cu.getScalar(1).getValue() == 0x06):
            break
        if (cu.getMnemonicString().lower() == 'mov' and
            cu.getOperandType(1) == OperandType.SCALAR and
            cu.getScalar(1).getValue() == 0x00):
            break
        if (cu.getMnemonicString().lower() == 'mov' and
            cu.getOperandType(1) == OperandType.SCALAR):
            ct.append(cu.getScalar(1).getValue())
        address = cu.getPrevious().getAddress()
    return b''.join([c.to_bytes(4, 'little') for c in reversed(ct)]).split(b'\x00')[0]

addrs = get_xrefs(search_memory('55 8b ec 83 ec 20 8b 4? ?? 33 d2 56 8b 7? ?? c7 4? ?? ?? ?? ?? ?? c7 4? ?? ?? ?? ?? ?? c7 4? ?? ?? ?? ?? ?? c7 4? ?? ?? ?? ?? ?? c7 4? ?? ?? ?? ?? ?? c7 4? ?? ?? ?? ?? ?? c7 4? ?? ?? ?? ?? ?? c7 4? ?? ?? ?? ?? ?? 85 f6 74 ?? 0f 1f 44 00 00 8b ca 83 e1 1f 8a 4c ?? ?? 30 0c 02 42 3b d6 72 ?? 5e 8b e5 5d c3')[0])

key = get_decrypt_key()

for addr in addrs:
    ct = get_ciphertext(addr)
    pt = decrypt(ct, key).rstrip(b'\x00').decode('ascii')
    set_comment_eol(addr, pt, debug=True)
    