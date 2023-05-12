#TODO write a description for this script
#@author Your Mom
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 


from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.lang import OperandType
from hexdump import hexdump
from pprint import pprint

g_decrypt_function = 0x00401420

def get_address(address: int):
	return currentProgram.getAddressFactory().getAddress(str(hex(address)))

def get_codeunit(address):
	return currentProgram.getListing().getCodeUnitAt(address)

def set_comment_eol(address, text, debug=False):
    cu = currentProgram.getListing().getCodeUnitAt(address)
    if debug is False: cu.setComment(CodeUnit.EOL_COMMENT, text)
    if debug is True: print(str(address) + ' | ' + text)

def decrypt(data):
    key = bytearray([0x51,0x66,0x3d,0x22,0x66,0x81,0x9e,0x53,0x90,0x41,0xa1,0x86,0x47,0x07,0xa3,0x75,0xae,0x8a,0xd0,0xb4,0xf6,0xf8,0x16,0xa3,0x23,0x2f,0x3a,0xfe,0x8f,0x10,0x6f,0xf7])
    data = bytearray(data)
    for i in range(0, len(data)):
        data[i] ^= key[i % 32]
    return bytes(data)

addrs = [x.getFromAddress() for x in getReferencesTo(get_address(g_decrypt_function))]

def get_ciphertext(address, max_insn=128):
    ct = []
    for i in range(0, max_insn):
        cu = get_codeunit(address)
        if cu.getMnemonicString().lower() == 'call' and i > 0:
            break
        if cu.getMnemonicString().lower() == 'mov' and cu.getOperandType(1) == OperandType.SCALAR and cu.getScalar(1).getValue() == 0x06:
            break
        if cu.getMnemonicString().lower() == 'mov' and cu.getOperandType(1) == OperandType.SCALAR and cu.getScalar(1).getValue() == 0x00:
            break
        if cu.getMnemonicString().lower() == 'mov' and cu.getOperandType(1) == OperandType.SCALAR:
            ct.append(cu.getScalar(1).getValue())
        address = cu.getPrevious().getAddress()
    return b''.join([c.to_bytes(4, 'little') for c in reversed(ct)]).split(b'\x00')[0]

for addr in addrs:
    ct = get_ciphertext(addr)
    pt = decrypt(ct).rstrip(b'\x00').decode('ascii')
    set_comment_eol(addr, pt, debug=True)
    