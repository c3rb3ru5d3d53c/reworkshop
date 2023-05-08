# API Hashing and String Decryption Reverse Engineering Workshop Solutions

These are the solutions to the workshop.

## API Hashing Algorithm

```cpp
// Original
__declspec(noinline) UINT32 resolve_hash(BYTE* data, SIZE_T data_size) {
	UINT32 hash = 0xdeadbeef;
	for (SIZE_T i = 0; i < data_size; i++) {
		BYTE c = data[i];
		hash += c;
		hash ^= hash << 8;
	}
	return hash;
}
```

```cpp
// Ghidra
uint32_t __cdecl mw::CreateHash(BYTE *data, SIZE_T size) {
  SIZE_T i;
  uint32_t h;
  
  h = 0xdeadbeef;
  for (i = 0; i < size; i = i + 1) {
    h = (data[i] + h) * 256 ^ data[i] + h;
  }
  return h;
}
```

```python
# Python
def create_hash(data: bytes):
    data = bytearray(data)
    h = 0xdeadbeef
    for i in range(0, len(data)):
        h = (data[i] + h) & 0xffffffff
        h ^= (h << 8) & 0xffffffff
    return h

def create_hash_stra(string):
    return create_hash(string.encode())

def create_strw(string):
    result = b''
    for c in string:
        result += c.encode() + b'\x00'
    return result.rstrip(b'\x00')

def create_hash_strw(string):
    return create_hash(create_strw(string))
```

## String Decryption Algorithm

```cpp
// Original
__declspec(noinline) BYTE* crypt(BYTE* data, SIZE_T data_size) {
    BYTE key[] = {
        0x51,0x66,0x3d,0x22,
        0x66,0x81,0x9e,0x53,
        0x90,0x41,0xa1,0x86,
        0x47,0x07,0xa3,0x75,
        0xae,0x8a,0xd0,0xb4,
        0xf6,0xf8,0x16,0xa3,
        0x23,0x2f,0x3a,0xfe,
        0x8f,0x10,0x6f,0xf7 };
    for (SIZE_T i = 0; i < data_size; i++) {
        data[i] ^= key[i % 32];
    }
    return data;
}
```

```cpp
// Ghidra
PVOID __cdecl mw::Decrypt(BYTE *data,uint data_size) {
  uint i;
  BYTE key [32];
  i = 0;
  key._0_4_ = 0x223d6651;
  key._4_4_ = 0x539e8166;
  key._8_4_ = 0x86a14190;
  key._12_4_ = 0x75a30747;
  key._16_4_ = 0xb4d08aae;
  key._20_4_ = 0xa316f8f6;
  key._24_4_ = 0xfe3a2f23;
  key._28_4_ = 0xf76f108f;
  if (data_size != 0) {
    do {
      data[i] = data[i] ^ key[i & 31];
      i = i + 1;
    } while (i < data_size);
  }
  return data;
}
```

```python
# Python
ciphertext = bytes(bytearray([0x39,0x12,0x49,0x52,0x15,0xbb,0xb1,0x7c,0xe7,0x36,0xd6,0xa8,0x3e,0x68, 0xd6,0x01,0xdb,0xe8,0xb5,0x9a,0x95,0x97,0x7b,0x8c,0x54,0x4e,0x4e,0x9d,0xe7,0x2f,0x19,0xca,0x35,0x37,0x4a,0x16,0x11,0xb8,0xc9,0x34,0xc8,0x22,0xf0,0x86]))
def decrypt(data):
    key = bytearray([0x51,0x66,0x3d,0x22,0x66,0x81,0x9e,0x53,0x90,0x41,0xa1,0x86,0x47,0x07,0xa3,0x75,0xae,0x8a,0xd0,0xb4,0xf6,0xf8,0x16,0xa3,0x23,0x2f,0x3a,0xfe,0x8f,0x10,0x6f,0xf7])
    data = bytearray(data)
    for i in range(0, len(data)):
        data[i] ^= key[i % 32]
    return bytes(data)
```
