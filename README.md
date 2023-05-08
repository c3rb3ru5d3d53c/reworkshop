# API Hashing and String Decryption Reverse Engineering Workshop

This project borrows code from the following:
- https://hero.handmade.network/forums/code-discussion/t/94-guide_-_how_to_avoid_c_c++_runtime_on_windows
- https://github.com/LloydLabs/Windows-API-Hashing

## Features
1. Empty Import Table
2. Empty Debug Directory
3. No Rich Header

## Workshop Goals

1. Write String Decryptor
2. Write API Hashing Algorithm
3. Prove they work

## Where to Start

1. Download `solutions/samples.zip`
2. Copy `samples.zip` to your VM (with internet)
3. In your Windows and Remnux VM, extract `samples.zip` (password is `infected`)
4. Open `stealer.exe` with x64dbg (32-bit)
5. In the Remnux VM, create a new Ghidra project and import `stealer.exe`
6. In the Remnux VM with Ghidra, import the `.h` files from the `include/` directory
7. Write a string decryptor in Python
8. Write the API hashing algorithm in Python

NOTE: Steps 7 or 8 and be in either order
