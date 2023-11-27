#---------------------------------------------------------------------------------
# 202301030 JPCERT/CC masubuchi
# IDA Version 8.4
#---------------------------------------------------------------------------------
try:
    import idaapi
    import idautils
    import ida_funcs
    import ida_bytes
    import ida_nalt
    import ida_search
    import ida_idaapi
    import idc
except ImportError:
    pass

try:
    from Crypto.Cipher import AES
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.IO import PEM
    from Crypto.Util import Counter
except ImportError:
    pass

import binascii

def read_ptr(ea):
    if idaapi.get_inf_structure().is_64bit():
        return idaapi.get_qword(ea)
    return idaapi.get_dword(ea)


def read_string(ea):
    size = ida_bytes.get_max_strlit_length(ea, ida_nalt.STRTYPE_C)
    strings_bytes = ida_bytes.get_strlit_contents(ea, size, ida_nalt.STRTYPE_C)
    print(strings_bytes)


def dbg_priHex(byte):
    print('[*] 0x{:02X}'.format(byte))


def dbg_priHex_bytes(bytes):
    print('[*] 0x', end="")
    for byte in bytes:
        print('{:02X}'.format(byte), end="")
    print("\t", end="")
    for byte in bytes:
        print('{}'.format(chr(byte)), end="")
    print("")


def get_list_of_xrefAddr_from_funcAddr(functionAddr, enablePrint=True):
    print("[*] FUNC address: {:02X}" .format(functionAddr))

    Xref_functionAddr = []
    for addr in idautils.CodeRefsTo(functionAddr, 0):
        Xref_functionAddr.append(addr)
    print("[*] XREF count: {}".format(len(Xref_functionAddr)))
    if enablePrint == True:
        for addr in Xref_functionAddr:
            print("[*] XREF Addr: 0x{:02X}".format(addr))

    return Xref_functionAddr
    

'''
How to use
    addr   : specified address
    offset: number of offset instruction from addr
    addrF  : get address
    opNum  : get string(opcode) or value(operand)
                0:opcode |  1:operand1 | 2:operand2  | 3:operand3
    typeF  : get type specified opNum
    dbgF   : debug print
'''
def get_op_type_addr_from_addr(addr, offset=-1, opNum=0, addrF=False, typeF=False, dbgF=False):
    target_addr = addr
    if offset < 0:
        for x in range(offset * -1):
            target_addr = idc.prev_head(target_addr)
    elif offset > 0:
        for x in range(offset):
            target_addr = idc.next_head(target_addr)

    if dbgF: 
        print("[*] XREF target instruction: 0x{:02X} {}" 
            .format(target_addr, idc.generate_disasm_line(target_addr, 0) ))
    if addrF:
        return target_addr

    if opNum == 0: 
        opcode = idc.print_insn_mnem(target_addr)
        return opcode
    elif opNum == 1 or opNum == 2 or opNum == 3: 
        oprValue = idc.get_operand_value(target_addr, opNum -1)
        oprType = idc.get_operand_type(target_addr, opNum -1)
        if typeF:
            return oprType
        else:
            return oprValue
    else:
        print("ERROR: Check arguments! into  get_opcode_oprand_addr_in_NumOfPrev()")


def ascii_to_bytes(inputstr):
    return inputstr.encode('utf-8')


def getAddr_from_FunctionName(SearchFuncName):
    for segea in idautils.Segments():
        for funcea in idautils.Functions(segea, idc.get_segm_end(segea)):
            functionName = ida_funcs.get_func_name(funcea)
            if functionName == SearchFuncName:
                return funcea
    print("Error Not Found function: {}".format(SearchFuncName))
    return False


def find_func_byName(functionname, notprint = False):
    EncFuncAddr = getAddr_from_FunctionName(functionname)
    if EncFuncAddr != False and notprint == False:
        dbg_priHex(EncFuncAddr)
    return EncFuncAddr


def decrypt_AES_from_key(enc, key, iv):
    ctr = Counter.new(128, initial_value=int.from_bytes(iv, byteorder='big'))

    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    return cipher.decrypt(enc)


def decrypt_gobrat(EncDATA):
    AES_IV = ascii_to_bytes("12345678abcdefgh")
    AESkey = b"\x05\x0C\xFE\x37\x06\x38\x07\x23\x43\x38\x07\x19\x3E\x03\xFE\x2F"

    bindata = decrypt_AES_from_key(EncDATA, AESkey, AES_IV)

    print(bindata)


def findBin_on_range_from_addr(Addr, SearchBytes, Range = -1):
    target_addr = Addr

    if Range < 0:
        for x in range(Range * -1):
            target_addr = idc.prev_head(target_addr)

        hit_addr = ida_search.find_binary(target_addr, Addr, SearchBytes, 0, idaapi.SEARCH_DOWN | idaapi.SEARCH_CASE)
        if hit_addr != idc.BADADDR: 
            return hit_addr

    elif Range > 0:
        for x in range(offset):
            target_addr = idc.next_head(target_addr)

        hit_addr = ida_search.find_binary(Addr, target_addr, SearchBytes, 0, idaapi.SEARCH_DOWN | idaapi.SEARCH_CASE)
        if hit_addr != idc.BADADDR: 
            return hit_addr

    return False

def extract_bytes_from_addr(addr, size):
    bytesdata = idaapi.get_bytes(addr, size)
    if bytesdata != ida_idaapi.BADADDR:
        return idaapi.get_bytes(addr, size)
    return False 


def get_ampersand_var(addr):
    if addr != ida_idaapi.BADADDR:
        if idaapi.get_inf_structure().is_64bit():
            return idaapi.get_qword(addr)
        return idaapi.get_dword(addr)
    return False


def get_ptr_var(addr, size):
    paddr = 0x0
    if idaapi.get_inf_structure().is_64bit():
        paddr = idaapi.get_qword(addr)
    else:
        paddr =  idaapi.get_dword(addr)
    if paddr != idc.BADADDR: 
        value = extract_bytes_from_addr(paddr, size)
        return value
    return False    


def wrap_decrypt():
    print('--Start!')
    EncFuncAddr = find_func_byName("aaa.com_bbb_mecrypt.AesEncrypt")

    xref_list = get_list_of_xrefAddr_from_funcAddr(EncFuncAddr)
    for xrefAddr in xref_list:
        dbg_priHex(xrefAddr)
        funcRef = ida_funcs.get_func(xrefAddr)
        xrefAddr

        # decrypt function itself
        if funcRef.start_ea == EncFuncAddr:
            print("[+] Skip decrypt function")
            continue

        # C2 strings
        hitAddr = findBin_on_range_from_addr(xrefAddr, "4C 8B 0D ?? ?? ?? ??", Range = -30)
        if hitAddr != False:
            pEncDATA = get_op_type_addr_from_addr(hitAddr, offset=0, opNum=2)
            EncDATA_size = get_ptr_var(pEncDATA, 2)
            if EncDATA_size != False:
                EncDATA_size_int = int.from_bytes(EncDATA_size, byteorder='little', signed=False) >> 0x8
        
                ptr_EncData = get_ampersand_var(pEncDATA) + 2

                EncDATA = extract_bytes_from_addr(ptr_EncData, EncDATA_size_int)
                dbg_priHex_bytes(EncDATA)
                decrypt_gobrat(EncDATA)
                continue



        # strings pattern 0
        hitAddr = findBin_on_range_from_addr(xrefAddr, "E8 ?? ?? ?? ?? 48 B9 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 08 48 B9 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 48 08", Range = -15)        
        if hitAddr != False:
            EncdataVal01 = get_op_type_addr_from_addr(hitAddr, offset=1, opNum=2)
            EncdataVal01_bytes = EncdataVal01.to_bytes(8,'little')

            hitAddr = findBin_on_range_from_addr(xrefAddr, "48 B9 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 48 08", Range = -15)
            if hitAddr != False:
                EncdataVal02 = get_op_type_addr_from_addr(hitAddr, offset=0, opNum=2)
                EncdataVal02_bytes = EncdataVal02.to_bytes(8,'little')
        
                hitAddr = findBin_on_range_from_addr(xrefAddr, "48 B9 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 48 10", Range = -15)
                if hitAddr != False:
                    EncdataVal03 = get_op_type_addr_from_addr(hitAddr, offset=0, opNum=2)
                    EncdataVal03_bytes = EncdataVal03.to_bytes(8,'little')

                    hitAddr = findBin_on_range_from_addr(xrefAddr, "48 B9 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 48 18", Range = -15)
                    if hitAddr != False:
                        EncdataVal04 = get_op_type_addr_from_addr(hitAddr, offset=0, opNum=2)
                        EncdataVal04_bytes = EncdataVal04.to_bytes(8,'little')

                        hitAddr = findBin_on_range_from_addr(xrefAddr, " C7 40 20", Range = -15)
                        if hitAddr != False:
                            EncdataVal05 = get_op_type_addr_from_addr(hitAddr, offset=0, opNum=2)
                            EncdataVal05_bytes = EncdataVal05.to_bytes(4,'little')

                        decrypt_gobrat(EncdataVal01_bytes + EncdataVal02_bytes + EncdataVal03_bytes + EncdataVal04_bytes + EncdataVal05_bytes)
                        continue
            continue
        
        # strings pattern 1
        hitAddr = findBin_on_range_from_addr(xrefAddr, "E8 ?? ?? ?? ?? 48 B9", Range = -15)       
        if hitAddr != False:
            EncdataVal01 = get_op_type_addr_from_addr(hitAddr, offset=1, opNum=2)
            EncdataVal01_bytes = EncdataVal01.to_bytes(8,'little')

            hitAddr = findBin_on_range_from_addr(xrefAddr, "66 C7 40 08", Range = -15)
            if hitAddr != False:
                EncdataVal02 = get_op_type_addr_from_addr(hitAddr, offset=0, opNum=2)
                EncdataVal02 = EncdataVal02  & 0xffff
                EncdataVal02_bytes = EncdataVal02.to_bytes(2,'little', signed=False)
                
                hitAddr = findBin_on_range_from_addr(xrefAddr, "C6 40 0A", Range = -15)
                if hitAddr != False:
                    EncdataVal03 = get_op_type_addr_from_addr(hitAddr, offset=0, opNum=2)
                    EncdataVal03_bytes = EncdataVal03.to_bytes(1,'little')

                    decrypt_gobrat(EncdataVal01_bytes + EncdataVal02_bytes + EncdataVal03_bytes)
                    continue
                continue

            hitAddr = findBin_on_range_from_addr(xrefAddr, "C6 40 08", Range = -15)
            if hitAddr != False:
                EncdataVal02 = get_op_type_addr_from_addr(hitAddr, offset=0, opNum=2)
                EncdataVal02_bytes = EncdataVal02.to_bytes(1,'little')
                
                decrypt_gobrat(EncdataVal01_bytes + EncdataVal02_bytes)
                continue


            hitAddr = findBin_on_range_from_addr(xrefAddr, "C7 40 08", Range = -15)
            if hitAddr != False:
                EncdataVal02 = get_op_type_addr_from_addr(hitAddr, offset=0, opNum=2)
                EncdataVal02 = EncdataVal02  & 0xffffffff
                EncdataVal02_bytes = EncdataVal02.to_bytes(4,'little')
                
                hitAddr = findBin_on_range_from_addr(xrefAddr, "C6 40 0C", Range = -15)
                if hitAddr != False:
                    EncdataVal03 = get_op_type_addr_from_addr(hitAddr, offset=0, opNum=2)
                    EncdataVal03_bytes = EncdataVal03.to_bytes(1,'little')

                    decrypt_gobrat(EncdataVal01_bytes + EncdataVal02_bytes + EncdataVal03_bytes)
                    continue
                continue


        # strings pattern 2
        hitAddr = findBin_on_range_from_addr(xrefAddr, "E8 ?? ?? ?? ?? C7", Range = -15)        
        if hitAddr != False:
            EncdataVal01 = get_op_type_addr_from_addr(hitAddr, offset=1, opNum=2)
            EncdataVal01_bytes = EncdataVal01.to_bytes(4,'little')

            hitAddr = findBin_on_range_from_addr(xrefAddr, "66 C7 40", Range = -15)
            if hitAddr != False:
                EncdataVal02 = get_op_type_addr_from_addr(hitAddr, offset=0, opNum=2)
                EncdataVal02_bytes = EncdataVal02.to_bytes(2,'little')
        
                hitAddr = findBin_on_range_from_addr(xrefAddr, "C6 40 06", Range = -15)
                if hitAddr != False:
                    EncdataVal03 = get_op_type_addr_from_addr(hitAddr, offset=0, opNum=2)
                    EncdataVal03_bytes = EncdataVal03.to_bytes(1,'little')
            
                    decrypt_gobrat(EncdataVal01_bytes + EncdataVal02_bytes + EncdataVal03_bytes)
                    continue

                hitAddr = findBin_on_range_from_addr(xrefAddr, "C6 40 0A", Range = -15)
                if hitAddr != False:
                    EncdataVal03 = get_op_type_addr_from_addr(hitAddr, offset=0, opNum=2)
                    EncdataVal03_bytes = EncdataVal03.to_bytes(1,'little')
            
                    decrypt_gobrat(EncdataVal01_bytes + EncdataVal02_bytes + EncdataVal03_bytes)
                    continue

                decrypt_gobrat(EncdataVal01_bytes + EncdataVal02_bytes)
                continue


            hitAddr = findBin_on_range_from_addr(xrefAddr, "C6 40 04", Range = -15)
            if hitAddr != False:
                EncdataVal02 = get_op_type_addr_from_addr(hitAddr, offset=0, opNum=2)
                EncdataVal02_bytes = EncdataVal02.to_bytes(1,'little')
        
                decrypt_gobrat(EncdataVal01_bytes + EncdataVal02_bytes)
                continue

            decrypt_gobrat(EncdataVal01_bytes)
            continue


        # strings pattern 3
        hitAddr = findBin_on_range_from_addr(xrefAddr, "E8 ?? ?? ?? ?? 66 C7", Range = -15)        
        if hitAddr != False:
            EncdataVal01 = get_op_type_addr_from_addr(hitAddr, offset=1, opNum=2)
            EncdataVal01_bytes = EncdataVal01.to_bytes(2,'little')

            hitAddr = findBin_on_range_from_addr(xrefAddr, "C6 40 02", Range = -15)

            if hitAddr != False:
                EncdataVal02 = get_op_type_addr_from_addr(hitAddr, offset=0, opNum=2)
                EncdataVal02_bytes = EncdataVal02.to_bytes(1,'little')
        
                decrypt_gobrat(EncdataVal01_bytes + EncdataVal02_bytes)
                continue
            else:
                decrypt_gobrat(EncdataVal01_bytes)
                continue


def Enable_addr_into_Function_quickly(checkAddr, FuncName):
    chkfuncname = idaapi.get_func_name(checkAddr)
    if chkfuncname == FuncName:
        return True
    else:
        return False


def find_version_x86_64():
    print("Start!")
    EncFuncAddr = find_func_byName("runtime.convTstring", notprint=True)
    xref_list = get_list_of_xrefAddr_from_funcAddr(EncFuncAddr, enablePrint=False)
    for xrefAddr in xref_list:
        funcname = "main.main"
        if Enable_addr_into_Function_quickly(xrefAddr, funcname) == True:

            argAddr = findBin_on_range_from_addr(xrefAddr, "48 8B 05 ?? ?? ?? ?? 48 8B 1D", Range = -3)
            if argAddr != False:
                ptr_version = get_op_type_addr_from_addr(argAddr, offset=0, opNum=2)
                dbg_priHex(ptr_version)

                addr_version = read_ptr(ptr_version)
                dbg_priHex(addr_version)

                read_string(addr_version)

    print("Finish!")


def main():
    find_version_x86_64()
    find_func_byName("aaa.com_bbb_mecrypt.AesEncrypt")
    wrap_decrypt()


if __name__ == '__main__':
    main()


class DecryptGobRAT_Plugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_DRAW
    comment = "Decrypt GobRAT strings."
    help = "Decrypt GobRAT"
    wanted_name = "DecryptGobRAT"
    wanted_hotkey = "" # = "Alt-F10"

    def init(self):
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        main()
        return

    def term(self):
        pass


def PLUGIN_ENTRY():
    return DecryptGobRAT_Plugin()

