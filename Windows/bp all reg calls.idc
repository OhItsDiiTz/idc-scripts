/*
This script is buggy, it breakpoints all of the indirect calls in an executable before debugging. But due to things sharing the same bytes not all will truely be indirect calls

*/

#include <idc/idc.idc>

static process_call(call_addr) {
    Message("call_addr: 0x%X\n", call_addr);
    add_bpt(call_addr);
}

static main() {
    //call rax
    auto call_reg = FindBinary(get_imagebase(), SEARCH_DOWN, "FF D0");
    while(call_reg != BADADDR) {
        process_call(call_reg);
        call_reg = FindBinary(call_reg + 1, SEARCH_DOWN, "FF D0");
    }
    
    //call rbx
    call_reg = FindBinary(get_imagebase(), SEARCH_DOWN, "FF D3");
    while(call_reg != BADADDR) {
        process_call(call_reg);
        call_reg = FindBinary(call_reg + 1, SEARCH_DOWN, "FF D3");
    }
    
    //call rcx
    call_reg = FindBinary(get_imagebase(), SEARCH_DOWN, "FF D1");
    while(call_reg != BADADDR) {
        process_call(call_reg);
        call_reg = FindBinary(call_reg + 1, SEARCH_DOWN, "FF D1");
    }
    
    //call rdx
    call_reg = FindBinary(get_imagebase(), SEARCH_DOWN, "FF D2");
    while(call_reg != BADADDR) {
        process_call(call_reg);
        call_reg = FindBinary(call_reg + 1, SEARCH_DOWN, "FF D2");
    }
    
    //call rsi
    call_reg = FindBinary(get_imagebase(), SEARCH_DOWN, "FF D6");
    while(call_reg != BADADDR) {
        process_call(call_reg);
        call_reg = FindBinary(call_reg + 1, SEARCH_DOWN, "FF D6");
    }
    
    //call rdi
    call_reg = FindBinary(get_imagebase(), SEARCH_DOWN, "FF D7");
    while(call_reg != BADADDR) {
        process_call(call_reg);
        call_reg = FindBinary(call_reg + 1, SEARCH_DOWN, "FF D7");
    }
    
    //call rbp
    call_reg = FindBinary(get_imagebase(), SEARCH_DOWN, "FF D5");
    while(call_reg != BADADDR) {
        process_call(call_reg);
        call_reg = FindBinary(call_reg + 1, SEARCH_DOWN, "FF D5");
    }
    
    //call rsp
    call_reg = FindBinary(get_imagebase(), SEARCH_DOWN, "FF D4");
    while(call_reg != BADADDR) {
        process_call(call_reg);
        call_reg = FindBinary(call_reg + 1, SEARCH_DOWN, "FF D4");
    }
    
	//call r8-r15
    auto reg_val = 0xD0;
    auto iReg = 0;
    for(iReg = 0;iReg < 8;iReg++) {
        call_reg = FindBinary(get_imagebase(), SEARCH_DOWN, sprintf("41 FF %02X", reg_val + iReg));
        while(call_reg != BADADDR) {
            process_call(call_reg);
            call_reg = FindBinary(call_reg + 1, SEARCH_DOWN, sprintf("41 FF %02X", reg_val + iReg));
        }
    }
    
}
