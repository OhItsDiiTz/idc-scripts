#include <idc/idc.idc>


static main(void) {
    auto count = 0;
	auto ea = FindBinary(0, SEARCH_DOWN, "4C 8B D1 B8 ? ? ? ? F6 04 25 ? ? ? ? ? 75 03 0F 05 C3 CD 2E C3");
	while(ea != -1) {
		add_func(ea);
		AddBpt(ea);
		if(GetFunctionName(ea) == "ntdll_NtSetInformationThread") {
			SetBptCnd(ea, "auto file = fopen(\"syscall trace.txt\", \"a\");writestr(file, sprintf(\"%s - 0x%X\\n\", GetFunctionName(rip), Qword(rsp)));fclose(file);Message(\"%s - 0x%X\\n\", GetFunctionName(rip), Qword(rsp));");
		}
		else {
			SetBptCnd(ea, "auto file = fopen(\"syscall trace.txt\", \"a\");writestr(file, sprintf(\"%s - 0x%X\\n\", GetFunctionName(rip), Qword(rsp)));fclose(file);Message(\"%s - 0x%X\\n\", GetFunctionName(rip), Qword(rsp));ResumeProcess();");
		}
		
		ea = FindBinary(ea + 1, SEARCH_DOWN, "4C 8B D1 B8 ? ? ? ? F6 04 25 ? ? ? ? ? 75 03 0F 05 C3 CD 2E C3");
		count++;
	}
	Message("%i functions breakpointed\n", count);
}
