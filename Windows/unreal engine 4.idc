#include <idc/idc.idc>

extern extra_prints;
extern UObjectCompiledInDefer;
extern ConstructUClass;

static FindConstructUClass() {
	
}

static ResolveClassParams(ClassParams) {
	//Read class info
	auto ClassNoRegisterFunc = Qword(ClassParams + 0x00);
	auto ClassConfigNameUTF8 = GetString(Qword(ClassParams + 0x08), -1, 0);
	auto CppClassInfo = Qword(ClassParams + 0x10);
	auto DependencySingletonFuncArray = Qword(ClassParams + 0x18);
	auto FunctionLinkArray = Qword(ClassParams + 0x20);
	auto PropertyArray = Qword(ClassParams + 0x28);
	auto ImplementedInterfaceArray = Qword(ClassParams + 0x30);
	auto NumDependencySingletons = Dword(ClassParams + 0x38);
	auto NumFunctions = Dword(ClassParams + 0x3C);
	auto NumProperties = Dword(ClassParams + 0x40);
	auto NumImplementedInterfaces = Dword(ClassParams + 0x44);
	auto ClassFlags = Dword(ClassParams + 0x48);
	
	//Read jmp in static class function
	auto GetPrivateStaticClass = decode_insn(ClassNoRegisterFunc).Op0.addr;
	
	//Find class name from within the "GetPrivateStaticClass" function
	auto class_name = FindBinary(GetPrivateStaticClass, SEARCH_DOWN, "48 8D 15 ?? ?? ?? ?? 49 89 43 D8 48 8D 05 ?? ?? ?? ??");
	
	//Resolve "lea rdx, offset"
	class_name = decode_insn(class_name).Op1.addr;
	
	//realign by 2 bytes for wide string if exists
	if(Byte(class_name - 2) != 0) {
		class_name = class_name - 2;
	}
	
	class_name = GetString(class_name, -1, 1);
	
	//Print and Format all properties
	if(NumProperties != 0 && PropertyArray != 0) {
		auto i = 0;
		for(i = 0;i < NumProperties;i++) {
		    auto PropertyPtr = PropertyArray + (i * 8);
			auto Property = Qword(PropertyPtr);
			auto PropertyName = GetString(Qword(Property), -1, 0);
			auto PropertyOffset = Dword(Property + 0x24);
			Message("%s: 0x%08X\n", PropertyName, PropertyOffset);
			MakeQword(PropertyPtr); //Format Pointer To Property
			MakeQword(Property); //Format Pointer In Property To String
		}
	}
	
	if(extra_prints == 1) {
		Message("ClassParams: %s\n", class_name);
	
		//Print class info
		Message("ClassNoRegisterFunc: 0x%X\n", ClassNoRegisterFunc);
		Message("ClassConfigNameUTF8: %s\n", ClassConfigNameUTF8);
		Message("CppClassInfo: 0x%X\n", CppClassInfo);
		Message("DependencySingletonFuncArray: 0x%X\n", DependencySingletonFuncArray);
		Message("FunctionLinkArray: 0x%X\n", FunctionLinkArray);
		Message("PropertyArray: 0x%X\n", PropertyArray);
		Message("NumDependencySingletons: %i\n", NumDependencySingletons);
		Message("NumFunctions: %i\n", NumFunctions);
		Message("NumProperties: %i\n", NumProperties);
		Message("NumImplementedInterfaces: %i\n", NumImplementedInterfaces);
		Message("ClassFlags: %i\n", ClassFlags);
		Message("\n\n");
	}
}

static main() {
	
	extra_prints = 1;
	
	
	//find the very first function that contains UObjectCompiledInDefer
	UObjectCompiledInDefer = FindBinary(get_imagebase(), SEARCH_DOWN, "48 83 EC 48 33 C0 4C 8D 0D ?? ?? ?? ?? 48 89 44 24 ?? 4C 8D 05 ?? ?? ?? ?? 48 89 44 24 ?? 48 8D 15 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? 88 44 24 20 E8 ?? ?? ?? ?? 48 83 C4 48 C3");
	
	//Find the call for UObjectCompiledInDefer
	UObjectCompiledInDefer = FindBinary(UObjectCompiledInDefer, SEARCH_DOWN, "E8 ?? ?? ?? ?? 48 83 C4 48 C3");
	
	//Resolve the call address for UObjectCompiledInDefer
	UObjectCompiledInDefer = decode_insn(UObjectCompiledInDefer).Op0.addr;
	
	//Find the ConstructUClass function to get all classes
	ConstructUClass = FindBinary(get_imagebase(), SEARCH_DOWN, "40 55 56 41 56 48 8D AC 24 ?? ?? ?? ?? 48 81 EC ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 85 ?? ?? ?? ?? 48 8B 01 4C 8B F2 48 8B F1 48 85 C0 74 10 F7 80 ?? ?? ?? ?? ?? ?? ?? ??");
	
	
	
	Message("UObjectCompiledInDefer: 0x%X\n", UObjectCompiledInDefer);
	
    //0x000000014E66B8C0 - UWorld class data
	ResolveClassParams(0x000000014E4AA960);
	
}

