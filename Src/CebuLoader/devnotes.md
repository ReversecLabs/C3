# Motivation

## Thread local storage
Thread safe static variable initialization is often used to implement singleton pattern. (C3 uses it to automate registration of Interfaces).
```
MWR::C3::InterfaceFactory& MWR::C3::InterfaceFactory::Instance()
{
	static auto instance = InterfaceFactory{};
	return instance;
}
```
In theory this doesn't seem like it would be using thread local storage, but in practice (for optimization) most compilers will generate code that uses TLS to store a flag once the variable has been initialized, in order to avoid unnecesary locking.

TL;DR: The PE's TLS Directory specifies the data that must be initialized for new threads.

## Exceptions
I don't think usage of exceptions in c++ codebase has to be justified.

Microsoft's Structured Exception Handling in depth: http://bytepointer.com/resources/pietrek_crash_course_depths_of_win32_seh.htm

C++ excetions are implemented in terms of SEH.

TL;DR: PE files specifies a table that contains data where to contiunue execution when exception is raised.

# Implementation

Our solution is to put a PE loader into donut's PE loader.

Limitations for the new loader:
- don't use TLS (inlcudes `__declspec(thread)`, Thread safe statics, `std::call_once` etc.) -> boils down to checking the CebuLoader's TLS directory size == 0
- don't use exceptions -> however CebuLoader.exe's exception directoy size != 0 (Probably beacause of statically linked CRT)
- don't rely on self image headers as those will be wiped by donut loader (eg. don't use  `kernel32!FindResource*`, read `pImageNtHeaders->OptionalHeader.SizeOfImage`)

## CebuLoader

Xenos injector (underlying Blackbone library) implements both static TLS data and EH.

TLS:
 - call private function `ntdll!LdrpHandleTlsData`

EH:
 - x64: call `ntdll!RtlAddFunctionTable` + add VEH that sets c++ exception base address and changes its magic number
 - x86: call private `ntdll!RtlInsertInvertedFunctionTable`. There's no need for installig VEH as in Xenos (beceause C3 compiles with `/SAFESEH`)

Using private functions from ntdll:
 - find a function pointer with pattern matching + offsets (credit to Blackbone for signatures and offsets)
 - select a calling convention and function signature at runtime acording to windows version

Embedding target dll in CebuLoader
 - use Tools/ResourceGenerator
 - embedded resource has format [16 byte guid][1 byte terminator 0xff][4 byte size][body][4 byte size][ExportName (null terminated)] (the guid if 0xff terminated to avoid finding the guid c-string when searching the module memory)

Limitations:
 - EH works only if both the embedded dll is statically linked with CRT. // TODO check if CebuLoader also has to be linked statically (currently it is)