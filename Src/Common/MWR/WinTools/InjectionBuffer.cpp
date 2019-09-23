#include "StdAfx.h"
#include "InjectionBuffer.h"

namespace MWR::WinTools
{
	InjectionBuffer::InjectionBuffer(MWR::ByteView code) : m_Size(code.size())
	{
		// Allocate memory as R/W
		auto codePointer = VirtualAlloc(0, m_Size, MEM_COMMIT, PAGE_READWRITE);
		if (!codePointer)
			throw std::runtime_error{ OBF("Couldn't allocate R/W virtual memory: ") + std::to_string(GetLastError()) + OBF(".") };

		m_Buffer = decltype(m_Buffer)(codePointer, [](void* buffer) { VirtualFree(buffer, 0, MEM_RELEASE); } );

		// copy the code into buffer
		memcpy_s(m_Buffer.get(), m_Size, code.data(), code.size());

		MarkAsExecutable();

		FlushInstructionCache(GetCurrentProcess(), m_Buffer.get(), m_Size);
	}

	void InjectionBuffer::MarkAsExecutable() const
	{
		// Mark the memory region R/X
		DWORD prev;
		if (!VirtualProtect(m_Buffer.get(), m_Size, PAGE_EXECUTE_READ, &prev))
			throw std::runtime_error(OBF("Couldn't mark virtual memory as R/X. ") + std::to_string(GetLastError()));
	}
}
