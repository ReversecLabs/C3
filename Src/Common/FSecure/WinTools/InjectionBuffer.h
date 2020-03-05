#pragma once

namespace FSecure::WinTools
{
	/// Wrapper for self-injection
	class InjectionBuffer
	{
	public:
		/// Default constructor, does not allocate
		InjectionBuffer() = default;

		/// Constructor, copies the buffer and marks it as executable
		/// @param code - code to inject
		/// @throws std::runtime_error if VirtualAlloc fails
		InjectionBuffer(FSecure::ByteView code);

		/// Mark internal buffer as executable page
		void MarkAsExecutable() const;

		/// Get base address of buffer
		/// @returns base address of buffer
		void* Get() noexcept { return m_Buffer.get(); };

	private:
		/// size of allocated buffer.
		size_t m_Size = 0;

		/// pointer to allocated buffer.
		std::unique_ptr<void, std::function<void(void*)>> m_Buffer = nullptr;
	};
}

