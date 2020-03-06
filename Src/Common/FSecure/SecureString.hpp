#pragma once

// For SecureZeroMemory
#ifndef NOMINMAX
#	define NOMINMAX																										//< Exclude min and max macros from windows.h.
#endif
#define WIN32_LEAN_AND_MEAN																								//< Exclude rarely-used stuff from Windows headers.
#include <windows.h>

#include <string>

// based on https://codereview.stackexchange.com/questions/107991/hacking-a-securestring-based-on-stdbasic-string-for-c

namespace FSecure
{
	/// Minimal allocator zeroing on deallocation
	/// @tparam T type to allocate
	template <typename T>
	struct SecureAllocator
	{
		using value_type = T;
		using propagate_on_container_move_assignment = typename std::allocator_traits<std::allocator<T>>::propagate_on_container_move_assignment;

		/// Default constructor
		constexpr SecureAllocator() = default;

		/// Defaulted copy constructor
		/// @param other SecureAllocator
		constexpr SecureAllocator(const SecureAllocator&) = default;

		/// Other type constructor
		/// @tparam U - different type
		/// @param other SecureAllocator
		template <class U>
		constexpr SecureAllocator(const SecureAllocator<U>&) noexcept
		{
		}

		/// Allocate memory for n T objects
		/// @param n - count of T objects to allocate
		/// @returns pointer to allocated memory
		static T* allocate(std::size_t n)
		{
			return std::allocator<T>{}.allocate(n);
		}

		/// Clear and deallocate memory for n T objects
		/// @param p - memory pointer
		/// @param n - count of T objects to deallocate
		static void deallocate(T* p, std::size_t n) noexcept
		{
			SecureZeroMemory(p, n * sizeof * p);
			std::allocator<T>{}.deallocate(p, n);
		}
	};

	/// Equality operator
	/// @returns true
	template <typename T, typename U>
	constexpr bool operator== (const SecureAllocator<T>&, const SecureAllocator<U>&) noexcept
	{
		return true;
	}

	/// Inequality operator
	/// @returns false
	template <typename T, typename U>
	constexpr bool operator!= (const SecureAllocator<T>&, const SecureAllocator<U>&) noexcept
	{
		return false;
	}

	template<typename CharT>
	using BasicSecureString = std::basic_string<CharT, std::char_traits<CharT>, SecureAllocator<CharT>>;

	/// alias for string with SecureAllocator
	using SecureString = BasicSecureString<char>;

	/// alias for wstring with SecureAllocator
	using SecureWString = BasicSecureString<wchar_t>;
}

namespace std
{
	/// Specialized SecureString destructor.
	/// Overwrites internal buffer (if SSO is in effect)
	template<>
	inline basic_string<char, std::char_traits<char>, FSecure::SecureAllocator<char>>::~basic_string() noexcept
	{
		// Clear internal buffer if SSO is in effect
#if _MSC_VER >= 1920 // v142 toolset
		auto& _My_data = _Mypair._Myval2;
#elif _MSC_VER >= 1910 // v141 toolset
		auto& _My_data = this->_Get_data();
#elif
#error Unsupported toolset
#endif
		if (!_My_data._Large_string_engaged())
			SecureZeroMemory(_My_data._Bx._Buf, sizeof _My_data._Bx._Buf);

		// This is a copy of basic_string dtor
		_Tidy_deallocate();
	}

	/// Specialized SecureWString destructor.
	/// Overwrites internal buffer (if SSO is in effect)
	template<>
	inline basic_string<wchar_t, std::char_traits<wchar_t>, FSecure::SecureAllocator<wchar_t>>::~basic_string() noexcept
	{
		// Clear internal buffer if SSO is in effect
#if _MSC_VER >= 1920 // v142 toolset
		auto& _My_data = _Mypair._Myval2;
#elif _MSC_VER >= 1910 // v141 toolset
		auto& _My_data = this->_Get_data();
#elif
#error Unsupported toolset
#endif
		if (!_My_data._Large_string_engaged())
			SecureZeroMemory(_My_data._Bx._Buf, sizeof _My_data._Bx._Buf);

		// This is a copy of basic_string dtor
		_Tidy_deallocate();
	}
}
