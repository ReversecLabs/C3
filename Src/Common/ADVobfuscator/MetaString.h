//
//  MetaString.h
//  ADVobfuscator
//
// Copyright (c) 2010-2017, Sebastien Andrivet
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Get latest version on https://github.com/andrivet/ADVobfuscator

#ifndef MetaString_h
#define MetaString_h

#include "Inline.h"
#include "Indexes.h"
#include "MetaRandom.h"
#include "Common/FSecure/SecureString.hpp"

namespace andrivet::ADVobfuscator
{
	// Helper to generate a key
	template<typename T, int N>
	struct MetaRandomChar
	{
		// Use 0x7F as maximum value since most of the time, char is signed (we have however 1 bit less of randomness)
		static const char value = static_cast<T>(1 + MetaRandom<N, 0x7F - 1>::value);
	};

	// Represents an obfuscated string, parametrized with an algorithm number N, a list of indexes Indexes and a key Key
	template<int N, char Key, typename Indexes>
	struct MetaString;

	// Partial specialization with a list of indexes I, a key K and algorithm N = 0
	// Each character is encrypted (XOR) with the same key

	template<char K, int... I>
	struct MetaString<0, K, Indexes<I...>>
	{
		// Constructor. Evaluated at compile time.
		constexpr ALWAYS_INLINE MetaString(const char* str)
			: key_{ K }, buffer_{ encrypt(str[I], K)... } { }

		// Runtime decryption. Most of the time, inlined
		inline const char* decrypt()
		{
			for (size_t i = 0; i < sizeof...(I); ++i)
				buffer_[i] = decrypt(buffer_[i]);
			buffer_[sizeof...(I)] = 0;
			return const_cast<const char*>(buffer_);
		}

		~MetaString()
		{
			SecureZeroMemory((void*)buffer_, sizeof(buffer_));
		}

	private:
		// Encrypt / decrypt a character of the original string with the key
		constexpr char key() const { return key_; }
		constexpr char ALWAYS_INLINE encrypt(char c, int k) const { return c ^ k; }
		constexpr char decrypt(char c) const { return encrypt(c, key()); }

		volatile int key_; // key. "volatile" is important to avoid uncontrolled over-optimization by the compiler
		volatile char buffer_[sizeof...(I) + 1]; // Buffer to store the encrypted string + terminating null byte
	};

	// Partial specialization with a list of indexes I, a key K and algorithm N = 1
	// Each character is encrypted (XOR) with an incremented key.

	template<char K, int... I>
	struct MetaString<1, K, Indexes<I...>>
	{
		// Constructor. Evaluated at compile time.
		constexpr ALWAYS_INLINE MetaString(const char* str)
			: key_(K), buffer_{ encrypt(str[I], I)... } { }

		// Runtime decryption. Most of the time, inlined
		inline const char* decrypt()
		{
			for (size_t i = 0; i < sizeof...(I); ++i)
				buffer_[i] = decrypt(buffer_[i], i);
			buffer_[sizeof...(I)] = 0;
			return const_cast<const char*>(buffer_);
		}

		~MetaString()
		{
			SecureZeroMemory((void*)buffer_, sizeof(buffer_));
		}

	private:
		// Encrypt / decrypt a character of the original string with the key
		constexpr char key(size_t position) const { return static_cast<char>(key_ + position); }
		constexpr char ALWAYS_INLINE encrypt(char c, size_t position) const { return c ^ key(position); }
		constexpr char decrypt(char c, size_t position) const { return encrypt(c, position); }

		volatile int key_; // key. "volatile" is important to avoid uncontrolled over-optimization by the compiler
		volatile char buffer_[sizeof...(I) + 1]; // Buffer to store the encrypted string + terminating null byte
	};

	// Partial specialization with a list of indexes I, a key K and algorithm N = 2
	// Shift the value of each character and does not store the key. It is only used at compile-time.

	template<char K, int... I>
	struct MetaString<2, K, Indexes<I...>>
	{
		// Constructor. Evaluated at compile time. Key is *not* stored
		constexpr ALWAYS_INLINE MetaString(const char* str)
			: buffer_{ encrypt(str[I])..., 0 } { }

		// Runtime decryption. Most of the time, inlined
		inline const char* decrypt()
		{
			for (size_t i = 0; i < sizeof...(I); ++i)
				buffer_[i] = decrypt(buffer_[i]);
			return const_cast<const char*>(buffer_);
		}

		~MetaString()
		{
			SecureZeroMemory((void*)buffer_, sizeof(buffer_));
		}

	private:
		// Encrypt / decrypt a character of the original string with the key
		// Be sure that the encryption key is never 0.
		constexpr char key(char key) const { return 1 + (key % 13); }
		constexpr char ALWAYS_INLINE encrypt(char c) const { return c + key(K); }
		constexpr char decrypt(char c) const { return c - key(K); }

		// Buffer to store the encrypted string + terminating null byte. Key is not stored
		volatile char buffer_[sizeof...(I) + 1];
	};

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	//Wchar
	// Represents an obfuscated string, parametrized with an algorithm number N, a list of indexes Indexes and a key Key
	template<int N, wchar_t Key, typename Indexes>
	struct MetaWString;

	// Partial specialization with a list of indexes I, a key K and algorithm N = 0
	// Each wchar_tacter is encrypted (XOR) with the same key

	template<wchar_t K, int... I>
	struct MetaWString<0, K, Indexes<I...>>
	{
		// Constructor. Evaluated at compile time.
		constexpr ALWAYS_INLINE MetaWString(const wchar_t* str)
			: key_{ K }, buffer_{ encrypt(str[I], K)... } { }

		// Runtime decryption. Most of the time, inlined
		inline const wchar_t* decrypt()
		{
			for (size_t i = 0; i < sizeof...(I); ++i)
				buffer_[i] = decrypt(buffer_[i]);
			buffer_[sizeof...(I)] = 0;
			return const_cast<const wchar_t*>(buffer_);
		}

		~MetaWString()
		{
			SecureZeroMemory((void*)buffer_, sizeof(buffer_));
		}

	private:
		// Encrypt / decrypt a wchar_tacter of the original string with the key
		constexpr wchar_t key() const { return key_; }
		constexpr wchar_t ALWAYS_INLINE encrypt(wchar_t c, int k) const { return c ^ k; }
		constexpr wchar_t decrypt(wchar_t c) const { return encrypt(c, key()); }

		volatile int key_; // key. "volatile" is important to avoid uncontrolled over-optimization by the compiler
		volatile wchar_t buffer_[sizeof...(I) + 1]; // Buffer to store the encrypted string + terminating null byte
	};

	// Partial specialization with a list of indexes I, a key K and algorithm N = 1
	// Each wchar_tacter is encrypted (XOR) with an incremented key.

	template<wchar_t K, int... I>
	struct MetaWString<1, K, Indexes<I...>>
	{
		// Constructor. Evaluated at compile time.
		constexpr ALWAYS_INLINE MetaWString(const wchar_t* str)
			: key_(K), buffer_{ encrypt(str[I], I)... } { }

		// Runtime decryption. Most of the time, inlined
		inline const wchar_t* decrypt()
		{
			for (size_t i = 0; i < sizeof...(I); ++i)
				buffer_[i] = decrypt(buffer_[i], i);
			buffer_[sizeof...(I)] = 0;
			return const_cast<const wchar_t*>(buffer_);
		}

		~MetaWString()
		{
			SecureZeroMemory((void*)buffer_, sizeof(buffer_));
		}

	private:
		// Encrypt / decrypt a wchar_tacter of the original string with the key
		constexpr wchar_t key(size_t position) const { return static_cast<wchar_t>(key_ + position); }
		constexpr wchar_t ALWAYS_INLINE encrypt(wchar_t c, size_t position) const { return c ^ key(position); }
		constexpr wchar_t decrypt(wchar_t c, size_t position) const { return encrypt(c, position); }

		volatile int key_; // key. "volatile" is important to avoid uncontrolled over-optimization by the compiler
		volatile wchar_t buffer_[sizeof...(I) + 1]; // Buffer to store the encrypted string + terminating null byte
	};

	// Partial specialization with a list of indexes I, a key K and algorithm N = 2
	// Shift the value of each wchar_tacter and does not store the key. It is only used at compile-time.

	template<wchar_t K, int... I>
	struct MetaWString<2, K, Indexes<I...>>
	{
		// Constructor. Evaluated at compile time. Key is *not* stored
		constexpr ALWAYS_INLINE MetaWString(const wchar_t* str)
			: buffer_{ encrypt(str[I])..., 0 } { }

		// Runtime decryption. Most of the time, inlined
		inline const wchar_t* decrypt()
		{
			for (size_t i = 0; i < sizeof...(I); ++i)
				buffer_[i] = decrypt(buffer_[i]);
			return const_cast<const wchar_t*>(buffer_);
		}

		~MetaWString()
		{
			SecureZeroMemory((void*)buffer_, sizeof(buffer_));
		}

	private:
		// Encrypt / decrypt a wchar_tacter of the original string with the key
		// Be sure that the encryption key is never 0.
		constexpr wchar_t key(wchar_t key) const { return 1 + (key % 13); }
		constexpr wchar_t ALWAYS_INLINE encrypt(wchar_t c) const { return c + key(K); }
		constexpr wchar_t decrypt(wchar_t c) const { return c - key(K); }

		// Buffer to store the encrypted string + terminating null byte. Key is not stored
		volatile wchar_t buffer_[sizeof...(I) + 1];
	};
}

// Prefix notation
#define DEF_OBFUSCATED(str) andrivet::ADVobfuscator::MetaString<andrivet::ADVobfuscator::MetaRandom<__COUNTER__, 3>::value, andrivet::ADVobfuscator::MetaRandomChar<char, __COUNTER__>::value, andrivet::ADVobfuscator::Make_Indexes<sizeof(str) - 1>::type>(str)
#define DEF_OBFUSCATED_W(str) andrivet::ADVobfuscator::MetaWString<andrivet::ADVobfuscator::MetaRandom<__COUNTER__, 3>::value, andrivet::ADVobfuscator::MetaRandomChar<wchar_t, __COUNTER__>::value, andrivet::ADVobfuscator::Make_Indexes<sizeof(str)/(sizeof(wchar_t)) - 1>::type>(str)

#define OBF(str) (DEF_OBFUSCATED(str).decrypt())
#define OBF_W(str) (DEF_OBFUSCATED_W(str).decrypt())

#define OBF_STR(str) (std::string{DEF_OBFUSCATED(str).decrypt()})
#define OBF_WSTR(str) (std::wstring{DEF_OBFUSCATED_W(str).decrypt()})

#define OBF_SEC(str) (FSecure::SecureString{DEF_OBFUSCATED(str).decrypt()})
#define OBF_WSEC(str) (FSecure::SecureWString{DEF_OBFUSCATED_W(str).decrypt()})

#endif
