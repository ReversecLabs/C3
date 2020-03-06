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
#include "MetaRandom.h"
#include "Common/MWR/SecureString.hpp"

namespace andrivet::ADVobfuscator
{
	namespace detail
	{
		// Helper to generate a key
		template<typename T, size_t N>
		struct MetaRandomKeyImpl
		{
			static const T value = static_cast<T>(1 + MetaRandom<N, T, std::numeric_limits<T>::max() - 1>);
		};
	}

	template<typename T, int N>
	inline static constexpr std::make_unsigned_t<T> MetaRandomKey = detail::MetaRandomKeyImpl<std::make_unsigned_t<T>, N>::value;

	template<typename CharT, typename Encryptor, typename Indexes>
	struct ObfString;

	template<typename CharT, typename Encryptor, size_t ...I>
	struct ObfString<CharT, Encryptor, std::index_sequence<I...>>
	{
		constexpr ALWAYS_INLINE ObfString(const CharT* str) noexcept
			: m_Encryptor{}, m_Buffer{ m_Encryptor.Encrypt<I>(str[I])... } { }

		~ObfString() noexcept
		{
			SecureZeroMemory((void*)m_Buffer, sizeof(m_Buffer));
		}

		constexpr const CharT* decrypt() noexcept
		{
			m_Encryptor.Decrypt(m_Buffer, sizeof...(I));
			m_Buffer[sizeof...(I)] = 0;
			return m_Buffer;
		}

	private:
		Encryptor m_Encryptor;
		CharT m_Buffer[sizeof...(I) + 1]; // Buffer to store the encrypted string
	};

	template<typename CharT, std::make_unsigned_t<CharT> Seed, std::make_unsigned_t<CharT> Multiplier>
	struct XorEncryptor
	{
		template<size_t Index>
		constexpr ALWAYS_INLINE CharT Encrypt(CharT a) const noexcept { return Encrypt(a, Index); }

		constexpr void Decrypt(CharT* buf, size_t size) const noexcept
		{
			for (size_t i = 0; i < size; ++i, ++buf)
				*buf = Encrypt(*buf, i);
		}

	private:
		constexpr static ALWAYS_INLINE CharT Encrypt(CharT c, size_t index) noexcept
		{
			return c ^ (Seed + static_cast<std::make_unsigned_t<CharT>>(index * Multiplier));
		}
	};

	template<typename CharT, std::make_unsigned_t<CharT> Seed, std::make_unsigned_t<CharT> Multiplier, typename Indexes>
	using XorStringT = ObfString<CharT, XorEncryptor<CharT, Seed, Multiplier>, Indexes>;

	template<std::make_unsigned_t<char> Seed, std::make_unsigned_t<char> Multiplier, typename Indexes>
	using XorString = XorStringT<char, Seed, Multiplier, Indexes>;

	template<std::make_unsigned_t<wchar_t> Seed, std::make_unsigned_t<wchar_t> Multiplier, typename Indexes>
	using XorWString = XorStringT<wchar_t, Seed, Multiplier, Indexes>;

	template <typename T>
	using PeelT = std::remove_const_t<std::remove_all_extents_t<std::remove_reference_t<T>>>;
}

namespace Obfuscator = andrivet::ADVobfuscator;

// Prefix notation
#define DEF_OBFUSCATED(str) Obfuscator::XorStringT<Obfuscator::PeelT<decltype(str)>, Obfuscator::MetaRandomKey<Obfuscator::PeelT<decltype(str)>, __COUNTER__>, Obfuscator::MetaRandomKey<Obfuscator::PeelT<decltype(str)>, __COUNTER__>, std::make_index_sequence<sizeof(str)/(sizeof(Obfuscator::PeelT<decltype(str)>)) - 1>>{ str }
#define OBF(str) (DEF_OBFUSCATED(str).decrypt())
#define OBF_STR(str) (std::basic_string<Obfuscator::PeelT<decltype(str)>>{ OBF(str) })
#define OBF_SEC(str) (MWR::BasicSecureString<Obfuscator::PeelT<decltype(str)>>{ OBF(str) })

#endif
