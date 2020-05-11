#pragma once
#include <string_view>

#include "Common/FSecure/SecureString.hpp"
#include "Common/FSecure/CppTools/ByteConverter/ByteView.h"
#include "Common/FSecure/Crypto/Crypto.hpp"

namespace FSecure::Crypto
{
	class String
	{
	public:
		String() = default;
		String(std::string_view sv);
		String& operator=(std::string_view sv);
		SecureString Decrypt();


	private:
		SymmetricKey m_Key; // This is poor man implementation, key should be kept in key storage.
		ByteVector m_Data;
	};
}