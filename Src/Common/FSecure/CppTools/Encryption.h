#pragma once

#include "ByteView.h"
#include "ByteVector.h"

//

namespace FSecure::Encryption
{
	/// @brief Encrypt/Decrypt data using R4.
	///
	/// @param data - Data to run RC4 on.
	/// @param key - Key used to encrypt data. Recommended size is 32 bytes. For long keys only first 256 bytes are used.
	///
	/// @returns ByteVector transformed data.
	ByteVector RC4(ByteView data, ByteView key);
}