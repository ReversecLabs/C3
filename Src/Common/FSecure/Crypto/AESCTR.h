#pragma once

namespace FSecure::Crypto
{
	FSecure::ByteVector AES_CTR_Process(FSecure::ByteView key, FSecure::ByteView iv, FSecure::ByteView input);
}
