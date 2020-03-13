#pragma once

#include "ByteConverter/ByteView.h"

namespace FSecure::Compression
{
	namespace Algorithm
	{
		struct Deflate {};
	};

	using namespace Algorithm;

	template <typename T>
	ByteVector Compress(ByteView data) = delete;

	template <typename T>
	ByteVector Decompress(ByteView data) = delete;

	template <>
	ByteVector Compress<Deflate>(ByteView data);

	template <>
	ByteVector Decompress<Deflate>(ByteView data);
}
