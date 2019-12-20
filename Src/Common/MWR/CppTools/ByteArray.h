#pragma once

namespace MWR
{
	/// Owning container with size known at compilation time.
	template <size_t N>
	using ByteArray = std::array<uint8_t, N>;

	/// Idiom for detecting tuple ByteArray.
	template <typename T>
	constexpr bool IsByteArray = false;
	template<size_t N>
	constexpr bool IsByteArray<ByteArray<N>> = true;
}