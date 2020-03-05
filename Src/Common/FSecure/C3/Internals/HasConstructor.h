#pragma once

#include <type_traits>

// Probably going to be removed
namespace FSecure
{
	/// Check if constructor exist. Signature of constructor is also checked.
	/// Ambiguous constructor will return false.
	template <typename T, size_t N>
	class HasConstructor
	{
		static constexpr bool init()
		{
			static_assert(false, "Constructor should support 1 - 3 arguments. All other options are forbidden.");
			return false;
		}
	public:
		static const bool value = init();
	};

	template <typename T>
	class HasConstructor<T, 3>
	{
		struct Any { template<size_t N> operator ByteArray<N>(void); };

		template <typename T3>
		static uint16_t Detect(decltype(T3(std::declval<ByteView>(), Any{}, Any{}))*);

		template <typename T3>
		static uint8_t Detect(...);
	public:
		static const bool value = sizeof(Detect<T>(nullptr)) == sizeof(uint16_t);
	};

	template <typename T>
	class HasConstructor<T, 2>
	{
		struct Any { template<size_t N> operator ByteArray<N>(void); };

		template <typename T3>
		static uint16_t Detect(decltype(T3(std::declval<ByteView>(), Any{}))*);

		template <typename T3>
		static uint8_t Detect(...);
	public:
		static const bool value = sizeof(Detect<T>(nullptr)) == sizeof(uint16_t);
	};

	template <typename T>
	class HasConstructor<T, 1>
	{
		template <typename T3>
		static uint16_t Detect(decltype(T3(std::declval<ByteView>()))*);

		template <typename T3>
		static uint8_t Detect(...);
	public:
		static const bool value = sizeof(Detect<T>(nullptr)) == sizeof(uint16_t);
	};

	template <typename T>
	class HasConstructor<T, 0>
	{
		template <typename T3>
		static uint16_t Detect(decltype(T3())*);

		template <typename T3>
		static uint8_t Detect(...);
	public:
		static const bool value = sizeof(Detect<T>(nullptr)) == sizeof(uint16_t);
	};
}
