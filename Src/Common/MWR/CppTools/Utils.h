#pragma once

namespace MWR::Utils
{
	/// Check if application is 64bit.
	/// @return true for x64 process.
	bool IsProcess64bit();

	/// Changes value to default if it is out of provided range.
	/// @param value to be clamped.
	/// @param minValue lowest accepted value.
	/// @param maxValue highest accepted value
	/// @param defaultValue default value if out of range.
	/// @return bool indicating if value was reseted to defaultValue.
	template <typename T, typename T2>
	bool IsInRange(T& value, T2 minValue, T2 maxValue, T2 defaultValue)
	{
		if (value >= minValue && value <= maxValue)
			return false;

		value = defaultValue;
		return true;
	}

	/// Generate random string.
	/// @param size of returned string.
	std::string GenerateRandomString(size_t size);

	/// Generate random unsigned int value.
	/// @param rangeFrom minimal allowed value.
	/// @param rangeTo maximal allowed value.
	/// @return random value.
	template <typename T>
	T GenerateRandomValue(T rangeFrom = std::numeric_limits<T>::min(), T rangeTo = std::numeric_limits<T>::max())
	{
		// Based on https://stackoverflow.com/a/7560564.
		static std::random_device rd;																								//< Obtain a random number from hardware.
		static std::mt19937 eng(rd());																								//< Seed the generator.
		std::uniform_int_distribution<T> distr(rangeFrom, rangeTo);																	//< Define the range.

		return distr(eng);
	}

	/// Generate random std::chrono:duration value.
	/// @param rangeFrom minimal allowed value.
	/// @param rangeTo maximal allowed value.
	/// @return random value.
	template<typename T, typename P>
	std::chrono::duration<T, P> GenerateRandomValue(std::chrono::duration<T, P> rangeFrom, std::chrono::duration<T, P> rangeTo)
	{
		return std::chrono::duration<T, P>{ GenerateRandomValue(rangeFrom.count(), rangeTo.count()) };
	}

	/// Cast a integral value to a different integral type, checking if the cast can be performed
	/// @tparam T - type to cast to
	/// @tparam T2 - type to cast from
	/// @param in - the value to cast
	/// @returns a value in T type
	/// @throws std::out_of_range if the value cannot be represented in T type
	template <typename T, typename T2>
	std::enable_if_t<(std::is_integral_v<T>&& std::is_integral_v<T2>), T> SafeCast(T2 in)
	{
		if (in < std::numeric_limits<T>::min() && in > std::numeric_limits<T>::max())
			throw std::out_of_range{ OBF("Cast cannot be performed") };

		return static_cast<T>(in);
	}

	/// Impersonation of Y2038 problem
	int32_t TimeSinceEpoch();

	/// Alias for float based seconds
	using FloatSeconds = std::chrono::duration<float, std::chrono::seconds::period>;

	/// Alias for double based seconds
	using DoubleSeconds = std::chrono::duration<double, std::chrono::seconds::period>;

	/// Get millisecond representation
	/// @param seconds - number of seconds
	/// @returns number of milliseconds from floating seconds
	constexpr inline std::chrono::milliseconds ToMilliseconds(float seconds)
	{
		using namespace std::chrono;
		return ceil<milliseconds>(FloatSeconds{ seconds });
	}

	/// Namespace storing internal implementation of features.
	/// Symbols declared in this namespace should not be used directly
	namespace Details
	{
		/// Check out MWR::Utils::CanApply
		/// This basic template will be used as default if instantiation of function searching idiom failed.
		template<template<class...>class T, class, class...>
		struct CanApply : std::false_type {};

		/// Check out MWR::Utils::CanApply.
		/// This specialized template will be used if instantiation of function searching idiom succeeded.
		template<template<class...>class T, class...Ts>
		struct CanApply<T, std::void_t<T<Ts...>>, Ts...> : std::true_type {};
	}

	/// Template way to look for functions in classes using variadic argument list.
	/// CanApply::value will be true if method was found.
	/// @example
	/// Create alias that gives type of Foo call.
	///	template<class T, class...Ts>
	///	using FooReturnType = decltype(std::declval<T>().Foo(std::declval<Ts>()...));
	///
	/// Create alias to CanApply that will be used to test if some type has method Foo.
	///	template<class T, class...Ts>
	///	using HasFoo = MWR::Utils::CanApply<FooReturnType, T, Ts...>;
	///
	/// Test type Bar can it call foo with int, double arguments.
	/// HasFoo<Bar&, int, double>::value
	template<template<class...>class T, class...Ts>
	using CanApply = Details::CanApply<T, void, Ts...>;
}
