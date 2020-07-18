#pragma once

#include <string_view>
#include <type_traits>
#include <utility>
#include <functional>
#include <array>
#include <vector>
#include <tuple>

#ifndef OBF
#	define OBF(x) x
#endif // !OBF

namespace FSecure::Utils
{
	/// Prevents compiler from optimizing out call.
	/// @param ptr pointer to memory to be cleared.
	/// @param n number of bytes to overwrite.
	inline void* SecureMemzero(void* ptr, size_t n)
	{
		if (ptr) for (auto p = reinterpret_cast<volatile char*>(ptr); n--; *p++ = 0);
		return ptr;
	}

	/// Template to evaluate if T is one of Ts types.
	template <typename T, typename ...Ts>
	struct IsOneOf
	{
		constexpr static bool value = [](bool ret) { return ret; }((std::is_same_v<T, Ts> || ...));
	};

	/// Template to evaluate all of Ts are equal to T.
	template <typename T, typename ...Ts>
	struct IsSame
	{
		constexpr static bool value = [](bool ret) { return ret; }((std::is_same_v<T, Ts> && ...));
	};

	/// Template to strip type out of const, volatile and reference.
	template <typename T>
	using RemoveCVR = std::remove_cv_t<std::remove_reference_t<T>>;

	/// Idioms for detecting tuple types.
	template <typename T>
	constexpr bool IsTuple = false;
	template<typename ...T>
	constexpr bool IsTuple<std::tuple<T...>> = true;
	template<typename ...T>
	constexpr bool IsTuple<std::pair<T...>> = true;
	template<typename T>
	constexpr bool IsPair = false;
	template<typename ...T>
	constexpr bool IsPair<std::pair<T...>> = true;


	/// Check if type is designed to view data owned by other container.
	template <typename T, typename = void>
	struct IsView
	{
		constexpr static bool value = false;
	};

	/// Every basic_string_view is a view.
	template <typename T>
	struct IsView<std::basic_string_view<T>, void>
	{
		constexpr static bool value = true;
	};

	/// Namespace full of helpers for containers template programing.
	namespace Container
	{
		/// Get type stored by container that uses iterators.
		template <typename T>
		using StoredValue = RemoveCVR<decltype(*begin(std::declval<T>()))>;

		/// Check if type can be iterated with begin() and end().
		template <typename T>
		class IsIterable
		{
			template <typename C> static uint8_t test(std::void_t<decltype(begin(std::declval<C>()), end(std::declval<C>()))>*);
			template <typename C> static uint16_t test(...);

		public:
			static constexpr bool value = (sizeof(test<T>(0)) == sizeof(uint8_t));
		};

		/// Check if type have own implementation of size method.
		template <typename T>
		class Size
		{
			template <typename C> static uint8_t test(std::void_t<decltype(size(std::declval<C>()))>*);
			template <typename C> static uint16_t test(...);

		public:
			static constexpr bool HasDedicatedImplementation = (sizeof(test<T>(0)) == sizeof(uint8_t));
			static size_t Calculate(std::enable_if_t<HasDedicatedImplementation || IsIterable<T>::value, T> const& obj)
			{
				size_t count = 0;
				if constexpr (HasDedicatedImplementation) count = size(obj);
				else for (auto it = obj.begin(); it != obj.end(); ++it, ++count);

				return count;
			}
		};

		/// Check if type have insert(iterator, value) function.
		template <typename T>
		class HasInsert
		{
			template <typename C> static uint8_t test(std::void_t<decltype(std::declval<C>().insert(begin(std::declval<C>()), *end(std::declval<C>())))>*);
			template <typename C> static uint16_t test(...);

		public:
			static constexpr bool value = (sizeof(test<T>(0)) == sizeof(uint8_t));
		};

		/// Check if type can reserve some space to avoid reallocations.
		template <typename T>
		class HasReserve
		{
			template <typename C> static uint8_t test(std::void_t<decltype(std::declval<C>().reserve(size_t{}))>*);
			template <typename C> static uint16_t test(...);

		public:
			static constexpr bool value = (sizeof(test<T>(0)) == sizeof(uint8_t));
		};

		/// Struct to generalize container construction.
		/// Defines one of allowed operators that will return requested container.
		/// @tparam T. Type to be constructed.
		/// @tparam unnamed typename with default value, to allow easy creation of partial specializations.
		template <typename T, typename = void>
		struct Generator
		{
			/// Form with queued access to each of container values.
			/// @param size. Defines numbers of elements in constructed container.
			/// @param next. Functor returning one of container values at a time.
			// T operator()(uint32_t size, std::function<StoredValue<T>()> next);

			/// Form with direct access to memory.
			/// @param size. Defines numbers of elements in constructed container.
			/// @param data. Allows access to data used to container generation.
			/// Dereferenced pointer should be changed, to represent number of bytes consumed for container generation.
			// T operator()(uint32_t size, const char** data)
		};

		/// Generator for any container that have insert method.
		template <typename T>
		struct Generator<T, std::enable_if_t<HasInsert<T>::value>>
		{
			/// Form with queued access to each of container values.
			/// @param size. Defines numbers of elements in constructed container.
			/// @param next. Functor returning one of container values at a time.
			T operator()(uint32_t size, std::function<StoredValue<T>()> next)
			{
				T ret;
				if constexpr (HasReserve<T>::value)
				{
					ret.reserve(size);
				}

				for (auto i = 0u; i < size; ++i)
					ret.insert(ret.end(), next());

				return ret;
			}
		};

		/// Generator for any container that is simmilar to std::basic_string_view.
		template <typename T>
		struct Generator<T, std::enable_if_t<IsView<T>::value>>
		{
			/// Form with direct access to memory.
			/// @param size. Defines numbers of elements in constructed container.
			/// @param data. Allows access to data used to container generation.
			/// Dereferenced pointer should be changed, to represent number of bytes consumed for container generation.
			T operator()(uint32_t size, const char** data)
			{
				auto ptr = reinterpret_cast<const T::value_type*>(*data);
				*data += size * sizeof(typename T::value_type);
				return { ptr, size };
			}
		};

		/// Generator for any array types.
		template <typename T, size_t N>
		struct Generator<std::array<T, N>>
		{
			/// Form with queued access to each of container values.
			/// @param size. Defines numbers of elements in constructed container.
			/// @param next. Functor returning one of container values at a time.
			std::array<T, N> operator()(uint32_t size, std::function<T()> next)
			{
				if (size != N)
					throw std::runtime_error{ OBF("Array size does not match declaration") };

				std::vector<T> temp;
				temp.reserve(N);
				for (auto i = 0u; i < N; ++i)
					temp.push_back(next());

				return MakeArray(std::move(temp), std::make_index_sequence<N>());
			}

		private:
			/// Create array with size N from provided vector.
			/// This helper function is required because T might not be default constructible, but array must be filled like aggregator.
			/// Reading data to vector first will ensure order of elements, independent of calling convention.
			/// @param obj. Temporary vector with data.
			/// @returns std::array with all elements.
			template<size_t... Is>
			std::array<T, N> MakeArray(std::vector<T>&& obj, std::index_sequence<Is...>)
			{
				return { std::move(obj[Is])... };
			}
		};

		/// Used to detect form of Generator operator() at compile time.
		template <typename T>
		class GeneratorSignature
		{
			template <typename C> static uint32_t  test(std::void_t<decltype(Generator<C>{}(std::declval<uint32_t>(), std::declval<std::function<StoredValue<C>()>>()))>*);
			template <typename C> static uint16_t  test(std::void_t<decltype(Generator<C>{}(std::declval<uint32_t>(), std::declval<const char**>()))>*);
			template <typename C> static uint8_t test(...);

		public:
			enum { other = 0, directMemoryAccess = (sizeof(uint16_t) - sizeof(uint8_t)), queuedAccess = (sizeof(uint32_t) - sizeof(uint8_t)) };
			enum { value = (sizeof(test<T>(0)) - sizeof(uint8_t)) };
		};
	}

	/// Namespace for internal implementation
	namespace Detail
	{
		/// @brief Default implementation of class checking if it is worth to take reference or copy by value
		/// Represents false.
		template<typename T, typename Enable>
		struct WorthAddingConstRefImpl : std::false_type
		{};

		/// @brief Specialization of class checking if it is worth to take reference or copy by value.
		/// Represents true.
		template<typename T>
		struct WorthAddingConstRefImpl<T,
			std::enable_if_t<
				!std::is_rvalue_reference_v<T> && (!std::is_trivial_v<std::remove_reference_t<T>> || (sizeof(T) > sizeof(long long)))
				>
		> : std::true_type{};

		/// @brief Default implementation of class declaring simpler type to use based on T type.
		/// Represents copy by value.
		template<typename T, typename Enable>
		struct AddConstRefToNonTrivialImpl
		{
			using type = std::remove_reference_t<T>;
		};

		/// @brief Specialization of class declaring simpler type to use based on T type.
		/// Represents copy by reference.
		template<typename T>
		struct  AddConstRefToNonTrivialImpl<T, std::enable_if_t<WorthAddingConstRefImpl<T, void>::value>>
		{
			using type = std::remove_reference_t<T> const&;
		};
	}

	/// @brief Class checking if it is worth to take reference or copy by value.
	template<typename T>
	struct WorthAddingConstRef : Detail::WorthAddingConstRefImpl<T, void> {};

	/// @brief Simplified WorthAddingConstRef<T>::value.
	template<typename T>
	static constexpr auto WorthAddingConstRefV = WorthAddingConstRef<T>::value;

	/// @brief Class declaring simpler type to use based on T type.
	template<typename T>
	struct  AddConstRefToNonTrivial : Detail::AddConstRefToNonTrivialImpl<T, void> {};

	/// @brief Simplified AddConstRefToNonTrivial<T>::type.
	template<typename T>
	using AddConstRefToNonTrivialT = typename AddConstRefToNonTrivial<T>::type;

	/// @brief Helper allowing transformation of provided arguments to tuple of values/references that are used for serialization.
	/// @param ...args arguments to be stored in tuple
	/// @return tuple with references to non trivial types, and values of simple ones.
	template<typename ...Args>
	auto MakeConversionTuple(Args&& ...args)
	{
		return std::tuple<AddConstRefToNonTrivialT<Args&&>...>(std::forward<Args>(args)...);
	}

	/// Construction with parentheses and with braces is not interchangeable.
	/// std::make_from_tuple must use constructor and is unable to create trivial type.
	/// Types implemented in this namespace, alongside with std::apply, allows us choose method used for construction.
	/// For more information look at:
	/// https://groups.google.com/a/isocpp.org/forum/#!topic/std-discussion/aQQzL0JoXLg
	namespace Construction
	{
		/// @brief Type used for construction with braces.
		template <typename T>
		struct Braces
		{
			template <typename ... As>
			constexpr auto operator () (As&& ... as) const
			{
				return T{ std::forward<As>(as)... };
			}
		};

		/// @brief Type used for construction with parentheses.
		template <typename T>
		struct Parentheses
		{
			template <typename ... As>
			constexpr auto operator () (As&& ... as) const
			{
				return T(std::forward<As>(as)...);
			}
		};
	}

	/// @brief Constexpr helper to perform logic on tuple types. Evaluation result is assigned to value member.
	/// @tparam T Class with function to be applied. Must define template<typename...> constexpr auto Apply(). Tuple types will be passed by parameter pack.
	/// @tparam Tpl Tuple with types on which logic will be applied.
	template <typename T, typename Tpl>
	struct Apply
	{
	private:
		template <size_t ...Is>
		constexpr static auto ApplyImpl(std::index_sequence<Is...>)
		{
			return T::template Apply<std::tuple_element_t<Is, Tpl>...>();
		}
	public:
		constexpr static auto value = ApplyImpl(std::make_index_sequence<std::tuple_size<Tpl>::value>{});
	};
}
