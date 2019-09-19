#pragma once

#include "ByteArray.h"

namespace MWR
{
	/// Forward declaration
	class ByteView;
	class ByteVector;

	/// Empty template of class that can convert data from and to byte form.
	/// @tparam T. Custom type that will work with byte containers using this converter type.
	/// Specialize this class to add methods:
	/// static ByteVector To(T const&);
	/// Used to write data.
	/// static T From(ByteView&);
	/// Used to retrieve data.
	/// Function must move ByteView& argument to position after the data that was retrieved.
	/// static size_t Size(T const&);
	/// Used to calculate size that type will need to be stored in ByteVector.
	/// This function is not mandatory. If not provided function `To` will be called twice.
	/// Once to calculate size for ByteVector allocation, and a second time to copy data.
	template <typename T>
	struct ByteConverter {};

	/// Example code of specializing ByteConverter for custom type A.
	//struct A
	//{
	//	uint16_t m_a, m_b;

	//	A(uint16_t a, uint16_t b) : m_a(a), m_b(b) {}
	//};

	//namespace MWR
	//{
	//	template <>
	//	struct ByteConverter<A>
	//	{
	//		static ByteVector To(A const& a)
	//		{
	//			return ByteVector::Create(a.m_a, a.m_b);
	//		}

	//		static size_t Size(A const& a)
	//		{
	//			return 2 * sizeof(uint16_t);
	//		}

	//		static A From(ByteView& bv)
	//		{
	//			auto [a, b] = bv.Read<uint16_t, uint16_t>();
	//			return A(a, b);
	//		}
	//	};
	//}

	/// Idiom for detecting tuple types.
	template <typename T>
	constexpr bool IsTuple = false;
	template<typename ...T>
	constexpr bool IsTuple<std::tuple<T...>> = true;

	/// Alias finding Store method return type.
	/// Should be used with MWR::Utils::CanApply, and not directly.
	template<class T, class...Ts>
	using StoreReturnType = decltype(std::declval<T>().Store(std::declval<bool>(), std::declval<Ts>()...));

	/// Alias for testing if type can be stored in ByteVector.
	/// Expresion CanStoreType<int, double, std::string>::value will be true.
	/// Expresion CanStoreType<SomeCustomType>::value will be false.
	template<class...Ts>
	using CanStoreType = MWR::Utils::CanApply<StoreReturnType, ByteVector, Ts...>;

	/// Check if MWR namespace has function to get size of type T when it is stored to ByteVector.
	template <typename T>
	class GotByteSize
	{
		template <typename C> static uint8_t test(decltype(MWR::ByteConverter<T>::Size(std::declval<T>())));
		template <typename C> static uint16_t test(...);

	public:
		enum { value = sizeof(test<T>(0)) == sizeof(uint8_t) };
	};

	/// An owning container.
	class ByteVector : std::vector<std::uint8_t>
	{
	public:
		/// Privately inherited Type.
		using Super = std::vector<std::uint8_t>;

		/// Type of stored values.
		using ValueType = Super::value_type;

		/// Destructor zeroing memory.
		~ByteVector();

		/// Copy constructor.
		/// @param other. Object to copy.
		ByteVector(ByteVector const& other);

		/// Move constructor.
		/// @param other. Object to move.
		ByteVector(ByteVector&& other);

		/// Copy assignment operator.
		/// @param other. Object to copy.
		ByteVector& operator=(ByteVector const& other);

		/// Move assignment operator.
		/// @param other. Object to move.
		ByteVector& operator=(ByteVector&& other);

		/// Create from std::vector.
		/// @param other. Object to copy.
		ByteVector(std::vector<uint8_t> other);

		// Enable methods.
		using Super::vector;
		using Super::value_type;
		using Super::allocator_type;
		using Super::size_type;
		using Super::difference_type;
		using Super::reference;
		using Super::const_reference;
		using Super::pointer;
		using Super::const_pointer;
		using Super::iterator;
		using Super::const_iterator;
		using Super::reverse_iterator;
		using Super::const_reverse_iterator;
		using Super::operator=;
		using Super::assign;
		using Super::get_allocator;
		using Super::at;
		using Super::operator[];
		using Super::front;
		using Super::back;
		using Super::data;
		using Super::begin;
		using Super::cbegin;
		using Super::end;
		using Super::cend;
		using Super::rbegin;
		using Super::crbegin;
		using Super::rend;
		using Super::crend;
		using Super::empty;
		using Super::size;
		using Super::max_size;
		using Super::reserve;
		using Super::capacity;
		using Super::shrink_to_fit;
		using Super::clear;
		using Super::insert;
		using Super::emplace;
		using Super::erase;
		using Super::push_back;
		using Super::emplace_back;
		using Super::pop_back;
		using Super::resize;

		/// Write content of of provided objects.
		/// Suports arithmetic types, std::string, std::wstring, std::string_view, std::wstring_view, ByteVector and ByteArray, and std::tuple of those types.
		/// Writes 4 Bytes header with size for types that have variable buffer length.
		/// @tparam T. Types to be stored.
		/// @return itself to allow chaining.
		template <typename ...T, typename std::enable_if_t<CanStoreType<T...>::value, int> = 0>
		ByteVector & Write(T const& ...args)
		{
			reserve(size() + CalculateStoreSize<T...>(true, args...));
			Store<T...>(true, args...);
			return *this;
		}

		/// Write content of of provided objects.
		/// Suports arithmetic types, std::string, std::wstring, std::string_view, std::wstring_view, ByteVector and ByteArray, and std::tuple of those types.
		/// Does not write header with size for types that have variable buffer length. Recipient must know size in advance to read, therefore should use Read<ByteArray<someSize>>.
		/// @tparam T. Types to be stored.
		/// @return itself to allow chaining.
		template <typename ...T, typename std::enable_if_t<CanStoreType<T...>::value, int> = 0>
		ByteVector & Concat(T const& ...args)
		{
			reserve(size() + CalculateStoreSize<T...>(false, args...));
			Store<T...>(false, args...);
			return *this;
		}

		/// Create new ByteVector with Variadic list of parameters.
		/// This function cannot be constructor, becouse it would be ambigious with std::vector costructors.
		/// @see ByteVector::Write and ByteVector::Concat for more informations.
		template <bool preferWriteOverConcat = true, typename ...T, typename std::enable_if_t<CanStoreType<T...>::value, int> = 0>
		static ByteVector Create(T const& ...args)
		{
			if constexpr (preferWriteOverConcat)
				return CreateByWrite(args...);
			else
				return CreateByConcat(args...);
		}

		/// Create new ByteVector with Variadic list of parameters.
		/// This function cannot be constructor, becouse it would be ambigious with std::vector costructors.
		/// @see ByteVector::Write for more informations.
		template <typename ...T, typename std::enable_if_t<CanStoreType<T...>::value, int> = 0>
		static ByteVector CreateByWrite(T const& ...args)
		{
			return ByteVector{}.Write(args...);
		}

		/// Create new ByteVector with Variadic list of parameters.
		/// This function cannot be constructor, becouse it would be ambigious with std::vector costructors.
		/// @see ByteVector::Concat for more informations.
		template <typename ...T, typename std::enable_if_t<CanStoreType<T...>::value, int> = 0>
		static ByteVector CreateByConcat(T const& ...args)
		{
			return ByteVector{}.Concat(args...);
		}

	private:
		/// Store content of of provided object.
		/// @param storeSize. If true function will add four byte header with size for those types.
		/// @param arg. argument to be stored. Supported types are ByteVector, ByteView, std::string, std::string_view, std::wstring, std::wstring_view.
		/// @return itself to allow chaining.
		template<typename T, typename std::enable_if_t<
			(
				std::is_same_v<T, ByteVector>
				|| std::is_same_v<T, ByteView>
				|| std::is_same_v<T, std::string>
				|| std::is_same_v<T, std::string_view>
				|| std::is_same_v<T, std::wstring>
				|| std::is_same_v<T, std::wstring_view>
				), int> = 0>
			ByteVector & Store(bool storeSize, T const& arg)
		{
			auto oldSize = size();
			if (storeSize)
			{
				resize(oldSize + sizeof(uint32_t) + arg.size() * sizeof(T::value_type));
				*reinterpret_cast<uint32_t*>(data() + oldSize) = static_cast<uint32_t>(arg.size());
				std::memcpy(data() + oldSize + sizeof(uint32_t), arg.data(), arg.size() * sizeof(T::value_type));
			}
			else
			{
				resize(oldSize + arg.size() * sizeof(T::value_type));
				std::memcpy(data() + oldSize, arg.data(), arg.size() * sizeof(T::value_type));
			}

			return *this;
		}

		/// Store content of array. Size must be known at compile time and will not be saved in data.
		/// @tparam T. Type to be stored. Supported types are ByteArray.
		/// @return itself to allow chaining.
		template<typename T, typename std::enable_if_t<IsByteArray<T>, int> = 0>
		ByteVector & Store(bool unused, T const& arg)
		{
			auto oldSize = size();
			resize(oldSize + arg.size());
			std::memcpy(data() + oldSize, arg.data(), arg.size());

			return *this;
		}

		/// Store arithmetic type.
		/// tparam T. Type to be stored.
		/// @return itself to allow chaining.
		template<typename T,  typename std::enable_if_t<std::is_arithmetic<T>::value, int> = 0>
		ByteVector & Store(bool unused, T const& arg)
		{
			auto oldSize = size();
			resize(oldSize + sizeof(T));
			*reinterpret_cast<T*>(data() + oldSize) = arg;

			return *this;
		}

		/// Store custom type.
		/// tparam T. Type to be stored. There must exsist MWR::ToBytes(T const&) method avalible to store custom type.
		/// @return itself to allow chaining.
		template<typename T, typename std::enable_if_t<std::is_same_v<decltype(MWR::ByteConverter<T>::To(std::declval<T>())), MWR::ByteVector >, int> = 0>
		ByteVector & Store(bool unused, T const& arg)
		{
			Concat(MWR::ByteConverter<T>::To(arg));
			return *this;
		}

		/// Store all arguments at the end of ByteVector.
		/// @param storeSize if true four byte header will be added to types in T that does not have size defined at compile time.
		/// @tparam T. Parameter pack to be written. Types are deduced from function call.
		/// @return itself to allow chaining.
		/// @remarks This function is called only for two or more arguments.
		/// @remarks Each type in parameter pack must have corresponding Write method for one argument.
		template <typename ...T, typename std::enable_if_t<(sizeof...(T) > 1), int> = 0>
		ByteVector & Store(bool storeSize, T const& ...args)
		{
			VariadicStoreHelper<T...>::Store(*this, storeSize, args...);
			return *this;
		}

		/// Store tuple type.
		/// @param storeSize if true four byte header will be added to types in T that does not have size defined at compile time.
		/// tparam T. Tuple type to be stored.
		/// @return itself to allow chaining.
		template<typename T, typename std::enable_if_t<IsTuple<T>, int> = 0>
		ByteVector & Store(bool storeSize, T const& arg)
		{
			StoreHelper<T>::Store(*this, storeSize, arg);
			return *this;
		}

		/// Calculate the size that the argument will take in memory
		/// @param storeSizeHeader. If true function will add four byte header with size for those types.
		/// @param arg. argument to be stored. Supported types are ByteVector, ByteView, std::string, std::string_view, std::wstring, std::wstring_view.
		/// @return size_t number of bytes needed.
		template<typename T, typename std::enable_if_t<
			(
				std::is_same_v<T, ByteVector>
				|| std::is_same_v<T, ByteView>
				|| std::is_same_v<T, std::string>
				|| std::is_same_v<T, std::string_view>
				|| std::is_same_v<T, std::wstring>
				|| std::is_same_v<T, std::wstring_view>
				), int> = 0>
		static size_t CalculateStoreSize(bool storeSizeHeader, T const& arg)
		{
			return storeSizeHeader ? arg.size() + sizeof(uint32_t) : arg.size();
		}

		/// Calculate the size that the argument will take in memory
		/// @param unused. Supports finding this function in template calls.
		/// @param arg. argument to be stored. Supports ByteArray type.
		/// @return size_t number of bytes needed.
		template<typename T, typename std::enable_if_t<IsByteArray<T>, int> = 0>
		static size_t CalculateStoreSize(bool unused, T const& arg)
		{
			return arg.size();
		}

		/// Calculate the size that the argument will take in memory
		/// @param unused. Supports finding this function in template calls.
		/// @param arg. argument to be stored. Supports arithmetic types.
		/// @return size_t number of bytes needed.
		template<typename T, typename std::enable_if_t<std::is_arithmetic<T>::value, int> = 0>
		static size_t CalculateStoreSize(bool unused, T const& arg)
		{
			return sizeof(T);
		}

		/// Calculate the size that the argument will take in memory
		/// tparam T. Type to be stored. There must exsist MWR::ByteConverter<T>::To(T const&) function and MWR::ByteConverter<T>::Size(T const&)
		/// @return size_t number of bytes needed.
		template<typename T, typename std::enable_if_t<std::is_same_v<decltype(MWR::ByteConverter<T>::To(std::declval<T>())), ByteVector> && GotByteSize<T>::value, int> = 0>
		static size_t CalculateStoreSize(bool unused, T const& arg)
		{
			return MWR::ByteConverter<T>::Size(arg);
		}

		/// Calculate the size that the argument will take in memory
		/// tparam T. Type to be stored. There must exsist MWR::ByteConverter<T>::To(T const&) method avalible to store custom type.
		/// @return size_t number of bytes needed.
		template<typename T, typename std::enable_if_t<std::is_same_v<decltype(MWR::ByteConverter<T>::To(std::declval<T>())), ByteVector> && !GotByteSize<T>::value, int> = 0>
		static size_t CalculateStoreSize(bool unused, T const& arg)
		{
			return MWR::ByteConverter<T>::To(arg).size();
		}

		/// Calculate the size that the arguments will take in memory. This function is responsible for unwrapping variadic arguments calls.
		/// @param storeSizeHeader. If true function writes 4 bytes header with size for types that have variable buffer length.
		/// @param args. arguments to be stored.
		/// @return size_t number of bytes needed.
		template <typename ...T, typename std::enable_if_t<(sizeof...(T) > 1), int> = 0>
		static size_t CalculateStoreSize(bool storeSizeHeader, T const& ...args)
		{
			return VariadicStoreHelper<T...>::CalculateStoreSize(storeSizeHeader, args...);
		}

		/// Calculate the size that the arguments will take in memory. This function is responsible for unwrapping calls with tuple type.
		/// @param storeSizeHeader. If true function writes 4 bytes header with size for types that have variable buffer length.
		/// @param arg. arguments to be stored in form of tuple.
		/// @return size_t number of bytes needed.
		template<typename T, typename std::enable_if_t<IsTuple<T>, int> = 0>
		static size_t CalculateStoreSize(bool storeSizeHeader, T const& arg)
		{
			return StoreHelper<T>::CalculateStoreSize(storeSizeHeader, arg);
		}

		/// Delegate to class idiom.
		/// Function templates cannot be partially specialized.
		/// @tparam T. First type from parameter pack. Each recursive call will unfold one type.
		/// @tparam Rest. Parameter pack storing rest of provided types.
		template <typename T, typename ...Rest>
		struct VariadicStoreHelper
		{
			/// Function responsible for recursively packing data to ByteVector.
			/// @param storeSizeHeader if true four byte header will be added to types in T that does not have size defined at compile time.
			/// @param self. Reference to ByteVector object using VariadicWriter.
			/// @note Template used here should remove function if one of types cannot be stored.
			/// Compiler should mark error of compilation in code location where function was used with wrong parameters.
			/// Becouse of MSVC SFINAE bug compiler can mark this function with std::enable_if_t<false... error.
			/// If you see this error examine ByteVector::Write and ByteVector::Concat usages for potential invalid parameters.
			template <typename std::enable_if_t<CanStoreType<T>::value, int> = 0>
			static void Store(ByteVector& self, bool storeSizeHeader, T const& current, Rest const& ...rest)
			{
				self.Store(storeSizeHeader, current);
				VariadicStoreHelper<Rest...>::Store(self, storeSizeHeader, rest...);
			}

			/// Function responsible for recursively calculating buffer size needed for call with variadic argument list.
			/// @param storeSizeHeader if true four byte header will be added to types in T that does not have size defined at compile time.
			/// @return size_t number of bytes needed.
			static size_t CalculateStoreSize(bool storeSizeHeader, T const& current, Rest const& ...rest)
			{
				return ByteVector::CalculateStoreSize(storeSizeHeader, current) + VariadicStoreHelper<Rest...>::CalculateStoreSize(storeSizeHeader, rest...);
			}
		};

		/// Delegate to class idiom.
		/// Function templates cannot be partially specialized.
		/// Closure specialization.
		/// @tparam T. Type to be extracted stored in ByteVector.
		/// @note Template used here should remove function if one of types cannot be stored.
		/// Compiler should mark error of compilation in code location where function was used with wrong parameters.
		/// Becouse of MSVC SFINAE bug compiler can mark this function with std::enable_if_t<false... error.
		/// If you see this error examine ByteVector::Write and ByteVector::Concat usages for potential invalid parameters.
		template <typename T>
		struct VariadicStoreHelper<T>
		{
			/// Function responsible for recursively packing data to ByteVector.
			/// @param storeSizeHeader if true four byte header will be added to types in T that does not have size defined at compile time.
			/// @param self. Reference to ByteVector object using VariadicWriter.
			template <typename std::enable_if_t<CanStoreType<T>::value, int> = 0>
			static void Store(ByteVector& self, bool storeSizeHeader, T const& current)
			{
				self.Store(storeSizeHeader, current);
			}

			/// Function responsible for recursively calculating buffer size needed for call with variadic argument list.
			/// @param storeSizeHeader if true four byte header will be added to types in T that does not have size defined at compile time.
			/// @return size_t number of bytes needed.
			static size_t CalculateStoreSize(bool storeSizeHeader, T const& current)
			{
				return ByteVector::CalculateStoreSize(storeSizeHeader, current);
			}
		};

		/// Delegate to class idiom.
		/// Function templates cannot be partially specialized.
		/// @tparam T. Tuple type to write.
		/// @tparam N. How many elements of tuple to write.
		template <typename T, size_t N = std::tuple_size_v<T>>
		struct StoreHelper
		{
			/// Function responsible for recursively packing data to ByteVector.
			/// @param self. Reference to ByteVector object using VariadicWriter.
			/// @param storeSizeHeader if true four byte header will be added to types in T that does not have size defined at compile time.
			/// @param t. reference to tuple.
			/// @note Template used here should remove function if one of types cannot be stored.
			/// Compiler should mark error of compilation in code location where function was used with wrong parameters.
			/// Becouse of MSVC SFINAE bug compiler can mark this function with std::enable_if_t<false... error.
			/// If you see this error examine ByteVector::Write and ByteVector::Concat usages for potential invalid parameters.
			template <typename std::enable_if_t<CanStoreType<decltype(std::get<std::tuple_size_v<T> -N>(t))>::value, int> = 0>
			static void Store(ByteVector& self, bool storeSizeHeader, T const& t)
			{
				self.Store(storeSizeHeader, std::get<std::tuple_size_v<T> - N>(t));
				StoreHelper<T, N - 1>::Store(self, storeSizeHeader, t);
			}

			/// Function responsible for recursively calculating buffer size needed for call with tuple argument.
			/// @param storeSizeHeader if true four byte header will be added to types in T that does not have size defined at compile time.
			/// @return size_t number of bytes needed.
			static size_t CalculateStoreSize(bool storeSize, T const& t)
			{
				return ByteVector::CalculateStoreSize(storeSizeHeader, std::get<std::tuple_size_v<T> - N>(t)) + StoreHelper<T, N - 1>::CalculateStoreSize(storeSizeHeader, t);
			}
		};

		/// Delegate to class idiom.
		/// Function templates cannot be partially specialized.
		/// Closure specialization.
		/// @tparam T. Tuple type to write.
		template <typename T>
		struct StoreHelper<T, 0>
		{
			/// Closing function, does nothing.
			static void Store(ByteVector&, bool, T const&)
			{
				// Do nothing.
			}

			/// Closing function, returns 0.
			static size_t CalculateStoreSize(bool, T const&)
			{
				return 0;
			}
		};
	};

	/// Checks if the contents of lhs and rhs are equal.
	/// @param lhs. Left hand side of operator.
	/// @param rhs. Right hand side of operator.
	bool operator==(ByteVector const& lhs, ByteVector const& rhs);

	/// Checks if the contents of lhs and rhs are equal.
	/// @param lhs. Left hand side of operator.
	/// @param rhs. Right hand side of operator.
	bool operator!=(ByteVector const& lhs, ByteVector const& rhs);

	namespace Literals
	{
		/// Create ByteVector with syntax ""_bvec
		ByteVector operator "" _b(const char* data, size_t size);

		/// Create ByteVector with syntax L""_bvec
		ByteVector operator "" _b(const wchar_t* data, size_t size);
	}
}

namespace std
{
	/// Add hashing function for ByteVector.
	template <>
	struct hash<MWR::ByteVector>
	{
		size_t operator()(MWR::ByteVector const& bv) const
		{
			return std::hash<std::string_view>{}(std::string_view{ reinterpret_cast<const char*>(bv.data()), bv.size() });
		}
	};
}
