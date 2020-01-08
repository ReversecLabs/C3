#pragma once

#include "ByteArray.h"
#include "Utils.h"

namespace MWR
{
	/// Forward declaration
	class ByteView;
	class ByteVector;

	/// Empty template of class that can convert data from and to byte form.
	/// Look for example in ByteConventer.h
	template <typename T, typename = void>
	struct ByteConverter {};

	/// Check if MWR namespace has function to get size of type T when it is stored to ByteVector.
	/// This class performs test that looks for implementation of Size function in ByteConverter<T>.
	/// Depending on test result 'value' is set to one of:
	/// absent - No implementation is available for Size function. Size can only be determined after serialization.
	/// compileTime - Size is determined by type, not object instance. Size() is constexpr function.
	/// runTime - Size depends on object instance. Size(T const&) can be used before serialization
	template <typename T>
	class ByteSizeFunctionType
	{
		template <typename C> static uint32_t test(decltype(MWR::ByteConverter<T>::Size(std::declval<C>())));
		template <typename C> static uint16_t test(decltype(MWR::ByteConverter<T>::Size(std::void_t<C>)));
		template <typename C> static uint8_t test(...);

	public:
		enum { absent = 0, compileTime = (sizeof(uint16_t) - sizeof(uint8_t)), runTime = (sizeof(uint32_t) - sizeof(uint8_t)) };
		enum { value = (sizeof(test<T>(0)) - sizeof(uint8_t)) };
	};

	/// An owning container.
	class ByteVector : std::vector<std::uint8_t>
	{
	public:
		/// Privately inherited Type.
		using Super = std::vector<std::uint8_t>;

		/// Type of stored values.
		using ValueType = Super::value_type;

#if defined BYTEVECTOR_ZERO_MEMORY_DESTRUCTION
		/// Destructor zeroing memory.
		~ByteVector()
		{
			Utils::SecureMemzero(data(), size());
		}
#endif

		/// Copy constructor.
		/// @param other. Object to copy.
		ByteVector(ByteVector const& other)
			: Super(static_cast<Super const&>(other))
		{

		}

		/// Move constructor.
		/// @param other. Object to move.
		ByteVector(ByteVector&& other)
			: Super(static_cast<Super&&>(other))
		{

		}

		/// Copy assignment operator.
		/// @param other. Object to copy.
		ByteVector& operator=(ByteVector const& other)
		{
			auto tmp = Super{ static_cast<Super const&>(other) };
			std::swap(static_cast<Super&>(*this), tmp);
			return *this;
		}

		/// Move assignment operator.
		/// @param other. Object to move.
		ByteVector& operator=(ByteVector&& other)
		{
			std::swap(static_cast<Super&>(*this), static_cast<Super&>(other));
			return *this;
		}

		/// Create from std::vector.
		/// @param other. Object to copy.
		ByteVector(std::vector<uint8_t> other)
			: Super(std::move(other))
		{

		}

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
		friend inline bool operator==(ByteVector const& lhs, ByteVector const& rhs);
		friend inline bool operator!=(ByteVector const& lhs, ByteVector const& rhs);

		/// Write content of of provided objects.
		/// Suports arithmetic types, std::string, std::wstring, std::string_view, std::wstring_view, ByteVector and ByteView.
		/// Include ByteConverter.h to add support for common types like enum, std::vector, std:map, std::pair, std::tuple and others.
		/// Create specialization on ByteConverter for custom types or template types to expand existing serialization functionality.
		/// @param arg. Object to be stored.
		/// @param args. Optional other objects to be stored.
		/// @return itself to allow chaining.
		template <typename T, typename ...Ts>
		ByteVector& Write(T const& arg, Ts const& ...args)
		{
			reserve(size() + Size<T, Ts...>(arg, args...));
			Store<T, Ts...>(arg, args...);
			return *this;
		}

		/// Write content of of provided objects.
		/// Supports ByteView and ByteVector.
		/// Does not write header with size.
		/// @param arg. Object to be stored.
		/// @param args. Optional other objects to be stored.
		/// @return itself to allow chaining.
		template <typename T, typename ...Ts, typename = std::enable_if_t<Utils::IsOneOf<T, ByteView, ByteVector>::value>>
		ByteVector& Concat(T const& arg, Ts const& ...args)
		{
			if constexpr (!sizeof...(Ts))
			{
				auto oldSize = size();
				resize(oldSize + arg.size());
				memcpy(data() + oldSize, arg.data(), arg.size());
			}
			else
			{
				Concat(arg);
				Concat(args...);
			}

			return *this;
		}

		// msvc can handle fold expression in debug mode, but fails with internal compiler error in release.
		//template <typename ...T, typename = std::enable_if_t<((Utils::IsOneOf<T, ByteView, ByteVector>::value && ...))>>
		//ByteVector& Concat(T const& ...arg)
		//{
		//	auto oldSize = size();
		//	auto foldSize = (arg.size() + ...);
		//	resize(oldSize + foldSize);
		//	auto ptr = data() + oldSize;
		//	((memcpy(ptr, arg.data(), arg.size()), (ptr += arg.size())), ...);
		//	return *this;
		//}

		/// Create new ByteVector with Variadic list of parameters.
		/// This function cannot be constructor, because it would be ambiguous with super class constructors.
		/// @param arg. Object to be stored.
		/// @param args. Optional other objects to be stored.
		/// @see ByteVector::Write for more informations.
		template <typename T, typename ...Ts>
		static ByteVector Create(T const& arg, Ts const& ...args)
		{
			return ByteVector{}.Write(arg, args...);
		}

		/// Proxy function to ByteView::Read.
		/// This function is added for convenience, but it does not change the state of ByteVector in a way ByteView::Read moves to next stored element after each Read.
		template<typename ...T, typename = std::void_t<decltype(std::declval<ByteView>().Read<T...>())>>
		auto Read() const
		{
			return ByteView{ *this }.Read<T...>();
		}

		/// Calculate the size that the argument will take in memory
		/// @param arg. Argument to be stored.
		/// @param args. Rest of types that will be handled with recursion.
		/// @return size_t number of bytes needed.
		template<typename T, typename ...Ts>
		static size_t Size(T const& arg, Ts const& ...args)
		{
			if constexpr (!sizeof...(Ts))
			{
				// There is only one type to calculate size for. Find implementation of Size for that type.
				if constexpr (ByteSizeFunctionType<T>::value == ByteSizeFunctionType<T>::compileTime)
					return MWR::ByteConverter<T>::Size();
				else if constexpr (ByteSizeFunctionType<T>::value == ByteSizeFunctionType<T>::runTime)
					return MWR::ByteConverter<T>::Size(arg);
				else if constexpr (ByteSizeFunctionType<T>::value == ByteSizeFunctionType<T>::absent)
					return MWR::ByteConverter<T>::To(arg).size();
			}
			else
			{
				return Size(arg) + Size(args...);
			}
		}

	private:
		/// Store custom type.
		/// @param arg. Object to be stored. There must exsist MWR::ByteConverter<T>::To(T const&) method avalible to store custom type.
		/// @param args. Rest of objects that will be handled with recursion.
		/// @return itself to allow chaining.
		template<typename T, typename ...Ts, typename std::enable_if_t<std::is_same_v<decltype(MWR::ByteConverter<T>::To(std::declval<T>())), MWR::ByteVector >, int> = 0>
		ByteVector & Store(T const& arg, Ts const& ...args)
		{
			if constexpr (!sizeof...(Ts))
			{
				Concat(MWR::ByteConverter<T>::To(arg));
			}
			else
			{
				Store(arg);
				Store(args...);
			}

			return *this;
		}
	};

	/// ByteConverter specialization for ByteVector, ByteView, std::string, std::string_view, std::wstring, std::wstring_view.
	/// This is a basic functionality that should be available with ByteVector. This specialization will not be moved to ByteConverter.h.
	template <typename T>
	struct ByteConverter<T, std::enable_if_t<Utils::IsOneOf<T, ByteVector, ByteView, std::string, std::string_view, std::wstring, std::wstring_view>::value>>
	{
		static ByteVector To(T const& obj)
		{
			auto ret = ByteVector{};
			auto elementSize = static_cast<uint32_t>(obj.size());
			ret.resize(Size(obj));
			memcpy(ret.data(), &elementSize, sizeof(elementSize));
			memcpy(ret.data() + sizeof(elementSize), obj.data(), elementSize * sizeof(T::value_type));
			return ret;
		}

		static size_t Size(T const& obj)
		{
			return sizeof(uint32_t) + (obj.size() * sizeof(T::value_type));
		}

		// Reading functions are part of ByteView implementation. To deserialize data include ByteView.h
		static T From(ByteView& bv);
	};

	/// ByteConverter specialization for arithmetic types.
	/// This is a basic functionality that should be available with ByteVector. This specialization will not be moved to ByteConverter.h.
	template <typename T>
	struct ByteConverter<T, std::enable_if_t<std::is_arithmetic_v<T>>>
	{
		static ByteVector To(T obj)
		{
			auto ret = ByteVector{};
			ret.resize(sizeof(T));
			*reinterpret_cast<T*>(ret.data()) = obj;

			return ret;
		}

		constexpr static size_t Size()
		{
			return sizeof(T);
		}

		// Reading functions are part of ByteView implementation. To deserialize data include ByteView.h
		static T From(ByteView& bv);
	};

	namespace Literals
	{
		/// Create ByteVector with syntax ""_bvec
		inline ByteVector operator "" _b(const char* data, size_t size)
		{
			MWR::ByteVector ret;
			ret.resize(size);
			std::memcpy(ret.data(), data, size);
			return ret;
		}

		/// Create ByteVector with syntax L""_bvec
		inline ByteVector operator "" _b(const wchar_t* data, size_t size)
		{
			MWR::ByteVector ret;
			ret.resize(size * sizeof(wchar_t));
			std::memcpy(ret.data(), data, size * sizeof(wchar_t));
			return ret;
		}
	}

	/// Checks if the contents of lhs and rhs are equal.
	/// @param lhs. Left hand side of operator.
	/// @param rhs. Right hand side of operator.
	inline bool operator==(MWR::ByteVector const& lhs, MWR::ByteVector const& rhs)
	{
		if (lhs.size() != rhs.size())
			return false;

		return !memcmp(lhs.data(), rhs.data(), lhs.size());
	}

	/// Checks if the contents of lhs and rhs are equal.
	/// @param lhs. Left hand side of operator.
	/// @param rhs. Right hand side of operator.
	inline bool operator!=(MWR::ByteVector const& lhs, MWR::ByteVector const& rhs)
	{
		return !(lhs == rhs);
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
