#pragma once

#include "ByteView.h"

/// Example code of specializing ByteConverter for custom type A.
//struct A
//{
//	uint16_t m_a, m_b;
//
//	A(uint16_t a, uint16_t b) : m_a(a), m_b(b) {}
//};
//
//namespace MWR
//{
//	template <>
//	struct ByteConverter<A>
//	{
//		static ByteVector To(A const& a)
//		{
//			return ByteVector::Create(a.m_a, a.m_b);
//		}
//
//		static size_t Size(A const& a)
//		{
//			return 2 * sizeof(uint16_t);
//		}
//
//		static A From(ByteView& bv)
//		{
//			auto [a, b] = bv.Read<uint16_t, uint16_t>();
//			return A(a, b);
//		}
//	};
//}

// specializations for ByteConverter for common types.
namespace MWR
{
	// ByteConverter specialization for enums.
	template <typename T>
	struct ByteConverter<T, std::enable_if_t<std::is_enum_v<T>>>
	{
		static ByteVector To(T obj)
		{
			return ByteVector::Create(static_cast<std::underlying_type_t<T>>(obj));
		}

		constexpr static size_t Size()
		{
			return sizeof(std::underlying_type_t<T>);
		}

		static T From(ByteView& bv)
		{
			return static_cast<T>(bv.Read<std::underlying_type_t<T>>());
		}
	};

	// ByteConverter specialization for std::pair<>.
	template <typename T1, typename T2>
	struct ByteConverter<std::pair<T1, T2>>
	{
		static ByteVector To(std::pair<T1, T2> const& obj)
		{
			return ByteVector::Create(obj.first, obj.second);
		}

		static size_t Size(std::pair<T1, T2> const& obj)
		{
			return ByteVector::Size(obj.first) + ByteVector::Size(obj.second);
		}

		static std::pair<T1, T2> From(ByteView& bv)
		{
			auto [t1, t2] = bv.Read<T1, T2>();
			return { std::move(t1), std::move(t2) };
		}
	};

	// ByteConverter specialization for std::filesystem::path.
	template <>
	struct ByteConverter<std::filesystem::path>
	{
		static ByteVector To(std::filesystem::path const& obj)
		{
			return ByteVector::Create(obj.wstring());
		}

		static size_t Size(std::filesystem::path const& obj)
		{
			return ByteVector::Size(obj.wstring());
		}

		static std::filesystem::path From(ByteView& bv)
		{
			return { bv.Read<std::wstring>() };
		}
	};

	// ByteConverter specialization for std::byte.
	template <>
	struct ByteConverter<std::byte>
	{
		static ByteVector To(std::byte obj)
		{
			return ByteVector::Create(static_cast<unsigned char>(obj));
		}

		constexpr static size_t Size()
		{
			return sizeof(unsigned char);
		}

		static std::byte From(ByteView& bv)
		{
 			return static_cast<std::byte>(bv.Read<unsigned char>());
		}
	};

	/// Class allowing reading N bytes without coping data like in ByeView::Read<ByteArray<N>> or ByteView::Reed(size_t).
	/// Using Bytes class in read will return ByteView with requested size using simple syntax:
	/// someByteViewObject.Read<int, int, Bytes<7>, std::string>
	template<size_t N>
	class Bytes
	{
		/// This class should never be instantiated.
		Bytes() = delete;
	};

	// ByteConverter specialization for MWR::Bytes.
	template <size_t N>
	struct ByteConverter<MWR::Bytes<N>>
	{
		static ByteView From(ByteView& bv)
		{
			if (N > bv.size())
				throw std::out_of_range{ OBF(": Cannot read data from ByteView") };

			auto retVal = bv.SubString(0, N);
			bv.remove_prefix(N);
			return retVal;
		}
	};

	// ByteConverter specialization for vector types.
	template <typename T>
	struct ByteConverter<std::vector<T>>
	{
		static ByteVector To(std::vector<T> const& obj)
		{
			ByteVector ret;
			ret.reserve(ByteVector::Size(obj));
			ret.Write(static_cast<uint32_t>(obj.size()));
			for (auto const& e : obj)
				ret.Concat(ByteVector::Create(e));

			return ret;
		}

		static size_t Size(std::vector<T> const& obj)
		{
			size_t size = sizeof(uint32_t); //four bytes for vector size.
			for (auto const& e : obj)
				size += ByteVector::Size(e);

			return size;
		}

		static std::vector<T> From(ByteView& bv)
		{
			std::vector<T> ret;
			auto size = bv.Read<uint32_t>();
			ret.reserve(size);
			for (auto i = 0u; i < size; ++i)
				ret.push_back(bv.Read<T>());
			return ret;
		}
	};

	// ByteConverter specialization for map types.
	template <typename T1, typename T2>
	struct ByteConverter<std::map<T1, T2>>
	{
		static ByteVector To(std::map<T1, T2> const& obj)
		{
			ByteVector ret;
			ret.reserve(ByteVector::Size(obj));
			ret.Write(static_cast<uint32_t>(obj.size()));
			for (auto const& [key, val] : obj)
				ret.Concat(ByteVector::Create(key, val));

			return ret;
		}

		static size_t Size(std::map<T1, T2> const& obj)
		{
			size_t size = sizeof(uint32_t); //four bytes for map size.
			for (auto const& [key, val] : obj)
				size += ByteVector::Size(key) + ByteVector::Size(val);

			return size;
		}

		static std::map<T1, T2> From(ByteView& bv)
		{
			std::map<T1, T2> ret;
			auto size = bv.Read<uint32_t>();
			for (auto i = 0u; i < size; ++i)
			{
				auto [key, val] = bv.Read<T1, T2>();
				ret.emplace(std::move(key), std::move(val));
			}

			return ret;
		}
	};

	// ByteConverter specialization for std:array.
	template <typename T, size_t N>
	struct ByteConverter<std::array<T, N>>
	{
		static ByteVector To(std::array<T, N> const& obj)
		{
			ByteVector ret;
			ret.reserve(ByteVector::Size(obj));
			for (auto const& e : obj)
				ret.Write(e);

			return ret;
		}

		static size_t Size(std::array<T, N> const& obj)
		{
			auto ret = size_t{ 0 };
			if constexpr (std::is_arithmetic_v<T>)
			{
				static_cast<void>(obj);
				ret = sizeof(T) * N; // avoid extra calls when size of array is known.
			}
			else
			{
				for (auto const& e : obj)
					ret += ByteVector::Size(e);
			}

			return ret;
		}

		static std::array<T, N> From(ByteView& bv)
		{
			// T might not be default constructible, array must be filled like aggregator,
			// order of reading from ByteView would depend on calling convention.
			std::vector<T> temp;
			temp.reserve(N);
			for (auto i = 0u; i < N; ++i)
				temp.push_back(bv.Read<T>());

			return MakeArray(std::move(temp), std::make_index_sequence<N>());
		}

	private:
		template<size_t...Is>
		static std::array<T, N> MakeArray(std::vector<T>&& vec, std::index_sequence<Is...>)
		{
			return { std::move(vec[Is])... };
		}
	};

	// ByteConverter specialization for tuple.
	template <typename T>
	struct ByteConverter<T, std::enable_if_t<Utils::IsTuple<T>>>
	{
		static ByteVector To(T const& obj)
		{
			ByteVector ret;
			ret.reserve(Size(obj));
			TupleHandler<T>::Write(ret, obj);
			return ret;
		}

		static size_t Size(T const& obj)
		{
			return TupleHandler<T>::Size(obj);
		}

		static auto From(ByteView& bv)
		{
			return TupleHandler<T>::Read(bv);
		}

	private:
		/// @tparam T. Tuple type to read/write.
		/// @tparam N. How many elements of tuple to handle. Functions will use recursion, decrementing N with each call.
		template <typename T, size_t N = std::tuple_size_v<T>>
		struct TupleHandler
		{
			/// Function responsible for recursively packing data to ByteVector.
			/// @param self. Reference to ByteVector object using VariadicWriter.
			/// @param t. reference to tuple.
			static void Write(ByteVector& self, T const& t)
			{
				if constexpr (N != 0)
				{
					self.Write(std::get<std::tuple_size_v<T> - N>(t));
					TupleHandler<T, N - 1>::Write(self, t);
				}
			}

			/// Function responsible for recursively calculating buffer size needed for call with tuple argument.
			/// @return size_t number of bytes needed.
			static size_t Size(T const& t)
			{
				if constexpr (N != 0)
					return ByteVector::Size(std::get<std::tuple_size_v<T> - N>(t)) + TupleHandler<T, N - 1>::Size(t);
				else
					return 0;
			}

			/// Function responsible for recursively packing data to tuple.
			/// @param self. Reference to ByteView object using generate method.
			static auto Read(ByteView& self)
			{
				if constexpr (N != 0)
				{
					auto current = std::make_tuple(self.Read<std::tuple_element_t<std::tuple_size_v<T> - N, T>>());
					auto rest = TupleHandler<T, N - 1>::Read(self);
					return std::tuple_cat(current, rest);
				}
				else
				{
					return std::tuple<>{};
				}

			}
		};
	};
}
