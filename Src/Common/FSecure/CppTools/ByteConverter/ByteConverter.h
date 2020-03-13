#pragma once

#include <filesystem>

#include "ByteView.h"

/// specializations for ByteConverter for common types.
namespace FSecure
{
	/// ByteConverter specialization for arithmetic types.
	template <typename T>
	struct ByteConverter<T, std::enable_if_t<std::is_arithmetic_v<T>>>
	{
		/// Serialize arithmetic type to ByteVector.
		/// @param obj. Object to be serialized.
		/// @return ByteVector. Serialized data.
		static ByteVector To(T obj)
		{
			auto ret = ByteVector{};
			ret.resize(sizeof(T));
			*reinterpret_cast<T*>(ret.data()) = obj;

			return ret;
		}

		/// Get size required after serialization.
		/// @return size_t. Number of bytes used after serialization.
		constexpr static size_t Size()
		{
			return sizeof(T);
		}

		/// Deserialize from ByteView.
		/// @param bv. Buffer with serialized data.
		/// @return arithmetic type.
		static T From(ByteView& bv)
		{
			if (sizeof(T) > bv.size())
				throw std::out_of_range{ OBF(": Cannot read size from ByteView ") };

			T ret;
			memcpy(&ret, bv.data(), sizeof(T));
			bv.remove_prefix(sizeof(T));
			return ret;
		}
	};

	/// ByteConverter specialization for enum.
	template <typename T>
	struct ByteConverter<T, std::enable_if_t<std::is_enum_v<T>>>
	{
		/// Serialize enum type to ByteVector.
		/// @param enumInstance. Object to be serialized.
		/// @return ByteVector. Serialized data.
		static ByteVector To(T enumInstance)
		{
			return ByteVector::Create(static_cast<std::underlying_type_t<T>>(enumInstance));
		}

		/// Get size required after serialization.
		/// @return size_t. Number of bytes used after serialization.
		constexpr static size_t Size()
		{
			return sizeof(std::underlying_type_t<T>);
		}

		/// Deserialize from ByteView.
		/// @param bv. Buffer with serialized data.
		/// @return enum.
		static T From(ByteView& bv)
		{
			return static_cast<T>(bv.Read<std::underlying_type_t<T>>());
		}
	};

	/// ByteConverter specialization for iterable types.
	template <typename T>
	struct ByteConverter<T, std::enable_if_t<Utils::Container::IsIterable<T>::value>>
	{
		/// Serialize iterable type to ByteVector.
		/// @param obj. Object to be serialized.
		/// @return ByteVector. Serialized data.
		static ByteVector To(T const& obj)
		{
			auto ret = ByteVector{};
			ret.reserve(ByteVector::Size(obj));
			if (auto numberOfElements = Utils::Container::Size<T>::Calculate(obj); numberOfElements <= std::numeric_limits<uint32_t>::max())
				ret.Write(static_cast<uint32_t>(numberOfElements));
			else
				throw std::out_of_range{ OBF(": Cannot write size to ByteVector ") };

			for (auto&& e : obj)
				ret.Write(e);

			return ret;
		}

		/// Get size required after serialization.
		/// @return size_t. Number of bytes used after serialization.
		static size_t Size(T const& obj)
		{
			using Element = Utils::Container::StoredValue<T>;
			auto ret = sizeof(uint32_t);
			if constexpr (ByteSizeFunctionType<Element>::value == ByteSizeFunctionType<Element>::compileTime)
				ret += ByteConverter<Element>::Size() * obj.size(); // avoid extra calls when size of stored type is known at compile time
			else
				for (auto const& e : obj)
					ret += ByteVector::Size(e);

			return ret;
		}

		/// Deserialize from ByteView.
		/// Writing to ByteVector is similar for any iterable type, but container construction can heavily differ.
		/// Utils::Container::Generator is used for unification of this process.
		/// @param bv. Buffer with serialized data.
		/// @return iterable type.
		static T From(ByteView& bv)
		{
			if (sizeof(uint32_t) > bv.size())
				throw std::out_of_range{ OBF(": Cannot read size from ByteView ") };

			if constexpr (Utils::Container::GeneratorSignature<T>::value == Utils::Container::GeneratorSignature<T>::queuedAccess)
			{
				return Utils::Container::Generator<T>{}(bv.Read<uint32_t>(),  [&bv] { return bv.Read<Utils::Container::StoredValue<T>>(); } );
			}
			else if constexpr (Utils::Container::GeneratorSignature<T>::value == Utils::Container::GeneratorSignature<T>::directMemoryAccess)
			{
				auto size = bv.Read<uint32_t>();
				auto data = bv.data();
				auto ret = Utils::Container::Generator<T>{}(size, reinterpret_cast<const char**>(&data));
				bv.remove_prefix(data - bv.data());
				return ret;
			}

			static_assert(Utils::Container::GeneratorSignature<T>::value != Utils::Container::GeneratorSignature<T>::other, "Unable to find container generator for provided type");
		}
	};

	/// ByteConverter specialization for std::filesystem::path.
	template <>
	struct ByteConverter<std::filesystem::path>
	{
		/// Serialize path type to ByteVector.
		/// @param pathInstance. Object to be serialized.
		/// @return ByteVector. Serialized data.
		static ByteVector To(std::filesystem::path const& pathInstance)
		{
			return ByteVector::Create(pathInstance.wstring());
		}

		/// Get size required after serialization.
		/// @param pathInstance. Instance for which size should be found.
		/// @return size_t. Number of bytes used after serialization.
		static size_t Size(std::filesystem::path const& pathInstance)
		{
			return ByteVector::Size(pathInstance.wstring());
		}

		/// Deserialize from ByteView.
		/// @param bv. Buffer with serialized data.
		/// @return std::filesystem::path.
		static std::filesystem::path From(ByteView& bv)
		{
			return { bv.Read<std::wstring>() };
		}
	};

	/// Tag allowing reading N bytes from ByteView.
	/// Provides simpler way of joining multiple reads than ByteView::Reed(size_t).
	/// @code someByteViewObject.Read<int, int, Bytes<7>, std::string> @endCode
	/// Size must be known at compile time.
	/// Using Bytes class in read will return ByteView, or ByteVector, depending on HardCopy template argument.
	template<size_t N, bool HardCopy = false>
	class Bytes
	{
		/// This class should never be instantiated.
		Bytes() = delete;
		static constexpr bool Copy = HardCopy;
	};

	/// Tag always coping data.
	template<size_t N>
	using BytesCopy = Bytes<N, true>;

	/// ByteConverter specialization for FSecure::Bytes.
	template <size_t N, bool HardCopy>
	struct ByteConverter<Bytes<N, HardCopy>>
	{
		/// Retrieve ByteView substring with requested size.
		/// @param bv. Buffer with serialized data. Will be moved by N bytes.
		/// @return ByteView new view with size equal to N.
		static auto From(ByteView& bv) -> std::conditional_t<HardCopy, ByteVector, ByteView>
		{
			if (N > bv.size())
				throw std::out_of_range{ OBF(": Cannot read data from ByteView") };

			auto retVal = bv.SubString(0, N);
			bv.remove_prefix(N);
			return retVal;
		}
	};

	/// ByteConverter specialization for tuple.
	template <typename T>
	struct ByteConverter<T, std::enable_if_t<Utils::IsTuple<T>>>
	{
		/// Serialize tuple type to ByteVector.
		/// @param tupleInstance. Object to be serialized.
		/// @return ByteVector. Serialized data.
		static ByteVector To(T const& tupleInstance)
		{
			ByteVector ret;
			ret.reserve(Size(tupleInstance));
			TupleHandler<T>::Write(ret, tupleInstance);
			return ret;
		}

		/// Get size required after serialization.
		/// @param tupleInstance. Instance for which size should be found.
		/// @return size_t. Number of bytes used after serialization.
		static size_t Size(T const& tupleInstance)
		{
			return TupleHandler<T>::Size(tupleInstance);
		}


		/// Deserialize from ByteView.
		/// @param bv. Buffer with serialized data.
		/// @return std::tuple.
		static auto From(ByteView& bv)
		{
			return TupleHandler<T>::ReadExplicit(bv);
		}

	private:
		/// @tparam T. Tuple type to read/write.
		/// @tparam N. How many elements of tuple to handle. Functions will use recursion, decrementing N with each call.
		template <typename T, size_t N = std::tuple_size_v<T>>
		struct TupleHandler
		{
			/// Function responsible for recursively packing data to ByteVector.
			/// @param self. Reference to ByteVector object using TupleHandler.
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
			/// @param t. reference to tuple.
			/// @return size_t number of bytes needed.
			static size_t Size(T const& t)
			{
				if constexpr (N != 0)
					return ByteVector::Size(std::get<std::tuple_size_v<T> - N>(t)) + TupleHandler<T, N - 1>::Size(t);
				else
					return 0;
			}

			/// C++ allows cast from pair to tuple of two, but not other way around.
			/// This is oversight, because pair is much older concept than tuple, and no proposition was made to expand old type.
			/// This function ensures, that TupleHandler always returns requested type, so no cast is necessary.
			static T ReadExplicit(ByteView& self)
			{
				auto tmp = Read(self);
				if constexpr (Utils::IsPair<T>)
					return { std::get<0>(tmp), std::get<1>(tmp) };
				else
					return tmp;
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
