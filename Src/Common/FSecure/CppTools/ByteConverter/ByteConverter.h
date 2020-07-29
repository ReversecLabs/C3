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
		/// @param bv. ByteVector to be expanded.
		static void To(T obj, ByteVector& bv)
		{
			auto oldSize = bv.size();
			bv.resize(oldSize + Size());
			*reinterpret_cast<T*>(bv.data() + oldSize) = obj;
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
			memcpy(&ret, bv.data(), Size());
			bv.remove_prefix(Size());
			return ret;
		}
	};

	/// ByteConverter specialization for enum.
	template <typename T>
	struct ByteConverter<T, std::enable_if_t<std::is_enum_v<T>>>
	{
		/// Serialize enum type to ByteVector.
		/// @param enumInstance. Object to be serialized.
		/// @param bv. ByteVector to be expanded.
		static void To(T enumInstance, ByteVector& bv)
		{
			bv.Store(static_cast<std::underlying_type_t<T>>(enumInstance));
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
		/// @param bv. ByteVector to be expanded.
		static void To(T const& obj, ByteVector& bv)
		{
			if (auto numberOfElements = Utils::Container::Size<T>::Calculate(obj); numberOfElements <= std::numeric_limits<uint32_t>::max())
				bv.Write(static_cast<uint32_t>(numberOfElements));
			else
				throw std::out_of_range{ OBF(": Cannot write size to ByteVector ") };

			for (auto&& e : obj)
				bv.Write(e);
		}

		/// Get size required after serialization.
		/// @return size_t. Number of bytes used after serialization.
		static size_t Size(T const& obj)
		{
			using Element = Utils::Container::StoredValue<T>;
			auto ret = sizeof(uint32_t);
			if constexpr (ConverterDeduction<Element>::FunctionSize::value == ConverterDeduction<Element>::FunctionSize::compileTime)
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
		/// @param bv. ByteVector to be expanded.
		static void To(std::filesystem::path const& pathInstance, ByteVector& bv)
		{
			bv.Store(pathInstance.wstring());
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
		/// @param bv. ByteVector to be expanded.
		static void To(T const& tupleInstance, ByteVector& bv)
		{
			TupleHandler<T>::Write(bv, tupleInstance);
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
			static void Write([[maybe_unused]] ByteVector& self, [[maybe_unused]] T const& t)
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
			static size_t Size([[maybe_unused]] T const& t)
			{
				if constexpr (N != 0)
					return ByteVector::Size(std::get<std::tuple_size_v<T> - N>(t)) + TupleHandler<T, N - 1>::Size(t);
				else
					return 0;
			}

			/// C++ allows cast from pair to tuple of two, but not other way around.
			/// This is oversight, because pair is much older concept than tuple, and no proposition was made to expand old type.
			/// This function ensures, that TupleHandler always returns requested type, so no cast is necessary.
			static auto ReadExplicit(ByteView& self)
			{
				auto tmp = Read(self);
				if constexpr (Utils::IsPair<T>)
					return std::pair{ std::get<0>(tmp), std::get<1>(tmp) };
				else
					return tmp;
			}

			/// Function responsible for recursively packing data to tuple.
			/// @param self. Reference to ByteView object using generate method.
			static auto Read(ByteView& self)
			{
				if constexpr (N != 0)
				{
					auto current = std::make_tuple(self.Read<Utils::RemoveCVR<std::tuple_element_t<std::tuple_size_v<T> - N, T>>>());
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

	/// @brief Class providing simple way of generating ByteConverter of custom types by treating them as tuple.
	/// ByteConverter can use this functionality by inheriting from TupleConverter and providing
	/// public static std::tuple<...> Convert(T const&) method.
	/// Use Utils::MakeConversionTuple to create efficient tuple of value or references to members.
	/// ByteVector can declare its own versions of To/From/Size methods if it needs dedicated logic to serialize type.
	/// @tparam T Type for serialization.
	template <typename T>
	struct TupleConverter
	{
	private:
		/// @brief Type returned by ByteConverter<C>::Convert.
		/// ByteConverter<C> specialization may not yet be defined.
		/// This type must be deduced late in instantiation procedure.
		/// @tparam C Type for serialization.
		template <typename C>
		using ConvertType = decltype(ByteConverter<C>::Convert(std::declval<C>()));

		/// @brief Helper class compatible with Utils::Apply. Checks if size after serialization, of all tuple types, can be determined at compile time.
		struct IsSizeConstexpr
		{
			template <typename ...Ts>
			static constexpr auto Apply()
			{
				return ((ConverterDeduction<Ts>::FunctionSize::value == ConverterDeduction<Ts>::FunctionSize::compileTime) && ...);
			}
		};

		/// @brief Helper class compatible with Utils::Apply. Determines size after serialization, of all tuple types.
		struct GetConstexprSize
		{
			template <typename ...Ts>
			static constexpr auto Apply()
			{
				return ((ByteConverter<Ts>::Size() + ...));
			}
		};

		/// @brief This class is designed for lazy evaluation of ConvertType<T> for IsSizeConstexpr template.
		/// If used for SFINAE, ConvertType will break compilation, at not defined Convert function.
		/// MSVC is evaluating default template parameter when, and only if, it is used. This behavior results in successful compilation
		/// Strict compilers like clang or gcc would evaluate ConvertType before correct ByteConverter specialization is provided.
		/// With this template, instantiation point is delayed, until Convert method is reachable in function lookup.
		/// @tparam C Type for serialization.
		template <typename C>
		class IsSizeConstexprLazy
		{
			template <typename S> static uint16_t test(std::enable_if_t<Utils::Apply<IsSizeConstexpr, ConvertType<S>>::value, int>);
			template <typename S> static uint8_t test(...);

		public:
			static constexpr bool value = sizeof(test<C>(0)) == sizeof(uint16_t);
		};

	public:
		/// @brief Use it to convert raw data into tuple.
		/// Allows splitting deserialization into two phases.
		/// 1. Retrieve data as tuple. ByteView internal pointer will be correctly moved in the process.
		/// 2. Create dedicated logic of transforming tuple into desired type.
		/// @param bv. Buffer with serialized data.
		/// @return tuple of retrieved data for type construction.
		static auto Convert(ByteView& bv)
		{
			return bv.Read<ConvertType<T>>();
		}

		// From this point forward will be implemented ByteConverter standard interface methods.

		/// @brief Default implementation of To method.
		/// Serializes data treating it as tuple generated by Convert.
		/// @param obj Object for serialization.
		/// @param bv output ByteVector with already allocated memory for data.
		static void To(T const& obj, ByteVector& bv)
		{
			bv.Store(ByteConverter<T>::Convert(obj));
		}

		/// @brief Default implementation of From method.
		/// Retrieves data from view and creates new object by passing tuple as arguments for T{...} construction.
		/// This implementation uses brace enclosed construction, becouse std::make_from_tuple does not support trivial types.
		/// Bear in mind that construction with parentheses, and with braces, is not interchangeable.
		/// @param bv. Buffer with serialized data.
		/// @return constructed type.
		static T From(ByteView& bv)
		{
			return std::apply(Utils::Construction::Braces<T>{}, Convert(bv));
		}

		/// @brief Default implementation of Size method with compile time evaluation.
		/// @note All template parameters are used only to determine if function should be defined.
		/// @return size_t. Number of bytes used after serialization.
		template <typename C = T, std::enable_if_t<IsSizeConstexprLazy<C>::value, int> = 0>
		static constexpr size_t Size()
		{
			return Utils::Apply<GetConstexprSize, ConvertType<T>>::value;
		}

		/// @brief Default implementation of Size method.
		/// @param obj Object for serialization.
		/// @note All template parameters are used only to determine if function should be defined.
		/// @return size_t. Number of bytes used after serialization.
		template <typename C = T, std::enable_if_t<!IsSizeConstexprLazy<C>::value, int> = 0>
		static size_t Size(T const& obj)
		{
			return ByteVector::Size(ByteConverter<T>::Convert(obj));
		}
	};

	/// @brief Class providing simple way of generating ByteConverter listing only necessary members once.
	/// ByteConverter can use this functionality by inheriting from PointerTupleConverter and providing
	/// public static std::tuple<T::*...> MemberPointers() method.
	/// Use std::make_tuple to create return value out of member list.
	/// ByteVector can declare its own versions of To/From/Size methods if it needs dedicated logic to serialize type.
	/// @tparam T Type for serialization.
	template <typename T>
	struct PointerTupleConverter : TupleConverter<T>
	{
	private:
		/// @brief Class applying pointers to members to object.
		/// Compatible with std::apply.
		/// Creates TupleConverter<T>::ConvertType object.
		class ReferenceMembers
		{
			T const& m_Obj;
		public:
			ReferenceMembers(T const& obj) : m_Obj{ obj } {}

			template <typename ... Ts>
			auto operator () (Ts T::*...ts) const
			{
				return Utils::MakeConversionTuple(m_Obj.*ts ...);
			}
		};

		/// @brief Function assigning object members with tuple of values using tuple member pointers.
		/// @tparam PtrTpl Tuple of pointers to members type.
		/// @tparam ValueTpl Tuple of values type.
		/// @tparam Is Index sequence used to match tuples one to one.
		/// @param obj Object to be assigned.
		/// @param ptrTpl Tuple of pointers to members.
		/// @param valueTpl Tuple of values.
		template <typename PtrTpl, typename ValueTpl, size_t ...Is>
		static void AssignToMembers(T& obj, PtrTpl const& ptrTpl, ValueTpl valueTpl, std::index_sequence<Is...>)
		{
			((obj.*(std::get<Is>(ptrTpl)) = std::move(std::get<Is>(valueTpl))), ...);
		}

	public:
		/// @brief Default implementation of Convert method used by TupleConverter for serialization.
		/// Function uses ByteConverter<T>::MemberPointers() to reference T object members.
		/// @param obj object to be serialized.
		/// @return TupleConverter<T>::ConvertType values to be serialized.
		static auto Convert(T const& obj)
		{
			auto ptrTpl = ByteConverter<T>::MemberPointers();
			return std::apply(ReferenceMembers{ obj }, ptrTpl);
		}

		/// @brief Shadowed TupleConverter<T>::From initalizing only selected members, skipped ones will be default initialized.
		/// @note T must have default constructor.
		/// @param bv. Buffer with serialized data.
		/// @return constructed type.
		static T From(ByteView& bv)
		{
			auto ret = T{};
			auto ptrTpl = ByteConverter<T>::MemberPointers();
			auto valueTpl = TupleConverter<T>::Convert(bv);
			AssignToMembers(ret, ptrTpl, std::move(valueTpl), std::make_index_sequence<std::tuple_size<decltype(ptrTpl)>::value>{});
			return ret;
		}
	};
}
