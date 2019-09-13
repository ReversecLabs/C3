#pragma once

#include "ByteVector.h"

namespace MWR
{
	/// Function splitting string.
	///
	/// @tparam copy. Indicates should strings be copied.
	/// @param stringToBeSplitted initial string to be tokenized.
	/// @param delimiter to be searched in string.
	/// @throws std::runtime_error if delimiter empty or greatter equal to stringToBeSplitted
	/// @returns std::vector<std::string> or std::vector<std::string_view> depending on copy flag.
	template<bool copy = false>
	std::vector<std::conditional_t<copy, std::string, std::string_view>> Split(std::string_view stringToBeSplitted, std::string_view delimiter)
	{
		if (delimiter.empty() && delimiter.size() >= stringToBeSplitted.size())
			throw std::runtime_error{ OBF("Delimiter size is incorrect") };

		using ReturnType = decltype(Split<copy>(stringToBeSplitted, delimiter));
		ReturnType splittedString;
		// startIndex can overflow, endIndex is checked first, and lazy check on startIndex will avoid last empty token.
		for (size_t startIndex = 0u, endIndex = 0u; endIndex < stringToBeSplitted.size() && startIndex < stringToBeSplitted.size(); startIndex = endIndex + delimiter.size())
		{
			endIndex = stringToBeSplitted.find(delimiter, startIndex);

			// skip empty tokens when delimiter is repeated.
			if (endIndex - startIndex)
				splittedString.emplace_back(stringToBeSplitted.substr(startIndex, endIndex - startIndex));
		}

		return splittedString;
	}

	/// Proxy to Split<true>
	///
	/// @param stringToBeSplitted initial string to be tokenized.
	/// @param delimiter to be searched in string.
	/// @throws std::runtime_error if delimiter empty or greatter equal to stringToBeSplitted
	/// @returns std::vector<std::string> tokenized string.
	std::vector<std::string> SplitAndCopy(std::string_view stringToBeSplitted, std::string_view delimiter);

	/// Idiom for detecting ByteView::Get.
	template <typename X>
	constexpr bool IsGetter = false;

	/// Non owning container.
	class ByteView : std::basic_string_view<ByteVector::value_type>
	{
	public:
		/// Privately inherited Type.
		using Super = std::basic_string_view<ByteVector::value_type>;

		/// Type of stored values.
		using ValueType = Super::value_type;

		/// Create from ByteVector.
		/// @param data. Data from which view will be constructed.
		/// @param offset. Offset from first byte of data collection.
		/// @return ByteView. View of data.
		/// @throw std::out_of range. If offset is greater than data.size().
		ByteView(ByteVector const& data, size_t offset = 0);

		/// Create from ByteVector iterators.
		/// @param begin. Iterator to first element of data.
		/// @param end. Iterator to past the last element of data.
		/// @return ByteView. View of data.
		/// @throw std::out_of range. If begin is greater than end.
		ByteView(ByteVector::const_iterator begin, ByteVector::const_iterator end);

		/// Create from std::basic_string_view<uint8_t>.
		/// @param data. Data from which view will be constructed.
		/// @return ByteView. View of data.
		ByteView(std::basic_string_view<ByteVector::value_type> data);

		/// Create from ByteArray.
		/// @param data. Data from which view will be constructed.
		/// @return ByteView. View of data.
		template <size_t N>
		ByteView(ByteArray<N> const& data)
			: Super(data.data(), data.size())
		{

		}

		/// Create from std::string_view.
		/// @param data. Data from which view will be constructed.
		/// @return ByteView. View of data.
		ByteView(std::string_view data);

		/// Allow cast to Privately inherited Type.
		operator Super() const noexcept;

		/// Allow cast to ByteVector.
		operator ByteVector() const;

		/// Allow cast to std::string().
		operator std::string() const;

		/// Allow cast to std::string_view.
		operator std::string_view() const;

		/// Create a sub-string from this ByteView.
/// @param offset. 	Position of the first byte.
/// @param count. Requested length
/// @returns ByteView. View of the substring
		ByteView SubString(const size_type offset = 0, size_type count = npos) const;

		// Enable methods.
		using std::basic_string_view<ByteVector::value_type>::basic_string_view;
		using Super::operator=;
		using Super::begin;
		using Super::cbegin;
		using Super::end;
		using Super::cend;
		using Super::rbegin;
		using Super::crbegin;
		using Super::rend;
		using Super::crend;
		using Super::operator[];
		using Super::at;
		using Super::front;
		using Super::back;
		using Super::data;
		using Super::size;
		using Super::length;
		using Super::max_size;
		using Super::empty;
		using Super::remove_prefix;
		using Super::remove_suffix;
		using Super::swap;
		using Super::copy;
		using Super::compare;
		using Super::find;
		using Super::rfind;
		using Super::find_first_of;
		using Super::find_last_of;
		using Super::find_first_not_of;
		using Super::find_last_not_of;
		using Super::npos;
		using Super::value_type;


		/// @returns ByteVector. Owning container with the read bytes.
		/// @param byteCount. How many bytes should be read.
		/// @remarks Read is not compatible with Read<ByteVector>.
		/// Data stored in ByteVector with Write<ByteVector> should be accessed with Read<ByteVector>
		/// @throws std::out_of_range. If byteCount > size().
		ByteVector Read(size_t byteCount);

		/// Read bytes and remove them from ByteView.
		/// @remarks Read is not compatible with Read<ByteVector>.
		/// Data stored in ByteVector with Write<ByteVector> should be accessed with Read<ByteVector>
		/// @returns T. Owning container with the read bytes.
		/// @throws std::out_of_range. If ByteView is too short to hold size of object to return.
		template<typename T = ByteVector>
		std::enable_if_t<(std::is_same_v<T, ByteVector> || std::is_same_v<T, std::string> || std::is_same_v<T, std::wstring>), T> Read()
		{
			if (sizeof(uint32_t) > size())
				throw std::out_of_range{ OBF(": Cannot read size from ByteView ") };

			auto elementCount = *reinterpret_cast<const uint32_t*>(data());
			auto byteCount = elementCount * sizeof(T::value_type);
			remove_prefix(sizeof(uint32_t));

			T retVal;
			retVal.resize(elementCount);
			std::memcpy(retVal.data(), data(), byteCount);
			remove_prefix(byteCount);
			return retVal;
		}

		/// Read bytes and remove them from ByteView.
		/// This function will return non owning container. It is helpful to prevent coping large buffers, if user know that original container is still valid.
		/// @returns T. Non owning container with the read bytes.
		/// @throws std::out_of_range. If ByteView is too short to hold size of object to return.
		template<typename T>
		std::enable_if_t<(std::is_same_v<T, ByteView> || std::is_same_v<T, std::string_view> || std::is_same_v<T, std::wstring_view>), T> Read()
		{
			if (sizeof(uint32_t) > size())
				throw std::out_of_range{ OBF(": Cannot read size from ByteView ") };

			auto elementCount = *reinterpret_cast<const uint32_t*>(data());
			auto byteCount = elementCount * sizeof(T::value_type);
			remove_prefix(sizeof(uint32_t));

			auto retVal = T{reinterpret_cast<T::value_type const*>(data()), elementCount};
			remove_prefix(byteCount);
			return retVal;
		}

		/// Read bytes and remove them from ByteView.
		/// @returns ByteArray. Owning container with the read bytes.
		/// @throws std::out_of_range. If ByteView is too short to hold size of object to return.
		template<typename T>
		std::enable_if_t<IsByteArray<T>, T> Read()
		{
			if (std::tuple_size<typename T>::value > size())
				throw std::out_of_range{ OBF(": Cannot read data from ByteView") };

			T retVal;
			std::memcpy(retVal.data(), data(), std::tuple_size<typename T>::value);
			remove_prefix(std::tuple_size<typename T>::value);
			return retVal;
		}

		/// Read arithmetic type and remove it from ByteView.
		/// @tparam T. Type to return;
		/// @returns T. Owning container with the read bytes.
		/// @throws std::out_of_range. If sizeof(T) > size().
		template<typename T>
		std::enable_if_t<std::is_arithmetic<T>::value, T> Read()
		{
			if (sizeof(T) > size())
				throw std::out_of_range{ OBF(": Size: ") + std::to_string(size()) + OBF(". Cannot read ") + std::to_string(sizeof(T)) + OBF(" bytes.") };

			auto retVal = *reinterpret_cast<const T*>(data());
			remove_prefix(sizeof(T));
			return retVal;
		}

		/// Read tuple type.
		/// @tparam T. Tuple type to return;
		/// @returns T. Owning container with the read bytes.
		template<typename T>
		std::enable_if_t<IsTuple<T>, T> Read()
		{
			return TupleGenerator<T>::Generate(*this);
		}

		/// Class allowing reading N bytes without coping data like in ByeView::Read<ByteArray<N>> or ByteView::Reed(size_t).
		template <size_t N>
		class Get
		{
		public:
			/// Define size marker.
			static constexpr size_t size = N;
			static constexpr size_t Size = size;

		private:
			/// Private constructor.
			/// This class should never be instantiated.
			Get() = default;
		};

		/// Read bytes and remove them from ByteView.
		/// @returns ByteView. Non owning container with the read bytes.
		/// @throws std::out_of_range. If ByteView is too short to hold size of object to return.
		template<typename T>
		std::enable_if_t<IsGetter<T>, ByteView> Read()
		{
			if (T::Size > size())
				throw std::out_of_range{ OBF(": Cannot read data from ByteView") };

			auto retVal = SubString(0, T::Size);
			remove_prefix(T::Size);
			return retVal;
		}

		/// Read tuple and remove bytes from ByteView.
		/// @tparam T. Parameter pack of types to be stored in tuple. Must consist more then one type. Each of types must be parsable by Reed template for one type.
		/// @returns std::tuple. Tuple will store types provided in parameter pack.
		/// @throws std::out_of_range. If ByteView is too short to possibly store all provided types.
		template<typename ...T, typename std::enable_if_t<(sizeof...(T) > 1), int> = 0>
		auto Read()
		{
			return VariadicTupleGenerator<T...>::Generate(*this);
		}

		/// Template function allowing structured binding to new std::string or std::string_view variables from text stored in ByteView.
		///
		/// auto [a,b] = ToStringArray<2>();
		/// @tparam expectedSize number of words that should be returned from function.
		/// @tparam copy if true words will be copied to std::string variables.
		/// @tparam modifyByteView if true parsed words will be removed from ByteView object.
		/// @returns std::array<std::string, expectedSize> or std::array<std::string_view, expectedSize> array of strings. Size of array is known at compile time.
		/// @throws std::runtime_error if bytes is empty or when bytes does not consist at least expectedSize numer of space separated strings.
		template<size_t expectedSize, bool copy = true, bool modifyByteView = true>
		std::array<std::conditional_t<copy, std::string, std::string_view>, expectedSize> ToStringArray()
		{
			auto splited = Split(*this, OBF(" "));
			if (splited.size() < expectedSize)
				throw std::runtime_error{ OBF("ByteVector does not consist expected number of strings") };

			using ReturnType = decltype(ToStringArray<expectedSize, copy, modifyByteView>());
			ReturnType retValue;
			for (auto i = 0u; i < expectedSize; ++i)
				retValue[i] = splited[i];

			if constexpr (modifyByteView)
				remove_prefix(splited[expectedSize - 1].data() - reinterpret_cast<const char*>(data()) + splited[expectedSize - 1].size());

			return retValue;
		}

	private:
		/// Delegate to class idiom.
		/// Function templates cannot be partially specialized.
		/// @tparam T. First type from parameter pack. Each recursive call will unfold one type.
		/// @tparam Rest. Parameter pack storing rest of provided types.
		template <typename T, typename ...Rest>
		struct VariadicTupleGenerator
		{
			/// Function responsible for recursively packing data to tuple.
			/// @param self. Reference to ByteView object using generate method.
			static auto Generate(ByteView& self)
			{
				auto current = std::make_tuple(self.Read<T>());
				auto rest = VariadicTupleGenerator<Rest...>::Generate(self);
				return std::tuple_cat(std::move(current), std::move(rest));
			}
		};

		/// Delegate to class idiom.
		/// Function templates cannot be partially specialized.
		/// Closure specialization.
		/// @tparam T. Type to be extracted from ByteView and stored in tuple.
		template <typename T>
		struct VariadicTupleGenerator<T>
		{
			/// Function responsible for recursively packing data to tuple.
			/// @param self. Reference to ByteView object using generate method.
			static auto Generate(ByteView& self)
			{
				return std::make_tuple(self.Read<T>());
			}
		};

		/// Delegate to class idiom.
		/// Function templates cannot be partially specialized.
		/// @tparam T. Tuple to be extracted.
		/// @tparam N. How many elements out of tuple to use.
		template <typename T, size_t N = std::tuple_size_v<T>>
		struct TupleGenerator
		{
			/// Function responsible for recursively packing data to tuple.
			/// @param self. Reference to ByteView object using generate method.
			static auto Generate(ByteView& self)
			{
				auto current = std::make_tuple(self.Read<std::tuple_element_t<std::tuple_size_v<T> -N, T>>());
				auto rest = TupleGenerator<T, N - 1>::Generate(self);
				return std::tuple_cat(current, rest);
			}
		};

		/// Delegate to class idiom.
		/// Function templates cannot be partially specialized.
		/// Closure specialization, return empty tuple.
		/// @tparam T. Tuple to be extracted.
		template <typename T>
		struct TupleGenerator<T, 0>
		{
			/// Function responsible for recursively packing data to tuple.
			/// @param self. Reference to ByteView object using generate method.
			static auto Generate(ByteView& self)
			{
				return std::tuple<>{};
			}
		};
	};

	/// Specialization of idiom for detecting ByteView::Get.
	template<size_t N>
	constexpr bool IsGetter<ByteView::Get<N>> = true;

	/// Alias for simpler use of ByteView::Get.
	template<size_t N>
	using Bytes = ByteView::Get<N>;

	namespace Literals
	{
		/// Create ByteView with syntax ""_bvec
		MWR::ByteView operator "" _bv(const char* data, size_t size);

		/// Create ByteView with syntax L""_bvec
		MWR::ByteView operator "" _bv(const wchar_t* data, size_t size);
	}

	/// Template function allowing structured binding to new std::string or std::string_view variables from text command stored in ByteView.
	///
	/// auto [a,b] = ToStringArray<2>(someByteView);
	/// @tparam expectedSize number of words that should be returned from function.
	/// @tparam copy if true words will be copied to std::string variables.
	/// @param bytes ByteView to parse. Strings should be separated with spaces.
	/// @returns std::array<std::string, expectedSize> or std::array<std::string_view, expectedSize> array of strings. Size of array is known at compile time.
	/// @throws std::runtime_error if bytes is empty or when bytes does not consist at least expectedSize numer of space separated strings.
	template<size_t expectedSize, bool copy = true>
	std::array<std::conditional_t<copy, std::string, std::string_view>, expectedSize> ToStringArray(ByteView bytes)
	{
		return bytes.ToStringArray<expectedSize, copy, false>();
	}
}

namespace std
{
	/// Add hashing function for ByteView.
	template <>
	struct hash<MWR::ByteView>
	{
		size_t operator()(MWR::ByteView const& bv) const
		{
			return std::hash<std::string_view>{}(bv);
		}
	};
}
