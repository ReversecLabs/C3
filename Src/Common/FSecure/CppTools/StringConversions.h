#pragma once

#include <string>
#include <string_view>
#include <utility>
#include <cuchar>
#include <locale>
#include <algorithm>
#include <stdexcept>

#ifndef OBF
#	define OBF(x) x
#endif // !OBF

/// String conversions.
namespace FSecure::StringConversions
{
	/// Tags for Convert function.
	namespace Tags
	{
		struct Lowercase;
		struct Uppercase;
		using Utf8 = std::string;
		using Utf16 = std::wstring;
		struct Hex;
		struct UnHex;
	}

	/// For convenience.
	using namespace Tags;

	/// Namaspace of helpers used by FSecure::StringConversions functions.
	namespace Detail
	{
		/// Detect character type stored by container.
		template <typename T>
		using CharT = std::remove_const_t<std::remove_reference_t<decltype(std::declval<T>()[0])>>;

		/// Detect view type corresponding to container.
		template <typename T>
		using ViewT = std::basic_string_view<CharT<T>>;

		/// Divide and round up
		template <typename T>
		T DivideCeil(T x, T y)
		{
			return (x + y - 1) / y;
		}

		/// Create new container using static_cast on each field of input container.
		template <typename OutContainer, typename InContainer>
		OutContainer ContainerStaticCast(InContainer const& arg)
		{
			OutContainer ret;
			ret.reserve(arg.size());
			for (auto e : arg)
				ret.push_back(static_cast<typename OutContainer::value_type>(e));
			return ret;
		}

		/// Declaration of base template.
		/// Overwrite it for specific tag.
		template<typename Tag, typename = void>
		struct ConvertStruct;

		/// Convert to Utf8.
		template <>
		struct ConvertStruct<Tags::Utf8>
		{
			/// Identity conversion.
			static auto Convert(std::string_view str)
			{
				return std::string{ str };
			}

			/// Convert wstring to string.
			static auto Convert(std::wstring_view str)
			{
				auto state = std::mbstate_t{};
				std::string ret;
				for (auto c : str)
				{
					char out[MB_LEN_MAX] = {};	// reset each time, because next string can be shorter than the previous one.
					auto converted = static_cast<char>(std::c16rtomb(out, c, &state));
					if (converted == -1)
						throw  std::runtime_error{ OBF("String is not UTF16") };

					if (!out[0] && converted)
						ret.push_back(out[0]);	// ensure that terminator is pushed to string. c16rtomb will also return 0. Avoid false terminator, when c16rtomb handles surrogate pair
					else
						ret.append(out);		// append transformed characters.
				}

				return ret;
			}
		};

		/// Convert to Utf16.
		template <>
		struct ConvertStruct<Tags::Utf16>
		{
			/// Identity conversion.
			static auto Convert(std::wstring_view str)
			{
				return  std::wstring{ str };
			}

			/// Convert string to wstring.
			static auto Convert(std::string_view str)
			{
				auto state = std::mbstate_t{};
				auto ptr = &str[0], end = &str[0] + str.size();
				char16_t out;
				std::wstring ret;
				while (ptr != end)
				{
					auto consumed = static_cast<char>(std::mbrtoc16(&out, ptr, end - ptr, &state));
					switch (consumed)
					{
					case -3:
						break;					// handle next character of surrogate pair.
					case -2:
					case -1:
						throw  std::runtime_error{ OBF("String is not UTF8") };
					case 0:
						ptr += 1;				// handle terminator, move ptr by one character.
						break;
					default:
						ptr += consumed;		// handle parsed chunk, move ptr.
					}
					ret.push_back(static_cast<wchar_t>(out));
				}

				// Handle last character being surrogate pair.
				if (static_cast<char>(std::mbrtoc16(&out, "", 0, &state)) == -3)
					ret.push_back(static_cast<wchar_t>(out));

				return ret;
			}
		};

		/// Default implementation of transform functionality. Works only for case transformation.
		template<typename Tag>
		struct ConvertStruct<Tag, std::enable_if_t<std::is_same_v<Tag, Tags::Lowercase> || std::is_same_v<Tag, Tags::Uppercase>>>
		{
			/// Convert utf16 case.
			static auto Convert(std::wstring_view str)
			{
				auto ret = std::wstring{ str };
				std::transform(ret.begin(), ret.end(), ret.begin(),
					[&, loc = std::locale{ "" }](auto c)
				{
					if constexpr (std::is_same_v<Tag, Tags::Uppercase>)
						return std::toupper(c, loc);
					else
						return std::tolower(c, loc);
				});

				return ret;
			}

			/// Convert utf8 case.
			static auto Convert(std::string_view str)
			{
				// Expensive, replace if the standard will add better way of utf8 transformation.
				return ConvertStruct<Utf8>::Convert(Convert(ConvertStruct<Utf16>::Convert(str)));
			}
		};

		char const HexChars[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

		/// Convert to hex.
		template <>
		struct ConvertStruct<Tags::Hex>
		{
			static auto Convert(std::string_view str)
			{
				std::string ret;
				ret.reserve(2 * str.size());
				for (auto byte : str)
				{
					ret += HexChars[(byte & 0xF0) >> 4];
					ret += HexChars[(byte & 0x0F) >> 0];
				}

				return ret;
			}

			static auto Convert(std::wstring_view str)
			{
				// Preserves machine endianness. May always be worth converting to big endian.
				auto ret = Convert(std::string_view{ reinterpret_cast<char const*>(str.data()), str.size() * 2 });
				return std::wstring{ ret.begin(), ret.end() };
			}
		};

		/// Retrieve from Hex.
		/// @note Sequence of hex, UnhHex is important.
		/// `Utf8, Hex, Utf16, UnHex` will change string into incorrect one.
		/// `Utf8, Hex, Utf16, Utf8, UnHex` will preserve correct data.
		/// `Utf8, Hex, Utf16, UnHex, Hex, Utf8, UnHex` will preserve correct data.
		template <>
		struct ConvertStruct<Tags::UnHex>
		{
			static auto Convert(std::string_view str)
			{
				auto size = str.size();
				if (size % 2 != 0)
					throw std::runtime_error{ OBF("String is not hex - incorrect size: ") + std::to_string(size) };

				auto ret = std::string{};
				ret.reserve(size / 2);

				auto decode = [str](size_t pos)
				{
					if (std::isdigit(str[pos]))
						return str[pos] - '0';

					if (str[pos] >= 'A' && str[pos] <= 'F')
						return str[pos] + 10 - 'A';

					if (str[pos] >= 'a' && str[pos] <= 'f')
						return str[pos] + 10 - 'a';

					throw std::runtime_error{ OBF("String is not hex - incorrect character at position: ") + std::to_string(pos) };
				};

				for (size_t i = 0u; i < size; i += 2)
					ret.push_back(static_cast<uint8_t>(decode(i)) << 4 | static_cast<uint8_t>(decode(i + 1)));

				return ret;
			}

			static auto Convert(std::wstring_view str)
			{
				auto raw = Convert(ContainerStaticCast<std::string>(str));
				auto size = raw.size();
				auto ret = std::wstring(DivideCeil(size, sizeof(wchar_t)), L'\0');
				for (size_t i = 0; i < size; ++i)
					ret[i / sizeof(wchar_t)] |= static_cast<uint8_t>(raw[i]) <<  i % sizeof(wchar_t) * 8;

				return ret;
			}
		};
	}

	/// Convert data according to provided tag.
	template<typename Tag, typename ...RestTags, typename ArgT>
	auto Convert(ArgT const& str)
	{
		auto ret = Detail::ConvertStruct<Tag>::Convert(Detail::ViewT<ArgT>{ &str[0], std::size(str) });
		if constexpr (sizeof...(RestTags) == 0)
			return ret;
		else
			return Convert<RestTags...>(ret);
	}
}
