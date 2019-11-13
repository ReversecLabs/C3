#include "StdAfx.h"
#include "FormElement.h"

namespace MWR::C3::Linter
{
	namespace
	{
		inline void CheckLengthConstraint(json const& definition, std::string_view input)
		{
			if (definition.contains("min") && input.length() < definition["min"].get<size_t>())
				throw std::invalid_argument("Input \""s + std::string(input) + "\" too short for argument " + definition.at("name").get<std::string>() + ". (min = " + std::to_string(definition["min"].get<size_t>()) + ", actual = " + std::to_string(input.length()) + ')');

			if (definition.contains("max") && input.length() > definition["max"].get<size_t>())
				throw std::invalid_argument("Input \""s + std::string(input) + "\" too long for argument " + definition.at("name").get<std::string>() + ". (max = " + std::to_string(definition["max"].get<size_t>()) + ", actual = " + std::to_string(input.length()) + ')');
		}

		template<typename Numeric>
		void CheckValueConstraint(json const& definition, Numeric value)
		{
			if (definition.contains("min") && value < definition["min"])
				throw std::invalid_argument("Value too low for argument " + definition.at("name").get<std::string>() + ". (min = " + std::to_string(definition["min"].get<Numeric>()) + ", actual = " + std::to_string(value) + ')');

			if (definition.contains("max") && value > definition["max"])
				throw std::invalid_argument("Value too high for argument " + definition.at("name").get<std::string>() + ". (min = " + std::to_string(definition["min"].get<Numeric>()) + ", actual = " + std::to_string(value) + ')');
		};

		class BooleanFormElement : public FormElement
		{
		public:
			BooleanFormElement(json& element) : FormElement(element)
			{
			}

			void ValidateAndSet(std::string_view input) override
			{
				std::string lowercase(input);
				std::transform(lowercase.begin(), lowercase.end(), lowercase.begin(), ::tolower);
				auto trueOptions = { "true", "yes", "y", "1" };
				m_Definition["value"] = std::any_of(begin(trueOptions), end(trueOptions), [&lowercase](auto&& trueOption) {return lowercase == trueOption; });
			}
		};

		class StringFormElement : public FormElement
		{
		public:
			StringFormElement(json& element) : FormElement(element)
			{
			}

			void ValidateAndSet(std::string_view input) override
			{
				CheckLengthConstraint(m_Definition, input);
				m_Definition["value"] = input;
			}
		};

		class IpFormElement : public FormElement
		{
		public:
			IpFormElement(json& element) : FormElement(element)
			{
			}

			void ValidateAndSet(std::string_view input) override
			{
				if (!IsIpV4(std::string(input)))
					throw std::invalid_argument("Failed to IPv4 value from input ("s + std::string(input) + ')');
				m_Definition["value"] = input;
			}

			static bool IsIpV4(std::string const& input)
			{
				sockaddr_in client;
				client.sin_family = AF_INET;
				switch (InetPtonA(AF_INET, input.c_str(), &client.sin_addr.s_addr))
				{
				case 1:
					return true;
				default:
					return false;
				}
			}
		};

		class BinaryFormElement : public FormElement
		{
		public:
			BinaryFormElement(json& element) : FormElement(element)
			{
			}

			void ValidateAndSet(std::string_view input) override
			{
				auto decoded = base64::decode<std::string>(input);
				CheckLengthConstraint(m_Definition, decoded);
				m_Definition["value"] = input;
			}
		};

		template<typename Numeric>
		class NumericFormElement : public FormElement
		{
		public:
			NumericFormElement(json& element) : FormElement(element)
			{
			}

			using NumericType = Numeric;
			void ValidateAndSet(std::string_view input) override
			{
				NumericType value;
				auto x = std::from_chars(input.data(), input.data() + input.size(), value);
				if (x.ptr != input.data() + input.size())
					throw std::invalid_argument("Failed to read numeric value from input \""s + std::string(input) + '"');
				CheckValueConstraint(m_Definition, value);
				m_Definition["value"] = value;
			}
		};
	}

	FormElement::FormElement(json& definition) :
		m_Definition(definition)
	{
		if (!m_Definition.contains("name"))
			throw std::invalid_argument{ "Form element must contain 'name' property." };
	}

	NLOHMANN_JSON_SERIALIZE_ENUM
	(
		FormElement::Type,
		{
			{FormElement::Type::Unknown, nullptr},
			{FormElement::Type::Uint8, "uint8"},
			{FormElement::Type::Uint16, "uint16"},
			{FormElement::Type::Uint32, "uint32"},
			{FormElement::Type::Uint64, "uint64"},
			{FormElement::Type::Int8, "int8"},
			{FormElement::Type::Int16, "int16"},
			{FormElement::Type::Int32, "int32"},
			{FormElement::Type::Int64, "int64"},
			{FormElement::Type::Float, "float"},
			{FormElement::Type::Boolean, "boolean"},
			{FormElement::Type::String, "string"},
			{FormElement::Type::Ip, "ip"},
			{FormElement::Type::Binary, "binary"},
		}
	);

	std::unique_ptr<FormElement> MakeFormElement(json& element)
	{
		if (!element.is_object())
			throw std::invalid_argument { "Form element must be a json object." };
		if (!element.contains("type"))
			throw std::invalid_argument{ "Form element must contain 'type' property." };

		switch (element["type"].get<FormElement::Type>())
		{
		case FormElement::Type::Uint8:
			return std::make_unique<NumericFormElement<uint8_t>>(element);
		case FormElement::Type::Uint16:
			return std::make_unique<NumericFormElement<uint16_t>>(element);
		case FormElement::Type::Uint32:
			return std::make_unique<NumericFormElement<uint32_t>>(element);
		case FormElement::Type::Uint64:
			return std::make_unique<NumericFormElement<uint64_t>>(element);
		case FormElement::Type::Int8:
			return std::make_unique<NumericFormElement<int8_t>>(element);
		case FormElement::Type::Int16:
			return std::make_unique<NumericFormElement<int16_t>>(element);
		case FormElement::Type::Int32:
			return std::make_unique<NumericFormElement<int32_t>>(element);
		case FormElement::Type::Int64:
			return std::make_unique<NumericFormElement<int64_t>>(element);
		case FormElement::Type::Float:
			return std::make_unique<NumericFormElement<float>>(element);
		case FormElement::Type::Boolean:
			return std::make_unique<BooleanFormElement>(element);
		case FormElement::Type::String:
			return std::make_unique<StringFormElement>(element);
		case FormElement::Type::Ip:
			return std::make_unique<IpFormElement>(element);
		case FormElement::Type::Binary:
			return std::make_unique<BinaryFormElement>(element);
		default:
			throw std::runtime_error("Unknown form argument type: \"" + element["type"].get<std::string>() + '"');
		}
	}

	void ValidateAndSet(json& element, std::string_view input)
	{
		auto formElement = MakeFormElement(element);
		formElement->ValidateAndSet(input);
	}

}
