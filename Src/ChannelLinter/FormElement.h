#pragma once

namespace MWR::C3::Linter
{
	class FormElement
	{
	public:
		enum class Type
		{
			Unknown = 0,
			Uint8,
			Uint16,
			Uint32,
			Uint64,
			Int8,
			Int16,
			Int32,
			Int64,
			Float,
			Boolean,
			String,
			Ip,
			Binary,
		};

		virtual void ValidateAndSet(std::string_view input) = 0;

	protected:
		FormElement(json& definition);

		json& m_Definition;
	};

	std::unique_ptr<FormElement> MakeFormElement(json& element);

	void ValidateAndSet(json& element, std::string_view input);
}
