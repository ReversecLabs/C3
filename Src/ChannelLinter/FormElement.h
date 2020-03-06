#pragma once

namespace FSecure::C3::Linter
{
	/// Abstract form element
	class FormElement
	{
	public:
		/// Type of form argument
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

		/// Destructor
		virtual ~FormElement() = default;

		/// Validate input against argument and set as value
		virtual void ValidateAndSet(std::string_view input) = 0;

	protected:
		/// Protected constructor - Create an abstract element
		/// @param reference to argument definition
		FormElement(json& definition);

		/// reference to argument definition
		json& m_Definition;
	};

	/// Factory method to create form elements of appropriate type
	/// @param reference to argument definition
	std::unique_ptr<FormElement> MakeFormElement(json& element);
}
