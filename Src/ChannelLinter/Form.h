#pragma once

namespace MWR::C3::Linter
{
	/// Representation of arguments form used in Capability json
	class Form
	{
	public:
		/// Create a form from json definition
		/// @param arguments form definition
		Form(json argumentForm);

		/// Copy constructor
		Form(Form const& other) noexcept;

		/// Copy assignment
		Form& operator=(Form const& other) noexcept;

		/// Move constructor
		Form(Form&& other) noexcept = default;

		/// Move assignment
		Form& operator=(Form&& other) noexcept = default;

		/// Fill and validate form with given arguments
		/// @returns json representation of filled form
		json Fill(StringVector const& input);

		/// Convert arguments to complementary (right shift argument groups)
		/// @param string representation of arguments
		/// @returns Complementary arguments
		StringVector GetComplementaryArgs(StringVector input);

	private:
		/// Internal store of json definition
		json m_ArgumentsForm;

		/// Vector of FormElements used to validate form definition
		std::vector<std::unique_ptr<FormElement>> m_Elements;
	};
}

