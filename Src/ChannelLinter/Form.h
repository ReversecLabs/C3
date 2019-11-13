#pragma once

namespace MWR::C3::Linter
{
	class Form
	{
	public:
		Form(json argumentForm);

		Form(Form const& other) noexcept;
		Form& operator=(Form const& other) noexcept;
		Form(Form&& other) noexcept = default;
		Form& operator=(Form&& other) noexcept = default;

		json Fill(StringVector input);

		StringVector GetComplementaryArgs(StringVector input);

	private:
		json m_ArgumentsForm;
		std::vector<std::unique_ptr<FormElement>> m_Elements;
	};
}

