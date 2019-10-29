#pragma once

namespace MWR::C3::Linter
{
	class Form
	{
	public:
		Form(json argumentForm);

		json FillForm(InputVector input);

		StringVector GetComplementaryArgs(json const& form);

	private:
		json m_ArgumentsForm;
	};
}

