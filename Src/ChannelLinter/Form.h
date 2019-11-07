#pragma once

namespace MWR::C3::Linter
{
	class Form
	{
	public:
		Form(json argumentForm);

		json FillForm(InputVector input);

		StringVector GetComplementaryArgs(StringVector input);

	private:
		// TODO Form should contain a list of form elements (validated), not just a json
		json m_ArgumentsForm;
	};
}

