#pragma once

namespace MWR::C3::Linter
{
	class Form
	{
	public:
		Form(json argumentForm);

		json FillForm(InputVector input);

	private:
		json m_ArgumentsForm;
	};
}

