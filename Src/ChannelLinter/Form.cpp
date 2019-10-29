#include "stdafx.h"
#include "Form.h"

namespace MWR::C3::Linter
{

	Form::Form(json argumentForm) : m_ArgumentsForm(std::move(argumentForm))
	{
	}

	json Form::FillForm(InputVector input)
	{
		try
		{
			auto createParams = m_ArgumentsForm;
			auto fillArg = [&input](json& arg)
			{
				auto& name = arg.at("name").get_ref<std::string const&>();
				auto& type = arg.at("type").get_ref<std::string const&>();
				arg["value"] = input.GetNext();
				// TODO input validation against m_ArgumentsForm min, max, type, etc.
			};
			for (size_t i = 0; i < createParams.size(); ++i)
			{
				auto& arg = createParams[i];
				if (arg.is_array())
					for (size_t j = 0; j < arg.size(); ++j)
						fillArg(arg[j]);
				else
					fillArg(arg);
			}
			return createParams;
		}
		catch (std::out_of_range&)
		{
			throw std::runtime_error("Failed to create channel: not enough arguments given");
		}
	}
}
