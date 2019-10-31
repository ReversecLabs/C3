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
				ValidateAndSet(arg, input.GetNext());
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
			input.Reset();
			std::string message;
			auto AddParameterMessage = [&message, &input](json& arg)
			{
				auto& name = arg.at("name").get_ref<std::string const&>();
				auto& type = arg.at("type").get_ref<std::string const&>();
				message += name + " (" + type + ") > " + input.GetOptionalNext().value_or("") + '\n';
			};
			for (size_t i = 0; i < m_ArgumentsForm.size(); ++i)
			{
				auto& arg = m_ArgumentsForm[i];
				if (arg.is_array())
					for (size_t j = 0; j < arg.size(); ++j)
						AddParameterMessage(arg[j]);
				else
					AddParameterMessage(arg);
			}
 			throw std::runtime_error("Failed to create channel: not enough arguments given.\nRequired parameter > received argument\n" + message);
		}
	}

	StringVector Form::GetComplementaryArgs(StringVector const& input)
	{
		StringVector args;
		size_t k = 0;
		for (size_t i = 0; i < m_ArgumentsForm.size(); ++i)
		{
			auto& arg = m_ArgumentsForm[i];
			if (arg.is_array())
			{
				for (size_t j = 0; j < arg.size(); ++j)
				{
					auto rotateRight = [s = arg.size()](size_t index) { return (index + s - 1) % s; };
					args.emplace_back(input.at(k + rotateRight(j)));
				}
				k += arg.size();
			}
			else
			{
				args.emplace_back(input.at(k++));
			}
		}
		return args;
	}
}
