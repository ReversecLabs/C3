#include "stdafx.h"
#include "Form.h"

namespace MWR::C3::Linter
{
	Form::Form(json argumentForm) :
		m_ArgumentsForm(std::move(argumentForm))
	{
		for (auto& arg : m_ArgumentsForm)
		{
			if (arg.is_array())
			{
				for (auto& a : arg)
				{
					m_Elements.emplace_back(MakeFormElement(a));
				}
			}
			else
			{
				m_Elements.emplace_back(MakeFormElement(arg));
			}
		}
	}

	Form::Form(Form const& other) noexcept :
		Form(other.m_ArgumentsForm)
	{
	}

	Form& Form::operator=(Form const& other) noexcept
	{
		Form tmp(other);
		std::swap(*this, tmp);
		return *this;
	}

	json Form::Fill(StringVector input)
	{
		if (input.size() < m_Elements.size())
			throw std::runtime_error("Not enough arguments given to fill out form [required = " + std::to_string(m_Elements.size()) + ", given = " + std::to_string(input.size()) + "]");

		// TODO log "Too many arguments, ignoring some of them"
		// if (input.size() > m_Elemets.size())

		auto inputIt = begin(input);
		std::for_each(begin(m_Elements), end(m_Elements), [&inputIt](auto& element) {element->ValidateAndSet(*inputIt++); });

		return m_ArgumentsForm;
	}

	StringVector Form::GetComplementaryArgs(StringVector input)
	{
		size_t currentOffset = 0;
		for (auto const& arg : m_ArgumentsForm)
		{
			if (arg.is_array())
			{
				auto size = arg.size();
				auto first = begin(input) + currentOffset;
				std::rotate(first, first + size - 1, first + size);
				currentOffset += size;
			}
			else
			{
				++currentOffset;
			}
		}
		return input;
	}
}
