#include "stdafx.h"

namespace MWR::C3::Linter
{
	InputVector::InputVector(StringVector input) : m_Input{ std::move(input) }, m_Current{ m_Input.cbegin() }
	{
		m_Current = m_Input.cbegin();
	}

	InputVector::InputVector(InputVector const& other) :
		m_Input{ other.m_Input },
		m_Current{ m_Input.cbegin() + std::distance(other.m_Input.begin(), other.m_Current) }
	{
	}

	InputVector& InputVector::operator=(InputVector const& other)
	{
		InputVector tmp(other);
		std::swap(tmp, *this);
		return *this;
	}

	std::string InputVector::GetNext()
	{
		if (m_Current == m_Input.cend())
			throw std::out_of_range("Input vector has no more elements");
		return *m_Current++;
	}

	void InputVector::Reset()
	{
		m_Current = m_Input.cbegin();
	}

	std::optional<std::string> InputVector::GetOptionalNext()
	{
		if (m_Current == m_Input.cend())
			return {};
		return *m_Current++;
	}
}
