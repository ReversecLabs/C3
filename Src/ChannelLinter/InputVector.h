#pragma once

namespace MWR::C3::Linter
{
	class InputVector
	{
	public:
		InputVector(StringVector input);
		InputVector(InputVector const& other);
		InputVector& operator = (InputVector const& other);

		std::string GetNext();
	private:
		StringVector m_Input;
		StringVector::const_iterator m_Current;
	};
}
