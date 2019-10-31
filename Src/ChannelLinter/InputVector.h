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
		void Reset();
		size_t Size() { return m_Input.size(); }
		std::string& operator[](size_t index) { return m_Input.operator [](index); }
		std::string const& operator[](size_t index) const { return m_Input.operator [](index); }
		std::string at(size_t index) { return m_Input.at(index); }
		std::string const& at(size_t index) const { return m_Input.at(index); }
		std::optional<std::string> GetOptionalNext();
	private:
		StringVector m_Input;
		StringVector::const_iterator m_Current;
	};
}
