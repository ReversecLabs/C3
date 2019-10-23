#pragma once

namespace MWR::C3::Linter
{
	struct InputError : public std::exception
	{
		using std::exception::exception;
		using std::exception::what;
	};

	class InputContext {
	public:
		InputContext(int argc, char* argv[]);

		std::string_view GetChannelName() const;

		static std::string_view GetUsage();

	private:
		std::string m_ChannelName;
	};
}

