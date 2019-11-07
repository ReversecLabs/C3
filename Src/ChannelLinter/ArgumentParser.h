#pragma once

namespace MWR::C3::Linter
{
	class ArgumentParser
	{
	public:
		ArgumentParser(int argc, char** argv);

		AppConfig GetConfig() const;

		std::string GetUsage() const;

	private:
		void ConfigureParser();

		argparse::ArgumentParser m_ArgParser;
	};
}

