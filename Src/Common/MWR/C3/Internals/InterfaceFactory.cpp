#include "Stdafx.h"
#include "InterfaceFactory.h"
#include "Common/json/json.hpp"

using json = nlohmann::json;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
MWR::C3::InterfaceFactory& MWR::C3::InterfaceFactory::Instance()
{
	static auto instance = InterfaceFactory{};
	return instance;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::string MWR::C3::InterfaceFactory::GetCapability()
{
	json retValue;
	auto populate = [&](auto* typePtr, std::string name)
	{
		for (auto& e : GetMap<std::remove_pointer_t<decltype(typePtr)>>())
		{
			try
			{
				json entry;
				entry["type"] = e.first;
				entry["name"] = e.second.m_Name;
				auto pin = json::parse(e.second.m_Capability);
				for (const auto& j : pin.items())
					entry[j.key()] = j.value();

				retValue[name].push_back(entry);
			}
			catch (std::exception& except) // log is not available in interfaceFactory,
			{
				std::cout << OBF("Caught std::excpetion when parsing: ") << e.second.m_Name << OBF(". Interface will be unavailable.\n") << except.what() << std::endl;
			}
			catch (...)
			{
				std::cout << OBF("Caught unknown exception when parsing: ") << e.second.m_Name << OBF(". Interface will be unavailable.\n") << std::endl;
			}
		}
	};

	populate((AbstractChannel*)nullptr, OBF("channels"));
	populate((AbstractConnector*)nullptr, OBF("connectors"));
	populate((AbstractPeripheral*)nullptr, OBF("peripherals"));
	return retValue.dump(4);
}
