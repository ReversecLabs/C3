#include "Stdafx.h"
#include "Common/MWR/C3/Internals/BackendCommons.h"
#include "Common/MWR/Crypto/Base64.h"
#include "GateRelay.h"
#include "NodeRelay.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// Anonymous namespace with helpers.
namespace
{
	/// Obtains Gateway's encryption keys. If the key file exists, it's contents will be Base64 decoded and validated. Otherwise they will be generated.
	/// @param keysFilePath path to the keys file.
	/// @return std::tuple with a flag (true if keys were read, false if generated) and all the keys.
	std::tuple<bool, MWR::Crypto::SignatureKeys, MWR::Crypto::SymmetricKey> ReadFromFileOrGenerateGatewayKeys(std::filesystem::path const& keysFilePath)
	{
		// Check if file exists.
		if (std::filesystem::exists(keysFilePath))
			try
			{
				// Parse keys.
				auto keys = json::parse(std::ifstream{ keysFilePath, std::ios::in });

				// Helper lambda to read patch entries. TODO: rewrite as a template lambda when C++20 is out.
				auto ParseEntry = [&keys](auto* typePtr, auto const& entryName) -> std::remove_pointer_t<decltype(typePtr)>
				{
					try
					{
						return cppcodec::base64_rfc4648::decode<MWR::ByteVector>(keys[entryName].template get<std::string>());
					}
					catch (std::exception& exception)
					{
						throw std::runtime_error{ OBF("Couldn't parse ") + std::string(entryName) + OBF(" element from patch. ") + exception.what() };
					}
					catch (...)
					{
						throw std::runtime_error{ OBF("Caught an unknown exception while parsing ") + std::string(entryName) + OBF(" element from patch.") };
					}
				};

				// Parse and return keys.
				return std::make_tuple(true, MWR::Crypto::SignatureKeys{ ParseEntry((MWR::Crypto::PrivateSignature*)nullptr, OBF("Private signature")),
					ParseEntry((MWR::Crypto::PublicSignature*)nullptr, OBF("Public signature")) }, ParseEntry((MWR::Crypto::SymmetricKey*)nullptr, OBF("Broadcast key")));
			}
			catch (const std::exception & exception)
			{
				throw std::runtime_error{ OBF_STR("Incorrect key file. ") + exception.what() };
			}

		// File doesn't exist. Generate all the keys.
		auto singatures = MWR::Crypto::GenerateSignatureKeys();
		auto broadcastKey = MWR::Crypto::GenerateSymmetricKey();

		// Create json tree.
		auto keys = json{};
		keys[OBF("Private signature")] = cppcodec::base64_rfc4648::encode(singatures.first.ToByteVector().data(), MWR::Crypto::PrivateSignature::Size);
		keys[OBF("Public signature")] = cppcodec::base64_rfc4648::encode(singatures.second.ToByteVector().data(), MWR::Crypto::PublicSignature::Size);
		keys[OBF("Broadcast key")] = cppcodec::base64_rfc4648::encode(broadcastKey.ToByteVector().data(), MWR::Crypto::SymmetricKey::Size);

		// Store them in provided file and return.
		std::ofstream{ keysFilePath, std::ios::out | std::ios::trunc } << keys.dump(4);									// dump(4) adds 4 space indentation to file.

		return std::make_tuple(false, singatures, broadcastKey);
	}

	/// Obtains Gateway's configuration.
	/// @param configurationFilePath path to the configuration file.
	/// @return std::tuple with read configuration.
	auto ReadGatewayConfigurationFile(std::filesystem::path const& configurationFilePath)
	{
		// Parse json configuration file.
		if (!std::filesystem::exists(configurationFilePath))
			throw std::invalid_argument{ OBF("Gateway configuration file not found.") };
		auto configuration = json::parse(std::ifstream{ configurationFilePath, std::ios::in });

		// Unfortunetly json::value throws for most value_types. This helper will return default in such case.
		auto jsonValueClosure = [&configuration](auto const& key, auto const& defaultValue)
		{
			return configuration.is_object() ? configuration.value(key, defaultValue) : defaultValue; };

		return std::make_tuple
		(
			jsonValueClosure(OBF("API Bridge IP"), OBF("127.0.0.1")),
			jsonValueClosure(OBF("API Bridge port"), std::uint16_t{ 2323 }),
			MWR::C3::BuildId{ jsonValueClosure(OBF("BuildId"), MWR::C3::BuildId::GenerateRandom().ToString()) },
			MWR::C3::AgentId{ jsonValueClosure(OBF("AgentId"), MWR::C3::AgentId::GenerateRandom().ToString()) },
			jsonValueClosure("Name", "")
		);
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::shared_ptr<MWR::C3::Relay> MWR::C3::Utils::CreateGatewayFromConfigurationFiles(LoggerCallback callbackOnLog, InterfaceFactory& interfaceFactory, std::filesystem::path const& keysFileName, std::filesystem::path const& configurationFileName)
{
	// Identify and store the directory that the executable is running in (-not- the current directory) using WinAPI.
	wchar_t executableFilePath[MAX_PATH];
	if (!GetModuleFileNameW(nullptr, executableFilePath, MAX_PATH))
		throw std::runtime_error{ OBF("Could not find process image path.") };

	// Read both input files.
	callbackOnLog({ OBF("Reading input files..."), LogMessage::Severity::Information }, nullptr);

	auto [apiBridgeIp, apiBrigdePort, buildId, agentId, name] = ReadGatewayConfigurationFile(std::filesystem::path{ executableFilePath }.remove_filename() / configurationFileName);
	auto [wereKeysReadOrGenerated, signatures, broadcastKey] = ReadFromFileOrGenerateGatewayKeys(std::filesystem::path{ executableFilePath }.remove_filename() / keysFileName);
	auto snapshotPath = std::filesystem::path{ executableFilePath }.remove_filename() / OBF("GatewaySnapshot.json");

	// Create and run the Gateway.
	if (!wereKeysReadOrGenerated)
		callbackOnLog({ OBF("Generated new keys/signatures and stored them on disk."), LogMessage::Severity::Information }, "");

	callbackOnLog({ OBF("Starting Gateway..."), LogMessage::Severity::Information }, nullptr);
	return MWR::C3::Core::GateRelay::CreateAndRun(callbackOnLog, interfaceFactory, apiBridgeIp, apiBrigdePort, signatures, broadcastKey, buildId, snapshotPath, agentId, name);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::shared_ptr<MWR::C3::Relay> MWR::C3::Utils::CreateNodeRelayFromImagePatch(LoggerCallback callbackOnLog, InterfaceFactory& interfaceFactory, ByteView buildId, ByteView gatewaySignature, ByteView broadcastKey, std::vector<ByteVector> const& gatewayInitialPackets)
{
	return Core::NodeRelay::CreateAndRun(callbackOnLog, interfaceFactory, gatewaySignature, broadcastKey, gatewayInitialPackets, buildId);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::string MWR::C3::Utils::ConvertLogMessageToConsoleText(std::string_view relayName, LogMessage const& message, std::string_view sender)
{
	// Format message as: "[relay]|@> [InterfaceID] message", where @ is different for each severity.
	std::string retVal = sender.empty() ? (std::string(relayName) + '|') : ""s;

	switch (message.m_Severity)
	{
	case MWR::C3::LogMessage::Severity::Error: retVal += OBF("Error> "); break;
	case MWR::C3::LogMessage::Severity::Information: retVal += OBF("Info> "); break;
	case MWR::C3::LogMessage::Severity::Warning: retVal += OBF("Warning> "); break;
	case MWR::C3::LogMessage::Severity::DebugInformation: retVal += OBF("Debug> "); break;
	default: retVal += OBF("???> ");
	}

	retVal += !sender.empty() ? '[' + std::string(sender) + "] " : "";
	return retVal += message.m_Body;
}
