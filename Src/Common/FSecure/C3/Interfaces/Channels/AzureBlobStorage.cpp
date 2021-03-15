#include "Stdafx.h"
#include "AzureBlobStorage.h"
#include "Common/FSecure/Crypto/Base64.h"

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Interfaces::Channels::AzureBlobStorage::AzureBlobStorage(ByteView arguments)
	: m_inboundDirectionName{ arguments.Read<std::string>() }
	, m_outboundDirectionName{ arguments.Read<std::string>() }
{
	auto [sasToken, storageAccountName, containerName, channelName] = arguments.Read<std::string, std::string, std::string, std::string>();
	m_AzureBlobStorageObj = FSecure::AzureBlobStorage{ sasToken, storageAccountName, containerName, channelName };
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
size_t FSecure::C3::Interfaces::Channels::AzureBlobStorage::OnSendToChannel(ByteView data)
{
	// There is a cap on uploads of files >5mb at which point different APIs are required.
	std::cout << "Entering OnSendToChannel\n";
	data = data.SubString(0, 5 * 1024 * 1024);
	m_AzureBlobStorageObj.WriteMessageToFile(m_outboundDirectionName, data, "");
	return data.size();
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::vector<FSecure::ByteVector> FSecure::C3::Interfaces::Channels::AzureBlobStorage::OnReceiveFromChannel()
{
	std::cout << "Entering OnReceiveFromChannel\n";
	std::vector<ByteVector> ret;
	for (auto& [ts, fileName]: m_AzureBlobStorageObj.GetMessagesByDirection(m_inboundDirectionName))
	{
		ret.push_back(m_AzureBlobStorageObj.ReadFile(fileName));
		//std::cout << "I've read the file\n";
		m_AzureBlobStorageObj.DeleteFile(fileName);
	}

	return ret;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
const char* FSecure::C3::Interfaces::Channels::AzureBlobStorage::GetCapability()
{
	return R"_(
{
	"create":
	{
		"arguments":
		[
			[
				{
					"type": "string",
					"name": "Input ID",
					"min": 4,
					"randomize": true,
					"description": "Used to distinguish packets for the channel"
				},
				{
					"type": "string",
					"name": "Output ID",
					"min": 4,
					"randomize": true,
					"description": "Used to distinguish packets from the channel"
				}
			],
			{
				"type": "string",
				"name": "Container SAS token",
				"min": 4,
				"description": "SAS token to provide the channel with full access to an Azure Storage Container"
			},
			{
				"type": "string",
				"name": "Azure Blob Storage Account Name",
				"min": 4,
				"description": "Name of the Azure Blob Storage Account"
			},
			{
				"type": "string",
				"name": "Azure Blob Storage Container Name",
				"min": 4,
				"description": "Name of the Azure Blob Storage Container"
			},
			{
				"type": "string",
				"name": "Folder name",
				"min": 4,
				"randomize": true,
				"description": "Folder to create for channel"
			}
		]
	},
	"commands": []
}
)_";
}
