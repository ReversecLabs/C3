#include "stdafx.h"
#ifndef SECURITY_WIN32 
#define SECURITY_WIN32 
#endif

#include "LDAP.h"
#include "Common/FSecure/Crypto/Base64.h"
#include <system_error>
#include <string>
#include "Common/FSecure/CppTools/StringConversions.h"
#include <locale>
#include <chrono>
#include <thread>
#include <stdio.h>      // Standard I/O
#include <comdef.h>     // COM definitions
#include <activeds.h>   // ADSI definitions
#include <cppcodec/base32_crockford.hpp>
#include <atlstr.h>
#pragma comment(lib, "Adsiid.lib")
#pragma comment(lib, "Activeds.lib")
#pragma comment(lib, "Secur32.lib")
#include <security.h>
#include <secext.h>
#include <Iads.h>
#include <adshlp.h>
#include <sstream>

using namespace FSecure::StringConversions;

IDirectoryObject* pDirObject;
HRESULT hr;

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Interfaces::Channels::LDAP::LDAP(ByteView arguments)
	: m_inboundDirectionName{ arguments.Read<std::string>() }
	, m_outboundDirectionName{ arguments.Read<std::string>() }
	, m_ldapAttribute{ arguments.Read<std::string>() }
	, m_ldapLockAttribute{ arguments.Read<std::string>() }
	, m_maxPacketSize{ arguments.Read<std::string>() }
	, m_domainController{ arguments.Read<std::string>() }
{
	// Initalise COM
	hr = CoInitialize(NULL);

	// Set up the directory object so we can query AD
	CreateDirectoryObject();

}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
size_t FSecure::C3::Interfaces::Channels::LDAP::OnSendToChannel(ByteView data)
{
	USES_CONVERSION_EX;

	// Check if the attribute is locked for writing already
	if (IsAttributeEmpty(m_ldapLockAttribute))
	{
		// If not then lock it by setting the lock attribute to be the name of our intended recipient 
		SetAttribute(m_ldapLockAttribute, m_outboundDirectionName);
	}
	else {
		// It's locked which means it hasn't been read yet
		size_t empty = 0;
		return empty;

	}

	//TODO check attribute exists 

	// Find out what size chunks we're able to send
	size_t sizeOfDataToWrite = CalculateDataSize(data);

	// Encode the data
	std::string dataToWrite = EncodeData(data, sizeOfDataToWrite);

	// Write the data
	SetAttribute(m_ldapAttribute, dataToWrite);

	//Debug
	std::cout << "Wrote this data: " << std::flush;
	std::cout << dataToWrite << std::flush;
	std::cout << "\n" << std::flush;

	return sizeOfDataToWrite;

}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::vector<FSecure::ByteVector> FSecure::C3::Interfaces::Channels::LDAP::OnReceiveFromChannel()
{

	std::vector<ByteVector> ret;

	// If attribute or lock is empty then nothing to be read
	if (IsAttributeEmpty(m_ldapAttribute) || IsAttributeEmpty(m_ldapLockAttribute))
	{
		return ret;
	}

	

	// If the message isn't locked for us then don't read it 
	if (GetAttributeValue(m_ldapLockAttribute) != m_inboundDirectionName)
	{
		return ret;
	}

	// Get the attribute value
	std::string attributeValue = GetAttributeValue(m_ldapAttribute);

	//Debug
	std::cout << "Read this data: " << std::flush;
	std::cout << attributeValue << std::flush;
	std::cout << "\n" << std::flush;

	// Add it onto the return stack
	ret.emplace_back(std::move(cppcodec::base32_crockford::decode(attributeValue)));

	// Clear the data attribute 
	ClearAttribute(m_ldapAttribute);

	// Clear the lock so that data can be written again
	ClearAttribute(m_ldapLockAttribute);



	return ret;
}


void FSecure::C3::Interfaces::Channels::LDAP::CreateDirectoryObject()
{
	// Get executing thread's FQDN
	TCHAR szDN[1024];
	ULONG ulSize = sizeof(szDN) / sizeof(szDN[0]);
	BOOL res = GetUserNameEx(NameFullyQualifiedDN, szDN, &ulSize);
	std::wstring concat = L"LDAP://" + Convert<Utf16>(m_domainController) + L"/" + szDN;

	LPCWSTR pwszADsPath = concat.c_str();
	std::wcout << pwszADsPath << std::endl;
	USES_CONVERSION_EX;
	DWORD dwReturn = NULL;
	ADSVALUE  snValue;
	DWORD dwAttrs = NULL;

	try {
		hr = ADsOpenObject(pwszADsPath,
			NULL,
			NULL,
			ADS_SECURE_AUTHENTICATION,
			IID_IDirectoryObject,
			(void**)&pDirObject);

		if (!SUCCEEDED(hr))
		{
			throw std::runtime_error{ "Couldn't bind to Active Directory." };
		}
	}
	catch (const std::exception& exc) {
		throw std::runtime_error{ "Couldn't bind to Active Directory." };
	}
}


void FSecure::C3::Interfaces::Channels::LDAP::ClearAttribute(std::string const& attribute)
{
	USES_CONVERSION_EX;
	ADSVALUE  snValue;
	DWORD dwReturn = NULL;

	ADS_ATTR_INFO attrInfo[] = { {A2W_EX(attribute.c_str(), text.length()),ADS_ATTR_CLEAR, ADSTYPE_CASE_IGNORE_STRING, NULL, 1} };
	hr = pDirObject->SetObjectAttributes(attrInfo, 1, &dwReturn);
}

std::string FSecure::C3::Interfaces::Channels::LDAP::GetAttributeValue(std::string const& attribute)
{
	USES_CONVERSION_EX;
	ADS_ATTR_INFO* pAttrInfo = NULL;
	LPWSTR pAttrNames[] = { A2W_EX(attribute.c_str(), attribute.length()) };
	DWORD dwNumAttr = 1;

	DWORD dwReturn = NULL;

	try {
		hr = pDirObject->GetObjectAttributes(pAttrNames,
			dwNumAttr,
			&pAttrInfo,
			&dwReturn);

		if (SUCCEEDED(hr))
		{
			switch (pAttrInfo[0].dwADsType)
			{
			case ADSTYPE_CASE_IGNORE_STRING:

				return CW2A(pAttrInfo[0].pADsValues[0].CaseIgnoreString);
			case ADSTYPE_OCTET_STRING:
				std::string s(reinterpret_cast<char const*>(pAttrInfo[0].pADsValues[0].OctetString.lpValue), pAttrInfo[0].pADsValues[0].OctetString.dwLength);
				return s;
			
			}
			throw std::runtime_error{ "Couldn't read the attribute type, pick a better attribute." };
		}
		else {
			throw std::runtime_error{ "Failed to get attribute value." };
		}
	}
	catch (const std::exception& exc) {
		throw std::runtime_error{ "Failed to get attribute value." };
	}
}



void FSecure::C3::Interfaces::Channels::LDAP::SetAttribute(std::string const& attribute, std::string value)
{
	USES_CONVERSION_EX;
	ADSVALUE  snValue;
	DWORD dwReturn = NULL;


	ADS_ATTR_INFO attrInfo[] = { {A2W_EX(attribute.c_str(), attribute.length()) , ADS_ATTR_UPDATE, ADSTYPE_CASE_IGNORE_STRING, &snValue, 1} };
	snValue.dwType = ADSTYPE_CASE_IGNORE_STRING;
	snValue.CaseExactString = A2W_EX(value.c_str(), value.length());
	try {
		hr = pDirObject->SetObjectAttributes(attrInfo, 1, &dwReturn);

		if (!SUCCEEDED(hr))
		{
			throw std::runtime_error{ "Failed to set attribute, likely because it doesn't exist." };
		}
	}
	catch (const std::exception& exc) {
		throw std::runtime_error{ "Failed to set attribute, likely because it doesn't exist." };
	}
}

bool FSecure::C3::Interfaces::Channels::LDAP::IsAttributeEmpty(std::string const& attribute)
{
	USES_CONVERSION_EX;
	ADS_ATTR_INFO* pAttrInfo = NULL;
	LPWSTR pAttrNames[] = { A2W_EX(m_ldapLockAttribute.c_str(), m_ldapLockAttribute.length()) };
	DWORD dwNumAttr = 1;

	DWORD dwReturn = NULL;

	try {
		hr = pDirObject->GetObjectAttributes(pAttrNames,
			dwNumAttr,
			&pAttrInfo,
			&dwReturn);

		if (SUCCEEDED(hr))
		{
			FreeADsMem(pAttrInfo);
			return dwReturn < 1;
		}
		else {
			throw std::runtime_error{ "Failed to check if attribute is empty." };
		}
	}
	catch (const std::exception& exc) {
		throw std::runtime_error{ "Failed to check if attribute is empty." };
	}

	
}


size_t FSecure::C3::Interfaces::Channels::LDAP::CalculateDataSize(ByteView data)
{
	std::stringstream sstream(m_maxPacketSize);
	size_t size;
	sstream >> size;
	
	auto maxPacketSize = cppcodec::base64_rfc4648::decoded_max_size(size);
	return std::min(maxPacketSize, data.size());
}



std::string FSecure::C3::Interfaces::Channels::LDAP::EncodeData(ByteView data, size_t dataSize)
{
	USES_CONVERSION_EX;
	auto sendData = data.SubString(0, dataSize);
	return cppcodec::base32_crockford::encode(sendData.data(), sendData.size());
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
const char* FSecure::C3::Interfaces::Channels::LDAP::GetCapability()
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
                "name": "Data LDAP Attribute",
                "min": 1,
				"defaultValue": "mSMQSignCertificates",
                "description": "The LDAP attribute to write data into. Recommend mSMQSignCertificates (MANUALLY CHECK THAT IT IS EMPTY)"
            },
			{
                "type": "string",
                "name": "Lock LDAP Attribute",
                "min": 1,
				"defaultValue": "primaryInternationalISDNNumber",
                "description": "The LDAP attribute to use as the lock. Recommend primaryInternationalISDNNumber (MANUALLY CHECK THAT IT IS EMPTY)"
            },
			{
                "type": "string",
                "name": "Max Packet Size",
                "min": 1,
				"defaultValue": "524288",
                "description": "The maximum number of bytes that your selected LDAP attribute supports"
            },
			{
                "type": "string",
                "name": "Domain Controller",
                "min": 1,
				"defaultValue": "<FQDN>",
                "description": "The domain controller to target, avoids waiting for syncronisations"
            }
        ]
    },
    "commands": []
}
)_";
}