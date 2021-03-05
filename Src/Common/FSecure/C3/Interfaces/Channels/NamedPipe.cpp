#include "Stdafx.h"
#include "NamedPipe.h"
#include "Common/FSecure/CppTools/ScopeGuard.h"
#include <tchar.h>
#include <Windows.h>
#include <aclapi.h>
#include "sddl.h"
#pragma comment(lib, "advapi32.lib")

#define PIPE_CHUNK_SIZE 4096

void CreateDACL(SECURITY_ATTRIBUTES* sa)
{
	DWORD dwRes;
	PSID pEveryoneSID = NULL; 
	PACL pACL = NULL;
	PSECURITY_DESCRIPTOR pSD = NULL;
	EXPLICIT_ACCESS ea[1];
	SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
	
	// Create a well-known SID for the Everyone group.
	if (!AllocateAndInitializeSid(&SIDAuthWorld, 1,
		SECURITY_WORLD_RID,
		0, 0, 0, 0, 0, 0, 0,
		&pEveryoneSID))
	{
		_tprintf(_T("AllocateAndInitializeSid Error %u\n"), GetLastError());
		goto Cleanup;
	}

	// Initialize an EXPLICIT_ACCESS structure for an ACE.
	// The ACE will allow Everyone Full Access to the named pipe.
	ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
	ea[0].grfAccessPermissions = FILE_ALL_ACCESS;
	ea[0].grfAccessMode = SET_ACCESS;
	ea[0].grfInheritance = NO_INHERITANCE;
	ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	ea[0].Trustee.ptstrName = (LPTSTR)pEveryoneSID;

	// Create a new ACL that contains the new ACEs.
	dwRes = SetEntriesInAcl(1, ea, NULL, &pACL);
	if (ERROR_SUCCESS != dwRes)
	{
		goto Cleanup;
	}

	// Initialize a security descriptor.  
	pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR,
		SECURITY_DESCRIPTOR_MIN_LENGTH);
	if (NULL == pSD)
	{
		goto Cleanup;
	}

	if (!InitializeSecurityDescriptor(pSD,
		SECURITY_DESCRIPTOR_REVISION))
	{
		goto Cleanup;
	}

	// Add the ACL to the security descriptor. 
	if (!SetSecurityDescriptorDacl(pSD,
		TRUE,     // bDaclPresent flag   
		pACL,
		FALSE))   // not a default DACL 
	{
		goto Cleanup;
	}

	// Initialize a security attributes structure.
	sa->nLength = sizeof(SECURITY_ATTRIBUTES);
	sa->lpSecurityDescriptor = pSD;
	sa->bInheritHandle = FALSE;

Cleanup:

	if (pEveryoneSID)
		FreeSid(pEveryoneSID);
	if (pACL)
		LocalFree(pACL);
	if (pSD)
		LocalFree(pSD);
	
	return;
}

FSecure::C3::Interfaces::Channels::NamedPipe::NamedPipe(ByteView arguments)
	: m_inboundDirectionName{ arguments.Read<std::string>() }
	, m_outboundDirectionName{ arguments.Read<std::string>() }
{
	ByteReader{ arguments }.Read(m_localPipe, m_remotePipe);
	
	SECURITY_ATTRIBUTES sa;
	CreateDACL(&sa);

	//If the local pipe arg is set, then this is the server that will accept connections
	//There is no initialisation for the client performed
	if (!m_localPipe.empty())
	{
		m_isServer = true;

		std::string pipeName = m_localPipe + m_outboundDirectionName;
		m_hServerWritePipe = CreateNamedPipeA(pipeName.c_str(), PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_ACCEPT_REMOTE_CLIENTS | PIPE_WAIT, 1, PIPE_CHUNK_SIZE, 2048000, 0, &sa);

		pipeName = m_localPipe + m_inboundDirectionName;
		m_hServerReadPipe = CreateNamedPipeA(pipeName.c_str(), PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_ACCEPT_REMOTE_CLIENTS | PIPE_WAIT, 1, PIPE_CHUNK_SIZE, 2048000, 0, &sa);
	}
}

HANDLE FSecure::C3::Interfaces::Channels::NamedPipe::ConnectOrOpen(BOOL read)
{
	HANDLE hPipe;
	if (m_isServer)
	{
		if (read)
			hPipe = m_hServerReadPipe;
		else
			hPipe = m_hServerWritePipe;

		ConnectNamedPipe(hPipe, NULL);
	}
	else
	{
		std::string pipeName;
		DWORD desiredAccess = 0;
		if (read)
		{
			pipeName = m_remotePipe + m_inboundDirectionName;
			desiredAccess = GENERIC_READ;
		}
		else
		{
			pipeName = m_remotePipe + m_outboundDirectionName;
			desiredAccess = GENERIC_WRITE;
		}

		if (!WaitNamedPipeA(pipeName.c_str(), INFINITE))
			return INVALID_HANDLE_VALUE;

		hPipe = CreateFileA(pipeName.c_str(), desiredAccess, 0, NULL, OPEN_EXISTING, NULL, NULL);
	}
	return hPipe;
}

size_t FSecure::C3::Interfaces::Channels::NamedPipe::OnSendToChannel(FSecure::ByteView packet)
{
	//Get a handle to a pipe we can write to
	HANDLE hPipe = ConnectOrOpen(false);

	if (hPipe == INVALID_HANDLE_VALUE)
		throw std::runtime_error{ OBF("[OnSend] Could not get handle to pipe. GetLastError returned: ") + std::to_string(GetLastError()) + OBF(".") };

	DWORD written;
	uint32_t len = static_cast<uint32_t>(packet.size());

	//Write the first chunk which indicates the size of the actual message
	WriteFile(hPipe, &len, sizeof(len), nullptr, nullptr);

	//Block until a read occurs 
	FlushFileBuffers(hPipe);

	//Loop and perform multiple chunked writes as needed.
	//Note that a single WriteFile call fails for messages > PIPE_CHUNK_SIZE - so we must loop.
	size_t total = 0;
	while (len > PIPE_CHUNK_SIZE)
	{
		WriteFile(hPipe, &packet.front() + total, PIPE_CHUNK_SIZE, &written, nullptr);
		total += written;
		len -= written;
	}

	//Perform the final write for the last chunk
	WriteFile(hPipe, &packet.front() + total, len, &written, nullptr);
	total += written;

	if (total != packet.size())
	{
		DisconnectOrClose(hPipe);
		throw std::runtime_error{ OBF("[OnSend Error] Could not write all bytes to pipe. GetLastError returned: ") + std::to_string(GetLastError()) + OBF(".") };
	}

	//Flush the buffer before disconnecting the client or closing any handles.
	FlushFileBuffers(hPipe);
	DisconnectOrClose(hPipe);

	return total;
}

FSecure::ByteVector FSecure::C3::Interfaces::Channels::NamedPipe::OnReceiveFromChannel()
{
	//Get a handle to a pipe we can read from
	HANDLE hPipe = ConnectOrOpen(true);

	if (hPipe == INVALID_HANDLE_VALUE)
		throw std::runtime_error{ OBF("[OnSend] Could not get handle to pipe. GetLastError returned: ") + std::to_string(GetLastError()) + OBF(".") };


	DWORD chunkSize;
	uint32_t dataSize = 0u;

	//Read 4 bytes to get the message length
	if (!ReadFile(hPipe, static_cast<LPVOID>(&dataSize), 4, nullptr, nullptr))
	{
		DisconnectOrClose(hPipe);
		throw std::runtime_error{ OBF("Couldn't read from Pipe: ") + std::to_string(GetLastError()) + OBF(".") };
	}


	ByteVector buffer;
	buffer.resize(dataSize);
	DWORD read = 0;

	//Now read dataSize bytes 
	while (read < dataSize)
	{
		if (!ReadFile(hPipe, (LPVOID)&buffer[read], static_cast<DWORD>((PIPE_CHUNK_SIZE < (dataSize - read)) ? PIPE_CHUNK_SIZE : (dataSize - read)), &chunkSize, nullptr) || !chunkSize)
		{
			DisconnectOrClose(hPipe);
			throw std::runtime_error{ OBF("Couldn't read from Pipe: ") + std::to_string(GetLastError()) + OBF(".") };
		}

		read += chunkSize;
	}

	DisconnectOrClose(hPipe);

	return buffer;
}

void FSecure::C3::Interfaces::Channels::NamedPipe::DisconnectOrClose(HANDLE hPipe)
{
	if (m_isServer)
		DisconnectNamedPipe(hPipe);
	else
		CloseHandle(hPipe);
}

const char* FSecure::C3::Interfaces::Channels::NamedPipe::GetCapability()
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
				"name": "local pipe name",
				"min": 0,
				"description": "The local named pipe name - only set this for the remote client",
				"defaultValue": "\\\\.\\pipe\\somepipename"
			},
			{
				"type": "string",
				"name": "remote pipe name",
				"min": 0,
				"description": "The remote named pipe name - only set this on a gateway or node relay",
				"defaultValue": "\\\\servername\\pipe\\somepipe"
			}
			
		]
	},
	"commands": []
}
)_";
}
