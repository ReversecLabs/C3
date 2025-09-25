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
	, m_pipeNamePrefix { arguments.Read<std::string>() }
	, m_isServer { arguments.Read<bool>() }
{
	m_isDisconnected = true;
	m_writePipeName = m_pipeNamePrefix + m_outboundDirectionName;
	m_readPipeName = m_pipeNamePrefix + m_inboundDirectionName;
	m_hReadPipe = INVALID_HANDLE_VALUE;
	m_hWritePipe = INVALID_HANDLE_VALUE;

	if (m_isServer)
	{
		CreateServerPipes();
	}
}

void FSecure::C3::Interfaces::Channels::NamedPipe::CreateServerPipes()
{
	SECURITY_ATTRIBUTES sa;
	CreateDACL(&sa);

	m_hWritePipe = CreateNamedPipeA(m_writePipeName.c_str(), PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_ACCEPT_REMOTE_CLIENTS | PIPE_WAIT, 1, PIPE_CHUNK_SIZE, 2048000, 0, &sa);
	m_hReadPipe = CreateNamedPipeA(m_readPipeName.c_str(), PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_ACCEPT_REMOTE_CLIENTS | PIPE_WAIT, 1, PIPE_CHUNK_SIZE, 2048000, 0, &sa);
}

BOOL FSecure::C3::Interfaces::Channels::NamedPipe::CreateClientPipes()
{
	DWORD desiredAccess = 0;
	std::string pipeName;

	pipeName = m_readPipeName;
	desiredAccess = GENERIC_READ;

	if (!WaitNamedPipeA(pipeName.c_str(), 1000))
		return false;

	m_hReadPipe = CreateFileA(pipeName.c_str(), desiredAccess, 0, NULL, OPEN_EXISTING, NULL, NULL);

	pipeName = m_writePipeName;
	desiredAccess = GENERIC_WRITE;

	if (!WaitNamedPipeA(pipeName.c_str(), 1000))
		return false;

	m_hWritePipe = CreateFileA(pipeName.c_str(), desiredAccess, 0, NULL, OPEN_EXISTING, NULL, NULL);
	return true;
}

HANDLE FSecure::C3::Interfaces::Channels::NamedPipe::ConnectOrOpen(BOOL read)
{
	HANDLE hPipe;

	if (m_isDisconnected || m_hReadPipe == INVALID_HANDLE_VALUE || m_hWritePipe == INVALID_HANDLE_VALUE)
	{
		if (m_isServer)
		{
			if (m_hReadPipe == INVALID_HANDLE_VALUE || m_hWritePipe == INVALID_HANDLE_VALUE)
				throw std::runtime_error{ OBF("[NamedPipe] Server named pipes invalid handles GetLastError: ") + std::to_string(GetLastError()) + OBF(".") };

			m_isDisconnected = !ConnectNamedPipe(m_hReadPipe, NULL);

			if (m_isDisconnected)
			{
				DWORD err = GetLastError();
				if (err == ERROR_PIPE_CONNECTED)
				{
					m_isDisconnected = false;
				}
				else
				{
					throw std::runtime_error{ OBF("[NamedPipe] Server named pipes connection failed GetLastError: ") + std::to_string(GetLastError()) + OBF(".") };
				}
			}

			m_isDisconnected = !ConnectNamedPipe(m_hWritePipe, NULL);

			if (m_isDisconnected)
			{
				DWORD err = GetLastError();
				if (err == ERROR_PIPE_CONNECTED)
				{
					m_isDisconnected = false;
				}
				else
				{
					throw std::runtime_error{ OBF("[NamedPipe] Server named pipes connection failed GetLastError: ") + std::to_string(GetLastError()) + OBF(".") };
				}
			}
		}
		else
		{
			m_isDisconnected = !CreateClientPipes();
		}
	}

	if (read)
		hPipe = m_hReadPipe;
	else
		hPipe = m_hWritePipe;

	return hPipe;
}

size_t FSecure::C3::Interfaces::Channels::NamedPipe::OnSendToChannel(FSecure::ByteView packet)
{
	// Get a handle to a pipe we can write to
	HANDLE hPipe = ConnectOrOpen(false);

	if (hPipe == INVALID_HANDLE_VALUE)
		throw std::runtime_error{ OBF("[OnSend] Could not get handle to pipe. GetLastError returned: ") + std::to_string(GetLastError()) + OBF(".") };

	DWORD written = 0;
	uint32_t len = static_cast<uint32_t>(packet.size());

	// Write the first chunk which indicates the size of the actual message
	if (!WriteFile(hPipe, &len, sizeof(len), &written, nullptr))
	{
		DWORD error = GetLastError();
		DisconnectOrClose();

		if (error == ERROR_BROKEN_PIPE || error == ERROR_NO_DATA)
			throw std::runtime_error{ OBF("[OnSend Error] Client disconnected. Error: ") + std::to_string(error) };
		else
			throw std::runtime_error{ OBF("[OnSend Error] Failed to write message length. Error: ") + std::to_string(error) };
	}

	// Block until a read occurs
	FlushFileBuffers(hPipe);

	// Loop and perform multiple chunked writes as needed
	size_t total = 0;
	while (len > PIPE_CHUNK_SIZE)
	{
		if (!WriteFile(hPipe, &packet.front() + total, PIPE_CHUNK_SIZE, &written, nullptr))
		{
			DWORD error = GetLastError();
			DisconnectOrClose();

			if (error == ERROR_BROKEN_PIPE || error == ERROR_NO_DATA)
				throw std::runtime_error{ OBF("[OnSend Error] Client disconnected during chunked write. Error: ") + std::to_string(error) };
			else
				throw std::runtime_error{ OBF("[OnSend Error] Failed during chunked write. Error: ") + std::to_string(error) };
		}

		total += written;
		len -= written;
	}

	// Final write for the last chunk
	if (!WriteFile(hPipe, &packet.front() + total, len, &written, nullptr))
	{
		DWORD error = GetLastError();
		DisconnectOrClose();

		if (error == ERROR_BROKEN_PIPE || error == ERROR_NO_DATA)
			throw std::runtime_error{ OBF("[OnSend Error] Client disconnected during final write. Error: ") + std::to_string(error) };
		else
			throw std::runtime_error{ OBF("[OnSend Error] Failed during final write. Error: ") + std::to_string(error) };
	}

	total += written;

	// Flush the buffer
	FlushFileBuffers(hPipe);

	return total;
}


FSecure::ByteVector FSecure::C3::Interfaces::Channels::NamedPipe::OnReceiveFromChannel()
{
	// Get a handle to a pipe we can read from
	HANDLE hPipe = ConnectOrOpen(true);

	if (hPipe == INVALID_HANDLE_VALUE)
		return {};
		//throw std::runtime_error{ OBF("[OnReceive] Could not get handle to pipe. GetLastError returned: ") + std::to_string(GetLastError()) + OBF(".") };

	DWORD chunkSize = 0;
	uint32_t dataSize = 0u;


	DWORD bytesAvailable = 0;
	if (!PeekNamedPipe(hPipe, nullptr, 0, nullptr, &bytesAvailable, nullptr))
	{
		DWORD error = GetLastError();
		DisconnectOrClose();
		throw std::runtime_error{ OBF("[OnReceive Error] PeekNamedPipe failed. Error: ") + std::to_string(error) };
	}

	if (bytesAvailable < sizeof(uint32_t))
	{
		// No full message length available yet — return or retry later
		return {};
	}


	// Read 4 bytes to get the message length
	if (!ReadFile(hPipe, static_cast<LPVOID>(&dataSize), sizeof(dataSize), nullptr, nullptr))
	{
		DWORD error = GetLastError();
		DisconnectOrClose();

		if (error == ERROR_BROKEN_PIPE || error == ERROR_NO_DATA)
			throw std::runtime_error{ OBF("[OnReceive Error] Client disconnected before message length read. Error: ") + std::to_string(error) };
		else
			throw std::runtime_error{ OBF("[OnReceive Error] Failed to read message length. Error: ") + std::to_string(error) };
	}

	// Allocate buffer
	ByteVector buffer;
	buffer.resize(dataSize);
	DWORD read = 0;

	// Read the full message in chunks
	while (read < dataSize)
	{
		DWORD toRead = static_cast<DWORD>((PIPE_CHUNK_SIZE < (dataSize - read)) ? PIPE_CHUNK_SIZE : (dataSize - read));

		if (!ReadFile(hPipe, (LPVOID)&buffer[read], toRead, &chunkSize, nullptr))
		{
			DWORD error = GetLastError();
			DisconnectOrClose();

			if (error == ERROR_BROKEN_PIPE || error == ERROR_NO_DATA)
				throw std::runtime_error{ OBF("[OnReceive Error] Client disconnected during chunked read. Error: ") + std::to_string(error) };
			else
				throw std::runtime_error{ OBF("[OnReceive Error] Failed during chunked read. Error: ") + std::to_string(error) };
		}

		if (chunkSize == 0)
		{
			DisconnectOrClose();
			throw std::runtime_error{ OBF("[OnReceive Error] Read returned 0 bytes, client may have disconnected.") };
		}

		read += chunkSize;
	}

	return buffer;
}


void FSecure::C3::Interfaces::Channels::NamedPipe::DisconnectOrClose()
{
	if (m_isServer)
	{
		DisconnectNamedPipe(m_hReadPipe);
		DisconnectNamedPipe(m_hWritePipe);
		CloseHandle(m_hReadPipe);
		CloseHandle(m_hWritePipe);
		CreateServerPipes();
	}
	else
	{
		CloseHandle(m_hReadPipe);
		CloseHandle(m_hWritePipe);
		m_hReadPipe = INVALID_HANDLE_VALUE;
		m_hWritePipe = INVALID_HANDLE_VALUE;
	}


	m_isDisconnected = true;
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
				"name": "pipename prefix",
				"min": 1,
				"description": "The pipename prefix, two pipes will be created with the input and output IDs appended.",
				"defaultValue": "\\\\.\\pipe\\somepipe"
			},
			{
				"type": "boolean",
				"name": "Server",
				"defaultValue": false,
				"description": "Is this the server?"
			}
			
		]
	},
	"commands": []
}
)_";
}
