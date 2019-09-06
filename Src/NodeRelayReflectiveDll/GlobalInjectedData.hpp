namespace MWR::C3::ReflectiveDll
{
	/// This structure is meant to be shared between injector and injectee in the Reflective DLL. Rules:
	///  1. Use only PODs as members.
	///  2. Constructor of the class is called only on the injector side.
	///  3. DON'T try to initialize this structure by copying globals, "predefined" constants, arrays (especially character arrays SUCH AS "..." STRINGS). It is safe to generate or read values from
	///		sources other than memory (files, pipes, etc.). This is because all addresses pointing to places other than stack should be considered re-based, thus invalid. Touching them might lead to
	///		garbage processing or a crash. Don't do that.
	/// 4. InjectionMethod, if used, needs to be the first field in the struct. It's safe to add more values to this enum, but keep it byte-wide.
	///
	/// Also ThreadStorage should be used in place of global and thread_local variables.
	struct GlobalInjectedData
	{
		enum class InjectionMethod : char
		{
			Regular = 0,														//< Loaded using the "regular" LoadLibrary() WinAPI OR Xenos/Black.
			Stephens = 1,														//< Loaded using Stephen Fewer's technique.
		} m_InjectionMethod;
		ULONG_PTR m_DllBaseAddress;
		DWORD m_SizeOfTheDll;

		GlobalInjectedData(InjectionMethod injectionMethod, ULONG_PTR dllBaseAddress, DWORD dllSize)
			: m_InjectionMethod(injectionMethod)
			, m_DllBaseAddress(dllBaseAddress)
			, m_SizeOfTheDll(dllSize)
		{
		}

		void*& AccessThreadStorage(std::thread::native_handle_type threadStorageId)
		{
			if (auto it = m_ThreadStorages.find(threadStorageId); it != m_ThreadStorages.end())
				return it->second;

			// Synchronized access.
			std::lock_guard<std::mutex> guard(m_ThreadStoragesMutex);
			return m_ThreadStorages[threadStorageId];
		}

		void ReleaseThreadStorage(std::thread::native_handle_type threadStorageId)
		{
			std::lock_guard<std::mutex> guard(m_ThreadStoragesMutex);
			m_ThreadStorages.erase(threadStorageId);
		}

	private:
		std::mutex m_ThreadStoragesMutex;										//< Mutex to synchronize changes in m_GlobalSets.
		std::unordered_map<std::thread::native_handle_type, void*> m_ThreadStorages;				//< Should be leveraged by threads in place of thread_local.
	};

	// Namespace for signature generation code.
	namespace CompileTimeRandomSignatureGenerator
	{
		// Pre-build step ("echo #define PER_BUILD_DYNAMIC_SIGNATURE_SEED %RANDOM% > PER_BUILD_DYNAMIC_SIGNATURE_SEED.hpp") changess this value every time you build the code.
		// Don't use any __TIME__ related tricks instead, as predefined macros are apparently inconsistent between compilation units.
#		include "PER_BUILD_DYNAMIC_SIGNATURE_SEED.hpp"
		const uint32_t SIGNATURE_SEED = PER_BUILD_DYNAMIC_SIGNATURE_SEED;

		// If needed, increase this value to reduce collision risk (but don't exceed 8 unless you add more layers of CHECK_SIGNATURE_BYTE and GENERATE_COMPILE_TIME_BYTE macros).
#		define SIGNATURE_LENGTH 4

		// LCG implemented as an template.
		template<uint32_t Seed>
		struct LCG
		{
			static const uint32_t value = (static_cast<uint64_t>(Seed) * 48271 + 7) % ((1UL << 31) - 1);
		};
		
		// Helper generator template
		template<std::size_t Index, uint32_t Seed>
		struct DoGenerate
		{
			static const char value = DoGenerate<Index - 1, LCG<Seed>::value>::value;
		};

		// Helper generator template specialization for last iteration.
		template<uint32_t Seed>
		struct DoGenerate<0, Seed>
		{
#			pragma warning(push)
#			pragma warning(disable:4309)										//< "'static_cast': truncation of constant value".
			static const char value = static_cast<char>(LCG<Seed>::value);
#			pragma warning(pop)
		};

		// A handy generator alias.
		template<std::size_t Index> using Generate = DoGenerate<Index, SIGNATURE_SEED>;

		// Global variable definition helper macros.
#		define GENERATE_COMPILE_TIME_BYTE(index) MWR::C3::ReflectiveDll::CompileTimeRandomSignatureGenerator::Generate<index>::value
#		define CHECK_SIGNATURE_BYTE(index) TJOCk6MZj9H7Z5iFExu9[index] == GENERATE_COMPILE_TIME_BYTE(index)

#		define GENERATE_COMPILE_TIME_BYTE_SEQUENCE1 GENERATE_COMPILE_TIME_BYTE(0)
#		define GENERATE_COMPILE_TIME_BYTE_SEQUENCE2 GENERATE_COMPILE_TIME_BYTE_SEQUENCE1, GENERATE_COMPILE_TIME_BYTE(1)
#		define GENERATE_COMPILE_TIME_BYTE_SEQUENCE3 GENERATE_COMPILE_TIME_BYTE_SEQUENCE2, GENERATE_COMPILE_TIME_BYTE(2)
#		define GENERATE_COMPILE_TIME_BYTE_SEQUENCE4 GENERATE_COMPILE_TIME_BYTE_SEQUENCE3, GENERATE_COMPILE_TIME_BYTE(3)
#		define GENERATE_COMPILE_TIME_BYTE_SEQUENCE5 GENERATE_COMPILE_TIME_BYTE_SEQUENCE4, GENERATE_COMPILE_TIME_BYTE(4)
#		define GENERATE_COMPILE_TIME_BYTE_SEQUENCE6 GENERATE_COMPILE_TIME_BYTE_SEQUENCE5, GENERATE_COMPILE_TIME_BYTE(5)
#		define GENERATE_COMPILE_TIME_BYTE_SEQUENCE7 GENERATE_COMPILE_TIME_BYTE_SEQUENCE6, GENERATE_COMPILE_TIME_BYTE(6)
#		define GENERATE_COMPILE_TIME_BYTE_SEQUENCE8 GENERATE_COMPILE_TIME_BYTE_SEQUENCE7, GENERATE_COMPILE_TIME_BYTE(7)
#		define GENERATE_COMPILE_TIME_BYTE_SEQUENCE9 GENERATE_COMPILE_TIME_BYTE_SEQUENCE8, GENERATE_COMPILE_TIME_BYTE(8)
#		define GENERATE_COMPILE_TIME_BYTE_SEQUENCE10 GENERATE_COMPILE_TIME_BYTE_SEQUENCE9, GENERATE_COMPILE_TIME_BYTE(9)
#		define GENERATE_COMPILE_TIME_BYTE_SEQUENCE11 GENERATE_COMPILE_TIME_BYTE_SEQUENCE10, GENERATE_COMPILE_TIME_BYTE(10)
#		define GENERATE_COMPILE_TIME_BYTE_SEQUENCE12 GENERATE_COMPILE_TIME_BYTE_SEQUENCE11, GENERATE_COMPILE_TIME_BYTE(11)
#		define GENERATE_COMPILE_TIME_BYTE_SEQUENCE13 GENERATE_COMPILE_TIME_BYTE_SEQUENCE12, GENERATE_COMPILE_TIME_BYTE(12)
#		define GENERATE_COMPILE_TIME_BYTE_SEQUENCE14 GENERATE_COMPILE_TIME_BYTE_SEQUENCE13, GENERATE_COMPILE_TIME_BYTE(13)
#		define GENERATE_COMPILE_TIME_BYTE_SEQUENCE15 GENERATE_COMPILE_TIME_BYTE_SEQUENCE14, GENERATE_COMPILE_TIME_BYTE(14)
#		define GENERATE_COMPILE_TIME_BYTE_SEQUENCE16 GENERATE_COMPILE_TIME_BYTE_SEQUENCE15, GENERATE_COMPILE_TIME_BYTE(15)

#		define CHECK_SIGNATURE_BYTE1 CHECK_SIGNATURE_BYTE(0)
#		define CHECK_SIGNATURE_BYTE2 CHECK_SIGNATURE_BYTE1 && CHECK_SIGNATURE_BYTE(1)
#		define CHECK_SIGNATURE_BYTE3 CHECK_SIGNATURE_BYTE2 && CHECK_SIGNATURE_BYTE(2)
#		define CHECK_SIGNATURE_BYTE4 CHECK_SIGNATURE_BYTE3 && CHECK_SIGNATURE_BYTE(3)
#		define CHECK_SIGNATURE_BYTE5 CHECK_SIGNATURE_BYTE4 && CHECK_SIGNATURE_BYTE(4)
#		define CHECK_SIGNATURE_BYTE6 CHECK_SIGNATURE_BYTE5 && CHECK_SIGNATURE_BYTE(5)
#		define CHECK_SIGNATURE_BYTE7 CHECK_SIGNATURE_BYTE6 && CHECK_SIGNATURE_BYTE(6)
#		define CHECK_SIGNATURE_BYTE8 CHECK_SIGNATURE_BYTE7 && CHECK_SIGNATURE_BYTE(7)
#		define CHECK_SIGNATURE_BYTE9 CHECK_SIGNATURE_BYTE8 && CHECK_SIGNATURE_BYTE(8)
#		define CHECK_SIGNATURE_BYTE10 CHECK_SIGNATURE_BYTE9 && CHECK_SIGNATURE_BYTE(9)
#		define CHECK_SIGNATURE_BYTE11 CHECK_SIGNATURE_BYTE10 && CHECK_SIGNATURE_BYTE(10)
#		define CHECK_SIGNATURE_BYTE12 CHECK_SIGNATURE_BYTE11 && CHECK_SIGNATURE_BYTE(11)
#		define CHECK_SIGNATURE_BYTE13 CHECK_SIGNATURE_BYTE12 && CHECK_SIGNATURE_BYTE(12)
#		define CHECK_SIGNATURE_BYTE14 CHECK_SIGNATURE_BYTE13 && CHECK_SIGNATURE_BYTE(13)
#		define CHECK_SIGNATURE_BYTE15 CHECK_SIGNATURE_BYTE14 && CHECK_SIGNATURE_BYTE(14)
#		define CHECK_SIGNATURE_BYTE16 CHECK_SIGNATURE_BYTE15 && CHECK_SIGNATURE_BYTE(15)

#		define PREPROCESSOR_CONCATENATE_EXPANDED(x,y) x##y
#		define PREPROCESSOR_CONCATENATE(x,y) PREPROCESSOR_CONCATENATE_EXPANDED(x,y)
#		define GENERATE_COMPILE_TIME_BYTE_SEQUENCE(number_of_elements_to_generate) PREPROCESSOR_CONCATENATE(GENERATE_COMPILE_TIME_BYTE_SEQUENCE,number_of_elements_to_generate)
#		define CHECK_IF_SIGNATURE_MATCHES_BYTES_AT_ADDRESS(address,number_of_bytes_to_check) 

		// The top-most macros.
#		define COMPARE_SIGNATURE_TO_BYTES_AT_ADDRESS(address) if (char* TJOCk6MZj9H7Z5iFExu9 = address; PREPROCESSOR_CONCATENATE(CHECK_SIGNATURE_BYTE,SIGNATURE_LENGTH))

		// Usage:
		//  1. Define a class that will be used as global singleton. Use only PODs as members. Constructor of that class will be called on injector side.
		//  2. Put DEFINE_INJECTED_GLOBAL_SINGLETON(your_class_name) somewhere near DllMain(), and nowhere else.
		//  3. You can access the singleton on injectee's side by calling GetInjectedGlobalSingleton() function.
#		define DEFINE_INJECTED_GLOBAL_SINGLETON	char SIGNATURE_GLOBAL_VARIABLE_NAME[sizeof(MWR::C3::ReflectiveDll::GlobalInjectedData) > SIGNATURE_LENGTH + 1 \
																				? sizeof(MWR::C3::ReflectiveDll::GlobalInjectedData) \
																				: SIGNATURE_LENGTH + 1] = { 0, GENERATE_COMPILE_TIME_BYTE_SEQUENCE(SIGNATURE_LENGTH) }; \
												MWR::C3::ReflectiveDll::GlobalInjectedData& GetInjectedGlobalSingleton() \
																				{ return reinterpret_cast<MWR::C3::ReflectiveDll::GlobalInjectedData&>(SIGNATURE_GLOBAL_VARIABLE_NAME); }
	}
}
