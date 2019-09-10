#pragma once

#include "Common/MWR/CppTools/Hash.h"
#include "InterfaceFactory.h"
#include "Interface.h"

namespace MWR::C3
{
	/// Template class handling registration of Interface before main function.
	/// @tparam Iface. Interface to be registered.
	template <typename Iface, typename AbstractType, HashT clousureConnectorHash = 0>
	struct Register : AbstractType
	{
		Register()
		{
			// Addressing variable in constructor prevents compiler from skipping template instantiation, because of possible side effects.
			static_cast<void>(m_Registered);
			static_cast<void>(s_InterfaceHash);
		}

		/// Main function responsible for registration of interface.
		/// Return value of function is used to initialize static variable assuring execution of code before main.
		/// @returns true.
		static bool Init()
		{
			static_assert(std::is_constructible_v<Iface, ByteView>, "Channel does not declare constructor from ByteView.");
			return InterfaceFactory::Instance().Register<AbstractType>(Iface::s_InterfaceHash, CreateInterfaceData());
		}

	private:
		template <typename T>
		class EnsureDefaultCapability
		{
			template <typename T2> static uint8_t	Test(decltype(T2::GetCapability)*);
			template <typename T2> static uint16_t	Test(...);

		public:
			static constexpr bool HasCustomCapability = (sizeof(Test<T>(nullptr)) == sizeof(uint8_t));
			template <bool>
			static std::string  GetCapability();

			template <>
			static std::string GetCapability<false>()
			{
				return "{}";
			}

			template <>
			static std::string GetCapability<true>()
			{
				return T::GetCapability();
			}
		};

		/// Create object of InterfaceData<AbstractType> to be stored.
		static InterfaceFactory::InterfaceData<AbstractType> CreateInterfaceData()
		{
			InterfaceFactory::InterfaceData<AbstractType> ret;
			ret.m_Builder = [](ByteView bv) { return std::shared_ptr<AbstractType>{ new Iface{ bv } }; };
			ret.m_ClousureConnectorHash = clousureConnectorHash;
			ret.m_StartupJitter = std::pair(Iface::s_MinUpdateFrequency, Iface::s_MaxUpdateFrequency);
#ifdef		C3_IS_GATEWAY
			ret.m_Name = GetInterfaceName<Iface>();
			ret.m_Capability = EnsureDefaultCapability<Iface>::GetCapability<EnsureDefaultCapability<Iface>::HasCustomCapability>(); // Simpler syntax should be available, but I've encountered MSVC bug with SFINAE.
#endif		//C3_IS_GATEWAY

			return ret;
		}

	private:
		/// Static hash of Interface.
		static const HashT s_InterfaceHash;

		/// Optimization member.
		/// Due to linking dependencies (when code is used to generate .lib file) Init() function must be called on static non-member variable in header file.
		/// Each compilation unit will use Init() separetly, but thanks to m_Registered only one will result in performing actual logic.
		static bool m_Registered;
	};

	/// Initialization of Register<T, T2, u32>::m_Registered.
	template <typename T, typename T2, HashT u32>
	bool Register<T, T2, u32>::m_Registered = Register<T, T2, u32>::Init();

	// Hash is calculated at compile time, compiler correctly notes multiple overflow, but it is valid operation for unsigned type and is used as modulo.
#pragma warning( push )
#pragma warning( disable : 4307)
	/// Initialization of Register<T, T2>::s_InterfaceHash.
	template <typename T, typename T2, HashT u32>
	constexpr HashT Register<T, T2, u32>::s_InterfaceHash = Hash::Fnv1aType<T>();
#pragma warning( pop )

	namespace Interfaces
	{
		/// Specialization of Registration mechanism for Channel type Interface.
		template <typename Iface>
		class Channel : public Register<Iface, AbstractChannel>
		{
		public:
			constexpr static std::chrono::milliseconds s_MinUpdateFrequency = 30ms;
			constexpr static std::chrono::milliseconds s_MaxUpdateFrequency = 30ms;

			Channel()
			{
				static_assert(Iface::s_MinUpdateFrequency >= 30ms && Iface::s_MinUpdateFrequency <= Iface::s_MaxUpdateFrequency, "The frequency is set incorrectly");
				m_MinUpdateFrequency = Iface::s_MinUpdateFrequency;
				m_MaxUpdateFrequency = Iface::s_MaxUpdateFrequency;
			}
		};

#ifdef C3_IS_GATEWAY
		/// Specialization of Registration mechanism for Connector type Interface.
		template <typename Iface>
		class Connector : public Register<Iface, AbstractConnector>
		{
		public:
			// connector in fact does not need those values. They are here to satisfy template requirements.
			constexpr static std::chrono::milliseconds s_MinUpdateFrequency = 0ms;
			constexpr static std::chrono::milliseconds s_MaxUpdateFrequency = 0ms;
		};
#else
		/// Don't register the connectors in node builds
		template <typename Iface>
		class Connector : public AbstractConnector
		{
		};
#endif C3_IS_GATEWAY

#pragma warning( push )
#pragma warning( disable : 4307)
		/// Specialization of Registration mechanism for Peripheral type Interface.
		template <typename Iface, typename Closure>
		class Peripheral : public Register<Iface, AbstractPeripheral, Hash::Fnv1aType<Closure>()>
		{
		public:
			constexpr static std::chrono::milliseconds s_MinUpdateFrequency = 30ms;
			constexpr static std::chrono::milliseconds s_MaxUpdateFrequency = 30ms;

			Peripheral()
			{
				static_assert(Iface::s_MinUpdateFrequency >= 30ms && Iface::s_MinUpdateFrequency <= Iface::s_MaxUpdateFrequency, "The frequency is set incorrectly");
				m_MinUpdateFrequency = Iface::s_MinUpdateFrequency;
				m_MaxUpdateFrequency = Iface::s_MaxUpdateFrequency;
			}
		};
#pragma warning( pop )
	}
}
