#pragma once

#include "Common/FSecure/CppTools/Hash.h"
#include "InterfaceFactory.h"
#include "Interface.h"

namespace FSecure::C3
{
	/// Template class handling registration of Interface before main function.
	/// @tparam Iface. Interface to be registered.
	template <typename Iface, typename AbstractType, HashT clousureConnectorHash = 0>
	struct Register : AbstractType
	{
		virtual ~Register()
		{
			// Addressing variable in virtual destructor prevents compiler from skipping template instantiation, because of possible side effects.
			// Similar effect can be achieved in gcc with attribute 'used'
			// Clang can ignore both approaches, if Iface does not declare any custom constructor.
			static_cast<void>(m_Registered);
			static_cast<void>(s_InterfaceHash);
		}

	private:
		/// Main function responsible for registration of interface.
		/// Return value of function is used to initialize static variable assuring execution of code before main.
		/// @returns true.
		static bool Init()
		{
			static_assert(std::is_constructible_v<Iface, ByteView>, "Channel does not declare constructor from ByteView.");
			return InterfaceFactory::Instance().Register<AbstractType>(Iface::s_InterfaceHash, CreateInterfaceData());
		}

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
			ret.m_StartupJitter = std::pair(Iface::s_MinUpdateDelay, Iface::s_MaxUpdateDelay);
#ifdef		C3_IS_GATEWAY
			ret.m_Name = GetInterfaceName<Iface>();
			ret.m_Capability = EnsureDefaultCapability<Iface>::template GetCapability<EnsureDefaultCapability<Iface>::HasCustomCapability>(); // Simpler syntax should be available, but I've encountered MSVC bug with SFINAE.
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
			constexpr static std::chrono::milliseconds s_MinUpdateDelay = 30ms;
			constexpr static std::chrono::milliseconds s_MaxUpdateDelay = 30ms;

			/// Constructor setting default update frequency for channel
			Channel()
			{
				static_assert(Iface::s_MinUpdateDelay >= 30ms && Iface::s_MinUpdateDelay <= Iface::s_MaxUpdateDelay, "The frequency is set incorrectly");
				this->m_MinUpdateDelay = Iface::s_MinUpdateDelay;
				this->m_MaxUpdateDelay = Iface::s_MaxUpdateDelay;
			}

			/// Callback that is periodically called for every Device to update itself.
			/// This is point where dynamic polymorphisms is replaced by static one with recognition of returned value.
			/// Types using Channel CRTP should implement FSecure::ByteVector OnReceiveFromChannel(), or std::vector<FSecure::ByteVector> OnReceiveFromChannel()
			/// @return std::vector<ByteVector> that contains all packets retrieved from Channel.
			std::vector<ByteVector> OnReceiveFromChannelInternal() override final
			{
				static_assert(CanRecive<>::value, "OnReceiveFromChannel is not implemented");
				static_assert(std::is_same_v<ReceiveReturnType<Iface>, ByteVector> || std::is_same_v<ReceiveReturnType<Iface>, std::vector<ByteVector>>, "OnReceiveFromChannel should return ByteVector or std::vector<ByteVector>");
				return ReceiveWrapper<Iface>();
			}

			/// Called every time Relay wants to send a packet through this Channel Device.
			/// This is point where dynamic polymorphisms is replaced by static one.
			/// Types using Channel CRTP should implement size_t OnSendToChannel(ByteView).
			/// @param blob buffer containing data to send.
			size_t  OnSendToChannelInternal(ByteView packet) override final
			{
				static_assert(CanSend<ByteView>::value, "OnSendToChannel is not implemented");
				auto self = static_cast<Iface*>(this);
				return self->OnSendToChannel(packet);
			}

		private:
			/// Alias to get result of OnReceiveFromChannel call.
			/// Use in form ReceiveReturnType<Iface> to obtain type.
			/// Can fail if function is not implemented.
			template<class T, class...Ts>
			using ReceiveReturnType = decltype(std::declval<T>().OnReceiveFromChannel(std::declval<Ts>()...));

			/// Alias to test if OnReceiveFromChannel is implemented.
			/// Use in form CanRecive<Iface>::value to obtain bool value with information.
			template<class...Ts>
			using CanRecive = FSecure::Utils::CanApply<ReceiveReturnType, Iface, Ts...>;

			/// Alias to get result of OnSendToChannel call.
			/// Use in form SendReturnType<Iface, ByteView> to obtain type.
			/// Can fail if function is not implemented.
			template<class T, class...Ts>
			using SendReturnType = decltype(std::declval<T>().OnSendToChannel(std::declval<Ts>()...));

			/// Alias to test if OnSendToChannel is implemented.
			/// Use in form CanSend<Iface>::value to obtain bool value with information.
			template<class...Ts>
			using CanSend = FSecure::Utils::CanApply<SendReturnType, Iface, Ts...>;

			/// Virtual OnSendToChannelInternal cannot be templated.
			/// This function will be available for call if OnReceiveFromChannel returns ByteVector.
			/// @returns std::vector<ByteVector> one packet pushed on collection if it is not empty..
			template <typename T>
			std::enable_if_t<std::is_same_v<ReceiveReturnType<T>, ByteVector>, std::vector<ByteVector>> ReceiveWrapper()
			{
				auto self = static_cast<Iface*>(this);
				std::vector<ByteVector> ret;
				if (auto packet = self->OnReceiveFromChannel(); !packet.empty())
					ret.push_back(std::move(packet));

				return ret;
			}

			/// Virtual OnSendToChannelInternal cannot be templated.
			/// This function will be available for call if OnReceiveFromChannel returns std::vector<ByteVector>.
			/// @returns std::vector<ByteVector> many packets that are not empty.
			template <typename T>
			std::enable_if_t<std::is_same_v<ReceiveReturnType<T>, std::vector<ByteVector>>, std::vector<ByteVector>> ReceiveWrapper()
			{
				auto self = static_cast<Iface*>(this);
				auto ret = self->OnReceiveFromChannel();
				static_cast<void>(std::remove_if(ret.begin(), ret.end(), [](auto&& e) { return e.empty(); }));
				return ret;
			}
		};

#ifdef C3_IS_GATEWAY
		/// Specialization of Registration mechanism for Connector type Interface.
		template <typename Iface>
		class Connector : public Register<Iface, AbstractConnector>
		{
		public:
			// connector in fact does not need those values. They are here to satisfy template requirements.
			constexpr static std::chrono::milliseconds s_MinUpdateDelay = 0ms;
			constexpr static std::chrono::milliseconds s_MaxUpdateDelay = 0ms;
		};
#else
		/// Don't register the connectors in node builds
		template <typename Iface>
		class Connector : public AbstractConnector
		{
		};
#endif // C3_IS_GATEWAY

#pragma warning( push )
#pragma warning( disable : 4307)
		/// Specialization of Registration mechanism for Peripheral type Interface.
		template <typename Iface, typename Closure>
		class Peripheral : public Register<Iface, AbstractPeripheral, Hash::Fnv1aType<Closure>()>
		{
		public:
			constexpr static std::chrono::milliseconds s_MinUpdateDelay = 30ms;
			constexpr static std::chrono::milliseconds s_MaxUpdateDelay = 30ms;

			Peripheral()
			{
				static_assert(Iface::s_MinUpdateDelay >= 30ms && Iface::s_MinUpdateDelay <= Iface::s_MaxUpdateDelay, "The frequency is set incorrectly");
				this->m_MinUpdateDelay = Iface::s_MinUpdateDelay;
				this->m_MaxUpdateDelay = Iface::s_MaxUpdateDelay;
			}
		};
#pragma warning( pop )
	}
}
