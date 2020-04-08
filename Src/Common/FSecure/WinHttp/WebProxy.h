#pragma once

#include "Uri.h"

namespace FSecure::WinHttp
{
	// from cpprestsdk
	class WebProxy
	{
		enum class ModeInternal
		{
			UseDefault,
			UseAutoDiscovery,
			Disabled,
			UserProvided
		};

	public:
		enum class Mode
		{
			UseDefault = static_cast<int>(ModeInternal::UseDefault),
			UseAutoDiscovery = static_cast<int>(ModeInternal::UseAutoDiscovery),
			Disabled = static_cast<int>(ModeInternal::Disabled)
		};

		/// <summary>
		/// Constructs a proxy with the default settings.
		/// </summary>
		WebProxy() : m_Address(), m_Mode(ModeInternal::UseDefault) {}

		/// <summary>
		/// Creates a proxy with specified mode.
		/// </summary>
		/// <param name="mode">Mode to use.</param>
		WebProxy(Mode mode) : m_Address(), m_Mode(static_cast<ModeInternal>(mode)) {}

		/// <summary>
		/// Creates a proxy explicitly with provided address.
		/// </summary>
		/// <param name="address">Proxy URI to use.</param>
		WebProxy(Uri address) : m_Address(std::move(address)), m_Mode(ModeInternal::UserProvided) {}

		/// <summary>
		/// Gets this proxy's URI address. Returns an empty URI if not explicitly set by user.
		/// </summary>
		/// <returns>A reference to this proxy's URI.</returns>
		const Uri& Address() const { return m_Address; }

		/* No proxy authentication support RN
		/// <summary>
		/// Gets the credentials used for authentication with this proxy.
		/// </summary>
		/// <returns>Credentials to for this proxy.</returns>
 		const web::credentials& credentials() const { return m_credentials; }

		/// <summary>
		/// Sets the credentials to use for authentication with this proxy.
		/// </summary>
		/// <param name="cred">Credentials to use for this proxy.</param>
		void set_credentials(web::credentials cred)
		{
			if (m_mode == disabled_)
			{
				throw std::invalid_argument("Cannot attach credentials to a disabled proxy");
			}
			m_credentials = std::move(cred);
		}
		*/

		/// <summary>
		/// Checks if this proxy was constructed with default settings.
		/// </summary>
		/// <returns>True if default, false otherwise.</param>
		bool IsDefault() const { return m_Mode == ModeInternal::UseDefault; }

		/// <summary>
		/// Checks if using a proxy is disabled.
		/// </summary>
		/// <returns>True if disabled, false otherwise.</returns>
		bool IsDisabled() const { return m_Mode == ModeInternal::Disabled; }

		/// <summary>
		/// Checks if the auto discovery protocol, WPAD, is to be used.
		/// </summary>
		/// <returns>True if auto discovery enabled, false otherwise.</returns>
		bool IsAutoDiscovery() const { return m_Mode == ModeInternal::UseAutoDiscovery; }

		/// <summary>
		/// Checks if a proxy address is explicitly specified by the user.
		/// </summary>
		/// <returns>True if a proxy address was explicitly specified, false otherwise.</returns>
		bool IsSpecified() const { return m_Mode == ModeInternal::UserProvided; }

	private:
		Uri m_Address;
		ModeInternal m_Mode;
		// 		web::credentials m_credentials;
	};
}
