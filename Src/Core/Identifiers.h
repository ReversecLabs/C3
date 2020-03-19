#pragma once

namespace FSecure::C3
{
	/// An abstract used as a base class for various identifiers used in C3.
	template<typename UnderlyingIntegerType = std::uint16_t>
	struct Identifier
	{
		// ID might only be built upon a fundamental integer type.
		static_assert(std::is_unsigned_v<UnderlyingIntegerType>);

		// Forward template arguments.
		typedef UnderlyingIntegerType UnderlyingIntegerType;

		/// Default ctor.
		constexpr Identifier();

		/// A public ctor.
		/// @param id identifier.
		constexpr Identifier(UnderlyingIntegerType id);

		/// Creates an ID object from a hex string.
		/// @param textId text containing the identifier.
		/// @throws std::runtime_error if string cannot be parsed.
		Identifier(std::string_view textId);

		/// Creates an ID object from a hex string.
		/// @param textId text containing the identifier.
		/// @throws std::runtime_error if string cannot be parsed.
		/// @notes this specialization exist only to satisfy implicit casts requirements.
		Identifier(std::string const& textId);

		/// Creates an ID object with a random ("unique") value.
		/// @return Identifier object.
		static Identifier GenerateRandom();

		/// Converts this ID to a string.
		/// @return a string that describes this ID object.
		std::string ToString() const;

		/// Converts identifier to underlying type.
		/// @returns UnderlyingIntegerType identifier in arithmetic form.
		UnderlyingIntegerType ToUnderlyingType() const;

		/// Logical negation operator. Can be used to check if ID is set.
		/// @return true if ID is not set.
		bool operator !() const;

		/// Comparison operator.
		/// @param c ID object to compare this to.
		/// @return true if provided ID is the same as this.
		bool operator ==(Identifier const& c) const;

		/// Difference operator.
		/// @param c ID object to compare this to.
		/// @return true if provided ID is different from this.
		bool operator !=(Identifier const& c) const;

		/// The less-than comparison operator.
		/// @param c ID object to compare this to.
		/// @return false if provided ID precedes this.
		bool operator <(Identifier const& c) const;

		/// Checks if ID is set.
		/// @return true if ID is set.
		bool IsNull() const;

		static constexpr size_t BinarySize = sizeof(UnderlyingIntegerType);												///< Length of the Identifier written in binary format.
		static constexpr size_t TextSize = BinarySize * 2;																///< Length of the Identifier written in text format.
		static const Identifier Null;																					///< Object that represents invalid Identifier. Might be used to address special cases (such as Gateway which is a special Relay).

	protected:
		UnderlyingIntegerType m_Id;																						///< Underlying ID value.
	};

	// Usings for particular C3 Identifiers.
	using DeviceId = Identifier<>;																						///< ID used by Relays to address attached Devices.
	using AgentId = Identifier<std::uint64_t>;																			///< ID of Relay's instance (i.e. instances of a particular Build).
	using BuildId = Identifier<std::uint32_t>;																			///< ID of Relay's configuration.
}

// Include template's implementation.
#include "Identifiers.hxx"
