#pragma once

namespace FSecure::C3::Core
{
	// Forward declarations.
	struct DeviceBridge;

	// Typedefs and constants.
	using ProceduresUnderlyingType = std::int8_t;																		///< Underlying type for Procedure number field.
	using SequenceNumberFieldUnderlyingType = std::uint32_t;															/// Underlying type for Query/Response sequence numbers (including type bits = 2 bits).
	static constexpr unsigned s_SequenceNumberBitLength = sizeof SequenceNumberFieldUnderlyingType * 8 - 2;				///< Number of bits sequence number occupy in the SequenceNumberType type.

	/// Abstract class for all Queries.
	struct BaseQuery
	{
		/// Enumeration for types of responses that can be requested for Queries.
		enum class ResponseType : std::uint8_t
		{
			StatusBits,																									///< Bit field: 00 - success, 01 - error, 10 - partial success, 11 - ACK.
			StatusCode,																									///< First - a bit field: 00 - success, 01 - error, 10 - success + extensions, 11 - partial success. Then StatusCode if the first bit-field was equal to 01 or 11.
			ACK,																										///< No status code nor bits. Just send back the ACK packet as soon as possible.
			StatusCodePlusExtensions,																					///< Same as StatusCode, but with extensions after bit-field, if the first bit field was 2 (e.g. iid of a newly added Interface) or after the StatusCode equal to 01 or 11. If status code doesn't require extensions (e.g. "No GDC") then extensions are omitted.
			None = 255,																									///< Do not respond.
		};

		/// Creates Query that is empty and should be  filled then sent.
		/// @param sender informs on the origin of message.
		BaseQuery(std::weak_ptr<DeviceBridge> sender);

		/// Creates Query that is empty and should be  filled then sent.
		/// @param responseType informs how recipient should react on message.
		BaseQuery(ResponseType responseType = ResponseType::None);

		/// Procedure number getter.
		/// @return Procedure number.
		/// @throws std::logic_error if not overriden.
		virtual ProceduresUnderlyingType GetProcedureNumber() const { throw std::logic_error{ OBF("This method need to be overridden.") }; }

		/// Deleted copy constructor.
		BaseQuery(BaseQuery&) = delete;

		/// Deleted copy assignment operator.
		BaseQuery& operator=(BaseQuery&) = delete;

		/// Default move constructor.
		BaseQuery(BaseQuery&&) = default;

		/// Default move assignment operator.
		BaseQuery& operator=(BaseQuery&&) = default;

		/// Response type setter.
		/// @param responseType response type to set.
		void SetResponseType(ResponseType responseType);

		/// Compiles Query packet into a ByteVector.
		/// @return Packet buffer.
		virtual ByteVector ComposeQueryPacket() const = 0;

		/// Sender Channel Getter.
		/// @return Sender Channel or nullptr if this Query is yet about to be sent.
		std::weak_ptr<DeviceBridge> GetSenderChannel();

		/// Returns sequence Number.
		auto GetSequenceNumber() const
		{
			return m_SequenceNumber;
		}

	protected:
		/// Constructs Procedure header.
		/// @return buffer containing composed header.
		virtual ByteVector CompileProtocolHeader() const = 0;

		/// Constructs Query packet header out of internal state and data.
		/// @return Buffer containing the headers.
		virtual ByteVector CompileQueryHeader() const;

	private:
		/// If true then this Query is just a copy of what was sent form remote Relay. If false then this is going to be send after filling up.
		const bool m_ReceivedOrWillBeSent;

		/// Underlying type for Query / Response sequence numbers(including type bits = 2 bits).
		using SequenceNumberFieldUnderlyingType = std::uint32_t;

		/// Number of bits sequence number occupy in the SequenceNumberType type.
		static constexpr unsigned s_SequenceNumberBitLength = sizeof SequenceNumberFieldUnderlyingType * 8 - 2;

		/// Sequence number
		const SequenceNumberFieldUnderlyingType m_SequenceNumber;

		/// sequence number generator (unique for every Query).
		/// @return a unique number that can be used for a Query sequence number.
		static SequenceNumberFieldUnderlyingType GenerateSequenceNumber();

		std::uint8_t BuildSequenceNumberField(std::uint8_t statusBits) const;

		/// Sender of this Query.Equals nullptr if this Query is yet about to be sent.
		std::weak_ptr<DeviceBridge> m_SenderChannel;

		/// Type of response requested for this Query.
		ResponseType m_ResponseType;
	};
}
