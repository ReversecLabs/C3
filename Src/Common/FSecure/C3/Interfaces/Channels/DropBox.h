#pragma once

namespace FSecure::C3::Interfaces::Channels
{
    /// Implementation of a File Channel.
    class DropBox : public FSecure::C3::Interfaces::Channel<DropBox>
    {
    public:
        /// Public constructor.
        /// @param arguments factory arguments.
        DropBox(FSecure::ByteView arguments);

        /// OnSend callback implementation. Called every time attached Relay wants to send a packet through this Channel Device. @see Device::OnSendToChannelInternal.
        /// @param packet data to send through the Channel.
        /// @return number of bytes successfully sent through the Channel. One call does not have to send all data. In that case chunking will take place, Chunks must be at least 64 bytes or equal to packet.size() to be accepted,
        size_t OnSendToChannel(FSecure::ByteView packet);

        /// Reads a single C3 packet from Channel. Periodically called by attached Relay. Implementation should read the data (or return an empty buffer if there's nothing in the Channel waiting to read) and leave as soon as possible.
        /// @return ByteVector that contains a single packet retrieved from Channel.
        FSecure::ByteVector OnReceiveFromChannel();


        /// Describes Channels creation parameters and custom Commands.
        /// @return Channel's capability description in JSON format.
        static const char* GetCapability();

        /// Makes a HTTP POST Request
        /// return HTTP response as a string if status is 200
        std::string SendHTTPRequest(std::string const& host, std::string const& contentType, std::string const& data);

        /// Makes a HTTP POST Request with additional headers
        /// return HTTP response as a string if status is 200
        std::string SendHTTPRequest(std::string const& host, json const& h_args, std::string const& contentType, std::string const& data);

        /// Makes a HTTP POST Request
        /// parses the HTTP response as a json string if status is 200
        json SendJsonRequest(std::string const& url, json const& data);

        /// Makes a HTTP POST Request with additional headers
        /// parses the HTTP response as a json string if status is 200
        json SendJsonRequest(std::string const& url, json const& h_args, std::string data);

        /// Processes Commands addressed to this Channel.
        /// @param command a buffer containing whole command and it's parameters.
        /// @return command result.
        ByteVector OnRunCommand(ByteView command) override;

        /// Clears all files created on Dropbox
        /// returns true if success
        bool Clear();

        /// Explicit values used as the defaults for Channel's UpdateDelayJitter. Values can be changed later, at runtime.
        constexpr static std::chrono::milliseconds s_MinUpdateDelay = 1000ms, s_MaxUpdateDelay = 1000ms;

    protected:
        /// Name of file used to receive data.
        std::string m_inFile;

        /// Name of file used to send data.
        std::string m_outFile;

        /// The Directory name to use in DropBox
        std::string m_Directory;

        /// Code token to communicate with API
        std::string m_Token;

    private:
        web::http::client::http_client_config m_HttpConfig;
    };
}