#pragma once

#include "UniqueHandle.h"

namespace MWR::WinTools
{
	/// Class that does not own any pipe, can be used to read and write data in alternating way.
	class AlternatingPipe // TODO support for creating pipe.
	{
	public:
		/// Public constructor.
		///
		/// @param pipename. Name used for pipe registration. Pipe prefix is not required.
		/// @throws std::runtime_error on any WinAPI errors occurring.
		AlternatingPipe(ByteView pipename);

		/// Sends data to pipe.
		/// @param data buffer to send.
		/// @throws std::runtime_error on any WinAPI errors occurring during writing to the named pipe.
		ByteVector Read();

		///Covenant specific implementation of Read
		ByteVector ReadCov();

		/// Retrieves data from the pipe.
		/// @throws std::runtime_error on any WinAPI errors occurring during reading from the named pipe.
		size_t Write(ByteView data);

		///Covenant specific implementation of Write
		size_t WriteCov(ByteView data);
	private:
		/// Name of the Pipe used to communicate with the implant.
		std::string m_PipeName;

		/// Communication Pipe handle.
		UniqueHandle m_Pipe;

		/// Unnamed event used to synchronize reads/writes to the pipe.
		UniqueHandle m_Event;
	};

	/// Class that owns one pipe and can write to it.
	class WritePipe
	{
	public:
		/// Public constructor.
		///
		/// @param pipename. Name used for pipe registration. Pipe prefix is not required.
		WritePipe(ByteView pipename);

		/// Connects pipe and writes whole message to pipe.
		///
		/// @param data to be written.
		/// @note function automatically adds 4 byte size prefix before actual data.
		/// @throws std::runtime_error if data.size() cannot be stored in uint32_t. This condition is highly unlikly in normal use.
		/// @throws std::runtime_error if conection was closed from other side during transmision.
		size_t Write(ByteView data);

	private:
		/// Name of pipe.
		std::string m_PipeName;

		/// Unique handle to pipe. Handle will be closed by custom deleter.
		std::unique_ptr<void, std::function<void(void*)>> m_Pipe;
	};

	/// Class that does not own any pipe, can be used to read data.
	class ReadPipe
	{
	public:
		/// Public constructor.
		///
		/// @param pipename. Name used for pipe registration. Pipe prefix is not required.
		ReadPipe(ByteView pipename);

		/// Tries to connect to opened pipe and reed one packet of data.
		///
		/// @note function automatically use 4 byte size prefix to consume whole packet. This prefix will not be present in returned string.
		/// @throws std::runtime_error if conection was closed from other side during transmision.
		ByteVector Read();

	private:
		/// Name of pipe.
		std::string m_PipeName;
	};

	/// Class using two pipe for duplex transmission.
	///
	/// Objects of PipeHelper should be used in pairs on both sides of communication.
	/// Methods of this class does not introduce new threads. Use external thread objects to preform asynchronous communication.
	class DuplexPipe
	{
	public:
		/// Public constructor.
		///
		/// @param inputPipeName. Name used for pipe registration. Pipe prefix is not required.
		/// @param outputPipeName. Name used for pipe registration. Pipe prefix is not required.
		DuplexPipe(ByteView inputPipeName, ByteView outputPipeName);

		/// Public constructor.
		///
		/// @param pipeNames. Tuple with first two arguments convertible to ByteView.
		template<typename T, std::enable_if_t<(std::tuple_size_v<T> > 1), int> = 0>
		DuplexPipe(T pipeNames)
			: DuplexPipe(std::get<0>(pipeNames), std::get<1>(pipeNames))
		{

		}

		/// Tries to connect to opened pipe and reed one packet of data.
		///
		/// @note function automatically use 4 byte size prefix to consume whole packet. This prefix will not be present in returned string.
		/// @throws std::runtime_error if conection was closed from other side during transmision.
		ByteVector Read();

		
		/// Connects pipe and writes whole message to pipe.
		///
		/// @param data to be written.
		/// @note function automatically adds 4 byte size prefix before actual data.
		/// @throws std::runtime_error if data.size() cannot be stored in uint32_t. This condition is highly unlikly in normal use.
		/// @throws std::runtime_error if conection was closed from other side during transmision.
		size_t Write(ByteView data);
		
	private:
		/// Input pipe.
		ReadPipe m_InputPipe;
		
		/// Output pipe.
		WritePipe m_OutputPipe;
	};
}
