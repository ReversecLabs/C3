#include "StdAfx.h"
#include "Compression.h"
#include "Common/zlib/include/zlib.h"

#if defined _WIN64
#define Z_PLATFORM "x64/"
#else
#define Z_PLATFORM "x86/"
#endif

#if defined _DEBUG
#define Z_DEBUG "d"
#else
#define Z_DEBUG ""
#endif

#pragma comment(lib, "Common/zlib/lib/" Z_PLATFORM "zlib" Z_DEBUG ".lib")

namespace MWR::Compression
{
	template <>
	ByteVector Compress<Deflate>(ByteView data)
	{
		ByteVector ret;
		ret.resize(data.size());

		z_stream defstream;
		defstream.zalloc = Z_NULL;
		defstream.zfree = Z_NULL;
		defstream.opaque = Z_NULL;

		defstream.avail_in = (uInt) data.size();	// size of input
		defstream.next_in = (Bytef*) data.data();	// input pointer
		defstream.avail_out = (uInt) data.size();	// size of output
		defstream.next_out = (Bytef*) ret.data();	// output pointer

		deflateInit2(&defstream,Z_BEST_COMPRESSION, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY);
		deflate(&defstream, Z_FINISH);
		deflateEnd(&defstream);

		// Compression call consumed part of buffer. Compressed size is equal to difference between size of buffer available before and after compression.
		ret.resize(data.size() - defstream.avail_out);

		return ret;
	}

	template <>
	ByteVector Decompress<Deflate>(ByteView data)
	{
		ByteVector ret;
		uint8_t buffer[4096];

		z_stream infstream;
		infstream.zalloc = Z_NULL;
		infstream.zfree = Z_NULL;
		infstream.opaque = Z_NULL;

		infstream.avail_in = (uInt)data.size();		// size of input
		infstream.next_in = (Bytef*)data.data();	// input pointer
		inflateInit2(&infstream, -15);
		do
		{
			infstream.avail_out = (uInt)sizeof(buffer);		// set size to use whole buffer
			infstream.next_out = (Bytef*)buffer;			// store intermediate data in buffer
			inflate(&infstream, Z_NO_FLUSH);				// intermediate call.
			ret.Concat(ByteView{ buffer, sizeof(buffer) - infstream.avail_out });

		} while (infstream.avail_out == 0);					// inflate processed all of data if out buffer was not consumed entirely.
		inflateEnd(&infstream);

		return ret;
	}
}