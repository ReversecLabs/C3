#include "StdAfx.h"

#ifdef C3_IS_GATEWAY
#include "AESCTR.h"
#include "tinyAES/aes.hpp"

FSecure::ByteVector FSecure::Crypto::AES_CTR_Process(FSecure::ByteView key, FSecure::ByteView iv, FSecure::ByteView input)
{

    if (key.size() != 16 && key.size() != 24 && key.size() != 32)
        throw std::invalid_argument("Invalid AES key size");

    if (iv.size() != 16)
        throw std::invalid_argument("CTR IV must be 16 bytes");

    FSecure::ByteVector output(input.begin(), input.end()); // Copy input to output

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key.data(), iv.data());
    AES_CTR_xcrypt_buffer(&ctx, output.data(), static_cast<uint32_t>(output.size()));

    return output;
}
#endif