/**
 *  Copyright (C) 2015 Topology LP
 *  All rights reserved.
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to
 *  deal in the Software without restriction, including without limitation the
 *  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 *  sell copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 *  THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 *  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 *  IN THE SOFTWARE.
 */

#ifndef CPPCODEC_DETAIL_STREAM_CODEC
#define CPPCODEC_DETAIL_STREAM_CODEC

#include <stdlib.h> // for abort()
#include <stdint.h>

#include "../parse_error.hpp"
#include "config.hpp"

namespace cppcodec {
namespace detail {

template <typename Codec, typename CodecVariant>
class stream_codec
{
public:
    template <typename Result, typename ResultState> static void encode(
            Result& encoded_result, ResultState&, const uint8_t* binary, size_t binary_size);

    template <typename Result, typename ResultState> static void decode(
            Result& binary_result, ResultState&, const char* encoded, size_t encoded_size);

    static constexpr size_t encoded_size(size_t binary_size) noexcept;
    static constexpr size_t decoded_max_size(size_t encoded_size) noexcept;
};

template <bool GeneratesPadding> // default for CodecVariant::generates_padding() == false
struct padder {
    template <typename CodecVariant, typename Result, typename ResultState, typename EncodedBlockSizeT>
    CPPCODEC_ALWAYS_INLINE void operator()(Result&, ResultState&, EncodedBlockSizeT) { }
};

template<> // specialization for CodecVariant::generates_padding() == true
struct padder<true> {
    template <typename CodecVariant, typename Result, typename ResultState, typename EncodedBlockSizeT>
    CPPCODEC_ALWAYS_INLINE void operator()(
            Result& encoded, ResultState& state, EncodedBlockSizeT num_padding_characters)
    {
        for (EncodedBlockSizeT i = 0; i < num_padding_characters; ++i) {
            data::put(encoded, state, CodecVariant::padding_symbol());
        }
    }
};

template <size_t I>
struct enc {
    // Block encoding: Go from 0 to (block size - 1), append a symbol for each iteration unconditionally.
    template <typename Codec, typename CodecVariant, typename Result, typename ResultState>
    static CPPCODEC_ALWAYS_INLINE void block(Result& encoded, ResultState& state, const uint8_t* src)
    {
        using EncodedBlockSizeT = decltype(Codec::encoded_block_size());
        constexpr static const EncodedBlockSizeT SymbolIndex = static_cast<EncodedBlockSizeT>(I - 1);

        enc<I - 1>().template block<Codec, CodecVariant>(encoded, state, src);
        data::put(encoded, state, CodecVariant::symbol(Codec::template index<SymbolIndex>(src)));
    }

    // Tail encoding: Go from 0 until (runtime) num_symbols, append a symbol for each iteration.
    template <typename Codec, typename CodecVariant, typename Result, typename ResultState,
            typename EncodedBlockSizeT = decltype(Codec::encoded_block_size())>
    static CPPCODEC_ALWAYS_INLINE void tail(
            Result& encoded, ResultState& state, const uint8_t* src, EncodedBlockSizeT num_symbols)
    {
        constexpr static const EncodedBlockSizeT SymbolIndex = Codec::encoded_block_size() - I;
        constexpr static const EncodedBlockSizeT NumSymbols = SymbolIndex + static_cast<EncodedBlockSizeT>(1);

        if (num_symbols == NumSymbols) {
            data::put(encoded, state, CodecVariant::symbol(Codec::template index_last<SymbolIndex>(src)));
            padder<CodecVariant::generates_padding()> pad;
            pad.template operator()<CodecVariant>(encoded, state, Codec::encoded_block_size() - NumSymbols);
            return;
        }
        data::put(encoded, state, CodecVariant::symbol(Codec::template index<SymbolIndex>(src)));
        enc<I - 1>().template tail<Codec, CodecVariant>(encoded, state, src, num_symbols);
    }
};

template<> // terminating specialization
struct enc<0> {

    template <typename Codec, typename CodecVariant, typename Result, typename ResultState>
    static CPPCODEC_ALWAYS_INLINE void block(Result&, ResultState&, const uint8_t*) { }

    template <typename Codec, typename CodecVariant, typename Result, typename ResultState,
            typename EncodedBlockSizeT = decltype(Codec::encoded_block_size())>
    static CPPCODEC_ALWAYS_INLINE void tail(Result&, ResultState&, const uint8_t*, EncodedBlockSizeT)
    {
        abort(); // Not reached: block() should be called if num_symbols == block size, not tail().
    }
};

template <typename Codec, typename CodecVariant>
template <typename Result, typename ResultState>
inline void stream_codec<Codec, CodecVariant>::encode(
        Result& encoded_result, ResultState& state,
        const uint8_t* src, size_t src_size)
{
    using encoder = enc<Codec::encoded_block_size()>;

    const uint8_t* src_end = src + src_size;

    if (src_size >= Codec::binary_block_size()) {
        src_end -= Codec::binary_block_size();

        for (; src <= src_end; src += Codec::binary_block_size()) {
            encoder::template block<Codec, CodecVariant>(encoded_result, state, src);
        }
        src_end += Codec::binary_block_size();
    }

    if (src_end > src) {
        auto remaining_src_len = src_end - src;
        if (!remaining_src_len || remaining_src_len >= Codec::binary_block_size()) {
            abort();
            return;
        }
        auto num_symbols = Codec::num_encoded_tail_symbols(static_cast<uint8_t>(remaining_src_len));
        encoder::template tail<Codec, CodecVariant>(encoded_result, state, src, num_symbols);
    }
}

template <typename Codec, typename CodecVariant>
template <typename Result, typename ResultState>
inline void stream_codec<Codec, CodecVariant>::decode(
        Result& binary_result, ResultState& state,
        const char* src_encoded, size_t src_size)
{
    const char* src = src_encoded;
    const char* src_end = src + src_size;

    uint8_t idx[Codec::encoded_block_size()] = {};
    uint8_t last_value_idx = 0;

    while (src < src_end) {
        if (CodecVariant::should_ignore(idx[last_value_idx] = CodecVariant::index_of(*(src++)))) {
            continue;
        }
        if (CodecVariant::is_special_character(idx[last_value_idx])) {
            break;
        }

        ++last_value_idx;
        if (last_value_idx == Codec::encoded_block_size()) {
            Codec::decode_block(binary_result, state, idx);
            last_value_idx = 0;
        }
    }

    uint8_t last_idx = last_value_idx;
    if (CodecVariant::is_padding_symbol(idx[last_value_idx])) {
        if (!last_value_idx) {
            // Don't accept padding at the start of a block.
            // The encoder should have omitted that padding altogether.
            throw padding_error();
        }
        // We're in here because we just read a (first) padding character. Try to read more.
        ++last_idx;
        while (src < src_end) {
            // Use idx[last_value_idx] to avoid declaring another uint8_t. It's unused now so that's okay.
            if (CodecVariant::is_eof(idx[last_value_idx] = CodecVariant::index_of(*(src++)))) {
                break;
            }
            if (!CodecVariant::is_padding_symbol(idx[last_value_idx])) {
                throw padding_error();
            }

            ++last_idx;
            if (last_idx > Codec::encoded_block_size()) {
                throw padding_error();
            }
        }
    }

    if (last_idx)  {
        if (CodecVariant::requires_padding() && last_idx != Codec::encoded_block_size()) {
            // If the input is not a multiple of the block size then the input is incorrect.
            throw padding_error();
        }
        if (last_value_idx >= Codec::encoded_block_size()) {
            abort();
            return;
        }
        Codec::decode_tail(binary_result, state, idx, last_value_idx);
    }
}

template <typename Codec, typename CodecVariant>
inline constexpr size_t stream_codec<Codec, CodecVariant>::encoded_size(size_t binary_size) noexcept
{
    using C = Codec;

    // constexpr rules make this a lot harder to read than it actually is.
    return CodecVariant::generates_padding()
            // With padding, the encoded size is a multiple of the encoded block size.
            // To calculate that, round the binary size up to multiple of the binary block size,
            // then convert to encoded by multiplying with { base32: 8/5, base64: 4/3 }.
            ? (binary_size + (C::binary_block_size() - 1)
                    - ((binary_size + (C::binary_block_size() - 1)) % C::binary_block_size()))
                    * C::encoded_block_size() / C::binary_block_size()
            // No padding: only pad to the next multiple of 5 bits, i.e. at most a single extra byte.
            : (binary_size * C::encoded_block_size() / C::binary_block_size())
                    + (((binary_size * C::encoded_block_size()) % C::binary_block_size()) ? 1 : 0);
}

template <typename Codec, typename CodecVariant>
inline constexpr size_t stream_codec<Codec, CodecVariant>::decoded_max_size(size_t encoded_size) noexcept
{
    using C = Codec;

    return CodecVariant::requires_padding()
            ? (encoded_size / C::encoded_block_size() * C::binary_block_size())
            : (encoded_size / C::encoded_block_size() * C::binary_block_size())
                    + ((encoded_size % C::encoded_block_size())
                            * C::binary_block_size() / C::encoded_block_size());
}

} // namespace detail
} // namespace cppcodec

#endif // CPPCODEC_DETAIL_STREAM_CODEC
