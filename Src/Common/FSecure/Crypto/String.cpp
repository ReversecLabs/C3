#include "StdAfx.h"
#include "Common/FSecure/Crypto/String.h"

FSecure::Crypto::String::String(std::string_view sv)
    : m_Key{ GenerateSymmetricKey() }
    , m_Data{ EncryptAnonymously(sv, m_Key) }
{

}

FSecure::Crypto::String::String(const char* str)
    : String(std::string_view{ str })
{

}

FSecure::SecureString FSecure::Crypto::String::Decrypt()
{
    auto tmp = m_Data.empty() ? ByteVector{} : DecryptFromAnonymous(m_Data, m_Key);
    return { tmp.begin(), tmp.end() };
}

FSecure::Crypto::String& FSecure::Crypto::String::operator=(std::string_view sv)
{
    m_Key = GenerateSymmetricKey();
    m_Data = EncryptAnonymously(sv, m_Key);
    return *this;
}

