#pragma once

#include "Config.h"

#include <cassert>
#include <string>

namespace FSecure::WinHttp
{
	enum class Method
	{
		GET,
		POST,
		PUT,
		DEL,
		HEAD,
		OPTIONS,
		TRCE,
		CONNECT,
		MERGE,
		PATCH,
	};

	inline std::wstring GetMethodString(Method method)
	{
		switch (method)
		{
		case (Method::GET): return OBF(L"GET");
		case (Method::POST): return OBF(L"POST");
		case (Method::PUT): return OBF(L"PUT");
		case (Method::DEL): return OBF(L"DELETE");
		case (Method::HEAD): return OBF(L"HEAD");
		case (Method::OPTIONS): return OBF(L"OPTIONS");
		case (Method::TRCE): return OBF(L"TRACE");
		case (Method::CONNECT): return OBF(L"CONNECT");
		case (Method::MERGE): return OBF(L"MERGE");
		case (Method::PATCH): return OBF(L"PATCH");
		default: { assert(false); return L""; }
		};
	}

	enum StatusCode
	{
		Continue = 100,
		SwitchingProtocols = 101,
		OK = 200,
		Created = 201,
		Accepted = 202,
		NonAuthInfo = 203,
		NoContent = 204,
		ResetContent = 205,
		PartialContent = 206,
		MultiStatus = 207,
		AlreadyReported = 208,
		IMUsed = 226,
		MultipleChoices = 300,
		MovedPermanently = 301,
		Found = 302,
		SeeOther = 303,
		NotModified = 304,
		UseProxy = 305,
		TemporaryRedirect = 307,
		PermanentRedirect = 308,
		BadRequest = 400,
		Unauthorized = 401,
		PaymentRequired = 402,
		Forbidden = 403,
		NotFound = 404,
		MethodNotAllowed = 405,
		NotAcceptable = 406,
		ProxyAuthRequired = 407,
		RequestTimeout = 408,
		Conflict = 409,
		Gone = 410,
		LengthRequired = 411,
		PreconditionFailed = 412,
		RequestEntityTooLarge = 413,
		RequestUriTooLarge = 414,
		UnsupportedMediaType = 415,
		RangeNotSatisfiable = 416,
		ExpectationFailed = 417,
		MisdirectedRequest = 421,
		UnprocessableEntity = 422,
		Locked = 423,
		FailedDependency = 424,
		UpgradeRequired = 426,
		PreconditionRequired = 428,
		TooManyRequests = 429,
		RequestHeaderFieldsTooLarge = 431,
		UnavailableForLegalReasons = 451,
		InternalError = 500,
		NotImplemented = 501,
		BadGateway = 502,
		ServiceUnavailable = 503,
		GatewayTimeout = 504,
		HttpVersionNotSupported = 505,
		VariantAlsoNegotiates = 506,
		InsufficientStorage = 507,
		LoopDetected = 508,
		NotExtended = 510,
		NetworkAuthenticationRequired = 511,
	};

	enum class Header
	{
		Accept,
		AcceptCharset,
		AcceptEncoding,
		AcceptLanguage,
		AcceptRanges,
		AccessControlAllowOrigin,
		Age,
		Allow,
		Authorization,
		CacheControl,
		Connection,
		ContentEncoding,
		ContentLanguage,
		ContentLength,
		ContentLocation,
		ContentMd5,
		ContentRange,
		ContentType,
		ContentDisposition,
		Date,
		Etag,
		Expect,
		Expires,
		From,
		Host,
		IfMatch,
		IfModifiedSince,
		IfNoneMatch,
		IfRange,
		IfUnmodifiedSince,
		LastModified,
		Location,
		MaxForwards,
		Pragma,
		ProxyAuthenticate,
		ProxyAuthorization,
		Range,
		Referer,
		RetryAfter,
		Server,
		Te,
		Trailer,
		TransferEncoding,
		Upgrade,
		UserAgent,
		Vary,
		Via,
		Warning,
		WwwAuthenticate,
	};

	inline std::wstring GetHeaderName(Header header)
	{
		switch (header)
		{
		case Header::Accept: return OBF(L"Accept");
		case Header::AcceptCharset: return OBF(L"Accept-Charset");
		case Header::AcceptEncoding: return OBF(L"Accept-Encoding");
		case Header::AcceptLanguage: return OBF(L"Accept-Language");
		case Header::AcceptRanges: return OBF(L"Accept-Ranges");
		case Header::AccessControlAllowOrigin: return OBF(L"Access-Control-Allow-Origin");
		case Header::Age: return OBF(L"Age");
		case Header::Allow: return OBF(L"Allow");
		case Header::Authorization: return OBF(L"Authorization");
		case Header::CacheControl: return OBF(L"Cache-Control");
		case Header::Connection: return OBF(L"Connection");
		case Header::ContentEncoding: return OBF(L"Content-Encoding");
		case Header::ContentLanguage: return OBF(L"Content-Language");
		case Header::ContentLength: return OBF(L"Content-Length");
		case Header::ContentLocation: return OBF(L"Content-Location");
		case Header::ContentMd5: return OBF(L"Content-MD5");
		case Header::ContentRange: return OBF(L"Content-Range");
		case Header::ContentType: return OBF(L"Content-Type");
		case Header::ContentDisposition: return OBF(L"Content-Disposition");
		case Header::Date: return OBF(L"Date");
		case Header::Etag: return OBF(L"ETag");
		case Header::Expect: return OBF(L"Expect");
		case Header::Expires: return OBF(L"Expires");
		case Header::From: return OBF(L"From");
		case Header::Host: return OBF(L"Host");
		case Header::IfMatch: return OBF(L"If-Match");
		case Header::IfModifiedSince: return OBF(L"If-Modified-Since");
		case Header::IfNoneMatch: return OBF(L"If-None-Match");
		case Header::IfRange: return OBF(L"If-Range");
		case Header::IfUnmodifiedSince: return OBF(L"If-Unmodified-Since");
		case Header::LastModified: return OBF(L"Last-Modified");
		case Header::Location: return OBF(L"Location");
		case Header::MaxForwards: return OBF(L"Max-Forwards");
		case Header::Pragma: return OBF(L"Pragma");
		case Header::ProxyAuthenticate: return OBF(L"Proxy-Authenticate");
		case Header::ProxyAuthorization: return OBF(L"Proxy-Authorization");
		case Header::Range: return OBF(L"Range");
		case Header::Referer: return OBF(L"Referer");
		case Header::RetryAfter: return OBF(L"Retry-After");
		case Header::Server: return OBF(L"Server");
		case Header::Te: return OBF(L"TE");
		case Header::Trailer: return OBF(L"Trailer");
		case Header::TransferEncoding: return OBF(L"Transfer-Encoding");
		case Header::Upgrade: return OBF(L"Upgrade");
		case Header::UserAgent: return OBF(L"User-Agent");
		case Header::Vary: return OBF(L"Vary");
		case Header::Via: return OBF(L"Via");
		case Header::Warning: return OBF(L"Warning");
		case Header::WwwAuthenticate: return OBF(L"WWW-Authenticate");
		default: {assert(false); return L""; }
		}
	}

	enum class ContentType
	{
		ApplicationAtomXml,
		ApplicationHttp,
		ApplicationJavascript,
		ApplicationJson,
		ApplicationJsonUtf8,
		ApplicationXjson,
		ApplicationOctetstream,
		ApplicationXWwwFormUrlencoded,
		MultipartFormData,
		Boundary,
		FormData,
		ApplicationXjavascript,
		ApplicationXml,
		MessageHttp,
		Text,
		TextJavascript,
		TextJson,
		TextPlain,
		TextPlainUtf16,
		TextPlainUtf16le,
		TextPlainUtf8,
		TextXjavascript,
		TextXjson,
	};

	inline std::wstring GetContentType(ContentType contentType)
	{
		switch (contentType)
		{
		case ContentType::ApplicationAtomXml: return OBF(L"application/atom+xml");
		case ContentType::ApplicationHttp: return OBF(L"application/http");
		case ContentType::ApplicationJavascript: return OBF(L"application/javascript");
		case ContentType::ApplicationJson: return OBF(L"application/json");
		case ContentType::ApplicationJsonUtf8: return OBF(L"application/json;charset=utf-8");
		case ContentType::ApplicationXjson: return OBF(L"application/x-json");
		case ContentType::ApplicationOctetstream: return OBF(L"application/octet-stream");
		case ContentType::ApplicationXWwwFormUrlencoded: return OBF(L"application/x-www-form-urlencoded");
		case ContentType::MultipartFormData: return OBF(L"multipart/form-data");
		case ContentType::Boundary: return OBF(L"boundary");
		case ContentType::FormData: return OBF(L"form-data");
		case ContentType::ApplicationXjavascript: return OBF(L"application/x-javascript");
		case ContentType::ApplicationXml: return OBF(L"application/xml");
		case ContentType::MessageHttp: return OBF(L"message/http");
		case ContentType::Text: return OBF(L"text");
		case ContentType::TextJavascript: return OBF(L"text/javascript");
		case ContentType::TextJson: return OBF(L"text/json");
		case ContentType::TextPlain: return OBF(L"text/plain");
		case ContentType::TextPlainUtf16: return OBF(L"text/plain; charset=utf-16");
		case ContentType::TextPlainUtf16le: return OBF(L"text/plain; charset=utf-16le");
		case ContentType::TextPlainUtf8: return OBF(L"text/plain; charset=utf-8");
		case ContentType::TextXjavascript: return OBF(L"text/x-javascript");
		case ContentType::TextXjson: return OBF(L"text/x-json");
		default: {assert(false); return L""; }
		}
	}
}
