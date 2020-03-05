#pragma once

namespace FSecure::CppCommons::CppTools
{
#	pragma region Internal structures

	/// Base, abstract structure for all XError incarnations.
	template <typename UnderlyingType> struct XErrorBase
	{
		/// Template params storage.
		typedef UnderlyingType UnderlyingType;

		/// Public ctor.
		/// @param value initialization value.
		XErrorBase(UnderlyingType value) : m_Value(value) { /*XErrorLogger(&value);*/ }

		/// UnderlyingType conversion operator.
		/// @return XError's UnderlyingObject's current value.
		operator UnderlyingType() { return m_Value; }

		/// Constant UnderlyingType conversion operator.
		/// @return XError's UnderlyingObject's current value.
		operator UnderlyingType() const { return m_Value; }

		/// Dereference operator.
		/// @return XError's UnderlyingObject's current value.
		UnderlyingType* operator * () { return &m_Value; }

		/// Constant dereference operator.
		/// @return XError's UnderlyingObject's current value.
		UnderlyingType* operator * () const { return &m_Value; }

		/// Arrow operator.
		/// @return XError's UnderlyingObject's current value.
		UnderlyingType* operator -> () { return &m_Value; }

		/// Constant arrow operator.
		/// @return XError's UnderlyingObject's current value.
		UnderlyingType* operator -> () const { return &m_Value; }

	protected:
		UnderlyingType m_Value;													///< Underlying value.
	};

	/// SFINAE for IsSuccess and IsFailure member functions. Used by XError template to deduce its contents.
	template<typename Type> class XErrorContentDeducer
	{
		typedef char yes[1];													///< Return type used to describe positive SFINAE resolution.
		typedef char no[2];														///< Return type used to describe negative SFINAE resolution.
		template<typename U, bool (U::*)() const> struct SFINAE {};				///< Function signature. Note that it's the same for both IsSuccess and IsFailure.

		template<typename U> static yes& TestIsSuccess(SFINAE<U, &U::IsSuccess>*);					///< Positive tester for IsSuccess.
		template<typename U> static no& TestIsSuccess(...);						///< Negative tester for IsSuccess.

		template<typename U> static yes& TestIsFailure(SFINAE<U, &U::IsFailure>*);					///< Positive tester for IsFailure.
		template<typename U> static no& TestIsFailure(...);						///< Negative tester for IsFailure.

	public:
		static const bool hasIsSuccess = sizeof(TestIsSuccess<Type>(nullptr)) == sizeof(yes);		///< Final tester for IsSuccess.
		static const bool hasIsFailure = sizeof(TestIsFailure<Type>(nullptr)) == sizeof(yes);		///< Final tester for IsFailure.
	};

	/// Abstract parent template to all XErrorImpl. @note You shouldn't use XErrorImpl templates directly. They have internal purposes. Use XError template instead.
	template <typename UnderlyingType, bool HasIsSuccessMethod, bool HasIsFailureMethod, bool IsPointer, bool IsEnum> struct XErrorImpl;

	/// XError specialization for types devoid of both IsSuccess and IsFailure methods. @note You shouldn't use XErrorImpl templates directly. They have internal purposes. Use XError template instead.
	template <typename UnderlyingType> struct XErrorImpl<UnderlyingType, false, false, false, false> : public XErrorBase<UnderlyingType>
	{
		/// Public ctor.
		/// @param value object value
		XErrorImpl(UnderlyingType value) : XErrorBase(value) { }
	};

	/// XError specialization for types that have no IsFailure method but do have IsSuccess method implemented. @note You shouldn't use XErrorImpl templates directly. They have internal purposes. Use XError template instead.
	template <typename UnderlyingType> struct XErrorImpl<UnderlyingType, true, false, false, false> : public XErrorBase<UnderlyingType>
	{
		/// Public ctor.
		/// @param value object value
		XErrorImpl(UnderlyingType value) : XErrorBase(value) { }

		/// Success translator.
		/// @return true if current state of the object indicates success.
		bool IsSuccess() const { return m_Value.IsSuccess(m_Value); }
	};

	/// XError specialization for types that have no IsSuccess method but do have IsFailure method implemented. @note You shouldn't use XErrorImpl templates directly. They have internal purposes. Use XError template instead.
	template <typename UnderlyingType> struct XErrorImpl<UnderlyingType, false, true, false, false> : public XErrorBase<UnderlyingType>
	{
		/// Public ctor.
		/// @param value object value
		XErrorImpl(UnderlyingType value) : XErrorBase(value) { }

		/// Failure translator.
		/// @return true if current state of the object indicates failure.
		bool IsFailure() const { return m_Value.IsFailure(); }
	};

	/// XError specialization for types that have both IsSuccess and IsFailure methods implemented. @note You shouldn't use XErrorImpl templates directly. They have internal purposes. Use XError template instead.
	template <typename UnderlyingType> struct XErrorImpl<UnderlyingType, true, true, false, false> : public XErrorBase<UnderlyingType>
	{
		/// Public ctor.
		/// @param value object value
		XErrorImpl(UnderlyingType value) : XErrorBase(value) { }

		/// Success translator.
		/// @return true if current state of the object indicates success.
		bool IsSuccess() const { return m_Value.IsSuccess(); }

		/// Failure translator.
		/// @return true if current state of the object indicates failure.
		bool IsFailure() const { return m_Value.IsFailure(); }
	};

	/// XError specialization for HRESULT - let's provide IsSuccess and IsFailure. @note You shouldn't use XErrorImpl templates directly. They have internal purposes. Use XError template instead.
	template <> struct XErrorImpl<HRESULT, false, false, false, false> : public XErrorBase<HRESULT>
	{
		/// Public ctor.
		/// @param value object value
		XErrorImpl(HRESULT value) : XErrorBase(value) { }

		/// Success translator.
		/// @return true if current state of the object indicates success.
		bool IsSuccess() const { return SUCCEEDED(m_Value); }

		/// Failure translator.
		/// @return true if current state of the object indicates failure.
		bool IsFailure() const { return FAILED(m_Value); }
	};

	/// XError specialization for bool type. IsSuccess and IsFailure methods are just value redirectors. @note You shouldn't use XErrorImpl templates directly. They have internal purposes. Use XError template instead.
	template <> struct XErrorImpl<bool, false, false, false, false> : public XErrorBase<bool>
	{
		/// Public ctor.
		/// @param value object value
		XErrorImpl(bool value) : XErrorBase(value) { }

		/// Success translator.
		/// @return true if current state of the object indicates success.
		bool IsSuccess() const { return m_Value; }

		/// Failure translator.
		/// @return true if current state of the object indicates failure.
		bool IsFailure() const { return !m_Value; }
	};

	/// XError specialization for pointers. IsSuccess and IsFailure are comparisons to nullptr. @note You shouldn't use XErrorImpl templates directly. They have internal purposes. Use XError template instead.
	template <typename UnderlyingPointerType> struct XErrorImpl<UnderlyingPointerType, false, false, true, false> : public XErrorBase<UnderlyingPointerType>
	{
		/// Public ctor.
		/// @param value object value
		XErrorImpl(UnderlyingPointerType value) : XErrorBase(value) { }

		/// Success translator.
		/// @return true if current state of the object indicates success.
		bool IsSuccess() const { return m_Value; }

		/// Failure translator.
		/// @return true if current state of the object indicates failure.
		bool IsFailure() const { return !m_Value; }
	};

	/// XError specialization for enums. We assume here that value equal to zero means success. @note You shouldn't use XErrorImpl templates directly. They have internal purposes. Use XError template instead.
	template <typename UnderlyingEnumType> struct XErrorImpl<UnderlyingEnumType, false, false, false, true> : public XErrorBase<UnderlyingEnumType>
	{
		/// Public ctor.
		/// @param value object value
		XErrorImpl(UnderlyingEnumType value) : XErrorBase(value) { }

		/// Success translator.
		/// @return true if current state of the object indicates success.
		bool IsSuccess() const { return (long long int)(m_Value) == 0; }

		/// Failure translator.
		/// @return true if current state of the object indicates failure.
		bool IsFailure() const { return (long long int)(m_Value) != 0; }
	};

	/// EnumWithHresult structure. A handy wrapper for functions performing many API calls, to indicate not only which error (HRESULT), but where (provided enum) it was obtained.
	template<typename Enum> struct EnumWithHresult
	{
		/// Template params storage.
		typedef Enum Enum;

		/// Getter for underlying enum.
		/// @return underlying enum.
		Enum GetApiCall() const { return m_ApiCall; }

		/// Getter for hresult.
		/// @return hresult value.
		HRESULT GetHresult() const { return m_ErrorCode; }

		/// Success translator.
		/// @return true if current state of the object indicates success.
		bool IsSuccess() const { return SUCCEEDED(m_ErrorCode); }

		/// Failure translator.
		/// @return true if current state of the object indicates failure.
		bool IsFailure() const { return FAILED(m_ErrorCode); }

		// Public members provided to allow simple initialization of EnumWithHresult with aggregation operator { }.
		Enum m_ApiCall;															///< Underlying enum value.
		HRESULT m_ErrorCode;													///< HRESULT value.
	};

	/// SystemError structure. A handy wrapper that can be used in code sections which disallows converting system error code to HRESULT.
	struct SystemErrorCode
	{
		/// Public ctor.
		SystemErrorCode(DWORD code) : m_ErrorCode(code) { }

		/// Success translator.
		/// @return true if current state of the object indicates success.
		bool IsSuccess() const { return !m_ErrorCode; }

		/// Failure translator.
		/// @return true if current state of the object indicates failure.
		bool IsFailure() const { return m_ErrorCode != 0; }

		/// Const DWORD conversion operator.
		operator DWORD () const { return m_ErrorCode; }

		/// DWORD conversion operator.
		operator DWORD () { return m_ErrorCode; }

		// Public members provided to allow simple initialization of this structure with aggregation operator { }.
		DWORD m_ErrorCode;														///< System error code value.
	};

#	pragma endregion Internal structures
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	// Finally, the XError alias templates.
	template<typename T> using XError = XErrorImpl<T, XErrorContentDeducer<T>::hasIsSuccess, XErrorContentDeducer<T>::hasIsFailure, std::is_pointer<T>::value, std::is_enum<T>::value>; ///< Main deducer.
	template<typename T> using XErrorRaw = XErrorImpl<T, false, false, false, false>;				///< XError devoid of implicit IsSuccess and IsFailure implementations.
	template<typename T> using XErrorEnumWithHresult = XError<EnumWithHresult<T>>;					///< A handy alias for XError specialization with EnumWithHresult.

	// Creator templates.
	template<typename T> XError<T> XErrorCreator(const T& value) { return value; }										///< A universal Creator.
	template<typename T> XErrorRaw<T> XErrorRawCreator(const T& value) { return value; }								///< Creator of raw XErrors.
	template<typename TEnum> XErrorEnumWithHresult<TEnum> XErrorEnumWithHresultCreator(TEnum enumValue, HRESULT hr)		///< Creator for EnumWithHresult template.
		{ static_assert(std::is_enum<TEnum>::value, OBF("XErrorEwhCreator template requires enumeration type.")); return FSecure::CppCommons::CppTools::EnumWithHresult<TEnum>{ enumValue, hr }; }

	// Macros. @warning There is no XError<decltype(GetLastError())>. Value got by calling GetLastError() should be immediately converted to HRESULT, e.g. by using those macros:
#	define XERROR_GETLASTERROR FSecure::CppCommons::CppTools::XErrorCreator(HRESULT_FROM_WIN32(GetLastError()))
#	define XERRORRAW_GETLASTERROR FSecure::CppCommons::CppTools::XErrorRawCreator(HRESULT_FROM_WIN32(GetLastError()))
}
