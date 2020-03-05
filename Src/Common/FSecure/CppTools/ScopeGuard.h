#pragma once

namespace FSecure
{
	/// ScopeGuard helps you automate resource deallocation in a clear, robust way. Guarantees to call destructors in reverse order.<br>
	/// Usage: auto p = new int; SCOPE_GUARD { delete p; }; ///< delete p; will be executed automatically on scope leave.<br>
	/// Based on https://www.codeproject.com/Articles/124130/Simple-Look-Scope-Guard-for-Visual-C.
	/// @warning Never use this class directly. Always use the SCOPE_GUARD macro.
	struct ScopeGuard
	{
		/// Class design.
		typedef ScopeGuard Type;												///< Can't use automatic LIGHT_CLASS_FILLER because of deleted constructors and operators.

		/// Cleanup function signature.
		typedef std::function<void()> CleanupFunction_t;

		/// The only valid to call manual constructor.
		/// @param function cleanup function to call on scope leave.
		Type(const CleanupFunction_t& function) : m_CleanupFunction(function) { }

		/// Deleted l-value constructor, to reject l-value references.
		Type(CleanupFunction_t&) = delete;

		/// R-value constructor, to accept r-value references.
		Type(CleanupFunction_t&& function) : m_CleanupFunction(function) { }

		/// Destructor.
		~ScopeGuard() { m_CleanupFunction(); }

		/// Operators.
		const Type& operator=(const Type&) = delete;							///< No copying between ScopeGuards is allowed.

		/// Conversion operators.
		Type(const Type&) = delete;												///< Same as above - no copying between ScopeGuard objects.

		/// Heap operators are rejected.
		void *operator new(size_t) = delete;
		void *operator new[](size_t) = delete;
		void operator delete(void *) = delete;
		void operator delete[](void *) = delete;

	private:
		const CleanupFunction_t m_CleanupFunction;								///< Pointer to cleanup function. This function will be called on ScopeGuard destruction i.e. on scope leave.
	};

	// Macros.
#	define SCOPE_GUARD_CAT_EXPANDED(x, y) x##y
#	define SCOPE_GUARD_CAT(x, y) SCOPE_GUARD_CAT_EXPANDED(x, y)

	/// SCOPE_GUARD macro definition. You should always use this macro instead of direct manipulations on ScopeGuard structure and it's objects.<br>
	/// Usage: SCOPE_GUARD { expressions; that; will; be; processed; on; scope; leave; }
#	define SCOPE_GUARD FSecure::ScopeGuard SCOPE_GUARD_CAT(scope_guard_, __COUNTER__) = [&]
}
