#pragma once

namespace FSecure
{
	/// Container with multi-threaded synchronization.
	template<typename T>
	struct SafeSmartPointerContainer
	{
		/// Enumerates over elements.
		/// @param comparator function that returns true to keep iterate or false to stop.
		void For(std::function<bool(T const&)> comparator) const
		{
			std::scoped_lock<std::mutex> lock(m_AccessMutex);																		// Request access to the underlying Container.
			for (auto element : m_Container)
				if (!comparator(element))
					return;
		}

		/// Finds Element using provided comparator.
		/// @param comparator function that returns true for requested Element.
		/// @return Element if existed, otherwise null.
		T Find(std::function<bool(T const&)> comparator) const
		{
			std::scoped_lock<std::mutex> lock(m_AccessMutex);																		// Request access to the underlying Container.
			auto it = std::find_if(m_Container.begin(), m_Container.end(), comparator);									// Find specified Element...
			return it == std::end(m_Container) ? T{} : *it;																// ...and return it (or null if it couldn't be found).
		}

		/// Adds a new Element.
		/// @tparam Args constructor arguments.
		/// @tparam args constructor arguments.
		/// @return newly added Element.
		template <typename... Args>
		T Add(Args&& ... args)
		{
			std::scoped_lock<std::mutex> lock(m_AccessMutex);																		// Request access to the underlying Container.
			m_Container.emplace_back(args...);																			// Add it at the end.
			return m_Container.back();
		}

		/// Adds an Element, but throws if Element is already in the container.
		/// @tparam Args constructor arguments.
		/// @param comparator function that returns true for requested Element.
		/// @tparam args constructor arguments.
		/// @return newly added Element.
		/// @throw std::invalid_argument if Element is already stored.
		template <typename... Args>
		T TryAdd(std::function<bool(T const&)> comparator, Args&& ... args)
		{
			std::scoped_lock<std::mutex> lock(m_AccessMutex);																		// Request access to the underlying Container.
			if (auto it = std::find_if(m_Container.begin(), m_Container.end(), comparator); it != m_Container.end())	// Find element...
				throw std::invalid_argument{ OBF("Tried to add an existing Element to the container.") };					// ...and throw.

			m_Container.emplace_back(std::forward<Args>(args)...);														// Otherwise add it at the end.
			return m_Container.back();
		}

		/// Finds provided Element or adds it if not found.
		/// @tparam Args constructor arguments.
		/// @param comparator function that returns true for requested Element.
		/// @tparam args constructor arguments.
		/// @param element an element to be added.
		template <typename... Args>
		T Ensure(std::function<bool(T const&)> comparator, Args&& ... args)
		{
			std::scoped_lock<std::mutex> lock(m_AccessMutex);																		// Request access to the underlying Container.
			if (auto it = std::find(m_Container.begin(), m_Container.end(), element); it != m_Container.end())			// Find element...
				return *it;																								// ...and return it.

			m_Container.emplace_back(std::forward<Args>(args)...);														// Otherwise add it at the end.
			return m_Container.back();
		}

		/// Removes an Elements.
		/// @param element what to remove.
		/// @throw std::invalid_argument on an attempt of removal of a non-existent Element.
		void Remove(T const& element)
		{
			std::scoped_lock<std::mutex> lock(m_AccessMutex);																		// Request access to the underlying Container.
			if (auto it = std::find(m_Container.begin(), m_Container.end(), element); it != m_Container.end())			// Find element...
				m_Container.erase(it);																					// ...and remove it.
			else
				throw std::invalid_argument{ OBF("Attempted to remove a non-existent Element.") };
		}

		/// Removes an Element using provided comparator.
		/// @param comparator function that returns true for requested Element.
		/// @throw std::invalid_argument on an attempt of removal of a non-existent Element.
		void Remove(std::function<bool(T const&)> comparator)
		{
			std::scoped_lock<std::mutex> lock(m_AccessMutex);																		// Request access to the underlying Container.
			if (auto it = std::find_if(m_Container.begin(), m_Container.end(), comparator); it != m_Container.end())	// Find specified Element...
				m_Container.erase(it);																					// ...and remove it.
			else
				throw std::invalid_argument{ OBF("Attempted to remove a non-existent Element.") };
		}

		/// Same as Remove, but returns the element removed from the container.
		/// @param comparator function that returns true for requested Element.
		/// @return Copy of the element that was requested to be removed.
		/// @throw std::invalid_argument on an attempt of removal of a non-existent Element.
		T Retrieve(std::function<bool(T const&)> comparator)
		{
			std::scoped_lock<std::mutex> lock(m_AccessMutex);																		// Request access to the underlying Container.
			if (auto it = std::find_if(m_Container.begin(), m_Container.end(), comparator); it != m_Container.end())	// Find specified Element...
			{
				auto element = std::move(*it);																			// ...move it...
				m_Container.erase(it);																					// ...remove...
				return std::move(element);																				// ...and return it.
			}
			else
				throw std::invalid_argument{ OBF("Attempted to remove a non-existent Element.") };
		}

		/// Gets element quantity.
		/// @return number of elements in the container.
		size_t GetSize() const
		{
			return m_Container.size();
		}

		/// Checks if the container has any elements.
		/// @return true if the container is empty.
		bool IsEmpty() const
		{
			return m_Container.empty();
		}

		/// Clear whole container.
		void Clear()
		{
			std::scoped_lock<std::mutex> lock(m_AccessMutex);
			m_Container.clear();
		}

	private:
		mutable std::mutex m_AccessMutex;																				///< Mutex for synchronization.
		std::vector<T> m_Container;																						///< Table of all Elements.
	};
}
