#pragma once

#include "Common/FSecure/CppTools/SafeSmartPointerContainer.h"
#include "RouteId.h"
#include "DeviceBridge.h"

namespace FSecure::C3::Core
{
	/// A template class responsible for managing C3 connections.
	struct RouteManager
	{
		/// Route is used by Relays to indicate that a particular Interface (actually a Channel) is used to transport packets towards a specific Agent.
		struct Route
		{
			/// A public ctor.
			/// @param routeId ID of the route.
			/// @param iface Channel's DeviceBridge pointer.
			Route(RouteId routeId, std::weak_ptr<DeviceBridge> iface);

			RouteId m_RouteId;																							///< ID of the Route.
			std::weak_ptr<DeviceBridge> m_Channel;																		///< Channel facing Route destination (i.e. the opposite direction to Gateway).
		};

		/// Destructor
		virtual ~RouteManager() = default;

		/// Finds Route specified by his ID.
		/// @param routeId ID of the Route to find.
		/// @return Route object if existed, otherwise null.
		std::shared_ptr<Route> FindRoute(RouteId const& routeId) const noexcept;

		/// Finds Any Route to Agent by his ID.
		/// @param Agent ID of the Route to find.
		/// @return Route object if any existed, otherwise null.
		std::shared_ptr<Route> FindRoute(AgentId const& AgentId) const noexcept;

		/// Finds Any Route by outgoing device ID.
		/// @param Device ID of the route's outgoing device.
		/// @return Route object if any existed, otherwise null.
		std::shared_ptr<Route> FindRouteByOutgoingChannel(DeviceId deviceId) const noexcept;

		/// Adds a new Route to the Route table.
		/// @param routeId an ID of the Route object to add.
		/// @param channel a Channel that "points" toward the Route (the opposite direction to Gateway).
		/// @return the newly created Route object.
		/// @throw std::invalid_argument if specified routeId is already in use.
		std::shared_ptr<Route> AddRoute(RouteId routeId, std::shared_ptr<DeviceBridge> channel);

		/// Removes a Route from the Route table.
		/// @param routeId ID of the Route to remove.
		/// @throw std::invalid_argument on an attempt of removal of a non-existent Route.
		void RemoveRoute(RouteId const& routeId);

		/// Removes all Routes from the Route table.
		void RemoveAllRoutes();

	private:
		SafeSmartPointerContainer<std::shared_ptr<Route>> m_Routes;														///< Table of Routes.
	};
}
