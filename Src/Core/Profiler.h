#pragma once

#include "GateRelay.h"
#include "Common/MWR/Sockets/Sockets.hpp"

namespace MWR::C3::Core
{
	/// Virtualizes whole C3 Network with it's remote elements.
	struct Profiler : std::enable_shared_from_this<Profiler>
	{
		/// Build properties
		struct BuildProperties
		{
			bool m_IsX64 = false;												///< Is x64 build (true = x64, false = x86)
			bool m_IsBanned = false;											///< Is build banned
			json m_StartupCmd;													///< Build startup command
		};

		// An std::vector-based container used by Profiler to manage its sub-types.
		template<typename Element>
		struct Manager
		{
			/// Finds Element specified by ID.
			/// @param id ID of the Element to find.
			/// @return Element object if existed, otherwise null.
			Element* Find(typename Element::Id const& id)
			{
				auto it = FindElementIterator(id);
				return it == m_Elements.end() ? nullptr : &*it;
			}

			/// Adds a new Element.
			/// @param id ID of the Element to add.
			/// @param element Element to add.
			/// @return the newly created Element.
			/// @throw std::invalid_argument if specified ID is already in use.
			Element* Add(typename Element::Id id, Element const& element)
			{
				if (FindElementIterator(id) != m_Elements.end())
					throw std::invalid_argument{ OBF("Element with specified ID already exists.") };

				m_Elements.push_back(std::move(element));
				return &m_Elements.back();
			}

			/// Removes Element from container.
			/// @param id ID of the Element to remove.
			/// @throw std::invalid_argument on an attempt of removal of a non-existent Element.
			void Remove(typename Element::Id id)
			{
				if (auto it = FindElementIterator(id); it != m_Elements.end())
					m_Elements.erase(it);
				else
					throw std::invalid_argument{ OBF("Attempt of removing Element that doesn't exist.") };
			}

			/// Tries to remove Element from container.
			/// @param id ID of the Element to remove.
			bool TryRemove(typename Element::Id id)
			{
				if (auto it = FindElementIterator(id); it != m_Elements.end())
				{
					m_Elements.erase(it);
					return true;
				}
				else
					return false;
			}

			/// Dumps container contents to JSON format.
			/// @return Container description in JSON format.
			virtual json CreateProfileSnapshot() const
			{
				auto profile = json::array();
				for (auto& element : m_Elements)
					profile += element.CreateProfileSnapshot();

				return profile;
			}

			/// Remove all elements
			void Clear() noexcept
			{
				m_Elements.clear();
			}

			// TODO remove this method
			auto const& GetUnderlyingContainer() const noexcept
			{
				return m_Elements;
			}

			// TODO remove this method
			auto& GetUnderlyingContainer() noexcept
			{
				return m_Elements;
			}

		protected:
			/// Finds Element iterator specified by ID.
			/// @param id ID of the Element to find.
			/// @return Element iterator if existed, otherwise null.
			typename std::vector<Element>::iterator FindElementIterator(typename Element::Id const& id)
			{
				return std::find_if(m_Elements.begin(), m_Elements.end(), [&id](Element const& element) { return id == element.m_Id; });
			}

		private:
			std::vector<Element> m_Elements;																			///< Elements Container.
		};

		/// Basic class of a remote C3 Network elements.
		struct ProfileElement
		{
			/// Constuct a profile elment
			/// @param owner - Profile that owns this element
			ProfileElement(std::weak_ptr<Profiler> owner);

			/// Dumps current Profile to JSON.
			/// @return Network Profile in JSON format.
			virtual json CreateProfileSnapshot() const;

			/// Performs C3 Command on itself.
			/// @param commandWithArguments whole Command in binary format.
			virtual void RunCommand(ByteView commandWithArguments) = 0;

			std::string m_ErrorState;																					///< A message like "BuildId collision" or empty if working correctly.
			std::weak_ptr<Profiler> m_Owner;																			///< Owner Profiler.
		};

		/// Virtual image of Device.
		struct Device : ProfileElement
		{
			using Id = DeviceId;																						///< ID typedef.

			/// Public ctor.
			/// @param id Device Identifier.
			/// @param typeHash Type of the Device.
			Device(std::weak_ptr<Profiler> owner, Id id, HashT typeHash);

			/// Dumps current Profile to JSON.
			/// @return Network Profile in JSON format.
			json CreateProfileSnapshot() const override;

			/// Performs C3 Command on itself.
			/// @param commandWithArguments whole Command in binary format.
			void RunCommand(ByteView commandWithArguments) override;

			Id m_Id;																									///< Device Identifier.
			HashT m_TypeHash;																							///< Type name hash of the Device.
			json m_StartupArguments;																					///< Device's startup arguments
			std::pair<std::chrono::milliseconds, std::chrono::milliseconds> m_Jitter;									///< Current jitter pm device
		};

		/// Virtual image of Device.
		struct Channel : Device
		{
			using Id = DeviceId;																						///< ID typedef.

			/// Public ctor.
			/// @param id Device Identifier.
			/// @param typeHash Type of the Device.
			Channel(std::weak_ptr<Profiler> owner, Id id, HashT typeHash, bool isReturnChannel = false, bool isNegotiationChannel = false);

			/// Dumps current Profile to JSON.
			/// @return Network Profile in JSON format.
			json CreateProfileSnapshot() const override;

			bool m_IsReturnChannel;
			bool m_IsNegotiationChannel;
		};

		/// Forward declaration.
		struct Agent;

		/// Route is used by Relays to indicate that a particular Device (actually a Channel) is used to transport packets towards a specific Agent.
		struct Route : ProfileElement
		{
			/// Route constructor
			/// @param owner - owner of this element
			/// @param rid - route id
			/// @param outgoingDeviceId
			/// @param isNeighbour - if agent specified by rid is neighbouring the owner agent
			Route(std::weak_ptr<Profiler> owner, RouteId rid, Device::Id outgoingDeviceId, bool isNeighbour = false);

			/// Dumps current Profile to JSON.
			/// @return Network Profile in JSON format.
			json CreateProfileSnapshot() const override;

			/// Performs C3 Command on itself.
			/// @param commandWithArguments whole Command in binary format.
			void RunCommand(ByteView commandWithArguments) override;

			Device::Id m_OutgoingDevice;

			using Id = RouteId;																							///< ID typedef.
			Id m_Id;																									///< Route Identifier.
			bool m_IsNeighbour = false;																					///< Is m_ReceivingAgent just after one Route hop?
		};

		/// Abstract class for all Relays.
		struct Relay : ProfileElement
		{
			/// A public ctor.
			/// @param agentId dynamic ID of the Relay.
			/// @param buildId Build identifier.
			/// @param encryptionKey asymmetric public key used to encrypt all outgoing transmission.
			/// @param isBanned flag indicating whether Agent should be added to the black-list.
			Relay(std::weak_ptr<Profiler> owner, AgentId agentId, BuildId buildId, int32_t lastSeen);

			using Id = AgentId;																							///< ID typedef.
			Id m_Id;																									///< Dynamic ID of the Relay.
			BuildId m_BuildId;																							///< Static ID of the Relay binary.

			/// Performs Command on a Device indicated by provided JSON format.
			/// @param jCommandElement JSON element to parse.
			/// @param commandWithArgs Command in binary format to run on Device.
			virtual void ParseAndRunCommand(json const& jCommandElement) noexcept(false);

			/// Performs C3 Command on itself.
			/// @param commandWithArguments whole Command in binary format.
			void RunCommand(ByteView commandWithArguments) override;

			/// Reprofile: AddNewChannel.
			/// @param did ID of the CHannel that was added.
			/// @param typeNameHash type name hash of a CHannel that was added.
			/// @param isReturnChannel if channel is a return channel.
			/// @param isNegotiationChannel if channel is a negotiation channel.
			virtual Channel* ReAddChannel(Device::Id did, HashT typeNameHash, bool isReturnChannel = false, bool isNegotiationChannel = false);

			/// Reprofile: AddNewPeripheral.
			/// @param did ID of the Peripheral that was added.
			/// @param typeNameHash type name hash of a Peripheral that was added.
			virtual Device* ReAddPeripheral(Device::Id did, HashT typeNameHash);

			/// Find a device that lies in direction of Agent
			/// @param aid - agent id to be reached
			/// @returns DeviceId through which agent aid can be reached
			DeviceId FindDirectionDevice(AgentId aid);

			/// Update new channel parameters based on negotiation channel parameters
			/// @param negotiationDid - negotiation channel device Id
			/// @param newDeviceId - newly created (negotiated) device
			/// @param newInputId - negotiated InputId
			/// @param newOutputId - negotiated OutputId
			void UpdateFromNegotiationChannel(DeviceId negotiationDid, DeviceId newDeviceId, std::string newInputId, std::string newOutputId);

			/// Add new route
			/// @param receivingRid - Destination receiving route id
			/// @param outgoingInterface - channel pointed towards receiving agent
			/// @param isNeighbour - true if agent specified in receivingRid is neigbour
			void ReAddRoute(RouteId receivingRid, DeviceId outgoingInterface, bool isNeighbour);

			/// Remove route
			/// @param rid - route to remove
			void ReRemoveRoute(RouteId rid);

			Manager<Route> m_Routes;																					///< Container for Routes.
			Manager<Channel> m_Channels;																				///< Container for Channels.
			Manager<Device> m_Peripherals;																				///< Container for Peripherals.

			DeviceId::UnderlyingIntegerType m_LastDeviceId = 0;															///< This value gets increased with every creation of an Device.

			int32_t m_LastSeen; // fixed size instead of 32 or 64 bits time_t
		};

		/// Virtual image of NodeRelay.
		struct Agent : Relay
		{
			/// A public ctor.
			/// @param agentId dynamic ID of the Relay.
			/// @param buildId Build identifier.
			/// @param encryptionKey asymmetric public key used to encrypt all outgoing transmission.
			/// @param isBanned flag indicating whether Agent should be added to the black-list.
			/// @param lastSeen timestamp when agent was last seen (responded)
			/// @param hostInfo agent's host information
			Agent(std::weak_ptr<Profiler> owner, AgentId agentId, BuildId buildId, MWR::Crypto::PublicKey encryptionKey, bool isBanned, int32_t lastSeen, bool isX64, HostInfo hostInfo);

			/// Dumps current Profile to JSON.
			/// @return Network Profile in JSON format.
			json CreateProfileSnapshot() const override;

			/// Performs Command on a Device indicated by provided JSON format.
			/// @param jCommandElement JSON element to parse.
			/// @param commandWithArgs Command in binary format to run on Device.
			void ParseAndRunCommand(json const& jCommandElement) noexcept(false) override;

			/// Performs C3 Command on remote NodeRelay.
			/// @param commandWithArguments whole Command in json format.
			void RunCommand(ByteView commandWithArguments) override;

			/// Performs a create command (create new device)
			/// @param commandWithArguments whole Command in json format.
			void PerformCreateCommand(json const& jCommandElement);

			/// Add channel
			/// @param did - new channel DeviceId
			/// @param typeNameHash - new channel typename hash
			/// @param isReturnChannel - true if channel is a gateway return channel
			/// @param isNegotiationChannel - true if channel is a negotiation channel
			/// @returns a pointer to newly created channel
			Channel* ReAddChannel(Device::Id did, HashT typeNameHash, bool isReturnChannel = false, bool isNegotiationChannel = false) override;

			/// Add peripheral
			/// @param did - new peripheral DeviceId
			/// @param typeNameHash - new peripheral typename hash
			/// @returns a pointer to newly created peripheral
			Device* ReAddPeripheral(Device::Id did, HashT typeNameHash) override;

			/// Add scheduled device parameters
			/// @param deviceId - scheduled device Id
			/// @param command - scheduled device command
			void AddScheduledDevice(DeviceId deviceId, json command);

			/// Find gateway return channel
			/// @returns return channel or nullptr
			Channel* FindGrc();

			MWR::Crypto::PublicKey m_EncryptionKey;																		///< Agent's public key.
			HostInfo m_HostInfo;																						///< Agent's Host information
			bool m_IsBanned;																							///< Is Agent black-listed?
			bool m_IsX64;

		private:
			std::unordered_map<DeviceId::UnderlyingIntegerType, json> m_ScheduledDevices;
		};

		/// Virtual image of Gateway.
		struct Gateway : Relay
		{
			/// A public ctor.
			/// @param gateway pointer to Gate Relay.
			Gateway(std::weak_ptr<Profiler> owner, std::string name, std::shared_ptr<GateRelay> gateway);

			/// Reprofile: TurnOnConnector.
			/// @param typeNameHash type name hash of a Connector that was turned on.
			/// @param connector pointer to the Connector object.
			void ReTurnOnConnector(HashT typeNameHash, std::shared_ptr<ConnectorBridge> connector);

			/// Reprofile: AddAgent.
			/// @param agentId - new agent Id
			/// @param buildId - new agents' build Id
			/// @param encryptionKey - new agent's public encryption key
			/// @param isBanned - is agent banned
			/// @param lastSeen - when agent was last seen
			/// @param hostInfo - new agnet's host information
			Agent* ReAddAgent(AgentId agentId, BuildId buildId, MWR::Crypto::PublicKey encryptionKey, bool isBanned, int32_t lastSeen, HostInfo hostInfo);

			/// Reprofile: Add remote agent (agent not neigbouring with gateway)
			/// @param agentId - new agent Id
			/// @param buildId - new agents' build Id
			/// @param encryptionKey - new agent's public encryption key
			/// @param ridOfConectionPlace
			/// @param childGrcHash - new agent's
			/// @param lastSeen - when agent was last seen
			/// @param hostInfo - new agnet's host information
			Agent* ReAddRemoteAgent(RouteId childRouteId, BuildId buildId, MWR::Crypto::PublicKey encryptionKey, RouteId ridOfConectionPlace, HashT childGrcHash, int32_t lastSeen, HostInfo hostInfo);

			/// Find an agent directly connected to relay through given channel
			/// @param relay - relay whose neighbour to find
			/// @param did - device id through which the agent is connected
			/// @returns direct neighbour to relay
			/// @throws std::logic_error
			Agent* FindNeighborOnDevice(Relay& relay, DeviceId did);

			/// Add new known build
			/// @oaram bid - new build Id
			/// @param properties - build properties
			void AddAgentBuild(BuildId bid, BuildProperties properties);

			/// Get a list of all agents on the path from agent to gateway
			/// @param agent - starting point of the path
			/// @returns list of agents on path from agent to gateway
			/// @throws std::runtime_error if any agent on the path doesn't have a gateway return channel
			std::vector<Agent*> GetPathFromAgent(Agent* agent);

			/// Dumps current Profile to JSON.
			/// @return Network Profile in JSON format.
			json CreateProfileSnapshot() const override;

			/// Adds a default 'create' property
			/// @param interface - json definition of interface
			static void EnsureCreateExists(json& interface);

			/// Adds built-in command definitions (Close/TurnOff and UpdateDelay)
			/// @param interface - json definition of interface
			/// @param isDevice - whether interfce is a device (channel/peripheral) or not (connstors)
			static void AddBuildInCommands(json& interface, bool isDevice);

			/// Get JSON representing available Commands.
			/// @return Network's Capability in JSON format.
			json GetCapability();

			/// Performs C3 Command on itself.
			/// @param commandWithArguments whole Command in binary format.
			void RunCommand(ByteView commandWithArguments) override;

			/// Performs Command on a Device indicated by provided JSON format.
			/// @param jCommandElement JSON element to parse.
			/// @param commandWithArgs Command in binary format to run on Device.
			void ParseAndRunCommand(json const& jCommandElement) noexcept(false) override;

			std::string m_Name;																							///< Gateway's Name
			std::weak_ptr<GateRelay> m_Gateway;																			///< The "physical" Gateway.
			Manager<Agent> m_Agents;																					///< Table of Agents.
			std::map<BuildId, BuildProperties> m_AgentBuilds;															///< Known agent builds

			/// Virtual image of Connector.
			struct Connector : ProfileElement
			{
				using Id = HashT;																						///< ID typedef.

				/// Public ctor.
				/// @param id Connector identifier.
				/// @param connector the Connector object.
				Connector(std::weak_ptr<Profiler> owner, Id id, std::shared_ptr<ConnectorBridge> connector);

				/// Dumps Profile to JSON.
				/// @return Network Profile in JSON format.
				json CreateProfileSnapshot() const override;

				/// Performs C3 Command on itself.
				/// @param commandWithArguments whole Command in binary format.
				void RunCommand(ByteView commandWithArguments) override;

				Id m_Id;																								///< Hash of the name of the Connector.
				std::weak_ptr<ConnectorBridge> m_Connector;																///< Pointer to the Connector object.
				json m_StartupArguments;
			};

			/// Performs a create command (create new device)
			/// @param commandWithArguments whole Command in json format.
			void PerformCreateCommand(json const& jCommandElement);

			struct CreateCommand
			{
				const uint16_t m_Id;
				const uint32_t m_Hash;
				const bool m_IsDevice;
				const bool m_IsNegotiableChannel;
			};

			std::vector<CreateCommand> m_CreateCommands;
			Manager<Connector> m_Connectors;																			///< Container for Connectors.

			/// Reprofile - Turn off connector
			/// Removes connector from profiler
			/// @param connectorNameHash - connector typename hash
			void ReTurnOffConnector(HashT connectorNameHash);

			/// Reprofile - Delete channel
			/// Removes channel from profiler
			/// @param iidOfDeviceToDetach - channel's device id
			void ReDeleteChannel(DeviceId iidOfDeviceToDetach);

			/// Reprofile - Delete peripheral
			/// Removes peripheral from profiler
			/// @param iidOfDeviceToDetach - peripheral's device id
			void ReDeletePeripheral(DeviceId iidOfDeviceToDetach);

			/// Update last-seen timestamps on route to given agent
			/// @param agentId - the last agent on the route (origin on the message)
			/// @param timestamp - current timestamp
			void UpdateRouteTimestamps(AgentId agentId, int32_t timestamp);

			/// Find a (parent) agent directly connected through (child) agent's return channel
			/// @param agent - child agent
			/// @returns agent directly connected through gateway return channel
			Agent* FindGatewaySideAgent(Agent* agent);

			/// Check if connection to agent exists
			/// @param agentId - agent to check connection to
			/// @returns true if any route to agent exists
			bool ConnectionExist(AgentId agentId);

			/// Update negotiated channel parameters (arguments) if all the necessary information is available.
			/// @param connecitonPlace - route Id constructed from agent and device channel ID's to update
			void ConditionalUpdateChannelParameters(RouteId connectionPlace);

			/// Reset profile state - remove all elements
			void Reset();
		};

		/// Public ctor.
		Profiler(std::filesystem::path snapshotPath);

		/// @param gateway pointer to Gate Relay.
		void Initialize(std::string name, std::shared_ptr<GateRelay> gateway);

		/// Performs Actions parsed from provided packet.
		/// @param actionsPacket packet to parse.
		void HandleActionsPacket(ByteView actionsPacket);

		/// NewBuild message handler
		/// @param message - NewBuild message to process.
		/// @returns json representation of NewBuild response
		json HandleNewBuildMessage(json const& message);

		/// Translate command from JSON to binary representation
		/// @param command - command in JSON format
		/// @returns Binary representation of command [commandId][packed arguments]
		/// @throws nlohmann::basic_json::exception
		static ByteVector TranslateCommand(json const& command);

		/// Translate arguments from JSON to binary representation
		/// @param command - command in JSON format
		/// @returns Binary representation of arguments [packed arguments]
		/// @throws nlohmann::basic_json::exception
		static ByteVector TranslateArguments(json const& arguments);

		/// Translate startup command from JSON to binary representation
		/// @param command - command in JSON format
		/// @returns Binary representation of command [add device command arguments]
		/// @throws nlohmann::basic_json::exception
		ByteVector TranslateStartupCommand(json const& jcommand);

		/// Translate single argument from JSON to binary representation
		/// @param type - string decryption of argument
		/// @param value - json value to translate
		/// @returns Binary representation of argument [packed argument]
		/// @throws std::out_of_range if any integer value casting fails
		/// @throws std::invalid_argument if type is not any of [int8, int16, int32, int64, uint8, uint16, uint32, uint64, float, boolean, string, ip, binary]
		static ByteVector Translate(std::string const& type, json::value_type const& value);

		/// Current Profile snapshot with synchronized access.
		struct Profile
		{
			/// Public ctor.
			/// @param gateway which profile is locked
			Profile(Gateway& gateway);

			Gateway& m_Gateway;																							///< Gateway profile.

		private:
			std::unique_lock<std::mutex> m_Lock;																		///< Access lock.
			static std::mutex m_Mutex;																					///< Lock object.
		};

		/// Profile getter.
		/// @return Current Profile snapshot.
		Profile Get();

		/// Maps peripheral type hash to connector type hash and other way around
		/// @param id beacon hash
		/// @returns binder id
		uint32_t GetBinderTo(uint32_t);

	protected:
		std::optional<Gateway> m_Gateway;																				///< The "virtual gateway object".

		// Forward declaration.
		struct SubAction;

		/// Base for all Actions.
		struct BaseAction
		{
			enum State
			{
				Unknown = 0,																							///< E.g. uninitialized.
				Planned = 1,																							///< Scheduled.
				Cancelled = 2,																							///< Cancelled by user (information from Controller).
				Pendning = 3,																							///< In progress.
				Succeeded = 4,																							///< Done.
				Failed = 5,																								///< Couldn't be done.
				Abandoned = 6,																							///< By Profiler (e.g. dependent on previous action which has failed).
			} m_State = State::Unknown;
			std::string m_StateComment;																					///< E.g. error text.

			/// Public ctor.
			/// @param state initial state.
			/// @param stateComment initial state comment.
			BaseAction(State state, std::string stateComment);

			// Identifier typedefs.
			using ActionId = std::uint32_t;																				///< ID typedef.
			using CommandSeqNo = std::uint32_t;																			///< Command sequence number given by Controller.

			std::vector<std::pair<std::string, SubAction>> m_SubActions;												///< For Scenarios.
		};

		/// Non-root Actions.
		struct SubAction : BaseAction
		{
			/// Public ctor.
			/// @param description a short summary of what is being done in this step.
			/// @param state initial state.
			/// @param stateComment initial state comment.
			SubAction(std::string description, State state = State::Planned, std::string stateComment = OBF(""));

			std::string m_Description;																					///< Short summary of what is being done in this step.
		};

		/// Root-Action.
		struct Action : BaseAction
		{
			/// Public ctor.
			/// @param commandSeqNo Command sequence number given by Controller.
			/// @param state initial state.
			/// @param stateComment initial state comment.
			Action(CommandSeqNo commandSeqNo, State state = State::Unknown, std::string stateComment = OBF(""));

			static ActionId m_LastActionId;																				///< Global counter for Action IDs.
			ActionId m_ActionId;																						///< ID given by Profiler for Command requested by Controller.
			CommandSeqNo m_CommandSeqNo;																				///< Command sequence number given by Controller.
		};

		mutable std::mutex m_AccessMutex;																				///< Mutex for synchronization.
		std::vector<Action> m_RelevantActions;																			///< List of Actions - planned, pending and finished but not yet reported to the Controller.

		/// Contains hashes of binders. This allows to call: auto tsConnectorhash = GetBinderTo(hashBeacona);. First hash in pair is Peripheral hash and second one is corresponding Connector.
		std::vector<std::pair<std::uint32_t, std::uint32_t>> m_BindersMappings;

		private:
			/// Dump snapshot file in regular intervals
			/// Creates a snapshot .tmp file and replaces previous snapshot file
			void DumpSnapshots();

			/// Restore Gateway and profiler state from snapshot
			void RestoreFromSnapshot();

			std::filesystem::path m_SnapshotPath;																		///< Snapshot dump path
	};
}
