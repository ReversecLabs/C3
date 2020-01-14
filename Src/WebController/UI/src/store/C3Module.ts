import { Module, GetterTree, MutationTree, ActionTree } from 'vuex';

import md5 from 'md5';
import axios from 'axios';
import { RootState } from '@/types/store/RootState';
import {
  C3State,
  C3Relay,
  C3Interface,
  C3Gateway,
  GatewayHeader,
  NodeKlass,
  C3Node,
  C3Edge,
  FetchData,
  C3Command,
  C3Route,
  C3RelayTime
} from '@/types/c3types';

const namespaced: boolean = true;
// State

export const state: C3State = {
  gateways: [],
  gateway: null,
  nodes: [],
  edges: [],
  relayTimestamps: [],
  mustRefresh: false,
  lastGetHash: ''
};

// Getters

export type GetGatewayFn = () => C3Node | undefined;
export type GetRelayFn = (id: string) => C3Node | undefined;
export type GetInterfaceFn = (uid: string) => C3Node | undefined;
export type GetInterfacesFn = (nodeKlass?: NodeKlass[]) => C3Node[];
export type GetInterfacesForFn = (
  nodeKlass: NodeKlass | NodeKlass[],
  parentId: string | null
) => C3Node[];
export type GetNodeKlassFn = (uid: string) => NodeKlass;
export type GetCommandFn = (id: string) => C3Command | undefined;
export type GetRelayRoutesFn = (id: string) => C3Route[];

export const getters: GetterTree<C3State, RootState> = {
  getNodes(c3State): C3Node[] {
    return c3State.nodes;
  },

  getEdges(c3State): C3Edge[] {
    return c3State.edges;
  },

  // return gateways agentIds
  getGateways(c3State): GatewayHeader[] {
    return c3State.gateways;
  },

  // return the selected gateway
  getGateway(c3State): C3Node | undefined {
    return c3State.nodes.find(node => {
      return node.klass === NodeKlass.Gateway;
    });
  },

  hasGatewaySelected(c3State): boolean {
    if (c3State.gateway) {
      return true;
    }
    return false;
  },

  // return all relays from the selected gateway
  getRelays(c3State): C3Node[] {
    return c3State.nodes.filter(node => {
      return node.klass === NodeKlass.Relay;
    });
  },

  getRelay: c3State => (id: string): C3Node | undefined => {
    return c3State.nodes.find(node => {
      return node.id === id && node.klass === NodeKlass.Relay;
    });
  },

  getGatewayRoutes(c3State): C3Route[] {
    if (c3State.gateway) {
      return c3State.gateway.routes;
    }
    return [];
  },

  getRelayRoutes: c3State => (id: string): C3Route[] => {
    if (!!c3State.gateway) {
      const relay = c3State.gateway.relays.find(target => {
        return target.agentId === id;
      });
      if (!!relay) {
        return relay.routes;
      }
    }
    return [];
  },

  getInterface: c3State => (uid: string): C3Node | undefined => {
    if (uid === 'new') {
      return {
        uid: 'new',
        klass: NodeKlass.Relay,
        id: 'new',
        buildId: '',
        name: 'new',
        pending: true,
        isActive: false,
        type: -1,
        error: null,
        parentId: null,
        parentKlass: NodeKlass.Gateway,
        initialCommand: {},
        timestamp: Math.floor(Date.now() / 1000)
      };
    }

    const c = c3State.nodes.find(node => {
      return node.uid === uid;
    });
    return c3State.nodes.find(node => {
      return node.uid === uid;
    });
  },

  getInterfaces: c3State => (
    nodeKlass: NodeKlass[] = [
      NodeKlass.Channel,
      NodeKlass.Connector,
      NodeKlass.Peripheral
    ]
  ): C3Node[] => {
    return c3State.nodes.filter(node => {
      return nodeKlass.includes(node.klass);
    });
  },

  getInterfacesFor: c3State => (
    nodeKlass: NodeKlass | NodeKlass[] = [
      NodeKlass.Channel,
      NodeKlass.Connector,
      NodeKlass.Peripheral
    ],
    parentId: string | null
  ): C3Node[] => {
    if ((parentId === '' || parentId === null) && c3State.gateway) {
      parentId = c3State.gateway.agentId;
    }
    return c3State.nodes.filter(node => {
      return nodeKlass.includes(node.klass) && node.parentId === parentId;
    });
  },

  getNodeKlass: c3State => (uid: string): NodeKlass => {
    const n = c3State.nodes.find(node => {
      return node.uid === uid;
    });
    if (n) {
      return n.klass;
    }
    return NodeKlass.Undefined;
  }
};

// Mutations

export type UpdateGatewaysFn = (relays: GatewayHeader[]) => void;
export type UpdateGatewayFn = (relays: C3Gateway) => void;

export const mutations: MutationTree<C3State> = {
  updateGateways(c3State, g: GatewayHeader[]) {
    c3State.gateways = g;
  },

  updateGateway(c3State, g: C3Gateway) {
    c3State.gateway = g;
  },

  populateNodes(c3State, data: C3Gateway) {
    const uuid = (...args: string[]): string => {
      return args.join('-');
    };

    const isRelayActive = (relay: C3Relay): boolean => {
      let active = relay.isActive;

      // If gateway down the relays are not managable either.
      if (data.isActive === false) {
        active = false;
      }

      return active;
    };

    c3State.nodes = [];
    c3State.mustRefresh = false;

    if (c3State.relayTimestamps === undefined) {
      c3State.relayTimestamps = [];
    }

    let gatewayTimestamp = 0;
    let relayTimestamp = 0;
    const relayTimestamps: C3RelayTime[] = [];

    if (!!data.timestamp) {
      gatewayTimestamp = data.timestamp;
    }

    c3State.nodes.push({
      uid: data.agentId,
      klass: NodeKlass.Gateway,
      id: data.agentId,
      buildId: data.buildId,
      name: data.name,
      pending: data.pending || false,
      isActive: data.isActive,
      type: -1,
      error: data.error || null,
      parentId: null,
      parentKlass: null,
      timestamp: gatewayTimestamp
    });

    data.channels.forEach((i: C3Interface) => {
      c3State.nodes.push({
        uid: uuid(i.iid, data.agentId),
        klass: NodeKlass.Channel,
        id: i.iid,
        pending: i.pending || false,
        type: i.type,
        error: i.error || null,
        parentId: data.agentId,
        isReturnChannel: i.isReturnChannel || false,
        isNegotiationChannel: i.isNegotiationChannel || false,
        parentKlass: NodeKlass.Gateway,
        propertiesText: i.propertiesText || ''
      });
    });

    data.peripherals.forEach((i: C3Interface) => {
      c3State.nodes.push({
        uid: uuid(i.iid, data.agentId),
        klass: NodeKlass.Peripheral,
        id: i.iid,
        pending: i.pending || false,
        type: i.type,
        error: i.error || null,
        parentId: data.agentId,
        parentKlass: NodeKlass.Gateway,
        propertiesText: i.propertiesText || ''
      });
    });

    data.connectors.forEach((i: C3Interface) => {
      c3State.nodes.push({
        uid: uuid(i.iid, data.agentId),
        klass: NodeKlass.Connector,
        id: i.iid,
        pending: i.pending || false,
        type: i.type,
        error: i.error || null,
        parentId: data.agentId,
        parentKlass: NodeKlass.Gateway,
        propertiesText: i.propertiesText || ''
      });
    });

    data.relays.forEach((relay: C3Relay) => {
      if (!!relay.timestamp) {
        relayTimestamp = relay.timestamp;
        if (relayTimestamp < gatewayTimestamp) {
          relayTimestamps!.push({
            id: relay.agentId,
            time: relayTimestamp
          });
        } else {
          const newTime = c3State.relayTimestamps!.find(t => {
            return t.id === relay.agentId;
          });
          if (newTime !== undefined) {
            c3State.mustRefresh = true;
          }
        }
      }

      c3State.nodes.push({
        uid: relay.agentId,
        klass: NodeKlass.Relay,
        id: relay.agentId,
        buildId: relay.buildId,
        name: relay.name,
        pending: relay.pending || false,
        isActive: isRelayActive(relay),
        type: -1,
        error: relay.error || null,
        parentId: data.agentId,
        parentKlass: NodeKlass.Gateway,
        initialCommand: relay.initialCommand || {},
        timestamp: relayTimestamp,
        hostInfo: relay.hostInfo
      });

      relay.channels.forEach((i: C3Interface) => {
        c3State.nodes.push({
          uid: uuid(i.iid, relay.agentId),
          klass: NodeKlass.Channel,
          id: i.iid,
          pending: i.pending || false,
          type: i.type,
          error: i.error || null,
          parentId: relay.agentId,
          isReturnChannel: i.isReturnChannel || false,
          isNegotiationChannel: i.isNegotiationChannel || false,
          parentKlass: NodeKlass.Relay,
          propertiesText: i.propertiesText || ''
        });
      });

      relay.peripherals.forEach((i: C3Interface) => {
        c3State.nodes.push({
          uid: uuid(i.iid, relay.agentId),
          klass: NodeKlass.Peripheral,
          id: i.iid,
          pending: i.pending || false,
          type: i.type,
          error: i.error || null,
          parentId: relay.agentId,
          parentKlass: NodeKlass.Relay,
          propertiesText: i.propertiesText || ''
        });
      });
    });
    c3State.relayTimestamps = relayTimestamps;
  },

  populateEdges(c3State, data: C3Gateway) {
    const uuid = (...args: string[]): string => {
      return args.join('-');
    };

    const guid = () => {
      return Math.random()
        .toString(36)
        .substring(2);
    };

    const interfaceIsExist = (agentId: string, iid: string) => {
      const relay = data.relays.find((r: C3Relay) => {
        return r.agentId === agentId;
      });
      if (relay !== undefined) {
        const c = relay.channels.find((i: C3Interface) => {
          return i.iid === iid;
        });
        if (c !== undefined) {
          return true;
        }
      }
      return false;
    };

    c3State.edges = [];

    data.channels.forEach((i: C3Interface) => {
      c3State.edges.push({
        id: guid(),
        klass: NodeKlass.Interface,
        isNegotiationChannel: !!i.isNegotiationChannel,
        length: 0,
        dashes: false,
        from: data.agentId,
        to: uuid(i.iid, data.agentId)
      });
    });

    data.peripherals.forEach((i: C3Interface) => {
      c3State.edges.push({
        id: guid(),
        klass: NodeKlass.Interface,
        length: 0,
        dashes: false,
        from: data.agentId,
        to: uuid(i.iid, data.agentId)
      });
    });

    data.connectors.forEach((i: C3Interface) => {
      c3State.edges.push({
        id: guid(),
        klass: NodeKlass.Interface,
        length: 0,
        dashes: true,
        from: data.agentId,
        to: uuid(i.iid, data.agentId)
      });
    });

    data.routes.forEach(route => {
      if (route.isNeighbour === true) {
        c3State.edges.push({
          id: guid(),
          klass: NodeKlass.Relay,
          length: 100,
          dashes: false,
          from: data.agentId,
          to: route.destinationAgent
        });

        c3State.edges.push({
          id: guid(),
          klass: NodeKlass.Interface,
          length: 0,
          dashes: false,
          from: uuid(route.outgoingInterface, data.agentId),
          to: uuid(route.receivingInterface, route.destinationAgent)
        });
      }
    });

    data.relays.forEach((relay: C3Relay) => {
      relay.channels.forEach((i: C3Interface) => {
        c3State.edges.push({
          id: guid(),
          klass: NodeKlass.Interface,
          isNegotiationChannel: !!i.isNegotiationChannel,
          length: 0,
          dashes: false,
          from: relay.agentId,
          to: uuid(i.iid, relay.agentId)
        });
      });

      relay.peripherals.forEach((i: C3Interface) => {
        c3State.edges.push({
          id: guid(),
          klass: NodeKlass.Interface,
          length: 0,
          dashes: false,
          from: relay.agentId,
          to: uuid(i.iid, relay.agentId)
        });
      });

      relay.routes.forEach(route => {
        if (route.isNeighbour === true) {
          let isDashed = true;
          if (
            interfaceIsExist(
              route.destinationAgent,
              route.receivingInterface
            ) &&
            interfaceIsExist(relay.agentId, route.outgoingInterface)
          ) {
            isDashed = false;
          }
          c3State.edges.push({
            id: guid(),
            klass: NodeKlass.Relay,
            length: 100,
            dashes: isDashed,
            from: relay.agentId,
            to: route.destinationAgent
          });

          c3State.edges.push({
            id: guid(),
            klass: NodeKlass.Interface,
            length: 0,
            dashes: false,
            from: uuid(route.outgoingInterface, relay.agentId),
            to: uuid(route.receivingInterface, route.destinationAgent)
          });
        }
      });
    });
  }
};

// Actions

export type FetchC3DataFn = (data: FetchData) => void;

const actions: ActionTree<C3State, RootState> = {
  fetchCapability(context, nodeIds: FetchData) {
    context.dispatch('c3Capability/fetchCapability', nodeIds, { root: true });
  },

  fetchGateways(context): void {
    const baseURL = `${context.rootGetters['optionsModule/getAPIUrl']}:${context.rootGetters['optionsModule/getAPIPort']}`;
    axios
      .get('/api/gateway', { baseURL })
      .then(response => {
        context.commit('updateGateways', response.data);
      })
      .catch(error => {
        context.dispatch(
          'notifyModule/insertNotify',
          { type: 'error', message: error.message },
          { root: true }
        );
        // tslint:disable-next-line:no-console
        console.error(error.message);
      });
  },

  fetchGateway(context, nodeIds: FetchData) {
    if (nodeIds.gatewayId) {
      const url = `/api/gateway/${nodeIds.gatewayId}`;
      const baseURL = `${context.rootGetters['optionsModule/getAPIUrl']}:${context.rootGetters['optionsModule/getAPIPort']}`;
      axios
        .get(url, { baseURL })
        .then(response => {
          let hash: string = '';

          if (context.state.mustRefresh !== true) {
            hash = md5(
              JSON.stringify(response.data).replace(
                /"timestamp":[0-9]*[,]{0,1}/g,
                ''
              )
            );
          }

          // store the gateway
          context.commit('updateGateway', response.data);
          context.commit('populateNodes', response.data);
          context.commit('populateEdges', response.data);

          if (context.state.mustRefresh || hash !== context.state.lastGetHash) {
            // generate the data structure to vis library
            context.dispatch('visModule/generateNodes', {}, { root: true });
            context.dispatch('visModule/generateEdges', {}, { root: true });
            context.commit('visModule/setGraphData', {}, { root: true });
            context.state.lastGetHash = hash;
          }
        })
        .catch(error => {
          context.dispatch(
            'notifyModule/insertNotify',
            { type: 'error', message: error.message },
            { root: true }
          );
          // tslint:disable-next-line:no-console
          console.error(error.message);
        });
    } else {
      context.dispatch(
        'notifyModule/insertNotify',
        { type: 'error', message: 'missing: gatewayId' },
        { root: true }
      );
      // tslint:disable-next-line:no-console
      console.error('missing: gatewayId');
    }
  }
};

export const c3Module: Module<C3State, RootState> = {
  namespaced,
  state,
  getters,
  mutations,
  actions
};
