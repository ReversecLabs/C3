import { Module, GetterTree, MutationTree, ActionTree } from 'vuex';
import { Node, Edge, Options } from 'vis-network';
import { DataSet } from 'vis-data/peer/esm/vis-data';

import { RootState } from '@/types/store/RootState';
import { C3Edge, NodeKlass, C3Node } from '@/types/c3types';
import {
  GATEWAY,
  RELAY,
  CHANNEL,
  PERIPHERAL,
  CONNECTOR,
  RETURN_CHANNEL,
  VisOptions,
  INACTIVE,
  NEGOTIATION_CHANNEL,
  GHOST
} from '@/options';

const namespaced: boolean = true;

interface VisState {
  nodes: any;
  edges: any;
  options: any;
  autoUpdateEnabled: boolean;
  showInterfaces: boolean;
  showLabels: boolean;
  graphData: {
    nodes: any;
    edges: any;
  };
}

// State

const state: VisState = {
  nodes: {},
  edges: {},
  options: VisOptions,
  showInterfaces: true,
  showLabels: true,
  autoUpdateEnabled: true,
  graphData: {
    nodes: new DataSet({}),
    edges: new DataSet({})
  }
};

// Getters
const getters: GetterTree<VisState, RootState> = {
  getVisNodes(visState): any {
    return visState.nodes;
  },

  getVisEdges(visState): any {
    return visState.edges;
  },

  getGrapData(visState): object {
    return visState.graphData;
  },

  getOptions(visState): Options {
    return visState.options;
  },

  getShowInterfaces(visState): boolean {
    return visState.showInterfaces;
  },

  getShowLabels(visState): boolean {
    return visState.showLabels;
  },

  getAutoUpdateEnabled(visState): boolean {
    return visState.autoUpdateEnabled;
  }
};

// Mutations

export type SetGraphDataFn = () => void;
export type SetOptionFn = (b: boolean) => void;
export type SetAutoUpdateEnabledFn = (d: boolean) => void;
export type SetOptionslFn = (options: Options) => void;

const mutations: MutationTree<VisState> = {
  setNodes(visState, n) {
    visState.nodes = n;
  },

  setEdges(visState, e) {
    visState.edges = e;
  },

  setGraphData(visState) {
    const nodes = new DataSet(visState.nodes);
    const edges = new DataSet(visState.edges);
    const graph = { nodes, edges };
    visState.graphData = graph;
  },

  setOptions(visState, options: Options): void {
    visState.options = options;
  },

  setShowInterfaces(visState, b: boolean): void {
    visState.showInterfaces = b;
  },

  setShowLabels(visState, b: boolean): void {
    visState.showLabels = b;
  },

  setTreeView(visState, b: boolean): void {
    visState.options.layout.hierarchical.enabled = b;
    visState.options.physics.stabilization.onlyDynamicEdges =
      b === true ? true : false;
  },

  setPhysics(visState, b: boolean): void {
    visState.options.physics.enabled = b;
  },

  setSmoothEdge(visState, b: boolean): void {
    visState.options.edges.smooth = b;
  },

  setAutoUpdateEnabled(visState, d: boolean): void {
    visState.autoUpdateEnabled = d;
  }
};

// Actions

export type GenerateNodesFn = () => void;
export type GenerateEdgesFn = () => void;

const actions: ActionTree<VisState, RootState> = {
  generateNodes(context) {
    const ns: C3Node[] = context.rootGetters['c3Module/getNodes'];
    const gatewayLastStartTime =
      context.rootGetters['c3Module/getGateway'].timestamp;
    const gatewayIsActive = context.rootGetters['c3Module/getGateway'].isActive;

    const setGroup = (
      target: C3Node,
      gatewayStartTime: number,
      isGatewayActive: boolean
    ): string => {
      let group: number = 0;

      // Add error if target has an error
      if (target.error !== null) {
        ++group;
      }

      let active = true;

      // If Target down told by API then make inactive
      if (target.isActive !== undefined && target.isActive === false) {
        active = false;
      }

      // If relay last seen begore gateway last start than we think gateway maybe down
      if (target.klass === NodeKlass.Relay) {
        if (!!target.timestamp) {
          active = target.timestamp < gatewayStartTime ? false : true;
        }

        // if gateway down the hole network down
        if (!isGatewayActive) {
          active = false;
        }

        if (target.isActive === false) {
          group = group + GHOST;
        }
      }

      if (!active) {
        group = group + INACTIVE;
      }

      switch (target.klass) {
        case NodeKlass.Channel:
          group += CHANNEL;
          if (target.isReturnChannel === true) {
            group += RETURN_CHANNEL;
          }
          if (target.isNegotiationChannel === true) {
            group += NEGOTIATION_CHANNEL;
          }
          return '' + group;
        case NodeKlass.Relay:
          group += RELAY;
          return '' + group;
        case NodeKlass.Peripheral:
          group += PERIPHERAL;
          return '' + group;
        case NodeKlass.Gateway:
          group += GATEWAY;
          return '' + group;
        case NodeKlass.Connector:
          group += CONNECTOR;
          return '' + group;
      }

      return '' + group;
    };
    const nodes: Node[] = [];
    const interfaccesIncluded: boolean = context.state.showInterfaces;

    ns.forEach((node: C3Node) => {
      if (
        context.state.showInterfaces === true ||
        (interfaccesIncluded !== true && node.klass === NodeKlass.Gateway) ||
        node.klass === NodeKlass.Relay
      ) {
        const group = setGroup(node, gatewayLastStartTime, gatewayIsActive);
        let label = '';
        if (context.state.showLabels) {
          label = node.name || '';
        }

        nodes.push({
          id: node.uid,
          group,
          label
        });
      } else {
        if (!!node.isNegotiationChannel && node.isNegotiationChannel === true) {
          const group = setGroup(node, gatewayLastStartTime, gatewayIsActive);
          let label = '';
          if (context.state.showLabels) {
            label = node.name || '';
          }

          nodes.push({
            id: node.uid,
            group,
            label
          });
        }
      }
    });

    context.commit('setNodes', nodes);
  },

  generateEdges(context) {
    const es: C3Edge[] = context.rootGetters['c3Module/getEdges'];
    const edges: Edge[] = [];
    const interfaccesIncluded: boolean = context.state.showInterfaces;

    es.forEach(edge => {
      if (interfaccesIncluded === true && edge.klass === NodeKlass.Interface) {
        edges.push({
          id: edge.id,
          length: edge.length,
          dashes: edge.dashes,
          from: edge.from,
          to: edge.to
        });
      }

      if (interfaccesIncluded !== true && edge.klass === NodeKlass.Interface) {
        if (!!edge.isNegotiationChannel) {
          edges.push({
            id: edge.id,
            length: edge.length,
            dashes: edge.dashes,
            from: edge.from,
            to: edge.to
          });
        }
      }

      if (interfaccesIncluded !== true && edge.klass !== NodeKlass.Interface) {
        const e = {
          id: edge.id,
          length: edge.length,
          dashes: edge.dashes,
          from: edge.from,
          to: edge.to,
          color: {}
        };
        if (edge.dashes === true) {
          e.color = {
            color: '#FFC24B'
          };
        }
        edges.push(e);
      }
    });
    context.commit('setEdges', edges);
  }
};

export const visModule: Module<VisState, RootState> = {
  namespaced,
  state,
  getters,
  mutations,
  actions
};
