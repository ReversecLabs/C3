import { C3State } from './../../../src/types/c3types';
import { mutations, getters } from './../../../src/store/C3Module';
import { RootState } from './../../../src/types/store/RootState';
import { Module, ActionTree } from 'vuex';
import { gateways } from './mockGateways';
import { gateway } from './mockGateway';
import { nodes } from './mockNodes';

const namespaced: boolean = true;

export const state: C3State = {
  gateways: JSON.parse(JSON.stringify(gateways)),
  gateway: JSON.parse(JSON.stringify(gateway)),
  nodes,
  edges: [],
  lastGetHash: 'string'
};

const actions: ActionTree<C3State, RootState> = {
  fetchGateways(context) {
    return (context.state.gateways = JSON.parse(JSON.stringify(gateways)));
  },

  fetchGateway(context) {
    return (context.state.gateway = JSON.parse(JSON.stringify(gateway)));
  }
};

export const c3Module: Module<C3State, RootState> = {
  namespaced,
  state,
  getters,
  mutations,
  actions
};
