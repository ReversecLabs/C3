import { RootState } from './../../../src/types/store/RootState';
import { Module, ActionTree } from 'vuex';
import {
  CapabilityState,
  getters,
  mutations
} from './../../../src/store/C3Capability';
import { capability } from './mockCapability';

const namespaced: boolean = true;

export const state: CapabilityState = {
  capability,
  interfaceList: []
};

const actions: ActionTree<CapabilityState, RootState> = {
  fetchCapability(context) {
    return (context.state.capability = JSON.parse(JSON.stringify(capability)));
  }
};

export const c3Capability: Module<CapabilityState, RootState> = {
  namespaced,
  state,
  getters,
  mutations,
  actions
};
