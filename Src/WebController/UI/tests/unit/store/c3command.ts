import { RootState } from '@/types/store/RootState';
import { Module, ActionTree } from 'vuex';
import { C3CommandState } from '@/store/C3Command';
import { getters, mutations } from '@/store/C3Command';
import { commands } from './mockCommandLogs';

const namespaced: boolean = true;

export const state: C3CommandState = {
  commands: JSON.parse(JSON.stringify(commands)),
  totalCount: 0
};

const actions: ActionTree<C3CommandState, RootState> = {
  fetchCapability(context) {
    return (context.state.commands = JSON.parse(JSON.stringify(commands)));
  }
};

export const c3CommandModule: Module<C3CommandState, RootState> = {
  namespaced,
  state,
  getters,
  mutations,
  actions
};
