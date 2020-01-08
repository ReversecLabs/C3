import { Module, GetterTree, MutationTree, ActionTree } from 'vuex';

import axios from 'axios';
import { RootState } from '@/types/store/RootState';
import { C3Command } from '@/types/c3types';

const namespaced: boolean = true;
// State

export interface C3CommandState {
  commands: C3Command[];
  totalCount: number;
}

export const state: C3CommandState = {
  commands: [],
  totalCount: 0
};

// Getters

export type GetCommandFn = (id: string) => C3Command | undefined;

export const getters: GetterTree<C3CommandState, RootState> = {
  // return gateways agentIds
  getCommands(C3State): C3Command[] {
    return C3State.commands;
  },

  getCommand: C3State => (id: string | number): C3Command | undefined => {
    return C3State.commands.find(command => {
      return '' + command.id === '' + id;
    });
  },

  getCommandCount(C3State): number {
    return C3State.totalCount;
  }
};

// Mutations

export const mutations: MutationTree<C3CommandState> = {
  updateCommands(C3State, data: any) {
    C3State.commands = data;
  },

  updateTotalCount(C3State, totalCount: number) {
    C3State.totalCount = totalCount;
  }
};

// Actions

export type FetchC3CommandFn = (gatewayId: string) => void;

const actions: ActionTree<C3CommandState, RootState> = {
  fetchCommands(context, gatewayId: string) {
    if (!!gatewayId) {
      const page = context.rootGetters['paginateModule/getActualPage'];
      const perPage = context.rootGetters['paginateModule/getItemPerPage'];

      const url = `/api/gateway/${gatewayId}/command?all=true&page=${page}&perPage=${perPage}`;
      const baseURL = `${context.rootGetters['optionsModule/getAPIUrl']}:${context.rootGetters['optionsModule/getAPIPort']}`;

      axios
        .get(url, { baseURL })
        .then(response => {
          // store the gateway
          context.commit('updateCommands', response.data);

          let totalCount = 0;
          if (!!response.headers['X-Total-Count']) {
            totalCount = response.headers['X-Total-Count'];
          } else if (response.headers['x-total-count']) {
            totalCount = response.headers['x-total-count'];
          }
          if (!!totalCount) {
            context.commit('updateTotalCount', totalCount);
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

export const c3CommandModule: Module<C3CommandState, RootState> = {
  namespaced,
  state,
  getters,
  mutations,
  actions
};
