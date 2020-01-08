import { Module, GetterTree, MutationTree, ActionTree } from 'vuex';
import { RootState } from '@/types/store/RootState';
import { refreshInterval } from '@/options';

const namespaced: boolean = true;

interface OptionsState {
  baseUrl: string;
  port: number;
  refreshInterval: number;
}

// State

const state: OptionsState = {
  baseUrl: 'http://localhost',
  port: 52935,
  refreshInterval: 2000
};

// Getters

const getters: GetterTree<OptionsState, RootState> = {
  getAPIUrl(optionsState): string {
    return optionsState.baseUrl;
  },

  getAPIPort(optionsState): number {
    return optionsState.port;
  },

  getAPIBaseUrl(optionsState): string {
    return optionsState.baseUrl + ':' + optionsState.port;
  },

  getRefreshInterval(optionsState): number {
    return optionsState.refreshInterval;
  }
};

// Mutations

export type SetBaseURLFn = (url: string) => void;
export type SetBasePortFn = (port: number) => void;
export type SetRefreshIntervalFn = (refreshInterval: number) => void;

export const mutations: MutationTree<OptionsState> = {
  setBaseURL(optionsState, url: string): void {
    optionsState.baseUrl = url;
  },

  setBasePort(optionsState, port: number): void {
    optionsState.port = port;
  },

  setRefreshInterval(optionsState, refreshRate: number): void {
    optionsState.refreshInterval = refreshRate;
  }
};

// Actions

const actions: ActionTree<OptionsState, RootState> = {};

export const optionsModule: Module<OptionsState, RootState> = {
  namespaced,
  state,
  getters,
  mutations,
  actions
};
