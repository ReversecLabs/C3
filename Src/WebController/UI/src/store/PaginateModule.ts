import { Module, GetterTree, MutationTree, ActionTree } from 'vuex';
import { RootState } from '@/types/store/RootState';

const namespaced: boolean = true;

interface PaginateState {
  itemPerPage: number;
  actualPage: number;
  lastChange: number;
}

// State

const state: PaginateState = {
  itemPerPage: 5,
  actualPage: 1,
  lastChange: Date.now()
};

// Getters

const getters: GetterTree<PaginateState, RootState> = {
  getItemPerPage(paginateState): number {
    return paginateState.itemPerPage;
  },

  getActualPage(paginateState): number {
    return paginateState.actualPage;
  },

  getLastChange(paginateState): number {
    return paginateState.lastChange;
  }
};

// Mutations

export type SetItemPerPageFn = (itemPerPage: number) => void;
export type SetActualPageFn = (itemPerPage: number) => void;

export const mutations: MutationTree<PaginateState> = {
  setItemPerPage(paginateState, itemPerPage: number): void {
    paginateState.actualPage = 1;
    paginateState.itemPerPage = itemPerPage;
    paginateState.lastChange = Date.now();
  },

  setActualPage(paginateState, actualPage: number): void {
    paginateState.actualPage = actualPage;
    paginateState.lastChange = Date.now();
  }
};

// Actions

const actions: ActionTree<PaginateState, RootState> = {};

export const paginateModule: Module<PaginateState, RootState> = {
  namespaced,
  state,
  getters,
  mutations,
  actions
};
