import { Module, GetterTree, MutationTree, ActionTree } from 'vuex';

import { RootState } from '@/types/store/RootState';

const namespaced: boolean = true;

export interface ModalState {
  modals: C3Modal[];
}

export interface C3Modal {
  modalTarget: string;
  modalTargetId: any;
  modalOptions: any;
}

// State

const state: ModalState = {
  modals: []
};

// Getters
const getters: GetterTree<ModalState, RootState> = {
  activeModal(modalState): C3Modal | undefined {
    if (modalState.modals.length > 0) {
      return modalState.modals[modalState.modals.length - 1];
    }
    return undefined;
  }
};

// Mutations

export type NewModalFn = (m: C3Modal) => void;
export type CloseModalFn = () => void;

const mutations: MutationTree<ModalState> = {
  newModal(modalState, m: C3Modal) {
    let last: any = false;
    if (modalState.modals.length > 1) {
      last = modalState.modals[modalState.modals.length - 2];
    }
    if (
      last !== false &&
      last.modalTarget === m.modalTarget &&
      last.modalTargetId === m.modalTargetId
    ) {
      modalState.modals.pop();
    } else {
      modalState.modals.push(m);
    }
  },

  closeModal(modalState) {
    if (modalState.modals.length > 0) {
      modalState.modals.pop();
    }
  },

  closeModalAll(modalState) {
    modalState.modals = [];
  }
};

// Actions

export const actions: ActionTree<ModalState, RootState> = {};

export const modalModule: Module<ModalState, RootState> = {
  namespaced,
  state,
  getters,
  mutations,
  actions
};
