import { Module, GetterTree, MutationTree, ActionTree } from 'vuex';

import { notifyLenght, maximumToast } from '@/options';
import { RootState } from '@/types/store/RootState';

const namespaced: boolean = true;

export interface Notify {
  id?: string;
  type: string;
  title?: string;
  message: string;
  timeoutID?: any;
}

interface NotifyState {
  notifys: Notify[];
}

// State

export const state: NotifyState = {
  notifys: []
};

// Getters

const getters: GetterTree<NotifyState, RootState> = {
  getNotifies(notifyState): Notify[] {
    return notifyState.notifys;
  }
};

// Mutations

export type AddNotifyFn = (notify: Notify) => void;
export type UpdateNotifyFn = (notify: Notify) => void;
export type RemoveNotifyFn = (id: string) => void;

export const mutations: MutationTree<NotifyState> = {
  addNotify(notifyState, notify: Notify): void {
    notifyState.notifys.push(notify);
  },

  updateNotify(notifyState, notify: Notify): void {
    const notifyIndex = notifyState.notifys.findIndex(n => n.id === notify.id);
    if (notifyIndex > -1) {
      notifyState.notifys[notifyIndex] = notify;
    }
  },

  removeNotify(notifyState, id: string): void {
    const notifyIndex = notifyState.notifys.findIndex(n => n.id === id);
    if (notifyIndex > -1) {
      notifyState.notifys.splice(notifyIndex, 1);
    }
  },

  removeOldestNotify(notifyState): void {
    const notifyCount = notifyState.notifys.length;

    if (notifyCount > 0) {
      const notify = notifyState.notifys[0];
      if (!!notify.timeoutID) {
        clearTimeout(notify.timeoutID);
      }
      notifyState.notifys.splice(0, 1);
    }
  }
};

// Actions

export type InsertNotifyFn = (notify: Notify) => void;

const actions: ActionTree<NotifyState, RootState> = {
  insertNotify(context, notify: Notify) {
    const addNotification = (notification: Notify) => {
      notify.id = Math.random()
        .toString(36)
        .substr(2);
      notify.timeoutID = setTimeout((): boolean => {
        context.commit('removeNotify', notify.id);
        return true;
      }, notifyLenght);
      context.commit('addNotify', notify);
    };

    // Check how many notification we have
    const notifyCount = context.state.notifys.length;

    // Don' add duplicate notifications
    // Mostly affecting: Network error - if backand not reachable
    if (notifyCount > 0) {
      if (notify.message !== context.state.notifys[notifyCount - 1].message) {
        addNotification(notify);
      } else {
        // Replace the timeout for the notification
        const lastNotify = context.state.notifys[notifyCount - 1];

        clearTimeout(lastNotify.timeoutID);

        lastNotify.timeoutID = setTimeout((): boolean => {
          context.commit('removeNotify', lastNotify.id);
          return true;
        }, notifyLenght);
        context.commit('updateNotify', lastNotify);
      }
    } else {
      addNotification(notify);
    }

    // If we already reach the maximum notification limit
    // remove the oldest
    if (notifyCount >= maximumToast) {
      context.commit('removeOldestNotify');
    }
  }
};

export const notifyModule: Module<NotifyState, RootState> = {
  namespaced,
  state,
  getters,
  mutations,
  actions
};
