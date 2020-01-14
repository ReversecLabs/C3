import Vue from 'vue';
import Vuex, { StoreOptions } from 'vuex';

import { RootState } from '@/types/store/RootState';

import { c3Module } from '@/store/C3Module';
import { modalModule } from '@/store/ModalModule';
import { paginateModule } from '@/store/PaginateModule';
import { visModule } from '@/store/VisModule';
import { notifyModule } from '@/store/NotifyModule';
import { c3Capability } from '@/store/C3Capability';
import { optionsModule } from '@/store/OptionsModule';
import { c3CommandModule } from '@/store/C3Command';

Vue.use(Vuex);

const store: StoreOptions<RootState> = {
  state: {
    version: '1.0.0'
  },
  modules: {
    c3Module,
    visModule,
    modalModule,
    notifyModule,
    c3Capability,
    optionsModule,
    paginateModule,
    c3CommandModule
  }
};

export default new Vuex.Store<RootState>(store);
