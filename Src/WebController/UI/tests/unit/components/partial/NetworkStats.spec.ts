/* tslint:disable no-unused-expression */
import { expect } from 'chai';
import { shallowMount, createLocalVue } from '@vue/test-utils';
import Vuex from 'vuex';

import NetworkStats from '@/components/partial/NetworkStats.vue';
import { modules } from '../../store/mockstore';

const localVue = createLocalVue();
localVue.use(Vuex);

describe('@/components/partial/NetworkStats.vue', () => {
  const store = new Vuex.Store({
    modules
  });

  it('NetworkStats is a Vue instance', () => {
    const wrapper = shallowMount(NetworkStats, {
      store,
      localVue
    });
    expect(wrapper.isVueInstance()).to.be.true;
  });
});
