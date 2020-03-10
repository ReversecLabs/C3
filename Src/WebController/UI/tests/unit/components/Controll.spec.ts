/* tslint:disable no-unused-expression */
import { expect } from 'chai';
import { shallowMount, createLocalVue } from '@vue/test-utils';
import Vuex from 'vuex';

import Controll from '@/components/Controll.vue';
import { modules } from '../store/mockstore';

const localVue = createLocalVue();
localVue.use(Vuex);

describe('@/components/Controll.vue', () => {
  const store = new Vuex.Store({
    modules
  });

  it('Controll is a Vue instance', () => {
    const wrapper = shallowMount(Controll, { store, localVue });
    expect(wrapper.isVueInstance()).to.be.true;
  });
});
