/* tslint:disable no-unused-expression */
import { expect } from 'chai';
import { shallowMount, createLocalVue } from '@vue/test-utils';
import Vuex from 'vuex';

import Navbar from '@/components/Navbar.vue';
import { modules } from '../store/mockstore';

const localVue = createLocalVue();
localVue.use(Vuex);

describe('@/components/Navbar.vue', () => {
  const store = new Vuex.Store({
    modules
  });

  it('Navbar is a Vue instance', () => {
    const wrapper = shallowMount(Navbar, { store, localVue });
    expect(wrapper.isVueInstance()).to.be.true;
  });
});
