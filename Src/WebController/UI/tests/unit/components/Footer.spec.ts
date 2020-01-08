/* tslint:disable no-unused-expression */
import { expect } from 'chai';
import { shallowMount, createLocalVue } from '@vue/test-utils';
import Vuex from 'vuex';

import Footer from '@/components/Footer.vue';
import { modules } from '../store/mockstore';

const localVue = createLocalVue();
localVue.use(Vuex);

describe('@/components/Footer.vue', () => {
  const store = new Vuex.Store({
    modules
  });

  it('Footer is a Vue instance', () => {
    const wrapper = shallowMount(Footer, { store, localVue });
    expect(wrapper.isVueInstance()).to.be.true;
  });
});
