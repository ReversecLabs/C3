/* tslint:disable no-unused-expression */
import { expect } from 'chai';
import { shallowMount, createLocalVue } from '@vue/test-utils';
import Vuex from 'vuex';

import Modal from '@/components/Modal.vue';
import { modules } from '../store/mockstore';

const localVue = createLocalVue();
localVue.use(Vuex);

describe('@/components/Modal.vue', () => {
  const store = new Vuex.Store({
    modules
  });

  it('Modal is a Vue instance', () => {
    const wrapper = shallowMount(Modal, { store, localVue });
    expect(wrapper.isVueInstance()).to.be.true;
  });
});
