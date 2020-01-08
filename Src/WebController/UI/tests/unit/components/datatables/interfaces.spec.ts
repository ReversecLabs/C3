/* tslint:disable no-unused-expression */
import { expect } from 'chai';
import { shallowMount, createLocalVue } from '@vue/test-utils';
import Vuex from 'vuex';

import InterfacesTab from '@/components/datatables/Interfaces.vue';
import { modules } from '../../store/mockstore';

const localVue = createLocalVue();
localVue.use(Vuex);

describe('@/components/datatables/Interfaces.vue', () => {
  const store = new Vuex.Store({
    modules
  });

  it('InterfacesTab is a Vue instance', () => {
    const wrapper = shallowMount(InterfacesTab, { store, localVue });
    expect(wrapper.isVueInstance()).to.be.true;
  });
});
