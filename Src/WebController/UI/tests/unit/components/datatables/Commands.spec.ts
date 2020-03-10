/* tslint:disable no-unused-expression */
import { expect } from 'chai';
import { shallowMount, createLocalVue } from '@vue/test-utils';
import Vuex from 'vuex';

import CommandsTab from '@/components/datatables/Commands.vue';
import { modules } from '../../store/mockstore';

const localVue = createLocalVue();

localVue.use(Vuex);

describe('@/components/datatables/Commands.vue', () => {
  const store = new Vuex.Store({
    modules
  });

  it('CommandsTab is a Vue instance', () => {
    const wrapper = shallowMount(CommandsTab, { store, localVue });
    expect(wrapper.isVueInstance()).to.be.true;
  });
});
