/* tslint:disable no-unused-expression */
import { expect } from 'chai';
import { shallowMount, createLocalVue } from '@vue/test-utils';
import Vuex from 'vuex';

import DataTableFooter from '@/components/datatables/DataTableFooter.vue';
import { modules } from '../../store/mockstore';

const localVue = createLocalVue();
localVue.use(Vuex);

describe('@/components/datatables/DataTableFooter.vue', () => {
  const store = new Vuex.Store({
    modules
  });

  it('DataTableFooter is a Vue instance', () => {
    const wrapper = shallowMount(DataTableFooter, { store, localVue });
    expect(wrapper.isVueInstance()).to.be.true;
  });
});
