/* tslint:disable no-unused-expression */
import { expect } from 'chai';
import { shallowMount, createLocalVue } from '@vue/test-utils';
import Vuex from 'vuex';

import GeneralForm from '@/components/datatables/Relays.vue';
import { modules } from '../../store/mockstore';

const localVue = createLocalVue();

localVue.use(Vuex);

describe('@/components/datatables/Relays.vue', () => {
  const store = new Vuex.Store({
    modules
  });

  it('GeneralForm is a Vue instance', () => {
    const wrapper = shallowMount(GeneralForm, { store, localVue });
    expect(wrapper.isVueInstance()).to.be.true;
  });
});
