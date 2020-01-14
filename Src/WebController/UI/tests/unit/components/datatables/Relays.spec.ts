/* tslint:disable no-unused-expression */
import { expect } from 'chai';
import { shallowMount, createLocalVue } from '@vue/test-utils';
import Vuex from 'vuex';

import RelaysTab from '@/components/datatables/Relays.vue';
import { modules } from '../../store/mockstore';

const localVue = createLocalVue();

localVue.use(Vuex);

describe('@/components/datatables/Relays.vue', () => {
  const store = new Vuex.Store({
    modules
  });

  it('RelaysTab is a Vue instance', () => {
    const wrapper = shallowMount(RelaysTab, { store, localVue });
    expect(wrapper.isVueInstance()).to.be.true;
  });
});
