/* tslint:disable no-unused-expression */
import { expect } from 'chai';
import { shallowMount, createLocalVue } from '@vue/test-utils';
import Vuex from 'vuex';

import GatewayModal from '@/components/modals/Gateway.vue';
import { modules } from '../../store/mockstore';

const localVue = createLocalVue();
localVue.use(Vuex);

describe('@/components/modals/Gateway.vue', () => {
  const store = new Vuex.Store({
    modules
  });

  it('GatewayModal is a Vue instance', () => {
    const wrapper = shallowMount(GatewayModal, {
      store,
      localVue
    });
    expect(wrapper.isVueInstance()).to.be.true;
  });
});
