/* tslint:disable no-unused-expression */
import { expect } from 'chai';
import { shallowMount, createLocalVue } from '@vue/test-utils';
import Vuex from 'vuex';

import CreateGatewayModal from '@/components/modals/CreateGateway.vue';
import { modules } from '../../store/mockstore';

const localVue = createLocalVue();
localVue.use(Vuex);

describe('@/components/modals/CreateGateway.vue', () => {
  const store = new Vuex.Store({
    modules
  });

  it('CreateGatewayModal is a Vue instance', () => {
    const wrapper = shallowMount(CreateGatewayModal, {
      store,
      localVue
    });
    expect(wrapper.isVueInstance()).to.be.true;
  });
});
