/* tslint:disable no-unused-expression */
import { expect } from 'chai';
import { shallowMount, createLocalVue } from '@vue/test-utils';
import Vuex from 'vuex';

import CreateRelayModal from '@/components/modals/CreateRelay.vue';
import { modules } from '../../store/mockstore';

const localVue = createLocalVue();
localVue.use(Vuex);

describe('@/components/modals/CreateRelay.vue', () => {
  const store = new Vuex.Store({
    modules
  });

  it('CreateRelayModal is a Vue instance', () => {
    const wrapper = shallowMount(CreateRelayModal, {
      store,
      localVue
    });
    expect(wrapper.isVueInstance()).to.be.true;
  });
});
