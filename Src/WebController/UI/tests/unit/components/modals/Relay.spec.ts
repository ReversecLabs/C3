/* tslint:disable no-unused-expression */
import { expect } from 'chai';
import { shallowMount, createLocalVue } from '@vue/test-utils';
import Vuex from 'vuex';

import RelayModal from '@/components/modals/Relay.vue';
import { modules } from '../../store/mockstore';

const localVue = createLocalVue();
localVue.use(Vuex);

describe('@/components/modals/Relay.vue', () => {
  const store = new Vuex.Store({
    modules
  });

  it('RelayModal is a Vue instance', () => {
    const wrapper = shallowMount(RelayModal, {
      propsData: {
        targetId: 'a1d2'
      },
      store,
      localVue
    });
    expect(wrapper.isVueInstance()).to.be.true;
  });
});
