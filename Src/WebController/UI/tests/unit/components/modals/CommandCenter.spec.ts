/* tslint:disable no-unused-expression */
import { expect } from 'chai';
import { shallowMount, createLocalVue } from '@vue/test-utils';
import Vuex from 'vuex';

import CommandCenterModal from '@/components/modals/CommandCenter.vue';
import { modules } from '../../store/mockstore';

const localVue = createLocalVue();
localVue.use(Vuex);

describe('@/components/modals/CommandCenter.vue', () => {
  const store = new Vuex.Store({
    modules
  });

  it('CommandCenterModal is a Vue instance', () => {
    const wrapper = shallowMount(CommandCenterModal, {
      propsData: {
        targetId: '7c864a181f31cdba'
      },
      store,
      localVue
    });
    expect(wrapper.isVueInstance()).to.be.true;
  });
});
