/* tslint:disable no-unused-expression */
import { expect } from 'chai';
import { shallowMount, createLocalVue } from '@vue/test-utils';
import Vuex from 'vuex';

import CommandModal from '@/components/modals/Command.vue';
import { modules } from '../../store/mockstore';

const localVue = createLocalVue();
localVue.use(Vuex);

describe('@/components/modals/Command.vue', () => {
  const store = new Vuex.Store({
    modules
  });

  it('CommandModal is a Vue instance', () => {
    const wrapper = shallowMount(CommandModal, {
      propsData: {
        targetId: 6
      },
      store,
      localVue
    });
    expect(wrapper.isVueInstance()).to.be.true;
  });
});
