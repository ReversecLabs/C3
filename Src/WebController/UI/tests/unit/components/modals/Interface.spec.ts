/* tslint:disable no-unused-expression */
import { expect } from 'chai';
import { shallowMount, createLocalVue } from '@vue/test-utils';
import Vuex from 'vuex';
import InterfaceModal from '@/components/modals/Interface.vue';
import { modules } from '../../store/mockstore';

const localVue = createLocalVue();
localVue.use(Vuex);

describe('@/components/modals/Channel.vue', () => {
  const store = new Vuex.Store({
    modules
  });

  it('InterfaceModal is a Vue instance', () => {
    const wrapper = shallowMount(InterfaceModal, {
      propsData: {
        targetId: '11d1-a1d0'
      },
      store,
      localVue
    });
    expect(wrapper.isVueInstance()).to.be.true;
  });
});
