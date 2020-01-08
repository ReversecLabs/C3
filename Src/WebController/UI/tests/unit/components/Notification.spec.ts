/* tslint:disable no-unused-expression */
import { expect } from 'chai';
import { shallowMount, createLocalVue } from '@vue/test-utils';
import Vuex from 'vuex';

import Notification from '@/components/Notification.vue';
import { modules } from '../store/mockstore';

const localVue = createLocalVue();
localVue.use(Vuex);

describe('@/components/Notification.vue', () => {
  const store = new Vuex.Store({
    modules
  });

  it('Notification is a Vue instance', () => {
    const wrapper = shallowMount(Notification, { store, localVue });
    expect(wrapper.isVueInstance()).to.be.true;
  });
});
