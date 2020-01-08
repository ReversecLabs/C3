/* tslint:disable no-unused-expression */
import { expect } from 'chai';
import { shallowMount, createLocalVue } from '@vue/test-utils';
import Vuex from 'vuex';

import RouteList from '@/components/partial/RouteList.vue';
import { modules } from '../../store/mockstore';

const localVue = createLocalVue();
localVue.use(Vuex);

describe('@/components/partial/RouteList.vue', () => {
  const store = new Vuex.Store({
    modules
  });

  it('RouteList is a Vue instance', () => {
    const wrapper = shallowMount(RouteList, {
      store,
      localVue
    });
    expect(wrapper.isVueInstance()).to.be.true;
  });
});
