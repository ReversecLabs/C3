/* tslint:disable no-unused-expression */
import { expect } from 'chai';
import { shallowMount, createLocalVue } from '@vue/test-utils';
import Vuex from 'vuex';

import Canvas from '@/components/Canvas.vue';
import { modules } from '../store/mockstore';

const localVue = createLocalVue();
localVue.use(Vuex);

describe('@/components/Canvas.vue', () => {
  const store = new Vuex.Store({
    modules
  });

  it('Canvas is a Vue instance', () => {
    const wrapper = shallowMount(Canvas, { store, localVue });
    expect(wrapper.isVueInstance()).to.be.true;
  });
});
