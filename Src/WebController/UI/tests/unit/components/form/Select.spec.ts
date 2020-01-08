/* tslint:disable no-unused-expression */
import { expect } from 'chai';
import { shallowMount, createLocalVue } from '@vue/test-utils';
import Vuex from 'vuex';

import Select from '@/components/form/Select.vue';
import { modules } from '../../store/mockstore';

const localVue = createLocalVue();
localVue.use(Vuex);

describe('@/components/form/Select.vue', () => {
  const store = new Vuex.Store({
    modules
  });

  it('Select is a Vue instance', () => {
    const wrapper = shallowMount(Select, {
      propsData: {
        selected: 'perPage',
        options:
          '{"5": "5", "10": "10","25": "25", "50": "50", "100": "100", "1000": "All"}'
      },
      store,
      localVue
    });
    expect(wrapper.isVueInstance()).to.be.true;
  });
});
