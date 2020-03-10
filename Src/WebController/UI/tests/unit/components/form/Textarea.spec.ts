/* tslint:disable no-unused-expression */
import { expect } from 'chai';
import { shallowMount, createLocalVue } from '@vue/test-utils';
import Vuex from 'vuex';
import VeeValidate from 'vee-validate';

import Textarea from '@/components/form/Textarea.vue';
import { modules } from '../../store/mockstore';

const localVue = createLocalVue();
localVue.use(Vuex);
localVue.use(VeeValidate, {
  inject: false,
  validity: true
});

describe('@/components/form/Textarea.vue', () => {
  const store = new Vuex.Store({
    modules
  });

  it('Textarea is a Vue instance', () => {
    const wrapper = shallowMount(Textarea, {
      propsData: {
        legend: 'legend...perPage',
        help: 'help text...'
      },
      store,
      localVue
    });
    expect(wrapper.isVueInstance()).to.be.true;
  });
});
