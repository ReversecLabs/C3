/* tslint:disable no-unused-expression */
import { expect } from 'chai';
import { shallowMount, createLocalVue } from '@vue/test-utils';
import Vuex from 'vuex';
import VeeValidate from 'vee-validate';

import SelectGatewayForm from '@/components/form/SelectGatewayForm.vue';
import { modules } from '../../store/mockstore';

const localVue = createLocalVue();
localVue.use(Vuex);
localVue.use(VeeValidate, {
  inject: false,
  validity: true
});

describe('@/components/form/SelectGatewayForm.vue', () => {
  const store = new Vuex.Store({
    modules
  });

  it('SelectGatewayForm is a Vue instance', () => {
    const wrapper = shallowMount(SelectGatewayForm, {
      store,
      localVue
    });
    expect(wrapper.isVueInstance()).to.be.true;
  });
});
