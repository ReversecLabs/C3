/* tslint:disable no-unused-expression */
import { expect } from 'chai';
import { shallowMount, createLocalVue } from '@vue/test-utils';
import Vuex from 'vuex';
import VeeValidate from 'vee-validate';

import Toggle from '@/components/form/Toggle.vue';
import { modules } from '../../store/mockstore';

const localVue = createLocalVue();
localVue.use(Vuex);
localVue.use(VeeValidate, {
  inject: false,
  validity: true
});

describe('@/components/form/Toggle.vue', () => {
  const store = new Vuex.Store({
    modules
  });

  it('Toggle is a Vue instance', () => {
    const wrapper = shallowMount(Toggle, {
      propsData: {
        legend: 'legend... toggle!',
        help: 'help text...'
      },
      store,
      localVue,
      sync: false
    });
    expect(wrapper.isVueInstance()).to.be.true;
  });

  it('On click the emitted value are correct', () => {
    const wrapper = shallowMount(Toggle, {
      propsData: {
        legend: 'legend... toggle!',
        help: 'help text...',
        checked: true
      },
      store,
      localVue
    });

    const input = wrapper.find('.c3toggle-input');
    input.trigger('click');

    const inputEmit = wrapper.emitted('change');
    expect(inputEmit[0][0].value).to.be.false;
  });

  it('Toggle contains the legend', () => {
    const wrapper = shallowMount(Toggle, {
      propsData: {
        legend: 'legend... toggle!',
        help: 'help text...',
        checked: true
      },
      store,
      localVue
    });

    const label = wrapper.find('.c3checkbox-row');
    expect(label.text()).to.contain('legend... toggle!');
  });

  it('Toggle contains the help icon', () => {
    const wrapper = shallowMount(Toggle, {
      propsData: {
        legend: 'legend... toggle!',
        help: 'help text...',
        checked: true
      },
      store,
      localVue
    });

    const hasHelp = wrapper.vm.hasHelp;
    expect(hasHelp).to.be.true;

    const help = wrapper.find('.icon.help');
    expect(help.text()).to.contain('help text...');
  });

  it('Toggle NOT contains the help icon', () => {
    const wrapper = shallowMount(Toggle, {
      propsData: {
        legend: 'legend... toggle!',
        checked: false
      },
      store,
      localVue
    });

    const hasHelp = wrapper.vm.hasHelp;
    expect(hasHelp).to.be.false;

    const label = wrapper.find('.icon.help');
    expect(label.exists()).to.be.false;
  });
});
