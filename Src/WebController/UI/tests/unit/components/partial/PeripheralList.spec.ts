/* tslint:disable no-unused-expression */
import { expect } from 'chai';
import { shallowMount, createLocalVue } from '@vue/test-utils';
import Vuex from 'vuex';

import PeripheralList from '@/components/partial/PeripheralList.vue';
import { modules } from '../../store/mockstore';

const localVue = createLocalVue();
localVue.use(Vuex);

describe('@/components/partial/PeripheralList.vue', () => {
  const store = new Vuex.Store({
    modules
  });

  it('PeripheralList is a Vue instance', () => {
    const wrapper = shallowMount(PeripheralList, {
      propsData: {
        targetId: 'a1d1'
      },
      store,
      localVue
    });
    expect(wrapper.isVueInstance()).to.be.true;
  });

  it('PeripheralList populated correctly (populated)', () => {
    const wrapper = shallowMount(PeripheralList, {
      propsData: {
        targetId: 'a1d1',
        title: 'Peripherals',
        showEmpty: true
      },
      store,
      localVue
    });

    const connectorsElementsCount = wrapper.vm.peripherals.length;
    expect(connectorsElementsCount).to.eql(0);
  });

  it('PeripheralList populated correctly (empty)', () => {
    const wrapper = shallowMount(PeripheralList, {
      propsData: {
        targetId: 'a1d0',
        title: 'Peripherals',
        showEmpty: true
      },
      store,
      localVue
    });

    const connectorsElementsCount = wrapper.vm.peripherals.length;
    expect(connectorsElementsCount).to.eql(0);
  });

  it('PeripheralList List hasTitle (has)', () => {
    const wrapper = shallowMount(PeripheralList, {
      propsData: {
        targetId: 'a1d1',
        title: 'Peripherals',
        showEmpty: true
      },
      store,
      localVue
    });

    const hasTitle = wrapper.vm.hasTitle;
    expect(hasTitle).to.be.true;
  });

  it('PeripheralList List hasTitle (has NOT)', () => {
    const wrapper = shallowMount(PeripheralList, {
      propsData: {
        targetId: 'a1d1',
        title: '',
        showEmpty: true
      },
      store,
      localVue
    });

    const hasTitle = wrapper.vm.hasTitle;
    expect(hasTitle).to.be.false;
  });

  it('PeripheralList List displayEmpty (true)', () => {
    const wrapper = shallowMount(PeripheralList, {
      propsData: {
        targetId: 'a1d1',
        title: 'Peripherals',
        showEmpty: true
      },
      store,
      localVue
    });

    const hasTitle = wrapper.vm.displayEmpty;
    expect(hasTitle).to.be.true;
  });

  it('PeripheralList List displayEmpty (false)', () => {
    const wrapper = shallowMount(PeripheralList, {
      propsData: {
        targetId: 'a1d1',
        title: 'Peripherals',
        showEmpty: false
      },
      store,
      localVue
    });

    const hasTitle = wrapper.vm.displayEmpty;
    expect(hasTitle).to.be.false;
  });
});
