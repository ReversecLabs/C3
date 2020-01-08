/* tslint:disable no-unused-expression */
import { expect } from 'chai';
import { shallowMount, createLocalVue } from '@vue/test-utils';
import Vuex from 'vuex';

import InterfaceList from '@/components/partial/InterfaceList.vue';
import { modules } from '../../store/mockstore';

const localVue = createLocalVue();
localVue.use(Vuex);

describe('@/components/partial/InterfaceList.vue', () => {
  const store = new Vuex.Store({
    modules
  });

  it('InterfaceList is a Vue instance', () => {
    const wrapper = shallowMount(InterfaceList, {
      propsData: {
        interfaceTypeFilter: 'ALL',
        returnChannelFilter: 'ALL'
      },
      store,
      localVue
    });
    expect(wrapper.isVueInstance()).to.be.true;
  });

  it('InterfaceList populated and filtered correctly (all)', () => {
    const wrapper = shallowMount(InterfaceList, {
      propsData: {
        title: 'Interfaces',
        showEmpty: true,
        interfaceTypeFilter: 'ALL',
        returnChannelFilter: 'ALL'
      },
      store,
      localVue
    });

    const connectorsElementsCount = wrapper.vm.c3Interfaces.length;
    expect(connectorsElementsCount).to.eql(26);
  });

  it('InterfaceList populated and filtered correctly (connector/return)', () => {
    const wrapper = shallowMount(InterfaceList, {
      propsData: {
        title: 'Interfaces',
        showEmpty: true,
        interfaceTypeFilter: 'CONNECTOR',
        returnChannelFilter: 'YES'
      },
      store,
      localVue
    });

    const connectorsElementsCount = wrapper.vm.c3Interfaces.length;
    expect(connectorsElementsCount).to.eql(0);
  });

  it('InterfaceList populated and filtered correctly (channel/return)', () => {
    const wrapper = shallowMount(InterfaceList, {
      propsData: {
        title: 'Interfaces',
        showEmpty: true,
        interfaceTypeFilter: 'CHANNEL',
        returnChannelFilter: 'YES'
      },
      store,
      localVue
    });

    const connectorsElementsCount = wrapper.vm.c3Interfaces.length;
    expect(connectorsElementsCount).to.eql(8);
  });

  it('InterfaceList List hasTitle (has)', () => {
    const wrapper = shallowMount(InterfaceList, {
      propsData: {
        title: 'Interfaces',
        showEmpty: true,
        interfaceTypeFilter: 'ALL',
        returnChannelFilter: 'ALL'
      },
      store,
      localVue
    });

    const hasTitle = wrapper.vm.hasTitle;
    expect(hasTitle).to.be.true;
  });

  it('InterfaceList List hasTitle (has NOT)', () => {
    const wrapper = shallowMount(InterfaceList, {
      propsData: {
        // title: 'Interfaces',
        showEmpty: true,
        interfaceTypeFilter: 'ALL',
        returnChannelFilter: 'ALL'
      },
      store,
      localVue
    });

    const hasTitle = wrapper.vm.hasTitle;
    expect(hasTitle).to.be.false;
  });

  it('InterfaceList List displayEmpty (true)', () => {
    const wrapper = shallowMount(InterfaceList, {
      propsData: {
        title: 'Interfaces',
        showEmpty: true,
        interfaceTypeFilter: 'ALL',
        returnChannelFilter: 'ALL'
      },
      store,
      localVue
    });

    const hasTitle = wrapper.vm.displayEmpty;
    expect(hasTitle).to.be.true;
  });

  it('InterfaceList List displayEmpty (false)', () => {
    const wrapper = shallowMount(InterfaceList, {
      propsData: {
        title: 'Interfaces',
        // showEmpty: true,
        interfaceTypeFilter: 'ALL',
        returnChannelFilter: 'ALL'
      },
      store,
      localVue
    });

    const hasTitle = wrapper.vm.displayEmpty;
    expect(hasTitle).to.be.false;
  });

  it('InterfaceList emiting the list length (all)', () => {
    const wrapper = shallowMount(InterfaceList, {
      propsData: {
        title: 'Interfaces',
        showEmpty: true,
        interfaceTypeFilter: 'ALL',
        returnChannelFilter: 'ALL'
      },
      store,
      localVue
    });

    const relayCount = wrapper.emitted('count');
    expect(relayCount[0][0]).to.eql(26);
  });

  it('InterfaceList emiting the list length (filtered)', () => {
    const wrapper = shallowMount(InterfaceList, {
      propsData: {
        title: 'Interfaces',
        showEmpty: true,
        interfaceTypeFilter: 'CHANNEL',
        returnChannelFilter: 'NO'
      },
      store,
      localVue
    });

    const relayCount = wrapper.emitted('count');
    expect(relayCount[0][0]).to.eql(18);
  });
});
