/* tslint:disable no-unused-expression */
import { expect } from 'chai';
import { shallowMount, createLocalVue } from '@vue/test-utils';
import Vuex from 'vuex';

import CommandList from '@/components/partial/CommandList.vue';
import { modules } from '../../store/mockstore';

const localVue = createLocalVue();
localVue.use(Vuex);

describe('@/components/partial/CommandList.vue', () => {
  const store = new Vuex.Store({
    modules
  });

  it('CommandList is a Vue instance', () => {
    const wrapper = shallowMount(CommandList, {
      propsData: {
        showEmpty: true,
        statusFilter: 'ALL',
        commandForFilter: 'ALL'
      },
      store,
      localVue
    });
    expect(wrapper.isVueInstance()).to.be.true;
  });

  it('Commands populated', () => {
    const wrapper = shallowMount(CommandList, {
      propsData: {
        showEmpty: true,
        statusFilter: 'ALL',
        commandForFilter: 'ALL'
      },
      store,
      localVue
    });

    const commandsElementsCount = wrapper.vm.commands.length;
    expect(commandsElementsCount).to.eql(18);
  });

  it('Commands populated and filtered correctly (complete/gateway)', () => {
    const wrapper = shallowMount(CommandList, {
      propsData: {
        showEmpty: true,
        statusFilter: 'COMPLETE',
        commandForFilter: 'GATEWAY'
      },
      store,
      localVue
    });

    const commandsElementsCount = wrapper.vm.commands.length;
    expect(commandsElementsCount).to.eql(0);
  });

  it('Commands populated and filtered correctly (pending/connector)', () => {
    const wrapper = shallowMount(CommandList, {
      propsData: {
        showEmpty: true,
        statusFilter: 'PENDING',
        commandForFilter: 'CONNECTOR'
      },
      store,
      localVue
    });

    const commandsElementsCount = wrapper.vm.commands.length;
    expect(commandsElementsCount).to.eql(0);
  });

  it('Commands List displayEmpty (true)', () => {
    const wrapper = shallowMount(CommandList, {
      propsData: {
        showEmpty: true,
        statusFilter: 'ALL',
        commandForFilter: 'ALL'
      },
      store,
      localVue
    });

    const hasTitle = wrapper.vm.displayEmpty;
    expect(hasTitle).to.be.true;
  });

  it('Commands List displayEmpty (false)', () => {
    const wrapper = shallowMount(CommandList, {
      propsData: {
        showEmpty: false,
        statusFilter: 'ALL',
        commandForFilter: 'ALL'
      },
      store,
      localVue
    });

    const hasTitle = wrapper.vm.displayEmpty;
    expect(hasTitle).to.be.false;
  });
});
