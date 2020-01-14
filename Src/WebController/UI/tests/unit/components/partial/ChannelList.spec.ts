/* tslint:disable no-unused-expression */
import { expect } from 'chai';
import { shallowMount, createLocalVue } from '@vue/test-utils';
import Vuex from 'vuex';

import ChannelList from '@/components/partial/ChannelList.vue';
import { modules } from '../../store/mockstore';

const localVue = createLocalVue();
localVue.use(Vuex);

describe('@/components/partial/ChannelList.vue', () => {
  const store = new Vuex.Store({
    modules
  });

  it('ChannelList is a Vue instance', () => {
    const wrapper = shallowMount(ChannelList, {
      propsData: {
        title: 'Channel List test',
        showEmpty: true,
        targetId: 'a1d1'
      },
      store,
      localVue
    });
    expect(wrapper.isVueInstance()).to.be.true;
  });

  it('Channels populated correctly (populated)', () => {
    const wrapper = shallowMount(ChannelList, {
      propsData: {
        title: 'Channel List test',
        showEmpty: true,
        targetId: '95896bc3757517b0'
      },
      store,
      localVue
    });

    const channelsElementsCount = wrapper.vm.channels.length;
    expect(channelsElementsCount).to.eql(5);
  });

  it('Channels populated correctly (empty)', () => {
    const wrapper = shallowMount(ChannelList, {
      propsData: {
        title: 'Channel List test',
        showEmpty: true,
        targetId: 'a1d4'
      },
      store,
      localVue
    });
    const channelsElementsCount = wrapper.vm.channels.length;
    expect(channelsElementsCount).to.eql(0);
  });

  it('Channel List hasTitle (has)', () => {
    const wrapper = shallowMount(ChannelList, {
      propsData: {
        title: 'Channel List test',
        showEmpty: true,
        targetId: 'a1d4'
      },
      store,
      localVue
    });

    const hasTitle = wrapper.vm.hasTitle;
    expect(hasTitle).to.be.true;
  });

  it('Channel List hasTitle (has NOT)', () => {
    const wrapper = shallowMount(ChannelList, {
      propsData: {
        // title: '',
        showEmpty: true,
        targetId: 'a1d4'
      },
      store,
      localVue
    });

    const hasTitle = wrapper.vm.hasTitle;
    expect(hasTitle).to.be.false;
  });

  it('Channel List displayEmpty (true)', () => {
    const wrapper = shallowMount(ChannelList, {
      propsData: {
        title: 'Channel List test',
        showEmpty: true,
        targetId: 'a1d4'
      },
      store,
      localVue
    });

    const hasTitle = wrapper.vm.displayEmpty;
    expect(hasTitle).to.be.true;
  });

  it('Channel List displayEmpty (false)', () => {
    const wrapper = shallowMount(ChannelList, {
      propsData: {
        // title: '',
        showEmpty: false,
        targetId: 'a1d4'
      },
      store,
      localVue
    });

    const hasTitle = wrapper.vm.displayEmpty;
    expect(hasTitle).to.be.false;
  });
});
