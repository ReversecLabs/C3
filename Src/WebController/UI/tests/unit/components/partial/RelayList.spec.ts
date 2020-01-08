/* tslint:disable no-unused-expression */
import { expect } from 'chai';
import { shallowMount, createLocalVue } from '@vue/test-utils';
import Vuex from 'vuex';

import RelayList from '@/components/partial/RelayList.vue';
import { modules } from '../../store/mockstore';

const localVue = createLocalVue();
localVue.use(Vuex);

describe('@/components/partial/RelayList.vue', () => {
  const store = new Vuex.Store({
    modules
  });

  it('RelayList is a Vue instance', () => {
    const wrapper = shallowMount(RelayList, {
      store,
      localVue
    });
    expect(wrapper.isVueInstance()).to.be.true;
  });

  it('RelayList populated correctly (populated)', () => {
    const wrapper = shallowMount(RelayList, {
      propsData: {
        title: 'Relays',
        showEmpty: true
      },
      store,
      localVue
    });

    const connectorsElementsCount = wrapper.vm.relays.length;
    expect(connectorsElementsCount).to.eql(8);
  });

  it('RelayList List hasTitle (has)', () => {
    const wrapper = shallowMount(RelayList, {
      propsData: {
        title: 'Relays',
        showEmpty: true
      },
      store,
      localVue
    });

    const hasTitle = wrapper.vm.hasTitle;
    expect(hasTitle).to.be.true;
  });

  it('RelayList List hasTitle (has NOT)', () => {
    const wrapper = shallowMount(RelayList, {
      propsData: {
        title: '',
        showEmpty: true
      },
      store,
      localVue
    });

    const hasTitle = wrapper.vm.hasTitle;
    expect(hasTitle).to.be.false;
  });

  it('RelayList List displayEmpty (true)', () => {
    const wrapper = shallowMount(RelayList, {
      propsData: {
        title: 'Relays',
        showEmpty: true
      },
      store,
      localVue
    });

    const hasTitle = wrapper.vm.displayEmpty;
    expect(hasTitle).to.be.true;
  });

  it('RelayList List displayEmpty (false)', () => {
    const wrapper = shallowMount(RelayList, {
      propsData: {
        title: 'Relays',
        showEmpty: false
      },
      store,
      localVue
    });

    const hasTitle = wrapper.vm.displayEmpty;
    expect(hasTitle).to.be.false;
  });

  it('RelayList Emiting the list length', () => {
    const wrapper = shallowMount(RelayList, {
      propsData: {
        title: 'Relays',
        showEmpty: false
      },
      store,
      localVue
    });

    const relayCount = wrapper.emitted('count');
    expect(relayCount[0][0]).to.eql(8);
  });
});
