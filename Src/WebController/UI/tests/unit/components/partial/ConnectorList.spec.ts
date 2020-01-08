/* tslint:disable no-unused-expression */
import { expect } from 'chai';
import { shallowMount, createLocalVue } from '@vue/test-utils';
import Vuex from 'vuex';

import ConnectorList from '@/components/partial/ConnectorList.vue';
import { modules } from '../../store/mockstore';

const localVue = createLocalVue();
localVue.use(Vuex);

describe('@/components/partial/ConnectorList.vue', () => {
  const store = new Vuex.Store({
    modules
  });

  it('ConnectorList is a Vue instance', () => {
    const wrapper = shallowMount(ConnectorList, {
      propsData: {
        title: 'Connectors',
        showEmpty: true
      },
      store,
      localVue
    });
    expect(wrapper.isVueInstance()).to.be.true;
  });

  it('ConnectorList populated correctly', () => {
    const wrapper = shallowMount(ConnectorList, {
      propsData: {
        title: 'Connectors',
        showEmpty: true
      },
      store,
      localVue
    });

    const connectorsElementsCount = wrapper.vm.connectors.length;
    expect(connectorsElementsCount).to.eql(0);
  });

  it('ConnectorList List hasTitle (has)', () => {
    const wrapper = shallowMount(ConnectorList, {
      propsData: {
        title: 'Connectors',
        showEmpty: true
      },
      store,
      localVue
    });

    const hasTitle = wrapper.vm.hasTitle;
    expect(hasTitle).to.be.true;
  });

  it('ConnectorList List hasTitle (has NOT)', () => {
    const wrapper = shallowMount(ConnectorList, {
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

  it('ConnectorList List displayEmpty (true)', () => {
    const wrapper = shallowMount(ConnectorList, {
      propsData: {
        title: 'Connectors',
        showEmpty: true
      },
      store,
      localVue
    });

    const hasTitle = wrapper.vm.displayEmpty;
    expect(hasTitle).to.be.true;
  });

  it('ConnectorList List displayEmpty (false)', () => {
    const wrapper = shallowMount(ConnectorList, {
      propsData: {
        title: 'Connectors',
        showEmpty: null
      },
      store,
      localVue
    });

    const hasTitle = wrapper.vm.displayEmpty;
    expect(hasTitle).to.be.false;
  });
});
