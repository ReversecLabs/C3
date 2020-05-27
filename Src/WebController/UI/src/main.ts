import Vue from 'vue';
import App from './App.vue';
import store from './store';
import VeeValidate from 'vee-validate';

import './scss/main.scss';

Vue.config.productionTip = false;

(window as any).networkc3 = {};

Vue.use(VeeValidate, {
  inject: false,
  validity: true
});

new Vue({
  store,
  render: h => h(App)
}).$mount('#app');
