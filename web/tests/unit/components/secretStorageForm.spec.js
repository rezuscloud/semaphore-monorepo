/* eslint-disable no-unused-expressions */
import { expect } from 'chai';
import { shallowMount } from '@vue/test-utils';
import SecretStorageForm from '@/components/SecretStorageForm.vue';

async function mountForm() {
  const wrapper = shallowMount(SecretStorageForm, {
    propsData: { itemType: 'secret_storage', itemId: 'new' },
    mocks: { $t: (k) => k },
  });
  // ItemFormBase loads the new item asynchronously in created().
  await new Promise((resolve) => { setTimeout(resolve, 10); });
  return wrapper;
}

describe('SecretStorageForm.vue', () => {
  it('authenticates with a token by default', async () => {
    const wrapper = await mountForm();

    expect(wrapper.vm.isAppRoleAuth).to.be.false;
    expect(wrapper.vm.credentialToggleLabel).to.equal('Token');
    expect(wrapper.vm.credentialFieldLabel).to.equal('Token');
  });

  it('switches the credential to AppRole Secret ID when a Role ID is set', async () => {
    const wrapper = await mountForm();

    wrapper.vm.$set(wrapper.vm.item.params, 'role_id', 'role-123');
    await wrapper.vm.$nextTick();

    expect(wrapper.vm.isAppRoleAuth).to.be.true;
    expect(wrapper.vm.credentialToggleLabel).to.equal('AppRole Secret ID');
    expect(wrapper.vm.credentialFieldLabel).to.equal('Secret ID');

    // Clearing the Role ID falls back to token auth.
    wrapper.vm.$set(wrapper.vm.item.params, 'role_id', '');
    await wrapper.vm.$nextTick();
    expect(wrapper.vm.isAppRoleAuth).to.be.false;
    expect(wrapper.vm.credentialToggleLabel).to.equal('Token');
  });
});
