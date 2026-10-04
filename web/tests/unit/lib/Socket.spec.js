/* eslint-disable symbol-description */
/* eslint-disable no-unused-expressions */
import { expect } from 'chai';
import Socket from '@/lib/Socket';

describe('Socket', () => {
  it('falls back to a fake socket when no session is active', () => {
    const socket = new Socket(() => ({ close: () => {} }));
    socket.start();
    expect(socket.ws).to.be.ok;
    expect(socket.isRunning()).to.be.true;
  });

  it('creates the real socket when the session is active', () => {
    let created = 0;
    const socket = new Socket(() => {
      created += 1;
      return { close: () => {} };
    });
    socket.setSessionActive(true);
    socket.start();
    expect(created).to.equal(1);
    expect(socket.ws).to.be.ok;
  });
});
