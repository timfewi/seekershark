import { expect, test as base, type Locator, type Page } from '@playwright/test';

const test = base.extend<{ runtimeErrors: string[] }>({
  runtimeErrors: [async ({ page }, use) => {
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    await use(errors);
    expect(errors, 'Nearby must not throw browser runtime errors').toEqual([]);
  }, { auto: true }],
});

async function navigate(page: Page, label: string) {
  const navigation = page.viewportSize()!.width <= 600 ? '.mobile-nav' : '.desktop-nav';
  await page.locator(navigation).getByRole('button', { name: label, exact: false }).click();
}

async function expectTouchTarget(control: Locator) {
  const box = await control.boundingBox();
  expect(box, 'The control is displayed').not.toBeNull();
  expect(box!.width).toBeGreaterThanOrEqual(44);
  expect(box!.height).toBeGreaterThanOrEqual(44);
}

async function installNearbyFixture(page: Page, options: { running?: boolean; received?: boolean; missingCode?: boolean } = {}) {
  // Controlled UI-only IPC fixture: this verifies no Bluetooth/Wi-Fi radios,
  // native permissions, authentication transport, or actual PCAP transfer.
  await page.addInitScript(({ running = false, received = false, missingCode = false }) => {
    (window as any).isTauri = true;
    const packet = (id: number, source: string, info: string) => ({
      id, timestamp: 1700000000, source, destination: '203.0.113.53', sourcePort: 53000,
      destinationPort: 53, protocol: 'DNS', length: 60, info, layers: [], hex: '',
    });
    const capture = (item: any) => ({ packets: [item], totalPackets: 1, totalBytes: 60, droppedPackets: 0, linkType: 101 });
    const peer = { id: 'peer-fixture', name: 'Other Seeker', state: 'found', authenticationCode: null };
    const incoming = { id: 'incoming-fixture', name: 'shared-fixture.pcap', peerName: 'Other Seeker', bytes: 120, totalBytes: 120, state: 'received', error: null };
    const fixture: any = {
      calls: [], failures: {}, running,
      capture: capture(packet(7, '198.51.100.20', 'LOCAL_CAPTURE_FIXTURE')),
      nearby: { supported: true, active: false, name: '', peers: [], transfers: [], lastError: null },
    };
    (window as any).__nearbyFixture = fixture;
    (window as any).__TAURI_INTERNALS__ = { invoke: async (command: string, args: any) => {
      fixture.calls.push({ command, args });
      if (fixture.failures[command]) {
        const error = fixture.failures[command];
        delete fixture.failures[command];
        throw new Error(error);
      }
      if (command === 'capture_snapshot') return structuredClone(fixture.capture);
      if (command === 'capture_status') return { running: fixture.running, receivedPackets: 1, receivedBytes: 60, droppedPackets: 0, queuedPackets: 0, queuedBytes: 0 };
      if (command === 'capture_stop') { fixture.running = false; return { running: false }; }
      if (command === 'nearby_status') return structuredClone(fixture.nearby);
      if (command === 'nearby_start') {
        fixture.nearby = { ...fixture.nearby, active: true, name: args.name, peers: [structuredClone(peer)], transfers: received ? [structuredClone(incoming)] : [] };
      } else if (command === 'nearby_connect') {
        fixture.nearby.peers[0] = { ...peer, state: 'confirming', authenticationCode: missingCode ? null : '4821' };
      } else if (command === 'nearby_confirm') {
        fixture.nearby.peers[0] = args.accept ? { ...peer, state: 'connected' } : structuredClone(peer);
      } else if (command === 'nearby_disconnect') {
        fixture.nearby.peers[0] = structuredClone(peer);
      } else if (command === 'nearby_share') {
        fixture.nearby.transfers.push({ id: 'outgoing-fixture', name: 'local-fixture.pcap', peerName: peer.name, bytes: 12, totalBytes: 120, state: 'sending', error: null });
      } else if (command === 'nearby_import') {
        fixture.capture = capture(packet(701, '192.0.2.42', 'RECEIVED_CAPTURE_FIXTURE'));
        return { capture: structuredClone(fixture.capture), name: incoming.name, peerName: incoming.peerName };
      } else if (command === 'nearby_discard') {
        fixture.nearby.transfers = fixture.nearby.transfers.filter((transfer: any) => transfer.id !== args.id);
      } else if (command === 'nearby_stop') {
        fixture.nearby = { ...fixture.nearby, active: false, peers: [], transfers: [] };
      } else {
        throw new Error(`Unexpected Nearby UI fixture command: ${command}`);
      }
      return structuredClone(fixture.nearby);
    } };
  }, options);
}

async function startFixture(page: Page) {
  await page.goto('/');
  await expect(page.locator('.packet-row')).toHaveCount(1);
  await navigate(page, 'Nearby');
  const nearby = page.getByRole('region', { name: 'Nearby devices', exact: true });
  await nearby.getByLabel('Your device name').fill('Test Seeker');
  await nearby.getByRole('button', { name: 'Start Nearby', exact: true }).click();
  await expect(nearby.getByRole('button', { name: 'Stop Nearby', exact: true })).toBeVisible();
  await expect(nearby.getByRole('article', { name: 'Device Other Seeker', exact: true })).toBeVisible();
  return nearby;
}

async function calls(page: Page, command: string) {
  return page.evaluate(command => (window as any).__nearbyFixture.calls.filter((call: any) => call.command === command), command);
}

async function failNext(page: Page, command: string, message: string) {
  await page.evaluate(({ command, message }) => { (window as any).__nearbyFixture.failures[command] = message; }, { command, message });
}

test('native capability failure explains why Nearby cannot start', async ({ page }) => {
  await installNearbyFixture(page);
  await page.goto('/');
  await page.evaluate(() => { (window as any).__nearbyFixture.nearby.supported = false; });
  await navigate(page, 'Nearby');
  const nearby = page.getByRole('region', { name: 'Nearby devices', exact: true });
  await expect(nearby).toContainText('Install or update Google Play services');
  await expect(nearby.getByRole('button', { name: 'Start Nearby', exact: true })).toBeDisabled();
  expect(await calls(page, 'nearby_start')).toHaveLength(0);
});

test('browser Nearby explains limitations and preserves names and packet navigation at 320px', async ({ page }) => {
  await page.goto('/');
  const filter = page.getByRole('textbox', { name: 'Filter packets' });
  await filter.fill('proto:DNS');
  await navigate(page, 'Nearby');
  const nearby = page.getByRole('region', { name: 'Nearby devices', exact: true });
  const name = nearby.getByLabel('Your device name');
  await name.fill('Pocket Seeker');
  await expect(nearby).toContainText('Device discovery is unavailable in this browser');
  await nearby.getByRole('button', { name: 'Start Nearby', exact: true }).click();
  await expect(nearby.getByRole('alert')).toContainText('The browser does not search for devices');
  await expect(nearby.getByRole('article')).toHaveCount(0);
  await navigate(page, 'Session');
  await page.getByRole('button', { name: 'Back to previous view' }).click();
  await expect(name).toHaveValue('Pocket Seeker');
  await page.getByRole('button', { name: 'Back to previous view' }).click();
  await expect(filter).toHaveValue('proto:DNS');
  await expect(page.locator('.packet-row')).toHaveCount(8);
  await navigate(page, 'Nearby');
  await page.setViewportSize({ width: 320, height: 780 });
  await expectTouchTarget(name);
  await expectTouchTarget(nearby.getByRole('button', { name: 'Start Nearby', exact: true }));
  for (const control of await page.locator('.mobile-nav button').all()) await expectTouchTarget(control);
  await nearby.getByText('Same Wi-Fi & limits', { exact: true }).click();
  await expect(nearby).toContainText('not every nearby phone');
  await expect(nearby).toContainText('HTTPS stays encrypted');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.reload();
  await navigate(page, 'Nearby');
  await expect(nearby.getByLabel('Your device name')).toHaveValue('Pocket Seeker');
});

test('UI fixture requires code confirmation, supports rejection, and shares only on an explicit tap', async ({ page }) => {
  await installNearbyFixture(page);
  const nearby = await startFixture(page);
  const peer = nearby.getByRole('article', { name: 'Device Other Seeker', exact: true });
  await expect(nearby.getByLabel('Your device name')).toBeDisabled();
  expect(await calls(page, 'nearby_start')).toEqual([{ command: 'nearby_start', args: { name: 'Test Seeker' } }]);
  await peer.getByRole('button', { name: 'Connect to Other Seeker' }).click();
  await expect(peer.getByLabel('Connection code')).toHaveText('4821');
  expect(await calls(page, 'nearby_confirm')).toHaveLength(0);
  expect(await calls(page, 'nearby_share')).toHaveLength(0);
  await page.setViewportSize({ width: 320, height: 780 });
  await expectTouchTarget(peer.getByRole('button', { name: 'Confirm code', exact: true }));
  await expectTouchTarget(peer.getByRole('button', { name: 'Reject', exact: true }));
  await expectTouchTarget(nearby.getByRole('button', { name: 'Stop Nearby', exact: true }));
  await peer.getByRole('button', { name: 'Reject', exact: true }).click();
  await expect(peer.getByRole('button', { name: 'Connect to Other Seeker' })).toBeVisible();
  expect(await calls(page, 'nearby_confirm')).toEqual([{ command: 'nearby_confirm', args: { endpointId: 'peer-fixture', accept: false } }]);
  await peer.getByRole('button', { name: 'Connect to Other Seeker' }).click();
  await peer.getByRole('button', { name: 'Confirm code', exact: true }).click();
  await expect(peer).toContainText('Connected');
  expect(await calls(page, 'nearby_confirm')).toEqual([
    { command: 'nearby_confirm', args: { endpointId: 'peer-fixture', accept: false } },
    { command: 'nearby_confirm', args: { endpointId: 'peer-fixture', accept: true } },
  ]);
  expect(await calls(page, 'nearby_share')).toHaveLength(0);
  const share = peer.getByRole('button', { name: 'Share current capture', exact: true });
  await expectTouchTarget(share);
  await expectTouchTarget(peer.getByRole('button', { name: 'Disconnect from Other Seeker' }));
  await share.click();
  expect(await calls(page, 'nearby_share')).toEqual([{ command: 'nearby_share', args: { endpointId: 'peer-fixture' } }]);
  await expect(nearby.getByRole('progressbar', { name: 'Transfer progress for local-fixture.pcap' })).toHaveAttribute('value', '12');
  await expect(nearby.getByRole('status').filter({ hasText: 'Capture transfer started' })).toBeVisible();
  await peer.getByRole('button', { name: 'Disconnect from Other Seeker' }).click();
  await expect(peer.getByRole('button', { name: 'Connect to Other Seeker' })).toBeVisible();
  await nearby.getByRole('button', { name: 'Stop Nearby', exact: true }).click();
  await expect(nearby.getByRole('article')).toHaveCount(0);
  await expect(nearby.getByLabel('Your device name')).toBeEnabled();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test('UI fixture cannot confirm a connection without an authentication code', async ({ page }) => {
  await installNearbyFixture(page, { missingCode: true });
  const nearby = await startFixture(page);
  await nearby.getByRole('button', { name: 'Connect to Other Seeker' }).click();
  await expect(nearby.getByLabel('Connection code')).toHaveText('Unavailable');
  await expect(nearby.getByRole('button', { name: 'Confirm code', exact: true })).toBeDisabled();
  expect(await calls(page, 'nearby_confirm')).toHaveLength(0);
  await nearby.getByRole('button', { name: 'Reject', exact: true }).click();
  await expect(nearby.getByRole('button', { name: 'Connect to Other Seeker' })).toBeVisible();
});

test('UI fixture keeps received PCAPs unopened until local capture stops and the user opens one', async ({ page }) => {
  await installNearbyFixture(page, { running: true, received: true });
  const nearby = await startFixture(page);
  const transfer = nearby.getByRole('article', { name: 'Transfer shared-fixture.pcap', exact: true });
  const open = transfer.getByRole('button', { name: 'Open capture', exact: true });
  await expect(open).toBeDisabled();
  await expect(transfer).toContainText('Stop local capture before opening');
  expect(await calls(page, 'nearby_import')).toHaveLength(0);
  await page.setViewportSize({ width: 320, height: 780 });
  await expectTouchTarget(open);
  await expectTouchTarget(transfer.getByRole('button', { name: 'Discard', exact: true }));
  await page.getByRole('button', { name: 'Stop capture', exact: true }).click();
  await expect(open).toBeEnabled();
  expect(await calls(page, 'nearby_import')).toHaveLength(0);
  await open.click();
  await expect(page.locator('.packet-row')).toHaveCount(1);
  await expect(page.locator('.packet-row')).toContainText('RECEIVED_CAPTURE_FIXTURE');
  await expect(page.locator('.packet-row')).not.toContainText('LOCAL_CAPTURE_FIXTURE');
  expect(await calls(page, 'nearby_import')).toEqual([{ command: 'nearby_import', args: { id: 'incoming-fixture' } }]);
  await expect(page.getByLabel('Capture: PCAP')).toBeVisible();
  await navigate(page, 'Nearby');
  await transfer.getByRole('button', { name: 'Discard', exact: true }).click();
  await expect(transfer).toHaveCount(0);
  expect(await calls(page, 'nearby_discard')).toEqual([{ command: 'nearby_discard', args: { id: 'incoming-fixture' } }]);
});

test('UI fixture preserves pairing, transfers, and the displayed capture when native commands fail', async ({ page }) => {
  await installNearbyFixture(page, { received: true });
  const nearby = await startFixture(page);
  const peer = nearby.getByRole('article', { name: 'Device Other Seeker', exact: true });
  await failNext(page, 'nearby_connect', 'Connection fixture failure');
  await peer.getByRole('button', { name: 'Connect to Other Seeker' }).click();
  await expect(nearby.getByRole('alert')).toContainText('Connection fixture failure');
  await expect(peer.getByRole('button', { name: 'Connect to Other Seeker' })).toBeEnabled();
  await peer.getByRole('button', { name: 'Connect to Other Seeker' }).click();
  await failNext(page, 'nearby_confirm', 'Confirmation fixture failure');
  await peer.getByRole('button', { name: 'Confirm code', exact: true }).click();
  await expect(nearby.getByRole('alert')).toContainText('Confirmation fixture failure');
  await expect(peer.getByLabel('Connection code')).toHaveText('4821');
  await expect(peer.getByRole('button', { name: 'Confirm code', exact: true })).toBeEnabled();
  await peer.getByRole('button', { name: 'Confirm code', exact: true }).click();
  await failNext(page, 'nearby_share', 'Share fixture failure');
  await peer.getByRole('button', { name: 'Share current capture', exact: true }).click();
  await expect(nearby.getByRole('alert')).toContainText('Share fixture failure');
  await expect(peer.getByRole('button', { name: 'Share current capture', exact: true })).toBeEnabled();
  await expect(nearby.getByRole('progressbar')).toHaveCount(0);
  const transfer = nearby.getByRole('article', { name: 'Transfer shared-fixture.pcap', exact: true });
  await failNext(page, 'nearby_import', 'Import fixture failure');
  await transfer.getByRole('button', { name: 'Open capture', exact: true }).click();
  await expect(nearby.getByRole('alert')).toContainText('Import fixture failure');
  await expect(transfer.getByRole('button', { name: 'Open capture', exact: true })).toBeEnabled();
  await page.getByRole('button', { name: 'Back to previous view' }).click();
  await expect(page.locator('.packet-row')).toContainText('LOCAL_CAPTURE_FIXTURE');
  await navigate(page, 'Nearby');
  await expect(transfer).toContainText('Ready to open');
  await failNext(page, 'nearby_stop', 'Stop fixture failure');
  await nearby.getByRole('button', { name: 'Stop Nearby', exact: true }).click();
  await expect(nearby.getByRole('alert')).toContainText('Stop fixture failure');
  await expect(nearby.getByRole('button', { name: 'Stop Nearby', exact: true })).toBeEnabled();
  await expect(peer).toContainText('Connected');
  await expect(transfer).toBeVisible();
});
