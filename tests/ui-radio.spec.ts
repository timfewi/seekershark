import { expect, test as base, type Locator, type Page } from '@playwright/test';

const test = base.extend<{ runtimeErrors: string[] }>({
  runtimeErrors: [async ({ page }, use) => {
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    await use(errors);
    expect(errors, 'Radio views must not throw browser runtime errors').toEqual([]);
  }, { auto: true }],
});

const sensorReport = {
  schemaVersion: 1,
  source: 'external-wifi-sensor',
  sensor: { id: 'sensor-fixture', label: 'Linux sensor fixture', adapter: 'wlan1', driver: 'ath9k_htc', bands: ['2.4GHz'], channels: [6] },
  startedAt: 1700000000000,
  endedAt: 1700000001000,
  observations: [{ transmitter: '02:11:22:33:44:55', firstSeen: 1700000000000, lastSeen: 1700000001000, frames: 3, rssiDbm: -55, channel: 6, frequencyMhz: 2437, frameTypes: ['probe-request'] }],
};

async function navigate(page: Page, label: string) {
  const navigation = page.viewportSize()!.width <= 600 ? '.mobile-nav' : '.desktop-nav';
  await page.locator(navigation).getByRole('button', { name: label, exact: false }).click();
}

async function expectTouchTarget(control: Locator) {
  const box = await control.boundingBox();
  expect(box, 'The control must be displayed').not.toBeNull();
  expect(box!.width).toBeGreaterThanOrEqual(44);
  expect(box!.height).toBeGreaterThanOrEqual(44);
}

async function installRadioFixture(page: Page) {
  // UI-only IPC fixture. No Bluetooth/Wi-Fi radio, Android permission, monitor
  // mode, physical device identification, or real sensor transport is verified.
  await page.addInitScript(() => {
    (window as any).isTauri = true;
    const observation = {
      id: 'ble-fixture-1', address: 'C2:11:22:33:44:55', name: 'Environmental tag fixture',
      rssi: -61, txPower: -12, connectable: false, legacy: true, primaryPhy: 1, secondaryPhy: 0,
      advertisingSid: null, manufacturerIds: [76], serviceUuids: ['0000180f-0000-1000-8000-00805f9b34fb'],
      advertisementHex: '02010603030f1805ff4c000102', payloadTruncated: false,
      firstSeen: 1700000000000, lastSeen: 1700000001000, advertisements: 7,
    };
    const emptyBle = () => ({ supported: true, active: false, startedAt: null, elapsedMs: 0, durationSeconds: 60, advertisements: 0, droppedObservations: 0, maxObservations: 256, observations: [], lastError: null });
    const emptyWifi = () => ({ schemaVersion: 1, transport: 'report-import', liveSupported: false, report: null, lastError: null });
    const fixture: any = { calls: [], failures: {}, ble: emptyBle(), wifi: emptyWifi() };
    (window as any).__radioFixture = fixture;
    (window as any).__TAURI_INTERNALS__ = { invoke: async (command: string, args: any) => {
      fixture.calls.push({ command, args: args instanceof Uint8Array ? Array.from(args) : args });
      if (fixture.failures[command]) {
        const message = fixture.failures[command];
        delete fixture.failures[command];
        throw new Error(message);
      }
      if (command === 'capture_snapshot') return {
        packets: [{ id: 7, timestamp: 1700000000, source: '198.51.100.20', destination: '203.0.113.53', sourcePort: 53000, destinationPort: 53, protocol: 'DNS', length: 60, info: 'LOCAL_CAPTURE_RADIO_FIXTURE', layers: [], hex: '' }],
        totalPackets: 1, totalBytes: 60, droppedPackets: 0, linkType: 101,
      };
      if (command === 'capture_status') return { running: false, receivedPackets: 1, receivedBytes: 60, droppedPackets: 0, queuedPackets: 0, queuedBytes: 0 };
      if (command === 'ble_status') {
        if (fixture.ble.active) fixture.ble.elapsedMs += 1000;
        return structuredClone(fixture.ble);
      }
      if (command === 'ble_start') {
        fixture.ble = { ...emptyBle(), active: true, startedAt: 1700000000000, elapsedMs: 1000, durationSeconds: args.durationSeconds, advertisements: 7, observations: [structuredClone(observation)] };
        return structuredClone(fixture.ble);
      }
      if (command === 'ble_stop') { fixture.ble.active = false; return structuredClone(fixture.ble); }
      if (command === 'ble_clear') { fixture.ble = emptyBle(); return structuredClone(fixture.ble); }
      if (command === 'ble_export') return 'content://downloads/seekershark-ble-fixture.json';
      if (command === 'wifi_sensor_status') return structuredClone(fixture.wifi);
      if (command === 'wifi_sensor_import') {
        // Native validation has dedicated Rust tests; this fixture only returns
        // a controlled successful response or a deliberate command rejection.
        fixture.wifi = { ...emptyWifi(), report: JSON.parse(new TextDecoder().decode(new Uint8Array(args))) };
        return structuredClone(fixture.wifi);
      }
      if (command === 'wifi_sensor_clear') { fixture.wifi = emptyWifi(); return structuredClone(fixture.wifi); }
      if (command === 'wifi_sensor_export') return 'content://downloads/seekershark-wifi-fixture.json';
      throw new Error(`Unexpected Radio UI fixture command: ${command}`);
    } };
  });
}

async function calls(page: Page, command: string) {
  return page.evaluate(command => (window as any).__radioFixture.calls.filter((call: any) => call.command === command), command);
}

async function failNext(page: Page, command: string, message: string) {
  await page.evaluate(({ command, message }) => { (window as any).__radioFixture.failures[command] = message; }, { command, message });
}

function radioPanel(page: Page) {
  return page.getByRole('region', { name: 'Radio observations', exact: true });
}

async function openRadio(page: Page) {
  await page.goto('/');
  await expect(page.locator('.packet-row')).toHaveCount(1);
  expect(await calls(page, 'ble_start')).toHaveLength(0);
  expect(await calls(page, 'ble_status')).toHaveLength(0);
  await navigate(page, 'Radio');
  return radioPanel(page);
}

test('browser radio tools explain hardware limits and preserve filters and subview state at 320px', async ({ page }) => {
  await page.goto('/');
  const filter = page.getByRole('textbox', { name: 'Filter packets' });
  await filter.fill('proto:DNS');
  await navigate(page, 'Radio');
  const radio = radioPanel(page);
  const duration = radio.getByLabel('Scan duration (seconds)', { exact: true });
  const bluetoothTab = radio.getByRole('tab', { name: 'Bluetooth', exact: true });
  await bluetoothTab.focus();
  await bluetoothTab.press('ArrowRight');
  await expect(radio.getByRole('tab', { name: 'Wi-Fi sensor', exact: true })).toBeFocused();
  await radio.getByRole('tab', { name: 'Wi-Fi sensor', exact: true }).press('Home');
  await expect(bluetoothTab).toBeFocused();
  await expect(bluetoothTab).toHaveAttribute('aria-selected', 'true');
  await duration.fill('30');
  await expect(radio).toContainText('Android');
  await radio.getByRole('button', { name: 'Start BLE scan', exact: true }).click();
  await expect(radio.getByRole('alert')).toContainText('Android');
  await expect(radio.getByRole('article')).toHaveCount(0);
  await radio.getByRole('tab', { name: 'Wi-Fi sensor', exact: true }).click();
  await expect(radio.getByRole('button', { name: 'Connect sensor', exact: true })).toBeDisabled();
  await expect(radio).toContainText('report');
  await navigate(page, 'Session');
  await page.getByRole('button', { name: 'Back to previous view' }).click();
  await expect(radio.getByRole('tab', { name: 'Wi-Fi sensor', exact: true })).toHaveAttribute('aria-selected', 'true');
  await radio.getByRole('tab', { name: 'Bluetooth', exact: true }).click();
  await expect(duration).toHaveValue('30');
  await page.getByRole('button', { name: 'Back to previous view' }).click();
  await expect(filter).toHaveValue('proto:DNS');
  await expect(page.locator('.packet-row')).toHaveCount(8);
  await navigate(page, 'Radio');
  await page.setViewportSize({ width: 320, height: 780 });
  await expect(page.locator('.mobile-nav button')).toHaveCount(6);
  for (const control of await page.locator('.mobile-nav button').all()) await expectTouchTarget(control);
  for (const control of [duration, radio.getByRole('tab', { name: 'Bluetooth', exact: true }), radio.getByRole('tab', { name: 'Wi-Fi sensor', exact: true }), radio.getByRole('button', { name: 'Start BLE scan', exact: true })]) await expectTouchTarget(control);
  await radio.getByRole('tab', { name: 'Wi-Fi sensor', exact: true }).click();
  await expectTouchTarget(radio.getByRole('button', { name: 'Connect sensor', exact: true }));
  await expectTouchTarget(radio.getByRole('button', { name: 'Import sensor report', exact: true }));
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test('UI-only BLE fixture starts a bounded scan, retains observed evidence after stop, exports and clears', async ({ page }) => {
  await installRadioFixture(page);
  const radio = await openRadio(page);
  const duration = radio.getByLabel('Scan duration (seconds)', { exact: true });
  await expect(duration).toHaveAttribute('min', '10');
  await expect(duration).toHaveAttribute('max', '120');
  await duration.fill('30');
  await radio.getByRole('button', { name: 'Start BLE scan', exact: true }).click();
  expect(await calls(page, 'ble_start')).toEqual([{ command: 'ble_start', args: { durationSeconds: 30 } }]);
  await expect(duration).toBeDisabled();
  await expect(radio.getByText('Environmental tag fixture', { exact: true })).toBeVisible();
  await expect(radio).toContainText('C2:11:22:33:44:55');
  await expect(radio).toContainText('-61');
  const observation = radio.getByLabel('BLE observation C2:11:22:33:44:55', { exact: true });
  await observation.locator('summary').click();
  await expect(observation).toContainText('device type unknown');
  await expect(observation).toContainText('0000180f-0000-1000-8000-00805f9b34fb');
  await expect(observation.locator('pre')).toHaveText('02010603030f1805ff4c000102');
  await expect.poll(async () => (await calls(page, 'ble_status')).length).toBeGreaterThan(1);
  await expect(observation).toHaveAttribute('open', '');
  await expect(radio.getByRole('button', { name: 'Clear observations', exact: true })).toBeDisabled();
  await page.setViewportSize({ width: 320, height: 780 });
  await expectTouchTarget(radio.getByRole('button', { name: 'Stop BLE scan', exact: true }));
  await radio.getByRole('button', { name: 'Stop BLE scan', exact: true }).click();
  await expect(duration).toBeEnabled();
  await expect(radio.getByText('Environmental tag fixture', { exact: true })).toBeVisible();
  expect(await calls(page, 'ble_stop')).toHaveLength(1);
  await expectTouchTarget(radio.getByRole('button', { name: 'Export JSON', exact: true }));
  await expectTouchTarget(radio.getByRole('button', { name: 'Clear observations', exact: true }));
  await radio.getByRole('button', { name: 'Export JSON', exact: true }).click();
  await expect(radio.getByRole('status').filter({ hasText: 'content://downloads/seekershark-ble-fixture.json' })).toBeVisible();
  expect(await calls(page, 'ble_export')).toHaveLength(1);
  await radio.getByRole('button', { name: 'Clear observations', exact: true }).click();
  await expect(radio.getByText('Environmental tag fixture', { exact: true })).toHaveCount(0);
  await expect(radio.getByRole('button', { name: 'Export JSON', exact: true })).toBeDisabled();
  expect(await calls(page, 'ble_clear')).toHaveLength(1);
  await page.getByRole('button', { name: 'Back to previous view' }).click();
  await expect(page.locator('.packet-row')).toContainText('LOCAL_CAPTURE_RADIO_FIXTURE');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test('UI-only BLE fixture keeps prior observations and usable controls when commands fail', async ({ page }) => {
  await installRadioFixture(page);
  const radio = await openRadio(page);
  await radio.getByRole('button', { name: 'Start BLE scan', exact: true }).click();
  await failNext(page, 'ble_stop', 'Stop fixture failure');
  await radio.getByRole('button', { name: 'Stop BLE scan', exact: true }).click();
  await expect(radio.getByRole('alert')).toContainText('Stop fixture failure');
  await expect(radio.getByRole('button', { name: 'Stop BLE scan', exact: true })).toBeEnabled();
  await expect(radio.getByText('Environmental tag fixture', { exact: true })).toBeVisible();
  await radio.getByRole('button', { name: 'Stop BLE scan', exact: true }).click();
  await failNext(page, 'ble_start', 'Bluetooth permission fixture failure');
  await radio.getByRole('button', { name: 'Start BLE scan', exact: true }).click();
  await expect(radio.getByRole('alert')).toContainText('Bluetooth permission fixture failure');
  await expect(radio.getByText('Environmental tag fixture', { exact: true })).toBeVisible();
  await expect(radio.getByRole('button', { name: 'Start BLE scan', exact: true })).toBeEnabled();
  await failNext(page, 'ble_clear', 'Clear fixture failure');
  await radio.getByRole('button', { name: 'Clear observations', exact: true }).click();
  await expect(radio.getByRole('alert')).toContainText('Clear fixture failure');
  await expect(radio.getByText('Environmental tag fixture', { exact: true })).toBeVisible();
  await failNext(page, 'ble_export', 'Export fixture failure');
  await radio.getByRole('button', { name: 'Export JSON', exact: true }).click();
  await expect(radio.getByRole('alert')).toContainText('Export fixture failure');
  await expect(radio.getByRole('button', { name: 'Export JSON', exact: true })).toBeEnabled();
});

test('UI-only Wi-Fi sensor fixture imports versioned reports and preserves them after a rejected import', async ({ page }) => {
  await installRadioFixture(page);
  const radio = await openRadio(page);
  await radio.getByRole('tab', { name: 'Wi-Fi sensor', exact: true }).click();
  await expect(radio.getByRole('button', { name: 'Connect sensor', exact: true })).toBeDisabled();
  expect(await calls(page, 'wifi_sensor_import')).toHaveLength(0);
  const file = radio.locator('input[type=file]');
  const json = JSON.stringify(sensorReport);
  await file.setInputFiles({ name: 'sensor-v1.json', mimeType: 'application/json', buffer: Buffer.from(json) });
  await expect(radio.getByText('Linux sensor fixture', { exact: true })).toBeVisible();
  await expect(radio).toContainText('02:11:22:33:44:55');
  await expect(radio).toContainText('-55');
  await expect(radio).toContainText('probe-request');
  expect(await calls(page, 'wifi_sensor_import')).toEqual([{ command: 'wifi_sensor_import', args: Array.from(Buffer.from(json)) }]);
  await page.setViewportSize({ width: 320, height: 780 });
  await expectTouchTarget(radio.getByRole('button', { name: 'Import sensor report', exact: true }));
  await radio.getByRole('button', { name: 'Export JSON', exact: true }).click();
  await expect(radio.getByRole('status').filter({ hasText: 'content://downloads/seekershark-wifi-fixture.json' })).toBeVisible();
  expect(await calls(page, 'wifi_sensor_export')).toHaveLength(1);
  await failNext(page, 'wifi_sensor_import', 'Unsupported sensor schemaVersion fixture');
  await file.setInputFiles({ name: 'sensor-v2.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify({ ...sensorReport, schemaVersion: 2 })) });
  await expect(radio.getByRole('alert')).toContainText('Unsupported sensor schemaVersion fixture');
  await expect(radio.getByText('Linux sensor fixture', { exact: true })).toBeVisible();
  await expect(radio).toContainText('02:11:22:33:44:55');
  await failNext(page, 'wifi_sensor_import', 'Invalid JSON fixture');
  await file.setInputFiles({ name: 'malformed.json', mimeType: 'application/json', buffer: Buffer.from('{ invalid') });
  await expect(radio.getByRole('alert')).toContainText('Invalid JSON fixture');
  await expect(radio.getByText('Linux sensor fixture', { exact: true })).toBeVisible();
  await radio.getByRole('button', { name: 'Clear report', exact: true }).click();
  await expect(radio.getByText('Linux sensor fixture', { exact: true })).toHaveCount(0);
  await expect(radio.getByRole('button', { name: 'Export JSON', exact: true })).toBeDisabled();
  expect(await calls(page, 'wifi_sensor_clear')).toHaveLength(1);
  await file.setInputFiles({ name: 'empty-sensor.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify({ ...sensorReport, observations: [] })) });
  await expect(radio.getByText('Linux sensor fixture', { exact: true })).toBeVisible();
  await expect(radio).toContainText('The sensor report contains no transmitter observations.');
  await expect(radio).not.toContainText('No sensor report loaded.');
  await page.getByRole('button', { name: 'Back to previous view' }).click();
  await expect(page.locator('.packet-row')).toContainText('LOCAL_CAPTURE_RADIO_FIXTURE');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});
