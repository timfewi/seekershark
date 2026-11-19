import { expect, test, type Page } from '@playwright/test';

async function openScan(page: Page) {
  const nav = page.viewportSize()!.width <= 600 ? '.mobile-nav' : '.desktop-nav';
  await page.locator(nav).getByRole('button', { name: 'Scan', exact: false }).click();
}

test('scanner presets, mobile targets and back navigation work without fabricating browser scans', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto('/');
  await page.getByRole('textbox', { name: 'Filter packets' }).fill('proto:DNS');
  await openScan(page);
  const scanner = page.getByRole('region', { name: 'Network scanner' });
  await scanner.getByLabel('Target', { exact: true }).fill('192.0.2.10');
  await scanner.getByRole('button', { name: 'All ports', exact: true }).click();
  await expect(scanner.getByLabel('TCP ports')).toHaveValue('1-65535');
  await scanner.getByRole('button', { name: 'Service probes' }).click();
  await scanner.getByText('Timing', { exact: false }).first().click();
  await expect(scanner.getByLabel('Probe timeout (ms)')).toBeVisible();
  await scanner.getByLabel('Concurrency', { exact: true }).fill('64');
  await scanner.getByRole('button', { name: 'Scan', exact: true }).click();
  await expect(scanner.getByRole('alert')).toContainText('requires the Android app');
  await expect(scanner.locator('.scan-result')).toHaveCount(0);
  await expect(scanner.getByRole('button', { name: 'Export JSON' })).toBeDisabled();
  await page.getByRole('button', { name: 'Back to previous view' }).click();
  await expect(page.getByRole('textbox', { name: 'Filter packets' })).toHaveValue('proto:DNS');
  await openScan(page);
  await expect(scanner.getByLabel('Target', { exact: true })).toHaveValue('192.0.2.10');
  await expect(scanner.getByLabel('TCP ports')).toHaveValue('1-65535');
  await page.setViewportSize({ width: 320, height: 780 });
  for (const name of ['Common', '1–1024', 'All ports', 'Fast TCP', 'Service probes', 'Scan', 'Export JSON']) {
    const box = await scanner.getByRole('button', { name, exact: true }).boundingBox();
    expect(box!.width).toBeGreaterThanOrEqual(44);
    expect(box!.height).toBeGreaterThanOrEqual(44);
  }
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  expect(errors).toEqual([]);
});

test('controlled IPC fixture exercises scan progress, evidence, cancellation, export and endpoint navigation', async ({ page }) => {
  // UI-only IPC fixture. Actual sockets and service probes are tested by scan-engine.
  await page.addInitScript(() => {
    (window as any).isTauri = true;
    const capture = { packets: [], totalPackets: 0, totalBytes: 0, droppedPackets: 0, linkType: 101 };
    let scan: Record<string, any> = { id: 0, phase: 'idle', request: null, addresses: [], portCount: 0, total: 0, completed: 0, open: 0, closed: 0, timedOut: 0, errors: 0, resultsRetained: 0, resultsDropped: 0, results: [], startedAt: 0, elapsedMs: 0, error: null };
    (window as any).__TAURI_INTERNALS__ = { invoke: async (command: string, args: any) => {
      if (command === 'capture_snapshot') return capture;
      if (command === 'capture_status') return { running: false };
      if (command === 'scan_status') { if (scan.phase === 'running') scan.elapsedMs += 1000; return structuredClone(scan); }
      if (command === 'scan_start') {
        scan = { ...scan, id: scan.id + 1, phase: 'running', request: args.request, addresses: ['192.0.2.10'], portCount: 3, total: 3, completed: 1, open: 1, resultsRetained: 1, elapsedMs: 100, results: [{ address: '192.0.2.10', port: 22, service: 'ssh', evidence: 'response', portHint: 'ssh', product: 'OpenSSH_fixture', banner: 'SSH-2.0-OpenSSH_fixture', connectMs: 12.5 }] };
        return scan;
      }
      if (command === 'scan_stop') { scan = { ...scan, phase: 'cancelled', elapsedMs: 250 }; return scan; }
      if (command === 'scan_export') return 'content://downloads/seekershark-scan-fixture.json';
      throw new Error(`Unexpected fixture command: ${command}`);
    } };
  });
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto('/');
  await openScan(page);
  const scanner = page.getByRole('region', { name: 'Network scanner' });
  await scanner.getByLabel('Target', { exact: true }).fill('192.0.2.10');
  await scanner.getByLabel('TCP ports').fill('22,80,443');
  await scanner.getByRole('button', { name: 'Scan', exact: true }).click();
  await expect(scanner.getByRole('heading', { name: 'Scanning', exact: true })).toBeVisible();
  await expect(scanner.getByLabel('Target', { exact: true })).toBeDisabled();
  await expect(scanner.getByRole('progressbar')).toHaveAttribute('value', '1');
  await scanner.locator('.scan-result summary').click();
  await expect(scanner.locator('.scan-result')).toContainText('response');
  await expect(scanner.locator('.scan-result pre')).toHaveText('SSH-2.0-OpenSSH_fixture');
  await expect(scanner.locator('.scan-status .panel-heading > span')).not.toHaveText('0.1 s');
  await expect(scanner.locator('.scan-result')).toHaveAttribute('open', '');
  await scanner.getByRole('button', { name: 'Stop scan' }).click();
  await expect(scanner.getByRole('heading', { name: 'Cancelled', exact: true })).toBeVisible();
  await scanner.getByRole('button', { name: 'Export JSON' }).click();
  await expect(scanner.getByRole('status')).toContainText('content://downloads/seekershark-scan-fixture.json');
  await scanner.getByRole('button', { name: 'Filter captured packets' }).click();
  await expect(page.getByRole('textbox', { name: 'Filter packets' })).toHaveValue('host:192.0.2.10');
  await page.getByRole('button', { name: 'Back to previous view' }).click();
  await expect(scanner.getByRole('heading', { name: 'Cancelled', exact: true })).toBeVisible();
  expect(errors).toEqual([]);
});
