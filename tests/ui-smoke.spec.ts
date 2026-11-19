import { readFile } from 'node:fs/promises';
import { expect, test as base, type Page } from '@playwright/test';

const test = base.extend<{ runtimeErrors: string[] }>({
  runtimeErrors: [async ({ page }, use) => {
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    await use(errors);
    expect(errors, 'The page must not throw runtime errors').toEqual([]);
  }, { auto: true }],
});

async function navigate(page: Page, label: string) {
  const navigation = page.viewportSize()!.width <= 600 ? page.locator('.mobile-nav') : page.locator('.desktop-nav');
  await navigation.getByRole('button', { name: label, exact: false }).click();
}

test.beforeEach(async ({ page }) => {
  await page.goto('/');
  await expect(page.getByLabel('Demo mode: synthetic packets')).toBeVisible();
  await expect(page.locator('.packet-row')).toHaveCount(32);
});

test('filters, inspects packet layers and hex, and drills into protocol analysis', async ({ page }) => {
  const filter = page.getByRole('textbox', { name: 'Filter packets' });
  await filter.fill('proto:DNS port:53');
  await expect(page.locator('.packet-row')).toHaveCount(8);
  await page.locator('.packet-row').first().click();
  const inspector = page.locator('dialog[open]');
  await expect(inspector).toBeVisible();
  await expect(inspector.locator('.protocol-layer')).toHaveCount(3);
  await expect(inspector).toContainText('Synthetic local example');
  await inspector.getByRole('tab', { name: 'Hex' }).click();
  await expect(inspector.locator('.hex-view')).toBeVisible();
  await expect(inspector.locator('.hex-caption')).toContainText('76 of 76 Bytes');
  await page.keyboard.press('Escape');
  await expect(inspector).toHaveCount(0);

  await filter.fill('proto:TLS port:443');
  await page.locator('.packet-row').first().click();
  await inspector.getByRole('tab', { name: 'Hex' }).click();
  await expect(inspector.locator('.hex-caption')).toContainText('256 of');
  await inspector.getByRole('button', { name: 'Show 256 more bytes' }).click();
  await expect(inspector.locator('.hex-caption')).toContainText('512 of');
  await inspector.getByRole('button', { name: 'Back to packet list' }).click();

  await filter.fill('host:unmatched.example');
  await expect(page.locator('.packet-row')).toHaveCount(0);
  await expect(page.getByText('No matches', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Reset filter' }).click();
  await expect(page.locator('.packet-row')).toHaveCount(32);

  await navigate(page, 'Analysis');
  await expect(page.locator('.traffic-chart svg')).toBeVisible();
  await page.locator('.distribution-row').first().click();
  await expect(filter).toHaveValue('proto:DNS');
  await expect(page.locator('.packet-row')).toHaveCount(8);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'No horizontal page overflow').toBe(true);
});

test('exports actual demo PCAP, resets the buffer, and explains browser limitations', async ({ page }) => {
  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export', exact: true }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toMatch(/^seekershark-demo-.*\.pcap$/);
  const path = await download.path();
  expect(path).not.toBeNull();
  const pcap = await readFile(path!);
  expect(pcap.readUInt32LE(0)).toBe(0xa1b2c3d4);
  expect(pcap.readUInt32LE(20)).toBe(101); // DLT_RAW
  let offset = 24;
  let count = 0;
  while (offset < pcap.length) {
    expect(offset + 16).toBeLessThanOrEqual(pcap.length);
    const length = pcap.readUInt32LE(offset + 8);
    expect(length).toBeGreaterThanOrEqual(20);
    expect(offset + 16 + length).toBeLessThanOrEqual(pcap.length);
    expect(pcap[offset + 16] >> 4).toBe(4);
    offset += 16 + length;
    count++;
  }
  expect(count).toBe(32);
  expect(offset).toBe(pcap.length);

  await page.getByRole('button', { name: 'Start capture' }).click();
  await expect(page.getByRole('alert')).toContainText('Android app');
  await page.getByRole('button', { name: 'Dismiss error' }).click();
  await navigate(page, 'Session');
  await page.getByRole('button', { name: 'Clear buffer' }).click();
  await expect(page.locator('.session-pane > section .session-card')).toContainText('0 packets');
  await page.getByRole('button', { name: 'Load demo' }).click();
  await expect(page.locator('.packet-row')).toHaveCount(32);
  await page.getByLabel('PCAP file', { exact: true }).setInputFiles({
    name: 'example.pcap', mimeType: 'application/vnd.tcpdump.pcap', buffer: pcap,
  });
  await expect(page.getByRole('alert')).toContainText('PCAP import requires the Android app');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'No horizontal page overflow').toBe(true);
});

test('keeps packets prominent and enables readable packet details only through Beautify', async ({ page }) => {
  const toggle = page.getByRole('switch', { name: 'Beautify', exact: true });
  await expect(toggle).not.toBeChecked();
  const firstRow = await page.locator('.packet-row').first().boundingBox();
  expect(firstRow!.y).toBeLessThan(page.viewportSize()!.height * .4);
  expect(await page.evaluate(() => document.documentElement.scrollHeight <= innerHeight)).toBe(true);

  const filter = page.getByRole('textbox', { name: 'Filter packets' });
  await filter.fill('proto:HTTP');
  await expect(page.locator('.packet-row')).toHaveCount(1);
  await page.locator('.packet-row').first().click();
  const inspector = page.locator('dialog[open]');
  await expect(inspector.locator('.readable-payload')).toHaveCount(0);
  await inspector.getByRole('switch', { name: 'Beautify', exact: true }).check();
  await expect(inspector.locator('.readable-payload h3')).toHaveText('HTTP + JSON');
  await expect(inspector.locator('.readable-payload pre')).toContainText('  "method": "getSlot"');
  await expect(inspector.locator('.readable-summary')).toContainText('synthetic packet');
  await inspector.getByRole('button', { name: 'Back to packet list' }).click();
  await expect(toggle).toBeChecked();

  await filter.fill('proto:TLS');
  await page.locator('.packet-row').first().click();
  await expect(inspector.locator('.readable-summary')).toContainText('no decryption');
  await expect(inspector.locator('.readable-payload')).toHaveCount(0);
  await inspector.getByRole('tab', { name: 'Hex', exact: true }).click();
  await expect(inspector.locator('.hex-view')).toBeVisible();
  await inspector.getByRole('button', { name: 'Back to packet list' }).click();

  await page.reload();
  await expect(toggle).toBeChecked();
  await expect(page.locator('.packet-row')).toHaveCount(32);
  await toggle.uncheck();
  await expect(page.locator('.readable-row')).toHaveCount(0);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test('back navigation restores packet filters, list position and analysis drill-down origins', async ({ page }) => {
  const filter = page.getByRole('textbox', { name: 'Filter packets' });
  await filter.fill('host:10.23.0.2');
  const list = page.locator('.packet-table');
  await list.evaluate(element => { element.scrollTop = 400; });
  const scroll = await list.evaluate(element => element.scrollTop);
  await page.locator('.packet-row').nth(10).click();
  const inspector = page.locator('dialog[open]');
  await expect(inspector.getByRole('button', { name: 'Back to packet list', exact: true })).toBeVisible();
  if (page.viewportSize()!.width <= 600) {
    await inspector.getByRole('button', { name: 'Back to list', exact: true }).click();
  } else await inspector.getByRole('button', { name: 'Back to packet list', exact: true }).click();
  await expect(inspector).toHaveCount(0);
  await expect(filter).toHaveValue('host:10.23.0.2');
  await expect.poll(async () => Math.abs(await list.evaluate(element => element.scrollTop) - scroll)).toBeLessThan(2);

  await navigate(page, 'Analysis');
  await page.locator('.distribution-row').first().click();
  await expect(filter).toHaveValue('proto:DNS');
  await page.locator('.packet-row').first().click();
  await inspector.getByRole('button', { name: 'Back to packet list', exact: true }).click();
  await expect(filter).toHaveValue('proto:DNS');
  const back = page.getByRole('button', { name: 'Back to previous view', exact: true });
  await back.click();
  await expect(page.locator('.traffic-chart')).toBeVisible();
  await back.click();
  await expect(filter).toHaveValue('host:10.23.0.2');
  await expect(page.locator('.packet-row')).toHaveCount(32);
  await expect.poll(async () => Math.abs(await list.evaluate(element => element.scrollTop) - scroll)).toBeLessThan(2);
  await expect(back).toHaveCount(0);

  await navigate(page, 'Session');
  await back.click();
  await expect(filter).toHaveValue('host:10.23.0.2');
  await page.getByLabel('Filter syntax').click();
  await expect(page.locator('.filter-help')).toHaveAttribute('open', '');
  await back.click();
  await expect(page.locator('.filter-help')).not.toHaveAttribute('open', '');
  await expect(back).toHaveCount(0);
});

test('mobile controls stay tappable and inspector back stays visible within safe areas', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 780 });
  const controls = [
    page.getByRole('button', { name: 'Start capture', exact: true }),
    page.getByRole('button', { name: 'Open PCAP', exact: true }),
    page.getByRole('button', { name: 'Export', exact: true }),
    page.getByRole('button', { name: 'Clear buffer', exact: true }),
    page.getByLabel('Filter syntax'),
    page.locator('.protocol-filters button').first(),
    ...await page.locator('.mobile-nav button').all(),
  ];
  for (const control of controls) {
    const box = await control.boundingBox();
    expect(box!.height).toBeGreaterThanOrEqual(44);
    expect(box!.width).toBeGreaterThanOrEqual(44);
  }
  const switchBox = await page.getByRole('switch', { name: 'Beautify' }).evaluate(element => {
    const box = element.closest('label')!.getBoundingClientRect(); return { width: box.width, height: box.height };
  });
  expect(switchBox.height).toBeGreaterThanOrEqual(44);
  expect(switchBox.width).toBeGreaterThanOrEqual(44);

  await page.setViewportSize({ width: 393, height: 852 });
  // Browser-only safe-area scenario. Real Android bars are fitted by MainActivity.
  await page.addStyleTag({ content: ':root{--safe-top:28px;--safe-bottom:24px}' });
  await page.getByRole('textbox', { name: 'Filter packets' }).fill('proto:HTTP');
  await page.locator('.packet-row').first().click();
  const inspector = page.locator('dialog[open]');
  await inspector.getByRole('switch', { name: 'Beautify' }).check();
  await inspector.locator('.detail-content').evaluate(element => { element.scrollTop = element.scrollHeight; });
  const topBack = await inspector.getByRole('button', { name: 'Back to packet list', exact: true }).boundingBox();
  const bottomBack = await inspector.getByRole('button', { name: 'Back to list', exact: true }).boundingBox();
  expect(topBack!.y).toBeGreaterThanOrEqual(28);
  expect(topBack!.height).toBeGreaterThanOrEqual(44);
  expect(bottomBack!.y + bottomBack!.height).toBeLessThanOrEqual(852 - 24);
  expect(bottomBack!.height).toBeGreaterThanOrEqual(44);
  await inspector.getByRole('button', { name: 'Back to list', exact: true }).click();
  await expect(inspector).toHaveCount(0);
  await expect(page.getByRole('textbox', { name: 'Filter packets' })).toHaveValue('proto:HTTP');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});
