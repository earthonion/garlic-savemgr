const { test, expect } = require('@playwright/test');
const fs = require('fs');
const path = require('path');

const ui = fs.readFileSync(path.join(__dirname, '..', 'src', 'ui.html'), 'utf8');

function makeSfo(format, width) {
  const entries = [
    { key: 'TITLE_ID', format: 0x0204, value: Buffer.from('PPSA25642\0') },
    { key: 'SAVEDATA_BLOCKS', format, value: Buffer.alloc(width) },
    { key: 'SYSTEM_BLOCKS', format, value: Buffer.alloc(width) },
  ];
  if (width === 8) {
    entries[1].value.writeBigUInt64LE(165n);
    entries[2].value.writeBigUInt64LE(165n);
  } else {
    entries[1].value.writeUInt32LE(165);
    entries[2].value.writeUInt32LE(165);
  }
  const keyOffset = 20 + entries.length * 16;
  const keys = [];
  let keyBytes = 0;
  for (const entry of entries) {
    entry.keyOffset = keyBytes;
    const encoded = Buffer.from(entry.key + '\0');
    keys.push(encoded);
    keyBytes += encoded.length;
  }
  const dataOffset = keyOffset + keyBytes;
  let valueBytes = 0;
  for (const entry of entries) {
    entry.valueOffset = valueBytes;
    valueBytes += entry.value.length;
  }
  const sfo = Buffer.alloc(dataOffset + valueBytes);
  sfo.writeUInt32LE(0x46535000, 0);
  sfo.writeUInt32LE(0x101, 4);
  sfo.writeUInt32LE(keyOffset, 8);
  sfo.writeUInt32LE(dataOffset, 12);
  sfo.writeUInt32LE(entries.length, 16);
  entries.forEach((entry, index) => {
    const offset = 20 + index * 16;
    sfo.writeUInt16LE(entry.keyOffset, offset);
    sfo.writeUInt16LE(entry.format, offset + 2);
    sfo.writeUInt32LE(entry.value.length, offset + 4);
    sfo.writeUInt32LE(entry.value.length, offset + 8);
    sfo.writeUInt32LE(entry.valueOffset, offset + 12);
    entry.value.copy(sfo, dataOffset + entry.valueOffset);
  });
  Buffer.concat(keys).copy(sfo, keyOffset);
  return sfo;
}

function json(route, body) {
  return route.fulfill({ contentType: 'application/json', body: JSON.stringify(body) });
}

async function openApp(page, handlers = {}) {
  await page.route('http://savemgr.local/**', async route => {
    const url = new URL(route.request().url());
    if (url.pathname === '/' || url.pathname === '/index.html')
      return route.fulfill({ contentType: 'text/html', body: ui });
    if (url.pathname === '/api/users')
      return json(route, { users: [{ id: '18c60ea3', name: 'test-user' }] });
    if (url.pathname === '/api/saves') return json(route, { saves: [] });
    if (url.pathname === '/api/transfer_begin')
      return json(route, { ok: true, id: '0123456789abcdef' });
    const handler = handlers[url.pathname];
    if (handler) return handler(route, url);
    return json(route, { ok: true });
  });
  await page.goto('/');
  await page.waitForFunction(() => typeof encDrop === 'function' && curUid === '18c60ea3');
}

async function openEncrypt(page) {
  await page.locator('nav .tab[data-tab="encrypt"]').click();
  await expect(page.getByRole('button', { name: 'Browse ZIP', exact: true })).toBeVisible();
}

const oldChives = {
  schema_version: 1,
  platform: 'PS5',
  title_id: 'PPSA25642',
  original_image_size_bytes: 33554432,
  pfs: {
    version: 2,
    block_size_bytes: 32768,
    block_count: 1024,
    mode_raw: 13,
    backup_header_count: 1,
    fs_ext: 0,
  },
};

test('Encrypt accepts a ZIP and sends it to the ZIP backend', async ({ page }) => {
  let uploaded = false;
  await openApp(page, {
    '/api/encrypt_upload': async route => {
      uploaded = true;
      expect(route.request().headers()['x-garlic-transfer']).toBe('0123456789abcdef');
      await json(route, { ok: true, size: 21626880, warning: '' });
    },
    '/api/encrypt_download': route => route.fulfill({
      contentType: 'application/octet-stream', body: Buffer.from([2, 0]),
    }),
  });
  await openEncrypt(page);
  const chooser = page.waitForEvent('filechooser');
  await page.getByRole('button', { name: 'Browse ZIP', exact: true }).click();
  await (await chooser).setFiles({ name: 'ff.zip', mimeType: 'application/zip', buffer: Buffer.from('zip') });
  await expect(page.locator('#encryptSelection')).toContainText('1 ZIP archive(s): ff.zip');
  const downloaded = page.waitForEvent('download');
  await page.locator('#encryptSelection').getByRole('button', { name: 'Encrypt', exact: true }).click();
  expect((await downloaded).suggestedFilename()).toBe('ff_enc');
  await expect(page.locator('#log')).toContainText('Encrypted save download started');
  expect(uploaded).toBe(true);
});

for (const [label, format, width] of [
  ['0x0004 eight-byte', 0x0004, 8],
  ['0x0404 four-byte', 0x0404, 4],
]) {
  test(`folder encryption recovers legacy geometry from ${label} SFO fields`, async ({ page }) => {
    let geometry = null;
    const uploads = [];
    await openApp(page, {
      '/api/create_pfs': async route => {
        geometry = route.request().postDataJSON();
        await json(route, { ok: true, key_recovered: true, native_allocation: true });
      },
      '/api/upload_file': async (route, url) => {
        uploads.push(url.searchParams.get('name'));
        await json(route, { ok: true });
      },
      '/api/download_new': route => route.fulfill({
        contentType: 'application/octet-stream', body: Buffer.from([2, 0]),
      }),
    });
    await openEncrypt(page);
    await page.evaluate(async ({ sfo, chives, keystone, payload }) => {
      const decode = value => Uint8Array.from(atob(value), char => char.charCodeAt(0));
      const file = (name, data) => {
        const result = new File([decode(data)], name.split('/').pop());
        result._path = name;
        return result;
      };
      await encDrop([
        file('ff/chives.json', chives),
        file('ff/sce_sys/param.sfo', sfo),
        file('ff/sce_sys/keystone', keystone),
        file('ff/ue4savegame.dpx.sav', payload),
      ], 'ff', null);
    }, {
      sfo: makeSfo(format, width).toString('base64'),
      chives: Buffer.from(JSON.stringify(oldChives)).toString('base64'),
      keystone: Buffer.alloc(96).toString('base64'),
      payload: Buffer.alloc(2233).toString('base64'),
    });
    const downloaded = page.waitForEvent('download');
    await page.locator('#encryptSelection').getByRole('button', { name: 'Encrypt', exact: true }).click();
    await downloaded;
    expect(geometry.pfs).toEqual({
      version: 2,
      block_size_bytes: 65536,
      block_count: 330,
      mode_raw: 13,
      backup_header_count: 1,
      fs_ext: 165,
    });
    expect(geometry.original_image_size_bytes).toBe(21626880);
    expect(uploads).toEqual(['sce_sys/param.sfo', 'sce_sys/keystone', 'ue4savegame.dpx.sav']);
    await expect(page.locator('#log')).toContainText('Recovered PFS geometry from param.sfo');
  });
}

for (const outcome of ['failure', 'success']) {
  test(`import reports native ${outcome} without claiming a false success`, async ({ page }) => {
    const failure = 'Zero fs_ext does not match the source-bound physical-SFO profile; output withheld; output was not published or installed';
    await openApp(page, {
      '/api/import_encrypted': route => json(route, {
        ok: true, title_id: 'PPSA25642', dir_name: 'AchievementsSaveData',
        match: true, exists: false,
      }),
      '/api/import_finish': route => json(route, outcome === 'failure'
        ? { error: failure }
        : { ok: true, title_id: 'PPSA25642', dir_name: 'AchievementsSaveData', exists: false, warning: '' }),
    });
    await page.locator('nav .tab[data-tab="import"]').click();
    const chooser = page.waitForEvent('filechooser');
    await page.getByRole('button', { name: 'Browse File', exact: true }).click();
    await (await chooser).setFiles({
      name: 'sdimg_AchievementsSaveData_dec_enc', mimeType: 'application/octet-stream',
      buffer: Buffer.from([2, 0]),
    });
    if (outcome === 'failure') {
      await expect(page.locator('#log')).toContainText(failure);
      await expect(page.locator('#log')).toContainText('Import: 0 succeeded, 1 failed, 0 skipped');
      await expect(page.locator('#log')).not.toContainText('Import complete:');
    } else {
      await expect(page.locator('#log')).toContainText('Import complete: PPSA25642/AchievementsSaveData (new)');
    }
  });
}

test('decrypted folder import passes SFO geometry into PFS creation', async ({ page }) => {
  let geometry = null;
  const uploads = [];
  await openApp(page, {
    '/api/create_pfs': async route => {
      geometry = route.request().postDataJSON();
      await json(route, { ok: true, key_recovered: true, native_allocation: true });
    },
    '/api/upload_file': async (route, url) => {
      uploads.push(url.searchParams.get('name'));
      await json(route, { ok: true });
    },
    '/api/import_check': route => json(route, { exists: false }),
    '/api/import_finish': route => json(route, {
      ok: true, title_id: 'PPSA25642', dir_name: 'AchievementsSaveData', exists: false, warning: '',
    }),
  });
  await page.locator('nav .tab[data-tab="import"]').click();
  await page.evaluate(async ({ sfo, chives, keystone, payload }) => {
    const decode = value => Uint8Array.from(atob(value), char => char.charCodeAt(0));
    const file = (name, data) => {
      const result = new File([decode(data)], name.split('/').pop());
      result._path = name;
      return result;
    };
    await importDrop([
      file('ff/chives.json', chives),
      file('ff/sce_sys/param.sfo', sfo),
      file('ff/sce_sys/keystone', keystone),
      file('ff/ue4savegame.dpx.sav', payload),
    ], 'ff', null);
  }, {
    sfo: makeSfo(0x0004, 8).toString('base64'),
    chives: Buffer.from(JSON.stringify(oldChives)).toString('base64'),
    keystone: Buffer.alloc(96).toString('base64'),
    payload: Buffer.alloc(2233).toString('base64'),
  });
  expect(geometry.pfs).toEqual({
    version: 2,
    block_size_bytes: 65536,
    block_count: 330,
    mode_raw: 13,
    backup_header_count: 1,
    fs_ext: 165,
  });
  expect(geometry.original_image_size_bytes).toBe(21626880);
  expect(uploads).toEqual(['sce_sys/param.sfo', 'sce_sys/keystone', 'ue4savegame.dpx.sav']);
  await expect(page.locator('#log')).toContainText('Import complete: PPSA25642/AchievementsSaveData (new)');
});
