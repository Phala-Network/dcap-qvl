const test = require('node:test');
const assert = require('node:assert/strict');

const { TcbStatus } = require('../src/tcb_info');

test('TcbStatus.merge converges an out-of-date component on a configuration-needed platform', () => {
    for (const platform of ['ConfigurationNeeded', 'ConfigurationAndSWHardeningNeeded']) {
        const merged = new TcbStatus(platform, ['A']).merge(new TcbStatus('OutOfDate', ['B']));
        assert.equal(merged.status, 'OutOfDateConfigurationNeeded');
        assert.deepEqual(merged.advisoryIds, ['A', 'B']);
    }
    assert.equal(new TcbStatus('SWHardeningNeeded').merge(new TcbStatus('OutOfDate')).status, 'OutOfDate');
    assert.equal(new TcbStatus('ConfigurationNeeded').merge(new TcbStatus('UpToDate')).status, 'ConfigurationNeeded');
});
