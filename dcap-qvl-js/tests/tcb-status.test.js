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

test('TcbStatus.merge ignores components that are neither OutOfDate nor Revoked', () => {
    for (const [platform, component, expected] of [
        ['UpToDate', 'ConfigurationNeeded', 'UpToDate'],
        ['UpToDate', 'OutOfDateConfigurationNeeded', 'UpToDate'],
        ['OutOfDateConfigurationNeeded', 'OutOfDate', 'OutOfDateConfigurationNeeded'],
        ['ConfigurationNeeded', 'Revoked', 'Revoked'],
    ]) {
        assert.equal(new TcbStatus(platform).merge(new TcbStatus(component)).status, expected);
    }
});

test('TcbStatus.checkForRelaunch matches Intel QVL', () => {
    for (const [launch, current, expected] of [
        ['OutOfDate', 'UpToDate', 'TDRelaunchAdvised'],
        ['OutOfDate', 'SWHardeningNeeded', 'TDRelaunchAdvised'],
        ['OutOfDate', 'ConfigurationNeeded', 'TDRelaunchAdvisedConfigurationNeeded'],
        ['OutOfDateConfigurationNeeded', 'UpToDate', 'TDRelaunchAdvisedConfigurationNeeded'],
        ['OutOfDate', 'OutOfDate', 'OutOfDate'],
        ['OutOfDate', 'Revoked', 'OutOfDate'],
        ['UpToDate', 'UpToDate', 'UpToDate'],
        ['ConfigurationNeeded', 'UpToDate', 'ConfigurationNeeded'],
    ]) {
        const result = new TcbStatus(launch, ['A']).checkForRelaunch(new TcbStatus(current, ['B']));
        assert.equal(result.status, expected);
        assert.deepEqual(result.advisoryIds, ['A']);
    }
});
