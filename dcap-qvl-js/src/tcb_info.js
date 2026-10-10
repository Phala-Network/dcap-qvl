// TCB Info structures
// Converted from tcb_info.rs

class TcbComponents {
    constructor(svn) {
        this.svn = svn;
    }
}

class Tcb {
    constructor(sgxComponents, tdxComponents, pceSvn) {
        this.sgxtcbcomponents = sgxComponents;
        this.tdxtcbcomponents = tdxComponents || [];
        this.pcesvn = pceSvn;
    }
}

class TcbLevel {
    constructor(tcb, tcbDate, tcbStatus, advisoryIds) {
        this.tcb = tcb;
        this.tcbDate = tcbDate;
        this.tcbStatus = tcbStatus;
        this.advisoryIDs = advisoryIds || [];
    }
}

class TcbInfo {
    constructor(id, version, issueDate, nextUpdate, fmspc, pceId, tcbType, tcbEvaluationDataNumber, tcbLevels, tdxModule, tdxModuleIdentities) {
        this.id = id;
        this.version = version;
        this.issueDate = issueDate;
        this.nextUpdate = nextUpdate;
        this.fmspc = fmspc;
        this.pceId = pceId;
        this.tcbType = tcbType;
        this.tcbEvaluationDataNumber = tcbEvaluationDataNumber;
        this.tcbLevels = tcbLevels;
        this.tdxModule = tdxModule || null;
        this.tdxModuleIdentities = tdxModuleIdentities || [];
    }

    static fromJSON(json) {
        const obj = typeof json === 'string' ? JSON.parse(json) : json;

        const tcbLevels = obj.tcbLevels.map(level => {
            const sgxComponents = level.tcb.sgxtcbcomponents.map(c => new TcbComponents(c.svn));
            const tdxComponents = (level.tcb.tdxtcbcomponents || []).map(c => new TcbComponents(c.svn));
            const tcb = new Tcb(sgxComponents, tdxComponents, level.tcb.pcesvn);
            return new TcbLevel(
                tcb,
                level.tcbDate,
                level.tcbStatus,
                level.advisoryIDs || []
            );
        });

        return new TcbInfo(
            obj.id,
            obj.version,
            obj.issueDate,
            obj.nextUpdate,
            obj.fmspc,
            obj.pceId,
            obj.tcbType,
            obj.tcbEvaluationDataNumber,
            tcbLevels,
            obj.tdxModule,
            obj.tdxModuleIdentities
        );
    }
}

class TcbStatus {
    constructor(status, advisoryIds) {
        this.status = status || 'Unknown';
        this.advisoryIds = advisoryIds || [];
    }

    static unknown() {
        return new TcbStatus('Unknown', []);
    }

    // Check if the TCB status is valid (not Revoked)
    isValid() {
        switch (this.status) {
            case 'UpToDate':
            case 'SWHardeningNeeded':
            case 'ConfigurationNeeded':
            case 'ConfigurationAndSWHardeningNeeded':
            case 'OutOfDate':
            case 'OutOfDateConfigurationNeeded':
            case 'TDRelaunchAdvised':
            case 'TDRelaunchAdvisedConfigurationNeeded':
                return true;
            case 'Revoked':
                return false;
            default:
                return false; // Unknown or other statuses are invalid
        }
    }

    // Merge a platform status with a QE or TDX module status like Intel QVL's
    // convergeTcbStatuses (only an OutOfDate or Revoked component affects the
    // platform status), combining advisory IDs
    merge(other) {
        let finalStatus = this.status;
        if (other.status === 'Revoked') {
            finalStatus = 'Revoked';
        } else if (other.status === 'OutOfDate') {
            if (finalStatus === 'UpToDate' || finalStatus === 'SWHardeningNeeded') {
                finalStatus = 'OutOfDate';
            } else if (finalStatus === 'ConfigurationNeeded' || finalStatus === 'ConfigurationAndSWHardeningNeeded') {
                finalStatus = 'OutOfDateConfigurationNeeded';
            }
        }

        const advisoryIds = [...this.advisoryIds];
        for (const id of other.advisoryIds) {
            if (!advisoryIds.includes(id)) {
                advisoryIds.push(id);
            }
        }

        return new TcbStatus(finalStatus, advisoryIds);
    }

    // Combine the launch and current statuses of a TD 1.5 like Intel QVL's
    // checkForRelaunch
    checkForRelaunch(current) {
        const launchOutOfDate = ['OutOfDate', 'OutOfDateConfigurationNeeded'].includes(this.status);
        const currentNotOutOfDate = ['UpToDate', 'SWHardeningNeeded', 'ConfigurationNeeded', 'ConfigurationAndSWHardeningNeeded']
            .includes(current.status);
        if (!launchOutOfDate || !currentNotOutOfDate) {
            return this;
        }
        const configurationNeeded = status => [
            'ConfigurationNeeded',
            'OutOfDateConfigurationNeeded',
            'ConfigurationAndSWHardeningNeeded',
            'TDRelaunchAdvisedConfigurationNeeded',
        ].includes(status);
        const status = configurationNeeded(this.status) || configurationNeeded(current.status)
            ? 'TDRelaunchAdvisedConfigurationNeeded'
            : 'TDRelaunchAdvised';
        return new TcbStatus(status, this.advisoryIds);
    }
}

module.exports = {
    TcbComponents,
    Tcb,
    TcbLevel,
    TcbInfo,
    TcbStatus,
};
