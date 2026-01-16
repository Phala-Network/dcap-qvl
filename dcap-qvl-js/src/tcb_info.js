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
    constructor(id, version, issueDate, nextUpdate, fmspc, pceId, tcbType, tcbEvaluationDataNumber, tcbLevels) {
        this.id = id;
        this.version = version;
        this.issueDate = issueDate;
        this.nextUpdate = nextUpdate;
        this.fmspc = fmspc;
        this.pceId = pceId;
        this.tcbType = tcbType;
        this.tcbEvaluationDataNumber = tcbEvaluationDataNumber;
        this.tcbLevels = tcbLevels;
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
            tcbLevels
        );
    }
}

// TCB status severity ordering (higher number = worse status)
function tcbStatusSeverity(status) {
    switch (status) {
        case 'UpToDate': return 0;
        case 'SWHardeningNeeded': return 1;
        case 'ConfigurationNeeded': return 2;
        case 'ConfigurationAndSWHardeningNeeded': return 3;
        case 'OutOfDate': return 4;
        case 'OutOfDateConfigurationNeeded': return 5;
        case 'Revoked': return 6;
        default: return 100; // Unknown status treated as worst
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
                return true;
            case 'Revoked':
                return false;
            default:
                return false; // Unknown or other statuses are invalid
        }
    }

    // Merge two TCB statuses, taking the worse status and combining advisory IDs
    merge(other) {
        const finalStatus = tcbStatusSeverity(other.status) > tcbStatusSeverity(this.status)
            ? other.status
            : this.status;

        const advisoryIds = [...this.advisoryIds];
        for (const id of other.advisoryIds) {
            if (!advisoryIds.includes(id)) {
                advisoryIds.push(id);
            }
        }

        return new TcbStatus(finalStatus, advisoryIds);
    }
}

module.exports = {
    TcbComponents,
    Tcb,
    TcbLevel,
    TcbInfo,
    TcbStatus,
    tcbStatusSeverity,
};
