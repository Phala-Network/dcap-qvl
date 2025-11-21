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

module.exports = {
    TcbComponents,
    Tcb,
    TcbLevel,
    TcbInfo,
};
