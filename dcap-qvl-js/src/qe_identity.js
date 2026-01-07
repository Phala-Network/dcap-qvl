// QE Identity structures
// Converted from qe_identity.rs

class QeTcb {
    constructor(isvsvn) {
        this.isvsvn = isvsvn;
    }
}

class QeTcbLevel {
    constructor(tcb, tcbDate, tcbStatus, advisoryIds) {
        this.tcb = tcb;
        this.tcbDate = tcbDate;
        this.tcbStatus = tcbStatus;
        this.advisoryIDs = advisoryIds || [];
    }
}

class QeIdentity {
    constructor(id, version, issueDate, nextUpdate, tcbEvaluationDataNumber,
                miscselect, miscselectMask, attributes, attributesMask,
                mrsigner, isvprodid, tcbLevels) {
        this.id = id;
        this.version = version;
        this.issueDate = issueDate;
        this.nextUpdate = nextUpdate;
        this.tcbEvaluationDataNumber = tcbEvaluationDataNumber;
        this.miscselect = miscselect;
        this.miscselectMask = miscselectMask;
        this.attributes = attributes;
        this.attributesMask = attributesMask;
        this.mrsigner = mrsigner;
        this.isvprodid = isvprodid;
        this.tcbLevels = tcbLevels;
    }

    static fromJSON(json) {
        const obj = typeof json === 'string' ? JSON.parse(json) : json;

        const tcbLevels = obj.tcbLevels.map(level => {
            const tcb = new QeTcb(level.tcb.isvsvn);
            return new QeTcbLevel(
                tcb,
                level.tcbDate,
                level.tcbStatus,
                level.advisoryIDs || []
            );
        });

        return new QeIdentity(
            obj.id,
            obj.version,
            obj.issueDate,
            obj.nextUpdate,
            obj.tcbEvaluationDataNumber,
            obj.miscselect,
            obj.miscselectMask,
            obj.attributes,
            obj.attributesMask,
            obj.mrsigner,
            obj.isvprodid,
            tcbLevels
        );
    }
}

module.exports = {
    QeTcb,
    QeTcbLevel,
    QeIdentity,
};
