var should = require('should');
var validator = require('../validator.js');


describe("Using nullReceipt - ", function () {

    var nullReceipt = null;
    var result = validator.isValidReceipt(nullReceipt);
    it("should receive error - bad Json", function () {
        result.should.have.property('isValid', false);
        result.should.have.property('error', 'Cannot parse receipt JSON');
    });

});

describe("Using stringReceipt - ", function () {

    var stringReceipt = 'dfsgsfgxcvbasfdg';
    var result = validator.isValidReceipt(stringReceipt);
    it("should receive error - bad Json", function () {
        result.should.have.property('isValid', false);
        result.should.have.property('error', 'Cannot parse receipt JSON');
    });

});

describe("Using numberReceipt - ", function () {

    var numberReceipt = 435345;
    var result = validator.isValidReceipt(numberReceipt);
    it("should receive error - unknown version", function () {
        result.should.have.property('isValid', false);
        result.should.have.property('error', 'Cannot identify Chainpoint version');
    });

});

describe("Using emptyReceipt - ", function () {

    var emptyReceipt = {};
    var result = validator.isValidReceipt(emptyReceipt);
    it("should receive error - unknown version", function () {
        result.should.have.property('isValid', false);
        result.should.have.property('error', 'Cannot identify Chainpoint version');
    });

});

describe("Using junkReceiptObject - ", function () {

    var junkReceiptObject = { 'sdf': 23424 };
    var result = validator.isValidReceipt(junkReceiptObject);
    it("should receive error - unknown version", function () {
        result.should.have.property('isValid', false);
        result.should.have.property('error', 'Cannot identify Chainpoint version');
    });

});

describe("Using junkReceiptString - ", function () {

    var junkReceiptString = '{ "sdf": 23424 }';
    var result = validator.isValidReceipt(junkReceiptString);
    it("should receive error - unknown version", function () {
        result.should.have.property('isValid', false);
        result.should.have.property('error', 'Cannot identify Chainpoint version');
    });

});

describe("Using badVersionNumberReceipt - ", function () {

    var badVersionNumberReceipt = {
        "header": {
            "chainpoint_version": "0.9"
        }
    };

    var result = validator.isValidReceipt(badVersionNumberReceipt);
    it("should receive error - bad version", function () {
        result.should.have.property('isValid', false);
        result.should.have.property('error', 'Invalid Chainpoint version - ' + badVersionNumberReceipt.header.chainpoint_version);
    });

});

describe("Using missingHashTypeReceipt - ", function () {

    var missingHashTypeReceipt = {
        "header": {
            "chainpoint_version": "1.1"
        }
    };

    var result = validator.isValidReceipt(missingHashTypeReceipt);
    it("should receive error - missing hashtype", function () {
        result.should.have.property('isValid', false);
        result.should.have.property('error', 'Missing hash type');
    });

});

describe("Using badHashTypeReceipt - ", function () {

    var badHashTypeReceipt = {
        "header": {
            "chainpoint_version": "1.1",
            "hash_type": "sha1"
        }
    };

    var result = validator.isValidReceipt(badHashTypeReceipt);
    it("should receive error - bad hashtype", function () {
        result.should.have.property('isValid', false);
        result.should.have.property('error', 'Invalid hash type - ' + badHashTypeReceipt.header.hash_type);
    });

});

describe("Using missingRootReceipt - ", function () {

    var missingRootReceipt = {
        "header": {
            "chainpoint_version": "1.1",
            "hash_type": "SHA-256"
        }
    };

    var result = validator.isValidReceipt(missingRootReceipt);
    it("should receive error - missing merkle root", function () {
        result.should.have.property('isValid', false);
        result.should.have.property('error', 'Missing merkle root');
    });

});

describe("Using badRootReceipt - ", function () {

    var badRootReceipt = {
        "header": {
            "chainpoint_version": "1.1",
            "hash_type": "SHA-256",
            "merkle_root": "bad-non-hash-value"
        }
    };

    var result = validator.isValidReceipt(badRootReceipt);
    it("should receive error - bad merkle root", function () {
        result.should.have.property('isValid', false);
        result.should.have.property('error', 'Invalid merkle root - ' + badRootReceipt.header.merkle_root);
    });

});

describe("Using missingTxReceipt - ", function () {

    var missingTxReceipt = {
        "header": {
            "chainpoint_version": "1.1",
            "hash_type": "SHA-256",
            "merkle_root": "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404"
        }
    };

    var result = validator.isValidReceipt(missingTxReceipt);
    it("should receive error - missing txId", function () {
        result.should.have.property('isValid', false);
        result.should.have.property('error', 'Missing transaction Id');
    });

});

describe("Using badTxReceipt - ", function () {

    var badTxReceipt = {
        "header": {
            "chainpoint_version": "1.1",
            "hash_type": "SHA-256",
            "merkle_root": "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404",
            "tx_id": "bad-tx-id-value"
        }
    };

    var result = validator.isValidReceipt(badTxReceipt);
    it("should receive error - bad txId", function () {
        result.should.have.property('isValid', false);
        result.should.have.property('error', 'Invalid transaction Id - ' + badTxReceipt.header.tx_id);
    });

});

describe("Using missingTimestampReceipt - ", function () {

    var missingTimestampReceipt = {
        "header": {
            "chainpoint_version": "1.1",
            "hash_type": "SHA-256",
            "merkle_root": "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404",
            "tx_id": "6d14a219a9aef975377bad9236cbc4e1e062cb5dd29b3dd3c1a1cb63540c1c9a"
        }
    };

    var result = validator.isValidReceipt(missingTimestampReceipt);
    it("should receive error - missing timestamp", function () {
        result.should.have.property('isValid', false);
        result.should.have.property('error', 'Missing timestamp');
    });

});

describe("Using badTimestampReceipt - ", function () {

    var badTimestampReceipt = {
        "header": {
            "chainpoint_version": "1.1",
            "hash_type": "SHA-256",
            "merkle_root": "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404",
            "tx_id": "6d14a219a9aef975377bad9236cbc4e1e062cb5dd29b3dd3c1a1cb63540c1c9a",
            "timestamp": "sdfsdf"
        }
    };

    var result = validator.isValidReceipt(badTimestampReceipt);
    it("should receive error - bad timestamp", function () {
        result.should.have.property('isValid', false);
        result.should.have.property('error', 'Invalid timestamp - ' + badTimestampReceipt.header.timestamp);
    });

});



var noProofReceipt = {
    "header": {
        "chainpoint_version": "1.1",
        "hash_type": "SHA-256",
        "merkle_root": "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404",
        "tx_id": "6d14a219a9aef975377bad9236cbc4e1e062cb5dd29b3dd3c1a1cb63540c1c9a",
        "timestamp": 1462888815
    },
    "target": {
        "target_hash": "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404",
        "target_proof": []
    }
};
