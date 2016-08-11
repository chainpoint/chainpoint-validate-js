var should = require('should');
var chainpointvalidate = require('../chainpointvalidate.js');


describe("Testing v1.x receipts - ", function () {

    describe("Using nullReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var nullReceipt = null;
        it("should receive error - bad Json", function (done) {
            chainpointValidate.isValidReceipt(nullReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Cannot parse receipt JSON');
                done();
            });
        });

    });

    describe("Using stringReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var stringReceipt = 'dfsgsfgxcvbasfdg';
        it("should receive error - bad Json", function (done) {
            chainpointValidate.isValidReceipt(stringReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Cannot parse receipt JSON');
                done();
            });
        });

    });

    describe("Using numberReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var numberReceipt = 435345;
        it("should receive error - unknown version", function (done) {
            chainpointValidate.isValidReceipt(numberReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Cannot identify Chainpoint version');
                done();
            });
        });

    });

    describe("Using emptyReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var emptyReceipt = {};
        it("should receive error - unknown version", function (done) {
            chainpointValidate.isValidReceipt(emptyReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Cannot identify Chainpoint version');
                done();
            });
        });

    });

    describe("Using junkReceiptObject - ", function () {

        var chainpointValidate = chainpointvalidate();
        var junkReceiptObject = { 'sdf': 23424 };
        it("should receive error - unknown version", function (done) {
            chainpointValidate.isValidReceipt(junkReceiptObject, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Cannot identify Chainpoint version');
                done();
            });
        });

    });

    describe("Using junkReceiptString - ", function () {

        var chainpointValidate = chainpointvalidate();
        var junkReceiptString = '{ "sdf": 23424 }';
        it("should receive error - unknown version", function (done) {
            chainpointValidate.isValidReceipt(junkReceiptString, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Cannot identify Chainpoint version');
                done();
            });
        });

    });

    describe("Using badVersionNumberReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var badVersionNumberReceipt = {
            "header": {
                "chainpoint_version": "0.9"
            }
        };

        it("should receive error - bad version", function (done) {
            chainpointValidate.isValidReceipt(badVersionNumberReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid Chainpoint version - ' + badVersionNumberReceipt.header.chainpoint_version);
                done();
            });

        });
    });

    describe("Using missingHashTypeReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var missingHashTypeReceipt = {
            "header": {
                "chainpoint_version": "1.1"
            }
        };

        it("should receive error - missing hashtype", function (done) {
            chainpointValidate.isValidReceipt(missingHashTypeReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Missing hash type');
                done();
            });
        });

    });

    describe("Using badHashTypeReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var badHashTypeReceipt = {
            "header": {
                "chainpoint_version": "1.1",
                "hash_type": "sha1"
            }
        };

        it("should receive error - bad hashtype", function (done) {
            chainpointValidate.isValidReceipt(badHashTypeReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid hash type - ' + badHashTypeReceipt.header.hash_type);
                done();
            });
        });

    });

    describe("Using missingRootReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var missingRootReceipt = {
            "header": {
                "chainpoint_version": "1.1",
                "hash_type": "SHA-256"
            }
        };

        it("should receive error - missing merkle root", function (done) {
            chainpointValidate.isValidReceipt(missingRootReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Missing merkle root');
                done();
            });
        });

    });

    describe("Using badRootReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var badRootReceipt = {
            "header": {
                "chainpoint_version": "1.1",
                "hash_type": "SHA-256",
                "merkle_root": "bad-non-hash-value"
            }
        };

        it("should receive error - bad merkle root", function (done) {
            chainpointValidate.isValidReceipt(badRootReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid merkle root - ' + badRootReceipt.header.merkle_root);
                done();
            });
        });

    });

    describe("Using missingTxReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var missingTxReceipt = {
            "header": {
                "chainpoint_version": "1.1",
                "hash_type": "SHA-256",
                "merkle_root": "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404"
            }
        };

        it("should receive error - missing txId", function (done) {
            chainpointValidate.isValidReceipt(missingTxReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Missing transaction Id');
                done();
            });
        });

    });

    describe("Using badTxReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var badTxReceipt = {
            "header": {
                "chainpoint_version": "1.1",
                "hash_type": "SHA-256",
                "merkle_root": "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404",
                "tx_id": "bad-tx-id-value"
            }
        };

        it("should receive error - bad txId", function (done) {
            chainpointValidate.isValidReceipt(badTxReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid transaction Id - ' + badTxReceipt.header.tx_id);
                done();
            });
        });

    });

    describe("Using missingTimestampReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var missingTimestampReceipt = {
            "header": {
                "chainpoint_version": "1.1",
                "hash_type": "SHA-256",
                "merkle_root": "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404",
                "tx_id": "6d14a219a9aef975377bad9236cbc4e1e062cb5dd29b3dd3c1a1cb63540c1c9a"
            }
        };

        it("should receive error - missing timestamp", function (done) {
            chainpointValidate.isValidReceipt(missingTimestampReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Missing timestamp');
                done();
            });
        });

    });

    describe("Using badTimestampReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var badTimestampReceipt = {
            "header": {
                "chainpoint_version": "1.1",
                "hash_type": "SHA-256",
                "merkle_root": "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404",
                "tx_id": "6d14a219a9aef975377bad9236cbc4e1e062cb5dd29b3dd3c1a1cb63540c1c9a",
                "timestamp": "sdfsdf"
            }
        };

        it("should receive error - bad timestamp", function (done) {
            chainpointValidate.isValidReceipt(badTimestampReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid timestamp - ' + badTimestampReceipt.header.timestamp);
                done();
            });
        });

    });

    describe("Using noTargetReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var noTargetReceipt = {
            "header": {
                "chainpoint_version": "1.1",
                "hash_type": "SHA-256",
                "merkle_root": "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404",
                "tx_id": "6d14a219a9aef975377bad9236cbc4e1e062cb5dd29b3dd3c1a1cb63540c1c9a",
                "timestamp": 1458126637
            }
        };

        it("should receive error - missing target", function (done) {
            chainpointValidate.isValidReceipt(noTargetReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Missing target');
                done();
            });
        });

    });

    describe("Using missingTargethashReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var missingTargethashReceipt = {
            "header": {
                "chainpoint_version": "1.1",
                "hash_type": "SHA-256",
                "merkle_root": "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404",
                "tx_id": "6d14a219a9aef975377bad9236cbc4e1e062cb5dd29b3dd3c1a1cb63540c1c9a",
                "timestamp": 1458126637
            },
            "target": {}
        };

        it("should receive error - missing target hash", function (done) {
            chainpointValidate.isValidReceipt(missingTargethashReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Missing target hash');
                done();
            });
        });

    });

    describe("Using badTargethashReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var badTargethashReceipt = {
            "header": {
                "chainpoint_version": "1.1",
                "hash_type": "SHA-256",
                "merkle_root": "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404",
                "tx_id": "6d14a219a9aef975377bad9236cbc4e1e062cb5dd29b3dd3c1a1cb63540c1c9a",
                "timestamp": 1458126637
            },
            "target": {
                "target_hash": "badhash"
            }
        };

        it("should receive error - bad target hash", function (done) {
            chainpointValidate.isValidReceipt(badTargethashReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid target hash - ' + badTargethashReceipt.target.target_hash);
                done();
            });
        });

    });

    describe("Using missingTargetproofReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var missingTargetproofReceipt = {
            "header": {
                "chainpoint_version": "1.1",
                "hash_type": "SHA-256",
                "merkle_root": "f17fbe8fc1a6e5a8289da6fea45d16a92b35c629fa1fd34178245420378bea19",
                "tx_id": "278277644b955a34bb087759773f80169738420f3e9ffb3206efb71d018d5502",
                "timestamp": 1463018411
            },
            "target": {
                "target_hash": "f17fbe8fc1a6e5a8289da6fea45d16a92b35c629fa1fd34178245420378bea19"
            }
        };

        it("should receive error - missing target proof", function (done) {
            chainpointValidate.isValidReceipt(missingTargetproofReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Missing target proof');
                done();
            });
        });

    });

    describe("Using badproofReceipt null - ", function () {

        var chainpointValidate = chainpointvalidate();
        var badproofReceipt = {
            "header": {
                "chainpoint_version": "1.1",
                "hash_type": "SHA-256",
                "merkle_root": "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404",
                "tx_id": "6d14a219a9aef975377bad9236cbc4e1e062cb5dd29b3dd3c1a1cb63540c1c9a",
                "timestamp": 1458126637
            },
            "target": {
                "target_hash": "f17fbe8fc1a6e5a8289da6fea45d16a92b35c629fa1fd34178245420378bea19",
                "target_proof": null
            }
        };

        it("should receive error - bad target proof", function (done) {
            chainpointValidate.isValidReceipt(badproofReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Missing target proof');
                done();
            });
        });
    });

    describe("Using badproofReceipt empty string- ", function () {

        var chainpointValidate = chainpointvalidate();
        var badproofReceipt = {
            "header": {
                "chainpoint_version": "1.1",
                "hash_type": "SHA-256",
                "merkle_root": "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404",
                "tx_id": "6d14a219a9aef975377bad9236cbc4e1e062cb5dd29b3dd3c1a1cb63540c1c9a",
                "timestamp": 1458126637
            },
            "target": {
                "target_hash": "f17fbe8fc1a6e5a8289da6fea45d16a92b35c629fa1fd34178245420378bea19",
                "target_proof": ""
            }
        };

        it("should receive error - bad target proof", function (done) {
            chainpointValidate.isValidReceipt(badproofReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Missing target proof');
                done();
            });
        });
    });

    describe("Using badproofReceipt dsfgdfg- ", function () {

        var chainpointValidate = chainpointvalidate();
        var badproofReceipt = {
            "header": {
                "chainpoint_version": "1.1",
                "hash_type": "SHA-256",
                "merkle_root": "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404",
                "tx_id": "6d14a219a9aef975377bad9236cbc4e1e062cb5dd29b3dd3c1a1cb63540c1c9a",
                "timestamp": 1458126637
            },
            "target": {
                "target_hash": "f17fbe8fc1a6e5a8289da6fea45d16a92b35c629fa1fd34178245420378bea19",
                "target_proof": "dsfgdfg"
            }
        };

        it("should receive error - bad target proof", function (done) {
            chainpointValidate.isValidReceipt(badproofReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid target proof - ' + badproofReceipt.target.target_proof);
                done();
            });
        });
    });

    describe("Using badproofReceipt {}- ", function () {

        var chainpointValidate = chainpointvalidate();
        var badproofReceipt = {
            "header": {
                "chainpoint_version": "1.1",
                "hash_type": "SHA-256",
                "merkle_root": "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404",
                "tx_id": "6d14a219a9aef975377bad9236cbc4e1e062cb5dd29b3dd3c1a1cb63540c1c9a",
                "timestamp": 1458126637
            },
            "target": {
                "target_hash": "f17fbe8fc1a6e5a8289da6fea45d16a92b35c629fa1fd34178245420378bea19",
                "target_proof": {}
            }
        };

        it("should receive error - bad target proof", function (done) {
            chainpointValidate.isValidReceipt(badproofReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid target proof - ' + badproofReceipt.target.target_proof);
                done();
            });
        });
    });

    describe("Using badproofReceipt bad object with value- ", function () {

        var chainpointValidate = chainpointvalidate();
        var badproofReceipt = {
            "header": {
                "chainpoint_version": "1.1",
                "hash_type": "SHA-256",
                "merkle_root": "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404",
                "tx_id": "6d14a219a9aef975377bad9236cbc4e1e062cb5dd29b3dd3c1a1cb63540c1c9a",
                "timestamp": 1458126637
            },
            "target": {
                "target_hash": "f17fbe8fc1a6e5a8289da6fea45d16a92b35c629fa1fd34178245420378bea19",
                "target_proof": { "parent": "something" }
            }
        };

        it("should receive error - bad target proof", function (done) {
            chainpointValidate.isValidReceipt(badproofReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid target proof - ' + badproofReceipt.target.target_proof);
                done();
            });
        });
    });


    describe("Using emptyProofInvalidReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var emptyProofInvalidReceipt = {
            "header": {
                "chainpoint_version": "1.1",
                "hash_type": "SHA-256",
                "merkle_root": "f17fbe8fc1a6e5a8289da6fea45d16a92b35c629fa1fd34178245420378bea19",
                "tx_id": "278277644b955a34bb087759773f80169738420f3e9ffb3206efb71d018d5502",
                "timestamp": 1463018411
            },
            "target": {
                "target_hash": "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404",
                "target_proof": []
            }
        };

        it("should receive error - invalid proof path", function (done) {
            chainpointValidate.isValidReceipt(emptyProofInvalidReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid proof path');
                done();
            });
        });

    });

    describe("Using invalidWithProofReceipt - missing proof[0].parent", function () {

        var chainpointValidate = chainpointvalidate();
        var invalidWithProofReceipt = { // missing proof[0].parent
            "header": {
                "chainpoint_version": "1.1",
                "hash_type": "SHA-256",
                "merkle_root": "5faa75ca2c838ceac7fb1b62127cfba51f011813c6c491335c2b69d54dd7d79c",
                "tx_id": "b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09",
                "timestamp": 1445033433
            },
            "target": {
                "target_hash": "cbda53ca51a184b366cbde3cb026987c53021de26fa5aabf814917c894769b65",
                "target_proof": [
                    {
                        "left": "cbda53ca51a184b366cbde3cb026987c53021de26fa5aabf814917c894769b65",
                        "right": "a52d9c0a0b077237f58c7e5b8b38d2dd7756176ca379947a093105574a465685"
                    },
                    {
                        "parent": "5faa75ca2c838ceac7fb1b62127cfba51f011813c6c491335c2b69d54dd7d79c",
                        "left": "4f0398f4707c7ddb8d5a85508bdaa9e22fb541fa0182ae54f25513b6bd3f8cb9",
                        "right": "3bd99c8660a226a62a7df1efc2a296a398ad91e2aa56d68fefd08571a853096e"
                    }
                ]
            }
        };

        it("should be invalid proof path", function (done) {
            chainpointValidate.isValidReceipt(invalidWithProofReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid proof path');
                done();
            });
        });
    });

    describe("Using invalidWithProofReceipt - proof[0].right invalid", function () {

        var chainpointValidate = chainpointvalidate();
        var invalidWithProofReceipt = { // proof[0].right invalid
            "header": {
                "chainpoint_version": "1.1",
                "hash_type": "SHA-256",
                "merkle_root": "5faa75ca2c838ceac7fb1b62127cfba51f011813c6c491335c2b69d54dd7d79c",
                "tx_id": "b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09",
                "timestamp": 1445033433
            },
            "target": {
                "target_hash": "cbda53ca51a184b366cbde3cb026987c53021de26fa5aabf814917c894769b65",
                "target_proof": [
                    {
                        "parent": "4f0398f4707c7ddb8d5a85508bdaa9e22fb541fa0182ae54f25513b6bd3f8cb9",
                        "left": "cbda53ca51a184b366cbde3cb026987c53021de26fa5aabf814917c894769b65",
                        "right": "cvbcvb"
                    },
                    {
                        "parent": "5faa75ca2c838ceac7fb1b62127cfba51f011813c6c491335c2b69d54dd7d79c",
                        "left": "4f0398f4707c7ddb8d5a85508bdaa9e22fb541fa0182ae54f25513b6bd3f8cb9",
                        "right": "3bd99c8660a226a62a7df1efc2a296a398ad91e2aa56d68fefd08571a853096e"
                    }
                ]
            }
        };

        it("should be invalid proof path", function (done) {
            chainpointValidate.isValidReceipt(invalidWithProofReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid proof path');
                done();
            });
        });
    });

    describe("Using invalidWithProofReceipt - parent != HASH(l+r)", function () {

        var chainpointValidate = chainpointvalidate();
        var invalidWithProofReceipt = { // parent != HASH(l+r)
            "header": {
                "chainpoint_version": "1.1",
                "hash_type": "SHA-256",
                "merkle_root": "5faa75ca2c838ceac7fb1b62127cfba51f011813c6c491335c2b69d54dd7d79c",
                "tx_id": "b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09",
                "timestamp": 1445033433
            },
            "target": {
                "target_hash": "cbda53ca51a184b366cbde3cb026987c53021de26fa5aabf814917c894769b65",
                "target_proof": [
                    {
                        "parent": "4f0398f4707c7ddb8d5a85508bdaa9e22fb541fa0182ae54f25513b6bd3f8cb9",
                        "left": "bbda53ca51a184b366cbde3cb026987c53021de26fa5aabf814917c894769b65",
                        "right": "b52d9c0a0b077237f58c7e5b8b38d2dd7756176ca379947a093105574a465685"
                    },
                    {
                        "parent": "5faa75ca2c838ceac7fb1b62127cfba51f011813c6c491335c2b69d54dd7d79c",
                        "left": "4f0398f4707c7ddb8d5a85508bdaa9e22fb541fa0182ae54f25513b6bd3f8cb9",
                        "right": "3bd99c8660a226a62a7df1efc2a296a398ad91e2aa56d68fefd08571a853096e"
                    }
                ]
            }
        };

        it("should be invalid proof path", function (done) {
            chainpointValidate.isValidReceipt(invalidWithProofReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid proof path');
                done();
            });
        });
    });

    describe("Using invalidWithProofReceipt - target hash not in proof[0]", function () {

        var chainpointValidate = chainpointvalidate();
        var invalidWithProofReceipt = { // target hash not in proof[0]
            "header": {
                "chainpoint_version": "1.1",
                "hash_type": "SHA-256",
                "merkle_root": "5faa75ca2c838ceac7fb1b62127cfba51f011813c6c491335c2b69d54dd7d79c",
                "tx_id": "b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09",
                "timestamp": 1445033433
            },
            "target": {
                "target_hash": "11da53ca51a184b366cbde3cb026987c53021de26fa5aabf814917c894769b65",
                "target_proof": [
                    {
                        "parent": "4f0398f4707c7ddb8d5a85508bdaa9e22fb541fa0182ae54f25513b6bd3f8cb9",
                        "left": "cbda53ca51a184b366cbde3cb026987c53021de26fa5aabf814917c894769b65",
                        "right": "a52d9c0a0b077237f58c7e5b8b38d2dd7756176ca379947a093105574a465685"
                    },
                    {
                        "parent": "5faa75ca2c838ceac7fb1b62127cfba51f011813c6c491335c2b69d54dd7d79c",
                        "left": "4f0398f4707c7ddb8d5a85508bdaa9e22fb541fa0182ae54f25513b6bd3f8cb9",
                        "right": "3bd99c8660a226a62a7df1efc2a296a398ad91e2aa56d68fefd08571a853096e"
                    }
                ]
            }
        };

        it("should be invalid proof path", function (done) {
            chainpointValidate.isValidReceipt(invalidWithProofReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid proof path');
                done();
            });
        });
    });

    describe("Using invalidWithProofReceipt - proof[1].left missing", function () {

        var chainpointValidate = chainpointvalidate();
        var invalidWithProofReceipt = { //proof[1].left missing
            "header": {
                "chainpoint_version": "1.1",
                "hash_type": "SHA-256",
                "merkle_root": "5faa75ca2c838ceac7fb1b62127cfba51f011813c6c491335c2b69d54dd7d79c",
                "tx_id": "b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09",
                "timestamp": 1445033433
            },
            "target": {
                "target_hash": "cbda53ca51a184b366cbde3cb026987c53021de26fa5aabf814917c894769b65",
                "target_proof": [
                    {
                        "parent": "4f0398f4707c7ddb8d5a85508bdaa9e22fb541fa0182ae54f25513b6bd3f8cb9",
                        "left": "cbda53ca51a184b366cbde3cb026987c53021de26fa5aabf814917c894769b65",
                        "right": "a52d9c0a0b077237f58c7e5b8b38d2dd7756176ca379947a093105574a465685"
                    },
                    {
                        "parent": "5faa75ca2c838ceac7fb1b62127cfba51f011813c6c491335c2b69d54dd7d79c",
                        "right": "3bd99c8660a226a62a7df1efc2a296a398ad91e2aa56d68fefd08571a853096e"
                    }
                ]
            }
        };

        it("should be invalid proof path", function (done) {
            chainpointValidate.isValidReceipt(invalidWithProofReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid proof path');
                done();
            });
        });
    });

    describe("Using invalidWithProofReceipt - previous parent not in proof[1]", function () {

        var chainpointValidate = chainpointvalidate();
        var invalidWithProofReceipt = { // previous parent not in proof[1]
            "header": {
                "chainpoint_version": "1.1",
                "hash_type": "SHA-256",
                "merkle_root": "5faa75ca2c838ceac7fb1b62127cfba51f011813c6c491335c2b69d54dd7d79c",
                "tx_id": "b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09",
                "timestamp": 1445033433
            },
            "target": {
                "target_hash": "cbda53ca51a184b366cbde3cb026987c53021de26fa5aabf814917c894769b65",
                "target_proof": [
                    {
                        "parent": "4f0398f4707c7ddb8d5a85508bdaa9e22fb541fa0182ae54f25513b6bd3f8cb9",
                        "left": "cbda53ca51a184b366cbde3cb026987c53021de26fa5aabf814917c894769b65",
                        "right": "a52d9c0a0b077237f58c7e5b8b38d2dd7756176ca379947a093105574a465685"
                    },
                    {
                        "parent": "5faa75ca2c838ceac7fb1b62127cfba51f011813c6c491335c2b69d54dd7d79c",
                        "left": "5f0398f4707c7ddb8d5a85508bdaa9e22fb541fa0182ae54f25513b6bd3f8cb9",
                        "right": "3bd99c8660a226a62a7df1efc2a296a398ad91e2aa56d68fefd08571a853096e"
                    }
                ]
            }
        };

        it("should be invalid proof path", function (done) {
            chainpointValidate.isValidReceipt(invalidWithProofReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid proof path');
                done();
            });
        });
    });

    describe("Using invalidWithProofReceipt - proof[1].parent != hash(l+r)", function () {

        var chainpointValidate = chainpointvalidate();
        var invalidWithProofReceipt = { // proof[1].parent != hash(l+r)
            "header": {
                "chainpoint_version": "1.1",
                "hash_type": "SHA-256",
                "merkle_root": "5faa75ca2c838ceac7fb1b62127cfba51f011813c6c491335c2b69d54dd7d79c",
                "tx_id": "b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09",
                "timestamp": 1445033433
            },
            "target": {
                "target_hash": "cbda53ca51a184b366cbde3cb026987c53021de26fa5aabf814917c894769b65",
                "target_proof": [
                    {
                        "parent": "4f0398f4707c7ddb8d5a85508bdaa9e22fb541fa0182ae54f25513b6bd3f8cb9",
                        "left": "cbda53ca51a184b366cbde3cb026987c53021de26fa5aabf814917c894769b65",
                        "right": "a52d9c0a0b077237f58c7e5b8b38d2dd7756176ca379947a093105574a465685"
                    },
                    {
                        "parent": "5faa75ca2c838ceac7fb1b62127cfba51f011813c6c491335c2b69d54dd7d79c",
                        "left": "4f0398f4707c7ddb8d5a85508bdaa9e22fb541fa0182ae54f25513b6bd3f8cb9",
                        "right": "2bd99c8660a226a62a7df1efc2a296a398ad91e2aa56d68fefd08571a853096e"
                    }
                ]
            }
        };

        it("should be invalid proof path", function (done) {
            chainpointValidate.isValidReceipt(invalidWithProofReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid proof path');
                done();
            });
        });
    });

    describe("Using invalidWithProofReceipt - proof[1].parent != merkle root", function () {

        var chainpointValidate = chainpointvalidate();
        var invalidWithProofReceipt = { // proof[1].parent != merkle root
            "header": {
                "chainpoint_version": "1.1",
                "hash_type": "SHA-256",
                "merkle_root": "6faa75ca2c838ceac7fb1b62127cfba51f011813c6c491335c2b69d54dd7d79c",
                "tx_id": "b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09",
                "timestamp": 1445033433
            },
            "target": {
                "target_hash": "cbda53ca51a184b366cbde3cb026987c53021de26fa5aabf814917c894769b65",
                "target_proof": [
                    {
                        "parent": "4f0398f4707c7ddb8d5a85508bdaa9e22fb541fa0182ae54f25513b6bd3f8cb9",
                        "left": "cbda53ca51a184b366cbde3cb026987c53021de26fa5aabf814917c894769b65",
                        "right": "a52d9c0a0b077237f58c7e5b8b38d2dd7756176ca379947a093105574a465685"
                    },
                    {
                        "parent": "5faa75ca2c838ceac7fb1b62127cfba51f011813c6c491335c2b69d54dd7d79c",
                        "left": "4f0398f4707c7ddb8d5a85508bdaa9e22fb541fa0182ae54f25513b6bd3f8cb9",
                        "right": "3bd99c8660a226a62a7df1efc2a296a398ad91e2aa56d68fefd08571a853096e"
                    }
                ]
            }
        };

        it("should be invalid proof path", function (done) {
            chainpointValidate.isValidReceipt(invalidWithProofReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid proof path');
                done();
            });
        });
    });

    describe("Using validEmptyProofReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var validEmptyProofReceipt = {
            "header": {
                "chainpoint_version": "1.1",
                "hash_type": "SHA-256",
                "merkle_root": "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404",
                "tx_id": "6d14a219a9aef975377bad9236cbc4e1e062cb5dd29b3dd3c1a1cb63540c1c9a",
                "timestamp": 1463018411
            },
            "target": {
                "target_hash": "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404",
                "target_proof": []
            }
        };

        it("should be considered valid", function (done) {
            chainpointValidate.isValidReceipt(validEmptyProofReceipt, false, function (err, result) {
                result.should.have.property('isValid', true);
                result.should.have.property('merkleRoot', "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404");
                result.should.have.property('anchors');
                result.anchors.should.be.instanceof(Array).and.have.lengthOf(1);
                result.anchors[0].should.have.property('type', 'BTCOpReturn');
                result.anchors[0].should.have.property('sourceId', '6d14a219a9aef975377bad9236cbc4e1e062cb5dd29b3dd3c1a1cb63540c1c9a');
                result.should.not.have.property('error');
                done();
            });
        });

    });

    describe("Using validWithProofReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var validWithProofReceipt = {
            "header": {
                "chainpoint_version": "1.1",
                "hash_type": "SHA-256",
                "merkle_root": "5faa75ca2c838ceac7fb1b62127cfba51f011813c6c491335c2b69d54dd7d79c",
                "tx_id": "b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09",
                "timestamp": 1445033433
            },
            "target": {
                "target_hash": "cbda53ca51a184b366cbde3cb026987c53021de26fa5aabf814917c894769b65",
                "target_proof": [
                    {
                        "parent": "4f0398f4707c7ddb8d5a85508bdaa9e22fb541fa0182ae54f25513b6bd3f8cb9",
                        "left": "cbda53ca51a184b366cbde3cb026987c53021de26fa5aabf814917c894769b65",
                        "right": "a52d9c0a0b077237f58c7e5b8b38d2dd7756176ca379947a093105574a465685"
                    },
                    {
                        "parent": "5faa75ca2c838ceac7fb1b62127cfba51f011813c6c491335c2b69d54dd7d79c",
                        "left": "4f0398f4707c7ddb8d5a85508bdaa9e22fb541fa0182ae54f25513b6bd3f8cb9",
                        "right": "3bd99c8660a226a62a7df1efc2a296a398ad91e2aa56d68fefd08571a853096e"
                    }
                ]
            }
        };

        it("should be considered valid", function (done) {
            chainpointValidate.isValidReceipt(validWithProofReceipt, false, function (err, result) {
                result.should.have.property('isValid', true);
                result.should.have.property('merkleRoot', "5faa75ca2c838ceac7fb1b62127cfba51f011813c6c491335c2b69d54dd7d79c");
                result.should.have.property('anchors');
                result.anchors.should.be.instanceof(Array).and.have.lengthOf(1);
                result.anchors[0].should.have.property('type', 'BTCOpReturn');
                result.anchors[0].should.have.property('sourceId', 'b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09');
                result.should.not.have.property('error');
                done();
            });

        });
    });

    describe("Using invalidWithProofReceiptString empty- ", function () {

        var chainpointValidate = chainpointvalidate();
        var invalidWithProofReceiptString = "";

        it("should be unparsable", function (done) {
            chainpointValidate.isValidReceipt("invalidWithProofReceiptString", false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Cannot parse receipt JSON');
                done();
            });
        });

    });

    describe("Using invalidWithProofReceiptString - bad", function () {

        var chainpointValidate = chainpointvalidate();
        var invalidWithProofReceiptString = "dfgdfgdfg";

        it("should be unparsable", function (done) {
            chainpointValidate.isValidReceipt("invalidWithProofReceiptString", false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Cannot parse receipt JSON');
                done();
            });

        });
    });

    describe("Using validWithProofReceiptString - ", function () {

        var chainpointValidate = chainpointvalidate();
        var validWithProofReceiptString = "{\"header\": {\n                \"chainpoint_version\": \"1.1\",\n                \"hash_type\": \"SHA-256\",\n                \"merkle_root\": \"5faa75ca2c838ceac7fb1b62127cfba51f011813c6c491335c2b69d54dd7d79c\",\n                \"tx_id\": \"b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09\",\n                \"timestamp\": 1445033433\n            },\n            \"target\": {\n                \"target_hash\": \"cbda53ca51a184b366cbde3cb026987c53021de26fa5aabf814917c894769b65\",\n                \"target_proof\": [\n                    {\n                        \"parent\": \"4f0398f4707c7ddb8d5a85508bdaa9e22fb541fa0182ae54f25513b6bd3f8cb9\",\n                        \"left\": \"cbda53ca51a184b366cbde3cb026987c53021de26fa5aabf814917c894769b65\",\n                        \"right\": \"a52d9c0a0b077237f58c7e5b8b38d2dd7756176ca379947a093105574a465685\"\n                    },\n                    {\n                        \"parent\": \"5faa75ca2c838ceac7fb1b62127cfba51f011813c6c491335c2b69d54dd7d79c\",\n                        \"left\": \"4f0398f4707c7ddb8d5a85508bdaa9e22fb541fa0182ae54f25513b6bd3f8cb9\",\n                        \"right\": \"3bd99c8660a226a62a7df1efc2a296a398ad91e2aa56d68fefd08571a853096e\"\n                    }\n                ]\n            }\n        }";

        it("should be considered valid", function (done) {
            chainpointValidate.isValidReceipt(validWithProofReceiptString, false, function (err, result) {
                result.should.have.property('isValid', true);
                result.should.have.property('merkleRoot', "5faa75ca2c838ceac7fb1b62127cfba51f011813c6c491335c2b69d54dd7d79c");
                result.should.have.property('anchors');
                result.anchors.should.be.instanceof(Array).and.have.lengthOf(1);
                result.anchors[0].should.have.property('type', 'BTCOpReturn');
                result.anchors[0].should.have.property('sourceId', 'b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09');
                result.should.not.have.property('error');
                done();
            });
        });

    });

    describe("Using validWithProofReceiptwithConfirmationBad - ", function () {

        var chainpointValidate = chainpointvalidate();
        var receipt = {
            "header": {
                "chainpoint_version": "1.1",
                "hash_type": "SHA-256",
                "merkle_root": "5faa75ca2c838ceac7fb1b62127cfba51f011813c6c491335c2b69d54dd7d79c",
                "tx_id": "aa4a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09",
                "timestamp": 1445033433
            },
            "target": {
                "target_hash": "cbda53ca51a184b366cbde3cb026987c53021de26fa5aabf814917c894769b65",
                "target_proof": [
                    {
                        "parent": "4f0398f4707c7ddb8d5a85508bdaa9e22fb541fa0182ae54f25513b6bd3f8cb9",
                        "left": "cbda53ca51a184b366cbde3cb026987c53021de26fa5aabf814917c894769b65",
                        "right": "a52d9c0a0b077237f58c7e5b8b38d2dd7756176ca379947a093105574a465685"
                    },
                    {
                        "parent": "5faa75ca2c838ceac7fb1b62127cfba51f011813c6c491335c2b69d54dd7d79c",
                        "left": "4f0398f4707c7ddb8d5a85508bdaa9e22fb541fa0182ae54f25513b6bd3f8cb9",
                        "right": "3bd99c8660a226a62a7df1efc2a296a398ad91e2aa56d68fefd08571a853096e"
                    }
                ]
            }
        };


        it("should be considered valid, bad anchor", function (done) {
            chainpointValidate.isValidReceipt(receipt, true, function (err, result) {
                result.should.have.property('isValid', true);
                result.should.have.property('merkleRoot', "5faa75ca2c838ceac7fb1b62127cfba51f011813c6c491335c2b69d54dd7d79c");
                result.should.have.property('anchors');
                result.anchors.should.be.instanceof(Array).and.have.lengthOf(1);
                result.anchors[0].should.have.property('type', 'BTCOpReturn');
                result.anchors[0].should.have.property('sourceId', 'aa4a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09');
                result.anchors[0].should.have.property('exists', false);
                result.should.not.have.property('error');
                done();
            });
        });

    });

    describe("Using validWithProofReceiptwithConfirmationOK - ", function () {

        var chainpointValidate = chainpointvalidate();
        var receipt = {
            "header": {
                "chainpoint_version": "1.1",
                "hash_type": "SHA-256",
                "merkle_root": "1d5c6418eb821aca1d34fac7ee5ec490541860a0ef1c99f3ba2c7b1d00dbe607",
                "tx_id": "2cabd868b1baca2060f93eb7ea7ece24ec4e01d04a18945b91a77b381ac7a14c",
                "timestamp": 1453781412
            },
            "target": {
                "target_hash": "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
                "target_proof": [
                    {
                        "parent": "1d5c6418eb821aca1d34fac7ee5ec490541860a0ef1c99f3ba2c7b1d00dbe607",
                        "left": "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
                        "right": "23f67820feaca41c22ae3c836a1548508c478ee6f1999f850c3a5b0e860e26b6"
                    }
                ]
            }
        };


        it("should be considered valid, bad anchor", function (done) {
            chainpointValidate.isValidReceipt(receipt, true, function (err, result) {
                result.should.have.property('isValid', true);
                result.should.have.property('merkleRoot', "1d5c6418eb821aca1d34fac7ee5ec490541860a0ef1c99f3ba2c7b1d00dbe607");
                result.should.have.property('anchors');
                result.anchors.should.be.instanceof(Array).and.have.lengthOf(1);
                result.anchors[0].should.have.property('type', 'BTCOpReturn');
                result.anchors[0].should.have.property('sourceId', '2cabd868b1baca2060f93eb7ea7ece24ec4e01d04a18945b91a77b381ac7a14c');
                result.anchors[0].should.have.property('exists', true);
                result.should.not.have.property('error');
                done();
            });
        });
    });

    describe("Using validNoProofReceiptwithConfirmationOK - ", function () {

        var chainpointValidate = chainpointvalidate();
        var receipt = {
            "header": {
                "chainpoint_version": "1.1",
                "hash_type": "SHA-256",
                "merkle_root": "17a2c1ebd89886f3118237a09f47ee237fd5b5d3df996d431e41573a4131d7db",
                "tx_id": "786463d911de1507fd774d216149caa4bcac1b2393f5a865022058dd0c37f793",
                "timestamp": 1453808412
            },
            "target": {
                "target_hash": "17a2c1ebd89886f3118237a09f47ee237fd5b5d3df996d431e41573a4131d7db",
                "target_proof": []
            }
        };


        it("should be considered valid, bad anchor", function (done) {
            chainpointValidate.isValidReceipt(receipt, true, function (err, result) {
                result.should.have.property('isValid', true);
                result.should.have.property('merkleRoot', "17a2c1ebd89886f3118237a09f47ee237fd5b5d3df996d431e41573a4131d7db");
                result.should.have.property('anchors');
                result.anchors.should.be.instanceof(Array).and.have.lengthOf(1);
                result.anchors[0].should.have.property('type', 'BTCOpReturn');
                result.anchors[0].should.have.property('sourceId', '786463d911de1507fd774d216149caa4bcac1b2393f5a865022058dd0c37f793');
                result.anchors[0].should.have.property('exists', true);
                result.should.not.have.property('error');
                done();
            });
        });
    });
});

describe("Testing v2.x receipts - ", function () {

    describe("Using badVersionNumberReceiptA - ", function () {

        var chainpointValidate = chainpointvalidate();
        var badVersionNumberReceipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "type": "ChainpointSHA256v35"
        };

        it("should receive error - bad version", function (done) {
            chainpointValidate.isValidReceipt(badVersionNumberReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid Chainpoint type - ' + badVersionNumberReceipt.type);
                done();
            });
        });

    });

    describe("Using badVersionNumberReceiptB - ", function () {

        var chainpointValidate = chainpointvalidate();
        var badVersionNumberReceipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA256v35"
        };

        it("should receive error - bad version", function (done) {
            chainpointValidate.isValidReceipt(badVersionNumberReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid Chainpoint type - ' + badVersionNumberReceipt['@type']);
                done();
            });
        });

    });

    describe("Using missingHashTypeReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var missingHashTypeReceipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "Chainpointv2"
        };

        it("should receive error - missing hashtype", function (done) {
            chainpointValidate.isValidReceipt(missingHashTypeReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid Chainpoint type - ' + missingHashTypeReceipt['@type']);
                done();
            });
        });

    });

    describe("Using badHashTypeReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var badHashTypeReceipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA2048v2"
        };

        it("should receive error - bad hashtype", function (done) {
            chainpointValidate.isValidReceipt(badHashTypeReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid Chainpoint type - ' + badHashTypeReceipt['@type']);
                done();
            });
        });

    });

    describe("Using missingTargethashReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var missingTargethashReceipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA256v2"
        };

        it("should receive error - missing target hash", function (done) {
            chainpointValidate.isValidReceipt(missingTargethashReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Missing target hash');
                done();
            });
        });

    });

    describe("Using badTargethashReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var badTargethashReceipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA256v2",
            "targetHash": "badhash"
        };

        it("should receive error - bad target hash", function (done) {
            chainpointValidate.isValidReceipt(badTargethashReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid target hash - badhash');
                done();
            });
        });

    });

    describe("Using missingRootReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var missingRootReceipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA256v2",
            "targetHash": "f17fbe8fc1a6e5a8289da6fea45d16a92b35c629fa1fd34178245420378bea19"
        };

        it("should receive error - missing merkle root", function (done) {
            chainpointValidate.isValidReceipt(missingRootReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Missing merkle root');
                done();
            });
        });

    });

    describe("Using badRootReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var badRootReceipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA256v2",
            "targetHash": "f17fbe8fc1a6e5a8289da6fea45d16a92b35c629fa1fd34178245420378bea19",
            "merkleRoot": "badroothash"
        };

        it("should receive error - bad merkle root", function (done) {
            chainpointValidate.isValidReceipt(badRootReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid merkle root - badroothash');
                done();
            });
        });

    });

    describe("Using missingTargetproofReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var missingTargetproofReceipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA256v2",
            "targetHash": "f17fbe8fc1a6e5a8289da6fea45d16a92b35c629fa1fd34178245420378bea19",
            "merkleRoot": "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404"
        };

        it("should receive error - missing target proof", function (done) {
            chainpointValidate.isValidReceipt(missingTargetproofReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Missing proof');
                done();
            });
        });

    });

    describe("Using badproofReceipt null - ", function () {

        var chainpointValidate = chainpointvalidate();
        var badproofReceipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA256v2",
            "targetHash": "f17fbe8fc1a6e5a8289da6fea45d16a92b35c629fa1fd34178245420378bea19",
            "merkleRoot": "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404",
            "proof": null
        };

        it("should receive error - bad target proof", function (done) {
            chainpointValidate.isValidReceipt(badproofReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Missing proof');
                done();
            });
        });
    });

    describe("Using badproofReceipt empty string- ", function () {

        var chainpointValidate = chainpointvalidate();
        var badproofReceipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA256v2",
            "targetHash": "f17fbe8fc1a6e5a8289da6fea45d16a92b35c629fa1fd34178245420378bea19",
            "merkleRoot": "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404",
            "proof": ""
        };

        it("should receive error - bad target proof", function (done) {
            chainpointValidate.isValidReceipt(badproofReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Missing proof');
                done();
            });
        });
    });

    describe("Using badproofReceipt dsfgdfg- ", function () {

        var chainpointValidate = chainpointvalidate();
        var badproofReceipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA256v2",
            "targetHash": "f17fbe8fc1a6e5a8289da6fea45d16a92b35c629fa1fd34178245420378bea19",
            "merkleRoot": "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404",
            "proof": "dfgdfg"
        };

        it("should receive error - bad target proof", function (done) {
            chainpointValidate.isValidReceipt(badproofReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid proof - ' + badproofReceipt.proof);
                done();
            });
        });
    });

    describe("Using badproofReceipt {}- ", function () {

        var chainpointValidate = chainpointvalidate();
        var badproofReceipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA256v2",
            "targetHash": "f17fbe8fc1a6e5a8289da6fea45d16a92b35c629fa1fd34178245420378bea19",
            "merkleRoot": "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404",
            "proof": {}
        };

        it("should receive error - bad target proof", function (done) {
            chainpointValidate.isValidReceipt(badproofReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid proof - ' + badproofReceipt.proof);
                done();
            });
        });
    });

    describe("Using badproofReceipt bad object with value- ", function () {

        var chainpointValidate = chainpointvalidate();
        var badproofReceipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA256v2",
            "targetHash": "f17fbe8fc1a6e5a8289da6fea45d16a92b35c629fa1fd34178245420378bea19",
            "merkleRoot": "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404",
            "proof": { parent: "something" }
        };

        it("should receive error - bad target proof", function (done) {
            chainpointValidate.isValidReceipt(badproofReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid proof - ' + badproofReceipt.proof);
                done();
            });
        });
    });

    describe("Using emptyProofInvalidReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var emptyProofInvalidReceipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA256v2",
            "targetHash": "f17fbe8fc1a6e5a8289da6fea45d16a92b35c629fa1fd34178245420378bea19",
            "merkleRoot": "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404",
            "proof": []
        };

        it("should receive error - invalid proof path", function (done) {
            chainpointValidate.isValidReceipt(emptyProofInvalidReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid proof path');
                done();
            });
        });

    });

    describe("Using invalidWithProofReceipt - missing left or right designation", function () {

        var chainpointValidate = chainpointvalidate();
        var emptyProofInvalidReceipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA256v2",
            "targetHash": "f17fbe8fc1a6e5a8289da6fea45d16a92b35c629fa1fd34178245420378bea19",
            "merkleRoot": "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404",
            "proof": [{ parent: "something" }]
        };

        it("should receive error - invalid proof path", function (done) {
            chainpointValidate.isValidReceipt(emptyProofInvalidReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid proof path');
                done();
            });
        });
    });

    describe("Using invalidWithProofReceipt - proof[0].right invalid", function () {

        var chainpointValidate = chainpointvalidate();
        var emptyProofInvalidReceipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA256v2",
            "targetHash": "f17fbe8fc1a6e5a8289da6fea45d16a92b35c629fa1fd34178245420378bea19",
            "merkleRoot": "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404",
            "proof": [{ right: "something" }]
        };

        it("should receive error - invalid proof path", function (done) {
            chainpointValidate.isValidReceipt(emptyProofInvalidReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid proof path');
                done();
            });
        });
    });

    describe("Using invalidWithProofReceipt - root != HASH(target+p0)", function () {

        var chainpointValidate = chainpointvalidate();
        var emptyProofInvalidReceipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA256v2",
            "targetHash": "f17fbe8fc1a6e5a8289da6fea45d16a92b35c629fa1fd34178245420378bea19",
            "merkleRoot": "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404",
            "proof": [{ right: "a99fbe8fc1a6e5a8289da6fea45d16a92b35c629fa1fd34178245420378bea19" }]
        };

        it("should receive error - invalid proof path", function (done) {
            chainpointValidate.isValidReceipt(emptyProofInvalidReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid proof path');
                done();
            });
        });
    });

    describe("Using invalidWithProofReceipt - proof[1] invalid", function () {

        var chainpointValidate = chainpointvalidate();
        var emptyProofInvalidReceipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA256v2",
            "targetHash": "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d",
            "merkleRoot": "d71f8983ad4ee170f8129f1ebcdd7440be7798d8e1c80420bf11f1eced610dba",
            "proof": [{ left: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb" },
                { right: "b00e0b34dba16bc6fac17c08bac55d676cded5a4ade41fe2c9924a5dde8f3e5b" },
                { right: "3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea" }]
        };

        it("should receive error - invalid proof path", function (done) {
            chainpointValidate.isValidReceipt(emptyProofInvalidReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid proof path');
                done();
            });
        });
    });

    describe("Using invalidWithProofReceipt - proof[2] invalid", function () {

        var chainpointValidate = chainpointvalidate();
        var emptyProofInvalidReceipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA256v2",
            "targetHash": "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d",
            "merkleRoot": "d71f8983ad4ee170f8129f1ebcdd7440be7798d8e1c80420bf11f1eced610dba",
            "proof": [{ left: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb" },
                { right: "bffe0b34dba16bc6fac17c08bac55d676cded5a4ade41fe2c9924a5dde8f3e5b" },
                { right: "3009bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea" }]
        };

        it("should receive error - invalid proof path", function (done) {
            chainpointValidate.isValidReceipt(emptyProofInvalidReceipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid proof path');
                done();
            });
        });
    });

    describe("Using missingAnchorsReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var receipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA256v2",
            "targetHash": "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d",
            "merkleRoot": "d71f8983ad4ee170f8129f1ebcdd7440be7798d8e1c80420bf11f1eced610dba",
            "proof": [{ left: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb" },
                { right: "bffe0b34dba16bc6fac17c08bac55d676cded5a4ade41fe2c9924a5dde8f3e5b" },
                { right: "3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea" }]
        };

        it("should receive error - missing anchors", function (done) {
            chainpointValidate.isValidReceipt(receipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Missing anchors');
                done();
            });
        });
    });

    describe("Using badanchorsReceipt null - ", function () {

        var chainpointValidate = chainpointvalidate();
        var receipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA256v2",
            "targetHash": "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d",
            "merkleRoot": "d71f8983ad4ee170f8129f1ebcdd7440be7798d8e1c80420bf11f1eced610dba",
            "proof": [{ left: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb" },
                { right: "bffe0b34dba16bc6fac17c08bac55d676cded5a4ade41fe2c9924a5dde8f3e5b" },
                { right: "3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea" }],
            "anchors": null
        };

        it("should receive error - invalid anchors array", function (done) {
            chainpointValidate.isValidReceipt(receipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Missing anchors');
                done();
            });
        });
    });

    describe("Using badanchorsReceipt empty string- ", function () {

        var chainpointValidate = chainpointvalidate();
        var receipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA256v2",
            "targetHash": "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d",
            "merkleRoot": "d71f8983ad4ee170f8129f1ebcdd7440be7798d8e1c80420bf11f1eced610dba",
            "proof": [{ left: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb" },
                { right: "bffe0b34dba16bc6fac17c08bac55d676cded5a4ade41fe2c9924a5dde8f3e5b" },
                { right: "3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea" }],
            "anchors": ""
        };

        it("should receive error - invalid anchors array", function (done) {
            chainpointValidate.isValidReceipt(receipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Missing anchors');
                done();
            });
        });
    });

    describe("Using badanchorsReceipt dsfgdfg- ", function () {

        var chainpointValidate = chainpointvalidate();
        var receipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA256v2",
            "targetHash": "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d",
            "merkleRoot": "d71f8983ad4ee170f8129f1ebcdd7440be7798d8e1c80420bf11f1eced610dba",
            "proof": [{ left: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb" },
                { right: "bffe0b34dba16bc6fac17c08bac55d676cded5a4ade41fe2c9924a5dde8f3e5b" },
                { right: "3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea" }],
            "anchors": "dfgdfg"
        };

        it("should receive error - invalid anchors array", function (done) {
            chainpointValidate.isValidReceipt(receipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid anchors array - ' + receipt.anchors);
                done();
            });
        });
    });

    describe("Using badanchorsReceipt {}- ", function () {

        var chainpointValidate = chainpointvalidate();
        var receipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA256v2",
            "targetHash": "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d",
            "merkleRoot": "d71f8983ad4ee170f8129f1ebcdd7440be7798d8e1c80420bf11f1eced610dba",
            "proof": [{ left: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb" },
                { right: "bffe0b34dba16bc6fac17c08bac55d676cded5a4ade41fe2c9924a5dde8f3e5b" },
                { right: "3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea" }],
            "anchors": {}
        };

        it("should receive error - invalid anchors array", function (done) {
            chainpointValidate.isValidReceipt(receipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid anchors array - ' + receipt.anchors);
                done();
            });
        });
    });

    describe("Using badanchorReceipt bad object with value- ", function () {

        var chainpointValidate = chainpointvalidate();
        var receipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA256v2",
            "targetHash": "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d",
            "merkleRoot": "d71f8983ad4ee170f8129f1ebcdd7440be7798d8e1c80420bf11f1eced610dba",
            "proof": [{ left: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb" },
                { right: "bffe0b34dba16bc6fac17c08bac55d676cded5a4ade41fe2c9924a5dde8f3e5b" },
                { right: "3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea" }],
            "anchors": { something: "something" }
        };

        it("should receive error - invalid anchors array", function (done) {
            chainpointValidate.isValidReceipt(receipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid anchors array - ' + receipt.anchors);
                done();
            });
        });
    });

    describe("Using emptyAnchorsInvalidReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var receipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA256v2",
            "targetHash": "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d",
            "merkleRoot": "d71f8983ad4ee170f8129f1ebcdd7440be7798d8e1c80420bf11f1eced610dba",
            "proof": [{ left: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb" },
                { right: "bffe0b34dba16bc6fac17c08bac55d676cded5a4ade41fe2c9924a5dde8f3e5b" },
                { right: "3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea" }],
            "anchors": []
        };

        it("should receive error - empty anchors array", function (done) {
            chainpointValidate.isValidReceipt(receipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Empty anchors array');
                done();
            });
        });

    });

    describe("Using missingtypeAnchorsInvalidReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var receipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA256v2",
            "targetHash": "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d",
            "merkleRoot": "d71f8983ad4ee170f8129f1ebcdd7440be7798d8e1c80420bf11f1eced610dba",
            "proof": [{ left: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb" },
                { right: "bffe0b34dba16bc6fac17c08bac55d676cded5a4ade41fe2c9924a5dde8f3e5b" },
                { right: "3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea" }],
            "anchors": [{ something: "something" }]
        };

        it("should receive error - Missing anchor type", function (done) {
            chainpointValidate.isValidReceipt(receipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Missing anchor type');
                done();
            });
        });

    });

    describe("Using invalidtypeAnchorsInvalidReceipt A - ", function () {

        var chainpointValidate = chainpointvalidate();
        var receipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA256v2",
            "targetHash": "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d",
            "merkleRoot": "d71f8983ad4ee170f8129f1ebcdd7440be7798d8e1c80420bf11f1eced610dba",
            "proof": [{ left: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb" },
                { right: "bffe0b34dba16bc6fac17c08bac55d676cded5a4ade41fe2c9924a5dde8f3e5b" },
                { right: "3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea" }],
            "anchors": [{ type: "something" }]
        };

        it("should receive error - invalid anchor type", function (done) {
            chainpointValidate.isValidReceipt(receipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid anchor type - ' + receipt.anchors[0].type);
                done();
            });
        });

    });

    describe("Using invalidtypeAnchorsInvalidReceipt B - ", function () {

        var chainpointValidate = chainpointvalidate();
        var receipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA256v2",
            "targetHash": "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d",
            "merkleRoot": "d71f8983ad4ee170f8129f1ebcdd7440be7798d8e1c80420bf11f1eced610dba",
            "proof": [{ left: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb" },
                { right: "bffe0b34dba16bc6fac17c08bac55d676cded5a4ade41fe2c9924a5dde8f3e5b" },
                { right: "3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea" }],
            "anchors": [{ "@type": "something" }]
        };

        it("should receive error - invalid anchor type", function (done) {
            chainpointValidate.isValidReceipt(receipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid anchor type - ' + receipt.anchors[0]["@type"]);
                done();
            });
        });

    });

    describe("Using missingsourceAnchorsInvalidReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var receipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA256v2",
            "targetHash": "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d",
            "merkleRoot": "d71f8983ad4ee170f8129f1ebcdd7440be7798d8e1c80420bf11f1eced610dba",
            "proof": [{ left: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb" },
                { right: "bffe0b34dba16bc6fac17c08bac55d676cded5a4ade41fe2c9924a5dde8f3e5b" },
                { right: "3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea" }],
            "anchors": [{ "@type": "BTCOpReturn" }]
        };

        it("should receive error - Missing anchor type", function (done) {
            chainpointValidate.isValidReceipt(receipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Missing sourceId');
                done();
            });
        });
    });

    describe("Using invalidsourceAnchorsInvalidReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var receipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA256v2",
            "targetHash": "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d",
            "merkleRoot": "d71f8983ad4ee170f8129f1ebcdd7440be7798d8e1c80420bf11f1eced610dba",
            "proof": [{ left: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb" },
                { right: "bffe0b34dba16bc6fac17c08bac55d676cded5a4ade41fe2c9924a5dde8f3e5b" },
                { right: "3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea" }],
            "anchors": [{ "@type": "BTCOpReturn", "sourceId": [{ sdf: "Dfgdfg" }] }]
        };

        it("should receive error - Invalid anchor type", function (done) {
            chainpointValidate.isValidReceipt(receipt, false, function (err, result) {
                result.should.have.property('isValid', false);
                result.should.have.property('error', 'Invalid sourceId for BTCOpReturn - ' + receipt.anchors[0].sourceId);
                done();
            });
        });

    });

    describe("Using validEmptyProofReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var receipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA256v2",
            "targetHash": "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404",
            "merkleRoot": "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404",
            "proof": [],
            "anchors": [{ "@type": "BTCOpReturn", "sourceId": "6d14a219a9aef975377bad9236cbc4e1e062cb5dd29b3dd3c1a1cb63540c1c9a" }]
        };

        it("should be considered valid", function (done) {
            chainpointValidate.isValidReceipt(receipt, false, function (err, result) {
                result.should.have.property('isValid', true);
                result.should.have.property('merkleRoot', "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404");
                result.should.have.property('anchors');
                result.anchors.should.be.instanceof(Array).and.have.lengthOf(1);
                result.anchors[0].should.have.property('@type', 'BTCOpReturn');
                result.anchors[0].should.have.property('sourceId', '6d14a219a9aef975377bad9236cbc4e1e062cb5dd29b3dd3c1a1cb63540c1c9a');
                result.anchors[0].should.not.have.property('exists');
                result.should.not.have.property('error');
                done();
            });
        });

    });

    describe("Using validWithProofReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var receipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA256v2",
            "targetHash": "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d",
            "merkleRoot": "d71f8983ad4ee170f8129f1ebcdd7440be7798d8e1c80420bf11f1eced610dba",
            "proof": [{ left: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb" },
                { right: "bffe0b34dba16bc6fac17c08bac55d676cded5a4ade41fe2c9924a5dde8f3e5b" },
                { right: "3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea" }],
            "anchors": [{ "type": "BTCOpReturn", "sourceId": "b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09" }]
        };

        it("should be considered valid", function (done) {
            chainpointValidate.isValidReceipt(receipt, false, function (err, result) {
                result.should.have.property('isValid', true);
                result.should.have.property('merkleRoot', "d71f8983ad4ee170f8129f1ebcdd7440be7798d8e1c80420bf11f1eced610dba");
                result.should.have.property('anchors');
                result.anchors.should.be.instanceof(Array).and.have.lengthOf(1);
                result.anchors[0].should.have.property('type', 'BTCOpReturn');
                result.anchors[0].should.have.property('sourceId', 'b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09');
                result.anchors[0].should.not.have.property('exists');
                result.should.not.have.property('error');
                done();
            });
        });

    });

    describe("Using validWithProofReceiptString - ", function () {

        var chainpointValidate = chainpointvalidate();
        var receiptString = "{\n            \"@context\": \"https://w3id.org/chainpoint/v2\",\n            \"@type\": \"ChainpointSHA256v2\",\n            \"targetHash\": \"3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d\",\n            \"merkleRoot\": \"d71f8983ad4ee170f8129f1ebcdd7440be7798d8e1c80420bf11f1eced610dba\",\n            \"proof\": [{ \"left\": \"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb\" },\n                { \"right\": \"bffe0b34dba16bc6fac17c08bac55d676cded5a4ade41fe2c9924a5dde8f3e5b\" },\n                { \"right\": \"3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea\" }],\n            \"anchors\": [{ \"type\": \"BTCOpReturn\", \"sourceId\": \"b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09\" }]\n        }";

        it("should be considered valid", function (done) {
            chainpointValidate.isValidReceipt(receiptString, false, function (err, result) {
                result.should.have.property('isValid', true);
                result.should.have.property('merkleRoot', "d71f8983ad4ee170f8129f1ebcdd7440be7798d8e1c80420bf11f1eced610dba");
                result.should.have.property('anchors');
                result.anchors.should.be.instanceof(Array).and.have.lengthOf(1);
                result.anchors[0].should.have.property('type', 'BTCOpReturn');
                result.anchors[0].should.have.property('sourceId', 'b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09');
                result.anchors[0].should.not.have.property('exists');
                result.should.not.have.property('error');
                done();
            });
        });

    });

    describe("Using validWithProofReceiptwithConfirmationBad - ", function () {

        var chainpointValidate = chainpointvalidate();
        var receipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA256v2",
            "targetHash": "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d",
            "merkleRoot": "d71f8983ad4ee170f8129f1ebcdd7440be7798d8e1c80420bf11f1eced610dba",
            "proof": [{ left: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb" },
                { right: "bffe0b34dba16bc6fac17c08bac55d676cded5a4ade41fe2c9924a5dde8f3e5b" },
                { right: "3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea" }],
            "anchors": [{ "type": "BTCOpReturn", "sourceId": "b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09" }]
        };


        it("should be considered valid", function (done) {
            chainpointValidate.isValidReceipt(receipt, true, function (err, result) {
                result.should.have.property('isValid', true);
                result.should.have.property('merkleRoot', "d71f8983ad4ee170f8129f1ebcdd7440be7798d8e1c80420bf11f1eced610dba");
                result.should.have.property('anchors');
                result.anchors.should.be.instanceof(Array).and.have.lengthOf(1);
                result.anchors[0].should.have.property('type', 'BTCOpReturn');
                result.anchors[0].should.have.property('sourceId', 'b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09');
                result.anchors[0].should.have.property('exists', false);
                result.should.not.have.property('error');
                done();
            });
        });

    });

    describe("Using validWithProofReceiptwithConfirmationOK - ", function () {

        var chainpointValidate = chainpointvalidate();
        var receipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA256v2",
            "targetHash": "5faa75ca2c838ceac7fb1b62127cfba51f011813c6c491335c2b69d54dd7d79c",
            "merkleRoot": "5faa75ca2c838ceac7fb1b62127cfba51f011813c6c491335c2b69d54dd7d79c",
            "proof": [],
            "anchors": [{ "type": "BTCOpReturn", "sourceId": "b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09" }]
        };

        it("should be considered valid", function (done) {
            chainpointValidate.isValidReceipt(receipt, true, function (err, result) {
                result.should.have.property('isValid', true);
                result.should.have.property('merkleRoot', "5faa75ca2c838ceac7fb1b62127cfba51f011813c6c491335c2b69d54dd7d79c");
                result.should.have.property('anchors');
                result.anchors.should.be.instanceof(Array).and.have.lengthOf(1);
                result.anchors[0].should.have.property('type', 'BTCOpReturn');
                result.anchors[0].should.have.property('sourceId', 'b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09');
                result.anchors[0].should.have.property('exists', true);
                result.should.not.have.property('error');
                done();
            });
        });
    });


});

describe("Testing v2.x simple receipt Hash Types - ", function () {

    describe("Using SHA224 validWithProofReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var receipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA224v2",
            "targetHash": "90a3ed9e32b2aaf4c61c410eb925426119e1a9dc53d4286ade99a809",
            "merkleRoot": "f48bc49bb77d3a3b1c8f8a70db693f41d879189cd1919f8326067ad7",
            "proof": [{ right: "35f757ad7f998eb6dd3dd1cd3b5c6de97348b84a951f13de25355177" }],
            "anchors": [{ "type": "BTCOpReturn", "sourceId": "b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09" }]
        };

        it("should be considered valid", function (done) {
            chainpointValidate.isValidReceipt(receipt, false, function (err, result) {
                result.should.have.property('isValid', true);
                result.should.have.property('merkleRoot', "f48bc49bb77d3a3b1c8f8a70db693f41d879189cd1919f8326067ad7");
                result.should.have.property('anchors');
                result.anchors.should.be.instanceof(Array).and.have.lengthOf(1);
                result.anchors[0].should.have.property('type', 'BTCOpReturn');
                result.anchors[0].should.have.property('sourceId', 'b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09');
                result.anchors[0].should.not.have.property('exists');
                result.should.not.have.property('error');
                done();
            });
        });

    });

    describe("Using SHA256 validWithProofReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var receipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA256v2",
            "targetHash": "1516f000de6cff5c8c63eef081ebcec2ad2fdcf7034db16045d024a90341e07d",
            "merkleRoot": "77c654b3d1605f78ed091cbd420c939c3feff7d57dc30c171fa45a5a3c81fd7d",
            "proof": [{ right: "e20af19f85f265579ead2578859bf089c92b76a048606983ad83f27ba8f32f1a" }],
            "anchors": [{ "type": "BTCOpReturn", "sourceId": "b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09" }]
        };

        it("should be considered valid", function (done) {
            chainpointValidate.isValidReceipt(receipt, false, function (err, result) {
                result.should.have.property('isValid', true);
                result.should.have.property('merkleRoot', "77c654b3d1605f78ed091cbd420c939c3feff7d57dc30c171fa45a5a3c81fd7d");
                result.should.have.property('anchors');
                result.anchors.should.be.instanceof(Array).and.have.lengthOf(1);
                result.anchors[0].should.have.property('type', 'BTCOpReturn');
                result.anchors[0].should.have.property('sourceId', 'b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09');
                result.anchors[0].should.not.have.property('exists');
                result.should.not.have.property('error');
                done();
            });
        });

    });

    describe("Using SHA384 validWithProofReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var receipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA384v2",
            "targetHash": "84ae8c6367d64899aef44a951edfa4833378b9e213f916c5eb8492cc37cb951c726e334dace7dbe4bb1dc80c1efe33d0",
            "merkleRoot": "c363aa3b824e3f3b927034fab826eff61a9bfa2030ae9fc4598992edf9f3e42f8b497d6742946caf7a771429eb1745cf",
            "proof": [{ right: "368c89a00446010def75ad7b179cea9a3d24f8cbb7e2755a28638d194809e7b614eb45453665032860b6c1a135fb6e8b" }],
            "anchors": [{ "type": "BTCOpReturn", "sourceId": "b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09" }]
        };

        it("should be considered valid", function (done) {
            chainpointValidate.isValidReceipt(receipt, false, function (err, result) {
                result.should.have.property('isValid', true);
                result.should.have.property('merkleRoot', "c363aa3b824e3f3b927034fab826eff61a9bfa2030ae9fc4598992edf9f3e42f8b497d6742946caf7a771429eb1745cf");
                result.should.have.property('anchors');
                result.anchors.should.be.instanceof(Array).and.have.lengthOf(1);
                result.anchors[0].should.have.property('type', 'BTCOpReturn');
                result.anchors[0].should.have.property('sourceId', 'b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09');
                result.anchors[0].should.not.have.property('exists');
                result.should.not.have.property('error');
                done();
            });
        });

    });

    describe("Using SHA512 validWithProofReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var receipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA512v2",
            "targetHash": "c0a8907588c1da716ce31cbef05da1a65986ec23afb75cd42327634dd53d754be6c00a22d6862a42be5f51187a8dff695c530a797f7704e4eb4b473a14ab416e",
            "merkleRoot": "d9d27704a3a785d204257bfa2b217a1890e55453b6686f091fa1be8aa2b265bc06c285a909459996e093546677c3f392458d7b1fc34a994a86689ed4100e8337",
            "proof": [{ right: "df1e07eccb2a2d4e1b30d11e646ba13ddc426c1aefbefcff3639405762f216fdcc40a684f3d1855e6d465f99fd9547e53fa8a485f18649fedec5448b45963976" }],
            "anchors": [{ "type": "BTCOpReturn", "sourceId": "b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09" }]
        };

        it("should be considered valid", function (done) {
            chainpointValidate.isValidReceipt(receipt, false, function (err, result) {
                result.should.have.property('isValid', true);
                result.should.have.property('merkleRoot', "d9d27704a3a785d204257bfa2b217a1890e55453b6686f091fa1be8aa2b265bc06c285a909459996e093546677c3f392458d7b1fc34a994a86689ed4100e8337");
                result.should.have.property('anchors');
                result.anchors.should.be.instanceof(Array).and.have.lengthOf(1);
                result.anchors[0].should.have.property('type', 'BTCOpReturn');
                result.anchors[0].should.have.property('sourceId', 'b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09');
                result.anchors[0].should.not.have.property('exists');
                result.should.not.have.property('error');
                done();
            });
        });

    });

    describe("Using SHA3-224 validWithProofReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var receipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA3-224v2",
            "targetHash": "6ed712b9472b671fd70bb950dc4ccfce197c92a7969f6bc2aa6b6d9f",
            "merkleRoot": "674bc9f53d5c666174cdd3ccb9df04768dfb7759655e7d937aef0c3a",
            "proof": [{ right: "08db5633d406804d044a3e67683e179b5ee51249ed2139c239d1e65a" }],
            "anchors": [{ "type": "BTCOpReturn", "sourceId": "b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09" }]
        };

        it("should be considered valid", function (done) {
            chainpointValidate.isValidReceipt(receipt, false, function (err, result) {
                result.should.have.property('isValid', true);
                result.should.have.property('merkleRoot', "674bc9f53d5c666174cdd3ccb9df04768dfb7759655e7d937aef0c3a");
                result.should.have.property('anchors');
                result.anchors.should.be.instanceof(Array).and.have.lengthOf(1);
                result.anchors[0].should.have.property('type', 'BTCOpReturn');
                result.anchors[0].should.have.property('sourceId', 'b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09');
                result.anchors[0].should.not.have.property('exists');
                result.should.not.have.property('error');
                done();
            });
        });

    });

    describe("Using SHA3-256 validWithProofReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var receipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA3-256v2",
            "targetHash": "1d7d4ea1cc029ca460e486642830c284657ea0921235c46298b51f0ed1bb7bf7",
            "merkleRoot": "6edf674f5ce762e096c3081aee2a0a977732e07f4d704baf34f5e3804db03343",
            "proof": [{ right: "89b9e14eae37e999b096a6f604adefe7feea4dc240ccecb5e4e92785cffc7070" }],
            "anchors": [{ "type": "BTCOpReturn", "sourceId": "b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09" }]
        };

        it("should be considered valid", function (done) {
            chainpointValidate.isValidReceipt(receipt, false, function (err, result) {
                result.should.have.property('isValid', true);
                result.should.have.property('merkleRoot', "6edf674f5ce762e096c3081aee2a0a977732e07f4d704baf34f5e3804db03343");
                result.should.have.property('anchors');
                result.anchors.should.be.instanceof(Array).and.have.lengthOf(1);
                result.anchors[0].should.have.property('type', 'BTCOpReturn');
                result.anchors[0].should.have.property('sourceId', 'b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09');
                result.anchors[0].should.not.have.property('exists');
                result.should.not.have.property('error');
                done();
            });
        });

    });

    describe("Using SHA3-384 validWithProofReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var receipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA3-384v2",
            "targetHash": "e222605f939aa69b964a0a03d7075676bb3dbb40c3bd10b22f0adcb149434e7c1085c206f0e3371470a49817aa6d5b16",
            "merkleRoot": "bd54df0015fa0d4fee713fbf5c8ae232c93239c75fb9d41c7dd7a9278711764a6ee83c81766b3945ed94030254537b57",
            "proof": [{ right: "ae331b6f8643ed7e404471c81be9a74f73fc84ffd5140a0ec9aa8596fa0d0a2ded5f7b780bb2fbfc4e2226ee2a04a2fa" }],
            "anchors": [{ "type": "BTCOpReturn", "sourceId": "b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09" }]
        };

        it("should be considered valid", function (done) {
            chainpointValidate.isValidReceipt(receipt, false, function (err, result) {
                result.should.have.property('isValid', true);
                result.should.have.property('merkleRoot', "bd54df0015fa0d4fee713fbf5c8ae232c93239c75fb9d41c7dd7a9278711764a6ee83c81766b3945ed94030254537b57");
                result.should.have.property('anchors');
                result.anchors.should.be.instanceof(Array).and.have.lengthOf(1);
                result.anchors[0].should.have.property('type', 'BTCOpReturn');
                result.anchors[0].should.have.property('sourceId', 'b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09');
                result.anchors[0].should.not.have.property('exists');
                result.should.not.have.property('error');
                done();
            });
        });

    });

    describe("Using SHA3-512 validWithProofReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var receipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA3-512v2",
            "targetHash": "004a237ea808cd9375ee9db9f85625948a890c54e2c30f736f54c969074eb56f0ff3d43dafb4b40d5d974acc1c2a68c046fa4d7c2c20cab6df956514040d0b8b",
            "merkleRoot": "3dff3f19b67628591d294cba2c07ed20d20d83e1624af8c1dca8fcf096127b9f86435e2d6a84ca4cee526525cacd1c628bf06ee938983413afafbb4598c5862a",
            "proof": [{ right: "0b43a85d08c05252d0e23c96bc6b1bda11dfa787049ff452b3c86f4c6135e870c058c05131f199ef8619cfac937a736bbc936a667e4d96a5bf68e4056ce5fdce" }],
            "anchors": [{ "type": "BTCOpReturn", "sourceId": "b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09" }]
        };

        it("should be considered valid", function (done) {
            chainpointValidate.isValidReceipt(receipt, false, function (err, result) {
                result.should.have.property('isValid', true);
                result.should.have.property('merkleRoot', "3dff3f19b67628591d294cba2c07ed20d20d83e1624af8c1dca8fcf096127b9f86435e2d6a84ca4cee526525cacd1c628bf06ee938983413afafbb4598c5862a");
                result.should.have.property('anchors');
                result.anchors.should.be.instanceof(Array).and.have.lengthOf(1);
                result.anchors[0].should.have.property('type', 'BTCOpReturn');
                result.anchors[0].should.have.property('sourceId', 'b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09');
                result.anchors[0].should.not.have.property('exists');
                result.should.not.have.property('error');
                done();
            });
        });

    });



});


