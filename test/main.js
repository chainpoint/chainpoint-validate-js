var should = require('should');
var chainpointvalidator = require('../chainpointvalidator.js');

describe("Testing v1.x receipts - ", function () {

    describe("Using nullReceipt - ", function () {

        var validator = chainpointvalidator();
        var nullReceipt = null;
        var result = validator.isValidReceipt(nullReceipt);
        it("should receive error - bad Json", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Cannot parse receipt JSON');
        });

    });

    describe("Using stringReceipt - ", function () {

        var validator = chainpointvalidator();
        var stringReceipt = 'dfsgsfgxcvbasfdg';
        var result = validator.isValidReceipt(stringReceipt);
        it("should receive error - bad Json", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Cannot parse receipt JSON');
        });

    });

    describe("Using numberReceipt - ", function () {

        var validator = chainpointvalidator();
        var numberReceipt = 435345;
        var result = validator.isValidReceipt(numberReceipt);
        it("should receive error - unknown version", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Cannot identify Chainpoint version');
        });

    });

    describe("Using emptyReceipt - ", function () {

        var validator = chainpointvalidator();
        var emptyReceipt = {};
        var result = validator.isValidReceipt(emptyReceipt);
        it("should receive error - unknown version", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Cannot identify Chainpoint version');
        });

    });

    describe("Using junkReceiptObject - ", function () {

        var validator = chainpointvalidator();
        var junkReceiptObject = { 'sdf': 23424 };
        var result = validator.isValidReceipt(junkReceiptObject);
        it("should receive error - unknown version", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Cannot identify Chainpoint version');
        });

    });

    describe("Using junkReceiptString - ", function () {

        var validator = chainpointvalidator();
        var junkReceiptString = '{ "sdf": 23424 }';
        var result = validator.isValidReceipt(junkReceiptString);
        it("should receive error - unknown version", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Cannot identify Chainpoint version');
        });

    });

    describe("Using badVersionNumberReceipt - ", function () {

        var validator = chainpointvalidator();
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

        var validator = chainpointvalidator();
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

        var validator = chainpointvalidator();
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

        var validator = chainpointvalidator();
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

        var validator = chainpointvalidator();
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

        var validator = chainpointvalidator();
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

        var validator = chainpointvalidator();
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

        var validator = chainpointvalidator();
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

        var validator = chainpointvalidator();
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

    describe("Using noTargetReceipt - ", function () {

        var validator = chainpointvalidator();
        var noTargetReceipt = {
            "header": {
                "chainpoint_version": "1.1",
                "hash_type": "SHA-256",
                "merkle_root": "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404",
                "tx_id": "6d14a219a9aef975377bad9236cbc4e1e062cb5dd29b3dd3c1a1cb63540c1c9a",
                "timestamp": 1458126637
            }
        };

        var result = validator.isValidReceipt(noTargetReceipt);
        it("should receive error - missing target", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Missing target');
        });

    });

    describe("Using missingTargethashReceipt - ", function () {

        var validator = chainpointvalidator();
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

        var result = validator.isValidReceipt(missingTargethashReceipt);
        it("should receive error - missing target hash", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Missing target hash');
        });

    });

    describe("Using badTargethashReceipt - ", function () {

        var validator = chainpointvalidator();
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

        var result = validator.isValidReceipt(badTargethashReceipt);
        it("should receive error - bad target hash", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid target hash - ' + badTargethashReceipt.target.target_hash);
        });

    });

    describe("Using missingTargetproofReceipt - ", function () {

        var validator = chainpointvalidator();
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

        var result = validator.isValidReceipt(missingTargetproofReceipt);
        it("should receive error - missing target proof", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Missing target proof');
        });

    });

    describe("Using badproofReceipt null - ", function () {

        var validator = chainpointvalidator();
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

        var result = validator.isValidReceipt(badproofReceipt);
        it("should receive error - bad target proof", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Missing target proof');
        });
    });

    describe("Using badproofReceipt empty string- ", function () {

        var validator = chainpointvalidator();
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

        var result = validator.isValidReceipt(badproofReceipt);
        it("should receive error - bad target proof", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Missing target proof');
        });
    });

    describe("Using badproofReceipt dsfgdfg- ", function () {

        var validator = chainpointvalidator();
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

        var result = validator.isValidReceipt(badproofReceipt);
        it("should receive error - bad target proof", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid target proof - ' + badproofReceipt.target.target_proof);
        });
    });

    describe("Using badproofReceipt {}- ", function () {

        var validator = chainpointvalidator();
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

        var result = validator.isValidReceipt(badproofReceipt);
        it("should receive error - bad target proof", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid target proof - ' + badproofReceipt.target.target_proof);
        });
    });

    describe("Using badproofReceipt bad object with value- ", function () {

        var validator = chainpointvalidator();
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

        var result = validator.isValidReceipt(badproofReceipt);
        it("should receive error - bad target proof", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid target proof - ' + badproofReceipt.target.target_proof);
        });
    });


    describe("Using emptyProofInvalidReceipt - ", function () {

        var validator = chainpointvalidator();
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

        var result = validator.isValidReceipt(emptyProofInvalidReceipt);
        it("should receive error - invalid proof path", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid proof path');
        });

    });

    describe("Using invalidWithProofReceipt - missing proof[0].parent", function () {

        var validator = chainpointvalidator();
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

        var result = validator.isValidReceipt(invalidWithProofReceipt);
        it("should be invalid proof path", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid proof path');
        });
    });

    describe("Using invalidWithProofReceipt - proof[0].right invalid", function () {

        var validator = chainpointvalidator();
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

        var result = validator.isValidReceipt(invalidWithProofReceipt);
        it("should be invalid proof path", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid proof path');
        });
    });

    describe("Using invalidWithProofReceipt - parent != HASH(l+r)", function () {

        var validator = chainpointvalidator();
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

        var result = validator.isValidReceipt(invalidWithProofReceipt);
        it("should be invalid proof path", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid proof path');
        });
    });

    describe("Using invalidWithProofReceipt - target hash not in proof[0]", function () {

        var validator = chainpointvalidator();
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

        var result = validator.isValidReceipt(invalidWithProofReceipt);
        it("should be invalid proof path", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid proof path');
        });
    });

    describe("Using invalidWithProofReceipt - proof[1].left missing", function () {

        var validator = chainpointvalidator();
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

        var result = validator.isValidReceipt(invalidWithProofReceipt);
        it("should be invalid proof path", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid proof path');
        });
    });

    describe("Using invalidWithProofReceipt - previous parent not in proof[1]", function () {

        var validator = chainpointvalidator();
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

        var result = validator.isValidReceipt(invalidWithProofReceipt);
        it("should be invalid proof path", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid proof path');
        });
    });

    describe("Using invalidWithProofReceipt - proof[1].parent != hash(l+r)", function () {

        var validator = chainpointvalidator();
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

        var result = validator.isValidReceipt(invalidWithProofReceipt);
        it("should be invalid proof path", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid proof path');
        });
    });

    describe("Using invalidWithProofReceipt - proof[1].parent != merkle root", function () {

        var validator = chainpointvalidator();
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

        var result = validator.isValidReceipt(invalidWithProofReceipt);
        it("should be invalid proof path", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid proof path');
        });
    });

    describe("Using validEmptyProofReceipt - ", function () {

        var validator = chainpointvalidator();
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

        var result = validator.isValidReceipt(validEmptyProofReceipt);
        it("should be considered valid", function () {
            result.should.have.property('isValid', true);
            result.should.have.property('tx_id', "6d14a219a9aef975377bad9236cbc4e1e062cb5dd29b3dd3c1a1cb63540c1c9a");
            result.should.have.property('merkle_root', "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404");
            result.should.not.have.property('error');
        });

    });

    describe("Using validWithProofReceipt - ", function () {

        var validator = chainpointvalidator();
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

        var result = validator.isValidReceipt(validWithProofReceipt);
        it("should be considered valid", function () {
            result.should.have.property('isValid', true);
            result.should.have.property('tx_id', "b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09");
            result.should.have.property('merkle_root', "5faa75ca2c838ceac7fb1b62127cfba51f011813c6c491335c2b69d54dd7d79c");
            result.should.not.have.property('error');
        });

    });

    describe("Using invalidWithProofReceiptString empty- ", function () {

        var validator = chainpointvalidator();
        var invalidWithProofReceiptString = "";

        var result = validator.isValidReceipt("invalidWithProofReceiptString");
        it("should be unparsable", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Cannot parse receipt JSON');
        });

    });

    describe("Using invalidWithProofReceiptString - bad", function () {

        var validator = chainpointvalidator();
        var invalidWithProofReceiptString = "dfgdfgdfg";

        var result = validator.isValidReceipt("invalidWithProofReceiptString");
        it("should be unparsable", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Cannot parse receipt JSON');
        });

    });

    describe("Using validWithProofReceiptString - ", function () {

        var validator = chainpointvalidator();
        var validWithProofReceiptString = "{\"header\": {\n                \"chainpoint_version\": \"1.1\",\n                \"hash_type\": \"SHA-256\",\n                \"merkle_root\": \"5faa75ca2c838ceac7fb1b62127cfba51f011813c6c491335c2b69d54dd7d79c\",\n                \"tx_id\": \"b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09\",\n                \"timestamp\": 1445033433\n            },\n            \"target\": {\n                \"target_hash\": \"cbda53ca51a184b366cbde3cb026987c53021de26fa5aabf814917c894769b65\",\n                \"target_proof\": [\n                    {\n                        \"parent\": \"4f0398f4707c7ddb8d5a85508bdaa9e22fb541fa0182ae54f25513b6bd3f8cb9\",\n                        \"left\": \"cbda53ca51a184b366cbde3cb026987c53021de26fa5aabf814917c894769b65\",\n                        \"right\": \"a52d9c0a0b077237f58c7e5b8b38d2dd7756176ca379947a093105574a465685\"\n                    },\n                    {\n                        \"parent\": \"5faa75ca2c838ceac7fb1b62127cfba51f011813c6c491335c2b69d54dd7d79c\",\n                        \"left\": \"4f0398f4707c7ddb8d5a85508bdaa9e22fb541fa0182ae54f25513b6bd3f8cb9\",\n                        \"right\": \"3bd99c8660a226a62a7df1efc2a296a398ad91e2aa56d68fefd08571a853096e\"\n                    }\n                ]\n            }\n        }";

        var result = validator.isValidReceipt(validWithProofReceiptString);
        it("should be considered valid", function () {
            result.should.have.property('isValid', true);
            result.should.have.property('tx_id', "b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09");
            result.should.have.property('merkle_root', "5faa75ca2c838ceac7fb1b62127cfba51f011813c6c491335c2b69d54dd7d79c");
            result.should.not.have.property('error');
        });

    });
});


