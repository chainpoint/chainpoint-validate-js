var should = require('should');
var chainpointvalidate = require('../chainpointvalidate.js');

describe("Testing v1.x receipts - ", function () {

    describe("Using nullReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var nullReceipt = null;
        var result = chainpointValidate.isValidReceipt(nullReceipt);
        it("should receive error - bad Json", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Cannot parse receipt JSON');
        });

    });

    describe("Using stringReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var stringReceipt = 'dfsgsfgxcvbasfdg';
        var result = chainpointValidate.isValidReceipt(stringReceipt);
        it("should receive error - bad Json", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Cannot parse receipt JSON');
        });

    });

    describe("Using numberReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var numberReceipt = 435345;
        var result = chainpointValidate.isValidReceipt(numberReceipt);
        it("should receive error - unknown version", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Cannot identify Chainpoint version');
        });

    });

    describe("Using emptyReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var emptyReceipt = {};
        var result = chainpointValidate.isValidReceipt(emptyReceipt);
        it("should receive error - unknown version", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Cannot identify Chainpoint version');
        });

    });

    describe("Using junkReceiptObject - ", function () {

        var chainpointValidate = chainpointvalidate();
        var junkReceiptObject = { 'sdf': 23424 };
        var result = chainpointValidate.isValidReceipt(junkReceiptObject);
        it("should receive error - unknown version", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Cannot identify Chainpoint version');
        });

    });

    describe("Using junkReceiptString - ", function () {

        var chainpointValidate = chainpointvalidate();
        var junkReceiptString = '{ "sdf": 23424 }';
        var result = chainpointValidate.isValidReceipt(junkReceiptString);
        it("should receive error - unknown version", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Cannot identify Chainpoint version');
        });

    });

    describe("Using badVersionNumberReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var badVersionNumberReceipt = {
            "header": {
                "chainpoint_version": "0.9"
            }
        };

        var result = chainpointValidate.isValidReceipt(badVersionNumberReceipt);
        it("should receive error - bad version", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid Chainpoint version - ' + badVersionNumberReceipt.header.chainpoint_version);
        });

    });

    describe("Using missingHashTypeReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var missingHashTypeReceipt = {
            "header": {
                "chainpoint_version": "1.1"
            }
        };

        var result = chainpointValidate.isValidReceipt(missingHashTypeReceipt);
        it("should receive error - missing hashtype", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Missing hash type');
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

        var result = chainpointValidate.isValidReceipt(badHashTypeReceipt);
        it("should receive error - bad hashtype", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid hash type - ' + badHashTypeReceipt.header.hash_type);
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

        var result = chainpointValidate.isValidReceipt(missingRootReceipt);
        it("should receive error - missing merkle root", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Missing merkle root');
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

        var result = chainpointValidate.isValidReceipt(badRootReceipt);
        it("should receive error - bad merkle root", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid merkle root - ' + badRootReceipt.header.merkle_root);
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

        var result = chainpointValidate.isValidReceipt(missingTxReceipt);
        it("should receive error - missing txId", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Missing transaction Id');
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

        var result = chainpointValidate.isValidReceipt(badTxReceipt);
        it("should receive error - bad txId", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid transaction Id - ' + badTxReceipt.header.tx_id);
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

        var result = chainpointValidate.isValidReceipt(missingTimestampReceipt);
        it("should receive error - missing timestamp", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Missing timestamp');
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

        var result = chainpointValidate.isValidReceipt(badTimestampReceipt);
        it("should receive error - bad timestamp", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid timestamp - ' + badTimestampReceipt.header.timestamp);
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

        var result = chainpointValidate.isValidReceipt(noTargetReceipt);
        it("should receive error - missing target", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Missing target');
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

        var result = chainpointValidate.isValidReceipt(missingTargethashReceipt);
        it("should receive error - missing target hash", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Missing target hash');
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

        var result = chainpointValidate.isValidReceipt(badTargethashReceipt);
        it("should receive error - bad target hash", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid target hash - ' + badTargethashReceipt.target.target_hash);
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

        var result = chainpointValidate.isValidReceipt(missingTargetproofReceipt);
        it("should receive error - missing target proof", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Missing target proof');
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

        var result = chainpointValidate.isValidReceipt(badproofReceipt);
        it("should receive error - bad target proof", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Missing target proof');
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

        var result = chainpointValidate.isValidReceipt(badproofReceipt);
        it("should receive error - bad target proof", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Missing target proof');
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

        var result = chainpointValidate.isValidReceipt(badproofReceipt);
        it("should receive error - bad target proof", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid target proof - ' + badproofReceipt.target.target_proof);
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

        var result = chainpointValidate.isValidReceipt(badproofReceipt);
        it("should receive error - bad target proof", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid target proof - ' + badproofReceipt.target.target_proof);
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

        var result = chainpointValidate.isValidReceipt(badproofReceipt);
        it("should receive error - bad target proof", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid target proof - ' + badproofReceipt.target.target_proof);
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

        var result = chainpointValidate.isValidReceipt(emptyProofInvalidReceipt);
        it("should receive error - invalid proof path", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid proof path');
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

        var result = chainpointValidate.isValidReceipt(invalidWithProofReceipt);
        it("should be invalid proof path", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid proof path');
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

        var result = chainpointValidate.isValidReceipt(invalidWithProofReceipt);
        it("should be invalid proof path", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid proof path');
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

        var result = chainpointValidate.isValidReceipt(invalidWithProofReceipt);
        it("should be invalid proof path", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid proof path');
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

        var result = chainpointValidate.isValidReceipt(invalidWithProofReceipt);
        it("should be invalid proof path", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid proof path');
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

        var result = chainpointValidate.isValidReceipt(invalidWithProofReceipt);
        it("should be invalid proof path", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid proof path');
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

        var result = chainpointValidate.isValidReceipt(invalidWithProofReceipt);
        it("should be invalid proof path", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid proof path');
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

        var result = chainpointValidate.isValidReceipt(invalidWithProofReceipt);
        it("should be invalid proof path", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid proof path');
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

        var result = chainpointValidate.isValidReceipt(invalidWithProofReceipt);
        it("should be invalid proof path", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid proof path');
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

        var result = chainpointValidate.isValidReceipt(validEmptyProofReceipt);
        it("should be considered valid", function () {
            result.should.have.property('isValid', true);
            result.should.have.property('merkleRoot', "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404");
            result.should.have.property('anchors');
            result.anchors.should.be.instanceof(Array).and.have.lengthOf(1);
            result.anchors[0].should.have.property('type', 'BTCOpReturn');
            result.anchors[0].should.have.property('sourceId', '6d14a219a9aef975377bad9236cbc4e1e062cb5dd29b3dd3c1a1cb63540c1c9a');
            result.should.not.have.property('error');
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

        var result = chainpointValidate.isValidReceipt(validWithProofReceipt);
        it("should be considered valid", function () {
            result.should.have.property('isValid', true);
            result.should.have.property('merkleRoot', "5faa75ca2c838ceac7fb1b62127cfba51f011813c6c491335c2b69d54dd7d79c");
            result.should.have.property('anchors');
            result.anchors.should.be.instanceof(Array).and.have.lengthOf(1);
            result.anchors[0].should.have.property('type', 'BTCOpReturn');
            result.anchors[0].should.have.property('sourceId', 'b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09');
            result.should.not.have.property('error');
        });

    });

    describe("Using invalidWithProofReceiptString empty- ", function () {

        var chainpointValidate = chainpointvalidate();
        var invalidWithProofReceiptString = "";

        var result = chainpointValidate.isValidReceipt("invalidWithProofReceiptString");
        it("should be unparsable", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Cannot parse receipt JSON');
        });

    });

    describe("Using invalidWithProofReceiptString - bad", function () {

        var chainpointValidate = chainpointvalidate();
        var invalidWithProofReceiptString = "dfgdfgdfg";

        var result = chainpointValidate.isValidReceipt("invalidWithProofReceiptString");
        it("should be unparsable", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Cannot parse receipt JSON');
        });

    });

    describe("Using validWithProofReceiptString - ", function () {

        var chainpointValidate = chainpointvalidate();
        var validWithProofReceiptString = "{\"header\": {\n                \"chainpoint_version\": \"1.1\",\n                \"hash_type\": \"SHA-256\",\n                \"merkle_root\": \"5faa75ca2c838ceac7fb1b62127cfba51f011813c6c491335c2b69d54dd7d79c\",\n                \"tx_id\": \"b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09\",\n                \"timestamp\": 1445033433\n            },\n            \"target\": {\n                \"target_hash\": \"cbda53ca51a184b366cbde3cb026987c53021de26fa5aabf814917c894769b65\",\n                \"target_proof\": [\n                    {\n                        \"parent\": \"4f0398f4707c7ddb8d5a85508bdaa9e22fb541fa0182ae54f25513b6bd3f8cb9\",\n                        \"left\": \"cbda53ca51a184b366cbde3cb026987c53021de26fa5aabf814917c894769b65\",\n                        \"right\": \"a52d9c0a0b077237f58c7e5b8b38d2dd7756176ca379947a093105574a465685\"\n                    },\n                    {\n                        \"parent\": \"5faa75ca2c838ceac7fb1b62127cfba51f011813c6c491335c2b69d54dd7d79c\",\n                        \"left\": \"4f0398f4707c7ddb8d5a85508bdaa9e22fb541fa0182ae54f25513b6bd3f8cb9\",\n                        \"right\": \"3bd99c8660a226a62a7df1efc2a296a398ad91e2aa56d68fefd08571a853096e\"\n                    }\n                ]\n            }\n        }";

        var result = chainpointValidate.isValidReceipt(validWithProofReceiptString);
        it("should be considered valid", function () {
            result.should.have.property('isValid', true);
            result.should.have.property('merkleRoot', "5faa75ca2c838ceac7fb1b62127cfba51f011813c6c491335c2b69d54dd7d79c");
            result.should.have.property('anchors');
            result.anchors.should.be.instanceof(Array).and.have.lengthOf(1);
            result.anchors[0].should.have.property('type', 'BTCOpReturn');
            result.anchors[0].should.have.property('sourceId', 'b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09');
            result.should.not.have.property('error');
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

        var result = chainpointValidate.isValidReceipt(badVersionNumberReceipt);
        it("should receive error - bad version", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid Chainpoint type - ' + badVersionNumberReceipt.type);
        });

    });

    describe("Using badVersionNumberReceiptB - ", function () {

        var chainpointValidate = chainpointvalidate();
        var badVersionNumberReceipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA256v35"
        };

        var result = chainpointValidate.isValidReceipt(badVersionNumberReceipt);
        it("should receive error - bad version", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid Chainpoint type - ' + badVersionNumberReceipt['@type']);
        });

    });

    describe("Using missingHashTypeReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var missingHashTypeReceipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "Chainpointv2"
        };

        var result = chainpointValidate.isValidReceipt(missingHashTypeReceipt);
        it("should receive error - missing hashtype", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid Chainpoint type - ' + missingHashTypeReceipt['@type']);
        });

    });

    describe("Using badHashTypeReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var badHashTypeReceipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA2048v2"
        };

        var result = chainpointValidate.isValidReceipt(badHashTypeReceipt);
        it("should receive error - bad hashtype", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid Chainpoint type - ' + badHashTypeReceipt['@type']);
        });

    });

    describe("Using missingTargethashReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var missingTargethashReceipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA256v2"
        };

        var result = chainpointValidate.isValidReceipt(missingTargethashReceipt);
        it("should receive error - missing target hash", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Missing target hash');
        });

    });

    describe("Using badTargethashReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var badTargethashReceipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA256v2",
            "targetHash": "badhash"
        };

        var result = chainpointValidate.isValidReceipt(badTargethashReceipt);
        it("should receive error - bad target hash", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid target hash - badhash');
        });

    });

    describe("Using missingRootReceipt - ", function () {

        var chainpointValidate = chainpointvalidate();
        var missingRootReceipt = {
            "@context": "https://w3id.org/chainpoint/v2",
            "@type": "ChainpointSHA256v2",
            "targetHash": "f17fbe8fc1a6e5a8289da6fea45d16a92b35c629fa1fd34178245420378bea19"
        };

        var result = chainpointValidate.isValidReceipt(missingRootReceipt);
        it("should receive error - missing merkle root", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Missing merkle root');
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

        var result = chainpointValidate.isValidReceipt(badRootReceipt);
        it("should receive error - bad merkle root", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid merkle root - badroothash');
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

        var result = chainpointValidate.isValidReceipt(missingTargetproofReceipt);
        it("should receive error - missing target proof", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Missing proof');
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

        var result = chainpointValidate.isValidReceipt(badproofReceipt);
        it("should receive error - bad target proof", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Missing proof');
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

        var result = chainpointValidate.isValidReceipt(badproofReceipt);
        it("should receive error - bad target proof", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Missing proof');
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

        var result = chainpointValidate.isValidReceipt(badproofReceipt);
        it("should receive error - bad target proof", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid proof - ' + badproofReceipt.proof);
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

        var result = chainpointValidate.isValidReceipt(badproofReceipt);
        it("should receive error - bad target proof", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid proof - ' + badproofReceipt.proof);
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

        var result = chainpointValidate.isValidReceipt(badproofReceipt);
        it("should receive error - bad target proof", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid proof - ' + badproofReceipt.proof);
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

        var result = chainpointValidate.isValidReceipt(emptyProofInvalidReceipt);
        it("should receive error - invalid proof path", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid proof path');
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

        var result = chainpointValidate.isValidReceipt(emptyProofInvalidReceipt);
        it("should receive error - invalid proof path", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid proof path');
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

        var result = chainpointValidate.isValidReceipt(emptyProofInvalidReceipt);
        it("should receive error - invalid proof path", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid proof path');
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

        var result = chainpointValidate.isValidReceipt(emptyProofInvalidReceipt);
        it("should receive error - invalid proof path", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid proof path');
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

        var result = chainpointValidate.isValidReceipt(emptyProofInvalidReceipt);
        it("should receive error - invalid proof path", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid proof path');
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

        var result = chainpointValidate.isValidReceipt(emptyProofInvalidReceipt);
        it("should receive error - invalid proof path", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid proof path');
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

        var result = chainpointValidate.isValidReceipt(receipt);
        it("should receive error - missing anchors", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Missing anchors');
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

        var result = chainpointValidate.isValidReceipt(receipt);
        it("should receive error - invalid anchors array", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Missing anchors');
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

        var result = chainpointValidate.isValidReceipt(receipt);
        it("should receive error - invalid anchors array", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Missing anchors');
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

        var result = chainpointValidate.isValidReceipt(receipt);
        it("should receive error - invalid anchors array", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid anchors array - ' + receipt.anchors);
        });
    });

    describe("Using badproofReceipt {}- ", function () {

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

        var result = chainpointValidate.isValidReceipt(receipt);
        it("should receive error - invalid anchors array", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid anchors array - ' + receipt.anchors);
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

        var result = chainpointValidate.isValidReceipt(receipt);
        it("should receive error - invalid anchors array", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid anchors array - ' + receipt.anchors);
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

        var result = chainpointValidate.isValidReceipt(receipt);
        it("should receive error - empty anchors array", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Empty anchors array');
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

        var result = chainpointValidate.isValidReceipt(receipt);
        it("should receive error - Missing anchor type", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Missing anchor type');
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

        var result = chainpointValidate.isValidReceipt(receipt);
        it("should receive error - invalid anchor type", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid anchor type - ' + receipt.anchors[0].type);
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

        var result = chainpointValidate.isValidReceipt(receipt);
        it("should receive error - invalid anchor type", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid anchor type - ' + receipt.anchors[0]["@type"]);
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

        var result = chainpointValidate.isValidReceipt(receipt);
        it("should receive error - Missing anchor type", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Missing sourceId');
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

        var result = chainpointValidate.isValidReceipt(receipt);
        it("should receive error - Invalid anchor type", function () {
            result.should.have.property('isValid', false);
            result.should.have.property('error', 'Invalid sourceId for BTCOpReturn - ' + receipt.anchors[0].sourceId);
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

        var result = chainpointValidate.isValidReceipt(receipt);
        it("should be considered valid", function () {
            result.should.have.property('isValid', true);
            result.should.have.property('merkleRoot', "fd3f0550fd1164f463d3e57b7bb6834872ada68501102cec6ce93cdbe7a17404");
            result.should.have.property('anchors');
            result.anchors.should.be.instanceof(Array).and.have.lengthOf(1);
            result.anchors[0].should.have.property('@type', 'BTCOpReturn');
            result.anchors[0].should.have.property('sourceId', '6d14a219a9aef975377bad9236cbc4e1e062cb5dd29b3dd3c1a1cb63540c1c9a');
            result.should.not.have.property('error');
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

        var result = chainpointValidate.isValidReceipt(receipt);
        it("should be considered valid", function () {
            result.should.have.property('isValid', true);
            result.should.have.property('merkleRoot', "d71f8983ad4ee170f8129f1ebcdd7440be7798d8e1c80420bf11f1eced610dba");
            result.should.have.property('anchors');
            result.anchors.should.be.instanceof(Array).and.have.lengthOf(1);
            result.anchors[0].should.have.property('type', 'BTCOpReturn');
            result.anchors[0].should.have.property('sourceId', 'b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09');
            result.should.not.have.property('error');
        });

    });

    describe("Using validWithProofReceiptString - ", function () {

        var chainpointValidate = chainpointvalidate();
        var receiptString = "{\n            \"@context\": \"https://w3id.org/chainpoint/v2\",\n            \"@type\": \"ChainpointSHA256v2\",\n            \"targetHash\": \"3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d\",\n            \"merkleRoot\": \"d71f8983ad4ee170f8129f1ebcdd7440be7798d8e1c80420bf11f1eced610dba\",\n            \"proof\": [{ \"left\": \"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb\" },\n                { \"right\": \"bffe0b34dba16bc6fac17c08bac55d676cded5a4ade41fe2c9924a5dde8f3e5b\" },\n                { \"right\": \"3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea\" }],\n            \"anchors\": [{ \"type\": \"BTCOpReturn\", \"sourceId\": \"b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09\" }]\n        }";

        var result = chainpointValidate.isValidReceipt(receiptString);
        it("should be considered valid", function () {
            result.should.have.property('isValid', true);
            result.should.have.property('merkleRoot', "d71f8983ad4ee170f8129f1ebcdd7440be7798d8e1c80420bf11f1eced610dba");
            result.should.have.property('anchors');
            result.anchors.should.be.instanceof(Array).and.have.lengthOf(1);
            result.anchors[0].should.have.property('type', 'BTCOpReturn');
            result.anchors[0].should.have.property('sourceId', 'b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09');
            result.should.not.have.property('error');
        });

    }); 
});


