/*jslint node: true */
'use strict';

var _ = require('lodash');
var crypto = require('crypto');

var CHAINPOINT_VALID_VERSIONS = ["1.0", "1.1"];
var CHAINPOINT_VALID_HASHTYPES = ["SHA-256"];

var ChainpointValidator = function () {
    // in case 'new' was omitted
    if (!(this instanceof ChainpointValidator)) {
        return new ChainpointValidator();
    }

    ////////////////////////////////////////////
    // Public Primary functions
    ////////////////////////////////////////////

    // Returns a boolean value, true if the receipt is valid.
    this.isValidReceipt = function (receipt) {
        // Ensure the receipt is not null
        if (!receipt) return _errorResult('Cannot parse receipt JSON');

        // If the receipt is provided as a string, attempt to parse into object
        if (_.isString(receipt)) {
            try {
                receipt = JSON.parse(receipt);
            }
            catch (err) {
                return _errorResult('Cannot parse receipt JSON');
            }
        }

        // Find the specified version of the receipt provided
        var receiptHeader = receipt.header;
        if (!receiptHeader) return _errorResult('Cannot identify Chainpoint version');

        var receiptVersion = receiptHeader.chainpoint_version;
        if (!receiptVersion) return _errorResult('Cannot identify Chainpoint version');

        // Ensure specified version is a valid Chainpoint version value
        if (_.indexOf(CHAINPOINT_VALID_VERSIONS, receiptVersion.toString()) == -1) return _errorResult('Invalid Chainpoint version - ' + receiptVersion);

        switch (receiptVersion) {
            case "1.0":
            case "1.1":
                {
                    return _validate1xReceipt(receipt, receiptVersion);
                }
        }
    };

    //////////////////////////////////////////
    // Private Utility functions
    //////////////////////////////////////////

    function _validate1xReceipt(receipt, receiptVersion) {

        // Find the Hash Type
        var hashType = receipt.header.hash_type;
        if (!hashType) return _errorResult('Missing hash type');

        if (_.indexOf(CHAINPOINT_VALID_HASHTYPES, hashType) == -1) return _errorResult('Invalid hash type - ' + hashType);

        // Find the Merkle Root
        var merkleRoot = receipt.header.merkle_root;
        if (!merkleRoot) return _errorResult('Missing merkle root');

        if (!/[A-Fa-f0-9]{64}/.test(merkleRoot)) return _errorResult('Invalid merkle root - ' + merkleRoot);

        // Find the transcation Id
        var txId = receipt.header.tx_id;
        if (!txId) return _errorResult('Missing transaction Id');

        if (!/[A-Fa-f0-9]{64}/.test(txId)) return _errorResult('Invalid transaction Id - ' + txId);

        // Find the timestamp
        var timestamp = receipt.header.timestamp;
        if (!timestamp) return _errorResult('Missing timestamp');

        if (!_.isNumber(timestamp)) return _errorResult('Invalid timestamp - ' + timestamp);

        // Find the target element
        var target = receipt.target;
        if (!target) return _errorResult('Missing target');

        // Find the target hash
        var targetHash = receipt.target.target_hash;
        if (!targetHash) return _errorResult('Missing target hash');

        if (!/[A-Fa-f0-9]{64}/.test(targetHash)) return _errorResult('Invalid target hash - ' + targetHash);

        // Find the target proof
        var targetProof = receipt.target.target_proof;
        if (!targetProof) return _errorResult('Missing target proof');

        if (!_.isArray(targetProof)) return _errorResult('Invalid target proof - ' + targetProof);

        // validate proof path if empty
        if (targetProof.length === 0) {
            if (targetHash == merkleRoot) return _validResult(txId, merkleRoot);
            return _errorResult('Invalid proof path');
        } else { // validate proof path with content
            var lastParent = targetHash;
            for (var x = 0; x < targetProof.length; x++) {

                // check for required values
                if (!targetProof[x].left || !targetProof[x].right || !targetProof[x].parent) return _errorResult('Invalid proof path');

                // ensure parent = hash(l+r)
                var hashlr = crypto.createHash('sha256').update(targetProof[x].left).update(targetProof[x].right).digest('hex');
                if (targetProof[x].parent != hashlr) return _errorResult('Invalid proof path');

                // check for presence of last parent
                if (targetProof[x].left != lastParent && targetProof[x].right != lastParent) {
                    return _errorResult('Invalid proof path');
                } else {
                    lastParent = targetProof[x].parent;
                }
            }

            // ensure proof path leads to merkle root
            if (merkleRoot != lastParent) {
                return _errorResult('Invalid proof path');
            } else {
                return _validResult(txId, merkleRoot);
            }
        }
    }

    function _errorResult(message) {
        return {
            isValid: false,
            error: message
        };
    }

    function _validResult(txId, merkleRoot) {
        return {
            isValid: true,
            tx_id: txId,
            merkle_root: merkleRoot
        };
    }
};



module.exports = ChainpointValidator;