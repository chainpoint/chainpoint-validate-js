'use strict';

var _ = require('lodash');
var crypto = require('crypto');

var CHAINPOINT_VALID_VERSIONS = ["1.0", "1.1"];
var CHAINPOINT_VALID_HASHTYPES = ["SHA-256"];

var Validator = {
    isValidReceipt: function (receipt) {

        // Ensure the receipt is not null
        if (!receipt) return errorResult('Cannot parse receipt JSON');

        // If the receipt is provided as a string, attempt to parse into object
        if (_.isString(receipt)) {
            try {
                receipt = JSON.parse(receipt);
            }
            catch (err) {
                return errorResult('Cannot parse receipt JSON');
            }
        }

        // Find the specified version of the receipt provided
        var receiptHeader = receipt.header;
        if (!receiptHeader) return errorResult('Cannot identify Chainpoint version');

        var receiptVersion = receiptHeader.chainpoint_version;
        if (!receiptVersion) return errorResult('Cannot identify Chainpoint version');

        // Ensure specified version is a valid Chainpoint version value
        if (_.indexOf(CHAINPOINT_VALID_VERSIONS, receiptVersion.toString()) == -1) return errorResult('Invalid Chainpoint version - ' + receiptVersion);

        switch (receiptVersion) {
            case "1.0":
            case "1.1":
                {
                    return validate1xReceipt(receipt, receiptVersion);
                }
        }

    }
};

function validate1xReceipt(receipt, receiptVersion) {

    // Find the Hash Type
    var hashType = receipt.header.hash_type;
    if (!hashType) return errorResult('Missing hash type');

    if (_.indexOf(CHAINPOINT_VALID_HASHTYPES, hashType) == -1) return errorResult('Invalid hash type - ' + hashType);

    // Find the Merkle Root
    var merkleRoot = receipt.header.merkle_root;
    if (!merkleRoot) return errorResult('Missing merkle root');

    if (!/[A-Fa-f0-9]{64}/.test(merkleRoot)) return errorResult('Invalid merkle root - ' + merkleRoot);

    // Find the transcation Id
    var txId = receipt.header.tx_id;
    if (!txId) return errorResult('Missing transaction Id');

    if (!/[A-Fa-f0-9]{64}/.test(txId)) return errorResult('Invalid transaction Id - ' + txId);

    // Find the timestamp
    var timestamp = receipt.header.timestamp;
    if (!timestamp) return errorResult('Missing timestamp');

    if (!_.isNumber(timestamp)) return errorResult('Invalid timestamp - ' + timestamp);

    // Find the target element
    var target = receipt.target;
    if (!target) return errorResult('Missing target');

    // Find the target hash
    var targetHash = receipt.target.target_hash;
    if (!targetHash) return errorResult('Missing target hash');

    if (!/[A-Fa-f0-9]{64}/.test(targetHash)) return errorResult('Invalid target hash - ' + targetHash);

    // Find the target proof
    var targetProof = receipt.target.target_proof;
    if (!targetProof) return errorResult('Missing target proof');

    if (!_.isArray(targetProof)) return errorResult('Invalid target proof - ' + targetProof);

    // validate proof path if empty
    if (targetProof.length == 0) {
        if (targetHash == merkleRoot) return validResult(txId, merkleRoot);
        return errorResult('Invalid proof path');
    } else { // validate proof path with content
        var lastParent = targetHash;
        for (var x = 0; x < targetProof.length; x++) {

            // check for required values
            if (!targetProof[x].left || !targetProof[x].right || !targetProof[x].parent) return errorResult('Invalid proof path');

            // ensure parent = hash(l+r)
            var hashlr = crypto.createHash('sha256').update(targetProof[x].left).update(targetProof[x].right).digest('hex');
            if (targetProof[x].parent != hashlr) return errorResult('Invalid proof path');

            // check for presence of last parent
            if (targetProof[x].left != lastParent && targetProof[x].right != lastParent) {
                return errorResult('Invalid proof path');
            } else {
                lastParent = targetProof[x].parent;
            }
        }
    }

    // ensure proof path leads to merkle root
    if (merkleRoot != lastParent) {
        return errorResult('Invalid proof path');
    } else {
        return validResult(txId, merkleRoot);
    }
};

function errorResult(message) {
    return {
        isValid: false,
        error: message
    }
};

function validResult(txId, merkleRoot) {
    return {
        isValid: true,
        tx_id: txId,
        merkle_root: merkleRoot
    }
};

module.exports = Validator;