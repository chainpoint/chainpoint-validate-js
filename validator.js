'use strict';

var _ = require('lodash');

var CHAINPOINT_VALID_VERSIONS = ["1.0", "1.1"];
var CHAINPOINT_VALID_HASHTYPES = ["SHA-256"];

var Validator = {
    isValidReceipt: function (receipt) {

        // Ensure the receipt is not null
        if (!receipt) {
            return {
                isValid: false,
                error: 'Cannot parse receipt JSON'
            }
        }

        // If the receipt is provided as a string, attempt to parse into object
        if (_.isString(receipt)) {
            try {
                receipt = JSON.parse(receipt);
            }
            catch (err) {
                return {
                    isValid: false,
                    error: 'Cannot parse receipt JSON'
                }
            }
        }

        // Find the specified version of the receipt provided
        var receiptHeader = receipt.header;
        if (!receiptHeader) {
            return {
                isValid: false,
                error: 'Cannot identify Chainpoint version'
            }
        }
        var receiptVersion = receiptHeader.chainpoint_version;
        if (!receiptVersion) {
            return {
                isValid: false,
                error: 'Cannot identify Chainpoint version'
            }
        }

        // Ensure specified version is a valid Chainpoint version value
        if (_.indexOf(CHAINPOINT_VALID_VERSIONS, receiptVersion.toString()) == -1) {
            return {
                isValid: false,
                error: 'Invalid Chainpoint version - ' + receiptVersion
            }
        }

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
    if (!hashType) {
        return {
            isValid: false,
            error: 'Missing hash type'
        }
    }
    if (_.indexOf(CHAINPOINT_VALID_HASHTYPES, hashType) == -1) {
        return {
            isValid: false,
            error: 'Invalid hash type - ' + hashType
        }
    }
    
    // Find the Merkle Root
    var merkleRoot = receipt.header.merkle_root;
    if (!merkleRoot) {
        return {
            isValid: false,
            error: 'Missing merkle root'
        }
    }
    if (!/[A-Fa-f0-9]{64}/.test(merkleRoot)) {
        return {
            isValid: false,
            error: 'Invalid merkle root - ' + merkleRoot
        }
    }
    
    // Find the transcation Id
    var txId = receipt.header.tx_id;
    if (!txId) {
        return {
            isValid: false,
            error: 'Missing transaction Id'
        }
    }
    if (!/[A-Fa-f0-9]{64}/.test(txId)) {
        return {
            isValid: false,
            error: 'Invalid transaction Id - ' + txId
        }
    }
    
    // Find the timestamp
    var timestamp = receipt.header.timestamp;
    if (!timestamp) {
        return {
            isValid: false,
            error: 'Missing timestamp'
        }
    }
    if (!_.isNumber(timestamp)) {
        return {
            isValid: false,
            error: 'Invalid timestamp - ' + timestamp
        }
    }
}


module.exports = Validator;