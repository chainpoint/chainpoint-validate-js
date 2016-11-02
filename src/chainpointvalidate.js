/*jslint node: true */
'use strict';

var _ = require('lodash');
var async = require('async');
var crypto = require('crypto');
var merkletools = require('merkle-tools');
var blockchainanchor = require('blockchain-anchor');
var chainpointBinary = require('chainpoint-binary');
var rgxs = require('./rgxs');

var ChainpointValidate = function () {
    // in case 'new' was omitted
    if (!(this instanceof ChainpointValidate)) {
        return new ChainpointValidate();
    }

    var CHAINPOINT_VALID_VERSIONS = ['1.0', '1.1', '2'];
    var CHAINPOINTv1_VALID_HASHTYPES = ['SHA-256'];
    var CHAINPOINTv2_VALID_HASHTYPES = ['SHA224', 'SHA256', 'SHA384', 'SHA512', 'SHA3-224', 'SHA3-256', 'SHA3-384', 'SHA3-512'];
    var CHAINPOINTv2_VALID_ANCHORTYPES = ['BTCOpReturn', 'ETHData', 'BTCBlockHeader'];
    var blockchainAnchor = new blockchainanchor();


    ////////////////////////////////////////////
    // Public Primary functions
    ////////////////////////////////////////////

    // Returns a boolean value, true if the receipt is valid.
    this.isValidReceipt = function (receipt, confirmAnchor, callback) {

        async.waterfall([

            // Ensure the receipt is not null
            function (wfCallback) {
                if (!receipt) return wfCallback('Cannot parse receipt JSON');
                return wfCallback(null);
            },

            // attempt to parse the receipt to an object
            function (wfCallback) {
                var cpb = new chainpointBinary();
                // if the receipt is binary in the form of a buffer or hex string
                if (Buffer.isBuffer(receipt) || (_.isString(receipt) && rgxs.isHex(receipt))) {
                    cpb.toObject(receipt, function (err, proofObject) {
                        if (err) {
                            return wfCallback(err);
                        } else {
                            return wfCallback(null, proofObject);
                        }
                    });
                } else if (_.isString(receipt)) {
                    try {
                        receipt = JSON.parse(receipt);
                    }
                    catch (err) {
                        return wfCallback('Cannot parse receipt JSON');
                    }
                    return wfCallback(null, receipt);
                } else {
                    return wfCallback(null, receipt);
                }
            },

            function (proofObject, wfCallback) {

                // Find the specified version of the receipt provided
                var receiptVersion = null;

                var receiptHeader = proofObject.header;
                if (receiptHeader) { // header section was found, so this could be a pre-v2 receipt
                    receiptVersion = receiptHeader.chainpoint_version;
                } else { // no header was found, so it is not a v1.x receipt, check for v2
                    var receiptType = proofObject.type || proofObject['@type']; // look for 'type' attribute
                    if (receiptType) {
                        var typeRegex = /^Chainpoint.*v2$/;
                        var isValidType = typeRegex.test(receiptType); // validate 'type' attribute value
                        if (isValidType) receiptVersion = '2';
                        if (!receiptVersion) return wfCallback('Invalid Chainpoint type - ' + receiptType);
                    }
                }
                if (!receiptVersion) return wfCallback('Cannot identify Chainpoint version');


                // Ensure specified version is a valid Chainpoint version value
                if (_.indexOf(CHAINPOINT_VALID_VERSIONS, receiptVersion.toString()) == -1) return wfCallback('Invalid Chainpoint version - ' + receiptVersion);

                switch (receiptVersion) {
                    case '1.0':
                    case '1.1': {
                        return _validate1xReceipt(receipt, confirmAnchor, wfCallback);
                    }
                    case '2': {
                        return _validate2xReceipt(receipt, confirmAnchor, wfCallback);
                    }
                }
            }
        ],
            function (err, merkleRoot, anchorArray) {
                if (err) return _errorResult(callback, err);
                return _validResult(callback, merkleRoot, anchorArray);
            });
    };

    //////////////////////////////////////////
    // Private Utility functions
    //////////////////////////////////////////

    function _validate1xReceipt(receipt, confirmAnchor, callback) {

        // Find the Hash Type
        var hashType = receipt.header.hash_type;
        if (!hashType) return callback('Missing hash type');

        if (_.indexOf(CHAINPOINTv1_VALID_HASHTYPES, hashType) == -1) return callback('Invalid hash type - ' + hashType);

        // Find the Merkle Root
        var merkleRoot = receipt.header.merkle_root;
        if (!merkleRoot) return callback('Missing merkle root');

        if (!/[A-Fa-f0-9]{64}/.test(merkleRoot)) return callback('Invalid merkle root - ' + merkleRoot);

        // Find the transcation Id
        var txId = receipt.header.tx_id;
        if (!txId) return callback('Missing transaction Id');

        if (!/[A-Fa-f0-9]{64}/.test(txId)) return callback('Invalid transaction Id - ' + txId);

        // Find the timestamp
        var timestamp = receipt.header.timestamp;
        if (!timestamp) return callback('Missing timestamp');

        if (!_.isNumber(timestamp)) return callback('Invalid timestamp - ' + timestamp);

        // Find the target element
        var target = receipt.target;
        if (!target) return callback('Missing target');

        // Find the target hash
        var targetHash = receipt.target.target_hash;
        if (!targetHash) return callback('Missing target hash');

        if (!/[A-Fa-f0-9]{64}/.test(targetHash)) return callback('Invalid target hash - ' + targetHash);

        // Find the target proof
        var targetProof = receipt.target.target_proof;
        if (!targetProof) return callback('Missing target proof');

        if (!_.isArray(targetProof)) return callback('Invalid target proof - ' + targetProof);

        // validate proof path if empty
        if (targetProof.length === 0 && targetHash !== merkleRoot) {
            return callback('Invalid proof path');
        } else { // validate proof path with content
            var lastParent = targetHash;
            for (var x = 0; x < targetProof.length; x++) {

                // check for required values
                if (!targetProof[x].left || !targetProof[x].right || !targetProof[x].parent) return callback('Invalid proof path');

                // ensure parent = hash(l+r)
                var hashlr = crypto.createHash('sha256').update(targetProof[x].left).update(targetProof[x].right).digest('hex');
                if (targetProof[x].parent != hashlr) return callback('Invalid proof path');

                // check for presence of last parent
                if (targetProof[x].left != lastParent && targetProof[x].right != lastParent) {
                    return callback('Invalid proof path');
                } else {
                    lastParent = targetProof[x].parent;
                }
            }

            // ensure proof path leads to merkle root
            if (merkleRoot != lastParent) {
                return callback('Invalid proof path');
            }

            var anchors = [];
            var anchorItem = {};
            anchorItem.type = 'BTCOpReturn';
            anchorItem.sourceId = txId;

            if (confirmAnchor) { // confirm this anchor  
                blockchainAnchor.confirm(txId, merkleRoot, function (err, result) {
                    if (err) {
                        return callback(err);
                    } else {
                        anchorItem.exists = result;
                        anchors.push(anchorItem);
                        return callback(null, merkleRoot, anchors);
                    }
                });
            } else {
                anchors.push(anchorItem);
                return callback(null, merkleRoot, anchors);
            }

        }
    }

    function _validate2xReceipt(receipt, confirmAnchor, callback) {

        // Ensure existance of @context definition
        var context = receipt['@context'];
        if (!context) return callback('Missing @context');

        // Find the Hash Type
        var receiptType = receipt.type || receipt['@type'];
        var hashTypeRegex = /^Chainpoint(.*)v2$/;
        var hashType = hashTypeRegex.exec(receiptType)[1];
        if (!hashType) return callback('Invalid Chainpoint type - ' + receiptType);

        if (_.indexOf(CHAINPOINTv2_VALID_HASHTYPES, hashType) == -1) return callback('Invalid Chainpoint type - ' + receiptType);

        var hashTestText = '^$';
        switch (hashType) {
            case 'SHA224':
            case 'SHA3-224':
                hashTestText = '^[A-Fa-f0-9]{56}$';
                break;
            case 'SHA256':
            case 'SHA3-256':
                hashTestText = '^[A-Fa-f0-9]{64}$';
                break;
            case 'SHA384':
            case 'SHA3-384':
                hashTestText = '^[A-Fa-f0-9]{96}$';
                break;
            case 'SHA512':
            case 'SHA3-512':
                hashTestText = '^[A-Fa-f0-9]{128}$';
                break;
        }
        var hashTestRegex = new RegExp(hashTestText);

        // Find the target hash
        var targetHash = receipt.targetHash;
        if (!targetHash) return callback('Missing target hash');

        if (!hashTestRegex.test(targetHash)) return callback('Invalid target hash - ' + targetHash);

        // Find the Merkle Root
        var merkleRoot = receipt.merkleRoot;
        if (!merkleRoot) return callback('Missing merkle root');

        if (!hashTestRegex.test(merkleRoot)) return callback('Invalid merkle root - ' + merkleRoot);

        // Find the target proof
        var proof = receipt.proof;
        if (!proof) return callback('Missing proof');

        if (!_.isArray(proof)) return callback('Invalid proof - ' + proof);

        // ensure proof values are hex
        var allValidHashes = true;
        for (var x = 0; x < proof.length; x++) {
            var proofItemValue = proof[x].left || proof[x].right;
            if (!proofItemValue || !hashTestRegex.test(proofItemValue)) allValidHashes = false;
        }
        if (!allValidHashes) return callback('Invalid proof path');

        // ensure proof path leads to merkle root
        var merkleToolsOptions = {
            hashType: hashType
        };
        var merkleTools = new merkletools(merkleToolsOptions);
        var isValid = merkleTools.validateProof(proof, targetHash, merkleRoot);
        if (!isValid) return callback('Invalid proof path');

        // Validate at least one achor item exists
        var anchors = receipt.anchors;
        if (!anchors) return callback('Missing anchors');

        if (!_.isArray(anchors)) return callback('Invalid anchors array - ' + anchors);
        if (anchors.length === 0) return callback('Empty anchors array');

        // Validate each anchor item contents
        for (x = 0; x < anchors.length; x++) {
            var anchorType = anchors[x].type || anchors[x]['@type'];
            if (!anchorType) return callback('Missing anchor type');
            if (_.indexOf(CHAINPOINTv2_VALID_ANCHORTYPES, anchorType) == -1) return callback('Invalid anchor type - ' + anchorType);

            var sourceId = anchors[x].sourceId;
            if (!sourceId) return callback('Missing sourceId');

            switch (anchorType) {
                case 'BTCOpReturn':
                    {
                        if (!/^[A-Fa-f0-9]{64}$/.test(sourceId)) return callback('Invalid sourceId for BTCOpReturn - ' + sourceId);
                        break;
                    }
                case 'ETHData':
                    {
                        if (!/^[A-Fa-f0-9]{64}$/.test(sourceId)) return callback('Invalid sourceId for ETHData - ' + sourceId);
                        break;
                    }
            }
        }

        if (confirmAnchor) { // confirm the anchors 
            async.forEachSeries(anchors, function (anchorItem, anchorCallback) {
                var anchorType = anchorItem.type || anchorItem['@type'];
                switch (anchorType) {
                    case 'BTCOpReturn':
                        {
                            blockchainAnchor.confirm(anchorItem.sourceId, merkleRoot, function (err, result) {
                                if (err) {
                                    anchorCallback(err);
                                } else {
                                    anchorItem.exists = result;
                                    anchorCallback();
                                }
                            });
                        }
                }
                switch (anchorType) {
                    case 'ETHData':
                        {
                            blockchainAnchor.confirmEth(anchorItem.sourceId, merkleRoot, function (err, result) {
                                if (err) {
                                    anchorCallback(err);
                                } else {
                                    anchorItem.exists = result;
                                    anchorCallback();
                                }
                            });
                        }
                }
            }, function (err) {
                if (err) return callback(err);
                return callback(null, merkleRoot, anchors);
            });
        } else {
            return callback(null, merkleRoot, anchors);
        }

    }

    function _errorResult(callback, message) {
        return callback(null, {
            isValid: false,
            error: message
        });
    }

    function _validResult(callback, merkleRoot, anchorArray) {
        return callback(null, {
            isValid: true,
            merkleRoot: merkleRoot,
            anchors: anchorArray
        });
    }
};

module.exports = ChainpointValidate;