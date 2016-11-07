/*jslint node: true */
'use strict';

var _ = require('lodash');
var async = require('async');
var crypto = require('crypto');
var merkletools = require('merkle-tools');
var blockchainanchor = require('blockchain-anchor');
var chainpointBinary = require('chainpoint-binary');
var rgxs = require('./rgxs');
var sha3_512 = require('js-sha3').sha3_512;
var sha3_384 = require('js-sha3').sha3_384;
var sha3_256 = require('js-sha3').sha3_256;
var sha3_224 = require('js-sha3').sha3_224;

var ChainpointValidate = function () {
    // in case 'new' was omitted
    if (!(this instanceof ChainpointValidate)) {
        return new ChainpointValidate();
    }

    var CHAINPOINT_VALID_VERSIONS = ['1.0', '1.1', '2'];
    var CHAINPOINTv1_VALID_HASHTYPES = ['SHA-256'];
    var CHAINPOINTv2_VALID_HASHTYPES = ['SHA224', 'SHA256', 'SHA384', 'SHA512', 'SHA3-224', 'SHA3-256', 'SHA3-384', 'SHA3-512', 'OpList'];
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

        if (hashType === 'OpList') {
            return _validate2xOpList(receipt, confirmAnchor, callback);
        } else {
            return _validate2xTypedProof(receipt, confirmAnchor, hashType, callback);
        }
    }

    function _validate2xOpList(receipt, confirmAnchor, callback) {
        var validHashOperations = ['sha-224', 'sha-256', 'sha-384', 'sha-512', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512'];

        // Find the target hash
        var targetHash = receipt.targetHash;
        if (!targetHash) return callback('Missing target hash');
        if (!rgxs.isHex(targetHash)) return callback('Invalid target hash - ' + targetHash);

        // Find the operations list
        var operations = receipt.operations;
        if (!operations) return callback('Missing operations');

        if (!_.isArray(operations)) return callback('Invalid operations - ' + operations);
        if (operations.length === 0) return callback('Invalid operations - ' + operations);

        var anchorArray = [];
        var hashResult = new Buffer(targetHash, 'hex');

        async.forEachSeries(operations, function (operation, operationCallback) {
            if (_.has(operation, 'left')) {
                if (!rgxs.isHex(operation.left)) return operationCallback('Invalid operation - ' + operation);
                hashResult = Buffer.concat([new Buffer(operation.left, 'hex'), hashResult]);
                return operationCallback();
            } else if (_.has(operation, 'right')) {
                if (!rgxs.isHex(operation.right)) return operationCallback('Invalid operation - ' + operation);
                hashResult = Buffer.concat([hashResult, new Buffer(operation.right, 'hex')]);
                return operationCallback();
            } else if (_.has(operation, 'op')) {
                if (validHashOperations.indexOf(operation.op) === -1) return operationCallback('Invalid operation - ' + operation);
                switch (operation.op) {
                    case 'sha-224':
                        hashResult = crypto.createHash('sha224').update(hashResult).digest();
                        break;
                    case 'sha-256':
                        hashResult = crypto.createHash('sha256').update(hashResult).digest();
                        break;
                    case 'sha-384':
                        hashResult = crypto.createHash('sha384').update(hashResult).digest();
                        break;
                    case 'sha-512':
                        hashResult = crypto.createHash('sha512').update(hashResult).digest();
                        break;
                    case 'sha3-224':
                        hashResult = new Buffer(sha3_224.array(hashResult));
                        break;
                    case 'sha3-256':
                        hashResult = new Buffer(sha3_256.array(hashResult));
                        break;
                    case 'sha3-384':
                        hashResult = new Buffer(sha3_384.array(hashResult));
                        break;
                    case 'sha3-512':
                        hashResult = new Buffer(sha3_512.array(hashResult));
                        break;
                }
                return operationCallback();
            } else if (_.has(operation, 'anchors')) {
                if (!_.isArray(operation.anchors)) return operationCallback('Invalid anchors operation - ' + operation.anchors);
                if (operation.anchors.length === 0) return operationCallback('Invalid anchors operation - ' + operation.anchors);

                // Validate each anchor item contents
                for (var x = 0; x < operation.anchors.length; x++) {
                    var anchorType = operation.anchors[x].type || operation.anchors[x]['@type'];
                    if (!anchorType) return operationCallback('Missing anchor type');
                    if (_.indexOf(CHAINPOINTv2_VALID_ANCHORTYPES, anchorType) == -1) return operationCallback('Invalid anchor type - ' + anchorType);

                    var sourceId = operation.anchors[x].sourceId;
                    if (!sourceId) return operationCallback('Missing sourceId');

                    switch (anchorType) {
                        case 'BTCOpReturn':
                            {
                                if (!/^[A-Fa-f0-9]{64}$/.test(sourceId)) return operationCallback('Invalid sourceId for BTCOpReturn - ' + sourceId);
                                break;
                            }
                        case 'ETHData':
                            {
                                if (!/^[A-Fa-f0-9]{64}$/.test(sourceId)) return operationCallback('Invalid sourceId for ETHData - ' + sourceId);
                                break;
                            }
                        case 'BTCBlockHeader':
                            {
                                // check sourceId exists and is an integer
                                if (!rgxs.isInt(sourceId)) return operationCallback('Invalid sourceId for BTCBlockHeader - ' + sourceId);
                                break;
                            }
                    }
                }

                async.forEachSeries(operation.anchors, function (anchor, anchorCallback) {
                    var anchorSummary = {};
                    var aType = anchor.type || anchor['@type'];
                    anchorSummary.type = aType;
                    anchorSummary.sourceId = anchor.sourceId;

                    if (confirmAnchor) {
                        switch (anchorSummary.type) {
                            case 'BTCOpReturn':
                                {
                                    blockchainAnchor.confirm(anchorSummary.sourceId, hashResult.toString('hex'), function (err, result) {
                                        if (err) {
                                            return anchorCallback(err);
                                        } else {
                                            anchorSummary.exists = result;
                                            anchorArray.push(anchorSummary);
                                            return anchorCallback();
                                        }
                                    });
                                    break;
                                }
                            case 'ETHData':
                                {
                                    blockchainAnchor.confirmEth(anchorSummary.sourceId, hashResult.toString('hex'), function (err, result) {
                                        if (err) {
                                            return anchorCallback(err);
                                        } else {
                                            anchorSummary.exists = result;
                                            anchorArray.push(anchorSummary);
                                            return anchorCallback();
                                        }
                                    });
                                    break;
                                }
                            case 'BTCBlockHeader':
                                {
                                    var hashResultHex = hashResult.toString('hex').match(/.{2}/g).reverse().join(''); // reverse bytes
                                    blockchainAnchor.confirmBTCBlockHeader(anchorSummary.sourceId, hashResultHex, function (err, result) {
                                        if (err) {
                                            return anchorCallback(err);
                                        } else {
                                            anchorSummary.exists = result;
                                            anchorArray.push(anchorSummary);
                                            return anchorCallback();
                                        }
                                    });
                                    break;
                                }
                        }
                    } else {
                        anchorArray.push(anchorSummary);
                        return anchorCallback();
                    }

                }, function (err) {
                    if (err) return operationCallback(err);
                    return operationCallback();
                });

            } else {
                return operationCallback('Invalid operation - ' + operation);
            }
        }, function (err) {
            if (err) return callback(err);
            if (anchorArray.length === 0) return callback('Missing anchors');

            return callback(null, null, anchorArray);
        });
    }

    function _validate2xTypedProof(receipt, confirmAnchor, hashType, callback) {
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

        _validateAnchors(anchors, hashTestRegex, receipt, callback);

        async.forEachSeries(anchors, function (anchorItem, anchorCallback) {
            if (confirmAnchor) {
                var anchorType = anchorItem.type || anchorItem['@type'];
                switch (anchorType) {
                    case 'BTCOpReturn':
                        {
                            blockchainAnchor.confirm(anchorItem.sourceId, merkleRoot, function (err, result) {
                                if (err) {
                                    return anchorCallback(err);
                                } else {
                                    anchorItem.exists = result;
                                    return anchorCallback();
                                }
                            });
                            break;
                        }
                    case 'ETHData':
                        {
                            blockchainAnchor.confirmEth(anchorItem.sourceId, merkleRoot, function (err, result) {
                                if (err) {
                                    return anchorCallback(err);
                                } else {
                                    anchorItem.exists = result;
                                    return anchorCallback();
                                }
                            });
                            break;
                        }
                    case 'BTCBlockHeader':
                        {
                            var hashResult = new Buffer(anchorItem.tx, 'hex');

                            hashResult = crypto.createHash('sha256').update(hashResult).digest();
                            hashResult = crypto.createHash('sha256').update(hashResult).digest(); // this should be the tx id
                            for (var x = 0; x < anchorItem.blockProof.length; x++) {
                                if (anchorItem.blockProof[x].left) {
                                    hashResult = Buffer.concat([new Buffer(anchorItem.blockProof[x].left, 'hex'), hashResult]);
                                } else if (anchorItem.blockProof[x].right) {
                                    hashResult = Buffer.concat([hashResult, new Buffer(anchorItem.blockProof[x].right, 'hex')]);
                                }
                                hashResult = crypto.createHash('sha256').update(hashResult).digest();
                                hashResult = crypto.createHash('sha256').update(hashResult).digest();
                            }
                            var hashResultHex = hashResult.toString('hex').match(/.{2}/g).reverse().join(''); // reverse bytes
                            blockchainAnchor.confirmBTCBlockHeader(anchorItem.sourceId, hashResultHex, function (err, result) {
                                if (err) {
                                    return anchorCallback(err);
                                } else {
                                    anchorItem.exists = result;
                                    return anchorCallback();
                                }
                            });
                            break;
                        }
                }
            } else {
                return anchorCallback();
            }
        }, function (err) {
            if (err) return callback(err);
            for (x = 0; x < anchors.length; x++) {
                var anchorSummary = {};
                var aType = anchors[x].type || anchors[x]['@type'];
                anchorSummary.type = aType;
                anchorSummary.sourceId = anchors[x].sourceId;
                if (_.has(anchors[x], 'exists')) anchorSummary.exists = anchors[x].exists;
                anchors[x] = anchorSummary;
            }
            return callback(null, merkleRoot, anchors);
        });



    }

    function _validateAnchors(anchors, hashTestRegex, receipt, callback) {
        // Validate each anchor item contents
        for (var x = 0; x < anchors.length; x++) {
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
                case 'BTCBlockHeader':
                    {
                        // check sourceId exists and is an integer
                        if (!rgxs.isInt(sourceId)) return callback('Invalid sourceId for BTCBlockHeader - ' + sourceId);

                        // check tx exists, is a hex string, and contains the merkle root value
                        var tx = anchors[x].tx;
                        if (!tx) return callback('Missing tx value');
                        if (!rgxs.isHex(tx)) return callback('Invalid tx value');
                        if (tx.indexOf(receipt.merkleRoot) === -1) return callback('Merkle root not found in tx value');

                        // Find the block proof
                        var blockProof = receipt.anchors[x].blockProof;
                        if (!blockProof) return callback('Missing block proof');

                        if (!_.isArray(blockProof)) return callback('Invalid block proof');
                        if (blockProof.length === 0) return callback('Invalid block proof');

                        // ensure block proof values are hex
                        var allValidHashes = true;
                        for (var y = 0; y < blockProof.length; y++) {
                            var blockProofItemValue = blockProof[y].left || blockProof[y].right;
                            if (!blockProofItemValue || !hashTestRegex.test(blockProofItemValue)) allValidHashes = false;
                        }
                        if (!allValidHashes) return callback('Invalid block proof path');

                        break;
                    }
            }
        }
    }

    function _errorResult(callback, message) {
        return callback(null, {
            isValid: false,
            error: message
        });
    }

    function _validResult(callback, merkleRoot, anchorArray) {
        if (merkleRoot) {
            return callback(null, {
                isValid: true,
                merkleRoot: merkleRoot,
                anchors: anchorArray
            });
        } else {
            return callback(null, {
                isValid: true,
                anchors: anchorArray
            });
        }
    }
};

module.exports = ChainpointValidate;