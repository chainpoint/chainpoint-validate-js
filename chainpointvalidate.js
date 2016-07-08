/*jslint node: true */
'use strict';

var _ = require('lodash');
var async = require('async');
var crypto = require('crypto');
var merkletools = require('merkle-tools');
var blockchainanchor = require('blockchain-anchor');

var ChainpointValidate = function () {
    // in case 'new' was omitted
    if (!(this instanceof ChainpointValidate)) {
        return new ChainpointValidate();
    }

    var CHAINPOINT_VALID_VERSIONS = ['1.0', '1.1', '2'];
    var CHAINPOINTv1_VALID_HASHTYPES = ['SHA-256'];
    var CHAINPOINTv2_VALID_HASHTYPES = ['SHA256', 'SHA512'];
    var CHAINPOINTv2_VALID_ANCHORTYPES = ['BTCOpReturn'];
    var blockchainAnchor = new blockchainanchor();


    ////////////////////////////////////////////
    // Public Primary functions
    ////////////////////////////////////////////

    // Returns a boolean value, true if the receipt is valid.
    this.isValidReceipt = function (receipt, confirmAnchor, callback) {

        // Ensure the receipt is not null
        if (!receipt) return _errorResult(callback, 'Cannot parse receipt JSON');

        // If the receipt is provided as a string, attempt to parse into object
        if (_.isString(receipt)) {
            try {
                receipt = JSON.parse(receipt);
            }
            catch (err) {
                return _errorResult(callback, 'Cannot parse receipt JSON');
            }
        }

        // Find the specified version of the receipt provided
        var receiptVersion = null;

        var receiptHeader = receipt.header;
        if (receiptHeader) { // header section was found, so this could be a pre-v2 receipt
            receiptVersion = receiptHeader.chainpoint_version;
        } else { // no header was found, so it is not a v1.x receipt, check for v2
            var receiptType = receipt.type || receipt['@type']; // look for 'type' attribute
            if (receiptType) {
                var typeRegex = /^Chainpoint.*v2$/;
                var isValidType = typeRegex.test(receiptType); // validate 'type' attribute value
                if (isValidType) receiptVersion = '2';
                if (!receiptVersion) return _errorResult(callback, 'Invalid Chainpoint type - ' + receiptType);
            }
        }
        if (!receiptVersion) return _errorResult(callback, 'Cannot identify Chainpoint version');


        // Ensure specified version is a valid Chainpoint version value
        if (_.indexOf(CHAINPOINT_VALID_VERSIONS, receiptVersion.toString()) == -1) return _errorResult(callback, 'Invalid Chainpoint version - ' + receiptVersion);

        switch (receiptVersion) {
            case '1.0':
            case '1.1': {
                return _validate1xReceipt(receipt, confirmAnchor, callback);
            }
            case '2': {
                return _validate2xReceipt(receipt, confirmAnchor, callback);
            }

        }
    };

    //////////////////////////////////////////
    // Private Utility functions
    //////////////////////////////////////////

    function _validate1xReceipt(receipt, confirmAnchor, callback) {

        // Find the Hash Type
        var hashType = receipt.header.hash_type;
        if (!hashType) return _errorResult(callback, 'Missing hash type');

        if (_.indexOf(CHAINPOINTv1_VALID_HASHTYPES, hashType) == -1) return _errorResult(callback, 'Invalid hash type - ' + hashType);

        // Find the Merkle Root
        var merkleRoot = receipt.header.merkle_root;
        if (!merkleRoot) return _errorResult(callback, 'Missing merkle root');

        if (!/[A-Fa-f0-9]{64}/.test(merkleRoot)) return _errorResult(callback, 'Invalid merkle root - ' + merkleRoot);

        // Find the transcation Id
        var txId = receipt.header.tx_id;
        if (!txId) return _errorResult(callback, 'Missing transaction Id');

        if (!/[A-Fa-f0-9]{64}/.test(txId)) return _errorResult(callback, 'Invalid transaction Id - ' + txId);

        // Find the timestamp
        var timestamp = receipt.header.timestamp;
        if (!timestamp) return _errorResult(callback, 'Missing timestamp');

        if (!_.isNumber(timestamp)) return _errorResult(callback, 'Invalid timestamp - ' + timestamp);

        // Find the target element
        var target = receipt.target;
        if (!target) return _errorResult(callback, 'Missing target');

        // Find the target hash
        var targetHash = receipt.target.target_hash;
        if (!targetHash) return _errorResult(callback, 'Missing target hash');

        if (!/[A-Fa-f0-9]{64}/.test(targetHash)) return _errorResult(callback, 'Invalid target hash - ' + targetHash);

        // Find the target proof
        var targetProof = receipt.target.target_proof;
        if (!targetProof) return _errorResult(callback, 'Missing target proof');

        if (!_.isArray(targetProof)) return _errorResult(callback, 'Invalid target proof - ' + targetProof);

        // validate proof path if empty
        if (targetProof.length === 0 && targetHash !== merkleRoot) {
            return _errorResult(callback, 'Invalid proof path');
        } else { // validate proof path with content
            var lastParent = targetHash;
            for (var x = 0; x < targetProof.length; x++) {

                // check for required values
                if (!targetProof[x].left || !targetProof[x].right || !targetProof[x].parent) return _errorResult(callback, 'Invalid proof path');

                // ensure parent = hash(l+r)
                var hashlr = crypto.createHash('sha256').update(targetProof[x].left).update(targetProof[x].right).digest('hex');
                if (targetProof[x].parent != hashlr) return _errorResult(callback, 'Invalid proof path');

                // check for presence of last parent
                if (targetProof[x].left != lastParent && targetProof[x].right != lastParent) {
                    return _errorResult(callback, 'Invalid proof path');
                } else {
                    lastParent = targetProof[x].parent;
                }
            }

            // ensure proof path leads to merkle root
            if (merkleRoot != lastParent) {
                return _errorResult(callback, 'Invalid proof path');
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
                        return _validResult(callback, merkleRoot, anchors);
                    }
                });
            } else {
                anchors.push(anchorItem);
                return _validResult(callback, merkleRoot, anchors);
            }

        }
    }

    function _validate2xReceipt(receipt, confirmAnchor, callback) {

        // Ensure existance of @context definition
        var context = receipt['@context'];
        if (!context) return _errorResult(callback, 'Missing @context');

        // Find the Hash Type
        var receiptType = receipt.type || receipt['@type'];
        var hashTypeRegex = /^Chainpoint(.*)v2$/;
        var hashType = hashTypeRegex.exec(receiptType)[1];
        if (!hashType) return _errorResult(callback, 'Invalid Chainpoint type - ' + receiptType);

        if (_.indexOf(CHAINPOINTv2_VALID_HASHTYPES, hashType) == -1) return _errorResult(callback, 'Invalid Chainpoint type - ' + receiptType);

        // Find the target hash
        var targetHash = receipt.targetHash;
        if (!targetHash) return _errorResult(callback, 'Missing target hash');

        if (!/[A-Fa-f0-9]{64}/.test(targetHash)) return _errorResult(callback, 'Invalid target hash - ' + targetHash);

        // Find the Merkle Root
        var merkleRoot = receipt.merkleRoot;
        if (!merkleRoot) return _errorResult(callback, 'Missing merkle root');

        if (!/[A-Fa-f0-9]{64}/.test(merkleRoot)) return _errorResult(callback, 'Invalid merkle root - ' + merkleRoot);

        // Find the target proof
        var proof = receipt.proof;
        if (!proof) return _errorResult(callback, 'Missing proof');

        if (!_.isArray(proof)) return _errorResult(callback, 'Invalid proof - ' + proof);

        // ensure proof values are hex
        var allHex = true;
        for (var x = 0; x < proof.length; x++) {
            var proofItemValue = proof[x].left || proof[x].right;
            if (!proofItemValue || !_isHex(proofItemValue)) allHex = false;
        }
        if (!allHex) return _errorResult(callback, 'Invalid proof path');

        // ensure proof path leads to merkle root
        var merkleToolsOptions = {
            hashType: hashType
        };
        var merkleTools = new merkletools(merkleToolsOptions);
        var isValid = merkleTools.validateProof(proof, targetHash, merkleRoot);
        if (!isValid) return _errorResult(callback, 'Invalid proof path');

        // Validate at least one achor item exists
        var anchors = receipt.anchors;
        if (!anchors) return _errorResult(callback, 'Missing anchors');

        if (!_.isArray(anchors)) return _errorResult(callback, 'Invalid anchors array - ' + anchors);
        if (anchors.length === 0) return _errorResult(callback, 'Empty anchors array');

        // Validate each anchor item contents
        for (x = 0; x < anchors.length; x++) {
            var anchorType = anchors[x].type || anchors[x]['@type'];
            if (!anchorType) return _errorResult(callback, 'Missing anchor type');
            if (_.indexOf(CHAINPOINTv2_VALID_ANCHORTYPES, anchorType) == -1) return _errorResult(callback, 'Invalid anchor type - ' + anchorType);

            var sourceId = anchors[x].sourceId;
            if (!sourceId) return _errorResult(callback, 'Missing sourceId');

            switch (anchorType) {
                case 'BTCOpReturn':
                    {
                        if (!/[A-Fa-f0-9]{64}/.test(sourceId)) return _errorResult(callback, 'Invalid sourceId for BTCOpReturn - ' + sourceId);
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
            }, function (err) {
                if (err) return callback(err);
                return _validResult(callback, merkleRoot, anchors);
            });
        } else {
            return _validResult(callback, merkleRoot, anchors);
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

    function _isHex(value) {
        var hexRegex = /^[0-9A-Fa-f]{2,}$/;
        return hexRegex.test(value);
    }
};

module.exports = ChainpointValidate;