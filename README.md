# chainpoint-validate-js

[![npm](https://img.shields.io/npm/l/chainpoint-validate.svg)](https://www.npmjs.com/package/chainpoint-validate)
[![npm](https://img.shields.io/npm/v/chainpoint-validate.svg)](https://www.npmjs.com/package/chainpoint-validate)

A Node.js module for validating Chainpoint blockchain receipts

### Installation

```
$ npm install --save chainpoint-validate
```

### Usage

Use the isValidReceipt function to validate your Chainpoint receipt. 
```js
chainpointValidate.isValidReceipt(receipt, confirmAnchor, callback);
/*
  receipt - the receipt to be validated, as a string or JSON
  confirmAnchor - boolean indicating whether you want to confirm the existence of the anchor at its source. True to confirm that the merkle root is stored at the source specified in the anchor object of the receipt (such as in a bitcoin transaction's OP_RETURN value). Will append an 'exists' value to the anchor object in the results when True. False to validate only the receipt content and proof data. 
  callback - This function should expect an error message as its first parameter, and a result object as its second parameter
*/
```

#### Example

```js
var chainpointvalidate = require('chainpoint-validate');

var chainpointValidate = new chainpointvalidate();

var validReceipt = {
 "@context": "https://w3id.org/chainpoint/v2",
 "type": "ChainpointSHA256v2",
 "targetHash": "bdf8c9bdf076d6aff0292a1c9448691d2ae283f2ce41b045355e2c8cb8e85ef2",
 "merkleRoot": "51296468ea48ddbcc546abb85b935c73058fd8acdb0b953da6aa1ae966581a7a",
 "proof": [
   {
     "left": "bdf8c9bdf076d6aff0292a1c9448691d2ae283f2ce41b045355e2c8cb8e85ef2"
   },
   {
     "left": "cb0dbbedb5ec5363e39be9fc43f56f321e1572cfcf304d26fc67cb6ea2e49faf"
   },
   {
     "right": "cb0dbbedb5ec5363e39be9fc43f56f321e1572cfcf304d26fc67cb6ea2e49faf"
   }
 ],
 "anchors": [
   {
     "type": "BTCOpReturn",
     "sourceId": "f3be82fe1b5d8f18e009cb9a491781289d2e01678311fe2b2e4e84381aafadee"
   }
 ]
};
var invalidReceipt = "not a receipt";

chainpointValidate.isValidReceipt(validReceipt, true, function (err, result) {
  if(err) {
    // handle this error
  } else {
    // result.isValid will equal true
    // result.anchors will be an array of anchor objects, optionally including
    // an exists parameter, if you configured validation to confirm the anchor as well
  }
});

chainpointValidate.isValidReceipt(invalidReceipt, true, function (err, result) {
  if(err) {
    // handle this error
  } else {
    // result.isValid will equal false
    // result.error will contain a reason why the receipt failed validation
  }
});
```

##### Sample Valid Result
```js
{
  isValid: true,
  anchors: [
    {
      type: 'BTCOpReturn',
      sourceId: '4f0398f4707c7ddb8d5a85508bdaa9e22fb541fa0182ae54f25513b6bd3f8cb9',
      exists: true
    }
  ]
}
```
The 'exists' value is only added when 'confirmAnchor' was set to true.

##### Sample Invalid Result
```js
{
  isValid: false,
  error: 'Cannot parse receipt JSON'
}
```
