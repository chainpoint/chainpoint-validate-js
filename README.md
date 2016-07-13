# chainpoint-validate-js

[![npm](https://img.shields.io/npm/l/chainpoint-validate.svg)](https://www.npmjs.com/package/chainpoint-validate)
[![npm](https://img.shields.io/npm/v/chainpoint-validate.svg)](https://www.npmjs.com/package/chainpoint-validate)

A Node.js module for validating Chainpoint blockchain receipts used by Tierion

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

var validReceipt = { /* some valid receipt data */ };
var invalidReceipt = "not a receipt";

chainpointValidate.isValidReceipt(validReceipt, true, function (err, result) {
  if(err) {
    // handle this error
  } else {
    // receipt.isValid will equal true
    // receipt.anchors will be an array of anchor objects, optionally including
    // an exists parameter, if you configured validation to confirm the anchor as well
  }
});

chainpointValidate.isValidReceipt(invalidReceipt, true, function (err, result) {
  if(err) {
    // handle this error
  } else {
    // receipt.isValid will equal false
    // receipt.error will contain a reason why the receipt failed validation
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
