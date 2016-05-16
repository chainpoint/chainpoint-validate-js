# chainpoint-validate-js

[![npm](https://img.shields.io/npm/l/chainpoint-validate.svg)](https://www.npmjs.com/package/chainpoint-validate)
[![npm](https://img.shields.io/npm/v/chainpoint-validate.svg)](https://www.npmjs.com/package/chainpoint-validate)

A Node.js module for validating Tierion's Chainpoint blockchain receipts

### Installation

```
$ npm install --save chainpoint-validate
```

### Usage

Use the isValidReceipt function to validate your Chainpoint receipt. You may supply the receipt as a string or as a JSON object. The function returns an object with the boolean parameter isValid. If isValid is false, you will also receive an error parameter describing what caused validation to fail.

#### Example

```js
var validator = require('chainpoint-validate');

var validReceipt = { /* some valid receipt data */ };
var invalidReceipt = "not a receipt";

var validResult = validator.isValidReceipt(validReceipt);

/*
validResult will be -> { "isValid": true }
*/

var invalidResult = validator.isValidReceipt(invalidReceipt);

/*
invalidResult will be -> { "isValid": false, "error": "Cannot parse receipt JSON" }
*/
```
