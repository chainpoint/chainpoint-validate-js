/*jslint node: true */
'use strict';

module.exports = {
    isHex: function (value) {
        var hexRegex = /^[0-9A-Fa-f]{2,}$/;
        return hexRegex.test(value);
    },
    isInt: function (value) {
        var intRegex = /^(0|[1-9]\d*)$/;
        return intRegex.test(value);
    }
};