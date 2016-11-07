/*jslint node: true */
'use strict';

module.exports = {
    isHex: function (value) {
        var hexRegex = /^[0-9A-Fa-f]{2,}$/;
        var result = hexRegex.test(value);
        if (result) result = value.length % 2 ? false : true;
        return result;
    },
    isInt: function (value) {
        var intRegex = /^(0|[1-9]\d*)$/;
        return intRegex.test(value);
    }
};