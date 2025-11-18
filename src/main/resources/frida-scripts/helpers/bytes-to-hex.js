// Convert Bytes to Hex String
function bytesToHex(bytes) {
    var hex = '';
    for (var i = 0; i < bytes.length; i++) {
        hex += ('0' + (bytes[i] & 0xFF).toString(16)).slice(-2);
    }
    return hex;
}

// Convert Hex String to Bytes
function hexToBytes(hex) {
    var bytes = [];
    for (var i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return bytes;
}

// Usage Example:
// var data = [0x48, 0x65, 0x6c, 0x6c, 0x6f];
// console.log(bytesToHex(data)); // Output: 48656c6c6f
