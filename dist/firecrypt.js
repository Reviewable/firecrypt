/******/ (function(modules) { // webpackBootstrap
/******/ 	// The module cache
/******/ 	var installedModules = {};
/******/
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/
/******/ 		// Check if module is in cache
/******/ 		if(installedModules[moduleId]) {
/******/ 			return installedModules[moduleId].exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = installedModules[moduleId] = {
/******/ 			i: moduleId,
/******/ 			l: false,
/******/ 			exports: {}
/******/ 		};
/******/
/******/ 		// Execute the module function
/******/ 		modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/
/******/ 		// Flag the module as loaded
/******/ 		module.l = true;
/******/
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/
/******/
/******/ 	// expose the modules object (__webpack_modules__)
/******/ 	__webpack_require__.m = modules;
/******/
/******/ 	// expose the module cache
/******/ 	__webpack_require__.c = installedModules;
/******/
/******/ 	// define getter function for harmony exports
/******/ 	__webpack_require__.d = function(exports, name, getter) {
/******/ 		if(!__webpack_require__.o(exports, name)) {
/******/ 			Object.defineProperty(exports, name, { enumerable: true, get: getter });
/******/ 		}
/******/ 	};
/******/
/******/ 	// define __esModule on exports
/******/ 	__webpack_require__.r = function(exports) {
/******/ 		if(typeof Symbol !== 'undefined' && Symbol.toStringTag) {
/******/ 			Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
/******/ 		}
/******/ 		Object.defineProperty(exports, '__esModule', { value: true });
/******/ 	};
/******/
/******/ 	// create a fake namespace object
/******/ 	// mode & 1: value is a module id, require it
/******/ 	// mode & 2: merge all properties of value into the ns
/******/ 	// mode & 4: return value when already ns object
/******/ 	// mode & 8|1: behave like require
/******/ 	__webpack_require__.t = function(value, mode) {
/******/ 		if(mode & 1) value = __webpack_require__(value);
/******/ 		if(mode & 8) return value;
/******/ 		if((mode & 4) && typeof value === 'object' && value && value.__esModule) return value;
/******/ 		var ns = Object.create(null);
/******/ 		__webpack_require__.r(ns);
/******/ 		Object.defineProperty(ns, 'default', { enumerable: true, value: value });
/******/ 		if(mode & 2 && typeof value != 'string') for(var key in value) __webpack_require__.d(ns, key, function(key) { return value[key]; }.bind(null, key));
/******/ 		return ns;
/******/ 	};
/******/
/******/ 	// getDefaultExport function for compatibility with non-harmony modules
/******/ 	__webpack_require__.n = function(module) {
/******/ 		var getter = module && module.__esModule ?
/******/ 			function getDefault() { return module['default']; } :
/******/ 			function getModuleExports() { return module; };
/******/ 		__webpack_require__.d(getter, 'a', getter);
/******/ 		return getter;
/******/ 	};
/******/
/******/ 	// Object.prototype.hasOwnProperty.call
/******/ 	__webpack_require__.o = function(object, property) { return Object.prototype.hasOwnProperty.call(object, property); };
/******/
/******/ 	// __webpack_public_path__
/******/ 	__webpack_require__.p = "";
/******/
/******/
/******/ 	// Load entry module and return exports
/******/ 	return __webpack_require__(__webpack_require__.s = "./index.js");
/******/ })
/************************************************************************/
/******/ ({

/***/ "./index.js":
/*!******************!*\
  !*** ./index.js ***!
  \******************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

module.exports = __webpack_require__(/*! ./src/firecrypt.js */ "./src/firecrypt.js");


/***/ }),

/***/ "./node_modules/crypto-js/aes.js":
/*!***************************************!*\
  !*** ./node_modules/crypto-js/aes.js ***!
  \***************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"), __webpack_require__(/*! ./enc-base64 */ "./node_modules/crypto-js/enc-base64.js"), __webpack_require__(/*! ./md5 */ "./node_modules/crypto-js/md5.js"), __webpack_require__(/*! ./evpkdf */ "./node_modules/crypto-js/evpkdf.js"), __webpack_require__(/*! ./cipher-core */ "./node_modules/crypto-js/cipher-core.js"));
	}
	else {}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var BlockCipher = C_lib.BlockCipher;
	    var C_algo = C.algo;

	    // Lookup tables
	    var SBOX = [];
	    var INV_SBOX = [];
	    var SUB_MIX_0 = [];
	    var SUB_MIX_1 = [];
	    var SUB_MIX_2 = [];
	    var SUB_MIX_3 = [];
	    var INV_SUB_MIX_0 = [];
	    var INV_SUB_MIX_1 = [];
	    var INV_SUB_MIX_2 = [];
	    var INV_SUB_MIX_3 = [];

	    // Compute lookup tables
	    (function () {
	        // Compute double table
	        var d = [];
	        for (var i = 0; i < 256; i++) {
	            if (i < 128) {
	                d[i] = i << 1;
	            } else {
	                d[i] = (i << 1) ^ 0x11b;
	            }
	        }

	        // Walk GF(2^8)
	        var x = 0;
	        var xi = 0;
	        for (var i = 0; i < 256; i++) {
	            // Compute sbox
	            var sx = xi ^ (xi << 1) ^ (xi << 2) ^ (xi << 3) ^ (xi << 4);
	            sx = (sx >>> 8) ^ (sx & 0xff) ^ 0x63;
	            SBOX[x] = sx;
	            INV_SBOX[sx] = x;

	            // Compute multiplication
	            var x2 = d[x];
	            var x4 = d[x2];
	            var x8 = d[x4];

	            // Compute sub bytes, mix columns tables
	            var t = (d[sx] * 0x101) ^ (sx * 0x1010100);
	            SUB_MIX_0[x] = (t << 24) | (t >>> 8);
	            SUB_MIX_1[x] = (t << 16) | (t >>> 16);
	            SUB_MIX_2[x] = (t << 8)  | (t >>> 24);
	            SUB_MIX_3[x] = t;

	            // Compute inv sub bytes, inv mix columns tables
	            var t = (x8 * 0x1010101) ^ (x4 * 0x10001) ^ (x2 * 0x101) ^ (x * 0x1010100);
	            INV_SUB_MIX_0[sx] = (t << 24) | (t >>> 8);
	            INV_SUB_MIX_1[sx] = (t << 16) | (t >>> 16);
	            INV_SUB_MIX_2[sx] = (t << 8)  | (t >>> 24);
	            INV_SUB_MIX_3[sx] = t;

	            // Compute next counter
	            if (!x) {
	                x = xi = 1;
	            } else {
	                x = x2 ^ d[d[d[x8 ^ x2]]];
	                xi ^= d[d[xi]];
	            }
	        }
	    }());

	    // Precomputed Rcon lookup
	    var RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

	    /**
	     * AES block cipher algorithm.
	     */
	    var AES = C_algo.AES = BlockCipher.extend({
	        _doReset: function () {
	            // Skip reset of nRounds has been set before and key did not change
	            if (this._nRounds && this._keyPriorReset === this._key) {
	                return;
	            }

	            // Shortcuts
	            var key = this._keyPriorReset = this._key;
	            var keyWords = key.words;
	            var keySize = key.sigBytes / 4;

	            // Compute number of rounds
	            var nRounds = this._nRounds = keySize + 6;

	            // Compute number of key schedule rows
	            var ksRows = (nRounds + 1) * 4;

	            // Compute key schedule
	            var keySchedule = this._keySchedule = [];
	            for (var ksRow = 0; ksRow < ksRows; ksRow++) {
	                if (ksRow < keySize) {
	                    keySchedule[ksRow] = keyWords[ksRow];
	                } else {
	                    var t = keySchedule[ksRow - 1];

	                    if (!(ksRow % keySize)) {
	                        // Rot word
	                        t = (t << 8) | (t >>> 24);

	                        // Sub word
	                        t = (SBOX[t >>> 24] << 24) | (SBOX[(t >>> 16) & 0xff] << 16) | (SBOX[(t >>> 8) & 0xff] << 8) | SBOX[t & 0xff];

	                        // Mix Rcon
	                        t ^= RCON[(ksRow / keySize) | 0] << 24;
	                    } else if (keySize > 6 && ksRow % keySize == 4) {
	                        // Sub word
	                        t = (SBOX[t >>> 24] << 24) | (SBOX[(t >>> 16) & 0xff] << 16) | (SBOX[(t >>> 8) & 0xff] << 8) | SBOX[t & 0xff];
	                    }

	                    keySchedule[ksRow] = keySchedule[ksRow - keySize] ^ t;
	                }
	            }

	            // Compute inv key schedule
	            var invKeySchedule = this._invKeySchedule = [];
	            for (var invKsRow = 0; invKsRow < ksRows; invKsRow++) {
	                var ksRow = ksRows - invKsRow;

	                if (invKsRow % 4) {
	                    var t = keySchedule[ksRow];
	                } else {
	                    var t = keySchedule[ksRow - 4];
	                }

	                if (invKsRow < 4 || ksRow <= 4) {
	                    invKeySchedule[invKsRow] = t;
	                } else {
	                    invKeySchedule[invKsRow] = INV_SUB_MIX_0[SBOX[t >>> 24]] ^ INV_SUB_MIX_1[SBOX[(t >>> 16) & 0xff]] ^
	                                               INV_SUB_MIX_2[SBOX[(t >>> 8) & 0xff]] ^ INV_SUB_MIX_3[SBOX[t & 0xff]];
	                }
	            }
	        },

	        encryptBlock: function (M, offset) {
	            this._doCryptBlock(M, offset, this._keySchedule, SUB_MIX_0, SUB_MIX_1, SUB_MIX_2, SUB_MIX_3, SBOX);
	        },

	        decryptBlock: function (M, offset) {
	            // Swap 2nd and 4th rows
	            var t = M[offset + 1];
	            M[offset + 1] = M[offset + 3];
	            M[offset + 3] = t;

	            this._doCryptBlock(M, offset, this._invKeySchedule, INV_SUB_MIX_0, INV_SUB_MIX_1, INV_SUB_MIX_2, INV_SUB_MIX_3, INV_SBOX);

	            // Inv swap 2nd and 4th rows
	            var t = M[offset + 1];
	            M[offset + 1] = M[offset + 3];
	            M[offset + 3] = t;
	        },

	        _doCryptBlock: function (M, offset, keySchedule, SUB_MIX_0, SUB_MIX_1, SUB_MIX_2, SUB_MIX_3, SBOX) {
	            // Shortcut
	            var nRounds = this._nRounds;

	            // Get input, add round key
	            var s0 = M[offset]     ^ keySchedule[0];
	            var s1 = M[offset + 1] ^ keySchedule[1];
	            var s2 = M[offset + 2] ^ keySchedule[2];
	            var s3 = M[offset + 3] ^ keySchedule[3];

	            // Key schedule row counter
	            var ksRow = 4;

	            // Rounds
	            for (var round = 1; round < nRounds; round++) {
	                // Shift rows, sub bytes, mix columns, add round key
	                var t0 = SUB_MIX_0[s0 >>> 24] ^ SUB_MIX_1[(s1 >>> 16) & 0xff] ^ SUB_MIX_2[(s2 >>> 8) & 0xff] ^ SUB_MIX_3[s3 & 0xff] ^ keySchedule[ksRow++];
	                var t1 = SUB_MIX_0[s1 >>> 24] ^ SUB_MIX_1[(s2 >>> 16) & 0xff] ^ SUB_MIX_2[(s3 >>> 8) & 0xff] ^ SUB_MIX_3[s0 & 0xff] ^ keySchedule[ksRow++];
	                var t2 = SUB_MIX_0[s2 >>> 24] ^ SUB_MIX_1[(s3 >>> 16) & 0xff] ^ SUB_MIX_2[(s0 >>> 8) & 0xff] ^ SUB_MIX_3[s1 & 0xff] ^ keySchedule[ksRow++];
	                var t3 = SUB_MIX_0[s3 >>> 24] ^ SUB_MIX_1[(s0 >>> 16) & 0xff] ^ SUB_MIX_2[(s1 >>> 8) & 0xff] ^ SUB_MIX_3[s2 & 0xff] ^ keySchedule[ksRow++];

	                // Update state
	                s0 = t0;
	                s1 = t1;
	                s2 = t2;
	                s3 = t3;
	            }

	            // Shift rows, sub bytes, add round key
	            var t0 = ((SBOX[s0 >>> 24] << 24) | (SBOX[(s1 >>> 16) & 0xff] << 16) | (SBOX[(s2 >>> 8) & 0xff] << 8) | SBOX[s3 & 0xff]) ^ keySchedule[ksRow++];
	            var t1 = ((SBOX[s1 >>> 24] << 24) | (SBOX[(s2 >>> 16) & 0xff] << 16) | (SBOX[(s3 >>> 8) & 0xff] << 8) | SBOX[s0 & 0xff]) ^ keySchedule[ksRow++];
	            var t2 = ((SBOX[s2 >>> 24] << 24) | (SBOX[(s3 >>> 16) & 0xff] << 16) | (SBOX[(s0 >>> 8) & 0xff] << 8) | SBOX[s1 & 0xff]) ^ keySchedule[ksRow++];
	            var t3 = ((SBOX[s3 >>> 24] << 24) | (SBOX[(s0 >>> 16) & 0xff] << 16) | (SBOX[(s1 >>> 8) & 0xff] << 8) | SBOX[s2 & 0xff]) ^ keySchedule[ksRow++];

	            // Set output
	            M[offset]     = t0;
	            M[offset + 1] = t1;
	            M[offset + 2] = t2;
	            M[offset + 3] = t3;
	        },

	        keySize: 256/32
	    });

	    /**
	     * Shortcut functions to the cipher's object interface.
	     *
	     * @example
	     *
	     *     var ciphertext = CryptoJS.AES.encrypt(message, key, cfg);
	     *     var plaintext  = CryptoJS.AES.decrypt(ciphertext, key, cfg);
	     */
	    C.AES = BlockCipher._createHelper(AES);
	}());


	return CryptoJS.AES;

}));

/***/ }),

/***/ "./node_modules/crypto-js/cipher-core.js":
/*!***********************************************!*\
  !*** ./node_modules/crypto-js/cipher-core.js ***!
  \***********************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"), __webpack_require__(/*! ./evpkdf */ "./node_modules/crypto-js/evpkdf.js"));
	}
	else {}
}(this, function (CryptoJS) {

	/**
	 * Cipher core components.
	 */
	CryptoJS.lib.Cipher || (function (undefined) {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var Base = C_lib.Base;
	    var WordArray = C_lib.WordArray;
	    var BufferedBlockAlgorithm = C_lib.BufferedBlockAlgorithm;
	    var C_enc = C.enc;
	    var Utf8 = C_enc.Utf8;
	    var Base64 = C_enc.Base64;
	    var C_algo = C.algo;
	    var EvpKDF = C_algo.EvpKDF;

	    /**
	     * Abstract base cipher template.
	     *
	     * @property {number} keySize This cipher's key size. Default: 4 (128 bits)
	     * @property {number} ivSize This cipher's IV size. Default: 4 (128 bits)
	     * @property {number} _ENC_XFORM_MODE A constant representing encryption mode.
	     * @property {number} _DEC_XFORM_MODE A constant representing decryption mode.
	     */
	    var Cipher = C_lib.Cipher = BufferedBlockAlgorithm.extend({
	        /**
	         * Configuration options.
	         *
	         * @property {WordArray} iv The IV to use for this operation.
	         */
	        cfg: Base.extend(),

	        /**
	         * Creates this cipher in encryption mode.
	         *
	         * @param {WordArray} key The key.
	         * @param {Object} cfg (Optional) The configuration options to use for this operation.
	         *
	         * @return {Cipher} A cipher instance.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var cipher = CryptoJS.algo.AES.createEncryptor(keyWordArray, { iv: ivWordArray });
	         */
	        createEncryptor: function (key, cfg) {
	            return this.create(this._ENC_XFORM_MODE, key, cfg);
	        },

	        /**
	         * Creates this cipher in decryption mode.
	         *
	         * @param {WordArray} key The key.
	         * @param {Object} cfg (Optional) The configuration options to use for this operation.
	         *
	         * @return {Cipher} A cipher instance.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var cipher = CryptoJS.algo.AES.createDecryptor(keyWordArray, { iv: ivWordArray });
	         */
	        createDecryptor: function (key, cfg) {
	            return this.create(this._DEC_XFORM_MODE, key, cfg);
	        },

	        /**
	         * Initializes a newly created cipher.
	         *
	         * @param {number} xformMode Either the encryption or decryption transormation mode constant.
	         * @param {WordArray} key The key.
	         * @param {Object} cfg (Optional) The configuration options to use for this operation.
	         *
	         * @example
	         *
	         *     var cipher = CryptoJS.algo.AES.create(CryptoJS.algo.AES._ENC_XFORM_MODE, keyWordArray, { iv: ivWordArray });
	         */
	        init: function (xformMode, key, cfg) {
	            // Apply config defaults
	            this.cfg = this.cfg.extend(cfg);

	            // Store transform mode and key
	            this._xformMode = xformMode;
	            this._key = key;

	            // Set initial values
	            this.reset();
	        },

	        /**
	         * Resets this cipher to its initial state.
	         *
	         * @example
	         *
	         *     cipher.reset();
	         */
	        reset: function () {
	            // Reset data buffer
	            BufferedBlockAlgorithm.reset.call(this);

	            // Perform concrete-cipher logic
	            this._doReset();
	        },

	        /**
	         * Adds data to be encrypted or decrypted.
	         *
	         * @param {WordArray|string} dataUpdate The data to encrypt or decrypt.
	         *
	         * @return {WordArray} The data after processing.
	         *
	         * @example
	         *
	         *     var encrypted = cipher.process('data');
	         *     var encrypted = cipher.process(wordArray);
	         */
	        process: function (dataUpdate) {
	            // Append
	            this._append(dataUpdate);

	            // Process available blocks
	            return this._process();
	        },

	        /**
	         * Finalizes the encryption or decryption process.
	         * Note that the finalize operation is effectively a destructive, read-once operation.
	         *
	         * @param {WordArray|string} dataUpdate The final data to encrypt or decrypt.
	         *
	         * @return {WordArray} The data after final processing.
	         *
	         * @example
	         *
	         *     var encrypted = cipher.finalize();
	         *     var encrypted = cipher.finalize('data');
	         *     var encrypted = cipher.finalize(wordArray);
	         */
	        finalize: function (dataUpdate) {
	            // Final data update
	            if (dataUpdate) {
	                this._append(dataUpdate);
	            }

	            // Perform concrete-cipher logic
	            var finalProcessedData = this._doFinalize();

	            return finalProcessedData;
	        },

	        keySize: 128/32,

	        ivSize: 128/32,

	        _ENC_XFORM_MODE: 1,

	        _DEC_XFORM_MODE: 2,

	        /**
	         * Creates shortcut functions to a cipher's object interface.
	         *
	         * @param {Cipher} cipher The cipher to create a helper for.
	         *
	         * @return {Object} An object with encrypt and decrypt shortcut functions.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var AES = CryptoJS.lib.Cipher._createHelper(CryptoJS.algo.AES);
	         */
	        _createHelper: (function () {
	            function selectCipherStrategy(key) {
	                if (typeof key == 'string') {
	                    return PasswordBasedCipher;
	                } else {
	                    return SerializableCipher;
	                }
	            }

	            return function (cipher) {
	                return {
	                    encrypt: function (message, key, cfg) {
	                        return selectCipherStrategy(key).encrypt(cipher, message, key, cfg);
	                    },

	                    decrypt: function (ciphertext, key, cfg) {
	                        return selectCipherStrategy(key).decrypt(cipher, ciphertext, key, cfg);
	                    }
	                };
	            };
	        }())
	    });

	    /**
	     * Abstract base stream cipher template.
	     *
	     * @property {number} blockSize The number of 32-bit words this cipher operates on. Default: 1 (32 bits)
	     */
	    var StreamCipher = C_lib.StreamCipher = Cipher.extend({
	        _doFinalize: function () {
	            // Process partial blocks
	            var finalProcessedBlocks = this._process(!!'flush');

	            return finalProcessedBlocks;
	        },

	        blockSize: 1
	    });

	    /**
	     * Mode namespace.
	     */
	    var C_mode = C.mode = {};

	    /**
	     * Abstract base block cipher mode template.
	     */
	    var BlockCipherMode = C_lib.BlockCipherMode = Base.extend({
	        /**
	         * Creates this mode for encryption.
	         *
	         * @param {Cipher} cipher A block cipher instance.
	         * @param {Array} iv The IV words.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var mode = CryptoJS.mode.CBC.createEncryptor(cipher, iv.words);
	         */
	        createEncryptor: function (cipher, iv) {
	            return this.Encryptor.create(cipher, iv);
	        },

	        /**
	         * Creates this mode for decryption.
	         *
	         * @param {Cipher} cipher A block cipher instance.
	         * @param {Array} iv The IV words.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var mode = CryptoJS.mode.CBC.createDecryptor(cipher, iv.words);
	         */
	        createDecryptor: function (cipher, iv) {
	            return this.Decryptor.create(cipher, iv);
	        },

	        /**
	         * Initializes a newly created mode.
	         *
	         * @param {Cipher} cipher A block cipher instance.
	         * @param {Array} iv The IV words.
	         *
	         * @example
	         *
	         *     var mode = CryptoJS.mode.CBC.Encryptor.create(cipher, iv.words);
	         */
	        init: function (cipher, iv) {
	            this._cipher = cipher;
	            this._iv = iv;
	        }
	    });

	    /**
	     * Cipher Block Chaining mode.
	     */
	    var CBC = C_mode.CBC = (function () {
	        /**
	         * Abstract base CBC mode.
	         */
	        var CBC = BlockCipherMode.extend();

	        /**
	         * CBC encryptor.
	         */
	        CBC.Encryptor = CBC.extend({
	            /**
	             * Processes the data block at offset.
	             *
	             * @param {Array} words The data words to operate on.
	             * @param {number} offset The offset where the block starts.
	             *
	             * @example
	             *
	             *     mode.processBlock(data.words, offset);
	             */
	            processBlock: function (words, offset) {
	                // Shortcuts
	                var cipher = this._cipher;
	                var blockSize = cipher.blockSize;

	                // XOR and encrypt
	                xorBlock.call(this, words, offset, blockSize);
	                cipher.encryptBlock(words, offset);

	                // Remember this block to use with next block
	                this._prevBlock = words.slice(offset, offset + blockSize);
	            }
	        });

	        /**
	         * CBC decryptor.
	         */
	        CBC.Decryptor = CBC.extend({
	            /**
	             * Processes the data block at offset.
	             *
	             * @param {Array} words The data words to operate on.
	             * @param {number} offset The offset where the block starts.
	             *
	             * @example
	             *
	             *     mode.processBlock(data.words, offset);
	             */
	            processBlock: function (words, offset) {
	                // Shortcuts
	                var cipher = this._cipher;
	                var blockSize = cipher.blockSize;

	                // Remember this block to use with next block
	                var thisBlock = words.slice(offset, offset + blockSize);

	                // Decrypt and XOR
	                cipher.decryptBlock(words, offset);
	                xorBlock.call(this, words, offset, blockSize);

	                // This block becomes the previous block
	                this._prevBlock = thisBlock;
	            }
	        });

	        function xorBlock(words, offset, blockSize) {
	            // Shortcut
	            var iv = this._iv;

	            // Choose mixing block
	            if (iv) {
	                var block = iv;

	                // Remove IV for subsequent blocks
	                this._iv = undefined;
	            } else {
	                var block = this._prevBlock;
	            }

	            // XOR blocks
	            for (var i = 0; i < blockSize; i++) {
	                words[offset + i] ^= block[i];
	            }
	        }

	        return CBC;
	    }());

	    /**
	     * Padding namespace.
	     */
	    var C_pad = C.pad = {};

	    /**
	     * PKCS #5/7 padding strategy.
	     */
	    var Pkcs7 = C_pad.Pkcs7 = {
	        /**
	         * Pads data using the algorithm defined in PKCS #5/7.
	         *
	         * @param {WordArray} data The data to pad.
	         * @param {number} blockSize The multiple that the data should be padded to.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     CryptoJS.pad.Pkcs7.pad(wordArray, 4);
	         */
	        pad: function (data, blockSize) {
	            // Shortcut
	            var blockSizeBytes = blockSize * 4;

	            // Count padding bytes
	            var nPaddingBytes = blockSizeBytes - data.sigBytes % blockSizeBytes;

	            // Create padding word
	            var paddingWord = (nPaddingBytes << 24) | (nPaddingBytes << 16) | (nPaddingBytes << 8) | nPaddingBytes;

	            // Create padding
	            var paddingWords = [];
	            for (var i = 0; i < nPaddingBytes; i += 4) {
	                paddingWords.push(paddingWord);
	            }
	            var padding = WordArray.create(paddingWords, nPaddingBytes);

	            // Add padding
	            data.concat(padding);
	        },

	        /**
	         * Unpads data that had been padded using the algorithm defined in PKCS #5/7.
	         *
	         * @param {WordArray} data The data to unpad.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     CryptoJS.pad.Pkcs7.unpad(wordArray);
	         */
	        unpad: function (data) {
	            // Get number of padding bytes from last byte
	            var nPaddingBytes = data.words[(data.sigBytes - 1) >>> 2] & 0xff;

	            // Remove padding
	            data.sigBytes -= nPaddingBytes;
	        }
	    };

	    /**
	     * Abstract base block cipher template.
	     *
	     * @property {number} blockSize The number of 32-bit words this cipher operates on. Default: 4 (128 bits)
	     */
	    var BlockCipher = C_lib.BlockCipher = Cipher.extend({
	        /**
	         * Configuration options.
	         *
	         * @property {Mode} mode The block mode to use. Default: CBC
	         * @property {Padding} padding The padding strategy to use. Default: Pkcs7
	         */
	        cfg: Cipher.cfg.extend({
	            mode: CBC,
	            padding: Pkcs7
	        }),

	        reset: function () {
	            // Reset cipher
	            Cipher.reset.call(this);

	            // Shortcuts
	            var cfg = this.cfg;
	            var iv = cfg.iv;
	            var mode = cfg.mode;

	            // Reset block mode
	            if (this._xformMode == this._ENC_XFORM_MODE) {
	                var modeCreator = mode.createEncryptor;
	            } else /* if (this._xformMode == this._DEC_XFORM_MODE) */ {
	                var modeCreator = mode.createDecryptor;
	                // Keep at least one block in the buffer for unpadding
	                this._minBufferSize = 1;
	            }

	            if (this._mode && this._mode.__creator == modeCreator) {
	                this._mode.init(this, iv && iv.words);
	            } else {
	                this._mode = modeCreator.call(mode, this, iv && iv.words);
	                this._mode.__creator = modeCreator;
	            }
	        },

	        _doProcessBlock: function (words, offset) {
	            this._mode.processBlock(words, offset);
	        },

	        _doFinalize: function () {
	            // Shortcut
	            var padding = this.cfg.padding;

	            // Finalize
	            if (this._xformMode == this._ENC_XFORM_MODE) {
	                // Pad data
	                padding.pad(this._data, this.blockSize);

	                // Process final blocks
	                var finalProcessedBlocks = this._process(!!'flush');
	            } else /* if (this._xformMode == this._DEC_XFORM_MODE) */ {
	                // Process final blocks
	                var finalProcessedBlocks = this._process(!!'flush');

	                // Unpad data
	                padding.unpad(finalProcessedBlocks);
	            }

	            return finalProcessedBlocks;
	        },

	        blockSize: 128/32
	    });

	    /**
	     * A collection of cipher parameters.
	     *
	     * @property {WordArray} ciphertext The raw ciphertext.
	     * @property {WordArray} key The key to this ciphertext.
	     * @property {WordArray} iv The IV used in the ciphering operation.
	     * @property {WordArray} salt The salt used with a key derivation function.
	     * @property {Cipher} algorithm The cipher algorithm.
	     * @property {Mode} mode The block mode used in the ciphering operation.
	     * @property {Padding} padding The padding scheme used in the ciphering operation.
	     * @property {number} blockSize The block size of the cipher.
	     * @property {Format} formatter The default formatting strategy to convert this cipher params object to a string.
	     */
	    var CipherParams = C_lib.CipherParams = Base.extend({
	        /**
	         * Initializes a newly created cipher params object.
	         *
	         * @param {Object} cipherParams An object with any of the possible cipher parameters.
	         *
	         * @example
	         *
	         *     var cipherParams = CryptoJS.lib.CipherParams.create({
	         *         ciphertext: ciphertextWordArray,
	         *         key: keyWordArray,
	         *         iv: ivWordArray,
	         *         salt: saltWordArray,
	         *         algorithm: CryptoJS.algo.AES,
	         *         mode: CryptoJS.mode.CBC,
	         *         padding: CryptoJS.pad.PKCS7,
	         *         blockSize: 4,
	         *         formatter: CryptoJS.format.OpenSSL
	         *     });
	         */
	        init: function (cipherParams) {
	            this.mixIn(cipherParams);
	        },

	        /**
	         * Converts this cipher params object to a string.
	         *
	         * @param {Format} formatter (Optional) The formatting strategy to use.
	         *
	         * @return {string} The stringified cipher params.
	         *
	         * @throws Error If neither the formatter nor the default formatter is set.
	         *
	         * @example
	         *
	         *     var string = cipherParams + '';
	         *     var string = cipherParams.toString();
	         *     var string = cipherParams.toString(CryptoJS.format.OpenSSL);
	         */
	        toString: function (formatter) {
	            return (formatter || this.formatter).stringify(this);
	        }
	    });

	    /**
	     * Format namespace.
	     */
	    var C_format = C.format = {};

	    /**
	     * OpenSSL formatting strategy.
	     */
	    var OpenSSLFormatter = C_format.OpenSSL = {
	        /**
	         * Converts a cipher params object to an OpenSSL-compatible string.
	         *
	         * @param {CipherParams} cipherParams The cipher params object.
	         *
	         * @return {string} The OpenSSL-compatible string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var openSSLString = CryptoJS.format.OpenSSL.stringify(cipherParams);
	         */
	        stringify: function (cipherParams) {
	            // Shortcuts
	            var ciphertext = cipherParams.ciphertext;
	            var salt = cipherParams.salt;

	            // Format
	            if (salt) {
	                var wordArray = WordArray.create([0x53616c74, 0x65645f5f]).concat(salt).concat(ciphertext);
	            } else {
	                var wordArray = ciphertext;
	            }

	            return wordArray.toString(Base64);
	        },

	        /**
	         * Converts an OpenSSL-compatible string to a cipher params object.
	         *
	         * @param {string} openSSLStr The OpenSSL-compatible string.
	         *
	         * @return {CipherParams} The cipher params object.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var cipherParams = CryptoJS.format.OpenSSL.parse(openSSLString);
	         */
	        parse: function (openSSLStr) {
	            // Parse base64
	            var ciphertext = Base64.parse(openSSLStr);

	            // Shortcut
	            var ciphertextWords = ciphertext.words;

	            // Test for salt
	            if (ciphertextWords[0] == 0x53616c74 && ciphertextWords[1] == 0x65645f5f) {
	                // Extract salt
	                var salt = WordArray.create(ciphertextWords.slice(2, 4));

	                // Remove salt from ciphertext
	                ciphertextWords.splice(0, 4);
	                ciphertext.sigBytes -= 16;
	            }

	            return CipherParams.create({ ciphertext: ciphertext, salt: salt });
	        }
	    };

	    /**
	     * A cipher wrapper that returns ciphertext as a serializable cipher params object.
	     */
	    var SerializableCipher = C_lib.SerializableCipher = Base.extend({
	        /**
	         * Configuration options.
	         *
	         * @property {Formatter} format The formatting strategy to convert cipher param objects to and from a string. Default: OpenSSL
	         */
	        cfg: Base.extend({
	            format: OpenSSLFormatter
	        }),

	        /**
	         * Encrypts a message.
	         *
	         * @param {Cipher} cipher The cipher algorithm to use.
	         * @param {WordArray|string} message The message to encrypt.
	         * @param {WordArray} key The key.
	         * @param {Object} cfg (Optional) The configuration options to use for this operation.
	         *
	         * @return {CipherParams} A cipher params object.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var ciphertextParams = CryptoJS.lib.SerializableCipher.encrypt(CryptoJS.algo.AES, message, key);
	         *     var ciphertextParams = CryptoJS.lib.SerializableCipher.encrypt(CryptoJS.algo.AES, message, key, { iv: iv });
	         *     var ciphertextParams = CryptoJS.lib.SerializableCipher.encrypt(CryptoJS.algo.AES, message, key, { iv: iv, format: CryptoJS.format.OpenSSL });
	         */
	        encrypt: function (cipher, message, key, cfg) {
	            // Apply config defaults
	            cfg = this.cfg.extend(cfg);

	            // Encrypt
	            var encryptor = cipher.createEncryptor(key, cfg);
	            var ciphertext = encryptor.finalize(message);

	            // Shortcut
	            var cipherCfg = encryptor.cfg;

	            // Create and return serializable cipher params
	            return CipherParams.create({
	                ciphertext: ciphertext,
	                key: key,
	                iv: cipherCfg.iv,
	                algorithm: cipher,
	                mode: cipherCfg.mode,
	                padding: cipherCfg.padding,
	                blockSize: cipher.blockSize,
	                formatter: cfg.format
	            });
	        },

	        /**
	         * Decrypts serialized ciphertext.
	         *
	         * @param {Cipher} cipher The cipher algorithm to use.
	         * @param {CipherParams|string} ciphertext The ciphertext to decrypt.
	         * @param {WordArray} key The key.
	         * @param {Object} cfg (Optional) The configuration options to use for this operation.
	         *
	         * @return {WordArray} The plaintext.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var plaintext = CryptoJS.lib.SerializableCipher.decrypt(CryptoJS.algo.AES, formattedCiphertext, key, { iv: iv, format: CryptoJS.format.OpenSSL });
	         *     var plaintext = CryptoJS.lib.SerializableCipher.decrypt(CryptoJS.algo.AES, ciphertextParams, key, { iv: iv, format: CryptoJS.format.OpenSSL });
	         */
	        decrypt: function (cipher, ciphertext, key, cfg) {
	            // Apply config defaults
	            cfg = this.cfg.extend(cfg);

	            // Convert string to CipherParams
	            ciphertext = this._parse(ciphertext, cfg.format);

	            // Decrypt
	            var plaintext = cipher.createDecryptor(key, cfg).finalize(ciphertext.ciphertext);

	            return plaintext;
	        },

	        /**
	         * Converts serialized ciphertext to CipherParams,
	         * else assumed CipherParams already and returns ciphertext unchanged.
	         *
	         * @param {CipherParams|string} ciphertext The ciphertext.
	         * @param {Formatter} format The formatting strategy to use to parse serialized ciphertext.
	         *
	         * @return {CipherParams} The unserialized ciphertext.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var ciphertextParams = CryptoJS.lib.SerializableCipher._parse(ciphertextStringOrParams, format);
	         */
	        _parse: function (ciphertext, format) {
	            if (typeof ciphertext == 'string') {
	                return format.parse(ciphertext, this);
	            } else {
	                return ciphertext;
	            }
	        }
	    });

	    /**
	     * Key derivation function namespace.
	     */
	    var C_kdf = C.kdf = {};

	    /**
	     * OpenSSL key derivation function.
	     */
	    var OpenSSLKdf = C_kdf.OpenSSL = {
	        /**
	         * Derives a key and IV from a password.
	         *
	         * @param {string} password The password to derive from.
	         * @param {number} keySize The size in words of the key to generate.
	         * @param {number} ivSize The size in words of the IV to generate.
	         * @param {WordArray|string} salt (Optional) A 64-bit salt to use. If omitted, a salt will be generated randomly.
	         *
	         * @return {CipherParams} A cipher params object with the key, IV, and salt.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var derivedParams = CryptoJS.kdf.OpenSSL.execute('Password', 256/32, 128/32);
	         *     var derivedParams = CryptoJS.kdf.OpenSSL.execute('Password', 256/32, 128/32, 'saltsalt');
	         */
	        execute: function (password, keySize, ivSize, salt) {
	            // Generate random salt
	            if (!salt) {
	                salt = WordArray.random(64/8);
	            }

	            // Derive key and IV
	            var key = EvpKDF.create({ keySize: keySize + ivSize }).compute(password, salt);

	            // Separate key and IV
	            var iv = WordArray.create(key.words.slice(keySize), ivSize * 4);
	            key.sigBytes = keySize * 4;

	            // Return params
	            return CipherParams.create({ key: key, iv: iv, salt: salt });
	        }
	    };

	    /**
	     * A serializable cipher wrapper that derives the key from a password,
	     * and returns ciphertext as a serializable cipher params object.
	     */
	    var PasswordBasedCipher = C_lib.PasswordBasedCipher = SerializableCipher.extend({
	        /**
	         * Configuration options.
	         *
	         * @property {KDF} kdf The key derivation function to use to generate a key and IV from a password. Default: OpenSSL
	         */
	        cfg: SerializableCipher.cfg.extend({
	            kdf: OpenSSLKdf
	        }),

	        /**
	         * Encrypts a message using a password.
	         *
	         * @param {Cipher} cipher The cipher algorithm to use.
	         * @param {WordArray|string} message The message to encrypt.
	         * @param {string} password The password.
	         * @param {Object} cfg (Optional) The configuration options to use for this operation.
	         *
	         * @return {CipherParams} A cipher params object.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var ciphertextParams = CryptoJS.lib.PasswordBasedCipher.encrypt(CryptoJS.algo.AES, message, 'password');
	         *     var ciphertextParams = CryptoJS.lib.PasswordBasedCipher.encrypt(CryptoJS.algo.AES, message, 'password', { format: CryptoJS.format.OpenSSL });
	         */
	        encrypt: function (cipher, message, password, cfg) {
	            // Apply config defaults
	            cfg = this.cfg.extend(cfg);

	            // Derive key and other params
	            var derivedParams = cfg.kdf.execute(password, cipher.keySize, cipher.ivSize);

	            // Add IV to config
	            cfg.iv = derivedParams.iv;

	            // Encrypt
	            var ciphertext = SerializableCipher.encrypt.call(this, cipher, message, derivedParams.key, cfg);

	            // Mix in derived params
	            ciphertext.mixIn(derivedParams);

	            return ciphertext;
	        },

	        /**
	         * Decrypts serialized ciphertext using a password.
	         *
	         * @param {Cipher} cipher The cipher algorithm to use.
	         * @param {CipherParams|string} ciphertext The ciphertext to decrypt.
	         * @param {string} password The password.
	         * @param {Object} cfg (Optional) The configuration options to use for this operation.
	         *
	         * @return {WordArray} The plaintext.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var plaintext = CryptoJS.lib.PasswordBasedCipher.decrypt(CryptoJS.algo.AES, formattedCiphertext, 'password', { format: CryptoJS.format.OpenSSL });
	         *     var plaintext = CryptoJS.lib.PasswordBasedCipher.decrypt(CryptoJS.algo.AES, ciphertextParams, 'password', { format: CryptoJS.format.OpenSSL });
	         */
	        decrypt: function (cipher, ciphertext, password, cfg) {
	            // Apply config defaults
	            cfg = this.cfg.extend(cfg);

	            // Convert string to CipherParams
	            ciphertext = this._parse(ciphertext, cfg.format);

	            // Derive key and other params
	            var derivedParams = cfg.kdf.execute(password, cipher.keySize, cipher.ivSize, ciphertext.salt);

	            // Add IV to config
	            cfg.iv = derivedParams.iv;

	            // Decrypt
	            var plaintext = SerializableCipher.decrypt.call(this, cipher, ciphertext, derivedParams.key, cfg);

	            return plaintext;
	        }
	    });
	}());


}));

/***/ }),

/***/ "./node_modules/crypto-js/core.js":
/*!****************************************!*\
  !*** ./node_modules/crypto-js/core.js ***!
  \****************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory) {
	if (true) {
		// CommonJS
		module.exports = exports = factory();
	}
	else {}
}(this, function () {

	/**
	 * CryptoJS core components.
	 */
	var CryptoJS = CryptoJS || (function (Math, undefined) {
	    /*
	     * Local polyfil of Object.create
	     */
	    var create = Object.create || (function () {
	        function F() {};

	        return function (obj) {
	            var subtype;

	            F.prototype = obj;

	            subtype = new F();

	            F.prototype = null;

	            return subtype;
	        };
	    }())

	    /**
	     * CryptoJS namespace.
	     */
	    var C = {};

	    /**
	     * Library namespace.
	     */
	    var C_lib = C.lib = {};

	    /**
	     * Base object for prototypal inheritance.
	     */
	    var Base = C_lib.Base = (function () {


	        return {
	            /**
	             * Creates a new object that inherits from this object.
	             *
	             * @param {Object} overrides Properties to copy into the new object.
	             *
	             * @return {Object} The new object.
	             *
	             * @static
	             *
	             * @example
	             *
	             *     var MyType = CryptoJS.lib.Base.extend({
	             *         field: 'value',
	             *
	             *         method: function () {
	             *         }
	             *     });
	             */
	            extend: function (overrides) {
	                // Spawn
	                var subtype = create(this);

	                // Augment
	                if (overrides) {
	                    subtype.mixIn(overrides);
	                }

	                // Create default initializer
	                if (!subtype.hasOwnProperty('init') || this.init === subtype.init) {
	                    subtype.init = function () {
	                        subtype.$super.init.apply(this, arguments);
	                    };
	                }

	                // Initializer's prototype is the subtype object
	                subtype.init.prototype = subtype;

	                // Reference supertype
	                subtype.$super = this;

	                return subtype;
	            },

	            /**
	             * Extends this object and runs the init method.
	             * Arguments to create() will be passed to init().
	             *
	             * @return {Object} The new object.
	             *
	             * @static
	             *
	             * @example
	             *
	             *     var instance = MyType.create();
	             */
	            create: function () {
	                var instance = this.extend();
	                instance.init.apply(instance, arguments);

	                return instance;
	            },

	            /**
	             * Initializes a newly created object.
	             * Override this method to add some logic when your objects are created.
	             *
	             * @example
	             *
	             *     var MyType = CryptoJS.lib.Base.extend({
	             *         init: function () {
	             *             // ...
	             *         }
	             *     });
	             */
	            init: function () {
	            },

	            /**
	             * Copies properties into this object.
	             *
	             * @param {Object} properties The properties to mix in.
	             *
	             * @example
	             *
	             *     MyType.mixIn({
	             *         field: 'value'
	             *     });
	             */
	            mixIn: function (properties) {
	                for (var propertyName in properties) {
	                    if (properties.hasOwnProperty(propertyName)) {
	                        this[propertyName] = properties[propertyName];
	                    }
	                }

	                // IE won't copy toString using the loop above
	                if (properties.hasOwnProperty('toString')) {
	                    this.toString = properties.toString;
	                }
	            },

	            /**
	             * Creates a copy of this object.
	             *
	             * @return {Object} The clone.
	             *
	             * @example
	             *
	             *     var clone = instance.clone();
	             */
	            clone: function () {
	                return this.init.prototype.extend(this);
	            }
	        };
	    }());

	    /**
	     * An array of 32-bit words.
	     *
	     * @property {Array} words The array of 32-bit words.
	     * @property {number} sigBytes The number of significant bytes in this word array.
	     */
	    var WordArray = C_lib.WordArray = Base.extend({
	        /**
	         * Initializes a newly created word array.
	         *
	         * @param {Array} words (Optional) An array of 32-bit words.
	         * @param {number} sigBytes (Optional) The number of significant bytes in the words.
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.lib.WordArray.create();
	         *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607]);
	         *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607], 6);
	         */
	        init: function (words, sigBytes) {
	            words = this.words = words || [];

	            if (sigBytes != undefined) {
	                this.sigBytes = sigBytes;
	            } else {
	                this.sigBytes = words.length * 4;
	            }
	        },

	        /**
	         * Converts this word array to a string.
	         *
	         * @param {Encoder} encoder (Optional) The encoding strategy to use. Default: CryptoJS.enc.Hex
	         *
	         * @return {string} The stringified word array.
	         *
	         * @example
	         *
	         *     var string = wordArray + '';
	         *     var string = wordArray.toString();
	         *     var string = wordArray.toString(CryptoJS.enc.Utf8);
	         */
	        toString: function (encoder) {
	            return (encoder || Hex).stringify(this);
	        },

	        /**
	         * Concatenates a word array to this word array.
	         *
	         * @param {WordArray} wordArray The word array to append.
	         *
	         * @return {WordArray} This word array.
	         *
	         * @example
	         *
	         *     wordArray1.concat(wordArray2);
	         */
	        concat: function (wordArray) {
	            // Shortcuts
	            var thisWords = this.words;
	            var thatWords = wordArray.words;
	            var thisSigBytes = this.sigBytes;
	            var thatSigBytes = wordArray.sigBytes;

	            // Clamp excess bits
	            this.clamp();

	            // Concat
	            if (thisSigBytes % 4) {
	                // Copy one byte at a time
	                for (var i = 0; i < thatSigBytes; i++) {
	                    var thatByte = (thatWords[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
	                    thisWords[(thisSigBytes + i) >>> 2] |= thatByte << (24 - ((thisSigBytes + i) % 4) * 8);
	                }
	            } else {
	                // Copy one word at a time
	                for (var i = 0; i < thatSigBytes; i += 4) {
	                    thisWords[(thisSigBytes + i) >>> 2] = thatWords[i >>> 2];
	                }
	            }
	            this.sigBytes += thatSigBytes;

	            // Chainable
	            return this;
	        },

	        /**
	         * Removes insignificant bits.
	         *
	         * @example
	         *
	         *     wordArray.clamp();
	         */
	        clamp: function () {
	            // Shortcuts
	            var words = this.words;
	            var sigBytes = this.sigBytes;

	            // Clamp
	            words[sigBytes >>> 2] &= 0xffffffff << (32 - (sigBytes % 4) * 8);
	            words.length = Math.ceil(sigBytes / 4);
	        },

	        /**
	         * Creates a copy of this word array.
	         *
	         * @return {WordArray} The clone.
	         *
	         * @example
	         *
	         *     var clone = wordArray.clone();
	         */
	        clone: function () {
	            var clone = Base.clone.call(this);
	            clone.words = this.words.slice(0);

	            return clone;
	        },

	        /**
	         * Creates a word array filled with random bytes.
	         *
	         * @param {number} nBytes The number of random bytes to generate.
	         *
	         * @return {WordArray} The random word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.lib.WordArray.random(16);
	         */
	        random: function (nBytes) {
	            var words = [];

	            var r = (function (m_w) {
	                var m_w = m_w;
	                var m_z = 0x3ade68b1;
	                var mask = 0xffffffff;

	                return function () {
	                    m_z = (0x9069 * (m_z & 0xFFFF) + (m_z >> 0x10)) & mask;
	                    m_w = (0x4650 * (m_w & 0xFFFF) + (m_w >> 0x10)) & mask;
	                    var result = ((m_z << 0x10) + m_w) & mask;
	                    result /= 0x100000000;
	                    result += 0.5;
	                    return result * (Math.random() > .5 ? 1 : -1);
	                }
	            });

	            for (var i = 0, rcache; i < nBytes; i += 4) {
	                var _r = r((rcache || Math.random()) * 0x100000000);

	                rcache = _r() * 0x3ade67b7;
	                words.push((_r() * 0x100000000) | 0);
	            }

	            return new WordArray.init(words, nBytes);
	        }
	    });

	    /**
	     * Encoder namespace.
	     */
	    var C_enc = C.enc = {};

	    /**
	     * Hex encoding strategy.
	     */
	    var Hex = C_enc.Hex = {
	        /**
	         * Converts a word array to a hex string.
	         *
	         * @param {WordArray} wordArray The word array.
	         *
	         * @return {string} The hex string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var hexString = CryptoJS.enc.Hex.stringify(wordArray);
	         */
	        stringify: function (wordArray) {
	            // Shortcuts
	            var words = wordArray.words;
	            var sigBytes = wordArray.sigBytes;

	            // Convert
	            var hexChars = [];
	            for (var i = 0; i < sigBytes; i++) {
	                var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
	                hexChars.push((bite >>> 4).toString(16));
	                hexChars.push((bite & 0x0f).toString(16));
	            }

	            return hexChars.join('');
	        },

	        /**
	         * Converts a hex string to a word array.
	         *
	         * @param {string} hexStr The hex string.
	         *
	         * @return {WordArray} The word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.enc.Hex.parse(hexString);
	         */
	        parse: function (hexStr) {
	            // Shortcut
	            var hexStrLength = hexStr.length;

	            // Convert
	            var words = [];
	            for (var i = 0; i < hexStrLength; i += 2) {
	                words[i >>> 3] |= parseInt(hexStr.substr(i, 2), 16) << (24 - (i % 8) * 4);
	            }

	            return new WordArray.init(words, hexStrLength / 2);
	        }
	    };

	    /**
	     * Latin1 encoding strategy.
	     */
	    var Latin1 = C_enc.Latin1 = {
	        /**
	         * Converts a word array to a Latin1 string.
	         *
	         * @param {WordArray} wordArray The word array.
	         *
	         * @return {string} The Latin1 string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var latin1String = CryptoJS.enc.Latin1.stringify(wordArray);
	         */
	        stringify: function (wordArray) {
	            // Shortcuts
	            var words = wordArray.words;
	            var sigBytes = wordArray.sigBytes;

	            // Convert
	            var latin1Chars = [];
	            for (var i = 0; i < sigBytes; i++) {
	                var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
	                latin1Chars.push(String.fromCharCode(bite));
	            }

	            return latin1Chars.join('');
	        },

	        /**
	         * Converts a Latin1 string to a word array.
	         *
	         * @param {string} latin1Str The Latin1 string.
	         *
	         * @return {WordArray} The word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.enc.Latin1.parse(latin1String);
	         */
	        parse: function (latin1Str) {
	            // Shortcut
	            var latin1StrLength = latin1Str.length;

	            // Convert
	            var words = [];
	            for (var i = 0; i < latin1StrLength; i++) {
	                words[i >>> 2] |= (latin1Str.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8);
	            }

	            return new WordArray.init(words, latin1StrLength);
	        }
	    };

	    /**
	     * UTF-8 encoding strategy.
	     */
	    var Utf8 = C_enc.Utf8 = {
	        /**
	         * Converts a word array to a UTF-8 string.
	         *
	         * @param {WordArray} wordArray The word array.
	         *
	         * @return {string} The UTF-8 string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var utf8String = CryptoJS.enc.Utf8.stringify(wordArray);
	         */
	        stringify: function (wordArray) {
	            try {
	                return decodeURIComponent(escape(Latin1.stringify(wordArray)));
	            } catch (e) {
	                throw new Error('Malformed UTF-8 data');
	            }
	        },

	        /**
	         * Converts a UTF-8 string to a word array.
	         *
	         * @param {string} utf8Str The UTF-8 string.
	         *
	         * @return {WordArray} The word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.enc.Utf8.parse(utf8String);
	         */
	        parse: function (utf8Str) {
	            return Latin1.parse(unescape(encodeURIComponent(utf8Str)));
	        }
	    };

	    /**
	     * Abstract buffered block algorithm template.
	     *
	     * The property blockSize must be implemented in a concrete subtype.
	     *
	     * @property {number} _minBufferSize The number of blocks that should be kept unprocessed in the buffer. Default: 0
	     */
	    var BufferedBlockAlgorithm = C_lib.BufferedBlockAlgorithm = Base.extend({
	        /**
	         * Resets this block algorithm's data buffer to its initial state.
	         *
	         * @example
	         *
	         *     bufferedBlockAlgorithm.reset();
	         */
	        reset: function () {
	            // Initial values
	            this._data = new WordArray.init();
	            this._nDataBytes = 0;
	        },

	        /**
	         * Adds new data to this block algorithm's buffer.
	         *
	         * @param {WordArray|string} data The data to append. Strings are converted to a WordArray using UTF-8.
	         *
	         * @example
	         *
	         *     bufferedBlockAlgorithm._append('data');
	         *     bufferedBlockAlgorithm._append(wordArray);
	         */
	        _append: function (data) {
	            // Convert string to WordArray, else assume WordArray already
	            if (typeof data == 'string') {
	                data = Utf8.parse(data);
	            }

	            // Append
	            this._data.concat(data);
	            this._nDataBytes += data.sigBytes;
	        },

	        /**
	         * Processes available data blocks.
	         *
	         * This method invokes _doProcessBlock(offset), which must be implemented by a concrete subtype.
	         *
	         * @param {boolean} doFlush Whether all blocks and partial blocks should be processed.
	         *
	         * @return {WordArray} The processed data.
	         *
	         * @example
	         *
	         *     var processedData = bufferedBlockAlgorithm._process();
	         *     var processedData = bufferedBlockAlgorithm._process(!!'flush');
	         */
	        _process: function (doFlush) {
	            // Shortcuts
	            var data = this._data;
	            var dataWords = data.words;
	            var dataSigBytes = data.sigBytes;
	            var blockSize = this.blockSize;
	            var blockSizeBytes = blockSize * 4;

	            // Count blocks ready
	            var nBlocksReady = dataSigBytes / blockSizeBytes;
	            if (doFlush) {
	                // Round up to include partial blocks
	                nBlocksReady = Math.ceil(nBlocksReady);
	            } else {
	                // Round down to include only full blocks,
	                // less the number of blocks that must remain in the buffer
	                nBlocksReady = Math.max((nBlocksReady | 0) - this._minBufferSize, 0);
	            }

	            // Count words ready
	            var nWordsReady = nBlocksReady * blockSize;

	            // Count bytes ready
	            var nBytesReady = Math.min(nWordsReady * 4, dataSigBytes);

	            // Process blocks
	            if (nWordsReady) {
	                for (var offset = 0; offset < nWordsReady; offset += blockSize) {
	                    // Perform concrete-algorithm logic
	                    this._doProcessBlock(dataWords, offset);
	                }

	                // Remove processed words
	                var processedWords = dataWords.splice(0, nWordsReady);
	                data.sigBytes -= nBytesReady;
	            }

	            // Return processed words
	            return new WordArray.init(processedWords, nBytesReady);
	        },

	        /**
	         * Creates a copy of this object.
	         *
	         * @return {Object} The clone.
	         *
	         * @example
	         *
	         *     var clone = bufferedBlockAlgorithm.clone();
	         */
	        clone: function () {
	            var clone = Base.clone.call(this);
	            clone._data = this._data.clone();

	            return clone;
	        },

	        _minBufferSize: 0
	    });

	    /**
	     * Abstract hasher template.
	     *
	     * @property {number} blockSize The number of 32-bit words this hasher operates on. Default: 16 (512 bits)
	     */
	    var Hasher = C_lib.Hasher = BufferedBlockAlgorithm.extend({
	        /**
	         * Configuration options.
	         */
	        cfg: Base.extend(),

	        /**
	         * Initializes a newly created hasher.
	         *
	         * @param {Object} cfg (Optional) The configuration options to use for this hash computation.
	         *
	         * @example
	         *
	         *     var hasher = CryptoJS.algo.SHA256.create();
	         */
	        init: function (cfg) {
	            // Apply config defaults
	            this.cfg = this.cfg.extend(cfg);

	            // Set initial values
	            this.reset();
	        },

	        /**
	         * Resets this hasher to its initial state.
	         *
	         * @example
	         *
	         *     hasher.reset();
	         */
	        reset: function () {
	            // Reset data buffer
	            BufferedBlockAlgorithm.reset.call(this);

	            // Perform concrete-hasher logic
	            this._doReset();
	        },

	        /**
	         * Updates this hasher with a message.
	         *
	         * @param {WordArray|string} messageUpdate The message to append.
	         *
	         * @return {Hasher} This hasher.
	         *
	         * @example
	         *
	         *     hasher.update('message');
	         *     hasher.update(wordArray);
	         */
	        update: function (messageUpdate) {
	            // Append
	            this._append(messageUpdate);

	            // Update the hash
	            this._process();

	            // Chainable
	            return this;
	        },

	        /**
	         * Finalizes the hash computation.
	         * Note that the finalize operation is effectively a destructive, read-once operation.
	         *
	         * @param {WordArray|string} messageUpdate (Optional) A final message update.
	         *
	         * @return {WordArray} The hash.
	         *
	         * @example
	         *
	         *     var hash = hasher.finalize();
	         *     var hash = hasher.finalize('message');
	         *     var hash = hasher.finalize(wordArray);
	         */
	        finalize: function (messageUpdate) {
	            // Final message update
	            if (messageUpdate) {
	                this._append(messageUpdate);
	            }

	            // Perform concrete-hasher logic
	            var hash = this._doFinalize();

	            return hash;
	        },

	        blockSize: 512/32,

	        /**
	         * Creates a shortcut function to a hasher's object interface.
	         *
	         * @param {Hasher} hasher The hasher to create a helper for.
	         *
	         * @return {Function} The shortcut function.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var SHA256 = CryptoJS.lib.Hasher._createHelper(CryptoJS.algo.SHA256);
	         */
	        _createHelper: function (hasher) {
	            return function (message, cfg) {
	                return new hasher.init(cfg).finalize(message);
	            };
	        },

	        /**
	         * Creates a shortcut function to the HMAC's object interface.
	         *
	         * @param {Hasher} hasher The hasher to use in this HMAC helper.
	         *
	         * @return {Function} The shortcut function.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var HmacSHA256 = CryptoJS.lib.Hasher._createHmacHelper(CryptoJS.algo.SHA256);
	         */
	        _createHmacHelper: function (hasher) {
	            return function (message, key) {
	                return new C_algo.HMAC.init(hasher, key).finalize(message);
	            };
	        }
	    });

	    /**
	     * Algorithm namespace.
	     */
	    var C_algo = C.algo = {};

	    return C;
	}(Math));


	return CryptoJS;

}));

/***/ }),

/***/ "./node_modules/crypto-js/enc-base64.js":
/*!**********************************************!*\
  !*** ./node_modules/crypto-js/enc-base64.js ***!
  \**********************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"));
	}
	else {}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var C_enc = C.enc;

	    /**
	     * Base64 encoding strategy.
	     */
	    var Base64 = C_enc.Base64 = {
	        /**
	         * Converts a word array to a Base64 string.
	         *
	         * @param {WordArray} wordArray The word array.
	         *
	         * @return {string} The Base64 string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var base64String = CryptoJS.enc.Base64.stringify(wordArray);
	         */
	        stringify: function (wordArray) {
	            // Shortcuts
	            var words = wordArray.words;
	            var sigBytes = wordArray.sigBytes;
	            var map = this._map;

	            // Clamp excess bits
	            wordArray.clamp();

	            // Convert
	            var base64Chars = [];
	            for (var i = 0; i < sigBytes; i += 3) {
	                var byte1 = (words[i >>> 2]       >>> (24 - (i % 4) * 8))       & 0xff;
	                var byte2 = (words[(i + 1) >>> 2] >>> (24 - ((i + 1) % 4) * 8)) & 0xff;
	                var byte3 = (words[(i + 2) >>> 2] >>> (24 - ((i + 2) % 4) * 8)) & 0xff;

	                var triplet = (byte1 << 16) | (byte2 << 8) | byte3;

	                for (var j = 0; (j < 4) && (i + j * 0.75 < sigBytes); j++) {
	                    base64Chars.push(map.charAt((triplet >>> (6 * (3 - j))) & 0x3f));
	                }
	            }

	            // Add padding
	            var paddingChar = map.charAt(64);
	            if (paddingChar) {
	                while (base64Chars.length % 4) {
	                    base64Chars.push(paddingChar);
	                }
	            }

	            return base64Chars.join('');
	        },

	        /**
	         * Converts a Base64 string to a word array.
	         *
	         * @param {string} base64Str The Base64 string.
	         *
	         * @return {WordArray} The word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.enc.Base64.parse(base64String);
	         */
	        parse: function (base64Str) {
	            // Shortcuts
	            var base64StrLength = base64Str.length;
	            var map = this._map;
	            var reverseMap = this._reverseMap;

	            if (!reverseMap) {
	                    reverseMap = this._reverseMap = [];
	                    for (var j = 0; j < map.length; j++) {
	                        reverseMap[map.charCodeAt(j)] = j;
	                    }
	            }

	            // Ignore padding
	            var paddingChar = map.charAt(64);
	            if (paddingChar) {
	                var paddingIndex = base64Str.indexOf(paddingChar);
	                if (paddingIndex !== -1) {
	                    base64StrLength = paddingIndex;
	                }
	            }

	            // Convert
	            return parseLoop(base64Str, base64StrLength, reverseMap);

	        },

	        _map: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
	    };

	    function parseLoop(base64Str, base64StrLength, reverseMap) {
	      var words = [];
	      var nBytes = 0;
	      for (var i = 0; i < base64StrLength; i++) {
	          if (i % 4) {
	              var bits1 = reverseMap[base64Str.charCodeAt(i - 1)] << ((i % 4) * 2);
	              var bits2 = reverseMap[base64Str.charCodeAt(i)] >>> (6 - (i % 4) * 2);
	              words[nBytes >>> 2] |= (bits1 | bits2) << (24 - (nBytes % 4) * 8);
	              nBytes++;
	          }
	      }
	      return WordArray.create(words, nBytes);
	    }
	}());


	return CryptoJS.enc.Base64;

}));

/***/ }),

/***/ "./node_modules/crypto-js/evpkdf.js":
/*!******************************************!*\
  !*** ./node_modules/crypto-js/evpkdf.js ***!
  \******************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"), __webpack_require__(/*! ./sha1 */ "./node_modules/crypto-js/sha1.js"), __webpack_require__(/*! ./hmac */ "./node_modules/crypto-js/hmac.js"));
	}
	else {}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var Base = C_lib.Base;
	    var WordArray = C_lib.WordArray;
	    var C_algo = C.algo;
	    var MD5 = C_algo.MD5;

	    /**
	     * This key derivation function is meant to conform with EVP_BytesToKey.
	     * www.openssl.org/docs/crypto/EVP_BytesToKey.html
	     */
	    var EvpKDF = C_algo.EvpKDF = Base.extend({
	        /**
	         * Configuration options.
	         *
	         * @property {number} keySize The key size in words to generate. Default: 4 (128 bits)
	         * @property {Hasher} hasher The hash algorithm to use. Default: MD5
	         * @property {number} iterations The number of iterations to perform. Default: 1
	         */
	        cfg: Base.extend({
	            keySize: 128/32,
	            hasher: MD5,
	            iterations: 1
	        }),

	        /**
	         * Initializes a newly created key derivation function.
	         *
	         * @param {Object} cfg (Optional) The configuration options to use for the derivation.
	         *
	         * @example
	         *
	         *     var kdf = CryptoJS.algo.EvpKDF.create();
	         *     var kdf = CryptoJS.algo.EvpKDF.create({ keySize: 8 });
	         *     var kdf = CryptoJS.algo.EvpKDF.create({ keySize: 8, iterations: 1000 });
	         */
	        init: function (cfg) {
	            this.cfg = this.cfg.extend(cfg);
	        },

	        /**
	         * Derives a key from a password.
	         *
	         * @param {WordArray|string} password The password.
	         * @param {WordArray|string} salt A salt.
	         *
	         * @return {WordArray} The derived key.
	         *
	         * @example
	         *
	         *     var key = kdf.compute(password, salt);
	         */
	        compute: function (password, salt) {
	            // Shortcut
	            var cfg = this.cfg;

	            // Init hasher
	            var hasher = cfg.hasher.create();

	            // Initial values
	            var derivedKey = WordArray.create();

	            // Shortcuts
	            var derivedKeyWords = derivedKey.words;
	            var keySize = cfg.keySize;
	            var iterations = cfg.iterations;

	            // Generate key
	            while (derivedKeyWords.length < keySize) {
	                if (block) {
	                    hasher.update(block);
	                }
	                var block = hasher.update(password).finalize(salt);
	                hasher.reset();

	                // Iterations
	                for (var i = 1; i < iterations; i++) {
	                    block = hasher.finalize(block);
	                    hasher.reset();
	                }

	                derivedKey.concat(block);
	            }
	            derivedKey.sigBytes = keySize * 4;

	            return derivedKey;
	        }
	    });

	    /**
	     * Derives a key from a password.
	     *
	     * @param {WordArray|string} password The password.
	     * @param {WordArray|string} salt A salt.
	     * @param {Object} cfg (Optional) The configuration options to use for this computation.
	     *
	     * @return {WordArray} The derived key.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var key = CryptoJS.EvpKDF(password, salt);
	     *     var key = CryptoJS.EvpKDF(password, salt, { keySize: 8 });
	     *     var key = CryptoJS.EvpKDF(password, salt, { keySize: 8, iterations: 1000 });
	     */
	    C.EvpKDF = function (password, salt, cfg) {
	        return EvpKDF.create(cfg).compute(password, salt);
	    };
	}());


	return CryptoJS.EvpKDF;

}));

/***/ }),

/***/ "./node_modules/crypto-js/hmac.js":
/*!****************************************!*\
  !*** ./node_modules/crypto-js/hmac.js ***!
  \****************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"));
	}
	else {}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var Base = C_lib.Base;
	    var C_enc = C.enc;
	    var Utf8 = C_enc.Utf8;
	    var C_algo = C.algo;

	    /**
	     * HMAC algorithm.
	     */
	    var HMAC = C_algo.HMAC = Base.extend({
	        /**
	         * Initializes a newly created HMAC.
	         *
	         * @param {Hasher} hasher The hash algorithm to use.
	         * @param {WordArray|string} key The secret key.
	         *
	         * @example
	         *
	         *     var hmacHasher = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, key);
	         */
	        init: function (hasher, key) {
	            // Init hasher
	            hasher = this._hasher = new hasher.init();

	            // Convert string to WordArray, else assume WordArray already
	            if (typeof key == 'string') {
	                key = Utf8.parse(key);
	            }

	            // Shortcuts
	            var hasherBlockSize = hasher.blockSize;
	            var hasherBlockSizeBytes = hasherBlockSize * 4;

	            // Allow arbitrary length keys
	            if (key.sigBytes > hasherBlockSizeBytes) {
	                key = hasher.finalize(key);
	            }

	            // Clamp excess bits
	            key.clamp();

	            // Clone key for inner and outer pads
	            var oKey = this._oKey = key.clone();
	            var iKey = this._iKey = key.clone();

	            // Shortcuts
	            var oKeyWords = oKey.words;
	            var iKeyWords = iKey.words;

	            // XOR keys with pad constants
	            for (var i = 0; i < hasherBlockSize; i++) {
	                oKeyWords[i] ^= 0x5c5c5c5c;
	                iKeyWords[i] ^= 0x36363636;
	            }
	            oKey.sigBytes = iKey.sigBytes = hasherBlockSizeBytes;

	            // Set initial values
	            this.reset();
	        },

	        /**
	         * Resets this HMAC to its initial state.
	         *
	         * @example
	         *
	         *     hmacHasher.reset();
	         */
	        reset: function () {
	            // Shortcut
	            var hasher = this._hasher;

	            // Reset
	            hasher.reset();
	            hasher.update(this._iKey);
	        },

	        /**
	         * Updates this HMAC with a message.
	         *
	         * @param {WordArray|string} messageUpdate The message to append.
	         *
	         * @return {HMAC} This HMAC instance.
	         *
	         * @example
	         *
	         *     hmacHasher.update('message');
	         *     hmacHasher.update(wordArray);
	         */
	        update: function (messageUpdate) {
	            this._hasher.update(messageUpdate);

	            // Chainable
	            return this;
	        },

	        /**
	         * Finalizes the HMAC computation.
	         * Note that the finalize operation is effectively a destructive, read-once operation.
	         *
	         * @param {WordArray|string} messageUpdate (Optional) A final message update.
	         *
	         * @return {WordArray} The HMAC.
	         *
	         * @example
	         *
	         *     var hmac = hmacHasher.finalize();
	         *     var hmac = hmacHasher.finalize('message');
	         *     var hmac = hmacHasher.finalize(wordArray);
	         */
	        finalize: function (messageUpdate) {
	            // Shortcut
	            var hasher = this._hasher;

	            // Compute HMAC
	            var innerHash = hasher.finalize(messageUpdate);
	            hasher.reset();
	            var hmac = hasher.finalize(this._oKey.clone().concat(innerHash));

	            return hmac;
	        }
	    });
	}());


}));

/***/ }),

/***/ "./node_modules/crypto-js/md5.js":
/*!***************************************!*\
  !*** ./node_modules/crypto-js/md5.js ***!
  \***************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"));
	}
	else {}
}(this, function (CryptoJS) {

	(function (Math) {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var Hasher = C_lib.Hasher;
	    var C_algo = C.algo;

	    // Constants table
	    var T = [];

	    // Compute constants
	    (function () {
	        for (var i = 0; i < 64; i++) {
	            T[i] = (Math.abs(Math.sin(i + 1)) * 0x100000000) | 0;
	        }
	    }());

	    /**
	     * MD5 hash algorithm.
	     */
	    var MD5 = C_algo.MD5 = Hasher.extend({
	        _doReset: function () {
	            this._hash = new WordArray.init([
	                0x67452301, 0xefcdab89,
	                0x98badcfe, 0x10325476
	            ]);
	        },

	        _doProcessBlock: function (M, offset) {
	            // Swap endian
	            for (var i = 0; i < 16; i++) {
	                // Shortcuts
	                var offset_i = offset + i;
	                var M_offset_i = M[offset_i];

	                M[offset_i] = (
	                    (((M_offset_i << 8)  | (M_offset_i >>> 24)) & 0x00ff00ff) |
	                    (((M_offset_i << 24) | (M_offset_i >>> 8))  & 0xff00ff00)
	                );
	            }

	            // Shortcuts
	            var H = this._hash.words;

	            var M_offset_0  = M[offset + 0];
	            var M_offset_1  = M[offset + 1];
	            var M_offset_2  = M[offset + 2];
	            var M_offset_3  = M[offset + 3];
	            var M_offset_4  = M[offset + 4];
	            var M_offset_5  = M[offset + 5];
	            var M_offset_6  = M[offset + 6];
	            var M_offset_7  = M[offset + 7];
	            var M_offset_8  = M[offset + 8];
	            var M_offset_9  = M[offset + 9];
	            var M_offset_10 = M[offset + 10];
	            var M_offset_11 = M[offset + 11];
	            var M_offset_12 = M[offset + 12];
	            var M_offset_13 = M[offset + 13];
	            var M_offset_14 = M[offset + 14];
	            var M_offset_15 = M[offset + 15];

	            // Working varialbes
	            var a = H[0];
	            var b = H[1];
	            var c = H[2];
	            var d = H[3];

	            // Computation
	            a = FF(a, b, c, d, M_offset_0,  7,  T[0]);
	            d = FF(d, a, b, c, M_offset_1,  12, T[1]);
	            c = FF(c, d, a, b, M_offset_2,  17, T[2]);
	            b = FF(b, c, d, a, M_offset_3,  22, T[3]);
	            a = FF(a, b, c, d, M_offset_4,  7,  T[4]);
	            d = FF(d, a, b, c, M_offset_5,  12, T[5]);
	            c = FF(c, d, a, b, M_offset_6,  17, T[6]);
	            b = FF(b, c, d, a, M_offset_7,  22, T[7]);
	            a = FF(a, b, c, d, M_offset_8,  7,  T[8]);
	            d = FF(d, a, b, c, M_offset_9,  12, T[9]);
	            c = FF(c, d, a, b, M_offset_10, 17, T[10]);
	            b = FF(b, c, d, a, M_offset_11, 22, T[11]);
	            a = FF(a, b, c, d, M_offset_12, 7,  T[12]);
	            d = FF(d, a, b, c, M_offset_13, 12, T[13]);
	            c = FF(c, d, a, b, M_offset_14, 17, T[14]);
	            b = FF(b, c, d, a, M_offset_15, 22, T[15]);

	            a = GG(a, b, c, d, M_offset_1,  5,  T[16]);
	            d = GG(d, a, b, c, M_offset_6,  9,  T[17]);
	            c = GG(c, d, a, b, M_offset_11, 14, T[18]);
	            b = GG(b, c, d, a, M_offset_0,  20, T[19]);
	            a = GG(a, b, c, d, M_offset_5,  5,  T[20]);
	            d = GG(d, a, b, c, M_offset_10, 9,  T[21]);
	            c = GG(c, d, a, b, M_offset_15, 14, T[22]);
	            b = GG(b, c, d, a, M_offset_4,  20, T[23]);
	            a = GG(a, b, c, d, M_offset_9,  5,  T[24]);
	            d = GG(d, a, b, c, M_offset_14, 9,  T[25]);
	            c = GG(c, d, a, b, M_offset_3,  14, T[26]);
	            b = GG(b, c, d, a, M_offset_8,  20, T[27]);
	            a = GG(a, b, c, d, M_offset_13, 5,  T[28]);
	            d = GG(d, a, b, c, M_offset_2,  9,  T[29]);
	            c = GG(c, d, a, b, M_offset_7,  14, T[30]);
	            b = GG(b, c, d, a, M_offset_12, 20, T[31]);

	            a = HH(a, b, c, d, M_offset_5,  4,  T[32]);
	            d = HH(d, a, b, c, M_offset_8,  11, T[33]);
	            c = HH(c, d, a, b, M_offset_11, 16, T[34]);
	            b = HH(b, c, d, a, M_offset_14, 23, T[35]);
	            a = HH(a, b, c, d, M_offset_1,  4,  T[36]);
	            d = HH(d, a, b, c, M_offset_4,  11, T[37]);
	            c = HH(c, d, a, b, M_offset_7,  16, T[38]);
	            b = HH(b, c, d, a, M_offset_10, 23, T[39]);
	            a = HH(a, b, c, d, M_offset_13, 4,  T[40]);
	            d = HH(d, a, b, c, M_offset_0,  11, T[41]);
	            c = HH(c, d, a, b, M_offset_3,  16, T[42]);
	            b = HH(b, c, d, a, M_offset_6,  23, T[43]);
	            a = HH(a, b, c, d, M_offset_9,  4,  T[44]);
	            d = HH(d, a, b, c, M_offset_12, 11, T[45]);
	            c = HH(c, d, a, b, M_offset_15, 16, T[46]);
	            b = HH(b, c, d, a, M_offset_2,  23, T[47]);

	            a = II(a, b, c, d, M_offset_0,  6,  T[48]);
	            d = II(d, a, b, c, M_offset_7,  10, T[49]);
	            c = II(c, d, a, b, M_offset_14, 15, T[50]);
	            b = II(b, c, d, a, M_offset_5,  21, T[51]);
	            a = II(a, b, c, d, M_offset_12, 6,  T[52]);
	            d = II(d, a, b, c, M_offset_3,  10, T[53]);
	            c = II(c, d, a, b, M_offset_10, 15, T[54]);
	            b = II(b, c, d, a, M_offset_1,  21, T[55]);
	            a = II(a, b, c, d, M_offset_8,  6,  T[56]);
	            d = II(d, a, b, c, M_offset_15, 10, T[57]);
	            c = II(c, d, a, b, M_offset_6,  15, T[58]);
	            b = II(b, c, d, a, M_offset_13, 21, T[59]);
	            a = II(a, b, c, d, M_offset_4,  6,  T[60]);
	            d = II(d, a, b, c, M_offset_11, 10, T[61]);
	            c = II(c, d, a, b, M_offset_2,  15, T[62]);
	            b = II(b, c, d, a, M_offset_9,  21, T[63]);

	            // Intermediate hash value
	            H[0] = (H[0] + a) | 0;
	            H[1] = (H[1] + b) | 0;
	            H[2] = (H[2] + c) | 0;
	            H[3] = (H[3] + d) | 0;
	        },

	        _doFinalize: function () {
	            // Shortcuts
	            var data = this._data;
	            var dataWords = data.words;

	            var nBitsTotal = this._nDataBytes * 8;
	            var nBitsLeft = data.sigBytes * 8;

	            // Add padding
	            dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);

	            var nBitsTotalH = Math.floor(nBitsTotal / 0x100000000);
	            var nBitsTotalL = nBitsTotal;
	            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 15] = (
	                (((nBitsTotalH << 8)  | (nBitsTotalH >>> 24)) & 0x00ff00ff) |
	                (((nBitsTotalH << 24) | (nBitsTotalH >>> 8))  & 0xff00ff00)
	            );
	            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = (
	                (((nBitsTotalL << 8)  | (nBitsTotalL >>> 24)) & 0x00ff00ff) |
	                (((nBitsTotalL << 24) | (nBitsTotalL >>> 8))  & 0xff00ff00)
	            );

	            data.sigBytes = (dataWords.length + 1) * 4;

	            // Hash final blocks
	            this._process();

	            // Shortcuts
	            var hash = this._hash;
	            var H = hash.words;

	            // Swap endian
	            for (var i = 0; i < 4; i++) {
	                // Shortcut
	                var H_i = H[i];

	                H[i] = (((H_i << 8)  | (H_i >>> 24)) & 0x00ff00ff) |
	                       (((H_i << 24) | (H_i >>> 8))  & 0xff00ff00);
	            }

	            // Return final computed hash
	            return hash;
	        },

	        clone: function () {
	            var clone = Hasher.clone.call(this);
	            clone._hash = this._hash.clone();

	            return clone;
	        }
	    });

	    function FF(a, b, c, d, x, s, t) {
	        var n = a + ((b & c) | (~b & d)) + x + t;
	        return ((n << s) | (n >>> (32 - s))) + b;
	    }

	    function GG(a, b, c, d, x, s, t) {
	        var n = a + ((b & d) | (c & ~d)) + x + t;
	        return ((n << s) | (n >>> (32 - s))) + b;
	    }

	    function HH(a, b, c, d, x, s, t) {
	        var n = a + (b ^ c ^ d) + x + t;
	        return ((n << s) | (n >>> (32 - s))) + b;
	    }

	    function II(a, b, c, d, x, s, t) {
	        var n = a + (c ^ (b | ~d)) + x + t;
	        return ((n << s) | (n >>> (32 - s))) + b;
	    }

	    /**
	     * Shortcut function to the hasher's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     *
	     * @return {WordArray} The hash.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hash = CryptoJS.MD5('message');
	     *     var hash = CryptoJS.MD5(wordArray);
	     */
	    C.MD5 = Hasher._createHelper(MD5);

	    /**
	     * Shortcut function to the HMAC's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     * @param {WordArray|string} key The secret key.
	     *
	     * @return {WordArray} The HMAC.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hmac = CryptoJS.HmacMD5(message, key);
	     */
	    C.HmacMD5 = Hasher._createHmacHelper(MD5);
	}(Math));


	return CryptoJS.MD5;

}));

/***/ }),

/***/ "./node_modules/crypto-js/mode-ctr.js":
/*!********************************************!*\
  !*** ./node_modules/crypto-js/mode-ctr.js ***!
  \********************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"), __webpack_require__(/*! ./cipher-core */ "./node_modules/crypto-js/cipher-core.js"));
	}
	else {}
}(this, function (CryptoJS) {

	/**
	 * Counter block mode.
	 */
	CryptoJS.mode.CTR = (function () {
	    var CTR = CryptoJS.lib.BlockCipherMode.extend();

	    var Encryptor = CTR.Encryptor = CTR.extend({
	        processBlock: function (words, offset) {
	            // Shortcuts
	            var cipher = this._cipher
	            var blockSize = cipher.blockSize;
	            var iv = this._iv;
	            var counter = this._counter;

	            // Generate keystream
	            if (iv) {
	                counter = this._counter = iv.slice(0);

	                // Remove IV for subsequent blocks
	                this._iv = undefined;
	            }
	            var keystream = counter.slice(0);
	            cipher.encryptBlock(keystream, 0);

	            // Increment counter
	            counter[blockSize - 1] = (counter[blockSize - 1] + 1) | 0

	            // Encrypt
	            for (var i = 0; i < blockSize; i++) {
	                words[offset + i] ^= keystream[i];
	            }
	        }
	    });

	    CTR.Decryptor = Encryptor;

	    return CTR;
	}());


	return CryptoJS.mode.CTR;

}));

/***/ }),

/***/ "./node_modules/crypto-js/sha1.js":
/*!****************************************!*\
  !*** ./node_modules/crypto-js/sha1.js ***!
  \****************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"));
	}
	else {}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var Hasher = C_lib.Hasher;
	    var C_algo = C.algo;

	    // Reusable object
	    var W = [];

	    /**
	     * SHA-1 hash algorithm.
	     */
	    var SHA1 = C_algo.SHA1 = Hasher.extend({
	        _doReset: function () {
	            this._hash = new WordArray.init([
	                0x67452301, 0xefcdab89,
	                0x98badcfe, 0x10325476,
	                0xc3d2e1f0
	            ]);
	        },

	        _doProcessBlock: function (M, offset) {
	            // Shortcut
	            var H = this._hash.words;

	            // Working variables
	            var a = H[0];
	            var b = H[1];
	            var c = H[2];
	            var d = H[3];
	            var e = H[4];

	            // Computation
	            for (var i = 0; i < 80; i++) {
	                if (i < 16) {
	                    W[i] = M[offset + i] | 0;
	                } else {
	                    var n = W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16];
	                    W[i] = (n << 1) | (n >>> 31);
	                }

	                var t = ((a << 5) | (a >>> 27)) + e + W[i];
	                if (i < 20) {
	                    t += ((b & c) | (~b & d)) + 0x5a827999;
	                } else if (i < 40) {
	                    t += (b ^ c ^ d) + 0x6ed9eba1;
	                } else if (i < 60) {
	                    t += ((b & c) | (b & d) | (c & d)) - 0x70e44324;
	                } else /* if (i < 80) */ {
	                    t += (b ^ c ^ d) - 0x359d3e2a;
	                }

	                e = d;
	                d = c;
	                c = (b << 30) | (b >>> 2);
	                b = a;
	                a = t;
	            }

	            // Intermediate hash value
	            H[0] = (H[0] + a) | 0;
	            H[1] = (H[1] + b) | 0;
	            H[2] = (H[2] + c) | 0;
	            H[3] = (H[3] + d) | 0;
	            H[4] = (H[4] + e) | 0;
	        },

	        _doFinalize: function () {
	            // Shortcuts
	            var data = this._data;
	            var dataWords = data.words;

	            var nBitsTotal = this._nDataBytes * 8;
	            var nBitsLeft = data.sigBytes * 8;

	            // Add padding
	            dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);
	            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = Math.floor(nBitsTotal / 0x100000000);
	            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 15] = nBitsTotal;
	            data.sigBytes = dataWords.length * 4;

	            // Hash final blocks
	            this._process();

	            // Return final computed hash
	            return this._hash;
	        },

	        clone: function () {
	            var clone = Hasher.clone.call(this);
	            clone._hash = this._hash.clone();

	            return clone;
	        }
	    });

	    /**
	     * Shortcut function to the hasher's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     *
	     * @return {WordArray} The hash.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hash = CryptoJS.SHA1('message');
	     *     var hash = CryptoJS.SHA1(wordArray);
	     */
	    C.SHA1 = Hasher._createHelper(SHA1);

	    /**
	     * Shortcut function to the HMAC's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     * @param {WordArray|string} key The secret key.
	     *
	     * @return {WordArray} The HMAC.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hmac = CryptoJS.HmacSHA1(message, key);
	     */
	    C.HmacSHA1 = Hasher._createHmacHelper(SHA1);
	}());


	return CryptoJS.SHA1;

}));

/***/ }),

/***/ "./node_modules/cryptojs-extension/build_node/cmac.js":
/*!************************************************************!*\
  !*** ./node_modules/cryptojs-extension/build_node/cmac.js ***!
  \************************************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory) {
  // CommonJS
  module.exports = exports = factory(__webpack_require__(/*! crypto-js/core */ "./node_modules/crypto-js/core.js"), __webpack_require__(/*! ./common-bit-ops */ "./node_modules/cryptojs-extension/build_node/common-bit-ops.js"), __webpack_require__(/*! ./common */ "./node_modules/cryptojs-extension/build_node/common.js"), __webpack_require__(/*! crypto-js/aes */ "./node_modules/crypto-js/aes.js"));
}(this, function (C) {

  /*
   * The MIT License (MIT)
   *
   * Copyright (c) 2015 artjomb
   */
  // Shortcuts
  var Base = C.lib.Base;
  var WordArray = C.lib.WordArray;
  var AES = C.algo.AES;
  var ext = C.ext;
  var OneZeroPadding = C.pad.OneZeroPadding;


  var CMAC = C.algo.CMAC = Base.extend({
      /**
       * Initializes a newly created CMAC
       *
       * @param {WordArray} key The secret key
       *
       * @example
       *
       *     var cmacer = CryptoJS.algo.CMAC.create(key);
       */
      init: function(key){
          // generate sub keys...
          this._aes = AES.createEncryptor(key, { iv: new WordArray.init(), padding: C.pad.NoPadding });

          // Step 1
          var L = this._aes.finalize(ext.const_Zero);

          // Step 2
          var K1 = L.clone();
          ext.dbl(K1);

          // Step 3
          if (!this._isTwo) {
              var K2 = K1.clone();
              ext.dbl(K2);
          } else {
              var K2 = L.clone();
              ext.inv(K2);
          }

          this._K1 = K1;
          this._K2 = K2;

          this._const_Bsize = 16;

          this.reset();
      },

      reset: function () {
          this._x = ext.const_Zero.clone();
          this._counter = 0;
          this._buffer = new WordArray.init();
      },

      update: function (messageUpdate) {
          if (!messageUpdate) {
              return this;
          }

          // Shortcuts
          var buffer = this._buffer;
          var bsize = this._const_Bsize;

          if (typeof messageUpdate === "string") {
              messageUpdate = C.enc.Utf8.parse(messageUpdate);
          }

          buffer.concat(messageUpdate);

          while(buffer.sigBytes > bsize){
              var M_i = ext.shiftBytes(buffer, bsize);
              ext.xor(this._x, M_i);
              this._x.clamp();
              this._aes.reset();
              this._x = this._aes.finalize(this._x);
              this._counter++;
          }

          // Chainable
          return this;
      },

      finalize: function (messageUpdate) {
          this.update(messageUpdate);

          // Shortcuts
          var buffer = this._buffer;
          var bsize = this._const_Bsize;

          var M_last = buffer.clone();
          if (buffer.sigBytes === bsize) {
              ext.xor(M_last, this._K1);
          } else {
              OneZeroPadding.pad(M_last, bsize/4);
              ext.xor(M_last, this._K2);
          }

          ext.xor(M_last, this._x);

          this.reset(); // Can be used immediately afterwards

          this._aes.reset();
          return this._aes.finalize(M_last);
      },

      _isTwo: false
  });

  /**
   * Directly invokes the CMAC and returns the calculated MAC.
   *
   * @param {WordArray} key The key to be used for CMAC
   * @param {WordArray|string} message The data to be MAC'ed (either WordArray or UTF-8 encoded string)
   *
   * @returns {WordArray} MAC
   */
  C.CMAC = function(key, message){
      return CMAC.create(key).finalize(message);
  };

  C.algo.OMAC1 = CMAC;
  C.algo.OMAC2 = CMAC.extend({
      _isTwo: true
  });


}));

/***/ }),

/***/ "./node_modules/cryptojs-extension/build_node/common-bit-ops.js":
/*!**********************************************************************!*\
  !*** ./node_modules/cryptojs-extension/build_node/common-bit-ops.js ***!
  \**********************************************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory) {
  // CommonJS
  module.exports = exports = factory(__webpack_require__(/*! crypto-js/core */ "./node_modules/crypto-js/core.js"));
}(this, function (C) {

  /*
   * The MIT License (MIT)
   *
   * Copyright (c) 2015 artjomb
   */
  // put on ext property in CryptoJS
  var ext;
  if (!C.hasOwnProperty("ext")) {
      ext = C.ext = {};
  } else {
      ext = C.ext;
  }

  /**
   * Shifts the array by n bits to the left. Zero bits are added as the
   * least significant bits. This operation modifies the current array.
   *
   * @param {WordArray} wordArray WordArray to work on
   * @param {int} n Bits to shift by
   *
   * @returns the WordArray that was passed in
   */
  ext.bitshift = function(wordArray, n){
      var carry = 0,
          words = wordArray.words,
          wres,
          skipped = 0,
          carryMask;
      if (n > 0) {
          while(n > 31) {
              // delete first element:
              words.splice(0, 1);

              // add `0` word to the back
              words.push(0);

              n -= 32;
              skipped++;
          }
          if (n == 0) {
              // 1. nothing to shift if the shift amount is on a word boundary
              // 2. This has to be done, because the following algorithm computes
              // wrong values only for n==0
              return carry;
          }
          for(var i = words.length - skipped - 1; i >= 0; i--) {
              wres = words[i];
              words[i] <<= n;
              words[i] |= carry;
              carry = wres >>> (32 - n);
          }
      } else if (n < 0) {
          while(n < -31) {
              // insert `0` word to the front:
              words.splice(0, 0, 0);

              // remove last element:
              words.length--;

              n += 32;
              skipped++;
          }
          if (n == 0) {
              // nothing to shift if the shift amount is on a word boundary
              return carry;
          }
          n = -n;
          carryMask = (1 << n) - 1;
          for(var i = skipped; i < words.length; i++) {
              wres = words[i] & carryMask;
              words[i] >>>= n;
              words[i] |= carry;
              carry = wres << (32 - n);
          }
      }
      return carry;
  };

  /**
   * Negates all bits in the WordArray. This manipulates the given array.
   *
   * @param {WordArray} wordArray WordArray to work on
   *
   * @returns the WordArray that was passed in
   */
  ext.neg = function(wordArray){
      var words = wordArray.words;
      for(var i = 0; i < words.length; i++) {
          words[i] = ~words[i];
      }
      return wordArray;
  };

  /**
   * Applies XOR on both given word arrays and returns a third resulting
   * WordArray. The initial word arrays must have the same length
   * (significant bytes).
   *
   * @param {WordArray} wordArray1 WordArray
   * @param {WordArray} wordArray2 WordArray
   *
   * @returns first passed WordArray (modified)
   */
  ext.xor = function(wordArray1, wordArray2){
      for(var i = 0; i < wordArray1.words.length; i++) {
          wordArray1.words[i] ^= wordArray2.words[i];
      }
      return wordArray1;
  };

  /**
   * Logical AND between the two passed arrays. Both arrays must have the
   * same length.
   *
   * @param {WordArray} arr1 Array 1
   * @param {WordArray} arr2 Array 2
   *
   * @returns new WordArray
   */
  ext.bitand = function(arr1, arr2){
      var newArr = arr1.clone(),
          tw = newArr.words,
          ow = arr2.words;
      for(var i = 0; i < tw.length; i++) {
          tw[i] &= ow[i];
      }
      return newArr;
  };


}));

/***/ }),

/***/ "./node_modules/cryptojs-extension/build_node/common.js":
/*!**************************************************************!*\
  !*** ./node_modules/cryptojs-extension/build_node/common.js ***!
  \**************************************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory) {
  // CommonJS
  module.exports = exports = factory(__webpack_require__(/*! crypto-js/core */ "./node_modules/crypto-js/core.js"), __webpack_require__(/*! ./common-bit-ops */ "./node_modules/cryptojs-extension/build_node/common-bit-ops.js"), __webpack_require__(/*! crypto-js/cipher-core */ "./node_modules/crypto-js/cipher-core.js"));
}(this, function (C) {

  /*
   * The MIT License (MIT)
   *
   * Copyright (c) 2015 artjomb
   */
  // put on ext property in CryptoJS
  var ext;
  if (!C.hasOwnProperty("ext")) {
      ext = C.ext = {};
  } else {
      ext = C.ext;
  }

  // Shortcuts
  var Base = C.lib.Base;
  var WordArray = C.lib.WordArray;

  // Constants
  ext.const_Zero = new WordArray.init([0x00000000, 0x00000000, 0x00000000, 0x00000000]);
  ext.const_One = new WordArray.init([0x00000000, 0x00000000, 0x00000000, 0x00000001]);
  ext.const_Rb = new WordArray.init([0x00000000, 0x00000000, 0x00000000, 0x00000087]); // 00..0010000111
  ext.const_Rb_Shifted = new WordArray.init([0x80000000, 0x00000000, 0x00000000, 0x00000043]); // 100..001000011
  ext.const_nonMSB = new WordArray.init([0xFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF]); // 1^64 || 0^1 || 1^31 || 0^1 || 1^31

  /**
   * Looks into the object to see if it is a WordArray.
   *
   * @param obj Some object
   *
   * @returns {boolean}

   */
  ext.isWordArray = function(obj) {
      return obj && typeof obj.clamp === "function" && typeof obj.concat === "function" && typeof obj.words === "array";
  }

  /**
   * This padding is a 1 bit followed by as many 0 bits as needed to fill
   * up the block. This implementation doesn't work on bits directly,
   * but on bytes. Therefore the granularity is much bigger.
   */
  C.pad.OneZeroPadding = {
      pad: function (data, blocksize) {
          // Shortcut
          var blockSizeBytes = blocksize * 4;

          // Count padding bytes
          var nPaddingBytes = blockSizeBytes - data.sigBytes % blockSizeBytes;

          // Create padding
          var paddingWords = [];
          for (var i = 0; i < nPaddingBytes; i += 4) {
              var paddingWord = 0x00000000;
              if (i === 0) {
                  paddingWord = 0x80000000;
              }
              paddingWords.push(paddingWord);
          }
          var padding = new WordArray.init(paddingWords, nPaddingBytes);

          // Add padding
          data.concat(padding);
      },
      unpad: function () {
          // TODO: implement
      }
  };

  /**
   * No padding is applied. This is necessary for streaming cipher modes
   * like CTR.
   */
  C.pad.NoPadding = {
      pad: function () {},
      unpad: function () {}
  };

  /**
   * Returns the n leftmost bytes of the WordArray.
   *
   * @param {WordArray} wordArray WordArray to work on
   * @param {int} n Bytes to retrieve
   *
   * @returns new WordArray
   */
  ext.leftmostBytes = function(wordArray, n){
      var lmArray = wordArray.clone();
      lmArray.sigBytes = n;
      lmArray.clamp();
      return lmArray;
  };

  /**
   * Returns the n rightmost bytes of the WordArray.
   *
   * @param {WordArray} wordArray WordArray to work on
   * @param {int} n Bytes to retrieve (must be positive)
   *
   * @returns new WordArray
   */
  ext.rightmostBytes = function(wordArray, n){
      wordArray.clamp();
      var wordSize = 32;
      var rmArray = wordArray.clone();
      var bitsToShift = (rmArray.sigBytes - n) * 8;
      if (bitsToShift >= wordSize) {
          var popCount = Math.floor(bitsToShift/wordSize);
          bitsToShift -= popCount * wordSize;
          rmArray.words.splice(0, popCount);
          rmArray.sigBytes -= popCount * wordSize / 8;
      }
      if (bitsToShift > 0) {
          ext.bitshift(rmArray, bitsToShift);
          rmArray.sigBytes -= bitsToShift / 8;
      }
      return rmArray;
  };

  /**
   * Returns the n rightmost words of the WordArray. It assumes
   * that the current WordArray has at least n words.
   *
   * @param {WordArray} wordArray WordArray to work on
   * @param {int} n Words to retrieve (must be positive)
   *
   * @returns popped words as new WordArray
   */
  ext.popWords = function(wordArray, n){
      var left = wordArray.words.splice(0, n);
      wordArray.sigBytes -= n * 4;
      return new WordArray.init(left);
  };

  /**
   * Shifts the array to the left and returns the shifted dropped elements
   * as WordArray. The initial WordArray must contain at least n bytes and
   * they have to be significant.
   *
   * @param {WordArray} wordArray WordArray to work on (is modified)
   * @param {int} n Bytes to shift (must be positive, default 16)
   *
   * @returns new WordArray
   */
  ext.shiftBytes = function(wordArray, n){
      n = n || 16;
      var r = n % 4;
      n -= r;

      var shiftedArray = new WordArray.init();
      for(var i = 0; i < n; i += 4) {
          shiftedArray.words.push(wordArray.words.shift());
          wordArray.sigBytes -= 4;
          shiftedArray.sigBytes += 4;
      }
      if (r > 0) {
          shiftedArray.words.push(wordArray.words[0]);
          shiftedArray.sigBytes += r;

          ext.bitshift(wordArray, r * 8);
          wordArray.sigBytes -= r;
      }
      return shiftedArray;
  };

  /**
   * XORs arr2 to the end of arr1 array. This doesn't modify the current
   * array aside from clamping.
   *
   * @param {WordArray} arr1 Bigger array
   * @param {WordArray} arr2 Smaller array to be XORed to the end
   *
   * @returns new WordArray
   */
  ext.xorendBytes = function(arr1, arr2){
      // TODO: more efficient
      return ext.leftmostBytes(arr1, arr1.sigBytes-arr2.sigBytes)
              .concat(ext.xor(ext.rightmostBytes(arr1, arr2.sigBytes), arr2));
  };

  /**
   * Doubling operation on a 128-bit value. This operation modifies the
   * passed array.
   *
   * @param {WordArray} wordArray WordArray to work on
   *
   * @returns passed WordArray
   */
  ext.dbl = function(wordArray){
      var carry = ext.msb(wordArray);
      ext.bitshift(wordArray, 1);
      ext.xor(wordArray, carry === 1 ? ext.const_Rb : ext.const_Zero);
      return wordArray;
  };

  /**
   * Inverse operation on a 128-bit value. This operation modifies the
   * passed array.
   *
   * @param {WordArray} wordArray WordArray to work on
   *
   * @returns passed WordArray
   */
  ext.inv = function(wordArray){
      var carry = wordArray.words[4] & 1;
      ext.bitshift(wordArray, -1);
      ext.xor(wordArray, carry === 1 ? ext.const_Rb_Shifted : ext.const_Zero);
      return wordArray;
  };

  /**
   * Check whether the word arrays are equal.
   *
   * @param {WordArray} arr1 Array 1
   * @param {WordArray} arr2 Array 2
   *
   * @returns boolean
   */
  ext.equals = function(arr1, arr2){
      if (!arr2 || !arr2.words || arr1.sigBytes !== arr2.sigBytes) {
          return false;
      }
      arr1.clamp();
      arr2.clamp();
      var equal = 0;
      for(var i = 0; i < arr1.words.length; i++) {
          equal |= arr1.words[i] ^ arr2.words[i];
      }
      return equal === 0;
  };

  /**
   * Retrieves the most significant bit of the WordArray as an Integer.
   *
   * @param {WordArray} arr
   *
   * @returns Integer
   */
  ext.msb = function(arr) {
      return arr.words[0] >>> 31;
  }


}));

/***/ }),

/***/ "./node_modules/cryptojs-extension/build_node/siv.js":
/*!***********************************************************!*\
  !*** ./node_modules/cryptojs-extension/build_node/siv.js ***!
  \***********************************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory) {
  // CommonJS
  module.exports = exports = factory(__webpack_require__(/*! crypto-js/core */ "./node_modules/crypto-js/core.js"), __webpack_require__(/*! ./common-bit-ops */ "./node_modules/cryptojs-extension/build_node/common-bit-ops.js"), __webpack_require__(/*! ./common */ "./node_modules/cryptojs-extension/build_node/common.js"), __webpack_require__(/*! ./cmac */ "./node_modules/cryptojs-extension/build_node/cmac.js"), __webpack_require__(/*! crypto-js/aes */ "./node_modules/crypto-js/aes.js"), __webpack_require__(/*! crypto-js/mode-ctr */ "./node_modules/crypto-js/mode-ctr.js"));
}(this, function (C) {

  /*
   * The MIT License (MIT)
   *
   * Copyright (c) 2015 artjomb
   */
  // Shortcuts
  var Base = C.lib.Base;
  var WordArray = C.lib.WordArray;
  var AES = C.algo.AES;
  var ext = C.ext;
  var OneZeroPadding = C.pad.OneZeroPadding;
  var CMAC = C.algo.CMAC;

  /**
   * updateAAD must be used before update, because the additional data is
   * expected to be authenticated before the plaintext stream starts.
   */
  var S2V = C.algo.S2V = Base.extend({
      init: function(key){
          this._blockSize = 16;
          this._cmacAD = CMAC.create(key);
          this._cmacPT = CMAC.create(key);
          this.reset();
      },
      reset: function(){
          this._buffer = new WordArray.init();
          this._cmacAD.reset();
          this._cmacPT.reset();
          this._d = this._cmacAD.finalize(ext.const_Zero);
          this._empty = true;
          this._ptStarted = false;
      },
      updateAAD: function(msgUpdate){
          if (this._ptStarted) {
              // It's not possible to authenticate any more additional data when the plaintext stream starts
              return this;
          }

          if (!msgUpdate) {
              return this;
          }

          if (typeof msgUpdate === "string") {
              msgUpdate = C.enc.Utf8.parse(msgUpdate);
          }

          this._d = ext.xor(ext.dbl(this._d), this._cmacAD.finalize(msgUpdate));
          this._empty = false;

          // Chainable
          return this;
      },
      update: function(msgUpdate){
          if (!msgUpdate) {
              return this;
          }

          this._ptStarted = true;
          var buffer = this._buffer;
          var bsize = this._blockSize;
          var wsize = bsize / 4;
          var cmac = this._cmacPT;
          if (typeof msgUpdate === "string") {
              msgUpdate = C.enc.Utf8.parse(msgUpdate);
          }

          buffer.concat(msgUpdate);

          while(buffer.sigBytes >= 2 * bsize){
              this._empty = false;
              var s_i = ext.popWords(buffer, wsize);
              cmac.update(s_i);
          }

          // Chainable
          return this;
      },
      finalize: function(msgUpdate){
          this.update(msgUpdate);

          var bsize = this._blockSize;
          var s_n = this._buffer;

          if (this._empty && s_n.sigBytes === 0) {
              return this._cmacAD.finalize(ext.const_One);
          }

          var t;
          if (s_n.sigBytes >= bsize) {
              t = ext.xorendBytes(s_n, this._d);
          } else {
              OneZeroPadding.pad(s_n, bsize);
              t = ext.xor(ext.dbl(this._d), s_n);
          }

          return this._cmacPT.finalize(t);
      }
  });

  var SIV = C.SIV = Base.extend({
      init: function(key){
          var len = key.sigBytes / 2;
          this._s2vKey = ext.shiftBytes(key, len);
          this._ctrKey = key;
      },
      encrypt: function(adArray, plaintext){
          if (!plaintext && adArray) {
              plaintext = adArray;
              adArray = [];
          }

          var s2v = S2V.create(this._s2vKey);
          Array.prototype.forEach.call(adArray, function(ad){
              s2v.updateAAD(ad);
          });
          var tag = s2v.finalize(plaintext);
          var filteredTag = ext.bitand(tag, ext.const_nonMSB);

          var ciphertext = C.AES.encrypt(plaintext, this._ctrKey, {
              iv: filteredTag,
              mode: C.mode.CTR,
              padding: C.pad.NoPadding
          });

          return tag.concat(ciphertext.ciphertext);
      },
      decrypt: function(adArray, ciphertext){
          if (!ciphertext && adArray) {
              ciphertext = adArray;
              adArray = [];
          }

          var tag = ext.shiftBytes(ciphertext, 16);
          var filteredTag = ext.bitand(tag, ext.const_nonMSB);

          var plaintext = C.AES.decrypt({ciphertext:ciphertext}, this._ctrKey, {
              iv: filteredTag,
              mode: C.mode.CTR,
              padding: C.pad.NoPadding
          });

          var s2v = S2V.create(this._s2vKey);
          Array.prototype.forEach.call(adArray, function(ad){
              s2v.updateAAD(ad);
          });
          var recoveredTag = s2v.finalize(plaintext);

          if (ext.equals(tag, recoveredTag)) {
              return plaintext;
          } else {
              return false;
          }
      }
  });


}));

/***/ }),

/***/ "./node_modules/firebase/lib/firebase-web.js":
/*!***************************************************!*\
  !*** ./node_modules/firebase/lib/firebase-web.js ***!
  \***************************************************/
/*! no static exports found */
/***/ (function(module, exports) {

/*! @license Firebase v2.4.2
    License: https://www.firebase.com/terms/terms-of-service.html */
(function() {var h,n=this;function p(a){return void 0!==a}function aa(){}function ba(a){a.yb=function(){return a.zf?a.zf:a.zf=new a}}
function ca(a){var b=typeof a;if("object"==b)if(a){if(a instanceof Array)return"array";if(a instanceof Object)return b;var c=Object.prototype.toString.call(a);if("[object Window]"==c)return"object";if("[object Array]"==c||"number"==typeof a.length&&"undefined"!=typeof a.splice&&"undefined"!=typeof a.propertyIsEnumerable&&!a.propertyIsEnumerable("splice"))return"array";if("[object Function]"==c||"undefined"!=typeof a.call&&"undefined"!=typeof a.propertyIsEnumerable&&!a.propertyIsEnumerable("call"))return"function"}else return"null";
else if("function"==b&&"undefined"==typeof a.call)return"object";return b}function da(a){return"array"==ca(a)}function ea(a){var b=ca(a);return"array"==b||"object"==b&&"number"==typeof a.length}function q(a){return"string"==typeof a}function fa(a){return"number"==typeof a}function r(a){return"function"==ca(a)}function ga(a){var b=typeof a;return"object"==b&&null!=a||"function"==b}function ha(a,b,c){return a.call.apply(a.bind,arguments)}
function ia(a,b,c){if(!a)throw Error();if(2<arguments.length){var d=Array.prototype.slice.call(arguments,2);return function(){var c=Array.prototype.slice.call(arguments);Array.prototype.unshift.apply(c,d);return a.apply(b,c)}}return function(){return a.apply(b,arguments)}}function u(a,b,c){u=Function.prototype.bind&&-1!=Function.prototype.bind.toString().indexOf("native code")?ha:ia;return u.apply(null,arguments)}var ja=Date.now||function(){return+new Date};
function ka(a,b){function c(){}c.prototype=b.prototype;a.ph=b.prototype;a.prototype=new c;a.prototype.constructor=a;a.lh=function(a,c,f){for(var g=Array(arguments.length-2),k=2;k<arguments.length;k++)g[k-2]=arguments[k];return b.prototype[c].apply(a,g)}};function la(a){if(Error.captureStackTrace)Error.captureStackTrace(this,la);else{var b=Error().stack;b&&(this.stack=b)}a&&(this.message=String(a))}ka(la,Error);la.prototype.name="CustomError";function v(a,b){for(var c in a)b.call(void 0,a[c],c,a)}function ma(a,b){var c={},d;for(d in a)c[d]=b.call(void 0,a[d],d,a);return c}function na(a,b){for(var c in a)if(!b.call(void 0,a[c],c,a))return!1;return!0}function oa(a){var b=0,c;for(c in a)b++;return b}function pa(a){for(var b in a)return b}function qa(a){var b=[],c=0,d;for(d in a)b[c++]=a[d];return b}function ra(a){var b=[],c=0,d;for(d in a)b[c++]=d;return b}function sa(a,b){for(var c in a)if(a[c]==b)return!0;return!1}
function ta(a,b,c){for(var d in a)if(b.call(c,a[d],d,a))return d}function ua(a,b){var c=ta(a,b,void 0);return c&&a[c]}function va(a){for(var b in a)return!1;return!0}function wa(a){var b={},c;for(c in a)b[c]=a[c];return b}var xa="constructor hasOwnProperty isPrototypeOf propertyIsEnumerable toLocaleString toString valueOf".split(" ");
function ya(a,b){for(var c,d,e=1;e<arguments.length;e++){d=arguments[e];for(c in d)a[c]=d[c];for(var f=0;f<xa.length;f++)c=xa[f],Object.prototype.hasOwnProperty.call(d,c)&&(a[c]=d[c])}};function za(a){a=String(a);if(/^\s*$/.test(a)?0:/^[\],:{}\s\u2028\u2029]*$/.test(a.replace(/\\["\\\/bfnrtu]/g,"@").replace(/"[^"\\\n\r\u2028\u2029\x00-\x08\x0a-\x1f]*"|true|false|null|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?/g,"]").replace(/(?:^|:|,)(?:[\s\u2028\u2029]*\[)+/g,"")))try{return eval("("+a+")")}catch(b){}throw Error("Invalid JSON string: "+a);}function Aa(){this.Vd=void 0}
function Ba(a,b,c){switch(typeof b){case "string":Ca(b,c);break;case "number":c.push(isFinite(b)&&!isNaN(b)?b:"null");break;case "boolean":c.push(b);break;case "undefined":c.push("null");break;case "object":if(null==b){c.push("null");break}if(da(b)){var d=b.length;c.push("[");for(var e="",f=0;f<d;f++)c.push(e),e=b[f],Ba(a,a.Vd?a.Vd.call(b,String(f),e):e,c),e=",";c.push("]");break}c.push("{");d="";for(f in b)Object.prototype.hasOwnProperty.call(b,f)&&(e=b[f],"function"!=typeof e&&(c.push(d),Ca(f,c),
c.push(":"),Ba(a,a.Vd?a.Vd.call(b,f,e):e,c),d=","));c.push("}");break;case "function":break;default:throw Error("Unknown type: "+typeof b);}}var Da={'"':'\\"',"\\":"\\\\","/":"\\/","\b":"\\b","\f":"\\f","\n":"\\n","\r":"\\r","\t":"\\t","\x0B":"\\u000b"},Ea=/\uffff/.test("\uffff")?/[\\\"\x00-\x1f\x7f-\uffff]/g:/[\\\"\x00-\x1f\x7f-\xff]/g;
function Ca(a,b){b.push('"',a.replace(Ea,function(a){if(a in Da)return Da[a];var b=a.charCodeAt(0),e="\\u";16>b?e+="000":256>b?e+="00":4096>b&&(e+="0");return Da[a]=e+b.toString(16)}),'"')};function Fa(){return Math.floor(2147483648*Math.random()).toString(36)+Math.abs(Math.floor(2147483648*Math.random())^ja()).toString(36)};var w;a:{var Ga=n.navigator;if(Ga){var Ha=Ga.userAgent;if(Ha){w=Ha;break a}}w=""};function Ia(){this.Ya=-1};function Ja(){this.Ya=-1;this.Ya=64;this.P=[];this.pe=[];this.eg=[];this.Od=[];this.Od[0]=128;for(var a=1;a<this.Ya;++a)this.Od[a]=0;this.ge=this.ec=0;this.reset()}ka(Ja,Ia);Ja.prototype.reset=function(){this.P[0]=1732584193;this.P[1]=4023233417;this.P[2]=2562383102;this.P[3]=271733878;this.P[4]=3285377520;this.ge=this.ec=0};
function Ka(a,b,c){c||(c=0);var d=a.eg;if(q(b))for(var e=0;16>e;e++)d[e]=b.charCodeAt(c)<<24|b.charCodeAt(c+1)<<16|b.charCodeAt(c+2)<<8|b.charCodeAt(c+3),c+=4;else for(e=0;16>e;e++)d[e]=b[c]<<24|b[c+1]<<16|b[c+2]<<8|b[c+3],c+=4;for(e=16;80>e;e++){var f=d[e-3]^d[e-8]^d[e-14]^d[e-16];d[e]=(f<<1|f>>>31)&4294967295}b=a.P[0];c=a.P[1];for(var g=a.P[2],k=a.P[3],m=a.P[4],l,e=0;80>e;e++)40>e?20>e?(f=k^c&(g^k),l=1518500249):(f=c^g^k,l=1859775393):60>e?(f=c&g|k&(c|g),l=2400959708):(f=c^g^k,l=3395469782),f=(b<<
5|b>>>27)+f+m+l+d[e]&4294967295,m=k,k=g,g=(c<<30|c>>>2)&4294967295,c=b,b=f;a.P[0]=a.P[0]+b&4294967295;a.P[1]=a.P[1]+c&4294967295;a.P[2]=a.P[2]+g&4294967295;a.P[3]=a.P[3]+k&4294967295;a.P[4]=a.P[4]+m&4294967295}
Ja.prototype.update=function(a,b){if(null!=a){p(b)||(b=a.length);for(var c=b-this.Ya,d=0,e=this.pe,f=this.ec;d<b;){if(0==f)for(;d<=c;)Ka(this,a,d),d+=this.Ya;if(q(a))for(;d<b;){if(e[f]=a.charCodeAt(d),++f,++d,f==this.Ya){Ka(this,e);f=0;break}}else for(;d<b;)if(e[f]=a[d],++f,++d,f==this.Ya){Ka(this,e);f=0;break}}this.ec=f;this.ge+=b}};var x=Array.prototype,La=x.indexOf?function(a,b,c){return x.indexOf.call(a,b,c)}:function(a,b,c){c=null==c?0:0>c?Math.max(0,a.length+c):c;if(q(a))return q(b)&&1==b.length?a.indexOf(b,c):-1;for(;c<a.length;c++)if(c in a&&a[c]===b)return c;return-1},Ma=x.forEach?function(a,b,c){x.forEach.call(a,b,c)}:function(a,b,c){for(var d=a.length,e=q(a)?a.split(""):a,f=0;f<d;f++)f in e&&b.call(c,e[f],f,a)},Na=x.filter?function(a,b,c){return x.filter.call(a,b,c)}:function(a,b,c){for(var d=a.length,e=[],f=0,g=q(a)?
a.split(""):a,k=0;k<d;k++)if(k in g){var m=g[k];b.call(c,m,k,a)&&(e[f++]=m)}return e},Oa=x.map?function(a,b,c){return x.map.call(a,b,c)}:function(a,b,c){for(var d=a.length,e=Array(d),f=q(a)?a.split(""):a,g=0;g<d;g++)g in f&&(e[g]=b.call(c,f[g],g,a));return e},Pa=x.reduce?function(a,b,c,d){for(var e=[],f=1,g=arguments.length;f<g;f++)e.push(arguments[f]);d&&(e[0]=u(b,d));return x.reduce.apply(a,e)}:function(a,b,c,d){var e=c;Ma(a,function(c,g){e=b.call(d,e,c,g,a)});return e},Qa=x.every?function(a,b,
c){return x.every.call(a,b,c)}:function(a,b,c){for(var d=a.length,e=q(a)?a.split(""):a,f=0;f<d;f++)if(f in e&&!b.call(c,e[f],f,a))return!1;return!0};function Ra(a,b){var c=Sa(a,b,void 0);return 0>c?null:q(a)?a.charAt(c):a[c]}function Sa(a,b,c){for(var d=a.length,e=q(a)?a.split(""):a,f=0;f<d;f++)if(f in e&&b.call(c,e[f],f,a))return f;return-1}function Ta(a,b){var c=La(a,b);0<=c&&x.splice.call(a,c,1)}function Ua(a,b,c){return 2>=arguments.length?x.slice.call(a,b):x.slice.call(a,b,c)}
function Va(a,b){a.sort(b||Wa)}function Wa(a,b){return a>b?1:a<b?-1:0};function Xa(a){n.setTimeout(function(){throw a;},0)}var Ya;
function Za(){var a=n.MessageChannel;"undefined"===typeof a&&"undefined"!==typeof window&&window.postMessage&&window.addEventListener&&-1==w.indexOf("Presto")&&(a=function(){var a=document.createElement("iframe");a.style.display="none";a.src="";document.documentElement.appendChild(a);var b=a.contentWindow,a=b.document;a.open();a.write("");a.close();var c="callImmediate"+Math.random(),d="file:"==b.location.protocol?"*":b.location.protocol+"//"+b.location.host,a=u(function(a){if(("*"==d||a.origin==
d)&&a.data==c)this.port1.onmessage()},this);b.addEventListener("message",a,!1);this.port1={};this.port2={postMessage:function(){b.postMessage(c,d)}}});if("undefined"!==typeof a&&-1==w.indexOf("Trident")&&-1==w.indexOf("MSIE")){var b=new a,c={},d=c;b.port1.onmessage=function(){if(p(c.next)){c=c.next;var a=c.hb;c.hb=null;a()}};return function(a){d.next={hb:a};d=d.next;b.port2.postMessage(0)}}return"undefined"!==typeof document&&"onreadystatechange"in document.createElement("script")?function(a){var b=
document.createElement("script");b.onreadystatechange=function(){b.onreadystatechange=null;b.parentNode.removeChild(b);b=null;a();a=null};document.documentElement.appendChild(b)}:function(a){n.setTimeout(a,0)}};function $a(a,b){ab||bb();cb||(ab(),cb=!0);db.push(new eb(a,b))}var ab;function bb(){if(n.Promise&&n.Promise.resolve){var a=n.Promise.resolve();ab=function(){a.then(fb)}}else ab=function(){var a=fb;!r(n.setImmediate)||n.Window&&n.Window.prototype&&n.Window.prototype.setImmediate==n.setImmediate?(Ya||(Ya=Za()),Ya(a)):n.setImmediate(a)}}var cb=!1,db=[];[].push(function(){cb=!1;db=[]});
function fb(){for(;db.length;){var a=db;db=[];for(var b=0;b<a.length;b++){var c=a[b];try{c.yg.call(c.scope)}catch(d){Xa(d)}}}cb=!1}function eb(a,b){this.yg=a;this.scope=b};var gb=-1!=w.indexOf("Opera")||-1!=w.indexOf("OPR"),hb=-1!=w.indexOf("Trident")||-1!=w.indexOf("MSIE"),ib=-1!=w.indexOf("Gecko")&&-1==w.toLowerCase().indexOf("webkit")&&!(-1!=w.indexOf("Trident")||-1!=w.indexOf("MSIE")),jb=-1!=w.toLowerCase().indexOf("webkit");
(function(){var a="",b;if(gb&&n.opera)return a=n.opera.version,r(a)?a():a;ib?b=/rv\:([^\);]+)(\)|;)/:hb?b=/\b(?:MSIE|rv)[: ]([^\);]+)(\)|;)/:jb&&(b=/WebKit\/(\S+)/);b&&(a=(a=b.exec(w))?a[1]:"");return hb&&(b=(b=n.document)?b.documentMode:void 0,b>parseFloat(a))?String(b):a})();var kb=null,lb=null,mb=null;function nb(a,b){if(!ea(a))throw Error("encodeByteArray takes an array as a parameter");ob();for(var c=b?lb:kb,d=[],e=0;e<a.length;e+=3){var f=a[e],g=e+1<a.length,k=g?a[e+1]:0,m=e+2<a.length,l=m?a[e+2]:0,t=f>>2,f=(f&3)<<4|k>>4,k=(k&15)<<2|l>>6,l=l&63;m||(l=64,g||(k=64));d.push(c[t],c[f],c[k],c[l])}return d.join("")}
function ob(){if(!kb){kb={};lb={};mb={};for(var a=0;65>a;a++)kb[a]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".charAt(a),lb[a]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.".charAt(a),mb[lb[a]]=a,62<=a&&(mb["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".charAt(a)]=a)}};function pb(a,b){this.N=qb;this.Rf=void 0;this.Ba=this.Ha=null;this.yd=this.ye=!1;if(a==rb)sb(this,tb,b);else try{var c=this;a.call(b,function(a){sb(c,tb,a)},function(a){if(!(a instanceof ub))try{if(a instanceof Error)throw a;throw Error("Promise rejected.");}catch(b){}sb(c,vb,a)})}catch(d){sb(this,vb,d)}}var qb=0,tb=2,vb=3;function rb(){}pb.prototype.then=function(a,b,c){return wb(this,r(a)?a:null,r(b)?b:null,c)};pb.prototype.then=pb.prototype.then;pb.prototype.$goog_Thenable=!0;h=pb.prototype;
h.gh=function(a,b){return wb(this,null,a,b)};h.cancel=function(a){this.N==qb&&$a(function(){var b=new ub(a);xb(this,b)},this)};function xb(a,b){if(a.N==qb)if(a.Ha){var c=a.Ha;if(c.Ba){for(var d=0,e=-1,f=0,g;g=c.Ba[f];f++)if(g=g.o)if(d++,g==a&&(e=f),0<=e&&1<d)break;0<=e&&(c.N==qb&&1==d?xb(c,b):(d=c.Ba.splice(e,1)[0],yb(c,d,vb,b)))}a.Ha=null}else sb(a,vb,b)}function zb(a,b){a.Ba&&a.Ba.length||a.N!=tb&&a.N!=vb||Ab(a);a.Ba||(a.Ba=[]);a.Ba.push(b)}
function wb(a,b,c,d){var e={o:null,Hf:null,Jf:null};e.o=new pb(function(a,g){e.Hf=b?function(c){try{var e=b.call(d,c);a(e)}catch(l){g(l)}}:a;e.Jf=c?function(b){try{var e=c.call(d,b);!p(e)&&b instanceof ub?g(b):a(e)}catch(l){g(l)}}:g});e.o.Ha=a;zb(a,e);return e.o}h.Yf=function(a){this.N=qb;sb(this,tb,a)};h.Zf=function(a){this.N=qb;sb(this,vb,a)};
function sb(a,b,c){if(a.N==qb){if(a==c)b=vb,c=new TypeError("Promise cannot resolve to itself");else{var d;if(c)try{d=!!c.$goog_Thenable}catch(e){d=!1}else d=!1;if(d){a.N=1;c.then(a.Yf,a.Zf,a);return}if(ga(c))try{var f=c.then;if(r(f)){Bb(a,c,f);return}}catch(g){b=vb,c=g}}a.Rf=c;a.N=b;a.Ha=null;Ab(a);b!=vb||c instanceof ub||Cb(a,c)}}function Bb(a,b,c){function d(b){f||(f=!0,a.Zf(b))}function e(b){f||(f=!0,a.Yf(b))}a.N=1;var f=!1;try{c.call(b,e,d)}catch(g){d(g)}}
function Ab(a){a.ye||(a.ye=!0,$a(a.wg,a))}h.wg=function(){for(;this.Ba&&this.Ba.length;){var a=this.Ba;this.Ba=null;for(var b=0;b<a.length;b++)yb(this,a[b],this.N,this.Rf)}this.ye=!1};function yb(a,b,c,d){if(c==tb)b.Hf(d);else{if(b.o)for(;a&&a.yd;a=a.Ha)a.yd=!1;b.Jf(d)}}function Cb(a,b){a.yd=!0;$a(function(){a.yd&&Db.call(null,b)})}var Db=Xa;function ub(a){la.call(this,a)}ka(ub,la);ub.prototype.name="cancel";var Eb=Eb||"2.4.2";function y(a,b){return Object.prototype.hasOwnProperty.call(a,b)}function z(a,b){if(Object.prototype.hasOwnProperty.call(a,b))return a[b]}function Fb(a,b){for(var c in a)Object.prototype.hasOwnProperty.call(a,c)&&b(c,a[c])}function Gb(a){var b={};Fb(a,function(a,d){b[a]=d});return b}function Hb(a){return"object"===typeof a&&null!==a};function Ib(a){var b=[];Fb(a,function(a,d){da(d)?Ma(d,function(d){b.push(encodeURIComponent(a)+"="+encodeURIComponent(d))}):b.push(encodeURIComponent(a)+"="+encodeURIComponent(d))});return b.length?"&"+b.join("&"):""}function Jb(a){var b={};a=a.replace(/^\?/,"").split("&");Ma(a,function(a){a&&(a=a.split("="),b[a[0]]=a[1])});return b};function Kb(a,b){if(!a)throw Lb(b);}function Lb(a){return Error("Firebase ("+Eb+") INTERNAL ASSERT FAILED: "+a)};var Mb=n.Promise||pb;pb.prototype["catch"]=pb.prototype.gh;function B(){var a=this;this.reject=this.resolve=null;this.D=new Mb(function(b,c){a.resolve=b;a.reject=c})}function C(a,b){return function(c,d){c?a.reject(c):a.resolve(d);r(b)&&(Nb(a.D),1===b.length?b(c):b(c,d))}}function Nb(a){a.then(void 0,aa)};function Ob(a){for(var b=[],c=0,d=0;d<a.length;d++){var e=a.charCodeAt(d);55296<=e&&56319>=e&&(e-=55296,d++,Kb(d<a.length,"Surrogate pair missing trail surrogate."),e=65536+(e<<10)+(a.charCodeAt(d)-56320));128>e?b[c++]=e:(2048>e?b[c++]=e>>6|192:(65536>e?b[c++]=e>>12|224:(b[c++]=e>>18|240,b[c++]=e>>12&63|128),b[c++]=e>>6&63|128),b[c++]=e&63|128)}return b}function Pb(a){for(var b=0,c=0;c<a.length;c++){var d=a.charCodeAt(c);128>d?b++:2048>d?b+=2:55296<=d&&56319>=d?(b+=4,c++):b+=3}return b};function D(a,b,c,d){var e;d<b?e="at least "+b:d>c&&(e=0===c?"none":"no more than "+c);if(e)throw Error(a+" failed: Was called with "+d+(1===d?" argument.":" arguments.")+" Expects "+e+".");}function E(a,b,c){var d="";switch(b){case 1:d=c?"first":"First";break;case 2:d=c?"second":"Second";break;case 3:d=c?"third":"Third";break;case 4:d=c?"fourth":"Fourth";break;default:throw Error("errorPrefix called with argumentNumber > 4.  Need to update it?");}return a=a+" failed: "+(d+" argument ")}
function F(a,b,c,d){if((!d||p(c))&&!r(c))throw Error(E(a,b,d)+"must be a valid function.");}function Qb(a,b,c){if(p(c)&&(!ga(c)||null===c))throw Error(E(a,b,!0)+"must be a valid context object.");};function Rb(a){return"undefined"!==typeof JSON&&p(JSON.parse)?JSON.parse(a):za(a)}function G(a){if("undefined"!==typeof JSON&&p(JSON.stringify))a=JSON.stringify(a);else{var b=[];Ba(new Aa,a,b);a=b.join("")}return a};function Sb(){this.Zd=H}Sb.prototype.j=function(a){return this.Zd.S(a)};Sb.prototype.toString=function(){return this.Zd.toString()};function Tb(){}Tb.prototype.uf=function(){return null};Tb.prototype.Ce=function(){return null};var Ub=new Tb;function Vb(a,b,c){this.bg=a;this.Oa=b;this.Nd=c}Vb.prototype.uf=function(a){var b=this.Oa.Q;if(Wb(b,a))return b.j().T(a);b=null!=this.Nd?new Xb(this.Nd,!0,!1):this.Oa.w();return this.bg.Bc(a,b)};Vb.prototype.Ce=function(a,b,c){var d=null!=this.Nd?this.Nd:Yb(this.Oa);a=this.bg.qe(d,b,1,c,a);return 0===a.length?null:a[0]};function Zb(){this.xb=[]}function $b(a,b){for(var c=null,d=0;d<b.length;d++){var e=b[d],f=e.cc();null===c||f.ea(c.cc())||(a.xb.push(c),c=null);null===c&&(c=new ac(f));c.add(e)}c&&a.xb.push(c)}function bc(a,b,c){$b(a,c);cc(a,function(a){return a.ea(b)})}function dc(a,b,c){$b(a,c);cc(a,function(a){return a.contains(b)||b.contains(a)})}
function cc(a,b){for(var c=!0,d=0;d<a.xb.length;d++){var e=a.xb[d];if(e)if(e=e.cc(),b(e)){for(var e=a.xb[d],f=0;f<e.xd.length;f++){var g=e.xd[f];if(null!==g){e.xd[f]=null;var k=g.Zb();ec&&fc("event: "+g.toString());gc(k)}}a.xb[d]=null}else c=!1}c&&(a.xb=[])}function ac(a){this.ta=a;this.xd=[]}ac.prototype.add=function(a){this.xd.push(a)};ac.prototype.cc=function(){return this.ta};function J(a,b,c,d){this.type=a;this.Na=b;this.Za=c;this.Oe=d;this.Td=void 0}function hc(a){return new J(ic,a)}var ic="value";function jc(a,b,c,d){this.xe=b;this.be=c;this.Td=d;this.wd=a}jc.prototype.cc=function(){var a=this.be.Mb();return"value"===this.wd?a.path:a.parent().path};jc.prototype.De=function(){return this.wd};jc.prototype.Zb=function(){return this.xe.Zb(this)};jc.prototype.toString=function(){return this.cc().toString()+":"+this.wd+":"+G(this.be.qf())};function kc(a,b,c){this.xe=a;this.error=b;this.path=c}kc.prototype.cc=function(){return this.path};kc.prototype.De=function(){return"cancel"};
kc.prototype.Zb=function(){return this.xe.Zb(this)};kc.prototype.toString=function(){return this.path.toString()+":cancel"};function Xb(a,b,c){this.A=a;this.ga=b;this.Yb=c}function lc(a){return a.ga}function mc(a){return a.Yb}function nc(a,b){return b.e()?a.ga&&!a.Yb:Wb(a,K(b))}function Wb(a,b){return a.ga&&!a.Yb||a.A.Fa(b)}Xb.prototype.j=function(){return this.A};function oc(a){this.pg=a;this.Gd=null}oc.prototype.get=function(){var a=this.pg.get(),b=wa(a);if(this.Gd)for(var c in this.Gd)b[c]-=this.Gd[c];this.Gd=a;return b};function pc(a,b){this.Vf={};this.hd=new oc(a);this.da=b;var c=1E4+2E4*Math.random();setTimeout(u(this.Of,this),Math.floor(c))}pc.prototype.Of=function(){var a=this.hd.get(),b={},c=!1,d;for(d in a)0<a[d]&&y(this.Vf,d)&&(b[d]=a[d],c=!0);c&&this.da.Ye(b);setTimeout(u(this.Of,this),Math.floor(6E5*Math.random()))};function qc(){this.Hc={}}function rc(a,b,c){p(c)||(c=1);y(a.Hc,b)||(a.Hc[b]=0);a.Hc[b]+=c}qc.prototype.get=function(){return wa(this.Hc)};var sc={},tc={};function uc(a){a=a.toString();sc[a]||(sc[a]=new qc);return sc[a]}function vc(a,b){var c=a.toString();tc[c]||(tc[c]=b());return tc[c]};function L(a,b){this.name=a;this.U=b}function wc(a,b){return new L(a,b)};function xc(a,b){return yc(a.name,b.name)}function zc(a,b){return yc(a,b)};function Ac(a,b,c){this.type=Bc;this.source=a;this.path=b;this.Ja=c}Ac.prototype.$c=function(a){return this.path.e()?new Ac(this.source,M,this.Ja.T(a)):new Ac(this.source,N(this.path),this.Ja)};Ac.prototype.toString=function(){return"Operation("+this.path+": "+this.source.toString()+" overwrite: "+this.Ja.toString()+")"};function Cc(a,b){this.type=Dc;this.source=a;this.path=b}Cc.prototype.$c=function(){return this.path.e()?new Cc(this.source,M):new Cc(this.source,N(this.path))};Cc.prototype.toString=function(){return"Operation("+this.path+": "+this.source.toString()+" listen_complete)"};function Ec(a,b){this.Pa=a;this.xa=b?b:Fc}h=Ec.prototype;h.Sa=function(a,b){return new Ec(this.Pa,this.xa.Sa(a,b,this.Pa).$(null,null,!1,null,null))};h.remove=function(a){return new Ec(this.Pa,this.xa.remove(a,this.Pa).$(null,null,!1,null,null))};h.get=function(a){for(var b,c=this.xa;!c.e();){b=this.Pa(a,c.key);if(0===b)return c.value;0>b?c=c.left:0<b&&(c=c.right)}return null};
function Gc(a,b){for(var c,d=a.xa,e=null;!d.e();){c=a.Pa(b,d.key);if(0===c){if(d.left.e())return e?e.key:null;for(d=d.left;!d.right.e();)d=d.right;return d.key}0>c?d=d.left:0<c&&(e=d,d=d.right)}throw Error("Attempted to find predecessor key for a nonexistent key.  What gives?");}h.e=function(){return this.xa.e()};h.count=function(){return this.xa.count()};h.Vc=function(){return this.xa.Vc()};h.jc=function(){return this.xa.jc()};h.ka=function(a){return this.xa.ka(a)};
h.ac=function(a){return new Hc(this.xa,null,this.Pa,!1,a)};h.bc=function(a,b){return new Hc(this.xa,a,this.Pa,!1,b)};h.dc=function(a,b){return new Hc(this.xa,a,this.Pa,!0,b)};h.xf=function(a){return new Hc(this.xa,null,this.Pa,!0,a)};function Hc(a,b,c,d,e){this.Xd=e||null;this.Je=d;this.Ta=[];for(e=1;!a.e();)if(e=b?c(a.key,b):1,d&&(e*=-1),0>e)a=this.Je?a.left:a.right;else if(0===e){this.Ta.push(a);break}else this.Ta.push(a),a=this.Je?a.right:a.left}
function Ic(a){if(0===a.Ta.length)return null;var b=a.Ta.pop(),c;c=a.Xd?a.Xd(b.key,b.value):{key:b.key,value:b.value};if(a.Je)for(b=b.left;!b.e();)a.Ta.push(b),b=b.right;else for(b=b.right;!b.e();)a.Ta.push(b),b=b.left;return c}function Jc(a){if(0===a.Ta.length)return null;var b;b=a.Ta;b=b[b.length-1];return a.Xd?a.Xd(b.key,b.value):{key:b.key,value:b.value}}function Kc(a,b,c,d,e){this.key=a;this.value=b;this.color=null!=c?c:!0;this.left=null!=d?d:Fc;this.right=null!=e?e:Fc}h=Kc.prototype;
h.$=function(a,b,c,d,e){return new Kc(null!=a?a:this.key,null!=b?b:this.value,null!=c?c:this.color,null!=d?d:this.left,null!=e?e:this.right)};h.count=function(){return this.left.count()+1+this.right.count()};h.e=function(){return!1};h.ka=function(a){return this.left.ka(a)||a(this.key,this.value)||this.right.ka(a)};function Lc(a){return a.left.e()?a:Lc(a.left)}h.Vc=function(){return Lc(this).key};h.jc=function(){return this.right.e()?this.key:this.right.jc()};
h.Sa=function(a,b,c){var d,e;e=this;d=c(a,e.key);e=0>d?e.$(null,null,null,e.left.Sa(a,b,c),null):0===d?e.$(null,b,null,null,null):e.$(null,null,null,null,e.right.Sa(a,b,c));return Mc(e)};function Nc(a){if(a.left.e())return Fc;a.left.ha()||a.left.left.ha()||(a=Oc(a));a=a.$(null,null,null,Nc(a.left),null);return Mc(a)}
h.remove=function(a,b){var c,d;c=this;if(0>b(a,c.key))c.left.e()||c.left.ha()||c.left.left.ha()||(c=Oc(c)),c=c.$(null,null,null,c.left.remove(a,b),null);else{c.left.ha()&&(c=Pc(c));c.right.e()||c.right.ha()||c.right.left.ha()||(c=Qc(c),c.left.left.ha()&&(c=Pc(c),c=Qc(c)));if(0===b(a,c.key)){if(c.right.e())return Fc;d=Lc(c.right);c=c.$(d.key,d.value,null,null,Nc(c.right))}c=c.$(null,null,null,null,c.right.remove(a,b))}return Mc(c)};h.ha=function(){return this.color};
function Mc(a){a.right.ha()&&!a.left.ha()&&(a=Rc(a));a.left.ha()&&a.left.left.ha()&&(a=Pc(a));a.left.ha()&&a.right.ha()&&(a=Qc(a));return a}function Oc(a){a=Qc(a);a.right.left.ha()&&(a=a.$(null,null,null,null,Pc(a.right)),a=Rc(a),a=Qc(a));return a}function Rc(a){return a.right.$(null,null,a.color,a.$(null,null,!0,null,a.right.left),null)}function Pc(a){return a.left.$(null,null,a.color,null,a.$(null,null,!0,a.left.right,null))}
function Qc(a){return a.$(null,null,!a.color,a.left.$(null,null,!a.left.color,null,null),a.right.$(null,null,!a.right.color,null,null))}function Sc(){}h=Sc.prototype;h.$=function(){return this};h.Sa=function(a,b){return new Kc(a,b,null)};h.remove=function(){return this};h.count=function(){return 0};h.e=function(){return!0};h.ka=function(){return!1};h.Vc=function(){return null};h.jc=function(){return null};h.ha=function(){return!1};var Fc=new Sc;function Tc(a,b){return a&&"object"===typeof a?(O(".sv"in a,"Unexpected leaf node or priority contents"),b[a[".sv"]]):a}function Uc(a,b){var c=new Vc;Wc(a,new P(""),function(a,e){c.rc(a,Xc(e,b))});return c}function Xc(a,b){var c=a.C().J(),c=Tc(c,b),d;if(a.L()){var e=Tc(a.Ea(),b);return e!==a.Ea()||c!==a.C().J()?new Yc(e,Q(c)):a}d=a;c!==a.C().J()&&(d=d.ia(new Yc(c)));a.R(R,function(a,c){var e=Xc(c,b);e!==c&&(d=d.W(a,e))});return d};function Zc(){this.Ac={}}Zc.prototype.set=function(a,b){null==b?delete this.Ac[a]:this.Ac[a]=b};Zc.prototype.get=function(a){return y(this.Ac,a)?this.Ac[a]:null};Zc.prototype.remove=function(a){delete this.Ac[a]};Zc.prototype.Af=!0;function $c(a){this.Ic=a;this.Sd="firebase:"}h=$c.prototype;h.set=function(a,b){null==b?this.Ic.removeItem(this.Sd+a):this.Ic.setItem(this.Sd+a,G(b))};h.get=function(a){a=this.Ic.getItem(this.Sd+a);return null==a?null:Rb(a)};h.remove=function(a){this.Ic.removeItem(this.Sd+a)};h.Af=!1;h.toString=function(){return this.Ic.toString()};function ad(a){try{if("undefined"!==typeof window&&"undefined"!==typeof window[a]){var b=window[a];b.setItem("firebase:sentinel","cache");b.removeItem("firebase:sentinel");return new $c(b)}}catch(c){}return new Zc}var bd=ad("localStorage"),cd=ad("sessionStorage");function dd(a,b,c,d,e){this.host=a.toLowerCase();this.domain=this.host.substr(this.host.indexOf(".")+1);this.ob=b;this.lc=c;this.jh=d;this.Rd=e||"";this.ab=bd.get("host:"+a)||this.host}function ed(a,b){b!==a.ab&&(a.ab=b,"s-"===a.ab.substr(0,2)&&bd.set("host:"+a.host,a.ab))}
function fd(a,b,c){O("string"===typeof b,"typeof type must == string");O("object"===typeof c,"typeof params must == object");if(b===gd)b=(a.ob?"wss://":"ws://")+a.ab+"/.ws?";else if(b===hd)b=(a.ob?"https://":"http://")+a.ab+"/.lp?";else throw Error("Unknown connection type: "+b);a.host!==a.ab&&(c.ns=a.lc);var d=[];v(c,function(a,b){d.push(b+"="+a)});return b+d.join("&")}dd.prototype.toString=function(){var a=(this.ob?"https://":"http://")+this.host;this.Rd&&(a+="<"+this.Rd+">");return a};var id=function(){var a=1;return function(){return a++}}(),O=Kb,jd=Lb;
function kd(a){try{var b;if("undefined"!==typeof atob)b=atob(a);else{ob();for(var c=mb,d=[],e=0;e<a.length;){var f=c[a.charAt(e++)],g=e<a.length?c[a.charAt(e)]:0;++e;var k=e<a.length?c[a.charAt(e)]:64;++e;var m=e<a.length?c[a.charAt(e)]:64;++e;if(null==f||null==g||null==k||null==m)throw Error();d.push(f<<2|g>>4);64!=k&&(d.push(g<<4&240|k>>2),64!=m&&d.push(k<<6&192|m))}if(8192>d.length)b=String.fromCharCode.apply(null,d);else{a="";for(c=0;c<d.length;c+=8192)a+=String.fromCharCode.apply(null,Ua(d,c,
c+8192));b=a}}return b}catch(l){fc("base64Decode failed: ",l)}return null}function ld(a){var b=Ob(a);a=new Ja;a.update(b);var b=[],c=8*a.ge;56>a.ec?a.update(a.Od,56-a.ec):a.update(a.Od,a.Ya-(a.ec-56));for(var d=a.Ya-1;56<=d;d--)a.pe[d]=c&255,c/=256;Ka(a,a.pe);for(d=c=0;5>d;d++)for(var e=24;0<=e;e-=8)b[c]=a.P[d]>>e&255,++c;return nb(b)}
function md(a){for(var b="",c=0;c<arguments.length;c++)b=ea(arguments[c])?b+md.apply(null,arguments[c]):"object"===typeof arguments[c]?b+G(arguments[c]):b+arguments[c],b+=" ";return b}var ec=null,nd=!0;
function od(a,b){Kb(!b||!0===a||!1===a,"Can't turn on custom loggers persistently.");!0===a?("undefined"!==typeof console&&("function"===typeof console.log?ec=u(console.log,console):"object"===typeof console.log&&(ec=function(a){console.log(a)})),b&&cd.set("logging_enabled",!0)):r(a)?ec=a:(ec=null,cd.remove("logging_enabled"))}function fc(a){!0===nd&&(nd=!1,null===ec&&!0===cd.get("logging_enabled")&&od(!0));if(ec){var b=md.apply(null,arguments);ec(b)}}
function pd(a){return function(){fc(a,arguments)}}function qd(a){if("undefined"!==typeof console){var b="FIREBASE INTERNAL ERROR: "+md.apply(null,arguments);"undefined"!==typeof console.error?console.error(b):console.log(b)}}function rd(a){var b=md.apply(null,arguments);throw Error("FIREBASE FATAL ERROR: "+b);}function S(a){if("undefined"!==typeof console){var b="FIREBASE WARNING: "+md.apply(null,arguments);"undefined"!==typeof console.warn?console.warn(b):console.log(b)}}
function sd(a){var b="",c="",d="",e="",f=!0,g="https",k=443;if(q(a)){var m=a.indexOf("//");0<=m&&(g=a.substring(0,m-1),a=a.substring(m+2));m=a.indexOf("/");-1===m&&(m=a.length);b=a.substring(0,m);e="";a=a.substring(m).split("/");for(m=0;m<a.length;m++)if(0<a[m].length){var l=a[m];try{l=decodeURIComponent(l.replace(/\+/g," "))}catch(t){}e+="/"+l}a=b.split(".");3===a.length?(c=a[1],d=a[0].toLowerCase()):2===a.length&&(c=a[0]);m=b.indexOf(":");0<=m&&(f="https"===g||"wss"===g,k=b.substring(m+1),isFinite(k)&&
(k=String(k)),k=q(k)?/^\s*-?0x/i.test(k)?parseInt(k,16):parseInt(k,10):NaN)}return{host:b,port:k,domain:c,fh:d,ob:f,scheme:g,bd:e}}function td(a){return fa(a)&&(a!=a||a==Number.POSITIVE_INFINITY||a==Number.NEGATIVE_INFINITY)}
function ud(a){if("complete"===document.readyState)a();else{var b=!1,c=function(){document.body?b||(b=!0,a()):setTimeout(c,Math.floor(10))};document.addEventListener?(document.addEventListener("DOMContentLoaded",c,!1),window.addEventListener("load",c,!1)):document.attachEvent&&(document.attachEvent("onreadystatechange",function(){"complete"===document.readyState&&c()}),window.attachEvent("onload",c))}}
function yc(a,b){if(a===b)return 0;if("[MIN_NAME]"===a||"[MAX_NAME]"===b)return-1;if("[MIN_NAME]"===b||"[MAX_NAME]"===a)return 1;var c=vd(a),d=vd(b);return null!==c?null!==d?0==c-d?a.length-b.length:c-d:-1:null!==d?1:a<b?-1:1}function wd(a,b){if(b&&a in b)return b[a];throw Error("Missing required key ("+a+") in object: "+G(b));}
function xd(a){if("object"!==typeof a||null===a)return G(a);var b=[],c;for(c in a)b.push(c);b.sort();c="{";for(var d=0;d<b.length;d++)0!==d&&(c+=","),c+=G(b[d]),c+=":",c+=xd(a[b[d]]);return c+"}"}function yd(a,b){if(a.length<=b)return[a];for(var c=[],d=0;d<a.length;d+=b)d+b>a?c.push(a.substring(d,a.length)):c.push(a.substring(d,d+b));return c}function zd(a,b){if(da(a))for(var c=0;c<a.length;++c)b(c,a[c]);else v(a,b)}
function Ad(a){O(!td(a),"Invalid JSON number");var b,c,d,e;0===a?(d=c=0,b=-Infinity===1/a?1:0):(b=0>a,a=Math.abs(a),a>=Math.pow(2,-1022)?(d=Math.min(Math.floor(Math.log(a)/Math.LN2),1023),c=d+1023,d=Math.round(a*Math.pow(2,52-d)-Math.pow(2,52))):(c=0,d=Math.round(a/Math.pow(2,-1074))));e=[];for(a=52;a;--a)e.push(d%2?1:0),d=Math.floor(d/2);for(a=11;a;--a)e.push(c%2?1:0),c=Math.floor(c/2);e.push(b?1:0);e.reverse();b=e.join("");c="";for(a=0;64>a;a+=8)d=parseInt(b.substr(a,8),2).toString(16),1===d.length&&
(d="0"+d),c+=d;return c.toLowerCase()}var Bd=/^-?\d{1,10}$/;function vd(a){return Bd.test(a)&&(a=Number(a),-2147483648<=a&&2147483647>=a)?a:null}function gc(a){try{a()}catch(b){setTimeout(function(){S("Exception was thrown by user callback.",b.stack||"");throw b;},Math.floor(0))}}function T(a,b){if(r(a)){var c=Array.prototype.slice.call(arguments,1).slice();gc(function(){a.apply(null,c)})}};function Cd(a){var b={},c={},d={},e="";try{var f=a.split("."),b=Rb(kd(f[0])||""),c=Rb(kd(f[1])||""),e=f[2],d=c.d||{};delete c.d}catch(g){}return{mh:b,Ec:c,data:d,bh:e}}function Dd(a){a=Cd(a).Ec;return"object"===typeof a&&a.hasOwnProperty("iat")?z(a,"iat"):null}function Ed(a){a=Cd(a);var b=a.Ec;return!!a.bh&&!!b&&"object"===typeof b&&b.hasOwnProperty("iat")};function Fd(a){this.Y=a;this.g=a.n.g}function Gd(a,b,c,d){var e=[],f=[];Ma(b,function(b){"child_changed"===b.type&&a.g.Dd(b.Oe,b.Na)&&f.push(new J("child_moved",b.Na,b.Za))});Hd(a,e,"child_removed",b,d,c);Hd(a,e,"child_added",b,d,c);Hd(a,e,"child_moved",f,d,c);Hd(a,e,"child_changed",b,d,c);Hd(a,e,ic,b,d,c);return e}function Hd(a,b,c,d,e,f){d=Na(d,function(a){return a.type===c});Va(d,u(a.qg,a));Ma(d,function(c){var d=Id(a,c,f);Ma(e,function(e){e.Qf(c.type)&&b.push(e.createEvent(d,a.Y))})})}
function Id(a,b,c){"value"!==b.type&&"child_removed"!==b.type&&(b.Td=c.wf(b.Za,b.Na,a.g));return b}Fd.prototype.qg=function(a,b){if(null==a.Za||null==b.Za)throw jd("Should only compare child_ events.");return this.g.compare(new L(a.Za,a.Na),new L(b.Za,b.Na))};function Jd(){this.ib={}}
function Kd(a,b){var c=b.type,d=b.Za;O("child_added"==c||"child_changed"==c||"child_removed"==c,"Only child changes supported for tracking");O(".priority"!==d,"Only non-priority child changes can be tracked.");var e=z(a.ib,d);if(e){var f=e.type;if("child_added"==c&&"child_removed"==f)a.ib[d]=new J("child_changed",b.Na,d,e.Na);else if("child_removed"==c&&"child_added"==f)delete a.ib[d];else if("child_removed"==c&&"child_changed"==f)a.ib[d]=new J("child_removed",e.Oe,d);else if("child_changed"==c&&
"child_added"==f)a.ib[d]=new J("child_added",b.Na,d);else if("child_changed"==c&&"child_changed"==f)a.ib[d]=new J("child_changed",b.Na,d,e.Oe);else throw jd("Illegal combination of changes: "+b+" occurred after "+e);}else a.ib[d]=b};function Ld(a){this.g=a}h=Ld.prototype;h.H=function(a,b,c,d,e,f){O(a.Mc(this.g),"A node must be indexed if only a child is updated");e=a.T(b);if(e.S(d).ea(c.S(d))&&e.e()==c.e())return a;null!=f&&(c.e()?a.Fa(b)?Kd(f,new J("child_removed",e,b)):O(a.L(),"A child remove without an old child only makes sense on a leaf node"):e.e()?Kd(f,new J("child_added",c,b)):Kd(f,new J("child_changed",c,b,e)));return a.L()&&c.e()?a:a.W(b,c).pb(this.g)};
h.ya=function(a,b,c){null!=c&&(a.L()||a.R(R,function(a,e){b.Fa(a)||Kd(c,new J("child_removed",e,a))}),b.L()||b.R(R,function(b,e){if(a.Fa(b)){var f=a.T(b);f.ea(e)||Kd(c,new J("child_changed",e,b,f))}else Kd(c,new J("child_added",e,b))}));return b.pb(this.g)};h.ia=function(a,b){return a.e()?H:a.ia(b)};h.Ra=function(){return!1};h.$b=function(){return this};function Md(a){this.Fe=new Ld(a.g);this.g=a.g;var b;a.oa?(b=Nd(a),b=a.g.Sc(Od(a),b)):b=a.g.Wc();this.gd=b;a.ra?(b=Pd(a),a=a.g.Sc(Rd(a),b)):a=a.g.Tc();this.Jc=a}h=Md.prototype;h.matches=function(a){return 0>=this.g.compare(this.gd,a)&&0>=this.g.compare(a,this.Jc)};h.H=function(a,b,c,d,e,f){this.matches(new L(b,c))||(c=H);return this.Fe.H(a,b,c,d,e,f)};
h.ya=function(a,b,c){b.L()&&(b=H);var d=b.pb(this.g),d=d.ia(H),e=this;b.R(R,function(a,b){e.matches(new L(a,b))||(d=d.W(a,H))});return this.Fe.ya(a,d,c)};h.ia=function(a){return a};h.Ra=function(){return!0};h.$b=function(){return this.Fe};function Sd(a){this.ua=new Md(a);this.g=a.g;O(a.la,"Only valid if limit has been set");this.ma=a.ma;this.Nb=!Td(a)}h=Sd.prototype;h.H=function(a,b,c,d,e,f){this.ua.matches(new L(b,c))||(c=H);return a.T(b).ea(c)?a:a.Hb()<this.ma?this.ua.$b().H(a,b,c,d,e,f):Ud(this,a,b,c,e,f)};
h.ya=function(a,b,c){var d;if(b.L()||b.e())d=H.pb(this.g);else if(2*this.ma<b.Hb()&&b.Mc(this.g)){d=H.pb(this.g);b=this.Nb?b.dc(this.ua.Jc,this.g):b.bc(this.ua.gd,this.g);for(var e=0;0<b.Ta.length&&e<this.ma;){var f=Ic(b),g;if(g=this.Nb?0>=this.g.compare(this.ua.gd,f):0>=this.g.compare(f,this.ua.Jc))d=d.W(f.name,f.U),e++;else break}}else{d=b.pb(this.g);d=d.ia(H);var k,m,l;if(this.Nb){b=d.xf(this.g);k=this.ua.Jc;m=this.ua.gd;var t=Vd(this.g);l=function(a,b){return t(b,a)}}else b=d.ac(this.g),k=this.ua.gd,
m=this.ua.Jc,l=Vd(this.g);for(var e=0,A=!1;0<b.Ta.length;)f=Ic(b),!A&&0>=l(k,f)&&(A=!0),(g=A&&e<this.ma&&0>=l(f,m))?e++:d=d.W(f.name,H)}return this.ua.$b().ya(a,d,c)};h.ia=function(a){return a};h.Ra=function(){return!0};h.$b=function(){return this.ua.$b()};
function Ud(a,b,c,d,e,f){var g;if(a.Nb){var k=Vd(a.g);g=function(a,b){return k(b,a)}}else g=Vd(a.g);O(b.Hb()==a.ma,"");var m=new L(c,d),l=a.Nb?Wd(b,a.g):Xd(b,a.g),t=a.ua.matches(m);if(b.Fa(c)){for(var A=b.T(c),l=e.Ce(a.g,l,a.Nb);null!=l&&(l.name==c||b.Fa(l.name));)l=e.Ce(a.g,l,a.Nb);e=null==l?1:g(l,m);if(t&&!d.e()&&0<=e)return null!=f&&Kd(f,new J("child_changed",d,c,A)),b.W(c,d);null!=f&&Kd(f,new J("child_removed",A,c));b=b.W(c,H);return null!=l&&a.ua.matches(l)?(null!=f&&Kd(f,new J("child_added",
l.U,l.name)),b.W(l.name,l.U)):b}return d.e()?b:t&&0<=g(l,m)?(null!=f&&(Kd(f,new J("child_removed",l.U,l.name)),Kd(f,new J("child_added",d,c))),b.W(c,d).W(l.name,H)):b};function Yd(a,b){this.me=a;this.og=b}function Zd(a){this.X=a}
Zd.prototype.gb=function(a,b,c,d){var e=new Jd,f;if(b.type===Bc)b.source.Ae?c=$d(this,a,b.path,b.Ja,c,d,e):(O(b.source.tf,"Unknown source."),f=b.source.ef||mc(a.w())&&!b.path.e(),c=ae(this,a,b.path,b.Ja,c,d,f,e));else if(b.type===be)b.source.Ae?c=ce(this,a,b.path,b.children,c,d,e):(O(b.source.tf,"Unknown source."),f=b.source.ef||mc(a.w()),c=de(this,a,b.path,b.children,c,d,f,e));else if(b.type===ee)if(b.Yd)if(b=b.path,null!=c.xc(b))c=a;else{f=new Vb(c,a,d);d=a.Q.j();if(b.e()||".priority"===K(b))lc(a.w())?
b=c.Aa(Yb(a)):(b=a.w().j(),O(b instanceof fe,"serverChildren would be complete if leaf node"),b=c.Cc(b)),b=this.X.ya(d,b,e);else{var g=K(b),k=c.Bc(g,a.w());null==k&&Wb(a.w(),g)&&(k=d.T(g));b=null!=k?this.X.H(d,g,k,N(b),f,e):a.Q.j().Fa(g)?this.X.H(d,g,H,N(b),f,e):d;b.e()&&lc(a.w())&&(d=c.Aa(Yb(a)),d.L()&&(b=this.X.ya(b,d,e)))}d=lc(a.w())||null!=c.xc(M);c=ge(a,b,d,this.X.Ra())}else c=he(this,a,b.path,b.Ub,c,d,e);else if(b.type===Dc)d=b.path,b=a.w(),f=b.j(),g=b.ga||d.e(),c=ie(this,new je(a.Q,new Xb(f,
g,b.Yb)),d,c,Ub,e);else throw jd("Unknown operation type: "+b.type);e=qa(e.ib);d=c;b=d.Q;b.ga&&(f=b.j().L()||b.j().e(),g=ke(a),(0<e.length||!a.Q.ga||f&&!b.j().ea(g)||!b.j().C().ea(g.C()))&&e.push(hc(ke(d))));return new Yd(c,e)};
function ie(a,b,c,d,e,f){var g=b.Q;if(null!=d.xc(c))return b;var k;if(c.e())O(lc(b.w()),"If change path is empty, we must have complete server data"),mc(b.w())?(e=Yb(b),d=d.Cc(e instanceof fe?e:H)):d=d.Aa(Yb(b)),f=a.X.ya(b.Q.j(),d,f);else{var m=K(c);if(".priority"==m)O(1==le(c),"Can't have a priority with additional path components"),f=g.j(),k=b.w().j(),d=d.nd(c,f,k),f=null!=d?a.X.ia(f,d):g.j();else{var l=N(c);Wb(g,m)?(k=b.w().j(),d=d.nd(c,g.j(),k),d=null!=d?g.j().T(m).H(l,d):g.j().T(m)):d=d.Bc(m,
b.w());f=null!=d?a.X.H(g.j(),m,d,l,e,f):g.j()}}return ge(b,f,g.ga||c.e(),a.X.Ra())}function ae(a,b,c,d,e,f,g,k){var m=b.w();g=g?a.X:a.X.$b();if(c.e())d=g.ya(m.j(),d,null);else if(g.Ra()&&!m.Yb)d=m.j().H(c,d),d=g.ya(m.j(),d,null);else{var l=K(c);if(!nc(m,c)&&1<le(c))return b;var t=N(c);d=m.j().T(l).H(t,d);d=".priority"==l?g.ia(m.j(),d):g.H(m.j(),l,d,t,Ub,null)}m=m.ga||c.e();b=new je(b.Q,new Xb(d,m,g.Ra()));return ie(a,b,c,e,new Vb(e,b,f),k)}
function $d(a,b,c,d,e,f,g){var k=b.Q;e=new Vb(e,b,f);if(c.e())g=a.X.ya(b.Q.j(),d,g),a=ge(b,g,!0,a.X.Ra());else if(f=K(c),".priority"===f)g=a.X.ia(b.Q.j(),d),a=ge(b,g,k.ga,k.Yb);else{c=N(c);var m=k.j().T(f);if(!c.e()){var l=e.uf(f);d=null!=l?".priority"===me(c)&&l.S(c.parent()).e()?l:l.H(c,d):H}m.ea(d)?a=b:(g=a.X.H(k.j(),f,d,c,e,g),a=ge(b,g,k.ga,a.X.Ra()))}return a}
function ce(a,b,c,d,e,f,g){var k=b;ne(d,function(d,l){var t=c.o(d);Wb(b.Q,K(t))&&(k=$d(a,k,t,l,e,f,g))});ne(d,function(d,l){var t=c.o(d);Wb(b.Q,K(t))||(k=$d(a,k,t,l,e,f,g))});return k}function oe(a,b){ne(b,function(b,d){a=a.H(b,d)});return a}
function de(a,b,c,d,e,f,g,k){if(b.w().j().e()&&!lc(b.w()))return b;var m=b;c=c.e()?d:pe(qe,c,d);var l=b.w().j();c.children.ka(function(c,d){if(l.Fa(c)){var I=b.w().j().T(c),I=oe(I,d);m=ae(a,m,new P(c),I,e,f,g,k)}});c.children.ka(function(c,d){var I=!Wb(b.w(),c)&&null==d.value;l.Fa(c)||I||(I=b.w().j().T(c),I=oe(I,d),m=ae(a,m,new P(c),I,e,f,g,k))});return m}
function he(a,b,c,d,e,f,g){if(null!=e.xc(c))return b;var k=mc(b.w()),m=b.w();if(null!=d.value){if(c.e()&&m.ga||nc(m,c))return ae(a,b,c,m.j().S(c),e,f,k,g);if(c.e()){var l=qe;m.j().R(re,function(a,b){l=l.set(new P(a),b)});return de(a,b,c,l,e,f,k,g)}return b}l=qe;ne(d,function(a){var b=c.o(a);nc(m,b)&&(l=l.set(a,m.j().S(b)))});return de(a,b,c,l,e,f,k,g)};function se(){}var te={};function Vd(a){return u(a.compare,a)}se.prototype.Dd=function(a,b){return 0!==this.compare(new L("[MIN_NAME]",a),new L("[MIN_NAME]",b))};se.prototype.Wc=function(){return ue};function ve(a){O(!a.e()&&".priority"!==K(a),"Can't create PathIndex with empty path or .priority key");this.gc=a}ka(ve,se);h=ve.prototype;h.Lc=function(a){return!a.S(this.gc).e()};h.compare=function(a,b){var c=a.U.S(this.gc),d=b.U.S(this.gc),c=c.Gc(d);return 0===c?yc(a.name,b.name):c};
h.Sc=function(a,b){var c=Q(a),c=H.H(this.gc,c);return new L(b,c)};h.Tc=function(){var a=H.H(this.gc,we);return new L("[MAX_NAME]",a)};h.toString=function(){return this.gc.slice().join("/")};function xe(){}ka(xe,se);h=xe.prototype;h.compare=function(a,b){var c=a.U.C(),d=b.U.C(),c=c.Gc(d);return 0===c?yc(a.name,b.name):c};h.Lc=function(a){return!a.C().e()};h.Dd=function(a,b){return!a.C().ea(b.C())};h.Wc=function(){return ue};h.Tc=function(){return new L("[MAX_NAME]",new Yc("[PRIORITY-POST]",we))};
h.Sc=function(a,b){var c=Q(a);return new L(b,new Yc("[PRIORITY-POST]",c))};h.toString=function(){return".priority"};var R=new xe;function ye(){}ka(ye,se);h=ye.prototype;h.compare=function(a,b){return yc(a.name,b.name)};h.Lc=function(){throw jd("KeyIndex.isDefinedOn not expected to be called.");};h.Dd=function(){return!1};h.Wc=function(){return ue};h.Tc=function(){return new L("[MAX_NAME]",H)};h.Sc=function(a){O(q(a),"KeyIndex indexValue must always be a string.");return new L(a,H)};h.toString=function(){return".key"};
var re=new ye;function ze(){}ka(ze,se);h=ze.prototype;h.compare=function(a,b){var c=a.U.Gc(b.U);return 0===c?yc(a.name,b.name):c};h.Lc=function(){return!0};h.Dd=function(a,b){return!a.ea(b)};h.Wc=function(){return ue};h.Tc=function(){return Ae};h.Sc=function(a,b){var c=Q(a);return new L(b,c)};h.toString=function(){return".value"};var Be=new ze;function Ce(){this.Xb=this.ra=this.Pb=this.oa=this.la=!1;this.ma=0;this.Rb="";this.ic=null;this.Bb="";this.fc=null;this.zb="";this.g=R}var De=new Ce;function Td(a){return""===a.Rb?a.oa:"l"===a.Rb}function Od(a){O(a.oa,"Only valid if start has been set");return a.ic}function Nd(a){O(a.oa,"Only valid if start has been set");return a.Pb?a.Bb:"[MIN_NAME]"}function Rd(a){O(a.ra,"Only valid if end has been set");return a.fc}
function Pd(a){O(a.ra,"Only valid if end has been set");return a.Xb?a.zb:"[MAX_NAME]"}function Ee(a){var b=new Ce;b.la=a.la;b.ma=a.ma;b.oa=a.oa;b.ic=a.ic;b.Pb=a.Pb;b.Bb=a.Bb;b.ra=a.ra;b.fc=a.fc;b.Xb=a.Xb;b.zb=a.zb;b.g=a.g;return b}h=Ce.prototype;h.Le=function(a){var b=Ee(this);b.la=!0;b.ma=a;b.Rb="";return b};h.Me=function(a){var b=Ee(this);b.la=!0;b.ma=a;b.Rb="l";return b};h.Ne=function(a){var b=Ee(this);b.la=!0;b.ma=a;b.Rb="r";return b};
h.ce=function(a,b){var c=Ee(this);c.oa=!0;p(a)||(a=null);c.ic=a;null!=b?(c.Pb=!0,c.Bb=b):(c.Pb=!1,c.Bb="");return c};h.vd=function(a,b){var c=Ee(this);c.ra=!0;p(a)||(a=null);c.fc=a;p(b)?(c.Xb=!0,c.zb=b):(c.oh=!1,c.zb="");return c};function Fe(a,b){var c=Ee(a);c.g=b;return c}function Ge(a){var b={};a.oa&&(b.sp=a.ic,a.Pb&&(b.sn=a.Bb));a.ra&&(b.ep=a.fc,a.Xb&&(b.en=a.zb));if(a.la){b.l=a.ma;var c=a.Rb;""===c&&(c=Td(a)?"l":"r");b.vf=c}a.g!==R&&(b.i=a.g.toString());return b}
function He(a){return!(a.oa||a.ra||a.la)}function Ie(a){return He(a)&&a.g==R}function Je(a){var b={};if(Ie(a))return b;var c;a.g===R?c="$priority":a.g===Be?c="$value":a.g===re?c="$key":(O(a.g instanceof ve,"Unrecognized index type!"),c=a.g.toString());b.orderBy=G(c);a.oa&&(b.startAt=G(a.ic),a.Pb&&(b.startAt+=","+G(a.Bb)));a.ra&&(b.endAt=G(a.fc),a.Xb&&(b.endAt+=","+G(a.zb)));a.la&&(Td(a)?b.limitToFirst=a.ma:b.limitToLast=a.ma);return b}h.toString=function(){return G(Ge(this))};function Ke(a,b){this.Ed=a;this.hc=b}Ke.prototype.get=function(a){var b=z(this.Ed,a);if(!b)throw Error("No index defined for "+a);return b===te?null:b};function Le(a,b,c){var d=ma(a.Ed,function(d,f){var g=z(a.hc,f);O(g,"Missing index implementation for "+f);if(d===te){if(g.Lc(b.U)){for(var k=[],m=c.ac(wc),l=Ic(m);l;)l.name!=b.name&&k.push(l),l=Ic(m);k.push(b);return Me(k,Vd(g))}return te}g=c.get(b.name);k=d;g&&(k=k.remove(new L(b.name,g)));return k.Sa(b,b.U)});return new Ke(d,a.hc)}
function Ne(a,b,c){var d=ma(a.Ed,function(a){if(a===te)return a;var d=c.get(b.name);return d?a.remove(new L(b.name,d)):a});return new Ke(d,a.hc)}var Oe=new Ke({".priority":te},{".priority":R});function Yc(a,b){this.B=a;O(p(this.B)&&null!==this.B,"LeafNode shouldn't be created with null/undefined value.");this.ca=b||H;Pe(this.ca);this.Gb=null}var Qe=["object","boolean","number","string"];h=Yc.prototype;h.L=function(){return!0};h.C=function(){return this.ca};h.ia=function(a){return new Yc(this.B,a)};h.T=function(a){return".priority"===a?this.ca:H};h.S=function(a){return a.e()?this:".priority"===K(a)?this.ca:H};h.Fa=function(){return!1};h.wf=function(){return null};
h.W=function(a,b){return".priority"===a?this.ia(b):b.e()&&".priority"!==a?this:H.W(a,b).ia(this.ca)};h.H=function(a,b){var c=K(a);if(null===c)return b;if(b.e()&&".priority"!==c)return this;O(".priority"!==c||1===le(a),".priority must be the last token in a path");return this.W(c,H.H(N(a),b))};h.e=function(){return!1};h.Hb=function(){return 0};h.R=function(){return!1};h.J=function(a){return a&&!this.C().e()?{".value":this.Ea(),".priority":this.C().J()}:this.Ea()};
h.hash=function(){if(null===this.Gb){var a="";this.ca.e()||(a+="priority:"+Re(this.ca.J())+":");var b=typeof this.B,a=a+(b+":"),a="number"===b?a+Ad(this.B):a+this.B;this.Gb=ld(a)}return this.Gb};h.Ea=function(){return this.B};h.Gc=function(a){if(a===H)return 1;if(a instanceof fe)return-1;O(a.L(),"Unknown node type");var b=typeof a.B,c=typeof this.B,d=La(Qe,b),e=La(Qe,c);O(0<=d,"Unknown leaf type: "+b);O(0<=e,"Unknown leaf type: "+c);return d===e?"object"===c?0:this.B<a.B?-1:this.B===a.B?0:1:e-d};
h.pb=function(){return this};h.Mc=function(){return!0};h.ea=function(a){return a===this?!0:a.L()?this.B===a.B&&this.ca.ea(a.ca):!1};h.toString=function(){return G(this.J(!0))};function fe(a,b,c){this.m=a;(this.ca=b)&&Pe(this.ca);a.e()&&O(!this.ca||this.ca.e(),"An empty node cannot have a priority");this.Ab=c;this.Gb=null}h=fe.prototype;h.L=function(){return!1};h.C=function(){return this.ca||H};h.ia=function(a){return this.m.e()?this:new fe(this.m,a,this.Ab)};h.T=function(a){if(".priority"===a)return this.C();a=this.m.get(a);return null===a?H:a};h.S=function(a){var b=K(a);return null===b?this:this.T(b).S(N(a))};h.Fa=function(a){return null!==this.m.get(a)};
h.W=function(a,b){O(b,"We should always be passing snapshot nodes");if(".priority"===a)return this.ia(b);var c=new L(a,b),d,e;b.e()?(d=this.m.remove(a),c=Ne(this.Ab,c,this.m)):(d=this.m.Sa(a,b),c=Le(this.Ab,c,this.m));e=d.e()?H:this.ca;return new fe(d,e,c)};h.H=function(a,b){var c=K(a);if(null===c)return b;O(".priority"!==K(a)||1===le(a),".priority must be the last token in a path");var d=this.T(c).H(N(a),b);return this.W(c,d)};h.e=function(){return this.m.e()};h.Hb=function(){return this.m.count()};
var Se=/^(0|[1-9]\d*)$/;h=fe.prototype;h.J=function(a){if(this.e())return null;var b={},c=0,d=0,e=!0;this.R(R,function(f,g){b[f]=g.J(a);c++;e&&Se.test(f)?d=Math.max(d,Number(f)):e=!1});if(!a&&e&&d<2*c){var f=[],g;for(g in b)f[g]=b[g];return f}a&&!this.C().e()&&(b[".priority"]=this.C().J());return b};h.hash=function(){if(null===this.Gb){var a="";this.C().e()||(a+="priority:"+Re(this.C().J())+":");this.R(R,function(b,c){var d=c.hash();""!==d&&(a+=":"+b+":"+d)});this.Gb=""===a?"":ld(a)}return this.Gb};
h.wf=function(a,b,c){return(c=Te(this,c))?(a=Gc(c,new L(a,b)))?a.name:null:Gc(this.m,a)};function Wd(a,b){var c;c=(c=Te(a,b))?(c=c.Vc())&&c.name:a.m.Vc();return c?new L(c,a.m.get(c)):null}function Xd(a,b){var c;c=(c=Te(a,b))?(c=c.jc())&&c.name:a.m.jc();return c?new L(c,a.m.get(c)):null}h.R=function(a,b){var c=Te(this,a);return c?c.ka(function(a){return b(a.name,a.U)}):this.m.ka(b)};h.ac=function(a){return this.bc(a.Wc(),a)};
h.bc=function(a,b){var c=Te(this,b);if(c)return c.bc(a,function(a){return a});for(var c=this.m.bc(a.name,wc),d=Jc(c);null!=d&&0>b.compare(d,a);)Ic(c),d=Jc(c);return c};h.xf=function(a){return this.dc(a.Tc(),a)};h.dc=function(a,b){var c=Te(this,b);if(c)return c.dc(a,function(a){return a});for(var c=this.m.dc(a.name,wc),d=Jc(c);null!=d&&0<b.compare(d,a);)Ic(c),d=Jc(c);return c};h.Gc=function(a){return this.e()?a.e()?0:-1:a.L()||a.e()?1:a===we?-1:0};
h.pb=function(a){if(a===re||sa(this.Ab.hc,a.toString()))return this;var b=this.Ab,c=this.m;O(a!==re,"KeyIndex always exists and isn't meant to be added to the IndexMap.");for(var d=[],e=!1,c=c.ac(wc),f=Ic(c);f;)e=e||a.Lc(f.U),d.push(f),f=Ic(c);d=e?Me(d,Vd(a)):te;e=a.toString();c=wa(b.hc);c[e]=a;a=wa(b.Ed);a[e]=d;return new fe(this.m,this.ca,new Ke(a,c))};h.Mc=function(a){return a===re||sa(this.Ab.hc,a.toString())};
h.ea=function(a){if(a===this)return!0;if(a.L())return!1;if(this.C().ea(a.C())&&this.m.count()===a.m.count()){var b=this.ac(R);a=a.ac(R);for(var c=Ic(b),d=Ic(a);c&&d;){if(c.name!==d.name||!c.U.ea(d.U))return!1;c=Ic(b);d=Ic(a)}return null===c&&null===d}return!1};function Te(a,b){return b===re?null:a.Ab.get(b.toString())}h.toString=function(){return G(this.J(!0))};function Q(a,b){if(null===a)return H;var c=null;"object"===typeof a&&".priority"in a?c=a[".priority"]:"undefined"!==typeof b&&(c=b);O(null===c||"string"===typeof c||"number"===typeof c||"object"===typeof c&&".sv"in c,"Invalid priority type found: "+typeof c);"object"===typeof a&&".value"in a&&null!==a[".value"]&&(a=a[".value"]);if("object"!==typeof a||".sv"in a)return new Yc(a,Q(c));if(a instanceof Array){var d=H,e=a;v(e,function(a,b){if(y(e,b)&&"."!==b.substring(0,1)){var c=Q(a);if(c.L()||!c.e())d=
d.W(b,c)}});return d.ia(Q(c))}var f=[],g=!1,k=a;Fb(k,function(a){if("string"!==typeof a||"."!==a.substring(0,1)){var b=Q(k[a]);b.e()||(g=g||!b.C().e(),f.push(new L(a,b)))}});if(0==f.length)return H;var m=Me(f,xc,function(a){return a.name},zc);if(g){var l=Me(f,Vd(R));return new fe(m,Q(c),new Ke({".priority":l},{".priority":R}))}return new fe(m,Q(c),Oe)}var Ue=Math.log(2);
function Ve(a){this.count=parseInt(Math.log(a+1)/Ue,10);this.nf=this.count-1;this.ng=a+1&parseInt(Array(this.count+1).join("1"),2)}function We(a){var b=!(a.ng&1<<a.nf);a.nf--;return b}
function Me(a,b,c,d){function e(b,d){var f=d-b;if(0==f)return null;if(1==f){var l=a[b],t=c?c(l):l;return new Kc(t,l.U,!1,null,null)}var l=parseInt(f/2,10)+b,f=e(b,l),A=e(l+1,d),l=a[l],t=c?c(l):l;return new Kc(t,l.U,!1,f,A)}a.sort(b);var f=function(b){function d(b,g){var k=t-b,A=t;t-=b;var A=e(k+1,A),k=a[k],I=c?c(k):k,A=new Kc(I,k.U,g,null,A);f?f.left=A:l=A;f=A}for(var f=null,l=null,t=a.length,A=0;A<b.count;++A){var I=We(b),Qd=Math.pow(2,b.count-(A+1));I?d(Qd,!1):(d(Qd,!1),d(Qd,!0))}return l}(new Ve(a.length));
return null!==f?new Ec(d||b,f):new Ec(d||b)}function Re(a){return"number"===typeof a?"number:"+Ad(a):"string:"+a}function Pe(a){if(a.L()){var b=a.J();O("string"===typeof b||"number"===typeof b||"object"===typeof b&&y(b,".sv"),"Priority must be a string or number.")}else O(a===we||a.e(),"priority of unexpected type.");O(a===we||a.C().e(),"Priority nodes can't have a priority of their own.")}var H=new fe(new Ec(zc),null,Oe);function Xe(){fe.call(this,new Ec(zc),H,Oe)}ka(Xe,fe);h=Xe.prototype;
h.Gc=function(a){return a===this?0:1};h.ea=function(a){return a===this};h.C=function(){return this};h.T=function(){return H};h.e=function(){return!1};var we=new Xe,ue=new L("[MIN_NAME]",H),Ae=new L("[MAX_NAME]",we);function je(a,b){this.Q=a;this.ae=b}function ge(a,b,c,d){return new je(new Xb(b,c,d),a.ae)}function ke(a){return a.Q.ga?a.Q.j():null}je.prototype.w=function(){return this.ae};function Yb(a){return a.ae.ga?a.ae.j():null};function Ye(a,b){this.Y=a;var c=a.n,d=new Ld(c.g),c=He(c)?new Ld(c.g):c.la?new Sd(c):new Md(c);this.Nf=new Zd(c);var e=b.w(),f=b.Q,g=d.ya(H,e.j(),null),k=c.ya(H,f.j(),null);this.Oa=new je(new Xb(k,f.ga,c.Ra()),new Xb(g,e.ga,d.Ra()));this.$a=[];this.ug=new Fd(a)}function Ze(a){return a.Y}h=Ye.prototype;h.w=function(){return this.Oa.w().j()};h.kb=function(a){var b=Yb(this.Oa);return b&&(He(this.Y.n)||!a.e()&&!b.T(K(a)).e())?b.S(a):null};h.e=function(){return 0===this.$a.length};h.Tb=function(a){this.$a.push(a)};
h.nb=function(a,b){var c=[];if(b){O(null==a,"A cancel should cancel all event registrations.");var d=this.Y.path;Ma(this.$a,function(a){(a=a.lf(b,d))&&c.push(a)})}if(a){for(var e=[],f=0;f<this.$a.length;++f){var g=this.$a[f];if(!g.matches(a))e.push(g);else if(a.yf()){e=e.concat(this.$a.slice(f+1));break}}this.$a=e}else this.$a=[];return c};
h.gb=function(a,b,c){a.type===be&&null!==a.source.Lb&&(O(Yb(this.Oa),"We should always have a full cache before handling merges"),O(ke(this.Oa),"Missing event cache, even though we have a server cache"));var d=this.Oa;a=this.Nf.gb(d,a,b,c);b=this.Nf;c=a.me;O(c.Q.j().Mc(b.X.g),"Event snap not indexed");O(c.w().j().Mc(b.X.g),"Server snap not indexed");O(lc(a.me.w())||!lc(d.w()),"Once a server snap is complete, it should never go back");this.Oa=a.me;return $e(this,a.og,a.me.Q.j(),null)};
function af(a,b){var c=a.Oa.Q,d=[];c.j().L()||c.j().R(R,function(a,b){d.push(new J("child_added",b,a))});c.ga&&d.push(hc(c.j()));return $e(a,d,c.j(),b)}function $e(a,b,c,d){return Gd(a.ug,b,c,d?[d]:a.$a)};function bf(a,b,c){this.type=be;this.source=a;this.path=b;this.children=c}bf.prototype.$c=function(a){if(this.path.e())return a=this.children.subtree(new P(a)),a.e()?null:a.value?new Ac(this.source,M,a.value):new bf(this.source,M,a);O(K(this.path)===a,"Can't get a merge for a child not on the path of the operation");return new bf(this.source,N(this.path),this.children)};bf.prototype.toString=function(){return"Operation("+this.path+": "+this.source.toString()+" merge: "+this.children.toString()+")"};function cf(a,b){this.f=pd("p:rest:");this.G=a;this.Kb=b;this.Ca=null;this.ba={}}function df(a,b){if(p(b))return"tag$"+b;O(Ie(a.n),"should have a tag if it's not a default query.");return a.path.toString()}h=cf.prototype;
h.Cf=function(a,b,c,d){var e=a.path.toString();this.f("Listen called for "+e+" "+a.wa());var f=df(a,c),g={};this.ba[f]=g;a=Je(a.n);var k=this;ef(this,e+".json",a,function(a,b){var t=b;404===a&&(a=t=null);null===a&&k.Kb(e,t,!1,c);z(k.ba,f)===g&&d(a?401==a?"permission_denied":"rest_error:"+a:"ok",null)})};h.$f=function(a,b){var c=df(a,b);delete this.ba[c]};h.O=function(a,b){this.Ca=a;var c=Cd(a),d=c.data,c=c.Ec&&c.Ec.exp;b&&b("ok",{auth:d,expires:c})};h.je=function(a){this.Ca=null;a("ok",null)};
h.Qe=function(){};h.Gf=function(){};h.Md=function(){};h.put=function(){};h.Df=function(){};h.Ye=function(){};
function ef(a,b,c,d){c=c||{};c.format="export";a.Ca&&(c.auth=a.Ca);var e=(a.G.ob?"https://":"http://")+a.G.host+b+"?"+Ib(c);a.f("Sending REST request for "+e);var f=new XMLHttpRequest;f.onreadystatechange=function(){if(d&&4===f.readyState){a.f("REST Response for "+e+" received. status:",f.status,"response:",f.responseText);var b=null;if(200<=f.status&&300>f.status){try{b=Rb(f.responseText)}catch(c){S("Failed to parse JSON response for "+e+": "+f.responseText)}d(null,b)}else 401!==f.status&&404!==
f.status&&S("Got unsuccessful REST response for "+e+" Status: "+f.status),d(f.status);d=null}};f.open("GET",e,!0);f.send()};function ff(a){O(da(a)&&0<a.length,"Requires a non-empty array");this.fg=a;this.Rc={}}ff.prototype.ie=function(a,b){var c;c=this.Rc[a]||[];var d=c.length;if(0<d){for(var e=Array(d),f=0;f<d;f++)e[f]=c[f];c=e}else c=[];for(d=0;d<c.length;d++)c[d].Dc.apply(c[d].Qa,Array.prototype.slice.call(arguments,1))};ff.prototype.Ib=function(a,b,c){gf(this,a);this.Rc[a]=this.Rc[a]||[];this.Rc[a].push({Dc:b,Qa:c});(a=this.Ee(a))&&b.apply(c,a)};
ff.prototype.mc=function(a,b,c){gf(this,a);a=this.Rc[a]||[];for(var d=0;d<a.length;d++)if(a[d].Dc===b&&(!c||c===a[d].Qa)){a.splice(d,1);break}};function gf(a,b){O(Ra(a.fg,function(a){return a===b}),"Unknown event: "+b)};var hf=function(){var a=0,b=[];return function(c){var d=c===a;a=c;for(var e=Array(8),f=7;0<=f;f--)e[f]="-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz".charAt(c%64),c=Math.floor(c/64);O(0===c,"Cannot push at time == 0");c=e.join("");if(d){for(f=11;0<=f&&63===b[f];f--)b[f]=0;b[f]++}else for(f=0;12>f;f++)b[f]=Math.floor(64*Math.random());for(f=0;12>f;f++)c+="-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz".charAt(b[f]);O(20===c.length,"nextPushId: Length should be 20.");
return c}}();function jf(){ff.call(this,["online"]);this.oc=!0;if("undefined"!==typeof window&&"undefined"!==typeof window.addEventListener){var a=this;window.addEventListener("online",function(){a.oc||(a.oc=!0,a.ie("online",!0))},!1);window.addEventListener("offline",function(){a.oc&&(a.oc=!1,a.ie("online",!1))},!1)}}ka(jf,ff);jf.prototype.Ee=function(a){O("online"===a,"Unknown event type: "+a);return[this.oc]};ba(jf);function kf(){ff.call(this,["visible"]);var a,b;"undefined"!==typeof document&&"undefined"!==typeof document.addEventListener&&("undefined"!==typeof document.hidden?(b="visibilitychange",a="hidden"):"undefined"!==typeof document.mozHidden?(b="mozvisibilitychange",a="mozHidden"):"undefined"!==typeof document.msHidden?(b="msvisibilitychange",a="msHidden"):"undefined"!==typeof document.webkitHidden&&(b="webkitvisibilitychange",a="webkitHidden"));this.Sb=!0;if(b){var c=this;document.addEventListener(b,
function(){var b=!document[a];b!==c.Sb&&(c.Sb=b,c.ie("visible",b))},!1)}}ka(kf,ff);kf.prototype.Ee=function(a){O("visible"===a,"Unknown event type: "+a);return[this.Sb]};ba(kf);function P(a,b){if(1==arguments.length){this.u=a.split("/");for(var c=0,d=0;d<this.u.length;d++)0<this.u[d].length&&(this.u[c]=this.u[d],c++);this.u.length=c;this.aa=0}else this.u=a,this.aa=b}function lf(a,b){var c=K(a);if(null===c)return b;if(c===K(b))return lf(N(a),N(b));throw Error("INTERNAL ERROR: innerPath ("+b+") is not within outerPath ("+a+")");}
function mf(a,b){for(var c=a.slice(),d=b.slice(),e=0;e<c.length&&e<d.length;e++){var f=yc(c[e],d[e]);if(0!==f)return f}return c.length===d.length?0:c.length<d.length?-1:1}function K(a){return a.aa>=a.u.length?null:a.u[a.aa]}function le(a){return a.u.length-a.aa}function N(a){var b=a.aa;b<a.u.length&&b++;return new P(a.u,b)}function me(a){return a.aa<a.u.length?a.u[a.u.length-1]:null}h=P.prototype;
h.toString=function(){for(var a="",b=this.aa;b<this.u.length;b++)""!==this.u[b]&&(a+="/"+this.u[b]);return a||"/"};h.slice=function(a){return this.u.slice(this.aa+(a||0))};h.parent=function(){if(this.aa>=this.u.length)return null;for(var a=[],b=this.aa;b<this.u.length-1;b++)a.push(this.u[b]);return new P(a,0)};
h.o=function(a){for(var b=[],c=this.aa;c<this.u.length;c++)b.push(this.u[c]);if(a instanceof P)for(c=a.aa;c<a.u.length;c++)b.push(a.u[c]);else for(a=a.split("/"),c=0;c<a.length;c++)0<a[c].length&&b.push(a[c]);return new P(b,0)};h.e=function(){return this.aa>=this.u.length};h.ea=function(a){if(le(this)!==le(a))return!1;for(var b=this.aa,c=a.aa;b<=this.u.length;b++,c++)if(this.u[b]!==a.u[c])return!1;return!0};
h.contains=function(a){var b=this.aa,c=a.aa;if(le(this)>le(a))return!1;for(;b<this.u.length;){if(this.u[b]!==a.u[c])return!1;++b;++c}return!0};var M=new P("");function nf(a,b){this.Ua=a.slice();this.Ka=Math.max(1,this.Ua.length);this.pf=b;for(var c=0;c<this.Ua.length;c++)this.Ka+=Pb(this.Ua[c]);of(this)}nf.prototype.push=function(a){0<this.Ua.length&&(this.Ka+=1);this.Ua.push(a);this.Ka+=Pb(a);of(this)};nf.prototype.pop=function(){var a=this.Ua.pop();this.Ka-=Pb(a);0<this.Ua.length&&--this.Ka};
function of(a){if(768<a.Ka)throw Error(a.pf+"has a key path longer than 768 bytes ("+a.Ka+").");if(32<a.Ua.length)throw Error(a.pf+"path specified exceeds the maximum depth that can be written (32) or object contains a cycle "+pf(a));}function pf(a){return 0==a.Ua.length?"":"in property '"+a.Ua.join(".")+"'"};function qf(a,b){this.value=a;this.children=b||rf}var rf=new Ec(function(a,b){return a===b?0:a<b?-1:1});function sf(a){var b=qe;v(a,function(a,d){b=b.set(new P(d),a)});return b}h=qf.prototype;h.e=function(){return null===this.value&&this.children.e()};function tf(a,b,c){if(null!=a.value&&c(a.value))return{path:M,value:a.value};if(b.e())return null;var d=K(b);a=a.children.get(d);return null!==a?(b=tf(a,N(b),c),null!=b?{path:(new P(d)).o(b.path),value:b.value}:null):null}
function uf(a,b){return tf(a,b,function(){return!0})}h.subtree=function(a){if(a.e())return this;var b=this.children.get(K(a));return null!==b?b.subtree(N(a)):qe};h.set=function(a,b){if(a.e())return new qf(b,this.children);var c=K(a),d=(this.children.get(c)||qe).set(N(a),b),c=this.children.Sa(c,d);return new qf(this.value,c)};
h.remove=function(a){if(a.e())return this.children.e()?qe:new qf(null,this.children);var b=K(a),c=this.children.get(b);return c?(a=c.remove(N(a)),b=a.e()?this.children.remove(b):this.children.Sa(b,a),null===this.value&&b.e()?qe:new qf(this.value,b)):this};h.get=function(a){if(a.e())return this.value;var b=this.children.get(K(a));return b?b.get(N(a)):null};
function pe(a,b,c){if(b.e())return c;var d=K(b);b=pe(a.children.get(d)||qe,N(b),c);d=b.e()?a.children.remove(d):a.children.Sa(d,b);return new qf(a.value,d)}function vf(a,b){return wf(a,M,b)}function wf(a,b,c){var d={};a.children.ka(function(a,f){d[a]=wf(f,b.o(a),c)});return c(b,a.value,d)}function xf(a,b,c){return yf(a,b,M,c)}function yf(a,b,c,d){var e=a.value?d(c,a.value):!1;if(e)return e;if(b.e())return null;e=K(b);return(a=a.children.get(e))?yf(a,N(b),c.o(e),d):null}
function zf(a,b,c){Af(a,b,M,c)}function Af(a,b,c,d){if(b.e())return a;a.value&&d(c,a.value);var e=K(b);return(a=a.children.get(e))?Af(a,N(b),c.o(e),d):qe}function ne(a,b){Bf(a,M,b)}function Bf(a,b,c){a.children.ka(function(a,e){Bf(e,b.o(a),c)});a.value&&c(b,a.value)}function Cf(a,b){a.children.ka(function(a,d){d.value&&b(a,d.value)})}var qe=new qf(null);qf.prototype.toString=function(){var a={};ne(this,function(b,c){a[b.toString()]=c.toString()});return G(a)};function Df(a,b,c){this.type=ee;this.source=Ef;this.path=a;this.Ub=b;this.Yd=c}Df.prototype.$c=function(a){if(this.path.e()){if(null!=this.Ub.value)return O(this.Ub.children.e(),"affectedTree should not have overlapping affected paths."),this;a=this.Ub.subtree(new P(a));return new Df(M,a,this.Yd)}O(K(this.path)===a,"operationForChild called for unrelated child.");return new Df(N(this.path),this.Ub,this.Yd)};
Df.prototype.toString=function(){return"Operation("+this.path+": "+this.source.toString()+" ack write revert="+this.Yd+" affectedTree="+this.Ub+")"};var Bc=0,be=1,ee=2,Dc=3;function Ff(a,b,c,d){this.Ae=a;this.tf=b;this.Lb=c;this.ef=d;O(!d||b,"Tagged queries must be from server.")}var Ef=new Ff(!0,!1,null,!1),Gf=new Ff(!1,!0,null,!1);Ff.prototype.toString=function(){return this.Ae?"user":this.ef?"server(queryID="+this.Lb+")":"server"};function Hf(a){this.Z=a}var If=new Hf(new qf(null));function Jf(a,b,c){if(b.e())return new Hf(new qf(c));var d=uf(a.Z,b);if(null!=d){var e=d.path,d=d.value;b=lf(e,b);d=d.H(b,c);return new Hf(a.Z.set(e,d))}a=pe(a.Z,b,new qf(c));return new Hf(a)}function Kf(a,b,c){var d=a;Fb(c,function(a,c){d=Jf(d,b.o(a),c)});return d}Hf.prototype.Ud=function(a){if(a.e())return If;a=pe(this.Z,a,qe);return new Hf(a)};function Lf(a,b){var c=uf(a.Z,b);return null!=c?a.Z.get(c.path).S(lf(c.path,b)):null}
function Mf(a){var b=[],c=a.Z.value;null!=c?c.L()||c.R(R,function(a,c){b.push(new L(a,c))}):a.Z.children.ka(function(a,c){null!=c.value&&b.push(new L(a,c.value))});return b}function Nf(a,b){if(b.e())return a;var c=Lf(a,b);return null!=c?new Hf(new qf(c)):new Hf(a.Z.subtree(b))}Hf.prototype.e=function(){return this.Z.e()};Hf.prototype.apply=function(a){return Of(M,this.Z,a)};
function Of(a,b,c){if(null!=b.value)return c.H(a,b.value);var d=null;b.children.ka(function(b,f){".priority"===b?(O(null!==f.value,"Priority writes must always be leaf nodes"),d=f.value):c=Of(a.o(b),f,c)});c.S(a).e()||null===d||(c=c.H(a.o(".priority"),d));return c};function Pf(){this.V=If;this.pa=[];this.Pc=-1}function Qf(a,b){for(var c=0;c<a.pa.length;c++){var d=a.pa[c];if(d.md===b)return d}return null}h=Pf.prototype;
h.Ud=function(a){var b=Sa(this.pa,function(b){return b.md===a});O(0<=b,"removeWrite called with nonexistent writeId.");var c=this.pa[b];this.pa.splice(b,1);for(var d=c.visible,e=!1,f=this.pa.length-1;d&&0<=f;){var g=this.pa[f];g.visible&&(f>=b&&Rf(g,c.path)?d=!1:c.path.contains(g.path)&&(e=!0));f--}if(d){if(e)this.V=Sf(this.pa,Tf,M),this.Pc=0<this.pa.length?this.pa[this.pa.length-1].md:-1;else if(c.Ja)this.V=this.V.Ud(c.path);else{var k=this;v(c.children,function(a,b){k.V=k.V.Ud(c.path.o(b))})}return!0}return!1};
h.Aa=function(a,b,c,d){if(c||d){var e=Nf(this.V,a);return!d&&e.e()?b:d||null!=b||null!=Lf(e,M)?(e=Sf(this.pa,function(b){return(b.visible||d)&&(!c||!(0<=La(c,b.md)))&&(b.path.contains(a)||a.contains(b.path))},a),b=b||H,e.apply(b)):null}e=Lf(this.V,a);if(null!=e)return e;e=Nf(this.V,a);return e.e()?b:null!=b||null!=Lf(e,M)?(b=b||H,e.apply(b)):null};
h.Cc=function(a,b){var c=H,d=Lf(this.V,a);if(d)d.L()||d.R(R,function(a,b){c=c.W(a,b)});else if(b){var e=Nf(this.V,a);b.R(R,function(a,b){var d=Nf(e,new P(a)).apply(b);c=c.W(a,d)});Ma(Mf(e),function(a){c=c.W(a.name,a.U)})}else e=Nf(this.V,a),Ma(Mf(e),function(a){c=c.W(a.name,a.U)});return c};h.nd=function(a,b,c,d){O(c||d,"Either existingEventSnap or existingServerSnap must exist");a=a.o(b);if(null!=Lf(this.V,a))return null;a=Nf(this.V,a);return a.e()?d.S(b):a.apply(d.S(b))};
h.Bc=function(a,b,c){a=a.o(b);var d=Lf(this.V,a);return null!=d?d:Wb(c,b)?Nf(this.V,a).apply(c.j().T(b)):null};h.xc=function(a){return Lf(this.V,a)};h.qe=function(a,b,c,d,e,f){var g;a=Nf(this.V,a);g=Lf(a,M);if(null==g)if(null!=b)g=a.apply(b);else return[];g=g.pb(f);if(g.e()||g.L())return[];b=[];a=Vd(f);e=e?g.dc(c,f):g.bc(c,f);for(f=Ic(e);f&&b.length<d;)0!==a(f,c)&&b.push(f),f=Ic(e);return b};
function Rf(a,b){return a.Ja?a.path.contains(b):!!ta(a.children,function(c,d){return a.path.o(d).contains(b)})}function Tf(a){return a.visible}
function Sf(a,b,c){for(var d=If,e=0;e<a.length;++e){var f=a[e];if(b(f)){var g=f.path;if(f.Ja)c.contains(g)?(g=lf(c,g),d=Jf(d,g,f.Ja)):g.contains(c)&&(g=lf(g,c),d=Jf(d,M,f.Ja.S(g)));else if(f.children)if(c.contains(g))g=lf(c,g),d=Kf(d,g,f.children);else{if(g.contains(c))if(g=lf(g,c),g.e())d=Kf(d,M,f.children);else if(f=z(f.children,K(g)))f=f.S(N(g)),d=Jf(d,M,f)}else throw jd("WriteRecord should have .snap or .children");}}return d}function Uf(a,b){this.Qb=a;this.Z=b}h=Uf.prototype;
h.Aa=function(a,b,c){return this.Z.Aa(this.Qb,a,b,c)};h.Cc=function(a){return this.Z.Cc(this.Qb,a)};h.nd=function(a,b,c){return this.Z.nd(this.Qb,a,b,c)};h.xc=function(a){return this.Z.xc(this.Qb.o(a))};h.qe=function(a,b,c,d,e){return this.Z.qe(this.Qb,a,b,c,d,e)};h.Bc=function(a,b){return this.Z.Bc(this.Qb,a,b)};h.o=function(a){return new Uf(this.Qb.o(a),this.Z)};function Vf(){this.children={};this.pd=0;this.value=null}function Wf(a,b,c){this.Jd=a?a:"";this.Ha=b?b:null;this.A=c?c:new Vf}function Xf(a,b){for(var c=b instanceof P?b:new P(b),d=a,e;null!==(e=K(c));)d=new Wf(e,d,z(d.A.children,e)||new Vf),c=N(c);return d}h=Wf.prototype;h.Ea=function(){return this.A.value};function Yf(a,b){O("undefined"!==typeof b,"Cannot set value to undefined");a.A.value=b;Zf(a)}h.clear=function(){this.A.value=null;this.A.children={};this.A.pd=0;Zf(this)};
h.zd=function(){return 0<this.A.pd};h.e=function(){return null===this.Ea()&&!this.zd()};h.R=function(a){var b=this;v(this.A.children,function(c,d){a(new Wf(d,b,c))})};function $f(a,b,c,d){c&&!d&&b(a);a.R(function(a){$f(a,b,!0,d)});c&&d&&b(a)}function ag(a,b){for(var c=a.parent();null!==c&&!b(c);)c=c.parent()}h.path=function(){return new P(null===this.Ha?this.Jd:this.Ha.path()+"/"+this.Jd)};h.name=function(){return this.Jd};h.parent=function(){return this.Ha};
function Zf(a){if(null!==a.Ha){var b=a.Ha,c=a.Jd,d=a.e(),e=y(b.A.children,c);d&&e?(delete b.A.children[c],b.A.pd--,Zf(b)):d||e||(b.A.children[c]=a.A,b.A.pd++,Zf(b))}};var bg=/[\[\].#$\/\u0000-\u001F\u007F]/,cg=/[\[\].#$\u0000-\u001F\u007F]/,dg=/^[a-zA-Z][a-zA-Z._\-+]+$/;function eg(a){return q(a)&&0!==a.length&&!bg.test(a)}function fg(a){return null===a||q(a)||fa(a)&&!td(a)||ga(a)&&y(a,".sv")}function gg(a,b,c,d){d&&!p(b)||hg(E(a,1,d),b,c)}
function hg(a,b,c){c instanceof P&&(c=new nf(c,a));if(!p(b))throw Error(a+"contains undefined "+pf(c));if(r(b))throw Error(a+"contains a function "+pf(c)+" with contents: "+b.toString());if(td(b))throw Error(a+"contains "+b.toString()+" "+pf(c));if(q(b)&&b.length>10485760/3&&10485760<Pb(b))throw Error(a+"contains a string greater than 10485760 utf8 bytes "+pf(c)+" ('"+b.substring(0,50)+"...')");if(ga(b)){var d=!1,e=!1;Fb(b,function(b,g){if(".value"===b)d=!0;else if(".priority"!==b&&".sv"!==b&&(e=
!0,!eg(b)))throw Error(a+" contains an invalid key ("+b+") "+pf(c)+'.  Keys must be non-empty strings and can\'t contain ".", "#", "$", "/", "[", or "]"');c.push(b);hg(a,g,c);c.pop()});if(d&&e)throw Error(a+' contains ".value" child '+pf(c)+" in addition to actual children.");}}
function ig(a,b){var c,d;for(c=0;c<b.length;c++){d=b[c];for(var e=d.slice(),f=0;f<e.length;f++)if((".priority"!==e[f]||f!==e.length-1)&&!eg(e[f]))throw Error(a+"contains an invalid key ("+e[f]+") in path "+d.toString()+'. Keys must be non-empty strings and can\'t contain ".", "#", "$", "/", "[", or "]"');}b.sort(mf);e=null;for(c=0;c<b.length;c++){d=b[c];if(null!==e&&e.contains(d))throw Error(a+"contains a path "+e.toString()+" that is ancestor of another path "+d.toString());e=d}}
function jg(a,b,c){var d=E(a,1,!1);if(!ga(b)||da(b))throw Error(d+" must be an object containing the children to replace.");var e=[];Fb(b,function(a,b){var k=new P(a);hg(d,b,c.o(k));if(".priority"===me(k)&&!fg(b))throw Error(d+"contains an invalid value for '"+k.toString()+"', which must be a valid Firebase priority (a string, finite number, server value, or null).");e.push(k)});ig(d,e)}
function kg(a,b,c){if(td(c))throw Error(E(a,b,!1)+"is "+c.toString()+", but must be a valid Firebase priority (a string, finite number, server value, or null).");if(!fg(c))throw Error(E(a,b,!1)+"must be a valid Firebase priority (a string, finite number, server value, or null).");}
function lg(a,b,c){if(!c||p(b))switch(b){case "value":case "child_added":case "child_removed":case "child_changed":case "child_moved":break;default:throw Error(E(a,1,c)+'must be a valid event type: "value", "child_added", "child_removed", "child_changed", or "child_moved".');}}function mg(a,b){if(p(b)&&!eg(b))throw Error(E(a,2,!0)+'was an invalid key: "'+b+'".  Firebase keys must be non-empty strings and can\'t contain ".", "#", "$", "/", "[", or "]").');}
function ng(a,b){if(!q(b)||0===b.length||cg.test(b))throw Error(E(a,1,!1)+'was an invalid path: "'+b+'". Paths must be non-empty strings and can\'t contain ".", "#", "$", "[", or "]"');}function og(a,b){if(".info"===K(b))throw Error(a+" failed: Can't modify data under /.info/");}function pg(a,b){if(!q(b))throw Error(E(a,1,!1)+"must be a valid credential (a string).");}function qg(a,b,c){if(!q(c))throw Error(E(a,b,!1)+"must be a valid string.");}
function rg(a,b){qg(a,1,b);if(!dg.test(b))throw Error(E(a,1,!1)+"'"+b+"' is not a valid authentication provider.");}function sg(a,b,c,d){if(!d||p(c))if(!ga(c)||null===c)throw Error(E(a,b,d)+"must be a valid object.");}function tg(a,b,c){if(!ga(b)||!y(b,c))throw Error(E(a,1,!1)+'must contain the key "'+c+'"');if(!q(z(b,c)))throw Error(E(a,1,!1)+'must contain the key "'+c+'" with type "string"');};function ug(){this.set={}}h=ug.prototype;h.add=function(a,b){this.set[a]=null!==b?b:!0};h.contains=function(a){return y(this.set,a)};h.get=function(a){return this.contains(a)?this.set[a]:void 0};h.remove=function(a){delete this.set[a]};h.clear=function(){this.set={}};h.e=function(){return va(this.set)};h.count=function(){return oa(this.set)};function vg(a,b){v(a.set,function(a,d){b(d,a)})}h.keys=function(){var a=[];v(this.set,function(b,c){a.push(c)});return a};function Vc(){this.m=this.B=null}Vc.prototype.find=function(a){if(null!=this.B)return this.B.S(a);if(a.e()||null==this.m)return null;var b=K(a);a=N(a);return this.m.contains(b)?this.m.get(b).find(a):null};Vc.prototype.rc=function(a,b){if(a.e())this.B=b,this.m=null;else if(null!==this.B)this.B=this.B.H(a,b);else{null==this.m&&(this.m=new ug);var c=K(a);this.m.contains(c)||this.m.add(c,new Vc);c=this.m.get(c);a=N(a);c.rc(a,b)}};
function wg(a,b){if(b.e())return a.B=null,a.m=null,!0;if(null!==a.B){if(a.B.L())return!1;var c=a.B;a.B=null;c.R(R,function(b,c){a.rc(new P(b),c)});return wg(a,b)}return null!==a.m?(c=K(b),b=N(b),a.m.contains(c)&&wg(a.m.get(c),b)&&a.m.remove(c),a.m.e()?(a.m=null,!0):!1):!0}function Wc(a,b,c){null!==a.B?c(b,a.B):a.R(function(a,e){var f=new P(b.toString()+"/"+a);Wc(e,f,c)})}Vc.prototype.R=function(a){null!==this.m&&vg(this.m,function(b,c){a(b,c)})};var xg="auth.firebase.com";function yg(a,b,c){this.qd=a||{};this.he=b||{};this.fb=c||{};this.qd.remember||(this.qd.remember="default")}var zg=["remember","redirectTo"];function Ag(a){var b={},c={};Fb(a||{},function(a,e){0<=La(zg,a)?b[a]=e:c[a]=e});return new yg(b,{},c)};function Bg(a,b){this.Ue=["session",a.Rd,a.lc].join(":");this.ee=b}Bg.prototype.set=function(a,b){if(!b)if(this.ee.length)b=this.ee[0];else throw Error("fb.login.SessionManager : No storage options available!");b.set(this.Ue,a)};Bg.prototype.get=function(){var a=Oa(this.ee,u(this.Bg,this)),a=Na(a,function(a){return null!==a});Va(a,function(a,c){return Dd(c.token)-Dd(a.token)});return 0<a.length?a.shift():null};Bg.prototype.Bg=function(a){try{var b=a.get(this.Ue);if(b&&b.token)return b}catch(c){}return null};
Bg.prototype.clear=function(){var a=this;Ma(this.ee,function(b){b.remove(a.Ue)})};function Cg(){return"undefined"!==typeof navigator&&"string"===typeof navigator.userAgent?navigator.userAgent:""}function Dg(){return"undefined"!==typeof window&&!!(window.cordova||window.phonegap||window.PhoneGap)&&/ios|iphone|ipod|ipad|android|blackberry|iemobile/i.test(Cg())}function Eg(){return"undefined"!==typeof location&&/^file:\//.test(location.href)}
function Fg(a){var b=Cg();if(""===b)return!1;if("Microsoft Internet Explorer"===navigator.appName){if((b=b.match(/MSIE ([0-9]{1,}[\.0-9]{0,})/))&&1<b.length)return parseFloat(b[1])>=a}else if(-1<b.indexOf("Trident")&&(b=b.match(/rv:([0-9]{2,2}[\.0-9]{0,})/))&&1<b.length)return parseFloat(b[1])>=a;return!1};function Gg(){var a=window.opener.frames,b;for(b=a.length-1;0<=b;b--)try{if(a[b].location.protocol===window.location.protocol&&a[b].location.host===window.location.host&&"__winchan_relay_frame"===a[b].name)return a[b]}catch(c){}return null}function Hg(a,b,c){a.attachEvent?a.attachEvent("on"+b,c):a.addEventListener&&a.addEventListener(b,c,!1)}function Ig(a,b,c){a.detachEvent?a.detachEvent("on"+b,c):a.removeEventListener&&a.removeEventListener(b,c,!1)}
function Jg(a){/^https?:\/\//.test(a)||(a=window.location.href);var b=/^(https?:\/\/[\-_a-zA-Z\.0-9:]+)/.exec(a);return b?b[1]:a}function Kg(a){var b="";try{a=a.replace(/.*\?/,"");var c=Jb(a);c&&y(c,"__firebase_request_key")&&(b=z(c,"__firebase_request_key"))}catch(d){}return b}function Lg(){try{var a=document.location.hash.replace(/&__firebase_request_key=([a-zA-z0-9]*)/,""),a=a.replace(/\?$/,""),a=a.replace(/^#+$/,"");document.location.hash=a}catch(b){}}
function Mg(){var a=sd(xg);return a.scheme+"://"+a.host+"/v2"}function Ng(a){return Mg()+"/"+a+"/auth/channel"};function Og(a){var b=this;this.hb=a;this.fe="*";Fg(8)?this.Uc=this.Cd=Gg():(this.Uc=window.opener,this.Cd=window);if(!b.Uc)throw"Unable to find relay frame";Hg(this.Cd,"message",u(this.nc,this));Hg(this.Cd,"message",u(this.Ff,this));try{Pg(this,{a:"ready"})}catch(c){Hg(this.Uc,"load",function(){Pg(b,{a:"ready"})})}Hg(window,"unload",u(this.Ng,this))}function Pg(a,b){b=G(b);Fg(8)?a.Uc.doPost(b,a.fe):a.Uc.postMessage(b,a.fe)}
Og.prototype.nc=function(a){var b=this,c;try{c=Rb(a.data)}catch(d){}c&&"request"===c.a&&(Ig(window,"message",this.nc),this.fe=a.origin,this.hb&&setTimeout(function(){b.hb(b.fe,c.d,function(a,c){b.mg=!c;b.hb=void 0;Pg(b,{a:"response",d:a,forceKeepWindowOpen:c})})},0))};Og.prototype.Ng=function(){try{Ig(this.Cd,"message",this.Ff)}catch(a){}this.hb&&(Pg(this,{a:"error",d:"unknown closed window"}),this.hb=void 0);try{window.close()}catch(b){}};Og.prototype.Ff=function(a){if(this.mg&&"die"===a.data)try{window.close()}catch(b){}};function Qg(a){this.tc=Fa()+Fa()+Fa();this.Kf=a}Qg.prototype.open=function(a,b){cd.set("redirect_request_id",this.tc);cd.set("redirect_request_id",this.tc);b.requestId=this.tc;b.redirectTo=b.redirectTo||window.location.href;a+=(/\?/.test(a)?"":"?")+Ib(b);window.location=a};Qg.isAvailable=function(){return!Eg()&&!Dg()};Qg.prototype.Fc=function(){return"redirect"};var Rg={NETWORK_ERROR:"Unable to contact the Firebase server.",SERVER_ERROR:"An unknown server error occurred.",TRANSPORT_UNAVAILABLE:"There are no login transports available for the requested method.",REQUEST_INTERRUPTED:"The browser redirected the page before the login request could complete.",USER_CANCELLED:"The user cancelled authentication."};function Sg(a){var b=Error(z(Rg,a),a);b.code=a;return b};function Tg(a){var b;(b=!a.window_features)||(b=Cg(),b=-1!==b.indexOf("Fennec/")||-1!==b.indexOf("Firefox/")&&-1!==b.indexOf("Android"));b&&(a.window_features=void 0);a.window_name||(a.window_name="_blank");this.options=a}
Tg.prototype.open=function(a,b,c){function d(a){g&&(document.body.removeChild(g),g=void 0);t&&(t=clearInterval(t));Ig(window,"message",e);Ig(window,"unload",d);if(l&&!a)try{l.close()}catch(b){k.postMessage("die",m)}l=k=void 0}function e(a){if(a.origin===m)try{var b=Rb(a.data);"ready"===b.a?k.postMessage(A,m):"error"===b.a?(d(!1),c&&(c(b.d),c=null)):"response"===b.a&&(d(b.forceKeepWindowOpen),c&&(c(null,b.d),c=null))}catch(e){}}var f=Fg(8),g,k;if(!this.options.relay_url)return c(Error("invalid arguments: origin of url and relay_url must match"));
var m=Jg(a);if(m!==Jg(this.options.relay_url))c&&setTimeout(function(){c(Error("invalid arguments: origin of url and relay_url must match"))},0);else{f&&(g=document.createElement("iframe"),g.setAttribute("src",this.options.relay_url),g.style.display="none",g.setAttribute("name","__winchan_relay_frame"),document.body.appendChild(g),k=g.contentWindow);a+=(/\?/.test(a)?"":"?")+Ib(b);var l=window.open(a,this.options.window_name,this.options.window_features);k||(k=l);var t=setInterval(function(){l&&l.closed&&
(d(!1),c&&(c(Sg("USER_CANCELLED")),c=null))},500),A=G({a:"request",d:b});Hg(window,"unload",d);Hg(window,"message",e)}};
Tg.isAvailable=function(){var a;if(a="postMessage"in window&&!Eg())(a=Dg()||"undefined"!==typeof navigator&&(!!Cg().match(/Windows Phone/)||!!window.Windows&&/^ms-appx:/.test(location.href)))||(a=Cg(),a="undefined"!==typeof navigator&&"undefined"!==typeof window&&!!(a.match(/(iPhone|iPod|iPad).*AppleWebKit(?!.*Safari)/i)||a.match(/CriOS/)||a.match(/Twitter for iPhone/)||a.match(/FBAN\/FBIOS/)||window.navigator.standalone)),a=!a;return a&&!Cg().match(/PhantomJS/)};Tg.prototype.Fc=function(){return"popup"};function Ug(a){a.method||(a.method="GET");a.headers||(a.headers={});a.headers.content_type||(a.headers.content_type="application/json");a.headers.content_type=a.headers.content_type.toLowerCase();this.options=a}
Ug.prototype.open=function(a,b,c){function d(){c&&(c(Sg("REQUEST_INTERRUPTED")),c=null)}var e=new XMLHttpRequest,f=this.options.method.toUpperCase(),g;Hg(window,"beforeunload",d);e.onreadystatechange=function(){if(c&&4===e.readyState){var a;if(200<=e.status&&300>e.status){try{a=Rb(e.responseText)}catch(b){}c(null,a)}else 500<=e.status&&600>e.status?c(Sg("SERVER_ERROR")):c(Sg("NETWORK_ERROR"));c=null;Ig(window,"beforeunload",d)}};if("GET"===f)a+=(/\?/.test(a)?"":"?")+Ib(b),g=null;else{var k=this.options.headers.content_type;
"application/json"===k&&(g=G(b));"application/x-www-form-urlencoded"===k&&(g=Ib(b))}e.open(f,a,!0);a={"X-Requested-With":"XMLHttpRequest",Accept:"application/json;text/plain"};ya(a,this.options.headers);for(var m in a)e.setRequestHeader(m,a[m]);e.send(g)};Ug.isAvailable=function(){var a;if(a=!!window.XMLHttpRequest)a=Cg(),a=!(a.match(/MSIE/)||a.match(/Trident/))||Fg(10);return a};Ug.prototype.Fc=function(){return"json"};function Vg(a){this.tc=Fa()+Fa()+Fa();this.Kf=a}
Vg.prototype.open=function(a,b,c){function d(){c&&(c(Sg("USER_CANCELLED")),c=null)}var e=this,f=sd(xg),g;b.requestId=this.tc;b.redirectTo=f.scheme+"://"+f.host+"/blank/page.html";a+=/\?/.test(a)?"":"?";a+=Ib(b);(g=window.open(a,"_blank","location=no"))&&r(g.addEventListener)?(g.addEventListener("loadstart",function(a){var b;if(b=a&&a.url)a:{try{var l=document.createElement("a");l.href=a.url;b=l.host===f.host&&"/blank/page.html"===l.pathname;break a}catch(t){}b=!1}b&&(a=Kg(a.url),g.removeEventListener("exit",
d),g.close(),a=new yg(null,null,{requestId:e.tc,requestKey:a}),e.Kf.requestWithCredential("/auth/session",a,c),c=null)}),g.addEventListener("exit",d)):c(Sg("TRANSPORT_UNAVAILABLE"))};Vg.isAvailable=function(){return Dg()};Vg.prototype.Fc=function(){return"redirect"};function Wg(a){a.callback_parameter||(a.callback_parameter="callback");this.options=a;window.__firebase_auth_jsonp=window.__firebase_auth_jsonp||{}}
Wg.prototype.open=function(a,b,c){function d(){c&&(c(Sg("REQUEST_INTERRUPTED")),c=null)}function e(){setTimeout(function(){window.__firebase_auth_jsonp[f]=void 0;va(window.__firebase_auth_jsonp)&&(window.__firebase_auth_jsonp=void 0);try{var a=document.getElementById(f);a&&a.parentNode.removeChild(a)}catch(b){}},1);Ig(window,"beforeunload",d)}var f="fn"+(new Date).getTime()+Math.floor(99999*Math.random());b[this.options.callback_parameter]="__firebase_auth_jsonp."+f;a+=(/\?/.test(a)?"":"?")+Ib(b);
Hg(window,"beforeunload",d);window.__firebase_auth_jsonp[f]=function(a){c&&(c(null,a),c=null);e()};Xg(f,a,c)};
function Xg(a,b,c){setTimeout(function(){try{var d=document.createElement("script");d.type="text/javascript";d.id=a;d.async=!0;d.src=b;d.onerror=function(){var b=document.getElementById(a);null!==b&&b.parentNode.removeChild(b);c&&c(Sg("NETWORK_ERROR"))};var e=document.getElementsByTagName("head");(e&&0!=e.length?e[0]:document.documentElement).appendChild(d)}catch(f){c&&c(Sg("NETWORK_ERROR"))}},0)}Wg.isAvailable=function(){return"undefined"!==typeof document&&null!=document.createElement};
Wg.prototype.Fc=function(){return"json"};function Yg(a,b,c,d){ff.call(this,["auth_status"]);this.G=a;this.hf=b;this.ih=c;this.Pe=d;this.wc=new Bg(a,[bd,cd]);this.qb=null;this.We=!1;Zg(this)}ka(Yg,ff);h=Yg.prototype;h.Be=function(){return this.qb||null};function Zg(a){cd.get("redirect_request_id")&&$g(a);var b=a.wc.get();b&&b.token?(ah(a,b),a.hf(b.token,function(c,d){bh(a,c,d,!1,b.token,b)},function(b,d){ch(a,"resumeSession()",b,d)})):ah(a,null)}
function dh(a,b,c,d,e,f){"firebaseio-demo.com"===a.G.domain&&S("Firebase authentication is not supported on demo Firebases (*.firebaseio-demo.com). To secure your Firebase, create a production Firebase at https://www.firebase.com.");a.hf(b,function(f,k){bh(a,f,k,!0,b,c,d||{},e)},function(b,c){ch(a,"auth()",b,c,f)})}function eh(a,b){a.wc.clear();ah(a,null);a.ih(function(a,d){if("ok"===a)T(b,null);else{var e=(a||"error").toUpperCase(),f=e;d&&(f+=": "+d);f=Error(f);f.code=e;T(b,f)}})}
function bh(a,b,c,d,e,f,g,k){"ok"===b?(d&&(b=c.auth,f.auth=b,f.expires=c.expires,f.token=Ed(e)?e:"",c=null,b&&y(b,"uid")?c=z(b,"uid"):y(f,"uid")&&(c=z(f,"uid")),f.uid=c,c="custom",b&&y(b,"provider")?c=z(b,"provider"):y(f,"provider")&&(c=z(f,"provider")),f.provider=c,a.wc.clear(),Ed(e)&&(g=g||{},c=bd,"sessionOnly"===g.remember&&(c=cd),"none"!==g.remember&&a.wc.set(f,c)),ah(a,f)),T(k,null,f)):(a.wc.clear(),ah(a,null),f=a=(b||"error").toUpperCase(),c&&(f+=": "+c),f=Error(f),f.code=a,T(k,f))}
function ch(a,b,c,d,e){S(b+" was canceled: "+d);a.wc.clear();ah(a,null);a=Error(d);a.code=c.toUpperCase();T(e,a)}function fh(a,b,c,d,e){gh(a);c=new yg(d||{},{},c||{});hh(a,[Ug,Wg],"/auth/"+b,c,e)}
function ih(a,b,c,d){gh(a);var e=[Tg,Vg];c=Ag(c);var f=625;"anonymous"===b||"password"===b?setTimeout(function(){T(d,Sg("TRANSPORT_UNAVAILABLE"))},0):("github"===b&&(f=1025),c.he.window_features="menubar=yes,modal=yes,alwaysRaised=yeslocation=yes,resizable=yes,scrollbars=yes,status=yes,height=625,width="+f+",top="+("object"===typeof screen?.5*(screen.height-625):0)+",left="+("object"===typeof screen?.5*(screen.width-f):0),c.he.relay_url=Ng(a.G.lc),c.he.requestWithCredential=u(a.uc,a),hh(a,e,"/auth/"+
b,c,d))}function $g(a){var b=cd.get("redirect_request_id");if(b){var c=cd.get("redirect_client_options");cd.remove("redirect_request_id");cd.remove("redirect_client_options");var d=[Ug,Wg],b={requestId:b,requestKey:Kg(document.location.hash)},c=new yg(c,{},b);a.We=!0;Lg();hh(a,d,"/auth/session",c,function(){this.We=!1}.bind(a))}}h.ve=function(a,b){gh(this);var c=Ag(a);c.fb._method="POST";this.uc("/users",c,function(a,c){a?T(b,a):T(b,a,c)})};
h.Xe=function(a,b){var c=this;gh(this);var d="/users/"+encodeURIComponent(a.email),e=Ag(a);e.fb._method="DELETE";this.uc(d,e,function(a,d){!a&&d&&d.uid&&c.qb&&c.qb.uid&&c.qb.uid===d.uid&&eh(c);T(b,a)})};h.se=function(a,b){gh(this);var c="/users/"+encodeURIComponent(a.email)+"/password",d=Ag(a);d.fb._method="PUT";d.fb.password=a.newPassword;this.uc(c,d,function(a){T(b,a)})};
h.re=function(a,b){gh(this);var c="/users/"+encodeURIComponent(a.oldEmail)+"/email",d=Ag(a);d.fb._method="PUT";d.fb.email=a.newEmail;d.fb.password=a.password;this.uc(c,d,function(a){T(b,a)})};h.Ze=function(a,b){gh(this);var c="/users/"+encodeURIComponent(a.email)+"/password",d=Ag(a);d.fb._method="POST";this.uc(c,d,function(a){T(b,a)})};h.uc=function(a,b,c){jh(this,[Ug,Wg],a,b,c)};
function hh(a,b,c,d,e){jh(a,b,c,d,function(b,c){!b&&c&&c.token&&c.uid?dh(a,c.token,c,d.qd,function(a,b){a?T(e,a):T(e,null,b)}):T(e,b||Sg("UNKNOWN_ERROR"))})}
function jh(a,b,c,d,e){b=Na(b,function(a){return"function"===typeof a.isAvailable&&a.isAvailable()});0===b.length?setTimeout(function(){T(e,Sg("TRANSPORT_UNAVAILABLE"))},0):(b=new (b.shift())(d.he),d=Gb(d.fb),d.v="js-"+Eb,d.transport=b.Fc(),d.suppress_status_codes=!0,a=Mg()+"/"+a.G.lc+c,b.open(a,d,function(a,b){if(a)T(e,a);else if(b&&b.error){var c=Error(b.error.message);c.code=b.error.code;c.details=b.error.details;T(e,c)}else T(e,null,b)}))}
function ah(a,b){var c=null!==a.qb||null!==b;a.qb=b;c&&a.ie("auth_status",b);a.Pe(null!==b)}h.Ee=function(a){O("auth_status"===a,'initial event must be of type "auth_status"');return this.We?null:[this.qb]};function gh(a){var b=a.G;if("firebaseio.com"!==b.domain&&"firebaseio-demo.com"!==b.domain&&"auth.firebase.com"===xg)throw Error("This custom Firebase server ('"+a.G.domain+"') does not support delegated login.");};var gd="websocket",hd="long_polling";function kh(a){this.nc=a;this.Qd=[];this.Wb=0;this.te=-1;this.Jb=null}function lh(a,b,c){a.te=b;a.Jb=c;a.te<a.Wb&&(a.Jb(),a.Jb=null)}function mh(a,b,c){for(a.Qd[b]=c;a.Qd[a.Wb];){var d=a.Qd[a.Wb];delete a.Qd[a.Wb];for(var e=0;e<d.length;++e)if(d[e]){var f=a;gc(function(){f.nc(d[e])})}if(a.Wb===a.te){a.Jb&&(clearTimeout(a.Jb),a.Jb(),a.Jb=null);break}a.Wb++}};function nh(a,b,c,d){this.ue=a;this.f=pd(a);this.rb=this.sb=0;this.Xa=uc(b);this.Xf=c;this.Kc=!1;this.Fb=d;this.ld=function(a){return fd(b,hd,a)}}var oh,ph;
nh.prototype.open=function(a,b){this.mf=0;this.na=b;this.Ef=new kh(a);this.Db=!1;var c=this;this.ub=setTimeout(function(){c.f("Timed out trying to connect.");c.bb();c.ub=null},Math.floor(3E4));ud(function(){if(!c.Db){c.Wa=new qh(function(a,b,d,k,m){rh(c,arguments);if(c.Wa)if(c.ub&&(clearTimeout(c.ub),c.ub=null),c.Kc=!0,"start"==a)c.id=b,c.Mf=d;else if("close"===a)b?(c.Wa.$d=!1,lh(c.Ef,b,function(){c.bb()})):c.bb();else throw Error("Unrecognized command received: "+a);},function(a,b){rh(c,arguments);
mh(c.Ef,a,b)},function(){c.bb()},c.ld);var a={start:"t"};a.ser=Math.floor(1E8*Math.random());c.Wa.ke&&(a.cb=c.Wa.ke);a.v="5";c.Xf&&(a.s=c.Xf);c.Fb&&(a.ls=c.Fb);"undefined"!==typeof location&&location.href&&-1!==location.href.indexOf("firebaseio.com")&&(a.r="f");a=c.ld(a);c.f("Connecting via long-poll to "+a);sh(c.Wa,a,function(){})}})};
nh.prototype.start=function(){var a=this.Wa,b=this.Mf;a.Gg=this.id;a.Hg=b;for(a.oe=!0;th(a););a=this.id;b=this.Mf;this.kc=document.createElement("iframe");var c={dframe:"t"};c.id=a;c.pw=b;this.kc.src=this.ld(c);this.kc.style.display="none";document.body.appendChild(this.kc)};
nh.isAvailable=function(){return oh||!ph&&"undefined"!==typeof document&&null!=document.createElement&&!("object"===typeof window&&window.chrome&&window.chrome.extension&&!/^chrome/.test(window.location.href))&&!("object"===typeof Windows&&"object"===typeof Windows.kh)&&!0};h=nh.prototype;h.Hd=function(){};h.fd=function(){this.Db=!0;this.Wa&&(this.Wa.close(),this.Wa=null);this.kc&&(document.body.removeChild(this.kc),this.kc=null);this.ub&&(clearTimeout(this.ub),this.ub=null)};
h.bb=function(){this.Db||(this.f("Longpoll is closing itself"),this.fd(),this.na&&(this.na(this.Kc),this.na=null))};h.close=function(){this.Db||(this.f("Longpoll is being closed."),this.fd())};h.send=function(a){a=G(a);this.sb+=a.length;rc(this.Xa,"bytes_sent",a.length);a=Ob(a);a=nb(a,!0);a=yd(a,1840);for(var b=0;b<a.length;b++){var c=this.Wa;c.cd.push({Yg:this.mf,hh:a.length,of:a[b]});c.oe&&th(c);this.mf++}};function rh(a,b){var c=G(b).length;a.rb+=c;rc(a.Xa,"bytes_received",c)}
function qh(a,b,c,d){this.ld=d;this.lb=c;this.Te=new ug;this.cd=[];this.we=Math.floor(1E8*Math.random());this.$d=!0;this.ke=id();window["pLPCommand"+this.ke]=a;window["pRTLPCB"+this.ke]=b;a=document.createElement("iframe");a.style.display="none";if(document.body){document.body.appendChild(a);try{a.contentWindow.document||fc("No IE domain setting required")}catch(e){a.src="javascript:void((function(){document.open();document.domain='"+document.domain+"';document.close();})())"}}else throw"Document body has not initialized. Wait to initialize Firebase until after the document is ready.";
a.contentDocument?a.jb=a.contentDocument:a.contentWindow?a.jb=a.contentWindow.document:a.document&&(a.jb=a.document);this.Ga=a;a="";this.Ga.src&&"javascript:"===this.Ga.src.substr(0,11)&&(a='<script>document.domain="'+document.domain+'";\x3c/script>');a="<html><body>"+a+"</body></html>";try{this.Ga.jb.open(),this.Ga.jb.write(a),this.Ga.jb.close()}catch(f){fc("frame writing exception"),f.stack&&fc(f.stack),fc(f)}}
qh.prototype.close=function(){this.oe=!1;if(this.Ga){this.Ga.jb.body.innerHTML="";var a=this;setTimeout(function(){null!==a.Ga&&(document.body.removeChild(a.Ga),a.Ga=null)},Math.floor(0))}var b=this.lb;b&&(this.lb=null,b())};
function th(a){if(a.oe&&a.$d&&a.Te.count()<(0<a.cd.length?2:1)){a.we++;var b={};b.id=a.Gg;b.pw=a.Hg;b.ser=a.we;for(var b=a.ld(b),c="",d=0;0<a.cd.length;)if(1870>=a.cd[0].of.length+30+c.length){var e=a.cd.shift(),c=c+"&seg"+d+"="+e.Yg+"&ts"+d+"="+e.hh+"&d"+d+"="+e.of;d++}else break;uh(a,b+c,a.we);return!0}return!1}function uh(a,b,c){function d(){a.Te.remove(c);th(a)}a.Te.add(c,1);var e=setTimeout(d,Math.floor(25E3));sh(a,b,function(){clearTimeout(e);d()})}
function sh(a,b,c){setTimeout(function(){try{if(a.$d){var d=a.Ga.jb.createElement("script");d.type="text/javascript";d.async=!0;d.src=b;d.onload=d.onreadystatechange=function(){var a=d.readyState;a&&"loaded"!==a&&"complete"!==a||(d.onload=d.onreadystatechange=null,d.parentNode&&d.parentNode.removeChild(d),c())};d.onerror=function(){fc("Long-poll script failed to load: "+b);a.$d=!1;a.close()};a.Ga.jb.body.appendChild(d)}}catch(e){}},Math.floor(1))};var vh=null;"undefined"!==typeof MozWebSocket?vh=MozWebSocket:"undefined"!==typeof WebSocket&&(vh=WebSocket);function wh(a,b,c,d){this.ue=a;this.f=pd(this.ue);this.frames=this.Nc=null;this.rb=this.sb=this.ff=0;this.Xa=uc(b);a={v:"5"};"undefined"!==typeof location&&location.href&&-1!==location.href.indexOf("firebaseio.com")&&(a.r="f");c&&(a.s=c);d&&(a.ls=d);this.jf=fd(b,gd,a)}var xh;
wh.prototype.open=function(a,b){this.lb=b;this.Lg=a;this.f("Websocket connecting to "+this.jf);this.Kc=!1;bd.set("previous_websocket_failure",!0);try{this.La=new vh(this.jf)}catch(c){this.f("Error instantiating WebSocket.");var d=c.message||c.data;d&&this.f(d);this.bb();return}var e=this;this.La.onopen=function(){e.f("Websocket connected.");e.Kc=!0};this.La.onclose=function(){e.f("Websocket connection was disconnected.");e.La=null;e.bb()};this.La.onmessage=function(a){if(null!==e.La)if(a=a.data,e.rb+=
a.length,rc(e.Xa,"bytes_received",a.length),yh(e),null!==e.frames)zh(e,a);else{a:{O(null===e.frames,"We already have a frame buffer");if(6>=a.length){var b=Number(a);if(!isNaN(b)){e.ff=b;e.frames=[];a=null;break a}}e.ff=1;e.frames=[]}null!==a&&zh(e,a)}};this.La.onerror=function(a){e.f("WebSocket error.  Closing connection.");(a=a.message||a.data)&&e.f(a);e.bb()}};wh.prototype.start=function(){};
wh.isAvailable=function(){var a=!1;if("undefined"!==typeof navigator&&navigator.userAgent){var b=navigator.userAgent.match(/Android ([0-9]{0,}\.[0-9]{0,})/);b&&1<b.length&&4.4>parseFloat(b[1])&&(a=!0)}return!a&&null!==vh&&!xh};wh.responsesRequiredToBeHealthy=2;wh.healthyTimeout=3E4;h=wh.prototype;h.Hd=function(){bd.remove("previous_websocket_failure")};function zh(a,b){a.frames.push(b);if(a.frames.length==a.ff){var c=a.frames.join("");a.frames=null;c=Rb(c);a.Lg(c)}}
h.send=function(a){yh(this);a=G(a);this.sb+=a.length;rc(this.Xa,"bytes_sent",a.length);a=yd(a,16384);1<a.length&&Ah(this,String(a.length));for(var b=0;b<a.length;b++)Ah(this,a[b])};h.fd=function(){this.Db=!0;this.Nc&&(clearInterval(this.Nc),this.Nc=null);this.La&&(this.La.close(),this.La=null)};h.bb=function(){this.Db||(this.f("WebSocket is closing itself"),this.fd(),this.lb&&(this.lb(this.Kc),this.lb=null))};h.close=function(){this.Db||(this.f("WebSocket is being closed"),this.fd())};
function yh(a){clearInterval(a.Nc);a.Nc=setInterval(function(){a.La&&Ah(a,"0");yh(a)},Math.floor(45E3))}function Ah(a,b){try{a.La.send(b)}catch(c){a.f("Exception thrown from WebSocket.send():",c.message||c.data,"Closing connection."),setTimeout(u(a.bb,a),0)}};function Bh(a){Ch(this,a)}var Dh=[nh,wh];function Ch(a,b){var c=wh&&wh.isAvailable(),d=c&&!(bd.Af||!0===bd.get("previous_websocket_failure"));b.jh&&(c||S("wss:// URL used, but browser isn't known to support websockets.  Trying anyway."),d=!0);if(d)a.jd=[wh];else{var e=a.jd=[];zd(Dh,function(a,b){b&&b.isAvailable()&&e.push(b)})}}function Eh(a){if(0<a.jd.length)return a.jd[0];throw Error("No transports available");};function Fh(a,b,c,d,e,f,g){this.id=a;this.f=pd("c:"+this.id+":");this.nc=c;this.Zc=d;this.na=e;this.Re=f;this.G=b;this.Pd=[];this.kf=0;this.Wf=new Bh(b);this.N=0;this.Fb=g;this.f("Connection created");Gh(this)}
function Gh(a){var b=Eh(a.Wf);a.K=new b("c:"+a.id+":"+a.kf++,a.G,void 0,a.Fb);a.Ve=b.responsesRequiredToBeHealthy||0;var c=Hh(a,a.K),d=Ih(a,a.K);a.kd=a.K;a.ed=a.K;a.F=null;a.Eb=!1;setTimeout(function(){a.K&&a.K.open(c,d)},Math.floor(0));b=b.healthyTimeout||0;0<b&&(a.Bd=setTimeout(function(){a.Bd=null;a.Eb||(a.K&&102400<a.K.rb?(a.f("Connection exceeded healthy timeout but has received "+a.K.rb+" bytes.  Marking connection healthy."),a.Eb=!0,a.K.Hd()):a.K&&10240<a.K.sb?a.f("Connection exceeded healthy timeout but has sent "+
a.K.sb+" bytes.  Leaving connection alive."):(a.f("Closing unhealthy connection after timeout."),a.close()))},Math.floor(b)))}function Ih(a,b){return function(c){b===a.K?(a.K=null,c||0!==a.N?1===a.N&&a.f("Realtime connection lost."):(a.f("Realtime connection failed."),"s-"===a.G.ab.substr(0,2)&&(bd.remove("host:"+a.G.host),a.G.ab=a.G.host)),a.close()):b===a.F?(a.f("Secondary connection lost."),c=a.F,a.F=null,a.kd!==c&&a.ed!==c||a.close()):a.f("closing an old connection")}}
function Hh(a,b){return function(c){if(2!=a.N)if(b===a.ed){var d=wd("t",c);c=wd("d",c);if("c"==d){if(d=wd("t",c),"d"in c)if(c=c.d,"h"===d){var d=c.ts,e=c.v,f=c.h;a.Uf=c.s;ed(a.G,f);0==a.N&&(a.K.start(),Jh(a,a.K,d),"5"!==e&&S("Protocol version mismatch detected"),c=a.Wf,(c=1<c.jd.length?c.jd[1]:null)&&Kh(a,c))}else if("n"===d){a.f("recvd end transmission on primary");a.ed=a.F;for(c=0;c<a.Pd.length;++c)a.Ld(a.Pd[c]);a.Pd=[];Lh(a)}else"s"===d?(a.f("Connection shutdown command received. Shutting down..."),
a.Re&&(a.Re(c),a.Re=null),a.na=null,a.close()):"r"===d?(a.f("Reset packet received.  New host: "+c),ed(a.G,c),1===a.N?a.close():(Mh(a),Gh(a))):"e"===d?qd("Server Error: "+c):"o"===d?(a.f("got pong on primary."),Nh(a),Oh(a)):qd("Unknown control packet command: "+d)}else"d"==d&&a.Ld(c)}else if(b===a.F)if(d=wd("t",c),c=wd("d",c),"c"==d)"t"in c&&(c=c.t,"a"===c?Ph(a):"r"===c?(a.f("Got a reset on secondary, closing it"),a.F.close(),a.kd!==a.F&&a.ed!==a.F||a.close()):"o"===c&&(a.f("got pong on secondary."),
a.Tf--,Ph(a)));else if("d"==d)a.Pd.push(c);else throw Error("Unknown protocol layer: "+d);else a.f("message on old connection")}}Fh.prototype.Ia=function(a){Qh(this,{t:"d",d:a})};function Lh(a){a.kd===a.F&&a.ed===a.F&&(a.f("cleaning up and promoting a connection: "+a.F.ue),a.K=a.F,a.F=null)}
function Ph(a){0>=a.Tf?(a.f("Secondary connection is healthy."),a.Eb=!0,a.F.Hd(),a.F.start(),a.f("sending client ack on secondary"),a.F.send({t:"c",d:{t:"a",d:{}}}),a.f("Ending transmission on primary"),a.K.send({t:"c",d:{t:"n",d:{}}}),a.kd=a.F,Lh(a)):(a.f("sending ping on secondary."),a.F.send({t:"c",d:{t:"p",d:{}}}))}Fh.prototype.Ld=function(a){Nh(this);this.nc(a)};function Nh(a){a.Eb||(a.Ve--,0>=a.Ve&&(a.f("Primary connection is healthy."),a.Eb=!0,a.K.Hd()))}
function Kh(a,b){a.F=new b("c:"+a.id+":"+a.kf++,a.G,a.Uf);a.Tf=b.responsesRequiredToBeHealthy||0;a.F.open(Hh(a,a.F),Ih(a,a.F));setTimeout(function(){a.F&&(a.f("Timed out trying to upgrade."),a.F.close())},Math.floor(6E4))}function Jh(a,b,c){a.f("Realtime connection established.");a.K=b;a.N=1;a.Zc&&(a.Zc(c,a.Uf),a.Zc=null);0===a.Ve?(a.f("Primary connection is healthy."),a.Eb=!0):setTimeout(function(){Oh(a)},Math.floor(5E3))}
function Oh(a){a.Eb||1!==a.N||(a.f("sending ping on primary."),Qh(a,{t:"c",d:{t:"p",d:{}}}))}function Qh(a,b){if(1!==a.N)throw"Connection is not connected";a.kd.send(b)}Fh.prototype.close=function(){2!==this.N&&(this.f("Closing realtime connection."),this.N=2,Mh(this),this.na&&(this.na(),this.na=null))};function Mh(a){a.f("Shutting down all connections");a.K&&(a.K.close(),a.K=null);a.F&&(a.F.close(),a.F=null);a.Bd&&(clearTimeout(a.Bd),a.Bd=null)};function Rh(a,b,c,d){this.id=Sh++;this.f=pd("p:"+this.id+":");this.Bf=this.Ie=!1;this.ba={};this.sa=[];this.ad=0;this.Yc=[];this.qa=!1;this.eb=1E3;this.Id=3E5;this.Kb=b;this.Xc=c;this.Se=d;this.G=a;this.wb=this.Ca=this.Ma=this.Fb=this.$e=null;this.Sb=!1;this.Wd={};this.Xg=0;this.rf=!0;this.Oc=this.Ke=null;Th(this,0);kf.yb().Ib("visible",this.Og,this);-1===a.host.indexOf("fblocal")&&jf.yb().Ib("online",this.Mg,this)}var Sh=0,Uh=0;h=Rh.prototype;
h.Ia=function(a,b,c){var d=++this.Xg;a={r:d,a:a,b:b};this.f(G(a));O(this.qa,"sendRequest call when we're not connected not allowed.");this.Ma.Ia(a);c&&(this.Wd[d]=c)};h.Cf=function(a,b,c,d){var e=a.wa(),f=a.path.toString();this.f("Listen called for "+f+" "+e);this.ba[f]=this.ba[f]||{};O(Ie(a.n)||!He(a.n),"listen() called for non-default but complete query");O(!this.ba[f][e],"listen() called twice for same path/queryId.");a={I:d,Ad:b,Ug:a,tag:c};this.ba[f][e]=a;this.qa&&Vh(this,a)};
function Vh(a,b){var c=b.Ug,d=c.path.toString(),e=c.wa();a.f("Listen on "+d+" for "+e);var f={p:d};b.tag&&(f.q=Ge(c.n),f.t=b.tag);f.h=b.Ad();a.Ia("q",f,function(f){var k=f.d,m=f.s;if(k&&"object"===typeof k&&y(k,"w")){var l=z(k,"w");da(l)&&0<=La(l,"no_index")&&S("Using an unspecified index. Consider adding "+('".indexOn": "'+c.n.g.toString()+'"')+" at "+c.path.toString()+" to your security rules for better performance")}(a.ba[d]&&a.ba[d][e])===b&&(a.f("listen response",f),"ok"!==m&&Wh(a,d,e),b.I&&
b.I(m,k))})}h.O=function(a,b,c){this.Ca={rg:a,sf:!1,Dc:b,od:c};this.f("Authenticating using credential: "+a);Xh(this);(b=40==a.length)||(a=Cd(a).Ec,b="object"===typeof a&&!0===z(a,"admin"));b&&(this.f("Admin auth credential detected.  Reducing max reconnect time."),this.Id=3E4)};h.je=function(a){this.Ca=null;this.qa&&this.Ia("unauth",{},function(b){a(b.s,b.d)})};
function Xh(a){var b=a.Ca;a.qa&&b&&a.Ia("auth",{cred:b.rg},function(c){var d=c.s;c=c.d||"error";"ok"!==d&&a.Ca===b&&(a.Ca=null);b.sf?"ok"!==d&&b.od&&b.od(d,c):(b.sf=!0,b.Dc&&b.Dc(d,c))})}h.$f=function(a,b){var c=a.path.toString(),d=a.wa();this.f("Unlisten called for "+c+" "+d);O(Ie(a.n)||!He(a.n),"unlisten() called for non-default but complete query");if(Wh(this,c,d)&&this.qa){var e=Ge(a.n);this.f("Unlisten on "+c+" for "+d);c={p:c};b&&(c.q=e,c.t=b);this.Ia("n",c)}};
h.Qe=function(a,b,c){this.qa?Yh(this,"o",a,b,c):this.Yc.push({bd:a,action:"o",data:b,I:c})};h.Gf=function(a,b,c){this.qa?Yh(this,"om",a,b,c):this.Yc.push({bd:a,action:"om",data:b,I:c})};h.Md=function(a,b){this.qa?Yh(this,"oc",a,null,b):this.Yc.push({bd:a,action:"oc",data:null,I:b})};function Yh(a,b,c,d,e){c={p:c,d:d};a.f("onDisconnect "+b,c);a.Ia(b,c,function(a){e&&setTimeout(function(){e(a.s,a.d)},Math.floor(0))})}h.put=function(a,b,c,d){Zh(this,"p",a,b,c,d)};
h.Df=function(a,b,c,d){Zh(this,"m",a,b,c,d)};function Zh(a,b,c,d,e,f){d={p:c,d:d};p(f)&&(d.h=f);a.sa.push({action:b,Pf:d,I:e});a.ad++;b=a.sa.length-1;a.qa?$h(a,b):a.f("Buffering put: "+c)}function $h(a,b){var c=a.sa[b].action,d=a.sa[b].Pf,e=a.sa[b].I;a.sa[b].Vg=a.qa;a.Ia(c,d,function(d){a.f(c+" response",d);delete a.sa[b];a.ad--;0===a.ad&&(a.sa=[]);e&&e(d.s,d.d)})}
h.Ye=function(a){this.qa&&(a={c:a},this.f("reportStats",a),this.Ia("s",a,function(a){"ok"!==a.s&&this.f("reportStats","Error sending stats: "+a.d)}))};
h.Ld=function(a){if("r"in a){this.f("from server: "+G(a));var b=a.r,c=this.Wd[b];c&&(delete this.Wd[b],c(a.b))}else{if("error"in a)throw"A server-side error has occurred: "+a.error;"a"in a&&(b=a.a,c=a.b,this.f("handleServerMessage",b,c),"d"===b?this.Kb(c.p,c.d,!1,c.t):"m"===b?this.Kb(c.p,c.d,!0,c.t):"c"===b?ai(this,c.p,c.q):"ac"===b?(a=c.s,b=c.d,c=this.Ca,this.Ca=null,c&&c.od&&c.od(a,b)):"sd"===b?this.$e?this.$e(c):"msg"in c&&"undefined"!==typeof console&&console.log("FIREBASE: "+c.msg.replace("\n",
"\nFIREBASE: ")):qd("Unrecognized action received from server: "+G(b)+"\nAre you using the latest client?"))}};h.Zc=function(a,b){this.f("connection ready");this.qa=!0;this.Oc=(new Date).getTime();this.Se({serverTimeOffset:a-(new Date).getTime()});this.Fb=b;if(this.rf){var c={};c["sdk.js."+Eb.replace(/\./g,"-")]=1;Dg()?c["framework.cordova"]=1:"object"===typeof navigator&&"ReactNative"===navigator.product&&(c["framework.reactnative"]=1);this.Ye(c)}bi(this);this.rf=!1;this.Xc(!0)};
function Th(a,b){O(!a.Ma,"Scheduling a connect when we're already connected/ing?");a.wb&&clearTimeout(a.wb);a.wb=setTimeout(function(){a.wb=null;ci(a)},Math.floor(b))}h.Og=function(a){a&&!this.Sb&&this.eb===this.Id&&(this.f("Window became visible.  Reducing delay."),this.eb=1E3,this.Ma||Th(this,0));this.Sb=a};h.Mg=function(a){a?(this.f("Browser went online."),this.eb=1E3,this.Ma||Th(this,0)):(this.f("Browser went offline.  Killing connection."),this.Ma&&this.Ma.close())};
h.If=function(){this.f("data client disconnected");this.qa=!1;this.Ma=null;for(var a=0;a<this.sa.length;a++){var b=this.sa[a];b&&"h"in b.Pf&&b.Vg&&(b.I&&b.I("disconnect"),delete this.sa[a],this.ad--)}0===this.ad&&(this.sa=[]);this.Wd={};di(this)&&(this.Sb?this.Oc&&(3E4<(new Date).getTime()-this.Oc&&(this.eb=1E3),this.Oc=null):(this.f("Window isn't visible.  Delaying reconnect."),this.eb=this.Id,this.Ke=(new Date).getTime()),a=Math.max(0,this.eb-((new Date).getTime()-this.Ke)),a*=Math.random(),this.f("Trying to reconnect in "+
a+"ms"),Th(this,a),this.eb=Math.min(this.Id,1.3*this.eb));this.Xc(!1)};function ci(a){if(di(a)){a.f("Making a connection attempt");a.Ke=(new Date).getTime();a.Oc=null;var b=u(a.Ld,a),c=u(a.Zc,a),d=u(a.If,a),e=a.id+":"+Uh++;a.Ma=new Fh(e,a.G,b,c,d,function(b){S(b+" ("+a.G.toString()+")");a.Bf=!0},a.Fb)}}h.Cb=function(){this.Ie=!0;this.Ma?this.Ma.close():(this.wb&&(clearTimeout(this.wb),this.wb=null),this.qa&&this.If())};h.vc=function(){this.Ie=!1;this.eb=1E3;this.Ma||Th(this,0)};
function ai(a,b,c){c=c?Oa(c,function(a){return xd(a)}).join("$"):"default";(a=Wh(a,b,c))&&a.I&&a.I("permission_denied")}function Wh(a,b,c){b=(new P(b)).toString();var d;p(a.ba[b])?(d=a.ba[b][c],delete a.ba[b][c],0===oa(a.ba[b])&&delete a.ba[b]):d=void 0;return d}function bi(a){Xh(a);v(a.ba,function(b){v(b,function(b){Vh(a,b)})});for(var b=0;b<a.sa.length;b++)a.sa[b]&&$h(a,b);for(;a.Yc.length;)b=a.Yc.shift(),Yh(a,b.action,b.bd,b.data,b.I)}function di(a){var b;b=jf.yb().oc;return!a.Bf&&!a.Ie&&b};var U={zg:function(){oh=xh=!0}};U.forceLongPolling=U.zg;U.Ag=function(){ph=!0};U.forceWebSockets=U.Ag;U.Eg=function(){return wh.isAvailable()};U.isWebSocketsAvailable=U.Eg;U.ah=function(a,b){a.k.Va.$e=b};U.setSecurityDebugCallback=U.ah;U.bf=function(a,b){a.k.bf(b)};U.stats=U.bf;U.cf=function(a,b){a.k.cf(b)};U.statsIncrementCounter=U.cf;U.ud=function(a){return a.k.ud};U.dataUpdateCount=U.ud;U.Dg=function(a,b){a.k.He=b};U.interceptServerData=U.Dg;U.Kg=function(a){new Og(a)};U.onPopupOpen=U.Kg;
U.Zg=function(a){xg=a};U.setAuthenticationServer=U.Zg;function ei(a,b){this.committed=a;this.snapshot=b};function V(a,b){this.dd=a;this.ta=b}V.prototype.cancel=function(a){D("Firebase.onDisconnect().cancel",0,1,arguments.length);F("Firebase.onDisconnect().cancel",1,a,!0);var b=new B;this.dd.Md(this.ta,C(b,a));return b.D};V.prototype.cancel=V.prototype.cancel;V.prototype.remove=function(a){D("Firebase.onDisconnect().remove",0,1,arguments.length);og("Firebase.onDisconnect().remove",this.ta);F("Firebase.onDisconnect().remove",1,a,!0);var b=new B;fi(this.dd,this.ta,null,C(b,a));return b.D};
V.prototype.remove=V.prototype.remove;V.prototype.set=function(a,b){D("Firebase.onDisconnect().set",1,2,arguments.length);og("Firebase.onDisconnect().set",this.ta);gg("Firebase.onDisconnect().set",a,this.ta,!1);F("Firebase.onDisconnect().set",2,b,!0);var c=new B;fi(this.dd,this.ta,a,C(c,b));return c.D};V.prototype.set=V.prototype.set;
V.prototype.Ob=function(a,b,c){D("Firebase.onDisconnect().setWithPriority",2,3,arguments.length);og("Firebase.onDisconnect().setWithPriority",this.ta);gg("Firebase.onDisconnect().setWithPriority",a,this.ta,!1);kg("Firebase.onDisconnect().setWithPriority",2,b);F("Firebase.onDisconnect().setWithPriority",3,c,!0);var d=new B;gi(this.dd,this.ta,a,b,C(d,c));return d.D};V.prototype.setWithPriority=V.prototype.Ob;
V.prototype.update=function(a,b){D("Firebase.onDisconnect().update",1,2,arguments.length);og("Firebase.onDisconnect().update",this.ta);if(da(a)){for(var c={},d=0;d<a.length;++d)c[""+d]=a[d];a=c;S("Passing an Array to Firebase.onDisconnect().update() is deprecated. Use set() if you want to overwrite the existing data, or an Object with integer keys if you really do want to only update some of the children.")}jg("Firebase.onDisconnect().update",a,this.ta);F("Firebase.onDisconnect().update",2,b,!0);
c=new B;hi(this.dd,this.ta,a,C(c,b));return c.D};V.prototype.update=V.prototype.update;function W(a,b,c){this.A=a;this.Y=b;this.g=c}W.prototype.J=function(){D("Firebase.DataSnapshot.val",0,0,arguments.length);return this.A.J()};W.prototype.val=W.prototype.J;W.prototype.qf=function(){D("Firebase.DataSnapshot.exportVal",0,0,arguments.length);return this.A.J(!0)};W.prototype.exportVal=W.prototype.qf;W.prototype.xg=function(){D("Firebase.DataSnapshot.exists",0,0,arguments.length);return!this.A.e()};W.prototype.exists=W.prototype.xg;
W.prototype.o=function(a){D("Firebase.DataSnapshot.child",0,1,arguments.length);fa(a)&&(a=String(a));ng("Firebase.DataSnapshot.child",a);var b=new P(a),c=this.Y.o(b);return new W(this.A.S(b),c,R)};W.prototype.child=W.prototype.o;W.prototype.Fa=function(a){D("Firebase.DataSnapshot.hasChild",1,1,arguments.length);ng("Firebase.DataSnapshot.hasChild",a);var b=new P(a);return!this.A.S(b).e()};W.prototype.hasChild=W.prototype.Fa;
W.prototype.C=function(){D("Firebase.DataSnapshot.getPriority",0,0,arguments.length);return this.A.C().J()};W.prototype.getPriority=W.prototype.C;W.prototype.forEach=function(a){D("Firebase.DataSnapshot.forEach",1,1,arguments.length);F("Firebase.DataSnapshot.forEach",1,a,!1);if(this.A.L())return!1;var b=this;return!!this.A.R(this.g,function(c,d){return a(new W(d,b.Y.o(c),R))})};W.prototype.forEach=W.prototype.forEach;
W.prototype.zd=function(){D("Firebase.DataSnapshot.hasChildren",0,0,arguments.length);return this.A.L()?!1:!this.A.e()};W.prototype.hasChildren=W.prototype.zd;W.prototype.name=function(){S("Firebase.DataSnapshot.name() being deprecated. Please use Firebase.DataSnapshot.key() instead.");D("Firebase.DataSnapshot.name",0,0,arguments.length);return this.key()};W.prototype.name=W.prototype.name;W.prototype.key=function(){D("Firebase.DataSnapshot.key",0,0,arguments.length);return this.Y.key()};
W.prototype.key=W.prototype.key;W.prototype.Hb=function(){D("Firebase.DataSnapshot.numChildren",0,0,arguments.length);return this.A.Hb()};W.prototype.numChildren=W.prototype.Hb;W.prototype.Mb=function(){D("Firebase.DataSnapshot.ref",0,0,arguments.length);return this.Y};W.prototype.ref=W.prototype.Mb;function ii(a,b,c){this.Vb=a;this.tb=b;this.vb=c||null}h=ii.prototype;h.Qf=function(a){return"value"===a};h.createEvent=function(a,b){var c=b.n.g;return new jc("value",this,new W(a.Na,b.Mb(),c))};h.Zb=function(a){var b=this.vb;if("cancel"===a.De()){O(this.tb,"Raising a cancel event on a listener with no cancel callback");var c=this.tb;return function(){c.call(b,a.error)}}var d=this.Vb;return function(){d.call(b,a.be)}};h.lf=function(a,b){return this.tb?new kc(this,a,b):null};
h.matches=function(a){return a instanceof ii?a.Vb&&this.Vb?a.Vb===this.Vb&&a.vb===this.vb:!0:!1};h.yf=function(){return null!==this.Vb};function ji(a,b,c){this.ja=a;this.tb=b;this.vb=c}h=ji.prototype;h.Qf=function(a){a="children_added"===a?"child_added":a;return("children_removed"===a?"child_removed":a)in this.ja};h.lf=function(a,b){return this.tb?new kc(this,a,b):null};
h.createEvent=function(a,b){O(null!=a.Za,"Child events should have a childName.");var c=b.Mb().o(a.Za);return new jc(a.type,this,new W(a.Na,c,b.n.g),a.Td)};h.Zb=function(a){var b=this.vb;if("cancel"===a.De()){O(this.tb,"Raising a cancel event on a listener with no cancel callback");var c=this.tb;return function(){c.call(b,a.error)}}var d=this.ja[a.wd];return function(){d.call(b,a.be,a.Td)}};
h.matches=function(a){if(a instanceof ji){if(!this.ja||!a.ja)return!0;if(this.vb===a.vb){var b=oa(a.ja);if(b===oa(this.ja)){if(1===b){var b=pa(a.ja),c=pa(this.ja);return c===b&&(!a.ja[b]||!this.ja[c]||a.ja[b]===this.ja[c])}return na(this.ja,function(b,c){return a.ja[c]===b})}}}return!1};h.yf=function(){return null!==this.ja};function ki(){this.za={}}h=ki.prototype;h.e=function(){return va(this.za)};h.gb=function(a,b,c){var d=a.source.Lb;if(null!==d)return d=z(this.za,d),O(null!=d,"SyncTree gave us an op for an invalid query."),d.gb(a,b,c);var e=[];v(this.za,function(d){e=e.concat(d.gb(a,b,c))});return e};h.Tb=function(a,b,c,d,e){var f=a.wa(),g=z(this.za,f);if(!g){var g=c.Aa(e?d:null),k=!1;g?k=!0:(g=d instanceof fe?c.Cc(d):H,k=!1);g=new Ye(a,new je(new Xb(g,k,!1),new Xb(d,e,!1)));this.za[f]=g}g.Tb(b);return af(g,b)};
h.nb=function(a,b,c){var d=a.wa(),e=[],f=[],g=null!=li(this);if("default"===d){var k=this;v(this.za,function(a,d){f=f.concat(a.nb(b,c));a.e()&&(delete k.za[d],He(a.Y.n)||e.push(a.Y))})}else{var m=z(this.za,d);m&&(f=f.concat(m.nb(b,c)),m.e()&&(delete this.za[d],He(m.Y.n)||e.push(m.Y)))}g&&null==li(this)&&e.push(new X(a.k,a.path));return{Wg:e,vg:f}};function mi(a){return Na(qa(a.za),function(a){return!He(a.Y.n)})}h.kb=function(a){var b=null;v(this.za,function(c){b=b||c.kb(a)});return b};
function ni(a,b){if(He(b.n))return li(a);var c=b.wa();return z(a.za,c)}function li(a){return ua(a.za,function(a){return He(a.Y.n)})||null};function oi(a){this.va=qe;this.mb=new Pf;this.df={};this.qc={};this.Qc=a}function pi(a,b,c,d,e){var f=a.mb,g=e;O(d>f.Pc,"Stacking an older write on top of newer ones");p(g)||(g=!0);f.pa.push({path:b,Ja:c,md:d,visible:g});g&&(f.V=Jf(f.V,b,c));f.Pc=d;return e?qi(a,new Ac(Ef,b,c)):[]}function ri(a,b,c,d){var e=a.mb;O(d>e.Pc,"Stacking an older merge on top of newer ones");e.pa.push({path:b,children:c,md:d,visible:!0});e.V=Kf(e.V,b,c);e.Pc=d;c=sf(c);return qi(a,new bf(Ef,b,c))}
function si(a,b,c){c=c||!1;var d=Qf(a.mb,b);if(a.mb.Ud(b)){var e=qe;null!=d.Ja?e=e.set(M,!0):Fb(d.children,function(a,b){e=e.set(new P(a),b)});return qi(a,new Df(d.path,e,c))}return[]}function ti(a,b,c){c=sf(c);return qi(a,new bf(Gf,b,c))}function ui(a,b,c,d){d=vi(a,d);if(null!=d){var e=wi(d);d=e.path;e=e.Lb;b=lf(d,b);c=new Ac(new Ff(!1,!0,e,!0),b,c);return xi(a,d,c)}return[]}
function yi(a,b,c,d){if(d=vi(a,d)){var e=wi(d);d=e.path;e=e.Lb;b=lf(d,b);c=sf(c);c=new bf(new Ff(!1,!0,e,!0),b,c);return xi(a,d,c)}return[]}
oi.prototype.Tb=function(a,b){var c=a.path,d=null,e=!1;zf(this.va,c,function(a,b){var f=lf(a,c);d=d||b.kb(f);e=e||null!=li(b)});var f=this.va.get(c);f?(e=e||null!=li(f),d=d||f.kb(M)):(f=new ki,this.va=this.va.set(c,f));var g;null!=d?g=!0:(g=!1,d=H,Cf(this.va.subtree(c),function(a,b){var c=b.kb(M);c&&(d=d.W(a,c))}));var k=null!=ni(f,a);if(!k&&!He(a.n)){var m=zi(a);O(!(m in this.qc),"View does not exist, but we have a tag");var l=Ai++;this.qc[m]=l;this.df["_"+l]=m}g=f.Tb(a,b,new Uf(c,this.mb),d,g);
k||e||(f=ni(f,a),g=g.concat(Bi(this,a,f)));return g};
oi.prototype.nb=function(a,b,c){var d=a.path,e=this.va.get(d),f=[];if(e&&("default"===a.wa()||null!=ni(e,a))){f=e.nb(a,b,c);e.e()&&(this.va=this.va.remove(d));e=f.Wg;f=f.vg;b=-1!==Sa(e,function(a){return He(a.n)});var g=xf(this.va,d,function(a,b){return null!=li(b)});if(b&&!g&&(d=this.va.subtree(d),!d.e()))for(var d=Ci(d),k=0;k<d.length;++k){var m=d[k],l=m.Y,m=Di(this,m);this.Qc.af(Ei(l),Fi(this,l),m.Ad,m.I)}if(!g&&0<e.length&&!c)if(b)this.Qc.de(Ei(a),null);else{var t=this;Ma(e,function(a){a.wa();
var b=t.qc[zi(a)];t.Qc.de(Ei(a),b)})}Gi(this,e)}return f};oi.prototype.Aa=function(a,b){var c=this.mb,d=xf(this.va,a,function(b,c){var d=lf(b,a);if(d=c.kb(d))return d});return c.Aa(a,d,b,!0)};function Ci(a){return vf(a,function(a,c,d){if(c&&null!=li(c))return[li(c)];var e=[];c&&(e=mi(c));v(d,function(a){e=e.concat(a)});return e})}function Gi(a,b){for(var c=0;c<b.length;++c){var d=b[c];if(!He(d.n)){var d=zi(d),e=a.qc[d];delete a.qc[d];delete a.df["_"+e]}}}
function Ei(a){return He(a.n)&&!Ie(a.n)?a.Mb():a}function Bi(a,b,c){var d=b.path,e=Fi(a,b);c=Di(a,c);b=a.Qc.af(Ei(b),e,c.Ad,c.I);d=a.va.subtree(d);if(e)O(null==li(d.value),"If we're adding a query, it shouldn't be shadowed");else for(e=vf(d,function(a,b,c){if(!a.e()&&b&&null!=li(b))return[Ze(li(b))];var d=[];b&&(d=d.concat(Oa(mi(b),function(a){return a.Y})));v(c,function(a){d=d.concat(a)});return d}),d=0;d<e.length;++d)c=e[d],a.Qc.de(Ei(c),Fi(a,c));return b}
function Di(a,b){var c=b.Y,d=Fi(a,c);return{Ad:function(){return(b.w()||H).hash()},I:function(b){if("ok"===b){if(d){var f=c.path;if(b=vi(a,d)){var g=wi(b);b=g.path;g=g.Lb;f=lf(b,f);f=new Cc(new Ff(!1,!0,g,!0),f);b=xi(a,b,f)}else b=[]}else b=qi(a,new Cc(Gf,c.path));return b}f="Unknown Error";"too_big"===b?f="The data requested exceeds the maximum size that can be accessed with a single request.":"permission_denied"==b?f="Client doesn't have permission to access the desired data.":"unavailable"==b&&
(f="The service is unavailable");f=Error(b+" at "+c.path.toString()+": "+f);f.code=b.toUpperCase();return a.nb(c,null,f)}}}function zi(a){return a.path.toString()+"$"+a.wa()}function wi(a){var b=a.indexOf("$");O(-1!==b&&b<a.length-1,"Bad queryKey.");return{Lb:a.substr(b+1),path:new P(a.substr(0,b))}}function vi(a,b){var c=a.df,d="_"+b;return d in c?c[d]:void 0}function Fi(a,b){var c=zi(b);return z(a.qc,c)}var Ai=1;
function xi(a,b,c){var d=a.va.get(b);O(d,"Missing sync point for query tag that we're tracking");return d.gb(c,new Uf(b,a.mb),null)}function qi(a,b){return Hi(a,b,a.va,null,new Uf(M,a.mb))}function Hi(a,b,c,d,e){if(b.path.e())return Ii(a,b,c,d,e);var f=c.get(M);null==d&&null!=f&&(d=f.kb(M));var g=[],k=K(b.path),m=b.$c(k);if((c=c.children.get(k))&&m)var l=d?d.T(k):null,k=e.o(k),g=g.concat(Hi(a,m,c,l,k));f&&(g=g.concat(f.gb(b,e,d)));return g}
function Ii(a,b,c,d,e){var f=c.get(M);null==d&&null!=f&&(d=f.kb(M));var g=[];c.children.ka(function(c,f){var l=d?d.T(c):null,t=e.o(c),A=b.$c(c);A&&(g=g.concat(Ii(a,A,f,l,t)))});f&&(g=g.concat(f.gb(b,e,d)));return g};function Ji(a,b){this.G=a;this.Xa=uc(a);this.hd=null;this.fa=new Zb;this.Kd=1;this.Va=null;b||0<=("object"===typeof window&&window.navigator&&window.navigator.userAgent||"").search(/googlebot|google webmaster tools|bingbot|yahoo! slurp|baiduspider|yandexbot|duckduckbot/i)?(this.da=new cf(this.G,u(this.Kb,this)),setTimeout(u(this.Xc,this,!0),0)):this.da=this.Va=new Rh(this.G,u(this.Kb,this),u(this.Xc,this),u(this.Se,this));this.eh=vc(a,u(function(){return new pc(this.Xa,this.da)},this));this.yc=new Wf;
this.Ge=new Sb;var c=this;this.Fd=new oi({af:function(a,b,f,g){b=[];f=c.Ge.j(a.path);f.e()||(b=qi(c.Fd,new Ac(Gf,a.path,f)),setTimeout(function(){g("ok")},0));return b},de:aa});Ki(this,"connected",!1);this.na=new Vc;this.O=new Yg(a,u(this.da.O,this.da),u(this.da.je,this.da),u(this.Pe,this));this.ud=0;this.He=null;this.M=new oi({af:function(a,b,f,g){c.da.Cf(a,f,b,function(b,e){var f=g(b,e);dc(c.fa,a.path,f)});return[]},de:function(a,b){c.da.$f(a,b)}})}h=Ji.prototype;
h.toString=function(){return(this.G.ob?"https://":"http://")+this.G.host};h.name=function(){return this.G.lc};function Li(a){a=a.Ge.j(new P(".info/serverTimeOffset")).J()||0;return(new Date).getTime()+a}function Mi(a){a=a={timestamp:Li(a)};a.timestamp=a.timestamp||(new Date).getTime();return a}
h.Kb=function(a,b,c,d){this.ud++;var e=new P(a);b=this.He?this.He(a,b):b;a=[];d?c?(b=ma(b,function(a){return Q(a)}),a=yi(this.M,e,b,d)):(b=Q(b),a=ui(this.M,e,b,d)):c?(d=ma(b,function(a){return Q(a)}),a=ti(this.M,e,d)):(d=Q(b),a=qi(this.M,new Ac(Gf,e,d)));d=e;0<a.length&&(d=Ni(this,e));dc(this.fa,d,a)};h.Xc=function(a){Ki(this,"connected",a);!1===a&&Oi(this)};h.Se=function(a){var b=this;zd(a,function(a,d){Ki(b,d,a)})};h.Pe=function(a){Ki(this,"authenticated",a)};
function Ki(a,b,c){b=new P("/.info/"+b);c=Q(c);var d=a.Ge;d.Zd=d.Zd.H(b,c);c=qi(a.Fd,new Ac(Gf,b,c));dc(a.fa,b,c)}h.Ob=function(a,b,c,d){this.f("set",{path:a.toString(),value:b,nh:c});var e=Mi(this);b=Q(b,c);var e=Xc(b,e),f=this.Kd++,e=pi(this.M,a,e,f,!0);$b(this.fa,e);var g=this;this.da.put(a.toString(),b.J(!0),function(b,c){var e="ok"===b;e||S("set at "+a+" failed: "+b);e=si(g.M,f,!e);dc(g.fa,a,e);Pi(d,b,c)});e=Qi(this,a);Ni(this,e);dc(this.fa,e,[])};
h.update=function(a,b,c){this.f("update",{path:a.toString(),value:b});var d=!0,e=Mi(this),f={};v(b,function(a,b){d=!1;var c=Q(a);f[b]=Xc(c,e)});if(d)fc("update() called with empty data.  Don't do anything."),Pi(c,"ok");else{var g=this.Kd++,k=ri(this.M,a,f,g);$b(this.fa,k);var m=this;this.da.Df(a.toString(),b,function(b,d){var e="ok"===b;e||S("update at "+a+" failed: "+b);var e=si(m.M,g,!e),f=a;0<e.length&&(f=Ni(m,a));dc(m.fa,f,e);Pi(c,b,d)});b=Qi(this,a);Ni(this,b);dc(this.fa,a,[])}};
function Oi(a){a.f("onDisconnectEvents");var b=Mi(a),c=[];Wc(Uc(a.na,b),M,function(b,e){c=c.concat(qi(a.M,new Ac(Gf,b,e)));var f=Qi(a,b);Ni(a,f)});a.na=new Vc;dc(a.fa,M,c)}h.Md=function(a,b){var c=this;this.da.Md(a.toString(),function(d,e){"ok"===d&&wg(c.na,a);Pi(b,d,e)})};function fi(a,b,c,d){var e=Q(c);a.da.Qe(b.toString(),e.J(!0),function(c,g){"ok"===c&&a.na.rc(b,e);Pi(d,c,g)})}function gi(a,b,c,d,e){var f=Q(c,d);a.da.Qe(b.toString(),f.J(!0),function(c,d){"ok"===c&&a.na.rc(b,f);Pi(e,c,d)})}
function hi(a,b,c,d){var e=!0,f;for(f in c)e=!1;e?(fc("onDisconnect().update() called with empty data.  Don't do anything."),Pi(d,"ok")):a.da.Gf(b.toString(),c,function(e,f){if("ok"===e)for(var m in c){var l=Q(c[m]);a.na.rc(b.o(m),l)}Pi(d,e,f)})}function Ri(a,b,c){c=".info"===K(b.path)?a.Fd.Tb(b,c):a.M.Tb(b,c);bc(a.fa,b.path,c)}h.Cb=function(){this.Va&&this.Va.Cb()};h.vc=function(){this.Va&&this.Va.vc()};
h.bf=function(a){if("undefined"!==typeof console){a?(this.hd||(this.hd=new oc(this.Xa)),a=this.hd.get()):a=this.Xa.get();var b=Pa(ra(a),function(a,b){return Math.max(b.length,a)},0),c;for(c in a){for(var d=a[c],e=c.length;e<b+2;e++)c+=" ";console.log(c+d)}}};h.cf=function(a){rc(this.Xa,a);this.eh.Vf[a]=!0};h.f=function(a){var b="";this.Va&&(b=this.Va.id+":");fc(b,arguments)};
function Pi(a,b,c){a&&gc(function(){if("ok"==b)a(null);else{var d=(b||"error").toUpperCase(),e=d;c&&(e+=": "+c);e=Error(e);e.code=d;a(e)}})};function Si(a,b,c,d,e){function f(){}a.f("transaction on "+b);var g=new X(a,b);g.Ib("value",f);c={path:b,update:c,I:d,status:null,Lf:id(),gf:e,Sf:0,le:function(){g.mc("value",f)},ne:null,Da:null,rd:null,sd:null,td:null};d=a.M.Aa(b,void 0)||H;c.rd=d;d=c.update(d.J());if(p(d)){hg("transaction failed: Data returned ",d,c.path);c.status=1;e=Xf(a.yc,b);var k=e.Ea()||[];k.push(c);Yf(e,k);"object"===typeof d&&null!==d&&y(d,".priority")?(k=z(d,".priority"),O(fg(k),"Invalid priority returned by transaction. Priority must be a valid string, finite number, server value, or null.")):
k=(a.M.Aa(b)||H).C().J();e=Mi(a);d=Q(d,k);e=Xc(d,e);c.sd=d;c.td=e;c.Da=a.Kd++;c=pi(a.M,b,e,c.Da,c.gf);dc(a.fa,b,c);Ti(a)}else c.le(),c.sd=null,c.td=null,c.I&&(a=new W(c.rd,new X(a,c.path),R),c.I(null,!1,a))}function Ti(a,b){var c=b||a.yc;b||Ui(a,c);if(null!==c.Ea()){var d=Vi(a,c);O(0<d.length,"Sending zero length transaction queue");Qa(d,function(a){return 1===a.status})&&Wi(a,c.path(),d)}else c.zd()&&c.R(function(b){Ti(a,b)})}
function Wi(a,b,c){for(var d=Oa(c,function(a){return a.Da}),e=a.M.Aa(b,d)||H,d=e,e=e.hash(),f=0;f<c.length;f++){var g=c[f];O(1===g.status,"tryToSendTransactionQueue_: items in queue should all be run.");g.status=2;g.Sf++;var k=lf(b,g.path),d=d.H(k,g.sd)}d=d.J(!0);a.da.put(b.toString(),d,function(d){a.f("transaction put response",{path:b.toString(),status:d});var e=[];if("ok"===d){d=[];for(f=0;f<c.length;f++){c[f].status=3;e=e.concat(si(a.M,c[f].Da));if(c[f].I){var g=c[f].td,k=new X(a,c[f].path);d.push(u(c[f].I,
null,null,!0,new W(g,k,R)))}c[f].le()}Ui(a,Xf(a.yc,b));Ti(a);dc(a.fa,b,e);for(f=0;f<d.length;f++)gc(d[f])}else{if("datastale"===d)for(f=0;f<c.length;f++)c[f].status=4===c[f].status?5:1;else for(S("transaction at "+b.toString()+" failed: "+d),f=0;f<c.length;f++)c[f].status=5,c[f].ne=d;Ni(a,b)}},e)}function Ni(a,b){var c=Xi(a,b),d=c.path(),c=Vi(a,c);Yi(a,c,d);return d}
function Yi(a,b,c){if(0!==b.length){for(var d=[],e=[],f=Na(b,function(a){return 1===a.status}),f=Oa(f,function(a){return a.Da}),g=0;g<b.length;g++){var k=b[g],m=lf(c,k.path),l=!1,t;O(null!==m,"rerunTransactionsUnderNode_: relativePath should not be null.");if(5===k.status)l=!0,t=k.ne,e=e.concat(si(a.M,k.Da,!0));else if(1===k.status)if(25<=k.Sf)l=!0,t="maxretry",e=e.concat(si(a.M,k.Da,!0));else{var A=a.M.Aa(k.path,f)||H;k.rd=A;var I=b[g].update(A.J());p(I)?(hg("transaction failed: Data returned ",
I,k.path),m=Q(I),"object"===typeof I&&null!=I&&y(I,".priority")||(m=m.ia(A.C())),A=k.Da,I=Mi(a),I=Xc(m,I),k.sd=m,k.td=I,k.Da=a.Kd++,Ta(f,A),e=e.concat(pi(a.M,k.path,I,k.Da,k.gf)),e=e.concat(si(a.M,A,!0))):(l=!0,t="nodata",e=e.concat(si(a.M,k.Da,!0)))}dc(a.fa,c,e);e=[];l&&(b[g].status=3,setTimeout(b[g].le,Math.floor(0)),b[g].I&&("nodata"===t?(k=new X(a,b[g].path),d.push(u(b[g].I,null,null,!1,new W(b[g].rd,k,R)))):d.push(u(b[g].I,null,Error(t),!1,null))))}Ui(a,a.yc);for(g=0;g<d.length;g++)gc(d[g]);
Ti(a)}}function Xi(a,b){for(var c,d=a.yc;null!==(c=K(b))&&null===d.Ea();)d=Xf(d,c),b=N(b);return d}function Vi(a,b){var c=[];Zi(a,b,c);c.sort(function(a,b){return a.Lf-b.Lf});return c}function Zi(a,b,c){var d=b.Ea();if(null!==d)for(var e=0;e<d.length;e++)c.push(d[e]);b.R(function(b){Zi(a,b,c)})}function Ui(a,b){var c=b.Ea();if(c){for(var d=0,e=0;e<c.length;e++)3!==c[e].status&&(c[d]=c[e],d++);c.length=d;Yf(b,0<c.length?c:null)}b.R(function(b){Ui(a,b)})}
function Qi(a,b){var c=Xi(a,b).path(),d=Xf(a.yc,b);ag(d,function(b){$i(a,b)});$i(a,d);$f(d,function(b){$i(a,b)});return c}
function $i(a,b){var c=b.Ea();if(null!==c){for(var d=[],e=[],f=-1,g=0;g<c.length;g++)4!==c[g].status&&(2===c[g].status?(O(f===g-1,"All SENT items should be at beginning of queue."),f=g,c[g].status=4,c[g].ne="set"):(O(1===c[g].status,"Unexpected transaction status in abort"),c[g].le(),e=e.concat(si(a.M,c[g].Da,!0)),c[g].I&&d.push(u(c[g].I,null,Error("set"),!1,null))));-1===f?Yf(b,null):c.length=f+1;dc(a.fa,b.path(),e);for(g=0;g<d.length;g++)gc(d[g])}};function aj(){this.sc={};this.ag=!1}aj.prototype.Cb=function(){for(var a in this.sc)this.sc[a].Cb()};aj.prototype.vc=function(){for(var a in this.sc)this.sc[a].vc()};aj.prototype.ze=function(){this.ag=!0};ba(aj);aj.prototype.interrupt=aj.prototype.Cb;aj.prototype.resume=aj.prototype.vc;function Y(a,b,c,d){this.k=a;this.path=b;this.n=c;this.pc=d}
function bj(a){var b=null,c=null;a.oa&&(b=Od(a));a.ra&&(c=Rd(a));if(a.g===re){if(a.oa){if("[MIN_NAME]"!=Nd(a))throw Error("Query: When ordering by key, you may only pass one argument to startAt(), endAt(), or equalTo().");if("string"!==typeof b)throw Error("Query: When ordering by key, the argument passed to startAt(), endAt(),or equalTo() must be a string.");}if(a.ra){if("[MAX_NAME]"!=Pd(a))throw Error("Query: When ordering by key, you may only pass one argument to startAt(), endAt(), or equalTo().");if("string"!==
typeof c)throw Error("Query: When ordering by key, the argument passed to startAt(), endAt(),or equalTo() must be a string.");}}else if(a.g===R){if(null!=b&&!fg(b)||null!=c&&!fg(c))throw Error("Query: When ordering by priority, the first argument passed to startAt(), endAt(), or equalTo() must be a valid priority value (null, a number, or a string).");}else if(O(a.g instanceof ve||a.g===Be,"unknown index type."),null!=b&&"object"===typeof b||null!=c&&"object"===typeof c)throw Error("Query: First argument passed to startAt(), endAt(), or equalTo() cannot be an object.");
}function cj(a){if(a.oa&&a.ra&&a.la&&(!a.la||""===a.Rb))throw Error("Query: Can't combine startAt(), endAt(), and limit(). Use limitToFirst() or limitToLast() instead.");}function dj(a,b){if(!0===a.pc)throw Error(b+": You can't combine multiple orderBy calls.");}h=Y.prototype;h.Mb=function(){D("Query.ref",0,0,arguments.length);return new X(this.k,this.path)};
h.Ib=function(a,b,c,d){D("Query.on",2,4,arguments.length);lg("Query.on",a,!1);F("Query.on",2,b,!1);var e=ej("Query.on",c,d);if("value"===a)Ri(this.k,this,new ii(b,e.cancel||null,e.Qa||null));else{var f={};f[a]=b;Ri(this.k,this,new ji(f,e.cancel,e.Qa))}return b};
h.mc=function(a,b,c){D("Query.off",0,3,arguments.length);lg("Query.off",a,!0);F("Query.off",2,b,!0);Qb("Query.off",3,c);var d=null,e=null;"value"===a?d=new ii(b||null,null,c||null):a&&(b&&(e={},e[a]=b),d=new ji(e,null,c||null));e=this.k;d=".info"===K(this.path)?e.Fd.nb(this,d):e.M.nb(this,d);bc(e.fa,this.path,d)};
h.Pg=function(a,b){function c(k){f&&(f=!1,e.mc(a,c),b&&b.call(d.Qa,k),g.resolve(k))}D("Query.once",1,4,arguments.length);lg("Query.once",a,!1);F("Query.once",2,b,!0);var d=ej("Query.once",arguments[2],arguments[3]),e=this,f=!0,g=new B;Nb(g.D);this.Ib(a,c,function(b){e.mc(a,c);d.cancel&&d.cancel.call(d.Qa,b);g.reject(b)});return g.D};
h.Le=function(a){S("Query.limit() being deprecated. Please use Query.limitToFirst() or Query.limitToLast() instead.");D("Query.limit",1,1,arguments.length);if(!fa(a)||Math.floor(a)!==a||0>=a)throw Error("Query.limit: First argument must be a positive integer.");if(this.n.la)throw Error("Query.limit: Limit was already set (by another call to limit, limitToFirst, orlimitToLast.");var b=this.n.Le(a);cj(b);return new Y(this.k,this.path,b,this.pc)};
h.Me=function(a){D("Query.limitToFirst",1,1,arguments.length);if(!fa(a)||Math.floor(a)!==a||0>=a)throw Error("Query.limitToFirst: First argument must be a positive integer.");if(this.n.la)throw Error("Query.limitToFirst: Limit was already set (by another call to limit, limitToFirst, or limitToLast).");return new Y(this.k,this.path,this.n.Me(a),this.pc)};
h.Ne=function(a){D("Query.limitToLast",1,1,arguments.length);if(!fa(a)||Math.floor(a)!==a||0>=a)throw Error("Query.limitToLast: First argument must be a positive integer.");if(this.n.la)throw Error("Query.limitToLast: Limit was already set (by another call to limit, limitToFirst, or limitToLast).");return new Y(this.k,this.path,this.n.Ne(a),this.pc)};
h.Qg=function(a){D("Query.orderByChild",1,1,arguments.length);if("$key"===a)throw Error('Query.orderByChild: "$key" is invalid.  Use Query.orderByKey() instead.');if("$priority"===a)throw Error('Query.orderByChild: "$priority" is invalid.  Use Query.orderByPriority() instead.');if("$value"===a)throw Error('Query.orderByChild: "$value" is invalid.  Use Query.orderByValue() instead.');ng("Query.orderByChild",a);dj(this,"Query.orderByChild");var b=new P(a);if(b.e())throw Error("Query.orderByChild: cannot pass in empty path.  Use Query.orderByValue() instead.");
b=new ve(b);b=Fe(this.n,b);bj(b);return new Y(this.k,this.path,b,!0)};h.Rg=function(){D("Query.orderByKey",0,0,arguments.length);dj(this,"Query.orderByKey");var a=Fe(this.n,re);bj(a);return new Y(this.k,this.path,a,!0)};h.Sg=function(){D("Query.orderByPriority",0,0,arguments.length);dj(this,"Query.orderByPriority");var a=Fe(this.n,R);bj(a);return new Y(this.k,this.path,a,!0)};
h.Tg=function(){D("Query.orderByValue",0,0,arguments.length);dj(this,"Query.orderByValue");var a=Fe(this.n,Be);bj(a);return new Y(this.k,this.path,a,!0)};h.ce=function(a,b){D("Query.startAt",0,2,arguments.length);gg("Query.startAt",a,this.path,!0);mg("Query.startAt",b);var c=this.n.ce(a,b);cj(c);bj(c);if(this.n.oa)throw Error("Query.startAt: Starting point was already set (by another call to startAt or equalTo).");p(a)||(b=a=null);return new Y(this.k,this.path,c,this.pc)};
h.vd=function(a,b){D("Query.endAt",0,2,arguments.length);gg("Query.endAt",a,this.path,!0);mg("Query.endAt",b);var c=this.n.vd(a,b);cj(c);bj(c);if(this.n.ra)throw Error("Query.endAt: Ending point was already set (by another call to endAt or equalTo).");return new Y(this.k,this.path,c,this.pc)};
h.tg=function(a,b){D("Query.equalTo",1,2,arguments.length);gg("Query.equalTo",a,this.path,!1);mg("Query.equalTo",b);if(this.n.oa)throw Error("Query.equalTo: Starting point was already set (by another call to endAt or equalTo).");if(this.n.ra)throw Error("Query.equalTo: Ending point was already set (by another call to endAt or equalTo).");return this.ce(a,b).vd(a,b)};
h.toString=function(){D("Query.toString",0,0,arguments.length);for(var a=this.path,b="",c=a.aa;c<a.u.length;c++)""!==a.u[c]&&(b+="/"+encodeURIComponent(String(a.u[c])));return this.k.toString()+(b||"/")};h.wa=function(){var a=xd(Ge(this.n));return"{}"===a?"default":a};
function ej(a,b,c){var d={cancel:null,Qa:null};if(b&&c)d.cancel=b,F(a,3,d.cancel,!0),d.Qa=c,Qb(a,4,d.Qa);else if(b)if("object"===typeof b&&null!==b)d.Qa=b;else if("function"===typeof b)d.cancel=b;else throw Error(E(a,3,!0)+" must either be a cancel callback or a context object.");return d}Y.prototype.ref=Y.prototype.Mb;Y.prototype.on=Y.prototype.Ib;Y.prototype.off=Y.prototype.mc;Y.prototype.once=Y.prototype.Pg;Y.prototype.limit=Y.prototype.Le;Y.prototype.limitToFirst=Y.prototype.Me;
Y.prototype.limitToLast=Y.prototype.Ne;Y.prototype.orderByChild=Y.prototype.Qg;Y.prototype.orderByKey=Y.prototype.Rg;Y.prototype.orderByPriority=Y.prototype.Sg;Y.prototype.orderByValue=Y.prototype.Tg;Y.prototype.startAt=Y.prototype.ce;Y.prototype.endAt=Y.prototype.vd;Y.prototype.equalTo=Y.prototype.tg;Y.prototype.toString=Y.prototype.toString;var Z={};Z.zc=Rh;Z.DataConnection=Z.zc;Rh.prototype.dh=function(a,b){this.Ia("q",{p:a},b)};Z.zc.prototype.simpleListen=Z.zc.prototype.dh;Rh.prototype.sg=function(a,b){this.Ia("echo",{d:a},b)};Z.zc.prototype.echo=Z.zc.prototype.sg;Rh.prototype.interrupt=Rh.prototype.Cb;Z.dg=Fh;Z.RealTimeConnection=Z.dg;Fh.prototype.sendRequest=Fh.prototype.Ia;Fh.prototype.close=Fh.prototype.close;
Z.Cg=function(a){var b=Rh.prototype.put;Rh.prototype.put=function(c,d,e,f){p(f)&&(f=a());b.call(this,c,d,e,f)};return function(){Rh.prototype.put=b}};Z.hijackHash=Z.Cg;Z.cg=dd;Z.ConnectionTarget=Z.cg;Z.wa=function(a){return a.wa()};Z.queryIdentifier=Z.wa;Z.Fg=function(a){return a.k.Va.ba};Z.listens=Z.Fg;Z.ze=function(a){a.ze()};Z.forceRestClient=Z.ze;function X(a,b){var c,d,e;if(a instanceof Ji)c=a,d=b;else{D("new Firebase",1,2,arguments.length);d=sd(arguments[0]);c=d.fh;"firebase"===d.domain&&rd(d.host+" is no longer supported. Please use <YOUR FIREBASE>.firebaseio.com instead");c&&"undefined"!=c||rd("Cannot parse Firebase url. Please use https://<YOUR FIREBASE>.firebaseio.com");d.ob||"undefined"!==typeof window&&window.location&&window.location.protocol&&-1!==window.location.protocol.indexOf("https:")&&S("Insecure Firebase access from a secure page. Please use https in calls to new Firebase().");
c=new dd(d.host,d.ob,c,"ws"===d.scheme||"wss"===d.scheme);d=new P(d.bd);e=d.toString();var f;!(f=!q(c.host)||0===c.host.length||!eg(c.lc))&&(f=0!==e.length)&&(e&&(e=e.replace(/^\/*\.info(\/|$)/,"/")),f=!(q(e)&&0!==e.length&&!cg.test(e)));if(f)throw Error(E("new Firebase",1,!1)+'must be a valid firebase URL and the path can\'t contain ".", "#", "$", "[", or "]".');if(b)if(b instanceof aj)e=b;else if(q(b))e=aj.yb(),c.Rd=b;else throw Error("Expected a valid Firebase.Context for second argument to new Firebase()");
else e=aj.yb();f=c.toString();var g=z(e.sc,f);g||(g=new Ji(c,e.ag),e.sc[f]=g);c=g}Y.call(this,c,d,De,!1);this.then=void 0;this["catch"]=void 0}ka(X,Y);var fj=X,gj=["Firebase"],hj=n;gj[0]in hj||!hj.execScript||hj.execScript("var "+gj[0]);for(var ij;gj.length&&(ij=gj.shift());)!gj.length&&p(fj)?hj[ij]=fj:hj=hj[ij]?hj[ij]:hj[ij]={};X.goOffline=function(){D("Firebase.goOffline",0,0,arguments.length);aj.yb().Cb()};X.goOnline=function(){D("Firebase.goOnline",0,0,arguments.length);aj.yb().vc()};
X.enableLogging=od;X.ServerValue={TIMESTAMP:{".sv":"timestamp"}};X.SDK_VERSION=Eb;X.INTERNAL=U;X.Context=aj;X.TEST_ACCESS=Z;X.prototype.name=function(){S("Firebase.name() being deprecated. Please use Firebase.key() instead.");D("Firebase.name",0,0,arguments.length);return this.key()};X.prototype.name=X.prototype.name;X.prototype.key=function(){D("Firebase.key",0,0,arguments.length);return this.path.e()?null:me(this.path)};X.prototype.key=X.prototype.key;
X.prototype.o=function(a){D("Firebase.child",1,1,arguments.length);if(fa(a))a=String(a);else if(!(a instanceof P))if(null===K(this.path)){var b=a;b&&(b=b.replace(/^\/*\.info(\/|$)/,"/"));ng("Firebase.child",b)}else ng("Firebase.child",a);return new X(this.k,this.path.o(a))};X.prototype.child=X.prototype.o;X.prototype.parent=function(){D("Firebase.parent",0,0,arguments.length);var a=this.path.parent();return null===a?null:new X(this.k,a)};X.prototype.parent=X.prototype.parent;
X.prototype.root=function(){D("Firebase.ref",0,0,arguments.length);for(var a=this;null!==a.parent();)a=a.parent();return a};X.prototype.root=X.prototype.root;X.prototype.set=function(a,b){D("Firebase.set",1,2,arguments.length);og("Firebase.set",this.path);gg("Firebase.set",a,this.path,!1);F("Firebase.set",2,b,!0);var c=new B;this.k.Ob(this.path,a,null,C(c,b));return c.D};X.prototype.set=X.prototype.set;
X.prototype.update=function(a,b){D("Firebase.update",1,2,arguments.length);og("Firebase.update",this.path);if(da(a)){for(var c={},d=0;d<a.length;++d)c[""+d]=a[d];a=c;S("Passing an Array to Firebase.update() is deprecated. Use set() if you want to overwrite the existing data, or an Object with integer keys if you really do want to only update some of the children.")}jg("Firebase.update",a,this.path);F("Firebase.update",2,b,!0);c=new B;this.k.update(this.path,a,C(c,b));return c.D};
X.prototype.update=X.prototype.update;X.prototype.Ob=function(a,b,c){D("Firebase.setWithPriority",2,3,arguments.length);og("Firebase.setWithPriority",this.path);gg("Firebase.setWithPriority",a,this.path,!1);kg("Firebase.setWithPriority",2,b);F("Firebase.setWithPriority",3,c,!0);if(".length"===this.key()||".keys"===this.key())throw"Firebase.setWithPriority failed: "+this.key()+" is a read-only object.";var d=new B;this.k.Ob(this.path,a,b,C(d,c));return d.D};X.prototype.setWithPriority=X.prototype.Ob;
X.prototype.remove=function(a){D("Firebase.remove",0,1,arguments.length);og("Firebase.remove",this.path);F("Firebase.remove",1,a,!0);return this.set(null,a)};X.prototype.remove=X.prototype.remove;
X.prototype.transaction=function(a,b,c){D("Firebase.transaction",1,3,arguments.length);og("Firebase.transaction",this.path);F("Firebase.transaction",1,a,!1);F("Firebase.transaction",2,b,!0);if(p(c)&&"boolean"!=typeof c)throw Error(E("Firebase.transaction",3,!0)+"must be a boolean.");if(".length"===this.key()||".keys"===this.key())throw"Firebase.transaction failed: "+this.key()+" is a read-only object.";"undefined"===typeof c&&(c=!0);var d=new B;r(b)&&Nb(d.D);Si(this.k,this.path,a,function(a,c,g){a?
d.reject(a):d.resolve(new ei(c,g));r(b)&&b(a,c,g)},c);return d.D};X.prototype.transaction=X.prototype.transaction;X.prototype.$g=function(a,b){D("Firebase.setPriority",1,2,arguments.length);og("Firebase.setPriority",this.path);kg("Firebase.setPriority",1,a);F("Firebase.setPriority",2,b,!0);var c=new B;this.k.Ob(this.path.o(".priority"),a,null,C(c,b));return c.D};X.prototype.setPriority=X.prototype.$g;
X.prototype.push=function(a,b){D("Firebase.push",0,2,arguments.length);og("Firebase.push",this.path);gg("Firebase.push",a,this.path,!0);F("Firebase.push",2,b,!0);var c=Li(this.k),d=hf(c),c=this.o(d);if(null!=a){var e=this,f=c.set(a,b).then(function(){return e.o(d)});c.then=u(f.then,f);c["catch"]=u(f.then,f,void 0);r(b)&&Nb(f)}return c};X.prototype.push=X.prototype.push;X.prototype.lb=function(){og("Firebase.onDisconnect",this.path);return new V(this.k,this.path)};X.prototype.onDisconnect=X.prototype.lb;
X.prototype.O=function(a,b,c){S("FirebaseRef.auth() being deprecated. Please use FirebaseRef.authWithCustomToken() instead.");D("Firebase.auth",1,3,arguments.length);pg("Firebase.auth",a);F("Firebase.auth",2,b,!0);F("Firebase.auth",3,b,!0);var d=new B;dh(this.k.O,a,{},{remember:"none"},C(d,b),c);return d.D};X.prototype.auth=X.prototype.O;X.prototype.je=function(a){D("Firebase.unauth",0,1,arguments.length);F("Firebase.unauth",1,a,!0);var b=new B;eh(this.k.O,C(b,a));return b.D};X.prototype.unauth=X.prototype.je;
X.prototype.Be=function(){D("Firebase.getAuth",0,0,arguments.length);return this.k.O.Be()};X.prototype.getAuth=X.prototype.Be;X.prototype.Jg=function(a,b){D("Firebase.onAuth",1,2,arguments.length);F("Firebase.onAuth",1,a,!1);Qb("Firebase.onAuth",2,b);this.k.O.Ib("auth_status",a,b)};X.prototype.onAuth=X.prototype.Jg;X.prototype.Ig=function(a,b){D("Firebase.offAuth",1,2,arguments.length);F("Firebase.offAuth",1,a,!1);Qb("Firebase.offAuth",2,b);this.k.O.mc("auth_status",a,b)};X.prototype.offAuth=X.prototype.Ig;
X.prototype.hg=function(a,b,c){D("Firebase.authWithCustomToken",1,3,arguments.length);2===arguments.length&&Hb(b)&&(c=b,b=void 0);pg("Firebase.authWithCustomToken",a);F("Firebase.authWithCustomToken",2,b,!0);sg("Firebase.authWithCustomToken",3,c,!0);var d=new B;dh(this.k.O,a,{},c||{},C(d,b));return d.D};X.prototype.authWithCustomToken=X.prototype.hg;
X.prototype.ig=function(a,b,c){D("Firebase.authWithOAuthPopup",1,3,arguments.length);2===arguments.length&&Hb(b)&&(c=b,b=void 0);rg("Firebase.authWithOAuthPopup",a);F("Firebase.authWithOAuthPopup",2,b,!0);sg("Firebase.authWithOAuthPopup",3,c,!0);var d=new B;ih(this.k.O,a,c,C(d,b));return d.D};X.prototype.authWithOAuthPopup=X.prototype.ig;
X.prototype.jg=function(a,b,c){D("Firebase.authWithOAuthRedirect",1,3,arguments.length);2===arguments.length&&Hb(b)&&(c=b,b=void 0);rg("Firebase.authWithOAuthRedirect",a);F("Firebase.authWithOAuthRedirect",2,b,!1);sg("Firebase.authWithOAuthRedirect",3,c,!0);var d=new B,e=this.k.O,f=c,g=C(d,b);gh(e);var k=[Qg],f=Ag(f);"anonymous"===a||"firebase"===a?T(g,Sg("TRANSPORT_UNAVAILABLE")):(cd.set("redirect_client_options",f.qd),hh(e,k,"/auth/"+a,f,g));return d.D};X.prototype.authWithOAuthRedirect=X.prototype.jg;
X.prototype.kg=function(a,b,c,d){D("Firebase.authWithOAuthToken",2,4,arguments.length);3===arguments.length&&Hb(c)&&(d=c,c=void 0);rg("Firebase.authWithOAuthToken",a);F("Firebase.authWithOAuthToken",3,c,!0);sg("Firebase.authWithOAuthToken",4,d,!0);var e=new B;q(b)?(qg("Firebase.authWithOAuthToken",2,b),fh(this.k.O,a+"/token",{access_token:b},d,C(e,c))):(sg("Firebase.authWithOAuthToken",2,b,!1),fh(this.k.O,a+"/token",b,d,C(e,c)));return e.D};X.prototype.authWithOAuthToken=X.prototype.kg;
X.prototype.gg=function(a,b){D("Firebase.authAnonymously",0,2,arguments.length);1===arguments.length&&Hb(a)&&(b=a,a=void 0);F("Firebase.authAnonymously",1,a,!0);sg("Firebase.authAnonymously",2,b,!0);var c=new B;fh(this.k.O,"anonymous",{},b,C(c,a));return c.D};X.prototype.authAnonymously=X.prototype.gg;
X.prototype.lg=function(a,b,c){D("Firebase.authWithPassword",1,3,arguments.length);2===arguments.length&&Hb(b)&&(c=b,b=void 0);sg("Firebase.authWithPassword",1,a,!1);tg("Firebase.authWithPassword",a,"email");tg("Firebase.authWithPassword",a,"password");F("Firebase.authWithPassword",2,b,!0);sg("Firebase.authWithPassword",3,c,!0);var d=new B;fh(this.k.O,"password",a,c,C(d,b));return d.D};X.prototype.authWithPassword=X.prototype.lg;
X.prototype.ve=function(a,b){D("Firebase.createUser",1,2,arguments.length);sg("Firebase.createUser",1,a,!1);tg("Firebase.createUser",a,"email");tg("Firebase.createUser",a,"password");F("Firebase.createUser",2,b,!0);var c=new B;this.k.O.ve(a,C(c,b));return c.D};X.prototype.createUser=X.prototype.ve;
X.prototype.Xe=function(a,b){D("Firebase.removeUser",1,2,arguments.length);sg("Firebase.removeUser",1,a,!1);tg("Firebase.removeUser",a,"email");tg("Firebase.removeUser",a,"password");F("Firebase.removeUser",2,b,!0);var c=new B;this.k.O.Xe(a,C(c,b));return c.D};X.prototype.removeUser=X.prototype.Xe;
X.prototype.se=function(a,b){D("Firebase.changePassword",1,2,arguments.length);sg("Firebase.changePassword",1,a,!1);tg("Firebase.changePassword",a,"email");tg("Firebase.changePassword",a,"oldPassword");tg("Firebase.changePassword",a,"newPassword");F("Firebase.changePassword",2,b,!0);var c=new B;this.k.O.se(a,C(c,b));return c.D};X.prototype.changePassword=X.prototype.se;
X.prototype.re=function(a,b){D("Firebase.changeEmail",1,2,arguments.length);sg("Firebase.changeEmail",1,a,!1);tg("Firebase.changeEmail",a,"oldEmail");tg("Firebase.changeEmail",a,"newEmail");tg("Firebase.changeEmail",a,"password");F("Firebase.changeEmail",2,b,!0);var c=new B;this.k.O.re(a,C(c,b));return c.D};X.prototype.changeEmail=X.prototype.re;
X.prototype.Ze=function(a,b){D("Firebase.resetPassword",1,2,arguments.length);sg("Firebase.resetPassword",1,a,!1);tg("Firebase.resetPassword",a,"email");F("Firebase.resetPassword",2,b,!0);var c=new B;this.k.O.Ze(a,C(c,b));return c.D};X.prototype.resetPassword=X.prototype.Ze;})();

module.exports = Firebase;


/***/ }),

/***/ "./node_modules/inherits/inherits_browser.js":
/*!***************************************************!*\
  !*** ./node_modules/inherits/inherits_browser.js ***!
  \***************************************************/
/*! no static exports found */
/***/ (function(module, exports) {

if (typeof Object.create === 'function') {
  // implementation from standard node.js 'util' module
  module.exports = function inherits(ctor, superCtor) {
    ctor.super_ = superCtor
    ctor.prototype = Object.create(superCtor.prototype, {
      constructor: {
        value: ctor,
        enumerable: false,
        writable: true,
        configurable: true
      }
    });
  };
} else {
  // old school shim for old browsers
  module.exports = function inherits(ctor, superCtor) {
    ctor.super_ = superCtor
    var TempCtor = function () {}
    TempCtor.prototype = superCtor.prototype
    ctor.prototype = new TempCtor()
    ctor.prototype.constructor = ctor
  }
}


/***/ }),

/***/ "./node_modules/lru-cache/index.js":
/*!*****************************************!*\
  !*** ./node_modules/lru-cache/index.js ***!
  \*****************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


module.exports = LRUCache

// This will be a proper iterable 'Map' in engines that support it,
// or a fakey-fake PseudoMap in older versions.
var Map = __webpack_require__(/*! pseudomap */ "./node_modules/pseudomap/map.js")
var util = __webpack_require__(/*! util */ "./node_modules/util/util.js")

// A linked list to keep track of recently-used-ness
var Yallist = __webpack_require__(/*! yallist */ "./node_modules/yallist/yallist.js")

// use symbols if possible, otherwise just _props
var hasSymbol = typeof Symbol === 'function'
var makeSymbol
if (hasSymbol) {
  makeSymbol = function (key) {
    return Symbol(key)
  }
} else {
  makeSymbol = function (key) {
    return '_' + key
  }
}

var MAX = makeSymbol('max')
var LENGTH = makeSymbol('length')
var LENGTH_CALCULATOR = makeSymbol('lengthCalculator')
var ALLOW_STALE = makeSymbol('allowStale')
var MAX_AGE = makeSymbol('maxAge')
var DISPOSE = makeSymbol('dispose')
var NO_DISPOSE_ON_SET = makeSymbol('noDisposeOnSet')
var LRU_LIST = makeSymbol('lruList')
var CACHE = makeSymbol('cache')

function naiveLength () { return 1 }

// lruList is a yallist where the head is the youngest
// item, and the tail is the oldest.  the list contains the Hit
// objects as the entries.
// Each Hit object has a reference to its Yallist.Node.  This
// never changes.
//
// cache is a Map (or PseudoMap) that matches the keys to
// the Yallist.Node object.
function LRUCache (options) {
  if (!(this instanceof LRUCache)) {
    return new LRUCache(options)
  }

  if (typeof options === 'number') {
    options = { max: options }
  }

  if (!options) {
    options = {}
  }

  var max = this[MAX] = options.max
  // Kind of weird to have a default max of Infinity, but oh well.
  if (!max ||
      !(typeof max === 'number') ||
      max <= 0) {
    this[MAX] = Infinity
  }

  var lc = options.length || naiveLength
  if (typeof lc !== 'function') {
    lc = naiveLength
  }
  this[LENGTH_CALCULATOR] = lc

  this[ALLOW_STALE] = options.stale || false
  this[MAX_AGE] = options.maxAge || 0
  this[DISPOSE] = options.dispose
  this[NO_DISPOSE_ON_SET] = options.noDisposeOnSet || false
  this.reset()
}

// resize the cache when the max changes.
Object.defineProperty(LRUCache.prototype, 'max', {
  set: function (mL) {
    if (!mL || !(typeof mL === 'number') || mL <= 0) {
      mL = Infinity
    }
    this[MAX] = mL
    trim(this)
  },
  get: function () {
    return this[MAX]
  },
  enumerable: true
})

Object.defineProperty(LRUCache.prototype, 'allowStale', {
  set: function (allowStale) {
    this[ALLOW_STALE] = !!allowStale
  },
  get: function () {
    return this[ALLOW_STALE]
  },
  enumerable: true
})

Object.defineProperty(LRUCache.prototype, 'maxAge', {
  set: function (mA) {
    if (!mA || !(typeof mA === 'number') || mA < 0) {
      mA = 0
    }
    this[MAX_AGE] = mA
    trim(this)
  },
  get: function () {
    return this[MAX_AGE]
  },
  enumerable: true
})

// resize the cache when the lengthCalculator changes.
Object.defineProperty(LRUCache.prototype, 'lengthCalculator', {
  set: function (lC) {
    if (typeof lC !== 'function') {
      lC = naiveLength
    }
    if (lC !== this[LENGTH_CALCULATOR]) {
      this[LENGTH_CALCULATOR] = lC
      this[LENGTH] = 0
      this[LRU_LIST].forEach(function (hit) {
        hit.length = this[LENGTH_CALCULATOR](hit.value, hit.key)
        this[LENGTH] += hit.length
      }, this)
    }
    trim(this)
  },
  get: function () { return this[LENGTH_CALCULATOR] },
  enumerable: true
})

Object.defineProperty(LRUCache.prototype, 'length', {
  get: function () { return this[LENGTH] },
  enumerable: true
})

Object.defineProperty(LRUCache.prototype, 'itemCount', {
  get: function () { return this[LRU_LIST].length },
  enumerable: true
})

LRUCache.prototype.rforEach = function (fn, thisp) {
  thisp = thisp || this
  for (var walker = this[LRU_LIST].tail; walker !== null;) {
    var prev = walker.prev
    forEachStep(this, fn, walker, thisp)
    walker = prev
  }
}

function forEachStep (self, fn, node, thisp) {
  var hit = node.value
  if (isStale(self, hit)) {
    del(self, node)
    if (!self[ALLOW_STALE]) {
      hit = undefined
    }
  }
  if (hit) {
    fn.call(thisp, hit.value, hit.key, self)
  }
}

LRUCache.prototype.forEach = function (fn, thisp) {
  thisp = thisp || this
  for (var walker = this[LRU_LIST].head; walker !== null;) {
    var next = walker.next
    forEachStep(this, fn, walker, thisp)
    walker = next
  }
}

LRUCache.prototype.keys = function () {
  return this[LRU_LIST].toArray().map(function (k) {
    return k.key
  }, this)
}

LRUCache.prototype.values = function () {
  return this[LRU_LIST].toArray().map(function (k) {
    return k.value
  }, this)
}

LRUCache.prototype.reset = function () {
  if (this[DISPOSE] &&
      this[LRU_LIST] &&
      this[LRU_LIST].length) {
    this[LRU_LIST].forEach(function (hit) {
      this[DISPOSE](hit.key, hit.value)
    }, this)
  }

  this[CACHE] = new Map() // hash of items by key
  this[LRU_LIST] = new Yallist() // list of items in order of use recency
  this[LENGTH] = 0 // length of items in the list
}

LRUCache.prototype.dump = function () {
  return this[LRU_LIST].map(function (hit) {
    if (!isStale(this, hit)) {
      return {
        k: hit.key,
        v: hit.value,
        e: hit.now + (hit.maxAge || 0)
      }
    }
  }, this).toArray().filter(function (h) {
    return h
  })
}

LRUCache.prototype.dumpLru = function () {
  return this[LRU_LIST]
}

LRUCache.prototype.inspect = function (n, opts) {
  var str = 'LRUCache {'
  var extras = false

  var as = this[ALLOW_STALE]
  if (as) {
    str += '\n  allowStale: true'
    extras = true
  }

  var max = this[MAX]
  if (max && max !== Infinity) {
    if (extras) {
      str += ','
    }
    str += '\n  max: ' + util.inspect(max, opts)
    extras = true
  }

  var maxAge = this[MAX_AGE]
  if (maxAge) {
    if (extras) {
      str += ','
    }
    str += '\n  maxAge: ' + util.inspect(maxAge, opts)
    extras = true
  }

  var lc = this[LENGTH_CALCULATOR]
  if (lc && lc !== naiveLength) {
    if (extras) {
      str += ','
    }
    str += '\n  length: ' + util.inspect(this[LENGTH], opts)
    extras = true
  }

  var didFirst = false
  this[LRU_LIST].forEach(function (item) {
    if (didFirst) {
      str += ',\n  '
    } else {
      if (extras) {
        str += ',\n'
      }
      didFirst = true
      str += '\n  '
    }
    var key = util.inspect(item.key).split('\n').join('\n  ')
    var val = { value: item.value }
    if (item.maxAge !== maxAge) {
      val.maxAge = item.maxAge
    }
    if (lc !== naiveLength) {
      val.length = item.length
    }
    if (isStale(this, item)) {
      val.stale = true
    }

    val = util.inspect(val, opts).split('\n').join('\n  ')
    str += key + ' => ' + val
  })

  if (didFirst || extras) {
    str += '\n'
  }
  str += '}'

  return str
}

LRUCache.prototype.set = function (key, value, maxAge) {
  maxAge = maxAge || this[MAX_AGE]

  var now = maxAge ? Date.now() : 0
  var len = this[LENGTH_CALCULATOR](value, key)

  if (this[CACHE].has(key)) {
    if (len > this[MAX]) {
      del(this, this[CACHE].get(key))
      return false
    }

    var node = this[CACHE].get(key)
    var item = node.value

    // dispose of the old one before overwriting
    // split out into 2 ifs for better coverage tracking
    if (this[DISPOSE]) {
      if (!this[NO_DISPOSE_ON_SET]) {
        this[DISPOSE](key, item.value)
      }
    }

    item.now = now
    item.maxAge = maxAge
    item.value = value
    this[LENGTH] += len - item.length
    item.length = len
    this.get(key)
    trim(this)
    return true
  }

  var hit = new Entry(key, value, len, now, maxAge)

  // oversized objects fall out of cache automatically.
  if (hit.length > this[MAX]) {
    if (this[DISPOSE]) {
      this[DISPOSE](key, value)
    }
    return false
  }

  this[LENGTH] += hit.length
  this[LRU_LIST].unshift(hit)
  this[CACHE].set(key, this[LRU_LIST].head)
  trim(this)
  return true
}

LRUCache.prototype.has = function (key) {
  if (!this[CACHE].has(key)) return false
  var hit = this[CACHE].get(key).value
  if (isStale(this, hit)) {
    return false
  }
  return true
}

LRUCache.prototype.get = function (key) {
  return get(this, key, true)
}

LRUCache.prototype.peek = function (key) {
  return get(this, key, false)
}

LRUCache.prototype.pop = function () {
  var node = this[LRU_LIST].tail
  if (!node) return null
  del(this, node)
  return node.value
}

LRUCache.prototype.del = function (key) {
  del(this, this[CACHE].get(key))
}

LRUCache.prototype.load = function (arr) {
  // reset the cache
  this.reset()

  var now = Date.now()
  // A previous serialized cache has the most recent items first
  for (var l = arr.length - 1; l >= 0; l--) {
    var hit = arr[l]
    var expiresAt = hit.e || 0
    if (expiresAt === 0) {
      // the item was created without expiration in a non aged cache
      this.set(hit.k, hit.v)
    } else {
      var maxAge = expiresAt - now
      // dont add already expired items
      if (maxAge > 0) {
        this.set(hit.k, hit.v, maxAge)
      }
    }
  }
}

LRUCache.prototype.prune = function () {
  var self = this
  this[CACHE].forEach(function (value, key) {
    get(self, key, false)
  })
}

function get (self, key, doUse) {
  var node = self[CACHE].get(key)
  if (node) {
    var hit = node.value
    if (isStale(self, hit)) {
      del(self, node)
      if (!self[ALLOW_STALE]) hit = undefined
    } else {
      if (doUse) {
        self[LRU_LIST].unshiftNode(node)
      }
    }
    if (hit) hit = hit.value
  }
  return hit
}

function isStale (self, hit) {
  if (!hit || (!hit.maxAge && !self[MAX_AGE])) {
    return false
  }
  var stale = false
  var diff = Date.now() - hit.now
  if (hit.maxAge) {
    stale = diff > hit.maxAge
  } else {
    stale = self[MAX_AGE] && (diff > self[MAX_AGE])
  }
  return stale
}

function trim (self) {
  if (self[LENGTH] > self[MAX]) {
    for (var walker = self[LRU_LIST].tail;
         self[LENGTH] > self[MAX] && walker !== null;) {
      // We know that we're about to delete this one, and also
      // what the next least recently used key will be, so just
      // go ahead and set it now.
      var prev = walker.prev
      del(self, walker)
      walker = prev
    }
  }
}

function del (self, node) {
  if (node) {
    var hit = node.value
    if (self[DISPOSE]) {
      self[DISPOSE](hit.key, hit.value)
    }
    self[LENGTH] -= hit.length
    self[CACHE].delete(hit.key)
    self[LRU_LIST].removeNode(node)
  }
}

// classy, since V8 prefers predictable objects.
function Entry (key, value, length, now, maxAge) {
  this.key = key
  this.value = value
  this.length = length
  this.now = now
  this.maxAge = maxAge || 0
}


/***/ }),

/***/ "./node_modules/process/browser.js":
/*!*****************************************!*\
  !*** ./node_modules/process/browser.js ***!
  \*****************************************/
/*! no static exports found */
/***/ (function(module, exports) {

// shim for using process in browser
var process = module.exports = {};

// cached from whatever global is present so that test runners that stub it
// don't break things.  But we need to wrap it in a try catch in case it is
// wrapped in strict mode code which doesn't define any globals.  It's inside a
// function because try/catches deoptimize in certain engines.

var cachedSetTimeout;
var cachedClearTimeout;

function defaultSetTimout() {
    throw new Error('setTimeout has not been defined');
}
function defaultClearTimeout () {
    throw new Error('clearTimeout has not been defined');
}
(function () {
    try {
        if (typeof setTimeout === 'function') {
            cachedSetTimeout = setTimeout;
        } else {
            cachedSetTimeout = defaultSetTimout;
        }
    } catch (e) {
        cachedSetTimeout = defaultSetTimout;
    }
    try {
        if (typeof clearTimeout === 'function') {
            cachedClearTimeout = clearTimeout;
        } else {
            cachedClearTimeout = defaultClearTimeout;
        }
    } catch (e) {
        cachedClearTimeout = defaultClearTimeout;
    }
} ())
function runTimeout(fun) {
    if (cachedSetTimeout === setTimeout) {
        //normal enviroments in sane situations
        return setTimeout(fun, 0);
    }
    // if setTimeout wasn't available but was latter defined
    if ((cachedSetTimeout === defaultSetTimout || !cachedSetTimeout) && setTimeout) {
        cachedSetTimeout = setTimeout;
        return setTimeout(fun, 0);
    }
    try {
        // when when somebody has screwed with setTimeout but no I.E. maddness
        return cachedSetTimeout(fun, 0);
    } catch(e){
        try {
            // When we are in I.E. but the script has been evaled so I.E. doesn't trust the global object when called normally
            return cachedSetTimeout.call(null, fun, 0);
        } catch(e){
            // same as above but when it's a version of I.E. that must have the global object for 'this', hopfully our context correct otherwise it will throw a global error
            return cachedSetTimeout.call(this, fun, 0);
        }
    }


}
function runClearTimeout(marker) {
    if (cachedClearTimeout === clearTimeout) {
        //normal enviroments in sane situations
        return clearTimeout(marker);
    }
    // if clearTimeout wasn't available but was latter defined
    if ((cachedClearTimeout === defaultClearTimeout || !cachedClearTimeout) && clearTimeout) {
        cachedClearTimeout = clearTimeout;
        return clearTimeout(marker);
    }
    try {
        // when when somebody has screwed with setTimeout but no I.E. maddness
        return cachedClearTimeout(marker);
    } catch (e){
        try {
            // When we are in I.E. but the script has been evaled so I.E. doesn't  trust the global object when called normally
            return cachedClearTimeout.call(null, marker);
        } catch (e){
            // same as above but when it's a version of I.E. that must have the global object for 'this', hopfully our context correct otherwise it will throw a global error.
            // Some versions of I.E. have different rules for clearTimeout vs setTimeout
            return cachedClearTimeout.call(this, marker);
        }
    }



}
var queue = [];
var draining = false;
var currentQueue;
var queueIndex = -1;

function cleanUpNextTick() {
    if (!draining || !currentQueue) {
        return;
    }
    draining = false;
    if (currentQueue.length) {
        queue = currentQueue.concat(queue);
    } else {
        queueIndex = -1;
    }
    if (queue.length) {
        drainQueue();
    }
}

function drainQueue() {
    if (draining) {
        return;
    }
    var timeout = runTimeout(cleanUpNextTick);
    draining = true;

    var len = queue.length;
    while(len) {
        currentQueue = queue;
        queue = [];
        while (++queueIndex < len) {
            if (currentQueue) {
                currentQueue[queueIndex].run();
            }
        }
        queueIndex = -1;
        len = queue.length;
    }
    currentQueue = null;
    draining = false;
    runClearTimeout(timeout);
}

process.nextTick = function (fun) {
    var args = new Array(arguments.length - 1);
    if (arguments.length > 1) {
        for (var i = 1; i < arguments.length; i++) {
            args[i - 1] = arguments[i];
        }
    }
    queue.push(new Item(fun, args));
    if (queue.length === 1 && !draining) {
        runTimeout(drainQueue);
    }
};

// v8 likes predictible objects
function Item(fun, array) {
    this.fun = fun;
    this.array = array;
}
Item.prototype.run = function () {
    this.fun.apply(null, this.array);
};
process.title = 'browser';
process.browser = true;
process.env = {};
process.argv = [];
process.version = ''; // empty string to avoid regexp issues
process.versions = {};

function noop() {}

process.on = noop;
process.addListener = noop;
process.once = noop;
process.off = noop;
process.removeListener = noop;
process.removeAllListeners = noop;
process.emit = noop;
process.prependListener = noop;
process.prependOnceListener = noop;

process.listeners = function (name) { return [] }

process.binding = function (name) {
    throw new Error('process.binding is not supported');
};

process.cwd = function () { return '/' };
process.chdir = function (dir) {
    throw new Error('process.chdir is not supported');
};
process.umask = function() { return 0; };


/***/ }),

/***/ "./node_modules/pseudomap/map.js":
/*!***************************************!*\
  !*** ./node_modules/pseudomap/map.js ***!
  \***************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

/* WEBPACK VAR INJECTION */(function(process) {if (process.env.npm_package_name === 'pseudomap' &&
    process.env.npm_lifecycle_script === 'test')
  process.env.TEST_PSEUDOMAP = 'true'

if (typeof Map === 'function' && !process.env.TEST_PSEUDOMAP) {
  module.exports = Map
} else {
  module.exports = __webpack_require__(/*! ./pseudomap */ "./node_modules/pseudomap/pseudomap.js")
}

/* WEBPACK VAR INJECTION */}.call(this, __webpack_require__(/*! ./../process/browser.js */ "./node_modules/process/browser.js")))

/***/ }),

/***/ "./node_modules/pseudomap/pseudomap.js":
/*!*********************************************!*\
  !*** ./node_modules/pseudomap/pseudomap.js ***!
  \*********************************************/
/*! no static exports found */
/***/ (function(module, exports) {

var hasOwnProperty = Object.prototype.hasOwnProperty

module.exports = PseudoMap

function PseudoMap (set) {
  if (!(this instanceof PseudoMap)) // whyyyyyyy
    throw new TypeError("Constructor PseudoMap requires 'new'")

  this.clear()

  if (set) {
    if ((set instanceof PseudoMap) ||
        (typeof Map === 'function' && set instanceof Map))
      set.forEach(function (value, key) {
        this.set(key, value)
      }, this)
    else if (Array.isArray(set))
      set.forEach(function (kv) {
        this.set(kv[0], kv[1])
      }, this)
    else
      throw new TypeError('invalid argument')
  }
}

PseudoMap.prototype.forEach = function (fn, thisp) {
  thisp = thisp || this
  Object.keys(this._data).forEach(function (k) {
    if (k !== 'size')
      fn.call(thisp, this._data[k].value, this._data[k].key)
  }, this)
}

PseudoMap.prototype.has = function (k) {
  return !!find(this._data, k)
}

PseudoMap.prototype.get = function (k) {
  var res = find(this._data, k)
  return res && res.value
}

PseudoMap.prototype.set = function (k, v) {
  set(this._data, k, v)
}

PseudoMap.prototype.delete = function (k) {
  var res = find(this._data, k)
  if (res) {
    delete this._data[res._index]
    this._data.size--
  }
}

PseudoMap.prototype.clear = function () {
  var data = Object.create(null)
  data.size = 0

  Object.defineProperty(this, '_data', {
    value: data,
    enumerable: false,
    configurable: true,
    writable: false
  })
}

Object.defineProperty(PseudoMap.prototype, 'size', {
  get: function () {
    return this._data.size
  },
  set: function (n) {},
  enumerable: true,
  configurable: true
})

PseudoMap.prototype.values =
PseudoMap.prototype.keys =
PseudoMap.prototype.entries = function () {
  throw new Error('iterators are not implemented in this version')
}

// Either identical, or both NaN
function same (a, b) {
  return a === b || a !== a && b !== b
}

function Entry (k, v, i) {
  this.key = k
  this.value = v
  this._index = i
}

function find (data, k) {
  for (var i = 0, s = '_' + k, key = s;
       hasOwnProperty.call(data, key);
       key = s + i++) {
    if (same(data[key].key, k))
      return data[key]
  }
}

function set (data, k, v) {
  for (var i = 0, s = '_' + k, key = s;
       hasOwnProperty.call(data, key);
       key = s + i++) {
    if (same(data[key].key, k)) {
      data[key].value = v
      return
    }
  }
  data.size++
  data[key] = new Entry(k, v, key)
}


/***/ }),

/***/ "./node_modules/util/support/isBufferBrowser.js":
/*!******************************************************!*\
  !*** ./node_modules/util/support/isBufferBrowser.js ***!
  \******************************************************/
/*! no static exports found */
/***/ (function(module, exports) {

module.exports = function isBuffer(arg) {
  return arg && typeof arg === 'object'
    && typeof arg.copy === 'function'
    && typeof arg.fill === 'function'
    && typeof arg.readUInt8 === 'function';
}

/***/ }),

/***/ "./node_modules/util/util.js":
/*!***********************************!*\
  !*** ./node_modules/util/util.js ***!
  \***********************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

/* WEBPACK VAR INJECTION */(function(global, process) {// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

var formatRegExp = /%[sdj%]/g;
exports.format = function(f) {
  if (!isString(f)) {
    var objects = [];
    for (var i = 0; i < arguments.length; i++) {
      objects.push(inspect(arguments[i]));
    }
    return objects.join(' ');
  }

  var i = 1;
  var args = arguments;
  var len = args.length;
  var str = String(f).replace(formatRegExp, function(x) {
    if (x === '%%') return '%';
    if (i >= len) return x;
    switch (x) {
      case '%s': return String(args[i++]);
      case '%d': return Number(args[i++]);
      case '%j':
        try {
          return JSON.stringify(args[i++]);
        } catch (_) {
          return '[Circular]';
        }
      default:
        return x;
    }
  });
  for (var x = args[i]; i < len; x = args[++i]) {
    if (isNull(x) || !isObject(x)) {
      str += ' ' + x;
    } else {
      str += ' ' + inspect(x);
    }
  }
  return str;
};


// Mark that a method should not be used.
// Returns a modified function which warns once by default.
// If --no-deprecation is set, then it is a no-op.
exports.deprecate = function(fn, msg) {
  // Allow for deprecating things in the process of starting up.
  if (isUndefined(global.process)) {
    return function() {
      return exports.deprecate(fn, msg).apply(this, arguments);
    };
  }

  if (process.noDeprecation === true) {
    return fn;
  }

  var warned = false;
  function deprecated() {
    if (!warned) {
      if (process.throwDeprecation) {
        throw new Error(msg);
      } else if (process.traceDeprecation) {
        console.trace(msg);
      } else {
        console.error(msg);
      }
      warned = true;
    }
    return fn.apply(this, arguments);
  }

  return deprecated;
};


var debugs = {};
var debugEnviron;
exports.debuglog = function(set) {
  if (isUndefined(debugEnviron))
    debugEnviron = process.env.NODE_DEBUG || '';
  set = set.toUpperCase();
  if (!debugs[set]) {
    if (new RegExp('\\b' + set + '\\b', 'i').test(debugEnviron)) {
      var pid = process.pid;
      debugs[set] = function() {
        var msg = exports.format.apply(exports, arguments);
        console.error('%s %d: %s', set, pid, msg);
      };
    } else {
      debugs[set] = function() {};
    }
  }
  return debugs[set];
};


/**
 * Echos the value of a value. Trys to print the value out
 * in the best way possible given the different types.
 *
 * @param {Object} obj The object to print out.
 * @param {Object} opts Optional options object that alters the output.
 */
/* legacy: obj, showHidden, depth, colors*/
function inspect(obj, opts) {
  // default options
  var ctx = {
    seen: [],
    stylize: stylizeNoColor
  };
  // legacy...
  if (arguments.length >= 3) ctx.depth = arguments[2];
  if (arguments.length >= 4) ctx.colors = arguments[3];
  if (isBoolean(opts)) {
    // legacy...
    ctx.showHidden = opts;
  } else if (opts) {
    // got an "options" object
    exports._extend(ctx, opts);
  }
  // set default options
  if (isUndefined(ctx.showHidden)) ctx.showHidden = false;
  if (isUndefined(ctx.depth)) ctx.depth = 2;
  if (isUndefined(ctx.colors)) ctx.colors = false;
  if (isUndefined(ctx.customInspect)) ctx.customInspect = true;
  if (ctx.colors) ctx.stylize = stylizeWithColor;
  return formatValue(ctx, obj, ctx.depth);
}
exports.inspect = inspect;


// http://en.wikipedia.org/wiki/ANSI_escape_code#graphics
inspect.colors = {
  'bold' : [1, 22],
  'italic' : [3, 23],
  'underline' : [4, 24],
  'inverse' : [7, 27],
  'white' : [37, 39],
  'grey' : [90, 39],
  'black' : [30, 39],
  'blue' : [34, 39],
  'cyan' : [36, 39],
  'green' : [32, 39],
  'magenta' : [35, 39],
  'red' : [31, 39],
  'yellow' : [33, 39]
};

// Don't use 'blue' not visible on cmd.exe
inspect.styles = {
  'special': 'cyan',
  'number': 'yellow',
  'boolean': 'yellow',
  'undefined': 'grey',
  'null': 'bold',
  'string': 'green',
  'date': 'magenta',
  // "name": intentionally not styling
  'regexp': 'red'
};


function stylizeWithColor(str, styleType) {
  var style = inspect.styles[styleType];

  if (style) {
    return '\u001b[' + inspect.colors[style][0] + 'm' + str +
           '\u001b[' + inspect.colors[style][1] + 'm';
  } else {
    return str;
  }
}


function stylizeNoColor(str, styleType) {
  return str;
}


function arrayToHash(array) {
  var hash = {};

  array.forEach(function(val, idx) {
    hash[val] = true;
  });

  return hash;
}


function formatValue(ctx, value, recurseTimes) {
  // Provide a hook for user-specified inspect functions.
  // Check that value is an object with an inspect function on it
  if (ctx.customInspect &&
      value &&
      isFunction(value.inspect) &&
      // Filter out the util module, it's inspect function is special
      value.inspect !== exports.inspect &&
      // Also filter out any prototype objects using the circular check.
      !(value.constructor && value.constructor.prototype === value)) {
    var ret = value.inspect(recurseTimes, ctx);
    if (!isString(ret)) {
      ret = formatValue(ctx, ret, recurseTimes);
    }
    return ret;
  }

  // Primitive types cannot have properties
  var primitive = formatPrimitive(ctx, value);
  if (primitive) {
    return primitive;
  }

  // Look up the keys of the object.
  var keys = Object.keys(value);
  var visibleKeys = arrayToHash(keys);

  if (ctx.showHidden) {
    keys = Object.getOwnPropertyNames(value);
  }

  // IE doesn't make error fields non-enumerable
  // http://msdn.microsoft.com/en-us/library/ie/dww52sbt(v=vs.94).aspx
  if (isError(value)
      && (keys.indexOf('message') >= 0 || keys.indexOf('description') >= 0)) {
    return formatError(value);
  }

  // Some type of object without properties can be shortcutted.
  if (keys.length === 0) {
    if (isFunction(value)) {
      var name = value.name ? ': ' + value.name : '';
      return ctx.stylize('[Function' + name + ']', 'special');
    }
    if (isRegExp(value)) {
      return ctx.stylize(RegExp.prototype.toString.call(value), 'regexp');
    }
    if (isDate(value)) {
      return ctx.stylize(Date.prototype.toString.call(value), 'date');
    }
    if (isError(value)) {
      return formatError(value);
    }
  }

  var base = '', array = false, braces = ['{', '}'];

  // Make Array say that they are Array
  if (isArray(value)) {
    array = true;
    braces = ['[', ']'];
  }

  // Make functions say that they are functions
  if (isFunction(value)) {
    var n = value.name ? ': ' + value.name : '';
    base = ' [Function' + n + ']';
  }

  // Make RegExps say that they are RegExps
  if (isRegExp(value)) {
    base = ' ' + RegExp.prototype.toString.call(value);
  }

  // Make dates with properties first say the date
  if (isDate(value)) {
    base = ' ' + Date.prototype.toUTCString.call(value);
  }

  // Make error with message first say the error
  if (isError(value)) {
    base = ' ' + formatError(value);
  }

  if (keys.length === 0 && (!array || value.length == 0)) {
    return braces[0] + base + braces[1];
  }

  if (recurseTimes < 0) {
    if (isRegExp(value)) {
      return ctx.stylize(RegExp.prototype.toString.call(value), 'regexp');
    } else {
      return ctx.stylize('[Object]', 'special');
    }
  }

  ctx.seen.push(value);

  var output;
  if (array) {
    output = formatArray(ctx, value, recurseTimes, visibleKeys, keys);
  } else {
    output = keys.map(function(key) {
      return formatProperty(ctx, value, recurseTimes, visibleKeys, key, array);
    });
  }

  ctx.seen.pop();

  return reduceToSingleString(output, base, braces);
}


function formatPrimitive(ctx, value) {
  if (isUndefined(value))
    return ctx.stylize('undefined', 'undefined');
  if (isString(value)) {
    var simple = '\'' + JSON.stringify(value).replace(/^"|"$/g, '')
                                             .replace(/'/g, "\\'")
                                             .replace(/\\"/g, '"') + '\'';
    return ctx.stylize(simple, 'string');
  }
  if (isNumber(value))
    return ctx.stylize('' + value, 'number');
  if (isBoolean(value))
    return ctx.stylize('' + value, 'boolean');
  // For some reason typeof null is "object", so special case here.
  if (isNull(value))
    return ctx.stylize('null', 'null');
}


function formatError(value) {
  return '[' + Error.prototype.toString.call(value) + ']';
}


function formatArray(ctx, value, recurseTimes, visibleKeys, keys) {
  var output = [];
  for (var i = 0, l = value.length; i < l; ++i) {
    if (hasOwnProperty(value, String(i))) {
      output.push(formatProperty(ctx, value, recurseTimes, visibleKeys,
          String(i), true));
    } else {
      output.push('');
    }
  }
  keys.forEach(function(key) {
    if (!key.match(/^\d+$/)) {
      output.push(formatProperty(ctx, value, recurseTimes, visibleKeys,
          key, true));
    }
  });
  return output;
}


function formatProperty(ctx, value, recurseTimes, visibleKeys, key, array) {
  var name, str, desc;
  desc = Object.getOwnPropertyDescriptor(value, key) || { value: value[key] };
  if (desc.get) {
    if (desc.set) {
      str = ctx.stylize('[Getter/Setter]', 'special');
    } else {
      str = ctx.stylize('[Getter]', 'special');
    }
  } else {
    if (desc.set) {
      str = ctx.stylize('[Setter]', 'special');
    }
  }
  if (!hasOwnProperty(visibleKeys, key)) {
    name = '[' + key + ']';
  }
  if (!str) {
    if (ctx.seen.indexOf(desc.value) < 0) {
      if (isNull(recurseTimes)) {
        str = formatValue(ctx, desc.value, null);
      } else {
        str = formatValue(ctx, desc.value, recurseTimes - 1);
      }
      if (str.indexOf('\n') > -1) {
        if (array) {
          str = str.split('\n').map(function(line) {
            return '  ' + line;
          }).join('\n').substr(2);
        } else {
          str = '\n' + str.split('\n').map(function(line) {
            return '   ' + line;
          }).join('\n');
        }
      }
    } else {
      str = ctx.stylize('[Circular]', 'special');
    }
  }
  if (isUndefined(name)) {
    if (array && key.match(/^\d+$/)) {
      return str;
    }
    name = JSON.stringify('' + key);
    if (name.match(/^"([a-zA-Z_][a-zA-Z_0-9]*)"$/)) {
      name = name.substr(1, name.length - 2);
      name = ctx.stylize(name, 'name');
    } else {
      name = name.replace(/'/g, "\\'")
                 .replace(/\\"/g, '"')
                 .replace(/(^"|"$)/g, "'");
      name = ctx.stylize(name, 'string');
    }
  }

  return name + ': ' + str;
}


function reduceToSingleString(output, base, braces) {
  var numLinesEst = 0;
  var length = output.reduce(function(prev, cur) {
    numLinesEst++;
    if (cur.indexOf('\n') >= 0) numLinesEst++;
    return prev + cur.replace(/\u001b\[\d\d?m/g, '').length + 1;
  }, 0);

  if (length > 60) {
    return braces[0] +
           (base === '' ? '' : base + '\n ') +
           ' ' +
           output.join(',\n  ') +
           ' ' +
           braces[1];
  }

  return braces[0] + base + ' ' + output.join(', ') + ' ' + braces[1];
}


// NOTE: These type checking functions intentionally don't use `instanceof`
// because it is fragile and can be easily faked with `Object.create()`.
function isArray(ar) {
  return Array.isArray(ar);
}
exports.isArray = isArray;

function isBoolean(arg) {
  return typeof arg === 'boolean';
}
exports.isBoolean = isBoolean;

function isNull(arg) {
  return arg === null;
}
exports.isNull = isNull;

function isNullOrUndefined(arg) {
  return arg == null;
}
exports.isNullOrUndefined = isNullOrUndefined;

function isNumber(arg) {
  return typeof arg === 'number';
}
exports.isNumber = isNumber;

function isString(arg) {
  return typeof arg === 'string';
}
exports.isString = isString;

function isSymbol(arg) {
  return typeof arg === 'symbol';
}
exports.isSymbol = isSymbol;

function isUndefined(arg) {
  return arg === void 0;
}
exports.isUndefined = isUndefined;

function isRegExp(re) {
  return isObject(re) && objectToString(re) === '[object RegExp]';
}
exports.isRegExp = isRegExp;

function isObject(arg) {
  return typeof arg === 'object' && arg !== null;
}
exports.isObject = isObject;

function isDate(d) {
  return isObject(d) && objectToString(d) === '[object Date]';
}
exports.isDate = isDate;

function isError(e) {
  return isObject(e) &&
      (objectToString(e) === '[object Error]' || e instanceof Error);
}
exports.isError = isError;

function isFunction(arg) {
  return typeof arg === 'function';
}
exports.isFunction = isFunction;

function isPrimitive(arg) {
  return arg === null ||
         typeof arg === 'boolean' ||
         typeof arg === 'number' ||
         typeof arg === 'string' ||
         typeof arg === 'symbol' ||  // ES6 symbol
         typeof arg === 'undefined';
}
exports.isPrimitive = isPrimitive;

exports.isBuffer = __webpack_require__(/*! ./support/isBuffer */ "./node_modules/util/support/isBufferBrowser.js");

function objectToString(o) {
  return Object.prototype.toString.call(o);
}


function pad(n) {
  return n < 10 ? '0' + n.toString(10) : n.toString(10);
}


var months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep',
              'Oct', 'Nov', 'Dec'];

// 26 Feb 16:19:34
function timestamp() {
  var d = new Date();
  var time = [pad(d.getHours()),
              pad(d.getMinutes()),
              pad(d.getSeconds())].join(':');
  return [d.getDate(), months[d.getMonth()], time].join(' ');
}


// log is just a thin wrapper to console.log that prepends a timestamp
exports.log = function() {
  console.log('%s - %s', timestamp(), exports.format.apply(exports, arguments));
};


/**
 * Inherit the prototype methods from one constructor into another.
 *
 * The Function.prototype.inherits from lang.js rewritten as a standalone
 * function (not on Function.prototype). NOTE: If this file is to be loaded
 * during bootstrapping this function needs to be rewritten using some native
 * functions as prototype setup using normal JavaScript does not work as
 * expected during bootstrapping (see mirror.js in r114903).
 *
 * @param {function} ctor Constructor function which needs to inherit the
 *     prototype.
 * @param {function} superCtor Constructor function to inherit prototype from.
 */
exports.inherits = __webpack_require__(/*! inherits */ "./node_modules/inherits/inherits_browser.js");

exports._extend = function(origin, add) {
  // Don't do anything if add isn't an object
  if (!add || !isObject(add)) return origin;

  var keys = Object.keys(add);
  var i = keys.length;
  while (i--) {
    origin[keys[i]] = add[keys[i]];
  }
  return origin;
};

function hasOwnProperty(obj, prop) {
  return Object.prototype.hasOwnProperty.call(obj, prop);
}

/* WEBPACK VAR INJECTION */}.call(this, __webpack_require__(/*! ./../webpack/buildin/global.js */ "./node_modules/webpack/buildin/global.js"), __webpack_require__(/*! ./../process/browser.js */ "./node_modules/process/browser.js")))

/***/ }),

/***/ "./node_modules/webpack/buildin/global.js":
/*!***********************************!*\
  !*** (webpack)/buildin/global.js ***!
  \***********************************/
/*! no static exports found */
/***/ (function(module, exports) {

var g;

// This works in non-strict mode
g = (function() {
	return this;
})();

try {
	// This works if eval is allowed (see CSP)
	g = g || Function("return this")() || (1, eval)("this");
} catch (e) {
	// This works if the window reference is available
	if (typeof window === "object") g = window;
}

// g can still be undefined, but nothing to do about it...
// We return undefined, instead of nothing here, so it's
// easier to handle this case. if(!global) { ...}

module.exports = g;


/***/ }),

/***/ "./node_modules/yallist/yallist.js":
/*!*****************************************!*\
  !*** ./node_modules/yallist/yallist.js ***!
  \*****************************************/
/*! no static exports found */
/***/ (function(module, exports) {

module.exports = Yallist

Yallist.Node = Node
Yallist.create = Yallist

function Yallist (list) {
  var self = this
  if (!(self instanceof Yallist)) {
    self = new Yallist()
  }

  self.tail = null
  self.head = null
  self.length = 0

  if (list && typeof list.forEach === 'function') {
    list.forEach(function (item) {
      self.push(item)
    })
  } else if (arguments.length > 0) {
    for (var i = 0, l = arguments.length; i < l; i++) {
      self.push(arguments[i])
    }
  }

  return self
}

Yallist.prototype.removeNode = function (node) {
  if (node.list !== this) {
    throw new Error('removing node which does not belong to this list')
  }

  var next = node.next
  var prev = node.prev

  if (next) {
    next.prev = prev
  }

  if (prev) {
    prev.next = next
  }

  if (node === this.head) {
    this.head = next
  }
  if (node === this.tail) {
    this.tail = prev
  }

  node.list.length--
  node.next = null
  node.prev = null
  node.list = null
}

Yallist.prototype.unshiftNode = function (node) {
  if (node === this.head) {
    return
  }

  if (node.list) {
    node.list.removeNode(node)
  }

  var head = this.head
  node.list = this
  node.next = head
  if (head) {
    head.prev = node
  }

  this.head = node
  if (!this.tail) {
    this.tail = node
  }
  this.length++
}

Yallist.prototype.pushNode = function (node) {
  if (node === this.tail) {
    return
  }

  if (node.list) {
    node.list.removeNode(node)
  }

  var tail = this.tail
  node.list = this
  node.prev = tail
  if (tail) {
    tail.next = node
  }

  this.tail = node
  if (!this.head) {
    this.head = node
  }
  this.length++
}

Yallist.prototype.push = function () {
  for (var i = 0, l = arguments.length; i < l; i++) {
    push(this, arguments[i])
  }
  return this.length
}

Yallist.prototype.unshift = function () {
  for (var i = 0, l = arguments.length; i < l; i++) {
    unshift(this, arguments[i])
  }
  return this.length
}

Yallist.prototype.pop = function () {
  if (!this.tail) {
    return undefined
  }

  var res = this.tail.value
  this.tail = this.tail.prev
  if (this.tail) {
    this.tail.next = null
  } else {
    this.head = null
  }
  this.length--
  return res
}

Yallist.prototype.shift = function () {
  if (!this.head) {
    return undefined
  }

  var res = this.head.value
  this.head = this.head.next
  if (this.head) {
    this.head.prev = null
  } else {
    this.tail = null
  }
  this.length--
  return res
}

Yallist.prototype.forEach = function (fn, thisp) {
  thisp = thisp || this
  for (var walker = this.head, i = 0; walker !== null; i++) {
    fn.call(thisp, walker.value, i, this)
    walker = walker.next
  }
}

Yallist.prototype.forEachReverse = function (fn, thisp) {
  thisp = thisp || this
  for (var walker = this.tail, i = this.length - 1; walker !== null; i--) {
    fn.call(thisp, walker.value, i, this)
    walker = walker.prev
  }
}

Yallist.prototype.get = function (n) {
  for (var i = 0, walker = this.head; walker !== null && i < n; i++) {
    // abort out of the list early if we hit a cycle
    walker = walker.next
  }
  if (i === n && walker !== null) {
    return walker.value
  }
}

Yallist.prototype.getReverse = function (n) {
  for (var i = 0, walker = this.tail; walker !== null && i < n; i++) {
    // abort out of the list early if we hit a cycle
    walker = walker.prev
  }
  if (i === n && walker !== null) {
    return walker.value
  }
}

Yallist.prototype.map = function (fn, thisp) {
  thisp = thisp || this
  var res = new Yallist()
  for (var walker = this.head; walker !== null;) {
    res.push(fn.call(thisp, walker.value, this))
    walker = walker.next
  }
  return res
}

Yallist.prototype.mapReverse = function (fn, thisp) {
  thisp = thisp || this
  var res = new Yallist()
  for (var walker = this.tail; walker !== null;) {
    res.push(fn.call(thisp, walker.value, this))
    walker = walker.prev
  }
  return res
}

Yallist.prototype.reduce = function (fn, initial) {
  var acc
  var walker = this.head
  if (arguments.length > 1) {
    acc = initial
  } else if (this.head) {
    walker = this.head.next
    acc = this.head.value
  } else {
    throw new TypeError('Reduce of empty list with no initial value')
  }

  for (var i = 0; walker !== null; i++) {
    acc = fn(acc, walker.value, i)
    walker = walker.next
  }

  return acc
}

Yallist.prototype.reduceReverse = function (fn, initial) {
  var acc
  var walker = this.tail
  if (arguments.length > 1) {
    acc = initial
  } else if (this.tail) {
    walker = this.tail.prev
    acc = this.tail.value
  } else {
    throw new TypeError('Reduce of empty list with no initial value')
  }

  for (var i = this.length - 1; walker !== null; i--) {
    acc = fn(acc, walker.value, i)
    walker = walker.prev
  }

  return acc
}

Yallist.prototype.toArray = function () {
  var arr = new Array(this.length)
  for (var i = 0, walker = this.head; walker !== null; i++) {
    arr[i] = walker.value
    walker = walker.next
  }
  return arr
}

Yallist.prototype.toArrayReverse = function () {
  var arr = new Array(this.length)
  for (var i = 0, walker = this.tail; walker !== null; i++) {
    arr[i] = walker.value
    walker = walker.prev
  }
  return arr
}

Yallist.prototype.slice = function (from, to) {
  to = to || this.length
  if (to < 0) {
    to += this.length
  }
  from = from || 0
  if (from < 0) {
    from += this.length
  }
  var ret = new Yallist()
  if (to < from || to < 0) {
    return ret
  }
  if (from < 0) {
    from = 0
  }
  if (to > this.length) {
    to = this.length
  }
  for (var i = 0, walker = this.head; walker !== null && i < from; i++) {
    walker = walker.next
  }
  for (; walker !== null && i < to; i++, walker = walker.next) {
    ret.push(walker.value)
  }
  return ret
}

Yallist.prototype.sliceReverse = function (from, to) {
  to = to || this.length
  if (to < 0) {
    to += this.length
  }
  from = from || 0
  if (from < 0) {
    from += this.length
  }
  var ret = new Yallist()
  if (to < from || to < 0) {
    return ret
  }
  if (from < 0) {
    from = 0
  }
  if (to > this.length) {
    to = this.length
  }
  for (var i = this.length, walker = this.tail; walker !== null && i > to; i--) {
    walker = walker.prev
  }
  for (; walker !== null && i > from; i--, walker = walker.prev) {
    ret.push(walker.value)
  }
  return ret
}

Yallist.prototype.reverse = function () {
  var head = this.head
  var tail = this.tail
  for (var walker = head; walker !== null; walker = walker.prev) {
    var p = walker.prev
    walker.prev = walker.next
    walker.next = p
  }
  this.head = tail
  this.tail = head
  return this
}

function push (self, item) {
  self.tail = new Node(item, self.tail, null, self)
  if (!self.head) {
    self.head = self.tail
  }
  self.length++
}

function unshift (self, item) {
  self.head = new Node(item, null, self.head, self)
  if (!self.tail) {
    self.tail = self.head
  }
  self.length++
}

function Node (value, prev, next, list) {
  if (!(this instanceof Node)) {
    return new Node(value, prev, next, list)
  }

  this.list = list
  this.value = value

  if (prev) {
    prev.next = this
    this.prev = prev
  } else {
    this.prev = null
  }

  if (next) {
    next.prev = this
    this.next = next
  } else {
    this.next = null
  }
}


/***/ }),

/***/ "./src/firecrypt.js":
/*!**************************!*\
  !*** ./src/firecrypt.js ***!
  \**************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

if (true) {
  if (typeof Firebase === 'undefined') Firebase = __webpack_require__(/*! firebase */ "./node_modules/firebase/lib/firebase-web.js");
  if (typeof LRUCache === 'undefined') LRUCache = __webpack_require__(/*! lru-cache */ "./node_modules/lru-cache/index.js");
  if (typeof CryptoJS === 'undefined') CryptoJS = __webpack_require__(/*! crypto-js/core */ "./node_modules/crypto-js/core.js");
  __webpack_require__(/*! crypto-js/enc-base64 */ "./node_modules/crypto-js/enc-base64.js");
  __webpack_require__(/*! cryptojs-extension/build_node/siv */ "./node_modules/cryptojs-extension/build_node/siv.js");
  try {
    __webpack_require__(!(function webpackMissingModule() { var e = new Error("Cannot find module 'firebase-childrenkeys'"); e.code = 'MODULE_NOT_FOUND'; throw e; }()));
  } catch (e) {
    // ignore, not installed
  }
}

CryptoJS.enc.Base64UrlSafe = {
  stringify: CryptoJS.enc.Base64.stringify,
  parse: CryptoJS.enc.Base64.parse,
  _map: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
};

(function() {
  'use strict';

  var fbp = Firebase.prototype;
  var originalQueryFbp = {};
  var firebaseWrapped = false;
  var encryptString, decryptString;

  var utils = __webpack_require__(/*! ./utils */ "./src/utils.js");

  Firebase.initializeEncryption = function(options, specification) {
    var result;
    options.cacheSize = options.cacheSize || 5 * 1000 * 1000;
    options.encryptionCacheSize = options.encryptionCacheSize || options.cacheSize;
    options.decryptionCacheSize = options.decryptionCacheSize || options.cacheSize;
    encryptString = decryptString = utils.throwNotSetUpError;
    if (typeof LRUCache === 'function') {
      utils.setEncryptionCache(new LRUCache({
        max: options.encryptionCacheSize, length: utils.computeCacheItemSize
      }));
      utils.setDecryptionCache(new LRUCache({
        max: options.decryptionCacheSize, length: utils.computeCacheItemSize
      }));
    }
    switch (options.algorithm) {
      case 'aes-siv':
        if (!options.key) throw new Error('You must specify a key to use AES encryption.');
        result = setupAesSiv(options.key, options.keyCheckValue);
        break;
      case 'passthrough':
        encryptString = decryptString = function(str) {return str;};
        break;
      case 'none':
        break;
      default:
        throw new Error('Unknown encryption algorithm "' + options.algorithm + '".');
    }
    utils.setSpec(specification);
    wrapFirebase();
    return result;
  };

  function setupAesSiv(key, checkValue) {
    var siv = CryptoJS.SIV.create(CryptoJS.enc.Base64.parse(key));
    encryptString = function(str) {
      return CryptoJS.enc.Base64UrlSafe.stringify(siv.encrypt(str));
    };
    decryptString = function(str) {
      var result = siv.decrypt(CryptoJS.enc.Base64UrlSafe.parse(str));
      if (result === false) {
        var e = new Error('Wrong decryption key');
        e.firecrypt = 'WRONG_KEY';
        throw e;
      }
      return CryptoJS.enc.Utf8.stringify(result);
    };
    if (checkValue) decryptString(checkValue);
    return encryptString(CryptoJS.enc.Base64UrlSafe.stringify(CryptoJS.lib.WordArray.random(10)));
  }

  function Query(query, order, original) {
    this._query = query;
    this._order = order || {};
    this._original = original || query;
  }
  Query.prototype.on = function(eventType, callback, cancelCallback, context) {
    wrapQueryCallback(callback);
    return this._original.on.call(
      this._query, eventType, callback.firecryptCallback, cancelCallback, context);
  };
  Query.prototype.off = function(eventType, callback, context) {
    if (callback && callback.firecryptCallback) callback = callback.firecryptCallback;
    return this._original.off.call(this._query, eventType, callback, context);
  };
  Query.prototype.once = function(eventType, successCallback, failureCallback, context) {
    wrapQueryCallback(successCallback);
    return this._original.once.call(
      this._query, eventType, successCallback && successCallback.firecryptCallback, failureCallback,
      context
    ).then(function(snap) {
      return new Snapshot(snap);
    });
  };
  Query.prototype.orderByChild = function(key) {
    return this._orderBy('orderByChild', 'child', key);
  };
  Query.prototype.orderByKey = function() {
    return this._orderBy('orderByKey', 'key');
  };
  Query.prototype.orderByValue = function() {
    return this._orderBy('orderByValue', 'value');
  };
  Query.prototype.orderByPriority = function() {
    return this._orderBy('orderByPriority', 'priority');
  };
  Query.prototype.startAt = function(value, key) {
    this._checkCanSort(key !== undefined);
    return this._delegate('startAt', arguments);
  };
  Query.prototype.endAt = function(value, key) {
    this._checkCanSort(key !== undefined);
    return this._delegate('endAt', arguments);
  };
  Query.prototype.equalTo = function(value, key) {
    if (this._order[this._order.by + 'Encrypted']) {
      value = utils.encrypt(value, utils.getType(value), this._order[this._order.by + 'Encrypted']);
    }
    if (key !== undefined && this._order.keyEncrypted) {
      key = utils.encrypt(key, 'string', this._order.keyEncrypted);
    }
    return new Query(this._original.equalTo.call(this._query, value, key), this._order);
  };
  Query.prototype.limitToFirst = function() {
    return this._delegate('limitToFirst', arguments);
  };
  Query.prototype.limitToLast = function() {
    return this._delegate('limitToLast', arguments);
  };
  Query.prototype.limit = function() {
    return this._delegate('limit', arguments);
  };
  Query.prototype.ref = function() {
    return utils.decryptRef(this._original.ref.call(this._query));
  };
  Query.prototype._delegate = function(methodName, args) {
    return new Query(this._original[methodName].apply(this._query, args), this._order);
  };
  Query.prototype._checkCanSort = function(hasExtraKey) {
    if (this._order.by === 'key' ?
        this._order.keyEncrypted :
        this._order.valueEncrypted || hasExtraKey && this._order.keyEncrypted) {
      throw new Error('Encrypted items cannot be ordered');
    }
  };
  Query.prototype._orderBy = function(methodName, by, childKey) {
    var def = utils.specForPath(utils.refToPath(this.ref()));
    var order = {by: by};
    var encryptedChildKey;
    if (def) {
      var childPath = childKey && childKey.split('/');
      for (var subKey in def) {
        if (!def.hasOwnProperty(subKey)) continue;
        var subDef = def[subKey];
        if (subDef['.encrypt']) {
          if (subDef['.encrypt'].key) order.keyEncrypted = subDef['.encrypt'].key;
          if (subDef['.encrypt'].value) order.valueEncrypted = subDef['.encrypt'].value;
        }
        if (childKey) {
          var childDef = utils.specForPath(childPath, subDef);
          if (childDef && childDef['.encrypt'] && childDef['.encrypt'].value) {
            order.childEncrypted = childDef['.encrypt'].value;
          }
          var encryptedChildKeyCandidate = utils.encryptPath(childPath, subDef).join('/');
          if (encryptedChildKey && encryptedChildKeyCandidate !== encryptedChildKey) {
            throw new Error(
              'Incompatible encryption specifications for orderByChild("' + childKey + '")');
          }
          encryptedChildKey = encryptedChildKeyCandidate;
        }
      }
    }
    if (childKey) {
      return new Query(
        this._original[methodName].call(this._query, encryptedChildKey || childKey), order);
    } else {
      return new Query(this._original[methodName].call(this._query), order);
    }
  };


  function Snapshot(snap) {
    this._ref = utils.decryptRef(snap.ref());
    this._path = utils.refToPath(this._ref);
    this._snap = snap;
  }
  delegateSnapshot('exists');
  delegateSnapshot('hasChildren');
  delegateSnapshot('numChildren');
  delegateSnapshot('getPriority');
  Snapshot.prototype.val = function() {
    return utils.transformValue(this._path, this._snap.val(), utils.decrypt);
  };
  Snapshot.prototype.child = function(childPath) {
    return new Snapshot(this._snap.child(childPath));
  };
  Snapshot.prototype.forEach = function(action) {
    return this._snap.forEach(function(childSnap) {
      return action(new Snapshot(childSnap));
    });
  };
  Snapshot.prototype.hasChild = function(childPath) {
    childPath = utils.encryptPath(childPath.split('/'), utils.specForPath(this._path)).join('/');
    return this._snap.hasChild(childPath);
  };
  Snapshot.prototype.key = function() {
    return this._ref.key();
  };
  Snapshot.prototype.name = function() {
    return this._ref.name();
  };
  Snapshot.prototype.ref = function() {
    return this._ref;
  };
  Snapshot.prototype.exportVal = function() {
    return utils.transformValue(this._path, this._snap.exportVal(), utils.decrypt);
  };

  function OnDisconnect(path, originalOnDisconnect) {
    this._path = path;
    this._originalOnDisconnect = originalOnDisconnect;
  }
  interceptOnDisconnectWrite('set', 0);
  interceptOnDisconnectWrite('update', 0);
  interceptOnDisconnectWrite('remove');
  interceptOnDisconnectWrite('setWithPriority', 0);
  interceptOnDisconnectWrite('cancel');


  function wrapFirebase() {
    if (firebaseWrapped) return;
    interceptWrite('set', 0);
    interceptWrite('update', 0);
    interceptPush();
    interceptWrite('setWithPriority', 0);
    interceptWrite('setPriority');
    if (fbp.childrenKeys) interceptChildrenKeys();
    interceptTransaction();
    interceptOnDisconnect();
    [
      'on', 'off', 'once', 'orderByChild', 'orderByKey', 'orderByValue', 'orderByPriority',
      'startAt', 'endAt', 'equalTo', 'limitToFirst', 'limitToLast', 'limit', 'ref'
    ].forEach(function(methodName) {interceptQuery(methodName);});
    firebaseWrapped = true;
  }

  function interceptWrite(methodName, argIndex) {
    var originalMethod = fbp[methodName];
    fbp[methodName] = function() {
      var path = utils.refToPath(this);
      var self = utils.encryptRef(this, path);
      var args = Array.prototype.slice.call(arguments);
      if (argIndex >= 0 && argIndex < args.length) {
        args[argIndex] = utils.transformValue(path, args[argIndex], utils.encrypt);
      }
      return originalMethod.apply(self, args);
    };
  }

  function interceptPush() {
    // Firebase.push delegates to Firebase.set, which will take care of encrypting the ref and the
    // argument.
    var originalMethod = fbp.push;
    fbp.push = function() {
      var ref = originalMethod.apply(this, arguments);
      var decryptedRef = utils.decryptRef(ref);
      decryptedRef.then = ref.then;
      decryptedRef.catch = ref.catch;
      if (ref.finally) decryptedRef.finally = ref.finally;
      return decryptedRef;
    };
  }

  function interceptChildrenKeys() {
    var originalMethod = fbp.childrenKeys;
    fbp.childrenKeys = function() {
      return originalMethod.apply(utils.encryptRef(this), arguments).then(function(keys) {
        if (!keys.some(function(key) {return /\x91/.test(key);})) return keys;
        return keys.map(utils.decrypt);
      });
    };
  }

  function interceptTransaction() {
    var originalMethod = fbp.transaction;
    fbp.transaction = function() {
      var path = utils.refToPath(this);
      var self = utils.encryptRef(this, path);
      var args = Array.prototype.slice.call(arguments);
      var originalCompute = args[0];
      args[0] = originalCompute && function(value) {
        value = utils.transformValue(path, value, utils.decrypt);
        value = originalCompute(value);
        value = utils.transformValue(path, value, utils.encrypt);
        return value;
      };
      if (args.length > 1) {
        var originalOnComplete = args[1];
        args[1] = originalOnComplete && function(error, committed, snapshot) {
          return originalOnComplete(error, committed, snapshot && new Snapshot(snapshot));
        };
      }
      return originalMethod.apply(self, args).then(function(result) {
        result.snapshot = result.snapshot && new Snapshot(result.snapshot);
        return result;
      });
    };
  }

  function interceptOnDisconnect() {
    var originalMethod = fbp.onDisconnect;
    fbp.onDisconnect = function() {
      var path = utils.refToPath(this);
      return new OnDisconnect(path, originalMethod.call(utils.encryptRef(this, path)));
    };
  }

  function interceptOnDisconnectWrite(methodName, argIndex) {
    OnDisconnect.prototype[methodName] = function() {
      var args = Array.prototype.slice.call(arguments);
      if (argIndex >= 0 && argIndex < args.length) {
        args[argIndex] = utils.transformValue(this._path, args[argIndex], utils.encrypt);
      }
      console.log('ARGS:', args);
      return this._originalOnDisconnect[methodName].apply(this._originalOnDisconnect, args);
    };
  }

  function interceptQuery(methodName) {
    originalQueryFbp[methodName] = fbp[methodName];
    fbp[methodName] = function() {
      var query = new Query(utils.encryptRef(this), {}, originalQueryFbp);
      return query[methodName].apply(query, arguments);
    };
  }

  function wrapQueryCallback(callback) {
    if (!callback || callback.firecryptCallback) return;
    var wrappedCallback = function(snap, previousChildKey) {
      return callback.call(this, new Snapshot(snap), previousChildKey);
    };
    wrappedCallback.firecryptCallback = wrappedCallback;
    callback.firecryptCallback = wrappedCallback;
  }

  function delegateSnapshot(methodName) {
    Snapshot.prototype[methodName] = function() {
      return this._snap[methodName].apply(this._snap, arguments);
    };
  }
})();


/***/ }),

/***/ "./src/utils.js":
/*!**********************!*\
  !*** ./src/utils.js ***!
  \**********************/
/*! no static exports found */
/***/ (function(module, exports) {

let _spec;
let _encryptionCache;
let _decryptionCache;

function setSpec(spec) {
  _spec = cleanSpecification(spec);
}

function setEncryptionCache(cache) {
  _encryptionCache = cache;
}

function setDecryptionCache(cache) {
  _decryptionCache = cache;
}

function cleanSpecification(def, path) {
  var keys = Object.keys(def);
  for (var i = 0; i < keys.length; i++) {
    var key = keys[i];
    if (key === '.encrypt') {
      var encryptKeys = Object.keys(def[key]);
      for (var j = 0; j < encryptKeys.length; j++) {
        var encryptKey = encryptKeys[j];
        if (encryptKey !== 'key' && encryptKey !== 'value' && encryptKey !== 'few') {
          throw new Error('Illegal .encrypt subkey: ' + encryptKeys[j]);
        }
      }
    } else {
      if (/[\x00-\x1f\x7f\x91\x92\.#\[\]/]/.test(key) || /[$]/.test(key.slice(1))) {
        throw new Error('Illegal character in specification key: ' + key);
      }
      cleanSpecification(def[key], (path || '') + '/' + key);
    }
    switch (key.charAt(0)) {
      case '$':
        if (key === '$') break;
        if (def.$) throw new Error('Multiple wildcard keys in specification at ' + path);
        def.$ = def[key];
        delete def[key];
        break;
      case '.':
        if (key !== '.encrypt') throw new Error('Unknown directive at ' + path + ': ' + key);
        break;
    }
  }
  return def;
}

function throwNotSetUpError() {
  var e = new Error('Encryption not set up');
  e.firecrypt = 'NO_KEY';
  throw e;
}

function computeCacheItemSize(value, key) {
  return key.length + (typeof value === 'string' ? value.length : 4);
}

function encryptPath(path, def) {
  def = def || _spec.rules;
  path = path.slice();
  for (var i = 0; i < path.length; i++) {
    def = def[path[i]] || def.$;
    if (!def) break;
    if (def['.encrypt'] && def['.encrypt'].key) {
      path[i] = encrypt(path[i], 'string', def['.encrypt'].key);
    }
  }
  return path;
}

function encryptRef(ref, path) {
  var encryptedPath = encryptPath(path || refToPath(ref));
  return encryptedPath.length ? ref.root().child(encryptedPath.join('/')) : ref.root();
}

function decryptRef(ref) {
  var path = refToPath(ref, true);
  var changed = false;
  for (var i = 0; i < path.length; i++) {
    var decryptedPathSegment = decrypt(path[i]);
    if (decryptedPathSegment !== path[i]) {
      path[i] = decryptedPathSegment;
      changed = true;
    }
  }
  return changed ? ref.root().child(path.join('/')) : ref;
}

function specForPath(path, def) {
  def = def || _spec.rules;
  for (var i = 0; def && i < path.length; i++) {
    def = def[path[i]] || def.$;
  }
  return def;
}

function transformValue(path, value, transform) {
  return transformTree(value, specForPath(path), transform);
}

function transformTree(value, def, transform) {
  if (!def) return value;
  var type = getType(value);
  var i;
  if (/^(string|number|boolean)$/.test(type)) {
    if (def['.encrypt'] && def['.encrypt'].value) {
      value = transform(value, type, def['.encrypt'].value);
    }
  } else if (type === 'object' && value !== null) {
    var transformedValue = {};
    for (var key in value) {
      if (!value.hasOwnProperty(key)) continue;
      var subValue = value[key], subDef;
      if (key.indexOf('/') >= 0) {  // for deep update keys
        var keyParts = key.split('/');
        subDef = def;
        for (i = 0; i < keyParts.length; i++) {
          if (transform === decrypt) {
            keyParts[i] = decrypt(keyParts[i]);
            subDef = subDef && (subDef[keyParts[i]] || subDef.$);
          } else {
            subDef = subDef && (subDef[keyParts[i]] || subDef.$);
            if (subDef && subDef['.encrypt'] && subDef['.encrypt'].key) {
              keyParts[i] = transform(keyParts[i], 'string', subDef['.encrypt'].key);
            }
          }
        }
        key = keyParts.join('/');
      } else {
        if (transform === decrypt) {
          key = decrypt(key);
          subDef = def[key] || def.$;
        } else {
          subDef = def[key] || def.$;
          if (subDef && subDef['.encrypt'] && subDef['.encrypt'].key) {
            key = transform(key, 'string', subDef['.encrypt'].key);
          }
        }
      }
      transformedValue[key] = transformTree(subValue, subDef, transform);
    }
    value = transformedValue;
  } else if (type === 'array') {
    if (!def.$) return value;
    for (i = 0; i < value.length; i++) value[i] = transformTree(value[i], def.$, transform);
  }
  return value;
}

function refToPath(ref, encrypted) {
  var root = ref.root();
  if (ref === root) return [];
  var pathStr = decodeURIComponent(ref.toString().slice(root.toString().length));
  if (!encrypted && pathStr && pathStr.charAt(0) !== '.' &&
      /[\x00-\x1f\x7f\x91\x92\.#$\[\]]/.test(pathStr)) {
    throw new Error('Path contains invalid characters: ' + pathStr);
  }
  return pathStr.split('/');
}

function encrypt(value, type, pattern) {
  var cacheKey;
  if (_encryptionCache) {
    cacheKey = type.charAt(0) + pattern + '\x91' + value;
    if (_encryptionCache.has(cacheKey)) return _encryptionCache.get(cacheKey);
  }
  var result;
  if (pattern === '#') {
    result = encryptValue(value, type);
  } else {
    if (type !== 'string') {
      throw new Error('Can\'t encrypt a ' + type + ' using pattern [' + pattern + ']');
    }
    var match = value.match(compilePattern(pattern));
    if (!match) {
      throw new Error(
        'Can\'t encrypt as value doesn\'t match pattern [' + pattern + ']: ' + value);
    }
    var i = 0;
    result = pattern.replace(/[#\.]/g, function(placeholder) {
      var part = match[++i];
      if (placeholder === '#') part = encryptValue(part, 'string');
      return part;
    });
  }
  if (_encryptionCache) _encryptionCache.set(cacheKey, result);
  return result;
}

function encryptValue(value, type) {
  if (!/^(string|number|boolean)$/.test(type)) throw new Error('Can\'t encrypt a ' + type);
  switch (type) {
    case 'number': value = '' + value; break;
    case 'boolean': value = value ? 't' : 'f'; break;
  }
  return '\x91' + type.charAt(0).toUpperCase() + encryptString(value) + '\x92';
}

function decrypt(value) {
  if (_decryptionCache && _decryptionCache.has(value)) return _decryptionCache.get(value);
  if (!/\x91/.test(value)) return value;
  var result;
  var match = value.match(/^\x91(.)([^\x92]*)\x92$/);
  if (match) {
    var decryptedString = decryptString(match[2]);
    switch (match[1]) {
      case 'S':
        result = decryptedString;
        break;
      case 'N':
        result = Number(decryptedString);
        // Check for NaN, since it's the only value where x !== x.
        if (result !== result) throw new Error('Invalid encrypted number: ' + decryptedString);
        break;
      case 'B':
        if (decryptedString === 't') result = true;
        else if (decryptedString === 'f') result = false;
        else throw new Error('Invalid encrypted boolean: ' + decryptedString);
        break;
      default:
        throw new Error('Invalid encrypted value type code: ' + match[1]);
    }
  } else {
    result = value.replace(/\x91(.)([^\x92]*)\x92/g, function(match, typeCode, encryptedString) {
      if (typeCode !== 'S') throw new Error('Invalid multi-segment encrypted value: ' + typeCode);
      return decryptString(encryptedString);
    });
  }
  if (_decryptionCache) _decryptionCache.set(value, result);
  return result;
}

function getType(value) {
  if (Array.isArray(value)) return 'array';
  var type = typeof value;
  if (type === 'object') {
    if (value instanceof String) type = 'string';
    else if (value instanceof Number) type = 'number';
    else if (value instanceof Boolean) type = 'boolean';
  }
  return type;
}

var patternRegexes = {};
function compilePattern(pattern) {
  var regex = patternRegexes[pattern];
  if (!regex) {
    regex = patternRegexes[pattern] = new RegExp('^' + pattern
      .replace(/\./g, '#')
      .replace(/[\-\[\]\/\{\}\(\)\*\+\?\.\\\^\$\|]/g, '\\$&')  // escape regex chars
      .replace(/#/g, '(.*?)') + '$');
  }
  return regex;
}

module.exports = {
  setSpec,
  encrypt,
  decrypt,
  getType,
  refToPath,
  decryptRef,
  encryptRef,
  encryptPath,
  specForPath,
  encryptValue,
  transformTree,
  transformValue,
  compilePattern,
  setEncryptionCache,
  setDecryptionCache,
  throwNotSetUpError,
  computeCacheItemSize,
}


/***/ })

/******/ });
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIndlYnBhY2s6Ly8vd2VicGFjay9ib290c3RyYXAiLCJ3ZWJwYWNrOi8vLy4vaW5kZXguanMiLCJ3ZWJwYWNrOi8vLy4vbm9kZV9tb2R1bGVzL2NyeXB0by1qcy9hZXMuanMiLCJ3ZWJwYWNrOi8vLy4vbm9kZV9tb2R1bGVzL2NyeXB0by1qcy9jaXBoZXItY29yZS5qcyIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvY3J5cHRvLWpzL2NvcmUuanMiLCJ3ZWJwYWNrOi8vLy4vbm9kZV9tb2R1bGVzL2NyeXB0by1qcy9lbmMtYmFzZTY0LmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9jcnlwdG8tanMvZXZwa2RmLmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9jcnlwdG8tanMvaG1hYy5qcyIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvY3J5cHRvLWpzL21kNS5qcyIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvY3J5cHRvLWpzL21vZGUtY3RyLmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9jcnlwdG8tanMvc2hhMS5qcyIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvY3J5cHRvanMtZXh0ZW5zaW9uL2J1aWxkX25vZGUvY21hYy5qcyIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvY3J5cHRvanMtZXh0ZW5zaW9uL2J1aWxkX25vZGUvY29tbW9uLWJpdC1vcHMuanMiLCJ3ZWJwYWNrOi8vLy4vbm9kZV9tb2R1bGVzL2NyeXB0b2pzLWV4dGVuc2lvbi9idWlsZF9ub2RlL2NvbW1vbi5qcyIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvY3J5cHRvanMtZXh0ZW5zaW9uL2J1aWxkX25vZGUvc2l2LmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9maXJlYmFzZS9saWIvZmlyZWJhc2Utd2ViLmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9pbmhlcml0cy9pbmhlcml0c19icm93c2VyLmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9scnUtY2FjaGUvaW5kZXguanMiLCJ3ZWJwYWNrOi8vLy4vbm9kZV9tb2R1bGVzL3Byb2Nlc3MvYnJvd3Nlci5qcyIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvcHNldWRvbWFwL21hcC5qcyIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvcHNldWRvbWFwL3BzZXVkb21hcC5qcyIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvdXRpbC9zdXBwb3J0L2lzQnVmZmVyQnJvd3Nlci5qcyIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvdXRpbC91dGlsLmpzIiwid2VicGFjazovLy8od2VicGFjaykvYnVpbGRpbi9nbG9iYWwuanMiLCJ3ZWJwYWNrOi8vLy4vbm9kZV9tb2R1bGVzL3lhbGxpc3QveWFsbGlzdC5qcyIsIndlYnBhY2s6Ly8vLi9zcmMvZmlyZWNyeXB0LmpzIiwid2VicGFjazovLy8uL3NyYy91dGlscy5qcyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiO0FBQUE7QUFDQTs7QUFFQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7O0FBRUE7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7OztBQUdBO0FBQ0E7O0FBRUE7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQSxrREFBMEMsZ0NBQWdDO0FBQzFFO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0EsZ0VBQXdELGtCQUFrQjtBQUMxRTtBQUNBLHlEQUFpRCxjQUFjO0FBQy9EOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxpREFBeUMsaUNBQWlDO0FBQzFFLHdIQUFnSCxtQkFBbUIsRUFBRTtBQUNySTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBLG1DQUEyQiwwQkFBMEIsRUFBRTtBQUN2RCx5Q0FBaUMsZUFBZTtBQUNoRDtBQUNBO0FBQ0E7O0FBRUE7QUFD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TztBQUMzQixvQkFBb0IsTUFBTTtBQUMxQjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxVQUFVOztBQUVWO0FBQ0E7QUFDQTtBQUNBLG9CQUFvQixPQUFPO0FBQzNCLG9CQUFvQixNQUFNO0FBQzFCO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFVBQVU7O0FBRVY7QUFDQTtBQUNBO0FBQ0Esb0JBQW9CLE9BQU87QUFDM0Isb0JBQW9CLE1BQU07QUFDMUI7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsTUFBTTs7QUFFTjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0Esd0JBQXdCLE1BQU07QUFDOUIsd0JBQXdCLE9BQU87QUFDL0I7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQSxVQUFVOztBQUVWO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0Esd0JBQXdCLE1BQU07QUFDOUIsd0JBQXdCLE9BQU87QUFDL0I7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBLFVBQVU7O0FBRVY7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0EsY0FBYztBQUNkO0FBQ0E7O0FBRUE7QUFDQSw0QkFBNEIsZUFBZTtBQUMzQztBQUNBO0FBQ0E7O0FBRUE7QUFDQSxNQUFNOztBQUVOO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0Esb0JBQW9CLFVBQVU7QUFDOUIsb0JBQW9CLE9BQU87QUFDM0I7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNB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QUFFQTtBQUNBO0FBQ0Esd0JBQXdCLFFBQVE7QUFDaEM7QUFDQTtBQUNBLE1BQU07O0FBRU47QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsVUFBVTs7QUFFVjtBQUNBO0FBQ0EsNEJBQTRCLFFBQVE7QUFDcEM7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFVBQVU7O0FBRVY7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTs7QUFFQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBOztBQUVBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBOztBQUVBO0FBQ0EsNEJBQTRCLE9BQU87QUFDbkM7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBLFVBQVU7O0FBRVY7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQSxNQUFNOztBQUVOO0FB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Qjs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsZUFBZTtBQUNmO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0EsR0FBRzs7QUFFSDtBQUNBO0FBQ0E7QUFDQSxXQUFXOztBQUVYO0FBQ0E7O0FBRUE7QUFDQTs7QUFFQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0EsOEJBQThCLFFBQVE7QUFDdEM7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLEtBQUs7QUFDTDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsR0FBRztBQUNIOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLEdBQUc7QUFDSDtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQSxxREFBcUQ7QUFDckQ7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7Ozs7Ozs7Ozs7O0FDbGRBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxTQUFTO0FBQ1Q7QUFDQTtBQUNBLEtBQUs7QUFDTDtBQUNBO0FBQ0EsQ0FBQztBQUNEO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0E7QUFDQTs7O0FBR0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLEtBQUs7QUFDTDtBQUNBO0FBQ0E7QUFDQSxTQUFTO0FBQ1Q7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7OztBQUlBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxLQUFLO0FBQ0w7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQSx1QkFBdUIsc0JBQXNCO0FBQzdDO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EscUJBQXFCO0FBQ3JCOztBQUVBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQSxxQ0FBcUM7O0FBRXJDO0FBQ0E7QUFDQTs7QUFFQSwyQkFBMkI7QUFDM0I7QUFDQTtBQUNBO0FBQ0EsNEJBQTRCLFVBQVU7Ozs7Ozs7Ozs7OztBQ3ZMdEM7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQSxDQUFDO0FBQ0Q7QUFDQTs7Ozs7Ozs7Ozs7OztBQ1JBOztBQUVBOztBQUVBO0FBQ0E7QUFDQTs7QUFFQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsT0FBTztBQUNQO0FBQ0E7QUFDQTtBQUNBLE9BQU87QUFDUDtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsR0FBRztBQUNIOztBQUVBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxHQUFHO0FBQ0g7O0FBRUE7QUFDQTtBQUNBO0FBQ0EsR0FBRztBQUNILHNCQUFzQjtBQUN0QjtBQUNBO0FBQ0EsQ0FBQzs7QUFFRDtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7Ozs7Ozs7Ozs7OztBQ2hIQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsQzs7Ozs7Ozs7Ozs7QUNMQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsbUJBQW1CLHNCQUFzQjtBQUN6QztBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxTQUFTO0FBQ1Q7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLEdBQUc7QUFDSCx1QkFBdUIsU0FBUztBQUNoQztBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7OztBQUdBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsT0FBTztBQUNQO0FBQ0EsT0FBTztBQUNQO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBOzs7QUFHQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLEtBQUs7QUFDTDtBQUNBO0FBQ0E7QUFDQTtBQUNBOzs7QUFHQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFdBQVcsT0FBTztBQUNsQixXQUFXLE9BQU87QUFDbEI7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLEdBQUc7QUFDSDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7OztBQUdBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7O0FBR0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQSxHQUFHO0FBQ0g7QUFDQTtBQUNBOzs7QUFHQTtBQUNBO0FBQ0E7OztBQUdBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBLEdBQUc7O0FBRUg7QUFDQTs7O0FBR0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQSw0Q0FBNEMsS0FBSzs7QUFFakQ7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQSxLQUFLO0FBQ0w7QUFDQTtBQUNBOztBQUVBOztBQUVBO0FBQ0E7QUFDQTtBQUNBLEdBQUc7QUFDSDtBQUNBO0FBQ0EsS0FBSztBQUNMOztBQUVBOztBQUVBO0FBQ0E7OztBQUdBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7OztBQUdBO0FBQ0E7QUFDQTs7O0FBR0E7QUFDQTtBQUNBLG1DQUFtQyxPQUFPO0FBQzFDO0FBQ0E7QUFDQTtBQUNBLEtBQUs7QUFDTDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsR0FBRztBQUNIO0FBQ0E7OztBQUdBO0FBQ0E7QUFDQSx5REFBeUQ7QUFDekQ7QUFDQTtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQSxHQUFHO0FBQ0g7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLE9BQU87QUFDUDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxXQUFXO0FBQ1gsU0FBUztBQUNUO0FBQ0E7QUFDQSxXQUFXO0FBQ1g7QUFDQTtBQUNBLEtBQUs7QUFDTDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBOzs7QUFHQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxHQUFHOztBQUVIO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTs7O0FBR0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBOztBQUVBO0FBQ0E7QUFDQTs7O0FBR0E7QUFDQTtBQUNBOzs7QUFHQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7OztBQUdBO0FBQ0E7QUFDQTtBQUNBOzs7QUFHQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxXQUFXLFNBQVM7QUFDcEI7QUFDQSxXQUFXLFNBQVM7QUFDcEI7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBOzs7Ozs7Ozs7Ozs7O0FDemtCQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQSxDQUFDOztBQUVEO0FBQ0E7QUFDQTtBQUNBLENBQUM7QUFDRDtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBLDRDQUE0Qzs7QUFFNUM7Ozs7Ozs7Ozs7OztBQ25CQTs7QUFFQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBLEtBQUs7QUFDTCxHQUFHO0FBQ0gseUNBQXlDLE9BQU87QUFDaEQ7QUFDQTtBQUNBOztBQUVBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0EsdUNBQXVDLE9BQU87QUFDOUM7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQSx1Q0FBdUMsT0FBTztBQUM5QztBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtB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QTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxLQUFLO0FBQ0w7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsaUJBQWlCO0FBQ2pCO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLEtBQUs7QUFDTDtBQUNBO0FBQ0E7OztBQUdBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLEtBQUs7QUFDTDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7O0FBR0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxvQ0FBb0MsNEJBQTRCO0FBQ2hFO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNB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Q0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLDJCQUEyQixFQUFFO0FBQzdCO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBIiwiZmlsZSI6ImZpcmVjcnlwdC5qcyIsInNvdXJjZXNDb250ZW50IjpbIiBcdC8vIFRoZSBtb2R1bGUgY2FjaGVcbiBcdHZhciBpbnN0YWxsZWRNb2R1bGVzID0ge307XG5cbiBcdC8vIFRoZSByZXF1aXJlIGZ1bmN0aW9uXG4gXHRmdW5jdGlvbiBfX3dlYnBhY2tfcmVxdWlyZV9fKG1vZHVsZUlkKSB7XG5cbiBcdFx0Ly8gQ2hlY2sgaWYgbW9kdWxlIGlzIGluIGNhY2hlXG4gXHRcdGlmKGluc3RhbGxlZE1vZHVsZXNbbW9kdWxlSWRdKSB7XG4gXHRcdFx0cmV0dXJuIGluc3RhbGxlZE1vZHVsZXNbbW9kdWxlSWRdLmV4cG9ydHM7XG4gXHRcdH1cbiBcdFx0Ly8gQ3JlYXRlIGEgbmV3IG1vZHVsZSAoYW5kIHB1dCBpdCBpbnRvIHRoZSBjYWNoZSlcbiBcdFx0dmFyIG1vZHVsZSA9IGluc3RhbGxlZE1vZHVsZXNbbW9kdWxlSWRdID0ge1xuIFx0XHRcdGk6IG1vZHVsZUlkLFxuIFx0XHRcdGw6IGZhbHNlLFxuIFx0XHRcdGV4cG9ydHM6IHt9XG4gXHRcdH07XG5cbiBcdFx0Ly8gRXhlY3V0ZSB0aGUgbW9kdWxlIGZ1bmN0aW9uXG4gXHRcdG1vZHVsZXNbbW9kdWxlSWRdLmNhbGwobW9kdWxlLmV4cG9ydHMsIG1vZHVsZSwgbW9kdWxlLmV4cG9ydHMsIF9fd2VicGFja19yZXF1aXJlX18pO1xuXG4gXHRcdC8vIEZsYWcgdGhlIG1vZHVsZSBhcyBsb2FkZWRcbiBcdFx0bW9kdWxlLmwgPSB0cnVlO1xuXG4gXHRcdC8vIFJldHVybiB0aGUgZXhwb3J0cyBvZiB0aGUgbW9kdWxlXG4gXHRcdHJldHVybiBtb2R1bGUuZXhwb3J0cztcbiBcdH1cblxuXG4gXHQvLyBleHBvc2UgdGhlIG1vZHVsZXMgb2JqZWN0IChfX3dlYnBhY2tfbW9kdWxlc19fKVxuIFx0X193ZWJwYWNrX3JlcXVpcmVfXy5tID0gbW9kdWxlcztcblxuIFx0Ly8gZXhwb3NlIHRoZSBtb2R1bGUgY2FjaGVcbiBcdF9fd2VicGFja19yZXF1aXJlX18uYyA9IGluc3RhbGxlZE1vZHVsZXM7XG5cbiBcdC8vIGRlZmluZSBnZXR0ZXIgZnVuY3Rpb24gZm9yIGhhcm1vbnkgZXhwb3J0c1xuIFx0X193ZWJwYWNrX3JlcXVpcmVfXy5kID0gZnVuY3Rpb24oZXhwb3J0cywgbmFtZSwgZ2V0dGVyKSB7XG4gXHRcdGlmKCFfX3dlYnBhY2tfcmVxdWlyZV9fLm8oZXhwb3J0cywgbmFtZSkpIHtcbiBcdFx0XHRPYmplY3QuZGVmaW5lUHJvcGVydHkoZXhwb3J0cywgbmFtZSwgeyBlbnVtZXJhYmxlOiB0cnVlLCBnZXQ6IGdldHRlciB9KTtcbiBcdFx0fVxuIFx0fTtcblxuIFx0Ly8gZGVmaW5lIF9fZXNNb2R1bGUgb24gZXhwb3J0c1xuIFx0X193ZWJwYWNrX3JlcXVpcmVfXy5yID0gZnVuY3Rpb24oZXhwb3J0cykge1xuIFx0XHRpZih0eXBlb2YgU3ltYm9sICE9PSAndW5kZWZpbmVkJyAmJiBTeW1ib2wudG9TdHJpbmdUYWcpIHtcbiBcdFx0XHRPYmplY3QuZGVmaW5lUHJvcGVydHkoZXhwb3J0cywgU3ltYm9sLnRvU3RyaW5nVGFnLCB7IHZhbHVlOiAnTW9kdWxlJyB9KTtcbiBcdFx0fVxuIFx0XHRPYmplY3QuZGVmaW5lUHJvcGVydHkoZXhwb3J0cywgJ19fZXNNb2R1bGUnLCB7IHZhbHVlOiB0cnVlIH0pO1xuIFx0fTtcblxuIFx0Ly8gY3JlYXRlIGEgZmFrZSBuYW1lc3BhY2Ugb2JqZWN0XG4gXHQvLyBtb2RlICYgMTogdmFsdWUgaXMgYSBtb2R1bGUgaWQsIHJlcXVpcmUgaXRcbiBcdC8vIG1vZGUgJiAyOiBtZXJnZSBhbGwgcHJvcGVydGllcyBvZiB2YWx1ZSBpbnRvIHRoZSBuc1xuIFx0Ly8gbW9kZSAmIDQ6IHJldHVybiB2YWx1ZSB3aGVuIGFscmVhZHkgbnMgb2JqZWN0XG4gXHQvLyBtb2RlICYgOHwxOiBiZWhhdmUgbGlrZSByZXF1aXJlXG4gXHRfX3dlYnBhY2tfcmVxdWlyZV9fLnQgPSBmdW5jdGlvbih2YWx1ZSwgbW9kZSkge1xuIFx0XHRpZihtb2RlICYgMSkgdmFsdWUgPSBfX3dlYnBhY2tfcmVxdWlyZV9fKHZhbHVlKTtcbiBcdFx0aWYobW9kZSAmIDgpIHJldHVybiB2YWx1ZTtcbiBcdFx0aWYoKG1vZGUgJiA0KSAmJiB0eXBlb2YgdmFsdWUgPT09ICdvYmplY3QnICYmIHZhbHVlICYmIHZhbHVlLl9fZXNNb2R1bGUpIHJldHVybiB2YWx1ZTtcbiBcdFx0dmFyIG5zID0gT2JqZWN0LmNyZWF0ZShudWxsKTtcbiBcdFx0X193ZWJwYWNrX3JlcXVpcmVfXy5yKG5zKTtcbiBcdFx0T2JqZWN0LmRlZmluZVByb3BlcnR5KG5zLCAnZGVmYXVsdCcsIHsgZW51bWVyYWJsZTogdHJ1ZSwgdmFsdWU6IHZhbHVlIH0pO1xuIFx0XHRpZihtb2RlICYgMiAmJiB0eXBlb2YgdmFsdWUgIT0gJ3N0cmluZycpIGZvcih2YXIga2V5IGluIHZhbHVlKSBfX3dlYnBhY2tfcmVxdWlyZV9fLmQobnMsIGtleSwgZnVuY3Rpb24oa2V5KSB7IHJldHVybiB2YWx1ZVtrZXldOyB9LmJpbmQobnVsbCwga2V5KSk7XG4gXHRcdHJldHVybiBucztcbiBcdH07XG5cbiBcdC8vIGdldERlZmF1bHRFeHBvcnQgZnVuY3Rpb24gZm9yIGNvbXBhdGliaWxpdHkgd2l0aCBub24taGFybW9ueSBtb2R1bGVzXG4gXHRfX3dlYnBhY2tfcmVxdWlyZV9fLm4gPSBmdW5jdGlvbihtb2R1bGUpIHtcbiBcdFx0dmFyIGdldHRlciA9IG1vZHVsZSAmJiBtb2R1bGUuX19lc01vZHVsZSA/XG4gXHRcdFx0ZnVuY3Rpb24gZ2V0RGVmYXVsdCgpIHsgcmV0dXJuIG1vZHVsZVsnZGVmYXVsdCddOyB9IDpcbiBcdFx0XHRmdW5jdGlvbiBnZXRNb2R1bGVFeHBvcnRzKCkgeyByZXR1cm4gbW9kdWxlOyB9O1xuIFx0XHRfX3dlYnBhY2tfcmVxdWlyZV9fLmQoZ2V0dGVyLCAnYScsIGdldHRlcik7XG4gXHRcdHJldHVybiBnZXR0ZXI7XG4gXHR9O1xuXG4gXHQvLyBPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGxcbiBcdF9fd2VicGFja19yZXF1aXJlX18ubyA9IGZ1bmN0aW9uKG9iamVjdCwgcHJvcGVydHkpIHsgcmV0dXJuIE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChvYmplY3QsIHByb3BlcnR5KTsgfTtcblxuIFx0Ly8gX193ZWJwYWNrX3B1YmxpY19wYXRoX19cbiBcdF9fd2VicGFja19yZXF1aXJlX18ucCA9IFwiXCI7XG5cblxuIFx0Ly8gTG9hZCBlbnRyeSBtb2R1bGUgYW5kIHJldHVybiBleHBvcnRzXG4gXHRyZXR1cm4gX193ZWJwYWNrX3JlcXVpcmVfXyhfX3dlYnBhY2tfcmVxdWlyZV9fLnMgPSBcIi4vaW5kZXguanNcIik7XG4iLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoJy4vc3JjL2ZpcmVjcnlwdC5qcycpO1xuIiwiOyhmdW5jdGlvbiAocm9vdCwgZmFjdG9yeSwgdW5kZWYpIHtcblx0aWYgKHR5cGVvZiBleHBvcnRzID09PSBcIm9iamVjdFwiKSB7XG5cdFx0Ly8gQ29tbW9uSlNcblx0XHRtb2R1bGUuZXhwb3J0cyA9IGV4cG9ydHMgPSBmYWN0b3J5KHJlcXVpcmUoXCIuL2NvcmVcIiksIHJlcXVpcmUoXCIuL2VuYy1iYXNlNjRcIiksIHJlcXVpcmUoXCIuL21kNVwiKSwgcmVxdWlyZShcIi4vZXZwa2RmXCIpLCByZXF1aXJlKFwiLi9jaXBoZXItY29yZVwiKSk7XG5cdH1cblx0ZWxzZSBpZiAodHlwZW9mIGRlZmluZSA9PT0gXCJmdW5jdGlvblwiICYmIGRlZmluZS5hbWQpIHtcblx0XHQvLyBBTURcblx0XHRkZWZpbmUoW1wiLi9jb3JlXCIsIFwiLi9lbmMtYmFzZTY0XCIsIFwiLi9tZDVcIiwgXCIuL2V2cGtkZlwiLCBcIi4vY2lwaGVyLWNvcmVcIl0sIGZhY3RvcnkpO1xuXHR9XG5cdGVsc2Uge1xuXHRcdC8vIEdsb2JhbCAoYnJvd3Nlcilcblx0XHRmYWN0b3J5KHJvb3QuQ3J5cHRvSlMpO1xuXHR9XG59KHRoaXMsIGZ1bmN0aW9uIChDcnlwdG9KUykge1xuXG5cdChmdW5jdGlvbiAoKSB7XG5cdCAgICAvLyBTaG9ydGN1dHNcblx0ICAgIHZhciBDID0gQ3J5cHRvSlM7XG5cdCAgICB2YXIgQ19saWIgPSBDLmxpYjtcblx0ICAgIHZhciBCbG9ja0NpcGhlciA9IENfbGliLkJsb2NrQ2lwaGVyO1xuXHQgICAgdmFyIENfYWxnbyA9IEMuYWxnbztcblxuXHQgICAgLy8gTG9va3VwIHRhYmxlc1xuXHQgICAgdmFyIFNCT1ggPSBbXTtcblx0ICAgIHZhciBJTlZfU0JPWCA9IFtdO1xuXHQgICAgdmFyIFNVQl9NSVhfMCA9IFtdO1xuXHQgICAgdmFyIFNVQl9NSVhfMSA9IFtdO1xuXHQgICAgdmFyIFNVQl9NSVhfMiA9IFtdO1xuXHQgICAgdmFyIFNVQl9NSVhfMyA9IFtdO1xuXHQgICAgdmFyIElOVl9TVUJfTUlYXzAgPSBbXTtcblx0ICAgIHZhciBJTlZfU1VCX01JWF8xID0gW107XG5cdCAgICB2YXIgSU5WX1NVQl9NSVhfMiA9IFtdO1xuXHQgICAgdmFyIElOVl9TVUJfTUlYXzMgPSBbXTtcblxuXHQgICAgLy8gQ29tcHV0ZSBsb29rdXAgdGFibGVzXG5cdCAgICAoZnVuY3Rpb24gKCkge1xuXHQgICAgICAgIC8vIENvbXB1dGUgZG91YmxlIHRhYmxlXG5cdCAgICAgICAgdmFyIGQgPSBbXTtcblx0ICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IDI1NjsgaSsrKSB7XG5cdCAgICAgICAgICAgIGlmIChpIDwgMTI4KSB7XG5cdCAgICAgICAgICAgICAgICBkW2ldID0gaSA8PCAxO1xuXHQgICAgICAgICAgICB9IGVsc2Uge1xuXHQgICAgICAgICAgICAgICAgZFtpXSA9IChpIDw8IDEpIF4gMHgxMWI7XG5cdCAgICAgICAgICAgIH1cblx0ICAgICAgICB9XG5cblx0ICAgICAgICAvLyBXYWxrIEdGKDJeOClcblx0ICAgICAgICB2YXIgeCA9IDA7XG5cdCAgICAgICAgdmFyIHhpID0gMDtcblx0ICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IDI1NjsgaSsrKSB7XG5cdCAgICAgICAgICAgIC8vIENvbXB1dGUgc2JveFxuXHQgICAgICAgICAgICB2YXIgc3ggPSB4aSBeICh4aSA8PCAxKSBeICh4aSA8PCAyKSBeICh4aSA8PCAzKSBeICh4aSA8PCA0KTtcblx0ICAgICAgICAgICAgc3ggPSAoc3ggPj4+IDgpIF4gKHN4ICYgMHhmZikgXiAweDYzO1xuXHQgICAgICAgICAgICBTQk9YW3hdID0gc3g7XG5cdCAgICAgICAgICAgIElOVl9TQk9YW3N4XSA9IHg7XG5cblx0ICAgICAgICAgICAgLy8gQ29tcHV0ZSBtdWx0aXBsaWNhdGlvblxuXHQgICAgICAgICAgICB2YXIgeDIgPSBkW3hdO1xuXHQgICAgICAgICAgICB2YXIgeDQgPSBkW3gyXTtcblx0ICAgICAgICAgICAgdmFyIHg4ID0gZFt4NF07XG5cblx0ICAgICAgICAgICAgLy8gQ29tcHV0ZSBzdWIgYnl0ZXMsIG1peCBjb2x1bW5zIHRhYmxlc1xuXHQgICAgICAgICAgICB2YXIgdCA9IChkW3N4XSAqIDB4MTAxKSBeIChzeCAqIDB4MTAxMDEwMCk7XG5cdCAgICAgICAgICAgIFNVQl9NSVhfMFt4XSA9ICh0IDw8IDI0KSB8ICh0ID4+PiA4KTtcblx0ICAgICAgICAgICAgU1VCX01JWF8xW3hdID0gKHQgPDwgMTYpIHwgKHQgPj4+IDE2KTtcblx0ICAgICAgICAgICAgU1VCX01JWF8yW3hdID0gKHQgPDwgOCkgIHwgKHQgPj4+IDI0KTtcblx0ICAgICAgICAgICAgU1VCX01JWF8zW3hdID0gdDtcblxuXHQgICAgICAgICAgICAvLyBDb21wdXRlIGludiBzdWIgYnl0ZXMsIGludiBtaXggY29sdW1ucyB0YWJsZXNcblx0ICAgICAgICAgICAgdmFyIHQgPSAoeDggKiAweDEwMTAxMDEpIF4gKHg0ICogMHgxMDAwMSkgXiAoeDIgKiAweDEwMSkgXiAoeCAqIDB4MTAxMDEwMCk7XG5cdCAgICAgICAgICAgIElOVl9TVUJfTUlYXzBbc3hdID0gKHQgPDwgMjQpIHwgKHQgPj4+IDgpO1xuXHQgICAgICAgICAgICBJTlZfU1VCX01JWF8xW3N4XSA9ICh0IDw8IDE2KSB8ICh0ID4+PiAxNik7XG5cdCAgICAgICAgICAgIElOVl9TVUJfTUlYXzJbc3hdID0gKHQgPDwgOCkgIHwgKHQgPj4+IDI0KTtcblx0ICAgICAgICAgICAgSU5WX1NVQl9NSVhfM1tzeF0gPSB0O1xuXG5cdCAgICAgICAgICAgIC8vIENvbXB1dGUgbmV4dCBjb3VudGVyXG5cdCAgICAgICAgICAgIGlmICgheCkge1xuXHQgICAgICAgICAgICAgICAgeCA9IHhpID0gMTtcblx0ICAgICAgICAgICAgfSBlbHNlIHtcblx0ICAgICAgICAgICAgICAgIHggPSB4MiBeIGRbZFtkW3g4IF4geDJdXV07XG5cdCAgICAgICAgICAgICAgICB4aSBePSBkW2RbeGldXTtcblx0ICAgICAgICAgICAgfVxuXHQgICAgICAgIH1cblx0ICAgIH0oKSk7XG5cblx0ICAgIC8vIFByZWNvbXB1dGVkIFJjb24gbG9va3VwXG5cdCAgICB2YXIgUkNPTiA9IFsweDAwLCAweDAxLCAweDAyLCAweDA0LCAweDA4LCAweDEwLCAweDIwLCAweDQwLCAweDgwLCAweDFiLCAweDM2XTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBBRVMgYmxvY2sgY2lwaGVyIGFsZ29yaXRobS5cblx0ICAgICAqL1xuXHQgICAgdmFyIEFFUyA9IENfYWxnby5BRVMgPSBCbG9ja0NpcGhlci5leHRlbmQoe1xuXHQgICAgICAgIF9kb1Jlc2V0OiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgIC8vIFNraXAgcmVzZXQgb2YgblJvdW5kcyBoYXMgYmVlbiBzZXQgYmVmb3JlIGFuZCBrZXkgZGlkIG5vdCBjaGFuZ2Vcblx0ICAgICAgICAgICAgaWYgKHRoaXMuX25Sb3VuZHMgJiYgdGhpcy5fa2V5UHJpb3JSZXNldCA9PT0gdGhpcy5fa2V5KSB7XG5cdCAgICAgICAgICAgICAgICByZXR1cm47XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICAgICAgdmFyIGtleSA9IHRoaXMuX2tleVByaW9yUmVzZXQgPSB0aGlzLl9rZXk7XG5cdCAgICAgICAgICAgIHZhciBrZXlXb3JkcyA9IGtleS53b3Jkcztcblx0ICAgICAgICAgICAgdmFyIGtleVNpemUgPSBrZXkuc2lnQnl0ZXMgLyA0O1xuXG5cdCAgICAgICAgICAgIC8vIENvbXB1dGUgbnVtYmVyIG9mIHJvdW5kc1xuXHQgICAgICAgICAgICB2YXIgblJvdW5kcyA9IHRoaXMuX25Sb3VuZHMgPSBrZXlTaXplICsgNjtcblxuXHQgICAgICAgICAgICAvLyBDb21wdXRlIG51bWJlciBvZiBrZXkgc2NoZWR1bGUgcm93c1xuXHQgICAgICAgICAgICB2YXIga3NSb3dzID0gKG5Sb3VuZHMgKyAxKSAqIDQ7XG5cblx0ICAgICAgICAgICAgLy8gQ29tcHV0ZSBrZXkgc2NoZWR1bGVcblx0ICAgICAgICAgICAgdmFyIGtleVNjaGVkdWxlID0gdGhpcy5fa2V5U2NoZWR1bGUgPSBbXTtcblx0ICAgICAgICAgICAgZm9yICh2YXIga3NSb3cgPSAwOyBrc1JvdyA8IGtzUm93czsga3NSb3crKykge1xuXHQgICAgICAgICAgICAgICAgaWYgKGtzUm93IDwga2V5U2l6ZSkge1xuXHQgICAgICAgICAgICAgICAgICAgIGtleVNjaGVkdWxlW2tzUm93XSA9IGtleVdvcmRzW2tzUm93XTtcblx0ICAgICAgICAgICAgICAgIH0gZWxzZSB7XG5cdCAgICAgICAgICAgICAgICAgICAgdmFyIHQgPSBrZXlTY2hlZHVsZVtrc1JvdyAtIDFdO1xuXG5cdCAgICAgICAgICAgICAgICAgICAgaWYgKCEoa3NSb3cgJSBrZXlTaXplKSkge1xuXHQgICAgICAgICAgICAgICAgICAgICAgICAvLyBSb3Qgd29yZFxuXHQgICAgICAgICAgICAgICAgICAgICAgICB0ID0gKHQgPDwgOCkgfCAodCA+Pj4gMjQpO1xuXG5cdCAgICAgICAgICAgICAgICAgICAgICAgIC8vIFN1YiB3b3JkXG5cdCAgICAgICAgICAgICAgICAgICAgICAgIHQgPSAoU0JPWFt0ID4+PiAyNF0gPDwgMjQpIHwgKFNCT1hbKHQgPj4+IDE2KSAmIDB4ZmZdIDw8IDE2KSB8IChTQk9YWyh0ID4+PiA4KSAmIDB4ZmZdIDw8IDgpIHwgU0JPWFt0ICYgMHhmZl07XG5cblx0ICAgICAgICAgICAgICAgICAgICAgICAgLy8gTWl4IFJjb25cblx0ICAgICAgICAgICAgICAgICAgICAgICAgdCBePSBSQ09OWyhrc1JvdyAvIGtleVNpemUpIHwgMF0gPDwgMjQ7XG5cdCAgICAgICAgICAgICAgICAgICAgfSBlbHNlIGlmIChrZXlTaXplID4gNiAmJiBrc1JvdyAlIGtleVNpemUgPT0gNCkge1xuXHQgICAgICAgICAgICAgICAgICAgICAgICAvLyBTdWIgd29yZFxuXHQgICAgICAgICAgICAgICAgICAgICAgICB0ID0gKFNCT1hbdCA+Pj4gMjRdIDw8IDI0KSB8IChTQk9YWyh0ID4+PiAxNikgJiAweGZmXSA8PCAxNikgfCAoU0JPWFsodCA+Pj4gOCkgJiAweGZmXSA8PCA4KSB8IFNCT1hbdCAmIDB4ZmZdO1xuXHQgICAgICAgICAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAgICAgICAgIGtleVNjaGVkdWxlW2tzUm93XSA9IGtleVNjaGVkdWxlW2tzUm93IC0ga2V5U2l6ZV0gXiB0O1xuXHQgICAgICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgLy8gQ29tcHV0ZSBpbnYga2V5IHNjaGVkdWxlXG5cdCAgICAgICAgICAgIHZhciBpbnZLZXlTY2hlZHVsZSA9IHRoaXMuX2ludktleVNjaGVkdWxlID0gW107XG5cdCAgICAgICAgICAgIGZvciAodmFyIGludktzUm93ID0gMDsgaW52S3NSb3cgPCBrc1Jvd3M7IGludktzUm93KyspIHtcblx0ICAgICAgICAgICAgICAgIHZhciBrc1JvdyA9IGtzUm93cyAtIGludktzUm93O1xuXG5cdCAgICAgICAgICAgICAgICBpZiAoaW52S3NSb3cgJSA0KSB7XG5cdCAgICAgICAgICAgICAgICAgICAgdmFyIHQgPSBrZXlTY2hlZHVsZVtrc1Jvd107XG5cdCAgICAgICAgICAgICAgICB9IGVsc2Uge1xuXHQgICAgICAgICAgICAgICAgICAgIHZhciB0ID0ga2V5U2NoZWR1bGVba3NSb3cgLSA0XTtcblx0ICAgICAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAgICAgaWYgKGludktzUm93IDwgNCB8fCBrc1JvdyA8PSA0KSB7XG5cdCAgICAgICAgICAgICAgICAgICAgaW52S2V5U2NoZWR1bGVbaW52S3NSb3ddID0gdDtcblx0ICAgICAgICAgICAgICAgIH0gZWxzZSB7XG5cdCAgICAgICAgICAgICAgICAgICAgaW52S2V5U2NoZWR1bGVbaW52S3NSb3ddID0gSU5WX1NVQl9NSVhfMFtTQk9YW3QgPj4+IDI0XV0gXiBJTlZfU1VCX01JWF8xW1NCT1hbKHQgPj4+IDE2KSAmIDB4ZmZdXSBeXG5cdCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgSU5WX1NVQl9NSVhfMltTQk9YWyh0ID4+PiA4KSAmIDB4ZmZdXSBeIElOVl9TVUJfTUlYXzNbU0JPWFt0ICYgMHhmZl1dO1xuXHQgICAgICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICB9XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIGVuY3J5cHRCbG9jazogZnVuY3Rpb24gKE0sIG9mZnNldCkge1xuXHQgICAgICAgICAgICB0aGlzLl9kb0NyeXB0QmxvY2soTSwgb2Zmc2V0LCB0aGlzLl9rZXlTY2hlZHVsZSwgU1VCX01JWF8wLCBTVUJfTUlYXzEsIFNVQl9NSVhfMiwgU1VCX01JWF8zLCBTQk9YKTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgZGVjcnlwdEJsb2NrOiBmdW5jdGlvbiAoTSwgb2Zmc2V0KSB7XG5cdCAgICAgICAgICAgIC8vIFN3YXAgMm5kIGFuZCA0dGggcm93c1xuXHQgICAgICAgICAgICB2YXIgdCA9IE1bb2Zmc2V0ICsgMV07XG5cdCAgICAgICAgICAgIE1bb2Zmc2V0ICsgMV0gPSBNW29mZnNldCArIDNdO1xuXHQgICAgICAgICAgICBNW29mZnNldCArIDNdID0gdDtcblxuXHQgICAgICAgICAgICB0aGlzLl9kb0NyeXB0QmxvY2soTSwgb2Zmc2V0LCB0aGlzLl9pbnZLZXlTY2hlZHVsZSwgSU5WX1NVQl9NSVhfMCwgSU5WX1NVQl9NSVhfMSwgSU5WX1NVQl9NSVhfMiwgSU5WX1NVQl9NSVhfMywgSU5WX1NCT1gpO1xuXG5cdCAgICAgICAgICAgIC8vIEludiBzd2FwIDJuZCBhbmQgNHRoIHJvd3Ncblx0ICAgICAgICAgICAgdmFyIHQgPSBNW29mZnNldCArIDFdO1xuXHQgICAgICAgICAgICBNW29mZnNldCArIDFdID0gTVtvZmZzZXQgKyAzXTtcblx0ICAgICAgICAgICAgTVtvZmZzZXQgKyAzXSA9IHQ7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIF9kb0NyeXB0QmxvY2s6IGZ1bmN0aW9uIChNLCBvZmZzZXQsIGtleVNjaGVkdWxlLCBTVUJfTUlYXzAsIFNVQl9NSVhfMSwgU1VCX01JWF8yLCBTVUJfTUlYXzMsIFNCT1gpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRcblx0ICAgICAgICAgICAgdmFyIG5Sb3VuZHMgPSB0aGlzLl9uUm91bmRzO1xuXG5cdCAgICAgICAgICAgIC8vIEdldCBpbnB1dCwgYWRkIHJvdW5kIGtleVxuXHQgICAgICAgICAgICB2YXIgczAgPSBNW29mZnNldF0gICAgIF4ga2V5U2NoZWR1bGVbMF07XG5cdCAgICAgICAgICAgIHZhciBzMSA9IE1bb2Zmc2V0ICsgMV0gXiBrZXlTY2hlZHVsZVsxXTtcblx0ICAgICAgICAgICAgdmFyIHMyID0gTVtvZmZzZXQgKyAyXSBeIGtleVNjaGVkdWxlWzJdO1xuXHQgICAgICAgICAgICB2YXIgczMgPSBNW29mZnNldCArIDNdIF4ga2V5U2NoZWR1bGVbM107XG5cblx0ICAgICAgICAgICAgLy8gS2V5IHNjaGVkdWxlIHJvdyBjb3VudGVyXG5cdCAgICAgICAgICAgIHZhciBrc1JvdyA9IDQ7XG5cblx0ICAgICAgICAgICAgLy8gUm91bmRzXG5cdCAgICAgICAgICAgIGZvciAodmFyIHJvdW5kID0gMTsgcm91bmQgPCBuUm91bmRzOyByb3VuZCsrKSB7XG5cdCAgICAgICAgICAgICAgICAvLyBTaGlmdCByb3dzLCBzdWIgYnl0ZXMsIG1peCBjb2x1bW5zLCBhZGQgcm91bmQga2V5XG5cdCAgICAgICAgICAgICAgICB2YXIgdDAgPSBTVUJfTUlYXzBbczAgPj4+IDI0XSBeIFNVQl9NSVhfMVsoczEgPj4+IDE2KSAmIDB4ZmZdIF4gU1VCX01JWF8yWyhzMiA+Pj4gOCkgJiAweGZmXSBeIFNVQl9NSVhfM1tzMyAmIDB4ZmZdIF4ga2V5U2NoZWR1bGVba3NSb3crK107XG5cdCAgICAgICAgICAgICAgICB2YXIgdDEgPSBTVUJfTUlYXzBbczEgPj4+IDI0XSBeIFNVQl9NSVhfMVsoczIgPj4+IDE2KSAmIDB4ZmZdIF4gU1VCX01JWF8yWyhzMyA+Pj4gOCkgJiAweGZmXSBeIFNVQl9NSVhfM1tzMCAmIDB4ZmZdIF4ga2V5U2NoZWR1bGVba3NSb3crK107XG5cdCAgICAgICAgICAgICAgICB2YXIgdDIgPSBTVUJfTUlYXzBbczIgPj4+IDI0XSBeIFNVQl9NSVhfMVsoczMgPj4+IDE2KSAmIDB4ZmZdIF4gU1VCX01JWF8yWyhzMCA+Pj4gOCkgJiAweGZmXSBeIFNVQl9NSVhfM1tzMSAmIDB4ZmZdIF4ga2V5U2NoZWR1bGVba3NSb3crK107XG5cdCAgICAgICAgICAgICAgICB2YXIgdDMgPSBTVUJfTUlYXzBbczMgPj4+IDI0XSBeIFNVQl9NSVhfMVsoczAgPj4+IDE2KSAmIDB4ZmZdIF4gU1VCX01JWF8yWyhzMSA+Pj4gOCkgJiAweGZmXSBeIFNVQl9NSVhfM1tzMiAmIDB4ZmZdIF4ga2V5U2NoZWR1bGVba3NSb3crK107XG5cblx0ICAgICAgICAgICAgICAgIC8vIFVwZGF0ZSBzdGF0ZVxuXHQgICAgICAgICAgICAgICAgczAgPSB0MDtcblx0ICAgICAgICAgICAgICAgIHMxID0gdDE7XG5cdCAgICAgICAgICAgICAgICBzMiA9IHQyO1xuXHQgICAgICAgICAgICAgICAgczMgPSB0Mztcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIC8vIFNoaWZ0IHJvd3MsIHN1YiBieXRlcywgYWRkIHJvdW5kIGtleVxuXHQgICAgICAgICAgICB2YXIgdDAgPSAoKFNCT1hbczAgPj4+IDI0XSA8PCAyNCkgfCAoU0JPWFsoczEgPj4+IDE2KSAmIDB4ZmZdIDw8IDE2KSB8IChTQk9YWyhzMiA+Pj4gOCkgJiAweGZmXSA8PCA4KSB8IFNCT1hbczMgJiAweGZmXSkgXiBrZXlTY2hlZHVsZVtrc1JvdysrXTtcblx0ICAgICAgICAgICAgdmFyIHQxID0gKChTQk9YW3MxID4+PiAyNF0gPDwgMjQpIHwgKFNCT1hbKHMyID4+PiAxNikgJiAweGZmXSA8PCAxNikgfCAoU0JPWFsoczMgPj4+IDgpICYgMHhmZl0gPDwgOCkgfCBTQk9YW3MwICYgMHhmZl0pIF4ga2V5U2NoZWR1bGVba3NSb3crK107XG5cdCAgICAgICAgICAgIHZhciB0MiA9ICgoU0JPWFtzMiA+Pj4gMjRdIDw8IDI0KSB8IChTQk9YWyhzMyA+Pj4gMTYpICYgMHhmZl0gPDwgMTYpIHwgKFNCT1hbKHMwID4+PiA4KSAmIDB4ZmZdIDw8IDgpIHwgU0JPWFtzMSAmIDB4ZmZdKSBeIGtleVNjaGVkdWxlW2tzUm93KytdO1xuXHQgICAgICAgICAgICB2YXIgdDMgPSAoKFNCT1hbczMgPj4+IDI0XSA8PCAyNCkgfCAoU0JPWFsoczAgPj4+IDE2KSAmIDB4ZmZdIDw8IDE2KSB8IChTQk9YWyhzMSA+Pj4gOCkgJiAweGZmXSA8PCA4KSB8IFNCT1hbczIgJiAweGZmXSkgXiBrZXlTY2hlZHVsZVtrc1JvdysrXTtcblxuXHQgICAgICAgICAgICAvLyBTZXQgb3V0cHV0XG5cdCAgICAgICAgICAgIE1bb2Zmc2V0XSAgICAgPSB0MDtcblx0ICAgICAgICAgICAgTVtvZmZzZXQgKyAxXSA9IHQxO1xuXHQgICAgICAgICAgICBNW29mZnNldCArIDJdID0gdDI7XG5cdCAgICAgICAgICAgIE1bb2Zmc2V0ICsgM10gPSB0Mztcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAga2V5U2l6ZTogMjU2LzMyXG5cdCAgICB9KTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBTaG9ydGN1dCBmdW5jdGlvbnMgdG8gdGhlIGNpcGhlcidzIG9iamVjdCBpbnRlcmZhY2UuXG5cdCAgICAgKlxuXHQgICAgICogQGV4YW1wbGVcblx0ICAgICAqXG5cdCAgICAgKiAgICAgdmFyIGNpcGhlcnRleHQgPSBDcnlwdG9KUy5BRVMuZW5jcnlwdChtZXNzYWdlLCBrZXksIGNmZyk7XG5cdCAgICAgKiAgICAgdmFyIHBsYWludGV4dCAgPSBDcnlwdG9KUy5BRVMuZGVjcnlwdChjaXBoZXJ0ZXh0LCBrZXksIGNmZyk7XG5cdCAgICAgKi9cblx0ICAgIEMuQUVTID0gQmxvY2tDaXBoZXIuX2NyZWF0ZUhlbHBlcihBRVMpO1xuXHR9KCkpO1xuXG5cblx0cmV0dXJuIENyeXB0b0pTLkFFUztcblxufSkpOyIsIjsoZnVuY3Rpb24gKHJvb3QsIGZhY3RvcnksIHVuZGVmKSB7XG5cdGlmICh0eXBlb2YgZXhwb3J0cyA9PT0gXCJvYmplY3RcIikge1xuXHRcdC8vIENvbW1vbkpTXG5cdFx0bW9kdWxlLmV4cG9ydHMgPSBleHBvcnRzID0gZmFjdG9yeShyZXF1aXJlKFwiLi9jb3JlXCIpLCByZXF1aXJlKFwiLi9ldnBrZGZcIikpO1xuXHR9XG5cdGVsc2UgaWYgKHR5cGVvZiBkZWZpbmUgPT09IFwiZnVuY3Rpb25cIiAmJiBkZWZpbmUuYW1kKSB7XG5cdFx0Ly8gQU1EXG5cdFx0ZGVmaW5lKFtcIi4vY29yZVwiLCBcIi4vZXZwa2RmXCJdLCBmYWN0b3J5KTtcblx0fVxuXHRlbHNlIHtcblx0XHQvLyBHbG9iYWwgKGJyb3dzZXIpXG5cdFx0ZmFjdG9yeShyb290LkNyeXB0b0pTKTtcblx0fVxufSh0aGlzLCBmdW5jdGlvbiAoQ3J5cHRvSlMpIHtcblxuXHQvKipcblx0ICogQ2lwaGVyIGNvcmUgY29tcG9uZW50cy5cblx0ICovXG5cdENyeXB0b0pTLmxpYi5DaXBoZXIgfHwgKGZ1bmN0aW9uICh1bmRlZmluZWQpIHtcblx0ICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgdmFyIEMgPSBDcnlwdG9KUztcblx0ICAgIHZhciBDX2xpYiA9IEMubGliO1xuXHQgICAgdmFyIEJhc2UgPSBDX2xpYi5CYXNlO1xuXHQgICAgdmFyIFdvcmRBcnJheSA9IENfbGliLldvcmRBcnJheTtcblx0ICAgIHZhciBCdWZmZXJlZEJsb2NrQWxnb3JpdGhtID0gQ19saWIuQnVmZmVyZWRCbG9ja0FsZ29yaXRobTtcblx0ICAgIHZhciBDX2VuYyA9IEMuZW5jO1xuXHQgICAgdmFyIFV0ZjggPSBDX2VuYy5VdGY4O1xuXHQgICAgdmFyIEJhc2U2NCA9IENfZW5jLkJhc2U2NDtcblx0ICAgIHZhciBDX2FsZ28gPSBDLmFsZ287XG5cdCAgICB2YXIgRXZwS0RGID0gQ19hbGdvLkV2cEtERjtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBBYnN0cmFjdCBiYXNlIGNpcGhlciB0ZW1wbGF0ZS5cblx0ICAgICAqXG5cdCAgICAgKiBAcHJvcGVydHkge251bWJlcn0ga2V5U2l6ZSBUaGlzIGNpcGhlcidzIGtleSBzaXplLiBEZWZhdWx0OiA0ICgxMjggYml0cylcblx0ICAgICAqIEBwcm9wZXJ0eSB7bnVtYmVyfSBpdlNpemUgVGhpcyBjaXBoZXIncyBJViBzaXplLiBEZWZhdWx0OiA0ICgxMjggYml0cylcblx0ICAgICAqIEBwcm9wZXJ0eSB7bnVtYmVyfSBfRU5DX1hGT1JNX01PREUgQSBjb25zdGFudCByZXByZXNlbnRpbmcgZW5jcnlwdGlvbiBtb2RlLlxuXHQgICAgICogQHByb3BlcnR5IHtudW1iZXJ9IF9ERUNfWEZPUk1fTU9ERSBBIGNvbnN0YW50IHJlcHJlc2VudGluZyBkZWNyeXB0aW9uIG1vZGUuXG5cdCAgICAgKi9cblx0ICAgIHZhciBDaXBoZXIgPSBDX2xpYi5DaXBoZXIgPSBCdWZmZXJlZEJsb2NrQWxnb3JpdGhtLmV4dGVuZCh7XG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ29uZmlndXJhdGlvbiBvcHRpb25zLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHByb3BlcnR5IHtXb3JkQXJyYXl9IGl2IFRoZSBJViB0byB1c2UgZm9yIHRoaXMgb3BlcmF0aW9uLlxuXHQgICAgICAgICAqL1xuXHQgICAgICAgIGNmZzogQmFzZS5leHRlbmQoKSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENyZWF0ZXMgdGhpcyBjaXBoZXIgaW4gZW5jcnlwdGlvbiBtb2RlLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtXb3JkQXJyYXl9IGtleSBUaGUga2V5LlxuXHQgICAgICAgICAqIEBwYXJhbSB7T2JqZWN0fSBjZmcgKE9wdGlvbmFsKSBUaGUgY29uZmlndXJhdGlvbiBvcHRpb25zIHRvIHVzZSBmb3IgdGhpcyBvcGVyYXRpb24uXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtDaXBoZXJ9IEEgY2lwaGVyIGluc3RhbmNlLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgY2lwaGVyID0gQ3J5cHRvSlMuYWxnby5BRVMuY3JlYXRlRW5jcnlwdG9yKGtleVdvcmRBcnJheSwgeyBpdjogaXZXb3JkQXJyYXkgfSk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgY3JlYXRlRW5jcnlwdG9yOiBmdW5jdGlvbiAoa2V5LCBjZmcpIHtcblx0ICAgICAgICAgICAgcmV0dXJuIHRoaXMuY3JlYXRlKHRoaXMuX0VOQ19YRk9STV9NT0RFLCBrZXksIGNmZyk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENyZWF0ZXMgdGhpcyBjaXBoZXIgaW4gZGVjcnlwdGlvbiBtb2RlLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtXb3JkQXJyYXl9IGtleSBUaGUga2V5LlxuXHQgICAgICAgICAqIEBwYXJhbSB7T2JqZWN0fSBjZmcgKE9wdGlvbmFsKSBUaGUgY29uZmlndXJhdGlvbiBvcHRpb25zIHRvIHVzZSBmb3IgdGhpcyBvcGVyYXRpb24uXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtDaXBoZXJ9IEEgY2lwaGVyIGluc3RhbmNlLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgY2lwaGVyID0gQ3J5cHRvSlMuYWxnby5BRVMuY3JlYXRlRGVjcnlwdG9yKGtleVdvcmRBcnJheSwgeyBpdjogaXZXb3JkQXJyYXkgfSk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgY3JlYXRlRGVjcnlwdG9yOiBmdW5jdGlvbiAoa2V5LCBjZmcpIHtcblx0ICAgICAgICAgICAgcmV0dXJuIHRoaXMuY3JlYXRlKHRoaXMuX0RFQ19YRk9STV9NT0RFLCBrZXksIGNmZyk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIEluaXRpYWxpemVzIGEgbmV3bHkgY3JlYXRlZCBjaXBoZXIuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge251bWJlcn0geGZvcm1Nb2RlIEVpdGhlciB0aGUgZW5jcnlwdGlvbiBvciBkZWNyeXB0aW9uIHRyYW5zb3JtYXRpb24gbW9kZSBjb25zdGFudC5cblx0ICAgICAgICAgKiBAcGFyYW0ge1dvcmRBcnJheX0ga2V5IFRoZSBrZXkuXG5cdCAgICAgICAgICogQHBhcmFtIHtPYmplY3R9IGNmZyAoT3B0aW9uYWwpIFRoZSBjb25maWd1cmF0aW9uIG9wdGlvbnMgdG8gdXNlIGZvciB0aGlzIG9wZXJhdGlvbi5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIGNpcGhlciA9IENyeXB0b0pTLmFsZ28uQUVTLmNyZWF0ZShDcnlwdG9KUy5hbGdvLkFFUy5fRU5DX1hGT1JNX01PREUsIGtleVdvcmRBcnJheSwgeyBpdjogaXZXb3JkQXJyYXkgfSk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgaW5pdDogZnVuY3Rpb24gKHhmb3JtTW9kZSwga2V5LCBjZmcpIHtcblx0ICAgICAgICAgICAgLy8gQXBwbHkgY29uZmlnIGRlZmF1bHRzXG5cdCAgICAgICAgICAgIHRoaXMuY2ZnID0gdGhpcy5jZmcuZXh0ZW5kKGNmZyk7XG5cblx0ICAgICAgICAgICAgLy8gU3RvcmUgdHJhbnNmb3JtIG1vZGUgYW5kIGtleVxuXHQgICAgICAgICAgICB0aGlzLl94Zm9ybU1vZGUgPSB4Zm9ybU1vZGU7XG5cdCAgICAgICAgICAgIHRoaXMuX2tleSA9IGtleTtcblxuXHQgICAgICAgICAgICAvLyBTZXQgaW5pdGlhbCB2YWx1ZXNcblx0ICAgICAgICAgICAgdGhpcy5yZXNldCgpO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBSZXNldHMgdGhpcyBjaXBoZXIgdG8gaXRzIGluaXRpYWwgc3RhdGUuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIGNpcGhlci5yZXNldCgpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIHJlc2V0OiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgIC8vIFJlc2V0IGRhdGEgYnVmZmVyXG5cdCAgICAgICAgICAgIEJ1ZmZlcmVkQmxvY2tBbGdvcml0aG0ucmVzZXQuY2FsbCh0aGlzKTtcblxuXHQgICAgICAgICAgICAvLyBQZXJmb3JtIGNvbmNyZXRlLWNpcGhlciBsb2dpY1xuXHQgICAgICAgICAgICB0aGlzLl9kb1Jlc2V0KCk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIEFkZHMgZGF0YSB0byBiZSBlbmNyeXB0ZWQgb3IgZGVjcnlwdGVkLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBkYXRhVXBkYXRlIFRoZSBkYXRhIHRvIGVuY3J5cHQgb3IgZGVjcnlwdC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge1dvcmRBcnJheX0gVGhlIGRhdGEgYWZ0ZXIgcHJvY2Vzc2luZy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIGVuY3J5cHRlZCA9IGNpcGhlci5wcm9jZXNzKCdkYXRhJyk7XG5cdCAgICAgICAgICogICAgIHZhciBlbmNyeXB0ZWQgPSBjaXBoZXIucHJvY2Vzcyh3b3JkQXJyYXkpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIHByb2Nlc3M6IGZ1bmN0aW9uIChkYXRhVXBkYXRlKSB7XG5cdCAgICAgICAgICAgIC8vIEFwcGVuZFxuXHQgICAgICAgICAgICB0aGlzLl9hcHBlbmQoZGF0YVVwZGF0ZSk7XG5cblx0ICAgICAgICAgICAgLy8gUHJvY2VzcyBhdmFpbGFibGUgYmxvY2tzXG5cdCAgICAgICAgICAgIHJldHVybiB0aGlzLl9wcm9jZXNzKCk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIEZpbmFsaXplcyB0aGUgZW5jcnlwdGlvbiBvciBkZWNyeXB0aW9uIHByb2Nlc3MuXG5cdCAgICAgICAgICogTm90ZSB0aGF0IHRoZSBmaW5hbGl6ZSBvcGVyYXRpb24gaXMgZWZmZWN0aXZlbHkgYSBkZXN0cnVjdGl2ZSwgcmVhZC1vbmNlIG9wZXJhdGlvbi5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7V29yZEFycmF5fHN0cmluZ30gZGF0YVVwZGF0ZSBUaGUgZmluYWwgZGF0YSB0byBlbmNyeXB0IG9yIGRlY3J5cHQuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtXb3JkQXJyYXl9IFRoZSBkYXRhIGFmdGVyIGZpbmFsIHByb2Nlc3NpbmcuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciBlbmNyeXB0ZWQgPSBjaXBoZXIuZmluYWxpemUoKTtcblx0ICAgICAgICAgKiAgICAgdmFyIGVuY3J5cHRlZCA9IGNpcGhlci5maW5hbGl6ZSgnZGF0YScpO1xuXHQgICAgICAgICAqICAgICB2YXIgZW5jcnlwdGVkID0gY2lwaGVyLmZpbmFsaXplKHdvcmRBcnJheSk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgZmluYWxpemU6IGZ1bmN0aW9uIChkYXRhVXBkYXRlKSB7XG5cdCAgICAgICAgICAgIC8vIEZpbmFsIGRhdGEgdXBkYXRlXG5cdCAgICAgICAgICAgIGlmIChkYXRhVXBkYXRlKSB7XG5cdCAgICAgICAgICAgICAgICB0aGlzLl9hcHBlbmQoZGF0YVVwZGF0ZSk7XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAvLyBQZXJmb3JtIGNvbmNyZXRlLWNpcGhlciBsb2dpY1xuXHQgICAgICAgICAgICB2YXIgZmluYWxQcm9jZXNzZWREYXRhID0gdGhpcy5fZG9GaW5hbGl6ZSgpO1xuXG5cdCAgICAgICAgICAgIHJldHVybiBmaW5hbFByb2Nlc3NlZERhdGE7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIGtleVNpemU6IDEyOC8zMixcblxuXHQgICAgICAgIGl2U2l6ZTogMTI4LzMyLFxuXG5cdCAgICAgICAgX0VOQ19YRk9STV9NT0RFOiAxLFxuXG5cdCAgICAgICAgX0RFQ19YRk9STV9NT0RFOiAyLFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ3JlYXRlcyBzaG9ydGN1dCBmdW5jdGlvbnMgdG8gYSBjaXBoZXIncyBvYmplY3QgaW50ZXJmYWNlLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtDaXBoZXJ9IGNpcGhlciBUaGUgY2lwaGVyIHRvIGNyZWF0ZSBhIGhlbHBlciBmb3IuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtPYmplY3R9IEFuIG9iamVjdCB3aXRoIGVuY3J5cHQgYW5kIGRlY3J5cHQgc2hvcnRjdXQgZnVuY3Rpb25zLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgQUVTID0gQ3J5cHRvSlMubGliLkNpcGhlci5fY3JlYXRlSGVscGVyKENyeXB0b0pTLmFsZ28uQUVTKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBfY3JlYXRlSGVscGVyOiAoZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICBmdW5jdGlvbiBzZWxlY3RDaXBoZXJTdHJhdGVneShrZXkpIHtcblx0ICAgICAgICAgICAgICAgIGlmICh0eXBlb2Yga2V5ID09ICdzdHJpbmcnKSB7XG5cdCAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFBhc3N3b3JkQmFzZWRDaXBoZXI7XG5cdCAgICAgICAgICAgICAgICB9IGVsc2Uge1xuXHQgICAgICAgICAgICAgICAgICAgIHJldHVybiBTZXJpYWxpemFibGVDaXBoZXI7XG5cdCAgICAgICAgICAgICAgICB9XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICByZXR1cm4gZnVuY3Rpb24gKGNpcGhlcikge1xuXHQgICAgICAgICAgICAgICAgcmV0dXJuIHtcblx0ICAgICAgICAgICAgICAgICAgICBlbmNyeXB0OiBmdW5jdGlvbiAobWVzc2FnZSwga2V5LCBjZmcpIHtcblx0ICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHNlbGVjdENpcGhlclN0cmF0ZWd5KGtleSkuZW5jcnlwdChjaXBoZXIsIG1lc3NhZ2UsIGtleSwgY2ZnKTtcblx0ICAgICAgICAgICAgICAgICAgICB9LFxuXG5cdCAgICAgICAgICAgICAgICAgICAgZGVjcnlwdDogZnVuY3Rpb24gKGNpcGhlcnRleHQsIGtleSwgY2ZnKSB7XG5cdCAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBzZWxlY3RDaXBoZXJTdHJhdGVneShrZXkpLmRlY3J5cHQoY2lwaGVyLCBjaXBoZXJ0ZXh0LCBrZXksIGNmZyk7XG5cdCAgICAgICAgICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICAgICAgfTtcblx0ICAgICAgICAgICAgfTtcblx0ICAgICAgICB9KCkpXG5cdCAgICB9KTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBBYnN0cmFjdCBiYXNlIHN0cmVhbSBjaXBoZXIgdGVtcGxhdGUuXG5cdCAgICAgKlxuXHQgICAgICogQHByb3BlcnR5IHtudW1iZXJ9IGJsb2NrU2l6ZSBUaGUgbnVtYmVyIG9mIDMyLWJpdCB3b3JkcyB0aGlzIGNpcGhlciBvcGVyYXRlcyBvbi4gRGVmYXVsdDogMSAoMzIgYml0cylcblx0ICAgICAqL1xuXHQgICAgdmFyIFN0cmVhbUNpcGhlciA9IENfbGliLlN0cmVhbUNpcGhlciA9IENpcGhlci5leHRlbmQoe1xuXHQgICAgICAgIF9kb0ZpbmFsaXplOiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgIC8vIFByb2Nlc3MgcGFydGlhbCBibG9ja3Ncblx0ICAgICAgICAgICAgdmFyIGZpbmFsUHJvY2Vzc2VkQmxvY2tzID0gdGhpcy5fcHJvY2VzcyghISdmbHVzaCcpO1xuXG5cdCAgICAgICAgICAgIHJldHVybiBmaW5hbFByb2Nlc3NlZEJsb2Nrcztcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgYmxvY2tTaXplOiAxXG5cdCAgICB9KTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBNb2RlIG5hbWVzcGFjZS5cblx0ICAgICAqL1xuXHQgICAgdmFyIENfbW9kZSA9IEMubW9kZSA9IHt9O1xuXG5cdCAgICAvKipcblx0ICAgICAqIEFic3RyYWN0IGJhc2UgYmxvY2sgY2lwaGVyIG1vZGUgdGVtcGxhdGUuXG5cdCAgICAgKi9cblx0ICAgIHZhciBCbG9ja0NpcGhlck1vZGUgPSBDX2xpYi5CbG9ja0NpcGhlck1vZGUgPSBCYXNlLmV4dGVuZCh7XG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ3JlYXRlcyB0aGlzIG1vZGUgZm9yIGVuY3J5cHRpb24uXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge0NpcGhlcn0gY2lwaGVyIEEgYmxvY2sgY2lwaGVyIGluc3RhbmNlLlxuXHQgICAgICAgICAqIEBwYXJhbSB7QXJyYXl9IGl2IFRoZSBJViB3b3Jkcy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBzdGF0aWNcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIG1vZGUgPSBDcnlwdG9KUy5tb2RlLkNCQy5jcmVhdGVFbmNyeXB0b3IoY2lwaGVyLCBpdi53b3Jkcyk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgY3JlYXRlRW5jcnlwdG9yOiBmdW5jdGlvbiAoY2lwaGVyLCBpdikge1xuXHQgICAgICAgICAgICByZXR1cm4gdGhpcy5FbmNyeXB0b3IuY3JlYXRlKGNpcGhlciwgaXYpO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBDcmVhdGVzIHRoaXMgbW9kZSBmb3IgZGVjcnlwdGlvbi5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7Q2lwaGVyfSBjaXBoZXIgQSBibG9jayBjaXBoZXIgaW5zdGFuY2UuXG5cdCAgICAgICAgICogQHBhcmFtIHtBcnJheX0gaXYgVGhlIElWIHdvcmRzLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgbW9kZSA9IENyeXB0b0pTLm1vZGUuQ0JDLmNyZWF0ZURlY3J5cHRvcihjaXBoZXIsIGl2LndvcmRzKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBjcmVhdGVEZWNyeXB0b3I6IGZ1bmN0aW9uIChjaXBoZXIsIGl2KSB7XG5cdCAgICAgICAgICAgIHJldHVybiB0aGlzLkRlY3J5cHRvci5jcmVhdGUoY2lwaGVyLCBpdik7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIEluaXRpYWxpemVzIGEgbmV3bHkgY3JlYXRlZCBtb2RlLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtDaXBoZXJ9IGNpcGhlciBBIGJsb2NrIGNpcGhlciBpbnN0YW5jZS5cblx0ICAgICAgICAgKiBAcGFyYW0ge0FycmF5fSBpdiBUaGUgSVYgd29yZHMuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciBtb2RlID0gQ3J5cHRvSlMubW9kZS5DQkMuRW5jcnlwdG9yLmNyZWF0ZShjaXBoZXIsIGl2LndvcmRzKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBpbml0OiBmdW5jdGlvbiAoY2lwaGVyLCBpdikge1xuXHQgICAgICAgICAgICB0aGlzLl9jaXBoZXIgPSBjaXBoZXI7XG5cdCAgICAgICAgICAgIHRoaXMuX2l2ID0gaXY7XG5cdCAgICAgICAgfVxuXHQgICAgfSk7XG5cblx0ICAgIC8qKlxuXHQgICAgICogQ2lwaGVyIEJsb2NrIENoYWluaW5nIG1vZGUuXG5cdCAgICAgKi9cblx0ICAgIHZhciBDQkMgPSBDX21vZGUuQ0JDID0gKGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBBYnN0cmFjdCBiYXNlIENCQyBtb2RlLlxuXHQgICAgICAgICAqL1xuXHQgICAgICAgIHZhciBDQkMgPSBCbG9ja0NpcGhlck1vZGUuZXh0ZW5kKCk7XG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBDQkMgZW5jcnlwdG9yLlxuXHQgICAgICAgICAqL1xuXHQgICAgICAgIENCQy5FbmNyeXB0b3IgPSBDQkMuZXh0ZW5kKHtcblx0ICAgICAgICAgICAgLyoqXG5cdCAgICAgICAgICAgICAqIFByb2Nlc3NlcyB0aGUgZGF0YSBibG9jayBhdCBvZmZzZXQuXG5cdCAgICAgICAgICAgICAqXG5cdCAgICAgICAgICAgICAqIEBwYXJhbSB7QXJyYXl9IHdvcmRzIFRoZSBkYXRhIHdvcmRzIHRvIG9wZXJhdGUgb24uXG5cdCAgICAgICAgICAgICAqIEBwYXJhbSB7bnVtYmVyfSBvZmZzZXQgVGhlIG9mZnNldCB3aGVyZSB0aGUgYmxvY2sgc3RhcnRzLlxuXHQgICAgICAgICAgICAgKlxuXHQgICAgICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAgICAgKlxuXHQgICAgICAgICAgICAgKiAgICAgbW9kZS5wcm9jZXNzQmxvY2soZGF0YS53b3Jkcywgb2Zmc2V0KTtcblx0ICAgICAgICAgICAgICovXG5cdCAgICAgICAgICAgIHByb2Nlc3NCbG9jazogZnVuY3Rpb24gKHdvcmRzLCBvZmZzZXQpIHtcblx0ICAgICAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICAgICAgdmFyIGNpcGhlciA9IHRoaXMuX2NpcGhlcjtcblx0ICAgICAgICAgICAgICAgIHZhciBibG9ja1NpemUgPSBjaXBoZXIuYmxvY2tTaXplO1xuXG5cdCAgICAgICAgICAgICAgICAvLyBYT1IgYW5kIGVuY3J5cHRcblx0ICAgICAgICAgICAgICAgIHhvckJsb2NrLmNhbGwodGhpcywgd29yZHMsIG9mZnNldCwgYmxvY2tTaXplKTtcblx0ICAgICAgICAgICAgICAgIGNpcGhlci5lbmNyeXB0QmxvY2sod29yZHMsIG9mZnNldCk7XG5cblx0ICAgICAgICAgICAgICAgIC8vIFJlbWVtYmVyIHRoaXMgYmxvY2sgdG8gdXNlIHdpdGggbmV4dCBibG9ja1xuXHQgICAgICAgICAgICAgICAgdGhpcy5fcHJldkJsb2NrID0gd29yZHMuc2xpY2Uob2Zmc2V0LCBvZmZzZXQgKyBibG9ja1NpemUpO1xuXHQgICAgICAgICAgICB9XG5cdCAgICAgICAgfSk7XG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBDQkMgZGVjcnlwdG9yLlxuXHQgICAgICAgICAqL1xuXHQgICAgICAgIENCQy5EZWNyeXB0b3IgPSBDQkMuZXh0ZW5kKHtcblx0ICAgICAgICAgICAgLyoqXG5cdCAgICAgICAgICAgICAqIFByb2Nlc3NlcyB0aGUgZGF0YSBibG9jayBhdCBvZmZzZXQuXG5cdCAgICAgICAgICAgICAqXG5cdCAgICAgICAgICAgICAqIEBwYXJhbSB7QXJyYXl9IHdvcmRzIFRoZSBkYXRhIHdvcmRzIHRvIG9wZXJhdGUgb24uXG5cdCAgICAgICAgICAgICAqIEBwYXJhbSB7bnVtYmVyfSBvZmZzZXQgVGhlIG9mZnNldCB3aGVyZSB0aGUgYmxvY2sgc3RhcnRzLlxuXHQgICAgICAgICAgICAgKlxuXHQgICAgICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAgICAgKlxuXHQgICAgICAgICAgICAgKiAgICAgbW9kZS5wcm9jZXNzQmxvY2soZGF0YS53b3Jkcywgb2Zmc2V0KTtcblx0ICAgICAgICAgICAgICovXG5cdCAgICAgICAgICAgIHByb2Nlc3NCbG9jazogZnVuY3Rpb24gKHdvcmRzLCBvZmZzZXQpIHtcblx0ICAgICAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICAgICAgdmFyIGNpcGhlciA9IHRoaXMuX2NpcGhlcjtcblx0ICAgICAgICAgICAgICAgIHZhciBibG9ja1NpemUgPSBjaXBoZXIuYmxvY2tTaXplO1xuXG5cdCAgICAgICAgICAgICAgICAvLyBSZW1lbWJlciB0aGlzIGJsb2NrIHRvIHVzZSB3aXRoIG5leHQgYmxvY2tcblx0ICAgICAgICAgICAgICAgIHZhciB0aGlzQmxvY2sgPSB3b3Jkcy5zbGljZShvZmZzZXQsIG9mZnNldCArIGJsb2NrU2l6ZSk7XG5cblx0ICAgICAgICAgICAgICAgIC8vIERlY3J5cHQgYW5kIFhPUlxuXHQgICAgICAgICAgICAgICAgY2lwaGVyLmRlY3J5cHRCbG9jayh3b3Jkcywgb2Zmc2V0KTtcblx0ICAgICAgICAgICAgICAgIHhvckJsb2NrLmNhbGwodGhpcywgd29yZHMsIG9mZnNldCwgYmxvY2tTaXplKTtcblxuXHQgICAgICAgICAgICAgICAgLy8gVGhpcyBibG9jayBiZWNvbWVzIHRoZSBwcmV2aW91cyBibG9ja1xuXHQgICAgICAgICAgICAgICAgdGhpcy5fcHJldkJsb2NrID0gdGhpc0Jsb2NrO1xuXHQgICAgICAgICAgICB9XG5cdCAgICAgICAgfSk7XG5cblx0ICAgICAgICBmdW5jdGlvbiB4b3JCbG9jayh3b3Jkcywgb2Zmc2V0LCBibG9ja1NpemUpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRcblx0ICAgICAgICAgICAgdmFyIGl2ID0gdGhpcy5faXY7XG5cblx0ICAgICAgICAgICAgLy8gQ2hvb3NlIG1peGluZyBibG9ja1xuXHQgICAgICAgICAgICBpZiAoaXYpIHtcblx0ICAgICAgICAgICAgICAgIHZhciBibG9jayA9IGl2O1xuXG5cdCAgICAgICAgICAgICAgICAvLyBSZW1vdmUgSVYgZm9yIHN1YnNlcXVlbnQgYmxvY2tzXG5cdCAgICAgICAgICAgICAgICB0aGlzLl9pdiA9IHVuZGVmaW5lZDtcblx0ICAgICAgICAgICAgfSBlbHNlIHtcblx0ICAgICAgICAgICAgICAgIHZhciBibG9jayA9IHRoaXMuX3ByZXZCbG9jaztcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIC8vIFhPUiBibG9ja3Ncblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBibG9ja1NpemU7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgd29yZHNbb2Zmc2V0ICsgaV0gXj0gYmxvY2tbaV07XG5cdCAgICAgICAgICAgIH1cblx0ICAgICAgICB9XG5cblx0ICAgICAgICByZXR1cm4gQ0JDO1xuXHQgICAgfSgpKTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBQYWRkaW5nIG5hbWVzcGFjZS5cblx0ICAgICAqL1xuXHQgICAgdmFyIENfcGFkID0gQy5wYWQgPSB7fTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBQS0NTICM1LzcgcGFkZGluZyBzdHJhdGVneS5cblx0ICAgICAqL1xuXHQgICAgdmFyIFBrY3M3ID0gQ19wYWQuUGtjczcgPSB7XG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogUGFkcyBkYXRhIHVzaW5nIHRoZSBhbGdvcml0aG0gZGVmaW5lZCBpbiBQS0NTICM1LzcuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge1dvcmRBcnJheX0gZGF0YSBUaGUgZGF0YSB0byBwYWQuXG5cdCAgICAgICAgICogQHBhcmFtIHtudW1iZXJ9IGJsb2NrU2l6ZSBUaGUgbXVsdGlwbGUgdGhhdCB0aGUgZGF0YSBzaG91bGQgYmUgcGFkZGVkIHRvLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICBDcnlwdG9KUy5wYWQuUGtjczcucGFkKHdvcmRBcnJheSwgNCk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgcGFkOiBmdW5jdGlvbiAoZGF0YSwgYmxvY2tTaXplKSB7XG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0XG5cdCAgICAgICAgICAgIHZhciBibG9ja1NpemVCeXRlcyA9IGJsb2NrU2l6ZSAqIDQ7XG5cblx0ICAgICAgICAgICAgLy8gQ291bnQgcGFkZGluZyBieXRlc1xuXHQgICAgICAgICAgICB2YXIgblBhZGRpbmdCeXRlcyA9IGJsb2NrU2l6ZUJ5dGVzIC0gZGF0YS5zaWdCeXRlcyAlIGJsb2NrU2l6ZUJ5dGVzO1xuXG5cdCAgICAgICAgICAgIC8vIENyZWF0ZSBwYWRkaW5nIHdvcmRcblx0ICAgICAgICAgICAgdmFyIHBhZGRpbmdXb3JkID0gKG5QYWRkaW5nQnl0ZXMgPDwgMjQpIHwgKG5QYWRkaW5nQnl0ZXMgPDwgMTYpIHwgKG5QYWRkaW5nQnl0ZXMgPDwgOCkgfCBuUGFkZGluZ0J5dGVzO1xuXG5cdCAgICAgICAgICAgIC8vIENyZWF0ZSBwYWRkaW5nXG5cdCAgICAgICAgICAgIHZhciBwYWRkaW5nV29yZHMgPSBbXTtcblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBuUGFkZGluZ0J5dGVzOyBpICs9IDQpIHtcblx0ICAgICAgICAgICAgICAgIHBhZGRpbmdXb3Jkcy5wdXNoKHBhZGRpbmdXb3JkKTtcblx0ICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICB2YXIgcGFkZGluZyA9IFdvcmRBcnJheS5jcmVhdGUocGFkZGluZ1dvcmRzLCBuUGFkZGluZ0J5dGVzKTtcblxuXHQgICAgICAgICAgICAvLyBBZGQgcGFkZGluZ1xuXHQgICAgICAgICAgICBkYXRhLmNvbmNhdChwYWRkaW5nKTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogVW5wYWRzIGRhdGEgdGhhdCBoYWQgYmVlbiBwYWRkZWQgdXNpbmcgdGhlIGFsZ29yaXRobSBkZWZpbmVkIGluIFBLQ1MgIzUvNy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7V29yZEFycmF5fSBkYXRhIFRoZSBkYXRhIHRvIHVucGFkLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICBDcnlwdG9KUy5wYWQuUGtjczcudW5wYWQod29yZEFycmF5KTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICB1bnBhZDogZnVuY3Rpb24gKGRhdGEpIHtcblx0ICAgICAgICAgICAgLy8gR2V0IG51bWJlciBvZiBwYWRkaW5nIGJ5dGVzIGZyb20gbGFzdCBieXRlXG5cdCAgICAgICAgICAgIHZhciBuUGFkZGluZ0J5dGVzID0gZGF0YS53b3Jkc1soZGF0YS5zaWdCeXRlcyAtIDEpID4+PiAyXSAmIDB4ZmY7XG5cblx0ICAgICAgICAgICAgLy8gUmVtb3ZlIHBhZGRpbmdcblx0ICAgICAgICAgICAgZGF0YS5zaWdCeXRlcyAtPSBuUGFkZGluZ0J5dGVzO1xuXHQgICAgICAgIH1cblx0ICAgIH07XG5cblx0ICAgIC8qKlxuXHQgICAgICogQWJzdHJhY3QgYmFzZSBibG9jayBjaXBoZXIgdGVtcGxhdGUuXG5cdCAgICAgKlxuXHQgICAgICogQHByb3BlcnR5IHtudW1iZXJ9IGJsb2NrU2l6ZSBUaGUgbnVtYmVyIG9mIDMyLWJpdCB3b3JkcyB0aGlzIGNpcGhlciBvcGVyYXRlcyBvbi4gRGVmYXVsdDogNCAoMTI4IGJpdHMpXG5cdCAgICAgKi9cblx0ICAgIHZhciBCbG9ja0NpcGhlciA9IENfbGliLkJsb2NrQ2lwaGVyID0gQ2lwaGVyLmV4dGVuZCh7XG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ29uZmlndXJhdGlvbiBvcHRpb25zLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHByb3BlcnR5IHtNb2RlfSBtb2RlIFRoZSBibG9jayBtb2RlIHRvIHVzZS4gRGVmYXVsdDogQ0JDXG5cdCAgICAgICAgICogQHByb3BlcnR5IHtQYWRkaW5nfSBwYWRkaW5nIFRoZSBwYWRkaW5nIHN0cmF0ZWd5IHRvIHVzZS4gRGVmYXVsdDogUGtjczdcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBjZmc6IENpcGhlci5jZmcuZXh0ZW5kKHtcblx0ICAgICAgICAgICAgbW9kZTogQ0JDLFxuXHQgICAgICAgICAgICBwYWRkaW5nOiBQa2NzN1xuXHQgICAgICAgIH0pLFxuXG5cdCAgICAgICAgcmVzZXQ6IGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgLy8gUmVzZXQgY2lwaGVyXG5cdCAgICAgICAgICAgIENpcGhlci5yZXNldC5jYWxsKHRoaXMpO1xuXG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICB2YXIgY2ZnID0gdGhpcy5jZmc7XG5cdCAgICAgICAgICAgIHZhciBpdiA9IGNmZy5pdjtcblx0ICAgICAgICAgICAgdmFyIG1vZGUgPSBjZmcubW9kZTtcblxuXHQgICAgICAgICAgICAvLyBSZXNldCBibG9jayBtb2RlXG5cdCAgICAgICAgICAgIGlmICh0aGlzLl94Zm9ybU1vZGUgPT0gdGhpcy5fRU5DX1hGT1JNX01PREUpIHtcblx0ICAgICAgICAgICAgICAgIHZhciBtb2RlQ3JlYXRvciA9IG1vZGUuY3JlYXRlRW5jcnlwdG9yO1xuXHQgICAgICAgICAgICB9IGVsc2UgLyogaWYgKHRoaXMuX3hmb3JtTW9kZSA9PSB0aGlzLl9ERUNfWEZPUk1fTU9ERSkgKi8ge1xuXHQgICAgICAgICAgICAgICAgdmFyIG1vZGVDcmVhdG9yID0gbW9kZS5jcmVhdGVEZWNyeXB0b3I7XG5cdCAgICAgICAgICAgICAgICAvLyBLZWVwIGF0IGxlYXN0IG9uZSBibG9jayBpbiB0aGUgYnVmZmVyIGZvciB1bnBhZGRpbmdcblx0ICAgICAgICAgICAgICAgIHRoaXMuX21pbkJ1ZmZlclNpemUgPSAxO1xuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgaWYgKHRoaXMuX21vZGUgJiYgdGhpcy5fbW9kZS5fX2NyZWF0b3IgPT0gbW9kZUNyZWF0b3IpIHtcblx0ICAgICAgICAgICAgICAgIHRoaXMuX21vZGUuaW5pdCh0aGlzLCBpdiAmJiBpdi53b3Jkcyk7XG5cdCAgICAgICAgICAgIH0gZWxzZSB7XG5cdCAgICAgICAgICAgICAgICB0aGlzLl9tb2RlID0gbW9kZUNyZWF0b3IuY2FsbChtb2RlLCB0aGlzLCBpdiAmJiBpdi53b3Jkcyk7XG5cdCAgICAgICAgICAgICAgICB0aGlzLl9tb2RlLl9fY3JlYXRvciA9IG1vZGVDcmVhdG9yO1xuXHQgICAgICAgICAgICB9XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIF9kb1Byb2Nlc3NCbG9jazogZnVuY3Rpb24gKHdvcmRzLCBvZmZzZXQpIHtcblx0ICAgICAgICAgICAgdGhpcy5fbW9kZS5wcm9jZXNzQmxvY2sod29yZHMsIG9mZnNldCk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIF9kb0ZpbmFsaXplOiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0XG5cdCAgICAgICAgICAgIHZhciBwYWRkaW5nID0gdGhpcy5jZmcucGFkZGluZztcblxuXHQgICAgICAgICAgICAvLyBGaW5hbGl6ZVxuXHQgICAgICAgICAgICBpZiAodGhpcy5feGZvcm1Nb2RlID09IHRoaXMuX0VOQ19YRk9STV9NT0RFKSB7XG5cdCAgICAgICAgICAgICAgICAvLyBQYWQgZGF0YVxuXHQgICAgICAgICAgICAgICAgcGFkZGluZy5wYWQodGhpcy5fZGF0YSwgdGhpcy5ibG9ja1NpemUpO1xuXG5cdCAgICAgICAgICAgICAgICAvLyBQcm9jZXNzIGZpbmFsIGJsb2Nrc1xuXHQgICAgICAgICAgICAgICAgdmFyIGZpbmFsUHJvY2Vzc2VkQmxvY2tzID0gdGhpcy5fcHJvY2VzcyghISdmbHVzaCcpO1xuXHQgICAgICAgICAgICB9IGVsc2UgLyogaWYgKHRoaXMuX3hmb3JtTW9kZSA9PSB0aGlzLl9ERUNfWEZPUk1fTU9ERSkgKi8ge1xuXHQgICAgICAgICAgICAgICAgLy8gUHJvY2VzcyBmaW5hbCBibG9ja3Ncblx0ICAgICAgICAgICAgICAgIHZhciBmaW5hbFByb2Nlc3NlZEJsb2NrcyA9IHRoaXMuX3Byb2Nlc3MoISEnZmx1c2gnKTtcblxuXHQgICAgICAgICAgICAgICAgLy8gVW5wYWQgZGF0YVxuXHQgICAgICAgICAgICAgICAgcGFkZGluZy51bnBhZChmaW5hbFByb2Nlc3NlZEJsb2Nrcyk7XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICByZXR1cm4gZmluYWxQcm9jZXNzZWRCbG9ja3M7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIGJsb2NrU2l6ZTogMTI4LzMyXG5cdCAgICB9KTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBBIGNvbGxlY3Rpb24gb2YgY2lwaGVyIHBhcmFtZXRlcnMuXG5cdCAgICAgKlxuXHQgICAgICogQHByb3BlcnR5IHtXb3JkQXJyYXl9IGNpcGhlcnRleHQgVGhlIHJhdyBjaXBoZXJ0ZXh0LlxuXHQgICAgICogQHByb3BlcnR5IHtXb3JkQXJyYXl9IGtleSBUaGUga2V5IHRvIHRoaXMgY2lwaGVydGV4dC5cblx0ICAgICAqIEBwcm9wZXJ0eSB7V29yZEFycmF5fSBpdiBUaGUgSVYgdXNlZCBpbiB0aGUgY2lwaGVyaW5nIG9wZXJhdGlvbi5cblx0ICAgICAqIEBwcm9wZXJ0eSB7V29yZEFycmF5fSBzYWx0IFRoZSBzYWx0IHVzZWQgd2l0aCBhIGtleSBkZXJpdmF0aW9uIGZ1bmN0aW9uLlxuXHQgICAgICogQHByb3BlcnR5IHtDaXBoZXJ9IGFsZ29yaXRobSBUaGUgY2lwaGVyIGFsZ29yaXRobS5cblx0ICAgICAqIEBwcm9wZXJ0eSB7TW9kZX0gbW9kZSBUaGUgYmxvY2sgbW9kZSB1c2VkIGluIHRoZSBjaXBoZXJpbmcgb3BlcmF0aW9uLlxuXHQgICAgICogQHByb3BlcnR5IHtQYWRkaW5nfSBwYWRkaW5nIFRoZSBwYWRkaW5nIHNjaGVtZSB1c2VkIGluIHRoZSBjaXBoZXJpbmcgb3BlcmF0aW9uLlxuXHQgICAgICogQHByb3BlcnR5IHtudW1iZXJ9IGJsb2NrU2l6ZSBUaGUgYmxvY2sgc2l6ZSBvZiB0aGUgY2lwaGVyLlxuXHQgICAgICogQHByb3BlcnR5IHtGb3JtYXR9IGZvcm1hdHRlciBUaGUgZGVmYXVsdCBmb3JtYXR0aW5nIHN0cmF0ZWd5IHRvIGNvbnZlcnQgdGhpcyBjaXBoZXIgcGFyYW1zIG9iamVjdCB0byBhIHN0cmluZy5cblx0ICAgICAqL1xuXHQgICAgdmFyIENpcGhlclBhcmFtcyA9IENfbGliLkNpcGhlclBhcmFtcyA9IEJhc2UuZXh0ZW5kKHtcblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBJbml0aWFsaXplcyBhIG5ld2x5IGNyZWF0ZWQgY2lwaGVyIHBhcmFtcyBvYmplY3QuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge09iamVjdH0gY2lwaGVyUGFyYW1zIEFuIG9iamVjdCB3aXRoIGFueSBvZiB0aGUgcG9zc2libGUgY2lwaGVyIHBhcmFtZXRlcnMuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciBjaXBoZXJQYXJhbXMgPSBDcnlwdG9KUy5saWIuQ2lwaGVyUGFyYW1zLmNyZWF0ZSh7XG5cdCAgICAgICAgICogICAgICAgICBjaXBoZXJ0ZXh0OiBjaXBoZXJ0ZXh0V29yZEFycmF5LFxuXHQgICAgICAgICAqICAgICAgICAga2V5OiBrZXlXb3JkQXJyYXksXG5cdCAgICAgICAgICogICAgICAgICBpdjogaXZXb3JkQXJyYXksXG5cdCAgICAgICAgICogICAgICAgICBzYWx0OiBzYWx0V29yZEFycmF5LFxuXHQgICAgICAgICAqICAgICAgICAgYWxnb3JpdGhtOiBDcnlwdG9KUy5hbGdvLkFFUyxcblx0ICAgICAgICAgKiAgICAgICAgIG1vZGU6IENyeXB0b0pTLm1vZGUuQ0JDLFxuXHQgICAgICAgICAqICAgICAgICAgcGFkZGluZzogQ3J5cHRvSlMucGFkLlBLQ1M3LFxuXHQgICAgICAgICAqICAgICAgICAgYmxvY2tTaXplOiA0LFxuXHQgICAgICAgICAqICAgICAgICAgZm9ybWF0dGVyOiBDcnlwdG9KUy5mb3JtYXQuT3BlblNTTFxuXHQgICAgICAgICAqICAgICB9KTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBpbml0OiBmdW5jdGlvbiAoY2lwaGVyUGFyYW1zKSB7XG5cdCAgICAgICAgICAgIHRoaXMubWl4SW4oY2lwaGVyUGFyYW1zKTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ29udmVydHMgdGhpcyBjaXBoZXIgcGFyYW1zIG9iamVjdCB0byBhIHN0cmluZy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7Rm9ybWF0fSBmb3JtYXR0ZXIgKE9wdGlvbmFsKSBUaGUgZm9ybWF0dGluZyBzdHJhdGVneSB0byB1c2UuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtzdHJpbmd9IFRoZSBzdHJpbmdpZmllZCBjaXBoZXIgcGFyYW1zLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHRocm93cyBFcnJvciBJZiBuZWl0aGVyIHRoZSBmb3JtYXR0ZXIgbm9yIHRoZSBkZWZhdWx0IGZvcm1hdHRlciBpcyBzZXQuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciBzdHJpbmcgPSBjaXBoZXJQYXJhbXMgKyAnJztcblx0ICAgICAgICAgKiAgICAgdmFyIHN0cmluZyA9IGNpcGhlclBhcmFtcy50b1N0cmluZygpO1xuXHQgICAgICAgICAqICAgICB2YXIgc3RyaW5nID0gY2lwaGVyUGFyYW1zLnRvU3RyaW5nKENyeXB0b0pTLmZvcm1hdC5PcGVuU1NMKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICB0b1N0cmluZzogZnVuY3Rpb24gKGZvcm1hdHRlcikge1xuXHQgICAgICAgICAgICByZXR1cm4gKGZvcm1hdHRlciB8fCB0aGlzLmZvcm1hdHRlcikuc3RyaW5naWZ5KHRoaXMpO1xuXHQgICAgICAgIH1cblx0ICAgIH0pO1xuXG5cdCAgICAvKipcblx0ICAgICAqIEZvcm1hdCBuYW1lc3BhY2UuXG5cdCAgICAgKi9cblx0ICAgIHZhciBDX2Zvcm1hdCA9IEMuZm9ybWF0ID0ge307XG5cblx0ICAgIC8qKlxuXHQgICAgICogT3BlblNTTCBmb3JtYXR0aW5nIHN0cmF0ZWd5LlxuXHQgICAgICovXG5cdCAgICB2YXIgT3BlblNTTEZvcm1hdHRlciA9IENfZm9ybWF0Lk9wZW5TU0wgPSB7XG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ29udmVydHMgYSBjaXBoZXIgcGFyYW1zIG9iamVjdCB0byBhbiBPcGVuU1NMLWNvbXBhdGlibGUgc3RyaW5nLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtDaXBoZXJQYXJhbXN9IGNpcGhlclBhcmFtcyBUaGUgY2lwaGVyIHBhcmFtcyBvYmplY3QuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtzdHJpbmd9IFRoZSBPcGVuU1NMLWNvbXBhdGlibGUgc3RyaW5nLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgb3BlblNTTFN0cmluZyA9IENyeXB0b0pTLmZvcm1hdC5PcGVuU1NMLnN0cmluZ2lmeShjaXBoZXJQYXJhbXMpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIHN0cmluZ2lmeTogZnVuY3Rpb24gKGNpcGhlclBhcmFtcykge1xuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICAgICAgdmFyIGNpcGhlcnRleHQgPSBjaXBoZXJQYXJhbXMuY2lwaGVydGV4dDtcblx0ICAgICAgICAgICAgdmFyIHNhbHQgPSBjaXBoZXJQYXJhbXMuc2FsdDtcblxuXHQgICAgICAgICAgICAvLyBGb3JtYXRcblx0ICAgICAgICAgICAgaWYgKHNhbHQpIHtcblx0ICAgICAgICAgICAgICAgIHZhciB3b3JkQXJyYXkgPSBXb3JkQXJyYXkuY3JlYXRlKFsweDUzNjE2Yzc0LCAweDY1NjQ1ZjVmXSkuY29uY2F0KHNhbHQpLmNvbmNhdChjaXBoZXJ0ZXh0KTtcblx0ICAgICAgICAgICAgfSBlbHNlIHtcblx0ICAgICAgICAgICAgICAgIHZhciB3b3JkQXJyYXkgPSBjaXBoZXJ0ZXh0O1xuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgcmV0dXJuIHdvcmRBcnJheS50b1N0cmluZyhCYXNlNjQpO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBDb252ZXJ0cyBhbiBPcGVuU1NMLWNvbXBhdGlibGUgc3RyaW5nIHRvIGEgY2lwaGVyIHBhcmFtcyBvYmplY3QuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge3N0cmluZ30gb3BlblNTTFN0ciBUaGUgT3BlblNTTC1jb21wYXRpYmxlIHN0cmluZy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge0NpcGhlclBhcmFtc30gVGhlIGNpcGhlciBwYXJhbXMgb2JqZWN0LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgY2lwaGVyUGFyYW1zID0gQ3J5cHRvSlMuZm9ybWF0Lk9wZW5TU0wucGFyc2Uob3BlblNTTFN0cmluZyk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgcGFyc2U6IGZ1bmN0aW9uIChvcGVuU1NMU3RyKSB7XG5cdCAgICAgICAgICAgIC8vIFBhcnNlIGJhc2U2NFxuXHQgICAgICAgICAgICB2YXIgY2lwaGVydGV4dCA9IEJhc2U2NC5wYXJzZShvcGVuU1NMU3RyKTtcblxuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dFxuXHQgICAgICAgICAgICB2YXIgY2lwaGVydGV4dFdvcmRzID0gY2lwaGVydGV4dC53b3JkcztcblxuXHQgICAgICAgICAgICAvLyBUZXN0IGZvciBzYWx0XG5cdCAgICAgICAgICAgIGlmIChjaXBoZXJ0ZXh0V29yZHNbMF0gPT0gMHg1MzYxNmM3NCAmJiBjaXBoZXJ0ZXh0V29yZHNbMV0gPT0gMHg2NTY0NWY1Zikge1xuXHQgICAgICAgICAgICAgICAgLy8gRXh0cmFjdCBzYWx0XG5cdCAgICAgICAgICAgICAgICB2YXIgc2FsdCA9IFdvcmRBcnJheS5jcmVhdGUoY2lwaGVydGV4dFdvcmRzLnNsaWNlKDIsIDQpKTtcblxuXHQgICAgICAgICAgICAgICAgLy8gUmVtb3ZlIHNhbHQgZnJvbSBjaXBoZXJ0ZXh0XG5cdCAgICAgICAgICAgICAgICBjaXBoZXJ0ZXh0V29yZHMuc3BsaWNlKDAsIDQpO1xuXHQgICAgICAgICAgICAgICAgY2lwaGVydGV4dC5zaWdCeXRlcyAtPSAxNjtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIHJldHVybiBDaXBoZXJQYXJhbXMuY3JlYXRlKHsgY2lwaGVydGV4dDogY2lwaGVydGV4dCwgc2FsdDogc2FsdCB9KTtcblx0ICAgICAgICB9XG5cdCAgICB9O1xuXG5cdCAgICAvKipcblx0ICAgICAqIEEgY2lwaGVyIHdyYXBwZXIgdGhhdCByZXR1cm5zIGNpcGhlcnRleHQgYXMgYSBzZXJpYWxpemFibGUgY2lwaGVyIHBhcmFtcyBvYmplY3QuXG5cdCAgICAgKi9cblx0ICAgIHZhciBTZXJpYWxpemFibGVDaXBoZXIgPSBDX2xpYi5TZXJpYWxpemFibGVDaXBoZXIgPSBCYXNlLmV4dGVuZCh7XG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ29uZmlndXJhdGlvbiBvcHRpb25zLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHByb3BlcnR5IHtGb3JtYXR0ZXJ9IGZvcm1hdCBUaGUgZm9ybWF0dGluZyBzdHJhdGVneSB0byBjb252ZXJ0IGNpcGhlciBwYXJhbSBvYmplY3RzIHRvIGFuZCBmcm9tIGEgc3RyaW5nLiBEZWZhdWx0OiBPcGVuU1NMXG5cdCAgICAgICAgICovXG5cdCAgICAgICAgY2ZnOiBCYXNlLmV4dGVuZCh7XG5cdCAgICAgICAgICAgIGZvcm1hdDogT3BlblNTTEZvcm1hdHRlclxuXHQgICAgICAgIH0pLFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogRW5jcnlwdHMgYSBtZXNzYWdlLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtDaXBoZXJ9IGNpcGhlciBUaGUgY2lwaGVyIGFsZ29yaXRobSB0byB1c2UuXG5cdCAgICAgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBtZXNzYWdlIFRoZSBtZXNzYWdlIHRvIGVuY3J5cHQuXG5cdCAgICAgICAgICogQHBhcmFtIHtXb3JkQXJyYXl9IGtleSBUaGUga2V5LlxuXHQgICAgICAgICAqIEBwYXJhbSB7T2JqZWN0fSBjZmcgKE9wdGlvbmFsKSBUaGUgY29uZmlndXJhdGlvbiBvcHRpb25zIHRvIHVzZSBmb3IgdGhpcyBvcGVyYXRpb24uXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtDaXBoZXJQYXJhbXN9IEEgY2lwaGVyIHBhcmFtcyBvYmplY3QuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAc3RhdGljXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciBjaXBoZXJ0ZXh0UGFyYW1zID0gQ3J5cHRvSlMubGliLlNlcmlhbGl6YWJsZUNpcGhlci5lbmNyeXB0KENyeXB0b0pTLmFsZ28uQUVTLCBtZXNzYWdlLCBrZXkpO1xuXHQgICAgICAgICAqICAgICB2YXIgY2lwaGVydGV4dFBhcmFtcyA9IENyeXB0b0pTLmxpYi5TZXJpYWxpemFibGVDaXBoZXIuZW5jcnlwdChDcnlwdG9KUy5hbGdvLkFFUywgbWVzc2FnZSwga2V5LCB7IGl2OiBpdiB9KTtcblx0ICAgICAgICAgKiAgICAgdmFyIGNpcGhlcnRleHRQYXJhbXMgPSBDcnlwdG9KUy5saWIuU2VyaWFsaXphYmxlQ2lwaGVyLmVuY3J5cHQoQ3J5cHRvSlMuYWxnby5BRVMsIG1lc3NhZ2UsIGtleSwgeyBpdjogaXYsIGZvcm1hdDogQ3J5cHRvSlMuZm9ybWF0Lk9wZW5TU0wgfSk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgZW5jcnlwdDogZnVuY3Rpb24gKGNpcGhlciwgbWVzc2FnZSwga2V5LCBjZmcpIHtcblx0ICAgICAgICAgICAgLy8gQXBwbHkgY29uZmlnIGRlZmF1bHRzXG5cdCAgICAgICAgICAgIGNmZyA9IHRoaXMuY2ZnLmV4dGVuZChjZmcpO1xuXG5cdCAgICAgICAgICAgIC8vIEVuY3J5cHRcblx0ICAgICAgICAgICAgdmFyIGVuY3J5cHRvciA9IGNpcGhlci5jcmVhdGVFbmNyeXB0b3Ioa2V5LCBjZmcpO1xuXHQgICAgICAgICAgICB2YXIgY2lwaGVydGV4dCA9IGVuY3J5cHRvci5maW5hbGl6ZShtZXNzYWdlKTtcblxuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dFxuXHQgICAgICAgICAgICB2YXIgY2lwaGVyQ2ZnID0gZW5jcnlwdG9yLmNmZztcblxuXHQgICAgICAgICAgICAvLyBDcmVhdGUgYW5kIHJldHVybiBzZXJpYWxpemFibGUgY2lwaGVyIHBhcmFtc1xuXHQgICAgICAgICAgICByZXR1cm4gQ2lwaGVyUGFyYW1zLmNyZWF0ZSh7XG5cdCAgICAgICAgICAgICAgICBjaXBoZXJ0ZXh0OiBjaXBoZXJ0ZXh0LFxuXHQgICAgICAgICAgICAgICAga2V5OiBrZXksXG5cdCAgICAgICAgICAgICAgICBpdjogY2lwaGVyQ2ZnLml2LFxuXHQgICAgICAgICAgICAgICAgYWxnb3JpdGhtOiBjaXBoZXIsXG5cdCAgICAgICAgICAgICAgICBtb2RlOiBjaXBoZXJDZmcubW9kZSxcblx0ICAgICAgICAgICAgICAgIHBhZGRpbmc6IGNpcGhlckNmZy5wYWRkaW5nLFxuXHQgICAgICAgICAgICAgICAgYmxvY2tTaXplOiBjaXBoZXIuYmxvY2tTaXplLFxuXHQgICAgICAgICAgICAgICAgZm9ybWF0dGVyOiBjZmcuZm9ybWF0XG5cdCAgICAgICAgICAgIH0pO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBEZWNyeXB0cyBzZXJpYWxpemVkIGNpcGhlcnRleHQuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge0NpcGhlcn0gY2lwaGVyIFRoZSBjaXBoZXIgYWxnb3JpdGhtIHRvIHVzZS5cblx0ICAgICAgICAgKiBAcGFyYW0ge0NpcGhlclBhcmFtc3xzdHJpbmd9IGNpcGhlcnRleHQgVGhlIGNpcGhlcnRleHQgdG8gZGVjcnlwdC5cblx0ICAgICAgICAgKiBAcGFyYW0ge1dvcmRBcnJheX0ga2V5IFRoZSBrZXkuXG5cdCAgICAgICAgICogQHBhcmFtIHtPYmplY3R9IGNmZyAoT3B0aW9uYWwpIFRoZSBjb25maWd1cmF0aW9uIG9wdGlvbnMgdG8gdXNlIGZvciB0aGlzIG9wZXJhdGlvbi5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge1dvcmRBcnJheX0gVGhlIHBsYWludGV4dC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBzdGF0aWNcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIHBsYWludGV4dCA9IENyeXB0b0pTLmxpYi5TZXJpYWxpemFibGVDaXBoZXIuZGVjcnlwdChDcnlwdG9KUy5hbGdvLkFFUywgZm9ybWF0dGVkQ2lwaGVydGV4dCwga2V5LCB7IGl2OiBpdiwgZm9ybWF0OiBDcnlwdG9KUy5mb3JtYXQuT3BlblNTTCB9KTtcblx0ICAgICAgICAgKiAgICAgdmFyIHBsYWludGV4dCA9IENyeXB0b0pTLmxpYi5TZXJpYWxpemFibGVDaXBoZXIuZGVjcnlwdChDcnlwdG9KUy5hbGdvLkFFUywgY2lwaGVydGV4dFBhcmFtcywga2V5LCB7IGl2OiBpdiwgZm9ybWF0OiBDcnlwdG9KUy5mb3JtYXQuT3BlblNTTCB9KTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBkZWNyeXB0OiBmdW5jdGlvbiAoY2lwaGVyLCBjaXBoZXJ0ZXh0LCBrZXksIGNmZykge1xuXHQgICAgICAgICAgICAvLyBBcHBseSBjb25maWcgZGVmYXVsdHNcblx0ICAgICAgICAgICAgY2ZnID0gdGhpcy5jZmcuZXh0ZW5kKGNmZyk7XG5cblx0ICAgICAgICAgICAgLy8gQ29udmVydCBzdHJpbmcgdG8gQ2lwaGVyUGFyYW1zXG5cdCAgICAgICAgICAgIGNpcGhlcnRleHQgPSB0aGlzLl9wYXJzZShjaXBoZXJ0ZXh0LCBjZmcuZm9ybWF0KTtcblxuXHQgICAgICAgICAgICAvLyBEZWNyeXB0XG5cdCAgICAgICAgICAgIHZhciBwbGFpbnRleHQgPSBjaXBoZXIuY3JlYXRlRGVjcnlwdG9yKGtleSwgY2ZnKS5maW5hbGl6ZShjaXBoZXJ0ZXh0LmNpcGhlcnRleHQpO1xuXG5cdCAgICAgICAgICAgIHJldHVybiBwbGFpbnRleHQ7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENvbnZlcnRzIHNlcmlhbGl6ZWQgY2lwaGVydGV4dCB0byBDaXBoZXJQYXJhbXMsXG5cdCAgICAgICAgICogZWxzZSBhc3N1bWVkIENpcGhlclBhcmFtcyBhbHJlYWR5IGFuZCByZXR1cm5zIGNpcGhlcnRleHQgdW5jaGFuZ2VkLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtDaXBoZXJQYXJhbXN8c3RyaW5nfSBjaXBoZXJ0ZXh0IFRoZSBjaXBoZXJ0ZXh0LlxuXHQgICAgICAgICAqIEBwYXJhbSB7Rm9ybWF0dGVyfSBmb3JtYXQgVGhlIGZvcm1hdHRpbmcgc3RyYXRlZ3kgdG8gdXNlIHRvIHBhcnNlIHNlcmlhbGl6ZWQgY2lwaGVydGV4dC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge0NpcGhlclBhcmFtc30gVGhlIHVuc2VyaWFsaXplZCBjaXBoZXJ0ZXh0LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgY2lwaGVydGV4dFBhcmFtcyA9IENyeXB0b0pTLmxpYi5TZXJpYWxpemFibGVDaXBoZXIuX3BhcnNlKGNpcGhlcnRleHRTdHJpbmdPclBhcmFtcywgZm9ybWF0KTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBfcGFyc2U6IGZ1bmN0aW9uIChjaXBoZXJ0ZXh0LCBmb3JtYXQpIHtcblx0ICAgICAgICAgICAgaWYgKHR5cGVvZiBjaXBoZXJ0ZXh0ID09ICdzdHJpbmcnKSB7XG5cdCAgICAgICAgICAgICAgICByZXR1cm4gZm9ybWF0LnBhcnNlKGNpcGhlcnRleHQsIHRoaXMpO1xuXHQgICAgICAgICAgICB9IGVsc2Uge1xuXHQgICAgICAgICAgICAgICAgcmV0dXJuIGNpcGhlcnRleHQ7XG5cdCAgICAgICAgICAgIH1cblx0ICAgICAgICB9XG5cdCAgICB9KTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBLZXkgZGVyaXZhdGlvbiBmdW5jdGlvbiBuYW1lc3BhY2UuXG5cdCAgICAgKi9cblx0ICAgIHZhciBDX2tkZiA9IEMua2RmID0ge307XG5cblx0ICAgIC8qKlxuXHQgICAgICogT3BlblNTTCBrZXkgZGVyaXZhdGlvbiBmdW5jdGlvbi5cblx0ICAgICAqL1xuXHQgICAgdmFyIE9wZW5TU0xLZGYgPSBDX2tkZi5PcGVuU1NMID0ge1xuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIERlcml2ZXMgYSBrZXkgYW5kIElWIGZyb20gYSBwYXNzd29yZC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7c3RyaW5nfSBwYXNzd29yZCBUaGUgcGFzc3dvcmQgdG8gZGVyaXZlIGZyb20uXG5cdCAgICAgICAgICogQHBhcmFtIHtudW1iZXJ9IGtleVNpemUgVGhlIHNpemUgaW4gd29yZHMgb2YgdGhlIGtleSB0byBnZW5lcmF0ZS5cblx0ICAgICAgICAgKiBAcGFyYW0ge251bWJlcn0gaXZTaXplIFRoZSBzaXplIGluIHdvcmRzIG9mIHRoZSBJViB0byBnZW5lcmF0ZS5cblx0ICAgICAgICAgKiBAcGFyYW0ge1dvcmRBcnJheXxzdHJpbmd9IHNhbHQgKE9wdGlvbmFsKSBBIDY0LWJpdCBzYWx0IHRvIHVzZS4gSWYgb21pdHRlZCwgYSBzYWx0IHdpbGwgYmUgZ2VuZXJhdGVkIHJhbmRvbWx5LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHJldHVybiB7Q2lwaGVyUGFyYW1zfSBBIGNpcGhlciBwYXJhbXMgb2JqZWN0IHdpdGggdGhlIGtleSwgSVYsIGFuZCBzYWx0LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgZGVyaXZlZFBhcmFtcyA9IENyeXB0b0pTLmtkZi5PcGVuU1NMLmV4ZWN1dGUoJ1Bhc3N3b3JkJywgMjU2LzMyLCAxMjgvMzIpO1xuXHQgICAgICAgICAqICAgICB2YXIgZGVyaXZlZFBhcmFtcyA9IENyeXB0b0pTLmtkZi5PcGVuU1NMLmV4ZWN1dGUoJ1Bhc3N3b3JkJywgMjU2LzMyLCAxMjgvMzIsICdzYWx0c2FsdCcpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIGV4ZWN1dGU6IGZ1bmN0aW9uIChwYXNzd29yZCwga2V5U2l6ZSwgaXZTaXplLCBzYWx0KSB7XG5cdCAgICAgICAgICAgIC8vIEdlbmVyYXRlIHJhbmRvbSBzYWx0XG5cdCAgICAgICAgICAgIGlmICghc2FsdCkge1xuXHQgICAgICAgICAgICAgICAgc2FsdCA9IFdvcmRBcnJheS5yYW5kb20oNjQvOCk7XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAvLyBEZXJpdmUga2V5IGFuZCBJVlxuXHQgICAgICAgICAgICB2YXIga2V5ID0gRXZwS0RGLmNyZWF0ZSh7IGtleVNpemU6IGtleVNpemUgKyBpdlNpemUgfSkuY29tcHV0ZShwYXNzd29yZCwgc2FsdCk7XG5cblx0ICAgICAgICAgICAgLy8gU2VwYXJhdGUga2V5IGFuZCBJVlxuXHQgICAgICAgICAgICB2YXIgaXYgPSBXb3JkQXJyYXkuY3JlYXRlKGtleS53b3Jkcy5zbGljZShrZXlTaXplKSwgaXZTaXplICogNCk7XG5cdCAgICAgICAgICAgIGtleS5zaWdCeXRlcyA9IGtleVNpemUgKiA0O1xuXG5cdCAgICAgICAgICAgIC8vIFJldHVybiBwYXJhbXNcblx0ICAgICAgICAgICAgcmV0dXJuIENpcGhlclBhcmFtcy5jcmVhdGUoeyBrZXk6IGtleSwgaXY6IGl2LCBzYWx0OiBzYWx0IH0pO1xuXHQgICAgICAgIH1cblx0ICAgIH07XG5cblx0ICAgIC8qKlxuXHQgICAgICogQSBzZXJpYWxpemFibGUgY2lwaGVyIHdyYXBwZXIgdGhhdCBkZXJpdmVzIHRoZSBrZXkgZnJvbSBhIHBhc3N3b3JkLFxuXHQgICAgICogYW5kIHJldHVybnMgY2lwaGVydGV4dCBhcyBhIHNlcmlhbGl6YWJsZSBjaXBoZXIgcGFyYW1zIG9iamVjdC5cblx0ICAgICAqL1xuXHQgICAgdmFyIFBhc3N3b3JkQmFzZWRDaXBoZXIgPSBDX2xpYi5QYXNzd29yZEJhc2VkQ2lwaGVyID0gU2VyaWFsaXphYmxlQ2lwaGVyLmV4dGVuZCh7XG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ29uZmlndXJhdGlvbiBvcHRpb25zLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHByb3BlcnR5IHtLREZ9IGtkZiBUaGUga2V5IGRlcml2YXRpb24gZnVuY3Rpb24gdG8gdXNlIHRvIGdlbmVyYXRlIGEga2V5IGFuZCBJViBmcm9tIGEgcGFzc3dvcmQuIERlZmF1bHQ6IE9wZW5TU0xcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBjZmc6IFNlcmlhbGl6YWJsZUNpcGhlci5jZmcuZXh0ZW5kKHtcblx0ICAgICAgICAgICAga2RmOiBPcGVuU1NMS2RmXG5cdCAgICAgICAgfSksXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBFbmNyeXB0cyBhIG1lc3NhZ2UgdXNpbmcgYSBwYXNzd29yZC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7Q2lwaGVyfSBjaXBoZXIgVGhlIGNpcGhlciBhbGdvcml0aG0gdG8gdXNlLlxuXHQgICAgICAgICAqIEBwYXJhbSB7V29yZEFycmF5fHN0cmluZ30gbWVzc2FnZSBUaGUgbWVzc2FnZSB0byBlbmNyeXB0LlxuXHQgICAgICAgICAqIEBwYXJhbSB7c3RyaW5nfSBwYXNzd29yZCBUaGUgcGFzc3dvcmQuXG5cdCAgICAgICAgICogQHBhcmFtIHtPYmplY3R9IGNmZyAoT3B0aW9uYWwpIFRoZSBjb25maWd1cmF0aW9uIG9wdGlvbnMgdG8gdXNlIGZvciB0aGlzIG9wZXJhdGlvbi5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge0NpcGhlclBhcmFtc30gQSBjaXBoZXIgcGFyYW1zIG9iamVjdC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBzdGF0aWNcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIGNpcGhlcnRleHRQYXJhbXMgPSBDcnlwdG9KUy5saWIuUGFzc3dvcmRCYXNlZENpcGhlci5lbmNyeXB0KENyeXB0b0pTLmFsZ28uQUVTLCBtZXNzYWdlLCAncGFzc3dvcmQnKTtcblx0ICAgICAgICAgKiAgICAgdmFyIGNpcGhlcnRleHRQYXJhbXMgPSBDcnlwdG9KUy5saWIuUGFzc3dvcmRCYXNlZENpcGhlci5lbmNyeXB0KENyeXB0b0pTLmFsZ28uQUVTLCBtZXNzYWdlLCAncGFzc3dvcmQnLCB7IGZvcm1hdDogQ3J5cHRvSlMuZm9ybWF0Lk9wZW5TU0wgfSk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgZW5jcnlwdDogZnVuY3Rpb24gKGNpcGhlciwgbWVzc2FnZSwgcGFzc3dvcmQsIGNmZykge1xuXHQgICAgICAgICAgICAvLyBBcHBseSBjb25maWcgZGVmYXVsdHNcblx0ICAgICAgICAgICAgY2ZnID0gdGhpcy5jZmcuZXh0ZW5kKGNmZyk7XG5cblx0ICAgICAgICAgICAgLy8gRGVyaXZlIGtleSBhbmQgb3RoZXIgcGFyYW1zXG5cdCAgICAgICAgICAgIHZhciBkZXJpdmVkUGFyYW1zID0gY2ZnLmtkZi5leGVjdXRlKHBhc3N3b3JkLCBjaXBoZXIua2V5U2l6ZSwgY2lwaGVyLml2U2l6ZSk7XG5cblx0ICAgICAgICAgICAgLy8gQWRkIElWIHRvIGNvbmZpZ1xuXHQgICAgICAgICAgICBjZmcuaXYgPSBkZXJpdmVkUGFyYW1zLml2O1xuXG5cdCAgICAgICAgICAgIC8vIEVuY3J5cHRcblx0ICAgICAgICAgICAgdmFyIGNpcGhlcnRleHQgPSBTZXJpYWxpemFibGVDaXBoZXIuZW5jcnlwdC5jYWxsKHRoaXMsIGNpcGhlciwgbWVzc2FnZSwgZGVyaXZlZFBhcmFtcy5rZXksIGNmZyk7XG5cblx0ICAgICAgICAgICAgLy8gTWl4IGluIGRlcml2ZWQgcGFyYW1zXG5cdCAgICAgICAgICAgIGNpcGhlcnRleHQubWl4SW4oZGVyaXZlZFBhcmFtcyk7XG5cblx0ICAgICAgICAgICAgcmV0dXJuIGNpcGhlcnRleHQ7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIERlY3J5cHRzIHNlcmlhbGl6ZWQgY2lwaGVydGV4dCB1c2luZyBhIHBhc3N3b3JkLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtDaXBoZXJ9IGNpcGhlciBUaGUgY2lwaGVyIGFsZ29yaXRobSB0byB1c2UuXG5cdCAgICAgICAgICogQHBhcmFtIHtDaXBoZXJQYXJhbXN8c3RyaW5nfSBjaXBoZXJ0ZXh0IFRoZSBjaXBoZXJ0ZXh0IHRvIGRlY3J5cHQuXG5cdCAgICAgICAgICogQHBhcmFtIHtzdHJpbmd9IHBhc3N3b3JkIFRoZSBwYXNzd29yZC5cblx0ICAgICAgICAgKiBAcGFyYW0ge09iamVjdH0gY2ZnIChPcHRpb25hbCkgVGhlIGNvbmZpZ3VyYXRpb24gb3B0aW9ucyB0byB1c2UgZm9yIHRoaXMgb3BlcmF0aW9uLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHJldHVybiB7V29yZEFycmF5fSBUaGUgcGxhaW50ZXh0LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgcGxhaW50ZXh0ID0gQ3J5cHRvSlMubGliLlBhc3N3b3JkQmFzZWRDaXBoZXIuZGVjcnlwdChDcnlwdG9KUy5hbGdvLkFFUywgZm9ybWF0dGVkQ2lwaGVydGV4dCwgJ3Bhc3N3b3JkJywgeyBmb3JtYXQ6IENyeXB0b0pTLmZvcm1hdC5PcGVuU1NMIH0pO1xuXHQgICAgICAgICAqICAgICB2YXIgcGxhaW50ZXh0ID0gQ3J5cHRvSlMubGliLlBhc3N3b3JkQmFzZWRDaXBoZXIuZGVjcnlwdChDcnlwdG9KUy5hbGdvLkFFUywgY2lwaGVydGV4dFBhcmFtcywgJ3Bhc3N3b3JkJywgeyBmb3JtYXQ6IENyeXB0b0pTLmZvcm1hdC5PcGVuU1NMIH0pO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIGRlY3J5cHQ6IGZ1bmN0aW9uIChjaXBoZXIsIGNpcGhlcnRleHQsIHBhc3N3b3JkLCBjZmcpIHtcblx0ICAgICAgICAgICAgLy8gQXBwbHkgY29uZmlnIGRlZmF1bHRzXG5cdCAgICAgICAgICAgIGNmZyA9IHRoaXMuY2ZnLmV4dGVuZChjZmcpO1xuXG5cdCAgICAgICAgICAgIC8vIENvbnZlcnQgc3RyaW5nIHRvIENpcGhlclBhcmFtc1xuXHQgICAgICAgICAgICBjaXBoZXJ0ZXh0ID0gdGhpcy5fcGFyc2UoY2lwaGVydGV4dCwgY2ZnLmZvcm1hdCk7XG5cblx0ICAgICAgICAgICAgLy8gRGVyaXZlIGtleSBhbmQgb3RoZXIgcGFyYW1zXG5cdCAgICAgICAgICAgIHZhciBkZXJpdmVkUGFyYW1zID0gY2ZnLmtkZi5leGVjdXRlKHBhc3N3b3JkLCBjaXBoZXIua2V5U2l6ZSwgY2lwaGVyLml2U2l6ZSwgY2lwaGVydGV4dC5zYWx0KTtcblxuXHQgICAgICAgICAgICAvLyBBZGQgSVYgdG8gY29uZmlnXG5cdCAgICAgICAgICAgIGNmZy5pdiA9IGRlcml2ZWRQYXJhbXMuaXY7XG5cblx0ICAgICAgICAgICAgLy8gRGVjcnlwdFxuXHQgICAgICAgICAgICB2YXIgcGxhaW50ZXh0ID0gU2VyaWFsaXphYmxlQ2lwaGVyLmRlY3J5cHQuY2FsbCh0aGlzLCBjaXBoZXIsIGNpcGhlcnRleHQsIGRlcml2ZWRQYXJhbXMua2V5LCBjZmcpO1xuXG5cdCAgICAgICAgICAgIHJldHVybiBwbGFpbnRleHQ7XG5cdCAgICAgICAgfVxuXHQgICAgfSk7XG5cdH0oKSk7XG5cblxufSkpOyIsIjsoZnVuY3Rpb24gKHJvb3QsIGZhY3RvcnkpIHtcblx0aWYgKHR5cGVvZiBleHBvcnRzID09PSBcIm9iamVjdFwiKSB7XG5cdFx0Ly8gQ29tbW9uSlNcblx0XHRtb2R1bGUuZXhwb3J0cyA9IGV4cG9ydHMgPSBmYWN0b3J5KCk7XG5cdH1cblx0ZWxzZSBpZiAodHlwZW9mIGRlZmluZSA9PT0gXCJmdW5jdGlvblwiICYmIGRlZmluZS5hbWQpIHtcblx0XHQvLyBBTURcblx0XHRkZWZpbmUoW10sIGZhY3RvcnkpO1xuXHR9XG5cdGVsc2Uge1xuXHRcdC8vIEdsb2JhbCAoYnJvd3Nlcilcblx0XHRyb290LkNyeXB0b0pTID0gZmFjdG9yeSgpO1xuXHR9XG59KHRoaXMsIGZ1bmN0aW9uICgpIHtcblxuXHQvKipcblx0ICogQ3J5cHRvSlMgY29yZSBjb21wb25lbnRzLlxuXHQgKi9cblx0dmFyIENyeXB0b0pTID0gQ3J5cHRvSlMgfHwgKGZ1bmN0aW9uIChNYXRoLCB1bmRlZmluZWQpIHtcblx0ICAgIC8qXG5cdCAgICAgKiBMb2NhbCBwb2x5ZmlsIG9mIE9iamVjdC5jcmVhdGVcblx0ICAgICAqL1xuXHQgICAgdmFyIGNyZWF0ZSA9IE9iamVjdC5jcmVhdGUgfHwgKGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICBmdW5jdGlvbiBGKCkge307XG5cblx0ICAgICAgICByZXR1cm4gZnVuY3Rpb24gKG9iaikge1xuXHQgICAgICAgICAgICB2YXIgc3VidHlwZTtcblxuXHQgICAgICAgICAgICBGLnByb3RvdHlwZSA9IG9iajtcblxuXHQgICAgICAgICAgICBzdWJ0eXBlID0gbmV3IEYoKTtcblxuXHQgICAgICAgICAgICBGLnByb3RvdHlwZSA9IG51bGw7XG5cblx0ICAgICAgICAgICAgcmV0dXJuIHN1YnR5cGU7XG5cdCAgICAgICAgfTtcblx0ICAgIH0oKSlcblxuXHQgICAgLyoqXG5cdCAgICAgKiBDcnlwdG9KUyBuYW1lc3BhY2UuXG5cdCAgICAgKi9cblx0ICAgIHZhciBDID0ge307XG5cblx0ICAgIC8qKlxuXHQgICAgICogTGlicmFyeSBuYW1lc3BhY2UuXG5cdCAgICAgKi9cblx0ICAgIHZhciBDX2xpYiA9IEMubGliID0ge307XG5cblx0ICAgIC8qKlxuXHQgICAgICogQmFzZSBvYmplY3QgZm9yIHByb3RvdHlwYWwgaW5oZXJpdGFuY2UuXG5cdCAgICAgKi9cblx0ICAgIHZhciBCYXNlID0gQ19saWIuQmFzZSA9IChmdW5jdGlvbiAoKSB7XG5cblxuXHQgICAgICAgIHJldHVybiB7XG5cdCAgICAgICAgICAgIC8qKlxuXHQgICAgICAgICAgICAgKiBDcmVhdGVzIGEgbmV3IG9iamVjdCB0aGF0IGluaGVyaXRzIGZyb20gdGhpcyBvYmplY3QuXG5cdCAgICAgICAgICAgICAqXG5cdCAgICAgICAgICAgICAqIEBwYXJhbSB7T2JqZWN0fSBvdmVycmlkZXMgUHJvcGVydGllcyB0byBjb3B5IGludG8gdGhlIG5ldyBvYmplY3QuXG5cdCAgICAgICAgICAgICAqXG5cdCAgICAgICAgICAgICAqIEByZXR1cm4ge09iamVjdH0gVGhlIG5ldyBvYmplY3QuXG5cdCAgICAgICAgICAgICAqXG5cdCAgICAgICAgICAgICAqIEBzdGF0aWNcblx0ICAgICAgICAgICAgICpcblx0ICAgICAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgICAgICpcblx0ICAgICAgICAgICAgICogICAgIHZhciBNeVR5cGUgPSBDcnlwdG9KUy5saWIuQmFzZS5leHRlbmQoe1xuXHQgICAgICAgICAgICAgKiAgICAgICAgIGZpZWxkOiAndmFsdWUnLFxuXHQgICAgICAgICAgICAgKlxuXHQgICAgICAgICAgICAgKiAgICAgICAgIG1ldGhvZDogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICAgKiAgICAgICAgIH1cblx0ICAgICAgICAgICAgICogICAgIH0pO1xuXHQgICAgICAgICAgICAgKi9cblx0ICAgICAgICAgICAgZXh0ZW5kOiBmdW5jdGlvbiAob3ZlcnJpZGVzKSB7XG5cdCAgICAgICAgICAgICAgICAvLyBTcGF3blxuXHQgICAgICAgICAgICAgICAgdmFyIHN1YnR5cGUgPSBjcmVhdGUodGhpcyk7XG5cblx0ICAgICAgICAgICAgICAgIC8vIEF1Z21lbnRcblx0ICAgICAgICAgICAgICAgIGlmIChvdmVycmlkZXMpIHtcblx0ICAgICAgICAgICAgICAgICAgICBzdWJ0eXBlLm1peEluKG92ZXJyaWRlcyk7XG5cdCAgICAgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgICAgIC8vIENyZWF0ZSBkZWZhdWx0IGluaXRpYWxpemVyXG5cdCAgICAgICAgICAgICAgICBpZiAoIXN1YnR5cGUuaGFzT3duUHJvcGVydHkoJ2luaXQnKSB8fCB0aGlzLmluaXQgPT09IHN1YnR5cGUuaW5pdCkge1xuXHQgICAgICAgICAgICAgICAgICAgIHN1YnR5cGUuaW5pdCA9IGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgICAgICAgICAgICAgc3VidHlwZS4kc3VwZXIuaW5pdC5hcHBseSh0aGlzLCBhcmd1bWVudHMpO1xuXHQgICAgICAgICAgICAgICAgICAgIH07XG5cdCAgICAgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgICAgIC8vIEluaXRpYWxpemVyJ3MgcHJvdG90eXBlIGlzIHRoZSBzdWJ0eXBlIG9iamVjdFxuXHQgICAgICAgICAgICAgICAgc3VidHlwZS5pbml0LnByb3RvdHlwZSA9IHN1YnR5cGU7XG5cblx0ICAgICAgICAgICAgICAgIC8vIFJlZmVyZW5jZSBzdXBlcnR5cGVcblx0ICAgICAgICAgICAgICAgIHN1YnR5cGUuJHN1cGVyID0gdGhpcztcblxuXHQgICAgICAgICAgICAgICAgcmV0dXJuIHN1YnR5cGU7XG5cdCAgICAgICAgICAgIH0sXG5cblx0ICAgICAgICAgICAgLyoqXG5cdCAgICAgICAgICAgICAqIEV4dGVuZHMgdGhpcyBvYmplY3QgYW5kIHJ1bnMgdGhlIGluaXQgbWV0aG9kLlxuXHQgICAgICAgICAgICAgKiBBcmd1bWVudHMgdG8gY3JlYXRlKCkgd2lsbCBiZSBwYXNzZWQgdG8gaW5pdCgpLlxuXHQgICAgICAgICAgICAgKlxuXHQgICAgICAgICAgICAgKiBAcmV0dXJuIHtPYmplY3R9IFRoZSBuZXcgb2JqZWN0LlxuXHQgICAgICAgICAgICAgKlxuXHQgICAgICAgICAgICAgKiBAc3RhdGljXG5cdCAgICAgICAgICAgICAqXG5cdCAgICAgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICAgICAqXG5cdCAgICAgICAgICAgICAqICAgICB2YXIgaW5zdGFuY2UgPSBNeVR5cGUuY3JlYXRlKCk7XG5cdCAgICAgICAgICAgICAqL1xuXHQgICAgICAgICAgICBjcmVhdGU6IGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgICAgIHZhciBpbnN0YW5jZSA9IHRoaXMuZXh0ZW5kKCk7XG5cdCAgICAgICAgICAgICAgICBpbnN0YW5jZS5pbml0LmFwcGx5KGluc3RhbmNlLCBhcmd1bWVudHMpO1xuXG5cdCAgICAgICAgICAgICAgICByZXR1cm4gaW5zdGFuY2U7XG5cdCAgICAgICAgICAgIH0sXG5cblx0ICAgICAgICAgICAgLyoqXG5cdCAgICAgICAgICAgICAqIEluaXRpYWxpemVzIGEgbmV3bHkgY3JlYXRlZCBvYmplY3QuXG5cdCAgICAgICAgICAgICAqIE92ZXJyaWRlIHRoaXMgbWV0aG9kIHRvIGFkZCBzb21lIGxvZ2ljIHdoZW4geW91ciBvYmplY3RzIGFyZSBjcmVhdGVkLlxuXHQgICAgICAgICAgICAgKlxuXHQgICAgICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAgICAgKlxuXHQgICAgICAgICAgICAgKiAgICAgdmFyIE15VHlwZSA9IENyeXB0b0pTLmxpYi5CYXNlLmV4dGVuZCh7XG5cdCAgICAgICAgICAgICAqICAgICAgICAgaW5pdDogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICAgKiAgICAgICAgICAgICAvLyAuLi5cblx0ICAgICAgICAgICAgICogICAgICAgICB9XG5cdCAgICAgICAgICAgICAqICAgICB9KTtcblx0ICAgICAgICAgICAgICovXG5cdCAgICAgICAgICAgIGluaXQ6IGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgfSxcblxuXHQgICAgICAgICAgICAvKipcblx0ICAgICAgICAgICAgICogQ29waWVzIHByb3BlcnRpZXMgaW50byB0aGlzIG9iamVjdC5cblx0ICAgICAgICAgICAgICpcblx0ICAgICAgICAgICAgICogQHBhcmFtIHtPYmplY3R9IHByb3BlcnRpZXMgVGhlIHByb3BlcnRpZXMgdG8gbWl4IGluLlxuXHQgICAgICAgICAgICAgKlxuXHQgICAgICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAgICAgKlxuXHQgICAgICAgICAgICAgKiAgICAgTXlUeXBlLm1peEluKHtcblx0ICAgICAgICAgICAgICogICAgICAgICBmaWVsZDogJ3ZhbHVlJ1xuXHQgICAgICAgICAgICAgKiAgICAgfSk7XG5cdCAgICAgICAgICAgICAqL1xuXHQgICAgICAgICAgICBtaXhJbjogZnVuY3Rpb24gKHByb3BlcnRpZXMpIHtcblx0ICAgICAgICAgICAgICAgIGZvciAodmFyIHByb3BlcnR5TmFtZSBpbiBwcm9wZXJ0aWVzKSB7XG5cdCAgICAgICAgICAgICAgICAgICAgaWYgKHByb3BlcnRpZXMuaGFzT3duUHJvcGVydHkocHJvcGVydHlOYW1lKSkge1xuXHQgICAgICAgICAgICAgICAgICAgICAgICB0aGlzW3Byb3BlcnR5TmFtZV0gPSBwcm9wZXJ0aWVzW3Byb3BlcnR5TmFtZV07XG5cdCAgICAgICAgICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgICAgICAvLyBJRSB3b24ndCBjb3B5IHRvU3RyaW5nIHVzaW5nIHRoZSBsb29wIGFib3ZlXG5cdCAgICAgICAgICAgICAgICBpZiAocHJvcGVydGllcy5oYXNPd25Qcm9wZXJ0eSgndG9TdHJpbmcnKSkge1xuXHQgICAgICAgICAgICAgICAgICAgIHRoaXMudG9TdHJpbmcgPSBwcm9wZXJ0aWVzLnRvU3RyaW5nO1xuXHQgICAgICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICB9LFxuXG5cdCAgICAgICAgICAgIC8qKlxuXHQgICAgICAgICAgICAgKiBDcmVhdGVzIGEgY29weSBvZiB0aGlzIG9iamVjdC5cblx0ICAgICAgICAgICAgICpcblx0ICAgICAgICAgICAgICogQHJldHVybiB7T2JqZWN0fSBUaGUgY2xvbmUuXG5cdCAgICAgICAgICAgICAqXG5cdCAgICAgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICAgICAqXG5cdCAgICAgICAgICAgICAqICAgICB2YXIgY2xvbmUgPSBpbnN0YW5jZS5jbG9uZSgpO1xuXHQgICAgICAgICAgICAgKi9cblx0ICAgICAgICAgICAgY2xvbmU6IGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgICAgIHJldHVybiB0aGlzLmluaXQucHJvdG90eXBlLmV4dGVuZCh0aGlzKTtcblx0ICAgICAgICAgICAgfVxuXHQgICAgICAgIH07XG5cdCAgICB9KCkpO1xuXG5cdCAgICAvKipcblx0ICAgICAqIEFuIGFycmF5IG9mIDMyLWJpdCB3b3Jkcy5cblx0ICAgICAqXG5cdCAgICAgKiBAcHJvcGVydHkge0FycmF5fSB3b3JkcyBUaGUgYXJyYXkgb2YgMzItYml0IHdvcmRzLlxuXHQgICAgICogQHByb3BlcnR5IHtudW1iZXJ9IHNpZ0J5dGVzIFRoZSBudW1iZXIgb2Ygc2lnbmlmaWNhbnQgYnl0ZXMgaW4gdGhpcyB3b3JkIGFycmF5LlxuXHQgICAgICovXG5cdCAgICB2YXIgV29yZEFycmF5ID0gQ19saWIuV29yZEFycmF5ID0gQmFzZS5leHRlbmQoe1xuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIEluaXRpYWxpemVzIGEgbmV3bHkgY3JlYXRlZCB3b3JkIGFycmF5LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtBcnJheX0gd29yZHMgKE9wdGlvbmFsKSBBbiBhcnJheSBvZiAzMi1iaXQgd29yZHMuXG5cdCAgICAgICAgICogQHBhcmFtIHtudW1iZXJ9IHNpZ0J5dGVzIChPcHRpb25hbCkgVGhlIG51bWJlciBvZiBzaWduaWZpY2FudCBieXRlcyBpbiB0aGUgd29yZHMuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciB3b3JkQXJyYXkgPSBDcnlwdG9KUy5saWIuV29yZEFycmF5LmNyZWF0ZSgpO1xuXHQgICAgICAgICAqICAgICB2YXIgd29yZEFycmF5ID0gQ3J5cHRvSlMubGliLldvcmRBcnJheS5jcmVhdGUoWzB4MDAwMTAyMDMsIDB4MDQwNTA2MDddKTtcblx0ICAgICAgICAgKiAgICAgdmFyIHdvcmRBcnJheSA9IENyeXB0b0pTLmxpYi5Xb3JkQXJyYXkuY3JlYXRlKFsweDAwMDEwMjAzLCAweDA0MDUwNjA3XSwgNik7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgaW5pdDogZnVuY3Rpb24gKHdvcmRzLCBzaWdCeXRlcykge1xuXHQgICAgICAgICAgICB3b3JkcyA9IHRoaXMud29yZHMgPSB3b3JkcyB8fCBbXTtcblxuXHQgICAgICAgICAgICBpZiAoc2lnQnl0ZXMgIT0gdW5kZWZpbmVkKSB7XG5cdCAgICAgICAgICAgICAgICB0aGlzLnNpZ0J5dGVzID0gc2lnQnl0ZXM7XG5cdCAgICAgICAgICAgIH0gZWxzZSB7XG5cdCAgICAgICAgICAgICAgICB0aGlzLnNpZ0J5dGVzID0gd29yZHMubGVuZ3RoICogNDtcblx0ICAgICAgICAgICAgfVxuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBDb252ZXJ0cyB0aGlzIHdvcmQgYXJyYXkgdG8gYSBzdHJpbmcuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge0VuY29kZXJ9IGVuY29kZXIgKE9wdGlvbmFsKSBUaGUgZW5jb2Rpbmcgc3RyYXRlZ3kgdG8gdXNlLiBEZWZhdWx0OiBDcnlwdG9KUy5lbmMuSGV4XG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtzdHJpbmd9IFRoZSBzdHJpbmdpZmllZCB3b3JkIGFycmF5LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgc3RyaW5nID0gd29yZEFycmF5ICsgJyc7XG5cdCAgICAgICAgICogICAgIHZhciBzdHJpbmcgPSB3b3JkQXJyYXkudG9TdHJpbmcoKTtcblx0ICAgICAgICAgKiAgICAgdmFyIHN0cmluZyA9IHdvcmRBcnJheS50b1N0cmluZyhDcnlwdG9KUy5lbmMuVXRmOCk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgdG9TdHJpbmc6IGZ1bmN0aW9uIChlbmNvZGVyKSB7XG5cdCAgICAgICAgICAgIHJldHVybiAoZW5jb2RlciB8fCBIZXgpLnN0cmluZ2lmeSh0aGlzKTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ29uY2F0ZW5hdGVzIGEgd29yZCBhcnJheSB0byB0aGlzIHdvcmQgYXJyYXkuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge1dvcmRBcnJheX0gd29yZEFycmF5IFRoZSB3b3JkIGFycmF5IHRvIGFwcGVuZC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge1dvcmRBcnJheX0gVGhpcyB3b3JkIGFycmF5LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB3b3JkQXJyYXkxLmNvbmNhdCh3b3JkQXJyYXkyKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBjb25jYXQ6IGZ1bmN0aW9uICh3b3JkQXJyYXkpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgIHZhciB0aGlzV29yZHMgPSB0aGlzLndvcmRzO1xuXHQgICAgICAgICAgICB2YXIgdGhhdFdvcmRzID0gd29yZEFycmF5LndvcmRzO1xuXHQgICAgICAgICAgICB2YXIgdGhpc1NpZ0J5dGVzID0gdGhpcy5zaWdCeXRlcztcblx0ICAgICAgICAgICAgdmFyIHRoYXRTaWdCeXRlcyA9IHdvcmRBcnJheS5zaWdCeXRlcztcblxuXHQgICAgICAgICAgICAvLyBDbGFtcCBleGNlc3MgYml0c1xuXHQgICAgICAgICAgICB0aGlzLmNsYW1wKCk7XG5cblx0ICAgICAgICAgICAgLy8gQ29uY2F0XG5cdCAgICAgICAgICAgIGlmICh0aGlzU2lnQnl0ZXMgJSA0KSB7XG5cdCAgICAgICAgICAgICAgICAvLyBDb3B5IG9uZSBieXRlIGF0IGEgdGltZVxuXHQgICAgICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCB0aGF0U2lnQnl0ZXM7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgICAgIHZhciB0aGF0Qnl0ZSA9ICh0aGF0V29yZHNbaSA+Pj4gMl0gPj4+ICgyNCAtIChpICUgNCkgKiA4KSkgJiAweGZmO1xuXHQgICAgICAgICAgICAgICAgICAgIHRoaXNXb3Jkc1sodGhpc1NpZ0J5dGVzICsgaSkgPj4+IDJdIHw9IHRoYXRCeXRlIDw8ICgyNCAtICgodGhpc1NpZ0J5dGVzICsgaSkgJSA0KSAqIDgpO1xuXHQgICAgICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICB9IGVsc2Uge1xuXHQgICAgICAgICAgICAgICAgLy8gQ29weSBvbmUgd29yZCBhdCBhIHRpbWVcblx0ICAgICAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgdGhhdFNpZ0J5dGVzOyBpICs9IDQpIHtcblx0ICAgICAgICAgICAgICAgICAgICB0aGlzV29yZHNbKHRoaXNTaWdCeXRlcyArIGkpID4+PiAyXSA9IHRoYXRXb3Jkc1tpID4+PiAyXTtcblx0ICAgICAgICAgICAgICAgIH1cblx0ICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICB0aGlzLnNpZ0J5dGVzICs9IHRoYXRTaWdCeXRlcztcblxuXHQgICAgICAgICAgICAvLyBDaGFpbmFibGVcblx0ICAgICAgICAgICAgcmV0dXJuIHRoaXM7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIFJlbW92ZXMgaW5zaWduaWZpY2FudCBiaXRzLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB3b3JkQXJyYXkuY2xhbXAoKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBjbGFtcDogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICAgICAgdmFyIHdvcmRzID0gdGhpcy53b3Jkcztcblx0ICAgICAgICAgICAgdmFyIHNpZ0J5dGVzID0gdGhpcy5zaWdCeXRlcztcblxuXHQgICAgICAgICAgICAvLyBDbGFtcFxuXHQgICAgICAgICAgICB3b3Jkc1tzaWdCeXRlcyA+Pj4gMl0gJj0gMHhmZmZmZmZmZiA8PCAoMzIgLSAoc2lnQnl0ZXMgJSA0KSAqIDgpO1xuXHQgICAgICAgICAgICB3b3Jkcy5sZW5ndGggPSBNYXRoLmNlaWwoc2lnQnl0ZXMgLyA0KTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ3JlYXRlcyBhIGNvcHkgb2YgdGhpcyB3b3JkIGFycmF5LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHJldHVybiB7V29yZEFycmF5fSBUaGUgY2xvbmUuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciBjbG9uZSA9IHdvcmRBcnJheS5jbG9uZSgpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIGNsb25lOiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgIHZhciBjbG9uZSA9IEJhc2UuY2xvbmUuY2FsbCh0aGlzKTtcblx0ICAgICAgICAgICAgY2xvbmUud29yZHMgPSB0aGlzLndvcmRzLnNsaWNlKDApO1xuXG5cdCAgICAgICAgICAgIHJldHVybiBjbG9uZTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ3JlYXRlcyBhIHdvcmQgYXJyYXkgZmlsbGVkIHdpdGggcmFuZG9tIGJ5dGVzLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtudW1iZXJ9IG5CeXRlcyBUaGUgbnVtYmVyIG9mIHJhbmRvbSBieXRlcyB0byBnZW5lcmF0ZS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge1dvcmRBcnJheX0gVGhlIHJhbmRvbSB3b3JkIGFycmF5LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgd29yZEFycmF5ID0gQ3J5cHRvSlMubGliLldvcmRBcnJheS5yYW5kb20oMTYpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIHJhbmRvbTogZnVuY3Rpb24gKG5CeXRlcykge1xuXHQgICAgICAgICAgICB2YXIgd29yZHMgPSBbXTtcblxuXHQgICAgICAgICAgICB2YXIgciA9IChmdW5jdGlvbiAobV93KSB7XG5cdCAgICAgICAgICAgICAgICB2YXIgbV93ID0gbV93O1xuXHQgICAgICAgICAgICAgICAgdmFyIG1feiA9IDB4M2FkZTY4YjE7XG5cdCAgICAgICAgICAgICAgICB2YXIgbWFzayA9IDB4ZmZmZmZmZmY7XG5cblx0ICAgICAgICAgICAgICAgIHJldHVybiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgICAgICAgICAgbV96ID0gKDB4OTA2OSAqIChtX3ogJiAweEZGRkYpICsgKG1feiA+PiAweDEwKSkgJiBtYXNrO1xuXHQgICAgICAgICAgICAgICAgICAgIG1fdyA9ICgweDQ2NTAgKiAobV93ICYgMHhGRkZGKSArIChtX3cgPj4gMHgxMCkpICYgbWFzaztcblx0ICAgICAgICAgICAgICAgICAgICB2YXIgcmVzdWx0ID0gKChtX3ogPDwgMHgxMCkgKyBtX3cpICYgbWFzaztcblx0ICAgICAgICAgICAgICAgICAgICByZXN1bHQgLz0gMHgxMDAwMDAwMDA7XG5cdCAgICAgICAgICAgICAgICAgICAgcmVzdWx0ICs9IDAuNTtcblx0ICAgICAgICAgICAgICAgICAgICByZXR1cm4gcmVzdWx0ICogKE1hdGgucmFuZG9tKCkgPiAuNSA/IDEgOiAtMSk7XG5cdCAgICAgICAgICAgICAgICB9XG5cdCAgICAgICAgICAgIH0pO1xuXG5cdCAgICAgICAgICAgIGZvciAodmFyIGkgPSAwLCByY2FjaGU7IGkgPCBuQnl0ZXM7IGkgKz0gNCkge1xuXHQgICAgICAgICAgICAgICAgdmFyIF9yID0gcigocmNhY2hlIHx8IE1hdGgucmFuZG9tKCkpICogMHgxMDAwMDAwMDApO1xuXG5cdCAgICAgICAgICAgICAgICByY2FjaGUgPSBfcigpICogMHgzYWRlNjdiNztcblx0ICAgICAgICAgICAgICAgIHdvcmRzLnB1c2goKF9yKCkgKiAweDEwMDAwMDAwMCkgfCAwKTtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIHJldHVybiBuZXcgV29yZEFycmF5LmluaXQod29yZHMsIG5CeXRlcyk7XG5cdCAgICAgICAgfVxuXHQgICAgfSk7XG5cblx0ICAgIC8qKlxuXHQgICAgICogRW5jb2RlciBuYW1lc3BhY2UuXG5cdCAgICAgKi9cblx0ICAgIHZhciBDX2VuYyA9IEMuZW5jID0ge307XG5cblx0ICAgIC8qKlxuXHQgICAgICogSGV4IGVuY29kaW5nIHN0cmF0ZWd5LlxuXHQgICAgICovXG5cdCAgICB2YXIgSGV4ID0gQ19lbmMuSGV4ID0ge1xuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENvbnZlcnRzIGEgd29yZCBhcnJheSB0byBhIGhleCBzdHJpbmcuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge1dvcmRBcnJheX0gd29yZEFycmF5IFRoZSB3b3JkIGFycmF5LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHJldHVybiB7c3RyaW5nfSBUaGUgaGV4IHN0cmluZy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBzdGF0aWNcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIGhleFN0cmluZyA9IENyeXB0b0pTLmVuYy5IZXguc3RyaW5naWZ5KHdvcmRBcnJheSk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgc3RyaW5naWZ5OiBmdW5jdGlvbiAod29yZEFycmF5KSB7XG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICB2YXIgd29yZHMgPSB3b3JkQXJyYXkud29yZHM7XG5cdCAgICAgICAgICAgIHZhciBzaWdCeXRlcyA9IHdvcmRBcnJheS5zaWdCeXRlcztcblxuXHQgICAgICAgICAgICAvLyBDb252ZXJ0XG5cdCAgICAgICAgICAgIHZhciBoZXhDaGFycyA9IFtdO1xuXHQgICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IHNpZ0J5dGVzOyBpKyspIHtcblx0ICAgICAgICAgICAgICAgIHZhciBiaXRlID0gKHdvcmRzW2kgPj4+IDJdID4+PiAoMjQgLSAoaSAlIDQpICogOCkpICYgMHhmZjtcblx0ICAgICAgICAgICAgICAgIGhleENoYXJzLnB1c2goKGJpdGUgPj4+IDQpLnRvU3RyaW5nKDE2KSk7XG5cdCAgICAgICAgICAgICAgICBoZXhDaGFycy5wdXNoKChiaXRlICYgMHgwZikudG9TdHJpbmcoMTYpKTtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIHJldHVybiBoZXhDaGFycy5qb2luKCcnKTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ29udmVydHMgYSBoZXggc3RyaW5nIHRvIGEgd29yZCBhcnJheS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7c3RyaW5nfSBoZXhTdHIgVGhlIGhleCBzdHJpbmcuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtXb3JkQXJyYXl9IFRoZSB3b3JkIGFycmF5LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgd29yZEFycmF5ID0gQ3J5cHRvSlMuZW5jLkhleC5wYXJzZShoZXhTdHJpbmcpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIHBhcnNlOiBmdW5jdGlvbiAoaGV4U3RyKSB7XG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0XG5cdCAgICAgICAgICAgIHZhciBoZXhTdHJMZW5ndGggPSBoZXhTdHIubGVuZ3RoO1xuXG5cdCAgICAgICAgICAgIC8vIENvbnZlcnRcblx0ICAgICAgICAgICAgdmFyIHdvcmRzID0gW107XG5cdCAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgaGV4U3RyTGVuZ3RoOyBpICs9IDIpIHtcblx0ICAgICAgICAgICAgICAgIHdvcmRzW2kgPj4+IDNdIHw9IHBhcnNlSW50KGhleFN0ci5zdWJzdHIoaSwgMiksIDE2KSA8PCAoMjQgLSAoaSAlIDgpICogNCk7XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICByZXR1cm4gbmV3IFdvcmRBcnJheS5pbml0KHdvcmRzLCBoZXhTdHJMZW5ndGggLyAyKTtcblx0ICAgICAgICB9XG5cdCAgICB9O1xuXG5cdCAgICAvKipcblx0ICAgICAqIExhdGluMSBlbmNvZGluZyBzdHJhdGVneS5cblx0ICAgICAqL1xuXHQgICAgdmFyIExhdGluMSA9IENfZW5jLkxhdGluMSA9IHtcblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBDb252ZXJ0cyBhIHdvcmQgYXJyYXkgdG8gYSBMYXRpbjEgc3RyaW5nLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtXb3JkQXJyYXl9IHdvcmRBcnJheSBUaGUgd29yZCBhcnJheS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge3N0cmluZ30gVGhlIExhdGluMSBzdHJpbmcuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAc3RhdGljXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciBsYXRpbjFTdHJpbmcgPSBDcnlwdG9KUy5lbmMuTGF0aW4xLnN0cmluZ2lmeSh3b3JkQXJyYXkpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIHN0cmluZ2lmeTogZnVuY3Rpb24gKHdvcmRBcnJheSkge1xuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICAgICAgdmFyIHdvcmRzID0gd29yZEFycmF5LndvcmRzO1xuXHQgICAgICAgICAgICB2YXIgc2lnQnl0ZXMgPSB3b3JkQXJyYXkuc2lnQnl0ZXM7XG5cblx0ICAgICAgICAgICAgLy8gQ29udmVydFxuXHQgICAgICAgICAgICB2YXIgbGF0aW4xQ2hhcnMgPSBbXTtcblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBzaWdCeXRlczsgaSsrKSB7XG5cdCAgICAgICAgICAgICAgICB2YXIgYml0ZSA9ICh3b3Jkc1tpID4+PiAyXSA+Pj4gKDI0IC0gKGkgJSA0KSAqIDgpKSAmIDB4ZmY7XG5cdCAgICAgICAgICAgICAgICBsYXRpbjFDaGFycy5wdXNoKFN0cmluZy5mcm9tQ2hhckNvZGUoYml0ZSkpO1xuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgcmV0dXJuIGxhdGluMUNoYXJzLmpvaW4oJycpO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBDb252ZXJ0cyBhIExhdGluMSBzdHJpbmcgdG8gYSB3b3JkIGFycmF5LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtzdHJpbmd9IGxhdGluMVN0ciBUaGUgTGF0aW4xIHN0cmluZy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge1dvcmRBcnJheX0gVGhlIHdvcmQgYXJyYXkuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAc3RhdGljXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciB3b3JkQXJyYXkgPSBDcnlwdG9KUy5lbmMuTGF0aW4xLnBhcnNlKGxhdGluMVN0cmluZyk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgcGFyc2U6IGZ1bmN0aW9uIChsYXRpbjFTdHIpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRcblx0ICAgICAgICAgICAgdmFyIGxhdGluMVN0ckxlbmd0aCA9IGxhdGluMVN0ci5sZW5ndGg7XG5cblx0ICAgICAgICAgICAgLy8gQ29udmVydFxuXHQgICAgICAgICAgICB2YXIgd29yZHMgPSBbXTtcblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBsYXRpbjFTdHJMZW5ndGg7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgd29yZHNbaSA+Pj4gMl0gfD0gKGxhdGluMVN0ci5jaGFyQ29kZUF0KGkpICYgMHhmZikgPDwgKDI0IC0gKGkgJSA0KSAqIDgpO1xuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgcmV0dXJuIG5ldyBXb3JkQXJyYXkuaW5pdCh3b3JkcywgbGF0aW4xU3RyTGVuZ3RoKTtcblx0ICAgICAgICB9XG5cdCAgICB9O1xuXG5cdCAgICAvKipcblx0ICAgICAqIFVURi04IGVuY29kaW5nIHN0cmF0ZWd5LlxuXHQgICAgICovXG5cdCAgICB2YXIgVXRmOCA9IENfZW5jLlV0ZjggPSB7XG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ29udmVydHMgYSB3b3JkIGFycmF5IHRvIGEgVVRGLTggc3RyaW5nLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtXb3JkQXJyYXl9IHdvcmRBcnJheSBUaGUgd29yZCBhcnJheS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge3N0cmluZ30gVGhlIFVURi04IHN0cmluZy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBzdGF0aWNcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIHV0ZjhTdHJpbmcgPSBDcnlwdG9KUy5lbmMuVXRmOC5zdHJpbmdpZnkod29yZEFycmF5KTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBzdHJpbmdpZnk6IGZ1bmN0aW9uICh3b3JkQXJyYXkpIHtcblx0ICAgICAgICAgICAgdHJ5IHtcblx0ICAgICAgICAgICAgICAgIHJldHVybiBkZWNvZGVVUklDb21wb25lbnQoZXNjYXBlKExhdGluMS5zdHJpbmdpZnkod29yZEFycmF5KSkpO1xuXHQgICAgICAgICAgICB9IGNhdGNoIChlKSB7XG5cdCAgICAgICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ01hbGZvcm1lZCBVVEYtOCBkYXRhJyk7XG5cdCAgICAgICAgICAgIH1cblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ29udmVydHMgYSBVVEYtOCBzdHJpbmcgdG8gYSB3b3JkIGFycmF5LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtzdHJpbmd9IHV0ZjhTdHIgVGhlIFVURi04IHN0cmluZy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge1dvcmRBcnJheX0gVGhlIHdvcmQgYXJyYXkuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAc3RhdGljXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciB3b3JkQXJyYXkgPSBDcnlwdG9KUy5lbmMuVXRmOC5wYXJzZSh1dGY4U3RyaW5nKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBwYXJzZTogZnVuY3Rpb24gKHV0ZjhTdHIpIHtcblx0ICAgICAgICAgICAgcmV0dXJuIExhdGluMS5wYXJzZSh1bmVzY2FwZShlbmNvZGVVUklDb21wb25lbnQodXRmOFN0cikpKTtcblx0ICAgICAgICB9XG5cdCAgICB9O1xuXG5cdCAgICAvKipcblx0ICAgICAqIEFic3RyYWN0IGJ1ZmZlcmVkIGJsb2NrIGFsZ29yaXRobSB0ZW1wbGF0ZS5cblx0ICAgICAqXG5cdCAgICAgKiBUaGUgcHJvcGVydHkgYmxvY2tTaXplIG11c3QgYmUgaW1wbGVtZW50ZWQgaW4gYSBjb25jcmV0ZSBzdWJ0eXBlLlxuXHQgICAgICpcblx0ICAgICAqIEBwcm9wZXJ0eSB7bnVtYmVyfSBfbWluQnVmZmVyU2l6ZSBUaGUgbnVtYmVyIG9mIGJsb2NrcyB0aGF0IHNob3VsZCBiZSBrZXB0IHVucHJvY2Vzc2VkIGluIHRoZSBidWZmZXIuIERlZmF1bHQ6IDBcblx0ICAgICAqL1xuXHQgICAgdmFyIEJ1ZmZlcmVkQmxvY2tBbGdvcml0aG0gPSBDX2xpYi5CdWZmZXJlZEJsb2NrQWxnb3JpdGhtID0gQmFzZS5leHRlbmQoe1xuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIFJlc2V0cyB0aGlzIGJsb2NrIGFsZ29yaXRobSdzIGRhdGEgYnVmZmVyIHRvIGl0cyBpbml0aWFsIHN0YXRlLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICBidWZmZXJlZEJsb2NrQWxnb3JpdGhtLnJlc2V0KCk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgcmVzZXQ6IGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgLy8gSW5pdGlhbCB2YWx1ZXNcblx0ICAgICAgICAgICAgdGhpcy5fZGF0YSA9IG5ldyBXb3JkQXJyYXkuaW5pdCgpO1xuXHQgICAgICAgICAgICB0aGlzLl9uRGF0YUJ5dGVzID0gMDtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQWRkcyBuZXcgZGF0YSB0byB0aGlzIGJsb2NrIGFsZ29yaXRobSdzIGJ1ZmZlci5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7V29yZEFycmF5fHN0cmluZ30gZGF0YSBUaGUgZGF0YSB0byBhcHBlbmQuIFN0cmluZ3MgYXJlIGNvbnZlcnRlZCB0byBhIFdvcmRBcnJheSB1c2luZyBVVEYtOC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgYnVmZmVyZWRCbG9ja0FsZ29yaXRobS5fYXBwZW5kKCdkYXRhJyk7XG5cdCAgICAgICAgICogICAgIGJ1ZmZlcmVkQmxvY2tBbGdvcml0aG0uX2FwcGVuZCh3b3JkQXJyYXkpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIF9hcHBlbmQ6IGZ1bmN0aW9uIChkYXRhKSB7XG5cdCAgICAgICAgICAgIC8vIENvbnZlcnQgc3RyaW5nIHRvIFdvcmRBcnJheSwgZWxzZSBhc3N1bWUgV29yZEFycmF5IGFscmVhZHlcblx0ICAgICAgICAgICAgaWYgKHR5cGVvZiBkYXRhID09ICdzdHJpbmcnKSB7XG5cdCAgICAgICAgICAgICAgICBkYXRhID0gVXRmOC5wYXJzZShkYXRhKTtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIC8vIEFwcGVuZFxuXHQgICAgICAgICAgICB0aGlzLl9kYXRhLmNvbmNhdChkYXRhKTtcblx0ICAgICAgICAgICAgdGhpcy5fbkRhdGFCeXRlcyArPSBkYXRhLnNpZ0J5dGVzO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBQcm9jZXNzZXMgYXZhaWxhYmxlIGRhdGEgYmxvY2tzLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogVGhpcyBtZXRob2QgaW52b2tlcyBfZG9Qcm9jZXNzQmxvY2sob2Zmc2V0KSwgd2hpY2ggbXVzdCBiZSBpbXBsZW1lbnRlZCBieSBhIGNvbmNyZXRlIHN1YnR5cGUuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge2Jvb2xlYW59IGRvRmx1c2ggV2hldGhlciBhbGwgYmxvY2tzIGFuZCBwYXJ0aWFsIGJsb2NrcyBzaG91bGQgYmUgcHJvY2Vzc2VkLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHJldHVybiB7V29yZEFycmF5fSBUaGUgcHJvY2Vzc2VkIGRhdGEuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciBwcm9jZXNzZWREYXRhID0gYnVmZmVyZWRCbG9ja0FsZ29yaXRobS5fcHJvY2VzcygpO1xuXHQgICAgICAgICAqICAgICB2YXIgcHJvY2Vzc2VkRGF0YSA9IGJ1ZmZlcmVkQmxvY2tBbGdvcml0aG0uX3Byb2Nlc3MoISEnZmx1c2gnKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBfcHJvY2VzczogZnVuY3Rpb24gKGRvRmx1c2gpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgIHZhciBkYXRhID0gdGhpcy5fZGF0YTtcblx0ICAgICAgICAgICAgdmFyIGRhdGFXb3JkcyA9IGRhdGEud29yZHM7XG5cdCAgICAgICAgICAgIHZhciBkYXRhU2lnQnl0ZXMgPSBkYXRhLnNpZ0J5dGVzO1xuXHQgICAgICAgICAgICB2YXIgYmxvY2tTaXplID0gdGhpcy5ibG9ja1NpemU7XG5cdCAgICAgICAgICAgIHZhciBibG9ja1NpemVCeXRlcyA9IGJsb2NrU2l6ZSAqIDQ7XG5cblx0ICAgICAgICAgICAgLy8gQ291bnQgYmxvY2tzIHJlYWR5XG5cdCAgICAgICAgICAgIHZhciBuQmxvY2tzUmVhZHkgPSBkYXRhU2lnQnl0ZXMgLyBibG9ja1NpemVCeXRlcztcblx0ICAgICAgICAgICAgaWYgKGRvRmx1c2gpIHtcblx0ICAgICAgICAgICAgICAgIC8vIFJvdW5kIHVwIHRvIGluY2x1ZGUgcGFydGlhbCBibG9ja3Ncblx0ICAgICAgICAgICAgICAgIG5CbG9ja3NSZWFkeSA9IE1hdGguY2VpbChuQmxvY2tzUmVhZHkpO1xuXHQgICAgICAgICAgICB9IGVsc2Uge1xuXHQgICAgICAgICAgICAgICAgLy8gUm91bmQgZG93biB0byBpbmNsdWRlIG9ubHkgZnVsbCBibG9ja3MsXG5cdCAgICAgICAgICAgICAgICAvLyBsZXNzIHRoZSBudW1iZXIgb2YgYmxvY2tzIHRoYXQgbXVzdCByZW1haW4gaW4gdGhlIGJ1ZmZlclxuXHQgICAgICAgICAgICAgICAgbkJsb2Nrc1JlYWR5ID0gTWF0aC5tYXgoKG5CbG9ja3NSZWFkeSB8IDApIC0gdGhpcy5fbWluQnVmZmVyU2l6ZSwgMCk7XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAvLyBDb3VudCB3b3JkcyByZWFkeVxuXHQgICAgICAgICAgICB2YXIgbldvcmRzUmVhZHkgPSBuQmxvY2tzUmVhZHkgKiBibG9ja1NpemU7XG5cblx0ICAgICAgICAgICAgLy8gQ291bnQgYnl0ZXMgcmVhZHlcblx0ICAgICAgICAgICAgdmFyIG5CeXRlc1JlYWR5ID0gTWF0aC5taW4obldvcmRzUmVhZHkgKiA0LCBkYXRhU2lnQnl0ZXMpO1xuXG5cdCAgICAgICAgICAgIC8vIFByb2Nlc3MgYmxvY2tzXG5cdCAgICAgICAgICAgIGlmIChuV29yZHNSZWFkeSkge1xuXHQgICAgICAgICAgICAgICAgZm9yICh2YXIgb2Zmc2V0ID0gMDsgb2Zmc2V0IDwgbldvcmRzUmVhZHk7IG9mZnNldCArPSBibG9ja1NpemUpIHtcblx0ICAgICAgICAgICAgICAgICAgICAvLyBQZXJmb3JtIGNvbmNyZXRlLWFsZ29yaXRobSBsb2dpY1xuXHQgICAgICAgICAgICAgICAgICAgIHRoaXMuX2RvUHJvY2Vzc0Jsb2NrKGRhdGFXb3Jkcywgb2Zmc2V0KTtcblx0ICAgICAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAgICAgLy8gUmVtb3ZlIHByb2Nlc3NlZCB3b3Jkc1xuXHQgICAgICAgICAgICAgICAgdmFyIHByb2Nlc3NlZFdvcmRzID0gZGF0YVdvcmRzLnNwbGljZSgwLCBuV29yZHNSZWFkeSk7XG5cdCAgICAgICAgICAgICAgICBkYXRhLnNpZ0J5dGVzIC09IG5CeXRlc1JlYWR5O1xuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgLy8gUmV0dXJuIHByb2Nlc3NlZCB3b3Jkc1xuXHQgICAgICAgICAgICByZXR1cm4gbmV3IFdvcmRBcnJheS5pbml0KHByb2Nlc3NlZFdvcmRzLCBuQnl0ZXNSZWFkeSk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENyZWF0ZXMgYSBjb3B5IG9mIHRoaXMgb2JqZWN0LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHJldHVybiB7T2JqZWN0fSBUaGUgY2xvbmUuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciBjbG9uZSA9IGJ1ZmZlcmVkQmxvY2tBbGdvcml0aG0uY2xvbmUoKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBjbG9uZTogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICB2YXIgY2xvbmUgPSBCYXNlLmNsb25lLmNhbGwodGhpcyk7XG5cdCAgICAgICAgICAgIGNsb25lLl9kYXRhID0gdGhpcy5fZGF0YS5jbG9uZSgpO1xuXG5cdCAgICAgICAgICAgIHJldHVybiBjbG9uZTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgX21pbkJ1ZmZlclNpemU6IDBcblx0ICAgIH0pO1xuXG5cdCAgICAvKipcblx0ICAgICAqIEFic3RyYWN0IGhhc2hlciB0ZW1wbGF0ZS5cblx0ICAgICAqXG5cdCAgICAgKiBAcHJvcGVydHkge251bWJlcn0gYmxvY2tTaXplIFRoZSBudW1iZXIgb2YgMzItYml0IHdvcmRzIHRoaXMgaGFzaGVyIG9wZXJhdGVzIG9uLiBEZWZhdWx0OiAxNiAoNTEyIGJpdHMpXG5cdCAgICAgKi9cblx0ICAgIHZhciBIYXNoZXIgPSBDX2xpYi5IYXNoZXIgPSBCdWZmZXJlZEJsb2NrQWxnb3JpdGhtLmV4dGVuZCh7XG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ29uZmlndXJhdGlvbiBvcHRpb25zLlxuXHQgICAgICAgICAqL1xuXHQgICAgICAgIGNmZzogQmFzZS5leHRlbmQoKSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIEluaXRpYWxpemVzIGEgbmV3bHkgY3JlYXRlZCBoYXNoZXIuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge09iamVjdH0gY2ZnIChPcHRpb25hbCkgVGhlIGNvbmZpZ3VyYXRpb24gb3B0aW9ucyB0byB1c2UgZm9yIHRoaXMgaGFzaCBjb21wdXRhdGlvbi5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIGhhc2hlciA9IENyeXB0b0pTLmFsZ28uU0hBMjU2LmNyZWF0ZSgpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIGluaXQ6IGZ1bmN0aW9uIChjZmcpIHtcblx0ICAgICAgICAgICAgLy8gQXBwbHkgY29uZmlnIGRlZmF1bHRzXG5cdCAgICAgICAgICAgIHRoaXMuY2ZnID0gdGhpcy5jZmcuZXh0ZW5kKGNmZyk7XG5cblx0ICAgICAgICAgICAgLy8gU2V0IGluaXRpYWwgdmFsdWVzXG5cdCAgICAgICAgICAgIHRoaXMucmVzZXQoKTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogUmVzZXRzIHRoaXMgaGFzaGVyIHRvIGl0cyBpbml0aWFsIHN0YXRlLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICBoYXNoZXIucmVzZXQoKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICByZXNldDogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICAvLyBSZXNldCBkYXRhIGJ1ZmZlclxuXHQgICAgICAgICAgICBCdWZmZXJlZEJsb2NrQWxnb3JpdGhtLnJlc2V0LmNhbGwodGhpcyk7XG5cblx0ICAgICAgICAgICAgLy8gUGVyZm9ybSBjb25jcmV0ZS1oYXNoZXIgbG9naWNcblx0ICAgICAgICAgICAgdGhpcy5fZG9SZXNldCgpO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBVcGRhdGVzIHRoaXMgaGFzaGVyIHdpdGggYSBtZXNzYWdlLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBtZXNzYWdlVXBkYXRlIFRoZSBtZXNzYWdlIHRvIGFwcGVuZC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge0hhc2hlcn0gVGhpcyBoYXNoZXIuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIGhhc2hlci51cGRhdGUoJ21lc3NhZ2UnKTtcblx0ICAgICAgICAgKiAgICAgaGFzaGVyLnVwZGF0ZSh3b3JkQXJyYXkpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIHVwZGF0ZTogZnVuY3Rpb24gKG1lc3NhZ2VVcGRhdGUpIHtcblx0ICAgICAgICAgICAgLy8gQXBwZW5kXG5cdCAgICAgICAgICAgIHRoaXMuX2FwcGVuZChtZXNzYWdlVXBkYXRlKTtcblxuXHQgICAgICAgICAgICAvLyBVcGRhdGUgdGhlIGhhc2hcblx0ICAgICAgICAgICAgdGhpcy5fcHJvY2VzcygpO1xuXG5cdCAgICAgICAgICAgIC8vIENoYWluYWJsZVxuXHQgICAgICAgICAgICByZXR1cm4gdGhpcztcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogRmluYWxpemVzIHRoZSBoYXNoIGNvbXB1dGF0aW9uLlxuXHQgICAgICAgICAqIE5vdGUgdGhhdCB0aGUgZmluYWxpemUgb3BlcmF0aW9uIGlzIGVmZmVjdGl2ZWx5IGEgZGVzdHJ1Y3RpdmUsIHJlYWQtb25jZSBvcGVyYXRpb24uXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge1dvcmRBcnJheXxzdHJpbmd9IG1lc3NhZ2VVcGRhdGUgKE9wdGlvbmFsKSBBIGZpbmFsIG1lc3NhZ2UgdXBkYXRlLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHJldHVybiB7V29yZEFycmF5fSBUaGUgaGFzaC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIGhhc2ggPSBoYXNoZXIuZmluYWxpemUoKTtcblx0ICAgICAgICAgKiAgICAgdmFyIGhhc2ggPSBoYXNoZXIuZmluYWxpemUoJ21lc3NhZ2UnKTtcblx0ICAgICAgICAgKiAgICAgdmFyIGhhc2ggPSBoYXNoZXIuZmluYWxpemUod29yZEFycmF5KTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBmaW5hbGl6ZTogZnVuY3Rpb24gKG1lc3NhZ2VVcGRhdGUpIHtcblx0ICAgICAgICAgICAgLy8gRmluYWwgbWVzc2FnZSB1cGRhdGVcblx0ICAgICAgICAgICAgaWYgKG1lc3NhZ2VVcGRhdGUpIHtcblx0ICAgICAgICAgICAgICAgIHRoaXMuX2FwcGVuZChtZXNzYWdlVXBkYXRlKTtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIC8vIFBlcmZvcm0gY29uY3JldGUtaGFzaGVyIGxvZ2ljXG5cdCAgICAgICAgICAgIHZhciBoYXNoID0gdGhpcy5fZG9GaW5hbGl6ZSgpO1xuXG5cdCAgICAgICAgICAgIHJldHVybiBoYXNoO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICBibG9ja1NpemU6IDUxMi8zMixcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENyZWF0ZXMgYSBzaG9ydGN1dCBmdW5jdGlvbiB0byBhIGhhc2hlcidzIG9iamVjdCBpbnRlcmZhY2UuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge0hhc2hlcn0gaGFzaGVyIFRoZSBoYXNoZXIgdG8gY3JlYXRlIGEgaGVscGVyIGZvci5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge0Z1bmN0aW9ufSBUaGUgc2hvcnRjdXQgZnVuY3Rpb24uXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAc3RhdGljXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciBTSEEyNTYgPSBDcnlwdG9KUy5saWIuSGFzaGVyLl9jcmVhdGVIZWxwZXIoQ3J5cHRvSlMuYWxnby5TSEEyNTYpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIF9jcmVhdGVIZWxwZXI6IGZ1bmN0aW9uIChoYXNoZXIpIHtcblx0ICAgICAgICAgICAgcmV0dXJuIGZ1bmN0aW9uIChtZXNzYWdlLCBjZmcpIHtcblx0ICAgICAgICAgICAgICAgIHJldHVybiBuZXcgaGFzaGVyLmluaXQoY2ZnKS5maW5hbGl6ZShtZXNzYWdlKTtcblx0ICAgICAgICAgICAgfTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ3JlYXRlcyBhIHNob3J0Y3V0IGZ1bmN0aW9uIHRvIHRoZSBITUFDJ3Mgb2JqZWN0IGludGVyZmFjZS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7SGFzaGVyfSBoYXNoZXIgVGhlIGhhc2hlciB0byB1c2UgaW4gdGhpcyBITUFDIGhlbHBlci5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge0Z1bmN0aW9ufSBUaGUgc2hvcnRjdXQgZnVuY3Rpb24uXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAc3RhdGljXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciBIbWFjU0hBMjU2ID0gQ3J5cHRvSlMubGliLkhhc2hlci5fY3JlYXRlSG1hY0hlbHBlcihDcnlwdG9KUy5hbGdvLlNIQTI1Nik7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgX2NyZWF0ZUhtYWNIZWxwZXI6IGZ1bmN0aW9uIChoYXNoZXIpIHtcblx0ICAgICAgICAgICAgcmV0dXJuIGZ1bmN0aW9uIChtZXNzYWdlLCBrZXkpIHtcblx0ICAgICAgICAgICAgICAgIHJldHVybiBuZXcgQ19hbGdvLkhNQUMuaW5pdChoYXNoZXIsIGtleSkuZmluYWxpemUobWVzc2FnZSk7XG5cdCAgICAgICAgICAgIH07XG5cdCAgICAgICAgfVxuXHQgICAgfSk7XG5cblx0ICAgIC8qKlxuXHQgICAgICogQWxnb3JpdGhtIG5hbWVzcGFjZS5cblx0ICAgICAqL1xuXHQgICAgdmFyIENfYWxnbyA9IEMuYWxnbyA9IHt9O1xuXG5cdCAgICByZXR1cm4gQztcblx0fShNYXRoKSk7XG5cblxuXHRyZXR1cm4gQ3J5cHRvSlM7XG5cbn0pKTsiLCI7KGZ1bmN0aW9uIChyb290LCBmYWN0b3J5KSB7XG5cdGlmICh0eXBlb2YgZXhwb3J0cyA9PT0gXCJvYmplY3RcIikge1xuXHRcdC8vIENvbW1vbkpTXG5cdFx0bW9kdWxlLmV4cG9ydHMgPSBleHBvcnRzID0gZmFjdG9yeShyZXF1aXJlKFwiLi9jb3JlXCIpKTtcblx0fVxuXHRlbHNlIGlmICh0eXBlb2YgZGVmaW5lID09PSBcImZ1bmN0aW9uXCIgJiYgZGVmaW5lLmFtZCkge1xuXHRcdC8vIEFNRFxuXHRcdGRlZmluZShbXCIuL2NvcmVcIl0sIGZhY3RvcnkpO1xuXHR9XG5cdGVsc2Uge1xuXHRcdC8vIEdsb2JhbCAoYnJvd3Nlcilcblx0XHRmYWN0b3J5KHJvb3QuQ3J5cHRvSlMpO1xuXHR9XG59KHRoaXMsIGZ1bmN0aW9uIChDcnlwdG9KUykge1xuXG5cdChmdW5jdGlvbiAoKSB7XG5cdCAgICAvLyBTaG9ydGN1dHNcblx0ICAgIHZhciBDID0gQ3J5cHRvSlM7XG5cdCAgICB2YXIgQ19saWIgPSBDLmxpYjtcblx0ICAgIHZhciBXb3JkQXJyYXkgPSBDX2xpYi5Xb3JkQXJyYXk7XG5cdCAgICB2YXIgQ19lbmMgPSBDLmVuYztcblxuXHQgICAgLyoqXG5cdCAgICAgKiBCYXNlNjQgZW5jb2Rpbmcgc3RyYXRlZ3kuXG5cdCAgICAgKi9cblx0ICAgIHZhciBCYXNlNjQgPSBDX2VuYy5CYXNlNjQgPSB7XG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ29udmVydHMgYSB3b3JkIGFycmF5IHRvIGEgQmFzZTY0IHN0cmluZy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7V29yZEFycmF5fSB3b3JkQXJyYXkgVGhlIHdvcmQgYXJyYXkuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtzdHJpbmd9IFRoZSBCYXNlNjQgc3RyaW5nLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgYmFzZTY0U3RyaW5nID0gQ3J5cHRvSlMuZW5jLkJhc2U2NC5zdHJpbmdpZnkod29yZEFycmF5KTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBzdHJpbmdpZnk6IGZ1bmN0aW9uICh3b3JkQXJyYXkpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgIHZhciB3b3JkcyA9IHdvcmRBcnJheS53b3Jkcztcblx0ICAgICAgICAgICAgdmFyIHNpZ0J5dGVzID0gd29yZEFycmF5LnNpZ0J5dGVzO1xuXHQgICAgICAgICAgICB2YXIgbWFwID0gdGhpcy5fbWFwO1xuXG5cdCAgICAgICAgICAgIC8vIENsYW1wIGV4Y2VzcyBiaXRzXG5cdCAgICAgICAgICAgIHdvcmRBcnJheS5jbGFtcCgpO1xuXG5cdCAgICAgICAgICAgIC8vIENvbnZlcnRcblx0ICAgICAgICAgICAgdmFyIGJhc2U2NENoYXJzID0gW107XG5cdCAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgc2lnQnl0ZXM7IGkgKz0gMykge1xuXHQgICAgICAgICAgICAgICAgdmFyIGJ5dGUxID0gKHdvcmRzW2kgPj4+IDJdICAgICAgID4+PiAoMjQgLSAoaSAlIDQpICogOCkpICAgICAgICYgMHhmZjtcblx0ICAgICAgICAgICAgICAgIHZhciBieXRlMiA9ICh3b3Jkc1soaSArIDEpID4+PiAyXSA+Pj4gKDI0IC0gKChpICsgMSkgJSA0KSAqIDgpKSAmIDB4ZmY7XG5cdCAgICAgICAgICAgICAgICB2YXIgYnl0ZTMgPSAod29yZHNbKGkgKyAyKSA+Pj4gMl0gPj4+ICgyNCAtICgoaSArIDIpICUgNCkgKiA4KSkgJiAweGZmO1xuXG5cdCAgICAgICAgICAgICAgICB2YXIgdHJpcGxldCA9IChieXRlMSA8PCAxNikgfCAoYnl0ZTIgPDwgOCkgfCBieXRlMztcblxuXHQgICAgICAgICAgICAgICAgZm9yICh2YXIgaiA9IDA7IChqIDwgNCkgJiYgKGkgKyBqICogMC43NSA8IHNpZ0J5dGVzKTsgaisrKSB7XG5cdCAgICAgICAgICAgICAgICAgICAgYmFzZTY0Q2hhcnMucHVzaChtYXAuY2hhckF0KCh0cmlwbGV0ID4+PiAoNiAqICgzIC0gaikpKSAmIDB4M2YpKTtcblx0ICAgICAgICAgICAgICAgIH1cblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIC8vIEFkZCBwYWRkaW5nXG5cdCAgICAgICAgICAgIHZhciBwYWRkaW5nQ2hhciA9IG1hcC5jaGFyQXQoNjQpO1xuXHQgICAgICAgICAgICBpZiAocGFkZGluZ0NoYXIpIHtcblx0ICAgICAgICAgICAgICAgIHdoaWxlIChiYXNlNjRDaGFycy5sZW5ndGggJSA0KSB7XG5cdCAgICAgICAgICAgICAgICAgICAgYmFzZTY0Q2hhcnMucHVzaChwYWRkaW5nQ2hhcik7XG5cdCAgICAgICAgICAgICAgICB9XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICByZXR1cm4gYmFzZTY0Q2hhcnMuam9pbignJyk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENvbnZlcnRzIGEgQmFzZTY0IHN0cmluZyB0byBhIHdvcmQgYXJyYXkuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge3N0cmluZ30gYmFzZTY0U3RyIFRoZSBCYXNlNjQgc3RyaW5nLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHJldHVybiB7V29yZEFycmF5fSBUaGUgd29yZCBhcnJheS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBzdGF0aWNcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIHdvcmRBcnJheSA9IENyeXB0b0pTLmVuYy5CYXNlNjQucGFyc2UoYmFzZTY0U3RyaW5nKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBwYXJzZTogZnVuY3Rpb24gKGJhc2U2NFN0cikge1xuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICAgICAgdmFyIGJhc2U2NFN0ckxlbmd0aCA9IGJhc2U2NFN0ci5sZW5ndGg7XG5cdCAgICAgICAgICAgIHZhciBtYXAgPSB0aGlzLl9tYXA7XG5cdCAgICAgICAgICAgIHZhciByZXZlcnNlTWFwID0gdGhpcy5fcmV2ZXJzZU1hcDtcblxuXHQgICAgICAgICAgICBpZiAoIXJldmVyc2VNYXApIHtcblx0ICAgICAgICAgICAgICAgICAgICByZXZlcnNlTWFwID0gdGhpcy5fcmV2ZXJzZU1hcCA9IFtdO1xuXHQgICAgICAgICAgICAgICAgICAgIGZvciAodmFyIGogPSAwOyBqIDwgbWFwLmxlbmd0aDsgaisrKSB7XG5cdCAgICAgICAgICAgICAgICAgICAgICAgIHJldmVyc2VNYXBbbWFwLmNoYXJDb2RlQXQoaildID0gajtcblx0ICAgICAgICAgICAgICAgICAgICB9XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAvLyBJZ25vcmUgcGFkZGluZ1xuXHQgICAgICAgICAgICB2YXIgcGFkZGluZ0NoYXIgPSBtYXAuY2hhckF0KDY0KTtcblx0ICAgICAgICAgICAgaWYgKHBhZGRpbmdDaGFyKSB7XG5cdCAgICAgICAgICAgICAgICB2YXIgcGFkZGluZ0luZGV4ID0gYmFzZTY0U3RyLmluZGV4T2YocGFkZGluZ0NoYXIpO1xuXHQgICAgICAgICAgICAgICAgaWYgKHBhZGRpbmdJbmRleCAhPT0gLTEpIHtcblx0ICAgICAgICAgICAgICAgICAgICBiYXNlNjRTdHJMZW5ndGggPSBwYWRkaW5nSW5kZXg7XG5cdCAgICAgICAgICAgICAgICB9XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAvLyBDb252ZXJ0XG5cdCAgICAgICAgICAgIHJldHVybiBwYXJzZUxvb3AoYmFzZTY0U3RyLCBiYXNlNjRTdHJMZW5ndGgsIHJldmVyc2VNYXApO1xuXG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIF9tYXA6ICdBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OSsvPSdcblx0ICAgIH07XG5cblx0ICAgIGZ1bmN0aW9uIHBhcnNlTG9vcChiYXNlNjRTdHIsIGJhc2U2NFN0ckxlbmd0aCwgcmV2ZXJzZU1hcCkge1xuXHQgICAgICB2YXIgd29yZHMgPSBbXTtcblx0ICAgICAgdmFyIG5CeXRlcyA9IDA7XG5cdCAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYmFzZTY0U3RyTGVuZ3RoOyBpKyspIHtcblx0ICAgICAgICAgIGlmIChpICUgNCkge1xuXHQgICAgICAgICAgICAgIHZhciBiaXRzMSA9IHJldmVyc2VNYXBbYmFzZTY0U3RyLmNoYXJDb2RlQXQoaSAtIDEpXSA8PCAoKGkgJSA0KSAqIDIpO1xuXHQgICAgICAgICAgICAgIHZhciBiaXRzMiA9IHJldmVyc2VNYXBbYmFzZTY0U3RyLmNoYXJDb2RlQXQoaSldID4+PiAoNiAtIChpICUgNCkgKiAyKTtcblx0ICAgICAgICAgICAgICB3b3Jkc1tuQnl0ZXMgPj4+IDJdIHw9IChiaXRzMSB8IGJpdHMyKSA8PCAoMjQgLSAobkJ5dGVzICUgNCkgKiA4KTtcblx0ICAgICAgICAgICAgICBuQnl0ZXMrKztcblx0ICAgICAgICAgIH1cblx0ICAgICAgfVxuXHQgICAgICByZXR1cm4gV29yZEFycmF5LmNyZWF0ZSh3b3JkcywgbkJ5dGVzKTtcblx0ICAgIH1cblx0fSgpKTtcblxuXG5cdHJldHVybiBDcnlwdG9KUy5lbmMuQmFzZTY0O1xuXG59KSk7IiwiOyhmdW5jdGlvbiAocm9vdCwgZmFjdG9yeSwgdW5kZWYpIHtcblx0aWYgKHR5cGVvZiBleHBvcnRzID09PSBcIm9iamVjdFwiKSB7XG5cdFx0Ly8gQ29tbW9uSlNcblx0XHRtb2R1bGUuZXhwb3J0cyA9IGV4cG9ydHMgPSBmYWN0b3J5KHJlcXVpcmUoXCIuL2NvcmVcIiksIHJlcXVpcmUoXCIuL3NoYTFcIiksIHJlcXVpcmUoXCIuL2htYWNcIikpO1xuXHR9XG5cdGVsc2UgaWYgKHR5cGVvZiBkZWZpbmUgPT09IFwiZnVuY3Rpb25cIiAmJiBkZWZpbmUuYW1kKSB7XG5cdFx0Ly8gQU1EXG5cdFx0ZGVmaW5lKFtcIi4vY29yZVwiLCBcIi4vc2hhMVwiLCBcIi4vaG1hY1wiXSwgZmFjdG9yeSk7XG5cdH1cblx0ZWxzZSB7XG5cdFx0Ly8gR2xvYmFsIChicm93c2VyKVxuXHRcdGZhY3Rvcnkocm9vdC5DcnlwdG9KUyk7XG5cdH1cbn0odGhpcywgZnVuY3Rpb24gKENyeXB0b0pTKSB7XG5cblx0KGZ1bmN0aW9uICgpIHtcblx0ICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgdmFyIEMgPSBDcnlwdG9KUztcblx0ICAgIHZhciBDX2xpYiA9IEMubGliO1xuXHQgICAgdmFyIEJhc2UgPSBDX2xpYi5CYXNlO1xuXHQgICAgdmFyIFdvcmRBcnJheSA9IENfbGliLldvcmRBcnJheTtcblx0ICAgIHZhciBDX2FsZ28gPSBDLmFsZ287XG5cdCAgICB2YXIgTUQ1ID0gQ19hbGdvLk1ENTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBUaGlzIGtleSBkZXJpdmF0aW9uIGZ1bmN0aW9uIGlzIG1lYW50IHRvIGNvbmZvcm0gd2l0aCBFVlBfQnl0ZXNUb0tleS5cblx0ICAgICAqIHd3dy5vcGVuc3NsLm9yZy9kb2NzL2NyeXB0by9FVlBfQnl0ZXNUb0tleS5odG1sXG5cdCAgICAgKi9cblx0ICAgIHZhciBFdnBLREYgPSBDX2FsZ28uRXZwS0RGID0gQmFzZS5leHRlbmQoe1xuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENvbmZpZ3VyYXRpb24gb3B0aW9ucy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwcm9wZXJ0eSB7bnVtYmVyfSBrZXlTaXplIFRoZSBrZXkgc2l6ZSBpbiB3b3JkcyB0byBnZW5lcmF0ZS4gRGVmYXVsdDogNCAoMTI4IGJpdHMpXG5cdCAgICAgICAgICogQHByb3BlcnR5IHtIYXNoZXJ9IGhhc2hlciBUaGUgaGFzaCBhbGdvcml0aG0gdG8gdXNlLiBEZWZhdWx0OiBNRDVcblx0ICAgICAgICAgKiBAcHJvcGVydHkge251bWJlcn0gaXRlcmF0aW9ucyBUaGUgbnVtYmVyIG9mIGl0ZXJhdGlvbnMgdG8gcGVyZm9ybS4gRGVmYXVsdDogMVxuXHQgICAgICAgICAqL1xuXHQgICAgICAgIGNmZzogQmFzZS5leHRlbmQoe1xuXHQgICAgICAgICAgICBrZXlTaXplOiAxMjgvMzIsXG5cdCAgICAgICAgICAgIGhhc2hlcjogTUQ1LFxuXHQgICAgICAgICAgICBpdGVyYXRpb25zOiAxXG5cdCAgICAgICAgfSksXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBJbml0aWFsaXplcyBhIG5ld2x5IGNyZWF0ZWQga2V5IGRlcml2YXRpb24gZnVuY3Rpb24uXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge09iamVjdH0gY2ZnIChPcHRpb25hbCkgVGhlIGNvbmZpZ3VyYXRpb24gb3B0aW9ucyB0byB1c2UgZm9yIHRoZSBkZXJpdmF0aW9uLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIga2RmID0gQ3J5cHRvSlMuYWxnby5FdnBLREYuY3JlYXRlKCk7XG5cdCAgICAgICAgICogICAgIHZhciBrZGYgPSBDcnlwdG9KUy5hbGdvLkV2cEtERi5jcmVhdGUoeyBrZXlTaXplOiA4IH0pO1xuXHQgICAgICAgICAqICAgICB2YXIga2RmID0gQ3J5cHRvSlMuYWxnby5FdnBLREYuY3JlYXRlKHsga2V5U2l6ZTogOCwgaXRlcmF0aW9uczogMTAwMCB9KTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBpbml0OiBmdW5jdGlvbiAoY2ZnKSB7XG5cdCAgICAgICAgICAgIHRoaXMuY2ZnID0gdGhpcy5jZmcuZXh0ZW5kKGNmZyk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIERlcml2ZXMgYSBrZXkgZnJvbSBhIHBhc3N3b3JkLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBwYXNzd29yZCBUaGUgcGFzc3dvcmQuXG5cdCAgICAgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBzYWx0IEEgc2FsdC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge1dvcmRBcnJheX0gVGhlIGRlcml2ZWQga2V5LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIga2V5ID0ga2RmLmNvbXB1dGUocGFzc3dvcmQsIHNhbHQpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIGNvbXB1dGU6IGZ1bmN0aW9uIChwYXNzd29yZCwgc2FsdCkge1xuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dFxuXHQgICAgICAgICAgICB2YXIgY2ZnID0gdGhpcy5jZmc7XG5cblx0ICAgICAgICAgICAgLy8gSW5pdCBoYXNoZXJcblx0ICAgICAgICAgICAgdmFyIGhhc2hlciA9IGNmZy5oYXNoZXIuY3JlYXRlKCk7XG5cblx0ICAgICAgICAgICAgLy8gSW5pdGlhbCB2YWx1ZXNcblx0ICAgICAgICAgICAgdmFyIGRlcml2ZWRLZXkgPSBXb3JkQXJyYXkuY3JlYXRlKCk7XG5cblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgIHZhciBkZXJpdmVkS2V5V29yZHMgPSBkZXJpdmVkS2V5LndvcmRzO1xuXHQgICAgICAgICAgICB2YXIga2V5U2l6ZSA9IGNmZy5rZXlTaXplO1xuXHQgICAgICAgICAgICB2YXIgaXRlcmF0aW9ucyA9IGNmZy5pdGVyYXRpb25zO1xuXG5cdCAgICAgICAgICAgIC8vIEdlbmVyYXRlIGtleVxuXHQgICAgICAgICAgICB3aGlsZSAoZGVyaXZlZEtleVdvcmRzLmxlbmd0aCA8IGtleVNpemUpIHtcblx0ICAgICAgICAgICAgICAgIGlmIChibG9jaykge1xuXHQgICAgICAgICAgICAgICAgICAgIGhhc2hlci51cGRhdGUoYmxvY2spO1xuXHQgICAgICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICAgICAgdmFyIGJsb2NrID0gaGFzaGVyLnVwZGF0ZShwYXNzd29yZCkuZmluYWxpemUoc2FsdCk7XG5cdCAgICAgICAgICAgICAgICBoYXNoZXIucmVzZXQoKTtcblxuXHQgICAgICAgICAgICAgICAgLy8gSXRlcmF0aW9uc1xuXHQgICAgICAgICAgICAgICAgZm9yICh2YXIgaSA9IDE7IGkgPCBpdGVyYXRpb25zOyBpKyspIHtcblx0ICAgICAgICAgICAgICAgICAgICBibG9jayA9IGhhc2hlci5maW5hbGl6ZShibG9jayk7XG5cdCAgICAgICAgICAgICAgICAgICAgaGFzaGVyLnJlc2V0KCk7XG5cdCAgICAgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgICAgIGRlcml2ZWRLZXkuY29uY2F0KGJsb2NrKTtcblx0ICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICBkZXJpdmVkS2V5LnNpZ0J5dGVzID0ga2V5U2l6ZSAqIDQ7XG5cblx0ICAgICAgICAgICAgcmV0dXJuIGRlcml2ZWRLZXk7XG5cdCAgICAgICAgfVxuXHQgICAgfSk7XG5cblx0ICAgIC8qKlxuXHQgICAgICogRGVyaXZlcyBhIGtleSBmcm9tIGEgcGFzc3dvcmQuXG5cdCAgICAgKlxuXHQgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBwYXNzd29yZCBUaGUgcGFzc3dvcmQuXG5cdCAgICAgKiBAcGFyYW0ge1dvcmRBcnJheXxzdHJpbmd9IHNhbHQgQSBzYWx0LlxuXHQgICAgICogQHBhcmFtIHtPYmplY3R9IGNmZyAoT3B0aW9uYWwpIFRoZSBjb25maWd1cmF0aW9uIG9wdGlvbnMgdG8gdXNlIGZvciB0aGlzIGNvbXB1dGF0aW9uLlxuXHQgICAgICpcblx0ICAgICAqIEByZXR1cm4ge1dvcmRBcnJheX0gVGhlIGRlcml2ZWQga2V5LlxuXHQgICAgICpcblx0ICAgICAqIEBzdGF0aWNcblx0ICAgICAqXG5cdCAgICAgKiBAZXhhbXBsZVxuXHQgICAgICpcblx0ICAgICAqICAgICB2YXIga2V5ID0gQ3J5cHRvSlMuRXZwS0RGKHBhc3N3b3JkLCBzYWx0KTtcblx0ICAgICAqICAgICB2YXIga2V5ID0gQ3J5cHRvSlMuRXZwS0RGKHBhc3N3b3JkLCBzYWx0LCB7IGtleVNpemU6IDggfSk7XG5cdCAgICAgKiAgICAgdmFyIGtleSA9IENyeXB0b0pTLkV2cEtERihwYXNzd29yZCwgc2FsdCwgeyBrZXlTaXplOiA4LCBpdGVyYXRpb25zOiAxMDAwIH0pO1xuXHQgICAgICovXG5cdCAgICBDLkV2cEtERiA9IGZ1bmN0aW9uIChwYXNzd29yZCwgc2FsdCwgY2ZnKSB7XG5cdCAgICAgICAgcmV0dXJuIEV2cEtERi5jcmVhdGUoY2ZnKS5jb21wdXRlKHBhc3N3b3JkLCBzYWx0KTtcblx0ICAgIH07XG5cdH0oKSk7XG5cblxuXHRyZXR1cm4gQ3J5cHRvSlMuRXZwS0RGO1xuXG59KSk7IiwiOyhmdW5jdGlvbiAocm9vdCwgZmFjdG9yeSkge1xuXHRpZiAodHlwZW9mIGV4cG9ydHMgPT09IFwib2JqZWN0XCIpIHtcblx0XHQvLyBDb21tb25KU1xuXHRcdG1vZHVsZS5leHBvcnRzID0gZXhwb3J0cyA9IGZhY3RvcnkocmVxdWlyZShcIi4vY29yZVwiKSk7XG5cdH1cblx0ZWxzZSBpZiAodHlwZW9mIGRlZmluZSA9PT0gXCJmdW5jdGlvblwiICYmIGRlZmluZS5hbWQpIHtcblx0XHQvLyBBTURcblx0XHRkZWZpbmUoW1wiLi9jb3JlXCJdLCBmYWN0b3J5KTtcblx0fVxuXHRlbHNlIHtcblx0XHQvLyBHbG9iYWwgKGJyb3dzZXIpXG5cdFx0ZmFjdG9yeShyb290LkNyeXB0b0pTKTtcblx0fVxufSh0aGlzLCBmdW5jdGlvbiAoQ3J5cHRvSlMpIHtcblxuXHQoZnVuY3Rpb24gKCkge1xuXHQgICAgLy8gU2hvcnRjdXRzXG5cdCAgICB2YXIgQyA9IENyeXB0b0pTO1xuXHQgICAgdmFyIENfbGliID0gQy5saWI7XG5cdCAgICB2YXIgQmFzZSA9IENfbGliLkJhc2U7XG5cdCAgICB2YXIgQ19lbmMgPSBDLmVuYztcblx0ICAgIHZhciBVdGY4ID0gQ19lbmMuVXRmODtcblx0ICAgIHZhciBDX2FsZ28gPSBDLmFsZ287XG5cblx0ICAgIC8qKlxuXHQgICAgICogSE1BQyBhbGdvcml0aG0uXG5cdCAgICAgKi9cblx0ICAgIHZhciBITUFDID0gQ19hbGdvLkhNQUMgPSBCYXNlLmV4dGVuZCh7XG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogSW5pdGlhbGl6ZXMgYSBuZXdseSBjcmVhdGVkIEhNQUMuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge0hhc2hlcn0gaGFzaGVyIFRoZSBoYXNoIGFsZ29yaXRobSB0byB1c2UuXG5cdCAgICAgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBrZXkgVGhlIHNlY3JldCBrZXkuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciBobWFjSGFzaGVyID0gQ3J5cHRvSlMuYWxnby5ITUFDLmNyZWF0ZShDcnlwdG9KUy5hbGdvLlNIQTI1Niwga2V5KTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBpbml0OiBmdW5jdGlvbiAoaGFzaGVyLCBrZXkpIHtcblx0ICAgICAgICAgICAgLy8gSW5pdCBoYXNoZXJcblx0ICAgICAgICAgICAgaGFzaGVyID0gdGhpcy5faGFzaGVyID0gbmV3IGhhc2hlci5pbml0KCk7XG5cblx0ICAgICAgICAgICAgLy8gQ29udmVydCBzdHJpbmcgdG8gV29yZEFycmF5LCBlbHNlIGFzc3VtZSBXb3JkQXJyYXkgYWxyZWFkeVxuXHQgICAgICAgICAgICBpZiAodHlwZW9mIGtleSA9PSAnc3RyaW5nJykge1xuXHQgICAgICAgICAgICAgICAga2V5ID0gVXRmOC5wYXJzZShrZXkpO1xuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgIHZhciBoYXNoZXJCbG9ja1NpemUgPSBoYXNoZXIuYmxvY2tTaXplO1xuXHQgICAgICAgICAgICB2YXIgaGFzaGVyQmxvY2tTaXplQnl0ZXMgPSBoYXNoZXJCbG9ja1NpemUgKiA0O1xuXG5cdCAgICAgICAgICAgIC8vIEFsbG93IGFyYml0cmFyeSBsZW5ndGgga2V5c1xuXHQgICAgICAgICAgICBpZiAoa2V5LnNpZ0J5dGVzID4gaGFzaGVyQmxvY2tTaXplQnl0ZXMpIHtcblx0ICAgICAgICAgICAgICAgIGtleSA9IGhhc2hlci5maW5hbGl6ZShrZXkpO1xuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgLy8gQ2xhbXAgZXhjZXNzIGJpdHNcblx0ICAgICAgICAgICAga2V5LmNsYW1wKCk7XG5cblx0ICAgICAgICAgICAgLy8gQ2xvbmUga2V5IGZvciBpbm5lciBhbmQgb3V0ZXIgcGFkc1xuXHQgICAgICAgICAgICB2YXIgb0tleSA9IHRoaXMuX29LZXkgPSBrZXkuY2xvbmUoKTtcblx0ICAgICAgICAgICAgdmFyIGlLZXkgPSB0aGlzLl9pS2V5ID0ga2V5LmNsb25lKCk7XG5cblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgIHZhciBvS2V5V29yZHMgPSBvS2V5LndvcmRzO1xuXHQgICAgICAgICAgICB2YXIgaUtleVdvcmRzID0gaUtleS53b3JkcztcblxuXHQgICAgICAgICAgICAvLyBYT1Iga2V5cyB3aXRoIHBhZCBjb25zdGFudHNcblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBoYXNoZXJCbG9ja1NpemU7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgb0tleVdvcmRzW2ldIF49IDB4NWM1YzVjNWM7XG5cdCAgICAgICAgICAgICAgICBpS2V5V29yZHNbaV0gXj0gMHgzNjM2MzYzNjtcblx0ICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICBvS2V5LnNpZ0J5dGVzID0gaUtleS5zaWdCeXRlcyA9IGhhc2hlckJsb2NrU2l6ZUJ5dGVzO1xuXG5cdCAgICAgICAgICAgIC8vIFNldCBpbml0aWFsIHZhbHVlc1xuXHQgICAgICAgICAgICB0aGlzLnJlc2V0KCk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIFJlc2V0cyB0aGlzIEhNQUMgdG8gaXRzIGluaXRpYWwgc3RhdGUuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIGhtYWNIYXNoZXIucmVzZXQoKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICByZXNldDogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dFxuXHQgICAgICAgICAgICB2YXIgaGFzaGVyID0gdGhpcy5faGFzaGVyO1xuXG5cdCAgICAgICAgICAgIC8vIFJlc2V0XG5cdCAgICAgICAgICAgIGhhc2hlci5yZXNldCgpO1xuXHQgICAgICAgICAgICBoYXNoZXIudXBkYXRlKHRoaXMuX2lLZXkpO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBVcGRhdGVzIHRoaXMgSE1BQyB3aXRoIGEgbWVzc2FnZS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7V29yZEFycmF5fHN0cmluZ30gbWVzc2FnZVVwZGF0ZSBUaGUgbWVzc2FnZSB0byBhcHBlbmQuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtITUFDfSBUaGlzIEhNQUMgaW5zdGFuY2UuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIGhtYWNIYXNoZXIudXBkYXRlKCdtZXNzYWdlJyk7XG5cdCAgICAgICAgICogICAgIGhtYWNIYXNoZXIudXBkYXRlKHdvcmRBcnJheSk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgdXBkYXRlOiBmdW5jdGlvbiAobWVzc2FnZVVwZGF0ZSkge1xuXHQgICAgICAgICAgICB0aGlzLl9oYXNoZXIudXBkYXRlKG1lc3NhZ2VVcGRhdGUpO1xuXG5cdCAgICAgICAgICAgIC8vIENoYWluYWJsZVxuXHQgICAgICAgICAgICByZXR1cm4gdGhpcztcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogRmluYWxpemVzIHRoZSBITUFDIGNvbXB1dGF0aW9uLlxuXHQgICAgICAgICAqIE5vdGUgdGhhdCB0aGUgZmluYWxpemUgb3BlcmF0aW9uIGlzIGVmZmVjdGl2ZWx5IGEgZGVzdHJ1Y3RpdmUsIHJlYWQtb25jZSBvcGVyYXRpb24uXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge1dvcmRBcnJheXxzdHJpbmd9IG1lc3NhZ2VVcGRhdGUgKE9wdGlvbmFsKSBBIGZpbmFsIG1lc3NhZ2UgdXBkYXRlLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHJldHVybiB7V29yZEFycmF5fSBUaGUgSE1BQy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIGhtYWMgPSBobWFjSGFzaGVyLmZpbmFsaXplKCk7XG5cdCAgICAgICAgICogICAgIHZhciBobWFjID0gaG1hY0hhc2hlci5maW5hbGl6ZSgnbWVzc2FnZScpO1xuXHQgICAgICAgICAqICAgICB2YXIgaG1hYyA9IGhtYWNIYXNoZXIuZmluYWxpemUod29yZEFycmF5KTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBmaW5hbGl6ZTogZnVuY3Rpb24gKG1lc3NhZ2VVcGRhdGUpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRcblx0ICAgICAgICAgICAgdmFyIGhhc2hlciA9IHRoaXMuX2hhc2hlcjtcblxuXHQgICAgICAgICAgICAvLyBDb21wdXRlIEhNQUNcblx0ICAgICAgICAgICAgdmFyIGlubmVySGFzaCA9IGhhc2hlci5maW5hbGl6ZShtZXNzYWdlVXBkYXRlKTtcblx0ICAgICAgICAgICAgaGFzaGVyLnJlc2V0KCk7XG5cdCAgICAgICAgICAgIHZhciBobWFjID0gaGFzaGVyLmZpbmFsaXplKHRoaXMuX29LZXkuY2xvbmUoKS5jb25jYXQoaW5uZXJIYXNoKSk7XG5cblx0ICAgICAgICAgICAgcmV0dXJuIGhtYWM7XG5cdCAgICAgICAgfVxuXHQgICAgfSk7XG5cdH0oKSk7XG5cblxufSkpOyIsIjsoZnVuY3Rpb24gKHJvb3QsIGZhY3RvcnkpIHtcblx0aWYgKHR5cGVvZiBleHBvcnRzID09PSBcIm9iamVjdFwiKSB7XG5cdFx0Ly8gQ29tbW9uSlNcblx0XHRtb2R1bGUuZXhwb3J0cyA9IGV4cG9ydHMgPSBmYWN0b3J5KHJlcXVpcmUoXCIuL2NvcmVcIikpO1xuXHR9XG5cdGVsc2UgaWYgKHR5cGVvZiBkZWZpbmUgPT09IFwiZnVuY3Rpb25cIiAmJiBkZWZpbmUuYW1kKSB7XG5cdFx0Ly8gQU1EXG5cdFx0ZGVmaW5lKFtcIi4vY29yZVwiXSwgZmFjdG9yeSk7XG5cdH1cblx0ZWxzZSB7XG5cdFx0Ly8gR2xvYmFsIChicm93c2VyKVxuXHRcdGZhY3Rvcnkocm9vdC5DcnlwdG9KUyk7XG5cdH1cbn0odGhpcywgZnVuY3Rpb24gKENyeXB0b0pTKSB7XG5cblx0KGZ1bmN0aW9uIChNYXRoKSB7XG5cdCAgICAvLyBTaG9ydGN1dHNcblx0ICAgIHZhciBDID0gQ3J5cHRvSlM7XG5cdCAgICB2YXIgQ19saWIgPSBDLmxpYjtcblx0ICAgIHZhciBXb3JkQXJyYXkgPSBDX2xpYi5Xb3JkQXJyYXk7XG5cdCAgICB2YXIgSGFzaGVyID0gQ19saWIuSGFzaGVyO1xuXHQgICAgdmFyIENfYWxnbyA9IEMuYWxnbztcblxuXHQgICAgLy8gQ29uc3RhbnRzIHRhYmxlXG5cdCAgICB2YXIgVCA9IFtdO1xuXG5cdCAgICAvLyBDb21wdXRlIGNvbnN0YW50c1xuXHQgICAgKGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IDY0OyBpKyspIHtcblx0ICAgICAgICAgICAgVFtpXSA9IChNYXRoLmFicyhNYXRoLnNpbihpICsgMSkpICogMHgxMDAwMDAwMDApIHwgMDtcblx0ICAgICAgICB9XG5cdCAgICB9KCkpO1xuXG5cdCAgICAvKipcblx0ICAgICAqIE1ENSBoYXNoIGFsZ29yaXRobS5cblx0ICAgICAqL1xuXHQgICAgdmFyIE1ENSA9IENfYWxnby5NRDUgPSBIYXNoZXIuZXh0ZW5kKHtcblx0ICAgICAgICBfZG9SZXNldDogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICB0aGlzLl9oYXNoID0gbmV3IFdvcmRBcnJheS5pbml0KFtcblx0ICAgICAgICAgICAgICAgIDB4Njc0NTIzMDEsIDB4ZWZjZGFiODksXG5cdCAgICAgICAgICAgICAgICAweDk4YmFkY2ZlLCAweDEwMzI1NDc2XG5cdCAgICAgICAgICAgIF0pO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICBfZG9Qcm9jZXNzQmxvY2s6IGZ1bmN0aW9uIChNLCBvZmZzZXQpIHtcblx0ICAgICAgICAgICAgLy8gU3dhcCBlbmRpYW5cblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCAxNjsgaSsrKSB7XG5cdCAgICAgICAgICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICAgICAgICAgIHZhciBvZmZzZXRfaSA9IG9mZnNldCArIGk7XG5cdCAgICAgICAgICAgICAgICB2YXIgTV9vZmZzZXRfaSA9IE1bb2Zmc2V0X2ldO1xuXG5cdCAgICAgICAgICAgICAgICBNW29mZnNldF9pXSA9IChcblx0ICAgICAgICAgICAgICAgICAgICAoKChNX29mZnNldF9pIDw8IDgpICB8IChNX29mZnNldF9pID4+PiAyNCkpICYgMHgwMGZmMDBmZikgfFxuXHQgICAgICAgICAgICAgICAgICAgICgoKE1fb2Zmc2V0X2kgPDwgMjQpIHwgKE1fb2Zmc2V0X2kgPj4+IDgpKSAgJiAweGZmMDBmZjAwKVxuXHQgICAgICAgICAgICAgICAgKTtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICB2YXIgSCA9IHRoaXMuX2hhc2gud29yZHM7XG5cblx0ICAgICAgICAgICAgdmFyIE1fb2Zmc2V0XzAgID0gTVtvZmZzZXQgKyAwXTtcblx0ICAgICAgICAgICAgdmFyIE1fb2Zmc2V0XzEgID0gTVtvZmZzZXQgKyAxXTtcblx0ICAgICAgICAgICAgdmFyIE1fb2Zmc2V0XzIgID0gTVtvZmZzZXQgKyAyXTtcblx0ICAgICAgICAgICAgdmFyIE1fb2Zmc2V0XzMgID0gTVtvZmZzZXQgKyAzXTtcblx0ICAgICAgICAgICAgdmFyIE1fb2Zmc2V0XzQgID0gTVtvZmZzZXQgKyA0XTtcblx0ICAgICAgICAgICAgdmFyIE1fb2Zmc2V0XzUgID0gTVtvZmZzZXQgKyA1XTtcblx0ICAgICAgICAgICAgdmFyIE1fb2Zmc2V0XzYgID0gTVtvZmZzZXQgKyA2XTtcblx0ICAgICAgICAgICAgdmFyIE1fb2Zmc2V0XzcgID0gTVtvZmZzZXQgKyA3XTtcblx0ICAgICAgICAgICAgdmFyIE1fb2Zmc2V0XzggID0gTVtvZmZzZXQgKyA4XTtcblx0ICAgICAgICAgICAgdmFyIE1fb2Zmc2V0XzkgID0gTVtvZmZzZXQgKyA5XTtcblx0ICAgICAgICAgICAgdmFyIE1fb2Zmc2V0XzEwID0gTVtvZmZzZXQgKyAxMF07XG5cdCAgICAgICAgICAgIHZhciBNX29mZnNldF8xMSA9IE1bb2Zmc2V0ICsgMTFdO1xuXHQgICAgICAgICAgICB2YXIgTV9vZmZzZXRfMTIgPSBNW29mZnNldCArIDEyXTtcblx0ICAgICAgICAgICAgdmFyIE1fb2Zmc2V0XzEzID0gTVtvZmZzZXQgKyAxM107XG5cdCAgICAgICAgICAgIHZhciBNX29mZnNldF8xNCA9IE1bb2Zmc2V0ICsgMTRdO1xuXHQgICAgICAgICAgICB2YXIgTV9vZmZzZXRfMTUgPSBNW29mZnNldCArIDE1XTtcblxuXHQgICAgICAgICAgICAvLyBXb3JraW5nIHZhcmlhbGJlc1xuXHQgICAgICAgICAgICB2YXIgYSA9IEhbMF07XG5cdCAgICAgICAgICAgIHZhciBiID0gSFsxXTtcblx0ICAgICAgICAgICAgdmFyIGMgPSBIWzJdO1xuXHQgICAgICAgICAgICB2YXIgZCA9IEhbM107XG5cblx0ICAgICAgICAgICAgLy8gQ29tcHV0YXRpb25cblx0ICAgICAgICAgICAgYSA9IEZGKGEsIGIsIGMsIGQsIE1fb2Zmc2V0XzAsICA3LCAgVFswXSk7XG5cdCAgICAgICAgICAgIGQgPSBGRihkLCBhLCBiLCBjLCBNX29mZnNldF8xLCAgMTIsIFRbMV0pO1xuXHQgICAgICAgICAgICBjID0gRkYoYywgZCwgYSwgYiwgTV9vZmZzZXRfMiwgIDE3LCBUWzJdKTtcblx0ICAgICAgICAgICAgYiA9IEZGKGIsIGMsIGQsIGEsIE1fb2Zmc2V0XzMsICAyMiwgVFszXSk7XG5cdCAgICAgICAgICAgIGEgPSBGRihhLCBiLCBjLCBkLCBNX29mZnNldF80LCAgNywgIFRbNF0pO1xuXHQgICAgICAgICAgICBkID0gRkYoZCwgYSwgYiwgYywgTV9vZmZzZXRfNSwgIDEyLCBUWzVdKTtcblx0ICAgICAgICAgICAgYyA9IEZGKGMsIGQsIGEsIGIsIE1fb2Zmc2V0XzYsICAxNywgVFs2XSk7XG5cdCAgICAgICAgICAgIGIgPSBGRihiLCBjLCBkLCBhLCBNX29mZnNldF83LCAgMjIsIFRbN10pO1xuXHQgICAgICAgICAgICBhID0gRkYoYSwgYiwgYywgZCwgTV9vZmZzZXRfOCwgIDcsICBUWzhdKTtcblx0ICAgICAgICAgICAgZCA9IEZGKGQsIGEsIGIsIGMsIE1fb2Zmc2V0XzksICAxMiwgVFs5XSk7XG5cdCAgICAgICAgICAgIGMgPSBGRihjLCBkLCBhLCBiLCBNX29mZnNldF8xMCwgMTcsIFRbMTBdKTtcblx0ICAgICAgICAgICAgYiA9IEZGKGIsIGMsIGQsIGEsIE1fb2Zmc2V0XzExLCAyMiwgVFsxMV0pO1xuXHQgICAgICAgICAgICBhID0gRkYoYSwgYiwgYywgZCwgTV9vZmZzZXRfMTIsIDcsICBUWzEyXSk7XG5cdCAgICAgICAgICAgIGQgPSBGRihkLCBhLCBiLCBjLCBNX29mZnNldF8xMywgMTIsIFRbMTNdKTtcblx0ICAgICAgICAgICAgYyA9IEZGKGMsIGQsIGEsIGIsIE1fb2Zmc2V0XzE0LCAxNywgVFsxNF0pO1xuXHQgICAgICAgICAgICBiID0gRkYoYiwgYywgZCwgYSwgTV9vZmZzZXRfMTUsIDIyLCBUWzE1XSk7XG5cblx0ICAgICAgICAgICAgYSA9IEdHKGEsIGIsIGMsIGQsIE1fb2Zmc2V0XzEsICA1LCAgVFsxNl0pO1xuXHQgICAgICAgICAgICBkID0gR0coZCwgYSwgYiwgYywgTV9vZmZzZXRfNiwgIDksICBUWzE3XSk7XG5cdCAgICAgICAgICAgIGMgPSBHRyhjLCBkLCBhLCBiLCBNX29mZnNldF8xMSwgMTQsIFRbMThdKTtcblx0ICAgICAgICAgICAgYiA9IEdHKGIsIGMsIGQsIGEsIE1fb2Zmc2V0XzAsICAyMCwgVFsxOV0pO1xuXHQgICAgICAgICAgICBhID0gR0coYSwgYiwgYywgZCwgTV9vZmZzZXRfNSwgIDUsICBUWzIwXSk7XG5cdCAgICAgICAgICAgIGQgPSBHRyhkLCBhLCBiLCBjLCBNX29mZnNldF8xMCwgOSwgIFRbMjFdKTtcblx0ICAgICAgICAgICAgYyA9IEdHKGMsIGQsIGEsIGIsIE1fb2Zmc2V0XzE1LCAxNCwgVFsyMl0pO1xuXHQgICAgICAgICAgICBiID0gR0coYiwgYywgZCwgYSwgTV9vZmZzZXRfNCwgIDIwLCBUWzIzXSk7XG5cdCAgICAgICAgICAgIGEgPSBHRyhhLCBiLCBjLCBkLCBNX29mZnNldF85LCAgNSwgIFRbMjRdKTtcblx0ICAgICAgICAgICAgZCA9IEdHKGQsIGEsIGIsIGMsIE1fb2Zmc2V0XzE0LCA5LCAgVFsyNV0pO1xuXHQgICAgICAgICAgICBjID0gR0coYywgZCwgYSwgYiwgTV9vZmZzZXRfMywgIDE0LCBUWzI2XSk7XG5cdCAgICAgICAgICAgIGIgPSBHRyhiLCBjLCBkLCBhLCBNX29mZnNldF84LCAgMjAsIFRbMjddKTtcblx0ICAgICAgICAgICAgYSA9IEdHKGEsIGIsIGMsIGQsIE1fb2Zmc2V0XzEzLCA1LCAgVFsyOF0pO1xuXHQgICAgICAgICAgICBkID0gR0coZCwgYSwgYiwgYywgTV9vZmZzZXRfMiwgIDksICBUWzI5XSk7XG5cdCAgICAgICAgICAgIGMgPSBHRyhjLCBkLCBhLCBiLCBNX29mZnNldF83LCAgMTQsIFRbMzBdKTtcblx0ICAgICAgICAgICAgYiA9IEdHKGIsIGMsIGQsIGEsIE1fb2Zmc2V0XzEyLCAyMCwgVFszMV0pO1xuXG5cdCAgICAgICAgICAgIGEgPSBISChhLCBiLCBjLCBkLCBNX29mZnNldF81LCAgNCwgIFRbMzJdKTtcblx0ICAgICAgICAgICAgZCA9IEhIKGQsIGEsIGIsIGMsIE1fb2Zmc2V0XzgsICAxMSwgVFszM10pO1xuXHQgICAgICAgICAgICBjID0gSEgoYywgZCwgYSwgYiwgTV9vZmZzZXRfMTEsIDE2LCBUWzM0XSk7XG5cdCAgICAgICAgICAgIGIgPSBISChiLCBjLCBkLCBhLCBNX29mZnNldF8xNCwgMjMsIFRbMzVdKTtcblx0ICAgICAgICAgICAgYSA9IEhIKGEsIGIsIGMsIGQsIE1fb2Zmc2V0XzEsICA0LCAgVFszNl0pO1xuXHQgICAgICAgICAgICBkID0gSEgoZCwgYSwgYiwgYywgTV9vZmZzZXRfNCwgIDExLCBUWzM3XSk7XG5cdCAgICAgICAgICAgIGMgPSBISChjLCBkLCBhLCBiLCBNX29mZnNldF83LCAgMTYsIFRbMzhdKTtcblx0ICAgICAgICAgICAgYiA9IEhIKGIsIGMsIGQsIGEsIE1fb2Zmc2V0XzEwLCAyMywgVFszOV0pO1xuXHQgICAgICAgICAgICBhID0gSEgoYSwgYiwgYywgZCwgTV9vZmZzZXRfMTMsIDQsICBUWzQwXSk7XG5cdCAgICAgICAgICAgIGQgPSBISChkLCBhLCBiLCBjLCBNX29mZnNldF8wLCAgMTEsIFRbNDFdKTtcblx0ICAgICAgICAgICAgYyA9IEhIKGMsIGQsIGEsIGIsIE1fb2Zmc2V0XzMsICAxNiwgVFs0Ml0pO1xuXHQgICAgICAgICAgICBiID0gSEgoYiwgYywgZCwgYSwgTV9vZmZzZXRfNiwgIDIzLCBUWzQzXSk7XG5cdCAgICAgICAgICAgIGEgPSBISChhLCBiLCBjLCBkLCBNX29mZnNldF85LCAgNCwgIFRbNDRdKTtcblx0ICAgICAgICAgICAgZCA9IEhIKGQsIGEsIGIsIGMsIE1fb2Zmc2V0XzEyLCAxMSwgVFs0NV0pO1xuXHQgICAgICAgICAgICBjID0gSEgoYywgZCwgYSwgYiwgTV9vZmZzZXRfMTUsIDE2LCBUWzQ2XSk7XG5cdCAgICAgICAgICAgIGIgPSBISChiLCBjLCBkLCBhLCBNX29mZnNldF8yLCAgMjMsIFRbNDddKTtcblxuXHQgICAgICAgICAgICBhID0gSUkoYSwgYiwgYywgZCwgTV9vZmZzZXRfMCwgIDYsICBUWzQ4XSk7XG5cdCAgICAgICAgICAgIGQgPSBJSShkLCBhLCBiLCBjLCBNX29mZnNldF83LCAgMTAsIFRbNDldKTtcblx0ICAgICAgICAgICAgYyA9IElJKGMsIGQsIGEsIGIsIE1fb2Zmc2V0XzE0LCAxNSwgVFs1MF0pO1xuXHQgICAgICAgICAgICBiID0gSUkoYiwgYywgZCwgYSwgTV9vZmZzZXRfNSwgIDIxLCBUWzUxXSk7XG5cdCAgICAgICAgICAgIGEgPSBJSShhLCBiLCBjLCBkLCBNX29mZnNldF8xMiwgNiwgIFRbNTJdKTtcblx0ICAgICAgICAgICAgZCA9IElJKGQsIGEsIGIsIGMsIE1fb2Zmc2V0XzMsICAxMCwgVFs1M10pO1xuXHQgICAgICAgICAgICBjID0gSUkoYywgZCwgYSwgYiwgTV9vZmZzZXRfMTAsIDE1LCBUWzU0XSk7XG5cdCAgICAgICAgICAgIGIgPSBJSShiLCBjLCBkLCBhLCBNX29mZnNldF8xLCAgMjEsIFRbNTVdKTtcblx0ICAgICAgICAgICAgYSA9IElJKGEsIGIsIGMsIGQsIE1fb2Zmc2V0XzgsICA2LCAgVFs1Nl0pO1xuXHQgICAgICAgICAgICBkID0gSUkoZCwgYSwgYiwgYywgTV9vZmZzZXRfMTUsIDEwLCBUWzU3XSk7XG5cdCAgICAgICAgICAgIGMgPSBJSShjLCBkLCBhLCBiLCBNX29mZnNldF82LCAgMTUsIFRbNThdKTtcblx0ICAgICAgICAgICAgYiA9IElJKGIsIGMsIGQsIGEsIE1fb2Zmc2V0XzEzLCAyMSwgVFs1OV0pO1xuXHQgICAgICAgICAgICBhID0gSUkoYSwgYiwgYywgZCwgTV9vZmZzZXRfNCwgIDYsICBUWzYwXSk7XG5cdCAgICAgICAgICAgIGQgPSBJSShkLCBhLCBiLCBjLCBNX29mZnNldF8xMSwgMTAsIFRbNjFdKTtcblx0ICAgICAgICAgICAgYyA9IElJKGMsIGQsIGEsIGIsIE1fb2Zmc2V0XzIsICAxNSwgVFs2Ml0pO1xuXHQgICAgICAgICAgICBiID0gSUkoYiwgYywgZCwgYSwgTV9vZmZzZXRfOSwgIDIxLCBUWzYzXSk7XG5cblx0ICAgICAgICAgICAgLy8gSW50ZXJtZWRpYXRlIGhhc2ggdmFsdWVcblx0ICAgICAgICAgICAgSFswXSA9IChIWzBdICsgYSkgfCAwO1xuXHQgICAgICAgICAgICBIWzFdID0gKEhbMV0gKyBiKSB8IDA7XG5cdCAgICAgICAgICAgIEhbMl0gPSAoSFsyXSArIGMpIHwgMDtcblx0ICAgICAgICAgICAgSFszXSA9IChIWzNdICsgZCkgfCAwO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICBfZG9GaW5hbGl6ZTogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICAgICAgdmFyIGRhdGEgPSB0aGlzLl9kYXRhO1xuXHQgICAgICAgICAgICB2YXIgZGF0YVdvcmRzID0gZGF0YS53b3JkcztcblxuXHQgICAgICAgICAgICB2YXIgbkJpdHNUb3RhbCA9IHRoaXMuX25EYXRhQnl0ZXMgKiA4O1xuXHQgICAgICAgICAgICB2YXIgbkJpdHNMZWZ0ID0gZGF0YS5zaWdCeXRlcyAqIDg7XG5cblx0ICAgICAgICAgICAgLy8gQWRkIHBhZGRpbmdcblx0ICAgICAgICAgICAgZGF0YVdvcmRzW25CaXRzTGVmdCA+Pj4gNV0gfD0gMHg4MCA8PCAoMjQgLSBuQml0c0xlZnQgJSAzMik7XG5cblx0ICAgICAgICAgICAgdmFyIG5CaXRzVG90YWxIID0gTWF0aC5mbG9vcihuQml0c1RvdGFsIC8gMHgxMDAwMDAwMDApO1xuXHQgICAgICAgICAgICB2YXIgbkJpdHNUb3RhbEwgPSBuQml0c1RvdGFsO1xuXHQgICAgICAgICAgICBkYXRhV29yZHNbKCgobkJpdHNMZWZ0ICsgNjQpID4+PiA5KSA8PCA0KSArIDE1XSA9IChcblx0ICAgICAgICAgICAgICAgICgoKG5CaXRzVG90YWxIIDw8IDgpICB8IChuQml0c1RvdGFsSCA+Pj4gMjQpKSAmIDB4MDBmZjAwZmYpIHxcblx0ICAgICAgICAgICAgICAgICgoKG5CaXRzVG90YWxIIDw8IDI0KSB8IChuQml0c1RvdGFsSCA+Pj4gOCkpICAmIDB4ZmYwMGZmMDApXG5cdCAgICAgICAgICAgICk7XG5cdCAgICAgICAgICAgIGRhdGFXb3Jkc1soKChuQml0c0xlZnQgKyA2NCkgPj4+IDkpIDw8IDQpICsgMTRdID0gKFxuXHQgICAgICAgICAgICAgICAgKCgobkJpdHNUb3RhbEwgPDwgOCkgIHwgKG5CaXRzVG90YWxMID4+PiAyNCkpICYgMHgwMGZmMDBmZikgfFxuXHQgICAgICAgICAgICAgICAgKCgobkJpdHNUb3RhbEwgPDwgMjQpIHwgKG5CaXRzVG90YWxMID4+PiA4KSkgICYgMHhmZjAwZmYwMClcblx0ICAgICAgICAgICAgKTtcblxuXHQgICAgICAgICAgICBkYXRhLnNpZ0J5dGVzID0gKGRhdGFXb3Jkcy5sZW5ndGggKyAxKSAqIDQ7XG5cblx0ICAgICAgICAgICAgLy8gSGFzaCBmaW5hbCBibG9ja3Ncblx0ICAgICAgICAgICAgdGhpcy5fcHJvY2VzcygpO1xuXG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICB2YXIgaGFzaCA9IHRoaXMuX2hhc2g7XG5cdCAgICAgICAgICAgIHZhciBIID0gaGFzaC53b3JkcztcblxuXHQgICAgICAgICAgICAvLyBTd2FwIGVuZGlhblxuXHQgICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IDQ7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgLy8gU2hvcnRjdXRcblx0ICAgICAgICAgICAgICAgIHZhciBIX2kgPSBIW2ldO1xuXG5cdCAgICAgICAgICAgICAgICBIW2ldID0gKCgoSF9pIDw8IDgpICB8IChIX2kgPj4+IDI0KSkgJiAweDAwZmYwMGZmKSB8XG5cdCAgICAgICAgICAgICAgICAgICAgICAgKCgoSF9pIDw8IDI0KSB8IChIX2kgPj4+IDgpKSAgJiAweGZmMDBmZjAwKTtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIC8vIFJldHVybiBmaW5hbCBjb21wdXRlZCBoYXNoXG5cdCAgICAgICAgICAgIHJldHVybiBoYXNoO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICBjbG9uZTogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICB2YXIgY2xvbmUgPSBIYXNoZXIuY2xvbmUuY2FsbCh0aGlzKTtcblx0ICAgICAgICAgICAgY2xvbmUuX2hhc2ggPSB0aGlzLl9oYXNoLmNsb25lKCk7XG5cblx0ICAgICAgICAgICAgcmV0dXJuIGNsb25lO1xuXHQgICAgICAgIH1cblx0ICAgIH0pO1xuXG5cdCAgICBmdW5jdGlvbiBGRihhLCBiLCBjLCBkLCB4LCBzLCB0KSB7XG5cdCAgICAgICAgdmFyIG4gPSBhICsgKChiICYgYykgfCAofmIgJiBkKSkgKyB4ICsgdDtcblx0ICAgICAgICByZXR1cm4gKChuIDw8IHMpIHwgKG4gPj4+ICgzMiAtIHMpKSkgKyBiO1xuXHQgICAgfVxuXG5cdCAgICBmdW5jdGlvbiBHRyhhLCBiLCBjLCBkLCB4LCBzLCB0KSB7XG5cdCAgICAgICAgdmFyIG4gPSBhICsgKChiICYgZCkgfCAoYyAmIH5kKSkgKyB4ICsgdDtcblx0ICAgICAgICByZXR1cm4gKChuIDw8IHMpIHwgKG4gPj4+ICgzMiAtIHMpKSkgKyBiO1xuXHQgICAgfVxuXG5cdCAgICBmdW5jdGlvbiBISChhLCBiLCBjLCBkLCB4LCBzLCB0KSB7XG5cdCAgICAgICAgdmFyIG4gPSBhICsgKGIgXiBjIF4gZCkgKyB4ICsgdDtcblx0ICAgICAgICByZXR1cm4gKChuIDw8IHMpIHwgKG4gPj4+ICgzMiAtIHMpKSkgKyBiO1xuXHQgICAgfVxuXG5cdCAgICBmdW5jdGlvbiBJSShhLCBiLCBjLCBkLCB4LCBzLCB0KSB7XG5cdCAgICAgICAgdmFyIG4gPSBhICsgKGMgXiAoYiB8IH5kKSkgKyB4ICsgdDtcblx0ICAgICAgICByZXR1cm4gKChuIDw8IHMpIHwgKG4gPj4+ICgzMiAtIHMpKSkgKyBiO1xuXHQgICAgfVxuXG5cdCAgICAvKipcblx0ICAgICAqIFNob3J0Y3V0IGZ1bmN0aW9uIHRvIHRoZSBoYXNoZXIncyBvYmplY3QgaW50ZXJmYWNlLlxuXHQgICAgICpcblx0ICAgICAqIEBwYXJhbSB7V29yZEFycmF5fHN0cmluZ30gbWVzc2FnZSBUaGUgbWVzc2FnZSB0byBoYXNoLlxuXHQgICAgICpcblx0ICAgICAqIEByZXR1cm4ge1dvcmRBcnJheX0gVGhlIGhhc2guXG5cdCAgICAgKlxuXHQgICAgICogQHN0YXRpY1xuXHQgICAgICpcblx0ICAgICAqIEBleGFtcGxlXG5cdCAgICAgKlxuXHQgICAgICogICAgIHZhciBoYXNoID0gQ3J5cHRvSlMuTUQ1KCdtZXNzYWdlJyk7XG5cdCAgICAgKiAgICAgdmFyIGhhc2ggPSBDcnlwdG9KUy5NRDUod29yZEFycmF5KTtcblx0ICAgICAqL1xuXHQgICAgQy5NRDUgPSBIYXNoZXIuX2NyZWF0ZUhlbHBlcihNRDUpO1xuXG5cdCAgICAvKipcblx0ICAgICAqIFNob3J0Y3V0IGZ1bmN0aW9uIHRvIHRoZSBITUFDJ3Mgb2JqZWN0IGludGVyZmFjZS5cblx0ICAgICAqXG5cdCAgICAgKiBAcGFyYW0ge1dvcmRBcnJheXxzdHJpbmd9IG1lc3NhZ2UgVGhlIG1lc3NhZ2UgdG8gaGFzaC5cblx0ICAgICAqIEBwYXJhbSB7V29yZEFycmF5fHN0cmluZ30ga2V5IFRoZSBzZWNyZXQga2V5LlxuXHQgICAgICpcblx0ICAgICAqIEByZXR1cm4ge1dvcmRBcnJheX0gVGhlIEhNQUMuXG5cdCAgICAgKlxuXHQgICAgICogQHN0YXRpY1xuXHQgICAgICpcblx0ICAgICAqIEBleGFtcGxlXG5cdCAgICAgKlxuXHQgICAgICogICAgIHZhciBobWFjID0gQ3J5cHRvSlMuSG1hY01ENShtZXNzYWdlLCBrZXkpO1xuXHQgICAgICovXG5cdCAgICBDLkhtYWNNRDUgPSBIYXNoZXIuX2NyZWF0ZUhtYWNIZWxwZXIoTUQ1KTtcblx0fShNYXRoKSk7XG5cblxuXHRyZXR1cm4gQ3J5cHRvSlMuTUQ1O1xuXG59KSk7IiwiOyhmdW5jdGlvbiAocm9vdCwgZmFjdG9yeSwgdW5kZWYpIHtcblx0aWYgKHR5cGVvZiBleHBvcnRzID09PSBcIm9iamVjdFwiKSB7XG5cdFx0Ly8gQ29tbW9uSlNcblx0XHRtb2R1bGUuZXhwb3J0cyA9IGV4cG9ydHMgPSBmYWN0b3J5KHJlcXVpcmUoXCIuL2NvcmVcIiksIHJlcXVpcmUoXCIuL2NpcGhlci1jb3JlXCIpKTtcblx0fVxuXHRlbHNlIGlmICh0eXBlb2YgZGVmaW5lID09PSBcImZ1bmN0aW9uXCIgJiYgZGVmaW5lLmFtZCkge1xuXHRcdC8vIEFNRFxuXHRcdGRlZmluZShbXCIuL2NvcmVcIiwgXCIuL2NpcGhlci1jb3JlXCJdLCBmYWN0b3J5KTtcblx0fVxuXHRlbHNlIHtcblx0XHQvLyBHbG9iYWwgKGJyb3dzZXIpXG5cdFx0ZmFjdG9yeShyb290LkNyeXB0b0pTKTtcblx0fVxufSh0aGlzLCBmdW5jdGlvbiAoQ3J5cHRvSlMpIHtcblxuXHQvKipcblx0ICogQ291bnRlciBibG9jayBtb2RlLlxuXHQgKi9cblx0Q3J5cHRvSlMubW9kZS5DVFIgPSAoZnVuY3Rpb24gKCkge1xuXHQgICAgdmFyIENUUiA9IENyeXB0b0pTLmxpYi5CbG9ja0NpcGhlck1vZGUuZXh0ZW5kKCk7XG5cblx0ICAgIHZhciBFbmNyeXB0b3IgPSBDVFIuRW5jcnlwdG9yID0gQ1RSLmV4dGVuZCh7XG5cdCAgICAgICAgcHJvY2Vzc0Jsb2NrOiBmdW5jdGlvbiAod29yZHMsIG9mZnNldCkge1xuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICAgICAgdmFyIGNpcGhlciA9IHRoaXMuX2NpcGhlclxuXHQgICAgICAgICAgICB2YXIgYmxvY2tTaXplID0gY2lwaGVyLmJsb2NrU2l6ZTtcblx0ICAgICAgICAgICAgdmFyIGl2ID0gdGhpcy5faXY7XG5cdCAgICAgICAgICAgIHZhciBjb3VudGVyID0gdGhpcy5fY291bnRlcjtcblxuXHQgICAgICAgICAgICAvLyBHZW5lcmF0ZSBrZXlzdHJlYW1cblx0ICAgICAgICAgICAgaWYgKGl2KSB7XG5cdCAgICAgICAgICAgICAgICBjb3VudGVyID0gdGhpcy5fY291bnRlciA9IGl2LnNsaWNlKDApO1xuXG5cdCAgICAgICAgICAgICAgICAvLyBSZW1vdmUgSVYgZm9yIHN1YnNlcXVlbnQgYmxvY2tzXG5cdCAgICAgICAgICAgICAgICB0aGlzLl9pdiA9IHVuZGVmaW5lZDtcblx0ICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICB2YXIga2V5c3RyZWFtID0gY291bnRlci5zbGljZSgwKTtcblx0ICAgICAgICAgICAgY2lwaGVyLmVuY3J5cHRCbG9jayhrZXlzdHJlYW0sIDApO1xuXG5cdCAgICAgICAgICAgIC8vIEluY3JlbWVudCBjb3VudGVyXG5cdCAgICAgICAgICAgIGNvdW50ZXJbYmxvY2tTaXplIC0gMV0gPSAoY291bnRlcltibG9ja1NpemUgLSAxXSArIDEpIHwgMFxuXG5cdCAgICAgICAgICAgIC8vIEVuY3J5cHRcblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBibG9ja1NpemU7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgd29yZHNbb2Zmc2V0ICsgaV0gXj0ga2V5c3RyZWFtW2ldO1xuXHQgICAgICAgICAgICB9XG5cdCAgICAgICAgfVxuXHQgICAgfSk7XG5cblx0ICAgIENUUi5EZWNyeXB0b3IgPSBFbmNyeXB0b3I7XG5cblx0ICAgIHJldHVybiBDVFI7XG5cdH0oKSk7XG5cblxuXHRyZXR1cm4gQ3J5cHRvSlMubW9kZS5DVFI7XG5cbn0pKTsiLCI7KGZ1bmN0aW9uIChyb290LCBmYWN0b3J5KSB7XG5cdGlmICh0eXBlb2YgZXhwb3J0cyA9PT0gXCJvYmplY3RcIikge1xuXHRcdC8vIENvbW1vbkpTXG5cdFx0bW9kdWxlLmV4cG9ydHMgPSBleHBvcnRzID0gZmFjdG9yeShyZXF1aXJlKFwiLi9jb3JlXCIpKTtcblx0fVxuXHRlbHNlIGlmICh0eXBlb2YgZGVmaW5lID09PSBcImZ1bmN0aW9uXCIgJiYgZGVmaW5lLmFtZCkge1xuXHRcdC8vIEFNRFxuXHRcdGRlZmluZShbXCIuL2NvcmVcIl0sIGZhY3RvcnkpO1xuXHR9XG5cdGVsc2Uge1xuXHRcdC8vIEdsb2JhbCAoYnJvd3Nlcilcblx0XHRmYWN0b3J5KHJvb3QuQ3J5cHRvSlMpO1xuXHR9XG59KHRoaXMsIGZ1bmN0aW9uIChDcnlwdG9KUykge1xuXG5cdChmdW5jdGlvbiAoKSB7XG5cdCAgICAvLyBTaG9ydGN1dHNcblx0ICAgIHZhciBDID0gQ3J5cHRvSlM7XG5cdCAgICB2YXIgQ19saWIgPSBDLmxpYjtcblx0ICAgIHZhciBXb3JkQXJyYXkgPSBDX2xpYi5Xb3JkQXJyYXk7XG5cdCAgICB2YXIgSGFzaGVyID0gQ19saWIuSGFzaGVyO1xuXHQgICAgdmFyIENfYWxnbyA9IEMuYWxnbztcblxuXHQgICAgLy8gUmV1c2FibGUgb2JqZWN0XG5cdCAgICB2YXIgVyA9IFtdO1xuXG5cdCAgICAvKipcblx0ICAgICAqIFNIQS0xIGhhc2ggYWxnb3JpdGhtLlxuXHQgICAgICovXG5cdCAgICB2YXIgU0hBMSA9IENfYWxnby5TSEExID0gSGFzaGVyLmV4dGVuZCh7XG5cdCAgICAgICAgX2RvUmVzZXQ6IGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgdGhpcy5faGFzaCA9IG5ldyBXb3JkQXJyYXkuaW5pdChbXG5cdCAgICAgICAgICAgICAgICAweDY3NDUyMzAxLCAweGVmY2RhYjg5LFxuXHQgICAgICAgICAgICAgICAgMHg5OGJhZGNmZSwgMHgxMDMyNTQ3Nixcblx0ICAgICAgICAgICAgICAgIDB4YzNkMmUxZjBcblx0ICAgICAgICAgICAgXSk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIF9kb1Byb2Nlc3NCbG9jazogZnVuY3Rpb24gKE0sIG9mZnNldCkge1xuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dFxuXHQgICAgICAgICAgICB2YXIgSCA9IHRoaXMuX2hhc2gud29yZHM7XG5cblx0ICAgICAgICAgICAgLy8gV29ya2luZyB2YXJpYWJsZXNcblx0ICAgICAgICAgICAgdmFyIGEgPSBIWzBdO1xuXHQgICAgICAgICAgICB2YXIgYiA9IEhbMV07XG5cdCAgICAgICAgICAgIHZhciBjID0gSFsyXTtcblx0ICAgICAgICAgICAgdmFyIGQgPSBIWzNdO1xuXHQgICAgICAgICAgICB2YXIgZSA9IEhbNF07XG5cblx0ICAgICAgICAgICAgLy8gQ29tcHV0YXRpb25cblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCA4MDsgaSsrKSB7XG5cdCAgICAgICAgICAgICAgICBpZiAoaSA8IDE2KSB7XG5cdCAgICAgICAgICAgICAgICAgICAgV1tpXSA9IE1bb2Zmc2V0ICsgaV0gfCAwO1xuXHQgICAgICAgICAgICAgICAgfSBlbHNlIHtcblx0ICAgICAgICAgICAgICAgICAgICB2YXIgbiA9IFdbaSAtIDNdIF4gV1tpIC0gOF0gXiBXW2kgLSAxNF0gXiBXW2kgLSAxNl07XG5cdCAgICAgICAgICAgICAgICAgICAgV1tpXSA9IChuIDw8IDEpIHwgKG4gPj4+IDMxKTtcblx0ICAgICAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAgICAgdmFyIHQgPSAoKGEgPDwgNSkgfCAoYSA+Pj4gMjcpKSArIGUgKyBXW2ldO1xuXHQgICAgICAgICAgICAgICAgaWYgKGkgPCAyMCkge1xuXHQgICAgICAgICAgICAgICAgICAgIHQgKz0gKChiICYgYykgfCAofmIgJiBkKSkgKyAweDVhODI3OTk5O1xuXHQgICAgICAgICAgICAgICAgfSBlbHNlIGlmIChpIDwgNDApIHtcblx0ICAgICAgICAgICAgICAgICAgICB0ICs9IChiIF4gYyBeIGQpICsgMHg2ZWQ5ZWJhMTtcblx0ICAgICAgICAgICAgICAgIH0gZWxzZSBpZiAoaSA8IDYwKSB7XG5cdCAgICAgICAgICAgICAgICAgICAgdCArPSAoKGIgJiBjKSB8IChiICYgZCkgfCAoYyAmIGQpKSAtIDB4NzBlNDQzMjQ7XG5cdCAgICAgICAgICAgICAgICB9IGVsc2UgLyogaWYgKGkgPCA4MCkgKi8ge1xuXHQgICAgICAgICAgICAgICAgICAgIHQgKz0gKGIgXiBjIF4gZCkgLSAweDM1OWQzZTJhO1xuXHQgICAgICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgICAgICBlID0gZDtcblx0ICAgICAgICAgICAgICAgIGQgPSBjO1xuXHQgICAgICAgICAgICAgICAgYyA9IChiIDw8IDMwKSB8IChiID4+PiAyKTtcblx0ICAgICAgICAgICAgICAgIGIgPSBhO1xuXHQgICAgICAgICAgICAgICAgYSA9IHQ7XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAvLyBJbnRlcm1lZGlhdGUgaGFzaCB2YWx1ZVxuXHQgICAgICAgICAgICBIWzBdID0gKEhbMF0gKyBhKSB8IDA7XG5cdCAgICAgICAgICAgIEhbMV0gPSAoSFsxXSArIGIpIHwgMDtcblx0ICAgICAgICAgICAgSFsyXSA9IChIWzJdICsgYykgfCAwO1xuXHQgICAgICAgICAgICBIWzNdID0gKEhbM10gKyBkKSB8IDA7XG5cdCAgICAgICAgICAgIEhbNF0gPSAoSFs0XSArIGUpIHwgMDtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgX2RvRmluYWxpemU6IGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgIHZhciBkYXRhID0gdGhpcy5fZGF0YTtcblx0ICAgICAgICAgICAgdmFyIGRhdGFXb3JkcyA9IGRhdGEud29yZHM7XG5cblx0ICAgICAgICAgICAgdmFyIG5CaXRzVG90YWwgPSB0aGlzLl9uRGF0YUJ5dGVzICogODtcblx0ICAgICAgICAgICAgdmFyIG5CaXRzTGVmdCA9IGRhdGEuc2lnQnl0ZXMgKiA4O1xuXG5cdCAgICAgICAgICAgIC8vIEFkZCBwYWRkaW5nXG5cdCAgICAgICAgICAgIGRhdGFXb3Jkc1tuQml0c0xlZnQgPj4+IDVdIHw9IDB4ODAgPDwgKDI0IC0gbkJpdHNMZWZ0ICUgMzIpO1xuXHQgICAgICAgICAgICBkYXRhV29yZHNbKCgobkJpdHNMZWZ0ICsgNjQpID4+PiA5KSA8PCA0KSArIDE0XSA9IE1hdGguZmxvb3IobkJpdHNUb3RhbCAvIDB4MTAwMDAwMDAwKTtcblx0ICAgICAgICAgICAgZGF0YVdvcmRzWygoKG5CaXRzTGVmdCArIDY0KSA+Pj4gOSkgPDwgNCkgKyAxNV0gPSBuQml0c1RvdGFsO1xuXHQgICAgICAgICAgICBkYXRhLnNpZ0J5dGVzID0gZGF0YVdvcmRzLmxlbmd0aCAqIDQ7XG5cblx0ICAgICAgICAgICAgLy8gSGFzaCBmaW5hbCBibG9ja3Ncblx0ICAgICAgICAgICAgdGhpcy5fcHJvY2VzcygpO1xuXG5cdCAgICAgICAgICAgIC8vIFJldHVybiBmaW5hbCBjb21wdXRlZCBoYXNoXG5cdCAgICAgICAgICAgIHJldHVybiB0aGlzLl9oYXNoO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICBjbG9uZTogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICB2YXIgY2xvbmUgPSBIYXNoZXIuY2xvbmUuY2FsbCh0aGlzKTtcblx0ICAgICAgICAgICAgY2xvbmUuX2hhc2ggPSB0aGlzLl9oYXNoLmNsb25lKCk7XG5cblx0ICAgICAgICAgICAgcmV0dXJuIGNsb25lO1xuXHQgICAgICAgIH1cblx0ICAgIH0pO1xuXG5cdCAgICAvKipcblx0ICAgICAqIFNob3J0Y3V0IGZ1bmN0aW9uIHRvIHRoZSBoYXNoZXIncyBvYmplY3QgaW50ZXJmYWNlLlxuXHQgICAgICpcblx0ICAgICAqIEBwYXJhbSB7V29yZEFycmF5fHN0cmluZ30gbWVzc2FnZSBUaGUgbWVzc2FnZSB0byBoYXNoLlxuXHQgICAgICpcblx0ICAgICAqIEByZXR1cm4ge1dvcmRBcnJheX0gVGhlIGhhc2guXG5cdCAgICAgKlxuXHQgICAgICogQHN0YXRpY1xuXHQgICAgICpcblx0ICAgICAqIEBleGFtcGxlXG5cdCAgICAgKlxuXHQgICAgICogICAgIHZhciBoYXNoID0gQ3J5cHRvSlMuU0hBMSgnbWVzc2FnZScpO1xuXHQgICAgICogICAgIHZhciBoYXNoID0gQ3J5cHRvSlMuU0hBMSh3b3JkQXJyYXkpO1xuXHQgICAgICovXG5cdCAgICBDLlNIQTEgPSBIYXNoZXIuX2NyZWF0ZUhlbHBlcihTSEExKTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBTaG9ydGN1dCBmdW5jdGlvbiB0byB0aGUgSE1BQydzIG9iamVjdCBpbnRlcmZhY2UuXG5cdCAgICAgKlxuXHQgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBtZXNzYWdlIFRoZSBtZXNzYWdlIHRvIGhhc2guXG5cdCAgICAgKiBAcGFyYW0ge1dvcmRBcnJheXxzdHJpbmd9IGtleSBUaGUgc2VjcmV0IGtleS5cblx0ICAgICAqXG5cdCAgICAgKiBAcmV0dXJuIHtXb3JkQXJyYXl9IFRoZSBITUFDLlxuXHQgICAgICpcblx0ICAgICAqIEBzdGF0aWNcblx0ICAgICAqXG5cdCAgICAgKiBAZXhhbXBsZVxuXHQgICAgICpcblx0ICAgICAqICAgICB2YXIgaG1hYyA9IENyeXB0b0pTLkhtYWNTSEExKG1lc3NhZ2UsIGtleSk7XG5cdCAgICAgKi9cblx0ICAgIEMuSG1hY1NIQTEgPSBIYXNoZXIuX2NyZWF0ZUhtYWNIZWxwZXIoU0hBMSk7XG5cdH0oKSk7XG5cblxuXHRyZXR1cm4gQ3J5cHRvSlMuU0hBMTtcblxufSkpOyIsIjsoZnVuY3Rpb24gKHJvb3QsIGZhY3RvcnkpIHtcbiAgLy8gQ29tbW9uSlNcbiAgbW9kdWxlLmV4cG9ydHMgPSBleHBvcnRzID0gZmFjdG9yeShyZXF1aXJlKFwiY3J5cHRvLWpzL2NvcmVcIiksIHJlcXVpcmUoXCIuL2NvbW1vbi1iaXQtb3BzXCIpLCByZXF1aXJlKFwiLi9jb21tb25cIiksIHJlcXVpcmUoXCJjcnlwdG8tanMvYWVzXCIpKTtcbn0odGhpcywgZnVuY3Rpb24gKEMpIHtcblxuICAvKlxuICAgKiBUaGUgTUlUIExpY2Vuc2UgKE1JVClcbiAgICpcbiAgICogQ29weXJpZ2h0IChjKSAyMDE1IGFydGpvbWJcbiAgICovXG4gIC8vIFNob3J0Y3V0c1xuICB2YXIgQmFzZSA9IEMubGliLkJhc2U7XG4gIHZhciBXb3JkQXJyYXkgPSBDLmxpYi5Xb3JkQXJyYXk7XG4gIHZhciBBRVMgPSBDLmFsZ28uQUVTO1xuICB2YXIgZXh0ID0gQy5leHQ7XG4gIHZhciBPbmVaZXJvUGFkZGluZyA9IEMucGFkLk9uZVplcm9QYWRkaW5nO1xuXG5cbiAgdmFyIENNQUMgPSBDLmFsZ28uQ01BQyA9IEJhc2UuZXh0ZW5kKHtcbiAgICAgIC8qKlxuICAgICAgICogSW5pdGlhbGl6ZXMgYSBuZXdseSBjcmVhdGVkIENNQUNcbiAgICAgICAqXG4gICAgICAgKiBAcGFyYW0ge1dvcmRBcnJheX0ga2V5IFRoZSBzZWNyZXQga2V5XG4gICAgICAgKlxuICAgICAgICogQGV4YW1wbGVcbiAgICAgICAqXG4gICAgICAgKiAgICAgdmFyIGNtYWNlciA9IENyeXB0b0pTLmFsZ28uQ01BQy5jcmVhdGUoa2V5KTtcbiAgICAgICAqL1xuICAgICAgaW5pdDogZnVuY3Rpb24oa2V5KXtcbiAgICAgICAgICAvLyBnZW5lcmF0ZSBzdWIga2V5cy4uLlxuICAgICAgICAgIHRoaXMuX2FlcyA9IEFFUy5jcmVhdGVFbmNyeXB0b3Ioa2V5LCB7IGl2OiBuZXcgV29yZEFycmF5LmluaXQoKSwgcGFkZGluZzogQy5wYWQuTm9QYWRkaW5nIH0pO1xuXG4gICAgICAgICAgLy8gU3RlcCAxXG4gICAgICAgICAgdmFyIEwgPSB0aGlzLl9hZXMuZmluYWxpemUoZXh0LmNvbnN0X1plcm8pO1xuXG4gICAgICAgICAgLy8gU3RlcCAyXG4gICAgICAgICAgdmFyIEsxID0gTC5jbG9uZSgpO1xuICAgICAgICAgIGV4dC5kYmwoSzEpO1xuXG4gICAgICAgICAgLy8gU3RlcCAzXG4gICAgICAgICAgaWYgKCF0aGlzLl9pc1R3bykge1xuICAgICAgICAgICAgICB2YXIgSzIgPSBLMS5jbG9uZSgpO1xuICAgICAgICAgICAgICBleHQuZGJsKEsyKTtcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICB2YXIgSzIgPSBMLmNsb25lKCk7XG4gICAgICAgICAgICAgIGV4dC5pbnYoSzIpO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIHRoaXMuX0sxID0gSzE7XG4gICAgICAgICAgdGhpcy5fSzIgPSBLMjtcblxuICAgICAgICAgIHRoaXMuX2NvbnN0X0JzaXplID0gMTY7XG5cbiAgICAgICAgICB0aGlzLnJlc2V0KCk7XG4gICAgICB9LFxuXG4gICAgICByZXNldDogZnVuY3Rpb24gKCkge1xuICAgICAgICAgIHRoaXMuX3ggPSBleHQuY29uc3RfWmVyby5jbG9uZSgpO1xuICAgICAgICAgIHRoaXMuX2NvdW50ZXIgPSAwO1xuICAgICAgICAgIHRoaXMuX2J1ZmZlciA9IG5ldyBXb3JkQXJyYXkuaW5pdCgpO1xuICAgICAgfSxcblxuICAgICAgdXBkYXRlOiBmdW5jdGlvbiAobWVzc2FnZVVwZGF0ZSkge1xuICAgICAgICAgIGlmICghbWVzc2FnZVVwZGF0ZSkge1xuICAgICAgICAgICAgICByZXR1cm4gdGhpcztcbiAgICAgICAgICB9XG5cbiAgICAgICAgICAvLyBTaG9ydGN1dHNcbiAgICAgICAgICB2YXIgYnVmZmVyID0gdGhpcy5fYnVmZmVyO1xuICAgICAgICAgIHZhciBic2l6ZSA9IHRoaXMuX2NvbnN0X0JzaXplO1xuXG4gICAgICAgICAgaWYgKHR5cGVvZiBtZXNzYWdlVXBkYXRlID09PSBcInN0cmluZ1wiKSB7XG4gICAgICAgICAgICAgIG1lc3NhZ2VVcGRhdGUgPSBDLmVuYy5VdGY4LnBhcnNlKG1lc3NhZ2VVcGRhdGUpO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGJ1ZmZlci5jb25jYXQobWVzc2FnZVVwZGF0ZSk7XG5cbiAgICAgICAgICB3aGlsZShidWZmZXIuc2lnQnl0ZXMgPiBic2l6ZSl7XG4gICAgICAgICAgICAgIHZhciBNX2kgPSBleHQuc2hpZnRCeXRlcyhidWZmZXIsIGJzaXplKTtcbiAgICAgICAgICAgICAgZXh0Lnhvcih0aGlzLl94LCBNX2kpO1xuICAgICAgICAgICAgICB0aGlzLl94LmNsYW1wKCk7XG4gICAgICAgICAgICAgIHRoaXMuX2Flcy5yZXNldCgpO1xuICAgICAgICAgICAgICB0aGlzLl94ID0gdGhpcy5fYWVzLmZpbmFsaXplKHRoaXMuX3gpO1xuICAgICAgICAgICAgICB0aGlzLl9jb3VudGVyKys7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgLy8gQ2hhaW5hYmxlXG4gICAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgICB9LFxuXG4gICAgICBmaW5hbGl6ZTogZnVuY3Rpb24gKG1lc3NhZ2VVcGRhdGUpIHtcbiAgICAgICAgICB0aGlzLnVwZGF0ZShtZXNzYWdlVXBkYXRlKTtcblxuICAgICAgICAgIC8vIFNob3J0Y3V0c1xuICAgICAgICAgIHZhciBidWZmZXIgPSB0aGlzLl9idWZmZXI7XG4gICAgICAgICAgdmFyIGJzaXplID0gdGhpcy5fY29uc3RfQnNpemU7XG5cbiAgICAgICAgICB2YXIgTV9sYXN0ID0gYnVmZmVyLmNsb25lKCk7XG4gICAgICAgICAgaWYgKGJ1ZmZlci5zaWdCeXRlcyA9PT0gYnNpemUpIHtcbiAgICAgICAgICAgICAgZXh0LnhvcihNX2xhc3QsIHRoaXMuX0sxKTtcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICBPbmVaZXJvUGFkZGluZy5wYWQoTV9sYXN0LCBic2l6ZS80KTtcbiAgICAgICAgICAgICAgZXh0LnhvcihNX2xhc3QsIHRoaXMuX0syKTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBleHQueG9yKE1fbGFzdCwgdGhpcy5feCk7XG5cbiAgICAgICAgICB0aGlzLnJlc2V0KCk7IC8vIENhbiBiZSB1c2VkIGltbWVkaWF0ZWx5IGFmdGVyd2FyZHNcblxuICAgICAgICAgIHRoaXMuX2Flcy5yZXNldCgpO1xuICAgICAgICAgIHJldHVybiB0aGlzLl9hZXMuZmluYWxpemUoTV9sYXN0KTtcbiAgICAgIH0sXG5cbiAgICAgIF9pc1R3bzogZmFsc2VcbiAgfSk7XG5cbiAgLyoqXG4gICAqIERpcmVjdGx5IGludm9rZXMgdGhlIENNQUMgYW5kIHJldHVybnMgdGhlIGNhbGN1bGF0ZWQgTUFDLlxuICAgKlxuICAgKiBAcGFyYW0ge1dvcmRBcnJheX0ga2V5IFRoZSBrZXkgdG8gYmUgdXNlZCBmb3IgQ01BQ1xuICAgKiBAcGFyYW0ge1dvcmRBcnJheXxzdHJpbmd9IG1lc3NhZ2UgVGhlIGRhdGEgdG8gYmUgTUFDJ2VkIChlaXRoZXIgV29yZEFycmF5IG9yIFVURi04IGVuY29kZWQgc3RyaW5nKVxuICAgKlxuICAgKiBAcmV0dXJucyB7V29yZEFycmF5fSBNQUNcbiAgICovXG4gIEMuQ01BQyA9IGZ1bmN0aW9uKGtleSwgbWVzc2FnZSl7XG4gICAgICByZXR1cm4gQ01BQy5jcmVhdGUoa2V5KS5maW5hbGl6ZShtZXNzYWdlKTtcbiAgfTtcblxuICBDLmFsZ28uT01BQzEgPSBDTUFDO1xuICBDLmFsZ28uT01BQzIgPSBDTUFDLmV4dGVuZCh7XG4gICAgICBfaXNUd286IHRydWVcbiAgfSk7XG5cblxufSkpOyIsIjsoZnVuY3Rpb24gKHJvb3QsIGZhY3RvcnkpIHtcbiAgLy8gQ29tbW9uSlNcbiAgbW9kdWxlLmV4cG9ydHMgPSBleHBvcnRzID0gZmFjdG9yeShyZXF1aXJlKFwiY3J5cHRvLWpzL2NvcmVcIikpO1xufSh0aGlzLCBmdW5jdGlvbiAoQykge1xuXG4gIC8qXG4gICAqIFRoZSBNSVQgTGljZW5zZSAoTUlUKVxuICAgKlxuICAgKiBDb3B5cmlnaHQgKGMpIDIwMTUgYXJ0am9tYlxuICAgKi9cbiAgLy8gcHV0IG9uIGV4dCBwcm9wZXJ0eSBpbiBDcnlwdG9KU1xuICB2YXIgZXh0O1xuICBpZiAoIUMuaGFzT3duUHJvcGVydHkoXCJleHRcIikpIHtcbiAgICAgIGV4dCA9IEMuZXh0ID0ge307XG4gIH0gZWxzZSB7XG4gICAgICBleHQgPSBDLmV4dDtcbiAgfVxuXG4gIC8qKlxuICAgKiBTaGlmdHMgdGhlIGFycmF5IGJ5IG4gYml0cyB0byB0aGUgbGVmdC4gWmVybyBiaXRzIGFyZSBhZGRlZCBhcyB0aGVcbiAgICogbGVhc3Qgc2lnbmlmaWNhbnQgYml0cy4gVGhpcyBvcGVyYXRpb24gbW9kaWZpZXMgdGhlIGN1cnJlbnQgYXJyYXkuXG4gICAqXG4gICAqIEBwYXJhbSB7V29yZEFycmF5fSB3b3JkQXJyYXkgV29yZEFycmF5IHRvIHdvcmsgb25cbiAgICogQHBhcmFtIHtpbnR9IG4gQml0cyB0byBzaGlmdCBieVxuICAgKlxuICAgKiBAcmV0dXJucyB0aGUgV29yZEFycmF5IHRoYXQgd2FzIHBhc3NlZCBpblxuICAgKi9cbiAgZXh0LmJpdHNoaWZ0ID0gZnVuY3Rpb24od29yZEFycmF5LCBuKXtcbiAgICAgIHZhciBjYXJyeSA9IDAsXG4gICAgICAgICAgd29yZHMgPSB3b3JkQXJyYXkud29yZHMsXG4gICAgICAgICAgd3JlcyxcbiAgICAgICAgICBza2lwcGVkID0gMCxcbiAgICAgICAgICBjYXJyeU1hc2s7XG4gICAgICBpZiAobiA+IDApIHtcbiAgICAgICAgICB3aGlsZShuID4gMzEpIHtcbiAgICAgICAgICAgICAgLy8gZGVsZXRlIGZpcnN0IGVsZW1lbnQ6XG4gICAgICAgICAgICAgIHdvcmRzLnNwbGljZSgwLCAxKTtcblxuICAgICAgICAgICAgICAvLyBhZGQgYDBgIHdvcmQgdG8gdGhlIGJhY2tcbiAgICAgICAgICAgICAgd29yZHMucHVzaCgwKTtcblxuICAgICAgICAgICAgICBuIC09IDMyO1xuICAgICAgICAgICAgICBza2lwcGVkKys7XG4gICAgICAgICAgfVxuICAgICAgICAgIGlmIChuID09IDApIHtcbiAgICAgICAgICAgICAgLy8gMS4gbm90aGluZyB0byBzaGlmdCBpZiB0aGUgc2hpZnQgYW1vdW50IGlzIG9uIGEgd29yZCBib3VuZGFyeVxuICAgICAgICAgICAgICAvLyAyLiBUaGlzIGhhcyB0byBiZSBkb25lLCBiZWNhdXNlIHRoZSBmb2xsb3dpbmcgYWxnb3JpdGhtIGNvbXB1dGVzXG4gICAgICAgICAgICAgIC8vIHdyb25nIHZhbHVlcyBvbmx5IGZvciBuPT0wXG4gICAgICAgICAgICAgIHJldHVybiBjYXJyeTtcbiAgICAgICAgICB9XG4gICAgICAgICAgZm9yKHZhciBpID0gd29yZHMubGVuZ3RoIC0gc2tpcHBlZCAtIDE7IGkgPj0gMDsgaS0tKSB7XG4gICAgICAgICAgICAgIHdyZXMgPSB3b3Jkc1tpXTtcbiAgICAgICAgICAgICAgd29yZHNbaV0gPDw9IG47XG4gICAgICAgICAgICAgIHdvcmRzW2ldIHw9IGNhcnJ5O1xuICAgICAgICAgICAgICBjYXJyeSA9IHdyZXMgPj4+ICgzMiAtIG4pO1xuICAgICAgICAgIH1cbiAgICAgIH0gZWxzZSBpZiAobiA8IDApIHtcbiAgICAgICAgICB3aGlsZShuIDwgLTMxKSB7XG4gICAgICAgICAgICAgIC8vIGluc2VydCBgMGAgd29yZCB0byB0aGUgZnJvbnQ6XG4gICAgICAgICAgICAgIHdvcmRzLnNwbGljZSgwLCAwLCAwKTtcblxuICAgICAgICAgICAgICAvLyByZW1vdmUgbGFzdCBlbGVtZW50OlxuICAgICAgICAgICAgICB3b3Jkcy5sZW5ndGgtLTtcblxuICAgICAgICAgICAgICBuICs9IDMyO1xuICAgICAgICAgICAgICBza2lwcGVkKys7XG4gICAgICAgICAgfVxuICAgICAgICAgIGlmIChuID09IDApIHtcbiAgICAgICAgICAgICAgLy8gbm90aGluZyB0byBzaGlmdCBpZiB0aGUgc2hpZnQgYW1vdW50IGlzIG9uIGEgd29yZCBib3VuZGFyeVxuICAgICAgICAgICAgICByZXR1cm4gY2Fycnk7XG4gICAgICAgICAgfVxuICAgICAgICAgIG4gPSAtbjtcbiAgICAgICAgICBjYXJyeU1hc2sgPSAoMSA8PCBuKSAtIDE7XG4gICAgICAgICAgZm9yKHZhciBpID0gc2tpcHBlZDsgaSA8IHdvcmRzLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICAgIHdyZXMgPSB3b3Jkc1tpXSAmIGNhcnJ5TWFzaztcbiAgICAgICAgICAgICAgd29yZHNbaV0gPj4+PSBuO1xuICAgICAgICAgICAgICB3b3Jkc1tpXSB8PSBjYXJyeTtcbiAgICAgICAgICAgICAgY2FycnkgPSB3cmVzIDw8ICgzMiAtIG4pO1xuICAgICAgICAgIH1cbiAgICAgIH1cbiAgICAgIHJldHVybiBjYXJyeTtcbiAgfTtcblxuICAvKipcbiAgICogTmVnYXRlcyBhbGwgYml0cyBpbiB0aGUgV29yZEFycmF5LiBUaGlzIG1hbmlwdWxhdGVzIHRoZSBnaXZlbiBhcnJheS5cbiAgICpcbiAgICogQHBhcmFtIHtXb3JkQXJyYXl9IHdvcmRBcnJheSBXb3JkQXJyYXkgdG8gd29yayBvblxuICAgKlxuICAgKiBAcmV0dXJucyB0aGUgV29yZEFycmF5IHRoYXQgd2FzIHBhc3NlZCBpblxuICAgKi9cbiAgZXh0Lm5lZyA9IGZ1bmN0aW9uKHdvcmRBcnJheSl7XG4gICAgICB2YXIgd29yZHMgPSB3b3JkQXJyYXkud29yZHM7XG4gICAgICBmb3IodmFyIGkgPSAwOyBpIDwgd29yZHMubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgICB3b3Jkc1tpXSA9IH53b3Jkc1tpXTtcbiAgICAgIH1cbiAgICAgIHJldHVybiB3b3JkQXJyYXk7XG4gIH07XG5cbiAgLyoqXG4gICAqIEFwcGxpZXMgWE9SIG9uIGJvdGggZ2l2ZW4gd29yZCBhcnJheXMgYW5kIHJldHVybnMgYSB0aGlyZCByZXN1bHRpbmdcbiAgICogV29yZEFycmF5LiBUaGUgaW5pdGlhbCB3b3JkIGFycmF5cyBtdXN0IGhhdmUgdGhlIHNhbWUgbGVuZ3RoXG4gICAqIChzaWduaWZpY2FudCBieXRlcykuXG4gICAqXG4gICAqIEBwYXJhbSB7V29yZEFycmF5fSB3b3JkQXJyYXkxIFdvcmRBcnJheVxuICAgKiBAcGFyYW0ge1dvcmRBcnJheX0gd29yZEFycmF5MiBXb3JkQXJyYXlcbiAgICpcbiAgICogQHJldHVybnMgZmlyc3QgcGFzc2VkIFdvcmRBcnJheSAobW9kaWZpZWQpXG4gICAqL1xuICBleHQueG9yID0gZnVuY3Rpb24od29yZEFycmF5MSwgd29yZEFycmF5Mil7XG4gICAgICBmb3IodmFyIGkgPSAwOyBpIDwgd29yZEFycmF5MS53b3Jkcy5sZW5ndGg7IGkrKykge1xuICAgICAgICAgIHdvcmRBcnJheTEud29yZHNbaV0gXj0gd29yZEFycmF5Mi53b3Jkc1tpXTtcbiAgICAgIH1cbiAgICAgIHJldHVybiB3b3JkQXJyYXkxO1xuICB9O1xuXG4gIC8qKlxuICAgKiBMb2dpY2FsIEFORCBiZXR3ZWVuIHRoZSB0d28gcGFzc2VkIGFycmF5cy4gQm90aCBhcnJheXMgbXVzdCBoYXZlIHRoZVxuICAgKiBzYW1lIGxlbmd0aC5cbiAgICpcbiAgICogQHBhcmFtIHtXb3JkQXJyYXl9IGFycjEgQXJyYXkgMVxuICAgKiBAcGFyYW0ge1dvcmRBcnJheX0gYXJyMiBBcnJheSAyXG4gICAqXG4gICAqIEByZXR1cm5zIG5ldyBXb3JkQXJyYXlcbiAgICovXG4gIGV4dC5iaXRhbmQgPSBmdW5jdGlvbihhcnIxLCBhcnIyKXtcbiAgICAgIHZhciBuZXdBcnIgPSBhcnIxLmNsb25lKCksXG4gICAgICAgICAgdHcgPSBuZXdBcnIud29yZHMsXG4gICAgICAgICAgb3cgPSBhcnIyLndvcmRzO1xuICAgICAgZm9yKHZhciBpID0gMDsgaSA8IHR3Lmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgdHdbaV0gJj0gb3dbaV07XG4gICAgICB9XG4gICAgICByZXR1cm4gbmV3QXJyO1xuICB9O1xuXG5cbn0pKTsiLCI7KGZ1bmN0aW9uIChyb290LCBmYWN0b3J5KSB7XG4gIC8vIENvbW1vbkpTXG4gIG1vZHVsZS5leHBvcnRzID0gZXhwb3J0cyA9IGZhY3RvcnkocmVxdWlyZShcImNyeXB0by1qcy9jb3JlXCIpLCByZXF1aXJlKFwiLi9jb21tb24tYml0LW9wc1wiKSwgcmVxdWlyZShcImNyeXB0by1qcy9jaXBoZXItY29yZVwiKSk7XG59KHRoaXMsIGZ1bmN0aW9uIChDKSB7XG5cbiAgLypcbiAgICogVGhlIE1JVCBMaWNlbnNlIChNSVQpXG4gICAqXG4gICAqIENvcHlyaWdodCAoYykgMjAxNSBhcnRqb21iXG4gICAqL1xuICAvLyBwdXQgb24gZXh0IHByb3BlcnR5IGluIENyeXB0b0pTXG4gIHZhciBleHQ7XG4gIGlmICghQy5oYXNPd25Qcm9wZXJ0eShcImV4dFwiKSkge1xuICAgICAgZXh0ID0gQy5leHQgPSB7fTtcbiAgfSBlbHNlIHtcbiAgICAgIGV4dCA9IEMuZXh0O1xuICB9XG5cbiAgLy8gU2hvcnRjdXRzXG4gIHZhciBCYXNlID0gQy5saWIuQmFzZTtcbiAgdmFyIFdvcmRBcnJheSA9IEMubGliLldvcmRBcnJheTtcblxuICAvLyBDb25zdGFudHNcbiAgZXh0LmNvbnN0X1plcm8gPSBuZXcgV29yZEFycmF5LmluaXQoWzB4MDAwMDAwMDAsIDB4MDAwMDAwMDAsIDB4MDAwMDAwMDAsIDB4MDAwMDAwMDBdKTtcbiAgZXh0LmNvbnN0X09uZSA9IG5ldyBXb3JkQXJyYXkuaW5pdChbMHgwMDAwMDAwMCwgMHgwMDAwMDAwMCwgMHgwMDAwMDAwMCwgMHgwMDAwMDAwMV0pO1xuICBleHQuY29uc3RfUmIgPSBuZXcgV29yZEFycmF5LmluaXQoWzB4MDAwMDAwMDAsIDB4MDAwMDAwMDAsIDB4MDAwMDAwMDAsIDB4MDAwMDAwODddKTsgLy8gMDAuLjAwMTAwMDAxMTFcbiAgZXh0LmNvbnN0X1JiX1NoaWZ0ZWQgPSBuZXcgV29yZEFycmF5LmluaXQoWzB4ODAwMDAwMDAsIDB4MDAwMDAwMDAsIDB4MDAwMDAwMDAsIDB4MDAwMDAwNDNdKTsgLy8gMTAwLi4wMDEwMDAwMTFcbiAgZXh0LmNvbnN0X25vbk1TQiA9IG5ldyBXb3JkQXJyYXkuaW5pdChbMHhGRkZGRkZGRiwgMHhGRkZGRkZGRiwgMHg3RkZGRkZGRiwgMHg3RkZGRkZGRl0pOyAvLyAxXjY0IHx8IDBeMSB8fCAxXjMxIHx8IDBeMSB8fCAxXjMxXG5cbiAgLyoqXG4gICAqIExvb2tzIGludG8gdGhlIG9iamVjdCB0byBzZWUgaWYgaXQgaXMgYSBXb3JkQXJyYXkuXG4gICAqXG4gICAqIEBwYXJhbSBvYmogU29tZSBvYmplY3RcbiAgICpcbiAgICogQHJldHVybnMge2Jvb2xlYW59XG5cbiAgICovXG4gIGV4dC5pc1dvcmRBcnJheSA9IGZ1bmN0aW9uKG9iaikge1xuICAgICAgcmV0dXJuIG9iaiAmJiB0eXBlb2Ygb2JqLmNsYW1wID09PSBcImZ1bmN0aW9uXCIgJiYgdHlwZW9mIG9iai5jb25jYXQgPT09IFwiZnVuY3Rpb25cIiAmJiB0eXBlb2Ygb2JqLndvcmRzID09PSBcImFycmF5XCI7XG4gIH1cblxuICAvKipcbiAgICogVGhpcyBwYWRkaW5nIGlzIGEgMSBiaXQgZm9sbG93ZWQgYnkgYXMgbWFueSAwIGJpdHMgYXMgbmVlZGVkIHRvIGZpbGxcbiAgICogdXAgdGhlIGJsb2NrLiBUaGlzIGltcGxlbWVudGF0aW9uIGRvZXNuJ3Qgd29yayBvbiBiaXRzIGRpcmVjdGx5LFxuICAgKiBidXQgb24gYnl0ZXMuIFRoZXJlZm9yZSB0aGUgZ3JhbnVsYXJpdHkgaXMgbXVjaCBiaWdnZXIuXG4gICAqL1xuICBDLnBhZC5PbmVaZXJvUGFkZGluZyA9IHtcbiAgICAgIHBhZDogZnVuY3Rpb24gKGRhdGEsIGJsb2Nrc2l6ZSkge1xuICAgICAgICAgIC8vIFNob3J0Y3V0XG4gICAgICAgICAgdmFyIGJsb2NrU2l6ZUJ5dGVzID0gYmxvY2tzaXplICogNDtcblxuICAgICAgICAgIC8vIENvdW50IHBhZGRpbmcgYnl0ZXNcbiAgICAgICAgICB2YXIgblBhZGRpbmdCeXRlcyA9IGJsb2NrU2l6ZUJ5dGVzIC0gZGF0YS5zaWdCeXRlcyAlIGJsb2NrU2l6ZUJ5dGVzO1xuXG4gICAgICAgICAgLy8gQ3JlYXRlIHBhZGRpbmdcbiAgICAgICAgICB2YXIgcGFkZGluZ1dvcmRzID0gW107XG4gICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBuUGFkZGluZ0J5dGVzOyBpICs9IDQpIHtcbiAgICAgICAgICAgICAgdmFyIHBhZGRpbmdXb3JkID0gMHgwMDAwMDAwMDtcbiAgICAgICAgICAgICAgaWYgKGkgPT09IDApIHtcbiAgICAgICAgICAgICAgICAgIHBhZGRpbmdXb3JkID0gMHg4MDAwMDAwMDtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICBwYWRkaW5nV29yZHMucHVzaChwYWRkaW5nV29yZCk7XG4gICAgICAgICAgfVxuICAgICAgICAgIHZhciBwYWRkaW5nID0gbmV3IFdvcmRBcnJheS5pbml0KHBhZGRpbmdXb3JkcywgblBhZGRpbmdCeXRlcyk7XG5cbiAgICAgICAgICAvLyBBZGQgcGFkZGluZ1xuICAgICAgICAgIGRhdGEuY29uY2F0KHBhZGRpbmcpO1xuICAgICAgfSxcbiAgICAgIHVucGFkOiBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgLy8gVE9ETzogaW1wbGVtZW50XG4gICAgICB9XG4gIH07XG5cbiAgLyoqXG4gICAqIE5vIHBhZGRpbmcgaXMgYXBwbGllZC4gVGhpcyBpcyBuZWNlc3NhcnkgZm9yIHN0cmVhbWluZyBjaXBoZXIgbW9kZXNcbiAgICogbGlrZSBDVFIuXG4gICAqL1xuICBDLnBhZC5Ob1BhZGRpbmcgPSB7XG4gICAgICBwYWQ6IGZ1bmN0aW9uICgpIHt9LFxuICAgICAgdW5wYWQ6IGZ1bmN0aW9uICgpIHt9XG4gIH07XG5cbiAgLyoqXG4gICAqIFJldHVybnMgdGhlIG4gbGVmdG1vc3QgYnl0ZXMgb2YgdGhlIFdvcmRBcnJheS5cbiAgICpcbiAgICogQHBhcmFtIHtXb3JkQXJyYXl9IHdvcmRBcnJheSBXb3JkQXJyYXkgdG8gd29yayBvblxuICAgKiBAcGFyYW0ge2ludH0gbiBCeXRlcyB0byByZXRyaWV2ZVxuICAgKlxuICAgKiBAcmV0dXJucyBuZXcgV29yZEFycmF5XG4gICAqL1xuICBleHQubGVmdG1vc3RCeXRlcyA9IGZ1bmN0aW9uKHdvcmRBcnJheSwgbil7XG4gICAgICB2YXIgbG1BcnJheSA9IHdvcmRBcnJheS5jbG9uZSgpO1xuICAgICAgbG1BcnJheS5zaWdCeXRlcyA9IG47XG4gICAgICBsbUFycmF5LmNsYW1wKCk7XG4gICAgICByZXR1cm4gbG1BcnJheTtcbiAgfTtcblxuICAvKipcbiAgICogUmV0dXJucyB0aGUgbiByaWdodG1vc3QgYnl0ZXMgb2YgdGhlIFdvcmRBcnJheS5cbiAgICpcbiAgICogQHBhcmFtIHtXb3JkQXJyYXl9IHdvcmRBcnJheSBXb3JkQXJyYXkgdG8gd29yayBvblxuICAgKiBAcGFyYW0ge2ludH0gbiBCeXRlcyB0byByZXRyaWV2ZSAobXVzdCBiZSBwb3NpdGl2ZSlcbiAgICpcbiAgICogQHJldHVybnMgbmV3IFdvcmRBcnJheVxuICAgKi9cbiAgZXh0LnJpZ2h0bW9zdEJ5dGVzID0gZnVuY3Rpb24od29yZEFycmF5LCBuKXtcbiAgICAgIHdvcmRBcnJheS5jbGFtcCgpO1xuICAgICAgdmFyIHdvcmRTaXplID0gMzI7XG4gICAgICB2YXIgcm1BcnJheSA9IHdvcmRBcnJheS5jbG9uZSgpO1xuICAgICAgdmFyIGJpdHNUb1NoaWZ0ID0gKHJtQXJyYXkuc2lnQnl0ZXMgLSBuKSAqIDg7XG4gICAgICBpZiAoYml0c1RvU2hpZnQgPj0gd29yZFNpemUpIHtcbiAgICAgICAgICB2YXIgcG9wQ291bnQgPSBNYXRoLmZsb29yKGJpdHNUb1NoaWZ0L3dvcmRTaXplKTtcbiAgICAgICAgICBiaXRzVG9TaGlmdCAtPSBwb3BDb3VudCAqIHdvcmRTaXplO1xuICAgICAgICAgIHJtQXJyYXkud29yZHMuc3BsaWNlKDAsIHBvcENvdW50KTtcbiAgICAgICAgICBybUFycmF5LnNpZ0J5dGVzIC09IHBvcENvdW50ICogd29yZFNpemUgLyA4O1xuICAgICAgfVxuICAgICAgaWYgKGJpdHNUb1NoaWZ0ID4gMCkge1xuICAgICAgICAgIGV4dC5iaXRzaGlmdChybUFycmF5LCBiaXRzVG9TaGlmdCk7XG4gICAgICAgICAgcm1BcnJheS5zaWdCeXRlcyAtPSBiaXRzVG9TaGlmdCAvIDg7XG4gICAgICB9XG4gICAgICByZXR1cm4gcm1BcnJheTtcbiAgfTtcblxuICAvKipcbiAgICogUmV0dXJucyB0aGUgbiByaWdodG1vc3Qgd29yZHMgb2YgdGhlIFdvcmRBcnJheS4gSXQgYXNzdW1lc1xuICAgKiB0aGF0IHRoZSBjdXJyZW50IFdvcmRBcnJheSBoYXMgYXQgbGVhc3QgbiB3b3Jkcy5cbiAgICpcbiAgICogQHBhcmFtIHtXb3JkQXJyYXl9IHdvcmRBcnJheSBXb3JkQXJyYXkgdG8gd29yayBvblxuICAgKiBAcGFyYW0ge2ludH0gbiBXb3JkcyB0byByZXRyaWV2ZSAobXVzdCBiZSBwb3NpdGl2ZSlcbiAgICpcbiAgICogQHJldHVybnMgcG9wcGVkIHdvcmRzIGFzIG5ldyBXb3JkQXJyYXlcbiAgICovXG4gIGV4dC5wb3BXb3JkcyA9IGZ1bmN0aW9uKHdvcmRBcnJheSwgbil7XG4gICAgICB2YXIgbGVmdCA9IHdvcmRBcnJheS53b3Jkcy5zcGxpY2UoMCwgbik7XG4gICAgICB3b3JkQXJyYXkuc2lnQnl0ZXMgLT0gbiAqIDQ7XG4gICAgICByZXR1cm4gbmV3IFdvcmRBcnJheS5pbml0KGxlZnQpO1xuICB9O1xuXG4gIC8qKlxuICAgKiBTaGlmdHMgdGhlIGFycmF5IHRvIHRoZSBsZWZ0IGFuZCByZXR1cm5zIHRoZSBzaGlmdGVkIGRyb3BwZWQgZWxlbWVudHNcbiAgICogYXMgV29yZEFycmF5LiBUaGUgaW5pdGlhbCBXb3JkQXJyYXkgbXVzdCBjb250YWluIGF0IGxlYXN0IG4gYnl0ZXMgYW5kXG4gICAqIHRoZXkgaGF2ZSB0byBiZSBzaWduaWZpY2FudC5cbiAgICpcbiAgICogQHBhcmFtIHtXb3JkQXJyYXl9IHdvcmRBcnJheSBXb3JkQXJyYXkgdG8gd29yayBvbiAoaXMgbW9kaWZpZWQpXG4gICAqIEBwYXJhbSB7aW50fSBuIEJ5dGVzIHRvIHNoaWZ0IChtdXN0IGJlIHBvc2l0aXZlLCBkZWZhdWx0IDE2KVxuICAgKlxuICAgKiBAcmV0dXJucyBuZXcgV29yZEFycmF5XG4gICAqL1xuICBleHQuc2hpZnRCeXRlcyA9IGZ1bmN0aW9uKHdvcmRBcnJheSwgbil7XG4gICAgICBuID0gbiB8fCAxNjtcbiAgICAgIHZhciByID0gbiAlIDQ7XG4gICAgICBuIC09IHI7XG5cbiAgICAgIHZhciBzaGlmdGVkQXJyYXkgPSBuZXcgV29yZEFycmF5LmluaXQoKTtcbiAgICAgIGZvcih2YXIgaSA9IDA7IGkgPCBuOyBpICs9IDQpIHtcbiAgICAgICAgICBzaGlmdGVkQXJyYXkud29yZHMucHVzaCh3b3JkQXJyYXkud29yZHMuc2hpZnQoKSk7XG4gICAgICAgICAgd29yZEFycmF5LnNpZ0J5dGVzIC09IDQ7XG4gICAgICAgICAgc2hpZnRlZEFycmF5LnNpZ0J5dGVzICs9IDQ7XG4gICAgICB9XG4gICAgICBpZiAociA+IDApIHtcbiAgICAgICAgICBzaGlmdGVkQXJyYXkud29yZHMucHVzaCh3b3JkQXJyYXkud29yZHNbMF0pO1xuICAgICAgICAgIHNoaWZ0ZWRBcnJheS5zaWdCeXRlcyArPSByO1xuXG4gICAgICAgICAgZXh0LmJpdHNoaWZ0KHdvcmRBcnJheSwgciAqIDgpO1xuICAgICAgICAgIHdvcmRBcnJheS5zaWdCeXRlcyAtPSByO1xuICAgICAgfVxuICAgICAgcmV0dXJuIHNoaWZ0ZWRBcnJheTtcbiAgfTtcblxuICAvKipcbiAgICogWE9ScyBhcnIyIHRvIHRoZSBlbmQgb2YgYXJyMSBhcnJheS4gVGhpcyBkb2Vzbid0IG1vZGlmeSB0aGUgY3VycmVudFxuICAgKiBhcnJheSBhc2lkZSBmcm9tIGNsYW1waW5nLlxuICAgKlxuICAgKiBAcGFyYW0ge1dvcmRBcnJheX0gYXJyMSBCaWdnZXIgYXJyYXlcbiAgICogQHBhcmFtIHtXb3JkQXJyYXl9IGFycjIgU21hbGxlciBhcnJheSB0byBiZSBYT1JlZCB0byB0aGUgZW5kXG4gICAqXG4gICAqIEByZXR1cm5zIG5ldyBXb3JkQXJyYXlcbiAgICovXG4gIGV4dC54b3JlbmRCeXRlcyA9IGZ1bmN0aW9uKGFycjEsIGFycjIpe1xuICAgICAgLy8gVE9ETzogbW9yZSBlZmZpY2llbnRcbiAgICAgIHJldHVybiBleHQubGVmdG1vc3RCeXRlcyhhcnIxLCBhcnIxLnNpZ0J5dGVzLWFycjIuc2lnQnl0ZXMpXG4gICAgICAgICAgICAgIC5jb25jYXQoZXh0LnhvcihleHQucmlnaHRtb3N0Qnl0ZXMoYXJyMSwgYXJyMi5zaWdCeXRlcyksIGFycjIpKTtcbiAgfTtcblxuICAvKipcbiAgICogRG91Ymxpbmcgb3BlcmF0aW9uIG9uIGEgMTI4LWJpdCB2YWx1ZS4gVGhpcyBvcGVyYXRpb24gbW9kaWZpZXMgdGhlXG4gICAqIHBhc3NlZCBhcnJheS5cbiAgICpcbiAgICogQHBhcmFtIHtXb3JkQXJyYXl9IHdvcmRBcnJheSBXb3JkQXJyYXkgdG8gd29yayBvblxuICAgKlxuICAgKiBAcmV0dXJucyBwYXNzZWQgV29yZEFycmF5XG4gICAqL1xuICBleHQuZGJsID0gZnVuY3Rpb24od29yZEFycmF5KXtcbiAgICAgIHZhciBjYXJyeSA9IGV4dC5tc2Iod29yZEFycmF5KTtcbiAgICAgIGV4dC5iaXRzaGlmdCh3b3JkQXJyYXksIDEpO1xuICAgICAgZXh0Lnhvcih3b3JkQXJyYXksIGNhcnJ5ID09PSAxID8gZXh0LmNvbnN0X1JiIDogZXh0LmNvbnN0X1plcm8pO1xuICAgICAgcmV0dXJuIHdvcmRBcnJheTtcbiAgfTtcblxuICAvKipcbiAgICogSW52ZXJzZSBvcGVyYXRpb24gb24gYSAxMjgtYml0IHZhbHVlLiBUaGlzIG9wZXJhdGlvbiBtb2RpZmllcyB0aGVcbiAgICogcGFzc2VkIGFycmF5LlxuICAgKlxuICAgKiBAcGFyYW0ge1dvcmRBcnJheX0gd29yZEFycmF5IFdvcmRBcnJheSB0byB3b3JrIG9uXG4gICAqXG4gICAqIEByZXR1cm5zIHBhc3NlZCBXb3JkQXJyYXlcbiAgICovXG4gIGV4dC5pbnYgPSBmdW5jdGlvbih3b3JkQXJyYXkpe1xuICAgICAgdmFyIGNhcnJ5ID0gd29yZEFycmF5LndvcmRzWzRdICYgMTtcbiAgICAgIGV4dC5iaXRzaGlmdCh3b3JkQXJyYXksIC0xKTtcbiAgICAgIGV4dC54b3Iod29yZEFycmF5LCBjYXJyeSA9PT0gMSA/IGV4dC5jb25zdF9SYl9TaGlmdGVkIDogZXh0LmNvbnN0X1plcm8pO1xuICAgICAgcmV0dXJuIHdvcmRBcnJheTtcbiAgfTtcblxuICAvKipcbiAgICogQ2hlY2sgd2hldGhlciB0aGUgd29yZCBhcnJheXMgYXJlIGVxdWFsLlxuICAgKlxuICAgKiBAcGFyYW0ge1dvcmRBcnJheX0gYXJyMSBBcnJheSAxXG4gICAqIEBwYXJhbSB7V29yZEFycmF5fSBhcnIyIEFycmF5IDJcbiAgICpcbiAgICogQHJldHVybnMgYm9vbGVhblxuICAgKi9cbiAgZXh0LmVxdWFscyA9IGZ1bmN0aW9uKGFycjEsIGFycjIpe1xuICAgICAgaWYgKCFhcnIyIHx8ICFhcnIyLndvcmRzIHx8IGFycjEuc2lnQnl0ZXMgIT09IGFycjIuc2lnQnl0ZXMpIHtcbiAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICB9XG4gICAgICBhcnIxLmNsYW1wKCk7XG4gICAgICBhcnIyLmNsYW1wKCk7XG4gICAgICB2YXIgZXF1YWwgPSAwO1xuICAgICAgZm9yKHZhciBpID0gMDsgaSA8IGFycjEud29yZHMubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgICBlcXVhbCB8PSBhcnIxLndvcmRzW2ldIF4gYXJyMi53b3Jkc1tpXTtcbiAgICAgIH1cbiAgICAgIHJldHVybiBlcXVhbCA9PT0gMDtcbiAgfTtcblxuICAvKipcbiAgICogUmV0cmlldmVzIHRoZSBtb3N0IHNpZ25pZmljYW50IGJpdCBvZiB0aGUgV29yZEFycmF5IGFzIGFuIEludGVnZXIuXG4gICAqXG4gICAqIEBwYXJhbSB7V29yZEFycmF5fSBhcnJcbiAgICpcbiAgICogQHJldHVybnMgSW50ZWdlclxuICAgKi9cbiAgZXh0Lm1zYiA9IGZ1bmN0aW9uKGFycikge1xuICAgICAgcmV0dXJuIGFyci53b3Jkc1swXSA+Pj4gMzE7XG4gIH1cblxuXG59KSk7IiwiOyhmdW5jdGlvbiAocm9vdCwgZmFjdG9yeSkge1xuICAvLyBDb21tb25KU1xuICBtb2R1bGUuZXhwb3J0cyA9IGV4cG9ydHMgPSBmYWN0b3J5KHJlcXVpcmUoXCJjcnlwdG8tanMvY29yZVwiKSwgcmVxdWlyZShcIi4vY29tbW9uLWJpdC1vcHNcIiksIHJlcXVpcmUoXCIuL2NvbW1vblwiKSwgcmVxdWlyZShcIi4vY21hY1wiKSwgcmVxdWlyZShcImNyeXB0by1qcy9hZXNcIiksIHJlcXVpcmUoXCJjcnlwdG8tanMvbW9kZS1jdHJcIikpO1xufSh0aGlzLCBmdW5jdGlvbiAoQykge1xuXG4gIC8qXG4gICAqIFRoZSBNSVQgTGljZW5zZSAoTUlUKVxuICAgKlxuICAgKiBDb3B5cmlnaHQgKGMpIDIwMTUgYXJ0am9tYlxuICAgKi9cbiAgLy8gU2hvcnRjdXRzXG4gIHZhciBCYXNlID0gQy5saWIuQmFzZTtcbiAgdmFyIFdvcmRBcnJheSA9IEMubGliLldvcmRBcnJheTtcbiAgdmFyIEFFUyA9IEMuYWxnby5BRVM7XG4gIHZhciBleHQgPSBDLmV4dDtcbiAgdmFyIE9uZVplcm9QYWRkaW5nID0gQy5wYWQuT25lWmVyb1BhZGRpbmc7XG4gIHZhciBDTUFDID0gQy5hbGdvLkNNQUM7XG5cbiAgLyoqXG4gICAqIHVwZGF0ZUFBRCBtdXN0IGJlIHVzZWQgYmVmb3JlIHVwZGF0ZSwgYmVjYXVzZSB0aGUgYWRkaXRpb25hbCBkYXRhIGlzXG4gICAqIGV4cGVjdGVkIHRvIGJlIGF1dGhlbnRpY2F0ZWQgYmVmb3JlIHRoZSBwbGFpbnRleHQgc3RyZWFtIHN0YXJ0cy5cbiAgICovXG4gIHZhciBTMlYgPSBDLmFsZ28uUzJWID0gQmFzZS5leHRlbmQoe1xuICAgICAgaW5pdDogZnVuY3Rpb24oa2V5KXtcbiAgICAgICAgICB0aGlzLl9ibG9ja1NpemUgPSAxNjtcbiAgICAgICAgICB0aGlzLl9jbWFjQUQgPSBDTUFDLmNyZWF0ZShrZXkpO1xuICAgICAgICAgIHRoaXMuX2NtYWNQVCA9IENNQUMuY3JlYXRlKGtleSk7XG4gICAgICAgICAgdGhpcy5yZXNldCgpO1xuICAgICAgfSxcbiAgICAgIHJlc2V0OiBmdW5jdGlvbigpe1xuICAgICAgICAgIHRoaXMuX2J1ZmZlciA9IG5ldyBXb3JkQXJyYXkuaW5pdCgpO1xuICAgICAgICAgIHRoaXMuX2NtYWNBRC5yZXNldCgpO1xuICAgICAgICAgIHRoaXMuX2NtYWNQVC5yZXNldCgpO1xuICAgICAgICAgIHRoaXMuX2QgPSB0aGlzLl9jbWFjQUQuZmluYWxpemUoZXh0LmNvbnN0X1plcm8pO1xuICAgICAgICAgIHRoaXMuX2VtcHR5ID0gdHJ1ZTtcbiAgICAgICAgICB0aGlzLl9wdFN0YXJ0ZWQgPSBmYWxzZTtcbiAgICAgIH0sXG4gICAgICB1cGRhdGVBQUQ6IGZ1bmN0aW9uKG1zZ1VwZGF0ZSl7XG4gICAgICAgICAgaWYgKHRoaXMuX3B0U3RhcnRlZCkge1xuICAgICAgICAgICAgICAvLyBJdCdzIG5vdCBwb3NzaWJsZSB0byBhdXRoZW50aWNhdGUgYW55IG1vcmUgYWRkaXRpb25hbCBkYXRhIHdoZW4gdGhlIHBsYWludGV4dCBzdHJlYW0gc3RhcnRzXG4gICAgICAgICAgICAgIHJldHVybiB0aGlzO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGlmICghbXNnVXBkYXRlKSB7XG4gICAgICAgICAgICAgIHJldHVybiB0aGlzO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGlmICh0eXBlb2YgbXNnVXBkYXRlID09PSBcInN0cmluZ1wiKSB7XG4gICAgICAgICAgICAgIG1zZ1VwZGF0ZSA9IEMuZW5jLlV0ZjgucGFyc2UobXNnVXBkYXRlKTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICB0aGlzLl9kID0gZXh0LnhvcihleHQuZGJsKHRoaXMuX2QpLCB0aGlzLl9jbWFjQUQuZmluYWxpemUobXNnVXBkYXRlKSk7XG4gICAgICAgICAgdGhpcy5fZW1wdHkgPSBmYWxzZTtcblxuICAgICAgICAgIC8vIENoYWluYWJsZVxuICAgICAgICAgIHJldHVybiB0aGlzO1xuICAgICAgfSxcbiAgICAgIHVwZGF0ZTogZnVuY3Rpb24obXNnVXBkYXRlKXtcbiAgICAgICAgICBpZiAoIW1zZ1VwZGF0ZSkge1xuICAgICAgICAgICAgICByZXR1cm4gdGhpcztcbiAgICAgICAgICB9XG5cbiAgICAgICAgICB0aGlzLl9wdFN0YXJ0ZWQgPSB0cnVlO1xuICAgICAgICAgIHZhciBidWZmZXIgPSB0aGlzLl9idWZmZXI7XG4gICAgICAgICAgdmFyIGJzaXplID0gdGhpcy5fYmxvY2tTaXplO1xuICAgICAgICAgIHZhciB3c2l6ZSA9IGJzaXplIC8gNDtcbiAgICAgICAgICB2YXIgY21hYyA9IHRoaXMuX2NtYWNQVDtcbiAgICAgICAgICBpZiAodHlwZW9mIG1zZ1VwZGF0ZSA9PT0gXCJzdHJpbmdcIikge1xuICAgICAgICAgICAgICBtc2dVcGRhdGUgPSBDLmVuYy5VdGY4LnBhcnNlKG1zZ1VwZGF0ZSk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgYnVmZmVyLmNvbmNhdChtc2dVcGRhdGUpO1xuXG4gICAgICAgICAgd2hpbGUoYnVmZmVyLnNpZ0J5dGVzID49IDIgKiBic2l6ZSl7XG4gICAgICAgICAgICAgIHRoaXMuX2VtcHR5ID0gZmFsc2U7XG4gICAgICAgICAgICAgIHZhciBzX2kgPSBleHQucG9wV29yZHMoYnVmZmVyLCB3c2l6ZSk7XG4gICAgICAgICAgICAgIGNtYWMudXBkYXRlKHNfaSk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgLy8gQ2hhaW5hYmxlXG4gICAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgICB9LFxuICAgICAgZmluYWxpemU6IGZ1bmN0aW9uKG1zZ1VwZGF0ZSl7XG4gICAgICAgICAgdGhpcy51cGRhdGUobXNnVXBkYXRlKTtcblxuICAgICAgICAgIHZhciBic2l6ZSA9IHRoaXMuX2Jsb2NrU2l6ZTtcbiAgICAgICAgICB2YXIgc19uID0gdGhpcy5fYnVmZmVyO1xuXG4gICAgICAgICAgaWYgKHRoaXMuX2VtcHR5ICYmIHNfbi5zaWdCeXRlcyA9PT0gMCkge1xuICAgICAgICAgICAgICByZXR1cm4gdGhpcy5fY21hY0FELmZpbmFsaXplKGV4dC5jb25zdF9PbmUpO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIHZhciB0O1xuICAgICAgICAgIGlmIChzX24uc2lnQnl0ZXMgPj0gYnNpemUpIHtcbiAgICAgICAgICAgICAgdCA9IGV4dC54b3JlbmRCeXRlcyhzX24sIHRoaXMuX2QpO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgIE9uZVplcm9QYWRkaW5nLnBhZChzX24sIGJzaXplKTtcbiAgICAgICAgICAgICAgdCA9IGV4dC54b3IoZXh0LmRibCh0aGlzLl9kKSwgc19uKTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICByZXR1cm4gdGhpcy5fY21hY1BULmZpbmFsaXplKHQpO1xuICAgICAgfVxuICB9KTtcblxuICB2YXIgU0lWID0gQy5TSVYgPSBCYXNlLmV4dGVuZCh7XG4gICAgICBpbml0OiBmdW5jdGlvbihrZXkpe1xuICAgICAgICAgIHZhciBsZW4gPSBrZXkuc2lnQnl0ZXMgLyAyO1xuICAgICAgICAgIHRoaXMuX3MydktleSA9IGV4dC5zaGlmdEJ5dGVzKGtleSwgbGVuKTtcbiAgICAgICAgICB0aGlzLl9jdHJLZXkgPSBrZXk7XG4gICAgICB9LFxuICAgICAgZW5jcnlwdDogZnVuY3Rpb24oYWRBcnJheSwgcGxhaW50ZXh0KXtcbiAgICAgICAgICBpZiAoIXBsYWludGV4dCAmJiBhZEFycmF5KSB7XG4gICAgICAgICAgICAgIHBsYWludGV4dCA9IGFkQXJyYXk7XG4gICAgICAgICAgICAgIGFkQXJyYXkgPSBbXTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICB2YXIgczJ2ID0gUzJWLmNyZWF0ZSh0aGlzLl9zMnZLZXkpO1xuICAgICAgICAgIEFycmF5LnByb3RvdHlwZS5mb3JFYWNoLmNhbGwoYWRBcnJheSwgZnVuY3Rpb24oYWQpe1xuICAgICAgICAgICAgICBzMnYudXBkYXRlQUFEKGFkKTtcbiAgICAgICAgICB9KTtcbiAgICAgICAgICB2YXIgdGFnID0gczJ2LmZpbmFsaXplKHBsYWludGV4dCk7XG4gICAgICAgICAgdmFyIGZpbHRlcmVkVGFnID0gZXh0LmJpdGFuZCh0YWcsIGV4dC5jb25zdF9ub25NU0IpO1xuXG4gICAgICAgICAgdmFyIGNpcGhlcnRleHQgPSBDLkFFUy5lbmNyeXB0KHBsYWludGV4dCwgdGhpcy5fY3RyS2V5LCB7XG4gICAgICAgICAgICAgIGl2OiBmaWx0ZXJlZFRhZyxcbiAgICAgICAgICAgICAgbW9kZTogQy5tb2RlLkNUUixcbiAgICAgICAgICAgICAgcGFkZGluZzogQy5wYWQuTm9QYWRkaW5nXG4gICAgICAgICAgfSk7XG5cbiAgICAgICAgICByZXR1cm4gdGFnLmNvbmNhdChjaXBoZXJ0ZXh0LmNpcGhlcnRleHQpO1xuICAgICAgfSxcbiAgICAgIGRlY3J5cHQ6IGZ1bmN0aW9uKGFkQXJyYXksIGNpcGhlcnRleHQpe1xuICAgICAgICAgIGlmICghY2lwaGVydGV4dCAmJiBhZEFycmF5KSB7XG4gICAgICAgICAgICAgIGNpcGhlcnRleHQgPSBhZEFycmF5O1xuICAgICAgICAgICAgICBhZEFycmF5ID0gW107XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgdmFyIHRhZyA9IGV4dC5zaGlmdEJ5dGVzKGNpcGhlcnRleHQsIDE2KTtcbiAgICAgICAgICB2YXIgZmlsdGVyZWRUYWcgPSBleHQuYml0YW5kKHRhZywgZXh0LmNvbnN0X25vbk1TQik7XG5cbiAgICAgICAgICB2YXIgcGxhaW50ZXh0ID0gQy5BRVMuZGVjcnlwdCh7Y2lwaGVydGV4dDpjaXBoZXJ0ZXh0fSwgdGhpcy5fY3RyS2V5LCB7XG4gICAgICAgICAgICAgIGl2OiBmaWx0ZXJlZFRhZyxcbiAgICAgICAgICAgICAgbW9kZTogQy5tb2RlLkNUUixcbiAgICAgICAgICAgICAgcGFkZGluZzogQy5wYWQuTm9QYWRkaW5nXG4gICAgICAgICAgfSk7XG5cbiAgICAgICAgICB2YXIgczJ2ID0gUzJWLmNyZWF0ZSh0aGlzLl9zMnZLZXkpO1xuICAgICAgICAgIEFycmF5LnByb3RvdHlwZS5mb3JFYWNoLmNhbGwoYWRBcnJheSwgZnVuY3Rpb24oYWQpe1xuICAgICAgICAgICAgICBzMnYudXBkYXRlQUFEKGFkKTtcbiAgICAgICAgICB9KTtcbiAgICAgICAgICB2YXIgcmVjb3ZlcmVkVGFnID0gczJ2LmZpbmFsaXplKHBsYWludGV4dCk7XG5cbiAgICAgICAgICBpZiAoZXh0LmVxdWFscyh0YWcsIHJlY292ZXJlZFRhZykpIHtcbiAgICAgICAgICAgICAgcmV0dXJuIHBsYWludGV4dDtcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgfVxuICAgICAgfVxuICB9KTtcblxuXG59KSk7IiwiLyohIEBsaWNlbnNlIEZpcmViYXNlIHYyLjQuMlxuICAgIExpY2Vuc2U6IGh0dHBzOi8vd3d3LmZpcmViYXNlLmNvbS90ZXJtcy90ZXJtcy1vZi1zZXJ2aWNlLmh0bWwgKi9cbihmdW5jdGlvbigpIHt2YXIgaCxuPXRoaXM7ZnVuY3Rpb24gcChhKXtyZXR1cm4gdm9pZCAwIT09YX1mdW5jdGlvbiBhYSgpe31mdW5jdGlvbiBiYShhKXthLnliPWZ1bmN0aW9uKCl7cmV0dXJuIGEuemY/YS56ZjphLnpmPW5ldyBhfX1cbmZ1bmN0aW9uIGNhKGEpe3ZhciBiPXR5cGVvZiBhO2lmKFwib2JqZWN0XCI9PWIpaWYoYSl7aWYoYSBpbnN0YW5jZW9mIEFycmF5KXJldHVyblwiYXJyYXlcIjtpZihhIGluc3RhbmNlb2YgT2JqZWN0KXJldHVybiBiO3ZhciBjPU9iamVjdC5wcm90b3R5cGUudG9TdHJpbmcuY2FsbChhKTtpZihcIltvYmplY3QgV2luZG93XVwiPT1jKXJldHVyblwib2JqZWN0XCI7aWYoXCJbb2JqZWN0IEFycmF5XVwiPT1jfHxcIm51bWJlclwiPT10eXBlb2YgYS5sZW5ndGgmJlwidW5kZWZpbmVkXCIhPXR5cGVvZiBhLnNwbGljZSYmXCJ1bmRlZmluZWRcIiE9dHlwZW9mIGEucHJvcGVydHlJc0VudW1lcmFibGUmJiFhLnByb3BlcnR5SXNFbnVtZXJhYmxlKFwic3BsaWNlXCIpKXJldHVyblwiYXJyYXlcIjtpZihcIltvYmplY3QgRnVuY3Rpb25dXCI9PWN8fFwidW5kZWZpbmVkXCIhPXR5cGVvZiBhLmNhbGwmJlwidW5kZWZpbmVkXCIhPXR5cGVvZiBhLnByb3BlcnR5SXNFbnVtZXJhYmxlJiYhYS5wcm9wZXJ0eUlzRW51bWVyYWJsZShcImNhbGxcIikpcmV0dXJuXCJmdW5jdGlvblwifWVsc2UgcmV0dXJuXCJudWxsXCI7XG5lbHNlIGlmKFwiZnVuY3Rpb25cIj09YiYmXCJ1bmRlZmluZWRcIj09dHlwZW9mIGEuY2FsbClyZXR1cm5cIm9iamVjdFwiO3JldHVybiBifWZ1bmN0aW9uIGRhKGEpe3JldHVyblwiYXJyYXlcIj09Y2EoYSl9ZnVuY3Rpb24gZWEoYSl7dmFyIGI9Y2EoYSk7cmV0dXJuXCJhcnJheVwiPT1ifHxcIm9iamVjdFwiPT1iJiZcIm51bWJlclwiPT10eXBlb2YgYS5sZW5ndGh9ZnVuY3Rpb24gcShhKXtyZXR1cm5cInN0cmluZ1wiPT10eXBlb2YgYX1mdW5jdGlvbiBmYShhKXtyZXR1cm5cIm51bWJlclwiPT10eXBlb2YgYX1mdW5jdGlvbiByKGEpe3JldHVyblwiZnVuY3Rpb25cIj09Y2EoYSl9ZnVuY3Rpb24gZ2EoYSl7dmFyIGI9dHlwZW9mIGE7cmV0dXJuXCJvYmplY3RcIj09YiYmbnVsbCE9YXx8XCJmdW5jdGlvblwiPT1ifWZ1bmN0aW9uIGhhKGEsYixjKXtyZXR1cm4gYS5jYWxsLmFwcGx5KGEuYmluZCxhcmd1bWVudHMpfVxuZnVuY3Rpb24gaWEoYSxiLGMpe2lmKCFhKXRocm93IEVycm9yKCk7aWYoMjxhcmd1bWVudHMubGVuZ3RoKXt2YXIgZD1BcnJheS5wcm90b3R5cGUuc2xpY2UuY2FsbChhcmd1bWVudHMsMik7cmV0dXJuIGZ1bmN0aW9uKCl7dmFyIGM9QXJyYXkucHJvdG90eXBlLnNsaWNlLmNhbGwoYXJndW1lbnRzKTtBcnJheS5wcm90b3R5cGUudW5zaGlmdC5hcHBseShjLGQpO3JldHVybiBhLmFwcGx5KGIsYyl9fXJldHVybiBmdW5jdGlvbigpe3JldHVybiBhLmFwcGx5KGIsYXJndW1lbnRzKX19ZnVuY3Rpb24gdShhLGIsYyl7dT1GdW5jdGlvbi5wcm90b3R5cGUuYmluZCYmLTEhPUZ1bmN0aW9uLnByb3RvdHlwZS5iaW5kLnRvU3RyaW5nKCkuaW5kZXhPZihcIm5hdGl2ZSBjb2RlXCIpP2hhOmlhO3JldHVybiB1LmFwcGx5KG51bGwsYXJndW1lbnRzKX12YXIgamE9RGF0ZS5ub3d8fGZ1bmN0aW9uKCl7cmV0dXJuK25ldyBEYXRlfTtcbmZ1bmN0aW9uIGthKGEsYil7ZnVuY3Rpb24gYygpe31jLnByb3RvdHlwZT1iLnByb3RvdHlwZTthLnBoPWIucHJvdG90eXBlO2EucHJvdG90eXBlPW5ldyBjO2EucHJvdG90eXBlLmNvbnN0cnVjdG9yPWE7YS5saD1mdW5jdGlvbihhLGMsZil7Zm9yKHZhciBnPUFycmF5KGFyZ3VtZW50cy5sZW5ndGgtMiksaz0yO2s8YXJndW1lbnRzLmxlbmd0aDtrKyspZ1trLTJdPWFyZ3VtZW50c1trXTtyZXR1cm4gYi5wcm90b3R5cGVbY10uYXBwbHkoYSxnKX19O2Z1bmN0aW9uIGxhKGEpe2lmKEVycm9yLmNhcHR1cmVTdGFja1RyYWNlKUVycm9yLmNhcHR1cmVTdGFja1RyYWNlKHRoaXMsbGEpO2Vsc2V7dmFyIGI9RXJyb3IoKS5zdGFjaztiJiYodGhpcy5zdGFjaz1iKX1hJiYodGhpcy5tZXNzYWdlPVN0cmluZyhhKSl9a2EobGEsRXJyb3IpO2xhLnByb3RvdHlwZS5uYW1lPVwiQ3VzdG9tRXJyb3JcIjtmdW5jdGlvbiB2KGEsYil7Zm9yKHZhciBjIGluIGEpYi5jYWxsKHZvaWQgMCxhW2NdLGMsYSl9ZnVuY3Rpb24gbWEoYSxiKXt2YXIgYz17fSxkO2ZvcihkIGluIGEpY1tkXT1iLmNhbGwodm9pZCAwLGFbZF0sZCxhKTtyZXR1cm4gY31mdW5jdGlvbiBuYShhLGIpe2Zvcih2YXIgYyBpbiBhKWlmKCFiLmNhbGwodm9pZCAwLGFbY10sYyxhKSlyZXR1cm4hMTtyZXR1cm4hMH1mdW5jdGlvbiBvYShhKXt2YXIgYj0wLGM7Zm9yKGMgaW4gYSliKys7cmV0dXJuIGJ9ZnVuY3Rpb24gcGEoYSl7Zm9yKHZhciBiIGluIGEpcmV0dXJuIGJ9ZnVuY3Rpb24gcWEoYSl7dmFyIGI9W10sYz0wLGQ7Zm9yKGQgaW4gYSliW2MrK109YVtkXTtyZXR1cm4gYn1mdW5jdGlvbiByYShhKXt2YXIgYj1bXSxjPTAsZDtmb3IoZCBpbiBhKWJbYysrXT1kO3JldHVybiBifWZ1bmN0aW9uIHNhKGEsYil7Zm9yKHZhciBjIGluIGEpaWYoYVtjXT09YilyZXR1cm4hMDtyZXR1cm4hMX1cbmZ1bmN0aW9uIHRhKGEsYixjKXtmb3IodmFyIGQgaW4gYSlpZihiLmNhbGwoYyxhW2RdLGQsYSkpcmV0dXJuIGR9ZnVuY3Rpb24gdWEoYSxiKXt2YXIgYz10YShhLGIsdm9pZCAwKTtyZXR1cm4gYyYmYVtjXX1mdW5jdGlvbiB2YShhKXtmb3IodmFyIGIgaW4gYSlyZXR1cm4hMTtyZXR1cm4hMH1mdW5jdGlvbiB3YShhKXt2YXIgYj17fSxjO2ZvcihjIGluIGEpYltjXT1hW2NdO3JldHVybiBifXZhciB4YT1cImNvbnN0cnVjdG9yIGhhc093blByb3BlcnR5IGlzUHJvdG90eXBlT2YgcHJvcGVydHlJc0VudW1lcmFibGUgdG9Mb2NhbGVTdHJpbmcgdG9TdHJpbmcgdmFsdWVPZlwiLnNwbGl0KFwiIFwiKTtcbmZ1bmN0aW9uIHlhKGEsYil7Zm9yKHZhciBjLGQsZT0xO2U8YXJndW1lbnRzLmxlbmd0aDtlKyspe2Q9YXJndW1lbnRzW2VdO2ZvcihjIGluIGQpYVtjXT1kW2NdO2Zvcih2YXIgZj0wO2Y8eGEubGVuZ3RoO2YrKyljPXhhW2ZdLE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChkLGMpJiYoYVtjXT1kW2NdKX19O2Z1bmN0aW9uIHphKGEpe2E9U3RyaW5nKGEpO2lmKC9eXFxzKiQvLnRlc3QoYSk/MDovXltcXF0sOnt9XFxzXFx1MjAyOFxcdTIwMjldKiQvLnRlc3QoYS5yZXBsYWNlKC9cXFxcW1wiXFxcXFxcL2JmbnJ0dV0vZyxcIkBcIikucmVwbGFjZSgvXCJbXlwiXFxcXFxcblxcclxcdTIwMjhcXHUyMDI5XFx4MDAtXFx4MDhcXHgwYS1cXHgxZl0qXCJ8dHJ1ZXxmYWxzZXxudWxsfC0/XFxkKyg/OlxcLlxcZCopPyg/OltlRV1bK1xcLV0/XFxkKyk/L2csXCJdXCIpLnJlcGxhY2UoLyg/Ol58OnwsKSg/OltcXHNcXHUyMDI4XFx1MjAyOV0qXFxbKSsvZyxcIlwiKSkpdHJ5e3JldHVybiBldmFsKFwiKFwiK2ErXCIpXCIpfWNhdGNoKGIpe310aHJvdyBFcnJvcihcIkludmFsaWQgSlNPTiBzdHJpbmc6IFwiK2EpO31mdW5jdGlvbiBBYSgpe3RoaXMuVmQ9dm9pZCAwfVxuZnVuY3Rpb24gQmEoYSxiLGMpe3N3aXRjaCh0eXBlb2YgYil7Y2FzZSBcInN0cmluZ1wiOkNhKGIsYyk7YnJlYWs7Y2FzZSBcIm51bWJlclwiOmMucHVzaChpc0Zpbml0ZShiKSYmIWlzTmFOKGIpP2I6XCJudWxsXCIpO2JyZWFrO2Nhc2UgXCJib29sZWFuXCI6Yy5wdXNoKGIpO2JyZWFrO2Nhc2UgXCJ1bmRlZmluZWRcIjpjLnB1c2goXCJudWxsXCIpO2JyZWFrO2Nhc2UgXCJvYmplY3RcIjppZihudWxsPT1iKXtjLnB1c2goXCJudWxsXCIpO2JyZWFrfWlmKGRhKGIpKXt2YXIgZD1iLmxlbmd0aDtjLnB1c2goXCJbXCIpO2Zvcih2YXIgZT1cIlwiLGY9MDtmPGQ7ZisrKWMucHVzaChlKSxlPWJbZl0sQmEoYSxhLlZkP2EuVmQuY2FsbChiLFN0cmluZyhmKSxlKTplLGMpLGU9XCIsXCI7Yy5wdXNoKFwiXVwiKTticmVha31jLnB1c2goXCJ7XCIpO2Q9XCJcIjtmb3IoZiBpbiBiKU9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChiLGYpJiYoZT1iW2ZdLFwiZnVuY3Rpb25cIiE9dHlwZW9mIGUmJihjLnB1c2goZCksQ2EoZixjKSxcbmMucHVzaChcIjpcIiksQmEoYSxhLlZkP2EuVmQuY2FsbChiLGYsZSk6ZSxjKSxkPVwiLFwiKSk7Yy5wdXNoKFwifVwiKTticmVhaztjYXNlIFwiZnVuY3Rpb25cIjpicmVhaztkZWZhdWx0OnRocm93IEVycm9yKFwiVW5rbm93biB0eXBlOiBcIit0eXBlb2YgYik7fX12YXIgRGE9eydcIic6J1xcXFxcIicsXCJcXFxcXCI6XCJcXFxcXFxcXFwiLFwiL1wiOlwiXFxcXC9cIixcIlxcYlwiOlwiXFxcXGJcIixcIlxcZlwiOlwiXFxcXGZcIixcIlxcblwiOlwiXFxcXG5cIixcIlxcclwiOlwiXFxcXHJcIixcIlxcdFwiOlwiXFxcXHRcIixcIlxceDBCXCI6XCJcXFxcdTAwMGJcIn0sRWE9L1xcdWZmZmYvLnRlc3QoXCJcXHVmZmZmXCIpPy9bXFxcXFxcXCJcXHgwMC1cXHgxZlxceDdmLVxcdWZmZmZdL2c6L1tcXFxcXFxcIlxceDAwLVxceDFmXFx4N2YtXFx4ZmZdL2c7XG5mdW5jdGlvbiBDYShhLGIpe2IucHVzaCgnXCInLGEucmVwbGFjZShFYSxmdW5jdGlvbihhKXtpZihhIGluIERhKXJldHVybiBEYVthXTt2YXIgYj1hLmNoYXJDb2RlQXQoMCksZT1cIlxcXFx1XCI7MTY+Yj9lKz1cIjAwMFwiOjI1Nj5iP2UrPVwiMDBcIjo0MDk2PmImJihlKz1cIjBcIik7cmV0dXJuIERhW2FdPWUrYi50b1N0cmluZygxNil9KSwnXCInKX07ZnVuY3Rpb24gRmEoKXtyZXR1cm4gTWF0aC5mbG9vcigyMTQ3NDgzNjQ4Kk1hdGgucmFuZG9tKCkpLnRvU3RyaW5nKDM2KStNYXRoLmFicyhNYXRoLmZsb29yKDIxNDc0ODM2NDgqTWF0aC5yYW5kb20oKSleamEoKSkudG9TdHJpbmcoMzYpfTt2YXIgdzthOnt2YXIgR2E9bi5uYXZpZ2F0b3I7aWYoR2Epe3ZhciBIYT1HYS51c2VyQWdlbnQ7aWYoSGEpe3c9SGE7YnJlYWsgYX19dz1cIlwifTtmdW5jdGlvbiBJYSgpe3RoaXMuWWE9LTF9O2Z1bmN0aW9uIEphKCl7dGhpcy5ZYT0tMTt0aGlzLllhPTY0O3RoaXMuUD1bXTt0aGlzLnBlPVtdO3RoaXMuZWc9W107dGhpcy5PZD1bXTt0aGlzLk9kWzBdPTEyODtmb3IodmFyIGE9MTthPHRoaXMuWWE7KythKXRoaXMuT2RbYV09MDt0aGlzLmdlPXRoaXMuZWM9MDt0aGlzLnJlc2V0KCl9a2EoSmEsSWEpO0phLnByb3RvdHlwZS5yZXNldD1mdW5jdGlvbigpe3RoaXMuUFswXT0xNzMyNTg0MTkzO3RoaXMuUFsxXT00MDIzMjMzNDE3O3RoaXMuUFsyXT0yNTYyMzgzMTAyO3RoaXMuUFszXT0yNzE3MzM4Nzg7dGhpcy5QWzRdPTMyODUzNzc1MjA7dGhpcy5nZT10aGlzLmVjPTB9O1xuZnVuY3Rpb24gS2EoYSxiLGMpe2N8fChjPTApO3ZhciBkPWEuZWc7aWYocShiKSlmb3IodmFyIGU9MDsxNj5lO2UrKylkW2VdPWIuY2hhckNvZGVBdChjKTw8MjR8Yi5jaGFyQ29kZUF0KGMrMSk8PDE2fGIuY2hhckNvZGVBdChjKzIpPDw4fGIuY2hhckNvZGVBdChjKzMpLGMrPTQ7ZWxzZSBmb3IoZT0wOzE2PmU7ZSsrKWRbZV09YltjXTw8MjR8YltjKzFdPDwxNnxiW2MrMl08PDh8YltjKzNdLGMrPTQ7Zm9yKGU9MTY7ODA+ZTtlKyspe3ZhciBmPWRbZS0zXV5kW2UtOF1eZFtlLTE0XV5kW2UtMTZdO2RbZV09KGY8PDF8Zj4+PjMxKSY0Mjk0OTY3Mjk1fWI9YS5QWzBdO2M9YS5QWzFdO2Zvcih2YXIgZz1hLlBbMl0saz1hLlBbM10sbT1hLlBbNF0sbCxlPTA7ODA+ZTtlKyspNDA+ZT8yMD5lPyhmPWteYyYoZ15rKSxsPTE1MTg1MDAyNDkpOihmPWNeZ15rLGw9MTg1OTc3NTM5Myk6NjA+ZT8oZj1jJmd8ayYoY3xnKSxsPTI0MDA5NTk3MDgpOihmPWNeZ15rLGw9MzM5NTQ2OTc4MiksZj0oYjw8XG41fGI+Pj4yNykrZittK2wrZFtlXSY0Mjk0OTY3Mjk1LG09ayxrPWcsZz0oYzw8MzB8Yz4+PjIpJjQyOTQ5NjcyOTUsYz1iLGI9ZjthLlBbMF09YS5QWzBdK2ImNDI5NDk2NzI5NTthLlBbMV09YS5QWzFdK2MmNDI5NDk2NzI5NTthLlBbMl09YS5QWzJdK2cmNDI5NDk2NzI5NTthLlBbM109YS5QWzNdK2smNDI5NDk2NzI5NTthLlBbNF09YS5QWzRdK20mNDI5NDk2NzI5NX1cbkphLnByb3RvdHlwZS51cGRhdGU9ZnVuY3Rpb24oYSxiKXtpZihudWxsIT1hKXtwKGIpfHwoYj1hLmxlbmd0aCk7Zm9yKHZhciBjPWItdGhpcy5ZYSxkPTAsZT10aGlzLnBlLGY9dGhpcy5lYztkPGI7KXtpZigwPT1mKWZvcig7ZDw9YzspS2EodGhpcyxhLGQpLGQrPXRoaXMuWWE7aWYocShhKSlmb3IoO2Q8Yjspe2lmKGVbZl09YS5jaGFyQ29kZUF0KGQpLCsrZiwrK2QsZj09dGhpcy5ZYSl7S2EodGhpcyxlKTtmPTA7YnJlYWt9fWVsc2UgZm9yKDtkPGI7KWlmKGVbZl09YVtkXSwrK2YsKytkLGY9PXRoaXMuWWEpe0thKHRoaXMsZSk7Zj0wO2JyZWFrfX10aGlzLmVjPWY7dGhpcy5nZSs9Yn19O3ZhciB4PUFycmF5LnByb3RvdHlwZSxMYT14LmluZGV4T2Y/ZnVuY3Rpb24oYSxiLGMpe3JldHVybiB4LmluZGV4T2YuY2FsbChhLGIsYyl9OmZ1bmN0aW9uKGEsYixjKXtjPW51bGw9PWM/MDowPmM/TWF0aC5tYXgoMCxhLmxlbmd0aCtjKTpjO2lmKHEoYSkpcmV0dXJuIHEoYikmJjE9PWIubGVuZ3RoP2EuaW5kZXhPZihiLGMpOi0xO2Zvcig7YzxhLmxlbmd0aDtjKyspaWYoYyBpbiBhJiZhW2NdPT09YilyZXR1cm4gYztyZXR1cm4tMX0sTWE9eC5mb3JFYWNoP2Z1bmN0aW9uKGEsYixjKXt4LmZvckVhY2guY2FsbChhLGIsYyl9OmZ1bmN0aW9uKGEsYixjKXtmb3IodmFyIGQ9YS5sZW5ndGgsZT1xKGEpP2Euc3BsaXQoXCJcIik6YSxmPTA7ZjxkO2YrKylmIGluIGUmJmIuY2FsbChjLGVbZl0sZixhKX0sTmE9eC5maWx0ZXI/ZnVuY3Rpb24oYSxiLGMpe3JldHVybiB4LmZpbHRlci5jYWxsKGEsYixjKX06ZnVuY3Rpb24oYSxiLGMpe2Zvcih2YXIgZD1hLmxlbmd0aCxlPVtdLGY9MCxnPXEoYSk/XG5hLnNwbGl0KFwiXCIpOmEsaz0wO2s8ZDtrKyspaWYoayBpbiBnKXt2YXIgbT1nW2tdO2IuY2FsbChjLG0sayxhKSYmKGVbZisrXT1tKX1yZXR1cm4gZX0sT2E9eC5tYXA/ZnVuY3Rpb24oYSxiLGMpe3JldHVybiB4Lm1hcC5jYWxsKGEsYixjKX06ZnVuY3Rpb24oYSxiLGMpe2Zvcih2YXIgZD1hLmxlbmd0aCxlPUFycmF5KGQpLGY9cShhKT9hLnNwbGl0KFwiXCIpOmEsZz0wO2c8ZDtnKyspZyBpbiBmJiYoZVtnXT1iLmNhbGwoYyxmW2ddLGcsYSkpO3JldHVybiBlfSxQYT14LnJlZHVjZT9mdW5jdGlvbihhLGIsYyxkKXtmb3IodmFyIGU9W10sZj0xLGc9YXJndW1lbnRzLmxlbmd0aDtmPGc7ZisrKWUucHVzaChhcmd1bWVudHNbZl0pO2QmJihlWzBdPXUoYixkKSk7cmV0dXJuIHgucmVkdWNlLmFwcGx5KGEsZSl9OmZ1bmN0aW9uKGEsYixjLGQpe3ZhciBlPWM7TWEoYSxmdW5jdGlvbihjLGcpe2U9Yi5jYWxsKGQsZSxjLGcsYSl9KTtyZXR1cm4gZX0sUWE9eC5ldmVyeT9mdW5jdGlvbihhLGIsXG5jKXtyZXR1cm4geC5ldmVyeS5jYWxsKGEsYixjKX06ZnVuY3Rpb24oYSxiLGMpe2Zvcih2YXIgZD1hLmxlbmd0aCxlPXEoYSk/YS5zcGxpdChcIlwiKTphLGY9MDtmPGQ7ZisrKWlmKGYgaW4gZSYmIWIuY2FsbChjLGVbZl0sZixhKSlyZXR1cm4hMTtyZXR1cm4hMH07ZnVuY3Rpb24gUmEoYSxiKXt2YXIgYz1TYShhLGIsdm9pZCAwKTtyZXR1cm4gMD5jP251bGw6cShhKT9hLmNoYXJBdChjKTphW2NdfWZ1bmN0aW9uIFNhKGEsYixjKXtmb3IodmFyIGQ9YS5sZW5ndGgsZT1xKGEpP2Euc3BsaXQoXCJcIik6YSxmPTA7ZjxkO2YrKylpZihmIGluIGUmJmIuY2FsbChjLGVbZl0sZixhKSlyZXR1cm4gZjtyZXR1cm4tMX1mdW5jdGlvbiBUYShhLGIpe3ZhciBjPUxhKGEsYik7MDw9YyYmeC5zcGxpY2UuY2FsbChhLGMsMSl9ZnVuY3Rpb24gVWEoYSxiLGMpe3JldHVybiAyPj1hcmd1bWVudHMubGVuZ3RoP3guc2xpY2UuY2FsbChhLGIpOnguc2xpY2UuY2FsbChhLGIsYyl9XG5mdW5jdGlvbiBWYShhLGIpe2Euc29ydChifHxXYSl9ZnVuY3Rpb24gV2EoYSxiKXtyZXR1cm4gYT5iPzE6YTxiPy0xOjB9O2Z1bmN0aW9uIFhhKGEpe24uc2V0VGltZW91dChmdW5jdGlvbigpe3Rocm93IGE7fSwwKX12YXIgWWE7XG5mdW5jdGlvbiBaYSgpe3ZhciBhPW4uTWVzc2FnZUNoYW5uZWw7XCJ1bmRlZmluZWRcIj09PXR5cGVvZiBhJiZcInVuZGVmaW5lZFwiIT09dHlwZW9mIHdpbmRvdyYmd2luZG93LnBvc3RNZXNzYWdlJiZ3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lciYmLTE9PXcuaW5kZXhPZihcIlByZXN0b1wiKSYmKGE9ZnVuY3Rpb24oKXt2YXIgYT1kb2N1bWVudC5jcmVhdGVFbGVtZW50KFwiaWZyYW1lXCIpO2Euc3R5bGUuZGlzcGxheT1cIm5vbmVcIjthLnNyYz1cIlwiO2RvY3VtZW50LmRvY3VtZW50RWxlbWVudC5hcHBlbmRDaGlsZChhKTt2YXIgYj1hLmNvbnRlbnRXaW5kb3csYT1iLmRvY3VtZW50O2Eub3BlbigpO2Eud3JpdGUoXCJcIik7YS5jbG9zZSgpO3ZhciBjPVwiY2FsbEltbWVkaWF0ZVwiK01hdGgucmFuZG9tKCksZD1cImZpbGU6XCI9PWIubG9jYXRpb24ucHJvdG9jb2w/XCIqXCI6Yi5sb2NhdGlvbi5wcm90b2NvbCtcIi8vXCIrYi5sb2NhdGlvbi5ob3N0LGE9dShmdW5jdGlvbihhKXtpZigoXCIqXCI9PWR8fGEub3JpZ2luPT1cbmQpJiZhLmRhdGE9PWMpdGhpcy5wb3J0MS5vbm1lc3NhZ2UoKX0sdGhpcyk7Yi5hZGRFdmVudExpc3RlbmVyKFwibWVzc2FnZVwiLGEsITEpO3RoaXMucG9ydDE9e307dGhpcy5wb3J0Mj17cG9zdE1lc3NhZ2U6ZnVuY3Rpb24oKXtiLnBvc3RNZXNzYWdlKGMsZCl9fX0pO2lmKFwidW5kZWZpbmVkXCIhPT10eXBlb2YgYSYmLTE9PXcuaW5kZXhPZihcIlRyaWRlbnRcIikmJi0xPT13LmluZGV4T2YoXCJNU0lFXCIpKXt2YXIgYj1uZXcgYSxjPXt9LGQ9YztiLnBvcnQxLm9ubWVzc2FnZT1mdW5jdGlvbigpe2lmKHAoYy5uZXh0KSl7Yz1jLm5leHQ7dmFyIGE9Yy5oYjtjLmhiPW51bGw7YSgpfX07cmV0dXJuIGZ1bmN0aW9uKGEpe2QubmV4dD17aGI6YX07ZD1kLm5leHQ7Yi5wb3J0Mi5wb3N0TWVzc2FnZSgwKX19cmV0dXJuXCJ1bmRlZmluZWRcIiE9PXR5cGVvZiBkb2N1bWVudCYmXCJvbnJlYWR5c3RhdGVjaGFuZ2VcImluIGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoXCJzY3JpcHRcIik/ZnVuY3Rpb24oYSl7dmFyIGI9XG5kb2N1bWVudC5jcmVhdGVFbGVtZW50KFwic2NyaXB0XCIpO2Iub25yZWFkeXN0YXRlY2hhbmdlPWZ1bmN0aW9uKCl7Yi5vbnJlYWR5c3RhdGVjaGFuZ2U9bnVsbDtiLnBhcmVudE5vZGUucmVtb3ZlQ2hpbGQoYik7Yj1udWxsO2EoKTthPW51bGx9O2RvY3VtZW50LmRvY3VtZW50RWxlbWVudC5hcHBlbmRDaGlsZChiKX06ZnVuY3Rpb24oYSl7bi5zZXRUaW1lb3V0KGEsMCl9fTtmdW5jdGlvbiAkYShhLGIpe2FifHxiYigpO2NifHwoYWIoKSxjYj0hMCk7ZGIucHVzaChuZXcgZWIoYSxiKSl9dmFyIGFiO2Z1bmN0aW9uIGJiKCl7aWYobi5Qcm9taXNlJiZuLlByb21pc2UucmVzb2x2ZSl7dmFyIGE9bi5Qcm9taXNlLnJlc29sdmUoKTthYj1mdW5jdGlvbigpe2EudGhlbihmYil9fWVsc2UgYWI9ZnVuY3Rpb24oKXt2YXIgYT1mYjshcihuLnNldEltbWVkaWF0ZSl8fG4uV2luZG93JiZuLldpbmRvdy5wcm90b3R5cGUmJm4uV2luZG93LnByb3RvdHlwZS5zZXRJbW1lZGlhdGU9PW4uc2V0SW1tZWRpYXRlPyhZYXx8KFlhPVphKCkpLFlhKGEpKTpuLnNldEltbWVkaWF0ZShhKX19dmFyIGNiPSExLGRiPVtdO1tdLnB1c2goZnVuY3Rpb24oKXtjYj0hMTtkYj1bXX0pO1xuZnVuY3Rpb24gZmIoKXtmb3IoO2RiLmxlbmd0aDspe3ZhciBhPWRiO2RiPVtdO2Zvcih2YXIgYj0wO2I8YS5sZW5ndGg7YisrKXt2YXIgYz1hW2JdO3RyeXtjLnlnLmNhbGwoYy5zY29wZSl9Y2F0Y2goZCl7WGEoZCl9fX1jYj0hMX1mdW5jdGlvbiBlYihhLGIpe3RoaXMueWc9YTt0aGlzLnNjb3BlPWJ9O3ZhciBnYj0tMSE9dy5pbmRleE9mKFwiT3BlcmFcIil8fC0xIT13LmluZGV4T2YoXCJPUFJcIiksaGI9LTEhPXcuaW5kZXhPZihcIlRyaWRlbnRcIil8fC0xIT13LmluZGV4T2YoXCJNU0lFXCIpLGliPS0xIT13LmluZGV4T2YoXCJHZWNrb1wiKSYmLTE9PXcudG9Mb3dlckNhc2UoKS5pbmRleE9mKFwid2Via2l0XCIpJiYhKC0xIT13LmluZGV4T2YoXCJUcmlkZW50XCIpfHwtMSE9dy5pbmRleE9mKFwiTVNJRVwiKSksamI9LTEhPXcudG9Mb3dlckNhc2UoKS5pbmRleE9mKFwid2Via2l0XCIpO1xuKGZ1bmN0aW9uKCl7dmFyIGE9XCJcIixiO2lmKGdiJiZuLm9wZXJhKXJldHVybiBhPW4ub3BlcmEudmVyc2lvbixyKGEpP2EoKTphO2liP2I9L3J2XFw6KFteXFwpO10rKShcXCl8OykvOmhiP2I9L1xcYig/Ok1TSUV8cnYpWzogXShbXlxcKTtdKykoXFwpfDspLzpqYiYmKGI9L1dlYktpdFxcLyhcXFMrKS8pO2ImJihhPShhPWIuZXhlYyh3KSk/YVsxXTpcIlwiKTtyZXR1cm4gaGImJihiPShiPW4uZG9jdW1lbnQpP2IuZG9jdW1lbnRNb2RlOnZvaWQgMCxiPnBhcnNlRmxvYXQoYSkpP1N0cmluZyhiKTphfSkoKTt2YXIga2I9bnVsbCxsYj1udWxsLG1iPW51bGw7ZnVuY3Rpb24gbmIoYSxiKXtpZighZWEoYSkpdGhyb3cgRXJyb3IoXCJlbmNvZGVCeXRlQXJyYXkgdGFrZXMgYW4gYXJyYXkgYXMgYSBwYXJhbWV0ZXJcIik7b2IoKTtmb3IodmFyIGM9Yj9sYjprYixkPVtdLGU9MDtlPGEubGVuZ3RoO2UrPTMpe3ZhciBmPWFbZV0sZz1lKzE8YS5sZW5ndGgsaz1nP2FbZSsxXTowLG09ZSsyPGEubGVuZ3RoLGw9bT9hW2UrMl06MCx0PWY+PjIsZj0oZiYzKTw8NHxrPj40LGs9KGsmMTUpPDwyfGw+PjYsbD1sJjYzO218fChsPTY0LGd8fChrPTY0KSk7ZC5wdXNoKGNbdF0sY1tmXSxjW2tdLGNbbF0pfXJldHVybiBkLmpvaW4oXCJcIil9XG5mdW5jdGlvbiBvYigpe2lmKCFrYil7a2I9e307bGI9e307bWI9e307Zm9yKHZhciBhPTA7NjU+YTthKyspa2JbYV09XCJBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OSsvPVwiLmNoYXJBdChhKSxsYlthXT1cIkFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5LV8uXCIuY2hhckF0KGEpLG1iW2xiW2FdXT1hLDYyPD1hJiYobWJbXCJBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OSsvPVwiLmNoYXJBdChhKV09YSl9fTtmdW5jdGlvbiBwYihhLGIpe3RoaXMuTj1xYjt0aGlzLlJmPXZvaWQgMDt0aGlzLkJhPXRoaXMuSGE9bnVsbDt0aGlzLnlkPXRoaXMueWU9ITE7aWYoYT09cmIpc2IodGhpcyx0YixiKTtlbHNlIHRyeXt2YXIgYz10aGlzO2EuY2FsbChiLGZ1bmN0aW9uKGEpe3NiKGMsdGIsYSl9LGZ1bmN0aW9uKGEpe2lmKCEoYSBpbnN0YW5jZW9mIHViKSl0cnl7aWYoYSBpbnN0YW5jZW9mIEVycm9yKXRocm93IGE7dGhyb3cgRXJyb3IoXCJQcm9taXNlIHJlamVjdGVkLlwiKTt9Y2F0Y2goYil7fXNiKGMsdmIsYSl9KX1jYXRjaChkKXtzYih0aGlzLHZiLGQpfX12YXIgcWI9MCx0Yj0yLHZiPTM7ZnVuY3Rpb24gcmIoKXt9cGIucHJvdG90eXBlLnRoZW49ZnVuY3Rpb24oYSxiLGMpe3JldHVybiB3Yih0aGlzLHIoYSk/YTpudWxsLHIoYik/YjpudWxsLGMpfTtwYi5wcm90b3R5cGUudGhlbj1wYi5wcm90b3R5cGUudGhlbjtwYi5wcm90b3R5cGUuJGdvb2dfVGhlbmFibGU9ITA7aD1wYi5wcm90b3R5cGU7XG5oLmdoPWZ1bmN0aW9uKGEsYil7cmV0dXJuIHdiKHRoaXMsbnVsbCxhLGIpfTtoLmNhbmNlbD1mdW5jdGlvbihhKXt0aGlzLk49PXFiJiYkYShmdW5jdGlvbigpe3ZhciBiPW5ldyB1YihhKTt4Yih0aGlzLGIpfSx0aGlzKX07ZnVuY3Rpb24geGIoYSxiKXtpZihhLk49PXFiKWlmKGEuSGEpe3ZhciBjPWEuSGE7aWYoYy5CYSl7Zm9yKHZhciBkPTAsZT0tMSxmPTAsZztnPWMuQmFbZl07ZisrKWlmKGc9Zy5vKWlmKGQrKyxnPT1hJiYoZT1mKSwwPD1lJiYxPGQpYnJlYWs7MDw9ZSYmKGMuTj09cWImJjE9PWQ/eGIoYyxiKTooZD1jLkJhLnNwbGljZShlLDEpWzBdLHliKGMsZCx2YixiKSkpfWEuSGE9bnVsbH1lbHNlIHNiKGEsdmIsYil9ZnVuY3Rpb24gemIoYSxiKXthLkJhJiZhLkJhLmxlbmd0aHx8YS5OIT10YiYmYS5OIT12Ynx8QWIoYSk7YS5CYXx8KGEuQmE9W10pO2EuQmEucHVzaChiKX1cbmZ1bmN0aW9uIHdiKGEsYixjLGQpe3ZhciBlPXtvOm51bGwsSGY6bnVsbCxKZjpudWxsfTtlLm89bmV3IHBiKGZ1bmN0aW9uKGEsZyl7ZS5IZj1iP2Z1bmN0aW9uKGMpe3RyeXt2YXIgZT1iLmNhbGwoZCxjKTthKGUpfWNhdGNoKGwpe2cobCl9fTphO2UuSmY9Yz9mdW5jdGlvbihiKXt0cnl7dmFyIGU9Yy5jYWxsKGQsYik7IXAoZSkmJmIgaW5zdGFuY2VvZiB1Yj9nKGIpOmEoZSl9Y2F0Y2gobCl7ZyhsKX19Omd9KTtlLm8uSGE9YTt6YihhLGUpO3JldHVybiBlLm99aC5ZZj1mdW5jdGlvbihhKXt0aGlzLk49cWI7c2IodGhpcyx0YixhKX07aC5aZj1mdW5jdGlvbihhKXt0aGlzLk49cWI7c2IodGhpcyx2YixhKX07XG5mdW5jdGlvbiBzYihhLGIsYyl7aWYoYS5OPT1xYil7aWYoYT09YyliPXZiLGM9bmV3IFR5cGVFcnJvcihcIlByb21pc2UgY2Fubm90IHJlc29sdmUgdG8gaXRzZWxmXCIpO2Vsc2V7dmFyIGQ7aWYoYyl0cnl7ZD0hIWMuJGdvb2dfVGhlbmFibGV9Y2F0Y2goZSl7ZD0hMX1lbHNlIGQ9ITE7aWYoZCl7YS5OPTE7Yy50aGVuKGEuWWYsYS5aZixhKTtyZXR1cm59aWYoZ2EoYykpdHJ5e3ZhciBmPWMudGhlbjtpZihyKGYpKXtCYihhLGMsZik7cmV0dXJufX1jYXRjaChnKXtiPXZiLGM9Z319YS5SZj1jO2EuTj1iO2EuSGE9bnVsbDtBYihhKTtiIT12Ynx8YyBpbnN0YW5jZW9mIHVifHxDYihhLGMpfX1mdW5jdGlvbiBCYihhLGIsYyl7ZnVuY3Rpb24gZChiKXtmfHwoZj0hMCxhLlpmKGIpKX1mdW5jdGlvbiBlKGIpe2Z8fChmPSEwLGEuWWYoYikpfWEuTj0xO3ZhciBmPSExO3RyeXtjLmNhbGwoYixlLGQpfWNhdGNoKGcpe2QoZyl9fVxuZnVuY3Rpb24gQWIoYSl7YS55ZXx8KGEueWU9ITAsJGEoYS53ZyxhKSl9aC53Zz1mdW5jdGlvbigpe2Zvcig7dGhpcy5CYSYmdGhpcy5CYS5sZW5ndGg7KXt2YXIgYT10aGlzLkJhO3RoaXMuQmE9bnVsbDtmb3IodmFyIGI9MDtiPGEubGVuZ3RoO2IrKyl5Yih0aGlzLGFbYl0sdGhpcy5OLHRoaXMuUmYpfXRoaXMueWU9ITF9O2Z1bmN0aW9uIHliKGEsYixjLGQpe2lmKGM9PXRiKWIuSGYoZCk7ZWxzZXtpZihiLm8pZm9yKDthJiZhLnlkO2E9YS5IYSlhLnlkPSExO2IuSmYoZCl9fWZ1bmN0aW9uIENiKGEsYil7YS55ZD0hMDskYShmdW5jdGlvbigpe2EueWQmJkRiLmNhbGwobnVsbCxiKX0pfXZhciBEYj1YYTtmdW5jdGlvbiB1YihhKXtsYS5jYWxsKHRoaXMsYSl9a2EodWIsbGEpO3ViLnByb3RvdHlwZS5uYW1lPVwiY2FuY2VsXCI7dmFyIEViPUVifHxcIjIuNC4yXCI7ZnVuY3Rpb24geShhLGIpe3JldHVybiBPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwoYSxiKX1mdW5jdGlvbiB6KGEsYil7aWYoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKGEsYikpcmV0dXJuIGFbYl19ZnVuY3Rpb24gRmIoYSxiKXtmb3IodmFyIGMgaW4gYSlPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwoYSxjKSYmYihjLGFbY10pfWZ1bmN0aW9uIEdiKGEpe3ZhciBiPXt9O0ZiKGEsZnVuY3Rpb24oYSxkKXtiW2FdPWR9KTtyZXR1cm4gYn1mdW5jdGlvbiBIYihhKXtyZXR1cm5cIm9iamVjdFwiPT09dHlwZW9mIGEmJm51bGwhPT1hfTtmdW5jdGlvbiBJYihhKXt2YXIgYj1bXTtGYihhLGZ1bmN0aW9uKGEsZCl7ZGEoZCk/TWEoZCxmdW5jdGlvbihkKXtiLnB1c2goZW5jb2RlVVJJQ29tcG9uZW50KGEpK1wiPVwiK2VuY29kZVVSSUNvbXBvbmVudChkKSl9KTpiLnB1c2goZW5jb2RlVVJJQ29tcG9uZW50KGEpK1wiPVwiK2VuY29kZVVSSUNvbXBvbmVudChkKSl9KTtyZXR1cm4gYi5sZW5ndGg/XCImXCIrYi5qb2luKFwiJlwiKTpcIlwifWZ1bmN0aW9uIEpiKGEpe3ZhciBiPXt9O2E9YS5yZXBsYWNlKC9eXFw/LyxcIlwiKS5zcGxpdChcIiZcIik7TWEoYSxmdW5jdGlvbihhKXthJiYoYT1hLnNwbGl0KFwiPVwiKSxiW2FbMF1dPWFbMV0pfSk7cmV0dXJuIGJ9O2Z1bmN0aW9uIEtiKGEsYil7aWYoIWEpdGhyb3cgTGIoYik7fWZ1bmN0aW9uIExiKGEpe3JldHVybiBFcnJvcihcIkZpcmViYXNlIChcIitFYitcIikgSU5URVJOQUwgQVNTRVJUIEZBSUxFRDogXCIrYSl9O3ZhciBNYj1uLlByb21pc2V8fHBiO3BiLnByb3RvdHlwZVtcImNhdGNoXCJdPXBiLnByb3RvdHlwZS5naDtmdW5jdGlvbiBCKCl7dmFyIGE9dGhpczt0aGlzLnJlamVjdD10aGlzLnJlc29sdmU9bnVsbDt0aGlzLkQ9bmV3IE1iKGZ1bmN0aW9uKGIsYyl7YS5yZXNvbHZlPWI7YS5yZWplY3Q9Y30pfWZ1bmN0aW9uIEMoYSxiKXtyZXR1cm4gZnVuY3Rpb24oYyxkKXtjP2EucmVqZWN0KGMpOmEucmVzb2x2ZShkKTtyKGIpJiYoTmIoYS5EKSwxPT09Yi5sZW5ndGg/YihjKTpiKGMsZCkpfX1mdW5jdGlvbiBOYihhKXthLnRoZW4odm9pZCAwLGFhKX07ZnVuY3Rpb24gT2IoYSl7Zm9yKHZhciBiPVtdLGM9MCxkPTA7ZDxhLmxlbmd0aDtkKyspe3ZhciBlPWEuY2hhckNvZGVBdChkKTs1NTI5Njw9ZSYmNTYzMTk+PWUmJihlLT01NTI5NixkKyssS2IoZDxhLmxlbmd0aCxcIlN1cnJvZ2F0ZSBwYWlyIG1pc3NpbmcgdHJhaWwgc3Vycm9nYXRlLlwiKSxlPTY1NTM2KyhlPDwxMCkrKGEuY2hhckNvZGVBdChkKS01NjMyMCkpOzEyOD5lP2JbYysrXT1lOigyMDQ4PmU/YltjKytdPWU+PjZ8MTkyOig2NTUzNj5lP2JbYysrXT1lPj4xMnwyMjQ6KGJbYysrXT1lPj4xOHwyNDAsYltjKytdPWU+PjEyJjYzfDEyOCksYltjKytdPWU+PjYmNjN8MTI4KSxiW2MrK109ZSY2M3wxMjgpfXJldHVybiBifWZ1bmN0aW9uIFBiKGEpe2Zvcih2YXIgYj0wLGM9MDtjPGEubGVuZ3RoO2MrKyl7dmFyIGQ9YS5jaGFyQ29kZUF0KGMpOzEyOD5kP2IrKzoyMDQ4PmQ/Yis9Mjo1NTI5Njw9ZCYmNTYzMTk+PWQ/KGIrPTQsYysrKTpiKz0zfXJldHVybiBifTtmdW5jdGlvbiBEKGEsYixjLGQpe3ZhciBlO2Q8Yj9lPVwiYXQgbGVhc3QgXCIrYjpkPmMmJihlPTA9PT1jP1wibm9uZVwiOlwibm8gbW9yZSB0aGFuIFwiK2MpO2lmKGUpdGhyb3cgRXJyb3IoYStcIiBmYWlsZWQ6IFdhcyBjYWxsZWQgd2l0aCBcIitkKygxPT09ZD9cIiBhcmd1bWVudC5cIjpcIiBhcmd1bWVudHMuXCIpK1wiIEV4cGVjdHMgXCIrZStcIi5cIik7fWZ1bmN0aW9uIEUoYSxiLGMpe3ZhciBkPVwiXCI7c3dpdGNoKGIpe2Nhc2UgMTpkPWM/XCJmaXJzdFwiOlwiRmlyc3RcIjticmVhaztjYXNlIDI6ZD1jP1wic2Vjb25kXCI6XCJTZWNvbmRcIjticmVhaztjYXNlIDM6ZD1jP1widGhpcmRcIjpcIlRoaXJkXCI7YnJlYWs7Y2FzZSA0OmQ9Yz9cImZvdXJ0aFwiOlwiRm91cnRoXCI7YnJlYWs7ZGVmYXVsdDp0aHJvdyBFcnJvcihcImVycm9yUHJlZml4IGNhbGxlZCB3aXRoIGFyZ3VtZW50TnVtYmVyID4gNC4gIE5lZWQgdG8gdXBkYXRlIGl0P1wiKTt9cmV0dXJuIGE9YStcIiBmYWlsZWQ6IFwiKyhkK1wiIGFyZ3VtZW50IFwiKX1cbmZ1bmN0aW9uIEYoYSxiLGMsZCl7aWYoKCFkfHxwKGMpKSYmIXIoYykpdGhyb3cgRXJyb3IoRShhLGIsZCkrXCJtdXN0IGJlIGEgdmFsaWQgZnVuY3Rpb24uXCIpO31mdW5jdGlvbiBRYihhLGIsYyl7aWYocChjKSYmKCFnYShjKXx8bnVsbD09PWMpKXRocm93IEVycm9yKEUoYSxiLCEwKStcIm11c3QgYmUgYSB2YWxpZCBjb250ZXh0IG9iamVjdC5cIik7fTtmdW5jdGlvbiBSYihhKXtyZXR1cm5cInVuZGVmaW5lZFwiIT09dHlwZW9mIEpTT04mJnAoSlNPTi5wYXJzZSk/SlNPTi5wYXJzZShhKTp6YShhKX1mdW5jdGlvbiBHKGEpe2lmKFwidW5kZWZpbmVkXCIhPT10eXBlb2YgSlNPTiYmcChKU09OLnN0cmluZ2lmeSkpYT1KU09OLnN0cmluZ2lmeShhKTtlbHNle3ZhciBiPVtdO0JhKG5ldyBBYSxhLGIpO2E9Yi5qb2luKFwiXCIpfXJldHVybiBhfTtmdW5jdGlvbiBTYigpe3RoaXMuWmQ9SH1TYi5wcm90b3R5cGUuaj1mdW5jdGlvbihhKXtyZXR1cm4gdGhpcy5aZC5TKGEpfTtTYi5wcm90b3R5cGUudG9TdHJpbmc9ZnVuY3Rpb24oKXtyZXR1cm4gdGhpcy5aZC50b1N0cmluZygpfTtmdW5jdGlvbiBUYigpe31UYi5wcm90b3R5cGUudWY9ZnVuY3Rpb24oKXtyZXR1cm4gbnVsbH07VGIucHJvdG90eXBlLkNlPWZ1bmN0aW9uKCl7cmV0dXJuIG51bGx9O3ZhciBVYj1uZXcgVGI7ZnVuY3Rpb24gVmIoYSxiLGMpe3RoaXMuYmc9YTt0aGlzLk9hPWI7dGhpcy5OZD1jfVZiLnByb3RvdHlwZS51Zj1mdW5jdGlvbihhKXt2YXIgYj10aGlzLk9hLlE7aWYoV2IoYixhKSlyZXR1cm4gYi5qKCkuVChhKTtiPW51bGwhPXRoaXMuTmQ/bmV3IFhiKHRoaXMuTmQsITAsITEpOnRoaXMuT2EudygpO3JldHVybiB0aGlzLmJnLkJjKGEsYil9O1ZiLnByb3RvdHlwZS5DZT1mdW5jdGlvbihhLGIsYyl7dmFyIGQ9bnVsbCE9dGhpcy5OZD90aGlzLk5kOlliKHRoaXMuT2EpO2E9dGhpcy5iZy5xZShkLGIsMSxjLGEpO3JldHVybiAwPT09YS5sZW5ndGg/bnVsbDphWzBdfTtmdW5jdGlvbiBaYigpe3RoaXMueGI9W119ZnVuY3Rpb24gJGIoYSxiKXtmb3IodmFyIGM9bnVsbCxkPTA7ZDxiLmxlbmd0aDtkKyspe3ZhciBlPWJbZF0sZj1lLmNjKCk7bnVsbD09PWN8fGYuZWEoYy5jYygpKXx8KGEueGIucHVzaChjKSxjPW51bGwpO251bGw9PT1jJiYoYz1uZXcgYWMoZikpO2MuYWRkKGUpfWMmJmEueGIucHVzaChjKX1mdW5jdGlvbiBiYyhhLGIsYyl7JGIoYSxjKTtjYyhhLGZ1bmN0aW9uKGEpe3JldHVybiBhLmVhKGIpfSl9ZnVuY3Rpb24gZGMoYSxiLGMpeyRiKGEsYyk7Y2MoYSxmdW5jdGlvbihhKXtyZXR1cm4gYS5jb250YWlucyhiKXx8Yi5jb250YWlucyhhKX0pfVxuZnVuY3Rpb24gY2MoYSxiKXtmb3IodmFyIGM9ITAsZD0wO2Q8YS54Yi5sZW5ndGg7ZCsrKXt2YXIgZT1hLnhiW2RdO2lmKGUpaWYoZT1lLmNjKCksYihlKSl7Zm9yKHZhciBlPWEueGJbZF0sZj0wO2Y8ZS54ZC5sZW5ndGg7ZisrKXt2YXIgZz1lLnhkW2ZdO2lmKG51bGwhPT1nKXtlLnhkW2ZdPW51bGw7dmFyIGs9Zy5aYigpO2VjJiZmYyhcImV2ZW50OiBcIitnLnRvU3RyaW5nKCkpO2djKGspfX1hLnhiW2RdPW51bGx9ZWxzZSBjPSExfWMmJihhLnhiPVtdKX1mdW5jdGlvbiBhYyhhKXt0aGlzLnRhPWE7dGhpcy54ZD1bXX1hYy5wcm90b3R5cGUuYWRkPWZ1bmN0aW9uKGEpe3RoaXMueGQucHVzaChhKX07YWMucHJvdG90eXBlLmNjPWZ1bmN0aW9uKCl7cmV0dXJuIHRoaXMudGF9O2Z1bmN0aW9uIEooYSxiLGMsZCl7dGhpcy50eXBlPWE7dGhpcy5OYT1iO3RoaXMuWmE9Yzt0aGlzLk9lPWQ7dGhpcy5UZD12b2lkIDB9ZnVuY3Rpb24gaGMoYSl7cmV0dXJuIG5ldyBKKGljLGEpfXZhciBpYz1cInZhbHVlXCI7ZnVuY3Rpb24gamMoYSxiLGMsZCl7dGhpcy54ZT1iO3RoaXMuYmU9Yzt0aGlzLlRkPWQ7dGhpcy53ZD1hfWpjLnByb3RvdHlwZS5jYz1mdW5jdGlvbigpe3ZhciBhPXRoaXMuYmUuTWIoKTtyZXR1cm5cInZhbHVlXCI9PT10aGlzLndkP2EucGF0aDphLnBhcmVudCgpLnBhdGh9O2pjLnByb3RvdHlwZS5EZT1mdW5jdGlvbigpe3JldHVybiB0aGlzLndkfTtqYy5wcm90b3R5cGUuWmI9ZnVuY3Rpb24oKXtyZXR1cm4gdGhpcy54ZS5aYih0aGlzKX07amMucHJvdG90eXBlLnRvU3RyaW5nPWZ1bmN0aW9uKCl7cmV0dXJuIHRoaXMuY2MoKS50b1N0cmluZygpK1wiOlwiK3RoaXMud2QrXCI6XCIrRyh0aGlzLmJlLnFmKCkpfTtmdW5jdGlvbiBrYyhhLGIsYyl7dGhpcy54ZT1hO3RoaXMuZXJyb3I9Yjt0aGlzLnBhdGg9Y31rYy5wcm90b3R5cGUuY2M9ZnVuY3Rpb24oKXtyZXR1cm4gdGhpcy5wYXRofTtrYy5wcm90b3R5cGUuRGU9ZnVuY3Rpb24oKXtyZXR1cm5cImNhbmNlbFwifTtcbmtjLnByb3RvdHlwZS5aYj1mdW5jdGlvbigpe3JldHVybiB0aGlzLnhlLlpiKHRoaXMpfTtrYy5wcm90b3R5cGUudG9TdHJpbmc9ZnVuY3Rpb24oKXtyZXR1cm4gdGhpcy5wYXRoLnRvU3RyaW5nKCkrXCI6Y2FuY2VsXCJ9O2Z1bmN0aW9uIFhiKGEsYixjKXt0aGlzLkE9YTt0aGlzLmdhPWI7dGhpcy5ZYj1jfWZ1bmN0aW9uIGxjKGEpe3JldHVybiBhLmdhfWZ1bmN0aW9uIG1jKGEpe3JldHVybiBhLllifWZ1bmN0aW9uIG5jKGEsYil7cmV0dXJuIGIuZSgpP2EuZ2EmJiFhLlliOldiKGEsSyhiKSl9ZnVuY3Rpb24gV2IoYSxiKXtyZXR1cm4gYS5nYSYmIWEuWWJ8fGEuQS5GYShiKX1YYi5wcm90b3R5cGUuaj1mdW5jdGlvbigpe3JldHVybiB0aGlzLkF9O2Z1bmN0aW9uIG9jKGEpe3RoaXMucGc9YTt0aGlzLkdkPW51bGx9b2MucHJvdG90eXBlLmdldD1mdW5jdGlvbigpe3ZhciBhPXRoaXMucGcuZ2V0KCksYj13YShhKTtpZih0aGlzLkdkKWZvcih2YXIgYyBpbiB0aGlzLkdkKWJbY10tPXRoaXMuR2RbY107dGhpcy5HZD1hO3JldHVybiBifTtmdW5jdGlvbiBwYyhhLGIpe3RoaXMuVmY9e307dGhpcy5oZD1uZXcgb2MoYSk7dGhpcy5kYT1iO3ZhciBjPTFFNCsyRTQqTWF0aC5yYW5kb20oKTtzZXRUaW1lb3V0KHUodGhpcy5PZix0aGlzKSxNYXRoLmZsb29yKGMpKX1wYy5wcm90b3R5cGUuT2Y9ZnVuY3Rpb24oKXt2YXIgYT10aGlzLmhkLmdldCgpLGI9e30sYz0hMSxkO2ZvcihkIGluIGEpMDxhW2RdJiZ5KHRoaXMuVmYsZCkmJihiW2RdPWFbZF0sYz0hMCk7YyYmdGhpcy5kYS5ZZShiKTtzZXRUaW1lb3V0KHUodGhpcy5PZix0aGlzKSxNYXRoLmZsb29yKDZFNSpNYXRoLnJhbmRvbSgpKSl9O2Z1bmN0aW9uIHFjKCl7dGhpcy5IYz17fX1mdW5jdGlvbiByYyhhLGIsYyl7cChjKXx8KGM9MSk7eShhLkhjLGIpfHwoYS5IY1tiXT0wKTthLkhjW2JdKz1jfXFjLnByb3RvdHlwZS5nZXQ9ZnVuY3Rpb24oKXtyZXR1cm4gd2EodGhpcy5IYyl9O3ZhciBzYz17fSx0Yz17fTtmdW5jdGlvbiB1YyhhKXthPWEudG9TdHJpbmcoKTtzY1thXXx8KHNjW2FdPW5ldyBxYyk7cmV0dXJuIHNjW2FdfWZ1bmN0aW9uIHZjKGEsYil7dmFyIGM9YS50b1N0cmluZygpO3RjW2NdfHwodGNbY109YigpKTtyZXR1cm4gdGNbY119O2Z1bmN0aW9uIEwoYSxiKXt0aGlzLm5hbWU9YTt0aGlzLlU9Yn1mdW5jdGlvbiB3YyhhLGIpe3JldHVybiBuZXcgTChhLGIpfTtmdW5jdGlvbiB4YyhhLGIpe3JldHVybiB5YyhhLm5hbWUsYi5uYW1lKX1mdW5jdGlvbiB6YyhhLGIpe3JldHVybiB5YyhhLGIpfTtmdW5jdGlvbiBBYyhhLGIsYyl7dGhpcy50eXBlPUJjO3RoaXMuc291cmNlPWE7dGhpcy5wYXRoPWI7dGhpcy5KYT1jfUFjLnByb3RvdHlwZS4kYz1mdW5jdGlvbihhKXtyZXR1cm4gdGhpcy5wYXRoLmUoKT9uZXcgQWModGhpcy5zb3VyY2UsTSx0aGlzLkphLlQoYSkpOm5ldyBBYyh0aGlzLnNvdXJjZSxOKHRoaXMucGF0aCksdGhpcy5KYSl9O0FjLnByb3RvdHlwZS50b1N0cmluZz1mdW5jdGlvbigpe3JldHVyblwiT3BlcmF0aW9uKFwiK3RoaXMucGF0aCtcIjogXCIrdGhpcy5zb3VyY2UudG9TdHJpbmcoKStcIiBvdmVyd3JpdGU6IFwiK3RoaXMuSmEudG9TdHJpbmcoKStcIilcIn07ZnVuY3Rpb24gQ2MoYSxiKXt0aGlzLnR5cGU9RGM7dGhpcy5zb3VyY2U9YTt0aGlzLnBhdGg9Yn1DYy5wcm90b3R5cGUuJGM9ZnVuY3Rpb24oKXtyZXR1cm4gdGhpcy5wYXRoLmUoKT9uZXcgQ2ModGhpcy5zb3VyY2UsTSk6bmV3IENjKHRoaXMuc291cmNlLE4odGhpcy5wYXRoKSl9O0NjLnByb3RvdHlwZS50b1N0cmluZz1mdW5jdGlvbigpe3JldHVyblwiT3BlcmF0aW9uKFwiK3RoaXMucGF0aCtcIjogXCIrdGhpcy5zb3VyY2UudG9TdHJpbmcoKStcIiBsaXN0ZW5fY29tcGxldGUpXCJ9O2Z1bmN0aW9uIEVjKGEsYil7dGhpcy5QYT1hO3RoaXMueGE9Yj9iOkZjfWg9RWMucHJvdG90eXBlO2guU2E9ZnVuY3Rpb24oYSxiKXtyZXR1cm4gbmV3IEVjKHRoaXMuUGEsdGhpcy54YS5TYShhLGIsdGhpcy5QYSkuJChudWxsLG51bGwsITEsbnVsbCxudWxsKSl9O2gucmVtb3ZlPWZ1bmN0aW9uKGEpe3JldHVybiBuZXcgRWModGhpcy5QYSx0aGlzLnhhLnJlbW92ZShhLHRoaXMuUGEpLiQobnVsbCxudWxsLCExLG51bGwsbnVsbCkpfTtoLmdldD1mdW5jdGlvbihhKXtmb3IodmFyIGIsYz10aGlzLnhhOyFjLmUoKTspe2I9dGhpcy5QYShhLGMua2V5KTtpZigwPT09YilyZXR1cm4gYy52YWx1ZTswPmI/Yz1jLmxlZnQ6MDxiJiYoYz1jLnJpZ2h0KX1yZXR1cm4gbnVsbH07XG5mdW5jdGlvbiBHYyhhLGIpe2Zvcih2YXIgYyxkPWEueGEsZT1udWxsOyFkLmUoKTspe2M9YS5QYShiLGQua2V5KTtpZigwPT09Yyl7aWYoZC5sZWZ0LmUoKSlyZXR1cm4gZT9lLmtleTpudWxsO2ZvcihkPWQubGVmdDshZC5yaWdodC5lKCk7KWQ9ZC5yaWdodDtyZXR1cm4gZC5rZXl9MD5jP2Q9ZC5sZWZ0OjA8YyYmKGU9ZCxkPWQucmlnaHQpfXRocm93IEVycm9yKFwiQXR0ZW1wdGVkIHRvIGZpbmQgcHJlZGVjZXNzb3Iga2V5IGZvciBhIG5vbmV4aXN0ZW50IGtleS4gIFdoYXQgZ2l2ZXM/XCIpO31oLmU9ZnVuY3Rpb24oKXtyZXR1cm4gdGhpcy54YS5lKCl9O2guY291bnQ9ZnVuY3Rpb24oKXtyZXR1cm4gdGhpcy54YS5jb3VudCgpfTtoLlZjPWZ1bmN0aW9uKCl7cmV0dXJuIHRoaXMueGEuVmMoKX07aC5qYz1mdW5jdGlvbigpe3JldHVybiB0aGlzLnhhLmpjKCl9O2gua2E9ZnVuY3Rpb24oYSl7cmV0dXJuIHRoaXMueGEua2EoYSl9O1xuaC5hYz1mdW5jdGlvbihhKXtyZXR1cm4gbmV3IEhjKHRoaXMueGEsbnVsbCx0aGlzLlBhLCExLGEpfTtoLmJjPWZ1bmN0aW9uKGEsYil7cmV0dXJuIG5ldyBIYyh0aGlzLnhhLGEsdGhpcy5QYSwhMSxiKX07aC5kYz1mdW5jdGlvbihhLGIpe3JldHVybiBuZXcgSGModGhpcy54YSxhLHRoaXMuUGEsITAsYil9O2gueGY9ZnVuY3Rpb24oYSl7cmV0dXJuIG5ldyBIYyh0aGlzLnhhLG51bGwsdGhpcy5QYSwhMCxhKX07ZnVuY3Rpb24gSGMoYSxiLGMsZCxlKXt0aGlzLlhkPWV8fG51bGw7dGhpcy5KZT1kO3RoaXMuVGE9W107Zm9yKGU9MTshYS5lKCk7KWlmKGU9Yj9jKGEua2V5LGIpOjEsZCYmKGUqPS0xKSwwPmUpYT10aGlzLkplP2EubGVmdDphLnJpZ2h0O2Vsc2UgaWYoMD09PWUpe3RoaXMuVGEucHVzaChhKTticmVha31lbHNlIHRoaXMuVGEucHVzaChhKSxhPXRoaXMuSmU/YS5yaWdodDphLmxlZnR9XG5mdW5jdGlvbiBJYyhhKXtpZigwPT09YS5UYS5sZW5ndGgpcmV0dXJuIG51bGw7dmFyIGI9YS5UYS5wb3AoKSxjO2M9YS5YZD9hLlhkKGIua2V5LGIudmFsdWUpOntrZXk6Yi5rZXksdmFsdWU6Yi52YWx1ZX07aWYoYS5KZSlmb3IoYj1iLmxlZnQ7IWIuZSgpOylhLlRhLnB1c2goYiksYj1iLnJpZ2h0O2Vsc2UgZm9yKGI9Yi5yaWdodDshYi5lKCk7KWEuVGEucHVzaChiKSxiPWIubGVmdDtyZXR1cm4gY31mdW5jdGlvbiBKYyhhKXtpZigwPT09YS5UYS5sZW5ndGgpcmV0dXJuIG51bGw7dmFyIGI7Yj1hLlRhO2I9YltiLmxlbmd0aC0xXTtyZXR1cm4gYS5YZD9hLlhkKGIua2V5LGIudmFsdWUpOntrZXk6Yi5rZXksdmFsdWU6Yi52YWx1ZX19ZnVuY3Rpb24gS2MoYSxiLGMsZCxlKXt0aGlzLmtleT1hO3RoaXMudmFsdWU9Yjt0aGlzLmNvbG9yPW51bGwhPWM/YzohMDt0aGlzLmxlZnQ9bnVsbCE9ZD9kOkZjO3RoaXMucmlnaHQ9bnVsbCE9ZT9lOkZjfWg9S2MucHJvdG90eXBlO1xuaC4kPWZ1bmN0aW9uKGEsYixjLGQsZSl7cmV0dXJuIG5ldyBLYyhudWxsIT1hP2E6dGhpcy5rZXksbnVsbCE9Yj9iOnRoaXMudmFsdWUsbnVsbCE9Yz9jOnRoaXMuY29sb3IsbnVsbCE9ZD9kOnRoaXMubGVmdCxudWxsIT1lP2U6dGhpcy5yaWdodCl9O2guY291bnQ9ZnVuY3Rpb24oKXtyZXR1cm4gdGhpcy5sZWZ0LmNvdW50KCkrMSt0aGlzLnJpZ2h0LmNvdW50KCl9O2guZT1mdW5jdGlvbigpe3JldHVybiExfTtoLmthPWZ1bmN0aW9uKGEpe3JldHVybiB0aGlzLmxlZnQua2EoYSl8fGEodGhpcy5rZXksdGhpcy52YWx1ZSl8fHRoaXMucmlnaHQua2EoYSl9O2Z1bmN0aW9uIExjKGEpe3JldHVybiBhLmxlZnQuZSgpP2E6TGMoYS5sZWZ0KX1oLlZjPWZ1bmN0aW9uKCl7cmV0dXJuIExjKHRoaXMpLmtleX07aC5qYz1mdW5jdGlvbigpe3JldHVybiB0aGlzLnJpZ2h0LmUoKT90aGlzLmtleTp0aGlzLnJpZ2h0LmpjKCl9O1xuaC5TYT1mdW5jdGlvbihhLGIsYyl7dmFyIGQsZTtlPXRoaXM7ZD1jKGEsZS5rZXkpO2U9MD5kP2UuJChudWxsLG51bGwsbnVsbCxlLmxlZnQuU2EoYSxiLGMpLG51bGwpOjA9PT1kP2UuJChudWxsLGIsbnVsbCxudWxsLG51bGwpOmUuJChudWxsLG51bGwsbnVsbCxudWxsLGUucmlnaHQuU2EoYSxiLGMpKTtyZXR1cm4gTWMoZSl9O2Z1bmN0aW9uIE5jKGEpe2lmKGEubGVmdC5lKCkpcmV0dXJuIEZjO2EubGVmdC5oYSgpfHxhLmxlZnQubGVmdC5oYSgpfHwoYT1PYyhhKSk7YT1hLiQobnVsbCxudWxsLG51bGwsTmMoYS5sZWZ0KSxudWxsKTtyZXR1cm4gTWMoYSl9XG5oLnJlbW92ZT1mdW5jdGlvbihhLGIpe3ZhciBjLGQ7Yz10aGlzO2lmKDA+YihhLGMua2V5KSljLmxlZnQuZSgpfHxjLmxlZnQuaGEoKXx8Yy5sZWZ0LmxlZnQuaGEoKXx8KGM9T2MoYykpLGM9Yy4kKG51bGwsbnVsbCxudWxsLGMubGVmdC5yZW1vdmUoYSxiKSxudWxsKTtlbHNle2MubGVmdC5oYSgpJiYoYz1QYyhjKSk7Yy5yaWdodC5lKCl8fGMucmlnaHQuaGEoKXx8Yy5yaWdodC5sZWZ0LmhhKCl8fChjPVFjKGMpLGMubGVmdC5sZWZ0LmhhKCkmJihjPVBjKGMpLGM9UWMoYykpKTtpZigwPT09YihhLGMua2V5KSl7aWYoYy5yaWdodC5lKCkpcmV0dXJuIEZjO2Q9TGMoYy5yaWdodCk7Yz1jLiQoZC5rZXksZC52YWx1ZSxudWxsLG51bGwsTmMoYy5yaWdodCkpfWM9Yy4kKG51bGwsbnVsbCxudWxsLG51bGwsYy5yaWdodC5yZW1vdmUoYSxiKSl9cmV0dXJuIE1jKGMpfTtoLmhhPWZ1bmN0aW9uKCl7cmV0dXJuIHRoaXMuY29sb3J9O1xuZnVuY3Rpb24gTWMoYSl7YS5yaWdodC5oYSgpJiYhYS5sZWZ0LmhhKCkmJihhPVJjKGEpKTthLmxlZnQuaGEoKSYmYS5sZWZ0LmxlZnQuaGEoKSYmKGE9UGMoYSkpO2EubGVmdC5oYSgpJiZhLnJpZ2h0LmhhKCkmJihhPVFjKGEpKTtyZXR1cm4gYX1mdW5jdGlvbiBPYyhhKXthPVFjKGEpO2EucmlnaHQubGVmdC5oYSgpJiYoYT1hLiQobnVsbCxudWxsLG51bGwsbnVsbCxQYyhhLnJpZ2h0KSksYT1SYyhhKSxhPVFjKGEpKTtyZXR1cm4gYX1mdW5jdGlvbiBSYyhhKXtyZXR1cm4gYS5yaWdodC4kKG51bGwsbnVsbCxhLmNvbG9yLGEuJChudWxsLG51bGwsITAsbnVsbCxhLnJpZ2h0LmxlZnQpLG51bGwpfWZ1bmN0aW9uIFBjKGEpe3JldHVybiBhLmxlZnQuJChudWxsLG51bGwsYS5jb2xvcixudWxsLGEuJChudWxsLG51bGwsITAsYS5sZWZ0LnJpZ2h0LG51bGwpKX1cbmZ1bmN0aW9uIFFjKGEpe3JldHVybiBhLiQobnVsbCxudWxsLCFhLmNvbG9yLGEubGVmdC4kKG51bGwsbnVsbCwhYS5sZWZ0LmNvbG9yLG51bGwsbnVsbCksYS5yaWdodC4kKG51bGwsbnVsbCwhYS5yaWdodC5jb2xvcixudWxsLG51bGwpKX1mdW5jdGlvbiBTYygpe31oPVNjLnByb3RvdHlwZTtoLiQ9ZnVuY3Rpb24oKXtyZXR1cm4gdGhpc307aC5TYT1mdW5jdGlvbihhLGIpe3JldHVybiBuZXcgS2MoYSxiLG51bGwpfTtoLnJlbW92ZT1mdW5jdGlvbigpe3JldHVybiB0aGlzfTtoLmNvdW50PWZ1bmN0aW9uKCl7cmV0dXJuIDB9O2guZT1mdW5jdGlvbigpe3JldHVybiEwfTtoLmthPWZ1bmN0aW9uKCl7cmV0dXJuITF9O2guVmM9ZnVuY3Rpb24oKXtyZXR1cm4gbnVsbH07aC5qYz1mdW5jdGlvbigpe3JldHVybiBudWxsfTtoLmhhPWZ1bmN0aW9uKCl7cmV0dXJuITF9O3ZhciBGYz1uZXcgU2M7ZnVuY3Rpb24gVGMoYSxiKXtyZXR1cm4gYSYmXCJvYmplY3RcIj09PXR5cGVvZiBhPyhPKFwiLnN2XCJpbiBhLFwiVW5leHBlY3RlZCBsZWFmIG5vZGUgb3IgcHJpb3JpdHkgY29udGVudHNcIiksYlthW1wiLnN2XCJdXSk6YX1mdW5jdGlvbiBVYyhhLGIpe3ZhciBjPW5ldyBWYztXYyhhLG5ldyBQKFwiXCIpLGZ1bmN0aW9uKGEsZSl7Yy5yYyhhLFhjKGUsYikpfSk7cmV0dXJuIGN9ZnVuY3Rpb24gWGMoYSxiKXt2YXIgYz1hLkMoKS5KKCksYz1UYyhjLGIpLGQ7aWYoYS5MKCkpe3ZhciBlPVRjKGEuRWEoKSxiKTtyZXR1cm4gZSE9PWEuRWEoKXx8YyE9PWEuQygpLkooKT9uZXcgWWMoZSxRKGMpKTphfWQ9YTtjIT09YS5DKCkuSigpJiYoZD1kLmlhKG5ldyBZYyhjKSkpO2EuUihSLGZ1bmN0aW9uKGEsYyl7dmFyIGU9WGMoYyxiKTtlIT09YyYmKGQ9ZC5XKGEsZSkpfSk7cmV0dXJuIGR9O2Z1bmN0aW9uIFpjKCl7dGhpcy5BYz17fX1aYy5wcm90b3R5cGUuc2V0PWZ1bmN0aW9uKGEsYil7bnVsbD09Yj9kZWxldGUgdGhpcy5BY1thXTp0aGlzLkFjW2FdPWJ9O1pjLnByb3RvdHlwZS5nZXQ9ZnVuY3Rpb24oYSl7cmV0dXJuIHkodGhpcy5BYyxhKT90aGlzLkFjW2FdOm51bGx9O1pjLnByb3RvdHlwZS5yZW1vdmU9ZnVuY3Rpb24oYSl7ZGVsZXRlIHRoaXMuQWNbYV19O1pjLnByb3RvdHlwZS5BZj0hMDtmdW5jdGlvbiAkYyhhKXt0aGlzLkljPWE7dGhpcy5TZD1cImZpcmViYXNlOlwifWg9JGMucHJvdG90eXBlO2guc2V0PWZ1bmN0aW9uKGEsYil7bnVsbD09Yj90aGlzLkljLnJlbW92ZUl0ZW0odGhpcy5TZCthKTp0aGlzLkljLnNldEl0ZW0odGhpcy5TZCthLEcoYikpfTtoLmdldD1mdW5jdGlvbihhKXthPXRoaXMuSWMuZ2V0SXRlbSh0aGlzLlNkK2EpO3JldHVybiBudWxsPT1hP251bGw6UmIoYSl9O2gucmVtb3ZlPWZ1bmN0aW9uKGEpe3RoaXMuSWMucmVtb3ZlSXRlbSh0aGlzLlNkK2EpfTtoLkFmPSExO2gudG9TdHJpbmc9ZnVuY3Rpb24oKXtyZXR1cm4gdGhpcy5JYy50b1N0cmluZygpfTtmdW5jdGlvbiBhZChhKXt0cnl7aWYoXCJ1bmRlZmluZWRcIiE9PXR5cGVvZiB3aW5kb3cmJlwidW5kZWZpbmVkXCIhPT10eXBlb2Ygd2luZG93W2FdKXt2YXIgYj13aW5kb3dbYV07Yi5zZXRJdGVtKFwiZmlyZWJhc2U6c2VudGluZWxcIixcImNhY2hlXCIpO2IucmVtb3ZlSXRlbShcImZpcmViYXNlOnNlbnRpbmVsXCIpO3JldHVybiBuZXcgJGMoYil9fWNhdGNoKGMpe31yZXR1cm4gbmV3IFpjfXZhciBiZD1hZChcImxvY2FsU3RvcmFnZVwiKSxjZD1hZChcInNlc3Npb25TdG9yYWdlXCIpO2Z1bmN0aW9uIGRkKGEsYixjLGQsZSl7dGhpcy5ob3N0PWEudG9Mb3dlckNhc2UoKTt0aGlzLmRvbWFpbj10aGlzLmhvc3Quc3Vic3RyKHRoaXMuaG9zdC5pbmRleE9mKFwiLlwiKSsxKTt0aGlzLm9iPWI7dGhpcy5sYz1jO3RoaXMuamg9ZDt0aGlzLlJkPWV8fFwiXCI7dGhpcy5hYj1iZC5nZXQoXCJob3N0OlwiK2EpfHx0aGlzLmhvc3R9ZnVuY3Rpb24gZWQoYSxiKXtiIT09YS5hYiYmKGEuYWI9YixcInMtXCI9PT1hLmFiLnN1YnN0cigwLDIpJiZiZC5zZXQoXCJob3N0OlwiK2EuaG9zdCxhLmFiKSl9XG5mdW5jdGlvbiBmZChhLGIsYyl7TyhcInN0cmluZ1wiPT09dHlwZW9mIGIsXCJ0eXBlb2YgdHlwZSBtdXN0ID09IHN0cmluZ1wiKTtPKFwib2JqZWN0XCI9PT10eXBlb2YgYyxcInR5cGVvZiBwYXJhbXMgbXVzdCA9PSBvYmplY3RcIik7aWYoYj09PWdkKWI9KGEub2I/XCJ3c3M6Ly9cIjpcIndzOi8vXCIpK2EuYWIrXCIvLndzP1wiO2Vsc2UgaWYoYj09PWhkKWI9KGEub2I/XCJodHRwczovL1wiOlwiaHR0cDovL1wiKSthLmFiK1wiLy5scD9cIjtlbHNlIHRocm93IEVycm9yKFwiVW5rbm93biBjb25uZWN0aW9uIHR5cGU6IFwiK2IpO2EuaG9zdCE9PWEuYWImJihjLm5zPWEubGMpO3ZhciBkPVtdO3YoYyxmdW5jdGlvbihhLGIpe2QucHVzaChiK1wiPVwiK2EpfSk7cmV0dXJuIGIrZC5qb2luKFwiJlwiKX1kZC5wcm90b3R5cGUudG9TdHJpbmc9ZnVuY3Rpb24oKXt2YXIgYT0odGhpcy5vYj9cImh0dHBzOi8vXCI6XCJodHRwOi8vXCIpK3RoaXMuaG9zdDt0aGlzLlJkJiYoYSs9XCI8XCIrdGhpcy5SZCtcIj5cIik7cmV0dXJuIGF9O3ZhciBpZD1mdW5jdGlvbigpe3ZhciBhPTE7cmV0dXJuIGZ1bmN0aW9uKCl7cmV0dXJuIGErK319KCksTz1LYixqZD1MYjtcbmZ1bmN0aW9uIGtkKGEpe3RyeXt2YXIgYjtpZihcInVuZGVmaW5lZFwiIT09dHlwZW9mIGF0b2IpYj1hdG9iKGEpO2Vsc2V7b2IoKTtmb3IodmFyIGM9bWIsZD1bXSxlPTA7ZTxhLmxlbmd0aDspe3ZhciBmPWNbYS5jaGFyQXQoZSsrKV0sZz1lPGEubGVuZ3RoP2NbYS5jaGFyQXQoZSldOjA7KytlO3ZhciBrPWU8YS5sZW5ndGg/Y1thLmNoYXJBdChlKV06NjQ7KytlO3ZhciBtPWU8YS5sZW5ndGg/Y1thLmNoYXJBdChlKV06NjQ7KytlO2lmKG51bGw9PWZ8fG51bGw9PWd8fG51bGw9PWt8fG51bGw9PW0pdGhyb3cgRXJyb3IoKTtkLnB1c2goZjw8MnxnPj40KTs2NCE9ayYmKGQucHVzaChnPDw0JjI0MHxrPj4yKSw2NCE9bSYmZC5wdXNoKGs8PDYmMTkyfG0pKX1pZig4MTkyPmQubGVuZ3RoKWI9U3RyaW5nLmZyb21DaGFyQ29kZS5hcHBseShudWxsLGQpO2Vsc2V7YT1cIlwiO2ZvcihjPTA7YzxkLmxlbmd0aDtjKz04MTkyKWErPVN0cmluZy5mcm9tQ2hhckNvZGUuYXBwbHkobnVsbCxVYShkLGMsXG5jKzgxOTIpKTtiPWF9fXJldHVybiBifWNhdGNoKGwpe2ZjKFwiYmFzZTY0RGVjb2RlIGZhaWxlZDogXCIsbCl9cmV0dXJuIG51bGx9ZnVuY3Rpb24gbGQoYSl7dmFyIGI9T2IoYSk7YT1uZXcgSmE7YS51cGRhdGUoYik7dmFyIGI9W10sYz04KmEuZ2U7NTY+YS5lYz9hLnVwZGF0ZShhLk9kLDU2LWEuZWMpOmEudXBkYXRlKGEuT2QsYS5ZYS0oYS5lYy01NikpO2Zvcih2YXIgZD1hLllhLTE7NTY8PWQ7ZC0tKWEucGVbZF09YyYyNTUsYy89MjU2O0thKGEsYS5wZSk7Zm9yKGQ9Yz0wOzU+ZDtkKyspZm9yKHZhciBlPTI0OzA8PWU7ZS09OCliW2NdPWEuUFtkXT4+ZSYyNTUsKytjO3JldHVybiBuYihiKX1cbmZ1bmN0aW9uIG1kKGEpe2Zvcih2YXIgYj1cIlwiLGM9MDtjPGFyZ3VtZW50cy5sZW5ndGg7YysrKWI9ZWEoYXJndW1lbnRzW2NdKT9iK21kLmFwcGx5KG51bGwsYXJndW1lbnRzW2NdKTpcIm9iamVjdFwiPT09dHlwZW9mIGFyZ3VtZW50c1tjXT9iK0coYXJndW1lbnRzW2NdKTpiK2FyZ3VtZW50c1tjXSxiKz1cIiBcIjtyZXR1cm4gYn12YXIgZWM9bnVsbCxuZD0hMDtcbmZ1bmN0aW9uIG9kKGEsYil7S2IoIWJ8fCEwPT09YXx8ITE9PT1hLFwiQ2FuJ3QgdHVybiBvbiBjdXN0b20gbG9nZ2VycyBwZXJzaXN0ZW50bHkuXCIpOyEwPT09YT8oXCJ1bmRlZmluZWRcIiE9PXR5cGVvZiBjb25zb2xlJiYoXCJmdW5jdGlvblwiPT09dHlwZW9mIGNvbnNvbGUubG9nP2VjPXUoY29uc29sZS5sb2csY29uc29sZSk6XCJvYmplY3RcIj09PXR5cGVvZiBjb25zb2xlLmxvZyYmKGVjPWZ1bmN0aW9uKGEpe2NvbnNvbGUubG9nKGEpfSkpLGImJmNkLnNldChcImxvZ2dpbmdfZW5hYmxlZFwiLCEwKSk6cihhKT9lYz1hOihlYz1udWxsLGNkLnJlbW92ZShcImxvZ2dpbmdfZW5hYmxlZFwiKSl9ZnVuY3Rpb24gZmMoYSl7ITA9PT1uZCYmKG5kPSExLG51bGw9PT1lYyYmITA9PT1jZC5nZXQoXCJsb2dnaW5nX2VuYWJsZWRcIikmJm9kKCEwKSk7aWYoZWMpe3ZhciBiPW1kLmFwcGx5KG51bGwsYXJndW1lbnRzKTtlYyhiKX19XG5mdW5jdGlvbiBwZChhKXtyZXR1cm4gZnVuY3Rpb24oKXtmYyhhLGFyZ3VtZW50cyl9fWZ1bmN0aW9uIHFkKGEpe2lmKFwidW5kZWZpbmVkXCIhPT10eXBlb2YgY29uc29sZSl7dmFyIGI9XCJGSVJFQkFTRSBJTlRFUk5BTCBFUlJPUjogXCIrbWQuYXBwbHkobnVsbCxhcmd1bWVudHMpO1widW5kZWZpbmVkXCIhPT10eXBlb2YgY29uc29sZS5lcnJvcj9jb25zb2xlLmVycm9yKGIpOmNvbnNvbGUubG9nKGIpfX1mdW5jdGlvbiByZChhKXt2YXIgYj1tZC5hcHBseShudWxsLGFyZ3VtZW50cyk7dGhyb3cgRXJyb3IoXCJGSVJFQkFTRSBGQVRBTCBFUlJPUjogXCIrYik7fWZ1bmN0aW9uIFMoYSl7aWYoXCJ1bmRlZmluZWRcIiE9PXR5cGVvZiBjb25zb2xlKXt2YXIgYj1cIkZJUkVCQVNFIFdBUk5JTkc6IFwiK21kLmFwcGx5KG51bGwsYXJndW1lbnRzKTtcInVuZGVmaW5lZFwiIT09dHlwZW9mIGNvbnNvbGUud2Fybj9jb25zb2xlLndhcm4oYik6Y29uc29sZS5sb2coYil9fVxuZnVuY3Rpb24gc2QoYSl7dmFyIGI9XCJcIixjPVwiXCIsZD1cIlwiLGU9XCJcIixmPSEwLGc9XCJodHRwc1wiLGs9NDQzO2lmKHEoYSkpe3ZhciBtPWEuaW5kZXhPZihcIi8vXCIpOzA8PW0mJihnPWEuc3Vic3RyaW5nKDAsbS0xKSxhPWEuc3Vic3RyaW5nKG0rMikpO209YS5pbmRleE9mKFwiL1wiKTstMT09PW0mJihtPWEubGVuZ3RoKTtiPWEuc3Vic3RyaW5nKDAsbSk7ZT1cIlwiO2E9YS5zdWJzdHJpbmcobSkuc3BsaXQoXCIvXCIpO2ZvcihtPTA7bTxhLmxlbmd0aDttKyspaWYoMDxhW21dLmxlbmd0aCl7dmFyIGw9YVttXTt0cnl7bD1kZWNvZGVVUklDb21wb25lbnQobC5yZXBsYWNlKC9cXCsvZyxcIiBcIikpfWNhdGNoKHQpe31lKz1cIi9cIitsfWE9Yi5zcGxpdChcIi5cIik7Mz09PWEubGVuZ3RoPyhjPWFbMV0sZD1hWzBdLnRvTG93ZXJDYXNlKCkpOjI9PT1hLmxlbmd0aCYmKGM9YVswXSk7bT1iLmluZGV4T2YoXCI6XCIpOzA8PW0mJihmPVwiaHR0cHNcIj09PWd8fFwid3NzXCI9PT1nLGs9Yi5zdWJzdHJpbmcobSsxKSxpc0Zpbml0ZShrKSYmXG4oaz1TdHJpbmcoaykpLGs9cShrKT8vXlxccyotPzB4L2kudGVzdChrKT9wYXJzZUludChrLDE2KTpwYXJzZUludChrLDEwKTpOYU4pfXJldHVybntob3N0OmIscG9ydDprLGRvbWFpbjpjLGZoOmQsb2I6ZixzY2hlbWU6ZyxiZDplfX1mdW5jdGlvbiB0ZChhKXtyZXR1cm4gZmEoYSkmJihhIT1hfHxhPT1OdW1iZXIuUE9TSVRJVkVfSU5GSU5JVFl8fGE9PU51bWJlci5ORUdBVElWRV9JTkZJTklUWSl9XG5mdW5jdGlvbiB1ZChhKXtpZihcImNvbXBsZXRlXCI9PT1kb2N1bWVudC5yZWFkeVN0YXRlKWEoKTtlbHNle3ZhciBiPSExLGM9ZnVuY3Rpb24oKXtkb2N1bWVudC5ib2R5P2J8fChiPSEwLGEoKSk6c2V0VGltZW91dChjLE1hdGguZmxvb3IoMTApKX07ZG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcj8oZG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcihcIkRPTUNvbnRlbnRMb2FkZWRcIixjLCExKSx3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcihcImxvYWRcIixjLCExKSk6ZG9jdW1lbnQuYXR0YWNoRXZlbnQmJihkb2N1bWVudC5hdHRhY2hFdmVudChcIm9ucmVhZHlzdGF0ZWNoYW5nZVwiLGZ1bmN0aW9uKCl7XCJjb21wbGV0ZVwiPT09ZG9jdW1lbnQucmVhZHlTdGF0ZSYmYygpfSksd2luZG93LmF0dGFjaEV2ZW50KFwib25sb2FkXCIsYykpfX1cbmZ1bmN0aW9uIHljKGEsYil7aWYoYT09PWIpcmV0dXJuIDA7aWYoXCJbTUlOX05BTUVdXCI9PT1hfHxcIltNQVhfTkFNRV1cIj09PWIpcmV0dXJuLTE7aWYoXCJbTUlOX05BTUVdXCI9PT1ifHxcIltNQVhfTkFNRV1cIj09PWEpcmV0dXJuIDE7dmFyIGM9dmQoYSksZD12ZChiKTtyZXR1cm4gbnVsbCE9PWM/bnVsbCE9PWQ/MD09Yy1kP2EubGVuZ3RoLWIubGVuZ3RoOmMtZDotMTpudWxsIT09ZD8xOmE8Yj8tMToxfWZ1bmN0aW9uIHdkKGEsYil7aWYoYiYmYSBpbiBiKXJldHVybiBiW2FdO3Rocm93IEVycm9yKFwiTWlzc2luZyByZXF1aXJlZCBrZXkgKFwiK2ErXCIpIGluIG9iamVjdDogXCIrRyhiKSk7fVxuZnVuY3Rpb24geGQoYSl7aWYoXCJvYmplY3RcIiE9PXR5cGVvZiBhfHxudWxsPT09YSlyZXR1cm4gRyhhKTt2YXIgYj1bXSxjO2ZvcihjIGluIGEpYi5wdXNoKGMpO2Iuc29ydCgpO2M9XCJ7XCI7Zm9yKHZhciBkPTA7ZDxiLmxlbmd0aDtkKyspMCE9PWQmJihjKz1cIixcIiksYys9RyhiW2RdKSxjKz1cIjpcIixjKz14ZChhW2JbZF1dKTtyZXR1cm4gYytcIn1cIn1mdW5jdGlvbiB5ZChhLGIpe2lmKGEubGVuZ3RoPD1iKXJldHVyblthXTtmb3IodmFyIGM9W10sZD0wO2Q8YS5sZW5ndGg7ZCs9YilkK2I+YT9jLnB1c2goYS5zdWJzdHJpbmcoZCxhLmxlbmd0aCkpOmMucHVzaChhLnN1YnN0cmluZyhkLGQrYikpO3JldHVybiBjfWZ1bmN0aW9uIHpkKGEsYil7aWYoZGEoYSkpZm9yKHZhciBjPTA7YzxhLmxlbmd0aDsrK2MpYihjLGFbY10pO2Vsc2UgdihhLGIpfVxuZnVuY3Rpb24gQWQoYSl7TyghdGQoYSksXCJJbnZhbGlkIEpTT04gbnVtYmVyXCIpO3ZhciBiLGMsZCxlOzA9PT1hPyhkPWM9MCxiPS1JbmZpbml0eT09PTEvYT8xOjApOihiPTA+YSxhPU1hdGguYWJzKGEpLGE+PU1hdGgucG93KDIsLTEwMjIpPyhkPU1hdGgubWluKE1hdGguZmxvb3IoTWF0aC5sb2coYSkvTWF0aC5MTjIpLDEwMjMpLGM9ZCsxMDIzLGQ9TWF0aC5yb3VuZChhKk1hdGgucG93KDIsNTItZCktTWF0aC5wb3coMiw1MikpKTooYz0wLGQ9TWF0aC5yb3VuZChhL01hdGgucG93KDIsLTEwNzQpKSkpO2U9W107Zm9yKGE9NTI7YTstLWEpZS5wdXNoKGQlMj8xOjApLGQ9TWF0aC5mbG9vcihkLzIpO2ZvcihhPTExO2E7LS1hKWUucHVzaChjJTI/MTowKSxjPU1hdGguZmxvb3IoYy8yKTtlLnB1c2goYj8xOjApO2UucmV2ZXJzZSgpO2I9ZS5qb2luKFwiXCIpO2M9XCJcIjtmb3IoYT0wOzY0PmE7YSs9OClkPXBhcnNlSW50KGIuc3Vic3RyKGEsOCksMikudG9TdHJpbmcoMTYpLDE9PT1kLmxlbmd0aCYmXG4oZD1cIjBcIitkKSxjKz1kO3JldHVybiBjLnRvTG93ZXJDYXNlKCl9dmFyIEJkPS9eLT9cXGR7MSwxMH0kLztmdW5jdGlvbiB2ZChhKXtyZXR1cm4gQmQudGVzdChhKSYmKGE9TnVtYmVyKGEpLC0yMTQ3NDgzNjQ4PD1hJiYyMTQ3NDgzNjQ3Pj1hKT9hOm51bGx9ZnVuY3Rpb24gZ2MoYSl7dHJ5e2EoKX1jYXRjaChiKXtzZXRUaW1lb3V0KGZ1bmN0aW9uKCl7UyhcIkV4Y2VwdGlvbiB3YXMgdGhyb3duIGJ5IHVzZXIgY2FsbGJhY2suXCIsYi5zdGFja3x8XCJcIik7dGhyb3cgYjt9LE1hdGguZmxvb3IoMCkpfX1mdW5jdGlvbiBUKGEsYil7aWYocihhKSl7dmFyIGM9QXJyYXkucHJvdG90eXBlLnNsaWNlLmNhbGwoYXJndW1lbnRzLDEpLnNsaWNlKCk7Z2MoZnVuY3Rpb24oKXthLmFwcGx5KG51bGwsYyl9KX19O2Z1bmN0aW9uIENkKGEpe3ZhciBiPXt9LGM9e30sZD17fSxlPVwiXCI7dHJ5e3ZhciBmPWEuc3BsaXQoXCIuXCIpLGI9UmIoa2QoZlswXSl8fFwiXCIpLGM9UmIoa2QoZlsxXSl8fFwiXCIpLGU9ZlsyXSxkPWMuZHx8e307ZGVsZXRlIGMuZH1jYXRjaChnKXt9cmV0dXJue21oOmIsRWM6YyxkYXRhOmQsYmg6ZX19ZnVuY3Rpb24gRGQoYSl7YT1DZChhKS5FYztyZXR1cm5cIm9iamVjdFwiPT09dHlwZW9mIGEmJmEuaGFzT3duUHJvcGVydHkoXCJpYXRcIik/eihhLFwiaWF0XCIpOm51bGx9ZnVuY3Rpb24gRWQoYSl7YT1DZChhKTt2YXIgYj1hLkVjO3JldHVybiEhYS5iaCYmISFiJiZcIm9iamVjdFwiPT09dHlwZW9mIGImJmIuaGFzT3duUHJvcGVydHkoXCJpYXRcIil9O2Z1bmN0aW9uIEZkKGEpe3RoaXMuWT1hO3RoaXMuZz1hLm4uZ31mdW5jdGlvbiBHZChhLGIsYyxkKXt2YXIgZT1bXSxmPVtdO01hKGIsZnVuY3Rpb24oYil7XCJjaGlsZF9jaGFuZ2VkXCI9PT1iLnR5cGUmJmEuZy5EZChiLk9lLGIuTmEpJiZmLnB1c2gobmV3IEooXCJjaGlsZF9tb3ZlZFwiLGIuTmEsYi5aYSkpfSk7SGQoYSxlLFwiY2hpbGRfcmVtb3ZlZFwiLGIsZCxjKTtIZChhLGUsXCJjaGlsZF9hZGRlZFwiLGIsZCxjKTtIZChhLGUsXCJjaGlsZF9tb3ZlZFwiLGYsZCxjKTtIZChhLGUsXCJjaGlsZF9jaGFuZ2VkXCIsYixkLGMpO0hkKGEsZSxpYyxiLGQsYyk7cmV0dXJuIGV9ZnVuY3Rpb24gSGQoYSxiLGMsZCxlLGYpe2Q9TmEoZCxmdW5jdGlvbihhKXtyZXR1cm4gYS50eXBlPT09Y30pO1ZhKGQsdShhLnFnLGEpKTtNYShkLGZ1bmN0aW9uKGMpe3ZhciBkPUlkKGEsYyxmKTtNYShlLGZ1bmN0aW9uKGUpe2UuUWYoYy50eXBlKSYmYi5wdXNoKGUuY3JlYXRlRXZlbnQoZCxhLlkpKX0pfSl9XG5mdW5jdGlvbiBJZChhLGIsYyl7XCJ2YWx1ZVwiIT09Yi50eXBlJiZcImNoaWxkX3JlbW92ZWRcIiE9PWIudHlwZSYmKGIuVGQ9Yy53ZihiLlphLGIuTmEsYS5nKSk7cmV0dXJuIGJ9RmQucHJvdG90eXBlLnFnPWZ1bmN0aW9uKGEsYil7aWYobnVsbD09YS5aYXx8bnVsbD09Yi5aYSl0aHJvdyBqZChcIlNob3VsZCBvbmx5IGNvbXBhcmUgY2hpbGRfIGV2ZW50cy5cIik7cmV0dXJuIHRoaXMuZy5jb21wYXJlKG5ldyBMKGEuWmEsYS5OYSksbmV3IEwoYi5aYSxiLk5hKSl9O2Z1bmN0aW9uIEpkKCl7dGhpcy5pYj17fX1cbmZ1bmN0aW9uIEtkKGEsYil7dmFyIGM9Yi50eXBlLGQ9Yi5aYTtPKFwiY2hpbGRfYWRkZWRcIj09Y3x8XCJjaGlsZF9jaGFuZ2VkXCI9PWN8fFwiY2hpbGRfcmVtb3ZlZFwiPT1jLFwiT25seSBjaGlsZCBjaGFuZ2VzIHN1cHBvcnRlZCBmb3IgdHJhY2tpbmdcIik7TyhcIi5wcmlvcml0eVwiIT09ZCxcIk9ubHkgbm9uLXByaW9yaXR5IGNoaWxkIGNoYW5nZXMgY2FuIGJlIHRyYWNrZWQuXCIpO3ZhciBlPXooYS5pYixkKTtpZihlKXt2YXIgZj1lLnR5cGU7aWYoXCJjaGlsZF9hZGRlZFwiPT1jJiZcImNoaWxkX3JlbW92ZWRcIj09ZilhLmliW2RdPW5ldyBKKFwiY2hpbGRfY2hhbmdlZFwiLGIuTmEsZCxlLk5hKTtlbHNlIGlmKFwiY2hpbGRfcmVtb3ZlZFwiPT1jJiZcImNoaWxkX2FkZGVkXCI9PWYpZGVsZXRlIGEuaWJbZF07ZWxzZSBpZihcImNoaWxkX3JlbW92ZWRcIj09YyYmXCJjaGlsZF9jaGFuZ2VkXCI9PWYpYS5pYltkXT1uZXcgSihcImNoaWxkX3JlbW92ZWRcIixlLk9lLGQpO2Vsc2UgaWYoXCJjaGlsZF9jaGFuZ2VkXCI9PWMmJlxuXCJjaGlsZF9hZGRlZFwiPT1mKWEuaWJbZF09bmV3IEooXCJjaGlsZF9hZGRlZFwiLGIuTmEsZCk7ZWxzZSBpZihcImNoaWxkX2NoYW5nZWRcIj09YyYmXCJjaGlsZF9jaGFuZ2VkXCI9PWYpYS5pYltkXT1uZXcgSihcImNoaWxkX2NoYW5nZWRcIixiLk5hLGQsZS5PZSk7ZWxzZSB0aHJvdyBqZChcIklsbGVnYWwgY29tYmluYXRpb24gb2YgY2hhbmdlczogXCIrYitcIiBvY2N1cnJlZCBhZnRlciBcIitlKTt9ZWxzZSBhLmliW2RdPWJ9O2Z1bmN0aW9uIExkKGEpe3RoaXMuZz1hfWg9TGQucHJvdG90eXBlO2guSD1mdW5jdGlvbihhLGIsYyxkLGUsZil7TyhhLk1jKHRoaXMuZyksXCJBIG5vZGUgbXVzdCBiZSBpbmRleGVkIGlmIG9ubHkgYSBjaGlsZCBpcyB1cGRhdGVkXCIpO2U9YS5UKGIpO2lmKGUuUyhkKS5lYShjLlMoZCkpJiZlLmUoKT09Yy5lKCkpcmV0dXJuIGE7bnVsbCE9ZiYmKGMuZSgpP2EuRmEoYik/S2QoZixuZXcgSihcImNoaWxkX3JlbW92ZWRcIixlLGIpKTpPKGEuTCgpLFwiQSBjaGlsZCByZW1vdmUgd2l0aG91dCBhbiBvbGQgY2hpbGQgb25seSBtYWtlcyBzZW5zZSBvbiBhIGxlYWYgbm9kZVwiKTplLmUoKT9LZChmLG5ldyBKKFwiY2hpbGRfYWRkZWRcIixjLGIpKTpLZChmLG5ldyBKKFwiY2hpbGRfY2hhbmdlZFwiLGMsYixlKSkpO3JldHVybiBhLkwoKSYmYy5lKCk/YTphLlcoYixjKS5wYih0aGlzLmcpfTtcbmgueWE9ZnVuY3Rpb24oYSxiLGMpe251bGwhPWMmJihhLkwoKXx8YS5SKFIsZnVuY3Rpb24oYSxlKXtiLkZhKGEpfHxLZChjLG5ldyBKKFwiY2hpbGRfcmVtb3ZlZFwiLGUsYSkpfSksYi5MKCl8fGIuUihSLGZ1bmN0aW9uKGIsZSl7aWYoYS5GYShiKSl7dmFyIGY9YS5UKGIpO2YuZWEoZSl8fEtkKGMsbmV3IEooXCJjaGlsZF9jaGFuZ2VkXCIsZSxiLGYpKX1lbHNlIEtkKGMsbmV3IEooXCJjaGlsZF9hZGRlZFwiLGUsYikpfSkpO3JldHVybiBiLnBiKHRoaXMuZyl9O2guaWE9ZnVuY3Rpb24oYSxiKXtyZXR1cm4gYS5lKCk/SDphLmlhKGIpfTtoLlJhPWZ1bmN0aW9uKCl7cmV0dXJuITF9O2guJGI9ZnVuY3Rpb24oKXtyZXR1cm4gdGhpc307ZnVuY3Rpb24gTWQoYSl7dGhpcy5GZT1uZXcgTGQoYS5nKTt0aGlzLmc9YS5nO3ZhciBiO2Eub2E/KGI9TmQoYSksYj1hLmcuU2MoT2QoYSksYikpOmI9YS5nLldjKCk7dGhpcy5nZD1iO2EucmE/KGI9UGQoYSksYT1hLmcuU2MoUmQoYSksYikpOmE9YS5nLlRjKCk7dGhpcy5KYz1hfWg9TWQucHJvdG90eXBlO2gubWF0Y2hlcz1mdW5jdGlvbihhKXtyZXR1cm4gMD49dGhpcy5nLmNvbXBhcmUodGhpcy5nZCxhKSYmMD49dGhpcy5nLmNvbXBhcmUoYSx0aGlzLkpjKX07aC5IPWZ1bmN0aW9uKGEsYixjLGQsZSxmKXt0aGlzLm1hdGNoZXMobmV3IEwoYixjKSl8fChjPUgpO3JldHVybiB0aGlzLkZlLkgoYSxiLGMsZCxlLGYpfTtcbmgueWE9ZnVuY3Rpb24oYSxiLGMpe2IuTCgpJiYoYj1IKTt2YXIgZD1iLnBiKHRoaXMuZyksZD1kLmlhKEgpLGU9dGhpcztiLlIoUixmdW5jdGlvbihhLGIpe2UubWF0Y2hlcyhuZXcgTChhLGIpKXx8KGQ9ZC5XKGEsSCkpfSk7cmV0dXJuIHRoaXMuRmUueWEoYSxkLGMpfTtoLmlhPWZ1bmN0aW9uKGEpe3JldHVybiBhfTtoLlJhPWZ1bmN0aW9uKCl7cmV0dXJuITB9O2guJGI9ZnVuY3Rpb24oKXtyZXR1cm4gdGhpcy5GZX07ZnVuY3Rpb24gU2QoYSl7dGhpcy51YT1uZXcgTWQoYSk7dGhpcy5nPWEuZztPKGEubGEsXCJPbmx5IHZhbGlkIGlmIGxpbWl0IGhhcyBiZWVuIHNldFwiKTt0aGlzLm1hPWEubWE7dGhpcy5OYj0hVGQoYSl9aD1TZC5wcm90b3R5cGU7aC5IPWZ1bmN0aW9uKGEsYixjLGQsZSxmKXt0aGlzLnVhLm1hdGNoZXMobmV3IEwoYixjKSl8fChjPUgpO3JldHVybiBhLlQoYikuZWEoYyk/YTphLkhiKCk8dGhpcy5tYT90aGlzLnVhLiRiKCkuSChhLGIsYyxkLGUsZik6VWQodGhpcyxhLGIsYyxlLGYpfTtcbmgueWE9ZnVuY3Rpb24oYSxiLGMpe3ZhciBkO2lmKGIuTCgpfHxiLmUoKSlkPUgucGIodGhpcy5nKTtlbHNlIGlmKDIqdGhpcy5tYTxiLkhiKCkmJmIuTWModGhpcy5nKSl7ZD1ILnBiKHRoaXMuZyk7Yj10aGlzLk5iP2IuZGModGhpcy51YS5KYyx0aGlzLmcpOmIuYmModGhpcy51YS5nZCx0aGlzLmcpO2Zvcih2YXIgZT0wOzA8Yi5UYS5sZW5ndGgmJmU8dGhpcy5tYTspe3ZhciBmPUljKGIpLGc7aWYoZz10aGlzLk5iPzA+PXRoaXMuZy5jb21wYXJlKHRoaXMudWEuZ2QsZik6MD49dGhpcy5nLmNvbXBhcmUoZix0aGlzLnVhLkpjKSlkPWQuVyhmLm5hbWUsZi5VKSxlKys7ZWxzZSBicmVha319ZWxzZXtkPWIucGIodGhpcy5nKTtkPWQuaWEoSCk7dmFyIGssbSxsO2lmKHRoaXMuTmIpe2I9ZC54Zih0aGlzLmcpO2s9dGhpcy51YS5KYzttPXRoaXMudWEuZ2Q7dmFyIHQ9VmQodGhpcy5nKTtsPWZ1bmN0aW9uKGEsYil7cmV0dXJuIHQoYixhKX19ZWxzZSBiPWQuYWModGhpcy5nKSxrPXRoaXMudWEuZ2QsXG5tPXRoaXMudWEuSmMsbD1WZCh0aGlzLmcpO2Zvcih2YXIgZT0wLEE9ITE7MDxiLlRhLmxlbmd0aDspZj1JYyhiKSwhQSYmMD49bChrLGYpJiYoQT0hMCksKGc9QSYmZTx0aGlzLm1hJiYwPj1sKGYsbSkpP2UrKzpkPWQuVyhmLm5hbWUsSCl9cmV0dXJuIHRoaXMudWEuJGIoKS55YShhLGQsYyl9O2guaWE9ZnVuY3Rpb24oYSl7cmV0dXJuIGF9O2guUmE9ZnVuY3Rpb24oKXtyZXR1cm4hMH07aC4kYj1mdW5jdGlvbigpe3JldHVybiB0aGlzLnVhLiRiKCl9O1xuZnVuY3Rpb24gVWQoYSxiLGMsZCxlLGYpe3ZhciBnO2lmKGEuTmIpe3ZhciBrPVZkKGEuZyk7Zz1mdW5jdGlvbihhLGIpe3JldHVybiBrKGIsYSl9fWVsc2UgZz1WZChhLmcpO08oYi5IYigpPT1hLm1hLFwiXCIpO3ZhciBtPW5ldyBMKGMsZCksbD1hLk5iP1dkKGIsYS5nKTpYZChiLGEuZyksdD1hLnVhLm1hdGNoZXMobSk7aWYoYi5GYShjKSl7Zm9yKHZhciBBPWIuVChjKSxsPWUuQ2UoYS5nLGwsYS5OYik7bnVsbCE9bCYmKGwubmFtZT09Y3x8Yi5GYShsLm5hbWUpKTspbD1lLkNlKGEuZyxsLGEuTmIpO2U9bnVsbD09bD8xOmcobCxtKTtpZih0JiYhZC5lKCkmJjA8PWUpcmV0dXJuIG51bGwhPWYmJktkKGYsbmV3IEooXCJjaGlsZF9jaGFuZ2VkXCIsZCxjLEEpKSxiLlcoYyxkKTtudWxsIT1mJiZLZChmLG5ldyBKKFwiY2hpbGRfcmVtb3ZlZFwiLEEsYykpO2I9Yi5XKGMsSCk7cmV0dXJuIG51bGwhPWwmJmEudWEubWF0Y2hlcyhsKT8obnVsbCE9ZiYmS2QoZixuZXcgSihcImNoaWxkX2FkZGVkXCIsXG5sLlUsbC5uYW1lKSksYi5XKGwubmFtZSxsLlUpKTpifXJldHVybiBkLmUoKT9iOnQmJjA8PWcobCxtKT8obnVsbCE9ZiYmKEtkKGYsbmV3IEooXCJjaGlsZF9yZW1vdmVkXCIsbC5VLGwubmFtZSkpLEtkKGYsbmV3IEooXCJjaGlsZF9hZGRlZFwiLGQsYykpKSxiLlcoYyxkKS5XKGwubmFtZSxIKSk6Yn07ZnVuY3Rpb24gWWQoYSxiKXt0aGlzLm1lPWE7dGhpcy5vZz1ifWZ1bmN0aW9uIFpkKGEpe3RoaXMuWD1hfVxuWmQucHJvdG90eXBlLmdiPWZ1bmN0aW9uKGEsYixjLGQpe3ZhciBlPW5ldyBKZCxmO2lmKGIudHlwZT09PUJjKWIuc291cmNlLkFlP2M9JGQodGhpcyxhLGIucGF0aCxiLkphLGMsZCxlKTooTyhiLnNvdXJjZS50ZixcIlVua25vd24gc291cmNlLlwiKSxmPWIuc291cmNlLmVmfHxtYyhhLncoKSkmJiFiLnBhdGguZSgpLGM9YWUodGhpcyxhLGIucGF0aCxiLkphLGMsZCxmLGUpKTtlbHNlIGlmKGIudHlwZT09PWJlKWIuc291cmNlLkFlP2M9Y2UodGhpcyxhLGIucGF0aCxiLmNoaWxkcmVuLGMsZCxlKTooTyhiLnNvdXJjZS50ZixcIlVua25vd24gc291cmNlLlwiKSxmPWIuc291cmNlLmVmfHxtYyhhLncoKSksYz1kZSh0aGlzLGEsYi5wYXRoLGIuY2hpbGRyZW4sYyxkLGYsZSkpO2Vsc2UgaWYoYi50eXBlPT09ZWUpaWYoYi5ZZClpZihiPWIucGF0aCxudWxsIT1jLnhjKGIpKWM9YTtlbHNle2Y9bmV3IFZiKGMsYSxkKTtkPWEuUS5qKCk7aWYoYi5lKCl8fFwiLnByaW9yaXR5XCI9PT1LKGIpKWxjKGEudygpKT9cbmI9Yy5BYShZYihhKSk6KGI9YS53KCkuaigpLE8oYiBpbnN0YW5jZW9mIGZlLFwic2VydmVyQ2hpbGRyZW4gd291bGQgYmUgY29tcGxldGUgaWYgbGVhZiBub2RlXCIpLGI9Yy5DYyhiKSksYj10aGlzLlgueWEoZCxiLGUpO2Vsc2V7dmFyIGc9SyhiKSxrPWMuQmMoZyxhLncoKSk7bnVsbD09ayYmV2IoYS53KCksZykmJihrPWQuVChnKSk7Yj1udWxsIT1rP3RoaXMuWC5IKGQsZyxrLE4oYiksZixlKTphLlEuaigpLkZhKGcpP3RoaXMuWC5IKGQsZyxILE4oYiksZixlKTpkO2IuZSgpJiZsYyhhLncoKSkmJihkPWMuQWEoWWIoYSkpLGQuTCgpJiYoYj10aGlzLlgueWEoYixkLGUpKSl9ZD1sYyhhLncoKSl8fG51bGwhPWMueGMoTSk7Yz1nZShhLGIsZCx0aGlzLlguUmEoKSl9ZWxzZSBjPWhlKHRoaXMsYSxiLnBhdGgsYi5VYixjLGQsZSk7ZWxzZSBpZihiLnR5cGU9PT1EYylkPWIucGF0aCxiPWEudygpLGY9Yi5qKCksZz1iLmdhfHxkLmUoKSxjPWllKHRoaXMsbmV3IGplKGEuUSxuZXcgWGIoZixcbmcsYi5ZYikpLGQsYyxVYixlKTtlbHNlIHRocm93IGpkKFwiVW5rbm93biBvcGVyYXRpb24gdHlwZTogXCIrYi50eXBlKTtlPXFhKGUuaWIpO2Q9YztiPWQuUTtiLmdhJiYoZj1iLmooKS5MKCl8fGIuaigpLmUoKSxnPWtlKGEpLCgwPGUubGVuZ3RofHwhYS5RLmdhfHxmJiYhYi5qKCkuZWEoZyl8fCFiLmooKS5DKCkuZWEoZy5DKCkpKSYmZS5wdXNoKGhjKGtlKGQpKSkpO3JldHVybiBuZXcgWWQoYyxlKX07XG5mdW5jdGlvbiBpZShhLGIsYyxkLGUsZil7dmFyIGc9Yi5RO2lmKG51bGwhPWQueGMoYykpcmV0dXJuIGI7dmFyIGs7aWYoYy5lKCkpTyhsYyhiLncoKSksXCJJZiBjaGFuZ2UgcGF0aCBpcyBlbXB0eSwgd2UgbXVzdCBoYXZlIGNvbXBsZXRlIHNlcnZlciBkYXRhXCIpLG1jKGIudygpKT8oZT1ZYihiKSxkPWQuQ2MoZSBpbnN0YW5jZW9mIGZlP2U6SCkpOmQ9ZC5BYShZYihiKSksZj1hLlgueWEoYi5RLmooKSxkLGYpO2Vsc2V7dmFyIG09SyhjKTtpZihcIi5wcmlvcml0eVwiPT1tKU8oMT09bGUoYyksXCJDYW4ndCBoYXZlIGEgcHJpb3JpdHkgd2l0aCBhZGRpdGlvbmFsIHBhdGggY29tcG9uZW50c1wiKSxmPWcuaigpLGs9Yi53KCkuaigpLGQ9ZC5uZChjLGYsayksZj1udWxsIT1kP2EuWC5pYShmLGQpOmcuaigpO2Vsc2V7dmFyIGw9TihjKTtXYihnLG0pPyhrPWIudygpLmooKSxkPWQubmQoYyxnLmooKSxrKSxkPW51bGwhPWQ/Zy5qKCkuVChtKS5IKGwsZCk6Zy5qKCkuVChtKSk6ZD1kLkJjKG0sXG5iLncoKSk7Zj1udWxsIT1kP2EuWC5IKGcuaigpLG0sZCxsLGUsZik6Zy5qKCl9fXJldHVybiBnZShiLGYsZy5nYXx8Yy5lKCksYS5YLlJhKCkpfWZ1bmN0aW9uIGFlKGEsYixjLGQsZSxmLGcsayl7dmFyIG09Yi53KCk7Zz1nP2EuWDphLlguJGIoKTtpZihjLmUoKSlkPWcueWEobS5qKCksZCxudWxsKTtlbHNlIGlmKGcuUmEoKSYmIW0uWWIpZD1tLmooKS5IKGMsZCksZD1nLnlhKG0uaigpLGQsbnVsbCk7ZWxzZXt2YXIgbD1LKGMpO2lmKCFuYyhtLGMpJiYxPGxlKGMpKXJldHVybiBiO3ZhciB0PU4oYyk7ZD1tLmooKS5UKGwpLkgodCxkKTtkPVwiLnByaW9yaXR5XCI9PWw/Zy5pYShtLmooKSxkKTpnLkgobS5qKCksbCxkLHQsVWIsbnVsbCl9bT1tLmdhfHxjLmUoKTtiPW5ldyBqZShiLlEsbmV3IFhiKGQsbSxnLlJhKCkpKTtyZXR1cm4gaWUoYSxiLGMsZSxuZXcgVmIoZSxiLGYpLGspfVxuZnVuY3Rpb24gJGQoYSxiLGMsZCxlLGYsZyl7dmFyIGs9Yi5RO2U9bmV3IFZiKGUsYixmKTtpZihjLmUoKSlnPWEuWC55YShiLlEuaigpLGQsZyksYT1nZShiLGcsITAsYS5YLlJhKCkpO2Vsc2UgaWYoZj1LKGMpLFwiLnByaW9yaXR5XCI9PT1mKWc9YS5YLmlhKGIuUS5qKCksZCksYT1nZShiLGcsay5nYSxrLlliKTtlbHNle2M9TihjKTt2YXIgbT1rLmooKS5UKGYpO2lmKCFjLmUoKSl7dmFyIGw9ZS51ZihmKTtkPW51bGwhPWw/XCIucHJpb3JpdHlcIj09PW1lKGMpJiZsLlMoYy5wYXJlbnQoKSkuZSgpP2w6bC5IKGMsZCk6SH1tLmVhKGQpP2E9YjooZz1hLlguSChrLmooKSxmLGQsYyxlLGcpLGE9Z2UoYixnLGsuZ2EsYS5YLlJhKCkpKX1yZXR1cm4gYX1cbmZ1bmN0aW9uIGNlKGEsYixjLGQsZSxmLGcpe3ZhciBrPWI7bmUoZCxmdW5jdGlvbihkLGwpe3ZhciB0PWMubyhkKTtXYihiLlEsSyh0KSkmJihrPSRkKGEsayx0LGwsZSxmLGcpKX0pO25lKGQsZnVuY3Rpb24oZCxsKXt2YXIgdD1jLm8oZCk7V2IoYi5RLEsodCkpfHwoaz0kZChhLGssdCxsLGUsZixnKSl9KTtyZXR1cm4ga31mdW5jdGlvbiBvZShhLGIpe25lKGIsZnVuY3Rpb24oYixkKXthPWEuSChiLGQpfSk7cmV0dXJuIGF9XG5mdW5jdGlvbiBkZShhLGIsYyxkLGUsZixnLGspe2lmKGIudygpLmooKS5lKCkmJiFsYyhiLncoKSkpcmV0dXJuIGI7dmFyIG09YjtjPWMuZSgpP2Q6cGUocWUsYyxkKTt2YXIgbD1iLncoKS5qKCk7Yy5jaGlsZHJlbi5rYShmdW5jdGlvbihjLGQpe2lmKGwuRmEoYykpe3ZhciBJPWIudygpLmooKS5UKGMpLEk9b2UoSSxkKTttPWFlKGEsbSxuZXcgUChjKSxJLGUsZixnLGspfX0pO2MuY2hpbGRyZW4ua2EoZnVuY3Rpb24oYyxkKXt2YXIgST0hV2IoYi53KCksYykmJm51bGw9PWQudmFsdWU7bC5GYShjKXx8SXx8KEk9Yi53KCkuaigpLlQoYyksST1vZShJLGQpLG09YWUoYSxtLG5ldyBQKGMpLEksZSxmLGcsaykpfSk7cmV0dXJuIG19XG5mdW5jdGlvbiBoZShhLGIsYyxkLGUsZixnKXtpZihudWxsIT1lLnhjKGMpKXJldHVybiBiO3ZhciBrPW1jKGIudygpKSxtPWIudygpO2lmKG51bGwhPWQudmFsdWUpe2lmKGMuZSgpJiZtLmdhfHxuYyhtLGMpKXJldHVybiBhZShhLGIsYyxtLmooKS5TKGMpLGUsZixrLGcpO2lmKGMuZSgpKXt2YXIgbD1xZTttLmooKS5SKHJlLGZ1bmN0aW9uKGEsYil7bD1sLnNldChuZXcgUChhKSxiKX0pO3JldHVybiBkZShhLGIsYyxsLGUsZixrLGcpfXJldHVybiBifWw9cWU7bmUoZCxmdW5jdGlvbihhKXt2YXIgYj1jLm8oYSk7bmMobSxiKSYmKGw9bC5zZXQoYSxtLmooKS5TKGIpKSl9KTtyZXR1cm4gZGUoYSxiLGMsbCxlLGYsayxnKX07ZnVuY3Rpb24gc2UoKXt9dmFyIHRlPXt9O2Z1bmN0aW9uIFZkKGEpe3JldHVybiB1KGEuY29tcGFyZSxhKX1zZS5wcm90b3R5cGUuRGQ9ZnVuY3Rpb24oYSxiKXtyZXR1cm4gMCE9PXRoaXMuY29tcGFyZShuZXcgTChcIltNSU5fTkFNRV1cIixhKSxuZXcgTChcIltNSU5fTkFNRV1cIixiKSl9O3NlLnByb3RvdHlwZS5XYz1mdW5jdGlvbigpe3JldHVybiB1ZX07ZnVuY3Rpb24gdmUoYSl7TyghYS5lKCkmJlwiLnByaW9yaXR5XCIhPT1LKGEpLFwiQ2FuJ3QgY3JlYXRlIFBhdGhJbmRleCB3aXRoIGVtcHR5IHBhdGggb3IgLnByaW9yaXR5IGtleVwiKTt0aGlzLmdjPWF9a2EodmUsc2UpO2g9dmUucHJvdG90eXBlO2guTGM9ZnVuY3Rpb24oYSl7cmV0dXJuIWEuUyh0aGlzLmdjKS5lKCl9O2guY29tcGFyZT1mdW5jdGlvbihhLGIpe3ZhciBjPWEuVS5TKHRoaXMuZ2MpLGQ9Yi5VLlModGhpcy5nYyksYz1jLkdjKGQpO3JldHVybiAwPT09Yz95YyhhLm5hbWUsYi5uYW1lKTpjfTtcbmguU2M9ZnVuY3Rpb24oYSxiKXt2YXIgYz1RKGEpLGM9SC5IKHRoaXMuZ2MsYyk7cmV0dXJuIG5ldyBMKGIsYyl9O2guVGM9ZnVuY3Rpb24oKXt2YXIgYT1ILkgodGhpcy5nYyx3ZSk7cmV0dXJuIG5ldyBMKFwiW01BWF9OQU1FXVwiLGEpfTtoLnRvU3RyaW5nPWZ1bmN0aW9uKCl7cmV0dXJuIHRoaXMuZ2Muc2xpY2UoKS5qb2luKFwiL1wiKX07ZnVuY3Rpb24geGUoKXt9a2EoeGUsc2UpO2g9eGUucHJvdG90eXBlO2guY29tcGFyZT1mdW5jdGlvbihhLGIpe3ZhciBjPWEuVS5DKCksZD1iLlUuQygpLGM9Yy5HYyhkKTtyZXR1cm4gMD09PWM/eWMoYS5uYW1lLGIubmFtZSk6Y307aC5MYz1mdW5jdGlvbihhKXtyZXR1cm4hYS5DKCkuZSgpfTtoLkRkPWZ1bmN0aW9uKGEsYil7cmV0dXJuIWEuQygpLmVhKGIuQygpKX07aC5XYz1mdW5jdGlvbigpe3JldHVybiB1ZX07aC5UYz1mdW5jdGlvbigpe3JldHVybiBuZXcgTChcIltNQVhfTkFNRV1cIixuZXcgWWMoXCJbUFJJT1JJVFktUE9TVF1cIix3ZSkpfTtcbmguU2M9ZnVuY3Rpb24oYSxiKXt2YXIgYz1RKGEpO3JldHVybiBuZXcgTChiLG5ldyBZYyhcIltQUklPUklUWS1QT1NUXVwiLGMpKX07aC50b1N0cmluZz1mdW5jdGlvbigpe3JldHVyblwiLnByaW9yaXR5XCJ9O3ZhciBSPW5ldyB4ZTtmdW5jdGlvbiB5ZSgpe31rYSh5ZSxzZSk7aD15ZS5wcm90b3R5cGU7aC5jb21wYXJlPWZ1bmN0aW9uKGEsYil7cmV0dXJuIHljKGEubmFtZSxiLm5hbWUpfTtoLkxjPWZ1bmN0aW9uKCl7dGhyb3cgamQoXCJLZXlJbmRleC5pc0RlZmluZWRPbiBub3QgZXhwZWN0ZWQgdG8gYmUgY2FsbGVkLlwiKTt9O2guRGQ9ZnVuY3Rpb24oKXtyZXR1cm4hMX07aC5XYz1mdW5jdGlvbigpe3JldHVybiB1ZX07aC5UYz1mdW5jdGlvbigpe3JldHVybiBuZXcgTChcIltNQVhfTkFNRV1cIixIKX07aC5TYz1mdW5jdGlvbihhKXtPKHEoYSksXCJLZXlJbmRleCBpbmRleFZhbHVlIG11c3QgYWx3YXlzIGJlIGEgc3RyaW5nLlwiKTtyZXR1cm4gbmV3IEwoYSxIKX07aC50b1N0cmluZz1mdW5jdGlvbigpe3JldHVyblwiLmtleVwifTtcbnZhciByZT1uZXcgeWU7ZnVuY3Rpb24gemUoKXt9a2EoemUsc2UpO2g9emUucHJvdG90eXBlO2guY29tcGFyZT1mdW5jdGlvbihhLGIpe3ZhciBjPWEuVS5HYyhiLlUpO3JldHVybiAwPT09Yz95YyhhLm5hbWUsYi5uYW1lKTpjfTtoLkxjPWZ1bmN0aW9uKCl7cmV0dXJuITB9O2guRGQ9ZnVuY3Rpb24oYSxiKXtyZXR1cm4hYS5lYShiKX07aC5XYz1mdW5jdGlvbigpe3JldHVybiB1ZX07aC5UYz1mdW5jdGlvbigpe3JldHVybiBBZX07aC5TYz1mdW5jdGlvbihhLGIpe3ZhciBjPVEoYSk7cmV0dXJuIG5ldyBMKGIsYyl9O2gudG9TdHJpbmc9ZnVuY3Rpb24oKXtyZXR1cm5cIi52YWx1ZVwifTt2YXIgQmU9bmV3IHplO2Z1bmN0aW9uIENlKCl7dGhpcy5YYj10aGlzLnJhPXRoaXMuUGI9dGhpcy5vYT10aGlzLmxhPSExO3RoaXMubWE9MDt0aGlzLlJiPVwiXCI7dGhpcy5pYz1udWxsO3RoaXMuQmI9XCJcIjt0aGlzLmZjPW51bGw7dGhpcy56Yj1cIlwiO3RoaXMuZz1SfXZhciBEZT1uZXcgQ2U7ZnVuY3Rpb24gVGQoYSl7cmV0dXJuXCJcIj09PWEuUmI/YS5vYTpcImxcIj09PWEuUmJ9ZnVuY3Rpb24gT2QoYSl7TyhhLm9hLFwiT25seSB2YWxpZCBpZiBzdGFydCBoYXMgYmVlbiBzZXRcIik7cmV0dXJuIGEuaWN9ZnVuY3Rpb24gTmQoYSl7TyhhLm9hLFwiT25seSB2YWxpZCBpZiBzdGFydCBoYXMgYmVlbiBzZXRcIik7cmV0dXJuIGEuUGI/YS5CYjpcIltNSU5fTkFNRV1cIn1mdW5jdGlvbiBSZChhKXtPKGEucmEsXCJPbmx5IHZhbGlkIGlmIGVuZCBoYXMgYmVlbiBzZXRcIik7cmV0dXJuIGEuZmN9XG5mdW5jdGlvbiBQZChhKXtPKGEucmEsXCJPbmx5IHZhbGlkIGlmIGVuZCBoYXMgYmVlbiBzZXRcIik7cmV0dXJuIGEuWGI/YS56YjpcIltNQVhfTkFNRV1cIn1mdW5jdGlvbiBFZShhKXt2YXIgYj1uZXcgQ2U7Yi5sYT1hLmxhO2IubWE9YS5tYTtiLm9hPWEub2E7Yi5pYz1hLmljO2IuUGI9YS5QYjtiLkJiPWEuQmI7Yi5yYT1hLnJhO2IuZmM9YS5mYztiLlhiPWEuWGI7Yi56Yj1hLnpiO2IuZz1hLmc7cmV0dXJuIGJ9aD1DZS5wcm90b3R5cGU7aC5MZT1mdW5jdGlvbihhKXt2YXIgYj1FZSh0aGlzKTtiLmxhPSEwO2IubWE9YTtiLlJiPVwiXCI7cmV0dXJuIGJ9O2guTWU9ZnVuY3Rpb24oYSl7dmFyIGI9RWUodGhpcyk7Yi5sYT0hMDtiLm1hPWE7Yi5SYj1cImxcIjtyZXR1cm4gYn07aC5OZT1mdW5jdGlvbihhKXt2YXIgYj1FZSh0aGlzKTtiLmxhPSEwO2IubWE9YTtiLlJiPVwiclwiO3JldHVybiBifTtcbmguY2U9ZnVuY3Rpb24oYSxiKXt2YXIgYz1FZSh0aGlzKTtjLm9hPSEwO3AoYSl8fChhPW51bGwpO2MuaWM9YTtudWxsIT1iPyhjLlBiPSEwLGMuQmI9Yik6KGMuUGI9ITEsYy5CYj1cIlwiKTtyZXR1cm4gY307aC52ZD1mdW5jdGlvbihhLGIpe3ZhciBjPUVlKHRoaXMpO2MucmE9ITA7cChhKXx8KGE9bnVsbCk7Yy5mYz1hO3AoYik/KGMuWGI9ITAsYy56Yj1iKTooYy5vaD0hMSxjLnpiPVwiXCIpO3JldHVybiBjfTtmdW5jdGlvbiBGZShhLGIpe3ZhciBjPUVlKGEpO2MuZz1iO3JldHVybiBjfWZ1bmN0aW9uIEdlKGEpe3ZhciBiPXt9O2Eub2EmJihiLnNwPWEuaWMsYS5QYiYmKGIuc249YS5CYikpO2EucmEmJihiLmVwPWEuZmMsYS5YYiYmKGIuZW49YS56YikpO2lmKGEubGEpe2IubD1hLm1hO3ZhciBjPWEuUmI7XCJcIj09PWMmJihjPVRkKGEpP1wibFwiOlwiclwiKTtiLnZmPWN9YS5nIT09UiYmKGIuaT1hLmcudG9TdHJpbmcoKSk7cmV0dXJuIGJ9XG5mdW5jdGlvbiBIZShhKXtyZXR1cm4hKGEub2F8fGEucmF8fGEubGEpfWZ1bmN0aW9uIEllKGEpe3JldHVybiBIZShhKSYmYS5nPT1SfWZ1bmN0aW9uIEplKGEpe3ZhciBiPXt9O2lmKEllKGEpKXJldHVybiBiO3ZhciBjO2EuZz09PVI/Yz1cIiRwcmlvcml0eVwiOmEuZz09PUJlP2M9XCIkdmFsdWVcIjphLmc9PT1yZT9jPVwiJGtleVwiOihPKGEuZyBpbnN0YW5jZW9mIHZlLFwiVW5yZWNvZ25pemVkIGluZGV4IHR5cGUhXCIpLGM9YS5nLnRvU3RyaW5nKCkpO2Iub3JkZXJCeT1HKGMpO2Eub2EmJihiLnN0YXJ0QXQ9RyhhLmljKSxhLlBiJiYoYi5zdGFydEF0Kz1cIixcIitHKGEuQmIpKSk7YS5yYSYmKGIuZW5kQXQ9RyhhLmZjKSxhLlhiJiYoYi5lbmRBdCs9XCIsXCIrRyhhLnpiKSkpO2EubGEmJihUZChhKT9iLmxpbWl0VG9GaXJzdD1hLm1hOmIubGltaXRUb0xhc3Q9YS5tYSk7cmV0dXJuIGJ9aC50b1N0cmluZz1mdW5jdGlvbigpe3JldHVybiBHKEdlKHRoaXMpKX07ZnVuY3Rpb24gS2UoYSxiKXt0aGlzLkVkPWE7dGhpcy5oYz1ifUtlLnByb3RvdHlwZS5nZXQ9ZnVuY3Rpb24oYSl7dmFyIGI9eih0aGlzLkVkLGEpO2lmKCFiKXRocm93IEVycm9yKFwiTm8gaW5kZXggZGVmaW5lZCBmb3IgXCIrYSk7cmV0dXJuIGI9PT10ZT9udWxsOmJ9O2Z1bmN0aW9uIExlKGEsYixjKXt2YXIgZD1tYShhLkVkLGZ1bmN0aW9uKGQsZil7dmFyIGc9eihhLmhjLGYpO08oZyxcIk1pc3NpbmcgaW5kZXggaW1wbGVtZW50YXRpb24gZm9yIFwiK2YpO2lmKGQ9PT10ZSl7aWYoZy5MYyhiLlUpKXtmb3IodmFyIGs9W10sbT1jLmFjKHdjKSxsPUljKG0pO2w7KWwubmFtZSE9Yi5uYW1lJiZrLnB1c2gobCksbD1JYyhtKTtrLnB1c2goYik7cmV0dXJuIE1lKGssVmQoZykpfXJldHVybiB0ZX1nPWMuZ2V0KGIubmFtZSk7az1kO2cmJihrPWsucmVtb3ZlKG5ldyBMKGIubmFtZSxnKSkpO3JldHVybiBrLlNhKGIsYi5VKX0pO3JldHVybiBuZXcgS2UoZCxhLmhjKX1cbmZ1bmN0aW9uIE5lKGEsYixjKXt2YXIgZD1tYShhLkVkLGZ1bmN0aW9uKGEpe2lmKGE9PT10ZSlyZXR1cm4gYTt2YXIgZD1jLmdldChiLm5hbWUpO3JldHVybiBkP2EucmVtb3ZlKG5ldyBMKGIubmFtZSxkKSk6YX0pO3JldHVybiBuZXcgS2UoZCxhLmhjKX12YXIgT2U9bmV3IEtlKHtcIi5wcmlvcml0eVwiOnRlfSx7XCIucHJpb3JpdHlcIjpSfSk7ZnVuY3Rpb24gWWMoYSxiKXt0aGlzLkI9YTtPKHAodGhpcy5CKSYmbnVsbCE9PXRoaXMuQixcIkxlYWZOb2RlIHNob3VsZG4ndCBiZSBjcmVhdGVkIHdpdGggbnVsbC91bmRlZmluZWQgdmFsdWUuXCIpO3RoaXMuY2E9Ynx8SDtQZSh0aGlzLmNhKTt0aGlzLkdiPW51bGx9dmFyIFFlPVtcIm9iamVjdFwiLFwiYm9vbGVhblwiLFwibnVtYmVyXCIsXCJzdHJpbmdcIl07aD1ZYy5wcm90b3R5cGU7aC5MPWZ1bmN0aW9uKCl7cmV0dXJuITB9O2guQz1mdW5jdGlvbigpe3JldHVybiB0aGlzLmNhfTtoLmlhPWZ1bmN0aW9uKGEpe3JldHVybiBuZXcgWWModGhpcy5CLGEpfTtoLlQ9ZnVuY3Rpb24oYSl7cmV0dXJuXCIucHJpb3JpdHlcIj09PWE/dGhpcy5jYTpIfTtoLlM9ZnVuY3Rpb24oYSl7cmV0dXJuIGEuZSgpP3RoaXM6XCIucHJpb3JpdHlcIj09PUsoYSk/dGhpcy5jYTpIfTtoLkZhPWZ1bmN0aW9uKCl7cmV0dXJuITF9O2gud2Y9ZnVuY3Rpb24oKXtyZXR1cm4gbnVsbH07XG5oLlc9ZnVuY3Rpb24oYSxiKXtyZXR1cm5cIi5wcmlvcml0eVwiPT09YT90aGlzLmlhKGIpOmIuZSgpJiZcIi5wcmlvcml0eVwiIT09YT90aGlzOkguVyhhLGIpLmlhKHRoaXMuY2EpfTtoLkg9ZnVuY3Rpb24oYSxiKXt2YXIgYz1LKGEpO2lmKG51bGw9PT1jKXJldHVybiBiO2lmKGIuZSgpJiZcIi5wcmlvcml0eVwiIT09YylyZXR1cm4gdGhpcztPKFwiLnByaW9yaXR5XCIhPT1jfHwxPT09bGUoYSksXCIucHJpb3JpdHkgbXVzdCBiZSB0aGUgbGFzdCB0b2tlbiBpbiBhIHBhdGhcIik7cmV0dXJuIHRoaXMuVyhjLEguSChOKGEpLGIpKX07aC5lPWZ1bmN0aW9uKCl7cmV0dXJuITF9O2guSGI9ZnVuY3Rpb24oKXtyZXR1cm4gMH07aC5SPWZ1bmN0aW9uKCl7cmV0dXJuITF9O2guSj1mdW5jdGlvbihhKXtyZXR1cm4gYSYmIXRoaXMuQygpLmUoKT97XCIudmFsdWVcIjp0aGlzLkVhKCksXCIucHJpb3JpdHlcIjp0aGlzLkMoKS5KKCl9OnRoaXMuRWEoKX07XG5oLmhhc2g9ZnVuY3Rpb24oKXtpZihudWxsPT09dGhpcy5HYil7dmFyIGE9XCJcIjt0aGlzLmNhLmUoKXx8KGErPVwicHJpb3JpdHk6XCIrUmUodGhpcy5jYS5KKCkpK1wiOlwiKTt2YXIgYj10eXBlb2YgdGhpcy5CLGE9YSsoYitcIjpcIiksYT1cIm51bWJlclwiPT09Yj9hK0FkKHRoaXMuQik6YSt0aGlzLkI7dGhpcy5HYj1sZChhKX1yZXR1cm4gdGhpcy5HYn07aC5FYT1mdW5jdGlvbigpe3JldHVybiB0aGlzLkJ9O2guR2M9ZnVuY3Rpb24oYSl7aWYoYT09PUgpcmV0dXJuIDE7aWYoYSBpbnN0YW5jZW9mIGZlKXJldHVybi0xO08oYS5MKCksXCJVbmtub3duIG5vZGUgdHlwZVwiKTt2YXIgYj10eXBlb2YgYS5CLGM9dHlwZW9mIHRoaXMuQixkPUxhKFFlLGIpLGU9TGEoUWUsYyk7TygwPD1kLFwiVW5rbm93biBsZWFmIHR5cGU6IFwiK2IpO08oMDw9ZSxcIlVua25vd24gbGVhZiB0eXBlOiBcIitjKTtyZXR1cm4gZD09PWU/XCJvYmplY3RcIj09PWM/MDp0aGlzLkI8YS5CPy0xOnRoaXMuQj09PWEuQj8wOjE6ZS1kfTtcbmgucGI9ZnVuY3Rpb24oKXtyZXR1cm4gdGhpc307aC5NYz1mdW5jdGlvbigpe3JldHVybiEwfTtoLmVhPWZ1bmN0aW9uKGEpe3JldHVybiBhPT09dGhpcz8hMDphLkwoKT90aGlzLkI9PT1hLkImJnRoaXMuY2EuZWEoYS5jYSk6ITF9O2gudG9TdHJpbmc9ZnVuY3Rpb24oKXtyZXR1cm4gRyh0aGlzLkooITApKX07ZnVuY3Rpb24gZmUoYSxiLGMpe3RoaXMubT1hOyh0aGlzLmNhPWIpJiZQZSh0aGlzLmNhKTthLmUoKSYmTyghdGhpcy5jYXx8dGhpcy5jYS5lKCksXCJBbiBlbXB0eSBub2RlIGNhbm5vdCBoYXZlIGEgcHJpb3JpdHlcIik7dGhpcy5BYj1jO3RoaXMuR2I9bnVsbH1oPWZlLnByb3RvdHlwZTtoLkw9ZnVuY3Rpb24oKXtyZXR1cm4hMX07aC5DPWZ1bmN0aW9uKCl7cmV0dXJuIHRoaXMuY2F8fEh9O2guaWE9ZnVuY3Rpb24oYSl7cmV0dXJuIHRoaXMubS5lKCk/dGhpczpuZXcgZmUodGhpcy5tLGEsdGhpcy5BYil9O2guVD1mdW5jdGlvbihhKXtpZihcIi5wcmlvcml0eVwiPT09YSlyZXR1cm4gdGhpcy5DKCk7YT10aGlzLm0uZ2V0KGEpO3JldHVybiBudWxsPT09YT9IOmF9O2guUz1mdW5jdGlvbihhKXt2YXIgYj1LKGEpO3JldHVybiBudWxsPT09Yj90aGlzOnRoaXMuVChiKS5TKE4oYSkpfTtoLkZhPWZ1bmN0aW9uKGEpe3JldHVybiBudWxsIT09dGhpcy5tLmdldChhKX07XG5oLlc9ZnVuY3Rpb24oYSxiKXtPKGIsXCJXZSBzaG91bGQgYWx3YXlzIGJlIHBhc3Npbmcgc25hcHNob3Qgbm9kZXNcIik7aWYoXCIucHJpb3JpdHlcIj09PWEpcmV0dXJuIHRoaXMuaWEoYik7dmFyIGM9bmV3IEwoYSxiKSxkLGU7Yi5lKCk/KGQ9dGhpcy5tLnJlbW92ZShhKSxjPU5lKHRoaXMuQWIsYyx0aGlzLm0pKTooZD10aGlzLm0uU2EoYSxiKSxjPUxlKHRoaXMuQWIsYyx0aGlzLm0pKTtlPWQuZSgpP0g6dGhpcy5jYTtyZXR1cm4gbmV3IGZlKGQsZSxjKX07aC5IPWZ1bmN0aW9uKGEsYil7dmFyIGM9SyhhKTtpZihudWxsPT09YylyZXR1cm4gYjtPKFwiLnByaW9yaXR5XCIhPT1LKGEpfHwxPT09bGUoYSksXCIucHJpb3JpdHkgbXVzdCBiZSB0aGUgbGFzdCB0b2tlbiBpbiBhIHBhdGhcIik7dmFyIGQ9dGhpcy5UKGMpLkgoTihhKSxiKTtyZXR1cm4gdGhpcy5XKGMsZCl9O2guZT1mdW5jdGlvbigpe3JldHVybiB0aGlzLm0uZSgpfTtoLkhiPWZ1bmN0aW9uKCl7cmV0dXJuIHRoaXMubS5jb3VudCgpfTtcbnZhciBTZT0vXigwfFsxLTldXFxkKikkLztoPWZlLnByb3RvdHlwZTtoLko9ZnVuY3Rpb24oYSl7aWYodGhpcy5lKCkpcmV0dXJuIG51bGw7dmFyIGI9e30sYz0wLGQ9MCxlPSEwO3RoaXMuUihSLGZ1bmN0aW9uKGYsZyl7YltmXT1nLkooYSk7YysrO2UmJlNlLnRlc3QoZik/ZD1NYXRoLm1heChkLE51bWJlcihmKSk6ZT0hMX0pO2lmKCFhJiZlJiZkPDIqYyl7dmFyIGY9W10sZztmb3IoZyBpbiBiKWZbZ109YltnXTtyZXR1cm4gZn1hJiYhdGhpcy5DKCkuZSgpJiYoYltcIi5wcmlvcml0eVwiXT10aGlzLkMoKS5KKCkpO3JldHVybiBifTtoLmhhc2g9ZnVuY3Rpb24oKXtpZihudWxsPT09dGhpcy5HYil7dmFyIGE9XCJcIjt0aGlzLkMoKS5lKCl8fChhKz1cInByaW9yaXR5OlwiK1JlKHRoaXMuQygpLkooKSkrXCI6XCIpO3RoaXMuUihSLGZ1bmN0aW9uKGIsYyl7dmFyIGQ9Yy5oYXNoKCk7XCJcIiE9PWQmJihhKz1cIjpcIitiK1wiOlwiK2QpfSk7dGhpcy5HYj1cIlwiPT09YT9cIlwiOmxkKGEpfXJldHVybiB0aGlzLkdifTtcbmgud2Y9ZnVuY3Rpb24oYSxiLGMpe3JldHVybihjPVRlKHRoaXMsYykpPyhhPUdjKGMsbmV3IEwoYSxiKSkpP2EubmFtZTpudWxsOkdjKHRoaXMubSxhKX07ZnVuY3Rpb24gV2QoYSxiKXt2YXIgYztjPShjPVRlKGEsYikpPyhjPWMuVmMoKSkmJmMubmFtZTphLm0uVmMoKTtyZXR1cm4gYz9uZXcgTChjLGEubS5nZXQoYykpOm51bGx9ZnVuY3Rpb24gWGQoYSxiKXt2YXIgYztjPShjPVRlKGEsYikpPyhjPWMuamMoKSkmJmMubmFtZTphLm0uamMoKTtyZXR1cm4gYz9uZXcgTChjLGEubS5nZXQoYykpOm51bGx9aC5SPWZ1bmN0aW9uKGEsYil7dmFyIGM9VGUodGhpcyxhKTtyZXR1cm4gYz9jLmthKGZ1bmN0aW9uKGEpe3JldHVybiBiKGEubmFtZSxhLlUpfSk6dGhpcy5tLmthKGIpfTtoLmFjPWZ1bmN0aW9uKGEpe3JldHVybiB0aGlzLmJjKGEuV2MoKSxhKX07XG5oLmJjPWZ1bmN0aW9uKGEsYil7dmFyIGM9VGUodGhpcyxiKTtpZihjKXJldHVybiBjLmJjKGEsZnVuY3Rpb24oYSl7cmV0dXJuIGF9KTtmb3IodmFyIGM9dGhpcy5tLmJjKGEubmFtZSx3YyksZD1KYyhjKTtudWxsIT1kJiYwPmIuY29tcGFyZShkLGEpOylJYyhjKSxkPUpjKGMpO3JldHVybiBjfTtoLnhmPWZ1bmN0aW9uKGEpe3JldHVybiB0aGlzLmRjKGEuVGMoKSxhKX07aC5kYz1mdW5jdGlvbihhLGIpe3ZhciBjPVRlKHRoaXMsYik7aWYoYylyZXR1cm4gYy5kYyhhLGZ1bmN0aW9uKGEpe3JldHVybiBhfSk7Zm9yKHZhciBjPXRoaXMubS5kYyhhLm5hbWUsd2MpLGQ9SmMoYyk7bnVsbCE9ZCYmMDxiLmNvbXBhcmUoZCxhKTspSWMoYyksZD1KYyhjKTtyZXR1cm4gY307aC5HYz1mdW5jdGlvbihhKXtyZXR1cm4gdGhpcy5lKCk/YS5lKCk/MDotMTphLkwoKXx8YS5lKCk/MTphPT09d2U/LTE6MH07XG5oLnBiPWZ1bmN0aW9uKGEpe2lmKGE9PT1yZXx8c2EodGhpcy5BYi5oYyxhLnRvU3RyaW5nKCkpKXJldHVybiB0aGlzO3ZhciBiPXRoaXMuQWIsYz10aGlzLm07TyhhIT09cmUsXCJLZXlJbmRleCBhbHdheXMgZXhpc3RzIGFuZCBpc24ndCBtZWFudCB0byBiZSBhZGRlZCB0byB0aGUgSW5kZXhNYXAuXCIpO2Zvcih2YXIgZD1bXSxlPSExLGM9Yy5hYyh3YyksZj1JYyhjKTtmOyllPWV8fGEuTGMoZi5VKSxkLnB1c2goZiksZj1JYyhjKTtkPWU/TWUoZCxWZChhKSk6dGU7ZT1hLnRvU3RyaW5nKCk7Yz13YShiLmhjKTtjW2VdPWE7YT13YShiLkVkKTthW2VdPWQ7cmV0dXJuIG5ldyBmZSh0aGlzLm0sdGhpcy5jYSxuZXcgS2UoYSxjKSl9O2guTWM9ZnVuY3Rpb24oYSl7cmV0dXJuIGE9PT1yZXx8c2EodGhpcy5BYi5oYyxhLnRvU3RyaW5nKCkpfTtcbmguZWE9ZnVuY3Rpb24oYSl7aWYoYT09PXRoaXMpcmV0dXJuITA7aWYoYS5MKCkpcmV0dXJuITE7aWYodGhpcy5DKCkuZWEoYS5DKCkpJiZ0aGlzLm0uY291bnQoKT09PWEubS5jb3VudCgpKXt2YXIgYj10aGlzLmFjKFIpO2E9YS5hYyhSKTtmb3IodmFyIGM9SWMoYiksZD1JYyhhKTtjJiZkOyl7aWYoYy5uYW1lIT09ZC5uYW1lfHwhYy5VLmVhKGQuVSkpcmV0dXJuITE7Yz1JYyhiKTtkPUljKGEpfXJldHVybiBudWxsPT09YyYmbnVsbD09PWR9cmV0dXJuITF9O2Z1bmN0aW9uIFRlKGEsYil7cmV0dXJuIGI9PT1yZT9udWxsOmEuQWIuZ2V0KGIudG9TdHJpbmcoKSl9aC50b1N0cmluZz1mdW5jdGlvbigpe3JldHVybiBHKHRoaXMuSighMCkpfTtmdW5jdGlvbiBRKGEsYil7aWYobnVsbD09PWEpcmV0dXJuIEg7dmFyIGM9bnVsbDtcIm9iamVjdFwiPT09dHlwZW9mIGEmJlwiLnByaW9yaXR5XCJpbiBhP2M9YVtcIi5wcmlvcml0eVwiXTpcInVuZGVmaW5lZFwiIT09dHlwZW9mIGImJihjPWIpO08obnVsbD09PWN8fFwic3RyaW5nXCI9PT10eXBlb2YgY3x8XCJudW1iZXJcIj09PXR5cGVvZiBjfHxcIm9iamVjdFwiPT09dHlwZW9mIGMmJlwiLnN2XCJpbiBjLFwiSW52YWxpZCBwcmlvcml0eSB0eXBlIGZvdW5kOiBcIit0eXBlb2YgYyk7XCJvYmplY3RcIj09PXR5cGVvZiBhJiZcIi52YWx1ZVwiaW4gYSYmbnVsbCE9PWFbXCIudmFsdWVcIl0mJihhPWFbXCIudmFsdWVcIl0pO2lmKFwib2JqZWN0XCIhPT10eXBlb2YgYXx8XCIuc3ZcImluIGEpcmV0dXJuIG5ldyBZYyhhLFEoYykpO2lmKGEgaW5zdGFuY2VvZiBBcnJheSl7dmFyIGQ9SCxlPWE7dihlLGZ1bmN0aW9uKGEsYil7aWYoeShlLGIpJiZcIi5cIiE9PWIuc3Vic3RyaW5nKDAsMSkpe3ZhciBjPVEoYSk7aWYoYy5MKCl8fCFjLmUoKSlkPVxuZC5XKGIsYyl9fSk7cmV0dXJuIGQuaWEoUShjKSl9dmFyIGY9W10sZz0hMSxrPWE7RmIoayxmdW5jdGlvbihhKXtpZihcInN0cmluZ1wiIT09dHlwZW9mIGF8fFwiLlwiIT09YS5zdWJzdHJpbmcoMCwxKSl7dmFyIGI9UShrW2FdKTtiLmUoKXx8KGc9Z3x8IWIuQygpLmUoKSxmLnB1c2gobmV3IEwoYSxiKSkpfX0pO2lmKDA9PWYubGVuZ3RoKXJldHVybiBIO3ZhciBtPU1lKGYseGMsZnVuY3Rpb24oYSl7cmV0dXJuIGEubmFtZX0semMpO2lmKGcpe3ZhciBsPU1lKGYsVmQoUikpO3JldHVybiBuZXcgZmUobSxRKGMpLG5ldyBLZSh7XCIucHJpb3JpdHlcIjpsfSx7XCIucHJpb3JpdHlcIjpSfSkpfXJldHVybiBuZXcgZmUobSxRKGMpLE9lKX12YXIgVWU9TWF0aC5sb2coMik7XG5mdW5jdGlvbiBWZShhKXt0aGlzLmNvdW50PXBhcnNlSW50KE1hdGgubG9nKGErMSkvVWUsMTApO3RoaXMubmY9dGhpcy5jb3VudC0xO3RoaXMubmc9YSsxJnBhcnNlSW50KEFycmF5KHRoaXMuY291bnQrMSkuam9pbihcIjFcIiksMil9ZnVuY3Rpb24gV2UoYSl7dmFyIGI9IShhLm5nJjE8PGEubmYpO2EubmYtLTtyZXR1cm4gYn1cbmZ1bmN0aW9uIE1lKGEsYixjLGQpe2Z1bmN0aW9uIGUoYixkKXt2YXIgZj1kLWI7aWYoMD09ZilyZXR1cm4gbnVsbDtpZigxPT1mKXt2YXIgbD1hW2JdLHQ9Yz9jKGwpOmw7cmV0dXJuIG5ldyBLYyh0LGwuVSwhMSxudWxsLG51bGwpfXZhciBsPXBhcnNlSW50KGYvMiwxMCkrYixmPWUoYixsKSxBPWUobCsxLGQpLGw9YVtsXSx0PWM/YyhsKTpsO3JldHVybiBuZXcgS2ModCxsLlUsITEsZixBKX1hLnNvcnQoYik7dmFyIGY9ZnVuY3Rpb24oYil7ZnVuY3Rpb24gZChiLGcpe3ZhciBrPXQtYixBPXQ7dC09Yjt2YXIgQT1lKGsrMSxBKSxrPWFba10sST1jP2Moayk6ayxBPW5ldyBLYyhJLGsuVSxnLG51bGwsQSk7Zj9mLmxlZnQ9QTpsPUE7Zj1BfWZvcih2YXIgZj1udWxsLGw9bnVsbCx0PWEubGVuZ3RoLEE9MDtBPGIuY291bnQ7KytBKXt2YXIgST1XZShiKSxRZD1NYXRoLnBvdygyLGIuY291bnQtKEErMSkpO0k/ZChRZCwhMSk6KGQoUWQsITEpLGQoUWQsITApKX1yZXR1cm4gbH0obmV3IFZlKGEubGVuZ3RoKSk7XG5yZXR1cm4gbnVsbCE9PWY/bmV3IEVjKGR8fGIsZik6bmV3IEVjKGR8fGIpfWZ1bmN0aW9uIFJlKGEpe3JldHVyblwibnVtYmVyXCI9PT10eXBlb2YgYT9cIm51bWJlcjpcIitBZChhKTpcInN0cmluZzpcIithfWZ1bmN0aW9uIFBlKGEpe2lmKGEuTCgpKXt2YXIgYj1hLkooKTtPKFwic3RyaW5nXCI9PT10eXBlb2YgYnx8XCJudW1iZXJcIj09PXR5cGVvZiBifHxcIm9iamVjdFwiPT09dHlwZW9mIGImJnkoYixcIi5zdlwiKSxcIlByaW9yaXR5IG11c3QgYmUgYSBzdHJpbmcgb3IgbnVtYmVyLlwiKX1lbHNlIE8oYT09PXdlfHxhLmUoKSxcInByaW9yaXR5IG9mIHVuZXhwZWN0ZWQgdHlwZS5cIik7TyhhPT09d2V8fGEuQygpLmUoKSxcIlByaW9yaXR5IG5vZGVzIGNhbid0IGhhdmUgYSBwcmlvcml0eSBvZiB0aGVpciBvd24uXCIpfXZhciBIPW5ldyBmZShuZXcgRWMoemMpLG51bGwsT2UpO2Z1bmN0aW9uIFhlKCl7ZmUuY2FsbCh0aGlzLG5ldyBFYyh6YyksSCxPZSl9a2EoWGUsZmUpO2g9WGUucHJvdG90eXBlO1xuaC5HYz1mdW5jdGlvbihhKXtyZXR1cm4gYT09PXRoaXM/MDoxfTtoLmVhPWZ1bmN0aW9uKGEpe3JldHVybiBhPT09dGhpc307aC5DPWZ1bmN0aW9uKCl7cmV0dXJuIHRoaXN9O2guVD1mdW5jdGlvbigpe3JldHVybiBIfTtoLmU9ZnVuY3Rpb24oKXtyZXR1cm4hMX07dmFyIHdlPW5ldyBYZSx1ZT1uZXcgTChcIltNSU5fTkFNRV1cIixIKSxBZT1uZXcgTChcIltNQVhfTkFNRV1cIix3ZSk7ZnVuY3Rpb24gamUoYSxiKXt0aGlzLlE9YTt0aGlzLmFlPWJ9ZnVuY3Rpb24gZ2UoYSxiLGMsZCl7cmV0dXJuIG5ldyBqZShuZXcgWGIoYixjLGQpLGEuYWUpfWZ1bmN0aW9uIGtlKGEpe3JldHVybiBhLlEuZ2E/YS5RLmooKTpudWxsfWplLnByb3RvdHlwZS53PWZ1bmN0aW9uKCl7cmV0dXJuIHRoaXMuYWV9O2Z1bmN0aW9uIFliKGEpe3JldHVybiBhLmFlLmdhP2EuYWUuaigpOm51bGx9O2Z1bmN0aW9uIFllKGEsYil7dGhpcy5ZPWE7dmFyIGM9YS5uLGQ9bmV3IExkKGMuZyksYz1IZShjKT9uZXcgTGQoYy5nKTpjLmxhP25ldyBTZChjKTpuZXcgTWQoYyk7dGhpcy5OZj1uZXcgWmQoYyk7dmFyIGU9Yi53KCksZj1iLlEsZz1kLnlhKEgsZS5qKCksbnVsbCksaz1jLnlhKEgsZi5qKCksbnVsbCk7dGhpcy5PYT1uZXcgamUobmV3IFhiKGssZi5nYSxjLlJhKCkpLG5ldyBYYihnLGUuZ2EsZC5SYSgpKSk7dGhpcy4kYT1bXTt0aGlzLnVnPW5ldyBGZChhKX1mdW5jdGlvbiBaZShhKXtyZXR1cm4gYS5ZfWg9WWUucHJvdG90eXBlO2gudz1mdW5jdGlvbigpe3JldHVybiB0aGlzLk9hLncoKS5qKCl9O2gua2I9ZnVuY3Rpb24oYSl7dmFyIGI9WWIodGhpcy5PYSk7cmV0dXJuIGImJihIZSh0aGlzLlkubil8fCFhLmUoKSYmIWIuVChLKGEpKS5lKCkpP2IuUyhhKTpudWxsfTtoLmU9ZnVuY3Rpb24oKXtyZXR1cm4gMD09PXRoaXMuJGEubGVuZ3RofTtoLlRiPWZ1bmN0aW9uKGEpe3RoaXMuJGEucHVzaChhKX07XG5oLm5iPWZ1bmN0aW9uKGEsYil7dmFyIGM9W107aWYoYil7TyhudWxsPT1hLFwiQSBjYW5jZWwgc2hvdWxkIGNhbmNlbCBhbGwgZXZlbnQgcmVnaXN0cmF0aW9ucy5cIik7dmFyIGQ9dGhpcy5ZLnBhdGg7TWEodGhpcy4kYSxmdW5jdGlvbihhKXsoYT1hLmxmKGIsZCkpJiZjLnB1c2goYSl9KX1pZihhKXtmb3IodmFyIGU9W10sZj0wO2Y8dGhpcy4kYS5sZW5ndGg7KytmKXt2YXIgZz10aGlzLiRhW2ZdO2lmKCFnLm1hdGNoZXMoYSkpZS5wdXNoKGcpO2Vsc2UgaWYoYS55ZigpKXtlPWUuY29uY2F0KHRoaXMuJGEuc2xpY2UoZisxKSk7YnJlYWt9fXRoaXMuJGE9ZX1lbHNlIHRoaXMuJGE9W107cmV0dXJuIGN9O1xuaC5nYj1mdW5jdGlvbihhLGIsYyl7YS50eXBlPT09YmUmJm51bGwhPT1hLnNvdXJjZS5MYiYmKE8oWWIodGhpcy5PYSksXCJXZSBzaG91bGQgYWx3YXlzIGhhdmUgYSBmdWxsIGNhY2hlIGJlZm9yZSBoYW5kbGluZyBtZXJnZXNcIiksTyhrZSh0aGlzLk9hKSxcIk1pc3NpbmcgZXZlbnQgY2FjaGUsIGV2ZW4gdGhvdWdoIHdlIGhhdmUgYSBzZXJ2ZXIgY2FjaGVcIikpO3ZhciBkPXRoaXMuT2E7YT10aGlzLk5mLmdiKGQsYSxiLGMpO2I9dGhpcy5OZjtjPWEubWU7TyhjLlEuaigpLk1jKGIuWC5nKSxcIkV2ZW50IHNuYXAgbm90IGluZGV4ZWRcIik7TyhjLncoKS5qKCkuTWMoYi5YLmcpLFwiU2VydmVyIHNuYXAgbm90IGluZGV4ZWRcIik7TyhsYyhhLm1lLncoKSl8fCFsYyhkLncoKSksXCJPbmNlIGEgc2VydmVyIHNuYXAgaXMgY29tcGxldGUsIGl0IHNob3VsZCBuZXZlciBnbyBiYWNrXCIpO3RoaXMuT2E9YS5tZTtyZXR1cm4gJGUodGhpcyxhLm9nLGEubWUuUS5qKCksbnVsbCl9O1xuZnVuY3Rpb24gYWYoYSxiKXt2YXIgYz1hLk9hLlEsZD1bXTtjLmooKS5MKCl8fGMuaigpLlIoUixmdW5jdGlvbihhLGIpe2QucHVzaChuZXcgSihcImNoaWxkX2FkZGVkXCIsYixhKSl9KTtjLmdhJiZkLnB1c2goaGMoYy5qKCkpKTtyZXR1cm4gJGUoYSxkLGMuaigpLGIpfWZ1bmN0aW9uICRlKGEsYixjLGQpe3JldHVybiBHZChhLnVnLGIsYyxkP1tkXTphLiRhKX07ZnVuY3Rpb24gYmYoYSxiLGMpe3RoaXMudHlwZT1iZTt0aGlzLnNvdXJjZT1hO3RoaXMucGF0aD1iO3RoaXMuY2hpbGRyZW49Y31iZi5wcm90b3R5cGUuJGM9ZnVuY3Rpb24oYSl7aWYodGhpcy5wYXRoLmUoKSlyZXR1cm4gYT10aGlzLmNoaWxkcmVuLnN1YnRyZWUobmV3IFAoYSkpLGEuZSgpP251bGw6YS52YWx1ZT9uZXcgQWModGhpcy5zb3VyY2UsTSxhLnZhbHVlKTpuZXcgYmYodGhpcy5zb3VyY2UsTSxhKTtPKEsodGhpcy5wYXRoKT09PWEsXCJDYW4ndCBnZXQgYSBtZXJnZSBmb3IgYSBjaGlsZCBub3Qgb24gdGhlIHBhdGggb2YgdGhlIG9wZXJhdGlvblwiKTtyZXR1cm4gbmV3IGJmKHRoaXMuc291cmNlLE4odGhpcy5wYXRoKSx0aGlzLmNoaWxkcmVuKX07YmYucHJvdG90eXBlLnRvU3RyaW5nPWZ1bmN0aW9uKCl7cmV0dXJuXCJPcGVyYXRpb24oXCIrdGhpcy5wYXRoK1wiOiBcIit0aGlzLnNvdXJjZS50b1N0cmluZygpK1wiIG1lcmdlOiBcIit0aGlzLmNoaWxkcmVuLnRvU3RyaW5nKCkrXCIpXCJ9O2Z1bmN0aW9uIGNmKGEsYil7dGhpcy5mPXBkKFwicDpyZXN0OlwiKTt0aGlzLkc9YTt0aGlzLktiPWI7dGhpcy5DYT1udWxsO3RoaXMuYmE9e319ZnVuY3Rpb24gZGYoYSxiKXtpZihwKGIpKXJldHVyblwidGFnJFwiK2I7TyhJZShhLm4pLFwic2hvdWxkIGhhdmUgYSB0YWcgaWYgaXQncyBub3QgYSBkZWZhdWx0IHF1ZXJ5LlwiKTtyZXR1cm4gYS5wYXRoLnRvU3RyaW5nKCl9aD1jZi5wcm90b3R5cGU7XG5oLkNmPWZ1bmN0aW9uKGEsYixjLGQpe3ZhciBlPWEucGF0aC50b1N0cmluZygpO3RoaXMuZihcIkxpc3RlbiBjYWxsZWQgZm9yIFwiK2UrXCIgXCIrYS53YSgpKTt2YXIgZj1kZihhLGMpLGc9e307dGhpcy5iYVtmXT1nO2E9SmUoYS5uKTt2YXIgaz10aGlzO2VmKHRoaXMsZStcIi5qc29uXCIsYSxmdW5jdGlvbihhLGIpe3ZhciB0PWI7NDA0PT09YSYmKGE9dD1udWxsKTtudWxsPT09YSYmay5LYihlLHQsITEsYyk7eihrLmJhLGYpPT09ZyYmZChhPzQwMT09YT9cInBlcm1pc3Npb25fZGVuaWVkXCI6XCJyZXN0X2Vycm9yOlwiK2E6XCJva1wiLG51bGwpfSl9O2guJGY9ZnVuY3Rpb24oYSxiKXt2YXIgYz1kZihhLGIpO2RlbGV0ZSB0aGlzLmJhW2NdfTtoLk89ZnVuY3Rpb24oYSxiKXt0aGlzLkNhPWE7dmFyIGM9Q2QoYSksZD1jLmRhdGEsYz1jLkVjJiZjLkVjLmV4cDtiJiZiKFwib2tcIix7YXV0aDpkLGV4cGlyZXM6Y30pfTtoLmplPWZ1bmN0aW9uKGEpe3RoaXMuQ2E9bnVsbDthKFwib2tcIixudWxsKX07XG5oLlFlPWZ1bmN0aW9uKCl7fTtoLkdmPWZ1bmN0aW9uKCl7fTtoLk1kPWZ1bmN0aW9uKCl7fTtoLnB1dD1mdW5jdGlvbigpe307aC5EZj1mdW5jdGlvbigpe307aC5ZZT1mdW5jdGlvbigpe307XG5mdW5jdGlvbiBlZihhLGIsYyxkKXtjPWN8fHt9O2MuZm9ybWF0PVwiZXhwb3J0XCI7YS5DYSYmKGMuYXV0aD1hLkNhKTt2YXIgZT0oYS5HLm9iP1wiaHR0cHM6Ly9cIjpcImh0dHA6Ly9cIikrYS5HLmhvc3QrYitcIj9cIitJYihjKTthLmYoXCJTZW5kaW5nIFJFU1QgcmVxdWVzdCBmb3IgXCIrZSk7dmFyIGY9bmV3IFhNTEh0dHBSZXF1ZXN0O2Yub25yZWFkeXN0YXRlY2hhbmdlPWZ1bmN0aW9uKCl7aWYoZCYmND09PWYucmVhZHlTdGF0ZSl7YS5mKFwiUkVTVCBSZXNwb25zZSBmb3IgXCIrZStcIiByZWNlaXZlZC4gc3RhdHVzOlwiLGYuc3RhdHVzLFwicmVzcG9uc2U6XCIsZi5yZXNwb25zZVRleHQpO3ZhciBiPW51bGw7aWYoMjAwPD1mLnN0YXR1cyYmMzAwPmYuc3RhdHVzKXt0cnl7Yj1SYihmLnJlc3BvbnNlVGV4dCl9Y2F0Y2goYyl7UyhcIkZhaWxlZCB0byBwYXJzZSBKU09OIHJlc3BvbnNlIGZvciBcIitlK1wiOiBcIitmLnJlc3BvbnNlVGV4dCl9ZChudWxsLGIpfWVsc2UgNDAxIT09Zi5zdGF0dXMmJjQwNCE9PVxuZi5zdGF0dXMmJlMoXCJHb3QgdW5zdWNjZXNzZnVsIFJFU1QgcmVzcG9uc2UgZm9yIFwiK2UrXCIgU3RhdHVzOiBcIitmLnN0YXR1cyksZChmLnN0YXR1cyk7ZD1udWxsfX07Zi5vcGVuKFwiR0VUXCIsZSwhMCk7Zi5zZW5kKCl9O2Z1bmN0aW9uIGZmKGEpe08oZGEoYSkmJjA8YS5sZW5ndGgsXCJSZXF1aXJlcyBhIG5vbi1lbXB0eSBhcnJheVwiKTt0aGlzLmZnPWE7dGhpcy5SYz17fX1mZi5wcm90b3R5cGUuaWU9ZnVuY3Rpb24oYSxiKXt2YXIgYztjPXRoaXMuUmNbYV18fFtdO3ZhciBkPWMubGVuZ3RoO2lmKDA8ZCl7Zm9yKHZhciBlPUFycmF5KGQpLGY9MDtmPGQ7ZisrKWVbZl09Y1tmXTtjPWV9ZWxzZSBjPVtdO2ZvcihkPTA7ZDxjLmxlbmd0aDtkKyspY1tkXS5EYy5hcHBseShjW2RdLlFhLEFycmF5LnByb3RvdHlwZS5zbGljZS5jYWxsKGFyZ3VtZW50cywxKSl9O2ZmLnByb3RvdHlwZS5JYj1mdW5jdGlvbihhLGIsYyl7Z2YodGhpcyxhKTt0aGlzLlJjW2FdPXRoaXMuUmNbYV18fFtdO3RoaXMuUmNbYV0ucHVzaCh7RGM6YixRYTpjfSk7KGE9dGhpcy5FZShhKSkmJmIuYXBwbHkoYyxhKX07XG5mZi5wcm90b3R5cGUubWM9ZnVuY3Rpb24oYSxiLGMpe2dmKHRoaXMsYSk7YT10aGlzLlJjW2FdfHxbXTtmb3IodmFyIGQ9MDtkPGEubGVuZ3RoO2QrKylpZihhW2RdLkRjPT09YiYmKCFjfHxjPT09YVtkXS5RYSkpe2Euc3BsaWNlKGQsMSk7YnJlYWt9fTtmdW5jdGlvbiBnZihhLGIpe08oUmEoYS5mZyxmdW5jdGlvbihhKXtyZXR1cm4gYT09PWJ9KSxcIlVua25vd24gZXZlbnQ6IFwiK2IpfTt2YXIgaGY9ZnVuY3Rpb24oKXt2YXIgYT0wLGI9W107cmV0dXJuIGZ1bmN0aW9uKGMpe3ZhciBkPWM9PT1hO2E9Yztmb3IodmFyIGU9QXJyYXkoOCksZj03OzA8PWY7Zi0tKWVbZl09XCItMDEyMzQ1Njc4OUFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaX2FiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6XCIuY2hhckF0KGMlNjQpLGM9TWF0aC5mbG9vcihjLzY0KTtPKDA9PT1jLFwiQ2Fubm90IHB1c2ggYXQgdGltZSA9PSAwXCIpO2M9ZS5qb2luKFwiXCIpO2lmKGQpe2ZvcihmPTExOzA8PWYmJjYzPT09YltmXTtmLS0pYltmXT0wO2JbZl0rK31lbHNlIGZvcihmPTA7MTI+ZjtmKyspYltmXT1NYXRoLmZsb29yKDY0Kk1hdGgucmFuZG9tKCkpO2ZvcihmPTA7MTI+ZjtmKyspYys9XCItMDEyMzQ1Njc4OUFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaX2FiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6XCIuY2hhckF0KGJbZl0pO08oMjA9PT1jLmxlbmd0aCxcIm5leHRQdXNoSWQ6IExlbmd0aCBzaG91bGQgYmUgMjAuXCIpO1xucmV0dXJuIGN9fSgpO2Z1bmN0aW9uIGpmKCl7ZmYuY2FsbCh0aGlzLFtcIm9ubGluZVwiXSk7dGhpcy5vYz0hMDtpZihcInVuZGVmaW5lZFwiIT09dHlwZW9mIHdpbmRvdyYmXCJ1bmRlZmluZWRcIiE9PXR5cGVvZiB3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcil7dmFyIGE9dGhpczt3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcihcIm9ubGluZVwiLGZ1bmN0aW9uKCl7YS5vY3x8KGEub2M9ITAsYS5pZShcIm9ubGluZVwiLCEwKSl9LCExKTt3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcihcIm9mZmxpbmVcIixmdW5jdGlvbigpe2Eub2MmJihhLm9jPSExLGEuaWUoXCJvbmxpbmVcIiwhMSkpfSwhMSl9fWthKGpmLGZmKTtqZi5wcm90b3R5cGUuRWU9ZnVuY3Rpb24oYSl7TyhcIm9ubGluZVwiPT09YSxcIlVua25vd24gZXZlbnQgdHlwZTogXCIrYSk7cmV0dXJuW3RoaXMub2NdfTtiYShqZik7ZnVuY3Rpb24ga2YoKXtmZi5jYWxsKHRoaXMsW1widmlzaWJsZVwiXSk7dmFyIGEsYjtcInVuZGVmaW5lZFwiIT09dHlwZW9mIGRvY3VtZW50JiZcInVuZGVmaW5lZFwiIT09dHlwZW9mIGRvY3VtZW50LmFkZEV2ZW50TGlzdGVuZXImJihcInVuZGVmaW5lZFwiIT09dHlwZW9mIGRvY3VtZW50LmhpZGRlbj8oYj1cInZpc2liaWxpdHljaGFuZ2VcIixhPVwiaGlkZGVuXCIpOlwidW5kZWZpbmVkXCIhPT10eXBlb2YgZG9jdW1lbnQubW96SGlkZGVuPyhiPVwibW96dmlzaWJpbGl0eWNoYW5nZVwiLGE9XCJtb3pIaWRkZW5cIik6XCJ1bmRlZmluZWRcIiE9PXR5cGVvZiBkb2N1bWVudC5tc0hpZGRlbj8oYj1cIm1zdmlzaWJpbGl0eWNoYW5nZVwiLGE9XCJtc0hpZGRlblwiKTpcInVuZGVmaW5lZFwiIT09dHlwZW9mIGRvY3VtZW50LndlYmtpdEhpZGRlbiYmKGI9XCJ3ZWJraXR2aXNpYmlsaXR5Y2hhbmdlXCIsYT1cIndlYmtpdEhpZGRlblwiKSk7dGhpcy5TYj0hMDtpZihiKXt2YXIgYz10aGlzO2RvY3VtZW50LmFkZEV2ZW50TGlzdGVuZXIoYixcbmZ1bmN0aW9uKCl7dmFyIGI9IWRvY3VtZW50W2FdO2IhPT1jLlNiJiYoYy5TYj1iLGMuaWUoXCJ2aXNpYmxlXCIsYikpfSwhMSl9fWthKGtmLGZmKTtrZi5wcm90b3R5cGUuRWU9ZnVuY3Rpb24oYSl7TyhcInZpc2libGVcIj09PWEsXCJVbmtub3duIGV2ZW50IHR5cGU6IFwiK2EpO3JldHVyblt0aGlzLlNiXX07YmEoa2YpO2Z1bmN0aW9uIFAoYSxiKXtpZigxPT1hcmd1bWVudHMubGVuZ3RoKXt0aGlzLnU9YS5zcGxpdChcIi9cIik7Zm9yKHZhciBjPTAsZD0wO2Q8dGhpcy51Lmxlbmd0aDtkKyspMDx0aGlzLnVbZF0ubGVuZ3RoJiYodGhpcy51W2NdPXRoaXMudVtkXSxjKyspO3RoaXMudS5sZW5ndGg9Yzt0aGlzLmFhPTB9ZWxzZSB0aGlzLnU9YSx0aGlzLmFhPWJ9ZnVuY3Rpb24gbGYoYSxiKXt2YXIgYz1LKGEpO2lmKG51bGw9PT1jKXJldHVybiBiO2lmKGM9PT1LKGIpKXJldHVybiBsZihOKGEpLE4oYikpO3Rocm93IEVycm9yKFwiSU5URVJOQUwgRVJST1I6IGlubmVyUGF0aCAoXCIrYitcIikgaXMgbm90IHdpdGhpbiBvdXRlclBhdGggKFwiK2ErXCIpXCIpO31cbmZ1bmN0aW9uIG1mKGEsYil7Zm9yKHZhciBjPWEuc2xpY2UoKSxkPWIuc2xpY2UoKSxlPTA7ZTxjLmxlbmd0aCYmZTxkLmxlbmd0aDtlKyspe3ZhciBmPXljKGNbZV0sZFtlXSk7aWYoMCE9PWYpcmV0dXJuIGZ9cmV0dXJuIGMubGVuZ3RoPT09ZC5sZW5ndGg/MDpjLmxlbmd0aDxkLmxlbmd0aD8tMToxfWZ1bmN0aW9uIEsoYSl7cmV0dXJuIGEuYWE+PWEudS5sZW5ndGg/bnVsbDphLnVbYS5hYV19ZnVuY3Rpb24gbGUoYSl7cmV0dXJuIGEudS5sZW5ndGgtYS5hYX1mdW5jdGlvbiBOKGEpe3ZhciBiPWEuYWE7YjxhLnUubGVuZ3RoJiZiKys7cmV0dXJuIG5ldyBQKGEudSxiKX1mdW5jdGlvbiBtZShhKXtyZXR1cm4gYS5hYTxhLnUubGVuZ3RoP2EudVthLnUubGVuZ3RoLTFdOm51bGx9aD1QLnByb3RvdHlwZTtcbmgudG9TdHJpbmc9ZnVuY3Rpb24oKXtmb3IodmFyIGE9XCJcIixiPXRoaXMuYWE7Yjx0aGlzLnUubGVuZ3RoO2IrKylcIlwiIT09dGhpcy51W2JdJiYoYSs9XCIvXCIrdGhpcy51W2JdKTtyZXR1cm4gYXx8XCIvXCJ9O2guc2xpY2U9ZnVuY3Rpb24oYSl7cmV0dXJuIHRoaXMudS5zbGljZSh0aGlzLmFhKyhhfHwwKSl9O2gucGFyZW50PWZ1bmN0aW9uKCl7aWYodGhpcy5hYT49dGhpcy51Lmxlbmd0aClyZXR1cm4gbnVsbDtmb3IodmFyIGE9W10sYj10aGlzLmFhO2I8dGhpcy51Lmxlbmd0aC0xO2IrKylhLnB1c2godGhpcy51W2JdKTtyZXR1cm4gbmV3IFAoYSwwKX07XG5oLm89ZnVuY3Rpb24oYSl7Zm9yKHZhciBiPVtdLGM9dGhpcy5hYTtjPHRoaXMudS5sZW5ndGg7YysrKWIucHVzaCh0aGlzLnVbY10pO2lmKGEgaW5zdGFuY2VvZiBQKWZvcihjPWEuYWE7YzxhLnUubGVuZ3RoO2MrKyliLnB1c2goYS51W2NdKTtlbHNlIGZvcihhPWEuc3BsaXQoXCIvXCIpLGM9MDtjPGEubGVuZ3RoO2MrKykwPGFbY10ubGVuZ3RoJiZiLnB1c2goYVtjXSk7cmV0dXJuIG5ldyBQKGIsMCl9O2guZT1mdW5jdGlvbigpe3JldHVybiB0aGlzLmFhPj10aGlzLnUubGVuZ3RofTtoLmVhPWZ1bmN0aW9uKGEpe2lmKGxlKHRoaXMpIT09bGUoYSkpcmV0dXJuITE7Zm9yKHZhciBiPXRoaXMuYWEsYz1hLmFhO2I8PXRoaXMudS5sZW5ndGg7YisrLGMrKylpZih0aGlzLnVbYl0hPT1hLnVbY10pcmV0dXJuITE7cmV0dXJuITB9O1xuaC5jb250YWlucz1mdW5jdGlvbihhKXt2YXIgYj10aGlzLmFhLGM9YS5hYTtpZihsZSh0aGlzKT5sZShhKSlyZXR1cm4hMTtmb3IoO2I8dGhpcy51Lmxlbmd0aDspe2lmKHRoaXMudVtiXSE9PWEudVtjXSlyZXR1cm4hMTsrK2I7KytjfXJldHVybiEwfTt2YXIgTT1uZXcgUChcIlwiKTtmdW5jdGlvbiBuZihhLGIpe3RoaXMuVWE9YS5zbGljZSgpO3RoaXMuS2E9TWF0aC5tYXgoMSx0aGlzLlVhLmxlbmd0aCk7dGhpcy5wZj1iO2Zvcih2YXIgYz0wO2M8dGhpcy5VYS5sZW5ndGg7YysrKXRoaXMuS2ErPVBiKHRoaXMuVWFbY10pO29mKHRoaXMpfW5mLnByb3RvdHlwZS5wdXNoPWZ1bmN0aW9uKGEpezA8dGhpcy5VYS5sZW5ndGgmJih0aGlzLkthKz0xKTt0aGlzLlVhLnB1c2goYSk7dGhpcy5LYSs9UGIoYSk7b2YodGhpcyl9O25mLnByb3RvdHlwZS5wb3A9ZnVuY3Rpb24oKXt2YXIgYT10aGlzLlVhLnBvcCgpO3RoaXMuS2EtPVBiKGEpOzA8dGhpcy5VYS5sZW5ndGgmJi0tdGhpcy5LYX07XG5mdW5jdGlvbiBvZihhKXtpZig3Njg8YS5LYSl0aHJvdyBFcnJvcihhLnBmK1wiaGFzIGEga2V5IHBhdGggbG9uZ2VyIHRoYW4gNzY4IGJ5dGVzIChcIithLkthK1wiKS5cIik7aWYoMzI8YS5VYS5sZW5ndGgpdGhyb3cgRXJyb3IoYS5wZitcInBhdGggc3BlY2lmaWVkIGV4Y2VlZHMgdGhlIG1heGltdW0gZGVwdGggdGhhdCBjYW4gYmUgd3JpdHRlbiAoMzIpIG9yIG9iamVjdCBjb250YWlucyBhIGN5Y2xlIFwiK3BmKGEpKTt9ZnVuY3Rpb24gcGYoYSl7cmV0dXJuIDA9PWEuVWEubGVuZ3RoP1wiXCI6XCJpbiBwcm9wZXJ0eSAnXCIrYS5VYS5qb2luKFwiLlwiKStcIidcIn07ZnVuY3Rpb24gcWYoYSxiKXt0aGlzLnZhbHVlPWE7dGhpcy5jaGlsZHJlbj1ifHxyZn12YXIgcmY9bmV3IEVjKGZ1bmN0aW9uKGEsYil7cmV0dXJuIGE9PT1iPzA6YTxiPy0xOjF9KTtmdW5jdGlvbiBzZihhKXt2YXIgYj1xZTt2KGEsZnVuY3Rpb24oYSxkKXtiPWIuc2V0KG5ldyBQKGQpLGEpfSk7cmV0dXJuIGJ9aD1xZi5wcm90b3R5cGU7aC5lPWZ1bmN0aW9uKCl7cmV0dXJuIG51bGw9PT10aGlzLnZhbHVlJiZ0aGlzLmNoaWxkcmVuLmUoKX07ZnVuY3Rpb24gdGYoYSxiLGMpe2lmKG51bGwhPWEudmFsdWUmJmMoYS52YWx1ZSkpcmV0dXJue3BhdGg6TSx2YWx1ZTphLnZhbHVlfTtpZihiLmUoKSlyZXR1cm4gbnVsbDt2YXIgZD1LKGIpO2E9YS5jaGlsZHJlbi5nZXQoZCk7cmV0dXJuIG51bGwhPT1hPyhiPXRmKGEsTihiKSxjKSxudWxsIT1iP3twYXRoOihuZXcgUChkKSkubyhiLnBhdGgpLHZhbHVlOmIudmFsdWV9Om51bGwpOm51bGx9XG5mdW5jdGlvbiB1ZihhLGIpe3JldHVybiB0ZihhLGIsZnVuY3Rpb24oKXtyZXR1cm4hMH0pfWguc3VidHJlZT1mdW5jdGlvbihhKXtpZihhLmUoKSlyZXR1cm4gdGhpczt2YXIgYj10aGlzLmNoaWxkcmVuLmdldChLKGEpKTtyZXR1cm4gbnVsbCE9PWI/Yi5zdWJ0cmVlKE4oYSkpOnFlfTtoLnNldD1mdW5jdGlvbihhLGIpe2lmKGEuZSgpKXJldHVybiBuZXcgcWYoYix0aGlzLmNoaWxkcmVuKTt2YXIgYz1LKGEpLGQ9KHRoaXMuY2hpbGRyZW4uZ2V0KGMpfHxxZSkuc2V0KE4oYSksYiksYz10aGlzLmNoaWxkcmVuLlNhKGMsZCk7cmV0dXJuIG5ldyBxZih0aGlzLnZhbHVlLGMpfTtcbmgucmVtb3ZlPWZ1bmN0aW9uKGEpe2lmKGEuZSgpKXJldHVybiB0aGlzLmNoaWxkcmVuLmUoKT9xZTpuZXcgcWYobnVsbCx0aGlzLmNoaWxkcmVuKTt2YXIgYj1LKGEpLGM9dGhpcy5jaGlsZHJlbi5nZXQoYik7cmV0dXJuIGM/KGE9Yy5yZW1vdmUoTihhKSksYj1hLmUoKT90aGlzLmNoaWxkcmVuLnJlbW92ZShiKTp0aGlzLmNoaWxkcmVuLlNhKGIsYSksbnVsbD09PXRoaXMudmFsdWUmJmIuZSgpP3FlOm5ldyBxZih0aGlzLnZhbHVlLGIpKTp0aGlzfTtoLmdldD1mdW5jdGlvbihhKXtpZihhLmUoKSlyZXR1cm4gdGhpcy52YWx1ZTt2YXIgYj10aGlzLmNoaWxkcmVuLmdldChLKGEpKTtyZXR1cm4gYj9iLmdldChOKGEpKTpudWxsfTtcbmZ1bmN0aW9uIHBlKGEsYixjKXtpZihiLmUoKSlyZXR1cm4gYzt2YXIgZD1LKGIpO2I9cGUoYS5jaGlsZHJlbi5nZXQoZCl8fHFlLE4oYiksYyk7ZD1iLmUoKT9hLmNoaWxkcmVuLnJlbW92ZShkKTphLmNoaWxkcmVuLlNhKGQsYik7cmV0dXJuIG5ldyBxZihhLnZhbHVlLGQpfWZ1bmN0aW9uIHZmKGEsYil7cmV0dXJuIHdmKGEsTSxiKX1mdW5jdGlvbiB3ZihhLGIsYyl7dmFyIGQ9e307YS5jaGlsZHJlbi5rYShmdW5jdGlvbihhLGYpe2RbYV09d2YoZixiLm8oYSksYyl9KTtyZXR1cm4gYyhiLGEudmFsdWUsZCl9ZnVuY3Rpb24geGYoYSxiLGMpe3JldHVybiB5ZihhLGIsTSxjKX1mdW5jdGlvbiB5ZihhLGIsYyxkKXt2YXIgZT1hLnZhbHVlP2QoYyxhLnZhbHVlKTohMTtpZihlKXJldHVybiBlO2lmKGIuZSgpKXJldHVybiBudWxsO2U9SyhiKTtyZXR1cm4oYT1hLmNoaWxkcmVuLmdldChlKSk/eWYoYSxOKGIpLGMubyhlKSxkKTpudWxsfVxuZnVuY3Rpb24gemYoYSxiLGMpe0FmKGEsYixNLGMpfWZ1bmN0aW9uIEFmKGEsYixjLGQpe2lmKGIuZSgpKXJldHVybiBhO2EudmFsdWUmJmQoYyxhLnZhbHVlKTt2YXIgZT1LKGIpO3JldHVybihhPWEuY2hpbGRyZW4uZ2V0KGUpKT9BZihhLE4oYiksYy5vKGUpLGQpOnFlfWZ1bmN0aW9uIG5lKGEsYil7QmYoYSxNLGIpfWZ1bmN0aW9uIEJmKGEsYixjKXthLmNoaWxkcmVuLmthKGZ1bmN0aW9uKGEsZSl7QmYoZSxiLm8oYSksYyl9KTthLnZhbHVlJiZjKGIsYS52YWx1ZSl9ZnVuY3Rpb24gQ2YoYSxiKXthLmNoaWxkcmVuLmthKGZ1bmN0aW9uKGEsZCl7ZC52YWx1ZSYmYihhLGQudmFsdWUpfSl9dmFyIHFlPW5ldyBxZihudWxsKTtxZi5wcm90b3R5cGUudG9TdHJpbmc9ZnVuY3Rpb24oKXt2YXIgYT17fTtuZSh0aGlzLGZ1bmN0aW9uKGIsYyl7YVtiLnRvU3RyaW5nKCldPWMudG9TdHJpbmcoKX0pO3JldHVybiBHKGEpfTtmdW5jdGlvbiBEZihhLGIsYyl7dGhpcy50eXBlPWVlO3RoaXMuc291cmNlPUVmO3RoaXMucGF0aD1hO3RoaXMuVWI9Yjt0aGlzLllkPWN9RGYucHJvdG90eXBlLiRjPWZ1bmN0aW9uKGEpe2lmKHRoaXMucGF0aC5lKCkpe2lmKG51bGwhPXRoaXMuVWIudmFsdWUpcmV0dXJuIE8odGhpcy5VYi5jaGlsZHJlbi5lKCksXCJhZmZlY3RlZFRyZWUgc2hvdWxkIG5vdCBoYXZlIG92ZXJsYXBwaW5nIGFmZmVjdGVkIHBhdGhzLlwiKSx0aGlzO2E9dGhpcy5VYi5zdWJ0cmVlKG5ldyBQKGEpKTtyZXR1cm4gbmV3IERmKE0sYSx0aGlzLllkKX1PKEsodGhpcy5wYXRoKT09PWEsXCJvcGVyYXRpb25Gb3JDaGlsZCBjYWxsZWQgZm9yIHVucmVsYXRlZCBjaGlsZC5cIik7cmV0dXJuIG5ldyBEZihOKHRoaXMucGF0aCksdGhpcy5VYix0aGlzLllkKX07XG5EZi5wcm90b3R5cGUudG9TdHJpbmc9ZnVuY3Rpb24oKXtyZXR1cm5cIk9wZXJhdGlvbihcIit0aGlzLnBhdGgrXCI6IFwiK3RoaXMuc291cmNlLnRvU3RyaW5nKCkrXCIgYWNrIHdyaXRlIHJldmVydD1cIit0aGlzLllkK1wiIGFmZmVjdGVkVHJlZT1cIit0aGlzLlViK1wiKVwifTt2YXIgQmM9MCxiZT0xLGVlPTIsRGM9MztmdW5jdGlvbiBGZihhLGIsYyxkKXt0aGlzLkFlPWE7dGhpcy50Zj1iO3RoaXMuTGI9Yzt0aGlzLmVmPWQ7TyghZHx8YixcIlRhZ2dlZCBxdWVyaWVzIG11c3QgYmUgZnJvbSBzZXJ2ZXIuXCIpfXZhciBFZj1uZXcgRmYoITAsITEsbnVsbCwhMSksR2Y9bmV3IEZmKCExLCEwLG51bGwsITEpO0ZmLnByb3RvdHlwZS50b1N0cmluZz1mdW5jdGlvbigpe3JldHVybiB0aGlzLkFlP1widXNlclwiOnRoaXMuZWY/XCJzZXJ2ZXIocXVlcnlJRD1cIit0aGlzLkxiK1wiKVwiOlwic2VydmVyXCJ9O2Z1bmN0aW9uIEhmKGEpe3RoaXMuWj1hfXZhciBJZj1uZXcgSGYobmV3IHFmKG51bGwpKTtmdW5jdGlvbiBKZihhLGIsYyl7aWYoYi5lKCkpcmV0dXJuIG5ldyBIZihuZXcgcWYoYykpO3ZhciBkPXVmKGEuWixiKTtpZihudWxsIT1kKXt2YXIgZT1kLnBhdGgsZD1kLnZhbHVlO2I9bGYoZSxiKTtkPWQuSChiLGMpO3JldHVybiBuZXcgSGYoYS5aLnNldChlLGQpKX1hPXBlKGEuWixiLG5ldyBxZihjKSk7cmV0dXJuIG5ldyBIZihhKX1mdW5jdGlvbiBLZihhLGIsYyl7dmFyIGQ9YTtGYihjLGZ1bmN0aW9uKGEsYyl7ZD1KZihkLGIubyhhKSxjKX0pO3JldHVybiBkfUhmLnByb3RvdHlwZS5VZD1mdW5jdGlvbihhKXtpZihhLmUoKSlyZXR1cm4gSWY7YT1wZSh0aGlzLlosYSxxZSk7cmV0dXJuIG5ldyBIZihhKX07ZnVuY3Rpb24gTGYoYSxiKXt2YXIgYz11ZihhLlosYik7cmV0dXJuIG51bGwhPWM/YS5aLmdldChjLnBhdGgpLlMobGYoYy5wYXRoLGIpKTpudWxsfVxuZnVuY3Rpb24gTWYoYSl7dmFyIGI9W10sYz1hLloudmFsdWU7bnVsbCE9Yz9jLkwoKXx8Yy5SKFIsZnVuY3Rpb24oYSxjKXtiLnB1c2gobmV3IEwoYSxjKSl9KTphLlouY2hpbGRyZW4ua2EoZnVuY3Rpb24oYSxjKXtudWxsIT1jLnZhbHVlJiZiLnB1c2gobmV3IEwoYSxjLnZhbHVlKSl9KTtyZXR1cm4gYn1mdW5jdGlvbiBOZihhLGIpe2lmKGIuZSgpKXJldHVybiBhO3ZhciBjPUxmKGEsYik7cmV0dXJuIG51bGwhPWM/bmV3IEhmKG5ldyBxZihjKSk6bmV3IEhmKGEuWi5zdWJ0cmVlKGIpKX1IZi5wcm90b3R5cGUuZT1mdW5jdGlvbigpe3JldHVybiB0aGlzLlouZSgpfTtIZi5wcm90b3R5cGUuYXBwbHk9ZnVuY3Rpb24oYSl7cmV0dXJuIE9mKE0sdGhpcy5aLGEpfTtcbmZ1bmN0aW9uIE9mKGEsYixjKXtpZihudWxsIT1iLnZhbHVlKXJldHVybiBjLkgoYSxiLnZhbHVlKTt2YXIgZD1udWxsO2IuY2hpbGRyZW4ua2EoZnVuY3Rpb24oYixmKXtcIi5wcmlvcml0eVwiPT09Yj8oTyhudWxsIT09Zi52YWx1ZSxcIlByaW9yaXR5IHdyaXRlcyBtdXN0IGFsd2F5cyBiZSBsZWFmIG5vZGVzXCIpLGQ9Zi52YWx1ZSk6Yz1PZihhLm8oYiksZixjKX0pO2MuUyhhKS5lKCl8fG51bGw9PT1kfHwoYz1jLkgoYS5vKFwiLnByaW9yaXR5XCIpLGQpKTtyZXR1cm4gY307ZnVuY3Rpb24gUGYoKXt0aGlzLlY9SWY7dGhpcy5wYT1bXTt0aGlzLlBjPS0xfWZ1bmN0aW9uIFFmKGEsYil7Zm9yKHZhciBjPTA7YzxhLnBhLmxlbmd0aDtjKyspe3ZhciBkPWEucGFbY107aWYoZC5tZD09PWIpcmV0dXJuIGR9cmV0dXJuIG51bGx9aD1QZi5wcm90b3R5cGU7XG5oLlVkPWZ1bmN0aW9uKGEpe3ZhciBiPVNhKHRoaXMucGEsZnVuY3Rpb24oYil7cmV0dXJuIGIubWQ9PT1hfSk7TygwPD1iLFwicmVtb3ZlV3JpdGUgY2FsbGVkIHdpdGggbm9uZXhpc3RlbnQgd3JpdGVJZC5cIik7dmFyIGM9dGhpcy5wYVtiXTt0aGlzLnBhLnNwbGljZShiLDEpO2Zvcih2YXIgZD1jLnZpc2libGUsZT0hMSxmPXRoaXMucGEubGVuZ3RoLTE7ZCYmMDw9Zjspe3ZhciBnPXRoaXMucGFbZl07Zy52aXNpYmxlJiYoZj49YiYmUmYoZyxjLnBhdGgpP2Q9ITE6Yy5wYXRoLmNvbnRhaW5zKGcucGF0aCkmJihlPSEwKSk7Zi0tfWlmKGQpe2lmKGUpdGhpcy5WPVNmKHRoaXMucGEsVGYsTSksdGhpcy5QYz0wPHRoaXMucGEubGVuZ3RoP3RoaXMucGFbdGhpcy5wYS5sZW5ndGgtMV0ubWQ6LTE7ZWxzZSBpZihjLkphKXRoaXMuVj10aGlzLlYuVWQoYy5wYXRoKTtlbHNle3ZhciBrPXRoaXM7dihjLmNoaWxkcmVuLGZ1bmN0aW9uKGEsYil7ay5WPWsuVi5VZChjLnBhdGgubyhiKSl9KX1yZXR1cm4hMH1yZXR1cm4hMX07XG5oLkFhPWZ1bmN0aW9uKGEsYixjLGQpe2lmKGN8fGQpe3ZhciBlPU5mKHRoaXMuVixhKTtyZXR1cm4hZCYmZS5lKCk/YjpkfHxudWxsIT1ifHxudWxsIT1MZihlLE0pPyhlPVNmKHRoaXMucGEsZnVuY3Rpb24oYil7cmV0dXJuKGIudmlzaWJsZXx8ZCkmJighY3x8ISgwPD1MYShjLGIubWQpKSkmJihiLnBhdGguY29udGFpbnMoYSl8fGEuY29udGFpbnMoYi5wYXRoKSl9LGEpLGI9Ynx8SCxlLmFwcGx5KGIpKTpudWxsfWU9TGYodGhpcy5WLGEpO2lmKG51bGwhPWUpcmV0dXJuIGU7ZT1OZih0aGlzLlYsYSk7cmV0dXJuIGUuZSgpP2I6bnVsbCE9Ynx8bnVsbCE9TGYoZSxNKT8oYj1ifHxILGUuYXBwbHkoYikpOm51bGx9O1xuaC5DYz1mdW5jdGlvbihhLGIpe3ZhciBjPUgsZD1MZih0aGlzLlYsYSk7aWYoZClkLkwoKXx8ZC5SKFIsZnVuY3Rpb24oYSxiKXtjPWMuVyhhLGIpfSk7ZWxzZSBpZihiKXt2YXIgZT1OZih0aGlzLlYsYSk7Yi5SKFIsZnVuY3Rpb24oYSxiKXt2YXIgZD1OZihlLG5ldyBQKGEpKS5hcHBseShiKTtjPWMuVyhhLGQpfSk7TWEoTWYoZSksZnVuY3Rpb24oYSl7Yz1jLlcoYS5uYW1lLGEuVSl9KX1lbHNlIGU9TmYodGhpcy5WLGEpLE1hKE1mKGUpLGZ1bmN0aW9uKGEpe2M9Yy5XKGEubmFtZSxhLlUpfSk7cmV0dXJuIGN9O2gubmQ9ZnVuY3Rpb24oYSxiLGMsZCl7TyhjfHxkLFwiRWl0aGVyIGV4aXN0aW5nRXZlbnRTbmFwIG9yIGV4aXN0aW5nU2VydmVyU25hcCBtdXN0IGV4aXN0XCIpO2E9YS5vKGIpO2lmKG51bGwhPUxmKHRoaXMuVixhKSlyZXR1cm4gbnVsbDthPU5mKHRoaXMuVixhKTtyZXR1cm4gYS5lKCk/ZC5TKGIpOmEuYXBwbHkoZC5TKGIpKX07XG5oLkJjPWZ1bmN0aW9uKGEsYixjKXthPWEubyhiKTt2YXIgZD1MZih0aGlzLlYsYSk7cmV0dXJuIG51bGwhPWQ/ZDpXYihjLGIpP05mKHRoaXMuVixhKS5hcHBseShjLmooKS5UKGIpKTpudWxsfTtoLnhjPWZ1bmN0aW9uKGEpe3JldHVybiBMZih0aGlzLlYsYSl9O2gucWU9ZnVuY3Rpb24oYSxiLGMsZCxlLGYpe3ZhciBnO2E9TmYodGhpcy5WLGEpO2c9TGYoYSxNKTtpZihudWxsPT1nKWlmKG51bGwhPWIpZz1hLmFwcGx5KGIpO2Vsc2UgcmV0dXJuW107Zz1nLnBiKGYpO2lmKGcuZSgpfHxnLkwoKSlyZXR1cm5bXTtiPVtdO2E9VmQoZik7ZT1lP2cuZGMoYyxmKTpnLmJjKGMsZik7Zm9yKGY9SWMoZSk7ZiYmYi5sZW5ndGg8ZDspMCE9PWEoZixjKSYmYi5wdXNoKGYpLGY9SWMoZSk7cmV0dXJuIGJ9O1xuZnVuY3Rpb24gUmYoYSxiKXtyZXR1cm4gYS5KYT9hLnBhdGguY29udGFpbnMoYik6ISF0YShhLmNoaWxkcmVuLGZ1bmN0aW9uKGMsZCl7cmV0dXJuIGEucGF0aC5vKGQpLmNvbnRhaW5zKGIpfSl9ZnVuY3Rpb24gVGYoYSl7cmV0dXJuIGEudmlzaWJsZX1cbmZ1bmN0aW9uIFNmKGEsYixjKXtmb3IodmFyIGQ9SWYsZT0wO2U8YS5sZW5ndGg7KytlKXt2YXIgZj1hW2VdO2lmKGIoZikpe3ZhciBnPWYucGF0aDtpZihmLkphKWMuY29udGFpbnMoZyk/KGc9bGYoYyxnKSxkPUpmKGQsZyxmLkphKSk6Zy5jb250YWlucyhjKSYmKGc9bGYoZyxjKSxkPUpmKGQsTSxmLkphLlMoZykpKTtlbHNlIGlmKGYuY2hpbGRyZW4paWYoYy5jb250YWlucyhnKSlnPWxmKGMsZyksZD1LZihkLGcsZi5jaGlsZHJlbik7ZWxzZXtpZihnLmNvbnRhaW5zKGMpKWlmKGc9bGYoZyxjKSxnLmUoKSlkPUtmKGQsTSxmLmNoaWxkcmVuKTtlbHNlIGlmKGY9eihmLmNoaWxkcmVuLEsoZykpKWY9Zi5TKE4oZykpLGQ9SmYoZCxNLGYpfWVsc2UgdGhyb3cgamQoXCJXcml0ZVJlY29yZCBzaG91bGQgaGF2ZSAuc25hcCBvciAuY2hpbGRyZW5cIik7fX1yZXR1cm4gZH1mdW5jdGlvbiBVZihhLGIpe3RoaXMuUWI9YTt0aGlzLlo9Yn1oPVVmLnByb3RvdHlwZTtcbmguQWE9ZnVuY3Rpb24oYSxiLGMpe3JldHVybiB0aGlzLlouQWEodGhpcy5RYixhLGIsYyl9O2guQ2M9ZnVuY3Rpb24oYSl7cmV0dXJuIHRoaXMuWi5DYyh0aGlzLlFiLGEpfTtoLm5kPWZ1bmN0aW9uKGEsYixjKXtyZXR1cm4gdGhpcy5aLm5kKHRoaXMuUWIsYSxiLGMpfTtoLnhjPWZ1bmN0aW9uKGEpe3JldHVybiB0aGlzLloueGModGhpcy5RYi5vKGEpKX07aC5xZT1mdW5jdGlvbihhLGIsYyxkLGUpe3JldHVybiB0aGlzLloucWUodGhpcy5RYixhLGIsYyxkLGUpfTtoLkJjPWZ1bmN0aW9uKGEsYil7cmV0dXJuIHRoaXMuWi5CYyh0aGlzLlFiLGEsYil9O2gubz1mdW5jdGlvbihhKXtyZXR1cm4gbmV3IFVmKHRoaXMuUWIubyhhKSx0aGlzLlopfTtmdW5jdGlvbiBWZigpe3RoaXMuY2hpbGRyZW49e307dGhpcy5wZD0wO3RoaXMudmFsdWU9bnVsbH1mdW5jdGlvbiBXZihhLGIsYyl7dGhpcy5KZD1hP2E6XCJcIjt0aGlzLkhhPWI/YjpudWxsO3RoaXMuQT1jP2M6bmV3IFZmfWZ1bmN0aW9uIFhmKGEsYil7Zm9yKHZhciBjPWIgaW5zdGFuY2VvZiBQP2I6bmV3IFAoYiksZD1hLGU7bnVsbCE9PShlPUsoYykpOylkPW5ldyBXZihlLGQseihkLkEuY2hpbGRyZW4sZSl8fG5ldyBWZiksYz1OKGMpO3JldHVybiBkfWg9V2YucHJvdG90eXBlO2guRWE9ZnVuY3Rpb24oKXtyZXR1cm4gdGhpcy5BLnZhbHVlfTtmdW5jdGlvbiBZZihhLGIpe08oXCJ1bmRlZmluZWRcIiE9PXR5cGVvZiBiLFwiQ2Fubm90IHNldCB2YWx1ZSB0byB1bmRlZmluZWRcIik7YS5BLnZhbHVlPWI7WmYoYSl9aC5jbGVhcj1mdW5jdGlvbigpe3RoaXMuQS52YWx1ZT1udWxsO3RoaXMuQS5jaGlsZHJlbj17fTt0aGlzLkEucGQ9MDtaZih0aGlzKX07XG5oLnpkPWZ1bmN0aW9uKCl7cmV0dXJuIDA8dGhpcy5BLnBkfTtoLmU9ZnVuY3Rpb24oKXtyZXR1cm4gbnVsbD09PXRoaXMuRWEoKSYmIXRoaXMuemQoKX07aC5SPWZ1bmN0aW9uKGEpe3ZhciBiPXRoaXM7dih0aGlzLkEuY2hpbGRyZW4sZnVuY3Rpb24oYyxkKXthKG5ldyBXZihkLGIsYykpfSl9O2Z1bmN0aW9uICRmKGEsYixjLGQpe2MmJiFkJiZiKGEpO2EuUihmdW5jdGlvbihhKXskZihhLGIsITAsZCl9KTtjJiZkJiZiKGEpfWZ1bmN0aW9uIGFnKGEsYil7Zm9yKHZhciBjPWEucGFyZW50KCk7bnVsbCE9PWMmJiFiKGMpOyljPWMucGFyZW50KCl9aC5wYXRoPWZ1bmN0aW9uKCl7cmV0dXJuIG5ldyBQKG51bGw9PT10aGlzLkhhP3RoaXMuSmQ6dGhpcy5IYS5wYXRoKCkrXCIvXCIrdGhpcy5KZCl9O2gubmFtZT1mdW5jdGlvbigpe3JldHVybiB0aGlzLkpkfTtoLnBhcmVudD1mdW5jdGlvbigpe3JldHVybiB0aGlzLkhhfTtcbmZ1bmN0aW9uIFpmKGEpe2lmKG51bGwhPT1hLkhhKXt2YXIgYj1hLkhhLGM9YS5KZCxkPWEuZSgpLGU9eShiLkEuY2hpbGRyZW4sYyk7ZCYmZT8oZGVsZXRlIGIuQS5jaGlsZHJlbltjXSxiLkEucGQtLSxaZihiKSk6ZHx8ZXx8KGIuQS5jaGlsZHJlbltjXT1hLkEsYi5BLnBkKyssWmYoYikpfX07dmFyIGJnPS9bXFxbXFxdLiMkXFwvXFx1MDAwMC1cXHUwMDFGXFx1MDA3Rl0vLGNnPS9bXFxbXFxdLiMkXFx1MDAwMC1cXHUwMDFGXFx1MDA3Rl0vLGRnPS9eW2EtekEtWl1bYS16QS1aLl9cXC0rXSskLztmdW5jdGlvbiBlZyhhKXtyZXR1cm4gcShhKSYmMCE9PWEubGVuZ3RoJiYhYmcudGVzdChhKX1mdW5jdGlvbiBmZyhhKXtyZXR1cm4gbnVsbD09PWF8fHEoYSl8fGZhKGEpJiYhdGQoYSl8fGdhKGEpJiZ5KGEsXCIuc3ZcIil9ZnVuY3Rpb24gZ2coYSxiLGMsZCl7ZCYmIXAoYil8fGhnKEUoYSwxLGQpLGIsYyl9XG5mdW5jdGlvbiBoZyhhLGIsYyl7YyBpbnN0YW5jZW9mIFAmJihjPW5ldyBuZihjLGEpKTtpZighcChiKSl0aHJvdyBFcnJvcihhK1wiY29udGFpbnMgdW5kZWZpbmVkIFwiK3BmKGMpKTtpZihyKGIpKXRocm93IEVycm9yKGErXCJjb250YWlucyBhIGZ1bmN0aW9uIFwiK3BmKGMpK1wiIHdpdGggY29udGVudHM6IFwiK2IudG9TdHJpbmcoKSk7aWYodGQoYikpdGhyb3cgRXJyb3IoYStcImNvbnRhaW5zIFwiK2IudG9TdHJpbmcoKStcIiBcIitwZihjKSk7aWYocShiKSYmYi5sZW5ndGg+MTA0ODU3NjAvMyYmMTA0ODU3NjA8UGIoYikpdGhyb3cgRXJyb3IoYStcImNvbnRhaW5zIGEgc3RyaW5nIGdyZWF0ZXIgdGhhbiAxMDQ4NTc2MCB1dGY4IGJ5dGVzIFwiK3BmKGMpK1wiICgnXCIrYi5zdWJzdHJpbmcoMCw1MCkrXCIuLi4nKVwiKTtpZihnYShiKSl7dmFyIGQ9ITEsZT0hMTtGYihiLGZ1bmN0aW9uKGIsZyl7aWYoXCIudmFsdWVcIj09PWIpZD0hMDtlbHNlIGlmKFwiLnByaW9yaXR5XCIhPT1iJiZcIi5zdlwiIT09YiYmKGU9XG4hMCwhZWcoYikpKXRocm93IEVycm9yKGErXCIgY29udGFpbnMgYW4gaW52YWxpZCBrZXkgKFwiK2IrXCIpIFwiK3BmKGMpKycuICBLZXlzIG11c3QgYmUgbm9uLWVtcHR5IHN0cmluZ3MgYW5kIGNhblxcJ3QgY29udGFpbiBcIi5cIiwgXCIjXCIsIFwiJFwiLCBcIi9cIiwgXCJbXCIsIG9yIFwiXVwiJyk7Yy5wdXNoKGIpO2hnKGEsZyxjKTtjLnBvcCgpfSk7aWYoZCYmZSl0aHJvdyBFcnJvcihhKycgY29udGFpbnMgXCIudmFsdWVcIiBjaGlsZCAnK3BmKGMpK1wiIGluIGFkZGl0aW9uIHRvIGFjdHVhbCBjaGlsZHJlbi5cIik7fX1cbmZ1bmN0aW9uIGlnKGEsYil7dmFyIGMsZDtmb3IoYz0wO2M8Yi5sZW5ndGg7YysrKXtkPWJbY107Zm9yKHZhciBlPWQuc2xpY2UoKSxmPTA7ZjxlLmxlbmd0aDtmKyspaWYoKFwiLnByaW9yaXR5XCIhPT1lW2ZdfHxmIT09ZS5sZW5ndGgtMSkmJiFlZyhlW2ZdKSl0aHJvdyBFcnJvcihhK1wiY29udGFpbnMgYW4gaW52YWxpZCBrZXkgKFwiK2VbZl0rXCIpIGluIHBhdGggXCIrZC50b1N0cmluZygpKycuIEtleXMgbXVzdCBiZSBub24tZW1wdHkgc3RyaW5ncyBhbmQgY2FuXFwndCBjb250YWluIFwiLlwiLCBcIiNcIiwgXCIkXCIsIFwiL1wiLCBcIltcIiwgb3IgXCJdXCInKTt9Yi5zb3J0KG1mKTtlPW51bGw7Zm9yKGM9MDtjPGIubGVuZ3RoO2MrKyl7ZD1iW2NdO2lmKG51bGwhPT1lJiZlLmNvbnRhaW5zKGQpKXRocm93IEVycm9yKGErXCJjb250YWlucyBhIHBhdGggXCIrZS50b1N0cmluZygpK1wiIHRoYXQgaXMgYW5jZXN0b3Igb2YgYW5vdGhlciBwYXRoIFwiK2QudG9TdHJpbmcoKSk7ZT1kfX1cbmZ1bmN0aW9uIGpnKGEsYixjKXt2YXIgZD1FKGEsMSwhMSk7aWYoIWdhKGIpfHxkYShiKSl0aHJvdyBFcnJvcihkK1wiIG11c3QgYmUgYW4gb2JqZWN0IGNvbnRhaW5pbmcgdGhlIGNoaWxkcmVuIHRvIHJlcGxhY2UuXCIpO3ZhciBlPVtdO0ZiKGIsZnVuY3Rpb24oYSxiKXt2YXIgaz1uZXcgUChhKTtoZyhkLGIsYy5vKGspKTtpZihcIi5wcmlvcml0eVwiPT09bWUoaykmJiFmZyhiKSl0aHJvdyBFcnJvcihkK1wiY29udGFpbnMgYW4gaW52YWxpZCB2YWx1ZSBmb3IgJ1wiK2sudG9TdHJpbmcoKStcIicsIHdoaWNoIG11c3QgYmUgYSB2YWxpZCBGaXJlYmFzZSBwcmlvcml0eSAoYSBzdHJpbmcsIGZpbml0ZSBudW1iZXIsIHNlcnZlciB2YWx1ZSwgb3IgbnVsbCkuXCIpO2UucHVzaChrKX0pO2lnKGQsZSl9XG5mdW5jdGlvbiBrZyhhLGIsYyl7aWYodGQoYykpdGhyb3cgRXJyb3IoRShhLGIsITEpK1wiaXMgXCIrYy50b1N0cmluZygpK1wiLCBidXQgbXVzdCBiZSBhIHZhbGlkIEZpcmViYXNlIHByaW9yaXR5IChhIHN0cmluZywgZmluaXRlIG51bWJlciwgc2VydmVyIHZhbHVlLCBvciBudWxsKS5cIik7aWYoIWZnKGMpKXRocm93IEVycm9yKEUoYSxiLCExKStcIm11c3QgYmUgYSB2YWxpZCBGaXJlYmFzZSBwcmlvcml0eSAoYSBzdHJpbmcsIGZpbml0ZSBudW1iZXIsIHNlcnZlciB2YWx1ZSwgb3IgbnVsbCkuXCIpO31cbmZ1bmN0aW9uIGxnKGEsYixjKXtpZighY3x8cChiKSlzd2l0Y2goYil7Y2FzZSBcInZhbHVlXCI6Y2FzZSBcImNoaWxkX2FkZGVkXCI6Y2FzZSBcImNoaWxkX3JlbW92ZWRcIjpjYXNlIFwiY2hpbGRfY2hhbmdlZFwiOmNhc2UgXCJjaGlsZF9tb3ZlZFwiOmJyZWFrO2RlZmF1bHQ6dGhyb3cgRXJyb3IoRShhLDEsYykrJ211c3QgYmUgYSB2YWxpZCBldmVudCB0eXBlOiBcInZhbHVlXCIsIFwiY2hpbGRfYWRkZWRcIiwgXCJjaGlsZF9yZW1vdmVkXCIsIFwiY2hpbGRfY2hhbmdlZFwiLCBvciBcImNoaWxkX21vdmVkXCIuJyk7fX1mdW5jdGlvbiBtZyhhLGIpe2lmKHAoYikmJiFlZyhiKSl0aHJvdyBFcnJvcihFKGEsMiwhMCkrJ3dhcyBhbiBpbnZhbGlkIGtleTogXCInK2IrJ1wiLiAgRmlyZWJhc2Uga2V5cyBtdXN0IGJlIG5vbi1lbXB0eSBzdHJpbmdzIGFuZCBjYW5cXCd0IGNvbnRhaW4gXCIuXCIsIFwiI1wiLCBcIiRcIiwgXCIvXCIsIFwiW1wiLCBvciBcIl1cIikuJyk7fVxuZnVuY3Rpb24gbmcoYSxiKXtpZighcShiKXx8MD09PWIubGVuZ3RofHxjZy50ZXN0KGIpKXRocm93IEVycm9yKEUoYSwxLCExKSsnd2FzIGFuIGludmFsaWQgcGF0aDogXCInK2IrJ1wiLiBQYXRocyBtdXN0IGJlIG5vbi1lbXB0eSBzdHJpbmdzIGFuZCBjYW5cXCd0IGNvbnRhaW4gXCIuXCIsIFwiI1wiLCBcIiRcIiwgXCJbXCIsIG9yIFwiXVwiJyk7fWZ1bmN0aW9uIG9nKGEsYil7aWYoXCIuaW5mb1wiPT09SyhiKSl0aHJvdyBFcnJvcihhK1wiIGZhaWxlZDogQ2FuJ3QgbW9kaWZ5IGRhdGEgdW5kZXIgLy5pbmZvL1wiKTt9ZnVuY3Rpb24gcGcoYSxiKXtpZighcShiKSl0aHJvdyBFcnJvcihFKGEsMSwhMSkrXCJtdXN0IGJlIGEgdmFsaWQgY3JlZGVudGlhbCAoYSBzdHJpbmcpLlwiKTt9ZnVuY3Rpb24gcWcoYSxiLGMpe2lmKCFxKGMpKXRocm93IEVycm9yKEUoYSxiLCExKStcIm11c3QgYmUgYSB2YWxpZCBzdHJpbmcuXCIpO31cbmZ1bmN0aW9uIHJnKGEsYil7cWcoYSwxLGIpO2lmKCFkZy50ZXN0KGIpKXRocm93IEVycm9yKEUoYSwxLCExKStcIidcIitiK1wiJyBpcyBub3QgYSB2YWxpZCBhdXRoZW50aWNhdGlvbiBwcm92aWRlci5cIik7fWZ1bmN0aW9uIHNnKGEsYixjLGQpe2lmKCFkfHxwKGMpKWlmKCFnYShjKXx8bnVsbD09PWMpdGhyb3cgRXJyb3IoRShhLGIsZCkrXCJtdXN0IGJlIGEgdmFsaWQgb2JqZWN0LlwiKTt9ZnVuY3Rpb24gdGcoYSxiLGMpe2lmKCFnYShiKXx8IXkoYixjKSl0aHJvdyBFcnJvcihFKGEsMSwhMSkrJ211c3QgY29udGFpbiB0aGUga2V5IFwiJytjKydcIicpO2lmKCFxKHooYixjKSkpdGhyb3cgRXJyb3IoRShhLDEsITEpKydtdXN0IGNvbnRhaW4gdGhlIGtleSBcIicrYysnXCIgd2l0aCB0eXBlIFwic3RyaW5nXCInKTt9O2Z1bmN0aW9uIHVnKCl7dGhpcy5zZXQ9e319aD11Zy5wcm90b3R5cGU7aC5hZGQ9ZnVuY3Rpb24oYSxiKXt0aGlzLnNldFthXT1udWxsIT09Yj9iOiEwfTtoLmNvbnRhaW5zPWZ1bmN0aW9uKGEpe3JldHVybiB5KHRoaXMuc2V0LGEpfTtoLmdldD1mdW5jdGlvbihhKXtyZXR1cm4gdGhpcy5jb250YWlucyhhKT90aGlzLnNldFthXTp2b2lkIDB9O2gucmVtb3ZlPWZ1bmN0aW9uKGEpe2RlbGV0ZSB0aGlzLnNldFthXX07aC5jbGVhcj1mdW5jdGlvbigpe3RoaXMuc2V0PXt9fTtoLmU9ZnVuY3Rpb24oKXtyZXR1cm4gdmEodGhpcy5zZXQpfTtoLmNvdW50PWZ1bmN0aW9uKCl7cmV0dXJuIG9hKHRoaXMuc2V0KX07ZnVuY3Rpb24gdmcoYSxiKXt2KGEuc2V0LGZ1bmN0aW9uKGEsZCl7YihkLGEpfSl9aC5rZXlzPWZ1bmN0aW9uKCl7dmFyIGE9W107dih0aGlzLnNldCxmdW5jdGlvbihiLGMpe2EucHVzaChjKX0pO3JldHVybiBhfTtmdW5jdGlvbiBWYygpe3RoaXMubT10aGlzLkI9bnVsbH1WYy5wcm90b3R5cGUuZmluZD1mdW5jdGlvbihhKXtpZihudWxsIT10aGlzLkIpcmV0dXJuIHRoaXMuQi5TKGEpO2lmKGEuZSgpfHxudWxsPT10aGlzLm0pcmV0dXJuIG51bGw7dmFyIGI9SyhhKTthPU4oYSk7cmV0dXJuIHRoaXMubS5jb250YWlucyhiKT90aGlzLm0uZ2V0KGIpLmZpbmQoYSk6bnVsbH07VmMucHJvdG90eXBlLnJjPWZ1bmN0aW9uKGEsYil7aWYoYS5lKCkpdGhpcy5CPWIsdGhpcy5tPW51bGw7ZWxzZSBpZihudWxsIT09dGhpcy5CKXRoaXMuQj10aGlzLkIuSChhLGIpO2Vsc2V7bnVsbD09dGhpcy5tJiYodGhpcy5tPW5ldyB1Zyk7dmFyIGM9SyhhKTt0aGlzLm0uY29udGFpbnMoYyl8fHRoaXMubS5hZGQoYyxuZXcgVmMpO2M9dGhpcy5tLmdldChjKTthPU4oYSk7Yy5yYyhhLGIpfX07XG5mdW5jdGlvbiB3ZyhhLGIpe2lmKGIuZSgpKXJldHVybiBhLkI9bnVsbCxhLm09bnVsbCwhMDtpZihudWxsIT09YS5CKXtpZihhLkIuTCgpKXJldHVybiExO3ZhciBjPWEuQjthLkI9bnVsbDtjLlIoUixmdW5jdGlvbihiLGMpe2EucmMobmV3IFAoYiksYyl9KTtyZXR1cm4gd2coYSxiKX1yZXR1cm4gbnVsbCE9PWEubT8oYz1LKGIpLGI9TihiKSxhLm0uY29udGFpbnMoYykmJndnKGEubS5nZXQoYyksYikmJmEubS5yZW1vdmUoYyksYS5tLmUoKT8oYS5tPW51bGwsITApOiExKTohMH1mdW5jdGlvbiBXYyhhLGIsYyl7bnVsbCE9PWEuQj9jKGIsYS5CKTphLlIoZnVuY3Rpb24oYSxlKXt2YXIgZj1uZXcgUChiLnRvU3RyaW5nKCkrXCIvXCIrYSk7V2MoZSxmLGMpfSl9VmMucHJvdG90eXBlLlI9ZnVuY3Rpb24oYSl7bnVsbCE9PXRoaXMubSYmdmcodGhpcy5tLGZ1bmN0aW9uKGIsYyl7YShiLGMpfSl9O3ZhciB4Zz1cImF1dGguZmlyZWJhc2UuY29tXCI7ZnVuY3Rpb24geWcoYSxiLGMpe3RoaXMucWQ9YXx8e307dGhpcy5oZT1ifHx7fTt0aGlzLmZiPWN8fHt9O3RoaXMucWQucmVtZW1iZXJ8fCh0aGlzLnFkLnJlbWVtYmVyPVwiZGVmYXVsdFwiKX12YXIgemc9W1wicmVtZW1iZXJcIixcInJlZGlyZWN0VG9cIl07ZnVuY3Rpb24gQWcoYSl7dmFyIGI9e30sYz17fTtGYihhfHx7fSxmdW5jdGlvbihhLGUpezA8PUxhKHpnLGEpP2JbYV09ZTpjW2FdPWV9KTtyZXR1cm4gbmV3IHlnKGIse30sYyl9O2Z1bmN0aW9uIEJnKGEsYil7dGhpcy5VZT1bXCJzZXNzaW9uXCIsYS5SZCxhLmxjXS5qb2luKFwiOlwiKTt0aGlzLmVlPWJ9QmcucHJvdG90eXBlLnNldD1mdW5jdGlvbihhLGIpe2lmKCFiKWlmKHRoaXMuZWUubGVuZ3RoKWI9dGhpcy5lZVswXTtlbHNlIHRocm93IEVycm9yKFwiZmIubG9naW4uU2Vzc2lvbk1hbmFnZXIgOiBObyBzdG9yYWdlIG9wdGlvbnMgYXZhaWxhYmxlIVwiKTtiLnNldCh0aGlzLlVlLGEpfTtCZy5wcm90b3R5cGUuZ2V0PWZ1bmN0aW9uKCl7dmFyIGE9T2EodGhpcy5lZSx1KHRoaXMuQmcsdGhpcykpLGE9TmEoYSxmdW5jdGlvbihhKXtyZXR1cm4gbnVsbCE9PWF9KTtWYShhLGZ1bmN0aW9uKGEsYyl7cmV0dXJuIERkKGMudG9rZW4pLURkKGEudG9rZW4pfSk7cmV0dXJuIDA8YS5sZW5ndGg/YS5zaGlmdCgpOm51bGx9O0JnLnByb3RvdHlwZS5CZz1mdW5jdGlvbihhKXt0cnl7dmFyIGI9YS5nZXQodGhpcy5VZSk7aWYoYiYmYi50b2tlbilyZXR1cm4gYn1jYXRjaChjKXt9cmV0dXJuIG51bGx9O1xuQmcucHJvdG90eXBlLmNsZWFyPWZ1bmN0aW9uKCl7dmFyIGE9dGhpcztNYSh0aGlzLmVlLGZ1bmN0aW9uKGIpe2IucmVtb3ZlKGEuVWUpfSl9O2Z1bmN0aW9uIENnKCl7cmV0dXJuXCJ1bmRlZmluZWRcIiE9PXR5cGVvZiBuYXZpZ2F0b3ImJlwic3RyaW5nXCI9PT10eXBlb2YgbmF2aWdhdG9yLnVzZXJBZ2VudD9uYXZpZ2F0b3IudXNlckFnZW50OlwiXCJ9ZnVuY3Rpb24gRGcoKXtyZXR1cm5cInVuZGVmaW5lZFwiIT09dHlwZW9mIHdpbmRvdyYmISEod2luZG93LmNvcmRvdmF8fHdpbmRvdy5waG9uZWdhcHx8d2luZG93LlBob25lR2FwKSYmL2lvc3xpcGhvbmV8aXBvZHxpcGFkfGFuZHJvaWR8YmxhY2tiZXJyeXxpZW1vYmlsZS9pLnRlc3QoQ2coKSl9ZnVuY3Rpb24gRWcoKXtyZXR1cm5cInVuZGVmaW5lZFwiIT09dHlwZW9mIGxvY2F0aW9uJiYvXmZpbGU6XFwvLy50ZXN0KGxvY2F0aW9uLmhyZWYpfVxuZnVuY3Rpb24gRmcoYSl7dmFyIGI9Q2coKTtpZihcIlwiPT09YilyZXR1cm4hMTtpZihcIk1pY3Jvc29mdCBJbnRlcm5ldCBFeHBsb3JlclwiPT09bmF2aWdhdG9yLmFwcE5hbWUpe2lmKChiPWIubWF0Y2goL01TSUUgKFswLTldezEsfVtcXC4wLTldezAsfSkvKSkmJjE8Yi5sZW5ndGgpcmV0dXJuIHBhcnNlRmxvYXQoYlsxXSk+PWF9ZWxzZSBpZigtMTxiLmluZGV4T2YoXCJUcmlkZW50XCIpJiYoYj1iLm1hdGNoKC9ydjooWzAtOV17MiwyfVtcXC4wLTldezAsfSkvKSkmJjE8Yi5sZW5ndGgpcmV0dXJuIHBhcnNlRmxvYXQoYlsxXSk+PWE7cmV0dXJuITF9O2Z1bmN0aW9uIEdnKCl7dmFyIGE9d2luZG93Lm9wZW5lci5mcmFtZXMsYjtmb3IoYj1hLmxlbmd0aC0xOzA8PWI7Yi0tKXRyeXtpZihhW2JdLmxvY2F0aW9uLnByb3RvY29sPT09d2luZG93LmxvY2F0aW9uLnByb3RvY29sJiZhW2JdLmxvY2F0aW9uLmhvc3Q9PT13aW5kb3cubG9jYXRpb24uaG9zdCYmXCJfX3dpbmNoYW5fcmVsYXlfZnJhbWVcIj09PWFbYl0ubmFtZSlyZXR1cm4gYVtiXX1jYXRjaChjKXt9cmV0dXJuIG51bGx9ZnVuY3Rpb24gSGcoYSxiLGMpe2EuYXR0YWNoRXZlbnQ/YS5hdHRhY2hFdmVudChcIm9uXCIrYixjKTphLmFkZEV2ZW50TGlzdGVuZXImJmEuYWRkRXZlbnRMaXN0ZW5lcihiLGMsITEpfWZ1bmN0aW9uIElnKGEsYixjKXthLmRldGFjaEV2ZW50P2EuZGV0YWNoRXZlbnQoXCJvblwiK2IsYyk6YS5yZW1vdmVFdmVudExpc3RlbmVyJiZhLnJlbW92ZUV2ZW50TGlzdGVuZXIoYixjLCExKX1cbmZ1bmN0aW9uIEpnKGEpey9eaHR0cHM/OlxcL1xcLy8udGVzdChhKXx8KGE9d2luZG93LmxvY2F0aW9uLmhyZWYpO3ZhciBiPS9eKGh0dHBzPzpcXC9cXC9bXFwtX2EtekEtWlxcLjAtOTpdKykvLmV4ZWMoYSk7cmV0dXJuIGI/YlsxXTphfWZ1bmN0aW9uIEtnKGEpe3ZhciBiPVwiXCI7dHJ5e2E9YS5yZXBsYWNlKC8uKlxcPy8sXCJcIik7dmFyIGM9SmIoYSk7YyYmeShjLFwiX19maXJlYmFzZV9yZXF1ZXN0X2tleVwiKSYmKGI9eihjLFwiX19maXJlYmFzZV9yZXF1ZXN0X2tleVwiKSl9Y2F0Y2goZCl7fXJldHVybiBifWZ1bmN0aW9uIExnKCl7dHJ5e3ZhciBhPWRvY3VtZW50LmxvY2F0aW9uLmhhc2gucmVwbGFjZSgvJl9fZmlyZWJhc2VfcmVxdWVzdF9rZXk9KFthLXpBLXowLTldKikvLFwiXCIpLGE9YS5yZXBsYWNlKC9cXD8kLyxcIlwiKSxhPWEucmVwbGFjZSgvXiMrJC8sXCJcIik7ZG9jdW1lbnQubG9jYXRpb24uaGFzaD1hfWNhdGNoKGIpe319XG5mdW5jdGlvbiBNZygpe3ZhciBhPXNkKHhnKTtyZXR1cm4gYS5zY2hlbWUrXCI6Ly9cIithLmhvc3QrXCIvdjJcIn1mdW5jdGlvbiBOZyhhKXtyZXR1cm4gTWcoKStcIi9cIithK1wiL2F1dGgvY2hhbm5lbFwifTtmdW5jdGlvbiBPZyhhKXt2YXIgYj10aGlzO3RoaXMuaGI9YTt0aGlzLmZlPVwiKlwiO0ZnKDgpP3RoaXMuVWM9dGhpcy5DZD1HZygpOih0aGlzLlVjPXdpbmRvdy5vcGVuZXIsdGhpcy5DZD13aW5kb3cpO2lmKCFiLlVjKXRocm93XCJVbmFibGUgdG8gZmluZCByZWxheSBmcmFtZVwiO0hnKHRoaXMuQ2QsXCJtZXNzYWdlXCIsdSh0aGlzLm5jLHRoaXMpKTtIZyh0aGlzLkNkLFwibWVzc2FnZVwiLHUodGhpcy5GZix0aGlzKSk7dHJ5e1BnKHRoaXMse2E6XCJyZWFkeVwifSl9Y2F0Y2goYyl7SGcodGhpcy5VYyxcImxvYWRcIixmdW5jdGlvbigpe1BnKGIse2E6XCJyZWFkeVwifSl9KX1IZyh3aW5kb3csXCJ1bmxvYWRcIix1KHRoaXMuTmcsdGhpcykpfWZ1bmN0aW9uIFBnKGEsYil7Yj1HKGIpO0ZnKDgpP2EuVWMuZG9Qb3N0KGIsYS5mZSk6YS5VYy5wb3N0TWVzc2FnZShiLGEuZmUpfVxuT2cucHJvdG90eXBlLm5jPWZ1bmN0aW9uKGEpe3ZhciBiPXRoaXMsYzt0cnl7Yz1SYihhLmRhdGEpfWNhdGNoKGQpe31jJiZcInJlcXVlc3RcIj09PWMuYSYmKElnKHdpbmRvdyxcIm1lc3NhZ2VcIix0aGlzLm5jKSx0aGlzLmZlPWEub3JpZ2luLHRoaXMuaGImJnNldFRpbWVvdXQoZnVuY3Rpb24oKXtiLmhiKGIuZmUsYy5kLGZ1bmN0aW9uKGEsYyl7Yi5tZz0hYztiLmhiPXZvaWQgMDtQZyhiLHthOlwicmVzcG9uc2VcIixkOmEsZm9yY2VLZWVwV2luZG93T3BlbjpjfSl9KX0sMCkpfTtPZy5wcm90b3R5cGUuTmc9ZnVuY3Rpb24oKXt0cnl7SWcodGhpcy5DZCxcIm1lc3NhZ2VcIix0aGlzLkZmKX1jYXRjaChhKXt9dGhpcy5oYiYmKFBnKHRoaXMse2E6XCJlcnJvclwiLGQ6XCJ1bmtub3duIGNsb3NlZCB3aW5kb3dcIn0pLHRoaXMuaGI9dm9pZCAwKTt0cnl7d2luZG93LmNsb3NlKCl9Y2F0Y2goYil7fX07T2cucHJvdG90eXBlLkZmPWZ1bmN0aW9uKGEpe2lmKHRoaXMubWcmJlwiZGllXCI9PT1hLmRhdGEpdHJ5e3dpbmRvdy5jbG9zZSgpfWNhdGNoKGIpe319O2Z1bmN0aW9uIFFnKGEpe3RoaXMudGM9RmEoKStGYSgpK0ZhKCk7dGhpcy5LZj1hfVFnLnByb3RvdHlwZS5vcGVuPWZ1bmN0aW9uKGEsYil7Y2Quc2V0KFwicmVkaXJlY3RfcmVxdWVzdF9pZFwiLHRoaXMudGMpO2NkLnNldChcInJlZGlyZWN0X3JlcXVlc3RfaWRcIix0aGlzLnRjKTtiLnJlcXVlc3RJZD10aGlzLnRjO2IucmVkaXJlY3RUbz1iLnJlZGlyZWN0VG98fHdpbmRvdy5sb2NhdGlvbi5ocmVmO2ErPSgvXFw/Ly50ZXN0KGEpP1wiXCI6XCI/XCIpK0liKGIpO3dpbmRvdy5sb2NhdGlvbj1hfTtRZy5pc0F2YWlsYWJsZT1mdW5jdGlvbigpe3JldHVybiFFZygpJiYhRGcoKX07UWcucHJvdG90eXBlLkZjPWZ1bmN0aW9uKCl7cmV0dXJuXCJyZWRpcmVjdFwifTt2YXIgUmc9e05FVFdPUktfRVJST1I6XCJVbmFibGUgdG8gY29udGFjdCB0aGUgRmlyZWJhc2Ugc2VydmVyLlwiLFNFUlZFUl9FUlJPUjpcIkFuIHVua25vd24gc2VydmVyIGVycm9yIG9jY3VycmVkLlwiLFRSQU5TUE9SVF9VTkFWQUlMQUJMRTpcIlRoZXJlIGFyZSBubyBsb2dpbiB0cmFuc3BvcnRzIGF2YWlsYWJsZSBmb3IgdGhlIHJlcXVlc3RlZCBtZXRob2QuXCIsUkVRVUVTVF9JTlRFUlJVUFRFRDpcIlRoZSBicm93c2VyIHJlZGlyZWN0ZWQgdGhlIHBhZ2UgYmVmb3JlIHRoZSBsb2dpbiByZXF1ZXN0IGNvdWxkIGNvbXBsZXRlLlwiLFVTRVJfQ0FOQ0VMTEVEOlwiVGhlIHVzZXIgY2FuY2VsbGVkIGF1dGhlbnRpY2F0aW9uLlwifTtmdW5jdGlvbiBTZyhhKXt2YXIgYj1FcnJvcih6KFJnLGEpLGEpO2IuY29kZT1hO3JldHVybiBifTtmdW5jdGlvbiBUZyhhKXt2YXIgYjsoYj0hYS53aW5kb3dfZmVhdHVyZXMpfHwoYj1DZygpLGI9LTEhPT1iLmluZGV4T2YoXCJGZW5uZWMvXCIpfHwtMSE9PWIuaW5kZXhPZihcIkZpcmVmb3gvXCIpJiYtMSE9PWIuaW5kZXhPZihcIkFuZHJvaWRcIikpO2ImJihhLndpbmRvd19mZWF0dXJlcz12b2lkIDApO2Eud2luZG93X25hbWV8fChhLndpbmRvd19uYW1lPVwiX2JsYW5rXCIpO3RoaXMub3B0aW9ucz1hfVxuVGcucHJvdG90eXBlLm9wZW49ZnVuY3Rpb24oYSxiLGMpe2Z1bmN0aW9uIGQoYSl7ZyYmKGRvY3VtZW50LmJvZHkucmVtb3ZlQ2hpbGQoZyksZz12b2lkIDApO3QmJih0PWNsZWFySW50ZXJ2YWwodCkpO0lnKHdpbmRvdyxcIm1lc3NhZ2VcIixlKTtJZyh3aW5kb3csXCJ1bmxvYWRcIixkKTtpZihsJiYhYSl0cnl7bC5jbG9zZSgpfWNhdGNoKGIpe2sucG9zdE1lc3NhZ2UoXCJkaWVcIixtKX1sPWs9dm9pZCAwfWZ1bmN0aW9uIGUoYSl7aWYoYS5vcmlnaW49PT1tKXRyeXt2YXIgYj1SYihhLmRhdGEpO1wicmVhZHlcIj09PWIuYT9rLnBvc3RNZXNzYWdlKEEsbSk6XCJlcnJvclwiPT09Yi5hPyhkKCExKSxjJiYoYyhiLmQpLGM9bnVsbCkpOlwicmVzcG9uc2VcIj09PWIuYSYmKGQoYi5mb3JjZUtlZXBXaW5kb3dPcGVuKSxjJiYoYyhudWxsLGIuZCksYz1udWxsKSl9Y2F0Y2goZSl7fX12YXIgZj1GZyg4KSxnLGs7aWYoIXRoaXMub3B0aW9ucy5yZWxheV91cmwpcmV0dXJuIGMoRXJyb3IoXCJpbnZhbGlkIGFyZ3VtZW50czogb3JpZ2luIG9mIHVybCBhbmQgcmVsYXlfdXJsIG11c3QgbWF0Y2hcIikpO1xudmFyIG09SmcoYSk7aWYobSE9PUpnKHRoaXMub3B0aW9ucy5yZWxheV91cmwpKWMmJnNldFRpbWVvdXQoZnVuY3Rpb24oKXtjKEVycm9yKFwiaW52YWxpZCBhcmd1bWVudHM6IG9yaWdpbiBvZiB1cmwgYW5kIHJlbGF5X3VybCBtdXN0IG1hdGNoXCIpKX0sMCk7ZWxzZXtmJiYoZz1kb2N1bWVudC5jcmVhdGVFbGVtZW50KFwiaWZyYW1lXCIpLGcuc2V0QXR0cmlidXRlKFwic3JjXCIsdGhpcy5vcHRpb25zLnJlbGF5X3VybCksZy5zdHlsZS5kaXNwbGF5PVwibm9uZVwiLGcuc2V0QXR0cmlidXRlKFwibmFtZVwiLFwiX193aW5jaGFuX3JlbGF5X2ZyYW1lXCIpLGRvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoZyksaz1nLmNvbnRlbnRXaW5kb3cpO2ErPSgvXFw/Ly50ZXN0KGEpP1wiXCI6XCI/XCIpK0liKGIpO3ZhciBsPXdpbmRvdy5vcGVuKGEsdGhpcy5vcHRpb25zLndpbmRvd19uYW1lLHRoaXMub3B0aW9ucy53aW5kb3dfZmVhdHVyZXMpO2t8fChrPWwpO3ZhciB0PXNldEludGVydmFsKGZ1bmN0aW9uKCl7bCYmbC5jbG9zZWQmJlxuKGQoITEpLGMmJihjKFNnKFwiVVNFUl9DQU5DRUxMRURcIikpLGM9bnVsbCkpfSw1MDApLEE9Ryh7YTpcInJlcXVlc3RcIixkOmJ9KTtIZyh3aW5kb3csXCJ1bmxvYWRcIixkKTtIZyh3aW5kb3csXCJtZXNzYWdlXCIsZSl9fTtcblRnLmlzQXZhaWxhYmxlPWZ1bmN0aW9uKCl7dmFyIGE7aWYoYT1cInBvc3RNZXNzYWdlXCJpbiB3aW5kb3cmJiFFZygpKShhPURnKCl8fFwidW5kZWZpbmVkXCIhPT10eXBlb2YgbmF2aWdhdG9yJiYoISFDZygpLm1hdGNoKC9XaW5kb3dzIFBob25lLyl8fCEhd2luZG93LldpbmRvd3MmJi9ebXMtYXBweDovLnRlc3QobG9jYXRpb24uaHJlZikpKXx8KGE9Q2coKSxhPVwidW5kZWZpbmVkXCIhPT10eXBlb2YgbmF2aWdhdG9yJiZcInVuZGVmaW5lZFwiIT09dHlwZW9mIHdpbmRvdyYmISEoYS5tYXRjaCgvKGlQaG9uZXxpUG9kfGlQYWQpLipBcHBsZVdlYktpdCg/IS4qU2FmYXJpKS9pKXx8YS5tYXRjaCgvQ3JpT1MvKXx8YS5tYXRjaCgvVHdpdHRlciBmb3IgaVBob25lLyl8fGEubWF0Y2goL0ZCQU5cXC9GQklPUy8pfHx3aW5kb3cubmF2aWdhdG9yLnN0YW5kYWxvbmUpKSxhPSFhO3JldHVybiBhJiYhQ2coKS5tYXRjaCgvUGhhbnRvbUpTLyl9O1RnLnByb3RvdHlwZS5GYz1mdW5jdGlvbigpe3JldHVyblwicG9wdXBcIn07ZnVuY3Rpb24gVWcoYSl7YS5tZXRob2R8fChhLm1ldGhvZD1cIkdFVFwiKTthLmhlYWRlcnN8fChhLmhlYWRlcnM9e30pO2EuaGVhZGVycy5jb250ZW50X3R5cGV8fChhLmhlYWRlcnMuY29udGVudF90eXBlPVwiYXBwbGljYXRpb24vanNvblwiKTthLmhlYWRlcnMuY29udGVudF90eXBlPWEuaGVhZGVycy5jb250ZW50X3R5cGUudG9Mb3dlckNhc2UoKTt0aGlzLm9wdGlvbnM9YX1cblVnLnByb3RvdHlwZS5vcGVuPWZ1bmN0aW9uKGEsYixjKXtmdW5jdGlvbiBkKCl7YyYmKGMoU2coXCJSRVFVRVNUX0lOVEVSUlVQVEVEXCIpKSxjPW51bGwpfXZhciBlPW5ldyBYTUxIdHRwUmVxdWVzdCxmPXRoaXMub3B0aW9ucy5tZXRob2QudG9VcHBlckNhc2UoKSxnO0hnKHdpbmRvdyxcImJlZm9yZXVubG9hZFwiLGQpO2Uub25yZWFkeXN0YXRlY2hhbmdlPWZ1bmN0aW9uKCl7aWYoYyYmND09PWUucmVhZHlTdGF0ZSl7dmFyIGE7aWYoMjAwPD1lLnN0YXR1cyYmMzAwPmUuc3RhdHVzKXt0cnl7YT1SYihlLnJlc3BvbnNlVGV4dCl9Y2F0Y2goYil7fWMobnVsbCxhKX1lbHNlIDUwMDw9ZS5zdGF0dXMmJjYwMD5lLnN0YXR1cz9jKFNnKFwiU0VSVkVSX0VSUk9SXCIpKTpjKFNnKFwiTkVUV09SS19FUlJPUlwiKSk7Yz1udWxsO0lnKHdpbmRvdyxcImJlZm9yZXVubG9hZFwiLGQpfX07aWYoXCJHRVRcIj09PWYpYSs9KC9cXD8vLnRlc3QoYSk/XCJcIjpcIj9cIikrSWIoYiksZz1udWxsO2Vsc2V7dmFyIGs9dGhpcy5vcHRpb25zLmhlYWRlcnMuY29udGVudF90eXBlO1xuXCJhcHBsaWNhdGlvbi9qc29uXCI9PT1rJiYoZz1HKGIpKTtcImFwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZFwiPT09ayYmKGc9SWIoYikpfWUub3BlbihmLGEsITApO2E9e1wiWC1SZXF1ZXN0ZWQtV2l0aFwiOlwiWE1MSHR0cFJlcXVlc3RcIixBY2NlcHQ6XCJhcHBsaWNhdGlvbi9qc29uO3RleHQvcGxhaW5cIn07eWEoYSx0aGlzLm9wdGlvbnMuaGVhZGVycyk7Zm9yKHZhciBtIGluIGEpZS5zZXRSZXF1ZXN0SGVhZGVyKG0sYVttXSk7ZS5zZW5kKGcpfTtVZy5pc0F2YWlsYWJsZT1mdW5jdGlvbigpe3ZhciBhO2lmKGE9ISF3aW5kb3cuWE1MSHR0cFJlcXVlc3QpYT1DZygpLGE9IShhLm1hdGNoKC9NU0lFLyl8fGEubWF0Y2goL1RyaWRlbnQvKSl8fEZnKDEwKTtyZXR1cm4gYX07VWcucHJvdG90eXBlLkZjPWZ1bmN0aW9uKCl7cmV0dXJuXCJqc29uXCJ9O2Z1bmN0aW9uIFZnKGEpe3RoaXMudGM9RmEoKStGYSgpK0ZhKCk7dGhpcy5LZj1hfVxuVmcucHJvdG90eXBlLm9wZW49ZnVuY3Rpb24oYSxiLGMpe2Z1bmN0aW9uIGQoKXtjJiYoYyhTZyhcIlVTRVJfQ0FOQ0VMTEVEXCIpKSxjPW51bGwpfXZhciBlPXRoaXMsZj1zZCh4ZyksZztiLnJlcXVlc3RJZD10aGlzLnRjO2IucmVkaXJlY3RUbz1mLnNjaGVtZStcIjovL1wiK2YuaG9zdCtcIi9ibGFuay9wYWdlLmh0bWxcIjthKz0vXFw/Ly50ZXN0KGEpP1wiXCI6XCI/XCI7YSs9SWIoYik7KGc9d2luZG93Lm9wZW4oYSxcIl9ibGFua1wiLFwibG9jYXRpb249bm9cIikpJiZyKGcuYWRkRXZlbnRMaXN0ZW5lcik/KGcuYWRkRXZlbnRMaXN0ZW5lcihcImxvYWRzdGFydFwiLGZ1bmN0aW9uKGEpe3ZhciBiO2lmKGI9YSYmYS51cmwpYTp7dHJ5e3ZhciBsPWRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoXCJhXCIpO2wuaHJlZj1hLnVybDtiPWwuaG9zdD09PWYuaG9zdCYmXCIvYmxhbmsvcGFnZS5odG1sXCI9PT1sLnBhdGhuYW1lO2JyZWFrIGF9Y2F0Y2godCl7fWI9ITF9YiYmKGE9S2coYS51cmwpLGcucmVtb3ZlRXZlbnRMaXN0ZW5lcihcImV4aXRcIixcbmQpLGcuY2xvc2UoKSxhPW5ldyB5ZyhudWxsLG51bGwse3JlcXVlc3RJZDplLnRjLHJlcXVlc3RLZXk6YX0pLGUuS2YucmVxdWVzdFdpdGhDcmVkZW50aWFsKFwiL2F1dGgvc2Vzc2lvblwiLGEsYyksYz1udWxsKX0pLGcuYWRkRXZlbnRMaXN0ZW5lcihcImV4aXRcIixkKSk6YyhTZyhcIlRSQU5TUE9SVF9VTkFWQUlMQUJMRVwiKSl9O1ZnLmlzQXZhaWxhYmxlPWZ1bmN0aW9uKCl7cmV0dXJuIERnKCl9O1ZnLnByb3RvdHlwZS5GYz1mdW5jdGlvbigpe3JldHVyblwicmVkaXJlY3RcIn07ZnVuY3Rpb24gV2coYSl7YS5jYWxsYmFja19wYXJhbWV0ZXJ8fChhLmNhbGxiYWNrX3BhcmFtZXRlcj1cImNhbGxiYWNrXCIpO3RoaXMub3B0aW9ucz1hO3dpbmRvdy5fX2ZpcmViYXNlX2F1dGhfanNvbnA9d2luZG93Ll9fZmlyZWJhc2VfYXV0aF9qc29ucHx8e319XG5XZy5wcm90b3R5cGUub3Blbj1mdW5jdGlvbihhLGIsYyl7ZnVuY3Rpb24gZCgpe2MmJihjKFNnKFwiUkVRVUVTVF9JTlRFUlJVUFRFRFwiKSksYz1udWxsKX1mdW5jdGlvbiBlKCl7c2V0VGltZW91dChmdW5jdGlvbigpe3dpbmRvdy5fX2ZpcmViYXNlX2F1dGhfanNvbnBbZl09dm9pZCAwO3ZhKHdpbmRvdy5fX2ZpcmViYXNlX2F1dGhfanNvbnApJiYod2luZG93Ll9fZmlyZWJhc2VfYXV0aF9qc29ucD12b2lkIDApO3RyeXt2YXIgYT1kb2N1bWVudC5nZXRFbGVtZW50QnlJZChmKTthJiZhLnBhcmVudE5vZGUucmVtb3ZlQ2hpbGQoYSl9Y2F0Y2goYil7fX0sMSk7SWcod2luZG93LFwiYmVmb3JldW5sb2FkXCIsZCl9dmFyIGY9XCJmblwiKyhuZXcgRGF0ZSkuZ2V0VGltZSgpK01hdGguZmxvb3IoOTk5OTkqTWF0aC5yYW5kb20oKSk7Ylt0aGlzLm9wdGlvbnMuY2FsbGJhY2tfcGFyYW1ldGVyXT1cIl9fZmlyZWJhc2VfYXV0aF9qc29ucC5cIitmO2ErPSgvXFw/Ly50ZXN0KGEpP1wiXCI6XCI/XCIpK0liKGIpO1xuSGcod2luZG93LFwiYmVmb3JldW5sb2FkXCIsZCk7d2luZG93Ll9fZmlyZWJhc2VfYXV0aF9qc29ucFtmXT1mdW5jdGlvbihhKXtjJiYoYyhudWxsLGEpLGM9bnVsbCk7ZSgpfTtYZyhmLGEsYyl9O1xuZnVuY3Rpb24gWGcoYSxiLGMpe3NldFRpbWVvdXQoZnVuY3Rpb24oKXt0cnl7dmFyIGQ9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudChcInNjcmlwdFwiKTtkLnR5cGU9XCJ0ZXh0L2phdmFzY3JpcHRcIjtkLmlkPWE7ZC5hc3luYz0hMDtkLnNyYz1iO2Qub25lcnJvcj1mdW5jdGlvbigpe3ZhciBiPWRvY3VtZW50LmdldEVsZW1lbnRCeUlkKGEpO251bGwhPT1iJiZiLnBhcmVudE5vZGUucmVtb3ZlQ2hpbGQoYik7YyYmYyhTZyhcIk5FVFdPUktfRVJST1JcIikpfTt2YXIgZT1kb2N1bWVudC5nZXRFbGVtZW50c0J5VGFnTmFtZShcImhlYWRcIik7KGUmJjAhPWUubGVuZ3RoP2VbMF06ZG9jdW1lbnQuZG9jdW1lbnRFbGVtZW50KS5hcHBlbmRDaGlsZChkKX1jYXRjaChmKXtjJiZjKFNnKFwiTkVUV09SS19FUlJPUlwiKSl9fSwwKX1XZy5pc0F2YWlsYWJsZT1mdW5jdGlvbigpe3JldHVyblwidW5kZWZpbmVkXCIhPT10eXBlb2YgZG9jdW1lbnQmJm51bGwhPWRvY3VtZW50LmNyZWF0ZUVsZW1lbnR9O1xuV2cucHJvdG90eXBlLkZjPWZ1bmN0aW9uKCl7cmV0dXJuXCJqc29uXCJ9O2Z1bmN0aW9uIFlnKGEsYixjLGQpe2ZmLmNhbGwodGhpcyxbXCJhdXRoX3N0YXR1c1wiXSk7dGhpcy5HPWE7dGhpcy5oZj1iO3RoaXMuaWg9Yzt0aGlzLlBlPWQ7dGhpcy53Yz1uZXcgQmcoYSxbYmQsY2RdKTt0aGlzLnFiPW51bGw7dGhpcy5XZT0hMTtaZyh0aGlzKX1rYShZZyxmZik7aD1ZZy5wcm90b3R5cGU7aC5CZT1mdW5jdGlvbigpe3JldHVybiB0aGlzLnFifHxudWxsfTtmdW5jdGlvbiBaZyhhKXtjZC5nZXQoXCJyZWRpcmVjdF9yZXF1ZXN0X2lkXCIpJiYkZyhhKTt2YXIgYj1hLndjLmdldCgpO2ImJmIudG9rZW4/KGFoKGEsYiksYS5oZihiLnRva2VuLGZ1bmN0aW9uKGMsZCl7YmgoYSxjLGQsITEsYi50b2tlbixiKX0sZnVuY3Rpb24oYixkKXtjaChhLFwicmVzdW1lU2Vzc2lvbigpXCIsYixkKX0pKTphaChhLG51bGwpfVxuZnVuY3Rpb24gZGgoYSxiLGMsZCxlLGYpe1wiZmlyZWJhc2Vpby1kZW1vLmNvbVwiPT09YS5HLmRvbWFpbiYmUyhcIkZpcmViYXNlIGF1dGhlbnRpY2F0aW9uIGlzIG5vdCBzdXBwb3J0ZWQgb24gZGVtbyBGaXJlYmFzZXMgKCouZmlyZWJhc2Vpby1kZW1vLmNvbSkuIFRvIHNlY3VyZSB5b3VyIEZpcmViYXNlLCBjcmVhdGUgYSBwcm9kdWN0aW9uIEZpcmViYXNlIGF0IGh0dHBzOi8vd3d3LmZpcmViYXNlLmNvbS5cIik7YS5oZihiLGZ1bmN0aW9uKGYsayl7YmgoYSxmLGssITAsYixjLGR8fHt9LGUpfSxmdW5jdGlvbihiLGMpe2NoKGEsXCJhdXRoKClcIixiLGMsZil9KX1mdW5jdGlvbiBlaChhLGIpe2Eud2MuY2xlYXIoKTthaChhLG51bGwpO2EuaWgoZnVuY3Rpb24oYSxkKXtpZihcIm9rXCI9PT1hKVQoYixudWxsKTtlbHNle3ZhciBlPShhfHxcImVycm9yXCIpLnRvVXBwZXJDYXNlKCksZj1lO2QmJihmKz1cIjogXCIrZCk7Zj1FcnJvcihmKTtmLmNvZGU9ZTtUKGIsZil9fSl9XG5mdW5jdGlvbiBiaChhLGIsYyxkLGUsZixnLGspe1wib2tcIj09PWI/KGQmJihiPWMuYXV0aCxmLmF1dGg9YixmLmV4cGlyZXM9Yy5leHBpcmVzLGYudG9rZW49RWQoZSk/ZTpcIlwiLGM9bnVsbCxiJiZ5KGIsXCJ1aWRcIik/Yz16KGIsXCJ1aWRcIik6eShmLFwidWlkXCIpJiYoYz16KGYsXCJ1aWRcIikpLGYudWlkPWMsYz1cImN1c3RvbVwiLGImJnkoYixcInByb3ZpZGVyXCIpP2M9eihiLFwicHJvdmlkZXJcIik6eShmLFwicHJvdmlkZXJcIikmJihjPXooZixcInByb3ZpZGVyXCIpKSxmLnByb3ZpZGVyPWMsYS53Yy5jbGVhcigpLEVkKGUpJiYoZz1nfHx7fSxjPWJkLFwic2Vzc2lvbk9ubHlcIj09PWcucmVtZW1iZXImJihjPWNkKSxcIm5vbmVcIiE9PWcucmVtZW1iZXImJmEud2Muc2V0KGYsYykpLGFoKGEsZikpLFQoayxudWxsLGYpKTooYS53Yy5jbGVhcigpLGFoKGEsbnVsbCksZj1hPShifHxcImVycm9yXCIpLnRvVXBwZXJDYXNlKCksYyYmKGYrPVwiOiBcIitjKSxmPUVycm9yKGYpLGYuY29kZT1hLFQoayxmKSl9XG5mdW5jdGlvbiBjaChhLGIsYyxkLGUpe1MoYitcIiB3YXMgY2FuY2VsZWQ6IFwiK2QpO2Eud2MuY2xlYXIoKTthaChhLG51bGwpO2E9RXJyb3IoZCk7YS5jb2RlPWMudG9VcHBlckNhc2UoKTtUKGUsYSl9ZnVuY3Rpb24gZmgoYSxiLGMsZCxlKXtnaChhKTtjPW5ldyB5ZyhkfHx7fSx7fSxjfHx7fSk7aGgoYSxbVWcsV2ddLFwiL2F1dGgvXCIrYixjLGUpfVxuZnVuY3Rpb24gaWgoYSxiLGMsZCl7Z2goYSk7dmFyIGU9W1RnLFZnXTtjPUFnKGMpO3ZhciBmPTYyNTtcImFub255bW91c1wiPT09Ynx8XCJwYXNzd29yZFwiPT09Yj9zZXRUaW1lb3V0KGZ1bmN0aW9uKCl7VChkLFNnKFwiVFJBTlNQT1JUX1VOQVZBSUxBQkxFXCIpKX0sMCk6KFwiZ2l0aHViXCI9PT1iJiYoZj0xMDI1KSxjLmhlLndpbmRvd19mZWF0dXJlcz1cIm1lbnViYXI9eWVzLG1vZGFsPXllcyxhbHdheXNSYWlzZWQ9eWVzbG9jYXRpb249eWVzLHJlc2l6YWJsZT15ZXMsc2Nyb2xsYmFycz15ZXMsc3RhdHVzPXllcyxoZWlnaHQ9NjI1LHdpZHRoPVwiK2YrXCIsdG9wPVwiKyhcIm9iamVjdFwiPT09dHlwZW9mIHNjcmVlbj8uNSooc2NyZWVuLmhlaWdodC02MjUpOjApK1wiLGxlZnQ9XCIrKFwib2JqZWN0XCI9PT10eXBlb2Ygc2NyZWVuPy41KihzY3JlZW4ud2lkdGgtZik6MCksYy5oZS5yZWxheV91cmw9TmcoYS5HLmxjKSxjLmhlLnJlcXVlc3RXaXRoQ3JlZGVudGlhbD11KGEudWMsYSksaGgoYSxlLFwiL2F1dGgvXCIrXG5iLGMsZCkpfWZ1bmN0aW9uICRnKGEpe3ZhciBiPWNkLmdldChcInJlZGlyZWN0X3JlcXVlc3RfaWRcIik7aWYoYil7dmFyIGM9Y2QuZ2V0KFwicmVkaXJlY3RfY2xpZW50X29wdGlvbnNcIik7Y2QucmVtb3ZlKFwicmVkaXJlY3RfcmVxdWVzdF9pZFwiKTtjZC5yZW1vdmUoXCJyZWRpcmVjdF9jbGllbnRfb3B0aW9uc1wiKTt2YXIgZD1bVWcsV2ddLGI9e3JlcXVlc3RJZDpiLHJlcXVlc3RLZXk6S2coZG9jdW1lbnQubG9jYXRpb24uaGFzaCl9LGM9bmV3IHlnKGMse30sYik7YS5XZT0hMDtMZygpO2hoKGEsZCxcIi9hdXRoL3Nlc3Npb25cIixjLGZ1bmN0aW9uKCl7dGhpcy5XZT0hMX0uYmluZChhKSl9fWgudmU9ZnVuY3Rpb24oYSxiKXtnaCh0aGlzKTt2YXIgYz1BZyhhKTtjLmZiLl9tZXRob2Q9XCJQT1NUXCI7dGhpcy51YyhcIi91c2Vyc1wiLGMsZnVuY3Rpb24oYSxjKXthP1QoYixhKTpUKGIsYSxjKX0pfTtcbmguWGU9ZnVuY3Rpb24oYSxiKXt2YXIgYz10aGlzO2doKHRoaXMpO3ZhciBkPVwiL3VzZXJzL1wiK2VuY29kZVVSSUNvbXBvbmVudChhLmVtYWlsKSxlPUFnKGEpO2UuZmIuX21ldGhvZD1cIkRFTEVURVwiO3RoaXMudWMoZCxlLGZ1bmN0aW9uKGEsZCl7IWEmJmQmJmQudWlkJiZjLnFiJiZjLnFiLnVpZCYmYy5xYi51aWQ9PT1kLnVpZCYmZWgoYyk7VChiLGEpfSl9O2guc2U9ZnVuY3Rpb24oYSxiKXtnaCh0aGlzKTt2YXIgYz1cIi91c2Vycy9cIitlbmNvZGVVUklDb21wb25lbnQoYS5lbWFpbCkrXCIvcGFzc3dvcmRcIixkPUFnKGEpO2QuZmIuX21ldGhvZD1cIlBVVFwiO2QuZmIucGFzc3dvcmQ9YS5uZXdQYXNzd29yZDt0aGlzLnVjKGMsZCxmdW5jdGlvbihhKXtUKGIsYSl9KX07XG5oLnJlPWZ1bmN0aW9uKGEsYil7Z2godGhpcyk7dmFyIGM9XCIvdXNlcnMvXCIrZW5jb2RlVVJJQ29tcG9uZW50KGEub2xkRW1haWwpK1wiL2VtYWlsXCIsZD1BZyhhKTtkLmZiLl9tZXRob2Q9XCJQVVRcIjtkLmZiLmVtYWlsPWEubmV3RW1haWw7ZC5mYi5wYXNzd29yZD1hLnBhc3N3b3JkO3RoaXMudWMoYyxkLGZ1bmN0aW9uKGEpe1QoYixhKX0pfTtoLlplPWZ1bmN0aW9uKGEsYil7Z2godGhpcyk7dmFyIGM9XCIvdXNlcnMvXCIrZW5jb2RlVVJJQ29tcG9uZW50KGEuZW1haWwpK1wiL3Bhc3N3b3JkXCIsZD1BZyhhKTtkLmZiLl9tZXRob2Q9XCJQT1NUXCI7dGhpcy51YyhjLGQsZnVuY3Rpb24oYSl7VChiLGEpfSl9O2gudWM9ZnVuY3Rpb24oYSxiLGMpe2poKHRoaXMsW1VnLFdnXSxhLGIsYyl9O1xuZnVuY3Rpb24gaGgoYSxiLGMsZCxlKXtqaChhLGIsYyxkLGZ1bmN0aW9uKGIsYyl7IWImJmMmJmMudG9rZW4mJmMudWlkP2RoKGEsYy50b2tlbixjLGQucWQsZnVuY3Rpb24oYSxiKXthP1QoZSxhKTpUKGUsbnVsbCxiKX0pOlQoZSxifHxTZyhcIlVOS05PV05fRVJST1JcIikpfSl9XG5mdW5jdGlvbiBqaChhLGIsYyxkLGUpe2I9TmEoYixmdW5jdGlvbihhKXtyZXR1cm5cImZ1bmN0aW9uXCI9PT10eXBlb2YgYS5pc0F2YWlsYWJsZSYmYS5pc0F2YWlsYWJsZSgpfSk7MD09PWIubGVuZ3RoP3NldFRpbWVvdXQoZnVuY3Rpb24oKXtUKGUsU2coXCJUUkFOU1BPUlRfVU5BVkFJTEFCTEVcIikpfSwwKTooYj1uZXcgKGIuc2hpZnQoKSkoZC5oZSksZD1HYihkLmZiKSxkLnY9XCJqcy1cIitFYixkLnRyYW5zcG9ydD1iLkZjKCksZC5zdXBwcmVzc19zdGF0dXNfY29kZXM9ITAsYT1NZygpK1wiL1wiK2EuRy5sYytjLGIub3BlbihhLGQsZnVuY3Rpb24oYSxiKXtpZihhKVQoZSxhKTtlbHNlIGlmKGImJmIuZXJyb3Ipe3ZhciBjPUVycm9yKGIuZXJyb3IubWVzc2FnZSk7Yy5jb2RlPWIuZXJyb3IuY29kZTtjLmRldGFpbHM9Yi5lcnJvci5kZXRhaWxzO1QoZSxjKX1lbHNlIFQoZSxudWxsLGIpfSkpfVxuZnVuY3Rpb24gYWgoYSxiKXt2YXIgYz1udWxsIT09YS5xYnx8bnVsbCE9PWI7YS5xYj1iO2MmJmEuaWUoXCJhdXRoX3N0YXR1c1wiLGIpO2EuUGUobnVsbCE9PWIpfWguRWU9ZnVuY3Rpb24oYSl7TyhcImF1dGhfc3RhdHVzXCI9PT1hLCdpbml0aWFsIGV2ZW50IG11c3QgYmUgb2YgdHlwZSBcImF1dGhfc3RhdHVzXCInKTtyZXR1cm4gdGhpcy5XZT9udWxsOlt0aGlzLnFiXX07ZnVuY3Rpb24gZ2goYSl7dmFyIGI9YS5HO2lmKFwiZmlyZWJhc2Vpby5jb21cIiE9PWIuZG9tYWluJiZcImZpcmViYXNlaW8tZGVtby5jb21cIiE9PWIuZG9tYWluJiZcImF1dGguZmlyZWJhc2UuY29tXCI9PT14Zyl0aHJvdyBFcnJvcihcIlRoaXMgY3VzdG9tIEZpcmViYXNlIHNlcnZlciAoJ1wiK2EuRy5kb21haW4rXCInKSBkb2VzIG5vdCBzdXBwb3J0IGRlbGVnYXRlZCBsb2dpbi5cIik7fTt2YXIgZ2Q9XCJ3ZWJzb2NrZXRcIixoZD1cImxvbmdfcG9sbGluZ1wiO2Z1bmN0aW9uIGtoKGEpe3RoaXMubmM9YTt0aGlzLlFkPVtdO3RoaXMuV2I9MDt0aGlzLnRlPS0xO3RoaXMuSmI9bnVsbH1mdW5jdGlvbiBsaChhLGIsYyl7YS50ZT1iO2EuSmI9YzthLnRlPGEuV2ImJihhLkpiKCksYS5KYj1udWxsKX1mdW5jdGlvbiBtaChhLGIsYyl7Zm9yKGEuUWRbYl09YzthLlFkW2EuV2JdOyl7dmFyIGQ9YS5RZFthLldiXTtkZWxldGUgYS5RZFthLldiXTtmb3IodmFyIGU9MDtlPGQubGVuZ3RoOysrZSlpZihkW2VdKXt2YXIgZj1hO2djKGZ1bmN0aW9uKCl7Zi5uYyhkW2VdKX0pfWlmKGEuV2I9PT1hLnRlKXthLkpiJiYoY2xlYXJUaW1lb3V0KGEuSmIpLGEuSmIoKSxhLkpiPW51bGwpO2JyZWFrfWEuV2IrK319O2Z1bmN0aW9uIG5oKGEsYixjLGQpe3RoaXMudWU9YTt0aGlzLmY9cGQoYSk7dGhpcy5yYj10aGlzLnNiPTA7dGhpcy5YYT11YyhiKTt0aGlzLlhmPWM7dGhpcy5LYz0hMTt0aGlzLkZiPWQ7dGhpcy5sZD1mdW5jdGlvbihhKXtyZXR1cm4gZmQoYixoZCxhKX19dmFyIG9oLHBoO1xubmgucHJvdG90eXBlLm9wZW49ZnVuY3Rpb24oYSxiKXt0aGlzLm1mPTA7dGhpcy5uYT1iO3RoaXMuRWY9bmV3IGtoKGEpO3RoaXMuRGI9ITE7dmFyIGM9dGhpczt0aGlzLnViPXNldFRpbWVvdXQoZnVuY3Rpb24oKXtjLmYoXCJUaW1lZCBvdXQgdHJ5aW5nIHRvIGNvbm5lY3QuXCIpO2MuYmIoKTtjLnViPW51bGx9LE1hdGguZmxvb3IoM0U0KSk7dWQoZnVuY3Rpb24oKXtpZighYy5EYil7Yy5XYT1uZXcgcWgoZnVuY3Rpb24oYSxiLGQsayxtKXtyaChjLGFyZ3VtZW50cyk7aWYoYy5XYSlpZihjLnViJiYoY2xlYXJUaW1lb3V0KGMudWIpLGMudWI9bnVsbCksYy5LYz0hMCxcInN0YXJ0XCI9PWEpYy5pZD1iLGMuTWY9ZDtlbHNlIGlmKFwiY2xvc2VcIj09PWEpYj8oYy5XYS4kZD0hMSxsaChjLkVmLGIsZnVuY3Rpb24oKXtjLmJiKCl9KSk6Yy5iYigpO2Vsc2UgdGhyb3cgRXJyb3IoXCJVbnJlY29nbml6ZWQgY29tbWFuZCByZWNlaXZlZDogXCIrYSk7fSxmdW5jdGlvbihhLGIpe3JoKGMsYXJndW1lbnRzKTtcbm1oKGMuRWYsYSxiKX0sZnVuY3Rpb24oKXtjLmJiKCl9LGMubGQpO3ZhciBhPXtzdGFydDpcInRcIn07YS5zZXI9TWF0aC5mbG9vcigxRTgqTWF0aC5yYW5kb20oKSk7Yy5XYS5rZSYmKGEuY2I9Yy5XYS5rZSk7YS52PVwiNVwiO2MuWGYmJihhLnM9Yy5YZik7Yy5GYiYmKGEubHM9Yy5GYik7XCJ1bmRlZmluZWRcIiE9PXR5cGVvZiBsb2NhdGlvbiYmbG9jYXRpb24uaHJlZiYmLTEhPT1sb2NhdGlvbi5ocmVmLmluZGV4T2YoXCJmaXJlYmFzZWlvLmNvbVwiKSYmKGEucj1cImZcIik7YT1jLmxkKGEpO2MuZihcIkNvbm5lY3RpbmcgdmlhIGxvbmctcG9sbCB0byBcIithKTtzaChjLldhLGEsZnVuY3Rpb24oKXt9KX19KX07XG5uaC5wcm90b3R5cGUuc3RhcnQ9ZnVuY3Rpb24oKXt2YXIgYT10aGlzLldhLGI9dGhpcy5NZjthLkdnPXRoaXMuaWQ7YS5IZz1iO2ZvcihhLm9lPSEwO3RoKGEpOyk7YT10aGlzLmlkO2I9dGhpcy5NZjt0aGlzLmtjPWRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoXCJpZnJhbWVcIik7dmFyIGM9e2RmcmFtZTpcInRcIn07Yy5pZD1hO2MucHc9Yjt0aGlzLmtjLnNyYz10aGlzLmxkKGMpO3RoaXMua2Muc3R5bGUuZGlzcGxheT1cIm5vbmVcIjtkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKHRoaXMua2MpfTtcbm5oLmlzQXZhaWxhYmxlPWZ1bmN0aW9uKCl7cmV0dXJuIG9ofHwhcGgmJlwidW5kZWZpbmVkXCIhPT10eXBlb2YgZG9jdW1lbnQmJm51bGwhPWRvY3VtZW50LmNyZWF0ZUVsZW1lbnQmJiEoXCJvYmplY3RcIj09PXR5cGVvZiB3aW5kb3cmJndpbmRvdy5jaHJvbWUmJndpbmRvdy5jaHJvbWUuZXh0ZW5zaW9uJiYhL15jaHJvbWUvLnRlc3Qod2luZG93LmxvY2F0aW9uLmhyZWYpKSYmIShcIm9iamVjdFwiPT09dHlwZW9mIFdpbmRvd3MmJlwib2JqZWN0XCI9PT10eXBlb2YgV2luZG93cy5raCkmJiEwfTtoPW5oLnByb3RvdHlwZTtoLkhkPWZ1bmN0aW9uKCl7fTtoLmZkPWZ1bmN0aW9uKCl7dGhpcy5EYj0hMDt0aGlzLldhJiYodGhpcy5XYS5jbG9zZSgpLHRoaXMuV2E9bnVsbCk7dGhpcy5rYyYmKGRvY3VtZW50LmJvZHkucmVtb3ZlQ2hpbGQodGhpcy5rYyksdGhpcy5rYz1udWxsKTt0aGlzLnViJiYoY2xlYXJUaW1lb3V0KHRoaXMudWIpLHRoaXMudWI9bnVsbCl9O1xuaC5iYj1mdW5jdGlvbigpe3RoaXMuRGJ8fCh0aGlzLmYoXCJMb25ncG9sbCBpcyBjbG9zaW5nIGl0c2VsZlwiKSx0aGlzLmZkKCksdGhpcy5uYSYmKHRoaXMubmEodGhpcy5LYyksdGhpcy5uYT1udWxsKSl9O2guY2xvc2U9ZnVuY3Rpb24oKXt0aGlzLkRifHwodGhpcy5mKFwiTG9uZ3BvbGwgaXMgYmVpbmcgY2xvc2VkLlwiKSx0aGlzLmZkKCkpfTtoLnNlbmQ9ZnVuY3Rpb24oYSl7YT1HKGEpO3RoaXMuc2IrPWEubGVuZ3RoO3JjKHRoaXMuWGEsXCJieXRlc19zZW50XCIsYS5sZW5ndGgpO2E9T2IoYSk7YT1uYihhLCEwKTthPXlkKGEsMTg0MCk7Zm9yKHZhciBiPTA7YjxhLmxlbmd0aDtiKyspe3ZhciBjPXRoaXMuV2E7Yy5jZC5wdXNoKHtZZzp0aGlzLm1mLGhoOmEubGVuZ3RoLG9mOmFbYl19KTtjLm9lJiZ0aChjKTt0aGlzLm1mKyt9fTtmdW5jdGlvbiByaChhLGIpe3ZhciBjPUcoYikubGVuZ3RoO2EucmIrPWM7cmMoYS5YYSxcImJ5dGVzX3JlY2VpdmVkXCIsYyl9XG5mdW5jdGlvbiBxaChhLGIsYyxkKXt0aGlzLmxkPWQ7dGhpcy5sYj1jO3RoaXMuVGU9bmV3IHVnO3RoaXMuY2Q9W107dGhpcy53ZT1NYXRoLmZsb29yKDFFOCpNYXRoLnJhbmRvbSgpKTt0aGlzLiRkPSEwO3RoaXMua2U9aWQoKTt3aW5kb3dbXCJwTFBDb21tYW5kXCIrdGhpcy5rZV09YTt3aW5kb3dbXCJwUlRMUENCXCIrdGhpcy5rZV09YjthPWRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoXCJpZnJhbWVcIik7YS5zdHlsZS5kaXNwbGF5PVwibm9uZVwiO2lmKGRvY3VtZW50LmJvZHkpe2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7dHJ5e2EuY29udGVudFdpbmRvdy5kb2N1bWVudHx8ZmMoXCJObyBJRSBkb21haW4gc2V0dGluZyByZXF1aXJlZFwiKX1jYXRjaChlKXthLnNyYz1cImphdmFzY3JpcHQ6dm9pZCgoZnVuY3Rpb24oKXtkb2N1bWVudC5vcGVuKCk7ZG9jdW1lbnQuZG9tYWluPSdcIitkb2N1bWVudC5kb21haW4rXCInO2RvY3VtZW50LmNsb3NlKCk7fSkoKSlcIn19ZWxzZSB0aHJvd1wiRG9jdW1lbnQgYm9keSBoYXMgbm90IGluaXRpYWxpemVkLiBXYWl0IHRvIGluaXRpYWxpemUgRmlyZWJhc2UgdW50aWwgYWZ0ZXIgdGhlIGRvY3VtZW50IGlzIHJlYWR5LlwiO1xuYS5jb250ZW50RG9jdW1lbnQ/YS5qYj1hLmNvbnRlbnREb2N1bWVudDphLmNvbnRlbnRXaW5kb3c/YS5qYj1hLmNvbnRlbnRXaW5kb3cuZG9jdW1lbnQ6YS5kb2N1bWVudCYmKGEuamI9YS5kb2N1bWVudCk7dGhpcy5HYT1hO2E9XCJcIjt0aGlzLkdhLnNyYyYmXCJqYXZhc2NyaXB0OlwiPT09dGhpcy5HYS5zcmMuc3Vic3RyKDAsMTEpJiYoYT0nPHNjcmlwdD5kb2N1bWVudC5kb21haW49XCInK2RvY3VtZW50LmRvbWFpbisnXCI7XFx4M2Mvc2NyaXB0PicpO2E9XCI8aHRtbD48Ym9keT5cIithK1wiPC9ib2R5PjwvaHRtbD5cIjt0cnl7dGhpcy5HYS5qYi5vcGVuKCksdGhpcy5HYS5qYi53cml0ZShhKSx0aGlzLkdhLmpiLmNsb3NlKCl9Y2F0Y2goZil7ZmMoXCJmcmFtZSB3cml0aW5nIGV4Y2VwdGlvblwiKSxmLnN0YWNrJiZmYyhmLnN0YWNrKSxmYyhmKX19XG5xaC5wcm90b3R5cGUuY2xvc2U9ZnVuY3Rpb24oKXt0aGlzLm9lPSExO2lmKHRoaXMuR2Epe3RoaXMuR2EuamIuYm9keS5pbm5lckhUTUw9XCJcIjt2YXIgYT10aGlzO3NldFRpbWVvdXQoZnVuY3Rpb24oKXtudWxsIT09YS5HYSYmKGRvY3VtZW50LmJvZHkucmVtb3ZlQ2hpbGQoYS5HYSksYS5HYT1udWxsKX0sTWF0aC5mbG9vcigwKSl9dmFyIGI9dGhpcy5sYjtiJiYodGhpcy5sYj1udWxsLGIoKSl9O1xuZnVuY3Rpb24gdGgoYSl7aWYoYS5vZSYmYS4kZCYmYS5UZS5jb3VudCgpPCgwPGEuY2QubGVuZ3RoPzI6MSkpe2Eud2UrKzt2YXIgYj17fTtiLmlkPWEuR2c7Yi5wdz1hLkhnO2Iuc2VyPWEud2U7Zm9yKHZhciBiPWEubGQoYiksYz1cIlwiLGQ9MDswPGEuY2QubGVuZ3RoOylpZigxODcwPj1hLmNkWzBdLm9mLmxlbmd0aCszMCtjLmxlbmd0aCl7dmFyIGU9YS5jZC5zaGlmdCgpLGM9YytcIiZzZWdcIitkK1wiPVwiK2UuWWcrXCImdHNcIitkK1wiPVwiK2UuaGgrXCImZFwiK2QrXCI9XCIrZS5vZjtkKyt9ZWxzZSBicmVhazt1aChhLGIrYyxhLndlKTtyZXR1cm4hMH1yZXR1cm4hMX1mdW5jdGlvbiB1aChhLGIsYyl7ZnVuY3Rpb24gZCgpe2EuVGUucmVtb3ZlKGMpO3RoKGEpfWEuVGUuYWRkKGMsMSk7dmFyIGU9c2V0VGltZW91dChkLE1hdGguZmxvb3IoMjVFMykpO3NoKGEsYixmdW5jdGlvbigpe2NsZWFyVGltZW91dChlKTtkKCl9KX1cbmZ1bmN0aW9uIHNoKGEsYixjKXtzZXRUaW1lb3V0KGZ1bmN0aW9uKCl7dHJ5e2lmKGEuJGQpe3ZhciBkPWEuR2EuamIuY3JlYXRlRWxlbWVudChcInNjcmlwdFwiKTtkLnR5cGU9XCJ0ZXh0L2phdmFzY3JpcHRcIjtkLmFzeW5jPSEwO2Quc3JjPWI7ZC5vbmxvYWQ9ZC5vbnJlYWR5c3RhdGVjaGFuZ2U9ZnVuY3Rpb24oKXt2YXIgYT1kLnJlYWR5U3RhdGU7YSYmXCJsb2FkZWRcIiE9PWEmJlwiY29tcGxldGVcIiE9PWF8fChkLm9ubG9hZD1kLm9ucmVhZHlzdGF0ZWNoYW5nZT1udWxsLGQucGFyZW50Tm9kZSYmZC5wYXJlbnROb2RlLnJlbW92ZUNoaWxkKGQpLGMoKSl9O2Qub25lcnJvcj1mdW5jdGlvbigpe2ZjKFwiTG9uZy1wb2xsIHNjcmlwdCBmYWlsZWQgdG8gbG9hZDogXCIrYik7YS4kZD0hMTthLmNsb3NlKCl9O2EuR2EuamIuYm9keS5hcHBlbmRDaGlsZChkKX19Y2F0Y2goZSl7fX0sTWF0aC5mbG9vcigxKSl9O3ZhciB2aD1udWxsO1widW5kZWZpbmVkXCIhPT10eXBlb2YgTW96V2ViU29ja2V0P3ZoPU1veldlYlNvY2tldDpcInVuZGVmaW5lZFwiIT09dHlwZW9mIFdlYlNvY2tldCYmKHZoPVdlYlNvY2tldCk7ZnVuY3Rpb24gd2goYSxiLGMsZCl7dGhpcy51ZT1hO3RoaXMuZj1wZCh0aGlzLnVlKTt0aGlzLmZyYW1lcz10aGlzLk5jPW51bGw7dGhpcy5yYj10aGlzLnNiPXRoaXMuZmY9MDt0aGlzLlhhPXVjKGIpO2E9e3Y6XCI1XCJ9O1widW5kZWZpbmVkXCIhPT10eXBlb2YgbG9jYXRpb24mJmxvY2F0aW9uLmhyZWYmJi0xIT09bG9jYXRpb24uaHJlZi5pbmRleE9mKFwiZmlyZWJhc2Vpby5jb21cIikmJihhLnI9XCJmXCIpO2MmJihhLnM9Yyk7ZCYmKGEubHM9ZCk7dGhpcy5qZj1mZChiLGdkLGEpfXZhciB4aDtcbndoLnByb3RvdHlwZS5vcGVuPWZ1bmN0aW9uKGEsYil7dGhpcy5sYj1iO3RoaXMuTGc9YTt0aGlzLmYoXCJXZWJzb2NrZXQgY29ubmVjdGluZyB0byBcIit0aGlzLmpmKTt0aGlzLktjPSExO2JkLnNldChcInByZXZpb3VzX3dlYnNvY2tldF9mYWlsdXJlXCIsITApO3RyeXt0aGlzLkxhPW5ldyB2aCh0aGlzLmpmKX1jYXRjaChjKXt0aGlzLmYoXCJFcnJvciBpbnN0YW50aWF0aW5nIFdlYlNvY2tldC5cIik7dmFyIGQ9Yy5tZXNzYWdlfHxjLmRhdGE7ZCYmdGhpcy5mKGQpO3RoaXMuYmIoKTtyZXR1cm59dmFyIGU9dGhpczt0aGlzLkxhLm9ub3Blbj1mdW5jdGlvbigpe2UuZihcIldlYnNvY2tldCBjb25uZWN0ZWQuXCIpO2UuS2M9ITB9O3RoaXMuTGEub25jbG9zZT1mdW5jdGlvbigpe2UuZihcIldlYnNvY2tldCBjb25uZWN0aW9uIHdhcyBkaXNjb25uZWN0ZWQuXCIpO2UuTGE9bnVsbDtlLmJiKCl9O3RoaXMuTGEub25tZXNzYWdlPWZ1bmN0aW9uKGEpe2lmKG51bGwhPT1lLkxhKWlmKGE9YS5kYXRhLGUucmIrPVxuYS5sZW5ndGgscmMoZS5YYSxcImJ5dGVzX3JlY2VpdmVkXCIsYS5sZW5ndGgpLHloKGUpLG51bGwhPT1lLmZyYW1lcyl6aChlLGEpO2Vsc2V7YTp7TyhudWxsPT09ZS5mcmFtZXMsXCJXZSBhbHJlYWR5IGhhdmUgYSBmcmFtZSBidWZmZXJcIik7aWYoNj49YS5sZW5ndGgpe3ZhciBiPU51bWJlcihhKTtpZighaXNOYU4oYikpe2UuZmY9YjtlLmZyYW1lcz1bXTthPW51bGw7YnJlYWsgYX19ZS5mZj0xO2UuZnJhbWVzPVtdfW51bGwhPT1hJiZ6aChlLGEpfX07dGhpcy5MYS5vbmVycm9yPWZ1bmN0aW9uKGEpe2UuZihcIldlYlNvY2tldCBlcnJvci4gIENsb3NpbmcgY29ubmVjdGlvbi5cIik7KGE9YS5tZXNzYWdlfHxhLmRhdGEpJiZlLmYoYSk7ZS5iYigpfX07d2gucHJvdG90eXBlLnN0YXJ0PWZ1bmN0aW9uKCl7fTtcbndoLmlzQXZhaWxhYmxlPWZ1bmN0aW9uKCl7dmFyIGE9ITE7aWYoXCJ1bmRlZmluZWRcIiE9PXR5cGVvZiBuYXZpZ2F0b3ImJm5hdmlnYXRvci51c2VyQWdlbnQpe3ZhciBiPW5hdmlnYXRvci51c2VyQWdlbnQubWF0Y2goL0FuZHJvaWQgKFswLTldezAsfVxcLlswLTldezAsfSkvKTtiJiYxPGIubGVuZ3RoJiY0LjQ+cGFyc2VGbG9hdChiWzFdKSYmKGE9ITApfXJldHVybiFhJiZudWxsIT09dmgmJiF4aH07d2gucmVzcG9uc2VzUmVxdWlyZWRUb0JlSGVhbHRoeT0yO3doLmhlYWx0aHlUaW1lb3V0PTNFNDtoPXdoLnByb3RvdHlwZTtoLkhkPWZ1bmN0aW9uKCl7YmQucmVtb3ZlKFwicHJldmlvdXNfd2Vic29ja2V0X2ZhaWx1cmVcIil9O2Z1bmN0aW9uIHpoKGEsYil7YS5mcmFtZXMucHVzaChiKTtpZihhLmZyYW1lcy5sZW5ndGg9PWEuZmYpe3ZhciBjPWEuZnJhbWVzLmpvaW4oXCJcIik7YS5mcmFtZXM9bnVsbDtjPVJiKGMpO2EuTGcoYyl9fVxuaC5zZW5kPWZ1bmN0aW9uKGEpe3loKHRoaXMpO2E9RyhhKTt0aGlzLnNiKz1hLmxlbmd0aDtyYyh0aGlzLlhhLFwiYnl0ZXNfc2VudFwiLGEubGVuZ3RoKTthPXlkKGEsMTYzODQpOzE8YS5sZW5ndGgmJkFoKHRoaXMsU3RyaW5nKGEubGVuZ3RoKSk7Zm9yKHZhciBiPTA7YjxhLmxlbmd0aDtiKyspQWgodGhpcyxhW2JdKX07aC5mZD1mdW5jdGlvbigpe3RoaXMuRGI9ITA7dGhpcy5OYyYmKGNsZWFySW50ZXJ2YWwodGhpcy5OYyksdGhpcy5OYz1udWxsKTt0aGlzLkxhJiYodGhpcy5MYS5jbG9zZSgpLHRoaXMuTGE9bnVsbCl9O2guYmI9ZnVuY3Rpb24oKXt0aGlzLkRifHwodGhpcy5mKFwiV2ViU29ja2V0IGlzIGNsb3NpbmcgaXRzZWxmXCIpLHRoaXMuZmQoKSx0aGlzLmxiJiYodGhpcy5sYih0aGlzLktjKSx0aGlzLmxiPW51bGwpKX07aC5jbG9zZT1mdW5jdGlvbigpe3RoaXMuRGJ8fCh0aGlzLmYoXCJXZWJTb2NrZXQgaXMgYmVpbmcgY2xvc2VkXCIpLHRoaXMuZmQoKSl9O1xuZnVuY3Rpb24geWgoYSl7Y2xlYXJJbnRlcnZhbChhLk5jKTthLk5jPXNldEludGVydmFsKGZ1bmN0aW9uKCl7YS5MYSYmQWgoYSxcIjBcIik7eWgoYSl9LE1hdGguZmxvb3IoNDVFMykpfWZ1bmN0aW9uIEFoKGEsYil7dHJ5e2EuTGEuc2VuZChiKX1jYXRjaChjKXthLmYoXCJFeGNlcHRpb24gdGhyb3duIGZyb20gV2ViU29ja2V0LnNlbmQoKTpcIixjLm1lc3NhZ2V8fGMuZGF0YSxcIkNsb3NpbmcgY29ubmVjdGlvbi5cIiksc2V0VGltZW91dCh1KGEuYmIsYSksMCl9fTtmdW5jdGlvbiBCaChhKXtDaCh0aGlzLGEpfXZhciBEaD1bbmgsd2hdO2Z1bmN0aW9uIENoKGEsYil7dmFyIGM9d2gmJndoLmlzQXZhaWxhYmxlKCksZD1jJiYhKGJkLkFmfHwhMD09PWJkLmdldChcInByZXZpb3VzX3dlYnNvY2tldF9mYWlsdXJlXCIpKTtiLmpoJiYoY3x8UyhcIndzczovLyBVUkwgdXNlZCwgYnV0IGJyb3dzZXIgaXNuJ3Qga25vd24gdG8gc3VwcG9ydCB3ZWJzb2NrZXRzLiAgVHJ5aW5nIGFueXdheS5cIiksZD0hMCk7aWYoZClhLmpkPVt3aF07ZWxzZXt2YXIgZT1hLmpkPVtdO3pkKERoLGZ1bmN0aW9uKGEsYil7YiYmYi5pc0F2YWlsYWJsZSgpJiZlLnB1c2goYil9KX19ZnVuY3Rpb24gRWgoYSl7aWYoMDxhLmpkLmxlbmd0aClyZXR1cm4gYS5qZFswXTt0aHJvdyBFcnJvcihcIk5vIHRyYW5zcG9ydHMgYXZhaWxhYmxlXCIpO307ZnVuY3Rpb24gRmgoYSxiLGMsZCxlLGYsZyl7dGhpcy5pZD1hO3RoaXMuZj1wZChcImM6XCIrdGhpcy5pZCtcIjpcIik7dGhpcy5uYz1jO3RoaXMuWmM9ZDt0aGlzLm5hPWU7dGhpcy5SZT1mO3RoaXMuRz1iO3RoaXMuUGQ9W107dGhpcy5rZj0wO3RoaXMuV2Y9bmV3IEJoKGIpO3RoaXMuTj0wO3RoaXMuRmI9Zzt0aGlzLmYoXCJDb25uZWN0aW9uIGNyZWF0ZWRcIik7R2godGhpcyl9XG5mdW5jdGlvbiBHaChhKXt2YXIgYj1FaChhLldmKTthLks9bmV3IGIoXCJjOlwiK2EuaWQrXCI6XCIrYS5rZisrLGEuRyx2b2lkIDAsYS5GYik7YS5WZT1iLnJlc3BvbnNlc1JlcXVpcmVkVG9CZUhlYWx0aHl8fDA7dmFyIGM9SGgoYSxhLkspLGQ9SWgoYSxhLkspO2Eua2Q9YS5LO2EuZWQ9YS5LO2EuRj1udWxsO2EuRWI9ITE7c2V0VGltZW91dChmdW5jdGlvbigpe2EuSyYmYS5LLm9wZW4oYyxkKX0sTWF0aC5mbG9vcigwKSk7Yj1iLmhlYWx0aHlUaW1lb3V0fHwwOzA8YiYmKGEuQmQ9c2V0VGltZW91dChmdW5jdGlvbigpe2EuQmQ9bnVsbDthLkVifHwoYS5LJiYxMDI0MDA8YS5LLnJiPyhhLmYoXCJDb25uZWN0aW9uIGV4Y2VlZGVkIGhlYWx0aHkgdGltZW91dCBidXQgaGFzIHJlY2VpdmVkIFwiK2EuSy5yYitcIiBieXRlcy4gIE1hcmtpbmcgY29ubmVjdGlvbiBoZWFsdGh5LlwiKSxhLkViPSEwLGEuSy5IZCgpKTphLksmJjEwMjQwPGEuSy5zYj9hLmYoXCJDb25uZWN0aW9uIGV4Y2VlZGVkIGhlYWx0aHkgdGltZW91dCBidXQgaGFzIHNlbnQgXCIrXG5hLksuc2IrXCIgYnl0ZXMuICBMZWF2aW5nIGNvbm5lY3Rpb24gYWxpdmUuXCIpOihhLmYoXCJDbG9zaW5nIHVuaGVhbHRoeSBjb25uZWN0aW9uIGFmdGVyIHRpbWVvdXQuXCIpLGEuY2xvc2UoKSkpfSxNYXRoLmZsb29yKGIpKSl9ZnVuY3Rpb24gSWgoYSxiKXtyZXR1cm4gZnVuY3Rpb24oYyl7Yj09PWEuSz8oYS5LPW51bGwsY3x8MCE9PWEuTj8xPT09YS5OJiZhLmYoXCJSZWFsdGltZSBjb25uZWN0aW9uIGxvc3QuXCIpOihhLmYoXCJSZWFsdGltZSBjb25uZWN0aW9uIGZhaWxlZC5cIiksXCJzLVwiPT09YS5HLmFiLnN1YnN0cigwLDIpJiYoYmQucmVtb3ZlKFwiaG9zdDpcIithLkcuaG9zdCksYS5HLmFiPWEuRy5ob3N0KSksYS5jbG9zZSgpKTpiPT09YS5GPyhhLmYoXCJTZWNvbmRhcnkgY29ubmVjdGlvbiBsb3N0LlwiKSxjPWEuRixhLkY9bnVsbCxhLmtkIT09YyYmYS5lZCE9PWN8fGEuY2xvc2UoKSk6YS5mKFwiY2xvc2luZyBhbiBvbGQgY29ubmVjdGlvblwiKX19XG5mdW5jdGlvbiBIaChhLGIpe3JldHVybiBmdW5jdGlvbihjKXtpZigyIT1hLk4paWYoYj09PWEuZWQpe3ZhciBkPXdkKFwidFwiLGMpO2M9d2QoXCJkXCIsYyk7aWYoXCJjXCI9PWQpe2lmKGQ9d2QoXCJ0XCIsYyksXCJkXCJpbiBjKWlmKGM9Yy5kLFwiaFwiPT09ZCl7dmFyIGQ9Yy50cyxlPWMudixmPWMuaDthLlVmPWMucztlZChhLkcsZik7MD09YS5OJiYoYS5LLnN0YXJ0KCksSmgoYSxhLkssZCksXCI1XCIhPT1lJiZTKFwiUHJvdG9jb2wgdmVyc2lvbiBtaXNtYXRjaCBkZXRlY3RlZFwiKSxjPWEuV2YsKGM9MTxjLmpkLmxlbmd0aD9jLmpkWzFdOm51bGwpJiZLaChhLGMpKX1lbHNlIGlmKFwiblwiPT09ZCl7YS5mKFwicmVjdmQgZW5kIHRyYW5zbWlzc2lvbiBvbiBwcmltYXJ5XCIpO2EuZWQ9YS5GO2ZvcihjPTA7YzxhLlBkLmxlbmd0aDsrK2MpYS5MZChhLlBkW2NdKTthLlBkPVtdO0xoKGEpfWVsc2VcInNcIj09PWQ/KGEuZihcIkNvbm5lY3Rpb24gc2h1dGRvd24gY29tbWFuZCByZWNlaXZlZC4gU2h1dHRpbmcgZG93bi4uLlwiKSxcbmEuUmUmJihhLlJlKGMpLGEuUmU9bnVsbCksYS5uYT1udWxsLGEuY2xvc2UoKSk6XCJyXCI9PT1kPyhhLmYoXCJSZXNldCBwYWNrZXQgcmVjZWl2ZWQuICBOZXcgaG9zdDogXCIrYyksZWQoYS5HLGMpLDE9PT1hLk4/YS5jbG9zZSgpOihNaChhKSxHaChhKSkpOlwiZVwiPT09ZD9xZChcIlNlcnZlciBFcnJvcjogXCIrYyk6XCJvXCI9PT1kPyhhLmYoXCJnb3QgcG9uZyBvbiBwcmltYXJ5LlwiKSxOaChhKSxPaChhKSk6cWQoXCJVbmtub3duIGNvbnRyb2wgcGFja2V0IGNvbW1hbmQ6IFwiK2QpfWVsc2VcImRcIj09ZCYmYS5MZChjKX1lbHNlIGlmKGI9PT1hLkYpaWYoZD13ZChcInRcIixjKSxjPXdkKFwiZFwiLGMpLFwiY1wiPT1kKVwidFwiaW4gYyYmKGM9Yy50LFwiYVwiPT09Yz9QaChhKTpcInJcIj09PWM/KGEuZihcIkdvdCBhIHJlc2V0IG9uIHNlY29uZGFyeSwgY2xvc2luZyBpdFwiKSxhLkYuY2xvc2UoKSxhLmtkIT09YS5GJiZhLmVkIT09YS5GfHxhLmNsb3NlKCkpOlwib1wiPT09YyYmKGEuZihcImdvdCBwb25nIG9uIHNlY29uZGFyeS5cIiksXG5hLlRmLS0sUGgoYSkpKTtlbHNlIGlmKFwiZFwiPT1kKWEuUGQucHVzaChjKTtlbHNlIHRocm93IEVycm9yKFwiVW5rbm93biBwcm90b2NvbCBsYXllcjogXCIrZCk7ZWxzZSBhLmYoXCJtZXNzYWdlIG9uIG9sZCBjb25uZWN0aW9uXCIpfX1GaC5wcm90b3R5cGUuSWE9ZnVuY3Rpb24oYSl7UWgodGhpcyx7dDpcImRcIixkOmF9KX07ZnVuY3Rpb24gTGgoYSl7YS5rZD09PWEuRiYmYS5lZD09PWEuRiYmKGEuZihcImNsZWFuaW5nIHVwIGFuZCBwcm9tb3RpbmcgYSBjb25uZWN0aW9uOiBcIithLkYudWUpLGEuSz1hLkYsYS5GPW51bGwpfVxuZnVuY3Rpb24gUGgoYSl7MD49YS5UZj8oYS5mKFwiU2Vjb25kYXJ5IGNvbm5lY3Rpb24gaXMgaGVhbHRoeS5cIiksYS5FYj0hMCxhLkYuSGQoKSxhLkYuc3RhcnQoKSxhLmYoXCJzZW5kaW5nIGNsaWVudCBhY2sgb24gc2Vjb25kYXJ5XCIpLGEuRi5zZW5kKHt0OlwiY1wiLGQ6e3Q6XCJhXCIsZDp7fX19KSxhLmYoXCJFbmRpbmcgdHJhbnNtaXNzaW9uIG9uIHByaW1hcnlcIiksYS5LLnNlbmQoe3Q6XCJjXCIsZDp7dDpcIm5cIixkOnt9fX0pLGEua2Q9YS5GLExoKGEpKTooYS5mKFwic2VuZGluZyBwaW5nIG9uIHNlY29uZGFyeS5cIiksYS5GLnNlbmQoe3Q6XCJjXCIsZDp7dDpcInBcIixkOnt9fX0pKX1GaC5wcm90b3R5cGUuTGQ9ZnVuY3Rpb24oYSl7TmgodGhpcyk7dGhpcy5uYyhhKX07ZnVuY3Rpb24gTmgoYSl7YS5FYnx8KGEuVmUtLSwwPj1hLlZlJiYoYS5mKFwiUHJpbWFyeSBjb25uZWN0aW9uIGlzIGhlYWx0aHkuXCIpLGEuRWI9ITAsYS5LLkhkKCkpKX1cbmZ1bmN0aW9uIEtoKGEsYil7YS5GPW5ldyBiKFwiYzpcIithLmlkK1wiOlwiK2Eua2YrKyxhLkcsYS5VZik7YS5UZj1iLnJlc3BvbnNlc1JlcXVpcmVkVG9CZUhlYWx0aHl8fDA7YS5GLm9wZW4oSGgoYSxhLkYpLEloKGEsYS5GKSk7c2V0VGltZW91dChmdW5jdGlvbigpe2EuRiYmKGEuZihcIlRpbWVkIG91dCB0cnlpbmcgdG8gdXBncmFkZS5cIiksYS5GLmNsb3NlKCkpfSxNYXRoLmZsb29yKDZFNCkpfWZ1bmN0aW9uIEpoKGEsYixjKXthLmYoXCJSZWFsdGltZSBjb25uZWN0aW9uIGVzdGFibGlzaGVkLlwiKTthLks9YjthLk49MTthLlpjJiYoYS5aYyhjLGEuVWYpLGEuWmM9bnVsbCk7MD09PWEuVmU/KGEuZihcIlByaW1hcnkgY29ubmVjdGlvbiBpcyBoZWFsdGh5LlwiKSxhLkViPSEwKTpzZXRUaW1lb3V0KGZ1bmN0aW9uKCl7T2goYSl9LE1hdGguZmxvb3IoNUUzKSl9XG5mdW5jdGlvbiBPaChhKXthLkVifHwxIT09YS5OfHwoYS5mKFwic2VuZGluZyBwaW5nIG9uIHByaW1hcnkuXCIpLFFoKGEse3Q6XCJjXCIsZDp7dDpcInBcIixkOnt9fX0pKX1mdW5jdGlvbiBRaChhLGIpe2lmKDEhPT1hLk4pdGhyb3dcIkNvbm5lY3Rpb24gaXMgbm90IGNvbm5lY3RlZFwiO2Eua2Quc2VuZChiKX1GaC5wcm90b3R5cGUuY2xvc2U9ZnVuY3Rpb24oKXsyIT09dGhpcy5OJiYodGhpcy5mKFwiQ2xvc2luZyByZWFsdGltZSBjb25uZWN0aW9uLlwiKSx0aGlzLk49MixNaCh0aGlzKSx0aGlzLm5hJiYodGhpcy5uYSgpLHRoaXMubmE9bnVsbCkpfTtmdW5jdGlvbiBNaChhKXthLmYoXCJTaHV0dGluZyBkb3duIGFsbCBjb25uZWN0aW9uc1wiKTthLksmJihhLksuY2xvc2UoKSxhLks9bnVsbCk7YS5GJiYoYS5GLmNsb3NlKCksYS5GPW51bGwpO2EuQmQmJihjbGVhclRpbWVvdXQoYS5CZCksYS5CZD1udWxsKX07ZnVuY3Rpb24gUmgoYSxiLGMsZCl7dGhpcy5pZD1TaCsrO3RoaXMuZj1wZChcInA6XCIrdGhpcy5pZCtcIjpcIik7dGhpcy5CZj10aGlzLkllPSExO3RoaXMuYmE9e307dGhpcy5zYT1bXTt0aGlzLmFkPTA7dGhpcy5ZYz1bXTt0aGlzLnFhPSExO3RoaXMuZWI9MUUzO3RoaXMuSWQ9M0U1O3RoaXMuS2I9Yjt0aGlzLlhjPWM7dGhpcy5TZT1kO3RoaXMuRz1hO3RoaXMud2I9dGhpcy5DYT10aGlzLk1hPXRoaXMuRmI9dGhpcy4kZT1udWxsO3RoaXMuU2I9ITE7dGhpcy5XZD17fTt0aGlzLlhnPTA7dGhpcy5yZj0hMDt0aGlzLk9jPXRoaXMuS2U9bnVsbDtUaCh0aGlzLDApO2tmLnliKCkuSWIoXCJ2aXNpYmxlXCIsdGhpcy5PZyx0aGlzKTstMT09PWEuaG9zdC5pbmRleE9mKFwiZmJsb2NhbFwiKSYmamYueWIoKS5JYihcIm9ubGluZVwiLHRoaXMuTWcsdGhpcyl9dmFyIFNoPTAsVWg9MDtoPVJoLnByb3RvdHlwZTtcbmguSWE9ZnVuY3Rpb24oYSxiLGMpe3ZhciBkPSsrdGhpcy5YZzthPXtyOmQsYTphLGI6Yn07dGhpcy5mKEcoYSkpO08odGhpcy5xYSxcInNlbmRSZXF1ZXN0IGNhbGwgd2hlbiB3ZSdyZSBub3QgY29ubmVjdGVkIG5vdCBhbGxvd2VkLlwiKTt0aGlzLk1hLklhKGEpO2MmJih0aGlzLldkW2RdPWMpfTtoLkNmPWZ1bmN0aW9uKGEsYixjLGQpe3ZhciBlPWEud2EoKSxmPWEucGF0aC50b1N0cmluZygpO3RoaXMuZihcIkxpc3RlbiBjYWxsZWQgZm9yIFwiK2YrXCIgXCIrZSk7dGhpcy5iYVtmXT10aGlzLmJhW2ZdfHx7fTtPKEllKGEubil8fCFIZShhLm4pLFwibGlzdGVuKCkgY2FsbGVkIGZvciBub24tZGVmYXVsdCBidXQgY29tcGxldGUgcXVlcnlcIik7TyghdGhpcy5iYVtmXVtlXSxcImxpc3RlbigpIGNhbGxlZCB0d2ljZSBmb3Igc2FtZSBwYXRoL3F1ZXJ5SWQuXCIpO2E9e0k6ZCxBZDpiLFVnOmEsdGFnOmN9O3RoaXMuYmFbZl1bZV09YTt0aGlzLnFhJiZWaCh0aGlzLGEpfTtcbmZ1bmN0aW9uIFZoKGEsYil7dmFyIGM9Yi5VZyxkPWMucGF0aC50b1N0cmluZygpLGU9Yy53YSgpO2EuZihcIkxpc3RlbiBvbiBcIitkK1wiIGZvciBcIitlKTt2YXIgZj17cDpkfTtiLnRhZyYmKGYucT1HZShjLm4pLGYudD1iLnRhZyk7Zi5oPWIuQWQoKTthLklhKFwicVwiLGYsZnVuY3Rpb24oZil7dmFyIGs9Zi5kLG09Zi5zO2lmKGsmJlwib2JqZWN0XCI9PT10eXBlb2YgayYmeShrLFwid1wiKSl7dmFyIGw9eihrLFwid1wiKTtkYShsKSYmMDw9TGEobCxcIm5vX2luZGV4XCIpJiZTKFwiVXNpbmcgYW4gdW5zcGVjaWZpZWQgaW5kZXguIENvbnNpZGVyIGFkZGluZyBcIisoJ1wiLmluZGV4T25cIjogXCInK2Mubi5nLnRvU3RyaW5nKCkrJ1wiJykrXCIgYXQgXCIrYy5wYXRoLnRvU3RyaW5nKCkrXCIgdG8geW91ciBzZWN1cml0eSBydWxlcyBmb3IgYmV0dGVyIHBlcmZvcm1hbmNlXCIpfShhLmJhW2RdJiZhLmJhW2RdW2VdKT09PWImJihhLmYoXCJsaXN0ZW4gcmVzcG9uc2VcIixmKSxcIm9rXCIhPT1tJiZXaChhLGQsZSksYi5JJiZcbmIuSShtLGspKX0pfWguTz1mdW5jdGlvbihhLGIsYyl7dGhpcy5DYT17cmc6YSxzZjohMSxEYzpiLG9kOmN9O3RoaXMuZihcIkF1dGhlbnRpY2F0aW5nIHVzaW5nIGNyZWRlbnRpYWw6IFwiK2EpO1hoKHRoaXMpOyhiPTQwPT1hLmxlbmd0aCl8fChhPUNkKGEpLkVjLGI9XCJvYmplY3RcIj09PXR5cGVvZiBhJiYhMD09PXooYSxcImFkbWluXCIpKTtiJiYodGhpcy5mKFwiQWRtaW4gYXV0aCBjcmVkZW50aWFsIGRldGVjdGVkLiAgUmVkdWNpbmcgbWF4IHJlY29ubmVjdCB0aW1lLlwiKSx0aGlzLklkPTNFNCl9O2guamU9ZnVuY3Rpb24oYSl7dGhpcy5DYT1udWxsO3RoaXMucWEmJnRoaXMuSWEoXCJ1bmF1dGhcIix7fSxmdW5jdGlvbihiKXthKGIucyxiLmQpfSl9O1xuZnVuY3Rpb24gWGgoYSl7dmFyIGI9YS5DYTthLnFhJiZiJiZhLklhKFwiYXV0aFwiLHtjcmVkOmIucmd9LGZ1bmN0aW9uKGMpe3ZhciBkPWMucztjPWMuZHx8XCJlcnJvclwiO1wib2tcIiE9PWQmJmEuQ2E9PT1iJiYoYS5DYT1udWxsKTtiLnNmP1wib2tcIiE9PWQmJmIub2QmJmIub2QoZCxjKTooYi5zZj0hMCxiLkRjJiZiLkRjKGQsYykpfSl9aC4kZj1mdW5jdGlvbihhLGIpe3ZhciBjPWEucGF0aC50b1N0cmluZygpLGQ9YS53YSgpO3RoaXMuZihcIlVubGlzdGVuIGNhbGxlZCBmb3IgXCIrYytcIiBcIitkKTtPKEllKGEubil8fCFIZShhLm4pLFwidW5saXN0ZW4oKSBjYWxsZWQgZm9yIG5vbi1kZWZhdWx0IGJ1dCBjb21wbGV0ZSBxdWVyeVwiKTtpZihXaCh0aGlzLGMsZCkmJnRoaXMucWEpe3ZhciBlPUdlKGEubik7dGhpcy5mKFwiVW5saXN0ZW4gb24gXCIrYytcIiBmb3IgXCIrZCk7Yz17cDpjfTtiJiYoYy5xPWUsYy50PWIpO3RoaXMuSWEoXCJuXCIsYyl9fTtcbmguUWU9ZnVuY3Rpb24oYSxiLGMpe3RoaXMucWE/WWgodGhpcyxcIm9cIixhLGIsYyk6dGhpcy5ZYy5wdXNoKHtiZDphLGFjdGlvbjpcIm9cIixkYXRhOmIsSTpjfSl9O2guR2Y9ZnVuY3Rpb24oYSxiLGMpe3RoaXMucWE/WWgodGhpcyxcIm9tXCIsYSxiLGMpOnRoaXMuWWMucHVzaCh7YmQ6YSxhY3Rpb246XCJvbVwiLGRhdGE6YixJOmN9KX07aC5NZD1mdW5jdGlvbihhLGIpe3RoaXMucWE/WWgodGhpcyxcIm9jXCIsYSxudWxsLGIpOnRoaXMuWWMucHVzaCh7YmQ6YSxhY3Rpb246XCJvY1wiLGRhdGE6bnVsbCxJOmJ9KX07ZnVuY3Rpb24gWWgoYSxiLGMsZCxlKXtjPXtwOmMsZDpkfTthLmYoXCJvbkRpc2Nvbm5lY3QgXCIrYixjKTthLklhKGIsYyxmdW5jdGlvbihhKXtlJiZzZXRUaW1lb3V0KGZ1bmN0aW9uKCl7ZShhLnMsYS5kKX0sTWF0aC5mbG9vcigwKSl9KX1oLnB1dD1mdW5jdGlvbihhLGIsYyxkKXtaaCh0aGlzLFwicFwiLGEsYixjLGQpfTtcbmguRGY9ZnVuY3Rpb24oYSxiLGMsZCl7WmgodGhpcyxcIm1cIixhLGIsYyxkKX07ZnVuY3Rpb24gWmgoYSxiLGMsZCxlLGYpe2Q9e3A6YyxkOmR9O3AoZikmJihkLmg9Zik7YS5zYS5wdXNoKHthY3Rpb246YixQZjpkLEk6ZX0pO2EuYWQrKztiPWEuc2EubGVuZ3RoLTE7YS5xYT8kaChhLGIpOmEuZihcIkJ1ZmZlcmluZyBwdXQ6IFwiK2MpfWZ1bmN0aW9uICRoKGEsYil7dmFyIGM9YS5zYVtiXS5hY3Rpb24sZD1hLnNhW2JdLlBmLGU9YS5zYVtiXS5JO2Euc2FbYl0uVmc9YS5xYTthLklhKGMsZCxmdW5jdGlvbihkKXthLmYoYytcIiByZXNwb25zZVwiLGQpO2RlbGV0ZSBhLnNhW2JdO2EuYWQtLTswPT09YS5hZCYmKGEuc2E9W10pO2UmJmUoZC5zLGQuZCl9KX1cbmguWWU9ZnVuY3Rpb24oYSl7dGhpcy5xYSYmKGE9e2M6YX0sdGhpcy5mKFwicmVwb3J0U3RhdHNcIixhKSx0aGlzLklhKFwic1wiLGEsZnVuY3Rpb24oYSl7XCJva1wiIT09YS5zJiZ0aGlzLmYoXCJyZXBvcnRTdGF0c1wiLFwiRXJyb3Igc2VuZGluZyBzdGF0czogXCIrYS5kKX0pKX07XG5oLkxkPWZ1bmN0aW9uKGEpe2lmKFwiclwiaW4gYSl7dGhpcy5mKFwiZnJvbSBzZXJ2ZXI6IFwiK0coYSkpO3ZhciBiPWEucixjPXRoaXMuV2RbYl07YyYmKGRlbGV0ZSB0aGlzLldkW2JdLGMoYS5iKSl9ZWxzZXtpZihcImVycm9yXCJpbiBhKXRocm93XCJBIHNlcnZlci1zaWRlIGVycm9yIGhhcyBvY2N1cnJlZDogXCIrYS5lcnJvcjtcImFcImluIGEmJihiPWEuYSxjPWEuYix0aGlzLmYoXCJoYW5kbGVTZXJ2ZXJNZXNzYWdlXCIsYixjKSxcImRcIj09PWI/dGhpcy5LYihjLnAsYy5kLCExLGMudCk6XCJtXCI9PT1iP3RoaXMuS2IoYy5wLGMuZCwhMCxjLnQpOlwiY1wiPT09Yj9haSh0aGlzLGMucCxjLnEpOlwiYWNcIj09PWI/KGE9Yy5zLGI9Yy5kLGM9dGhpcy5DYSx0aGlzLkNhPW51bGwsYyYmYy5vZCYmYy5vZChhLGIpKTpcInNkXCI9PT1iP3RoaXMuJGU/dGhpcy4kZShjKTpcIm1zZ1wiaW4gYyYmXCJ1bmRlZmluZWRcIiE9PXR5cGVvZiBjb25zb2xlJiZjb25zb2xlLmxvZyhcIkZJUkVCQVNFOiBcIitjLm1zZy5yZXBsYWNlKFwiXFxuXCIsXG5cIlxcbkZJUkVCQVNFOiBcIikpOnFkKFwiVW5yZWNvZ25pemVkIGFjdGlvbiByZWNlaXZlZCBmcm9tIHNlcnZlcjogXCIrRyhiKStcIlxcbkFyZSB5b3UgdXNpbmcgdGhlIGxhdGVzdCBjbGllbnQ/XCIpKX19O2guWmM9ZnVuY3Rpb24oYSxiKXt0aGlzLmYoXCJjb25uZWN0aW9uIHJlYWR5XCIpO3RoaXMucWE9ITA7dGhpcy5PYz0obmV3IERhdGUpLmdldFRpbWUoKTt0aGlzLlNlKHtzZXJ2ZXJUaW1lT2Zmc2V0OmEtKG5ldyBEYXRlKS5nZXRUaW1lKCl9KTt0aGlzLkZiPWI7aWYodGhpcy5yZil7dmFyIGM9e307Y1tcInNkay5qcy5cIitFYi5yZXBsYWNlKC9cXC4vZyxcIi1cIildPTE7RGcoKT9jW1wiZnJhbWV3b3JrLmNvcmRvdmFcIl09MTpcIm9iamVjdFwiPT09dHlwZW9mIG5hdmlnYXRvciYmXCJSZWFjdE5hdGl2ZVwiPT09bmF2aWdhdG9yLnByb2R1Y3QmJihjW1wiZnJhbWV3b3JrLnJlYWN0bmF0aXZlXCJdPTEpO3RoaXMuWWUoYyl9YmkodGhpcyk7dGhpcy5yZj0hMTt0aGlzLlhjKCEwKX07XG5mdW5jdGlvbiBUaChhLGIpe08oIWEuTWEsXCJTY2hlZHVsaW5nIGEgY29ubmVjdCB3aGVuIHdlJ3JlIGFscmVhZHkgY29ubmVjdGVkL2luZz9cIik7YS53YiYmY2xlYXJUaW1lb3V0KGEud2IpO2Eud2I9c2V0VGltZW91dChmdW5jdGlvbigpe2Eud2I9bnVsbDtjaShhKX0sTWF0aC5mbG9vcihiKSl9aC5PZz1mdW5jdGlvbihhKXthJiYhdGhpcy5TYiYmdGhpcy5lYj09PXRoaXMuSWQmJih0aGlzLmYoXCJXaW5kb3cgYmVjYW1lIHZpc2libGUuICBSZWR1Y2luZyBkZWxheS5cIiksdGhpcy5lYj0xRTMsdGhpcy5NYXx8VGgodGhpcywwKSk7dGhpcy5TYj1hfTtoLk1nPWZ1bmN0aW9uKGEpe2E/KHRoaXMuZihcIkJyb3dzZXIgd2VudCBvbmxpbmUuXCIpLHRoaXMuZWI9MUUzLHRoaXMuTWF8fFRoKHRoaXMsMCkpOih0aGlzLmYoXCJCcm93c2VyIHdlbnQgb2ZmbGluZS4gIEtpbGxpbmcgY29ubmVjdGlvbi5cIiksdGhpcy5NYSYmdGhpcy5NYS5jbG9zZSgpKX07XG5oLklmPWZ1bmN0aW9uKCl7dGhpcy5mKFwiZGF0YSBjbGllbnQgZGlzY29ubmVjdGVkXCIpO3RoaXMucWE9ITE7dGhpcy5NYT1udWxsO2Zvcih2YXIgYT0wO2E8dGhpcy5zYS5sZW5ndGg7YSsrKXt2YXIgYj10aGlzLnNhW2FdO2ImJlwiaFwiaW4gYi5QZiYmYi5WZyYmKGIuSSYmYi5JKFwiZGlzY29ubmVjdFwiKSxkZWxldGUgdGhpcy5zYVthXSx0aGlzLmFkLS0pfTA9PT10aGlzLmFkJiYodGhpcy5zYT1bXSk7dGhpcy5XZD17fTtkaSh0aGlzKSYmKHRoaXMuU2I/dGhpcy5PYyYmKDNFNDwobmV3IERhdGUpLmdldFRpbWUoKS10aGlzLk9jJiYodGhpcy5lYj0xRTMpLHRoaXMuT2M9bnVsbCk6KHRoaXMuZihcIldpbmRvdyBpc24ndCB2aXNpYmxlLiAgRGVsYXlpbmcgcmVjb25uZWN0LlwiKSx0aGlzLmViPXRoaXMuSWQsdGhpcy5LZT0obmV3IERhdGUpLmdldFRpbWUoKSksYT1NYXRoLm1heCgwLHRoaXMuZWItKChuZXcgRGF0ZSkuZ2V0VGltZSgpLXRoaXMuS2UpKSxhKj1NYXRoLnJhbmRvbSgpLHRoaXMuZihcIlRyeWluZyB0byByZWNvbm5lY3QgaW4gXCIrXG5hK1wibXNcIiksVGgodGhpcyxhKSx0aGlzLmViPU1hdGgubWluKHRoaXMuSWQsMS4zKnRoaXMuZWIpKTt0aGlzLlhjKCExKX07ZnVuY3Rpb24gY2koYSl7aWYoZGkoYSkpe2EuZihcIk1ha2luZyBhIGNvbm5lY3Rpb24gYXR0ZW1wdFwiKTthLktlPShuZXcgRGF0ZSkuZ2V0VGltZSgpO2EuT2M9bnVsbDt2YXIgYj11KGEuTGQsYSksYz11KGEuWmMsYSksZD11KGEuSWYsYSksZT1hLmlkK1wiOlwiK1VoKys7YS5NYT1uZXcgRmgoZSxhLkcsYixjLGQsZnVuY3Rpb24oYil7UyhiK1wiIChcIithLkcudG9TdHJpbmcoKStcIilcIik7YS5CZj0hMH0sYS5GYil9fWguQ2I9ZnVuY3Rpb24oKXt0aGlzLkllPSEwO3RoaXMuTWE/dGhpcy5NYS5jbG9zZSgpOih0aGlzLndiJiYoY2xlYXJUaW1lb3V0KHRoaXMud2IpLHRoaXMud2I9bnVsbCksdGhpcy5xYSYmdGhpcy5JZigpKX07aC52Yz1mdW5jdGlvbigpe3RoaXMuSWU9ITE7dGhpcy5lYj0xRTM7dGhpcy5NYXx8VGgodGhpcywwKX07XG5mdW5jdGlvbiBhaShhLGIsYyl7Yz1jP09hKGMsZnVuY3Rpb24oYSl7cmV0dXJuIHhkKGEpfSkuam9pbihcIiRcIik6XCJkZWZhdWx0XCI7KGE9V2goYSxiLGMpKSYmYS5JJiZhLkkoXCJwZXJtaXNzaW9uX2RlbmllZFwiKX1mdW5jdGlvbiBXaChhLGIsYyl7Yj0obmV3IFAoYikpLnRvU3RyaW5nKCk7dmFyIGQ7cChhLmJhW2JdKT8oZD1hLmJhW2JdW2NdLGRlbGV0ZSBhLmJhW2JdW2NdLDA9PT1vYShhLmJhW2JdKSYmZGVsZXRlIGEuYmFbYl0pOmQ9dm9pZCAwO3JldHVybiBkfWZ1bmN0aW9uIGJpKGEpe1hoKGEpO3YoYS5iYSxmdW5jdGlvbihiKXt2KGIsZnVuY3Rpb24oYil7VmgoYSxiKX0pfSk7Zm9yKHZhciBiPTA7YjxhLnNhLmxlbmd0aDtiKyspYS5zYVtiXSYmJGgoYSxiKTtmb3IoO2EuWWMubGVuZ3RoOyliPWEuWWMuc2hpZnQoKSxZaChhLGIuYWN0aW9uLGIuYmQsYi5kYXRhLGIuSSl9ZnVuY3Rpb24gZGkoYSl7dmFyIGI7Yj1qZi55YigpLm9jO3JldHVybiFhLkJmJiYhYS5JZSYmYn07dmFyIFU9e3pnOmZ1bmN0aW9uKCl7b2g9eGg9ITB9fTtVLmZvcmNlTG9uZ1BvbGxpbmc9VS56ZztVLkFnPWZ1bmN0aW9uKCl7cGg9ITB9O1UuZm9yY2VXZWJTb2NrZXRzPVUuQWc7VS5FZz1mdW5jdGlvbigpe3JldHVybiB3aC5pc0F2YWlsYWJsZSgpfTtVLmlzV2ViU29ja2V0c0F2YWlsYWJsZT1VLkVnO1UuYWg9ZnVuY3Rpb24oYSxiKXthLmsuVmEuJGU9Yn07VS5zZXRTZWN1cml0eURlYnVnQ2FsbGJhY2s9VS5haDtVLmJmPWZ1bmN0aW9uKGEsYil7YS5rLmJmKGIpfTtVLnN0YXRzPVUuYmY7VS5jZj1mdW5jdGlvbihhLGIpe2Euay5jZihiKX07VS5zdGF0c0luY3JlbWVudENvdW50ZXI9VS5jZjtVLnVkPWZ1bmN0aW9uKGEpe3JldHVybiBhLmsudWR9O1UuZGF0YVVwZGF0ZUNvdW50PVUudWQ7VS5EZz1mdW5jdGlvbihhLGIpe2Euay5IZT1ifTtVLmludGVyY2VwdFNlcnZlckRhdGE9VS5EZztVLktnPWZ1bmN0aW9uKGEpe25ldyBPZyhhKX07VS5vblBvcHVwT3Blbj1VLktnO1xuVS5aZz1mdW5jdGlvbihhKXt4Zz1hfTtVLnNldEF1dGhlbnRpY2F0aW9uU2VydmVyPVUuWmc7ZnVuY3Rpb24gZWkoYSxiKXt0aGlzLmNvbW1pdHRlZD1hO3RoaXMuc25hcHNob3Q9Yn07ZnVuY3Rpb24gVihhLGIpe3RoaXMuZGQ9YTt0aGlzLnRhPWJ9Vi5wcm90b3R5cGUuY2FuY2VsPWZ1bmN0aW9uKGEpe0QoXCJGaXJlYmFzZS5vbkRpc2Nvbm5lY3QoKS5jYW5jZWxcIiwwLDEsYXJndW1lbnRzLmxlbmd0aCk7RihcIkZpcmViYXNlLm9uRGlzY29ubmVjdCgpLmNhbmNlbFwiLDEsYSwhMCk7dmFyIGI9bmV3IEI7dGhpcy5kZC5NZCh0aGlzLnRhLEMoYixhKSk7cmV0dXJuIGIuRH07Vi5wcm90b3R5cGUuY2FuY2VsPVYucHJvdG90eXBlLmNhbmNlbDtWLnByb3RvdHlwZS5yZW1vdmU9ZnVuY3Rpb24oYSl7RChcIkZpcmViYXNlLm9uRGlzY29ubmVjdCgpLnJlbW92ZVwiLDAsMSxhcmd1bWVudHMubGVuZ3RoKTtvZyhcIkZpcmViYXNlLm9uRGlzY29ubmVjdCgpLnJlbW92ZVwiLHRoaXMudGEpO0YoXCJGaXJlYmFzZS5vbkRpc2Nvbm5lY3QoKS5yZW1vdmVcIiwxLGEsITApO3ZhciBiPW5ldyBCO2ZpKHRoaXMuZGQsdGhpcy50YSxudWxsLEMoYixhKSk7cmV0dXJuIGIuRH07XG5WLnByb3RvdHlwZS5yZW1vdmU9Vi5wcm90b3R5cGUucmVtb3ZlO1YucHJvdG90eXBlLnNldD1mdW5jdGlvbihhLGIpe0QoXCJGaXJlYmFzZS5vbkRpc2Nvbm5lY3QoKS5zZXRcIiwxLDIsYXJndW1lbnRzLmxlbmd0aCk7b2coXCJGaXJlYmFzZS5vbkRpc2Nvbm5lY3QoKS5zZXRcIix0aGlzLnRhKTtnZyhcIkZpcmViYXNlLm9uRGlzY29ubmVjdCgpLnNldFwiLGEsdGhpcy50YSwhMSk7RihcIkZpcmViYXNlLm9uRGlzY29ubmVjdCgpLnNldFwiLDIsYiwhMCk7dmFyIGM9bmV3IEI7ZmkodGhpcy5kZCx0aGlzLnRhLGEsQyhjLGIpKTtyZXR1cm4gYy5EfTtWLnByb3RvdHlwZS5zZXQ9Vi5wcm90b3R5cGUuc2V0O1xuVi5wcm90b3R5cGUuT2I9ZnVuY3Rpb24oYSxiLGMpe0QoXCJGaXJlYmFzZS5vbkRpc2Nvbm5lY3QoKS5zZXRXaXRoUHJpb3JpdHlcIiwyLDMsYXJndW1lbnRzLmxlbmd0aCk7b2coXCJGaXJlYmFzZS5vbkRpc2Nvbm5lY3QoKS5zZXRXaXRoUHJpb3JpdHlcIix0aGlzLnRhKTtnZyhcIkZpcmViYXNlLm9uRGlzY29ubmVjdCgpLnNldFdpdGhQcmlvcml0eVwiLGEsdGhpcy50YSwhMSk7a2coXCJGaXJlYmFzZS5vbkRpc2Nvbm5lY3QoKS5zZXRXaXRoUHJpb3JpdHlcIiwyLGIpO0YoXCJGaXJlYmFzZS5vbkRpc2Nvbm5lY3QoKS5zZXRXaXRoUHJpb3JpdHlcIiwzLGMsITApO3ZhciBkPW5ldyBCO2dpKHRoaXMuZGQsdGhpcy50YSxhLGIsQyhkLGMpKTtyZXR1cm4gZC5EfTtWLnByb3RvdHlwZS5zZXRXaXRoUHJpb3JpdHk9Vi5wcm90b3R5cGUuT2I7XG5WLnByb3RvdHlwZS51cGRhdGU9ZnVuY3Rpb24oYSxiKXtEKFwiRmlyZWJhc2Uub25EaXNjb25uZWN0KCkudXBkYXRlXCIsMSwyLGFyZ3VtZW50cy5sZW5ndGgpO29nKFwiRmlyZWJhc2Uub25EaXNjb25uZWN0KCkudXBkYXRlXCIsdGhpcy50YSk7aWYoZGEoYSkpe2Zvcih2YXIgYz17fSxkPTA7ZDxhLmxlbmd0aDsrK2QpY1tcIlwiK2RdPWFbZF07YT1jO1MoXCJQYXNzaW5nIGFuIEFycmF5IHRvIEZpcmViYXNlLm9uRGlzY29ubmVjdCgpLnVwZGF0ZSgpIGlzIGRlcHJlY2F0ZWQuIFVzZSBzZXQoKSBpZiB5b3Ugd2FudCB0byBvdmVyd3JpdGUgdGhlIGV4aXN0aW5nIGRhdGEsIG9yIGFuIE9iamVjdCB3aXRoIGludGVnZXIga2V5cyBpZiB5b3UgcmVhbGx5IGRvIHdhbnQgdG8gb25seSB1cGRhdGUgc29tZSBvZiB0aGUgY2hpbGRyZW4uXCIpfWpnKFwiRmlyZWJhc2Uub25EaXNjb25uZWN0KCkudXBkYXRlXCIsYSx0aGlzLnRhKTtGKFwiRmlyZWJhc2Uub25EaXNjb25uZWN0KCkudXBkYXRlXCIsMixiLCEwKTtcbmM9bmV3IEI7aGkodGhpcy5kZCx0aGlzLnRhLGEsQyhjLGIpKTtyZXR1cm4gYy5EfTtWLnByb3RvdHlwZS51cGRhdGU9Vi5wcm90b3R5cGUudXBkYXRlO2Z1bmN0aW9uIFcoYSxiLGMpe3RoaXMuQT1hO3RoaXMuWT1iO3RoaXMuZz1jfVcucHJvdG90eXBlLko9ZnVuY3Rpb24oKXtEKFwiRmlyZWJhc2UuRGF0YVNuYXBzaG90LnZhbFwiLDAsMCxhcmd1bWVudHMubGVuZ3RoKTtyZXR1cm4gdGhpcy5BLkooKX07Vy5wcm90b3R5cGUudmFsPVcucHJvdG90eXBlLko7Vy5wcm90b3R5cGUucWY9ZnVuY3Rpb24oKXtEKFwiRmlyZWJhc2UuRGF0YVNuYXBzaG90LmV4cG9ydFZhbFwiLDAsMCxhcmd1bWVudHMubGVuZ3RoKTtyZXR1cm4gdGhpcy5BLkooITApfTtXLnByb3RvdHlwZS5leHBvcnRWYWw9Vy5wcm90b3R5cGUucWY7Vy5wcm90b3R5cGUueGc9ZnVuY3Rpb24oKXtEKFwiRmlyZWJhc2UuRGF0YVNuYXBzaG90LmV4aXN0c1wiLDAsMCxhcmd1bWVudHMubGVuZ3RoKTtyZXR1cm4hdGhpcy5BLmUoKX07Vy5wcm90b3R5cGUuZXhpc3RzPVcucHJvdG90eXBlLnhnO1xuVy5wcm90b3R5cGUubz1mdW5jdGlvbihhKXtEKFwiRmlyZWJhc2UuRGF0YVNuYXBzaG90LmNoaWxkXCIsMCwxLGFyZ3VtZW50cy5sZW5ndGgpO2ZhKGEpJiYoYT1TdHJpbmcoYSkpO25nKFwiRmlyZWJhc2UuRGF0YVNuYXBzaG90LmNoaWxkXCIsYSk7dmFyIGI9bmV3IFAoYSksYz10aGlzLlkubyhiKTtyZXR1cm4gbmV3IFcodGhpcy5BLlMoYiksYyxSKX07Vy5wcm90b3R5cGUuY2hpbGQ9Vy5wcm90b3R5cGUubztXLnByb3RvdHlwZS5GYT1mdW5jdGlvbihhKXtEKFwiRmlyZWJhc2UuRGF0YVNuYXBzaG90Lmhhc0NoaWxkXCIsMSwxLGFyZ3VtZW50cy5sZW5ndGgpO25nKFwiRmlyZWJhc2UuRGF0YVNuYXBzaG90Lmhhc0NoaWxkXCIsYSk7dmFyIGI9bmV3IFAoYSk7cmV0dXJuIXRoaXMuQS5TKGIpLmUoKX07Vy5wcm90b3R5cGUuaGFzQ2hpbGQ9Vy5wcm90b3R5cGUuRmE7XG5XLnByb3RvdHlwZS5DPWZ1bmN0aW9uKCl7RChcIkZpcmViYXNlLkRhdGFTbmFwc2hvdC5nZXRQcmlvcml0eVwiLDAsMCxhcmd1bWVudHMubGVuZ3RoKTtyZXR1cm4gdGhpcy5BLkMoKS5KKCl9O1cucHJvdG90eXBlLmdldFByaW9yaXR5PVcucHJvdG90eXBlLkM7Vy5wcm90b3R5cGUuZm9yRWFjaD1mdW5jdGlvbihhKXtEKFwiRmlyZWJhc2UuRGF0YVNuYXBzaG90LmZvckVhY2hcIiwxLDEsYXJndW1lbnRzLmxlbmd0aCk7RihcIkZpcmViYXNlLkRhdGFTbmFwc2hvdC5mb3JFYWNoXCIsMSxhLCExKTtpZih0aGlzLkEuTCgpKXJldHVybiExO3ZhciBiPXRoaXM7cmV0dXJuISF0aGlzLkEuUih0aGlzLmcsZnVuY3Rpb24oYyxkKXtyZXR1cm4gYShuZXcgVyhkLGIuWS5vKGMpLFIpKX0pfTtXLnByb3RvdHlwZS5mb3JFYWNoPVcucHJvdG90eXBlLmZvckVhY2g7XG5XLnByb3RvdHlwZS56ZD1mdW5jdGlvbigpe0QoXCJGaXJlYmFzZS5EYXRhU25hcHNob3QuaGFzQ2hpbGRyZW5cIiwwLDAsYXJndW1lbnRzLmxlbmd0aCk7cmV0dXJuIHRoaXMuQS5MKCk/ITE6IXRoaXMuQS5lKCl9O1cucHJvdG90eXBlLmhhc0NoaWxkcmVuPVcucHJvdG90eXBlLnpkO1cucHJvdG90eXBlLm5hbWU9ZnVuY3Rpb24oKXtTKFwiRmlyZWJhc2UuRGF0YVNuYXBzaG90Lm5hbWUoKSBiZWluZyBkZXByZWNhdGVkLiBQbGVhc2UgdXNlIEZpcmViYXNlLkRhdGFTbmFwc2hvdC5rZXkoKSBpbnN0ZWFkLlwiKTtEKFwiRmlyZWJhc2UuRGF0YVNuYXBzaG90Lm5hbWVcIiwwLDAsYXJndW1lbnRzLmxlbmd0aCk7cmV0dXJuIHRoaXMua2V5KCl9O1cucHJvdG90eXBlLm5hbWU9Vy5wcm90b3R5cGUubmFtZTtXLnByb3RvdHlwZS5rZXk9ZnVuY3Rpb24oKXtEKFwiRmlyZWJhc2UuRGF0YVNuYXBzaG90LmtleVwiLDAsMCxhcmd1bWVudHMubGVuZ3RoKTtyZXR1cm4gdGhpcy5ZLmtleSgpfTtcblcucHJvdG90eXBlLmtleT1XLnByb3RvdHlwZS5rZXk7Vy5wcm90b3R5cGUuSGI9ZnVuY3Rpb24oKXtEKFwiRmlyZWJhc2UuRGF0YVNuYXBzaG90Lm51bUNoaWxkcmVuXCIsMCwwLGFyZ3VtZW50cy5sZW5ndGgpO3JldHVybiB0aGlzLkEuSGIoKX07Vy5wcm90b3R5cGUubnVtQ2hpbGRyZW49Vy5wcm90b3R5cGUuSGI7Vy5wcm90b3R5cGUuTWI9ZnVuY3Rpb24oKXtEKFwiRmlyZWJhc2UuRGF0YVNuYXBzaG90LnJlZlwiLDAsMCxhcmd1bWVudHMubGVuZ3RoKTtyZXR1cm4gdGhpcy5ZfTtXLnByb3RvdHlwZS5yZWY9Vy5wcm90b3R5cGUuTWI7ZnVuY3Rpb24gaWkoYSxiLGMpe3RoaXMuVmI9YTt0aGlzLnRiPWI7dGhpcy52Yj1jfHxudWxsfWg9aWkucHJvdG90eXBlO2guUWY9ZnVuY3Rpb24oYSl7cmV0dXJuXCJ2YWx1ZVwiPT09YX07aC5jcmVhdGVFdmVudD1mdW5jdGlvbihhLGIpe3ZhciBjPWIubi5nO3JldHVybiBuZXcgamMoXCJ2YWx1ZVwiLHRoaXMsbmV3IFcoYS5OYSxiLk1iKCksYykpfTtoLlpiPWZ1bmN0aW9uKGEpe3ZhciBiPXRoaXMudmI7aWYoXCJjYW5jZWxcIj09PWEuRGUoKSl7Tyh0aGlzLnRiLFwiUmFpc2luZyBhIGNhbmNlbCBldmVudCBvbiBhIGxpc3RlbmVyIHdpdGggbm8gY2FuY2VsIGNhbGxiYWNrXCIpO3ZhciBjPXRoaXMudGI7cmV0dXJuIGZ1bmN0aW9uKCl7Yy5jYWxsKGIsYS5lcnJvcil9fXZhciBkPXRoaXMuVmI7cmV0dXJuIGZ1bmN0aW9uKCl7ZC5jYWxsKGIsYS5iZSl9fTtoLmxmPWZ1bmN0aW9uKGEsYil7cmV0dXJuIHRoaXMudGI/bmV3IGtjKHRoaXMsYSxiKTpudWxsfTtcbmgubWF0Y2hlcz1mdW5jdGlvbihhKXtyZXR1cm4gYSBpbnN0YW5jZW9mIGlpP2EuVmImJnRoaXMuVmI/YS5WYj09PXRoaXMuVmImJmEudmI9PT10aGlzLnZiOiEwOiExfTtoLnlmPWZ1bmN0aW9uKCl7cmV0dXJuIG51bGwhPT10aGlzLlZifTtmdW5jdGlvbiBqaShhLGIsYyl7dGhpcy5qYT1hO3RoaXMudGI9Yjt0aGlzLnZiPWN9aD1qaS5wcm90b3R5cGU7aC5RZj1mdW5jdGlvbihhKXthPVwiY2hpbGRyZW5fYWRkZWRcIj09PWE/XCJjaGlsZF9hZGRlZFwiOmE7cmV0dXJuKFwiY2hpbGRyZW5fcmVtb3ZlZFwiPT09YT9cImNoaWxkX3JlbW92ZWRcIjphKWluIHRoaXMuamF9O2gubGY9ZnVuY3Rpb24oYSxiKXtyZXR1cm4gdGhpcy50Yj9uZXcga2ModGhpcyxhLGIpOm51bGx9O1xuaC5jcmVhdGVFdmVudD1mdW5jdGlvbihhLGIpe08obnVsbCE9YS5aYSxcIkNoaWxkIGV2ZW50cyBzaG91bGQgaGF2ZSBhIGNoaWxkTmFtZS5cIik7dmFyIGM9Yi5NYigpLm8oYS5aYSk7cmV0dXJuIG5ldyBqYyhhLnR5cGUsdGhpcyxuZXcgVyhhLk5hLGMsYi5uLmcpLGEuVGQpfTtoLlpiPWZ1bmN0aW9uKGEpe3ZhciBiPXRoaXMudmI7aWYoXCJjYW5jZWxcIj09PWEuRGUoKSl7Tyh0aGlzLnRiLFwiUmFpc2luZyBhIGNhbmNlbCBldmVudCBvbiBhIGxpc3RlbmVyIHdpdGggbm8gY2FuY2VsIGNhbGxiYWNrXCIpO3ZhciBjPXRoaXMudGI7cmV0dXJuIGZ1bmN0aW9uKCl7Yy5jYWxsKGIsYS5lcnJvcil9fXZhciBkPXRoaXMuamFbYS53ZF07cmV0dXJuIGZ1bmN0aW9uKCl7ZC5jYWxsKGIsYS5iZSxhLlRkKX19O1xuaC5tYXRjaGVzPWZ1bmN0aW9uKGEpe2lmKGEgaW5zdGFuY2VvZiBqaSl7aWYoIXRoaXMuamF8fCFhLmphKXJldHVybiEwO2lmKHRoaXMudmI9PT1hLnZiKXt2YXIgYj1vYShhLmphKTtpZihiPT09b2EodGhpcy5qYSkpe2lmKDE9PT1iKXt2YXIgYj1wYShhLmphKSxjPXBhKHRoaXMuamEpO3JldHVybiBjPT09YiYmKCFhLmphW2JdfHwhdGhpcy5qYVtjXXx8YS5qYVtiXT09PXRoaXMuamFbY10pfXJldHVybiBuYSh0aGlzLmphLGZ1bmN0aW9uKGIsYyl7cmV0dXJuIGEuamFbY109PT1ifSl9fX1yZXR1cm4hMX07aC55Zj1mdW5jdGlvbigpe3JldHVybiBudWxsIT09dGhpcy5qYX07ZnVuY3Rpb24ga2koKXt0aGlzLnphPXt9fWg9a2kucHJvdG90eXBlO2guZT1mdW5jdGlvbigpe3JldHVybiB2YSh0aGlzLnphKX07aC5nYj1mdW5jdGlvbihhLGIsYyl7dmFyIGQ9YS5zb3VyY2UuTGI7aWYobnVsbCE9PWQpcmV0dXJuIGQ9eih0aGlzLnphLGQpLE8obnVsbCE9ZCxcIlN5bmNUcmVlIGdhdmUgdXMgYW4gb3AgZm9yIGFuIGludmFsaWQgcXVlcnkuXCIpLGQuZ2IoYSxiLGMpO3ZhciBlPVtdO3YodGhpcy56YSxmdW5jdGlvbihkKXtlPWUuY29uY2F0KGQuZ2IoYSxiLGMpKX0pO3JldHVybiBlfTtoLlRiPWZ1bmN0aW9uKGEsYixjLGQsZSl7dmFyIGY9YS53YSgpLGc9eih0aGlzLnphLGYpO2lmKCFnKXt2YXIgZz1jLkFhKGU/ZDpudWxsKSxrPSExO2c/az0hMDooZz1kIGluc3RhbmNlb2YgZmU/Yy5DYyhkKTpILGs9ITEpO2c9bmV3IFllKGEsbmV3IGplKG5ldyBYYihnLGssITEpLG5ldyBYYihkLGUsITEpKSk7dGhpcy56YVtmXT1nfWcuVGIoYik7cmV0dXJuIGFmKGcsYil9O1xuaC5uYj1mdW5jdGlvbihhLGIsYyl7dmFyIGQ9YS53YSgpLGU9W10sZj1bXSxnPW51bGwhPWxpKHRoaXMpO2lmKFwiZGVmYXVsdFwiPT09ZCl7dmFyIGs9dGhpczt2KHRoaXMuemEsZnVuY3Rpb24oYSxkKXtmPWYuY29uY2F0KGEubmIoYixjKSk7YS5lKCkmJihkZWxldGUgay56YVtkXSxIZShhLlkubil8fGUucHVzaChhLlkpKX0pfWVsc2V7dmFyIG09eih0aGlzLnphLGQpO20mJihmPWYuY29uY2F0KG0ubmIoYixjKSksbS5lKCkmJihkZWxldGUgdGhpcy56YVtkXSxIZShtLlkubil8fGUucHVzaChtLlkpKSl9ZyYmbnVsbD09bGkodGhpcykmJmUucHVzaChuZXcgWChhLmssYS5wYXRoKSk7cmV0dXJue1dnOmUsdmc6Zn19O2Z1bmN0aW9uIG1pKGEpe3JldHVybiBOYShxYShhLnphKSxmdW5jdGlvbihhKXtyZXR1cm4hSGUoYS5ZLm4pfSl9aC5rYj1mdW5jdGlvbihhKXt2YXIgYj1udWxsO3YodGhpcy56YSxmdW5jdGlvbihjKXtiPWJ8fGMua2IoYSl9KTtyZXR1cm4gYn07XG5mdW5jdGlvbiBuaShhLGIpe2lmKEhlKGIubikpcmV0dXJuIGxpKGEpO3ZhciBjPWIud2EoKTtyZXR1cm4geihhLnphLGMpfWZ1bmN0aW9uIGxpKGEpe3JldHVybiB1YShhLnphLGZ1bmN0aW9uKGEpe3JldHVybiBIZShhLlkubil9KXx8bnVsbH07ZnVuY3Rpb24gb2koYSl7dGhpcy52YT1xZTt0aGlzLm1iPW5ldyBQZjt0aGlzLmRmPXt9O3RoaXMucWM9e307dGhpcy5RYz1hfWZ1bmN0aW9uIHBpKGEsYixjLGQsZSl7dmFyIGY9YS5tYixnPWU7TyhkPmYuUGMsXCJTdGFja2luZyBhbiBvbGRlciB3cml0ZSBvbiB0b3Agb2YgbmV3ZXIgb25lc1wiKTtwKGcpfHwoZz0hMCk7Zi5wYS5wdXNoKHtwYXRoOmIsSmE6YyxtZDpkLHZpc2libGU6Z30pO2cmJihmLlY9SmYoZi5WLGIsYykpO2YuUGM9ZDtyZXR1cm4gZT9xaShhLG5ldyBBYyhFZixiLGMpKTpbXX1mdW5jdGlvbiByaShhLGIsYyxkKXt2YXIgZT1hLm1iO08oZD5lLlBjLFwiU3RhY2tpbmcgYW4gb2xkZXIgbWVyZ2Ugb24gdG9wIG9mIG5ld2VyIG9uZXNcIik7ZS5wYS5wdXNoKHtwYXRoOmIsY2hpbGRyZW46YyxtZDpkLHZpc2libGU6ITB9KTtlLlY9S2YoZS5WLGIsYyk7ZS5QYz1kO2M9c2YoYyk7cmV0dXJuIHFpKGEsbmV3IGJmKEVmLGIsYykpfVxuZnVuY3Rpb24gc2koYSxiLGMpe2M9Y3x8ITE7dmFyIGQ9UWYoYS5tYixiKTtpZihhLm1iLlVkKGIpKXt2YXIgZT1xZTtudWxsIT1kLkphP2U9ZS5zZXQoTSwhMCk6RmIoZC5jaGlsZHJlbixmdW5jdGlvbihhLGIpe2U9ZS5zZXQobmV3IFAoYSksYil9KTtyZXR1cm4gcWkoYSxuZXcgRGYoZC5wYXRoLGUsYykpfXJldHVybltdfWZ1bmN0aW9uIHRpKGEsYixjKXtjPXNmKGMpO3JldHVybiBxaShhLG5ldyBiZihHZixiLGMpKX1mdW5jdGlvbiB1aShhLGIsYyxkKXtkPXZpKGEsZCk7aWYobnVsbCE9ZCl7dmFyIGU9d2koZCk7ZD1lLnBhdGg7ZT1lLkxiO2I9bGYoZCxiKTtjPW5ldyBBYyhuZXcgRmYoITEsITAsZSwhMCksYixjKTtyZXR1cm4geGkoYSxkLGMpfXJldHVybltdfVxuZnVuY3Rpb24geWkoYSxiLGMsZCl7aWYoZD12aShhLGQpKXt2YXIgZT13aShkKTtkPWUucGF0aDtlPWUuTGI7Yj1sZihkLGIpO2M9c2YoYyk7Yz1uZXcgYmYobmV3IEZmKCExLCEwLGUsITApLGIsYyk7cmV0dXJuIHhpKGEsZCxjKX1yZXR1cm5bXX1cbm9pLnByb3RvdHlwZS5UYj1mdW5jdGlvbihhLGIpe3ZhciBjPWEucGF0aCxkPW51bGwsZT0hMTt6Zih0aGlzLnZhLGMsZnVuY3Rpb24oYSxiKXt2YXIgZj1sZihhLGMpO2Q9ZHx8Yi5rYihmKTtlPWV8fG51bGwhPWxpKGIpfSk7dmFyIGY9dGhpcy52YS5nZXQoYyk7Zj8oZT1lfHxudWxsIT1saShmKSxkPWR8fGYua2IoTSkpOihmPW5ldyBraSx0aGlzLnZhPXRoaXMudmEuc2V0KGMsZikpO3ZhciBnO251bGwhPWQ/Zz0hMDooZz0hMSxkPUgsQ2YodGhpcy52YS5zdWJ0cmVlKGMpLGZ1bmN0aW9uKGEsYil7dmFyIGM9Yi5rYihNKTtjJiYoZD1kLlcoYSxjKSl9KSk7dmFyIGs9bnVsbCE9bmkoZixhKTtpZighayYmIUhlKGEubikpe3ZhciBtPXppKGEpO08oIShtIGluIHRoaXMucWMpLFwiVmlldyBkb2VzIG5vdCBleGlzdCwgYnV0IHdlIGhhdmUgYSB0YWdcIik7dmFyIGw9QWkrKzt0aGlzLnFjW21dPWw7dGhpcy5kZltcIl9cIitsXT1tfWc9Zi5UYihhLGIsbmV3IFVmKGMsdGhpcy5tYiksZCxnKTtcbmt8fGV8fChmPW5pKGYsYSksZz1nLmNvbmNhdChCaSh0aGlzLGEsZikpKTtyZXR1cm4gZ307XG5vaS5wcm90b3R5cGUubmI9ZnVuY3Rpb24oYSxiLGMpe3ZhciBkPWEucGF0aCxlPXRoaXMudmEuZ2V0KGQpLGY9W107aWYoZSYmKFwiZGVmYXVsdFwiPT09YS53YSgpfHxudWxsIT1uaShlLGEpKSl7Zj1lLm5iKGEsYixjKTtlLmUoKSYmKHRoaXMudmE9dGhpcy52YS5yZW1vdmUoZCkpO2U9Zi5XZztmPWYudmc7Yj0tMSE9PVNhKGUsZnVuY3Rpb24oYSl7cmV0dXJuIEhlKGEubil9KTt2YXIgZz14Zih0aGlzLnZhLGQsZnVuY3Rpb24oYSxiKXtyZXR1cm4gbnVsbCE9bGkoYil9KTtpZihiJiYhZyYmKGQ9dGhpcy52YS5zdWJ0cmVlKGQpLCFkLmUoKSkpZm9yKHZhciBkPUNpKGQpLGs9MDtrPGQubGVuZ3RoOysrayl7dmFyIG09ZFtrXSxsPW0uWSxtPURpKHRoaXMsbSk7dGhpcy5RYy5hZihFaShsKSxGaSh0aGlzLGwpLG0uQWQsbS5JKX1pZighZyYmMDxlLmxlbmd0aCYmIWMpaWYoYil0aGlzLlFjLmRlKEVpKGEpLG51bGwpO2Vsc2V7dmFyIHQ9dGhpcztNYShlLGZ1bmN0aW9uKGEpe2Eud2EoKTtcbnZhciBiPXQucWNbemkoYSldO3QuUWMuZGUoRWkoYSksYil9KX1HaSh0aGlzLGUpfXJldHVybiBmfTtvaS5wcm90b3R5cGUuQWE9ZnVuY3Rpb24oYSxiKXt2YXIgYz10aGlzLm1iLGQ9eGYodGhpcy52YSxhLGZ1bmN0aW9uKGIsYyl7dmFyIGQ9bGYoYixhKTtpZihkPWMua2IoZCkpcmV0dXJuIGR9KTtyZXR1cm4gYy5BYShhLGQsYiwhMCl9O2Z1bmN0aW9uIENpKGEpe3JldHVybiB2ZihhLGZ1bmN0aW9uKGEsYyxkKXtpZihjJiZudWxsIT1saShjKSlyZXR1cm5bbGkoYyldO3ZhciBlPVtdO2MmJihlPW1pKGMpKTt2KGQsZnVuY3Rpb24oYSl7ZT1lLmNvbmNhdChhKX0pO3JldHVybiBlfSl9ZnVuY3Rpb24gR2koYSxiKXtmb3IodmFyIGM9MDtjPGIubGVuZ3RoOysrYyl7dmFyIGQ9YltjXTtpZighSGUoZC5uKSl7dmFyIGQ9emkoZCksZT1hLnFjW2RdO2RlbGV0ZSBhLnFjW2RdO2RlbGV0ZSBhLmRmW1wiX1wiK2VdfX19XG5mdW5jdGlvbiBFaShhKXtyZXR1cm4gSGUoYS5uKSYmIUllKGEubik/YS5NYigpOmF9ZnVuY3Rpb24gQmkoYSxiLGMpe3ZhciBkPWIucGF0aCxlPUZpKGEsYik7Yz1EaShhLGMpO2I9YS5RYy5hZihFaShiKSxlLGMuQWQsYy5JKTtkPWEudmEuc3VidHJlZShkKTtpZihlKU8obnVsbD09bGkoZC52YWx1ZSksXCJJZiB3ZSdyZSBhZGRpbmcgYSBxdWVyeSwgaXQgc2hvdWxkbid0IGJlIHNoYWRvd2VkXCIpO2Vsc2UgZm9yKGU9dmYoZCxmdW5jdGlvbihhLGIsYyl7aWYoIWEuZSgpJiZiJiZudWxsIT1saShiKSlyZXR1cm5bWmUobGkoYikpXTt2YXIgZD1bXTtiJiYoZD1kLmNvbmNhdChPYShtaShiKSxmdW5jdGlvbihhKXtyZXR1cm4gYS5ZfSkpKTt2KGMsZnVuY3Rpb24oYSl7ZD1kLmNvbmNhdChhKX0pO3JldHVybiBkfSksZD0wO2Q8ZS5sZW5ndGg7KytkKWM9ZVtkXSxhLlFjLmRlKEVpKGMpLEZpKGEsYykpO3JldHVybiBifVxuZnVuY3Rpb24gRGkoYSxiKXt2YXIgYz1iLlksZD1GaShhLGMpO3JldHVybntBZDpmdW5jdGlvbigpe3JldHVybihiLncoKXx8SCkuaGFzaCgpfSxJOmZ1bmN0aW9uKGIpe2lmKFwib2tcIj09PWIpe2lmKGQpe3ZhciBmPWMucGF0aDtpZihiPXZpKGEsZCkpe3ZhciBnPXdpKGIpO2I9Zy5wYXRoO2c9Zy5MYjtmPWxmKGIsZik7Zj1uZXcgQ2MobmV3IEZmKCExLCEwLGcsITApLGYpO2I9eGkoYSxiLGYpfWVsc2UgYj1bXX1lbHNlIGI9cWkoYSxuZXcgQ2MoR2YsYy5wYXRoKSk7cmV0dXJuIGJ9Zj1cIlVua25vd24gRXJyb3JcIjtcInRvb19iaWdcIj09PWI/Zj1cIlRoZSBkYXRhIHJlcXVlc3RlZCBleGNlZWRzIHRoZSBtYXhpbXVtIHNpemUgdGhhdCBjYW4gYmUgYWNjZXNzZWQgd2l0aCBhIHNpbmdsZSByZXF1ZXN0LlwiOlwicGVybWlzc2lvbl9kZW5pZWRcIj09Yj9mPVwiQ2xpZW50IGRvZXNuJ3QgaGF2ZSBwZXJtaXNzaW9uIHRvIGFjY2VzcyB0aGUgZGVzaXJlZCBkYXRhLlwiOlwidW5hdmFpbGFibGVcIj09YiYmXG4oZj1cIlRoZSBzZXJ2aWNlIGlzIHVuYXZhaWxhYmxlXCIpO2Y9RXJyb3IoYitcIiBhdCBcIitjLnBhdGgudG9TdHJpbmcoKStcIjogXCIrZik7Zi5jb2RlPWIudG9VcHBlckNhc2UoKTtyZXR1cm4gYS5uYihjLG51bGwsZil9fX1mdW5jdGlvbiB6aShhKXtyZXR1cm4gYS5wYXRoLnRvU3RyaW5nKCkrXCIkXCIrYS53YSgpfWZ1bmN0aW9uIHdpKGEpe3ZhciBiPWEuaW5kZXhPZihcIiRcIik7TygtMSE9PWImJmI8YS5sZW5ndGgtMSxcIkJhZCBxdWVyeUtleS5cIik7cmV0dXJue0xiOmEuc3Vic3RyKGIrMSkscGF0aDpuZXcgUChhLnN1YnN0cigwLGIpKX19ZnVuY3Rpb24gdmkoYSxiKXt2YXIgYz1hLmRmLGQ9XCJfXCIrYjtyZXR1cm4gZCBpbiBjP2NbZF06dm9pZCAwfWZ1bmN0aW9uIEZpKGEsYil7dmFyIGM9emkoYik7cmV0dXJuIHooYS5xYyxjKX12YXIgQWk9MTtcbmZ1bmN0aW9uIHhpKGEsYixjKXt2YXIgZD1hLnZhLmdldChiKTtPKGQsXCJNaXNzaW5nIHN5bmMgcG9pbnQgZm9yIHF1ZXJ5IHRhZyB0aGF0IHdlJ3JlIHRyYWNraW5nXCIpO3JldHVybiBkLmdiKGMsbmV3IFVmKGIsYS5tYiksbnVsbCl9ZnVuY3Rpb24gcWkoYSxiKXtyZXR1cm4gSGkoYSxiLGEudmEsbnVsbCxuZXcgVWYoTSxhLm1iKSl9ZnVuY3Rpb24gSGkoYSxiLGMsZCxlKXtpZihiLnBhdGguZSgpKXJldHVybiBJaShhLGIsYyxkLGUpO3ZhciBmPWMuZ2V0KE0pO251bGw9PWQmJm51bGwhPWYmJihkPWYua2IoTSkpO3ZhciBnPVtdLGs9SyhiLnBhdGgpLG09Yi4kYyhrKTtpZigoYz1jLmNoaWxkcmVuLmdldChrKSkmJm0pdmFyIGw9ZD9kLlQoayk6bnVsbCxrPWUubyhrKSxnPWcuY29uY2F0KEhpKGEsbSxjLGwsaykpO2YmJihnPWcuY29uY2F0KGYuZ2IoYixlLGQpKSk7cmV0dXJuIGd9XG5mdW5jdGlvbiBJaShhLGIsYyxkLGUpe3ZhciBmPWMuZ2V0KE0pO251bGw9PWQmJm51bGwhPWYmJihkPWYua2IoTSkpO3ZhciBnPVtdO2MuY2hpbGRyZW4ua2EoZnVuY3Rpb24oYyxmKXt2YXIgbD1kP2QuVChjKTpudWxsLHQ9ZS5vKGMpLEE9Yi4kYyhjKTtBJiYoZz1nLmNvbmNhdChJaShhLEEsZixsLHQpKSl9KTtmJiYoZz1nLmNvbmNhdChmLmdiKGIsZSxkKSkpO3JldHVybiBnfTtmdW5jdGlvbiBKaShhLGIpe3RoaXMuRz1hO3RoaXMuWGE9dWMoYSk7dGhpcy5oZD1udWxsO3RoaXMuZmE9bmV3IFpiO3RoaXMuS2Q9MTt0aGlzLlZhPW51bGw7Ynx8MDw9KFwib2JqZWN0XCI9PT10eXBlb2Ygd2luZG93JiZ3aW5kb3cubmF2aWdhdG9yJiZ3aW5kb3cubmF2aWdhdG9yLnVzZXJBZ2VudHx8XCJcIikuc2VhcmNoKC9nb29nbGVib3R8Z29vZ2xlIHdlYm1hc3RlciB0b29sc3xiaW5nYm90fHlhaG9vISBzbHVycHxiYWlkdXNwaWRlcnx5YW5kZXhib3R8ZHVja2R1Y2tib3QvaSk/KHRoaXMuZGE9bmV3IGNmKHRoaXMuRyx1KHRoaXMuS2IsdGhpcykpLHNldFRpbWVvdXQodSh0aGlzLlhjLHRoaXMsITApLDApKTp0aGlzLmRhPXRoaXMuVmE9bmV3IFJoKHRoaXMuRyx1KHRoaXMuS2IsdGhpcyksdSh0aGlzLlhjLHRoaXMpLHUodGhpcy5TZSx0aGlzKSk7dGhpcy5laD12YyhhLHUoZnVuY3Rpb24oKXtyZXR1cm4gbmV3IHBjKHRoaXMuWGEsdGhpcy5kYSl9LHRoaXMpKTt0aGlzLnljPW5ldyBXZjtcbnRoaXMuR2U9bmV3IFNiO3ZhciBjPXRoaXM7dGhpcy5GZD1uZXcgb2koe2FmOmZ1bmN0aW9uKGEsYixmLGcpe2I9W107Zj1jLkdlLmooYS5wYXRoKTtmLmUoKXx8KGI9cWkoYy5GZCxuZXcgQWMoR2YsYS5wYXRoLGYpKSxzZXRUaW1lb3V0KGZ1bmN0aW9uKCl7ZyhcIm9rXCIpfSwwKSk7cmV0dXJuIGJ9LGRlOmFhfSk7S2kodGhpcyxcImNvbm5lY3RlZFwiLCExKTt0aGlzLm5hPW5ldyBWYzt0aGlzLk89bmV3IFlnKGEsdSh0aGlzLmRhLk8sdGhpcy5kYSksdSh0aGlzLmRhLmplLHRoaXMuZGEpLHUodGhpcy5QZSx0aGlzKSk7dGhpcy51ZD0wO3RoaXMuSGU9bnVsbDt0aGlzLk09bmV3IG9pKHthZjpmdW5jdGlvbihhLGIsZixnKXtjLmRhLkNmKGEsZixiLGZ1bmN0aW9uKGIsZSl7dmFyIGY9ZyhiLGUpO2RjKGMuZmEsYS5wYXRoLGYpfSk7cmV0dXJuW119LGRlOmZ1bmN0aW9uKGEsYil7Yy5kYS4kZihhLGIpfX0pfWg9SmkucHJvdG90eXBlO1xuaC50b1N0cmluZz1mdW5jdGlvbigpe3JldHVybih0aGlzLkcub2I/XCJodHRwczovL1wiOlwiaHR0cDovL1wiKSt0aGlzLkcuaG9zdH07aC5uYW1lPWZ1bmN0aW9uKCl7cmV0dXJuIHRoaXMuRy5sY307ZnVuY3Rpb24gTGkoYSl7YT1hLkdlLmoobmV3IFAoXCIuaW5mby9zZXJ2ZXJUaW1lT2Zmc2V0XCIpKS5KKCl8fDA7cmV0dXJuKG5ldyBEYXRlKS5nZXRUaW1lKCkrYX1mdW5jdGlvbiBNaShhKXthPWE9e3RpbWVzdGFtcDpMaShhKX07YS50aW1lc3RhbXA9YS50aW1lc3RhbXB8fChuZXcgRGF0ZSkuZ2V0VGltZSgpO3JldHVybiBhfVxuaC5LYj1mdW5jdGlvbihhLGIsYyxkKXt0aGlzLnVkKys7dmFyIGU9bmV3IFAoYSk7Yj10aGlzLkhlP3RoaXMuSGUoYSxiKTpiO2E9W107ZD9jPyhiPW1hKGIsZnVuY3Rpb24oYSl7cmV0dXJuIFEoYSl9KSxhPXlpKHRoaXMuTSxlLGIsZCkpOihiPVEoYiksYT11aSh0aGlzLk0sZSxiLGQpKTpjPyhkPW1hKGIsZnVuY3Rpb24oYSl7cmV0dXJuIFEoYSl9KSxhPXRpKHRoaXMuTSxlLGQpKTooZD1RKGIpLGE9cWkodGhpcy5NLG5ldyBBYyhHZixlLGQpKSk7ZD1lOzA8YS5sZW5ndGgmJihkPU5pKHRoaXMsZSkpO2RjKHRoaXMuZmEsZCxhKX07aC5YYz1mdW5jdGlvbihhKXtLaSh0aGlzLFwiY29ubmVjdGVkXCIsYSk7ITE9PT1hJiZPaSh0aGlzKX07aC5TZT1mdW5jdGlvbihhKXt2YXIgYj10aGlzO3pkKGEsZnVuY3Rpb24oYSxkKXtLaShiLGQsYSl9KX07aC5QZT1mdW5jdGlvbihhKXtLaSh0aGlzLFwiYXV0aGVudGljYXRlZFwiLGEpfTtcbmZ1bmN0aW9uIEtpKGEsYixjKXtiPW5ldyBQKFwiLy5pbmZvL1wiK2IpO2M9UShjKTt2YXIgZD1hLkdlO2QuWmQ9ZC5aZC5IKGIsYyk7Yz1xaShhLkZkLG5ldyBBYyhHZixiLGMpKTtkYyhhLmZhLGIsYyl9aC5PYj1mdW5jdGlvbihhLGIsYyxkKXt0aGlzLmYoXCJzZXRcIix7cGF0aDphLnRvU3RyaW5nKCksdmFsdWU6YixuaDpjfSk7dmFyIGU9TWkodGhpcyk7Yj1RKGIsYyk7dmFyIGU9WGMoYixlKSxmPXRoaXMuS2QrKyxlPXBpKHRoaXMuTSxhLGUsZiwhMCk7JGIodGhpcy5mYSxlKTt2YXIgZz10aGlzO3RoaXMuZGEucHV0KGEudG9TdHJpbmcoKSxiLkooITApLGZ1bmN0aW9uKGIsYyl7dmFyIGU9XCJva1wiPT09YjtlfHxTKFwic2V0IGF0IFwiK2ErXCIgZmFpbGVkOiBcIitiKTtlPXNpKGcuTSxmLCFlKTtkYyhnLmZhLGEsZSk7UGkoZCxiLGMpfSk7ZT1RaSh0aGlzLGEpO05pKHRoaXMsZSk7ZGModGhpcy5mYSxlLFtdKX07XG5oLnVwZGF0ZT1mdW5jdGlvbihhLGIsYyl7dGhpcy5mKFwidXBkYXRlXCIse3BhdGg6YS50b1N0cmluZygpLHZhbHVlOmJ9KTt2YXIgZD0hMCxlPU1pKHRoaXMpLGY9e307dihiLGZ1bmN0aW9uKGEsYil7ZD0hMTt2YXIgYz1RKGEpO2ZbYl09WGMoYyxlKX0pO2lmKGQpZmMoXCJ1cGRhdGUoKSBjYWxsZWQgd2l0aCBlbXB0eSBkYXRhLiAgRG9uJ3QgZG8gYW55dGhpbmcuXCIpLFBpKGMsXCJva1wiKTtlbHNle3ZhciBnPXRoaXMuS2QrKyxrPXJpKHRoaXMuTSxhLGYsZyk7JGIodGhpcy5mYSxrKTt2YXIgbT10aGlzO3RoaXMuZGEuRGYoYS50b1N0cmluZygpLGIsZnVuY3Rpb24oYixkKXt2YXIgZT1cIm9rXCI9PT1iO2V8fFMoXCJ1cGRhdGUgYXQgXCIrYStcIiBmYWlsZWQ6IFwiK2IpO3ZhciBlPXNpKG0uTSxnLCFlKSxmPWE7MDxlLmxlbmd0aCYmKGY9TmkobSxhKSk7ZGMobS5mYSxmLGUpO1BpKGMsYixkKX0pO2I9UWkodGhpcyxhKTtOaSh0aGlzLGIpO2RjKHRoaXMuZmEsYSxbXSl9fTtcbmZ1bmN0aW9uIE9pKGEpe2EuZihcIm9uRGlzY29ubmVjdEV2ZW50c1wiKTt2YXIgYj1NaShhKSxjPVtdO1djKFVjKGEubmEsYiksTSxmdW5jdGlvbihiLGUpe2M9Yy5jb25jYXQocWkoYS5NLG5ldyBBYyhHZixiLGUpKSk7dmFyIGY9UWkoYSxiKTtOaShhLGYpfSk7YS5uYT1uZXcgVmM7ZGMoYS5mYSxNLGMpfWguTWQ9ZnVuY3Rpb24oYSxiKXt2YXIgYz10aGlzO3RoaXMuZGEuTWQoYS50b1N0cmluZygpLGZ1bmN0aW9uKGQsZSl7XCJva1wiPT09ZCYmd2coYy5uYSxhKTtQaShiLGQsZSl9KX07ZnVuY3Rpb24gZmkoYSxiLGMsZCl7dmFyIGU9UShjKTthLmRhLlFlKGIudG9TdHJpbmcoKSxlLkooITApLGZ1bmN0aW9uKGMsZyl7XCJva1wiPT09YyYmYS5uYS5yYyhiLGUpO1BpKGQsYyxnKX0pfWZ1bmN0aW9uIGdpKGEsYixjLGQsZSl7dmFyIGY9UShjLGQpO2EuZGEuUWUoYi50b1N0cmluZygpLGYuSighMCksZnVuY3Rpb24oYyxkKXtcIm9rXCI9PT1jJiZhLm5hLnJjKGIsZik7UGkoZSxjLGQpfSl9XG5mdW5jdGlvbiBoaShhLGIsYyxkKXt2YXIgZT0hMCxmO2ZvcihmIGluIGMpZT0hMTtlPyhmYyhcIm9uRGlzY29ubmVjdCgpLnVwZGF0ZSgpIGNhbGxlZCB3aXRoIGVtcHR5IGRhdGEuICBEb24ndCBkbyBhbnl0aGluZy5cIiksUGkoZCxcIm9rXCIpKTphLmRhLkdmKGIudG9TdHJpbmcoKSxjLGZ1bmN0aW9uKGUsZil7aWYoXCJva1wiPT09ZSlmb3IodmFyIG0gaW4gYyl7dmFyIGw9UShjW21dKTthLm5hLnJjKGIubyhtKSxsKX1QaShkLGUsZil9KX1mdW5jdGlvbiBSaShhLGIsYyl7Yz1cIi5pbmZvXCI9PT1LKGIucGF0aCk/YS5GZC5UYihiLGMpOmEuTS5UYihiLGMpO2JjKGEuZmEsYi5wYXRoLGMpfWguQ2I9ZnVuY3Rpb24oKXt0aGlzLlZhJiZ0aGlzLlZhLkNiKCl9O2gudmM9ZnVuY3Rpb24oKXt0aGlzLlZhJiZ0aGlzLlZhLnZjKCl9O1xuaC5iZj1mdW5jdGlvbihhKXtpZihcInVuZGVmaW5lZFwiIT09dHlwZW9mIGNvbnNvbGUpe2E/KHRoaXMuaGR8fCh0aGlzLmhkPW5ldyBvYyh0aGlzLlhhKSksYT10aGlzLmhkLmdldCgpKTphPXRoaXMuWGEuZ2V0KCk7dmFyIGI9UGEocmEoYSksZnVuY3Rpb24oYSxiKXtyZXR1cm4gTWF0aC5tYXgoYi5sZW5ndGgsYSl9LDApLGM7Zm9yKGMgaW4gYSl7Zm9yKHZhciBkPWFbY10sZT1jLmxlbmd0aDtlPGIrMjtlKyspYys9XCIgXCI7Y29uc29sZS5sb2coYytkKX19fTtoLmNmPWZ1bmN0aW9uKGEpe3JjKHRoaXMuWGEsYSk7dGhpcy5laC5WZlthXT0hMH07aC5mPWZ1bmN0aW9uKGEpe3ZhciBiPVwiXCI7dGhpcy5WYSYmKGI9dGhpcy5WYS5pZCtcIjpcIik7ZmMoYixhcmd1bWVudHMpfTtcbmZ1bmN0aW9uIFBpKGEsYixjKXthJiZnYyhmdW5jdGlvbigpe2lmKFwib2tcIj09YilhKG51bGwpO2Vsc2V7dmFyIGQ9KGJ8fFwiZXJyb3JcIikudG9VcHBlckNhc2UoKSxlPWQ7YyYmKGUrPVwiOiBcIitjKTtlPUVycm9yKGUpO2UuY29kZT1kO2EoZSl9fSl9O2Z1bmN0aW9uIFNpKGEsYixjLGQsZSl7ZnVuY3Rpb24gZigpe31hLmYoXCJ0cmFuc2FjdGlvbiBvbiBcIitiKTt2YXIgZz1uZXcgWChhLGIpO2cuSWIoXCJ2YWx1ZVwiLGYpO2M9e3BhdGg6Yix1cGRhdGU6YyxJOmQsc3RhdHVzOm51bGwsTGY6aWQoKSxnZjplLFNmOjAsbGU6ZnVuY3Rpb24oKXtnLm1jKFwidmFsdWVcIixmKX0sbmU6bnVsbCxEYTpudWxsLHJkOm51bGwsc2Q6bnVsbCx0ZDpudWxsfTtkPWEuTS5BYShiLHZvaWQgMCl8fEg7Yy5yZD1kO2Q9Yy51cGRhdGUoZC5KKCkpO2lmKHAoZCkpe2hnKFwidHJhbnNhY3Rpb24gZmFpbGVkOiBEYXRhIHJldHVybmVkIFwiLGQsYy5wYXRoKTtjLnN0YXR1cz0xO2U9WGYoYS55YyxiKTt2YXIgaz1lLkVhKCl8fFtdO2sucHVzaChjKTtZZihlLGspO1wib2JqZWN0XCI9PT10eXBlb2YgZCYmbnVsbCE9PWQmJnkoZCxcIi5wcmlvcml0eVwiKT8oaz16KGQsXCIucHJpb3JpdHlcIiksTyhmZyhrKSxcIkludmFsaWQgcHJpb3JpdHkgcmV0dXJuZWQgYnkgdHJhbnNhY3Rpb24uIFByaW9yaXR5IG11c3QgYmUgYSB2YWxpZCBzdHJpbmcsIGZpbml0ZSBudW1iZXIsIHNlcnZlciB2YWx1ZSwgb3IgbnVsbC5cIikpOlxuaz0oYS5NLkFhKGIpfHxIKS5DKCkuSigpO2U9TWkoYSk7ZD1RKGQsayk7ZT1YYyhkLGUpO2Muc2Q9ZDtjLnRkPWU7Yy5EYT1hLktkKys7Yz1waShhLk0sYixlLGMuRGEsYy5nZik7ZGMoYS5mYSxiLGMpO1RpKGEpfWVsc2UgYy5sZSgpLGMuc2Q9bnVsbCxjLnRkPW51bGwsYy5JJiYoYT1uZXcgVyhjLnJkLG5ldyBYKGEsYy5wYXRoKSxSKSxjLkkobnVsbCwhMSxhKSl9ZnVuY3Rpb24gVGkoYSxiKXt2YXIgYz1ifHxhLnljO2J8fFVpKGEsYyk7aWYobnVsbCE9PWMuRWEoKSl7dmFyIGQ9VmkoYSxjKTtPKDA8ZC5sZW5ndGgsXCJTZW5kaW5nIHplcm8gbGVuZ3RoIHRyYW5zYWN0aW9uIHF1ZXVlXCIpO1FhKGQsZnVuY3Rpb24oYSl7cmV0dXJuIDE9PT1hLnN0YXR1c30pJiZXaShhLGMucGF0aCgpLGQpfWVsc2UgYy56ZCgpJiZjLlIoZnVuY3Rpb24oYil7VGkoYSxiKX0pfVxuZnVuY3Rpb24gV2koYSxiLGMpe2Zvcih2YXIgZD1PYShjLGZ1bmN0aW9uKGEpe3JldHVybiBhLkRhfSksZT1hLk0uQWEoYixkKXx8SCxkPWUsZT1lLmhhc2goKSxmPTA7ZjxjLmxlbmd0aDtmKyspe3ZhciBnPWNbZl07TygxPT09Zy5zdGF0dXMsXCJ0cnlUb1NlbmRUcmFuc2FjdGlvblF1ZXVlXzogaXRlbXMgaW4gcXVldWUgc2hvdWxkIGFsbCBiZSBydW4uXCIpO2cuc3RhdHVzPTI7Zy5TZisrO3ZhciBrPWxmKGIsZy5wYXRoKSxkPWQuSChrLGcuc2QpfWQ9ZC5KKCEwKTthLmRhLnB1dChiLnRvU3RyaW5nKCksZCxmdW5jdGlvbihkKXthLmYoXCJ0cmFuc2FjdGlvbiBwdXQgcmVzcG9uc2VcIix7cGF0aDpiLnRvU3RyaW5nKCksc3RhdHVzOmR9KTt2YXIgZT1bXTtpZihcIm9rXCI9PT1kKXtkPVtdO2ZvcihmPTA7ZjxjLmxlbmd0aDtmKyspe2NbZl0uc3RhdHVzPTM7ZT1lLmNvbmNhdChzaShhLk0sY1tmXS5EYSkpO2lmKGNbZl0uSSl7dmFyIGc9Y1tmXS50ZCxrPW5ldyBYKGEsY1tmXS5wYXRoKTtkLnB1c2godShjW2ZdLkksXG5udWxsLG51bGwsITAsbmV3IFcoZyxrLFIpKSl9Y1tmXS5sZSgpfVVpKGEsWGYoYS55YyxiKSk7VGkoYSk7ZGMoYS5mYSxiLGUpO2ZvcihmPTA7ZjxkLmxlbmd0aDtmKyspZ2MoZFtmXSl9ZWxzZXtpZihcImRhdGFzdGFsZVwiPT09ZClmb3IoZj0wO2Y8Yy5sZW5ndGg7ZisrKWNbZl0uc3RhdHVzPTQ9PT1jW2ZdLnN0YXR1cz81OjE7ZWxzZSBmb3IoUyhcInRyYW5zYWN0aW9uIGF0IFwiK2IudG9TdHJpbmcoKStcIiBmYWlsZWQ6IFwiK2QpLGY9MDtmPGMubGVuZ3RoO2YrKyljW2ZdLnN0YXR1cz01LGNbZl0ubmU9ZDtOaShhLGIpfX0sZSl9ZnVuY3Rpb24gTmkoYSxiKXt2YXIgYz1YaShhLGIpLGQ9Yy5wYXRoKCksYz1WaShhLGMpO1lpKGEsYyxkKTtyZXR1cm4gZH1cbmZ1bmN0aW9uIFlpKGEsYixjKXtpZigwIT09Yi5sZW5ndGgpe2Zvcih2YXIgZD1bXSxlPVtdLGY9TmEoYixmdW5jdGlvbihhKXtyZXR1cm4gMT09PWEuc3RhdHVzfSksZj1PYShmLGZ1bmN0aW9uKGEpe3JldHVybiBhLkRhfSksZz0wO2c8Yi5sZW5ndGg7ZysrKXt2YXIgaz1iW2ddLG09bGYoYyxrLnBhdGgpLGw9ITEsdDtPKG51bGwhPT1tLFwicmVydW5UcmFuc2FjdGlvbnNVbmRlck5vZGVfOiByZWxhdGl2ZVBhdGggc2hvdWxkIG5vdCBiZSBudWxsLlwiKTtpZig1PT09ay5zdGF0dXMpbD0hMCx0PWsubmUsZT1lLmNvbmNhdChzaShhLk0say5EYSwhMCkpO2Vsc2UgaWYoMT09PWsuc3RhdHVzKWlmKDI1PD1rLlNmKWw9ITAsdD1cIm1heHJldHJ5XCIsZT1lLmNvbmNhdChzaShhLk0say5EYSwhMCkpO2Vsc2V7dmFyIEE9YS5NLkFhKGsucGF0aCxmKXx8SDtrLnJkPUE7dmFyIEk9YltnXS51cGRhdGUoQS5KKCkpO3AoSSk/KGhnKFwidHJhbnNhY3Rpb24gZmFpbGVkOiBEYXRhIHJldHVybmVkIFwiLFxuSSxrLnBhdGgpLG09UShJKSxcIm9iamVjdFwiPT09dHlwZW9mIEkmJm51bGwhPUkmJnkoSSxcIi5wcmlvcml0eVwiKXx8KG09bS5pYShBLkMoKSkpLEE9ay5EYSxJPU1pKGEpLEk9WGMobSxJKSxrLnNkPW0say50ZD1JLGsuRGE9YS5LZCsrLFRhKGYsQSksZT1lLmNvbmNhdChwaShhLk0say5wYXRoLEksay5EYSxrLmdmKSksZT1lLmNvbmNhdChzaShhLk0sQSwhMCkpKToobD0hMCx0PVwibm9kYXRhXCIsZT1lLmNvbmNhdChzaShhLk0say5EYSwhMCkpKX1kYyhhLmZhLGMsZSk7ZT1bXTtsJiYoYltnXS5zdGF0dXM9MyxzZXRUaW1lb3V0KGJbZ10ubGUsTWF0aC5mbG9vcigwKSksYltnXS5JJiYoXCJub2RhdGFcIj09PXQ/KGs9bmV3IFgoYSxiW2ddLnBhdGgpLGQucHVzaCh1KGJbZ10uSSxudWxsLG51bGwsITEsbmV3IFcoYltnXS5yZCxrLFIpKSkpOmQucHVzaCh1KGJbZ10uSSxudWxsLEVycm9yKHQpLCExLG51bGwpKSkpfVVpKGEsYS55Yyk7Zm9yKGc9MDtnPGQubGVuZ3RoO2crKylnYyhkW2ddKTtcblRpKGEpfX1mdW5jdGlvbiBYaShhLGIpe2Zvcih2YXIgYyxkPWEueWM7bnVsbCE9PShjPUsoYikpJiZudWxsPT09ZC5FYSgpOylkPVhmKGQsYyksYj1OKGIpO3JldHVybiBkfWZ1bmN0aW9uIFZpKGEsYil7dmFyIGM9W107WmkoYSxiLGMpO2Muc29ydChmdW5jdGlvbihhLGIpe3JldHVybiBhLkxmLWIuTGZ9KTtyZXR1cm4gY31mdW5jdGlvbiBaaShhLGIsYyl7dmFyIGQ9Yi5FYSgpO2lmKG51bGwhPT1kKWZvcih2YXIgZT0wO2U8ZC5sZW5ndGg7ZSsrKWMucHVzaChkW2VdKTtiLlIoZnVuY3Rpb24oYil7WmkoYSxiLGMpfSl9ZnVuY3Rpb24gVWkoYSxiKXt2YXIgYz1iLkVhKCk7aWYoYyl7Zm9yKHZhciBkPTAsZT0wO2U8Yy5sZW5ndGg7ZSsrKTMhPT1jW2VdLnN0YXR1cyYmKGNbZF09Y1tlXSxkKyspO2MubGVuZ3RoPWQ7WWYoYiwwPGMubGVuZ3RoP2M6bnVsbCl9Yi5SKGZ1bmN0aW9uKGIpe1VpKGEsYil9KX1cbmZ1bmN0aW9uIFFpKGEsYil7dmFyIGM9WGkoYSxiKS5wYXRoKCksZD1YZihhLnljLGIpO2FnKGQsZnVuY3Rpb24oYil7JGkoYSxiKX0pOyRpKGEsZCk7JGYoZCxmdW5jdGlvbihiKXskaShhLGIpfSk7cmV0dXJuIGN9XG5mdW5jdGlvbiAkaShhLGIpe3ZhciBjPWIuRWEoKTtpZihudWxsIT09Yyl7Zm9yKHZhciBkPVtdLGU9W10sZj0tMSxnPTA7ZzxjLmxlbmd0aDtnKyspNCE9PWNbZ10uc3RhdHVzJiYoMj09PWNbZ10uc3RhdHVzPyhPKGY9PT1nLTEsXCJBbGwgU0VOVCBpdGVtcyBzaG91bGQgYmUgYXQgYmVnaW5uaW5nIG9mIHF1ZXVlLlwiKSxmPWcsY1tnXS5zdGF0dXM9NCxjW2ddLm5lPVwic2V0XCIpOihPKDE9PT1jW2ddLnN0YXR1cyxcIlVuZXhwZWN0ZWQgdHJhbnNhY3Rpb24gc3RhdHVzIGluIGFib3J0XCIpLGNbZ10ubGUoKSxlPWUuY29uY2F0KHNpKGEuTSxjW2ddLkRhLCEwKSksY1tnXS5JJiZkLnB1c2godShjW2ddLkksbnVsbCxFcnJvcihcInNldFwiKSwhMSxudWxsKSkpKTstMT09PWY/WWYoYixudWxsKTpjLmxlbmd0aD1mKzE7ZGMoYS5mYSxiLnBhdGgoKSxlKTtmb3IoZz0wO2c8ZC5sZW5ndGg7ZysrKWdjKGRbZ10pfX07ZnVuY3Rpb24gYWooKXt0aGlzLnNjPXt9O3RoaXMuYWc9ITF9YWoucHJvdG90eXBlLkNiPWZ1bmN0aW9uKCl7Zm9yKHZhciBhIGluIHRoaXMuc2MpdGhpcy5zY1thXS5DYigpfTthai5wcm90b3R5cGUudmM9ZnVuY3Rpb24oKXtmb3IodmFyIGEgaW4gdGhpcy5zYyl0aGlzLnNjW2FdLnZjKCl9O2FqLnByb3RvdHlwZS56ZT1mdW5jdGlvbigpe3RoaXMuYWc9ITB9O2JhKGFqKTthai5wcm90b3R5cGUuaW50ZXJydXB0PWFqLnByb3RvdHlwZS5DYjthai5wcm90b3R5cGUucmVzdW1lPWFqLnByb3RvdHlwZS52YztmdW5jdGlvbiBZKGEsYixjLGQpe3RoaXMuaz1hO3RoaXMucGF0aD1iO3RoaXMubj1jO3RoaXMucGM9ZH1cbmZ1bmN0aW9uIGJqKGEpe3ZhciBiPW51bGwsYz1udWxsO2Eub2EmJihiPU9kKGEpKTthLnJhJiYoYz1SZChhKSk7aWYoYS5nPT09cmUpe2lmKGEub2Epe2lmKFwiW01JTl9OQU1FXVwiIT1OZChhKSl0aHJvdyBFcnJvcihcIlF1ZXJ5OiBXaGVuIG9yZGVyaW5nIGJ5IGtleSwgeW91IG1heSBvbmx5IHBhc3Mgb25lIGFyZ3VtZW50IHRvIHN0YXJ0QXQoKSwgZW5kQXQoKSwgb3IgZXF1YWxUbygpLlwiKTtpZihcInN0cmluZ1wiIT09dHlwZW9mIGIpdGhyb3cgRXJyb3IoXCJRdWVyeTogV2hlbiBvcmRlcmluZyBieSBrZXksIHRoZSBhcmd1bWVudCBwYXNzZWQgdG8gc3RhcnRBdCgpLCBlbmRBdCgpLG9yIGVxdWFsVG8oKSBtdXN0IGJlIGEgc3RyaW5nLlwiKTt9aWYoYS5yYSl7aWYoXCJbTUFYX05BTUVdXCIhPVBkKGEpKXRocm93IEVycm9yKFwiUXVlcnk6IFdoZW4gb3JkZXJpbmcgYnkga2V5LCB5b3UgbWF5IG9ubHkgcGFzcyBvbmUgYXJndW1lbnQgdG8gc3RhcnRBdCgpLCBlbmRBdCgpLCBvciBlcXVhbFRvKCkuXCIpO2lmKFwic3RyaW5nXCIhPT1cbnR5cGVvZiBjKXRocm93IEVycm9yKFwiUXVlcnk6IFdoZW4gb3JkZXJpbmcgYnkga2V5LCB0aGUgYXJndW1lbnQgcGFzc2VkIHRvIHN0YXJ0QXQoKSwgZW5kQXQoKSxvciBlcXVhbFRvKCkgbXVzdCBiZSBhIHN0cmluZy5cIik7fX1lbHNlIGlmKGEuZz09PVIpe2lmKG51bGwhPWImJiFmZyhiKXx8bnVsbCE9YyYmIWZnKGMpKXRocm93IEVycm9yKFwiUXVlcnk6IFdoZW4gb3JkZXJpbmcgYnkgcHJpb3JpdHksIHRoZSBmaXJzdCBhcmd1bWVudCBwYXNzZWQgdG8gc3RhcnRBdCgpLCBlbmRBdCgpLCBvciBlcXVhbFRvKCkgbXVzdCBiZSBhIHZhbGlkIHByaW9yaXR5IHZhbHVlIChudWxsLCBhIG51bWJlciwgb3IgYSBzdHJpbmcpLlwiKTt9ZWxzZSBpZihPKGEuZyBpbnN0YW5jZW9mIHZlfHxhLmc9PT1CZSxcInVua25vd24gaW5kZXggdHlwZS5cIiksbnVsbCE9YiYmXCJvYmplY3RcIj09PXR5cGVvZiBifHxudWxsIT1jJiZcIm9iamVjdFwiPT09dHlwZW9mIGMpdGhyb3cgRXJyb3IoXCJRdWVyeTogRmlyc3QgYXJndW1lbnQgcGFzc2VkIHRvIHN0YXJ0QXQoKSwgZW5kQXQoKSwgb3IgZXF1YWxUbygpIGNhbm5vdCBiZSBhbiBvYmplY3QuXCIpO1xufWZ1bmN0aW9uIGNqKGEpe2lmKGEub2EmJmEucmEmJmEubGEmJighYS5sYXx8XCJcIj09PWEuUmIpKXRocm93IEVycm9yKFwiUXVlcnk6IENhbid0IGNvbWJpbmUgc3RhcnRBdCgpLCBlbmRBdCgpLCBhbmQgbGltaXQoKS4gVXNlIGxpbWl0VG9GaXJzdCgpIG9yIGxpbWl0VG9MYXN0KCkgaW5zdGVhZC5cIik7fWZ1bmN0aW9uIGRqKGEsYil7aWYoITA9PT1hLnBjKXRocm93IEVycm9yKGIrXCI6IFlvdSBjYW4ndCBjb21iaW5lIG11bHRpcGxlIG9yZGVyQnkgY2FsbHMuXCIpO31oPVkucHJvdG90eXBlO2guTWI9ZnVuY3Rpb24oKXtEKFwiUXVlcnkucmVmXCIsMCwwLGFyZ3VtZW50cy5sZW5ndGgpO3JldHVybiBuZXcgWCh0aGlzLmssdGhpcy5wYXRoKX07XG5oLkliPWZ1bmN0aW9uKGEsYixjLGQpe0QoXCJRdWVyeS5vblwiLDIsNCxhcmd1bWVudHMubGVuZ3RoKTtsZyhcIlF1ZXJ5Lm9uXCIsYSwhMSk7RihcIlF1ZXJ5Lm9uXCIsMixiLCExKTt2YXIgZT1laihcIlF1ZXJ5Lm9uXCIsYyxkKTtpZihcInZhbHVlXCI9PT1hKVJpKHRoaXMuayx0aGlzLG5ldyBpaShiLGUuY2FuY2VsfHxudWxsLGUuUWF8fG51bGwpKTtlbHNle3ZhciBmPXt9O2ZbYV09YjtSaSh0aGlzLmssdGhpcyxuZXcgamkoZixlLmNhbmNlbCxlLlFhKSl9cmV0dXJuIGJ9O1xuaC5tYz1mdW5jdGlvbihhLGIsYyl7RChcIlF1ZXJ5Lm9mZlwiLDAsMyxhcmd1bWVudHMubGVuZ3RoKTtsZyhcIlF1ZXJ5Lm9mZlwiLGEsITApO0YoXCJRdWVyeS5vZmZcIiwyLGIsITApO1FiKFwiUXVlcnkub2ZmXCIsMyxjKTt2YXIgZD1udWxsLGU9bnVsbDtcInZhbHVlXCI9PT1hP2Q9bmV3IGlpKGJ8fG51bGwsbnVsbCxjfHxudWxsKTphJiYoYiYmKGU9e30sZVthXT1iKSxkPW5ldyBqaShlLG51bGwsY3x8bnVsbCkpO2U9dGhpcy5rO2Q9XCIuaW5mb1wiPT09Syh0aGlzLnBhdGgpP2UuRmQubmIodGhpcyxkKTplLk0ubmIodGhpcyxkKTtiYyhlLmZhLHRoaXMucGF0aCxkKX07XG5oLlBnPWZ1bmN0aW9uKGEsYil7ZnVuY3Rpb24gYyhrKXtmJiYoZj0hMSxlLm1jKGEsYyksYiYmYi5jYWxsKGQuUWEsayksZy5yZXNvbHZlKGspKX1EKFwiUXVlcnkub25jZVwiLDEsNCxhcmd1bWVudHMubGVuZ3RoKTtsZyhcIlF1ZXJ5Lm9uY2VcIixhLCExKTtGKFwiUXVlcnkub25jZVwiLDIsYiwhMCk7dmFyIGQ9ZWooXCJRdWVyeS5vbmNlXCIsYXJndW1lbnRzWzJdLGFyZ3VtZW50c1szXSksZT10aGlzLGY9ITAsZz1uZXcgQjtOYihnLkQpO3RoaXMuSWIoYSxjLGZ1bmN0aW9uKGIpe2UubWMoYSxjKTtkLmNhbmNlbCYmZC5jYW5jZWwuY2FsbChkLlFhLGIpO2cucmVqZWN0KGIpfSk7cmV0dXJuIGcuRH07XG5oLkxlPWZ1bmN0aW9uKGEpe1MoXCJRdWVyeS5saW1pdCgpIGJlaW5nIGRlcHJlY2F0ZWQuIFBsZWFzZSB1c2UgUXVlcnkubGltaXRUb0ZpcnN0KCkgb3IgUXVlcnkubGltaXRUb0xhc3QoKSBpbnN0ZWFkLlwiKTtEKFwiUXVlcnkubGltaXRcIiwxLDEsYXJndW1lbnRzLmxlbmd0aCk7aWYoIWZhKGEpfHxNYXRoLmZsb29yKGEpIT09YXx8MD49YSl0aHJvdyBFcnJvcihcIlF1ZXJ5LmxpbWl0OiBGaXJzdCBhcmd1bWVudCBtdXN0IGJlIGEgcG9zaXRpdmUgaW50ZWdlci5cIik7aWYodGhpcy5uLmxhKXRocm93IEVycm9yKFwiUXVlcnkubGltaXQ6IExpbWl0IHdhcyBhbHJlYWR5IHNldCAoYnkgYW5vdGhlciBjYWxsIHRvIGxpbWl0LCBsaW1pdFRvRmlyc3QsIG9ybGltaXRUb0xhc3QuXCIpO3ZhciBiPXRoaXMubi5MZShhKTtjaihiKTtyZXR1cm4gbmV3IFkodGhpcy5rLHRoaXMucGF0aCxiLHRoaXMucGMpfTtcbmguTWU9ZnVuY3Rpb24oYSl7RChcIlF1ZXJ5LmxpbWl0VG9GaXJzdFwiLDEsMSxhcmd1bWVudHMubGVuZ3RoKTtpZighZmEoYSl8fE1hdGguZmxvb3IoYSkhPT1hfHwwPj1hKXRocm93IEVycm9yKFwiUXVlcnkubGltaXRUb0ZpcnN0OiBGaXJzdCBhcmd1bWVudCBtdXN0IGJlIGEgcG9zaXRpdmUgaW50ZWdlci5cIik7aWYodGhpcy5uLmxhKXRocm93IEVycm9yKFwiUXVlcnkubGltaXRUb0ZpcnN0OiBMaW1pdCB3YXMgYWxyZWFkeSBzZXQgKGJ5IGFub3RoZXIgY2FsbCB0byBsaW1pdCwgbGltaXRUb0ZpcnN0LCBvciBsaW1pdFRvTGFzdCkuXCIpO3JldHVybiBuZXcgWSh0aGlzLmssdGhpcy5wYXRoLHRoaXMubi5NZShhKSx0aGlzLnBjKX07XG5oLk5lPWZ1bmN0aW9uKGEpe0QoXCJRdWVyeS5saW1pdFRvTGFzdFwiLDEsMSxhcmd1bWVudHMubGVuZ3RoKTtpZighZmEoYSl8fE1hdGguZmxvb3IoYSkhPT1hfHwwPj1hKXRocm93IEVycm9yKFwiUXVlcnkubGltaXRUb0xhc3Q6IEZpcnN0IGFyZ3VtZW50IG11c3QgYmUgYSBwb3NpdGl2ZSBpbnRlZ2VyLlwiKTtpZih0aGlzLm4ubGEpdGhyb3cgRXJyb3IoXCJRdWVyeS5saW1pdFRvTGFzdDogTGltaXQgd2FzIGFscmVhZHkgc2V0IChieSBhbm90aGVyIGNhbGwgdG8gbGltaXQsIGxpbWl0VG9GaXJzdCwgb3IgbGltaXRUb0xhc3QpLlwiKTtyZXR1cm4gbmV3IFkodGhpcy5rLHRoaXMucGF0aCx0aGlzLm4uTmUoYSksdGhpcy5wYyl9O1xuaC5RZz1mdW5jdGlvbihhKXtEKFwiUXVlcnkub3JkZXJCeUNoaWxkXCIsMSwxLGFyZ3VtZW50cy5sZW5ndGgpO2lmKFwiJGtleVwiPT09YSl0aHJvdyBFcnJvcignUXVlcnkub3JkZXJCeUNoaWxkOiBcIiRrZXlcIiBpcyBpbnZhbGlkLiAgVXNlIFF1ZXJ5Lm9yZGVyQnlLZXkoKSBpbnN0ZWFkLicpO2lmKFwiJHByaW9yaXR5XCI9PT1hKXRocm93IEVycm9yKCdRdWVyeS5vcmRlckJ5Q2hpbGQ6IFwiJHByaW9yaXR5XCIgaXMgaW52YWxpZC4gIFVzZSBRdWVyeS5vcmRlckJ5UHJpb3JpdHkoKSBpbnN0ZWFkLicpO2lmKFwiJHZhbHVlXCI9PT1hKXRocm93IEVycm9yKCdRdWVyeS5vcmRlckJ5Q2hpbGQ6IFwiJHZhbHVlXCIgaXMgaW52YWxpZC4gIFVzZSBRdWVyeS5vcmRlckJ5VmFsdWUoKSBpbnN0ZWFkLicpO25nKFwiUXVlcnkub3JkZXJCeUNoaWxkXCIsYSk7ZGoodGhpcyxcIlF1ZXJ5Lm9yZGVyQnlDaGlsZFwiKTt2YXIgYj1uZXcgUChhKTtpZihiLmUoKSl0aHJvdyBFcnJvcihcIlF1ZXJ5Lm9yZGVyQnlDaGlsZDogY2Fubm90IHBhc3MgaW4gZW1wdHkgcGF0aC4gIFVzZSBRdWVyeS5vcmRlckJ5VmFsdWUoKSBpbnN0ZWFkLlwiKTtcbmI9bmV3IHZlKGIpO2I9RmUodGhpcy5uLGIpO2JqKGIpO3JldHVybiBuZXcgWSh0aGlzLmssdGhpcy5wYXRoLGIsITApfTtoLlJnPWZ1bmN0aW9uKCl7RChcIlF1ZXJ5Lm9yZGVyQnlLZXlcIiwwLDAsYXJndW1lbnRzLmxlbmd0aCk7ZGoodGhpcyxcIlF1ZXJ5Lm9yZGVyQnlLZXlcIik7dmFyIGE9RmUodGhpcy5uLHJlKTtiaihhKTtyZXR1cm4gbmV3IFkodGhpcy5rLHRoaXMucGF0aCxhLCEwKX07aC5TZz1mdW5jdGlvbigpe0QoXCJRdWVyeS5vcmRlckJ5UHJpb3JpdHlcIiwwLDAsYXJndW1lbnRzLmxlbmd0aCk7ZGoodGhpcyxcIlF1ZXJ5Lm9yZGVyQnlQcmlvcml0eVwiKTt2YXIgYT1GZSh0aGlzLm4sUik7YmooYSk7cmV0dXJuIG5ldyBZKHRoaXMuayx0aGlzLnBhdGgsYSwhMCl9O1xuaC5UZz1mdW5jdGlvbigpe0QoXCJRdWVyeS5vcmRlckJ5VmFsdWVcIiwwLDAsYXJndW1lbnRzLmxlbmd0aCk7ZGoodGhpcyxcIlF1ZXJ5Lm9yZGVyQnlWYWx1ZVwiKTt2YXIgYT1GZSh0aGlzLm4sQmUpO2JqKGEpO3JldHVybiBuZXcgWSh0aGlzLmssdGhpcy5wYXRoLGEsITApfTtoLmNlPWZ1bmN0aW9uKGEsYil7RChcIlF1ZXJ5LnN0YXJ0QXRcIiwwLDIsYXJndW1lbnRzLmxlbmd0aCk7Z2coXCJRdWVyeS5zdGFydEF0XCIsYSx0aGlzLnBhdGgsITApO21nKFwiUXVlcnkuc3RhcnRBdFwiLGIpO3ZhciBjPXRoaXMubi5jZShhLGIpO2NqKGMpO2JqKGMpO2lmKHRoaXMubi5vYSl0aHJvdyBFcnJvcihcIlF1ZXJ5LnN0YXJ0QXQ6IFN0YXJ0aW5nIHBvaW50IHdhcyBhbHJlYWR5IHNldCAoYnkgYW5vdGhlciBjYWxsIHRvIHN0YXJ0QXQgb3IgZXF1YWxUbykuXCIpO3AoYSl8fChiPWE9bnVsbCk7cmV0dXJuIG5ldyBZKHRoaXMuayx0aGlzLnBhdGgsYyx0aGlzLnBjKX07XG5oLnZkPWZ1bmN0aW9uKGEsYil7RChcIlF1ZXJ5LmVuZEF0XCIsMCwyLGFyZ3VtZW50cy5sZW5ndGgpO2dnKFwiUXVlcnkuZW5kQXRcIixhLHRoaXMucGF0aCwhMCk7bWcoXCJRdWVyeS5lbmRBdFwiLGIpO3ZhciBjPXRoaXMubi52ZChhLGIpO2NqKGMpO2JqKGMpO2lmKHRoaXMubi5yYSl0aHJvdyBFcnJvcihcIlF1ZXJ5LmVuZEF0OiBFbmRpbmcgcG9pbnQgd2FzIGFscmVhZHkgc2V0IChieSBhbm90aGVyIGNhbGwgdG8gZW5kQXQgb3IgZXF1YWxUbykuXCIpO3JldHVybiBuZXcgWSh0aGlzLmssdGhpcy5wYXRoLGMsdGhpcy5wYyl9O1xuaC50Zz1mdW5jdGlvbihhLGIpe0QoXCJRdWVyeS5lcXVhbFRvXCIsMSwyLGFyZ3VtZW50cy5sZW5ndGgpO2dnKFwiUXVlcnkuZXF1YWxUb1wiLGEsdGhpcy5wYXRoLCExKTttZyhcIlF1ZXJ5LmVxdWFsVG9cIixiKTtpZih0aGlzLm4ub2EpdGhyb3cgRXJyb3IoXCJRdWVyeS5lcXVhbFRvOiBTdGFydGluZyBwb2ludCB3YXMgYWxyZWFkeSBzZXQgKGJ5IGFub3RoZXIgY2FsbCB0byBlbmRBdCBvciBlcXVhbFRvKS5cIik7aWYodGhpcy5uLnJhKXRocm93IEVycm9yKFwiUXVlcnkuZXF1YWxUbzogRW5kaW5nIHBvaW50IHdhcyBhbHJlYWR5IHNldCAoYnkgYW5vdGhlciBjYWxsIHRvIGVuZEF0IG9yIGVxdWFsVG8pLlwiKTtyZXR1cm4gdGhpcy5jZShhLGIpLnZkKGEsYil9O1xuaC50b1N0cmluZz1mdW5jdGlvbigpe0QoXCJRdWVyeS50b1N0cmluZ1wiLDAsMCxhcmd1bWVudHMubGVuZ3RoKTtmb3IodmFyIGE9dGhpcy5wYXRoLGI9XCJcIixjPWEuYWE7YzxhLnUubGVuZ3RoO2MrKylcIlwiIT09YS51W2NdJiYoYis9XCIvXCIrZW5jb2RlVVJJQ29tcG9uZW50KFN0cmluZyhhLnVbY10pKSk7cmV0dXJuIHRoaXMuay50b1N0cmluZygpKyhifHxcIi9cIil9O2gud2E9ZnVuY3Rpb24oKXt2YXIgYT14ZChHZSh0aGlzLm4pKTtyZXR1cm5cInt9XCI9PT1hP1wiZGVmYXVsdFwiOmF9O1xuZnVuY3Rpb24gZWooYSxiLGMpe3ZhciBkPXtjYW5jZWw6bnVsbCxRYTpudWxsfTtpZihiJiZjKWQuY2FuY2VsPWIsRihhLDMsZC5jYW5jZWwsITApLGQuUWE9YyxRYihhLDQsZC5RYSk7ZWxzZSBpZihiKWlmKFwib2JqZWN0XCI9PT10eXBlb2YgYiYmbnVsbCE9PWIpZC5RYT1iO2Vsc2UgaWYoXCJmdW5jdGlvblwiPT09dHlwZW9mIGIpZC5jYW5jZWw9YjtlbHNlIHRocm93IEVycm9yKEUoYSwzLCEwKStcIiBtdXN0IGVpdGhlciBiZSBhIGNhbmNlbCBjYWxsYmFjayBvciBhIGNvbnRleHQgb2JqZWN0LlwiKTtyZXR1cm4gZH1ZLnByb3RvdHlwZS5yZWY9WS5wcm90b3R5cGUuTWI7WS5wcm90b3R5cGUub249WS5wcm90b3R5cGUuSWI7WS5wcm90b3R5cGUub2ZmPVkucHJvdG90eXBlLm1jO1kucHJvdG90eXBlLm9uY2U9WS5wcm90b3R5cGUuUGc7WS5wcm90b3R5cGUubGltaXQ9WS5wcm90b3R5cGUuTGU7WS5wcm90b3R5cGUubGltaXRUb0ZpcnN0PVkucHJvdG90eXBlLk1lO1xuWS5wcm90b3R5cGUubGltaXRUb0xhc3Q9WS5wcm90b3R5cGUuTmU7WS5wcm90b3R5cGUub3JkZXJCeUNoaWxkPVkucHJvdG90eXBlLlFnO1kucHJvdG90eXBlLm9yZGVyQnlLZXk9WS5wcm90b3R5cGUuUmc7WS5wcm90b3R5cGUub3JkZXJCeVByaW9yaXR5PVkucHJvdG90eXBlLlNnO1kucHJvdG90eXBlLm9yZGVyQnlWYWx1ZT1ZLnByb3RvdHlwZS5UZztZLnByb3RvdHlwZS5zdGFydEF0PVkucHJvdG90eXBlLmNlO1kucHJvdG90eXBlLmVuZEF0PVkucHJvdG90eXBlLnZkO1kucHJvdG90eXBlLmVxdWFsVG89WS5wcm90b3R5cGUudGc7WS5wcm90b3R5cGUudG9TdHJpbmc9WS5wcm90b3R5cGUudG9TdHJpbmc7dmFyIFo9e307Wi56Yz1SaDtaLkRhdGFDb25uZWN0aW9uPVouemM7UmgucHJvdG90eXBlLmRoPWZ1bmN0aW9uKGEsYil7dGhpcy5JYShcInFcIix7cDphfSxiKX07Wi56Yy5wcm90b3R5cGUuc2ltcGxlTGlzdGVuPVouemMucHJvdG90eXBlLmRoO1JoLnByb3RvdHlwZS5zZz1mdW5jdGlvbihhLGIpe3RoaXMuSWEoXCJlY2hvXCIse2Q6YX0sYil9O1ouemMucHJvdG90eXBlLmVjaG89Wi56Yy5wcm90b3R5cGUuc2c7UmgucHJvdG90eXBlLmludGVycnVwdD1SaC5wcm90b3R5cGUuQ2I7Wi5kZz1GaDtaLlJlYWxUaW1lQ29ubmVjdGlvbj1aLmRnO0ZoLnByb3RvdHlwZS5zZW5kUmVxdWVzdD1GaC5wcm90b3R5cGUuSWE7RmgucHJvdG90eXBlLmNsb3NlPUZoLnByb3RvdHlwZS5jbG9zZTtcblouQ2c9ZnVuY3Rpb24oYSl7dmFyIGI9UmgucHJvdG90eXBlLnB1dDtSaC5wcm90b3R5cGUucHV0PWZ1bmN0aW9uKGMsZCxlLGYpe3AoZikmJihmPWEoKSk7Yi5jYWxsKHRoaXMsYyxkLGUsZil9O3JldHVybiBmdW5jdGlvbigpe1JoLnByb3RvdHlwZS5wdXQ9Yn19O1ouaGlqYWNrSGFzaD1aLkNnO1ouY2c9ZGQ7Wi5Db25uZWN0aW9uVGFyZ2V0PVouY2c7Wi53YT1mdW5jdGlvbihhKXtyZXR1cm4gYS53YSgpfTtaLnF1ZXJ5SWRlbnRpZmllcj1aLndhO1ouRmc9ZnVuY3Rpb24oYSl7cmV0dXJuIGEuay5WYS5iYX07Wi5saXN0ZW5zPVouRmc7Wi56ZT1mdW5jdGlvbihhKXthLnplKCl9O1ouZm9yY2VSZXN0Q2xpZW50PVouemU7ZnVuY3Rpb24gWChhLGIpe3ZhciBjLGQsZTtpZihhIGluc3RhbmNlb2YgSmkpYz1hLGQ9YjtlbHNle0QoXCJuZXcgRmlyZWJhc2VcIiwxLDIsYXJndW1lbnRzLmxlbmd0aCk7ZD1zZChhcmd1bWVudHNbMF0pO2M9ZC5maDtcImZpcmViYXNlXCI9PT1kLmRvbWFpbiYmcmQoZC5ob3N0K1wiIGlzIG5vIGxvbmdlciBzdXBwb3J0ZWQuIFBsZWFzZSB1c2UgPFlPVVIgRklSRUJBU0U+LmZpcmViYXNlaW8uY29tIGluc3RlYWRcIik7YyYmXCJ1bmRlZmluZWRcIiE9Y3x8cmQoXCJDYW5ub3QgcGFyc2UgRmlyZWJhc2UgdXJsLiBQbGVhc2UgdXNlIGh0dHBzOi8vPFlPVVIgRklSRUJBU0U+LmZpcmViYXNlaW8uY29tXCIpO2Qub2J8fFwidW5kZWZpbmVkXCIhPT10eXBlb2Ygd2luZG93JiZ3aW5kb3cubG9jYXRpb24mJndpbmRvdy5sb2NhdGlvbi5wcm90b2NvbCYmLTEhPT13aW5kb3cubG9jYXRpb24ucHJvdG9jb2wuaW5kZXhPZihcImh0dHBzOlwiKSYmUyhcIkluc2VjdXJlIEZpcmViYXNlIGFjY2VzcyBmcm9tIGEgc2VjdXJlIHBhZ2UuIFBsZWFzZSB1c2UgaHR0cHMgaW4gY2FsbHMgdG8gbmV3IEZpcmViYXNlKCkuXCIpO1xuYz1uZXcgZGQoZC5ob3N0LGQub2IsYyxcIndzXCI9PT1kLnNjaGVtZXx8XCJ3c3NcIj09PWQuc2NoZW1lKTtkPW5ldyBQKGQuYmQpO2U9ZC50b1N0cmluZygpO3ZhciBmOyEoZj0hcShjLmhvc3QpfHwwPT09Yy5ob3N0Lmxlbmd0aHx8IWVnKGMubGMpKSYmKGY9MCE9PWUubGVuZ3RoKSYmKGUmJihlPWUucmVwbGFjZSgvXlxcLypcXC5pbmZvKFxcL3wkKS8sXCIvXCIpKSxmPSEocShlKSYmMCE9PWUubGVuZ3RoJiYhY2cudGVzdChlKSkpO2lmKGYpdGhyb3cgRXJyb3IoRShcIm5ldyBGaXJlYmFzZVwiLDEsITEpKydtdXN0IGJlIGEgdmFsaWQgZmlyZWJhc2UgVVJMIGFuZCB0aGUgcGF0aCBjYW5cXCd0IGNvbnRhaW4gXCIuXCIsIFwiI1wiLCBcIiRcIiwgXCJbXCIsIG9yIFwiXVwiLicpO2lmKGIpaWYoYiBpbnN0YW5jZW9mIGFqKWU9YjtlbHNlIGlmKHEoYikpZT1hai55YigpLGMuUmQ9YjtlbHNlIHRocm93IEVycm9yKFwiRXhwZWN0ZWQgYSB2YWxpZCBGaXJlYmFzZS5Db250ZXh0IGZvciBzZWNvbmQgYXJndW1lbnQgdG8gbmV3IEZpcmViYXNlKClcIik7XG5lbHNlIGU9YWoueWIoKTtmPWMudG9TdHJpbmcoKTt2YXIgZz16KGUuc2MsZik7Z3x8KGc9bmV3IEppKGMsZS5hZyksZS5zY1tmXT1nKTtjPWd9WS5jYWxsKHRoaXMsYyxkLERlLCExKTt0aGlzLnRoZW49dm9pZCAwO3RoaXNbXCJjYXRjaFwiXT12b2lkIDB9a2EoWCxZKTt2YXIgZmo9WCxnaj1bXCJGaXJlYmFzZVwiXSxoaj1uO2dqWzBdaW4gaGp8fCFoai5leGVjU2NyaXB0fHxoai5leGVjU2NyaXB0KFwidmFyIFwiK2dqWzBdKTtmb3IodmFyIGlqO2dqLmxlbmd0aCYmKGlqPWdqLnNoaWZ0KCkpOykhZ2oubGVuZ3RoJiZwKGZqKT9oaltpal09Zmo6aGo9aGpbaWpdP2hqW2lqXTpoaltpal09e307WC5nb09mZmxpbmU9ZnVuY3Rpb24oKXtEKFwiRmlyZWJhc2UuZ29PZmZsaW5lXCIsMCwwLGFyZ3VtZW50cy5sZW5ndGgpO2FqLnliKCkuQ2IoKX07WC5nb09ubGluZT1mdW5jdGlvbigpe0QoXCJGaXJlYmFzZS5nb09ubGluZVwiLDAsMCxhcmd1bWVudHMubGVuZ3RoKTthai55YigpLnZjKCl9O1xuWC5lbmFibGVMb2dnaW5nPW9kO1guU2VydmVyVmFsdWU9e1RJTUVTVEFNUDp7XCIuc3ZcIjpcInRpbWVzdGFtcFwifX07WC5TREtfVkVSU0lPTj1FYjtYLklOVEVSTkFMPVU7WC5Db250ZXh0PWFqO1guVEVTVF9BQ0NFU1M9WjtYLnByb3RvdHlwZS5uYW1lPWZ1bmN0aW9uKCl7UyhcIkZpcmViYXNlLm5hbWUoKSBiZWluZyBkZXByZWNhdGVkLiBQbGVhc2UgdXNlIEZpcmViYXNlLmtleSgpIGluc3RlYWQuXCIpO0QoXCJGaXJlYmFzZS5uYW1lXCIsMCwwLGFyZ3VtZW50cy5sZW5ndGgpO3JldHVybiB0aGlzLmtleSgpfTtYLnByb3RvdHlwZS5uYW1lPVgucHJvdG90eXBlLm5hbWU7WC5wcm90b3R5cGUua2V5PWZ1bmN0aW9uKCl7RChcIkZpcmViYXNlLmtleVwiLDAsMCxhcmd1bWVudHMubGVuZ3RoKTtyZXR1cm4gdGhpcy5wYXRoLmUoKT9udWxsOm1lKHRoaXMucGF0aCl9O1gucHJvdG90eXBlLmtleT1YLnByb3RvdHlwZS5rZXk7XG5YLnByb3RvdHlwZS5vPWZ1bmN0aW9uKGEpe0QoXCJGaXJlYmFzZS5jaGlsZFwiLDEsMSxhcmd1bWVudHMubGVuZ3RoKTtpZihmYShhKSlhPVN0cmluZyhhKTtlbHNlIGlmKCEoYSBpbnN0YW5jZW9mIFApKWlmKG51bGw9PT1LKHRoaXMucGF0aCkpe3ZhciBiPWE7YiYmKGI9Yi5yZXBsYWNlKC9eXFwvKlxcLmluZm8oXFwvfCQpLyxcIi9cIikpO25nKFwiRmlyZWJhc2UuY2hpbGRcIixiKX1lbHNlIG5nKFwiRmlyZWJhc2UuY2hpbGRcIixhKTtyZXR1cm4gbmV3IFgodGhpcy5rLHRoaXMucGF0aC5vKGEpKX07WC5wcm90b3R5cGUuY2hpbGQ9WC5wcm90b3R5cGUubztYLnByb3RvdHlwZS5wYXJlbnQ9ZnVuY3Rpb24oKXtEKFwiRmlyZWJhc2UucGFyZW50XCIsMCwwLGFyZ3VtZW50cy5sZW5ndGgpO3ZhciBhPXRoaXMucGF0aC5wYXJlbnQoKTtyZXR1cm4gbnVsbD09PWE/bnVsbDpuZXcgWCh0aGlzLmssYSl9O1gucHJvdG90eXBlLnBhcmVudD1YLnByb3RvdHlwZS5wYXJlbnQ7XG5YLnByb3RvdHlwZS5yb290PWZ1bmN0aW9uKCl7RChcIkZpcmViYXNlLnJlZlwiLDAsMCxhcmd1bWVudHMubGVuZ3RoKTtmb3IodmFyIGE9dGhpcztudWxsIT09YS5wYXJlbnQoKTspYT1hLnBhcmVudCgpO3JldHVybiBhfTtYLnByb3RvdHlwZS5yb290PVgucHJvdG90eXBlLnJvb3Q7WC5wcm90b3R5cGUuc2V0PWZ1bmN0aW9uKGEsYil7RChcIkZpcmViYXNlLnNldFwiLDEsMixhcmd1bWVudHMubGVuZ3RoKTtvZyhcIkZpcmViYXNlLnNldFwiLHRoaXMucGF0aCk7Z2coXCJGaXJlYmFzZS5zZXRcIixhLHRoaXMucGF0aCwhMSk7RihcIkZpcmViYXNlLnNldFwiLDIsYiwhMCk7dmFyIGM9bmV3IEI7dGhpcy5rLk9iKHRoaXMucGF0aCxhLG51bGwsQyhjLGIpKTtyZXR1cm4gYy5EfTtYLnByb3RvdHlwZS5zZXQ9WC5wcm90b3R5cGUuc2V0O1xuWC5wcm90b3R5cGUudXBkYXRlPWZ1bmN0aW9uKGEsYil7RChcIkZpcmViYXNlLnVwZGF0ZVwiLDEsMixhcmd1bWVudHMubGVuZ3RoKTtvZyhcIkZpcmViYXNlLnVwZGF0ZVwiLHRoaXMucGF0aCk7aWYoZGEoYSkpe2Zvcih2YXIgYz17fSxkPTA7ZDxhLmxlbmd0aDsrK2QpY1tcIlwiK2RdPWFbZF07YT1jO1MoXCJQYXNzaW5nIGFuIEFycmF5IHRvIEZpcmViYXNlLnVwZGF0ZSgpIGlzIGRlcHJlY2F0ZWQuIFVzZSBzZXQoKSBpZiB5b3Ugd2FudCB0byBvdmVyd3JpdGUgdGhlIGV4aXN0aW5nIGRhdGEsIG9yIGFuIE9iamVjdCB3aXRoIGludGVnZXIga2V5cyBpZiB5b3UgcmVhbGx5IGRvIHdhbnQgdG8gb25seSB1cGRhdGUgc29tZSBvZiB0aGUgY2hpbGRyZW4uXCIpfWpnKFwiRmlyZWJhc2UudXBkYXRlXCIsYSx0aGlzLnBhdGgpO0YoXCJGaXJlYmFzZS51cGRhdGVcIiwyLGIsITApO2M9bmV3IEI7dGhpcy5rLnVwZGF0ZSh0aGlzLnBhdGgsYSxDKGMsYikpO3JldHVybiBjLkR9O1xuWC5wcm90b3R5cGUudXBkYXRlPVgucHJvdG90eXBlLnVwZGF0ZTtYLnByb3RvdHlwZS5PYj1mdW5jdGlvbihhLGIsYyl7RChcIkZpcmViYXNlLnNldFdpdGhQcmlvcml0eVwiLDIsMyxhcmd1bWVudHMubGVuZ3RoKTtvZyhcIkZpcmViYXNlLnNldFdpdGhQcmlvcml0eVwiLHRoaXMucGF0aCk7Z2coXCJGaXJlYmFzZS5zZXRXaXRoUHJpb3JpdHlcIixhLHRoaXMucGF0aCwhMSk7a2coXCJGaXJlYmFzZS5zZXRXaXRoUHJpb3JpdHlcIiwyLGIpO0YoXCJGaXJlYmFzZS5zZXRXaXRoUHJpb3JpdHlcIiwzLGMsITApO2lmKFwiLmxlbmd0aFwiPT09dGhpcy5rZXkoKXx8XCIua2V5c1wiPT09dGhpcy5rZXkoKSl0aHJvd1wiRmlyZWJhc2Uuc2V0V2l0aFByaW9yaXR5IGZhaWxlZDogXCIrdGhpcy5rZXkoKStcIiBpcyBhIHJlYWQtb25seSBvYmplY3QuXCI7dmFyIGQ9bmV3IEI7dGhpcy5rLk9iKHRoaXMucGF0aCxhLGIsQyhkLGMpKTtyZXR1cm4gZC5EfTtYLnByb3RvdHlwZS5zZXRXaXRoUHJpb3JpdHk9WC5wcm90b3R5cGUuT2I7XG5YLnByb3RvdHlwZS5yZW1vdmU9ZnVuY3Rpb24oYSl7RChcIkZpcmViYXNlLnJlbW92ZVwiLDAsMSxhcmd1bWVudHMubGVuZ3RoKTtvZyhcIkZpcmViYXNlLnJlbW92ZVwiLHRoaXMucGF0aCk7RihcIkZpcmViYXNlLnJlbW92ZVwiLDEsYSwhMCk7cmV0dXJuIHRoaXMuc2V0KG51bGwsYSl9O1gucHJvdG90eXBlLnJlbW92ZT1YLnByb3RvdHlwZS5yZW1vdmU7XG5YLnByb3RvdHlwZS50cmFuc2FjdGlvbj1mdW5jdGlvbihhLGIsYyl7RChcIkZpcmViYXNlLnRyYW5zYWN0aW9uXCIsMSwzLGFyZ3VtZW50cy5sZW5ndGgpO29nKFwiRmlyZWJhc2UudHJhbnNhY3Rpb25cIix0aGlzLnBhdGgpO0YoXCJGaXJlYmFzZS50cmFuc2FjdGlvblwiLDEsYSwhMSk7RihcIkZpcmViYXNlLnRyYW5zYWN0aW9uXCIsMixiLCEwKTtpZihwKGMpJiZcImJvb2xlYW5cIiE9dHlwZW9mIGMpdGhyb3cgRXJyb3IoRShcIkZpcmViYXNlLnRyYW5zYWN0aW9uXCIsMywhMCkrXCJtdXN0IGJlIGEgYm9vbGVhbi5cIik7aWYoXCIubGVuZ3RoXCI9PT10aGlzLmtleSgpfHxcIi5rZXlzXCI9PT10aGlzLmtleSgpKXRocm93XCJGaXJlYmFzZS50cmFuc2FjdGlvbiBmYWlsZWQ6IFwiK3RoaXMua2V5KCkrXCIgaXMgYSByZWFkLW9ubHkgb2JqZWN0LlwiO1widW5kZWZpbmVkXCI9PT10eXBlb2YgYyYmKGM9ITApO3ZhciBkPW5ldyBCO3IoYikmJk5iKGQuRCk7U2kodGhpcy5rLHRoaXMucGF0aCxhLGZ1bmN0aW9uKGEsYyxnKXthP1xuZC5yZWplY3QoYSk6ZC5yZXNvbHZlKG5ldyBlaShjLGcpKTtyKGIpJiZiKGEsYyxnKX0sYyk7cmV0dXJuIGQuRH07WC5wcm90b3R5cGUudHJhbnNhY3Rpb249WC5wcm90b3R5cGUudHJhbnNhY3Rpb247WC5wcm90b3R5cGUuJGc9ZnVuY3Rpb24oYSxiKXtEKFwiRmlyZWJhc2Uuc2V0UHJpb3JpdHlcIiwxLDIsYXJndW1lbnRzLmxlbmd0aCk7b2coXCJGaXJlYmFzZS5zZXRQcmlvcml0eVwiLHRoaXMucGF0aCk7a2coXCJGaXJlYmFzZS5zZXRQcmlvcml0eVwiLDEsYSk7RihcIkZpcmViYXNlLnNldFByaW9yaXR5XCIsMixiLCEwKTt2YXIgYz1uZXcgQjt0aGlzLmsuT2IodGhpcy5wYXRoLm8oXCIucHJpb3JpdHlcIiksYSxudWxsLEMoYyxiKSk7cmV0dXJuIGMuRH07WC5wcm90b3R5cGUuc2V0UHJpb3JpdHk9WC5wcm90b3R5cGUuJGc7XG5YLnByb3RvdHlwZS5wdXNoPWZ1bmN0aW9uKGEsYil7RChcIkZpcmViYXNlLnB1c2hcIiwwLDIsYXJndW1lbnRzLmxlbmd0aCk7b2coXCJGaXJlYmFzZS5wdXNoXCIsdGhpcy5wYXRoKTtnZyhcIkZpcmViYXNlLnB1c2hcIixhLHRoaXMucGF0aCwhMCk7RihcIkZpcmViYXNlLnB1c2hcIiwyLGIsITApO3ZhciBjPUxpKHRoaXMuayksZD1oZihjKSxjPXRoaXMubyhkKTtpZihudWxsIT1hKXt2YXIgZT10aGlzLGY9Yy5zZXQoYSxiKS50aGVuKGZ1bmN0aW9uKCl7cmV0dXJuIGUubyhkKX0pO2MudGhlbj11KGYudGhlbixmKTtjW1wiY2F0Y2hcIl09dShmLnRoZW4sZix2b2lkIDApO3IoYikmJk5iKGYpfXJldHVybiBjfTtYLnByb3RvdHlwZS5wdXNoPVgucHJvdG90eXBlLnB1c2g7WC5wcm90b3R5cGUubGI9ZnVuY3Rpb24oKXtvZyhcIkZpcmViYXNlLm9uRGlzY29ubmVjdFwiLHRoaXMucGF0aCk7cmV0dXJuIG5ldyBWKHRoaXMuayx0aGlzLnBhdGgpfTtYLnByb3RvdHlwZS5vbkRpc2Nvbm5lY3Q9WC5wcm90b3R5cGUubGI7XG5YLnByb3RvdHlwZS5PPWZ1bmN0aW9uKGEsYixjKXtTKFwiRmlyZWJhc2VSZWYuYXV0aCgpIGJlaW5nIGRlcHJlY2F0ZWQuIFBsZWFzZSB1c2UgRmlyZWJhc2VSZWYuYXV0aFdpdGhDdXN0b21Ub2tlbigpIGluc3RlYWQuXCIpO0QoXCJGaXJlYmFzZS5hdXRoXCIsMSwzLGFyZ3VtZW50cy5sZW5ndGgpO3BnKFwiRmlyZWJhc2UuYXV0aFwiLGEpO0YoXCJGaXJlYmFzZS5hdXRoXCIsMixiLCEwKTtGKFwiRmlyZWJhc2UuYXV0aFwiLDMsYiwhMCk7dmFyIGQ9bmV3IEI7ZGgodGhpcy5rLk8sYSx7fSx7cmVtZW1iZXI6XCJub25lXCJ9LEMoZCxiKSxjKTtyZXR1cm4gZC5EfTtYLnByb3RvdHlwZS5hdXRoPVgucHJvdG90eXBlLk87WC5wcm90b3R5cGUuamU9ZnVuY3Rpb24oYSl7RChcIkZpcmViYXNlLnVuYXV0aFwiLDAsMSxhcmd1bWVudHMubGVuZ3RoKTtGKFwiRmlyZWJhc2UudW5hdXRoXCIsMSxhLCEwKTt2YXIgYj1uZXcgQjtlaCh0aGlzLmsuTyxDKGIsYSkpO3JldHVybiBiLkR9O1gucHJvdG90eXBlLnVuYXV0aD1YLnByb3RvdHlwZS5qZTtcblgucHJvdG90eXBlLkJlPWZ1bmN0aW9uKCl7RChcIkZpcmViYXNlLmdldEF1dGhcIiwwLDAsYXJndW1lbnRzLmxlbmd0aCk7cmV0dXJuIHRoaXMuay5PLkJlKCl9O1gucHJvdG90eXBlLmdldEF1dGg9WC5wcm90b3R5cGUuQmU7WC5wcm90b3R5cGUuSmc9ZnVuY3Rpb24oYSxiKXtEKFwiRmlyZWJhc2Uub25BdXRoXCIsMSwyLGFyZ3VtZW50cy5sZW5ndGgpO0YoXCJGaXJlYmFzZS5vbkF1dGhcIiwxLGEsITEpO1FiKFwiRmlyZWJhc2Uub25BdXRoXCIsMixiKTt0aGlzLmsuTy5JYihcImF1dGhfc3RhdHVzXCIsYSxiKX07WC5wcm90b3R5cGUub25BdXRoPVgucHJvdG90eXBlLkpnO1gucHJvdG90eXBlLklnPWZ1bmN0aW9uKGEsYil7RChcIkZpcmViYXNlLm9mZkF1dGhcIiwxLDIsYXJndW1lbnRzLmxlbmd0aCk7RihcIkZpcmViYXNlLm9mZkF1dGhcIiwxLGEsITEpO1FiKFwiRmlyZWJhc2Uub2ZmQXV0aFwiLDIsYik7dGhpcy5rLk8ubWMoXCJhdXRoX3N0YXR1c1wiLGEsYil9O1gucHJvdG90eXBlLm9mZkF1dGg9WC5wcm90b3R5cGUuSWc7XG5YLnByb3RvdHlwZS5oZz1mdW5jdGlvbihhLGIsYyl7RChcIkZpcmViYXNlLmF1dGhXaXRoQ3VzdG9tVG9rZW5cIiwxLDMsYXJndW1lbnRzLmxlbmd0aCk7Mj09PWFyZ3VtZW50cy5sZW5ndGgmJkhiKGIpJiYoYz1iLGI9dm9pZCAwKTtwZyhcIkZpcmViYXNlLmF1dGhXaXRoQ3VzdG9tVG9rZW5cIixhKTtGKFwiRmlyZWJhc2UuYXV0aFdpdGhDdXN0b21Ub2tlblwiLDIsYiwhMCk7c2coXCJGaXJlYmFzZS5hdXRoV2l0aEN1c3RvbVRva2VuXCIsMyxjLCEwKTt2YXIgZD1uZXcgQjtkaCh0aGlzLmsuTyxhLHt9LGN8fHt9LEMoZCxiKSk7cmV0dXJuIGQuRH07WC5wcm90b3R5cGUuYXV0aFdpdGhDdXN0b21Ub2tlbj1YLnByb3RvdHlwZS5oZztcblgucHJvdG90eXBlLmlnPWZ1bmN0aW9uKGEsYixjKXtEKFwiRmlyZWJhc2UuYXV0aFdpdGhPQXV0aFBvcHVwXCIsMSwzLGFyZ3VtZW50cy5sZW5ndGgpOzI9PT1hcmd1bWVudHMubGVuZ3RoJiZIYihiKSYmKGM9YixiPXZvaWQgMCk7cmcoXCJGaXJlYmFzZS5hdXRoV2l0aE9BdXRoUG9wdXBcIixhKTtGKFwiRmlyZWJhc2UuYXV0aFdpdGhPQXV0aFBvcHVwXCIsMixiLCEwKTtzZyhcIkZpcmViYXNlLmF1dGhXaXRoT0F1dGhQb3B1cFwiLDMsYywhMCk7dmFyIGQ9bmV3IEI7aWgodGhpcy5rLk8sYSxjLEMoZCxiKSk7cmV0dXJuIGQuRH07WC5wcm90b3R5cGUuYXV0aFdpdGhPQXV0aFBvcHVwPVgucHJvdG90eXBlLmlnO1xuWC5wcm90b3R5cGUuamc9ZnVuY3Rpb24oYSxiLGMpe0QoXCJGaXJlYmFzZS5hdXRoV2l0aE9BdXRoUmVkaXJlY3RcIiwxLDMsYXJndW1lbnRzLmxlbmd0aCk7Mj09PWFyZ3VtZW50cy5sZW5ndGgmJkhiKGIpJiYoYz1iLGI9dm9pZCAwKTtyZyhcIkZpcmViYXNlLmF1dGhXaXRoT0F1dGhSZWRpcmVjdFwiLGEpO0YoXCJGaXJlYmFzZS5hdXRoV2l0aE9BdXRoUmVkaXJlY3RcIiwyLGIsITEpO3NnKFwiRmlyZWJhc2UuYXV0aFdpdGhPQXV0aFJlZGlyZWN0XCIsMyxjLCEwKTt2YXIgZD1uZXcgQixlPXRoaXMuay5PLGY9YyxnPUMoZCxiKTtnaChlKTt2YXIgaz1bUWddLGY9QWcoZik7XCJhbm9ueW1vdXNcIj09PWF8fFwiZmlyZWJhc2VcIj09PWE/VChnLFNnKFwiVFJBTlNQT1JUX1VOQVZBSUxBQkxFXCIpKTooY2Quc2V0KFwicmVkaXJlY3RfY2xpZW50X29wdGlvbnNcIixmLnFkKSxoaChlLGssXCIvYXV0aC9cIithLGYsZykpO3JldHVybiBkLkR9O1gucHJvdG90eXBlLmF1dGhXaXRoT0F1dGhSZWRpcmVjdD1YLnByb3RvdHlwZS5qZztcblgucHJvdG90eXBlLmtnPWZ1bmN0aW9uKGEsYixjLGQpe0QoXCJGaXJlYmFzZS5hdXRoV2l0aE9BdXRoVG9rZW5cIiwyLDQsYXJndW1lbnRzLmxlbmd0aCk7Mz09PWFyZ3VtZW50cy5sZW5ndGgmJkhiKGMpJiYoZD1jLGM9dm9pZCAwKTtyZyhcIkZpcmViYXNlLmF1dGhXaXRoT0F1dGhUb2tlblwiLGEpO0YoXCJGaXJlYmFzZS5hdXRoV2l0aE9BdXRoVG9rZW5cIiwzLGMsITApO3NnKFwiRmlyZWJhc2UuYXV0aFdpdGhPQXV0aFRva2VuXCIsNCxkLCEwKTt2YXIgZT1uZXcgQjtxKGIpPyhxZyhcIkZpcmViYXNlLmF1dGhXaXRoT0F1dGhUb2tlblwiLDIsYiksZmgodGhpcy5rLk8sYStcIi90b2tlblwiLHthY2Nlc3NfdG9rZW46Yn0sZCxDKGUsYykpKTooc2coXCJGaXJlYmFzZS5hdXRoV2l0aE9BdXRoVG9rZW5cIiwyLGIsITEpLGZoKHRoaXMuay5PLGErXCIvdG9rZW5cIixiLGQsQyhlLGMpKSk7cmV0dXJuIGUuRH07WC5wcm90b3R5cGUuYXV0aFdpdGhPQXV0aFRva2VuPVgucHJvdG90eXBlLmtnO1xuWC5wcm90b3R5cGUuZ2c9ZnVuY3Rpb24oYSxiKXtEKFwiRmlyZWJhc2UuYXV0aEFub255bW91c2x5XCIsMCwyLGFyZ3VtZW50cy5sZW5ndGgpOzE9PT1hcmd1bWVudHMubGVuZ3RoJiZIYihhKSYmKGI9YSxhPXZvaWQgMCk7RihcIkZpcmViYXNlLmF1dGhBbm9ueW1vdXNseVwiLDEsYSwhMCk7c2coXCJGaXJlYmFzZS5hdXRoQW5vbnltb3VzbHlcIiwyLGIsITApO3ZhciBjPW5ldyBCO2ZoKHRoaXMuay5PLFwiYW5vbnltb3VzXCIse30sYixDKGMsYSkpO3JldHVybiBjLkR9O1gucHJvdG90eXBlLmF1dGhBbm9ueW1vdXNseT1YLnByb3RvdHlwZS5nZztcblgucHJvdG90eXBlLmxnPWZ1bmN0aW9uKGEsYixjKXtEKFwiRmlyZWJhc2UuYXV0aFdpdGhQYXNzd29yZFwiLDEsMyxhcmd1bWVudHMubGVuZ3RoKTsyPT09YXJndW1lbnRzLmxlbmd0aCYmSGIoYikmJihjPWIsYj12b2lkIDApO3NnKFwiRmlyZWJhc2UuYXV0aFdpdGhQYXNzd29yZFwiLDEsYSwhMSk7dGcoXCJGaXJlYmFzZS5hdXRoV2l0aFBhc3N3b3JkXCIsYSxcImVtYWlsXCIpO3RnKFwiRmlyZWJhc2UuYXV0aFdpdGhQYXNzd29yZFwiLGEsXCJwYXNzd29yZFwiKTtGKFwiRmlyZWJhc2UuYXV0aFdpdGhQYXNzd29yZFwiLDIsYiwhMCk7c2coXCJGaXJlYmFzZS5hdXRoV2l0aFBhc3N3b3JkXCIsMyxjLCEwKTt2YXIgZD1uZXcgQjtmaCh0aGlzLmsuTyxcInBhc3N3b3JkXCIsYSxjLEMoZCxiKSk7cmV0dXJuIGQuRH07WC5wcm90b3R5cGUuYXV0aFdpdGhQYXNzd29yZD1YLnByb3RvdHlwZS5sZztcblgucHJvdG90eXBlLnZlPWZ1bmN0aW9uKGEsYil7RChcIkZpcmViYXNlLmNyZWF0ZVVzZXJcIiwxLDIsYXJndW1lbnRzLmxlbmd0aCk7c2coXCJGaXJlYmFzZS5jcmVhdGVVc2VyXCIsMSxhLCExKTt0ZyhcIkZpcmViYXNlLmNyZWF0ZVVzZXJcIixhLFwiZW1haWxcIik7dGcoXCJGaXJlYmFzZS5jcmVhdGVVc2VyXCIsYSxcInBhc3N3b3JkXCIpO0YoXCJGaXJlYmFzZS5jcmVhdGVVc2VyXCIsMixiLCEwKTt2YXIgYz1uZXcgQjt0aGlzLmsuTy52ZShhLEMoYyxiKSk7cmV0dXJuIGMuRH07WC5wcm90b3R5cGUuY3JlYXRlVXNlcj1YLnByb3RvdHlwZS52ZTtcblgucHJvdG90eXBlLlhlPWZ1bmN0aW9uKGEsYil7RChcIkZpcmViYXNlLnJlbW92ZVVzZXJcIiwxLDIsYXJndW1lbnRzLmxlbmd0aCk7c2coXCJGaXJlYmFzZS5yZW1vdmVVc2VyXCIsMSxhLCExKTt0ZyhcIkZpcmViYXNlLnJlbW92ZVVzZXJcIixhLFwiZW1haWxcIik7dGcoXCJGaXJlYmFzZS5yZW1vdmVVc2VyXCIsYSxcInBhc3N3b3JkXCIpO0YoXCJGaXJlYmFzZS5yZW1vdmVVc2VyXCIsMixiLCEwKTt2YXIgYz1uZXcgQjt0aGlzLmsuTy5YZShhLEMoYyxiKSk7cmV0dXJuIGMuRH07WC5wcm90b3R5cGUucmVtb3ZlVXNlcj1YLnByb3RvdHlwZS5YZTtcblgucHJvdG90eXBlLnNlPWZ1bmN0aW9uKGEsYil7RChcIkZpcmViYXNlLmNoYW5nZVBhc3N3b3JkXCIsMSwyLGFyZ3VtZW50cy5sZW5ndGgpO3NnKFwiRmlyZWJhc2UuY2hhbmdlUGFzc3dvcmRcIiwxLGEsITEpO3RnKFwiRmlyZWJhc2UuY2hhbmdlUGFzc3dvcmRcIixhLFwiZW1haWxcIik7dGcoXCJGaXJlYmFzZS5jaGFuZ2VQYXNzd29yZFwiLGEsXCJvbGRQYXNzd29yZFwiKTt0ZyhcIkZpcmViYXNlLmNoYW5nZVBhc3N3b3JkXCIsYSxcIm5ld1Bhc3N3b3JkXCIpO0YoXCJGaXJlYmFzZS5jaGFuZ2VQYXNzd29yZFwiLDIsYiwhMCk7dmFyIGM9bmV3IEI7dGhpcy5rLk8uc2UoYSxDKGMsYikpO3JldHVybiBjLkR9O1gucHJvdG90eXBlLmNoYW5nZVBhc3N3b3JkPVgucHJvdG90eXBlLnNlO1xuWC5wcm90b3R5cGUucmU9ZnVuY3Rpb24oYSxiKXtEKFwiRmlyZWJhc2UuY2hhbmdlRW1haWxcIiwxLDIsYXJndW1lbnRzLmxlbmd0aCk7c2coXCJGaXJlYmFzZS5jaGFuZ2VFbWFpbFwiLDEsYSwhMSk7dGcoXCJGaXJlYmFzZS5jaGFuZ2VFbWFpbFwiLGEsXCJvbGRFbWFpbFwiKTt0ZyhcIkZpcmViYXNlLmNoYW5nZUVtYWlsXCIsYSxcIm5ld0VtYWlsXCIpO3RnKFwiRmlyZWJhc2UuY2hhbmdlRW1haWxcIixhLFwicGFzc3dvcmRcIik7RihcIkZpcmViYXNlLmNoYW5nZUVtYWlsXCIsMixiLCEwKTt2YXIgYz1uZXcgQjt0aGlzLmsuTy5yZShhLEMoYyxiKSk7cmV0dXJuIGMuRH07WC5wcm90b3R5cGUuY2hhbmdlRW1haWw9WC5wcm90b3R5cGUucmU7XG5YLnByb3RvdHlwZS5aZT1mdW5jdGlvbihhLGIpe0QoXCJGaXJlYmFzZS5yZXNldFBhc3N3b3JkXCIsMSwyLGFyZ3VtZW50cy5sZW5ndGgpO3NnKFwiRmlyZWJhc2UucmVzZXRQYXNzd29yZFwiLDEsYSwhMSk7dGcoXCJGaXJlYmFzZS5yZXNldFBhc3N3b3JkXCIsYSxcImVtYWlsXCIpO0YoXCJGaXJlYmFzZS5yZXNldFBhc3N3b3JkXCIsMixiLCEwKTt2YXIgYz1uZXcgQjt0aGlzLmsuTy5aZShhLEMoYyxiKSk7cmV0dXJuIGMuRH07WC5wcm90b3R5cGUucmVzZXRQYXNzd29yZD1YLnByb3RvdHlwZS5aZTt9KSgpO1xuXG5tb2R1bGUuZXhwb3J0cyA9IEZpcmViYXNlO1xuIiwiaWYgKHR5cGVvZiBPYmplY3QuY3JlYXRlID09PSAnZnVuY3Rpb24nKSB7XG4gIC8vIGltcGxlbWVudGF0aW9uIGZyb20gc3RhbmRhcmQgbm9kZS5qcyAndXRpbCcgbW9kdWxlXG4gIG1vZHVsZS5leHBvcnRzID0gZnVuY3Rpb24gaW5oZXJpdHMoY3Rvciwgc3VwZXJDdG9yKSB7XG4gICAgY3Rvci5zdXBlcl8gPSBzdXBlckN0b3JcbiAgICBjdG9yLnByb3RvdHlwZSA9IE9iamVjdC5jcmVhdGUoc3VwZXJDdG9yLnByb3RvdHlwZSwge1xuICAgICAgY29uc3RydWN0b3I6IHtcbiAgICAgICAgdmFsdWU6IGN0b3IsXG4gICAgICAgIGVudW1lcmFibGU6IGZhbHNlLFxuICAgICAgICB3cml0YWJsZTogdHJ1ZSxcbiAgICAgICAgY29uZmlndXJhYmxlOiB0cnVlXG4gICAgICB9XG4gICAgfSk7XG4gIH07XG59IGVsc2Uge1xuICAvLyBvbGQgc2Nob29sIHNoaW0gZm9yIG9sZCBicm93c2Vyc1xuICBtb2R1bGUuZXhwb3J0cyA9IGZ1bmN0aW9uIGluaGVyaXRzKGN0b3IsIHN1cGVyQ3Rvcikge1xuICAgIGN0b3Iuc3VwZXJfID0gc3VwZXJDdG9yXG4gICAgdmFyIFRlbXBDdG9yID0gZnVuY3Rpb24gKCkge31cbiAgICBUZW1wQ3Rvci5wcm90b3R5cGUgPSBzdXBlckN0b3IucHJvdG90eXBlXG4gICAgY3Rvci5wcm90b3R5cGUgPSBuZXcgVGVtcEN0b3IoKVxuICAgIGN0b3IucHJvdG90eXBlLmNvbnN0cnVjdG9yID0gY3RvclxuICB9XG59XG4iLCIndXNlIHN0cmljdCdcblxubW9kdWxlLmV4cG9ydHMgPSBMUlVDYWNoZVxuXG4vLyBUaGlzIHdpbGwgYmUgYSBwcm9wZXIgaXRlcmFibGUgJ01hcCcgaW4gZW5naW5lcyB0aGF0IHN1cHBvcnQgaXQsXG4vLyBvciBhIGZha2V5LWZha2UgUHNldWRvTWFwIGluIG9sZGVyIHZlcnNpb25zLlxudmFyIE1hcCA9IHJlcXVpcmUoJ3BzZXVkb21hcCcpXG52YXIgdXRpbCA9IHJlcXVpcmUoJ3V0aWwnKVxuXG4vLyBBIGxpbmtlZCBsaXN0IHRvIGtlZXAgdHJhY2sgb2YgcmVjZW50bHktdXNlZC1uZXNzXG52YXIgWWFsbGlzdCA9IHJlcXVpcmUoJ3lhbGxpc3QnKVxuXG4vLyB1c2Ugc3ltYm9scyBpZiBwb3NzaWJsZSwgb3RoZXJ3aXNlIGp1c3QgX3Byb3BzXG52YXIgaGFzU3ltYm9sID0gdHlwZW9mIFN5bWJvbCA9PT0gJ2Z1bmN0aW9uJ1xudmFyIG1ha2VTeW1ib2xcbmlmIChoYXNTeW1ib2wpIHtcbiAgbWFrZVN5bWJvbCA9IGZ1bmN0aW9uIChrZXkpIHtcbiAgICByZXR1cm4gU3ltYm9sKGtleSlcbiAgfVxufSBlbHNlIHtcbiAgbWFrZVN5bWJvbCA9IGZ1bmN0aW9uIChrZXkpIHtcbiAgICByZXR1cm4gJ18nICsga2V5XG4gIH1cbn1cblxudmFyIE1BWCA9IG1ha2VTeW1ib2woJ21heCcpXG52YXIgTEVOR1RIID0gbWFrZVN5bWJvbCgnbGVuZ3RoJylcbnZhciBMRU5HVEhfQ0FMQ1VMQVRPUiA9IG1ha2VTeW1ib2woJ2xlbmd0aENhbGN1bGF0b3InKVxudmFyIEFMTE9XX1NUQUxFID0gbWFrZVN5bWJvbCgnYWxsb3dTdGFsZScpXG52YXIgTUFYX0FHRSA9IG1ha2VTeW1ib2woJ21heEFnZScpXG52YXIgRElTUE9TRSA9IG1ha2VTeW1ib2woJ2Rpc3Bvc2UnKVxudmFyIE5PX0RJU1BPU0VfT05fU0VUID0gbWFrZVN5bWJvbCgnbm9EaXNwb3NlT25TZXQnKVxudmFyIExSVV9MSVNUID0gbWFrZVN5bWJvbCgnbHJ1TGlzdCcpXG52YXIgQ0FDSEUgPSBtYWtlU3ltYm9sKCdjYWNoZScpXG5cbmZ1bmN0aW9uIG5haXZlTGVuZ3RoICgpIHsgcmV0dXJuIDEgfVxuXG4vLyBscnVMaXN0IGlzIGEgeWFsbGlzdCB3aGVyZSB0aGUgaGVhZCBpcyB0aGUgeW91bmdlc3Rcbi8vIGl0ZW0sIGFuZCB0aGUgdGFpbCBpcyB0aGUgb2xkZXN0LiAgdGhlIGxpc3QgY29udGFpbnMgdGhlIEhpdFxuLy8gb2JqZWN0cyBhcyB0aGUgZW50cmllcy5cbi8vIEVhY2ggSGl0IG9iamVjdCBoYXMgYSByZWZlcmVuY2UgdG8gaXRzIFlhbGxpc3QuTm9kZS4gIFRoaXNcbi8vIG5ldmVyIGNoYW5nZXMuXG4vL1xuLy8gY2FjaGUgaXMgYSBNYXAgKG9yIFBzZXVkb01hcCkgdGhhdCBtYXRjaGVzIHRoZSBrZXlzIHRvXG4vLyB0aGUgWWFsbGlzdC5Ob2RlIG9iamVjdC5cbmZ1bmN0aW9uIExSVUNhY2hlIChvcHRpb25zKSB7XG4gIGlmICghKHRoaXMgaW5zdGFuY2VvZiBMUlVDYWNoZSkpIHtcbiAgICByZXR1cm4gbmV3IExSVUNhY2hlKG9wdGlvbnMpXG4gIH1cblxuICBpZiAodHlwZW9mIG9wdGlvbnMgPT09ICdudW1iZXInKSB7XG4gICAgb3B0aW9ucyA9IHsgbWF4OiBvcHRpb25zIH1cbiAgfVxuXG4gIGlmICghb3B0aW9ucykge1xuICAgIG9wdGlvbnMgPSB7fVxuICB9XG5cbiAgdmFyIG1heCA9IHRoaXNbTUFYXSA9IG9wdGlvbnMubWF4XG4gIC8vIEtpbmQgb2Ygd2VpcmQgdG8gaGF2ZSBhIGRlZmF1bHQgbWF4IG9mIEluZmluaXR5LCBidXQgb2ggd2VsbC5cbiAgaWYgKCFtYXggfHxcbiAgICAgICEodHlwZW9mIG1heCA9PT0gJ251bWJlcicpIHx8XG4gICAgICBtYXggPD0gMCkge1xuICAgIHRoaXNbTUFYXSA9IEluZmluaXR5XG4gIH1cblxuICB2YXIgbGMgPSBvcHRpb25zLmxlbmd0aCB8fCBuYWl2ZUxlbmd0aFxuICBpZiAodHlwZW9mIGxjICE9PSAnZnVuY3Rpb24nKSB7XG4gICAgbGMgPSBuYWl2ZUxlbmd0aFxuICB9XG4gIHRoaXNbTEVOR1RIX0NBTENVTEFUT1JdID0gbGNcblxuICB0aGlzW0FMTE9XX1NUQUxFXSA9IG9wdGlvbnMuc3RhbGUgfHwgZmFsc2VcbiAgdGhpc1tNQVhfQUdFXSA9IG9wdGlvbnMubWF4QWdlIHx8IDBcbiAgdGhpc1tESVNQT1NFXSA9IG9wdGlvbnMuZGlzcG9zZVxuICB0aGlzW05PX0RJU1BPU0VfT05fU0VUXSA9IG9wdGlvbnMubm9EaXNwb3NlT25TZXQgfHwgZmFsc2VcbiAgdGhpcy5yZXNldCgpXG59XG5cbi8vIHJlc2l6ZSB0aGUgY2FjaGUgd2hlbiB0aGUgbWF4IGNoYW5nZXMuXG5PYmplY3QuZGVmaW5lUHJvcGVydHkoTFJVQ2FjaGUucHJvdG90eXBlLCAnbWF4Jywge1xuICBzZXQ6IGZ1bmN0aW9uIChtTCkge1xuICAgIGlmICghbUwgfHwgISh0eXBlb2YgbUwgPT09ICdudW1iZXInKSB8fCBtTCA8PSAwKSB7XG4gICAgICBtTCA9IEluZmluaXR5XG4gICAgfVxuICAgIHRoaXNbTUFYXSA9IG1MXG4gICAgdHJpbSh0aGlzKVxuICB9LFxuICBnZXQ6IGZ1bmN0aW9uICgpIHtcbiAgICByZXR1cm4gdGhpc1tNQVhdXG4gIH0sXG4gIGVudW1lcmFibGU6IHRydWVcbn0pXG5cbk9iamVjdC5kZWZpbmVQcm9wZXJ0eShMUlVDYWNoZS5wcm90b3R5cGUsICdhbGxvd1N0YWxlJywge1xuICBzZXQ6IGZ1bmN0aW9uIChhbGxvd1N0YWxlKSB7XG4gICAgdGhpc1tBTExPV19TVEFMRV0gPSAhIWFsbG93U3RhbGVcbiAgfSxcbiAgZ2V0OiBmdW5jdGlvbiAoKSB7XG4gICAgcmV0dXJuIHRoaXNbQUxMT1dfU1RBTEVdXG4gIH0sXG4gIGVudW1lcmFibGU6IHRydWVcbn0pXG5cbk9iamVjdC5kZWZpbmVQcm9wZXJ0eShMUlVDYWNoZS5wcm90b3R5cGUsICdtYXhBZ2UnLCB7XG4gIHNldDogZnVuY3Rpb24gKG1BKSB7XG4gICAgaWYgKCFtQSB8fCAhKHR5cGVvZiBtQSA9PT0gJ251bWJlcicpIHx8IG1BIDwgMCkge1xuICAgICAgbUEgPSAwXG4gICAgfVxuICAgIHRoaXNbTUFYX0FHRV0gPSBtQVxuICAgIHRyaW0odGhpcylcbiAgfSxcbiAgZ2V0OiBmdW5jdGlvbiAoKSB7XG4gICAgcmV0dXJuIHRoaXNbTUFYX0FHRV1cbiAgfSxcbiAgZW51bWVyYWJsZTogdHJ1ZVxufSlcblxuLy8gcmVzaXplIHRoZSBjYWNoZSB3aGVuIHRoZSBsZW5ndGhDYWxjdWxhdG9yIGNoYW5nZXMuXG5PYmplY3QuZGVmaW5lUHJvcGVydHkoTFJVQ2FjaGUucHJvdG90eXBlLCAnbGVuZ3RoQ2FsY3VsYXRvcicsIHtcbiAgc2V0OiBmdW5jdGlvbiAobEMpIHtcbiAgICBpZiAodHlwZW9mIGxDICE9PSAnZnVuY3Rpb24nKSB7XG4gICAgICBsQyA9IG5haXZlTGVuZ3RoXG4gICAgfVxuICAgIGlmIChsQyAhPT0gdGhpc1tMRU5HVEhfQ0FMQ1VMQVRPUl0pIHtcbiAgICAgIHRoaXNbTEVOR1RIX0NBTENVTEFUT1JdID0gbENcbiAgICAgIHRoaXNbTEVOR1RIXSA9IDBcbiAgICAgIHRoaXNbTFJVX0xJU1RdLmZvckVhY2goZnVuY3Rpb24gKGhpdCkge1xuICAgICAgICBoaXQubGVuZ3RoID0gdGhpc1tMRU5HVEhfQ0FMQ1VMQVRPUl0oaGl0LnZhbHVlLCBoaXQua2V5KVxuICAgICAgICB0aGlzW0xFTkdUSF0gKz0gaGl0Lmxlbmd0aFxuICAgICAgfSwgdGhpcylcbiAgICB9XG4gICAgdHJpbSh0aGlzKVxuICB9LFxuICBnZXQ6IGZ1bmN0aW9uICgpIHsgcmV0dXJuIHRoaXNbTEVOR1RIX0NBTENVTEFUT1JdIH0sXG4gIGVudW1lcmFibGU6IHRydWVcbn0pXG5cbk9iamVjdC5kZWZpbmVQcm9wZXJ0eShMUlVDYWNoZS5wcm90b3R5cGUsICdsZW5ndGgnLCB7XG4gIGdldDogZnVuY3Rpb24gKCkgeyByZXR1cm4gdGhpc1tMRU5HVEhdIH0sXG4gIGVudW1lcmFibGU6IHRydWVcbn0pXG5cbk9iamVjdC5kZWZpbmVQcm9wZXJ0eShMUlVDYWNoZS5wcm90b3R5cGUsICdpdGVtQ291bnQnLCB7XG4gIGdldDogZnVuY3Rpb24gKCkgeyByZXR1cm4gdGhpc1tMUlVfTElTVF0ubGVuZ3RoIH0sXG4gIGVudW1lcmFibGU6IHRydWVcbn0pXG5cbkxSVUNhY2hlLnByb3RvdHlwZS5yZm9yRWFjaCA9IGZ1bmN0aW9uIChmbiwgdGhpc3ApIHtcbiAgdGhpc3AgPSB0aGlzcCB8fCB0aGlzXG4gIGZvciAodmFyIHdhbGtlciA9IHRoaXNbTFJVX0xJU1RdLnRhaWw7IHdhbGtlciAhPT0gbnVsbDspIHtcbiAgICB2YXIgcHJldiA9IHdhbGtlci5wcmV2XG4gICAgZm9yRWFjaFN0ZXAodGhpcywgZm4sIHdhbGtlciwgdGhpc3ApXG4gICAgd2Fsa2VyID0gcHJldlxuICB9XG59XG5cbmZ1bmN0aW9uIGZvckVhY2hTdGVwIChzZWxmLCBmbiwgbm9kZSwgdGhpc3ApIHtcbiAgdmFyIGhpdCA9IG5vZGUudmFsdWVcbiAgaWYgKGlzU3RhbGUoc2VsZiwgaGl0KSkge1xuICAgIGRlbChzZWxmLCBub2RlKVxuICAgIGlmICghc2VsZltBTExPV19TVEFMRV0pIHtcbiAgICAgIGhpdCA9IHVuZGVmaW5lZFxuICAgIH1cbiAgfVxuICBpZiAoaGl0KSB7XG4gICAgZm4uY2FsbCh0aGlzcCwgaGl0LnZhbHVlLCBoaXQua2V5LCBzZWxmKVxuICB9XG59XG5cbkxSVUNhY2hlLnByb3RvdHlwZS5mb3JFYWNoID0gZnVuY3Rpb24gKGZuLCB0aGlzcCkge1xuICB0aGlzcCA9IHRoaXNwIHx8IHRoaXNcbiAgZm9yICh2YXIgd2Fsa2VyID0gdGhpc1tMUlVfTElTVF0uaGVhZDsgd2Fsa2VyICE9PSBudWxsOykge1xuICAgIHZhciBuZXh0ID0gd2Fsa2VyLm5leHRcbiAgICBmb3JFYWNoU3RlcCh0aGlzLCBmbiwgd2Fsa2VyLCB0aGlzcClcbiAgICB3YWxrZXIgPSBuZXh0XG4gIH1cbn1cblxuTFJVQ2FjaGUucHJvdG90eXBlLmtleXMgPSBmdW5jdGlvbiAoKSB7XG4gIHJldHVybiB0aGlzW0xSVV9MSVNUXS50b0FycmF5KCkubWFwKGZ1bmN0aW9uIChrKSB7XG4gICAgcmV0dXJuIGsua2V5XG4gIH0sIHRoaXMpXG59XG5cbkxSVUNhY2hlLnByb3RvdHlwZS52YWx1ZXMgPSBmdW5jdGlvbiAoKSB7XG4gIHJldHVybiB0aGlzW0xSVV9MSVNUXS50b0FycmF5KCkubWFwKGZ1bmN0aW9uIChrKSB7XG4gICAgcmV0dXJuIGsudmFsdWVcbiAgfSwgdGhpcylcbn1cblxuTFJVQ2FjaGUucHJvdG90eXBlLnJlc2V0ID0gZnVuY3Rpb24gKCkge1xuICBpZiAodGhpc1tESVNQT1NFXSAmJlxuICAgICAgdGhpc1tMUlVfTElTVF0gJiZcbiAgICAgIHRoaXNbTFJVX0xJU1RdLmxlbmd0aCkge1xuICAgIHRoaXNbTFJVX0xJU1RdLmZvckVhY2goZnVuY3Rpb24gKGhpdCkge1xuICAgICAgdGhpc1tESVNQT1NFXShoaXQua2V5LCBoaXQudmFsdWUpXG4gICAgfSwgdGhpcylcbiAgfVxuXG4gIHRoaXNbQ0FDSEVdID0gbmV3IE1hcCgpIC8vIGhhc2ggb2YgaXRlbXMgYnkga2V5XG4gIHRoaXNbTFJVX0xJU1RdID0gbmV3IFlhbGxpc3QoKSAvLyBsaXN0IG9mIGl0ZW1zIGluIG9yZGVyIG9mIHVzZSByZWNlbmN5XG4gIHRoaXNbTEVOR1RIXSA9IDAgLy8gbGVuZ3RoIG9mIGl0ZW1zIGluIHRoZSBsaXN0XG59XG5cbkxSVUNhY2hlLnByb3RvdHlwZS5kdW1wID0gZnVuY3Rpb24gKCkge1xuICByZXR1cm4gdGhpc1tMUlVfTElTVF0ubWFwKGZ1bmN0aW9uIChoaXQpIHtcbiAgICBpZiAoIWlzU3RhbGUodGhpcywgaGl0KSkge1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgazogaGl0LmtleSxcbiAgICAgICAgdjogaGl0LnZhbHVlLFxuICAgICAgICBlOiBoaXQubm93ICsgKGhpdC5tYXhBZ2UgfHwgMClcbiAgICAgIH1cbiAgICB9XG4gIH0sIHRoaXMpLnRvQXJyYXkoKS5maWx0ZXIoZnVuY3Rpb24gKGgpIHtcbiAgICByZXR1cm4gaFxuICB9KVxufVxuXG5MUlVDYWNoZS5wcm90b3R5cGUuZHVtcExydSA9IGZ1bmN0aW9uICgpIHtcbiAgcmV0dXJuIHRoaXNbTFJVX0xJU1RdXG59XG5cbkxSVUNhY2hlLnByb3RvdHlwZS5pbnNwZWN0ID0gZnVuY3Rpb24gKG4sIG9wdHMpIHtcbiAgdmFyIHN0ciA9ICdMUlVDYWNoZSB7J1xuICB2YXIgZXh0cmFzID0gZmFsc2VcblxuICB2YXIgYXMgPSB0aGlzW0FMTE9XX1NUQUxFXVxuICBpZiAoYXMpIHtcbiAgICBzdHIgKz0gJ1xcbiAgYWxsb3dTdGFsZTogdHJ1ZSdcbiAgICBleHRyYXMgPSB0cnVlXG4gIH1cblxuICB2YXIgbWF4ID0gdGhpc1tNQVhdXG4gIGlmIChtYXggJiYgbWF4ICE9PSBJbmZpbml0eSkge1xuICAgIGlmIChleHRyYXMpIHtcbiAgICAgIHN0ciArPSAnLCdcbiAgICB9XG4gICAgc3RyICs9ICdcXG4gIG1heDogJyArIHV0aWwuaW5zcGVjdChtYXgsIG9wdHMpXG4gICAgZXh0cmFzID0gdHJ1ZVxuICB9XG5cbiAgdmFyIG1heEFnZSA9IHRoaXNbTUFYX0FHRV1cbiAgaWYgKG1heEFnZSkge1xuICAgIGlmIChleHRyYXMpIHtcbiAgICAgIHN0ciArPSAnLCdcbiAgICB9XG4gICAgc3RyICs9ICdcXG4gIG1heEFnZTogJyArIHV0aWwuaW5zcGVjdChtYXhBZ2UsIG9wdHMpXG4gICAgZXh0cmFzID0gdHJ1ZVxuICB9XG5cbiAgdmFyIGxjID0gdGhpc1tMRU5HVEhfQ0FMQ1VMQVRPUl1cbiAgaWYgKGxjICYmIGxjICE9PSBuYWl2ZUxlbmd0aCkge1xuICAgIGlmIChleHRyYXMpIHtcbiAgICAgIHN0ciArPSAnLCdcbiAgICB9XG4gICAgc3RyICs9ICdcXG4gIGxlbmd0aDogJyArIHV0aWwuaW5zcGVjdCh0aGlzW0xFTkdUSF0sIG9wdHMpXG4gICAgZXh0cmFzID0gdHJ1ZVxuICB9XG5cbiAgdmFyIGRpZEZpcnN0ID0gZmFsc2VcbiAgdGhpc1tMUlVfTElTVF0uZm9yRWFjaChmdW5jdGlvbiAoaXRlbSkge1xuICAgIGlmIChkaWRGaXJzdCkge1xuICAgICAgc3RyICs9ICcsXFxuICAnXG4gICAgfSBlbHNlIHtcbiAgICAgIGlmIChleHRyYXMpIHtcbiAgICAgICAgc3RyICs9ICcsXFxuJ1xuICAgICAgfVxuICAgICAgZGlkRmlyc3QgPSB0cnVlXG4gICAgICBzdHIgKz0gJ1xcbiAgJ1xuICAgIH1cbiAgICB2YXIga2V5ID0gdXRpbC5pbnNwZWN0KGl0ZW0ua2V5KS5zcGxpdCgnXFxuJykuam9pbignXFxuICAnKVxuICAgIHZhciB2YWwgPSB7IHZhbHVlOiBpdGVtLnZhbHVlIH1cbiAgICBpZiAoaXRlbS5tYXhBZ2UgIT09IG1heEFnZSkge1xuICAgICAgdmFsLm1heEFnZSA9IGl0ZW0ubWF4QWdlXG4gICAgfVxuICAgIGlmIChsYyAhPT0gbmFpdmVMZW5ndGgpIHtcbiAgICAgIHZhbC5sZW5ndGggPSBpdGVtLmxlbmd0aFxuICAgIH1cbiAgICBpZiAoaXNTdGFsZSh0aGlzLCBpdGVtKSkge1xuICAgICAgdmFsLnN0YWxlID0gdHJ1ZVxuICAgIH1cblxuICAgIHZhbCA9IHV0aWwuaW5zcGVjdCh2YWwsIG9wdHMpLnNwbGl0KCdcXG4nKS5qb2luKCdcXG4gICcpXG4gICAgc3RyICs9IGtleSArICcgPT4gJyArIHZhbFxuICB9KVxuXG4gIGlmIChkaWRGaXJzdCB8fCBleHRyYXMpIHtcbiAgICBzdHIgKz0gJ1xcbidcbiAgfVxuICBzdHIgKz0gJ30nXG5cbiAgcmV0dXJuIHN0clxufVxuXG5MUlVDYWNoZS5wcm90b3R5cGUuc2V0ID0gZnVuY3Rpb24gKGtleSwgdmFsdWUsIG1heEFnZSkge1xuICBtYXhBZ2UgPSBtYXhBZ2UgfHwgdGhpc1tNQVhfQUdFXVxuXG4gIHZhciBub3cgPSBtYXhBZ2UgPyBEYXRlLm5vdygpIDogMFxuICB2YXIgbGVuID0gdGhpc1tMRU5HVEhfQ0FMQ1VMQVRPUl0odmFsdWUsIGtleSlcblxuICBpZiAodGhpc1tDQUNIRV0uaGFzKGtleSkpIHtcbiAgICBpZiAobGVuID4gdGhpc1tNQVhdKSB7XG4gICAgICBkZWwodGhpcywgdGhpc1tDQUNIRV0uZ2V0KGtleSkpXG4gICAgICByZXR1cm4gZmFsc2VcbiAgICB9XG5cbiAgICB2YXIgbm9kZSA9IHRoaXNbQ0FDSEVdLmdldChrZXkpXG4gICAgdmFyIGl0ZW0gPSBub2RlLnZhbHVlXG5cbiAgICAvLyBkaXNwb3NlIG9mIHRoZSBvbGQgb25lIGJlZm9yZSBvdmVyd3JpdGluZ1xuICAgIC8vIHNwbGl0IG91dCBpbnRvIDIgaWZzIGZvciBiZXR0ZXIgY292ZXJhZ2UgdHJhY2tpbmdcbiAgICBpZiAodGhpc1tESVNQT1NFXSkge1xuICAgICAgaWYgKCF0aGlzW05PX0RJU1BPU0VfT05fU0VUXSkge1xuICAgICAgICB0aGlzW0RJU1BPU0VdKGtleSwgaXRlbS52YWx1ZSlcbiAgICAgIH1cbiAgICB9XG5cbiAgICBpdGVtLm5vdyA9IG5vd1xuICAgIGl0ZW0ubWF4QWdlID0gbWF4QWdlXG4gICAgaXRlbS52YWx1ZSA9IHZhbHVlXG4gICAgdGhpc1tMRU5HVEhdICs9IGxlbiAtIGl0ZW0ubGVuZ3RoXG4gICAgaXRlbS5sZW5ndGggPSBsZW5cbiAgICB0aGlzLmdldChrZXkpXG4gICAgdHJpbSh0aGlzKVxuICAgIHJldHVybiB0cnVlXG4gIH1cblxuICB2YXIgaGl0ID0gbmV3IEVudHJ5KGtleSwgdmFsdWUsIGxlbiwgbm93LCBtYXhBZ2UpXG5cbiAgLy8gb3ZlcnNpemVkIG9iamVjdHMgZmFsbCBvdXQgb2YgY2FjaGUgYXV0b21hdGljYWxseS5cbiAgaWYgKGhpdC5sZW5ndGggPiB0aGlzW01BWF0pIHtcbiAgICBpZiAodGhpc1tESVNQT1NFXSkge1xuICAgICAgdGhpc1tESVNQT1NFXShrZXksIHZhbHVlKVxuICAgIH1cbiAgICByZXR1cm4gZmFsc2VcbiAgfVxuXG4gIHRoaXNbTEVOR1RIXSArPSBoaXQubGVuZ3RoXG4gIHRoaXNbTFJVX0xJU1RdLnVuc2hpZnQoaGl0KVxuICB0aGlzW0NBQ0hFXS5zZXQoa2V5LCB0aGlzW0xSVV9MSVNUXS5oZWFkKVxuICB0cmltKHRoaXMpXG4gIHJldHVybiB0cnVlXG59XG5cbkxSVUNhY2hlLnByb3RvdHlwZS5oYXMgPSBmdW5jdGlvbiAoa2V5KSB7XG4gIGlmICghdGhpc1tDQUNIRV0uaGFzKGtleSkpIHJldHVybiBmYWxzZVxuICB2YXIgaGl0ID0gdGhpc1tDQUNIRV0uZ2V0KGtleSkudmFsdWVcbiAgaWYgKGlzU3RhbGUodGhpcywgaGl0KSkge1xuICAgIHJldHVybiBmYWxzZVxuICB9XG4gIHJldHVybiB0cnVlXG59XG5cbkxSVUNhY2hlLnByb3RvdHlwZS5nZXQgPSBmdW5jdGlvbiAoa2V5KSB7XG4gIHJldHVybiBnZXQodGhpcywga2V5LCB0cnVlKVxufVxuXG5MUlVDYWNoZS5wcm90b3R5cGUucGVlayA9IGZ1bmN0aW9uIChrZXkpIHtcbiAgcmV0dXJuIGdldCh0aGlzLCBrZXksIGZhbHNlKVxufVxuXG5MUlVDYWNoZS5wcm90b3R5cGUucG9wID0gZnVuY3Rpb24gKCkge1xuICB2YXIgbm9kZSA9IHRoaXNbTFJVX0xJU1RdLnRhaWxcbiAgaWYgKCFub2RlKSByZXR1cm4gbnVsbFxuICBkZWwodGhpcywgbm9kZSlcbiAgcmV0dXJuIG5vZGUudmFsdWVcbn1cblxuTFJVQ2FjaGUucHJvdG90eXBlLmRlbCA9IGZ1bmN0aW9uIChrZXkpIHtcbiAgZGVsKHRoaXMsIHRoaXNbQ0FDSEVdLmdldChrZXkpKVxufVxuXG5MUlVDYWNoZS5wcm90b3R5cGUubG9hZCA9IGZ1bmN0aW9uIChhcnIpIHtcbiAgLy8gcmVzZXQgdGhlIGNhY2hlXG4gIHRoaXMucmVzZXQoKVxuXG4gIHZhciBub3cgPSBEYXRlLm5vdygpXG4gIC8vIEEgcHJldmlvdXMgc2VyaWFsaXplZCBjYWNoZSBoYXMgdGhlIG1vc3QgcmVjZW50IGl0ZW1zIGZpcnN0XG4gIGZvciAodmFyIGwgPSBhcnIubGVuZ3RoIC0gMTsgbCA+PSAwOyBsLS0pIHtcbiAgICB2YXIgaGl0ID0gYXJyW2xdXG4gICAgdmFyIGV4cGlyZXNBdCA9IGhpdC5lIHx8IDBcbiAgICBpZiAoZXhwaXJlc0F0ID09PSAwKSB7XG4gICAgICAvLyB0aGUgaXRlbSB3YXMgY3JlYXRlZCB3aXRob3V0IGV4cGlyYXRpb24gaW4gYSBub24gYWdlZCBjYWNoZVxuICAgICAgdGhpcy5zZXQoaGl0LmssIGhpdC52KVxuICAgIH0gZWxzZSB7XG4gICAgICB2YXIgbWF4QWdlID0gZXhwaXJlc0F0IC0gbm93XG4gICAgICAvLyBkb250IGFkZCBhbHJlYWR5IGV4cGlyZWQgaXRlbXNcbiAgICAgIGlmIChtYXhBZ2UgPiAwKSB7XG4gICAgICAgIHRoaXMuc2V0KGhpdC5rLCBoaXQudiwgbWF4QWdlKVxuICAgICAgfVxuICAgIH1cbiAgfVxufVxuXG5MUlVDYWNoZS5wcm90b3R5cGUucHJ1bmUgPSBmdW5jdGlvbiAoKSB7XG4gIHZhciBzZWxmID0gdGhpc1xuICB0aGlzW0NBQ0hFXS5mb3JFYWNoKGZ1bmN0aW9uICh2YWx1ZSwga2V5KSB7XG4gICAgZ2V0KHNlbGYsIGtleSwgZmFsc2UpXG4gIH0pXG59XG5cbmZ1bmN0aW9uIGdldCAoc2VsZiwga2V5LCBkb1VzZSkge1xuICB2YXIgbm9kZSA9IHNlbGZbQ0FDSEVdLmdldChrZXkpXG4gIGlmIChub2RlKSB7XG4gICAgdmFyIGhpdCA9IG5vZGUudmFsdWVcbiAgICBpZiAoaXNTdGFsZShzZWxmLCBoaXQpKSB7XG4gICAgICBkZWwoc2VsZiwgbm9kZSlcbiAgICAgIGlmICghc2VsZltBTExPV19TVEFMRV0pIGhpdCA9IHVuZGVmaW5lZFxuICAgIH0gZWxzZSB7XG4gICAgICBpZiAoZG9Vc2UpIHtcbiAgICAgICAgc2VsZltMUlVfTElTVF0udW5zaGlmdE5vZGUobm9kZSlcbiAgICAgIH1cbiAgICB9XG4gICAgaWYgKGhpdCkgaGl0ID0gaGl0LnZhbHVlXG4gIH1cbiAgcmV0dXJuIGhpdFxufVxuXG5mdW5jdGlvbiBpc1N0YWxlIChzZWxmLCBoaXQpIHtcbiAgaWYgKCFoaXQgfHwgKCFoaXQubWF4QWdlICYmICFzZWxmW01BWF9BR0VdKSkge1xuICAgIHJldHVybiBmYWxzZVxuICB9XG4gIHZhciBzdGFsZSA9IGZhbHNlXG4gIHZhciBkaWZmID0gRGF0ZS5ub3coKSAtIGhpdC5ub3dcbiAgaWYgKGhpdC5tYXhBZ2UpIHtcbiAgICBzdGFsZSA9IGRpZmYgPiBoaXQubWF4QWdlXG4gIH0gZWxzZSB7XG4gICAgc3RhbGUgPSBzZWxmW01BWF9BR0VdICYmIChkaWZmID4gc2VsZltNQVhfQUdFXSlcbiAgfVxuICByZXR1cm4gc3RhbGVcbn1cblxuZnVuY3Rpb24gdHJpbSAoc2VsZikge1xuICBpZiAoc2VsZltMRU5HVEhdID4gc2VsZltNQVhdKSB7XG4gICAgZm9yICh2YXIgd2Fsa2VyID0gc2VsZltMUlVfTElTVF0udGFpbDtcbiAgICAgICAgIHNlbGZbTEVOR1RIXSA+IHNlbGZbTUFYXSAmJiB3YWxrZXIgIT09IG51bGw7KSB7XG4gICAgICAvLyBXZSBrbm93IHRoYXQgd2UncmUgYWJvdXQgdG8gZGVsZXRlIHRoaXMgb25lLCBhbmQgYWxzb1xuICAgICAgLy8gd2hhdCB0aGUgbmV4dCBsZWFzdCByZWNlbnRseSB1c2VkIGtleSB3aWxsIGJlLCBzbyBqdXN0XG4gICAgICAvLyBnbyBhaGVhZCBhbmQgc2V0IGl0IG5vdy5cbiAgICAgIHZhciBwcmV2ID0gd2Fsa2VyLnByZXZcbiAgICAgIGRlbChzZWxmLCB3YWxrZXIpXG4gICAgICB3YWxrZXIgPSBwcmV2XG4gICAgfVxuICB9XG59XG5cbmZ1bmN0aW9uIGRlbCAoc2VsZiwgbm9kZSkge1xuICBpZiAobm9kZSkge1xuICAgIHZhciBoaXQgPSBub2RlLnZhbHVlXG4gICAgaWYgKHNlbGZbRElTUE9TRV0pIHtcbiAgICAgIHNlbGZbRElTUE9TRV0oaGl0LmtleSwgaGl0LnZhbHVlKVxuICAgIH1cbiAgICBzZWxmW0xFTkdUSF0gLT0gaGl0Lmxlbmd0aFxuICAgIHNlbGZbQ0FDSEVdLmRlbGV0ZShoaXQua2V5KVxuICAgIHNlbGZbTFJVX0xJU1RdLnJlbW92ZU5vZGUobm9kZSlcbiAgfVxufVxuXG4vLyBjbGFzc3ksIHNpbmNlIFY4IHByZWZlcnMgcHJlZGljdGFibGUgb2JqZWN0cy5cbmZ1bmN0aW9uIEVudHJ5IChrZXksIHZhbHVlLCBsZW5ndGgsIG5vdywgbWF4QWdlKSB7XG4gIHRoaXMua2V5ID0ga2V5XG4gIHRoaXMudmFsdWUgPSB2YWx1ZVxuICB0aGlzLmxlbmd0aCA9IGxlbmd0aFxuICB0aGlzLm5vdyA9IG5vd1xuICB0aGlzLm1heEFnZSA9IG1heEFnZSB8fCAwXG59XG4iLCIvLyBzaGltIGZvciB1c2luZyBwcm9jZXNzIGluIGJyb3dzZXJcbnZhciBwcm9jZXNzID0gbW9kdWxlLmV4cG9ydHMgPSB7fTtcblxuLy8gY2FjaGVkIGZyb20gd2hhdGV2ZXIgZ2xvYmFsIGlzIHByZXNlbnQgc28gdGhhdCB0ZXN0IHJ1bm5lcnMgdGhhdCBzdHViIGl0XG4vLyBkb24ndCBicmVhayB0aGluZ3MuICBCdXQgd2UgbmVlZCB0byB3cmFwIGl0IGluIGEgdHJ5IGNhdGNoIGluIGNhc2UgaXQgaXNcbi8vIHdyYXBwZWQgaW4gc3RyaWN0IG1vZGUgY29kZSB3aGljaCBkb2Vzbid0IGRlZmluZSBhbnkgZ2xvYmFscy4gIEl0J3MgaW5zaWRlIGFcbi8vIGZ1bmN0aW9uIGJlY2F1c2UgdHJ5L2NhdGNoZXMgZGVvcHRpbWl6ZSBpbiBjZXJ0YWluIGVuZ2luZXMuXG5cbnZhciBjYWNoZWRTZXRUaW1lb3V0O1xudmFyIGNhY2hlZENsZWFyVGltZW91dDtcblxuZnVuY3Rpb24gZGVmYXVsdFNldFRpbW91dCgpIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoJ3NldFRpbWVvdXQgaGFzIG5vdCBiZWVuIGRlZmluZWQnKTtcbn1cbmZ1bmN0aW9uIGRlZmF1bHRDbGVhclRpbWVvdXQgKCkge1xuICAgIHRocm93IG5ldyBFcnJvcignY2xlYXJUaW1lb3V0IGhhcyBub3QgYmVlbiBkZWZpbmVkJyk7XG59XG4oZnVuY3Rpb24gKCkge1xuICAgIHRyeSB7XG4gICAgICAgIGlmICh0eXBlb2Ygc2V0VGltZW91dCA9PT0gJ2Z1bmN0aW9uJykge1xuICAgICAgICAgICAgY2FjaGVkU2V0VGltZW91dCA9IHNldFRpbWVvdXQ7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBjYWNoZWRTZXRUaW1lb3V0ID0gZGVmYXVsdFNldFRpbW91dDtcbiAgICAgICAgfVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgY2FjaGVkU2V0VGltZW91dCA9IGRlZmF1bHRTZXRUaW1vdXQ7XG4gICAgfVxuICAgIHRyeSB7XG4gICAgICAgIGlmICh0eXBlb2YgY2xlYXJUaW1lb3V0ID09PSAnZnVuY3Rpb24nKSB7XG4gICAgICAgICAgICBjYWNoZWRDbGVhclRpbWVvdXQgPSBjbGVhclRpbWVvdXQ7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBjYWNoZWRDbGVhclRpbWVvdXQgPSBkZWZhdWx0Q2xlYXJUaW1lb3V0O1xuICAgICAgICB9XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgICBjYWNoZWRDbGVhclRpbWVvdXQgPSBkZWZhdWx0Q2xlYXJUaW1lb3V0O1xuICAgIH1cbn0gKCkpXG5mdW5jdGlvbiBydW5UaW1lb3V0KGZ1bikge1xuICAgIGlmIChjYWNoZWRTZXRUaW1lb3V0ID09PSBzZXRUaW1lb3V0KSB7XG4gICAgICAgIC8vbm9ybWFsIGVudmlyb21lbnRzIGluIHNhbmUgc2l0dWF0aW9uc1xuICAgICAgICByZXR1cm4gc2V0VGltZW91dChmdW4sIDApO1xuICAgIH1cbiAgICAvLyBpZiBzZXRUaW1lb3V0IHdhc24ndCBhdmFpbGFibGUgYnV0IHdhcyBsYXR0ZXIgZGVmaW5lZFxuICAgIGlmICgoY2FjaGVkU2V0VGltZW91dCA9PT0gZGVmYXVsdFNldFRpbW91dCB8fCAhY2FjaGVkU2V0VGltZW91dCkgJiYgc2V0VGltZW91dCkge1xuICAgICAgICBjYWNoZWRTZXRUaW1lb3V0ID0gc2V0VGltZW91dDtcbiAgICAgICAgcmV0dXJuIHNldFRpbWVvdXQoZnVuLCAwKTtcbiAgICB9XG4gICAgdHJ5IHtcbiAgICAgICAgLy8gd2hlbiB3aGVuIHNvbWVib2R5IGhhcyBzY3Jld2VkIHdpdGggc2V0VGltZW91dCBidXQgbm8gSS5FLiBtYWRkbmVzc1xuICAgICAgICByZXR1cm4gY2FjaGVkU2V0VGltZW91dChmdW4sIDApO1xuICAgIH0gY2F0Y2goZSl7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICAvLyBXaGVuIHdlIGFyZSBpbiBJLkUuIGJ1dCB0aGUgc2NyaXB0IGhhcyBiZWVuIGV2YWxlZCBzbyBJLkUuIGRvZXNuJ3QgdHJ1c3QgdGhlIGdsb2JhbCBvYmplY3Qgd2hlbiBjYWxsZWQgbm9ybWFsbHlcbiAgICAgICAgICAgIHJldHVybiBjYWNoZWRTZXRUaW1lb3V0LmNhbGwobnVsbCwgZnVuLCAwKTtcbiAgICAgICAgfSBjYXRjaChlKXtcbiAgICAgICAgICAgIC8vIHNhbWUgYXMgYWJvdmUgYnV0IHdoZW4gaXQncyBhIHZlcnNpb24gb2YgSS5FLiB0aGF0IG11c3QgaGF2ZSB0aGUgZ2xvYmFsIG9iamVjdCBmb3IgJ3RoaXMnLCBob3BmdWxseSBvdXIgY29udGV4dCBjb3JyZWN0IG90aGVyd2lzZSBpdCB3aWxsIHRocm93IGEgZ2xvYmFsIGVycm9yXG4gICAgICAgICAgICByZXR1cm4gY2FjaGVkU2V0VGltZW91dC5jYWxsKHRoaXMsIGZ1biwgMCk7XG4gICAgICAgIH1cbiAgICB9XG5cblxufVxuZnVuY3Rpb24gcnVuQ2xlYXJUaW1lb3V0KG1hcmtlcikge1xuICAgIGlmIChjYWNoZWRDbGVhclRpbWVvdXQgPT09IGNsZWFyVGltZW91dCkge1xuICAgICAgICAvL25vcm1hbCBlbnZpcm9tZW50cyBpbiBzYW5lIHNpdHVhdGlvbnNcbiAgICAgICAgcmV0dXJuIGNsZWFyVGltZW91dChtYXJrZXIpO1xuICAgIH1cbiAgICAvLyBpZiBjbGVhclRpbWVvdXQgd2Fzbid0IGF2YWlsYWJsZSBidXQgd2FzIGxhdHRlciBkZWZpbmVkXG4gICAgaWYgKChjYWNoZWRDbGVhclRpbWVvdXQgPT09IGRlZmF1bHRDbGVhclRpbWVvdXQgfHwgIWNhY2hlZENsZWFyVGltZW91dCkgJiYgY2xlYXJUaW1lb3V0KSB7XG4gICAgICAgIGNhY2hlZENsZWFyVGltZW91dCA9IGNsZWFyVGltZW91dDtcbiAgICAgICAgcmV0dXJuIGNsZWFyVGltZW91dChtYXJrZXIpO1xuICAgIH1cbiAgICB0cnkge1xuICAgICAgICAvLyB3aGVuIHdoZW4gc29tZWJvZHkgaGFzIHNjcmV3ZWQgd2l0aCBzZXRUaW1lb3V0IGJ1dCBubyBJLkUuIG1hZGRuZXNzXG4gICAgICAgIHJldHVybiBjYWNoZWRDbGVhclRpbWVvdXQobWFya2VyKTtcbiAgICB9IGNhdGNoIChlKXtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIC8vIFdoZW4gd2UgYXJlIGluIEkuRS4gYnV0IHRoZSBzY3JpcHQgaGFzIGJlZW4gZXZhbGVkIHNvIEkuRS4gZG9lc24ndCAgdHJ1c3QgdGhlIGdsb2JhbCBvYmplY3Qgd2hlbiBjYWxsZWQgbm9ybWFsbHlcbiAgICAgICAgICAgIHJldHVybiBjYWNoZWRDbGVhclRpbWVvdXQuY2FsbChudWxsLCBtYXJrZXIpO1xuICAgICAgICB9IGNhdGNoIChlKXtcbiAgICAgICAgICAgIC8vIHNhbWUgYXMgYWJvdmUgYnV0IHdoZW4gaXQncyBhIHZlcnNpb24gb2YgSS5FLiB0aGF0IG11c3QgaGF2ZSB0aGUgZ2xvYmFsIG9iamVjdCBmb3IgJ3RoaXMnLCBob3BmdWxseSBvdXIgY29udGV4dCBjb3JyZWN0IG90aGVyd2lzZSBpdCB3aWxsIHRocm93IGEgZ2xvYmFsIGVycm9yLlxuICAgICAgICAgICAgLy8gU29tZSB2ZXJzaW9ucyBvZiBJLkUuIGhhdmUgZGlmZmVyZW50IHJ1bGVzIGZvciBjbGVhclRpbWVvdXQgdnMgc2V0VGltZW91dFxuICAgICAgICAgICAgcmV0dXJuIGNhY2hlZENsZWFyVGltZW91dC5jYWxsKHRoaXMsIG1hcmtlcik7XG4gICAgICAgIH1cbiAgICB9XG5cblxuXG59XG52YXIgcXVldWUgPSBbXTtcbnZhciBkcmFpbmluZyA9IGZhbHNlO1xudmFyIGN1cnJlbnRRdWV1ZTtcbnZhciBxdWV1ZUluZGV4ID0gLTE7XG5cbmZ1bmN0aW9uIGNsZWFuVXBOZXh0VGljaygpIHtcbiAgICBpZiAoIWRyYWluaW5nIHx8ICFjdXJyZW50UXVldWUpIHtcbiAgICAgICAgcmV0dXJuO1xuICAgIH1cbiAgICBkcmFpbmluZyA9IGZhbHNlO1xuICAgIGlmIChjdXJyZW50UXVldWUubGVuZ3RoKSB7XG4gICAgICAgIHF1ZXVlID0gY3VycmVudFF1ZXVlLmNvbmNhdChxdWV1ZSk7XG4gICAgfSBlbHNlIHtcbiAgICAgICAgcXVldWVJbmRleCA9IC0xO1xuICAgIH1cbiAgICBpZiAocXVldWUubGVuZ3RoKSB7XG4gICAgICAgIGRyYWluUXVldWUoKTtcbiAgICB9XG59XG5cbmZ1bmN0aW9uIGRyYWluUXVldWUoKSB7XG4gICAgaWYgKGRyYWluaW5nKSB7XG4gICAgICAgIHJldHVybjtcbiAgICB9XG4gICAgdmFyIHRpbWVvdXQgPSBydW5UaW1lb3V0KGNsZWFuVXBOZXh0VGljayk7XG4gICAgZHJhaW5pbmcgPSB0cnVlO1xuXG4gICAgdmFyIGxlbiA9IHF1ZXVlLmxlbmd0aDtcbiAgICB3aGlsZShsZW4pIHtcbiAgICAgICAgY3VycmVudFF1ZXVlID0gcXVldWU7XG4gICAgICAgIHF1ZXVlID0gW107XG4gICAgICAgIHdoaWxlICgrK3F1ZXVlSW5kZXggPCBsZW4pIHtcbiAgICAgICAgICAgIGlmIChjdXJyZW50UXVldWUpIHtcbiAgICAgICAgICAgICAgICBjdXJyZW50UXVldWVbcXVldWVJbmRleF0ucnVuKCk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgcXVldWVJbmRleCA9IC0xO1xuICAgICAgICBsZW4gPSBxdWV1ZS5sZW5ndGg7XG4gICAgfVxuICAgIGN1cnJlbnRRdWV1ZSA9IG51bGw7XG4gICAgZHJhaW5pbmcgPSBmYWxzZTtcbiAgICBydW5DbGVhclRpbWVvdXQodGltZW91dCk7XG59XG5cbnByb2Nlc3MubmV4dFRpY2sgPSBmdW5jdGlvbiAoZnVuKSB7XG4gICAgdmFyIGFyZ3MgPSBuZXcgQXJyYXkoYXJndW1lbnRzLmxlbmd0aCAtIDEpO1xuICAgIGlmIChhcmd1bWVudHMubGVuZ3RoID4gMSkge1xuICAgICAgICBmb3IgKHZhciBpID0gMTsgaSA8IGFyZ3VtZW50cy5sZW5ndGg7IGkrKykge1xuICAgICAgICAgICAgYXJnc1tpIC0gMV0gPSBhcmd1bWVudHNbaV07XG4gICAgICAgIH1cbiAgICB9XG4gICAgcXVldWUucHVzaChuZXcgSXRlbShmdW4sIGFyZ3MpKTtcbiAgICBpZiAocXVldWUubGVuZ3RoID09PSAxICYmICFkcmFpbmluZykge1xuICAgICAgICBydW5UaW1lb3V0KGRyYWluUXVldWUpO1xuICAgIH1cbn07XG5cbi8vIHY4IGxpa2VzIHByZWRpY3RpYmxlIG9iamVjdHNcbmZ1bmN0aW9uIEl0ZW0oZnVuLCBhcnJheSkge1xuICAgIHRoaXMuZnVuID0gZnVuO1xuICAgIHRoaXMuYXJyYXkgPSBhcnJheTtcbn1cbkl0ZW0ucHJvdG90eXBlLnJ1biA9IGZ1bmN0aW9uICgpIHtcbiAgICB0aGlzLmZ1bi5hcHBseShudWxsLCB0aGlzLmFycmF5KTtcbn07XG5wcm9jZXNzLnRpdGxlID0gJ2Jyb3dzZXInO1xucHJvY2Vzcy5icm93c2VyID0gdHJ1ZTtcbnByb2Nlc3MuZW52ID0ge307XG5wcm9jZXNzLmFyZ3YgPSBbXTtcbnByb2Nlc3MudmVyc2lvbiA9ICcnOyAvLyBlbXB0eSBzdHJpbmcgdG8gYXZvaWQgcmVnZXhwIGlzc3Vlc1xucHJvY2Vzcy52ZXJzaW9ucyA9IHt9O1xuXG5mdW5jdGlvbiBub29wKCkge31cblxucHJvY2Vzcy5vbiA9IG5vb3A7XG5wcm9jZXNzLmFkZExpc3RlbmVyID0gbm9vcDtcbnByb2Nlc3Mub25jZSA9IG5vb3A7XG5wcm9jZXNzLm9mZiA9IG5vb3A7XG5wcm9jZXNzLnJlbW92ZUxpc3RlbmVyID0gbm9vcDtcbnByb2Nlc3MucmVtb3ZlQWxsTGlzdGVuZXJzID0gbm9vcDtcbnByb2Nlc3MuZW1pdCA9IG5vb3A7XG5wcm9jZXNzLnByZXBlbmRMaXN0ZW5lciA9IG5vb3A7XG5wcm9jZXNzLnByZXBlbmRPbmNlTGlzdGVuZXIgPSBub29wO1xuXG5wcm9jZXNzLmxpc3RlbmVycyA9IGZ1bmN0aW9uIChuYW1lKSB7IHJldHVybiBbXSB9XG5cbnByb2Nlc3MuYmluZGluZyA9IGZ1bmN0aW9uIChuYW1lKSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKCdwcm9jZXNzLmJpbmRpbmcgaXMgbm90IHN1cHBvcnRlZCcpO1xufTtcblxucHJvY2Vzcy5jd2QgPSBmdW5jdGlvbiAoKSB7IHJldHVybiAnLycgfTtcbnByb2Nlc3MuY2hkaXIgPSBmdW5jdGlvbiAoZGlyKSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKCdwcm9jZXNzLmNoZGlyIGlzIG5vdCBzdXBwb3J0ZWQnKTtcbn07XG5wcm9jZXNzLnVtYXNrID0gZnVuY3Rpb24oKSB7IHJldHVybiAwOyB9O1xuIiwiaWYgKHByb2Nlc3MuZW52Lm5wbV9wYWNrYWdlX25hbWUgPT09ICdwc2V1ZG9tYXAnICYmXG4gICAgcHJvY2Vzcy5lbnYubnBtX2xpZmVjeWNsZV9zY3JpcHQgPT09ICd0ZXN0JylcbiAgcHJvY2Vzcy5lbnYuVEVTVF9QU0VVRE9NQVAgPSAndHJ1ZSdcblxuaWYgKHR5cGVvZiBNYXAgPT09ICdmdW5jdGlvbicgJiYgIXByb2Nlc3MuZW52LlRFU1RfUFNFVURPTUFQKSB7XG4gIG1vZHVsZS5leHBvcnRzID0gTWFwXG59IGVsc2Uge1xuICBtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoJy4vcHNldWRvbWFwJylcbn1cbiIsInZhciBoYXNPd25Qcm9wZXJ0eSA9IE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHlcblxubW9kdWxlLmV4cG9ydHMgPSBQc2V1ZG9NYXBcblxuZnVuY3Rpb24gUHNldWRvTWFwIChzZXQpIHtcbiAgaWYgKCEodGhpcyBpbnN0YW5jZW9mIFBzZXVkb01hcCkpIC8vIHdoeXl5eXl5eVxuICAgIHRocm93IG5ldyBUeXBlRXJyb3IoXCJDb25zdHJ1Y3RvciBQc2V1ZG9NYXAgcmVxdWlyZXMgJ25ldydcIilcblxuICB0aGlzLmNsZWFyKClcblxuICBpZiAoc2V0KSB7XG4gICAgaWYgKChzZXQgaW5zdGFuY2VvZiBQc2V1ZG9NYXApIHx8XG4gICAgICAgICh0eXBlb2YgTWFwID09PSAnZnVuY3Rpb24nICYmIHNldCBpbnN0YW5jZW9mIE1hcCkpXG4gICAgICBzZXQuZm9yRWFjaChmdW5jdGlvbiAodmFsdWUsIGtleSkge1xuICAgICAgICB0aGlzLnNldChrZXksIHZhbHVlKVxuICAgICAgfSwgdGhpcylcbiAgICBlbHNlIGlmIChBcnJheS5pc0FycmF5KHNldCkpXG4gICAgICBzZXQuZm9yRWFjaChmdW5jdGlvbiAoa3YpIHtcbiAgICAgICAgdGhpcy5zZXQoa3ZbMF0sIGt2WzFdKVxuICAgICAgfSwgdGhpcylcbiAgICBlbHNlXG4gICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdpbnZhbGlkIGFyZ3VtZW50JylcbiAgfVxufVxuXG5Qc2V1ZG9NYXAucHJvdG90eXBlLmZvckVhY2ggPSBmdW5jdGlvbiAoZm4sIHRoaXNwKSB7XG4gIHRoaXNwID0gdGhpc3AgfHwgdGhpc1xuICBPYmplY3Qua2V5cyh0aGlzLl9kYXRhKS5mb3JFYWNoKGZ1bmN0aW9uIChrKSB7XG4gICAgaWYgKGsgIT09ICdzaXplJylcbiAgICAgIGZuLmNhbGwodGhpc3AsIHRoaXMuX2RhdGFba10udmFsdWUsIHRoaXMuX2RhdGFba10ua2V5KVxuICB9LCB0aGlzKVxufVxuXG5Qc2V1ZG9NYXAucHJvdG90eXBlLmhhcyA9IGZ1bmN0aW9uIChrKSB7XG4gIHJldHVybiAhIWZpbmQodGhpcy5fZGF0YSwgaylcbn1cblxuUHNldWRvTWFwLnByb3RvdHlwZS5nZXQgPSBmdW5jdGlvbiAoaykge1xuICB2YXIgcmVzID0gZmluZCh0aGlzLl9kYXRhLCBrKVxuICByZXR1cm4gcmVzICYmIHJlcy52YWx1ZVxufVxuXG5Qc2V1ZG9NYXAucHJvdG90eXBlLnNldCA9IGZ1bmN0aW9uIChrLCB2KSB7XG4gIHNldCh0aGlzLl9kYXRhLCBrLCB2KVxufVxuXG5Qc2V1ZG9NYXAucHJvdG90eXBlLmRlbGV0ZSA9IGZ1bmN0aW9uIChrKSB7XG4gIHZhciByZXMgPSBmaW5kKHRoaXMuX2RhdGEsIGspXG4gIGlmIChyZXMpIHtcbiAgICBkZWxldGUgdGhpcy5fZGF0YVtyZXMuX2luZGV4XVxuICAgIHRoaXMuX2RhdGEuc2l6ZS0tXG4gIH1cbn1cblxuUHNldWRvTWFwLnByb3RvdHlwZS5jbGVhciA9IGZ1bmN0aW9uICgpIHtcbiAgdmFyIGRhdGEgPSBPYmplY3QuY3JlYXRlKG51bGwpXG4gIGRhdGEuc2l6ZSA9IDBcblxuICBPYmplY3QuZGVmaW5lUHJvcGVydHkodGhpcywgJ19kYXRhJywge1xuICAgIHZhbHVlOiBkYXRhLFxuICAgIGVudW1lcmFibGU6IGZhbHNlLFxuICAgIGNvbmZpZ3VyYWJsZTogdHJ1ZSxcbiAgICB3cml0YWJsZTogZmFsc2VcbiAgfSlcbn1cblxuT2JqZWN0LmRlZmluZVByb3BlcnR5KFBzZXVkb01hcC5wcm90b3R5cGUsICdzaXplJywge1xuICBnZXQ6IGZ1bmN0aW9uICgpIHtcbiAgICByZXR1cm4gdGhpcy5fZGF0YS5zaXplXG4gIH0sXG4gIHNldDogZnVuY3Rpb24gKG4pIHt9LFxuICBlbnVtZXJhYmxlOiB0cnVlLFxuICBjb25maWd1cmFibGU6IHRydWVcbn0pXG5cblBzZXVkb01hcC5wcm90b3R5cGUudmFsdWVzID1cblBzZXVkb01hcC5wcm90b3R5cGUua2V5cyA9XG5Qc2V1ZG9NYXAucHJvdG90eXBlLmVudHJpZXMgPSBmdW5jdGlvbiAoKSB7XG4gIHRocm93IG5ldyBFcnJvcignaXRlcmF0b3JzIGFyZSBub3QgaW1wbGVtZW50ZWQgaW4gdGhpcyB2ZXJzaW9uJylcbn1cblxuLy8gRWl0aGVyIGlkZW50aWNhbCwgb3IgYm90aCBOYU5cbmZ1bmN0aW9uIHNhbWUgKGEsIGIpIHtcbiAgcmV0dXJuIGEgPT09IGIgfHwgYSAhPT0gYSAmJiBiICE9PSBiXG59XG5cbmZ1bmN0aW9uIEVudHJ5IChrLCB2LCBpKSB7XG4gIHRoaXMua2V5ID0ga1xuICB0aGlzLnZhbHVlID0gdlxuICB0aGlzLl9pbmRleCA9IGlcbn1cblxuZnVuY3Rpb24gZmluZCAoZGF0YSwgaykge1xuICBmb3IgKHZhciBpID0gMCwgcyA9ICdfJyArIGssIGtleSA9IHM7XG4gICAgICAgaGFzT3duUHJvcGVydHkuY2FsbChkYXRhLCBrZXkpO1xuICAgICAgIGtleSA9IHMgKyBpKyspIHtcbiAgICBpZiAoc2FtZShkYXRhW2tleV0ua2V5LCBrKSlcbiAgICAgIHJldHVybiBkYXRhW2tleV1cbiAgfVxufVxuXG5mdW5jdGlvbiBzZXQgKGRhdGEsIGssIHYpIHtcbiAgZm9yICh2YXIgaSA9IDAsIHMgPSAnXycgKyBrLCBrZXkgPSBzO1xuICAgICAgIGhhc093blByb3BlcnR5LmNhbGwoZGF0YSwga2V5KTtcbiAgICAgICBrZXkgPSBzICsgaSsrKSB7XG4gICAgaWYgKHNhbWUoZGF0YVtrZXldLmtleSwgaykpIHtcbiAgICAgIGRhdGFba2V5XS52YWx1ZSA9IHZcbiAgICAgIHJldHVyblxuICAgIH1cbiAgfVxuICBkYXRhLnNpemUrK1xuICBkYXRhW2tleV0gPSBuZXcgRW50cnkoaywgdiwga2V5KVxufVxuIiwibW9kdWxlLmV4cG9ydHMgPSBmdW5jdGlvbiBpc0J1ZmZlcihhcmcpIHtcbiAgcmV0dXJuIGFyZyAmJiB0eXBlb2YgYXJnID09PSAnb2JqZWN0J1xuICAgICYmIHR5cGVvZiBhcmcuY29weSA9PT0gJ2Z1bmN0aW9uJ1xuICAgICYmIHR5cGVvZiBhcmcuZmlsbCA9PT0gJ2Z1bmN0aW9uJ1xuICAgICYmIHR5cGVvZiBhcmcucmVhZFVJbnQ4ID09PSAnZnVuY3Rpb24nO1xufSIsIi8vIENvcHlyaWdodCBKb3llbnQsIEluYy4gYW5kIG90aGVyIE5vZGUgY29udHJpYnV0b3JzLlxuLy9cbi8vIFBlcm1pc3Npb24gaXMgaGVyZWJ5IGdyYW50ZWQsIGZyZWUgb2YgY2hhcmdlLCB0byBhbnkgcGVyc29uIG9idGFpbmluZyBhXG4vLyBjb3B5IG9mIHRoaXMgc29mdHdhcmUgYW5kIGFzc29jaWF0ZWQgZG9jdW1lbnRhdGlvbiBmaWxlcyAodGhlXG4vLyBcIlNvZnR3YXJlXCIpLCB0byBkZWFsIGluIHRoZSBTb2Z0d2FyZSB3aXRob3V0IHJlc3RyaWN0aW9uLCBpbmNsdWRpbmdcbi8vIHdpdGhvdXQgbGltaXRhdGlvbiB0aGUgcmlnaHRzIHRvIHVzZSwgY29weSwgbW9kaWZ5LCBtZXJnZSwgcHVibGlzaCxcbi8vIGRpc3RyaWJ1dGUsIHN1YmxpY2Vuc2UsIGFuZC9vciBzZWxsIGNvcGllcyBvZiB0aGUgU29mdHdhcmUsIGFuZCB0byBwZXJtaXRcbi8vIHBlcnNvbnMgdG8gd2hvbSB0aGUgU29mdHdhcmUgaXMgZnVybmlzaGVkIHRvIGRvIHNvLCBzdWJqZWN0IHRvIHRoZVxuLy8gZm9sbG93aW5nIGNvbmRpdGlvbnM6XG4vL1xuLy8gVGhlIGFib3ZlIGNvcHlyaWdodCBub3RpY2UgYW5kIHRoaXMgcGVybWlzc2lvbiBub3RpY2Ugc2hhbGwgYmUgaW5jbHVkZWRcbi8vIGluIGFsbCBjb3BpZXMgb3Igc3Vic3RhbnRpYWwgcG9ydGlvbnMgb2YgdGhlIFNvZnR3YXJlLlxuLy9cbi8vIFRIRSBTT0ZUV0FSRSBJUyBQUk9WSURFRCBcIkFTIElTXCIsIFdJVEhPVVQgV0FSUkFOVFkgT0YgQU5ZIEtJTkQsIEVYUFJFU1Ncbi8vIE9SIElNUExJRUQsIElOQ0xVRElORyBCVVQgTk9UIExJTUlURUQgVE8gVEhFIFdBUlJBTlRJRVMgT0Zcbi8vIE1FUkNIQU5UQUJJTElUWSwgRklUTkVTUyBGT1IgQSBQQVJUSUNVTEFSIFBVUlBPU0UgQU5EIE5PTklORlJJTkdFTUVOVC4gSU5cbi8vIE5PIEVWRU5UIFNIQUxMIFRIRSBBVVRIT1JTIE9SIENPUFlSSUdIVCBIT0xERVJTIEJFIExJQUJMRSBGT1IgQU5ZIENMQUlNLFxuLy8gREFNQUdFUyBPUiBPVEhFUiBMSUFCSUxJVFksIFdIRVRIRVIgSU4gQU4gQUNUSU9OIE9GIENPTlRSQUNULCBUT1JUIE9SXG4vLyBPVEhFUldJU0UsIEFSSVNJTkcgRlJPTSwgT1VUIE9GIE9SIElOIENPTk5FQ1RJT04gV0lUSCBUSEUgU09GVFdBUkUgT1IgVEhFXG4vLyBVU0UgT1IgT1RIRVIgREVBTElOR1MgSU4gVEhFIFNPRlRXQVJFLlxuXG52YXIgZm9ybWF0UmVnRXhwID0gLyVbc2RqJV0vZztcbmV4cG9ydHMuZm9ybWF0ID0gZnVuY3Rpb24oZikge1xuICBpZiAoIWlzU3RyaW5nKGYpKSB7XG4gICAgdmFyIG9iamVjdHMgPSBbXTtcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IGFyZ3VtZW50cy5sZW5ndGg7IGkrKykge1xuICAgICAgb2JqZWN0cy5wdXNoKGluc3BlY3QoYXJndW1lbnRzW2ldKSk7XG4gICAgfVxuICAgIHJldHVybiBvYmplY3RzLmpvaW4oJyAnKTtcbiAgfVxuXG4gIHZhciBpID0gMTtcbiAgdmFyIGFyZ3MgPSBhcmd1bWVudHM7XG4gIHZhciBsZW4gPSBhcmdzLmxlbmd0aDtcbiAgdmFyIHN0ciA9IFN0cmluZyhmKS5yZXBsYWNlKGZvcm1hdFJlZ0V4cCwgZnVuY3Rpb24oeCkge1xuICAgIGlmICh4ID09PSAnJSUnKSByZXR1cm4gJyUnO1xuICAgIGlmIChpID49IGxlbikgcmV0dXJuIHg7XG4gICAgc3dpdGNoICh4KSB7XG4gICAgICBjYXNlICclcyc6IHJldHVybiBTdHJpbmcoYXJnc1tpKytdKTtcbiAgICAgIGNhc2UgJyVkJzogcmV0dXJuIE51bWJlcihhcmdzW2krK10pO1xuICAgICAgY2FzZSAnJWonOlxuICAgICAgICB0cnkge1xuICAgICAgICAgIHJldHVybiBKU09OLnN0cmluZ2lmeShhcmdzW2krK10pO1xuICAgICAgICB9IGNhdGNoIChfKSB7XG4gICAgICAgICAgcmV0dXJuICdbQ2lyY3VsYXJdJztcbiAgICAgICAgfVxuICAgICAgZGVmYXVsdDpcbiAgICAgICAgcmV0dXJuIHg7XG4gICAgfVxuICB9KTtcbiAgZm9yICh2YXIgeCA9IGFyZ3NbaV07IGkgPCBsZW47IHggPSBhcmdzWysraV0pIHtcbiAgICBpZiAoaXNOdWxsKHgpIHx8ICFpc09iamVjdCh4KSkge1xuICAgICAgc3RyICs9ICcgJyArIHg7XG4gICAgfSBlbHNlIHtcbiAgICAgIHN0ciArPSAnICcgKyBpbnNwZWN0KHgpO1xuICAgIH1cbiAgfVxuICByZXR1cm4gc3RyO1xufTtcblxuXG4vLyBNYXJrIHRoYXQgYSBtZXRob2Qgc2hvdWxkIG5vdCBiZSB1c2VkLlxuLy8gUmV0dXJucyBhIG1vZGlmaWVkIGZ1bmN0aW9uIHdoaWNoIHdhcm5zIG9uY2UgYnkgZGVmYXVsdC5cbi8vIElmIC0tbm8tZGVwcmVjYXRpb24gaXMgc2V0LCB0aGVuIGl0IGlzIGEgbm8tb3AuXG5leHBvcnRzLmRlcHJlY2F0ZSA9IGZ1bmN0aW9uKGZuLCBtc2cpIHtcbiAgLy8gQWxsb3cgZm9yIGRlcHJlY2F0aW5nIHRoaW5ncyBpbiB0aGUgcHJvY2VzcyBvZiBzdGFydGluZyB1cC5cbiAgaWYgKGlzVW5kZWZpbmVkKGdsb2JhbC5wcm9jZXNzKSkge1xuICAgIHJldHVybiBmdW5jdGlvbigpIHtcbiAgICAgIHJldHVybiBleHBvcnRzLmRlcHJlY2F0ZShmbiwgbXNnKS5hcHBseSh0aGlzLCBhcmd1bWVudHMpO1xuICAgIH07XG4gIH1cblxuICBpZiAocHJvY2Vzcy5ub0RlcHJlY2F0aW9uID09PSB0cnVlKSB7XG4gICAgcmV0dXJuIGZuO1xuICB9XG5cbiAgdmFyIHdhcm5lZCA9IGZhbHNlO1xuICBmdW5jdGlvbiBkZXByZWNhdGVkKCkge1xuICAgIGlmICghd2FybmVkKSB7XG4gICAgICBpZiAocHJvY2Vzcy50aHJvd0RlcHJlY2F0aW9uKSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcihtc2cpO1xuICAgICAgfSBlbHNlIGlmIChwcm9jZXNzLnRyYWNlRGVwcmVjYXRpb24pIHtcbiAgICAgICAgY29uc29sZS50cmFjZShtc2cpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgY29uc29sZS5lcnJvcihtc2cpO1xuICAgICAgfVxuICAgICAgd2FybmVkID0gdHJ1ZTtcbiAgICB9XG4gICAgcmV0dXJuIGZuLmFwcGx5KHRoaXMsIGFyZ3VtZW50cyk7XG4gIH1cblxuICByZXR1cm4gZGVwcmVjYXRlZDtcbn07XG5cblxudmFyIGRlYnVncyA9IHt9O1xudmFyIGRlYnVnRW52aXJvbjtcbmV4cG9ydHMuZGVidWdsb2cgPSBmdW5jdGlvbihzZXQpIHtcbiAgaWYgKGlzVW5kZWZpbmVkKGRlYnVnRW52aXJvbikpXG4gICAgZGVidWdFbnZpcm9uID0gcHJvY2Vzcy5lbnYuTk9ERV9ERUJVRyB8fCAnJztcbiAgc2V0ID0gc2V0LnRvVXBwZXJDYXNlKCk7XG4gIGlmICghZGVidWdzW3NldF0pIHtcbiAgICBpZiAobmV3IFJlZ0V4cCgnXFxcXGInICsgc2V0ICsgJ1xcXFxiJywgJ2knKS50ZXN0KGRlYnVnRW52aXJvbikpIHtcbiAgICAgIHZhciBwaWQgPSBwcm9jZXNzLnBpZDtcbiAgICAgIGRlYnVnc1tzZXRdID0gZnVuY3Rpb24oKSB7XG4gICAgICAgIHZhciBtc2cgPSBleHBvcnRzLmZvcm1hdC5hcHBseShleHBvcnRzLCBhcmd1bWVudHMpO1xuICAgICAgICBjb25zb2xlLmVycm9yKCclcyAlZDogJXMnLCBzZXQsIHBpZCwgbXNnKTtcbiAgICAgIH07XG4gICAgfSBlbHNlIHtcbiAgICAgIGRlYnVnc1tzZXRdID0gZnVuY3Rpb24oKSB7fTtcbiAgICB9XG4gIH1cbiAgcmV0dXJuIGRlYnVnc1tzZXRdO1xufTtcblxuXG4vKipcbiAqIEVjaG9zIHRoZSB2YWx1ZSBvZiBhIHZhbHVlLiBUcnlzIHRvIHByaW50IHRoZSB2YWx1ZSBvdXRcbiAqIGluIHRoZSBiZXN0IHdheSBwb3NzaWJsZSBnaXZlbiB0aGUgZGlmZmVyZW50IHR5cGVzLlxuICpcbiAqIEBwYXJhbSB7T2JqZWN0fSBvYmogVGhlIG9iamVjdCB0byBwcmludCBvdXQuXG4gKiBAcGFyYW0ge09iamVjdH0gb3B0cyBPcHRpb25hbCBvcHRpb25zIG9iamVjdCB0aGF0IGFsdGVycyB0aGUgb3V0cHV0LlxuICovXG4vKiBsZWdhY3k6IG9iaiwgc2hvd0hpZGRlbiwgZGVwdGgsIGNvbG9ycyovXG5mdW5jdGlvbiBpbnNwZWN0KG9iaiwgb3B0cykge1xuICAvLyBkZWZhdWx0IG9wdGlvbnNcbiAgdmFyIGN0eCA9IHtcbiAgICBzZWVuOiBbXSxcbiAgICBzdHlsaXplOiBzdHlsaXplTm9Db2xvclxuICB9O1xuICAvLyBsZWdhY3kuLi5cbiAgaWYgKGFyZ3VtZW50cy5sZW5ndGggPj0gMykgY3R4LmRlcHRoID0gYXJndW1lbnRzWzJdO1xuICBpZiAoYXJndW1lbnRzLmxlbmd0aCA+PSA0KSBjdHguY29sb3JzID0gYXJndW1lbnRzWzNdO1xuICBpZiAoaXNCb29sZWFuKG9wdHMpKSB7XG4gICAgLy8gbGVnYWN5Li4uXG4gICAgY3R4LnNob3dIaWRkZW4gPSBvcHRzO1xuICB9IGVsc2UgaWYgKG9wdHMpIHtcbiAgICAvLyBnb3QgYW4gXCJvcHRpb25zXCIgb2JqZWN0XG4gICAgZXhwb3J0cy5fZXh0ZW5kKGN0eCwgb3B0cyk7XG4gIH1cbiAgLy8gc2V0IGRlZmF1bHQgb3B0aW9uc1xuICBpZiAoaXNVbmRlZmluZWQoY3R4LnNob3dIaWRkZW4pKSBjdHguc2hvd0hpZGRlbiA9IGZhbHNlO1xuICBpZiAoaXNVbmRlZmluZWQoY3R4LmRlcHRoKSkgY3R4LmRlcHRoID0gMjtcbiAgaWYgKGlzVW5kZWZpbmVkKGN0eC5jb2xvcnMpKSBjdHguY29sb3JzID0gZmFsc2U7XG4gIGlmIChpc1VuZGVmaW5lZChjdHguY3VzdG9tSW5zcGVjdCkpIGN0eC5jdXN0b21JbnNwZWN0ID0gdHJ1ZTtcbiAgaWYgKGN0eC5jb2xvcnMpIGN0eC5zdHlsaXplID0gc3R5bGl6ZVdpdGhDb2xvcjtcbiAgcmV0dXJuIGZvcm1hdFZhbHVlKGN0eCwgb2JqLCBjdHguZGVwdGgpO1xufVxuZXhwb3J0cy5pbnNwZWN0ID0gaW5zcGVjdDtcblxuXG4vLyBodHRwOi8vZW4ud2lraXBlZGlhLm9yZy93aWtpL0FOU0lfZXNjYXBlX2NvZGUjZ3JhcGhpY3Ncbmluc3BlY3QuY29sb3JzID0ge1xuICAnYm9sZCcgOiBbMSwgMjJdLFxuICAnaXRhbGljJyA6IFszLCAyM10sXG4gICd1bmRlcmxpbmUnIDogWzQsIDI0XSxcbiAgJ2ludmVyc2UnIDogWzcsIDI3XSxcbiAgJ3doaXRlJyA6IFszNywgMzldLFxuICAnZ3JleScgOiBbOTAsIDM5XSxcbiAgJ2JsYWNrJyA6IFszMCwgMzldLFxuICAnYmx1ZScgOiBbMzQsIDM5XSxcbiAgJ2N5YW4nIDogWzM2LCAzOV0sXG4gICdncmVlbicgOiBbMzIsIDM5XSxcbiAgJ21hZ2VudGEnIDogWzM1LCAzOV0sXG4gICdyZWQnIDogWzMxLCAzOV0sXG4gICd5ZWxsb3cnIDogWzMzLCAzOV1cbn07XG5cbi8vIERvbid0IHVzZSAnYmx1ZScgbm90IHZpc2libGUgb24gY21kLmV4ZVxuaW5zcGVjdC5zdHlsZXMgPSB7XG4gICdzcGVjaWFsJzogJ2N5YW4nLFxuICAnbnVtYmVyJzogJ3llbGxvdycsXG4gICdib29sZWFuJzogJ3llbGxvdycsXG4gICd1bmRlZmluZWQnOiAnZ3JleScsXG4gICdudWxsJzogJ2JvbGQnLFxuICAnc3RyaW5nJzogJ2dyZWVuJyxcbiAgJ2RhdGUnOiAnbWFnZW50YScsXG4gIC8vIFwibmFtZVwiOiBpbnRlbnRpb25hbGx5IG5vdCBzdHlsaW5nXG4gICdyZWdleHAnOiAncmVkJ1xufTtcblxuXG5mdW5jdGlvbiBzdHlsaXplV2l0aENvbG9yKHN0ciwgc3R5bGVUeXBlKSB7XG4gIHZhciBzdHlsZSA9IGluc3BlY3Quc3R5bGVzW3N0eWxlVHlwZV07XG5cbiAgaWYgKHN0eWxlKSB7XG4gICAgcmV0dXJuICdcXHUwMDFiWycgKyBpbnNwZWN0LmNvbG9yc1tzdHlsZV1bMF0gKyAnbScgKyBzdHIgK1xuICAgICAgICAgICAnXFx1MDAxYlsnICsgaW5zcGVjdC5jb2xvcnNbc3R5bGVdWzFdICsgJ20nO1xuICB9IGVsc2Uge1xuICAgIHJldHVybiBzdHI7XG4gIH1cbn1cblxuXG5mdW5jdGlvbiBzdHlsaXplTm9Db2xvcihzdHIsIHN0eWxlVHlwZSkge1xuICByZXR1cm4gc3RyO1xufVxuXG5cbmZ1bmN0aW9uIGFycmF5VG9IYXNoKGFycmF5KSB7XG4gIHZhciBoYXNoID0ge307XG5cbiAgYXJyYXkuZm9yRWFjaChmdW5jdGlvbih2YWwsIGlkeCkge1xuICAgIGhhc2hbdmFsXSA9IHRydWU7XG4gIH0pO1xuXG4gIHJldHVybiBoYXNoO1xufVxuXG5cbmZ1bmN0aW9uIGZvcm1hdFZhbHVlKGN0eCwgdmFsdWUsIHJlY3Vyc2VUaW1lcykge1xuICAvLyBQcm92aWRlIGEgaG9vayBmb3IgdXNlci1zcGVjaWZpZWQgaW5zcGVjdCBmdW5jdGlvbnMuXG4gIC8vIENoZWNrIHRoYXQgdmFsdWUgaXMgYW4gb2JqZWN0IHdpdGggYW4gaW5zcGVjdCBmdW5jdGlvbiBvbiBpdFxuICBpZiAoY3R4LmN1c3RvbUluc3BlY3QgJiZcbiAgICAgIHZhbHVlICYmXG4gICAgICBpc0Z1bmN0aW9uKHZhbHVlLmluc3BlY3QpICYmXG4gICAgICAvLyBGaWx0ZXIgb3V0IHRoZSB1dGlsIG1vZHVsZSwgaXQncyBpbnNwZWN0IGZ1bmN0aW9uIGlzIHNwZWNpYWxcbiAgICAgIHZhbHVlLmluc3BlY3QgIT09IGV4cG9ydHMuaW5zcGVjdCAmJlxuICAgICAgLy8gQWxzbyBmaWx0ZXIgb3V0IGFueSBwcm90b3R5cGUgb2JqZWN0cyB1c2luZyB0aGUgY2lyY3VsYXIgY2hlY2suXG4gICAgICAhKHZhbHVlLmNvbnN0cnVjdG9yICYmIHZhbHVlLmNvbnN0cnVjdG9yLnByb3RvdHlwZSA9PT0gdmFsdWUpKSB7XG4gICAgdmFyIHJldCA9IHZhbHVlLmluc3BlY3QocmVjdXJzZVRpbWVzLCBjdHgpO1xuICAgIGlmICghaXNTdHJpbmcocmV0KSkge1xuICAgICAgcmV0ID0gZm9ybWF0VmFsdWUoY3R4LCByZXQsIHJlY3Vyc2VUaW1lcyk7XG4gICAgfVxuICAgIHJldHVybiByZXQ7XG4gIH1cblxuICAvLyBQcmltaXRpdmUgdHlwZXMgY2Fubm90IGhhdmUgcHJvcGVydGllc1xuICB2YXIgcHJpbWl0aXZlID0gZm9ybWF0UHJpbWl0aXZlKGN0eCwgdmFsdWUpO1xuICBpZiAocHJpbWl0aXZlKSB7XG4gICAgcmV0dXJuIHByaW1pdGl2ZTtcbiAgfVxuXG4gIC8vIExvb2sgdXAgdGhlIGtleXMgb2YgdGhlIG9iamVjdC5cbiAgdmFyIGtleXMgPSBPYmplY3Qua2V5cyh2YWx1ZSk7XG4gIHZhciB2aXNpYmxlS2V5cyA9IGFycmF5VG9IYXNoKGtleXMpO1xuXG4gIGlmIChjdHguc2hvd0hpZGRlbikge1xuICAgIGtleXMgPSBPYmplY3QuZ2V0T3duUHJvcGVydHlOYW1lcyh2YWx1ZSk7XG4gIH1cblxuICAvLyBJRSBkb2Vzbid0IG1ha2UgZXJyb3IgZmllbGRzIG5vbi1lbnVtZXJhYmxlXG4gIC8vIGh0dHA6Ly9tc2RuLm1pY3Jvc29mdC5jb20vZW4tdXMvbGlicmFyeS9pZS9kd3c1MnNidCh2PXZzLjk0KS5hc3B4XG4gIGlmIChpc0Vycm9yKHZhbHVlKVxuICAgICAgJiYgKGtleXMuaW5kZXhPZignbWVzc2FnZScpID49IDAgfHwga2V5cy5pbmRleE9mKCdkZXNjcmlwdGlvbicpID49IDApKSB7XG4gICAgcmV0dXJuIGZvcm1hdEVycm9yKHZhbHVlKTtcbiAgfVxuXG4gIC8vIFNvbWUgdHlwZSBvZiBvYmplY3Qgd2l0aG91dCBwcm9wZXJ0aWVzIGNhbiBiZSBzaG9ydGN1dHRlZC5cbiAgaWYgKGtleXMubGVuZ3RoID09PSAwKSB7XG4gICAgaWYgKGlzRnVuY3Rpb24odmFsdWUpKSB7XG4gICAgICB2YXIgbmFtZSA9IHZhbHVlLm5hbWUgPyAnOiAnICsgdmFsdWUubmFtZSA6ICcnO1xuICAgICAgcmV0dXJuIGN0eC5zdHlsaXplKCdbRnVuY3Rpb24nICsgbmFtZSArICddJywgJ3NwZWNpYWwnKTtcbiAgICB9XG4gICAgaWYgKGlzUmVnRXhwKHZhbHVlKSkge1xuICAgICAgcmV0dXJuIGN0eC5zdHlsaXplKFJlZ0V4cC5wcm90b3R5cGUudG9TdHJpbmcuY2FsbCh2YWx1ZSksICdyZWdleHAnKTtcbiAgICB9XG4gICAgaWYgKGlzRGF0ZSh2YWx1ZSkpIHtcbiAgICAgIHJldHVybiBjdHguc3R5bGl6ZShEYXRlLnByb3RvdHlwZS50b1N0cmluZy5jYWxsKHZhbHVlKSwgJ2RhdGUnKTtcbiAgICB9XG4gICAgaWYgKGlzRXJyb3IodmFsdWUpKSB7XG4gICAgICByZXR1cm4gZm9ybWF0RXJyb3IodmFsdWUpO1xuICAgIH1cbiAgfVxuXG4gIHZhciBiYXNlID0gJycsIGFycmF5ID0gZmFsc2UsIGJyYWNlcyA9IFsneycsICd9J107XG5cbiAgLy8gTWFrZSBBcnJheSBzYXkgdGhhdCB0aGV5IGFyZSBBcnJheVxuICBpZiAoaXNBcnJheSh2YWx1ZSkpIHtcbiAgICBhcnJheSA9IHRydWU7XG4gICAgYnJhY2VzID0gWydbJywgJ10nXTtcbiAgfVxuXG4gIC8vIE1ha2UgZnVuY3Rpb25zIHNheSB0aGF0IHRoZXkgYXJlIGZ1bmN0aW9uc1xuICBpZiAoaXNGdW5jdGlvbih2YWx1ZSkpIHtcbiAgICB2YXIgbiA9IHZhbHVlLm5hbWUgPyAnOiAnICsgdmFsdWUubmFtZSA6ICcnO1xuICAgIGJhc2UgPSAnIFtGdW5jdGlvbicgKyBuICsgJ10nO1xuICB9XG5cbiAgLy8gTWFrZSBSZWdFeHBzIHNheSB0aGF0IHRoZXkgYXJlIFJlZ0V4cHNcbiAgaWYgKGlzUmVnRXhwKHZhbHVlKSkge1xuICAgIGJhc2UgPSAnICcgKyBSZWdFeHAucHJvdG90eXBlLnRvU3RyaW5nLmNhbGwodmFsdWUpO1xuICB9XG5cbiAgLy8gTWFrZSBkYXRlcyB3aXRoIHByb3BlcnRpZXMgZmlyc3Qgc2F5IHRoZSBkYXRlXG4gIGlmIChpc0RhdGUodmFsdWUpKSB7XG4gICAgYmFzZSA9ICcgJyArIERhdGUucHJvdG90eXBlLnRvVVRDU3RyaW5nLmNhbGwodmFsdWUpO1xuICB9XG5cbiAgLy8gTWFrZSBlcnJvciB3aXRoIG1lc3NhZ2UgZmlyc3Qgc2F5IHRoZSBlcnJvclxuICBpZiAoaXNFcnJvcih2YWx1ZSkpIHtcbiAgICBiYXNlID0gJyAnICsgZm9ybWF0RXJyb3IodmFsdWUpO1xuICB9XG5cbiAgaWYgKGtleXMubGVuZ3RoID09PSAwICYmICghYXJyYXkgfHwgdmFsdWUubGVuZ3RoID09IDApKSB7XG4gICAgcmV0dXJuIGJyYWNlc1swXSArIGJhc2UgKyBicmFjZXNbMV07XG4gIH1cblxuICBpZiAocmVjdXJzZVRpbWVzIDwgMCkge1xuICAgIGlmIChpc1JlZ0V4cCh2YWx1ZSkpIHtcbiAgICAgIHJldHVybiBjdHguc3R5bGl6ZShSZWdFeHAucHJvdG90eXBlLnRvU3RyaW5nLmNhbGwodmFsdWUpLCAncmVnZXhwJyk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHJldHVybiBjdHguc3R5bGl6ZSgnW09iamVjdF0nLCAnc3BlY2lhbCcpO1xuICAgIH1cbiAgfVxuXG4gIGN0eC5zZWVuLnB1c2godmFsdWUpO1xuXG4gIHZhciBvdXRwdXQ7XG4gIGlmIChhcnJheSkge1xuICAgIG91dHB1dCA9IGZvcm1hdEFycmF5KGN0eCwgdmFsdWUsIHJlY3Vyc2VUaW1lcywgdmlzaWJsZUtleXMsIGtleXMpO1xuICB9IGVsc2Uge1xuICAgIG91dHB1dCA9IGtleXMubWFwKGZ1bmN0aW9uKGtleSkge1xuICAgICAgcmV0dXJuIGZvcm1hdFByb3BlcnR5KGN0eCwgdmFsdWUsIHJlY3Vyc2VUaW1lcywgdmlzaWJsZUtleXMsIGtleSwgYXJyYXkpO1xuICAgIH0pO1xuICB9XG5cbiAgY3R4LnNlZW4ucG9wKCk7XG5cbiAgcmV0dXJuIHJlZHVjZVRvU2luZ2xlU3RyaW5nKG91dHB1dCwgYmFzZSwgYnJhY2VzKTtcbn1cblxuXG5mdW5jdGlvbiBmb3JtYXRQcmltaXRpdmUoY3R4LCB2YWx1ZSkge1xuICBpZiAoaXNVbmRlZmluZWQodmFsdWUpKVxuICAgIHJldHVybiBjdHguc3R5bGl6ZSgndW5kZWZpbmVkJywgJ3VuZGVmaW5lZCcpO1xuICBpZiAoaXNTdHJpbmcodmFsdWUpKSB7XG4gICAgdmFyIHNpbXBsZSA9ICdcXCcnICsgSlNPTi5zdHJpbmdpZnkodmFsdWUpLnJlcGxhY2UoL15cInxcIiQvZywgJycpXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAucmVwbGFjZSgvJy9nLCBcIlxcXFwnXCIpXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAucmVwbGFjZSgvXFxcXFwiL2csICdcIicpICsgJ1xcJyc7XG4gICAgcmV0dXJuIGN0eC5zdHlsaXplKHNpbXBsZSwgJ3N0cmluZycpO1xuICB9XG4gIGlmIChpc051bWJlcih2YWx1ZSkpXG4gICAgcmV0dXJuIGN0eC5zdHlsaXplKCcnICsgdmFsdWUsICdudW1iZXInKTtcbiAgaWYgKGlzQm9vbGVhbih2YWx1ZSkpXG4gICAgcmV0dXJuIGN0eC5zdHlsaXplKCcnICsgdmFsdWUsICdib29sZWFuJyk7XG4gIC8vIEZvciBzb21lIHJlYXNvbiB0eXBlb2YgbnVsbCBpcyBcIm9iamVjdFwiLCBzbyBzcGVjaWFsIGNhc2UgaGVyZS5cbiAgaWYgKGlzTnVsbCh2YWx1ZSkpXG4gICAgcmV0dXJuIGN0eC5zdHlsaXplKCdudWxsJywgJ251bGwnKTtcbn1cblxuXG5mdW5jdGlvbiBmb3JtYXRFcnJvcih2YWx1ZSkge1xuICByZXR1cm4gJ1snICsgRXJyb3IucHJvdG90eXBlLnRvU3RyaW5nLmNhbGwodmFsdWUpICsgJ10nO1xufVxuXG5cbmZ1bmN0aW9uIGZvcm1hdEFycmF5KGN0eCwgdmFsdWUsIHJlY3Vyc2VUaW1lcywgdmlzaWJsZUtleXMsIGtleXMpIHtcbiAgdmFyIG91dHB1dCA9IFtdO1xuICBmb3IgKHZhciBpID0gMCwgbCA9IHZhbHVlLmxlbmd0aDsgaSA8IGw7ICsraSkge1xuICAgIGlmIChoYXNPd25Qcm9wZXJ0eSh2YWx1ZSwgU3RyaW5nKGkpKSkge1xuICAgICAgb3V0cHV0LnB1c2goZm9ybWF0UHJvcGVydHkoY3R4LCB2YWx1ZSwgcmVjdXJzZVRpbWVzLCB2aXNpYmxlS2V5cyxcbiAgICAgICAgICBTdHJpbmcoaSksIHRydWUpKTtcbiAgICB9IGVsc2Uge1xuICAgICAgb3V0cHV0LnB1c2goJycpO1xuICAgIH1cbiAgfVxuICBrZXlzLmZvckVhY2goZnVuY3Rpb24oa2V5KSB7XG4gICAgaWYgKCFrZXkubWF0Y2goL15cXGQrJC8pKSB7XG4gICAgICBvdXRwdXQucHVzaChmb3JtYXRQcm9wZXJ0eShjdHgsIHZhbHVlLCByZWN1cnNlVGltZXMsIHZpc2libGVLZXlzLFxuICAgICAgICAgIGtleSwgdHJ1ZSkpO1xuICAgIH1cbiAgfSk7XG4gIHJldHVybiBvdXRwdXQ7XG59XG5cblxuZnVuY3Rpb24gZm9ybWF0UHJvcGVydHkoY3R4LCB2YWx1ZSwgcmVjdXJzZVRpbWVzLCB2aXNpYmxlS2V5cywga2V5LCBhcnJheSkge1xuICB2YXIgbmFtZSwgc3RyLCBkZXNjO1xuICBkZXNjID0gT2JqZWN0LmdldE93blByb3BlcnR5RGVzY3JpcHRvcih2YWx1ZSwga2V5KSB8fCB7IHZhbHVlOiB2YWx1ZVtrZXldIH07XG4gIGlmIChkZXNjLmdldCkge1xuICAgIGlmIChkZXNjLnNldCkge1xuICAgICAgc3RyID0gY3R4LnN0eWxpemUoJ1tHZXR0ZXIvU2V0dGVyXScsICdzcGVjaWFsJyk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHN0ciA9IGN0eC5zdHlsaXplKCdbR2V0dGVyXScsICdzcGVjaWFsJyk7XG4gICAgfVxuICB9IGVsc2Uge1xuICAgIGlmIChkZXNjLnNldCkge1xuICAgICAgc3RyID0gY3R4LnN0eWxpemUoJ1tTZXR0ZXJdJywgJ3NwZWNpYWwnKTtcbiAgICB9XG4gIH1cbiAgaWYgKCFoYXNPd25Qcm9wZXJ0eSh2aXNpYmxlS2V5cywga2V5KSkge1xuICAgIG5hbWUgPSAnWycgKyBrZXkgKyAnXSc7XG4gIH1cbiAgaWYgKCFzdHIpIHtcbiAgICBpZiAoY3R4LnNlZW4uaW5kZXhPZihkZXNjLnZhbHVlKSA8IDApIHtcbiAgICAgIGlmIChpc051bGwocmVjdXJzZVRpbWVzKSkge1xuICAgICAgICBzdHIgPSBmb3JtYXRWYWx1ZShjdHgsIGRlc2MudmFsdWUsIG51bGwpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgc3RyID0gZm9ybWF0VmFsdWUoY3R4LCBkZXNjLnZhbHVlLCByZWN1cnNlVGltZXMgLSAxKTtcbiAgICAgIH1cbiAgICAgIGlmIChzdHIuaW5kZXhPZignXFxuJykgPiAtMSkge1xuICAgICAgICBpZiAoYXJyYXkpIHtcbiAgICAgICAgICBzdHIgPSBzdHIuc3BsaXQoJ1xcbicpLm1hcChmdW5jdGlvbihsaW5lKSB7XG4gICAgICAgICAgICByZXR1cm4gJyAgJyArIGxpbmU7XG4gICAgICAgICAgfSkuam9pbignXFxuJykuc3Vic3RyKDIpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHN0ciA9ICdcXG4nICsgc3RyLnNwbGl0KCdcXG4nKS5tYXAoZnVuY3Rpb24obGluZSkge1xuICAgICAgICAgICAgcmV0dXJuICcgICAnICsgbGluZTtcbiAgICAgICAgICB9KS5qb2luKCdcXG4nKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0gZWxzZSB7XG4gICAgICBzdHIgPSBjdHguc3R5bGl6ZSgnW0NpcmN1bGFyXScsICdzcGVjaWFsJyk7XG4gICAgfVxuICB9XG4gIGlmIChpc1VuZGVmaW5lZChuYW1lKSkge1xuICAgIGlmIChhcnJheSAmJiBrZXkubWF0Y2goL15cXGQrJC8pKSB7XG4gICAgICByZXR1cm4gc3RyO1xuICAgIH1cbiAgICBuYW1lID0gSlNPTi5zdHJpbmdpZnkoJycgKyBrZXkpO1xuICAgIGlmIChuYW1lLm1hdGNoKC9eXCIoW2EtekEtWl9dW2EtekEtWl8wLTldKilcIiQvKSkge1xuICAgICAgbmFtZSA9IG5hbWUuc3Vic3RyKDEsIG5hbWUubGVuZ3RoIC0gMik7XG4gICAgICBuYW1lID0gY3R4LnN0eWxpemUobmFtZSwgJ25hbWUnKTtcbiAgICB9IGVsc2Uge1xuICAgICAgbmFtZSA9IG5hbWUucmVwbGFjZSgvJy9nLCBcIlxcXFwnXCIpXG4gICAgICAgICAgICAgICAgIC5yZXBsYWNlKC9cXFxcXCIvZywgJ1wiJylcbiAgICAgICAgICAgICAgICAgLnJlcGxhY2UoLyheXCJ8XCIkKS9nLCBcIidcIik7XG4gICAgICBuYW1lID0gY3R4LnN0eWxpemUobmFtZSwgJ3N0cmluZycpO1xuICAgIH1cbiAgfVxuXG4gIHJldHVybiBuYW1lICsgJzogJyArIHN0cjtcbn1cblxuXG5mdW5jdGlvbiByZWR1Y2VUb1NpbmdsZVN0cmluZyhvdXRwdXQsIGJhc2UsIGJyYWNlcykge1xuICB2YXIgbnVtTGluZXNFc3QgPSAwO1xuICB2YXIgbGVuZ3RoID0gb3V0cHV0LnJlZHVjZShmdW5jdGlvbihwcmV2LCBjdXIpIHtcbiAgICBudW1MaW5lc0VzdCsrO1xuICAgIGlmIChjdXIuaW5kZXhPZignXFxuJykgPj0gMCkgbnVtTGluZXNFc3QrKztcbiAgICByZXR1cm4gcHJldiArIGN1ci5yZXBsYWNlKC9cXHUwMDFiXFxbXFxkXFxkP20vZywgJycpLmxlbmd0aCArIDE7XG4gIH0sIDApO1xuXG4gIGlmIChsZW5ndGggPiA2MCkge1xuICAgIHJldHVybiBicmFjZXNbMF0gK1xuICAgICAgICAgICAoYmFzZSA9PT0gJycgPyAnJyA6IGJhc2UgKyAnXFxuICcpICtcbiAgICAgICAgICAgJyAnICtcbiAgICAgICAgICAgb3V0cHV0LmpvaW4oJyxcXG4gICcpICtcbiAgICAgICAgICAgJyAnICtcbiAgICAgICAgICAgYnJhY2VzWzFdO1xuICB9XG5cbiAgcmV0dXJuIGJyYWNlc1swXSArIGJhc2UgKyAnICcgKyBvdXRwdXQuam9pbignLCAnKSArICcgJyArIGJyYWNlc1sxXTtcbn1cblxuXG4vLyBOT1RFOiBUaGVzZSB0eXBlIGNoZWNraW5nIGZ1bmN0aW9ucyBpbnRlbnRpb25hbGx5IGRvbid0IHVzZSBgaW5zdGFuY2VvZmBcbi8vIGJlY2F1c2UgaXQgaXMgZnJhZ2lsZSBhbmQgY2FuIGJlIGVhc2lseSBmYWtlZCB3aXRoIGBPYmplY3QuY3JlYXRlKClgLlxuZnVuY3Rpb24gaXNBcnJheShhcikge1xuICByZXR1cm4gQXJyYXkuaXNBcnJheShhcik7XG59XG5leHBvcnRzLmlzQXJyYXkgPSBpc0FycmF5O1xuXG5mdW5jdGlvbiBpc0Jvb2xlYW4oYXJnKSB7XG4gIHJldHVybiB0eXBlb2YgYXJnID09PSAnYm9vbGVhbic7XG59XG5leHBvcnRzLmlzQm9vbGVhbiA9IGlzQm9vbGVhbjtcblxuZnVuY3Rpb24gaXNOdWxsKGFyZykge1xuICByZXR1cm4gYXJnID09PSBudWxsO1xufVxuZXhwb3J0cy5pc051bGwgPSBpc051bGw7XG5cbmZ1bmN0aW9uIGlzTnVsbE9yVW5kZWZpbmVkKGFyZykge1xuICByZXR1cm4gYXJnID09IG51bGw7XG59XG5leHBvcnRzLmlzTnVsbE9yVW5kZWZpbmVkID0gaXNOdWxsT3JVbmRlZmluZWQ7XG5cbmZ1bmN0aW9uIGlzTnVtYmVyKGFyZykge1xuICByZXR1cm4gdHlwZW9mIGFyZyA9PT0gJ251bWJlcic7XG59XG5leHBvcnRzLmlzTnVtYmVyID0gaXNOdW1iZXI7XG5cbmZ1bmN0aW9uIGlzU3RyaW5nKGFyZykge1xuICByZXR1cm4gdHlwZW9mIGFyZyA9PT0gJ3N0cmluZyc7XG59XG5leHBvcnRzLmlzU3RyaW5nID0gaXNTdHJpbmc7XG5cbmZ1bmN0aW9uIGlzU3ltYm9sKGFyZykge1xuICByZXR1cm4gdHlwZW9mIGFyZyA9PT0gJ3N5bWJvbCc7XG59XG5leHBvcnRzLmlzU3ltYm9sID0gaXNTeW1ib2w7XG5cbmZ1bmN0aW9uIGlzVW5kZWZpbmVkKGFyZykge1xuICByZXR1cm4gYXJnID09PSB2b2lkIDA7XG59XG5leHBvcnRzLmlzVW5kZWZpbmVkID0gaXNVbmRlZmluZWQ7XG5cbmZ1bmN0aW9uIGlzUmVnRXhwKHJlKSB7XG4gIHJldHVybiBpc09iamVjdChyZSkgJiYgb2JqZWN0VG9TdHJpbmcocmUpID09PSAnW29iamVjdCBSZWdFeHBdJztcbn1cbmV4cG9ydHMuaXNSZWdFeHAgPSBpc1JlZ0V4cDtcblxuZnVuY3Rpb24gaXNPYmplY3QoYXJnKSB7XG4gIHJldHVybiB0eXBlb2YgYXJnID09PSAnb2JqZWN0JyAmJiBhcmcgIT09IG51bGw7XG59XG5leHBvcnRzLmlzT2JqZWN0ID0gaXNPYmplY3Q7XG5cbmZ1bmN0aW9uIGlzRGF0ZShkKSB7XG4gIHJldHVybiBpc09iamVjdChkKSAmJiBvYmplY3RUb1N0cmluZyhkKSA9PT0gJ1tvYmplY3QgRGF0ZV0nO1xufVxuZXhwb3J0cy5pc0RhdGUgPSBpc0RhdGU7XG5cbmZ1bmN0aW9uIGlzRXJyb3IoZSkge1xuICByZXR1cm4gaXNPYmplY3QoZSkgJiZcbiAgICAgIChvYmplY3RUb1N0cmluZyhlKSA9PT0gJ1tvYmplY3QgRXJyb3JdJyB8fCBlIGluc3RhbmNlb2YgRXJyb3IpO1xufVxuZXhwb3J0cy5pc0Vycm9yID0gaXNFcnJvcjtcblxuZnVuY3Rpb24gaXNGdW5jdGlvbihhcmcpIHtcbiAgcmV0dXJuIHR5cGVvZiBhcmcgPT09ICdmdW5jdGlvbic7XG59XG5leHBvcnRzLmlzRnVuY3Rpb24gPSBpc0Z1bmN0aW9uO1xuXG5mdW5jdGlvbiBpc1ByaW1pdGl2ZShhcmcpIHtcbiAgcmV0dXJuIGFyZyA9PT0gbnVsbCB8fFxuICAgICAgICAgdHlwZW9mIGFyZyA9PT0gJ2Jvb2xlYW4nIHx8XG4gICAgICAgICB0eXBlb2YgYXJnID09PSAnbnVtYmVyJyB8fFxuICAgICAgICAgdHlwZW9mIGFyZyA9PT0gJ3N0cmluZycgfHxcbiAgICAgICAgIHR5cGVvZiBhcmcgPT09ICdzeW1ib2wnIHx8ICAvLyBFUzYgc3ltYm9sXG4gICAgICAgICB0eXBlb2YgYXJnID09PSAndW5kZWZpbmVkJztcbn1cbmV4cG9ydHMuaXNQcmltaXRpdmUgPSBpc1ByaW1pdGl2ZTtcblxuZXhwb3J0cy5pc0J1ZmZlciA9IHJlcXVpcmUoJy4vc3VwcG9ydC9pc0J1ZmZlcicpO1xuXG5mdW5jdGlvbiBvYmplY3RUb1N0cmluZyhvKSB7XG4gIHJldHVybiBPYmplY3QucHJvdG90eXBlLnRvU3RyaW5nLmNhbGwobyk7XG59XG5cblxuZnVuY3Rpb24gcGFkKG4pIHtcbiAgcmV0dXJuIG4gPCAxMCA/ICcwJyArIG4udG9TdHJpbmcoMTApIDogbi50b1N0cmluZygxMCk7XG59XG5cblxudmFyIG1vbnRocyA9IFsnSmFuJywgJ0ZlYicsICdNYXInLCAnQXByJywgJ01heScsICdKdW4nLCAnSnVsJywgJ0F1ZycsICdTZXAnLFxuICAgICAgICAgICAgICAnT2N0JywgJ05vdicsICdEZWMnXTtcblxuLy8gMjYgRmViIDE2OjE5OjM0XG5mdW5jdGlvbiB0aW1lc3RhbXAoKSB7XG4gIHZhciBkID0gbmV3IERhdGUoKTtcbiAgdmFyIHRpbWUgPSBbcGFkKGQuZ2V0SG91cnMoKSksXG4gICAgICAgICAgICAgIHBhZChkLmdldE1pbnV0ZXMoKSksXG4gICAgICAgICAgICAgIHBhZChkLmdldFNlY29uZHMoKSldLmpvaW4oJzonKTtcbiAgcmV0dXJuIFtkLmdldERhdGUoKSwgbW9udGhzW2QuZ2V0TW9udGgoKV0sIHRpbWVdLmpvaW4oJyAnKTtcbn1cblxuXG4vLyBsb2cgaXMganVzdCBhIHRoaW4gd3JhcHBlciB0byBjb25zb2xlLmxvZyB0aGF0IHByZXBlbmRzIGEgdGltZXN0YW1wXG5leHBvcnRzLmxvZyA9IGZ1bmN0aW9uKCkge1xuICBjb25zb2xlLmxvZygnJXMgLSAlcycsIHRpbWVzdGFtcCgpLCBleHBvcnRzLmZvcm1hdC5hcHBseShleHBvcnRzLCBhcmd1bWVudHMpKTtcbn07XG5cblxuLyoqXG4gKiBJbmhlcml0IHRoZSBwcm90b3R5cGUgbWV0aG9kcyBmcm9tIG9uZSBjb25zdHJ1Y3RvciBpbnRvIGFub3RoZXIuXG4gKlxuICogVGhlIEZ1bmN0aW9uLnByb3RvdHlwZS5pbmhlcml0cyBmcm9tIGxhbmcuanMgcmV3cml0dGVuIGFzIGEgc3RhbmRhbG9uZVxuICogZnVuY3Rpb24gKG5vdCBvbiBGdW5jdGlvbi5wcm90b3R5cGUpLiBOT1RFOiBJZiB0aGlzIGZpbGUgaXMgdG8gYmUgbG9hZGVkXG4gKiBkdXJpbmcgYm9vdHN0cmFwcGluZyB0aGlzIGZ1bmN0aW9uIG5lZWRzIHRvIGJlIHJld3JpdHRlbiB1c2luZyBzb21lIG5hdGl2ZVxuICogZnVuY3Rpb25zIGFzIHByb3RvdHlwZSBzZXR1cCB1c2luZyBub3JtYWwgSmF2YVNjcmlwdCBkb2VzIG5vdCB3b3JrIGFzXG4gKiBleHBlY3RlZCBkdXJpbmcgYm9vdHN0cmFwcGluZyAoc2VlIG1pcnJvci5qcyBpbiByMTE0OTAzKS5cbiAqXG4gKiBAcGFyYW0ge2Z1bmN0aW9ufSBjdG9yIENvbnN0cnVjdG9yIGZ1bmN0aW9uIHdoaWNoIG5lZWRzIHRvIGluaGVyaXQgdGhlXG4gKiAgICAgcHJvdG90eXBlLlxuICogQHBhcmFtIHtmdW5jdGlvbn0gc3VwZXJDdG9yIENvbnN0cnVjdG9yIGZ1bmN0aW9uIHRvIGluaGVyaXQgcHJvdG90eXBlIGZyb20uXG4gKi9cbmV4cG9ydHMuaW5oZXJpdHMgPSByZXF1aXJlKCdpbmhlcml0cycpO1xuXG5leHBvcnRzLl9leHRlbmQgPSBmdW5jdGlvbihvcmlnaW4sIGFkZCkge1xuICAvLyBEb24ndCBkbyBhbnl0aGluZyBpZiBhZGQgaXNuJ3QgYW4gb2JqZWN0XG4gIGlmICghYWRkIHx8ICFpc09iamVjdChhZGQpKSByZXR1cm4gb3JpZ2luO1xuXG4gIHZhciBrZXlzID0gT2JqZWN0LmtleXMoYWRkKTtcbiAgdmFyIGkgPSBrZXlzLmxlbmd0aDtcbiAgd2hpbGUgKGktLSkge1xuICAgIG9yaWdpbltrZXlzW2ldXSA9IGFkZFtrZXlzW2ldXTtcbiAgfVxuICByZXR1cm4gb3JpZ2luO1xufTtcblxuZnVuY3Rpb24gaGFzT3duUHJvcGVydHkob2JqLCBwcm9wKSB7XG4gIHJldHVybiBPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwob2JqLCBwcm9wKTtcbn1cbiIsInZhciBnO1xuXG4vLyBUaGlzIHdvcmtzIGluIG5vbi1zdHJpY3QgbW9kZVxuZyA9IChmdW5jdGlvbigpIHtcblx0cmV0dXJuIHRoaXM7XG59KSgpO1xuXG50cnkge1xuXHQvLyBUaGlzIHdvcmtzIGlmIGV2YWwgaXMgYWxsb3dlZCAoc2VlIENTUClcblx0ZyA9IGcgfHwgRnVuY3Rpb24oXCJyZXR1cm4gdGhpc1wiKSgpIHx8ICgxLCBldmFsKShcInRoaXNcIik7XG59IGNhdGNoIChlKSB7XG5cdC8vIFRoaXMgd29ya3MgaWYgdGhlIHdpbmRvdyByZWZlcmVuY2UgaXMgYXZhaWxhYmxlXG5cdGlmICh0eXBlb2Ygd2luZG93ID09PSBcIm9iamVjdFwiKSBnID0gd2luZG93O1xufVxuXG4vLyBnIGNhbiBzdGlsbCBiZSB1bmRlZmluZWQsIGJ1dCBub3RoaW5nIHRvIGRvIGFib3V0IGl0Li4uXG4vLyBXZSByZXR1cm4gdW5kZWZpbmVkLCBpbnN0ZWFkIG9mIG5vdGhpbmcgaGVyZSwgc28gaXQnc1xuLy8gZWFzaWVyIHRvIGhhbmRsZSB0aGlzIGNhc2UuIGlmKCFnbG9iYWwpIHsgLi4ufVxuXG5tb2R1bGUuZXhwb3J0cyA9IGc7XG4iLCJtb2R1bGUuZXhwb3J0cyA9IFlhbGxpc3RcblxuWWFsbGlzdC5Ob2RlID0gTm9kZVxuWWFsbGlzdC5jcmVhdGUgPSBZYWxsaXN0XG5cbmZ1bmN0aW9uIFlhbGxpc3QgKGxpc3QpIHtcbiAgdmFyIHNlbGYgPSB0aGlzXG4gIGlmICghKHNlbGYgaW5zdGFuY2VvZiBZYWxsaXN0KSkge1xuICAgIHNlbGYgPSBuZXcgWWFsbGlzdCgpXG4gIH1cblxuICBzZWxmLnRhaWwgPSBudWxsXG4gIHNlbGYuaGVhZCA9IG51bGxcbiAgc2VsZi5sZW5ndGggPSAwXG5cbiAgaWYgKGxpc3QgJiYgdHlwZW9mIGxpc3QuZm9yRWFjaCA9PT0gJ2Z1bmN0aW9uJykge1xuICAgIGxpc3QuZm9yRWFjaChmdW5jdGlvbiAoaXRlbSkge1xuICAgICAgc2VsZi5wdXNoKGl0ZW0pXG4gICAgfSlcbiAgfSBlbHNlIGlmIChhcmd1bWVudHMubGVuZ3RoID4gMCkge1xuICAgIGZvciAodmFyIGkgPSAwLCBsID0gYXJndW1lbnRzLmxlbmd0aDsgaSA8IGw7IGkrKykge1xuICAgICAgc2VsZi5wdXNoKGFyZ3VtZW50c1tpXSlcbiAgICB9XG4gIH1cblxuICByZXR1cm4gc2VsZlxufVxuXG5ZYWxsaXN0LnByb3RvdHlwZS5yZW1vdmVOb2RlID0gZnVuY3Rpb24gKG5vZGUpIHtcbiAgaWYgKG5vZGUubGlzdCAhPT0gdGhpcykge1xuICAgIHRocm93IG5ldyBFcnJvcigncmVtb3Zpbmcgbm9kZSB3aGljaCBkb2VzIG5vdCBiZWxvbmcgdG8gdGhpcyBsaXN0JylcbiAgfVxuXG4gIHZhciBuZXh0ID0gbm9kZS5uZXh0XG4gIHZhciBwcmV2ID0gbm9kZS5wcmV2XG5cbiAgaWYgKG5leHQpIHtcbiAgICBuZXh0LnByZXYgPSBwcmV2XG4gIH1cblxuICBpZiAocHJldikge1xuICAgIHByZXYubmV4dCA9IG5leHRcbiAgfVxuXG4gIGlmIChub2RlID09PSB0aGlzLmhlYWQpIHtcbiAgICB0aGlzLmhlYWQgPSBuZXh0XG4gIH1cbiAgaWYgKG5vZGUgPT09IHRoaXMudGFpbCkge1xuICAgIHRoaXMudGFpbCA9IHByZXZcbiAgfVxuXG4gIG5vZGUubGlzdC5sZW5ndGgtLVxuICBub2RlLm5leHQgPSBudWxsXG4gIG5vZGUucHJldiA9IG51bGxcbiAgbm9kZS5saXN0ID0gbnVsbFxufVxuXG5ZYWxsaXN0LnByb3RvdHlwZS51bnNoaWZ0Tm9kZSA9IGZ1bmN0aW9uIChub2RlKSB7XG4gIGlmIChub2RlID09PSB0aGlzLmhlYWQpIHtcbiAgICByZXR1cm5cbiAgfVxuXG4gIGlmIChub2RlLmxpc3QpIHtcbiAgICBub2RlLmxpc3QucmVtb3ZlTm9kZShub2RlKVxuICB9XG5cbiAgdmFyIGhlYWQgPSB0aGlzLmhlYWRcbiAgbm9kZS5saXN0ID0gdGhpc1xuICBub2RlLm5leHQgPSBoZWFkXG4gIGlmIChoZWFkKSB7XG4gICAgaGVhZC5wcmV2ID0gbm9kZVxuICB9XG5cbiAgdGhpcy5oZWFkID0gbm9kZVxuICBpZiAoIXRoaXMudGFpbCkge1xuICAgIHRoaXMudGFpbCA9IG5vZGVcbiAgfVxuICB0aGlzLmxlbmd0aCsrXG59XG5cbllhbGxpc3QucHJvdG90eXBlLnB1c2hOb2RlID0gZnVuY3Rpb24gKG5vZGUpIHtcbiAgaWYgKG5vZGUgPT09IHRoaXMudGFpbCkge1xuICAgIHJldHVyblxuICB9XG5cbiAgaWYgKG5vZGUubGlzdCkge1xuICAgIG5vZGUubGlzdC5yZW1vdmVOb2RlKG5vZGUpXG4gIH1cblxuICB2YXIgdGFpbCA9IHRoaXMudGFpbFxuICBub2RlLmxpc3QgPSB0aGlzXG4gIG5vZGUucHJldiA9IHRhaWxcbiAgaWYgKHRhaWwpIHtcbiAgICB0YWlsLm5leHQgPSBub2RlXG4gIH1cblxuICB0aGlzLnRhaWwgPSBub2RlXG4gIGlmICghdGhpcy5oZWFkKSB7XG4gICAgdGhpcy5oZWFkID0gbm9kZVxuICB9XG4gIHRoaXMubGVuZ3RoKytcbn1cblxuWWFsbGlzdC5wcm90b3R5cGUucHVzaCA9IGZ1bmN0aW9uICgpIHtcbiAgZm9yICh2YXIgaSA9IDAsIGwgPSBhcmd1bWVudHMubGVuZ3RoOyBpIDwgbDsgaSsrKSB7XG4gICAgcHVzaCh0aGlzLCBhcmd1bWVudHNbaV0pXG4gIH1cbiAgcmV0dXJuIHRoaXMubGVuZ3RoXG59XG5cbllhbGxpc3QucHJvdG90eXBlLnVuc2hpZnQgPSBmdW5jdGlvbiAoKSB7XG4gIGZvciAodmFyIGkgPSAwLCBsID0gYXJndW1lbnRzLmxlbmd0aDsgaSA8IGw7IGkrKykge1xuICAgIHVuc2hpZnQodGhpcywgYXJndW1lbnRzW2ldKVxuICB9XG4gIHJldHVybiB0aGlzLmxlbmd0aFxufVxuXG5ZYWxsaXN0LnByb3RvdHlwZS5wb3AgPSBmdW5jdGlvbiAoKSB7XG4gIGlmICghdGhpcy50YWlsKSB7XG4gICAgcmV0dXJuIHVuZGVmaW5lZFxuICB9XG5cbiAgdmFyIHJlcyA9IHRoaXMudGFpbC52YWx1ZVxuICB0aGlzLnRhaWwgPSB0aGlzLnRhaWwucHJldlxuICBpZiAodGhpcy50YWlsKSB7XG4gICAgdGhpcy50YWlsLm5leHQgPSBudWxsXG4gIH0gZWxzZSB7XG4gICAgdGhpcy5oZWFkID0gbnVsbFxuICB9XG4gIHRoaXMubGVuZ3RoLS1cbiAgcmV0dXJuIHJlc1xufVxuXG5ZYWxsaXN0LnByb3RvdHlwZS5zaGlmdCA9IGZ1bmN0aW9uICgpIHtcbiAgaWYgKCF0aGlzLmhlYWQpIHtcbiAgICByZXR1cm4gdW5kZWZpbmVkXG4gIH1cblxuICB2YXIgcmVzID0gdGhpcy5oZWFkLnZhbHVlXG4gIHRoaXMuaGVhZCA9IHRoaXMuaGVhZC5uZXh0XG4gIGlmICh0aGlzLmhlYWQpIHtcbiAgICB0aGlzLmhlYWQucHJldiA9IG51bGxcbiAgfSBlbHNlIHtcbiAgICB0aGlzLnRhaWwgPSBudWxsXG4gIH1cbiAgdGhpcy5sZW5ndGgtLVxuICByZXR1cm4gcmVzXG59XG5cbllhbGxpc3QucHJvdG90eXBlLmZvckVhY2ggPSBmdW5jdGlvbiAoZm4sIHRoaXNwKSB7XG4gIHRoaXNwID0gdGhpc3AgfHwgdGhpc1xuICBmb3IgKHZhciB3YWxrZXIgPSB0aGlzLmhlYWQsIGkgPSAwOyB3YWxrZXIgIT09IG51bGw7IGkrKykge1xuICAgIGZuLmNhbGwodGhpc3AsIHdhbGtlci52YWx1ZSwgaSwgdGhpcylcbiAgICB3YWxrZXIgPSB3YWxrZXIubmV4dFxuICB9XG59XG5cbllhbGxpc3QucHJvdG90eXBlLmZvckVhY2hSZXZlcnNlID0gZnVuY3Rpb24gKGZuLCB0aGlzcCkge1xuICB0aGlzcCA9IHRoaXNwIHx8IHRoaXNcbiAgZm9yICh2YXIgd2Fsa2VyID0gdGhpcy50YWlsLCBpID0gdGhpcy5sZW5ndGggLSAxOyB3YWxrZXIgIT09IG51bGw7IGktLSkge1xuICAgIGZuLmNhbGwodGhpc3AsIHdhbGtlci52YWx1ZSwgaSwgdGhpcylcbiAgICB3YWxrZXIgPSB3YWxrZXIucHJldlxuICB9XG59XG5cbllhbGxpc3QucHJvdG90eXBlLmdldCA9IGZ1bmN0aW9uIChuKSB7XG4gIGZvciAodmFyIGkgPSAwLCB3YWxrZXIgPSB0aGlzLmhlYWQ7IHdhbGtlciAhPT0gbnVsbCAmJiBpIDwgbjsgaSsrKSB7XG4gICAgLy8gYWJvcnQgb3V0IG9mIHRoZSBsaXN0IGVhcmx5IGlmIHdlIGhpdCBhIGN5Y2xlXG4gICAgd2Fsa2VyID0gd2Fsa2VyLm5leHRcbiAgfVxuICBpZiAoaSA9PT0gbiAmJiB3YWxrZXIgIT09IG51bGwpIHtcbiAgICByZXR1cm4gd2Fsa2VyLnZhbHVlXG4gIH1cbn1cblxuWWFsbGlzdC5wcm90b3R5cGUuZ2V0UmV2ZXJzZSA9IGZ1bmN0aW9uIChuKSB7XG4gIGZvciAodmFyIGkgPSAwLCB3YWxrZXIgPSB0aGlzLnRhaWw7IHdhbGtlciAhPT0gbnVsbCAmJiBpIDwgbjsgaSsrKSB7XG4gICAgLy8gYWJvcnQgb3V0IG9mIHRoZSBsaXN0IGVhcmx5IGlmIHdlIGhpdCBhIGN5Y2xlXG4gICAgd2Fsa2VyID0gd2Fsa2VyLnByZXZcbiAgfVxuICBpZiAoaSA9PT0gbiAmJiB3YWxrZXIgIT09IG51bGwpIHtcbiAgICByZXR1cm4gd2Fsa2VyLnZhbHVlXG4gIH1cbn1cblxuWWFsbGlzdC5wcm90b3R5cGUubWFwID0gZnVuY3Rpb24gKGZuLCB0aGlzcCkge1xuICB0aGlzcCA9IHRoaXNwIHx8IHRoaXNcbiAgdmFyIHJlcyA9IG5ldyBZYWxsaXN0KClcbiAgZm9yICh2YXIgd2Fsa2VyID0gdGhpcy5oZWFkOyB3YWxrZXIgIT09IG51bGw7KSB7XG4gICAgcmVzLnB1c2goZm4uY2FsbCh0aGlzcCwgd2Fsa2VyLnZhbHVlLCB0aGlzKSlcbiAgICB3YWxrZXIgPSB3YWxrZXIubmV4dFxuICB9XG4gIHJldHVybiByZXNcbn1cblxuWWFsbGlzdC5wcm90b3R5cGUubWFwUmV2ZXJzZSA9IGZ1bmN0aW9uIChmbiwgdGhpc3ApIHtcbiAgdGhpc3AgPSB0aGlzcCB8fCB0aGlzXG4gIHZhciByZXMgPSBuZXcgWWFsbGlzdCgpXG4gIGZvciAodmFyIHdhbGtlciA9IHRoaXMudGFpbDsgd2Fsa2VyICE9PSBudWxsOykge1xuICAgIHJlcy5wdXNoKGZuLmNhbGwodGhpc3AsIHdhbGtlci52YWx1ZSwgdGhpcykpXG4gICAgd2Fsa2VyID0gd2Fsa2VyLnByZXZcbiAgfVxuICByZXR1cm4gcmVzXG59XG5cbllhbGxpc3QucHJvdG90eXBlLnJlZHVjZSA9IGZ1bmN0aW9uIChmbiwgaW5pdGlhbCkge1xuICB2YXIgYWNjXG4gIHZhciB3YWxrZXIgPSB0aGlzLmhlYWRcbiAgaWYgKGFyZ3VtZW50cy5sZW5ndGggPiAxKSB7XG4gICAgYWNjID0gaW5pdGlhbFxuICB9IGVsc2UgaWYgKHRoaXMuaGVhZCkge1xuICAgIHdhbGtlciA9IHRoaXMuaGVhZC5uZXh0XG4gICAgYWNjID0gdGhpcy5oZWFkLnZhbHVlXG4gIH0gZWxzZSB7XG4gICAgdGhyb3cgbmV3IFR5cGVFcnJvcignUmVkdWNlIG9mIGVtcHR5IGxpc3Qgd2l0aCBubyBpbml0aWFsIHZhbHVlJylcbiAgfVxuXG4gIGZvciAodmFyIGkgPSAwOyB3YWxrZXIgIT09IG51bGw7IGkrKykge1xuICAgIGFjYyA9IGZuKGFjYywgd2Fsa2VyLnZhbHVlLCBpKVxuICAgIHdhbGtlciA9IHdhbGtlci5uZXh0XG4gIH1cblxuICByZXR1cm4gYWNjXG59XG5cbllhbGxpc3QucHJvdG90eXBlLnJlZHVjZVJldmVyc2UgPSBmdW5jdGlvbiAoZm4sIGluaXRpYWwpIHtcbiAgdmFyIGFjY1xuICB2YXIgd2Fsa2VyID0gdGhpcy50YWlsXG4gIGlmIChhcmd1bWVudHMubGVuZ3RoID4gMSkge1xuICAgIGFjYyA9IGluaXRpYWxcbiAgfSBlbHNlIGlmICh0aGlzLnRhaWwpIHtcbiAgICB3YWxrZXIgPSB0aGlzLnRhaWwucHJldlxuICAgIGFjYyA9IHRoaXMudGFpbC52YWx1ZVxuICB9IGVsc2Uge1xuICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ1JlZHVjZSBvZiBlbXB0eSBsaXN0IHdpdGggbm8gaW5pdGlhbCB2YWx1ZScpXG4gIH1cblxuICBmb3IgKHZhciBpID0gdGhpcy5sZW5ndGggLSAxOyB3YWxrZXIgIT09IG51bGw7IGktLSkge1xuICAgIGFjYyA9IGZuKGFjYywgd2Fsa2VyLnZhbHVlLCBpKVxuICAgIHdhbGtlciA9IHdhbGtlci5wcmV2XG4gIH1cblxuICByZXR1cm4gYWNjXG59XG5cbllhbGxpc3QucHJvdG90eXBlLnRvQXJyYXkgPSBmdW5jdGlvbiAoKSB7XG4gIHZhciBhcnIgPSBuZXcgQXJyYXkodGhpcy5sZW5ndGgpXG4gIGZvciAodmFyIGkgPSAwLCB3YWxrZXIgPSB0aGlzLmhlYWQ7IHdhbGtlciAhPT0gbnVsbDsgaSsrKSB7XG4gICAgYXJyW2ldID0gd2Fsa2VyLnZhbHVlXG4gICAgd2Fsa2VyID0gd2Fsa2VyLm5leHRcbiAgfVxuICByZXR1cm4gYXJyXG59XG5cbllhbGxpc3QucHJvdG90eXBlLnRvQXJyYXlSZXZlcnNlID0gZnVuY3Rpb24gKCkge1xuICB2YXIgYXJyID0gbmV3IEFycmF5KHRoaXMubGVuZ3RoKVxuICBmb3IgKHZhciBpID0gMCwgd2Fsa2VyID0gdGhpcy50YWlsOyB3YWxrZXIgIT09IG51bGw7IGkrKykge1xuICAgIGFycltpXSA9IHdhbGtlci52YWx1ZVxuICAgIHdhbGtlciA9IHdhbGtlci5wcmV2XG4gIH1cbiAgcmV0dXJuIGFyclxufVxuXG5ZYWxsaXN0LnByb3RvdHlwZS5zbGljZSA9IGZ1bmN0aW9uIChmcm9tLCB0bykge1xuICB0byA9IHRvIHx8IHRoaXMubGVuZ3RoXG4gIGlmICh0byA8IDApIHtcbiAgICB0byArPSB0aGlzLmxlbmd0aFxuICB9XG4gIGZyb20gPSBmcm9tIHx8IDBcbiAgaWYgKGZyb20gPCAwKSB7XG4gICAgZnJvbSArPSB0aGlzLmxlbmd0aFxuICB9XG4gIHZhciByZXQgPSBuZXcgWWFsbGlzdCgpXG4gIGlmICh0byA8IGZyb20gfHwgdG8gPCAwKSB7XG4gICAgcmV0dXJuIHJldFxuICB9XG4gIGlmIChmcm9tIDwgMCkge1xuICAgIGZyb20gPSAwXG4gIH1cbiAgaWYgKHRvID4gdGhpcy5sZW5ndGgpIHtcbiAgICB0byA9IHRoaXMubGVuZ3RoXG4gIH1cbiAgZm9yICh2YXIgaSA9IDAsIHdhbGtlciA9IHRoaXMuaGVhZDsgd2Fsa2VyICE9PSBudWxsICYmIGkgPCBmcm9tOyBpKyspIHtcbiAgICB3YWxrZXIgPSB3YWxrZXIubmV4dFxuICB9XG4gIGZvciAoOyB3YWxrZXIgIT09IG51bGwgJiYgaSA8IHRvOyBpKyssIHdhbGtlciA9IHdhbGtlci5uZXh0KSB7XG4gICAgcmV0LnB1c2god2Fsa2VyLnZhbHVlKVxuICB9XG4gIHJldHVybiByZXRcbn1cblxuWWFsbGlzdC5wcm90b3R5cGUuc2xpY2VSZXZlcnNlID0gZnVuY3Rpb24gKGZyb20sIHRvKSB7XG4gIHRvID0gdG8gfHwgdGhpcy5sZW5ndGhcbiAgaWYgKHRvIDwgMCkge1xuICAgIHRvICs9IHRoaXMubGVuZ3RoXG4gIH1cbiAgZnJvbSA9IGZyb20gfHwgMFxuICBpZiAoZnJvbSA8IDApIHtcbiAgICBmcm9tICs9IHRoaXMubGVuZ3RoXG4gIH1cbiAgdmFyIHJldCA9IG5ldyBZYWxsaXN0KClcbiAgaWYgKHRvIDwgZnJvbSB8fCB0byA8IDApIHtcbiAgICByZXR1cm4gcmV0XG4gIH1cbiAgaWYgKGZyb20gPCAwKSB7XG4gICAgZnJvbSA9IDBcbiAgfVxuICBpZiAodG8gPiB0aGlzLmxlbmd0aCkge1xuICAgIHRvID0gdGhpcy5sZW5ndGhcbiAgfVxuICBmb3IgKHZhciBpID0gdGhpcy5sZW5ndGgsIHdhbGtlciA9IHRoaXMudGFpbDsgd2Fsa2VyICE9PSBudWxsICYmIGkgPiB0bzsgaS0tKSB7XG4gICAgd2Fsa2VyID0gd2Fsa2VyLnByZXZcbiAgfVxuICBmb3IgKDsgd2Fsa2VyICE9PSBudWxsICYmIGkgPiBmcm9tOyBpLS0sIHdhbGtlciA9IHdhbGtlci5wcmV2KSB7XG4gICAgcmV0LnB1c2god2Fsa2VyLnZhbHVlKVxuICB9XG4gIHJldHVybiByZXRcbn1cblxuWWFsbGlzdC5wcm90b3R5cGUucmV2ZXJzZSA9IGZ1bmN0aW9uICgpIHtcbiAgdmFyIGhlYWQgPSB0aGlzLmhlYWRcbiAgdmFyIHRhaWwgPSB0aGlzLnRhaWxcbiAgZm9yICh2YXIgd2Fsa2VyID0gaGVhZDsgd2Fsa2VyICE9PSBudWxsOyB3YWxrZXIgPSB3YWxrZXIucHJldikge1xuICAgIHZhciBwID0gd2Fsa2VyLnByZXZcbiAgICB3YWxrZXIucHJldiA9IHdhbGtlci5uZXh0XG4gICAgd2Fsa2VyLm5leHQgPSBwXG4gIH1cbiAgdGhpcy5oZWFkID0gdGFpbFxuICB0aGlzLnRhaWwgPSBoZWFkXG4gIHJldHVybiB0aGlzXG59XG5cbmZ1bmN0aW9uIHB1c2ggKHNlbGYsIGl0ZW0pIHtcbiAgc2VsZi50YWlsID0gbmV3IE5vZGUoaXRlbSwgc2VsZi50YWlsLCBudWxsLCBzZWxmKVxuICBpZiAoIXNlbGYuaGVhZCkge1xuICAgIHNlbGYuaGVhZCA9IHNlbGYudGFpbFxuICB9XG4gIHNlbGYubGVuZ3RoKytcbn1cblxuZnVuY3Rpb24gdW5zaGlmdCAoc2VsZiwgaXRlbSkge1xuICBzZWxmLmhlYWQgPSBuZXcgTm9kZShpdGVtLCBudWxsLCBzZWxmLmhlYWQsIHNlbGYpXG4gIGlmICghc2VsZi50YWlsKSB7XG4gICAgc2VsZi50YWlsID0gc2VsZi5oZWFkXG4gIH1cbiAgc2VsZi5sZW5ndGgrK1xufVxuXG5mdW5jdGlvbiBOb2RlICh2YWx1ZSwgcHJldiwgbmV4dCwgbGlzdCkge1xuICBpZiAoISh0aGlzIGluc3RhbmNlb2YgTm9kZSkpIHtcbiAgICByZXR1cm4gbmV3IE5vZGUodmFsdWUsIHByZXYsIG5leHQsIGxpc3QpXG4gIH1cblxuICB0aGlzLmxpc3QgPSBsaXN0XG4gIHRoaXMudmFsdWUgPSB2YWx1ZVxuXG4gIGlmIChwcmV2KSB7XG4gICAgcHJldi5uZXh0ID0gdGhpc1xuICAgIHRoaXMucHJldiA9IHByZXZcbiAgfSBlbHNlIHtcbiAgICB0aGlzLnByZXYgPSBudWxsXG4gIH1cblxuICBpZiAobmV4dCkge1xuICAgIG5leHQucHJldiA9IHRoaXNcbiAgICB0aGlzLm5leHQgPSBuZXh0XG4gIH0gZWxzZSB7XG4gICAgdGhpcy5uZXh0ID0gbnVsbFxuICB9XG59XG4iLCJpZiAodHlwZW9mIHJlcXVpcmUgIT09ICd1bmRlZmluZWQnKSB7XG4gIGlmICh0eXBlb2YgRmlyZWJhc2UgPT09ICd1bmRlZmluZWQnKSBGaXJlYmFzZSA9IHJlcXVpcmUoJ2ZpcmViYXNlJyk7XG4gIGlmICh0eXBlb2YgTFJVQ2FjaGUgPT09ICd1bmRlZmluZWQnKSBMUlVDYWNoZSA9IHJlcXVpcmUoJ2xydS1jYWNoZScpO1xuICBpZiAodHlwZW9mIENyeXB0b0pTID09PSAndW5kZWZpbmVkJykgQ3J5cHRvSlMgPSByZXF1aXJlKCdjcnlwdG8tanMvY29yZScpO1xuICByZXF1aXJlKCdjcnlwdG8tanMvZW5jLWJhc2U2NCcpO1xuICByZXF1aXJlKCdjcnlwdG9qcy1leHRlbnNpb24vYnVpbGRfbm9kZS9zaXYnKTtcbiAgdHJ5IHtcbiAgICByZXF1aXJlKCdmaXJlYmFzZS1jaGlsZHJlbmtleXMnKTtcbiAgfSBjYXRjaCAoZSkge1xuICAgIC8vIGlnbm9yZSwgbm90IGluc3RhbGxlZFxuICB9XG59XG5cbkNyeXB0b0pTLmVuYy5CYXNlNjRVcmxTYWZlID0ge1xuICBzdHJpbmdpZnk6IENyeXB0b0pTLmVuYy5CYXNlNjQuc3RyaW5naWZ5LFxuICBwYXJzZTogQ3J5cHRvSlMuZW5jLkJhc2U2NC5wYXJzZSxcbiAgX21hcDogJ0FCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5LV8nXG59O1xuXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICB2YXIgZmJwID0gRmlyZWJhc2UucHJvdG90eXBlO1xuICB2YXIgb3JpZ2luYWxRdWVyeUZicCA9IHt9O1xuICB2YXIgZmlyZWJhc2VXcmFwcGVkID0gZmFsc2U7XG4gIHZhciBlbmNyeXB0U3RyaW5nLCBkZWNyeXB0U3RyaW5nO1xuXG4gIHZhciB1dGlscyA9IHJlcXVpcmUoJy4vdXRpbHMnKTtcblxuICBGaXJlYmFzZS5pbml0aWFsaXplRW5jcnlwdGlvbiA9IGZ1bmN0aW9uKG9wdGlvbnMsIHNwZWNpZmljYXRpb24pIHtcbiAgICB2YXIgcmVzdWx0O1xuICAgIG9wdGlvbnMuY2FjaGVTaXplID0gb3B0aW9ucy5jYWNoZVNpemUgfHwgNSAqIDEwMDAgKiAxMDAwO1xuICAgIG9wdGlvbnMuZW5jcnlwdGlvbkNhY2hlU2l6ZSA9IG9wdGlvbnMuZW5jcnlwdGlvbkNhY2hlU2l6ZSB8fCBvcHRpb25zLmNhY2hlU2l6ZTtcbiAgICBvcHRpb25zLmRlY3J5cHRpb25DYWNoZVNpemUgPSBvcHRpb25zLmRlY3J5cHRpb25DYWNoZVNpemUgfHwgb3B0aW9ucy5jYWNoZVNpemU7XG4gICAgZW5jcnlwdFN0cmluZyA9IGRlY3J5cHRTdHJpbmcgPSB1dGlscy50aHJvd05vdFNldFVwRXJyb3I7XG4gICAgaWYgKHR5cGVvZiBMUlVDYWNoZSA9PT0gJ2Z1bmN0aW9uJykge1xuICAgICAgdXRpbHMuc2V0RW5jcnlwdGlvbkNhY2hlKG5ldyBMUlVDYWNoZSh7XG4gICAgICAgIG1heDogb3B0aW9ucy5lbmNyeXB0aW9uQ2FjaGVTaXplLCBsZW5ndGg6IHV0aWxzLmNvbXB1dGVDYWNoZUl0ZW1TaXplXG4gICAgICB9KSk7XG4gICAgICB1dGlscy5zZXREZWNyeXB0aW9uQ2FjaGUobmV3IExSVUNhY2hlKHtcbiAgICAgICAgbWF4OiBvcHRpb25zLmRlY3J5cHRpb25DYWNoZVNpemUsIGxlbmd0aDogdXRpbHMuY29tcHV0ZUNhY2hlSXRlbVNpemVcbiAgICAgIH0pKTtcbiAgICB9XG4gICAgc3dpdGNoIChvcHRpb25zLmFsZ29yaXRobSkge1xuICAgICAgY2FzZSAnYWVzLXNpdic6XG4gICAgICAgIGlmICghb3B0aW9ucy5rZXkpIHRocm93IG5ldyBFcnJvcignWW91IG11c3Qgc3BlY2lmeSBhIGtleSB0byB1c2UgQUVTIGVuY3J5cHRpb24uJyk7XG4gICAgICAgIHJlc3VsdCA9IHNldHVwQWVzU2l2KG9wdGlvbnMua2V5LCBvcHRpb25zLmtleUNoZWNrVmFsdWUpO1xuICAgICAgICBicmVhaztcbiAgICAgIGNhc2UgJ3Bhc3N0aHJvdWdoJzpcbiAgICAgICAgZW5jcnlwdFN0cmluZyA9IGRlY3J5cHRTdHJpbmcgPSBmdW5jdGlvbihzdHIpIHtyZXR1cm4gc3RyO307XG4gICAgICAgIGJyZWFrO1xuICAgICAgY2FzZSAnbm9uZSc6XG4gICAgICAgIGJyZWFrO1xuICAgICAgZGVmYXVsdDpcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdVbmtub3duIGVuY3J5cHRpb24gYWxnb3JpdGhtIFwiJyArIG9wdGlvbnMuYWxnb3JpdGhtICsgJ1wiLicpO1xuICAgIH1cbiAgICB1dGlscy5zZXRTcGVjKHNwZWNpZmljYXRpb24pO1xuICAgIHdyYXBGaXJlYmFzZSgpO1xuICAgIHJldHVybiByZXN1bHQ7XG4gIH07XG5cbiAgZnVuY3Rpb24gc2V0dXBBZXNTaXYoa2V5LCBjaGVja1ZhbHVlKSB7XG4gICAgdmFyIHNpdiA9IENyeXB0b0pTLlNJVi5jcmVhdGUoQ3J5cHRvSlMuZW5jLkJhc2U2NC5wYXJzZShrZXkpKTtcbiAgICBlbmNyeXB0U3RyaW5nID0gZnVuY3Rpb24oc3RyKSB7XG4gICAgICByZXR1cm4gQ3J5cHRvSlMuZW5jLkJhc2U2NFVybFNhZmUuc3RyaW5naWZ5KHNpdi5lbmNyeXB0KHN0cikpO1xuICAgIH07XG4gICAgZGVjcnlwdFN0cmluZyA9IGZ1bmN0aW9uKHN0cikge1xuICAgICAgdmFyIHJlc3VsdCA9IHNpdi5kZWNyeXB0KENyeXB0b0pTLmVuYy5CYXNlNjRVcmxTYWZlLnBhcnNlKHN0cikpO1xuICAgICAgaWYgKHJlc3VsdCA9PT0gZmFsc2UpIHtcbiAgICAgICAgdmFyIGUgPSBuZXcgRXJyb3IoJ1dyb25nIGRlY3J5cHRpb24ga2V5Jyk7XG4gICAgICAgIGUuZmlyZWNyeXB0ID0gJ1dST05HX0tFWSc7XG4gICAgICAgIHRocm93IGU7XG4gICAgICB9XG4gICAgICByZXR1cm4gQ3J5cHRvSlMuZW5jLlV0Zjguc3RyaW5naWZ5KHJlc3VsdCk7XG4gICAgfTtcbiAgICBpZiAoY2hlY2tWYWx1ZSkgZGVjcnlwdFN0cmluZyhjaGVja1ZhbHVlKTtcbiAgICByZXR1cm4gZW5jcnlwdFN0cmluZyhDcnlwdG9KUy5lbmMuQmFzZTY0VXJsU2FmZS5zdHJpbmdpZnkoQ3J5cHRvSlMubGliLldvcmRBcnJheS5yYW5kb20oMTApKSk7XG4gIH1cblxuICBmdW5jdGlvbiBRdWVyeShxdWVyeSwgb3JkZXIsIG9yaWdpbmFsKSB7XG4gICAgdGhpcy5fcXVlcnkgPSBxdWVyeTtcbiAgICB0aGlzLl9vcmRlciA9IG9yZGVyIHx8IHt9O1xuICAgIHRoaXMuX29yaWdpbmFsID0gb3JpZ2luYWwgfHwgcXVlcnk7XG4gIH1cbiAgUXVlcnkucHJvdG90eXBlLm9uID0gZnVuY3Rpb24oZXZlbnRUeXBlLCBjYWxsYmFjaywgY2FuY2VsQ2FsbGJhY2ssIGNvbnRleHQpIHtcbiAgICB3cmFwUXVlcnlDYWxsYmFjayhjYWxsYmFjayk7XG4gICAgcmV0dXJuIHRoaXMuX29yaWdpbmFsLm9uLmNhbGwoXG4gICAgICB0aGlzLl9xdWVyeSwgZXZlbnRUeXBlLCBjYWxsYmFjay5maXJlY3J5cHRDYWxsYmFjaywgY2FuY2VsQ2FsbGJhY2ssIGNvbnRleHQpO1xuICB9O1xuICBRdWVyeS5wcm90b3R5cGUub2ZmID0gZnVuY3Rpb24oZXZlbnRUeXBlLCBjYWxsYmFjaywgY29udGV4dCkge1xuICAgIGlmIChjYWxsYmFjayAmJiBjYWxsYmFjay5maXJlY3J5cHRDYWxsYmFjaykgY2FsbGJhY2sgPSBjYWxsYmFjay5maXJlY3J5cHRDYWxsYmFjaztcbiAgICByZXR1cm4gdGhpcy5fb3JpZ2luYWwub2ZmLmNhbGwodGhpcy5fcXVlcnksIGV2ZW50VHlwZSwgY2FsbGJhY2ssIGNvbnRleHQpO1xuICB9O1xuICBRdWVyeS5wcm90b3R5cGUub25jZSA9IGZ1bmN0aW9uKGV2ZW50VHlwZSwgc3VjY2Vzc0NhbGxiYWNrLCBmYWlsdXJlQ2FsbGJhY2ssIGNvbnRleHQpIHtcbiAgICB3cmFwUXVlcnlDYWxsYmFjayhzdWNjZXNzQ2FsbGJhY2spO1xuICAgIHJldHVybiB0aGlzLl9vcmlnaW5hbC5vbmNlLmNhbGwoXG4gICAgICB0aGlzLl9xdWVyeSwgZXZlbnRUeXBlLCBzdWNjZXNzQ2FsbGJhY2sgJiYgc3VjY2Vzc0NhbGxiYWNrLmZpcmVjcnlwdENhbGxiYWNrLCBmYWlsdXJlQ2FsbGJhY2ssXG4gICAgICBjb250ZXh0XG4gICAgKS50aGVuKGZ1bmN0aW9uKHNuYXApIHtcbiAgICAgIHJldHVybiBuZXcgU25hcHNob3Qoc25hcCk7XG4gICAgfSk7XG4gIH07XG4gIFF1ZXJ5LnByb3RvdHlwZS5vcmRlckJ5Q2hpbGQgPSBmdW5jdGlvbihrZXkpIHtcbiAgICByZXR1cm4gdGhpcy5fb3JkZXJCeSgnb3JkZXJCeUNoaWxkJywgJ2NoaWxkJywga2V5KTtcbiAgfTtcbiAgUXVlcnkucHJvdG90eXBlLm9yZGVyQnlLZXkgPSBmdW5jdGlvbigpIHtcbiAgICByZXR1cm4gdGhpcy5fb3JkZXJCeSgnb3JkZXJCeUtleScsICdrZXknKTtcbiAgfTtcbiAgUXVlcnkucHJvdG90eXBlLm9yZGVyQnlWYWx1ZSA9IGZ1bmN0aW9uKCkge1xuICAgIHJldHVybiB0aGlzLl9vcmRlckJ5KCdvcmRlckJ5VmFsdWUnLCAndmFsdWUnKTtcbiAgfTtcbiAgUXVlcnkucHJvdG90eXBlLm9yZGVyQnlQcmlvcml0eSA9IGZ1bmN0aW9uKCkge1xuICAgIHJldHVybiB0aGlzLl9vcmRlckJ5KCdvcmRlckJ5UHJpb3JpdHknLCAncHJpb3JpdHknKTtcbiAgfTtcbiAgUXVlcnkucHJvdG90eXBlLnN0YXJ0QXQgPSBmdW5jdGlvbih2YWx1ZSwga2V5KSB7XG4gICAgdGhpcy5fY2hlY2tDYW5Tb3J0KGtleSAhPT0gdW5kZWZpbmVkKTtcbiAgICByZXR1cm4gdGhpcy5fZGVsZWdhdGUoJ3N0YXJ0QXQnLCBhcmd1bWVudHMpO1xuICB9O1xuICBRdWVyeS5wcm90b3R5cGUuZW5kQXQgPSBmdW5jdGlvbih2YWx1ZSwga2V5KSB7XG4gICAgdGhpcy5fY2hlY2tDYW5Tb3J0KGtleSAhPT0gdW5kZWZpbmVkKTtcbiAgICByZXR1cm4gdGhpcy5fZGVsZWdhdGUoJ2VuZEF0JywgYXJndW1lbnRzKTtcbiAgfTtcbiAgUXVlcnkucHJvdG90eXBlLmVxdWFsVG8gPSBmdW5jdGlvbih2YWx1ZSwga2V5KSB7XG4gICAgaWYgKHRoaXMuX29yZGVyW3RoaXMuX29yZGVyLmJ5ICsgJ0VuY3J5cHRlZCddKSB7XG4gICAgICB2YWx1ZSA9IHV0aWxzLmVuY3J5cHQodmFsdWUsIHV0aWxzLmdldFR5cGUodmFsdWUpLCB0aGlzLl9vcmRlclt0aGlzLl9vcmRlci5ieSArICdFbmNyeXB0ZWQnXSk7XG4gICAgfVxuICAgIGlmIChrZXkgIT09IHVuZGVmaW5lZCAmJiB0aGlzLl9vcmRlci5rZXlFbmNyeXB0ZWQpIHtcbiAgICAgIGtleSA9IHV0aWxzLmVuY3J5cHQoa2V5LCAnc3RyaW5nJywgdGhpcy5fb3JkZXIua2V5RW5jcnlwdGVkKTtcbiAgICB9XG4gICAgcmV0dXJuIG5ldyBRdWVyeSh0aGlzLl9vcmlnaW5hbC5lcXVhbFRvLmNhbGwodGhpcy5fcXVlcnksIHZhbHVlLCBrZXkpLCB0aGlzLl9vcmRlcik7XG4gIH07XG4gIFF1ZXJ5LnByb3RvdHlwZS5saW1pdFRvRmlyc3QgPSBmdW5jdGlvbigpIHtcbiAgICByZXR1cm4gdGhpcy5fZGVsZWdhdGUoJ2xpbWl0VG9GaXJzdCcsIGFyZ3VtZW50cyk7XG4gIH07XG4gIFF1ZXJ5LnByb3RvdHlwZS5saW1pdFRvTGFzdCA9IGZ1bmN0aW9uKCkge1xuICAgIHJldHVybiB0aGlzLl9kZWxlZ2F0ZSgnbGltaXRUb0xhc3QnLCBhcmd1bWVudHMpO1xuICB9O1xuICBRdWVyeS5wcm90b3R5cGUubGltaXQgPSBmdW5jdGlvbigpIHtcbiAgICByZXR1cm4gdGhpcy5fZGVsZWdhdGUoJ2xpbWl0JywgYXJndW1lbnRzKTtcbiAgfTtcbiAgUXVlcnkucHJvdG90eXBlLnJlZiA9IGZ1bmN0aW9uKCkge1xuICAgIHJldHVybiB1dGlscy5kZWNyeXB0UmVmKHRoaXMuX29yaWdpbmFsLnJlZi5jYWxsKHRoaXMuX3F1ZXJ5KSk7XG4gIH07XG4gIFF1ZXJ5LnByb3RvdHlwZS5fZGVsZWdhdGUgPSBmdW5jdGlvbihtZXRob2ROYW1lLCBhcmdzKSB7XG4gICAgcmV0dXJuIG5ldyBRdWVyeSh0aGlzLl9vcmlnaW5hbFttZXRob2ROYW1lXS5hcHBseSh0aGlzLl9xdWVyeSwgYXJncyksIHRoaXMuX29yZGVyKTtcbiAgfTtcbiAgUXVlcnkucHJvdG90eXBlLl9jaGVja0NhblNvcnQgPSBmdW5jdGlvbihoYXNFeHRyYUtleSkge1xuICAgIGlmICh0aGlzLl9vcmRlci5ieSA9PT0gJ2tleScgP1xuICAgICAgICB0aGlzLl9vcmRlci5rZXlFbmNyeXB0ZWQgOlxuICAgICAgICB0aGlzLl9vcmRlci52YWx1ZUVuY3J5cHRlZCB8fCBoYXNFeHRyYUtleSAmJiB0aGlzLl9vcmRlci5rZXlFbmNyeXB0ZWQpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignRW5jcnlwdGVkIGl0ZW1zIGNhbm5vdCBiZSBvcmRlcmVkJyk7XG4gICAgfVxuICB9O1xuICBRdWVyeS5wcm90b3R5cGUuX29yZGVyQnkgPSBmdW5jdGlvbihtZXRob2ROYW1lLCBieSwgY2hpbGRLZXkpIHtcbiAgICB2YXIgZGVmID0gdXRpbHMuc3BlY0ZvclBhdGgodXRpbHMucmVmVG9QYXRoKHRoaXMucmVmKCkpKTtcbiAgICB2YXIgb3JkZXIgPSB7Ynk6IGJ5fTtcbiAgICB2YXIgZW5jcnlwdGVkQ2hpbGRLZXk7XG4gICAgaWYgKGRlZikge1xuICAgICAgdmFyIGNoaWxkUGF0aCA9IGNoaWxkS2V5ICYmIGNoaWxkS2V5LnNwbGl0KCcvJyk7XG4gICAgICBmb3IgKHZhciBzdWJLZXkgaW4gZGVmKSB7XG4gICAgICAgIGlmICghZGVmLmhhc093blByb3BlcnR5KHN1YktleSkpIGNvbnRpbnVlO1xuICAgICAgICB2YXIgc3ViRGVmID0gZGVmW3N1YktleV07XG4gICAgICAgIGlmIChzdWJEZWZbJy5lbmNyeXB0J10pIHtcbiAgICAgICAgICBpZiAoc3ViRGVmWycuZW5jcnlwdCddLmtleSkgb3JkZXIua2V5RW5jcnlwdGVkID0gc3ViRGVmWycuZW5jcnlwdCddLmtleTtcbiAgICAgICAgICBpZiAoc3ViRGVmWycuZW5jcnlwdCddLnZhbHVlKSBvcmRlci52YWx1ZUVuY3J5cHRlZCA9IHN1YkRlZlsnLmVuY3J5cHQnXS52YWx1ZTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoY2hpbGRLZXkpIHtcbiAgICAgICAgICB2YXIgY2hpbGREZWYgPSB1dGlscy5zcGVjRm9yUGF0aChjaGlsZFBhdGgsIHN1YkRlZik7XG4gICAgICAgICAgaWYgKGNoaWxkRGVmICYmIGNoaWxkRGVmWycuZW5jcnlwdCddICYmIGNoaWxkRGVmWycuZW5jcnlwdCddLnZhbHVlKSB7XG4gICAgICAgICAgICBvcmRlci5jaGlsZEVuY3J5cHRlZCA9IGNoaWxkRGVmWycuZW5jcnlwdCddLnZhbHVlO1xuICAgICAgICAgIH1cbiAgICAgICAgICB2YXIgZW5jcnlwdGVkQ2hpbGRLZXlDYW5kaWRhdGUgPSB1dGlscy5lbmNyeXB0UGF0aChjaGlsZFBhdGgsIHN1YkRlZikuam9pbignLycpO1xuICAgICAgICAgIGlmIChlbmNyeXB0ZWRDaGlsZEtleSAmJiBlbmNyeXB0ZWRDaGlsZEtleUNhbmRpZGF0ZSAhPT0gZW5jcnlwdGVkQ2hpbGRLZXkpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgICAgICAgJ0luY29tcGF0aWJsZSBlbmNyeXB0aW9uIHNwZWNpZmljYXRpb25zIGZvciBvcmRlckJ5Q2hpbGQoXCInICsgY2hpbGRLZXkgKyAnXCIpJyk7XG4gICAgICAgICAgfVxuICAgICAgICAgIGVuY3J5cHRlZENoaWxkS2V5ID0gZW5jcnlwdGVkQ2hpbGRLZXlDYW5kaWRhdGU7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9XG4gICAgaWYgKGNoaWxkS2V5KSB7XG4gICAgICByZXR1cm4gbmV3IFF1ZXJ5KFxuICAgICAgICB0aGlzLl9vcmlnaW5hbFttZXRob2ROYW1lXS5jYWxsKHRoaXMuX3F1ZXJ5LCBlbmNyeXB0ZWRDaGlsZEtleSB8fCBjaGlsZEtleSksIG9yZGVyKTtcbiAgICB9IGVsc2Uge1xuICAgICAgcmV0dXJuIG5ldyBRdWVyeSh0aGlzLl9vcmlnaW5hbFttZXRob2ROYW1lXS5jYWxsKHRoaXMuX3F1ZXJ5KSwgb3JkZXIpO1xuICAgIH1cbiAgfTtcblxuXG4gIGZ1bmN0aW9uIFNuYXBzaG90KHNuYXApIHtcbiAgICB0aGlzLl9yZWYgPSB1dGlscy5kZWNyeXB0UmVmKHNuYXAucmVmKCkpO1xuICAgIHRoaXMuX3BhdGggPSB1dGlscy5yZWZUb1BhdGgodGhpcy5fcmVmKTtcbiAgICB0aGlzLl9zbmFwID0gc25hcDtcbiAgfVxuICBkZWxlZ2F0ZVNuYXBzaG90KCdleGlzdHMnKTtcbiAgZGVsZWdhdGVTbmFwc2hvdCgnaGFzQ2hpbGRyZW4nKTtcbiAgZGVsZWdhdGVTbmFwc2hvdCgnbnVtQ2hpbGRyZW4nKTtcbiAgZGVsZWdhdGVTbmFwc2hvdCgnZ2V0UHJpb3JpdHknKTtcbiAgU25hcHNob3QucHJvdG90eXBlLnZhbCA9IGZ1bmN0aW9uKCkge1xuICAgIHJldHVybiB1dGlscy50cmFuc2Zvcm1WYWx1ZSh0aGlzLl9wYXRoLCB0aGlzLl9zbmFwLnZhbCgpLCB1dGlscy5kZWNyeXB0KTtcbiAgfTtcbiAgU25hcHNob3QucHJvdG90eXBlLmNoaWxkID0gZnVuY3Rpb24oY2hpbGRQYXRoKSB7XG4gICAgcmV0dXJuIG5ldyBTbmFwc2hvdCh0aGlzLl9zbmFwLmNoaWxkKGNoaWxkUGF0aCkpO1xuICB9O1xuICBTbmFwc2hvdC5wcm90b3R5cGUuZm9yRWFjaCA9IGZ1bmN0aW9uKGFjdGlvbikge1xuICAgIHJldHVybiB0aGlzLl9zbmFwLmZvckVhY2goZnVuY3Rpb24oY2hpbGRTbmFwKSB7XG4gICAgICByZXR1cm4gYWN0aW9uKG5ldyBTbmFwc2hvdChjaGlsZFNuYXApKTtcbiAgICB9KTtcbiAgfTtcbiAgU25hcHNob3QucHJvdG90eXBlLmhhc0NoaWxkID0gZnVuY3Rpb24oY2hpbGRQYXRoKSB7XG4gICAgY2hpbGRQYXRoID0gdXRpbHMuZW5jcnlwdFBhdGgoY2hpbGRQYXRoLnNwbGl0KCcvJyksIHV0aWxzLnNwZWNGb3JQYXRoKHRoaXMuX3BhdGgpKS5qb2luKCcvJyk7XG4gICAgcmV0dXJuIHRoaXMuX3NuYXAuaGFzQ2hpbGQoY2hpbGRQYXRoKTtcbiAgfTtcbiAgU25hcHNob3QucHJvdG90eXBlLmtleSA9IGZ1bmN0aW9uKCkge1xuICAgIHJldHVybiB0aGlzLl9yZWYua2V5KCk7XG4gIH07XG4gIFNuYXBzaG90LnByb3RvdHlwZS5uYW1lID0gZnVuY3Rpb24oKSB7XG4gICAgcmV0dXJuIHRoaXMuX3JlZi5uYW1lKCk7XG4gIH07XG4gIFNuYXBzaG90LnByb3RvdHlwZS5yZWYgPSBmdW5jdGlvbigpIHtcbiAgICByZXR1cm4gdGhpcy5fcmVmO1xuICB9O1xuICBTbmFwc2hvdC5wcm90b3R5cGUuZXhwb3J0VmFsID0gZnVuY3Rpb24oKSB7XG4gICAgcmV0dXJuIHV0aWxzLnRyYW5zZm9ybVZhbHVlKHRoaXMuX3BhdGgsIHRoaXMuX3NuYXAuZXhwb3J0VmFsKCksIHV0aWxzLmRlY3J5cHQpO1xuICB9O1xuXG4gIGZ1bmN0aW9uIE9uRGlzY29ubmVjdChwYXRoLCBvcmlnaW5hbE9uRGlzY29ubmVjdCkge1xuICAgIHRoaXMuX3BhdGggPSBwYXRoO1xuICAgIHRoaXMuX29yaWdpbmFsT25EaXNjb25uZWN0ID0gb3JpZ2luYWxPbkRpc2Nvbm5lY3Q7XG4gIH1cbiAgaW50ZXJjZXB0T25EaXNjb25uZWN0V3JpdGUoJ3NldCcsIDApO1xuICBpbnRlcmNlcHRPbkRpc2Nvbm5lY3RXcml0ZSgndXBkYXRlJywgMCk7XG4gIGludGVyY2VwdE9uRGlzY29ubmVjdFdyaXRlKCdyZW1vdmUnKTtcbiAgaW50ZXJjZXB0T25EaXNjb25uZWN0V3JpdGUoJ3NldFdpdGhQcmlvcml0eScsIDApO1xuICBpbnRlcmNlcHRPbkRpc2Nvbm5lY3RXcml0ZSgnY2FuY2VsJyk7XG5cblxuICBmdW5jdGlvbiB3cmFwRmlyZWJhc2UoKSB7XG4gICAgaWYgKGZpcmViYXNlV3JhcHBlZCkgcmV0dXJuO1xuICAgIGludGVyY2VwdFdyaXRlKCdzZXQnLCAwKTtcbiAgICBpbnRlcmNlcHRXcml0ZSgndXBkYXRlJywgMCk7XG4gICAgaW50ZXJjZXB0UHVzaCgpO1xuICAgIGludGVyY2VwdFdyaXRlKCdzZXRXaXRoUHJpb3JpdHknLCAwKTtcbiAgICBpbnRlcmNlcHRXcml0ZSgnc2V0UHJpb3JpdHknKTtcbiAgICBpZiAoZmJwLmNoaWxkcmVuS2V5cykgaW50ZXJjZXB0Q2hpbGRyZW5LZXlzKCk7XG4gICAgaW50ZXJjZXB0VHJhbnNhY3Rpb24oKTtcbiAgICBpbnRlcmNlcHRPbkRpc2Nvbm5lY3QoKTtcbiAgICBbXG4gICAgICAnb24nLCAnb2ZmJywgJ29uY2UnLCAnb3JkZXJCeUNoaWxkJywgJ29yZGVyQnlLZXknLCAnb3JkZXJCeVZhbHVlJywgJ29yZGVyQnlQcmlvcml0eScsXG4gICAgICAnc3RhcnRBdCcsICdlbmRBdCcsICdlcXVhbFRvJywgJ2xpbWl0VG9GaXJzdCcsICdsaW1pdFRvTGFzdCcsICdsaW1pdCcsICdyZWYnXG4gICAgXS5mb3JFYWNoKGZ1bmN0aW9uKG1ldGhvZE5hbWUpIHtpbnRlcmNlcHRRdWVyeShtZXRob2ROYW1lKTt9KTtcbiAgICBmaXJlYmFzZVdyYXBwZWQgPSB0cnVlO1xuICB9XG5cbiAgZnVuY3Rpb24gaW50ZXJjZXB0V3JpdGUobWV0aG9kTmFtZSwgYXJnSW5kZXgpIHtcbiAgICB2YXIgb3JpZ2luYWxNZXRob2QgPSBmYnBbbWV0aG9kTmFtZV07XG4gICAgZmJwW21ldGhvZE5hbWVdID0gZnVuY3Rpb24oKSB7XG4gICAgICB2YXIgcGF0aCA9IHV0aWxzLnJlZlRvUGF0aCh0aGlzKTtcbiAgICAgIHZhciBzZWxmID0gdXRpbHMuZW5jcnlwdFJlZih0aGlzLCBwYXRoKTtcbiAgICAgIHZhciBhcmdzID0gQXJyYXkucHJvdG90eXBlLnNsaWNlLmNhbGwoYXJndW1lbnRzKTtcbiAgICAgIGlmIChhcmdJbmRleCA+PSAwICYmIGFyZ0luZGV4IDwgYXJncy5sZW5ndGgpIHtcbiAgICAgICAgYXJnc1thcmdJbmRleF0gPSB1dGlscy50cmFuc2Zvcm1WYWx1ZShwYXRoLCBhcmdzW2FyZ0luZGV4XSwgdXRpbHMuZW5jcnlwdCk7XG4gICAgICB9XG4gICAgICByZXR1cm4gb3JpZ2luYWxNZXRob2QuYXBwbHkoc2VsZiwgYXJncyk7XG4gICAgfTtcbiAgfVxuXG4gIGZ1bmN0aW9uIGludGVyY2VwdFB1c2goKSB7XG4gICAgLy8gRmlyZWJhc2UucHVzaCBkZWxlZ2F0ZXMgdG8gRmlyZWJhc2Uuc2V0LCB3aGljaCB3aWxsIHRha2UgY2FyZSBvZiBlbmNyeXB0aW5nIHRoZSByZWYgYW5kIHRoZVxuICAgIC8vIGFyZ3VtZW50LlxuICAgIHZhciBvcmlnaW5hbE1ldGhvZCA9IGZicC5wdXNoO1xuICAgIGZicC5wdXNoID0gZnVuY3Rpb24oKSB7XG4gICAgICB2YXIgcmVmID0gb3JpZ2luYWxNZXRob2QuYXBwbHkodGhpcywgYXJndW1lbnRzKTtcbiAgICAgIHZhciBkZWNyeXB0ZWRSZWYgPSB1dGlscy5kZWNyeXB0UmVmKHJlZik7XG4gICAgICBkZWNyeXB0ZWRSZWYudGhlbiA9IHJlZi50aGVuO1xuICAgICAgZGVjcnlwdGVkUmVmLmNhdGNoID0gcmVmLmNhdGNoO1xuICAgICAgaWYgKHJlZi5maW5hbGx5KSBkZWNyeXB0ZWRSZWYuZmluYWxseSA9IHJlZi5maW5hbGx5O1xuICAgICAgcmV0dXJuIGRlY3J5cHRlZFJlZjtcbiAgICB9O1xuICB9XG5cbiAgZnVuY3Rpb24gaW50ZXJjZXB0Q2hpbGRyZW5LZXlzKCkge1xuICAgIHZhciBvcmlnaW5hbE1ldGhvZCA9IGZicC5jaGlsZHJlbktleXM7XG4gICAgZmJwLmNoaWxkcmVuS2V5cyA9IGZ1bmN0aW9uKCkge1xuICAgICAgcmV0dXJuIG9yaWdpbmFsTWV0aG9kLmFwcGx5KHV0aWxzLmVuY3J5cHRSZWYodGhpcyksIGFyZ3VtZW50cykudGhlbihmdW5jdGlvbihrZXlzKSB7XG4gICAgICAgIGlmICgha2V5cy5zb21lKGZ1bmN0aW9uKGtleSkge3JldHVybiAvXFx4OTEvLnRlc3Qoa2V5KTt9KSkgcmV0dXJuIGtleXM7XG4gICAgICAgIHJldHVybiBrZXlzLm1hcCh1dGlscy5kZWNyeXB0KTtcbiAgICAgIH0pO1xuICAgIH07XG4gIH1cblxuICBmdW5jdGlvbiBpbnRlcmNlcHRUcmFuc2FjdGlvbigpIHtcbiAgICB2YXIgb3JpZ2luYWxNZXRob2QgPSBmYnAudHJhbnNhY3Rpb247XG4gICAgZmJwLnRyYW5zYWN0aW9uID0gZnVuY3Rpb24oKSB7XG4gICAgICB2YXIgcGF0aCA9IHV0aWxzLnJlZlRvUGF0aCh0aGlzKTtcbiAgICAgIHZhciBzZWxmID0gdXRpbHMuZW5jcnlwdFJlZih0aGlzLCBwYXRoKTtcbiAgICAgIHZhciBhcmdzID0gQXJyYXkucHJvdG90eXBlLnNsaWNlLmNhbGwoYXJndW1lbnRzKTtcbiAgICAgIHZhciBvcmlnaW5hbENvbXB1dGUgPSBhcmdzWzBdO1xuICAgICAgYXJnc1swXSA9IG9yaWdpbmFsQ29tcHV0ZSAmJiBmdW5jdGlvbih2YWx1ZSkge1xuICAgICAgICB2YWx1ZSA9IHV0aWxzLnRyYW5zZm9ybVZhbHVlKHBhdGgsIHZhbHVlLCB1dGlscy5kZWNyeXB0KTtcbiAgICAgICAgdmFsdWUgPSBvcmlnaW5hbENvbXB1dGUodmFsdWUpO1xuICAgICAgICB2YWx1ZSA9IHV0aWxzLnRyYW5zZm9ybVZhbHVlKHBhdGgsIHZhbHVlLCB1dGlscy5lbmNyeXB0KTtcbiAgICAgICAgcmV0dXJuIHZhbHVlO1xuICAgICAgfTtcbiAgICAgIGlmIChhcmdzLmxlbmd0aCA+IDEpIHtcbiAgICAgICAgdmFyIG9yaWdpbmFsT25Db21wbGV0ZSA9IGFyZ3NbMV07XG4gICAgICAgIGFyZ3NbMV0gPSBvcmlnaW5hbE9uQ29tcGxldGUgJiYgZnVuY3Rpb24oZXJyb3IsIGNvbW1pdHRlZCwgc25hcHNob3QpIHtcbiAgICAgICAgICByZXR1cm4gb3JpZ2luYWxPbkNvbXBsZXRlKGVycm9yLCBjb21taXR0ZWQsIHNuYXBzaG90ICYmIG5ldyBTbmFwc2hvdChzbmFwc2hvdCkpO1xuICAgICAgICB9O1xuICAgICAgfVxuICAgICAgcmV0dXJuIG9yaWdpbmFsTWV0aG9kLmFwcGx5KHNlbGYsIGFyZ3MpLnRoZW4oZnVuY3Rpb24ocmVzdWx0KSB7XG4gICAgICAgIHJlc3VsdC5zbmFwc2hvdCA9IHJlc3VsdC5zbmFwc2hvdCAmJiBuZXcgU25hcHNob3QocmVzdWx0LnNuYXBzaG90KTtcbiAgICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgICAgIH0pO1xuICAgIH07XG4gIH1cblxuICBmdW5jdGlvbiBpbnRlcmNlcHRPbkRpc2Nvbm5lY3QoKSB7XG4gICAgdmFyIG9yaWdpbmFsTWV0aG9kID0gZmJwLm9uRGlzY29ubmVjdDtcbiAgICBmYnAub25EaXNjb25uZWN0ID0gZnVuY3Rpb24oKSB7XG4gICAgICB2YXIgcGF0aCA9IHV0aWxzLnJlZlRvUGF0aCh0aGlzKTtcbiAgICAgIHJldHVybiBuZXcgT25EaXNjb25uZWN0KHBhdGgsIG9yaWdpbmFsTWV0aG9kLmNhbGwodXRpbHMuZW5jcnlwdFJlZih0aGlzLCBwYXRoKSkpO1xuICAgIH07XG4gIH1cblxuICBmdW5jdGlvbiBpbnRlcmNlcHRPbkRpc2Nvbm5lY3RXcml0ZShtZXRob2ROYW1lLCBhcmdJbmRleCkge1xuICAgIE9uRGlzY29ubmVjdC5wcm90b3R5cGVbbWV0aG9kTmFtZV0gPSBmdW5jdGlvbigpIHtcbiAgICAgIHZhciBhcmdzID0gQXJyYXkucHJvdG90eXBlLnNsaWNlLmNhbGwoYXJndW1lbnRzKTtcbiAgICAgIGlmIChhcmdJbmRleCA+PSAwICYmIGFyZ0luZGV4IDwgYXJncy5sZW5ndGgpIHtcbiAgICAgICAgYXJnc1thcmdJbmRleF0gPSB1dGlscy50cmFuc2Zvcm1WYWx1ZSh0aGlzLl9wYXRoLCBhcmdzW2FyZ0luZGV4XSwgdXRpbHMuZW5jcnlwdCk7XG4gICAgICB9XG4gICAgICBjb25zb2xlLmxvZygnQVJHUzonLCBhcmdzKTtcbiAgICAgIHJldHVybiB0aGlzLl9vcmlnaW5hbE9uRGlzY29ubmVjdFttZXRob2ROYW1lXS5hcHBseSh0aGlzLl9vcmlnaW5hbE9uRGlzY29ubmVjdCwgYXJncyk7XG4gICAgfTtcbiAgfVxuXG4gIGZ1bmN0aW9uIGludGVyY2VwdFF1ZXJ5KG1ldGhvZE5hbWUpIHtcbiAgICBvcmlnaW5hbFF1ZXJ5RmJwW21ldGhvZE5hbWVdID0gZmJwW21ldGhvZE5hbWVdO1xuICAgIGZicFttZXRob2ROYW1lXSA9IGZ1bmN0aW9uKCkge1xuICAgICAgdmFyIHF1ZXJ5ID0gbmV3IFF1ZXJ5KHV0aWxzLmVuY3J5cHRSZWYodGhpcyksIHt9LCBvcmlnaW5hbFF1ZXJ5RmJwKTtcbiAgICAgIHJldHVybiBxdWVyeVttZXRob2ROYW1lXS5hcHBseShxdWVyeSwgYXJndW1lbnRzKTtcbiAgICB9O1xuICB9XG5cbiAgZnVuY3Rpb24gd3JhcFF1ZXJ5Q2FsbGJhY2soY2FsbGJhY2spIHtcbiAgICBpZiAoIWNhbGxiYWNrIHx8IGNhbGxiYWNrLmZpcmVjcnlwdENhbGxiYWNrKSByZXR1cm47XG4gICAgdmFyIHdyYXBwZWRDYWxsYmFjayA9IGZ1bmN0aW9uKHNuYXAsIHByZXZpb3VzQ2hpbGRLZXkpIHtcbiAgICAgIHJldHVybiBjYWxsYmFjay5jYWxsKHRoaXMsIG5ldyBTbmFwc2hvdChzbmFwKSwgcHJldmlvdXNDaGlsZEtleSk7XG4gICAgfTtcbiAgICB3cmFwcGVkQ2FsbGJhY2suZmlyZWNyeXB0Q2FsbGJhY2sgPSB3cmFwcGVkQ2FsbGJhY2s7XG4gICAgY2FsbGJhY2suZmlyZWNyeXB0Q2FsbGJhY2sgPSB3cmFwcGVkQ2FsbGJhY2s7XG4gIH1cblxuICBmdW5jdGlvbiBkZWxlZ2F0ZVNuYXBzaG90KG1ldGhvZE5hbWUpIHtcbiAgICBTbmFwc2hvdC5wcm90b3R5cGVbbWV0aG9kTmFtZV0gPSBmdW5jdGlvbigpIHtcbiAgICAgIHJldHVybiB0aGlzLl9zbmFwW21ldGhvZE5hbWVdLmFwcGx5KHRoaXMuX3NuYXAsIGFyZ3VtZW50cyk7XG4gICAgfTtcbiAgfVxufSkoKTtcbiIsImxldCBfc3BlYztcbmxldCBfZW5jcnlwdGlvbkNhY2hlO1xubGV0IF9kZWNyeXB0aW9uQ2FjaGU7XG5cbmZ1bmN0aW9uIHNldFNwZWMoc3BlYykge1xuICBfc3BlYyA9IGNsZWFuU3BlY2lmaWNhdGlvbihzcGVjKTtcbn1cblxuZnVuY3Rpb24gc2V0RW5jcnlwdGlvbkNhY2hlKGNhY2hlKSB7XG4gIF9lbmNyeXB0aW9uQ2FjaGUgPSBjYWNoZTtcbn1cblxuZnVuY3Rpb24gc2V0RGVjcnlwdGlvbkNhY2hlKGNhY2hlKSB7XG4gIF9kZWNyeXB0aW9uQ2FjaGUgPSBjYWNoZTtcbn1cblxuZnVuY3Rpb24gY2xlYW5TcGVjaWZpY2F0aW9uKGRlZiwgcGF0aCkge1xuICB2YXIga2V5cyA9IE9iamVjdC5rZXlzKGRlZik7XG4gIGZvciAodmFyIGkgPSAwOyBpIDwga2V5cy5sZW5ndGg7IGkrKykge1xuICAgIHZhciBrZXkgPSBrZXlzW2ldO1xuICAgIGlmIChrZXkgPT09ICcuZW5jcnlwdCcpIHtcbiAgICAgIHZhciBlbmNyeXB0S2V5cyA9IE9iamVjdC5rZXlzKGRlZltrZXldKTtcbiAgICAgIGZvciAodmFyIGogPSAwOyBqIDwgZW5jcnlwdEtleXMubGVuZ3RoOyBqKyspIHtcbiAgICAgICAgdmFyIGVuY3J5cHRLZXkgPSBlbmNyeXB0S2V5c1tqXTtcbiAgICAgICAgaWYgKGVuY3J5cHRLZXkgIT09ICdrZXknICYmIGVuY3J5cHRLZXkgIT09ICd2YWx1ZScgJiYgZW5jcnlwdEtleSAhPT0gJ2ZldycpIHtcbiAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ0lsbGVnYWwgLmVuY3J5cHQgc3Via2V5OiAnICsgZW5jcnlwdEtleXNbal0pO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSBlbHNlIHtcbiAgICAgIGlmICgvW1xceDAwLVxceDFmXFx4N2ZcXHg5MVxceDkyXFwuI1xcW1xcXS9dLy50ZXN0KGtleSkgfHwgL1skXS8udGVzdChrZXkuc2xpY2UoMSkpKSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcignSWxsZWdhbCBjaGFyYWN0ZXIgaW4gc3BlY2lmaWNhdGlvbiBrZXk6ICcgKyBrZXkpO1xuICAgICAgfVxuICAgICAgY2xlYW5TcGVjaWZpY2F0aW9uKGRlZltrZXldLCAocGF0aCB8fCAnJykgKyAnLycgKyBrZXkpO1xuICAgIH1cbiAgICBzd2l0Y2ggKGtleS5jaGFyQXQoMCkpIHtcbiAgICAgIGNhc2UgJyQnOlxuICAgICAgICBpZiAoa2V5ID09PSAnJCcpIGJyZWFrO1xuICAgICAgICBpZiAoZGVmLiQpIHRocm93IG5ldyBFcnJvcignTXVsdGlwbGUgd2lsZGNhcmQga2V5cyBpbiBzcGVjaWZpY2F0aW9uIGF0ICcgKyBwYXRoKTtcbiAgICAgICAgZGVmLiQgPSBkZWZba2V5XTtcbiAgICAgICAgZGVsZXRlIGRlZltrZXldO1xuICAgICAgICBicmVhaztcbiAgICAgIGNhc2UgJy4nOlxuICAgICAgICBpZiAoa2V5ICE9PSAnLmVuY3J5cHQnKSB0aHJvdyBuZXcgRXJyb3IoJ1Vua25vd24gZGlyZWN0aXZlIGF0ICcgKyBwYXRoICsgJzogJyArIGtleSk7XG4gICAgICAgIGJyZWFrO1xuICAgIH1cbiAgfVxuICByZXR1cm4gZGVmO1xufVxuXG5mdW5jdGlvbiB0aHJvd05vdFNldFVwRXJyb3IoKSB7XG4gIHZhciBlID0gbmV3IEVycm9yKCdFbmNyeXB0aW9uIG5vdCBzZXQgdXAnKTtcbiAgZS5maXJlY3J5cHQgPSAnTk9fS0VZJztcbiAgdGhyb3cgZTtcbn1cblxuZnVuY3Rpb24gY29tcHV0ZUNhY2hlSXRlbVNpemUodmFsdWUsIGtleSkge1xuICByZXR1cm4ga2V5Lmxlbmd0aCArICh0eXBlb2YgdmFsdWUgPT09ICdzdHJpbmcnID8gdmFsdWUubGVuZ3RoIDogNCk7XG59XG5cbmZ1bmN0aW9uIGVuY3J5cHRQYXRoKHBhdGgsIGRlZikge1xuICBkZWYgPSBkZWYgfHwgX3NwZWMucnVsZXM7XG4gIHBhdGggPSBwYXRoLnNsaWNlKCk7XG4gIGZvciAodmFyIGkgPSAwOyBpIDwgcGF0aC5sZW5ndGg7IGkrKykge1xuICAgIGRlZiA9IGRlZltwYXRoW2ldXSB8fCBkZWYuJDtcbiAgICBpZiAoIWRlZikgYnJlYWs7XG4gICAgaWYgKGRlZlsnLmVuY3J5cHQnXSAmJiBkZWZbJy5lbmNyeXB0J10ua2V5KSB7XG4gICAgICBwYXRoW2ldID0gZW5jcnlwdChwYXRoW2ldLCAnc3RyaW5nJywgZGVmWycuZW5jcnlwdCddLmtleSk7XG4gICAgfVxuICB9XG4gIHJldHVybiBwYXRoO1xufVxuXG5mdW5jdGlvbiBlbmNyeXB0UmVmKHJlZiwgcGF0aCkge1xuICB2YXIgZW5jcnlwdGVkUGF0aCA9IGVuY3J5cHRQYXRoKHBhdGggfHwgcmVmVG9QYXRoKHJlZikpO1xuICByZXR1cm4gZW5jcnlwdGVkUGF0aC5sZW5ndGggPyByZWYucm9vdCgpLmNoaWxkKGVuY3J5cHRlZFBhdGguam9pbignLycpKSA6IHJlZi5yb290KCk7XG59XG5cbmZ1bmN0aW9uIGRlY3J5cHRSZWYocmVmKSB7XG4gIHZhciBwYXRoID0gcmVmVG9QYXRoKHJlZiwgdHJ1ZSk7XG4gIHZhciBjaGFuZ2VkID0gZmFsc2U7XG4gIGZvciAodmFyIGkgPSAwOyBpIDwgcGF0aC5sZW5ndGg7IGkrKykge1xuICAgIHZhciBkZWNyeXB0ZWRQYXRoU2VnbWVudCA9IGRlY3J5cHQocGF0aFtpXSk7XG4gICAgaWYgKGRlY3J5cHRlZFBhdGhTZWdtZW50ICE9PSBwYXRoW2ldKSB7XG4gICAgICBwYXRoW2ldID0gZGVjcnlwdGVkUGF0aFNlZ21lbnQ7XG4gICAgICBjaGFuZ2VkID0gdHJ1ZTtcbiAgICB9XG4gIH1cbiAgcmV0dXJuIGNoYW5nZWQgPyByZWYucm9vdCgpLmNoaWxkKHBhdGguam9pbignLycpKSA6IHJlZjtcbn1cblxuZnVuY3Rpb24gc3BlY0ZvclBhdGgocGF0aCwgZGVmKSB7XG4gIGRlZiA9IGRlZiB8fCBfc3BlYy5ydWxlcztcbiAgZm9yICh2YXIgaSA9IDA7IGRlZiAmJiBpIDwgcGF0aC5sZW5ndGg7IGkrKykge1xuICAgIGRlZiA9IGRlZltwYXRoW2ldXSB8fCBkZWYuJDtcbiAgfVxuICByZXR1cm4gZGVmO1xufVxuXG5mdW5jdGlvbiB0cmFuc2Zvcm1WYWx1ZShwYXRoLCB2YWx1ZSwgdHJhbnNmb3JtKSB7XG4gIHJldHVybiB0cmFuc2Zvcm1UcmVlKHZhbHVlLCBzcGVjRm9yUGF0aChwYXRoKSwgdHJhbnNmb3JtKTtcbn1cblxuZnVuY3Rpb24gdHJhbnNmb3JtVHJlZSh2YWx1ZSwgZGVmLCB0cmFuc2Zvcm0pIHtcbiAgaWYgKCFkZWYpIHJldHVybiB2YWx1ZTtcbiAgdmFyIHR5cGUgPSBnZXRUeXBlKHZhbHVlKTtcbiAgdmFyIGk7XG4gIGlmICgvXihzdHJpbmd8bnVtYmVyfGJvb2xlYW4pJC8udGVzdCh0eXBlKSkge1xuICAgIGlmIChkZWZbJy5lbmNyeXB0J10gJiYgZGVmWycuZW5jcnlwdCddLnZhbHVlKSB7XG4gICAgICB2YWx1ZSA9IHRyYW5zZm9ybSh2YWx1ZSwgdHlwZSwgZGVmWycuZW5jcnlwdCddLnZhbHVlKTtcbiAgICB9XG4gIH0gZWxzZSBpZiAodHlwZSA9PT0gJ29iamVjdCcgJiYgdmFsdWUgIT09IG51bGwpIHtcbiAgICB2YXIgdHJhbnNmb3JtZWRWYWx1ZSA9IHt9O1xuICAgIGZvciAodmFyIGtleSBpbiB2YWx1ZSkge1xuICAgICAgaWYgKCF2YWx1ZS5oYXNPd25Qcm9wZXJ0eShrZXkpKSBjb250aW51ZTtcbiAgICAgIHZhciBzdWJWYWx1ZSA9IHZhbHVlW2tleV0sIHN1YkRlZjtcbiAgICAgIGlmIChrZXkuaW5kZXhPZignLycpID49IDApIHsgIC8vIGZvciBkZWVwIHVwZGF0ZSBrZXlzXG4gICAgICAgIHZhciBrZXlQYXJ0cyA9IGtleS5zcGxpdCgnLycpO1xuICAgICAgICBzdWJEZWYgPSBkZWY7XG4gICAgICAgIGZvciAoaSA9IDA7IGkgPCBrZXlQYXJ0cy5sZW5ndGg7IGkrKykge1xuICAgICAgICAgIGlmICh0cmFuc2Zvcm0gPT09IGRlY3J5cHQpIHtcbiAgICAgICAgICAgIGtleVBhcnRzW2ldID0gZGVjcnlwdChrZXlQYXJ0c1tpXSk7XG4gICAgICAgICAgICBzdWJEZWYgPSBzdWJEZWYgJiYgKHN1YkRlZltrZXlQYXJ0c1tpXV0gfHwgc3ViRGVmLiQpO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBzdWJEZWYgPSBzdWJEZWYgJiYgKHN1YkRlZltrZXlQYXJ0c1tpXV0gfHwgc3ViRGVmLiQpO1xuICAgICAgICAgICAgaWYgKHN1YkRlZiAmJiBzdWJEZWZbJy5lbmNyeXB0J10gJiYgc3ViRGVmWycuZW5jcnlwdCddLmtleSkge1xuICAgICAgICAgICAgICBrZXlQYXJ0c1tpXSA9IHRyYW5zZm9ybShrZXlQYXJ0c1tpXSwgJ3N0cmluZycsIHN1YkRlZlsnLmVuY3J5cHQnXS5rZXkpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICBrZXkgPSBrZXlQYXJ0cy5qb2luKCcvJyk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBpZiAodHJhbnNmb3JtID09PSBkZWNyeXB0KSB7XG4gICAgICAgICAga2V5ID0gZGVjcnlwdChrZXkpO1xuICAgICAgICAgIHN1YkRlZiA9IGRlZltrZXldIHx8IGRlZi4kO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHN1YkRlZiA9IGRlZltrZXldIHx8IGRlZi4kO1xuICAgICAgICAgIGlmIChzdWJEZWYgJiYgc3ViRGVmWycuZW5jcnlwdCddICYmIHN1YkRlZlsnLmVuY3J5cHQnXS5rZXkpIHtcbiAgICAgICAgICAgIGtleSA9IHRyYW5zZm9ybShrZXksICdzdHJpbmcnLCBzdWJEZWZbJy5lbmNyeXB0J10ua2V5KTtcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICAgIHRyYW5zZm9ybWVkVmFsdWVba2V5XSA9IHRyYW5zZm9ybVRyZWUoc3ViVmFsdWUsIHN1YkRlZiwgdHJhbnNmb3JtKTtcbiAgICB9XG4gICAgdmFsdWUgPSB0cmFuc2Zvcm1lZFZhbHVlO1xuICB9IGVsc2UgaWYgKHR5cGUgPT09ICdhcnJheScpIHtcbiAgICBpZiAoIWRlZi4kKSByZXR1cm4gdmFsdWU7XG4gICAgZm9yIChpID0gMDsgaSA8IHZhbHVlLmxlbmd0aDsgaSsrKSB2YWx1ZVtpXSA9IHRyYW5zZm9ybVRyZWUodmFsdWVbaV0sIGRlZi4kLCB0cmFuc2Zvcm0pO1xuICB9XG4gIHJldHVybiB2YWx1ZTtcbn1cblxuZnVuY3Rpb24gcmVmVG9QYXRoKHJlZiwgZW5jcnlwdGVkKSB7XG4gIHZhciByb290ID0gcmVmLnJvb3QoKTtcbiAgaWYgKHJlZiA9PT0gcm9vdCkgcmV0dXJuIFtdO1xuICB2YXIgcGF0aFN0ciA9IGRlY29kZVVSSUNvbXBvbmVudChyZWYudG9TdHJpbmcoKS5zbGljZShyb290LnRvU3RyaW5nKCkubGVuZ3RoKSk7XG4gIGlmICghZW5jcnlwdGVkICYmIHBhdGhTdHIgJiYgcGF0aFN0ci5jaGFyQXQoMCkgIT09ICcuJyAmJlxuICAgICAgL1tcXHgwMC1cXHgxZlxceDdmXFx4OTFcXHg5MlxcLiMkXFxbXFxdXS8udGVzdChwYXRoU3RyKSkge1xuICAgIHRocm93IG5ldyBFcnJvcignUGF0aCBjb250YWlucyBpbnZhbGlkIGNoYXJhY3RlcnM6ICcgKyBwYXRoU3RyKTtcbiAgfVxuICByZXR1cm4gcGF0aFN0ci5zcGxpdCgnLycpO1xufVxuXG5mdW5jdGlvbiBlbmNyeXB0KHZhbHVlLCB0eXBlLCBwYXR0ZXJuKSB7XG4gIHZhciBjYWNoZUtleTtcbiAgaWYgKF9lbmNyeXB0aW9uQ2FjaGUpIHtcbiAgICBjYWNoZUtleSA9IHR5cGUuY2hhckF0KDApICsgcGF0dGVybiArICdcXHg5MScgKyB2YWx1ZTtcbiAgICBpZiAoX2VuY3J5cHRpb25DYWNoZS5oYXMoY2FjaGVLZXkpKSByZXR1cm4gX2VuY3J5cHRpb25DYWNoZS5nZXQoY2FjaGVLZXkpO1xuICB9XG4gIHZhciByZXN1bHQ7XG4gIGlmIChwYXR0ZXJuID09PSAnIycpIHtcbiAgICByZXN1bHQgPSBlbmNyeXB0VmFsdWUodmFsdWUsIHR5cGUpO1xuICB9IGVsc2Uge1xuICAgIGlmICh0eXBlICE9PSAnc3RyaW5nJykge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCdDYW5cXCd0IGVuY3J5cHQgYSAnICsgdHlwZSArICcgdXNpbmcgcGF0dGVybiBbJyArIHBhdHRlcm4gKyAnXScpO1xuICAgIH1cbiAgICB2YXIgbWF0Y2ggPSB2YWx1ZS5tYXRjaChjb21waWxlUGF0dGVybihwYXR0ZXJuKSk7XG4gICAgaWYgKCFtYXRjaCkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKFxuICAgICAgICAnQ2FuXFwndCBlbmNyeXB0IGFzIHZhbHVlIGRvZXNuXFwndCBtYXRjaCBwYXR0ZXJuIFsnICsgcGF0dGVybiArICddOiAnICsgdmFsdWUpO1xuICAgIH1cbiAgICB2YXIgaSA9IDA7XG4gICAgcmVzdWx0ID0gcGF0dGVybi5yZXBsYWNlKC9bI1xcLl0vZywgZnVuY3Rpb24ocGxhY2Vob2xkZXIpIHtcbiAgICAgIHZhciBwYXJ0ID0gbWF0Y2hbKytpXTtcbiAgICAgIGlmIChwbGFjZWhvbGRlciA9PT0gJyMnKSBwYXJ0ID0gZW5jcnlwdFZhbHVlKHBhcnQsICdzdHJpbmcnKTtcbiAgICAgIHJldHVybiBwYXJ0O1xuICAgIH0pO1xuICB9XG4gIGlmIChfZW5jcnlwdGlvbkNhY2hlKSBfZW5jcnlwdGlvbkNhY2hlLnNldChjYWNoZUtleSwgcmVzdWx0KTtcbiAgcmV0dXJuIHJlc3VsdDtcbn1cblxuZnVuY3Rpb24gZW5jcnlwdFZhbHVlKHZhbHVlLCB0eXBlKSB7XG4gIGlmICghL14oc3RyaW5nfG51bWJlcnxib29sZWFuKSQvLnRlc3QodHlwZSkpIHRocm93IG5ldyBFcnJvcignQ2FuXFwndCBlbmNyeXB0IGEgJyArIHR5cGUpO1xuICBzd2l0Y2ggKHR5cGUpIHtcbiAgICBjYXNlICdudW1iZXInOiB2YWx1ZSA9ICcnICsgdmFsdWU7IGJyZWFrO1xuICAgIGNhc2UgJ2Jvb2xlYW4nOiB2YWx1ZSA9IHZhbHVlID8gJ3QnIDogJ2YnOyBicmVhaztcbiAgfVxuICByZXR1cm4gJ1xceDkxJyArIHR5cGUuY2hhckF0KDApLnRvVXBwZXJDYXNlKCkgKyBlbmNyeXB0U3RyaW5nKHZhbHVlKSArICdcXHg5Mic7XG59XG5cbmZ1bmN0aW9uIGRlY3J5cHQodmFsdWUpIHtcbiAgaWYgKF9kZWNyeXB0aW9uQ2FjaGUgJiYgX2RlY3J5cHRpb25DYWNoZS5oYXModmFsdWUpKSByZXR1cm4gX2RlY3J5cHRpb25DYWNoZS5nZXQodmFsdWUpO1xuICBpZiAoIS9cXHg5MS8udGVzdCh2YWx1ZSkpIHJldHVybiB2YWx1ZTtcbiAgdmFyIHJlc3VsdDtcbiAgdmFyIG1hdGNoID0gdmFsdWUubWF0Y2goL15cXHg5MSguKShbXlxceDkyXSopXFx4OTIkLyk7XG4gIGlmIChtYXRjaCkge1xuICAgIHZhciBkZWNyeXB0ZWRTdHJpbmcgPSBkZWNyeXB0U3RyaW5nKG1hdGNoWzJdKTtcbiAgICBzd2l0Y2ggKG1hdGNoWzFdKSB7XG4gICAgICBjYXNlICdTJzpcbiAgICAgICAgcmVzdWx0ID0gZGVjcnlwdGVkU3RyaW5nO1xuICAgICAgICBicmVhaztcbiAgICAgIGNhc2UgJ04nOlxuICAgICAgICByZXN1bHQgPSBOdW1iZXIoZGVjcnlwdGVkU3RyaW5nKTtcbiAgICAgICAgLy8gQ2hlY2sgZm9yIE5hTiwgc2luY2UgaXQncyB0aGUgb25seSB2YWx1ZSB3aGVyZSB4ICE9PSB4LlxuICAgICAgICBpZiAocmVzdWx0ICE9PSByZXN1bHQpIHRocm93IG5ldyBFcnJvcignSW52YWxpZCBlbmNyeXB0ZWQgbnVtYmVyOiAnICsgZGVjcnlwdGVkU3RyaW5nKTtcbiAgICAgICAgYnJlYWs7XG4gICAgICBjYXNlICdCJzpcbiAgICAgICAgaWYgKGRlY3J5cHRlZFN0cmluZyA9PT0gJ3QnKSByZXN1bHQgPSB0cnVlO1xuICAgICAgICBlbHNlIGlmIChkZWNyeXB0ZWRTdHJpbmcgPT09ICdmJykgcmVzdWx0ID0gZmFsc2U7XG4gICAgICAgIGVsc2UgdGhyb3cgbmV3IEVycm9yKCdJbnZhbGlkIGVuY3J5cHRlZCBib29sZWFuOiAnICsgZGVjcnlwdGVkU3RyaW5nKTtcbiAgICAgICAgYnJlYWs7XG4gICAgICBkZWZhdWx0OlxuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ0ludmFsaWQgZW5jcnlwdGVkIHZhbHVlIHR5cGUgY29kZTogJyArIG1hdGNoWzFdKTtcbiAgICB9XG4gIH0gZWxzZSB7XG4gICAgcmVzdWx0ID0gdmFsdWUucmVwbGFjZSgvXFx4OTEoLikoW15cXHg5Ml0qKVxceDkyL2csIGZ1bmN0aW9uKG1hdGNoLCB0eXBlQ29kZSwgZW5jcnlwdGVkU3RyaW5nKSB7XG4gICAgICBpZiAodHlwZUNvZGUgIT09ICdTJykgdGhyb3cgbmV3IEVycm9yKCdJbnZhbGlkIG11bHRpLXNlZ21lbnQgZW5jcnlwdGVkIHZhbHVlOiAnICsgdHlwZUNvZGUpO1xuICAgICAgcmV0dXJuIGRlY3J5cHRTdHJpbmcoZW5jcnlwdGVkU3RyaW5nKTtcbiAgICB9KTtcbiAgfVxuICBpZiAoX2RlY3J5cHRpb25DYWNoZSkgX2RlY3J5cHRpb25DYWNoZS5zZXQodmFsdWUsIHJlc3VsdCk7XG4gIHJldHVybiByZXN1bHQ7XG59XG5cbmZ1bmN0aW9uIGdldFR5cGUodmFsdWUpIHtcbiAgaWYgKEFycmF5LmlzQXJyYXkodmFsdWUpKSByZXR1cm4gJ2FycmF5JztcbiAgdmFyIHR5cGUgPSB0eXBlb2YgdmFsdWU7XG4gIGlmICh0eXBlID09PSAnb2JqZWN0Jykge1xuICAgIGlmICh2YWx1ZSBpbnN0YW5jZW9mIFN0cmluZykgdHlwZSA9ICdzdHJpbmcnO1xuICAgIGVsc2UgaWYgKHZhbHVlIGluc3RhbmNlb2YgTnVtYmVyKSB0eXBlID0gJ251bWJlcic7XG4gICAgZWxzZSBpZiAodmFsdWUgaW5zdGFuY2VvZiBCb29sZWFuKSB0eXBlID0gJ2Jvb2xlYW4nO1xuICB9XG4gIHJldHVybiB0eXBlO1xufVxuXG52YXIgcGF0dGVyblJlZ2V4ZXMgPSB7fTtcbmZ1bmN0aW9uIGNvbXBpbGVQYXR0ZXJuKHBhdHRlcm4pIHtcbiAgdmFyIHJlZ2V4ID0gcGF0dGVyblJlZ2V4ZXNbcGF0dGVybl07XG4gIGlmICghcmVnZXgpIHtcbiAgICByZWdleCA9IHBhdHRlcm5SZWdleGVzW3BhdHRlcm5dID0gbmV3IFJlZ0V4cCgnXicgKyBwYXR0ZXJuXG4gICAgICAucmVwbGFjZSgvXFwuL2csICcjJylcbiAgICAgIC5yZXBsYWNlKC9bXFwtXFxbXFxdXFwvXFx7XFx9XFwoXFwpXFwqXFwrXFw/XFwuXFxcXFxcXlxcJFxcfF0vZywgJ1xcXFwkJicpICAvLyBlc2NhcGUgcmVnZXggY2hhcnNcbiAgICAgIC5yZXBsYWNlKC8jL2csICcoLio/KScpICsgJyQnKTtcbiAgfVxuICByZXR1cm4gcmVnZXg7XG59XG5cbm1vZHVsZS5leHBvcnRzID0ge1xuICBzZXRTcGVjLFxuICBlbmNyeXB0LFxuICBkZWNyeXB0LFxuICBnZXRUeXBlLFxuICByZWZUb1BhdGgsXG4gIGRlY3J5cHRSZWYsXG4gIGVuY3J5cHRSZWYsXG4gIGVuY3J5cHRQYXRoLFxuICBzcGVjRm9yUGF0aCxcbiAgZW5jcnlwdFZhbHVlLFxuICB0cmFuc2Zvcm1UcmVlLFxuICB0cmFuc2Zvcm1WYWx1ZSxcbiAgY29tcGlsZVBhdHRlcm4sXG4gIHNldEVuY3J5cHRpb25DYWNoZSxcbiAgc2V0RGVjcnlwdGlvbkNhY2hlLFxuICB0aHJvd05vdFNldFVwRXJyb3IsXG4gIGNvbXB1dGVDYWNoZUl0ZW1TaXplLFxufVxuIl0sInNvdXJjZVJvb3QiOiIifQ==