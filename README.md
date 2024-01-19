# credits
- *https://github.com/chrisveness/crypto*, **MIT**, `Aes`, `AesCtr` (algorithms; follow for docs and more)
- *https://github.com/davidchambers/Base64.js*, **Apache 2.0**, `btoa`, `atob` (algorithms; follow for more)
- https://github.com/slnknrr/js.es14.cryptography.aes, **MIT**, `this` (export func. / wrapper)
## Browser
```JavaScript
var aes=window['@niknils/aes'].aes;
```
## Node.js
```JavaScript
//in review exports
var { aes } = require(`${__dirname}/aes.js`);
```
# usage
```JavaScript
aes('encryptMe', 'myPass', true)
aes('decryptMe', 'myPass', false)
aes('data',192) //window.location.hostname or require('os').hostname() as password; by default encrypt mode (like `true` in options)
//128,192,256
```
