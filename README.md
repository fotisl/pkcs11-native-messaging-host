# Chrome native messaging host for PKCS#11 signing

## Introduction

A [native messaging](https://developer.chrome.com/extensions/nativeMessaging) host for signing from a web extension using any PKCS#11 device.

The app is in a very primitive state. It tries to load the safenet and gemalto classic client PKCS#11 libraries from their default locations, and if it cannot load them it asks the user for the location of the library.

You will need to change the manifest file in order to include the correct web extension that will be able to connect to the host. The format of the manifest is based on the Google Chrome specification, for Firefox you may need to change one thing or two, please check [the appropriate page](https://wiki.mozilla.org/WebExtensions/Native_Messaging).

I do not plan on fully maintaining this, and there may be bugs in the code.

## Input

| Parameter | Value |
| --- | --- |
| message | The message to sign |
| srcenc (optional) | The encoding of the message. Valid values are: <br><ul><li>base64</li><li>base32</li><li>base16</li><li>plain (default)</li></ul> |
| dstenc (optional) | The encoding of the final signature. Valid values are: <br><ul><li>base64</li><li>base32</li><li>base16</li><li>hex (default)</li></ul> |
| hash (optional) | Hash to apply to message. Valid values are: <br><ul><li>md5</li><li>sha1</li><li>sha256</li><li>sha384</li><li>sha512</li><li>none (default)</li></ul> |
| includecert (optional) | Include the certificate that signed the message in the reply. Valid values are: <br><ul><li>0 - do not include (default)</li><li>1 - include</li></ul> |

## Output

| Parameter | Value |
| --- | --- |
| signature | The signature |
| cert | The certificate that signed the message if includecert is 1 |
| error | In case of error, holds the error message |
