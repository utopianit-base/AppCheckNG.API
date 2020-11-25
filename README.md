# AppCheckNG.API

An **UNOFFICIAL PowerShell based Module** that provides a fully functional API Client for the [AppCheck-NG](https://appcheck-ng.com/) Application Security Platform.
AppCheck-NG is a licensed Application and Infrastructure Vulnerability Scanner.

Developed by Chris Harris of [Utopian IT](https://utopian.it/)

More details about the [AppCheck-NG](https://appcheck-ng.com/) platform can be found via the following link.

https://appcheck-ng.com/

*Ensure that you have an account with AppCheck-NG first and request a user specific API Key!*

It's recommended to setup a new API User for this purpose and assign the API Key to that user rather than attaching it to a named user if possible.
The API Key itself must be put into the `APIKey.txt` file before use, if the `Test-AppCheckNG.ps1` is to be used for testing. The target will also need to be changed in this script as well so that the test has some meaningful output.

This Module is based on v1.2 of the AppCheck-NG API that can be found here:

https://api.appcheck-ng.com/apidoc-00.html

**This is an UNOFFICIAL API Client for AppCheck-NG and ALL uses of the platform must adhere to the Acceptable Usage Policy from AppCheck-NG.**

Use of the Module is demonstrated in the `Test-AppcheckNG.ps1` file. The module is imported as usual using `import-module`.

Documentation for the various functions can be found in the `/Docs` folder including HTML and Markdown versions.

[MD Docs](https://github.com/utopianit-base/AppCheckNG.API/blob/main/Docs/AppCheck-NG.md)

[HTML Docs](https://github.com/utopianit-base/AppCheckNG.API/blob/main/Docs/AppCheck-NG.html)

If the Module is changed, ensure the current path is that of the module itself and run `Auto-Documenter.ps1` and this will update the HTML and MD docs accordingly.
