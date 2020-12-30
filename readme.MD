# ZOLOZ GATEWAY SAMPLE PHP
## ABOUT
This php sample code is a reference of integration with ZOLOZ gateway.
For more details, please read 
[Interact with Gateway](https://idocs.alipay.com/zoloz/saas/docs/bmu795)
and
[The Gateway Protocol
](https://idocs.alipay.com/zoloz/saas/docs/ixxcaf)

## HOW TO
The code is self-explained.
When you test it, you should change the clientId, publicKey, privateKey inside the code.

simply run 
```php request-with(out)-encryption-sample.php```
or
```php request-without-encryption-sample.php```

if you see
```verify result = 1```
or  
```real body = {"title":"hello","description":"just for demonstration."}```
with encryption one.

it means the interation is working.

## LAST
This sample code has been tested in macOS, centos7 and windows with php 5.x and 7.x

**Do not use the exact code in production, make your own implementation**


