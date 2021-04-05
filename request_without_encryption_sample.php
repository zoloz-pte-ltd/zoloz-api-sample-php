<?php

$request_body = json_encode(array("title"=>"hello", "description"=>"just for demonstration."));
// $request_body = "{}";
echo "request_body = ".$request_body."\r\n";

$request_time = date("Y-m-d\TH:i:sO");
// $request_time ="2020-01-01T00:00:00+0000";
echo "request_time = ".$request_time."\r\n";

// change to your client id
$client_id = "2188455383736145";
// this is sandbox env host, for production it is https://sg-production-api.zoloz.com
$host = "https://sg-sandbox-api.zoloz.com";
$url = "/api/v1/zoloz/authentication/test";

$content_to_be_sign = "POST ".$url."\n".$client_id.".".$request_time.".".$request_body;
echo "content_to_be_sign = ".$content_to_be_sign."\r\n";

// change where you private key file is
$pkeyid = openssl_pkey_get_private("file:///tmp/merchant.pem");
// use openssl sha256 to sign
openssl_sign($content_to_be_sign, $signature, $pkeyid, OPENSSL_ALGO_SHA256);
// free the key from memory
openssl_free_key($pkeyid);
$url_encode_signature = urlencode(base64_encode($signature));
echo "signature = ".$url_encode_signature."\r\n";

$ch = curl_init();
// change the keyVersion you use
curl_setopt($ch, CURLOPT_HTTPHEADER, array(
    "Content-Type: application/json; charset=UTF-8",
    "Client-Id: ".$client_id,
	"Request-Time: ".$request_time,
	"Signature: algorithm=RSA256, keyVersion=v1, signature=".$url_encode_signature
));
curl_setopt($ch, CURLOPT_URL, $host.$url);
curl_setopt($ch, CURLOPT_POST, 1);
curl_setopt($ch, CURLOPT_POSTFIELDS, $request_body);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_HEADER, 1);
curl_setopt($ch, CURLOPT_USERAGENT, "test"); // change it to your agent name, this is a mandatory header for passing our WAF.

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
echo "response status code = ".$httpCode."\r\n";
$header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
$response_body = substr($response, $header_size);
echo "response body = ".$response_body."\r\n";
$headers = get_headers_from_curl_response($response);
$response_time = $headers["response-time"];
echo "response time = ".$response_time."\r\n";

echo "response signature value = ".$headers["signature"]."\r\n";
$signature = after("signature=", $headers["signature"]); 
echo "the full signature = ".$signature."\r\n";
$version = between("keyVersion=", ",", $headers["signature"]);
echo "the key version = ".$version."\r\n";

$content_to_be_verify = "POST ".$url."\n".$client_id.".".$response_time.".".$response_body;
echo "content_to_be_verify = ".$content_to_be_verify."\r\n";

$zoloz_public_key = loadKey($version);
echo "zoloz_public_key = ".$zoloz_public_key."\r\n";

$ok = openssl_verify($content_to_be_verify, base64_decode(urldecode($signature)), $zoloz_public_key, OPENSSL_ALGO_SHA256);
echo "verify result = ".$ok."\r\n";

curl_close($ch);

// implement your own method to return zoloz PublicKey
function loadKey($version) 
{
	$str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApGvGJwJtVtSYQk1tRZIxfvqKKu9hc92fUw+EXju0MVui18TzMQWSHzSlRtPzbPTXW9cuJ9A1hn4gSsxoLT43MxtnHsU+L2RzRifONDy/BDKeydEpdpQriXZHvwiB7bhr7SYrDMbxpFZez92vrHJQ4w6kdjG/1F764897i0Tj8789Dval0Uyc1P251hrDdQheyp/GHJ659NzzNeorv87/2Z3h17ohlb4ELkpiNQEWTDV11DJ5tXznYcP42IlXocUUyFiT/flxR6vsJ5gZyR/N6rx1KRWYoI+/OClHiMYz7wBCfHjJKZXPdfzYh9UCx8NZwV1iZPfrbPh92hz2Eafa0wIDAQAB";
	$str = chunk_split($str, 64, "\n");
	$public_key = "-----BEGIN PUBLIC KEY-----\n$str-----END PUBLIC KEY-----\n";
	return $public_key;
}

function after ($substr, $str)
{
	if (!is_bool(strpos($str, $substr)))
	return substr($str, strpos($str,$substr)+strlen($substr));
}

function before ($substr, $str)
{
	return substr($str, 0, strpos($str, $substr));
}

function between ($start, $after, $str)
{
	return before ($after, after($start, $str));
}

function get_headers_from_curl_response($response)
{
    $headers = array();

    $header_text = substr($response, 0, strpos($response, "\r\n\r\n"));

    foreach (explode("\r\n", $header_text) as $i => $line)
        if ($i === 0)
            $headers['http_code'] = $line;
        else
        {
            list ($key, $value) = explode(': ', $line);

            $headers[strtolower($key)] = $value;
        }

    return $headers;
}

?>