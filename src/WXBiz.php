<?php
namespace WxCrypt;

use Illuminate\Http\Request;

class WXBiz extends WXBizMsgCrypt
{
	public function callback(Request $request)
	{
		$sVerifyMsgSig = $request->input('msg_signature');
		$sVerifyTimeStamp = $request->input('timestamp');
		$sVerifyNonce = $request->input('nonce');
		$sVerifyEchoStr = $request->input('echostr');

		$res = new \stdClass;
		$res->data = '';
		$res->code = $this->VerifyURL($sVerifyMsgSig, $sVerifyTimeStamp, $sVerifyNonce, $sVerifyEchoStr, $res->data);

		return $res;
	}

	public function decrypt(Request $request)
	{
		$sVerifyMsgSig = $request->input('msg_signature');
		$sVerifyTimeStamp = $request->input('timestamp');
		$sVerifyNonce = $request->input('nonce');

		$sReqData = $GLOBALS['HTTP_RAW_POST_DATA'];

		$res = new \stdClass;
		$sMsg = '';

		libxml_disable_entity_loader(true);
		$res->code = $this->DecryptMsg($sVerifyMsgSig, $sVerifyTimeStamp, $sVerifyNonce, $sReqData, $sMsg);
		$res->xml = $sMsg;
		$res->data = json_decode(json_encode(simplexml_load_string($sMsg, 'SimpleXMLElement', LIBXML_NOCDATA)), true);
		$res->timeStamp = $sVerifyTimeStamp;
		$res->nonce = $sVerifyNonce;

		return $res;
	}

	public function encrypt($xml, $timeStamp = null, $nonce = null)
	{
		$res = new \stdClass;

		$timeStamp = isset($timeStamp) ? $timeStamp : time();
		$nonce = isset($nonce) ? $nonce : str_random();

		$res->data = ""; //xml格式的密文
		$res->code = $this->EncryptMsg($xml, $timeStamp, $nonce, $res->data);

		return $res;
	}
}