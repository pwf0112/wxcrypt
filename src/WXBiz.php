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

		$echo = '';
		$code = $this->VerifyURL($sVerifyMsgSig, $sVerifyTimeStamp, $sVerifyNonce, $sVerifyEchoStr, $echo);

		return $code === 0 ? $echo : $this->throwException($code);
	}

	public function decrypt(Request $request)
	{
		$sVerifyMsgSig = $request->input('msg_signature');
		$sVerifyTimeStamp = $request->input('timestamp');
		$sVerifyNonce = $request->input('nonce');

		$sReqData = $GLOBALS['HTTP_RAW_POST_DATA'];

		$sMsg = '';
		libxml_disable_entity_loader(true);
		$code = $this->DecryptMsg($sVerifyMsgSig, $sVerifyTimeStamp, $sVerifyNonce, $sReqData, $sMsg);

		return $code === 0 ? simplexml_load_string($sMsg) : $this->throwException($code);
	}

	public function encrypt($xml, $timeStamp = null, $nonce = null)
	{
		$timeStamp = isset($timeStamp) ? $timeStamp : time();
		$nonce = isset($nonce) ? $nonce : str_random();

		$cryptXml = ""; //xml格式的密文
		$code = $this->EncryptMsg($xml, $timeStamp, $nonce, $cryptXml);

		return $code === 0 ? $cryptXml : $this->throwException($code);
	}

	private function throwException($code)
	{
		switch ($code) {
			case -40001: throw new Exception('签名验证错误', $code);
			case -40002: throw new Exception('xml解析失败', $code);
			case -40003: throw new Exception('sha加密生成签名失败', $code);
			case -40004: throw new Exception('AESKey 非法', $code);
			case -40005: throw new Exception('corpid 校验错误', $code);
			case -40006: throw new Exception('AES 加密失败', $code);
			case -40007: throw new Exception('AES 解密失败', $code);
			case -40008: throw new Exception('解密后得到的buffer非法', $code);
			case -40009: throw new Exception('base64加密失败', $code);
			case -40010: throw new Exception('base64解密失败', $code);
			case -40011: throw new Exception('生成xml失败', $code);
			default: throw new Exception('未定义的异常');
		}
	}
}