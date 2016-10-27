<?php
namespace WxCrypt;

use Illuminate\Http\Request;

/**
 * 微信企业号回调消息加解密类库
 */
class WXBiz extends WXBizMsgCrypt
{
    /**
     * 企业号回调URL合法性验证
     * @param Request $request 企业号回调URL验证消息的请求对象
     * @return string|void 无错误发生时返回响应字符串，否则抛出异常
     * @throws Exception 当发生错误时
     */
    public function verify(Request $request)
	{
		$sVerifyMsgSig = $request->input('msg_signature');
		$sVerifyTimeStamp = $request->input('timestamp');
		$sVerifyNonce = $request->input('nonce');
		$sVerifyEchoStr = $request->input('echostr');

		$echo = '';
		$code = $this->VerifyURL($sVerifyMsgSig, $sVerifyTimeStamp, $sVerifyNonce, $sVerifyEchoStr, $echo);

		return $code === 0 ? $echo : $this->throwException($code);
	}

    /**
     * 企业号回调URL推送消息解密
     * @param Request $request 企业号回调消息推送的请求对象
     * @return \SimpleXMLElement|void 当无错误时返回解密后的SimpleXML对象，否则抛出异常
     * @throws Exception 当有错误发生时
     */
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

    /**
     * 企业号回调URL被动响应消息加密
     * @param string $xml 被动响应的明文XML数据
     * @param int|null $timeStamp 随机时间戳，默认当前时间的时间戳
     * @param string|null $nonce 随机字符串，默认自动生成16位长度字符串
     * @return string|void 无错误时返回加密后的XML字符串，否则抛出异常
     * @throws Exception 当有错误发生时
     */
    public function encrypt($xml, $timeStamp = null, $nonce = null)
	{
		$timeStamp = isset($timeStamp) ? $timeStamp : time();
		$nonce = isset($nonce) ? $nonce : str_random();

		$cryptXml = ""; //xml格式的密文
		$code = $this->EncryptMsg($xml, $timeStamp, $nonce, $cryptXml);

		return $code === 0 ? $cryptXml : $this->throwException($code);
	}

    /**
     * 异常检测抛出
     * @param int $code 返回错误码
     * @throws Exception 当发生错误时，返回对应错误码异常
     */
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