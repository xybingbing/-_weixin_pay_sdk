<?php
/*
* 
*/
class weixin_jssdk{
 	const LSappid = 'wxdb590d9b92c067ab';
	const LSappsecret = '43251f650eae2ceaec201ae22584ecb0';
	
	const GET_ACCESS_TOKEN_URL = 'https://api.weixin.qq.com/cgi-bin/token';	
	const GET_JSAPI_TICKET_URL = 'https://api.weixin.qq.com/cgi-bin/ticket/getticket';
	const GET_OAUTH_CODE_URL = 'https://open.weixin.qq.com/connect/oauth2/authorize';
	const GET_OAUTH_ACCESS_TOKEN_URL = 'https://api.weixin.qq.com/sns/oauth2/access_token';	
	private $appid;			//微信ID
 	private $appsecret;		//微信密钥
 	private $cache_path;		//保存access_token和jsapi_ticket 目录
 	private $cache_jsapi_ticket;		//jsapi_ticket文件名
	private $cache_access_token;		//access_token文件名
	private $cache_oauth_access_token;		//oauth_access_token文件名
	private $cache_oauth_user_access_token;	//可以获取未关注的微信用户信息的oauth_user_access_token文件名
 	public function __construct($options = array()){
	 	$this->appid     =  isset($options['appid'])      ? $options['appid']     : self::LSappid;
		$this->appsecret =  isset($options['appsecret'])  ? $options['appsecret'] : self::LSappsecret;
		$this->cache_path  =  isset($options['cache_path'])  ? $options['cache_path'] : dirname(__FILE__).'/cache/';
		if(!is_dir($this->cache_path)){ @mkdir($this->cache_path,0755,true); }
		$this->cache_jsapi_ticket = 'cache_jsapi_ticket_'.$this->appid.'.php';
		$this->cache_access_token = 'cache_access_token_'.$this->appid.'.php';
		$this->cache_oauth_access_token = 'cache_oauth_access_token_'.$this->appid;
		$this->cache_oauth_user_access_token = 'cache_oauth_user_access_token_'.$this->appid;
		if(session_id()==""){ session_start(); }
	}
	//jssdk
	public function jsapi(){
	    $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || $_SERVER['SERVER_PORT'] == 443) ? "https://" : "http://";
	    $url = $protocol.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'];
	    $timestamp = time();
	    $nonceStr = self::createNonceStr();
		$data['jsapi_ticket']=$this->get_jsapi_ticket();
		$data['noncestr']=$nonceStr;
		$data['timestamp']=$timestamp;
		$data['url']=$url;
	    ksort($data);
	    $string = self::ToUrlParams($data);
	    $signature = sha1($string);
	    $signPackage = array(
	      "appId"     => $this->appid,
	      "timestamp" => $timestamp,
	      "nonceStr"  => $nonceStr,
	      "signature" => $signature
	    );
		return $signPackage;
	}
	//获取微信收货地址
	public function get_adderss(){
		$oauth_access_token=$this->get_set_oauth_access_token();		//缓存里面的access_token不行，必须每次调用地址都要重新获取一下access_token
		if($oauth_access_token){
			$protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || $_SERVER['SERVER_PORT'] == 443) ? "https://" : "http://";
			$data["url"] = $protocol.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'];
			if(empty($_GET['code']) || empty($_GET['state'])){
				if(strpos($data["url"],'?')){
					$data["url"].="&code=".$oauth_access_token['code'].'&state='.$oauth_access_token['state'];
				}else{
					$data["url"].="?code=".$oauth_access_token['code'].'&state='.$oauth_access_token['state'];
				}
			}
			$data["appid"] = $this->appid;
			$time = time();
			$data["timestamp"] = "$time";
			$data["noncestr"] = self::createNonceStr();
			$data["accesstoken"] = $oauth_access_token['access_token'];
			ksort($data);
			$params = self::ToUrlParams($data);
			$addrSign = sha1($params);
			$afterData = array(
				"appId" => $this->appid,
				"scope" => "jsapi_address",
				"signType" => "sha1",
				"addrSign" => $addrSign,
				"timeStamp" => $data["timestamp"],
				"nonceStr" => $data["noncestr"]
			);
			return $parameters = json_encode($afterData);
		}
	}
	//获取用户信息
	public function get_user_info(){
		$oauth_access_token=$this->get_oauth_access_token();
		$url='https://api.weixin.qq.com/sns/userinfo?access_token='.$oauth_access_token['access_token'].'&openid='.$oauth_access_token['openid'].'&lang=zh_CN';
		$res = json_decode($this->httpget($url),true);
		return $res;
	}
	//刷新access_token
	public function refresh_oauth_access_token(){
		$oauth_access_token=$this->get_oauth_access_token();
		$url='https://api.weixin.qq.com/sns/oauth2/refresh_token?appid='.$this->appid.'&grant_type=refresh_token&refresh_token='.$oauth_access_token['refresh_token'];
		$res = json_decode($this->httpget($url),true);
		return $res;
	}
	//检验授权凭证是否失效
	public function is_access_token(){
		$oauth_access_token=$this->get_oauth_access_token();
		$url='https://api.weixin.qq.com/sns/auth?access_token='.$oauth_access_token['access_token'].'&openid='.$oauth_access_token['openid'];
		$res = json_decode($this->httpget($url),true);
		return $res;
	}
	private function get_oauth_access_token($scope='snsapi_base'){
		if($scope=='snsapi_base'){
			$oauth_access_token=$this->get_cache($this->cache_path.$this->cache_oauth_access_token.'_'.$_SESSION[$this->appid.'wx_openid'].".php");
		}else{
			$oauth_access_token=$this->get_cache($this->cache_path.$this->cache_oauth_user_access_token.'_'.$_SESSION[$this->appid.'wx_openid'].".php");
		}
		if(!$oauth_access_token){
			//获取 并写入缓存
			$re_oauth_access_token=$this->get_set_oauth_access_token($scope);
		}else{
			//读取缓存 并 判断是否过期 更新缓存
			$data = json_decode($oauth_access_token,true);
			if($data['expire_time'] < time()){
				$re_oauth_access_token = $this->get_set_oauth_access_token($scope);
			}else{
				$re_oauth_access_token = $data;
			}
		}
		//返回 缓存里面的数据
		return $re_oauth_access_token;
	}
	
	private function get_set_oauth_access_token($scope='snsapi_base'){
		if (!isset($_GET['code'])){
			$protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || $_SERVER['SERVER_PORT'] == 443) ? "https://" : "http://";
		    $url = $protocol.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'];
			$urlObj['appid'] = $this->appid;
			$urlObj['redirect_uri'] =urlencode($url);
			$urlObj['response_type'] = 'code';
			$urlObj['scope'] = $scope;
			$urlObj['state'] = 'STATE'."#wechat_redirect";
			$bizString = self::ToUrlParams($urlObj);
			$url=self::GET_OAUTH_CODE_URL.'?'.$bizString;
			Header("Location: $url");
		}else{
			$code = $_GET['code'];
			$urlObj['appid'] = $this->appid;
			$urlObj['secret'] = $this->appsecret;
			$urlObj['code'] = $code;
			$urlObj['grant_type'] = 'authorization_code';
			$bizString = self::ToUrlParams($urlObj);
			$url=self::GET_OAUTH_ACCESS_TOKEN_URL.'?'.$bizString;
			$res = json_decode($this->httpget($url),true);
			if($res['access_token'] && $res['openid']){
				$res['expire_time'] = time() + 7000;
				$res['code']=$code;
				$res['state']='STATE';
				$_SESSION[$this->appid.'wx_openid']=$res['openid'];
				if($scope=='snsapi_base'){
					$this->set_cache($this->cache_path.$this->cache_oauth_access_token.'_'.$res['openid'].".php",json_encode($res));
				}else{
					$this->set_cache($this->cache_path.$this->cache_oauth_user_access_token.'_'.$res['openid'].".php",json_encode($res));
				}
				return $res;
			}
		}
	}
	//获取ApiTicket
	private function get_jsapi_ticket(){
		$jsapi_ticket=$this->get_cache($this->cache_path.$this->cache_jsapi_ticket);
		if(!$jsapi_ticket){
			//获取 并写入缓存
			$re_jsapi_ticket=$this->get_set_jsapi_ticket();
		}else{
			//读取缓存 并 判断是否过期 更新缓存
			$data = json_decode($jsapi_ticket);
			if($data->expire_time < time()){
				$re_jsapi_ticket = $this->get_set_jsapi_ticket();
			}else{
				$re_jsapi_ticket = $data->ticket;
			}
		}
		//返回 缓存里面的数据
		return $re_jsapi_ticket;
	}
	private function get_set_jsapi_ticket(){
		$accesstoken = $this->get_access_token();
		$url = self::GET_JSAPI_TICKET_URL."?type=jsapi&access_token=".$accesstoken;
      	$res = json_decode($this->httpget($url));
	    if($res->ticket){
	        $data['expire_time'] = time() + 7000;
	        $data['ticket'] = $res->ticket;
	        $this->set_cache($this->cache_path.$this->cache_jsapi_ticket,json_encode($data));
			return $res->ticket;
	    }
	}
	//获取access_token
	private function get_access_token(){
		$access_token=$this->get_cache($this->cache_path.$this->cache_access_token);
		if(!$access_token){
			//获取 并写入缓存
			$re_access_token=$this->get_set_access_token();
		}else{
			//读取缓存 并 判断是否过期 更新缓存
			$data = json_decode($access_token);
			if($data->expire_time < time()){
				$re_access_token = $this->get_set_access_token();
			}else{
				$re_access_token = $data->access_token;
			}
		}
		//返回 缓存里面的数据
		return $re_access_token;
	}
	
	private function get_set_access_token(){
		//获取 并写入缓存
		$url = self::GET_ACCESS_TOKEN_URL."?grant_type=client_credential&appid=".$this->appid."&secret=".$this->appsecret;
      	$res = json_decode($this->httpget($url));
		if($res->access_token){
			$data['expire_time'] = time() + 7000;
        		$data['access_token'] = $res->access_token;
			$this->set_cache($this->cache_path.$this->cache_access_token,json_encode($data));
			return $res->access_token;
		}
	}
	private function get_cache($filename){
		if(file_exists($filename)){
			return trim(substr(file_get_contents($filename), 15));
		}else{
			return false;
		}
	}
	private function set_cache($filename, $content){
		$fp = fopen($filename, "w");
		fwrite($fp, "<?php exit();?>" . $content);
	    fclose($fp);
	}
	//随机字符串
	private static function createNonceStr($length = 16){
	    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	    $str = "";
	    for ($i = 0; $i < $length; $i++) {
	      $str .= substr($chars, mt_rand(0, strlen($chars) - 1), 1);
	    }
	    return $str;
	}
	/**
	* 格式化参数格式化成url参数
	*/
	protected static function ToUrlParams($options){
		$buff = "";
		foreach ($options as $k => $v){
			if($k!= "sign" && $v != "" && !is_array($v)){
				$buff .= $k . "=" . $v . "&";
			}
		}
		$buff = trim($buff, "&");
		return $buff;
	}
	//curl http  get请求获取数据
	private function httpget($url){
    		$curl = curl_init();
    		curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
    		curl_setopt($curl, CURLOPT_TIMEOUT, 100);
    		curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, true);
    		curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 2);
    		curl_setopt($curl, CURLOPT_URL, $url);
    		$res = curl_exec($curl);
    		curl_close($curl);
    		return $res;
	}
}
