<?php

require_once "weixin_jssdk.class.php";

$jssdk=new weixin_jssdk();
//$wOpt=$jssdk->jsapi();
//$wOpt=$jssdk->get_adderss();
//$wOpt=$jssdk->get_user_info();
//$wOpt=$jssdk->refresh_oauth_access_token();
//$wOpt=$jssdk->is_access_token();
print_r($wOpt);
