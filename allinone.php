<?php
 session_start();
// error_reporting(E_ALL);
// ini_set('display_errors', '1');
$namegf="";
$emailgf="";
$baseredirecturl="https://2me.digital/register";
// ====================micro================
$client_id = "874b8c77-ba73-476c-ae31-41ab7c82b2c3";
$client_secret = "AQm8Q~0MQQ89zucl_6HofBWT7mtt5N4TriRV0cnl";
$redirect_uri = $baseredirecturl;
$scopes = "User.Read+openid+profile+offline_access";
function microurl($client_id,$redirect_uri){
   $url="https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=" . $client_id . "&scope=User.Read+offline_access&response_type=code&redirect_uri=" . $redirect_uri."&state=meena";
   return $url;
}
 $resultd='';
if($_GET["state"]=='meena')
{  
  $url = "https://login.microsoftonline.com/common/oauth2/v2.0/token";
      $fields = array("client_id" => $client_id, "redirect_uri" => $redirect_uri, "client_secret" => $client_secret, "code" => $_GET["code"], "grant_type" => "authorization_code");
      $fields_string="client_id=".$client_id."&redirect_uri=".$redirect_uri."&client_secret=".$client_secret."&code=".$_GET["code"]."&grant_type=authorization_code";
      $ch = curl_init();
      curl_setopt($ch,CURLOPT_URL, $url);
      curl_setopt($ch,CURLOPT_HTTPHEADER, array("content-type: application/x-www-form-urlencoded"));
      curl_setopt($ch,CURLOPT_POST, count($fields));
      curl_setopt($ch,CURLOPT_POSTFIELDS, $fields_string);
      curl_setopt($ch,CURLOPT_RETURNTRANSFER,1);
      $result = curl_exec($ch);
      $result  = json_decode($result);
      curl_close($ch);
      $access_token = $result->access_token;
      $refresh_token = $result->refresh_token;
      $ch = curl_init();
      $headers = [
        'Content-Type : application/json',
        'Authorization: Bearer ' .$access_token,
    ];  
         curl_setopt($ch,CURLOPT_URL, "https://graph.microsoft.com/v1.0/me");
         curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
         curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
         $resultd = curl_exec($ch);
          $resultd = rtrim($resultd, "1");
          $resultd=json_decode($resultd);
          // print_r($resultd->displayName);
          // print_r($resultd->userPrincipalName);  
          $namegf=$resultd->displayName;
          $emailgf= $resultd->userPrincipalName;
          curl_close($ch);
  }
// ====================end-micro================
require_once 'Facebook/autoload.php';
define('APP_ID', '273569798452794');
define('APP_SECRET', 'ebee39a067b61016bd21849648ea56e5');
define('API_VERSION', 'v2.5');
define('FB_BASE_URL', $baseredirecturl);
define('BASE_URL', 'https://2me.digital/');
if(!session_id()){
  session_start();
}

// Call Facebook API
$fb = new Facebook\Facebook([
'app_id' => APP_ID,
'app_secret' => APP_SECRET,
'default_graph_version' => API_VERSION,
]);

// Get redirect login helper
$fb_helper = $fb->getRedirectLoginHelper();
$permissions = ['email']; //optional
$fb_login_url = $fb_helper->getLoginUrl($baseredirecturl, $permissions);
if(isset($_GET['state']) && $_GET["state"]!='meena'){
try {
  if(isset($_SESSION['facebook_access_token']))
  {$accessToken = $_SESSION['facebook_access_token'];}
else
  {$accessToken = $fb_helper->getAccessToken();}
} catch(FacebookResponseException $e) {
   echo 'Facebook API Error: ' . $e->getMessage();
    exit;
} catch(FacebookSDKException $e) {
  echo 'Facebook SDK Error: ' . $e->getMessage();
    exit;
}

if (isset($accessToken))
{
if (!isset($_SESSION['facebook_access_token'])) 
{
  //get short-lived access token
  $_SESSION['facebook_access_token'] = (string) $accessToken;
  
  //OAuth 2.0 client handler
  $oAuth2Client = $fb->getOAuth2Client();
  
  //Exchanges a short-lived access token for a long-lived one
  $longLivedAccessToken = $oAuth2Client->getLongLivedAccessToken($_SESSION['facebook_access_token']);
  $_SESSION['facebook_access_token'] = (string) $longLivedAccessToken;
  
  //setting default access token to be used in script
  $fb->setDefaultAccessToken($_SESSION['facebook_access_token']);
} 
else 
{
  $fb->setDefaultAccessToken($_SESSION['facebook_access_token']);
}


//redirect the user to the index page if it has $_GET['code']
if (isset($_GET['code'])) 
{

}


try {
  $fb_response = $fb->get('/me?fields=name,first_name,last_name,email');
// 		$fb_response_picture = $fb->get('/me/picture?redirect=false&height=200');
  
  $fb_user = $fb_response->getGraphUser();
// 		$picture = $fb_response_picture->getGraphUser();
// 		echo$fb_user->getProperty('id');
// 		$_SESSION['fb_user_id'] = $fb_user->getProperty('id');
// 		$_SESSION['fb_user_name'] = $fb_user->getProperty('name');
// 		$_SESSION['fb_user_email'] = $fb_user->getProperty('email');
// 		$_SESSION['fb_user_pic'] = $picture['url'];
$namegf=$fb_user->getProperty('name');
$emailgf=$fb_user->getProperty('email');
  
} catch(Facebook\Exceptions\FacebookResponseException $e) {
  echo 'Facebook API Error: ' . $e->getMessage();
  session_destroy();
  // redirecting user back to app login page

  exit;
} catch(Facebook\Exceptions\FacebookSDKException $e) {
  echo 'Facebook SDK Error: ' . $e->getMessage();
  exit;
}
} 
else 
{	
// replace your website URL same as added in the developers.Facebook.com/apps e.g. if you used http instead of https and you used

}
}
// ===========gooogle
require_once 'vendor/autoload.php';
$google_client = new Google_Client();
$google_client->setClientId('969741686211-4t3e3kpohjloogt8jhtd3lcuc7l6s4qh.apps.googleusercontent.com');
$google_client->setClientSecret('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');
$google_client->setRedirectUri($baseredirecturl);
$google_client->addScope('email');
$google_client->addScope('profile');
$google_login_btn = $google_client->createAuthUrl();
if(isset($_GET["code"]) && $_GET["state"]!='meena')
{ 
$google_login_btn='';
$token = $google_client->fetchAccessTokenWithAuthCode($_GET["code"]);
if(!isset($token['error']))
{
$google_client->setAccessToken($token['access_token']);
$google_service = new Google_Service_Oauth2($google_client);
$data = $google_service->userinfo->get();
$data['given_name'] = $data['given_name'].' '.$data['family_name'];
$namegf= $data['given_name'];
$emailgf= $data['email'];
}
}
// ====end==============google===========


?>
















