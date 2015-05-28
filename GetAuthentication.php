<?php
//Created by Jeetendra Maharjan

class GetAuthentication
	{
		
	public $url,$username,$password;
	private static $stsUrl = 'https://login.microsoftonline.com/extSTS.srf';
	public $FedAuth,$rtFa,$FormDigestValue;
	private static $signInPageUrl = '/_forms/default.aspx?wa=wsignin1.0';
		
	public function GetAuthentication($username,$password,$url)
		{
		if (!function_exists('curl_init')) {
            die("Curl is not enabled");
        }
        $this->url = $url;
		$this->password = $password;
		$this->username = $username;
		}
	
	public function SignIn()
		{
		$token = $this->requestToken();
        $header = $this->submitToken($token);
		$this->saveAuthCookies($header);
        $this->getrequestdigest();
		//$this->FormDigestValue;
		}
		
	
	public function requestToken()
		{
			$samlRequest = $this->buildSamlRequest();
			$ch = curl_init();
			curl_setopt($ch,CURLOPT_SSL_VERIFYPEER,false);
			curl_setopt($ch,CURLOPT_URL,self::$stsUrl);
			curl_setopt($ch,CURLOPT_POST,1);
			curl_setopt($ch,CURLOPT_POSTFIELDS,$samlRequest);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			$result = curl_exec($ch);
			if($result === false) {
				throw new Exception(curl_error($ch));
			}
			curl_close($ch);
			return $this->processToken($result);
		}
	
	
	public function buildSamlRequest()
		{
			$endpoint = $this->url.'/_forms/default.aspx?wa=wsignin1.0';
			return <<<TOKEN
    <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
      xmlns:a="http://www.w3.org/2005/08/addressing"
      xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <s:Header>
    <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</a:Action>
    <a:ReplyTo>
      <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
    </a:ReplyTo>
    <a:To s:mustUnderstand="1">https://login.microsoftonline.com/extSTS.srf</a:To>
    <o:Security s:mustUnderstand="1"
       xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
      <o:UsernameToken>
        <o:Username>$this->username</o:Username>
        <o:Password>$this->password</o:Password>
      </o:UsernameToken>
    </o:Security>
  </s:Header>
  <s:Body>
    <t:RequestSecurityToken xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust">
      <wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">
        <a:EndpointReference>
          <a:Address>$endpoint</a:Address>
        </a:EndpointReference>
      </wsp:AppliesTo>
      <t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType>
      <t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType>
      <t:TokenType>urn:oasis:names:tc:SAML:1.0:assertion</t:TokenType>
    </t:RequestSecurityToken>
  </s:Body>
</s:Envelope>
TOKEN;
			
		}
	
	
	 private function processToken($body)
    {
        $xml = new DOMDocument();
        $xml->loadXML($body);
        $xpath = new DOMXPath($xml);
        if($xpath->query("//S:Fault")->length > 0) {
            $nodeErr = $xpath->query("//S:Fault/S:Detail/psf:error/psf:internalerror/psf:text")->item(0);
            throw new Exception($nodeErr->nodeValue);
        }
        $nodeToken = $xpath->query("//wsse:BinarySecurityToken")->item(0);
        return $nodeToken->nodeValue;
    }
	
	
	
	private function submitToken($token) {

        $urlinfo = parse_url($this->url);
        $url =  $urlinfo['scheme'] . '://' . $urlinfo['host'] . self::$signInPageUrl;
		
        $ch = curl_init();
        curl_setopt($ch,CURLOPT_SSL_VERIFYPEER,false);
        curl_setopt($ch,CURLOPT_URL,$url);
        curl_setopt($ch,CURLOPT_POST,1);
        curl_setopt($ch,CURLOPT_POSTFIELDS,$token);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        $result = curl_exec($ch);
        if($result === false) {
			echo 'aa';
            throw new Exception(curl_error($ch));
        }
        $header=substr($result,0,curl_getinfo($ch,CURLINFO_HEADER_SIZE));
        curl_close($ch);

        return $header;
    }
	
	private function saveAuthCookies($header){
       	$cookies = $this->cookie_parse($header);
        $this->FedAuth = $cookies['FedAuth'];
        $this->rtFa = $cookies['rtFa'];
		
    }
	
	
private function cookie_parse( $header ) {
    $headerLines = explode("\r\n",$header);
    $cookies = array();
    foreach( $headerLines as $line ) {
        if( preg_match( '/^Set-Cookie: /i', $line ) ) {
            $line = preg_replace( '/^Set-Cookie: /i', '', trim( $line ) );
            $csplit = explode( ';', $line);
            $cinfo = explode( '=', $csplit[0],2);
            $cookies[$cinfo[0]] = $cinfo[1];
        }
    }
    return $cookies;
}
	
	
	
	private function getrequestdigest()
    {
		
        //$data = array_key_exists('data', $options) ? json_encode($options['data']) : '';
		//echo $data;
		//exit;
		//echo $FedAuth;
		$method = 'POST';
		$urlinfo = parse_url($this->url);
		$url =  $urlinfo['scheme'] . '://' . $urlinfo['host'] . "/sites/edvelop/_api/contextinfo";
        $headers = array(
            'Accept: application/json; odata=verbose',
            'Content-type: application/json; odata=verbose',
            'Cookie: FedAuth=' . $this->FedAuth . '; rtFa=' . $this->rtFa,
            'Content-length:0'
        );
        

        $ch = curl_init();
        curl_setopt($ch,CURLOPT_SSL_VERIFYPEER,0);
        curl_setopt($ch,CURLOPT_URL,$url);
        curl_setopt($ch,CURLOPT_HTTPHEADER,$headers);
		curl_setopt($ch,CURLOPT_POST,1);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $result = curl_exec($ch);
		//var_dump($result);
		//exit;
        if($result === false) {
            throw new Exception(curl_error($ch));
        }

        curl_close($ch);
        $contextInfo = json_decode($result);
		//echo '<pre>';
		//var_dump($contextInfo);
		$b = $contextInfo->d;
		$FormDigestValue = $b->GetContextWebInformation->FormDigestValue;
		$this->FormDigestValue = $FormDigestValue;
		//return $FormDigestValue;
    }
	
	
	
	}
?>