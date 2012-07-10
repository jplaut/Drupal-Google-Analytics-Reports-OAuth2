<?php

/**
 * @file
 * Provides the GAFeed object type and associated methods.
 */

/**
 * GAFeed class to authorize access to and request data from
 * the Google Analytics Data Export API.
 */
class GAFeed {

  /* Methods require at least v2 */
  const gaFeedVersion = 2;
  const OAUTH2_REVOKE_URI = 'https://accounts.google.com/o/oauth2/revoke';
  const OAUTH2_TOKEN_URI = 'https://accounts.google.com/o/oauth2/token';
  const OAUTH2_AUTH_URL = 'https://accounts.google.com/o/oauth2/auth';
  const SCOPE = 'https://www.googleapis.com/auth/analytics.readonly https://www.google.com/analytics/feeds/';

  /* Response object */
  public $response;

  /* Formatted array of request results */
  public $results;

  /* Formatted array of request meta info */
  public $meta;

  /* URL to Google Analytics Data Export API */
  public $queryPath;

  /* Aggregate numbers from response */
  public $totals;

  /* Translated error message */
  public $error;

  /* Boolean TRUE if data is from the cache tables */
  public $fromCache = FALSE;

  /* Domain of Data Feed API */
  protected $host = 'www.google.com';

  /* OAuth access token */
  public $access_token;

  /* OAuth refresh token */
  public $refresh_token;

  /* OAuth expiration time */
  public $expires_at;

  /**
   * Constructor for the GAFeed class
   */
  public function __construct($token = NULL) {
    $this->access_token = $token;
  }

  /**
   * Get the current page url
   *
   * @return String
   */
  public static function currentUrl() {
    $https = $_SERVER['HTTPS'] == 'on';
    $url = $https ? 'https://' : 'http://';
    $url .= $_SERVER['SERVER_NAME'];
    if ((!$https && $_SERVER['SERVER_PORT'] != '80') ||
      ($https && $_SERVER['SERVER_PORT'] != '443')) {
      $url .= ':' . $_SERVER['SERVER_PORT'];
    }
    return $url . str_replace("&code=" . $_GET['code'], '', $_SERVER['REQUEST_URI']);
  }

	/**
	* Create a URL to obtain user authorization.
	* The authorization endpoint allows the user to first
	* authenticate, and then grant/deny the access request.
	* @param string $client_id
	* @return string
	*/
	public function createAuthUrl($client_id) {
	  	$params = array(
	      		'response_type=code',
			    'redirect_uri=' . self::currentUrl(),
			    'client_id=' . urlencode($client_id),
			    'scope=' . self::SCOPE,
			    'access_type=offline',
			    'approval_prompt=force' 
	  			);

		$params = implode('&', $params);
		return self::OAUTH2_AUTH_URL . "?$params";
	}
	
	/**
	* Authenticate with the Google API
	*
	* @param String $client_id
	* @param String $client_secret
	* @param String $refresh_token
	* @return GAFeed
	*/
	protected function fetchToken($client_id, $client_secret, $refresh_token=NULL) {
		$redirect_uri = self::currentUrl();
		
		if ($refresh_token) {
			$params = array(
					'client_id=' . $client_id,
					'client_secret=' . $client_secret,
					'refresh_token=' . $refresh_token,
					'grant_type=refresh_token',
					);
		}
		else {
			$params = array(
					'code=' . $_GET['code'],
		        	'grant_type=authorization_code',
		        	'redirect_uri=' . $redirect_uri,
		        	'client_id=' . $client_id,
		        	'client_secret=' . $client_secret,
					);
		}
		
		$data = implode('&', $params);
		$this->response = drupal_http_request(self::OAUTH2_TOKEN_URI, array('Content-Type' => 'application/x-www-form-urlencoded'), 'POST', $data);

		if (substr($this->response->code, 0, 1) == '2') {
			$decoded_response = json_decode($this->response->data, true);
			$this->access_token = $decoded_response['access_token'];
			$this->expires_at = time() + $decoded_response['expires_in'];
			if (!$refresh_token) {
				$this->refresh_token = $decoded_response['refresh_token'];
			}
		} 
		else {
	        $error_msg = 'Code: !code - Error: !message - Message: !details';
		    $error_vars = array('!code' => $this->response->code, '!message' => $this->response->error, '!details' => strip_tags($this->response->data));
		    $this->error =  t($error_msg, $error_vars);
		    watchdog('google analytics reports', $error_msg, $error_vars, WATCHDOG_ERROR);
		}
	}
	
	/**
  * Complete the authentication process.
  * We got here after being redirected from a successful authorization grant.
  * Fetch the access token
  *
  * @param String $client_id
  * @param String $client_secret
  */
  public function finishAuthentication($client_id, $client_secret) {
    $this -> fetchToken($client_id, $client_secret);
  }
	
  /**
  * Begin authentication by allowing the user to grant/deny access to the Google account
  *
  * @param String $client_id
  */
  public function beginAuthentication($client_id) {
	drupal_goto($this -> createAuthUrl($client_id));
  }

	/**
	* Fetches a fresh access token with the given refresh token.
	* @param String $client_id
	* @param String $client_secret
	* @param string $refresh_token
	*/
	public function refreshToken($client_id, $client_secret, $refresh_token) {
		$this->refresh_token = $refresh_token;
		$this -> fetchToken($client_id, $client_secret, $refresh_token);
	}
	
	/**
	* Revoke an OAuth2 access token or refresh token. This method will revoke the current access
	* token, if a token isn't provided.
	* @param string|NULL $token The token (access token or a refresh token) that should be revoked.
	* @return boolean Returns True if the revocation was successful, otherwise False.
	*/
	public function revokeToken($token = NULL) {
		if (!$token) {
			$token = $this->refresh_token;
		}
		
		$this->response = drupal_http_request(self::OAUTH2_REVOKE_URI, array('Content-Type' => 'application/x-www-form-urlencoded'), 'POST', "token=$token");

		if ($this->response->code == 200) {
			$this->access_token = NULL;
			return true;
		}

		return false;
	}
	
	/**
  * Generate authorization token header for all requests
  *
  * @return Array
  */
	public function generateAuthHeader($token=NULL) {
		if ($token == NULL) {
			$token = $this->access_token;
		}
		return array('Authorization' => 'Bearer ' . $token);
	}


  /**
   * Set the queryPath property for all Data Export API requests
  */
  protected function setQueryPath($path) {
    $this->queryPath = 'https://'. $this->host .'/'. $path;
  }

  /**
   * Public query method for all Data Export API features.
   */
  public function query($url, $params = array(), $method = 'GET', $headers, $cache_options) {

    $params_defaults = array(
      'v' => self::gaFeedVersion,
    );
    $params += $params_defaults;

    /* Provide cache defaults if a developer did not override them */
    $cache_defaults = array(
      'cid' => NULL,
      'expire' => google_analytics_reports_cache_time(),
      'refresh' => FALSE,
    );
    $cache_options += $cache_defaults;

    /* Provide a query MD5 for the cid if the developer did not provide one */
    if (empty($cache_options['cid'])) {
      $cache_options['cid'] = 'GAFeed:' . md5(serialize(array_merge($params, array($path, $method))));
    }

    $cache = cache_get($cache_options['cid']);

    if (!$cache_options['refresh'] && isset($cache) && !empty($cache->data)) {
      $this->response = $cache->data;
      $this->fromCache = TRUE;
    }
    else {
      $this->request($url, $params, $headers);
    }

    /* Do not cache erroneous queries */
    if (empty($this->error)) {
      cache_set($cache_options['cid'], $this->response, 'cache', $cache_options['expire']);
    }

    return (empty($this->error));
  }

  /**
   * Execute a query
   */
  protected function request($url, $params = array(), $headers, $method = 'GET') {
    $data = '';
    if (count($params) > 0) {
      if ($method == 'GET') {
        $url .= '?'. http_build_query($params, '', '&');
      }
      else {
        $data = http_build_query($params, '', '&');
      }
    }

    $this->response = drupal_http_request($url, $headers, $method, $data);
    if ($this->response->code != '200') {
      // data is undefined if the connection failed.
      if (!isset($this->response->data)) {
        $this->response->data = '';
      }
      $error_msg = 'Code: !code - Error: !message - Message: !details';
      $error_vars = array('!code' => $this->response->code, '!message' => $this->response->error, '!details' => strip_tags($this->response->data));
      $this->error =  t($error_msg, $error_vars);
      watchdog('google analytics reports', $error_msg, $error_vars, WATCHDOG_ERROR);
    }
  }

  /**
   * Query and sanitize account data
   */
  public function queryAccountFeed($params = array(), $cache_options = array()) {

    $params  += array(
      'start-index' => 1,
      'max-results' => 1000,
    );

    $this->setQueryPath('analytics/feeds/accounts/default');
    if ($this->query($this->queryPath, $params, 'GET', $this->generateAuthHeader(), $cache_options)) {
      $this->sanitizeAccount();
    }
  }

  /**
   * Sanitize account data
   */
  protected function sanitizeAccount() {
    $xml = simplexml_load_string($this->response->data);

    $this->results = NULL;
    $results = array();
    $meta = array();

    /* Save meta info */
    $meta['updated'] = check_plain(strval($xml->updated));
    $meta['generator'] = check_plain(strval($xml->generator));
    $meta['generatorVersion'] = check_plain(strval($xml->generator->attributes()));

    $opensearch = $xml->children('http://a9.com/-/spec/opensearchrss/1.0/');
    foreach ($opensearch as $key => $open_search_result) {
      $meta[$key] = intval($open_search_result);
    }

    /* Save results */
    foreach ($xml->entry as $entry) {
      $properties = array();
      foreach ($entry->children('http://schemas.google.com/analytics/2009')->property as $property) {
        $properties[str_replace('ga:', '', check_plain($property->attributes()->name))] = check_plain(strval($property->attributes()->value));
      }
      $properties['title'] = check_plain(strval($entry->title));
      $properties['updated'] = check_plain(strval($entry->updated));
      $results[$properties['profileId']] = $properties;
    }

    $this->meta = $meta;
    $this->results = $results;
  }

  /**
   * Query and sanitize report data
   */
  public function queryReportFeed($params = array(), $cache_options = array()) {

    /* Provide defaults if the developer did not override them */
    $params += array(
      'profile_id' => 0,
      'dimensions' => NULL,
      'metrics' => 'ga:visits',
      'sort_metric' => NULL,
      'filters' => NULL,
      'segment' => NULL,
      'start_date' => NULL,
      'end_date' => NULL,
      'start_index' => 1,
      'max_results' => 10000,
    );

    $parameters = array('ids' => $params['profile_id']);

    if (is_array($params['dimensions'])) {
      $parameters['dimensions'] = implode(',', $params['dimensions']);
    }
    elseif ($params['dimensions'] !== NULL) {
      $parameters['dimensions'] = $params['dimensions'];
    }

    if (is_array($params['metrics'])) {
      $parameters['metrics'] = implode(',', $params['metrics']);
    }
    else {
      $parameters['metrics'] = $params['metrics'];
    }

    if ($params['sort_metric'] == NULL && isset($parameters['metrics'])) {
      $parameters['sort'] = $parameters['metrics'];
    }
    elseif (is_array($params['sort_metric'])) {
      $parameters['sort'] = implode(',', $params['sort_metric']);
    }
    else {
      $parameters['sort'] = $params['sort_metric'];
    }

    if ($params['start_date'] == NULL) {
      /* Use the day that Google Analytics was released (1 Jan 2005) */
      $start_date = '2005-01-01';
    }
    elseif (is_int($params['start_date'])) {
      /* Assume a Unix timestamp */
      $start_date = date('Y-m-d', $params['start_date']);
    }

    $parameters['start-date'] = $start_date;

    if ($params['end_date'] == NULL) {
      $end_date = date('Y-m-d');
    }
    elseif (is_int($params['end_date'])) {
      /* Assume a Unix timestamp */
      $end_date = date('Y-m-d', $params['end_date']);
    }

    $parameters['end-date'] = $end_date;

    /* Accept only strings, not arrays, for the following parameters */
    $parameters['filters'] = $params['filters'];
    $parameters['segment'] = $params['segment'];
    $parameters['start-index'] = $params['start_index'];
    $parameters['max-results'] = $params['max_results'];

    $this->setQueryPath('analytics/feeds/data');
    if ($this->query($this->queryPath, $parameters, 'GET', $this->generateAuthHeader(), $cache_options)) {
      $this->sanitizeReport();
    }
  }

  /**
   * Sanitize report data
   */
  protected function sanitizeReport() {
    $xml = simplexml_load_string($this->response->data);

    $this->results = NULL;
    $results = array();
    $meta = array();
    $totals = array();


    /* Save meta info */
    $meta['updated'] = check_plain(strval($xml->updated));
    $meta['generator'] = check_plain(strval($xml->generator));
    $meta['generatorVersion'] = check_plain(strval($xml->generator->attributes()));

    $opensearch = $xml->children('http://a9.com/-/spec/opensearchrss/1.0/');
    foreach ($opensearch as $key => $open_search_result) {
      $meta[$key] = intval($open_search_result);
    }

    $google_results = $xml->children('http://schemas.google.com/analytics/2009');
    foreach ($google_results->dataSource->property as $property_attributes) {
      $meta[str_replace('ga:', '', check_plain($property_attributes->attributes()->name))] = check_plain(strval($property_attributes->attributes()->value));
    }
    $meta['startDate'] = check_plain(strval($google_results->startDate));
    $meta['endDate'] = check_plain(strval($google_results->endDate));

    /* Save totals */
    foreach ($google_results->aggregates->metric as $aggregate_metric) {
      $metric_value = check_plain(strval($aggregate_metric->attributes()->value));
      /* Check for float, or value with scientific notation */
      if (preg_match('/^(\d+\.\d+)|(\d+E\d+)|(\d+.\d+E\d+)$/', $metric_value)) {
        $totals[str_replace('ga:', '', check_plain($aggregate_metric->attributes()->name))] = floatval($metric_value);
      }
      else {
        $totals[str_replace('ga:', '', check_plain($aggregate_metric->attributes()->name))] = intval($metric_value);
      }
    }

    /* Save results */
    foreach ($xml->entry as $entry) {
      $metrics = array();
      foreach ($entry->children('http://schemas.google.com/analytics/2009')->metric as $metric) {
        $metric_value = check_plain(strval($metric->attributes()->value));

        //Check for float, or value with scientific notation
        if (preg_match('/^(\d+\.\d+)|(\d+E\d+)|(\d+.\d+E\d+)$/', $metric_value)) {
          $metrics[str_replace('ga:', '', check_plain($metric->attributes()->name))] = floatval($metric_value);
        }
        else {
          $metrics[str_replace('ga:', '', check_plain($metric->attributes()->name))] = intval($metric_value);
        }
      }

      $dimensions = array();
      foreach ($entry->children('http://schemas.google.com/analytics/2009')->dimension as $dimension) {
        $dimensions[str_replace('ga:', '', check_plain($dimension->attributes()->name))] = check_plain(strval($dimension->attributes()->value));
      }

      $results[] = array_merge($metrics, $dimensions);
    }

    $this->meta = $meta;
    $this->totals = $totals;
    $this->results = $results;
  }
}