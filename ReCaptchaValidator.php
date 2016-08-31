<?php
/**
 * @link https://github.com/himiklab/yii2-recaptcha-widget
 * @copyright Copyright (c) 2014 HimikLab
 * @license http://opensource.org/licenses/MIT MIT
 */

namespace himiklab\yii2\recaptcha;

use Yii;
use yii\base\Exception;
use yii\base\InvalidConfigException;
use yii\helpers\Json;
use yii\validators\Validator;

/**
 * ReCaptcha widget validator.
 *
 * @author HimikLab
 * @package himiklab\yii2\recaptcha
 */
class ReCaptchaValidator extends Validator
{
    const GRABBER_PHP = 1; // file_get_contents
    const GRABBER_CURL = 2; // CURL, because sometimes file_get_contents is deprecated

    const SITE_VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify';
    const CAPTCHA_RESPONSE_FIELD = 'g-recaptcha-response';

    /** @var boolean Whether to skip this validator if the input is empty. */
    public $skipOnEmpty = false;

    /** @var string The shared key between your site and ReCAPTCHA. */
    public $secret;

    /** @var int Choose your grabber for getting JSON, self::GRABBER_PHP = file_get_contents, self::GRABBER_CURL = CURL */
    public $grabberType = self::GRABBER_PHP;

    public $uncheckedMessage;

    public function init()
    {
        parent::init();
        if (empty($this->secret)) {
            if (!empty(Yii::$app->reCaptcha->secret)) {
                $this->secret = Yii::$app->reCaptcha->secret;
            } else {
                throw new InvalidConfigException('Required `secret` param isn\'t set.');
            }
        }

        if ($this->message === null) {
            $this->message = Yii::t('yii', 'The verification code is incorrect.');
        }
    }

    /**
     * @param \yii\base\Model $model
     * @param string $attribute
     * @param \yii\web\View $view
     * @return string
     */
    public function clientValidateAttribute($model, $attribute, $view)
    {
        $message = $this->uncheckedMessage ? $this->uncheckedMessage : Yii::t(
            'yii',
            '{attribute} cannot be blank.',
            ['attribute' => $model->getAttributeLabel($attribute)]
        );
        return "(function(messages){if(!grecaptcha.getResponse()){messages.push('{$message}');}})(messages);";
    }

    /**
     * @param string $value
     * @return array|null
     * @throws Exception
     */
    protected function validateValue($value)
    {
        if (empty($value)) {
            if (!($value = Yii::$app->request->post(self::CAPTCHA_RESPONSE_FIELD))) {
                return [$this->message, []];
            }
        }

        $request = self::SITE_VERIFY_URL . '?' . http_build_query([
                'secret' => $this->secret,
                'response' => $value,
                'remoteip' => Yii::$app->request->userIP
            ]);
        $response = $this->getResponse($request);
        if (!isset($response['success'])) {
            throw new Exception('Invalid recaptcha verify response.');
        }
        return $response['success'] ? null : [$this->message, []];
    }

    /**
     * @param string $request
     * @return mixed
     * @throws Exception
     */
    protected function getResponse($request)
    {
        if ($this->grabberType === self::GRABBER_PHP) {
            $response = @file_get_contents($request);

            if ($response === false) {
                throw new Exception('Unable connection to the captcha server.');
            }
        } else {
            $ch = curl_init($request);

            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
            curl_setopt($ch, CURLOPT_POST, false);
            curl_setopt($ch, CURLOPT_HEADER, false);
            curl_setopt($ch, CURLOPT_ENCODING, '');
            curl_setopt($ch, CURLOPT_AUTOREFERER, true);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 120);
            curl_setopt($ch, CURLOPT_TIMEOUT, 120);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

            $content = $this->curlExec($ch);
            $err = curl_errno($ch);
            $errmsg = curl_error($ch);
            $header = curl_getinfo($ch);
            curl_close($ch);

            $header['errno'] = $err;
            $header['errmsg'] = $errmsg;
            $response = $content;

            if ($header['errno'] !== 0) {
                throw new Exception('Unable connection to the captcha server. ' . $header['errmsg']);
            }
        }

        return Json::decode($response, true);
    }

    protected function curlExec($ch, &$maxredirect = null)
    {
        // we emulate a browser here since some websites detect
        // us as a bot and don't let us do our job
        $user_agent = "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.7.5)" .
            " Gecko/20041107 Firefox/1.0";
        curl_setopt($ch, CURLOPT_USERAGENT, $user_agent);

        $mr = $maxredirect === null ? 10 : intval($maxredirect);

        if (
            filter_var(ini_get('open_basedir'), FILTER_VALIDATE_BOOLEAN) === false &&
            filter_var(ini_get('safe_mode'), FILTER_VALIDATE_BOOLEAN) === false
        ) {
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, $mr > 0);
            curl_setopt($ch, CURLOPT_MAXREDIRS, $mr);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        } else {

            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);

            if ($mr > 0) {
                $original_url = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
                $newurl = $original_url;

                $rch = curl_copy_handle($ch);

                curl_setopt($rch, CURLOPT_HEADER, true);
                curl_setopt($rch, CURLOPT_NOBODY, true);
                curl_setopt($rch, CURLOPT_FORBID_REUSE, false);

                do {
                    curl_setopt($rch, CURLOPT_URL, $newurl);
                    $header = curl_exec($rch);
                    if (curl_errno($rch)) {
                        $code = 0;
                    } else {
                        $code = curl_getinfo($rch, CURLINFO_HTTP_CODE);
                        if ($code == 301 || $code == 302) {
                            preg_match('/Location:(.*?)\n/i', $header, $matches);
                            $newurl = trim(array_pop($matches));

                            // if no scheme is present then the new url is a
                            // relative path and thus needs some extra care
                            if (!preg_match("/^https?:/i", $newurl)) {
                                $newurl = $original_url . $newurl;
                            }
                        } else {
                            $code = 0;
                        }
                    }
                } while ($code && --$mr);

                curl_close($rch);

                if (!$mr) {
                    if ($maxredirect === null)
                        trigger_error('Too many redirects.', E_USER_WARNING);
                    else
                        $maxredirect = 0;

                    return false;
                }
                curl_setopt($ch, CURLOPT_URL, $newurl);
            }
        }

        return curl_exec($ch);
    }
}
