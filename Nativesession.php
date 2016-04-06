<?php
if ( ! defined('BASEPATH') )
    exit( 'No direct script access allowed' );

class Nativesession
{
    private $ci;
    private $session_path = FCPATH . 'sessions';

    public function __construct()
    {
        $this->ci = get_instance();

        session_name($this->ci->config->item('sess_cookie_name'));

        if (!file_exists($this->session_path)) {
            mkdir($this->session_path);
        }

        session_save_path(FCPATH . 'sessions');
        if (!session_start() || !$this->session_valid_id(session_id())) {
            log_message('error', 'Failed to create session or existing session ID is invalid');
            $this->ci->input->set_cookie(session_name(), null);
            die('Failed to create session or existing session ID is invalid');
        }

        $params = session_get_cookie_params();
        if (!$this->ci->config->item('sess_expire_on_close')) {
            $time = $this->ci->config->item('sess_expiration');

            if ($time == 0) {
                $time = 60 * 60 * 24 * 356;
            }

            setcookie(session_name(), session_id(), time() + $time, $params["path"], $params["domain"], $this->ci->config->item('cookie_secure'), $params["httponly"]);
        } else {
            setcookie(session_name(), session_id(), $params["lifetime"], $params["path"], $params["domain"], $this->ci->config->item('cookie_secure'), $params["httponly"]);
        }

        // Delete 'old' flashdata (from last request)
        $this->_flashdata_sweep();

        // Mark all new flashdata as old (data will be deleted before next request)
        $this->_flashdata_mark();

        if ($last_act = $this->userdata('last_activity')) {
            //Regenerate session id
            $time2upd = $this->ci->config->item('sess_time_to_update');
            if ($last_act + $time2upd < time()) {
                $oldsess =  session_id();
                $this->regenerateId(true);
                log_message('debug', 'Regenerating session from ' . $oldsess .' to ' . session_id());
            }
        }

        if ($ip_address = $this->userdata('ip_address')) {
            if ($this->ci->config->item('sess_match_ip') && $ip_address !== $this->ci->input->ip_address()) {
                log_message('error', 'Session mismatch ip address ' . $ip_address . ' !== ' . $this->ci->input->ip_address());
                $_SESSION = array();
            }
        }

        if ($user_agent = $this->userdata('user_agent')) {
            if ($this->ci->config->item('sess_match_useragent') && $user_agent !== $this->ci->input->user_agent()) {
                log_message('error', 'Session mismatch user agent ' . $user_agent . ' !== ' . $this->ci->input->user_agent());
                $_SESSION = array();
            }
        }

        if (!$this->userdata('created')) {
            $this->set_userdata('created', date('Y-m-d H:i:s', time()));
        }

        $this->set_userdata(array(
            'last_activity' => time(),
            'ip_address' => $this->ci->input->ip_address(),
            'user_agent' => $this->ci->input->user_agent()
        ));

    }

    public function set_userdata($newdata = array(), $newval = '')
    {
        if (is_string($newdata))
        {
            $newdata = array($newdata => $newval);
        }

        if (count($newdata) > 0)
        {
            foreach ($newdata as $key => $val)
            {
                $_SESSION[$key] = $val;
            }
        }
    }

    public function unset_userdata($newdata = array())
    {
        if (is_string($newdata))
        {
            $newdata = array($newdata => '');
        }

        if (count($newdata) > 0)
        {
            foreach ($newdata as $key => $val)
            {
                unset($_SESSION[$key]);
            }
        }
    }

    public function userdata($key)
    {
        return isset( $_SESSION[$key] ) ? $_SESSION[$key] : null;
    }

    public function all_userdata()
    {
        return $_SESSION;
    }

    /**
     * Add or change flashdata, only available
     * until the next request
     *
     * @access	public
     * @param	mixed
     * @param	string
     * @return	void
     */
    function set_flashdata($newdata = array(), $newval = '')
    {
        if (is_string($newdata))
        {
            $newdata = array($newdata => $newval);
        }

        if (count($newdata) > 0)
        {
            foreach ($newdata as $key => $val)
            {
                $flashdata_key = 'flashdata:new:'.$key;
                $this->set_userdata($flashdata_key, $val);
            }
        }
    }

    function flashdata($key)
    {
        $flashdata_key = 'flashdata:old:'.$key;
        return $this->userdata($flashdata_key);
    }

    /**
     * Keeps existing flashdata available to next request.
     *
     * @access	public
     * @param	string
     * @return	void
     */
    function keep_flashdata($key)
    {
        // 'old' flashdata gets removed.  Here we mark all
        // flashdata as 'new' to preserve it from _flashdata_sweep()
        // Note the function will return FALSE if the $key
        // provided cannot be found
        $old_flashdata_key = 'flashdata:old:'.$key;
        $value = $this->userdata($old_flashdata_key);

        $new_flashdata_key = 'flashdata:new:'.$key;
        $this->set_userdata($new_flashdata_key, $value);
    }

    /**
     * Identifies flashdata as 'old' for removal
     * when _flashdata_sweep() runs.
     *
     * @access	private
     * @return	void
     */
    function _flashdata_mark()
    {
        $userdata = $this->all_userdata();
        foreach ($userdata as $name => $value)
        {
            $parts = explode(':new:', $name);
            if (is_array($parts) && count($parts) === 2)
            {
                $new_name = 'flashdata:old:'.$parts[1];
                $this->set_userdata($new_name, $value);
                $this->unset_userdata($name);
            }
        }
    }

    // ------------------------------------------------------------------------

    /**
     * Removes all flashdata marked as 'old'
     *
     * @access	private
     * @return	void
     */

    function _flashdata_sweep()
    {
        $userdata = $this->all_userdata();
        foreach ($userdata as $key => $value)
        {
            if (strpos($key, ':old:'))
            {
                $this->unset_userdata($key);
            }
        }

    }

    public function regenerateId($delOld = false)
    {
        if (!$this->ci->input->is_ajax_request()) {
            session_regenerate_id($delOld);
        }
    }

    public function sess_destroy()
    {
        $this->ci->input->set_cookie(session_name(), null);
        session_destroy();
        session_write_close();
    }

    public function session_valid_id($session_id)
    {
        return preg_match('/^[-,a-zA-Z0-9]{1,128}$/', $session_id) > 0;
    }

}