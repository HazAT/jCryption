<?php

class sqAES
{
    /**
     * decrypt AES 256
     *
     * @param string $password
     * @param data $edata
     *
     * @return dencrypted data
     */
    public static function decrypt($password, $edata)
    {
        $data = base64_decode($edata);
        $salt = substr($data, 8, 8);
        $ct = substr($data, 16);

        /**
         * From https://github.com/mdp/gibberish-aes
         *
         * Number of rounds depends on the size of the AES in use
         * 3 rounds for 256
         *        2 rounds for the key, 1 for the IV
         * 2 rounds for 128
         *        1 round for the key, 1 round for the IV
         * 3 rounds for 192 since it's not evenly divided by 128 bits
         */
        $rounds = 3;
        $data00 = $password.$salt;
        $md5_hash = array();
        $md5_hash[0] = md5($data00, true);
        $result = $md5_hash[0];

        for ($i = 1; $i < $rounds; $i++) {
            $md5_hash[$i] = md5($md5_hash[$i - 1].$data00, true);
            $result .= $md5_hash[$i];
        }

        $key = substr($result, 0, 32);
        $iv  = substr($result, 32, 16);

        return openssl_decrypt($ct, 'aes-256-cbc', $key, true, $iv);
    }

    /**
     * crypt AES 256
     *
     * @param string $password
     * @param data $data
     *
     * @return base64 encrypted data
     */
    public static function crypt($password, $data)
    {
        // Set a random salt
        $salt = openssl_random_pseudo_bytes(8);

        $salted = '';
        $dx = '';

        // Salt the key(32) and iv(16) = 48
        while (strlen($salted) < 48) {
            $dx = md5($dx.$password.$salt, true);
            $salted .= $dx;
        }

        $key = substr($salted, 0, 32);
        $iv  = substr($salted, 32, 16);

        $encrypted_data = openssl_encrypt($data, 'aes-256-cbc', $key, true, $iv);

        return base64_encode('Salted__'.$salt.$encrypted_data);
    }
}
