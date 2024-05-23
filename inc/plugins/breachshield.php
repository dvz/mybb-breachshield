<?php

namespace
{
    $plugins->add_hook('datahandler_login_validate_end', 'breachshield\Hooks\datahandler_login_validate_end');
    $plugins->add_hook('member_resetpassword_start', 'breachshield\Hooks\member_resetpassword_start');
    $plugins->add_hook('member_resetpassword_process', 'breachshield\Hooks\member_resetpassword_process');

    // MyBB plugin system
    function breachshield_info()
    {
        return [
            'name'          => 'Breach Shield',
            'description'   => 'Rejects breached passwords.',
            'author'        => 'dvz',
            'authorsite'    => 'https://devilshakerz.com/',
            'version'       => '1.0',
            'codename'      => 'breachshield',
            'compatibility' => '18*',
        ];
    }
}

namespace breachshield\Hooks
{

    function datahandler_login_validate_end(\LoginDataHandler $loginDataHandler): void
    {
        global $mybb, $lang;

        if (count($loginDataHandler->get_errors()) === 0) {
            if (\breachshield\passwordCompromised($loginDataHandler->data['password']) === true) {
                $lang->load('breachshield', true);

                $loginDataHandler->set_error('password_compromised', [
                    $mybb->settings['bburl'] . '/member.php?action=lostpw',
                ]);
            }
        }
    }

    function member_resetpassword_start(): void
    {
        global $mybb, $breachshield;

        $breachshield['settingDefaults']['minpasswordlength'] = $mybb->settings['minpasswordlength'];

        $mybb->settings['minpasswordlength'] = \breachshield\RANDOM_PASSWORD_LENGTH;
    }

    function member_resetpassword_process(): void
    {
        global $mybb, $breachshield;

        $default = &$breachshield['settingDefaults']['minpasswordlength'];

        if (isset($default)) {
            $mybb->settings['minpasswordlength'] = $default;
        }
    }
}

namespace breachshield
{
    const API_URL = 'https://api.pwnedpasswords.com/range/';
    const RANDOM_PASSWORD_LENGTH = 20;

    function passwordCompromised(string $password): ?bool
    {
        $hash = strtoupper(
            hash('sha1', $password)
        );

        $hashPrefix = substr($hash, 0, 5);

        $compromisedSuffixes = \breachshield\getCompromisedSuffixes($hashPrefix);

        if ($compromisedSuffixes !== null) {
            $hashSuffix = substr($hash, 5);

            if (in_array($hashSuffix, $compromisedSuffixes, true)) {
                return true;
            } else {
                return false;
            }
        }

        return null;
    }

    function getCompromisedSuffixes(string $prefix): ?array
    {
        if (strlen($prefix) !== 5) {
            throw new \InvalidArgumentException();
        }

        $response = fetch_remote_file(API_URL . $prefix);

        if ($response !== false) {
            $suffixes = [];

            $lines = explode("\n", $response);

            foreach ($lines as $line) {
                $parts = explode(':', $line);

                $suffixes[] = $parts[0] ?? null;
            }

            return $suffixes;
        } else {
            return null;
        }
    }
}
