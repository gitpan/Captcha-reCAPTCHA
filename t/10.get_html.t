use strict;
use warnings;
use Test::More;
use Captcha::reCAPTCHA;

my @schedule;

my $PUBKEY;

BEGIN {

    # Looks real. Isn't.
    $PUBKEY   = '6LdAAAkAwAAAFJj6ACG3Wlix_GuQJMNGjMQnw5UY';
    @schedule = (
        {
            name => 'Simple',
            args => [$PUBKEY],
            expect =>
              qq{<script src="http://api.recaptcha.net/challenge?k=$PUBKEY" }
              . qq{type="text/javascript"></script>\n}
              . qq{<noscript><iframe frameborder="0" height="300" }
              . qq{src="http://api.recaptcha.net/noscript?k=$PUBKEY" }
              . qq{width="500"></iframe><textarea cols="40" name="recaptcha_challenge_field" }
              . qq{rows="3"></textarea><input name="recaptcha_response_field" type="hidden" }
              . qq{value="manual_challenge" /></noscript>}
        },
        {
            name => 'Error',
            args => [$PUBKEY, '<<some random error>>'],
            expect =>
              qq{<script src="http://api.recaptcha.net/challenge?error=%3c%3csome+random+error%3e%3e&amp;k=$PUBKEY" }
              . qq{type="text/javascript"></script>\n}
              . qq{<noscript><iframe frameborder="0" height="300" }
              . qq{src="http://api.recaptcha.net/noscript?error=%3c%3csome+random+error%3e%3e&amp;k=$PUBKEY" }
              . qq{width="500"></iframe><textarea cols="40" name="recaptcha_challenge_field" }
              . qq{rows="3"></textarea><input name="recaptcha_response_field" type="hidden" }
              . qq{value="manual_challenge" /></noscript>}
        },
        {
            name => 'Secure',
            args => [$PUBKEY, undef, 1],
            expect =>
              qq{<script src="https://api-secure.recaptcha.net/challenge?k=$PUBKEY" }
              . qq{type="text/javascript"></script>\n}
              . qq{<noscript><iframe frameborder="0" height="300" }
              . qq{src="https://api-secure.recaptcha.net/noscript?k=$PUBKEY" }
              . qq{width="500"></iframe><textarea cols="40" name="recaptcha_challenge_field" }
              . qq{rows="3"></textarea><input name="recaptcha_response_field" type="hidden" }
              . qq{value="manual_challenge" /></noscript>}
        },
    );
    plan tests => 3 * @schedule;
}

for my $test ( @schedule ) {
    my $name = $test->{name};
    ok my $captcha = Captcha::reCAPTCHA->new(), "$name: Created OK";
    isa_ok $captcha, 'Captcha::reCAPTCHA';
    my $args = $test->{args};
    my $html = $captcha->get_html( @$args );
    is $html, $test->{expect}, "$name: Generate HTML OK";
}
