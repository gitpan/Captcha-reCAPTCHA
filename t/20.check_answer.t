use strict;
use warnings;
use Test::More;
use HTTP::Response;
use Captcha::reCAPTCHA;

my @schedule;
my $PRIVKEY;

BEGIN {

    # Looks real. Isn't.
    $PRIVKEY  = '6LdAAAkAwAAAix_GF6AMQnw5UCG3JjWluQJMNGjY';
    @schedule = (
        {
            name => 'Simple',
            args =>
              [ $PRIVKEY, '192.168.0.1', '..challenge..', '..response..' ],
            check_args => {
                privatekey => $PRIVKEY,
                remoteip   => '192.168.0.1',
                challenge  => '..challenge..',
                response   => '..response..'
            },
            check_url => 'http://api-verify.recaptcha.net/verify'
        },
    );
    plan tests => 6 * @schedule;
}

package T::Captcha::reCAPTCHA;

our @ISA = qw(Captcha::reCAPTCHA);
use Captcha::reCAPTCHA;

sub _post_request {
    my $self = shift;
    my $url  = shift;
    my $args = shift;

    # Just keep the args
    $self->{t_url}  = $url;
    $self->{t_args} = $args;

    return HTTP::Response->new( 200, 'OK', [ 'Content-type:' => 'text/plain' ],
        "true\n" );
}

sub get_url  { shift->{t_url} }
sub get_args { shift->{t_args} }

package main;

for my $test ( @schedule ) {
    my $name = $test->{name};
    ok my $captcha = T::Captcha::reCAPTCHA->new(), "$name: Created OK";
    isa_ok $captcha, 'Captcha::reCAPTCHA';
    ok my $resp = $captcha->check_answer( @{ $test->{args} } ), "$name: got response";
    is $captcha->get_url, $test->{check_url}, "$name: URL OK";
    is_deeply $captcha->get_args, $test->{check_args}, "$name: args OK";
    is_deeply $resp, { is_valid => 1 }, "$name: result OK";
}
