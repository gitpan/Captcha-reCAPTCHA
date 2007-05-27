use strict;
use warnings;
use Test::More;
use Captcha::reCAPTCHA;

use constant PUBKEY     => '6LdAAAkAwAAAFJj6ACG3Wlix_GuQJMNGjMQnw5UY';
use constant PRIVKEY    => '6LdAAAkAwAAAix_GF6AMQnw5UCG3JjWluQJMNGjY';
use constant MH_PUBKEY  => 'UcV0oq5XNVM01AyYmMNRqvRA==';
use constant MH_PRIVKEY => 'E542D5DB870FF2D2B9D01070FF04F0C8';

my @schedule;

BEGIN {
    @schedule = (
        {
            name => 'new: Bad args',
            try  => sub {
                my $c = Captcha::reCAPTCHA->new( PUBKEY );
            },
            expect => qr/reference to a hash/
        },
        {
            name => 'get_html: No args',
            try  => sub {
                my $c = shift;
                $c->get_html();
            },
            expect => qr/To use reCAPTCHA you must get an API key from/
        },
        {
            name => 'get_html: No key',
            try  => sub {
                my $c = shift;
                $c->get_html( '' );
            },
            expect => qr/To use reCAPTCHA you must get an API key from/
        },
        {
            name => 'get_html: Garbage key',
            try  => sub {
                my $c = shift;
                $c->get_html( 'splibble' );
            },
            expect =>
              qr/Expected a reCAPCTHA key. The supplied key should match/
        },
        {
            name => 'get_html: MH_PUBKEY',
            try  => sub {
                my $c = shift;
                $c->get_html( MH_PUBKEY );
            },
            expect =>
              qr/Expected a reCAPCTHA key. The supplied key looks like a Mailhide public key/
        },
        {
            name => 'get_html: MH_PRIVKEY',
            try  => sub {
                my $c = shift;
                $c->get_html( MH_PRIVKEY );
            },
            expect =>
              qr/Expected a reCAPCTHA key. The supplied key looks like a Mailhide private key/
        },
        {
            name => 'check_answer: No args',
            try  => sub {
                my $c = shift;
                $c->check_answer();
            },
            expect => qr/To use reCAPTCHA you must get an API key from/
        },
        {
            name => 'check_answer: MH_PUBKEY',
            try  => sub {
                my $c = shift;
                $c->check_answer( MH_PUBKEY );
            },
            expect =>
              qr/Expected a reCAPCTHA key. The supplied key looks like a Mailhide public key/
        },
        {
            name => 'check_answer: MH_PRIVKEY',
            try  => sub {
                my $c = shift;
                $c->check_answer( MH_PRIVKEY );
            },
            expect =>
              qr/Expected a reCAPCTHA key. The supplied key looks like a Mailhide private key/
        },
        {
            name => 'check_answer: no ip',
            try  => sub {
                my $c = shift;
                $c->check_answer( PRIVKEY );
            },
            expect => qr/you must pass the remote ip/
        },
        {
            name => 'mailhide_html: No args',
            try  => sub {
                my $c = shift;
                $c->mailhide_html();
            },
            expect => qr/you have to sign up for a public and private key/
        },
        {
            name => 'mailhide_html: Main keys',
            try  => sub {
                my $c = shift;
                $c->mailhide_html( PUBKEY, MH_PRIVKEY, 'someone@example.com' );
            },
            expect =>
              qr/Expected a Mailhide public key. The supplied key looks like a reCAPCTHA key/
        },
        {
            name => 'mailhide_html: Main keys 2',
            try  => sub {
                my $c = shift;
                $c->mailhide_html( MH_PUBKEY, PRIVKEY, 'someone@example.com' );
            },
            expect =>
              qr/Expected a Mailhide private key. The supplied key looks like a reCAPCTHA key/
        },
        {
            name => 'mailhide_html: No email',
            try  => sub {
                my $c = shift;
                $c->mailhide_html( MH_PUBKEY, MH_PRIVKEY );
            },
            expect => qr/You must supply an email address/
        },
    );

    plan tests => 3 * @schedule;
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
    ok my $captcha = T::Captcha::reCAPTCHA->new, "$name: create OK";
    isa_ok $captcha, 'Captcha::reCAPTCHA';
    eval { $test->{try}->( $captcha ); };
    if ( my $expect = $test->{expect} ) {
        like $@, $expect, "$name: error OK";
    }
    else {
        ok !$@, "$name: no error OK";
    }
}
