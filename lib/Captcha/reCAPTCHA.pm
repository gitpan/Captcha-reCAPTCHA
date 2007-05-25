package Captcha::reCAPTCHA;

use warnings;
use strict;
use Carp;
use LWP::UserAgent;

use version; our $VERSION = qv( '0.2' );

use constant API_SERVER        => 'http://api.recaptcha.net';
use constant API_SECURE_SERVER => 'https://api-secure.recaptcha.net';
use constant API_VERIFY_SERVER => 'http://api-verify.recaptcha.net';

sub new {
    my $class = shift;
    my $self = bless {}, $class;
    $self->_initialize( @_ );
    return $self;
}

sub _initialize {
    my $self = shift;
    my $args = shift || {};

    croak "new must be called with a reference to a hash of parameters"
      unless 'HASH' eq ref $args;

    $self->{ua} = LWP::UserAgent->new();
}

sub _encode_url {
    my $str = shift;
    $str =~ s/([^A-Za-z0-9_])/$1 eq ' ' ? '+' : sprintf("%%%02x", ord($1))/eg;
    return $str;
}

sub _encode_query {
    my $hash = shift || {};
    return join '&',
      map { _encode_url( $_ ) . '=' . _encode_url( $hash->{$_} ) }
      sort keys %$hash;
}

sub _encode_entity {
    my $str     = shift;
    my %ent_map = (
        '&' => '&amp;',
        '<' => '&lt;',
        '>' => '&gt;',
        '"' => '&quot;',
        "'" => '&apos;'
    );
    $str =~ s/([&<>'"])/$ent_map{$1}/eg;
    return $str;
}

sub _open_tag {
    my $name   = shift;
    my $attr   = shift || {};
    my $closed = shift;

    return "<$name"
      . join( '',
        map { ' ' . $_ . '="' . _encode_entity( $attr->{$_} ) . '"' }
          sort keys %$attr )
      . ( $closed ? ' />' : '>' );
}

sub _close_tag {
    my $name = shift;
    return "</$name>";
}

sub get_html {
    my $self = shift;
    my ( $pubkey, $error, $use_ssl ) = @_;

    croak "To use reCAPTCHA you must get an API key from "
      . "<a href='http:/ / recaptcha
      . net / api / getkey '>http://recaptcha.net/api/getkey</a>"
      unless $pubkey;

    my $server = $use_ssl ? API_SECURE_SERVER : API_SERVER;

    my $query = { k => $pubkey };
    $query->{error} = $error if $error;
    my $qs = _encode_query( $query );

    return join(
        '',
        _open_tag(
            'script',
            {
                type => 'text/javascript',
                src  => "$server/challenge?$qs"
            }
        ),
        _close_tag( 'script' ),
        "\n",
        _open_tag( 'noscript' ),
        _open_tag(
            'iframe',
            {
                src         => "$server/noscript?$qs",
                height      => 300,
                width       => 500,
                frameborder => 0
            }
        ),
        _close_tag( 'iframe' ),
        _open_tag(
            'textarea',
            { name => 'recaptcha_challenge_field', rows => 3, cols => 40 }
        ),
        _close_tag( 'textarea' ),
        _open_tag(
            'input',
            {
                type  => 'hidden',
                name  => 'recaptcha_response_field',
                value => 'manual_challenge'
            },
            1
        ),
        _close_tag( 'noscript' )
    );
}

sub _post_request {
    my $self = shift;
    my $url  = shift;
    my $args = shift;

    return $self->{ua}->post( $url, $args );
}

sub check_answer {
    my $self = shift;
    my ( $privkey, $remoteip, $challenge, $response ) = @_;

    croak
      "To use reCAPTCHA you must get an API key from <a href='http://recaptcha.net/api/getkey'>http://recaptcha.net/api/getkey</a>"
      unless $privkey;

    croak "For security reasons, you must pass the remote ip to reCAPTCHA"
      unless $remoteip;

    return { is_valid => 0, error => 'incorrect-challenge-sol' }
      unless $challenge && $response;

    my $resp = $self->_post_request(
        API_VERIFY_SERVER . '/verify',
        {
            privatekey => $privkey,
            remoteip   => $remoteip,
            challenge  => $challenge,
            response   => $response
        }
    );

    if ( $resp->is_success ) {
        my ( $answer, $message ) = split( /\n/, $resp->content, 2 );
        if ( $answer =~ /true/ ) {
            return { is_valid => 1 };
        }
        else {
            return { is_valid => 0, error => $message };
        }
    }
    else {
        return { is_valid => 0, error => 'server-error' };
    }
}

1;
__END__

=head1 NAME

Captcha::reCAPTCHA - A Perl implentation of the reCAPTCHA API

=head1 VERSION

This document describes Captcha::reCAPTCHA version 0.2

=head1 SYNOPSIS

    use Captcha::reCAPTCHA;

    my $c = Captcha::reCAPTCHA->new;

    # Output form
    print $c->get_html( 'your public key here' );

    # Verify submission
    my $result = $c->check_answer(
        'your private key here', $ENV{'REMOTE_ADDR'},
        $challenge, $response
    );

    if ( $result->{is_valid} ) {
        print "Yes!";
    }
    else {
        # Error
        $error = $result->{error};
    }

For complete examples see the /examples subdirectory
    
=head1 DESCRIPTION

reCAPTCHA is a hybrid mechanical turk and captcha that allows visitors
who complete the captcha to assist in the digitization of books.

From L<http://recaptcha.net/learnmore.html>:

    reCAPTCHA improves the process of digitizing books by sending words that
    cannot be read by computers to the Web in the form of CAPTCHAs for
    humans to decipher. More specifically, each word that cannot be read
    correctly by OCR is placed on an image and used as a CAPTCHA. This is
    possible because most OCR programs alert you when a word cannot be read
    correctly.

This is a Perl implementation of the PHP interface that can be found here:

L<http://recaptcha.net/plugins/php/>

=head1 INTERFACE 

=over

=item C<< new >>

Create a new C<< Captcha::reCAPTCHA >>.

=item C<< get_html( $pubkey, $error, $use_ssl ) >>

Generates HTML to display the captcha.

=over

=item C<< $pubkey >>

Your reCAPTCHA public key, from the API Signup Page

=item C<< $use_ssl >>

Should the SSL-based API be used? If you are displaying a page to the
user over SSL, be sure to set this to true so an error dialog doesn't
come up in the user's browser.

=item C<< $error >>

If this string is set, the reCAPTCHA area will display the error code
given. This error code comes from $response->{error}.

=back

Returns a string containing the HTML that should be used to display
the captcha.

=item C<< check_answer >>

After the user has filled out the HTML form, including their answer for
the CAPTCHA, use C<< check_answer >> to check their answer when they
submit the form. The user's answer will be in two form fields,
recaptcha_challenge_field and recaptcha_response_field. The reCAPTCHA
library will make an HTTP request to the reCAPTCHA server and verify the
user's answer.

=over

=item C<< $privkey >>

Your reCAPTCHA private key, from the API Signup Page.

=item C<< $remoteip >>

The user's IP address, in the format 192.168.0.1.

=item C<< $challenge >>

The value of the form field recaptcha_challenge_field

=item C<< $response >>

The value of the form field recaptcha_response_field.

=back

Returns a reference to a hash containing two fields: C<is_valid>
and C<error>.

    my $result = $c->check_answer(
        'your private key here', $ENV{'REMOTE_ADDR'},
        $challenge, $response
    );

    if ( $result->{is_valid} ) {
        print "Yes!";
    }
    else {
        # Error
        $error = $result->{error};
    }

See the /examples subdirectory for examples of how to call C<check_answer>.

=back

=head1 CONFIGURATION AND ENVIRONMENT

Captcha::reCAPTCHA requires no configuration files or environment
variables.

=head1 DEPENDENCIES

LWP::UserAgent

=head1 INCOMPATIBILITIES

None reported .

=head1 BUGS AND LIMITATIONS

Doesn't currently implement Mailhide support.

No bugs have been reported.

Please report any bugs or feature requests to
C<bug-captcha-recaptcha@rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org>.

=head1 AUTHOR

Andy Armstrong  C<< <andy@hexten.net> >>

=head1 LICENCE AND COPYRIGHT

Copyright (c) 2007, Andy Armstrong C<< <andy@hexten.net> >>. All rights reserved.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself. See L<perlartistic>.

=head1 DISCLAIMER OF WARRANTY

BECAUSE THIS SOFTWARE IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
FOR THE SOFTWARE, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN
OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
PROVIDE THE SOFTWARE "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE
ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE SOFTWARE IS WITH
YOU. SHOULD THE SOFTWARE PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL
NECESSARY SERVICING, REPAIR, OR CORRECTION.

IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
REDISTRIBUTE THE SOFTWARE AS PERMITTED BY THE ABOVE LICENCE, BE
LIABLE TO YOU FOR DAMAGES, INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL,
OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR INABILITY TO USE
THE SOFTWARE (INCLUDING BUT NOT LIMITED TO LOSS OF DATA OR DATA BEING
RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR A
FAILURE OF THE SOFTWARE TO OPERATE WITH ANY OTHER SOFTWARE), EVEN IF
SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF
SUCH DAMAGES.
