#!/usr/bin/env perl

use strict;
use warnings;
use CGI qw(param cookie);
use CGI::Session;
use URI::Escape qw(uri_unescape);

use File::Slurp::Tiny qw/read_file/;
use Crypt::OpenSSL::RSA;
use Crypt::CBC;
use MIME::Base64;

use JSON qw/encode_json/;

# for session db
if ( !-e '/tmp/sessions.db' ) {
    system("/usr/bin/touch /tmp/sessions.db");
}

if ( $ENV{REQUEST_METHOD} eq 'GET' and param('getPublicKey')) {
    # download public key file
    my $publickey = read_file('rsa_4096_pub.pem');

    print "Content-Type: text/plain; charset=utf-8\n\n";
    print encode_json({ publickey => $publickey});
}
elsif ( $ENV{REQUEST_METHOD} eq 'POST' and param('handshake')) {
    # handshake
    my $key = param('key');
    $key = decode_base64($key);
    my $privatekey = read_file('rsa_4096_priv.pem');

    Crypt::OpenSSL::RSA->import_random_seed();
    my $rsa_priv = Crypt::OpenSSL::RSA->new_private_key($privatekey);
    $rsa_priv->use_sslv23_padding();    # PKCS #1: RSA Cryptography Specifications v2.0
    $key = $rsa_priv->decrypt($key);


    my $cipher = Crypt::CBC->new(
        -key        => $key,
        -keylength  => '256',
        -cipher     => "Crypt::OpenSSL::AES"
        );

    my $challenge = $cipher->encrypt($key);
    $challenge = encode_base64($challenge);
    $challenge =~ s/\n//g;


    my $session = CGI::Session->new("driver:DB_File", undef, {Directory=>"/tmp/", FileName=> "sessions.db"}) or die CGI::Session->errstr;
    $session->param('key', $key);
    $session->expire('key', '+10s');
    my $session_id = $session->id();

    print "Set-Cookie: JCRYPTIONSESSION=$session_id; path=/;\n";
    print "Content-Type: text/plain; charset=utf-8\n\n";

    print encode_json({ challenge => $challenge });
}
elsif ( $ENV{REQUEST_METHOD} eq 'POST' ) {
    my $session_id = cookie('JCRYPTIONSESSION');
    my $session = CGI::Session->new("driver:DB_File", $session_id, {Directory=>"/tmp/", FileName=> "sessions.db"}) or die CGI::Session->errstr;

    my $key = $session->param('key');
    $session->clear();
    $session->delete();
    $session->flush();

    print "Set-Cookie: JCRYPTIONSESSION=deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT\n";
    print "Content-Type: text/plain; charset=utf-8\n\n";


    my $data = param('jCryption');

    my $cipher = Crypt::CBC->new(
        -key        => $key,
        -keylength  => '256',
        -cipher     => "Crypt::OpenSSL::AES"
        );

    $data = decode_base64($data);
    $data = $cipher->decrypt($data);

    my %param;
    for my $pair ( split(/&/, $data) ) {
        my ($name, $value) = split(/=/, $pair);
        $param{$name} = uri_unescape($value);
    }

    for (keys %param) {
        print "$_ : $param{$_}\n";
    }
}

1;
