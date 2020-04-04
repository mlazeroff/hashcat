#! /usr/bin/env perl

##
## Author:  Matthew Lazeroff <mlazeroff>
## License: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use Digest::HMAC;
use Digest::SHA1;
use MIME::Base64 qw (encode_base64 decode_base64);

sub module_constraints { [[0, 256], [0, 256], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
    my $word = shift;
    my $salt = shift;
    my $iter = shift // random_number (100, 10000);

    # PBKDF2-SHA1
    my $kdf = Crypt::PBKDF2->new
    (
        hash_class => "HMACSHA1",
        iterations => $iter,
        output_len => 20
    );

    my $key = $kdf->PBKDF2 ($salt, $word);
    my $key_b64 = encode_base64 ($key, "");
    printf ("PBKDF2: %s\n", $kdf->PBKDF2_hex ($salt, $word));

    # HMAC-SHA1(PBKDF2, "Client Key")
    my $hmac = Digest::HMAC->new
    (
        $key,
        "Digest::SHA1"
    );
    $hmac->add("Client Key");
    my $hmac_key = $hmac->digest;

    $hmac = Digest::HMAC->new
    (
        $key,
        "Digest::SHA1"
    );
    $hmac->add("Client Key");
    printf("HMAC:   %s\n", $hmac->hexdigest);

    # SHA1(HMAC-SHA1(PBDKF2))
    my $sha = Digest::SHA1->new;
    $sha->add($hmac_key);
    my $sha_key = $sha->digest;

    $sha = Digest::SHA1->new;
    $sha->add($hmac_key);
    my $hex_key = $sha->hexdigest;
    printf("SHA1:   %s\n\n", $hex_key);

    $key_b64 = encode_base64($sha_key, "");

    my $salt_b64 = encode_base64($salt, "");

    my $hash = sprintf("%i:%s:%s", $iter, $salt_b64, $key_b64);

    return $hash;
}

sub module_verify_hash
{
    my $line = shift;

    # iterations
    my $index1 = index ($line, ":");

    return if $index1 < 1;

    my $iter = substr($line, 0, $index1);

    # salt
    my $index2 = index ($line, ":", $index1 + 1);
    return if $index2 < 1;

    my $salt = substr ($line, $index1 + 1, $index2 - $index1 - 1);
    
    $salt = decode_base64 ($salt);

    # digest
    $index1 = index ($line, ":", $index2 + 1);
    return if $index1 < 1;

    # word
    my $word = substr ($line, $index1 + 1);

    my $word_packed = pack_if_HEX_notation ($word);

    my $new_hash = module_generate_hash ($word_packed, $salt, $iter);

    return ($new_hash, $word);

}

1;
