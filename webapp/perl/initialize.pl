#!/usr/bin/env perl
use strict;
use warnings;
use utf8;

use DBIx::Sunny;
use JSON;
use Furl;
use IO::Socket::SSL qw(SSL_VERIFY_NONE);

use lib './lib';
use Isucon5f::Web;

for my $user_id (1 .. 10000) {
    my $arg_json = Isucon5f::Web::db->select_one("SELECT arg FROM subscriptions WHERE user_id=?", $user_id);
    my $arg = from_json($arg_json);
    for my $key (keys %$arg) {
        my $row = $Isucon5f::Web::endpoints{$key};
        next unless $row->{cache};

        my $conf = $arg->{$key};
        my $method = $row->{meth};
        my $token_type = $row->{token_type};
        my $token_key = $row->{token_key};
        my $uri_template = $row->{uri};
        my $headers = +{};
        my $params = $conf->{params} || +{};

        if ($token_type) {
            if ($token_type eq 'header') {
                $headers->{$token_key} = $conf->{'token'};
            }
            if ($token_type eq 'param') {
                $params->{$token_key} = $conf->{'token'};
            }
        }
        my $uri = sprintf($uri_template, @{$conf->{keys} || []});
        my $key = encode_json([$uri, $params, $headers]);

        {
            my $client = Furl->new(ssl_opts => { SSL_verify_mode => SSL_VERIFY_NONE });
            $client->env_proxy;
            $uri = URI->new($uri);
            $uri->query_form(%$params);
            my $res = $client->request(
                method => $method,
                url => $uri,
                headers => [%$headers],
            );
            if ($res->is_success) {
                Isucon5f::Web::memd->set($key, $res->content);
            }
        }
    }
}
