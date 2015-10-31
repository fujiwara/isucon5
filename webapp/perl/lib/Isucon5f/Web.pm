package Isucon5f::Web;

use 5.020;
use strict;
use warnings;
use utf8;
use Kossy;
use Cache::Memcached::Fast;
use DBIx::Sunny;
use JSON;
use Furl;
use URI;
use IO::Socket::SSL qw(SSL_VERIFY_NONE);
use String::Util qw(trim);
use File::Basename qw(dirname);
use File::Spec;

my %endpoints = (
    'ken2' => {
        'uri' => 'http://api.five-final.isucon.net:8080/',
        'service' => 'ken2',
        'token_type' => undef,
        'token_key' => undef,
        'meth' => 'GET',
        'cache' => 1,
    },
    'perfectsec_attacked' => {
        'meth' => 'GET',
        'token_type' => 'header',
        'token_key' => 'X-PERFECT-SECURITY-TOKEN',
        'uri' => 'https://api.five-final.isucon.net:8443/attacked_list',
        'service' => 'perfectsec_attacked',
    },
    'givenname' => {
        'meth' => 'GET',
        'token_type' => undef,
        'token_key' => undef,
        'service' => 'givenname',
        'uri' => 'http://api.five-final.isucon.net:8081/givenname',
        'cache' => 1,
    },
    'tenki' => {
        'service' => 'tenki',
        'uri' => 'http://api.five-final.isucon.net:8988/',
        'meth' => 'GET',
        'token_key' => 'zipcode',
        'token_type' => 'param',
    },
    'surname' => {
        'service' => 'surname',
        'uri' => 'http://api.five-final.isucon.net:8081/surname',
        'meth' => 'GET',
        'token_type' => undef,
        'token_key' => undef,
        'cache' => 1,
    },
    'perfectsec' => {
        'uri' => 'https://api.five-final.isucon.net:8443/tokens',
        'service' => 'perfectsec',
        'token_key' => 'X-PERFECT-SECURITY-TOKEN',
        'token_type' => 'header',
        'meth' => 'GET',
        'cache' => 1,
    },
    'ken' => {
        'meth' => 'GET',
        'token_key' => undef,
        'token_type' => undef,
        'service' => 'ken',
        'uri' => 'http://api.five-final.isucon.net:8080/%s',
        'cache' => 1,
    },
);

sub db {
    state $db ||= do {
        my %db = (
            host => $ENV{ISUCON5_DB_HOST} || 'localhost',
            port => $ENV{ISUCON5_DB_PORT} || 5432,
            username => $ENV{ISUCON5_DB_USER} || 'isucon',
            password => $ENV{ISUCON5_DB_PASSWORD},
            database => $ENV{ISUCON5_DB_NAME} || 'isucon5f',
        );
        DBIx::Sunny->connect(
            "dbi:Pg:dbname=$db{database};host=$db{host};port=$db{port}", $db{username}, $db{password}, {
                RaiseError => 1,
                PrintError => 0,
                AutoInactiveDestroy => 1,
            },
        );
    };
}

sub memd {
    state $memd = Cache::Memcached::Fast->new({ servers => ["127.0.0.1:11211"] });
}

my ($SELF, $C);
sub session : lvalue {
    $C->req->env->{"psgix.session"};
}

sub stash {
    $C->stash;
}

sub authenticate {
    my ($email, $password) = @_;
    my $query = <<SQL;
SELECT id, email, grade FROM users WHERE email=? AND passhash=digest(salt || ?, 'sha512')
SQL
    my $user = db->select_row($query, $email, $password);
    if ($user) {
        session->{user_id} = $user->{id};
    }
    return $user;
}

sub current_user {
    my $user = stash->{user};
    return $user if $user;
    return undef if !session->{user_id};
    $user = db->select_row('SELECT id,email,grade FROM users WHERE id=?', session->{user_id});
    if (!$user) {
        session = +{};
    } else {
        stash->{user} = $user;
    }
    return $user;
}

my @SALT_CHARS = ('a'..'z', 'A'..'Z', '0'..'9');
sub generate_salt {
    my $salt = '';
    $salt .= $SALT_CHARS[int(rand(0+@SALT_CHARS))] for 1..32;
    $salt;
}

filter 'set_global' => sub {
    my ($app) = @_;
    sub {
        my ($self, $c) = @_;
        $SELF = $self;
        $C = $c;
        $app->($self, $c);
    }
};

get '/signup' => [qw(set_global)] => sub {
    my ($self, $c) = @_;
    session = +{};
    $c->render('signup.tx');
};

post '/signup' => [qw(set_global)] => sub {
    my ($self, $c) = @_;
    my $params = $c->req->parameters;
    my $email = $params->{email};
    my $password = $params->{password};
    my $grade = $params->{grade};
    my $salt = generate_salt();
    my $insert_user_query = <<SQL;
INSERT INTO users (email,salt,passhash,grade) VALUES (?,?,digest(? || ?, 'sha512'),?) RETURNING id
SQL
    my $default_arg = +{};
    my $insert_subscription_query = <<SQL;
INSERT INTO subscriptions (user_id,arg) VALUES (?,?)
SQL
    {
        my $txn = db->txn_scope;
        my $user_id = db->select_one($insert_user_query, $email, $salt, $salt, $password, $grade);
        db->query($insert_subscription_query, $user_id, to_json($default_arg));
        $txn->commit;
    }
    $c->redirect('/login');
};

post '/cancel' => [qw(set_global)] => sub {
    my ($self, $c) = @_;
    $c->redirect('/signup');
};

get '/login' => [qw(set_global)] => sub {
    my ($self, $c) = @_;
    session = +{};
    $c->render('login.tx');
};

post '/login' => [qw(set_global)] => sub {
    my ($self, $c) = @_;
    my $email = $c->req->param("email");
    my $password = $c->req->param("password");
    authenticate($email, $password);
    $c->halt(403) if !current_user();
    $c->redirect('/');
};

get '/logout' => [qw(set_global)] => sub {
    my ($self, $c) = @_;
    session = +{};
    $c->redirect('/login');
};

get '/' => [qw(set_global)] => sub {
    my ($self, $c) = @_;

    if (!current_user()) {
        return $c->redirect('/login');
    }
    $c->render('main.tx', { user => current_user() });
};

get '/user.js' => [qw(set_global)] => sub {
    my ($self, $c) = @_;
    $c->halt(403) if !current_user();
    $c->res->header('Content-Type', 'application/javascript');
    $c->render('userjs.tx', { grade => current_user()->{grade} });
};

get '/modify' => [qw(set_global)] => sub {
    my ($self, $c) = @_;
    my $user = current_user();
    $c->halt(403) if !$user;
    my $query = <<SQL;
SELECT arg FROM subscriptions WHERE user_id=?
SQL
    my $arg = db->select_one($query, $user->{id});
    $c->render('modify.tx', { user => $user, arg => $arg });
};

post '/modify' => [qw(set_global)] => sub {
    my ($self, $c) = @_;
    my $user = current_user();
    $c->halt(403) if !$user;
    my $params = $c->req->parameters;
    my $service = $params->{service} ? trim($params->{service}): undef;
    my $token = $params->{token} ? trim($params->{token}) : undef;
    my $keys = $params->{keys} ? [split(/\s+/, trim($params->{keys}))] : undef;
    my $param_name = $params->{param_name} ? trim($params->{param_name}) : undef;
    my $param_value = $params->{param_value} ? trim($params->{param_value}) : undef;
    my $select_query = <<SQL;
SELECT arg FROM subscriptions WHERE user_id=? FOR UPDATE
SQL
    my $update_query = <<SQL;
UPDATE subscriptions SET arg=? WHERE user_id=?
SQL
    {
        my $txn = db->txn_scope;
        my $arg_json = db->select_one($select_query, $user->{id});
        my $arg = from_json($arg_json);
        if (!$arg->{$service}) { $arg->{$service} = +{}; }
        if ($token) { $arg->{$service}{token} = $token; }
        if ($keys) { $arg->{$service}{keys} = $keys; }
        if ($param_name && $param_value) {
            if (!$arg->{$service}{params}) { $arg->{$service}{params} = +{}; }
            $arg->{$service}{params}{$param_name} = $param_value;
        }
        db->query($update_query, to_json($arg), $user->{id});
        $txn->commit;
    }
    $c->redirect('/modify');
};

sub fetch_api {
    my ($method, $uri, $headers, $params) = @_;
    my $client = Furl->new(ssl_opts => { SSL_verify_mode => SSL_VERIFY_NONE });
    $client->env_proxy;
    $uri = URI->new($uri);
    $uri->query_form(%$params);
    my $res = $client->request(
        method => $method,
        url => $uri,
        headers => [%$headers],
    );
    return $res->content;
}

get '/data' => [qw(set_global)] => sub {
    my ($self, $c) = @_;
    my $user = current_user();
    $c->halt(403) if !$user;

    my $arg_json = db->select_one("SELECT arg FROM subscriptions WHERE user_id=?", $user->{id});
    my $arg = from_json($arg_json);

    my $data = [];

    while (my ($service, $conf) = each(%$arg)) {
        my $row = $endpoints{$service};

        my $method = $row->{meth};
        my $token_type = $row->{token_type};
        my $token_key = $row->{token_key};
        my $uri_template = $row->{uri};
        my $headers = +{};
        my $params = $conf->{params} || +{};
        given ($token_type) {
            when ('header') {
                $headers->{$token_key} = $conf->{'token'};
            }
            when ('param') {
                $params->{$token_key} = $conf->{'token'};
            }
        }
        my $uri = sprintf($uri_template, @{$conf->{keys} || []});

        my $d;
        if ($row->{cache}) {
            my $key = encode_json([$uri, $params]);
            $d = memd->get($key);
            unless (defined $d) {
                $d = fetch_api($method, $uri, $headers, $params);
                memd->set($key => $d);
            }
        } else {
            $d = fetch_api($method, $uri, $headers, $params);
        }
        $d = decode_json($d);

        push @$data, { service => $service, data => $d, };
    }

    $c->res->header('Content-Type', 'application/json');
    $c->res->body(encode_json($data));
};

get '/initialize' => sub {
    my ($self, $c) = @_;
    my $file = File::Spec->rel2abs("../../sql/initialize.sql", dirname(dirname(__FILE__)));
    system("psql", "-f", $file, "isucon5f");
    [200];
};

1;
