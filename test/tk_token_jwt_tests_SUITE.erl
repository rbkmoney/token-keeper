-module(tk_token_jwt_tests_SUITE).

-include_lib("stdlib/include/assert.hrl").
-include_lib("common_test/include/ct.hrl").
-include_lib("jose/include/jose_jwk.hrl").

-export([all/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).

-export([
    verify_test/1,
    bad_token_test/1,
    bad_signee_test/1
]).

-type test_case_name() :: atom().
-type config() :: [{atom(), any()}].

-spec all() -> [test_case_name()].
all() ->
    [
        verify_test,
        bad_token_test,
        bad_signee_test
    ].

-spec init_per_suite(config()) -> config().
init_per_suite(Config) ->
    Apps =
        genlib_app:start_application(woody) ++
            genlib_app:start_application_with(scoper, [
                {storage, scoper_storage_logger}
            ]) ++
            genlib_app:start_application_with(
                token_keeper,
                [
                    {ip, "127.0.0.1"},
                    {port, 8022},
                    {services, #{
                        token_keeper => #{
                            path => <<"/v1/token-keeper">>
                        }
                    }},
                    {jwt, #{
                        keyset => #{
                            test => #{
                                source => {pem_file, get_keysource("keys/local/private.pem", Config)},
                                authority => test
                            }
                        }
                    }}
                ]
            ),
    [{apps, Apps}] ++ Config.

-spec end_per_suite(config()) -> _.
end_per_suite(Config) ->
    Config.

%%

-spec verify_test(config()) -> _.
verify_test(_) ->
    JTI = unique_id(),
    PartyID = <<"TEST">>,
    {ok, Token} = issue_token(JTI, #{<<"sub">> => PartyID, <<"TEST">> => <<"TEST">>}, unlimited),
    {ok, {#{<<"jti">> := JTI, <<"sub">> := PartyID, <<"TEST">> := <<"TEST">>}, test, #{}}} = tk_token_jwt:verify(
        Token,
        #{}
    ).

-spec bad_token_test(config()) -> _.
bad_token_test(Config) ->
    {ok, Token} = issue_dummy_token(Config),
    {error, invalid_signature} = tk_token_jwt:verify(Token, #{}).

-spec bad_signee_test(config()) -> _.
bad_signee_test(_) ->
    Claims = tk_token_jwt:create_claims(#{}, unlimited),
    {error, nonexistent_key} =
        tk_token_jwt:issue(unique_id(), Claims, random).

%%

issue_token(JTI, Claims0, Expiration) ->
    Claims1 = tk_token_jwt:create_claims(Claims0, Expiration),
    tk_token_jwt:issue(JTI, Claims1, test).

issue_dummy_token(Config) ->
    Claims = #{
        <<"jti">> => unique_id(),
        <<"sub">> => <<"TEST">>,
        <<"exp">> => 0
    },
    BadPemFile = get_keysource("keys/local/dummy.pem", Config),
    BadJWK = jose_jwk:from_pem_file(BadPemFile),
    GoodPemFile = get_keysource("keys/local/private.pem", Config),
    GoodJWK = jose_jwk:from_pem_file(GoodPemFile),
    JWKPublic = jose_jwk:to_public(GoodJWK),
    {_Module, PublicKey} = JWKPublic#jose_jwk.kty,
    {_PemEntry, Data, _} = public_key:pem_entry_encode('SubjectPublicKeyInfo', PublicKey),
    KID = jose_base64url:encode(crypto:hash(sha256, Data)),
    JWT = jose_jwt:sign(BadJWK, #{<<"alg">> => <<"RS256">>, <<"kid">> => KID}, Claims),
    {_Modules, Token} = jose_jws:compact(JWT),
    {ok, Token}.

get_keysource(Key, Config) ->
    filename:join(?config(data_dir, Config), Key).

unique_id() ->
    <<ID:64>> = snowflake:new(),
    genlib_format:format_int_base(ID, 62).
