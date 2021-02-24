-module(tk_tests_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include_lib("jose/include/jose_jwk.hrl").

-include_lib("token_keeper_proto/include/tk_token_keeper_thrift.hrl").
-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").

-include_lib("bouncer_proto/include/bouncer_context_v1_thrift.hrl").

-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).
-export([init_per_testcase/2]).
-export([end_per_testcase/2]).

-export([detect_api_key_test/1]).
-export([detect_user_session_token_test/1]).
-export([detect_dummy_token_test/1]).
-export([no_token_claim_test/1]).
-export([bouncer_context_from_claims_test/1]).

-type config() :: ct_helper:config().
-type group_name() :: atom().
-type test_case_name() :: atom().

-define(CONFIG(Key, C), (element(2, lists:keyfind(Key, 1, C)))).

-define(TK_AUTHORITY_TOKEN_KEEPER, <<"com.rbkmoney.token-keeper">>).
-define(TK_AUTHORITY_KEYCLOAK, <<"com.rbkmoney.keycloak">>).

-define(PARTY_METADATA(Authority, SubjectID), #{Authority := #{<<"party_id">> := SubjectID}}).

-define(TOKEN_SOURCE_CONTEXT(), ?TOKEN_SOURCE_CONTEXT(<<"http://spanish.inquisition">>)).
-define(TOKEN_SOURCE_CONTEXT(SourceURL), #token_keeper_TokenSourceContext{request_origin = SourceURL}).

-define(USER_TOKEN_SOURCE, <<"https://dashboard.rbk.money">>).

-define(CTX_ENTITY(ID), #bctx_v1_Entity{id = ID}).

%%

-spec all() -> [atom()].

all() ->
    [
        {group, detect_token_type},
        {group, claim_only}
    ].

-spec groups() -> [{group_name(), list(), [test_case_name()]}].
groups() ->
    [
        {detect_token_type, [parallel], [
            detect_api_key_test,
            detect_user_session_token_test,
            detect_dummy_token_test
        ]},
        {claim_only, [parallel], [
            no_token_claim_test,
            bouncer_context_from_claims_test
        ]}
    ].

-spec init_per_suite(config()) -> config().

init_per_suite(C) ->
    Apps =
        genlib_app:start_application(woody) ++
            genlib_app:start_application_with(scoper, [
                {storage, scoper_storage_logger}
            ]),
    [{suite_apps, Apps} | C].

-spec end_per_suite(config()) -> ok.
end_per_suite(C) ->
    genlib_app:stop_unload_applications(?CONFIG(suite_apps, C)).

-spec init_per_group(group_name(), config()) -> config().
init_per_group(detect_token_type = Name, C) ->
    start_keeper([
        {tokens, #{
            jwt => #{
                keyset => #{
                    test => #{
                        source => {pem_file, get_keysource("keys/local/private.pem", C)},
                        metadata => #{
                            type => keycloak
                        }
                    }
                }
            }
        }},
        {authdata_sources, #{
            keycloak => [
                storage,
                {extract, #{
                    methods => [
                        claim,
                        {detect_token, #{
                            user_session_token_origins => [?USER_TOKEN_SOURCE],
                            user_realm => <<"external">>,
                            metadata_ns => ?TK_AUTHORITY_TOKEN_KEEPER
                        }}
                    ],
                    authority => ?TK_AUTHORITY_KEYCLOAK
                }}
            ]
        }}
    ]) ++
        [{groupname, Name} | C];
init_per_group(claim_only = Name, C) ->
    start_keeper([
        {tokens, #{
            jwt => #{
                keyset => #{
                    test => #{
                        source => {pem_file, get_keysource("keys/local/private.pem", C)},
                        metadata => #{
                            type => claim_only
                        }
                    }
                }
            }
        }},
        {authdata_sources, #{
            claim_only => [
                {extract, #{
                    methods => [claim],
                    authority => ?TK_AUTHORITY_KEYCLOAK
                }}
            ]
        }}
    ]) ++
        [{groupname, Name} | C];
init_per_group(Name, C) ->
    [{groupname, Name} | C].

-spec end_per_group(group_name(), config()) -> _.
end_per_group(GroupName, C) when
    GroupName =:= detect_token_type;
    GroupName =:= no_token_metadata
->
    ok = stop_keeper(C),
    ok;
end_per_group(_Name, _C) ->
    ok.

-spec init_per_testcase(atom(), config()) -> config().

init_per_testcase(Name, C) ->
    [{testcase, Name} | C].

-spec end_per_testcase(atom(), config()) -> config().

end_per_testcase(_Name, _C) ->
    ok.

start_keeper(Env) ->
    IP = "127.0.0.1",
    Port = 8022,
    Path = <<"/v1/token-keeper">>,
    Apps = genlib_app:start_application_with(
        token_keeper,
        [
            {ip, IP},
            {port, Port},
            {services, #{
                token_keeper => #{
                    path => Path
                }
            }}
        ] ++ Env
    ),
    Services = #{
        token_keeper => mk_url(IP, Port, Path)
    },
    [{group_apps, Apps}, {service_urls, Services}].

mk_url(IP, Port, Path) ->
    iolist_to_binary(["http://", IP, ":", genlib:to_binary(Port), Path]).

stop_keeper(C) ->
    genlib_app:stop_unload_applications(?CONFIG(group_apps, C)).

%%

-spec detect_api_key_test(config()) -> ok.
detect_api_key_test(C) ->
    Client = mk_client(C),
    JTI = unique_id(),
    SubjectID = <<"TEST">>,
    {ok, Token} = issue_token(JTI, #{<<"sub">> => SubjectID}, unlimited),
    AuthData = call_get_by_token(Token, ?TOKEN_SOURCE_CONTEXT(), Client),
    ?assertEqual(undefined, AuthData#token_keeper_AuthData.id),
    ?assertEqual(Token, AuthData#token_keeper_AuthData.token),
    ?assertEqual(active, AuthData#token_keeper_AuthData.status),
    ?assert(assert_context({api_key_token, JTI, SubjectID}, AuthData#token_keeper_AuthData.context)),
    ?assertMatch(?PARTY_METADATA(?TK_AUTHORITY_TOKEN_KEEPER, SubjectID), AuthData#token_keeper_AuthData.metadata),
    ?assertEqual(?TK_AUTHORITY_KEYCLOAK, AuthData#token_keeper_AuthData.authority).

-spec detect_user_session_token_test(config()) -> ok.
detect_user_session_token_test(C) ->
    Client = mk_client(C),
    JTI = unique_id(),
    SubjectID = <<"TEST">>,
    SubjectEmail = <<"test@test.test">>,
    {ok, Token} = issue_token(JTI, #{<<"sub">> => SubjectID, <<"email">> => SubjectEmail}, unlimited),
    AuthData = call_get_by_token(Token, ?TOKEN_SOURCE_CONTEXT(?USER_TOKEN_SOURCE), Client),
    ?assertEqual(undefined, AuthData#token_keeper_AuthData.id),
    ?assertEqual(Token, AuthData#token_keeper_AuthData.token),
    ?assertEqual(active, AuthData#token_keeper_AuthData.status),
    ?assert(
        assert_context(
            {user_session_token, JTI, SubjectID, SubjectEmail, unlimited},
            AuthData#token_keeper_AuthData.context
        )
    ),
    ?assertMatch(#{}, AuthData#token_keeper_AuthData.metadata),
    ?assertEqual(?TK_AUTHORITY_KEYCLOAK, AuthData#token_keeper_AuthData.authority).

-spec detect_dummy_token_test(config()) -> ok.
detect_dummy_token_test(C) ->
    Client = mk_client(C),
    {ok, Token} = issue_dummy_token(C),
    #token_keeper_InvalidToken{} =
        (catch call_get_by_token(Token, ?TOKEN_SOURCE_CONTEXT(), Client)).

-spec no_token_claim_test(config()) -> ok.
no_token_claim_test(C) ->
    Client = mk_client(C),
    JTI = unique_id(),
    SubjectID = <<"TEST">>,
    {ok, Token} = issue_token(JTI, #{<<"sub">> => SubjectID}, unlimited),
    #token_keeper_AuthDataNotFound{} =
        (catch call_get_by_token(Token, ?TOKEN_SOURCE_CONTEXT(), Client)).

-spec bouncer_context_from_claims_test(config()) -> ok.
bouncer_context_from_claims_test(C) ->
    Client = mk_client(C),
    JTI = unique_id(),
    SubjectID = <<"TEST">>,
    {ok, Token} = issue_token_with_context(JTI, SubjectID),
    AuthData = call_get_by_token(Token, ?TOKEN_SOURCE_CONTEXT(), Client),
    ?assertEqual(undefined, AuthData#token_keeper_AuthData.id),
    ?assertEqual(Token, AuthData#token_keeper_AuthData.token),
    ?assertEqual(active, AuthData#token_keeper_AuthData.status),
    ?assert(assert_context({claim_token, JTI}, AuthData#token_keeper_AuthData.context)),
    ?assertMatch(#{}, AuthData#token_keeper_AuthData.metadata),
    ?assertEqual(?TK_AUTHORITY_KEYCLOAK, AuthData#token_keeper_AuthData.authority).

%%

mk_client(C) ->
    WoodyCtx = woody_context:new(genlib:to_binary(?CONFIG(testcase, C))),
    ServiceURLs = ?CONFIG(service_urls, C),
    {WoodyCtx, ServiceURLs}.

call_get_by_token(Token, TokenSourceContext, Client) ->
    call_token_keeper('GetByToken', {Token, TokenSourceContext}, Client).

call_token_keeper(Operation, Args, Client) ->
    call(token_keeper, Operation, Args, Client).

call(ServiceName, Fn, Args, {WoodyCtx, ServiceURLs}) ->
    Service = get_service_spec(ServiceName),
    Opts = #{
        url => maps:get(ServiceName, ServiceURLs),
        event_handler => scoper_woody_event_handler
    },
    case woody_client:call({Service, Fn, Args}, Opts, WoodyCtx) of
        {ok, Response} ->
            Response;
        {exception, Exception} ->
            throw(Exception)
    end.

get_service_spec(token_keeper) ->
    {tk_token_keeper_thrift, 'TokenKeeper'}.

%%

assert_context(TokenInfo, EncodedContextFragment) ->
    #bctx_v1_ContextFragment{auth = Auth, user = User} = decode_bouncer_fragment(EncodedContextFragment),
    ?assert(assert_auth(TokenInfo, Auth)),
    ?assert(assert_user(TokenInfo, User)),
    true.

assert_auth({claim_token, JTI}, Auth) ->
    ?assertEqual(<<"ClaimToken">>, Auth#bctx_v1_Auth.method),
    ?assertMatch(#bctx_v1_Token{id = JTI}, Auth#bctx_v1_Auth.token),
    true;
assert_auth({api_key_token, JTI, SubjectID}, Auth) ->
    ?assertEqual(<<"ApiKeyToken">>, Auth#bctx_v1_Auth.method),
    ?assertMatch(#bctx_v1_Token{id = JTI}, Auth#bctx_v1_Auth.token),
    ?assertMatch([#bctx_v1_AuthScope{party = ?CTX_ENTITY(SubjectID)}], Auth#bctx_v1_Auth.scope),
    true;
assert_auth({user_session_token, JTI, _SubjectID, _SubjectEmail, Exp}, Auth) ->
    ?assertEqual(<<"SessionToken">>, Auth#bctx_v1_Auth.method),
    ?assertMatch(#bctx_v1_Token{id = JTI}, Auth#bctx_v1_Auth.token),
    ?assertEqual(make_auth_expiration(Exp), Auth#bctx_v1_Auth.expiration),
    true.

assert_user({claim_token, _}, undefined) ->
    true;
assert_user({api_key_token, _, _}, undefined) ->
    true;
assert_user({user_session_token, _JTI, SubjectID, SubjectEmail, _Exp}, User) ->
    ?assertEqual(SubjectID, User#bctx_v1_User.id),
    ?assertEqual(SubjectEmail, User#bctx_v1_User.email),
    ?assertEqual(?CTX_ENTITY(<<"external">>), User#bctx_v1_User.realm),
    true.

%%

make_auth_expiration(Timestamp) when is_integer(Timestamp) ->
    genlib_rfc3339:format(Timestamp, second);
make_auth_expiration(unlimited) ->
    undefined.

%%

issue_token(JTI, Claims0, Expiration) ->
    Claims = tk_token_jwt:create_claims(Claims0, Expiration),
    tk_token_jwt:issue(JTI, Claims, test).

issue_token_with_context(JTI, SubjectID) ->
    Acc0 = bouncer_context_helpers:empty(),
    Acc1 = bouncer_context_helpers:add_auth(
        #{
            method => <<"ClaimToken">>,
            token => #{id => JTI}
        },
        Acc0
    ),
    FragmentContent = encode_context_fragment_content(Acc1),
    issue_token(
        JTI,
        #{
            <<"sub">> => SubjectID,
            <<"bouncer_ctx">> => #{
                <<"ty">> => <<"v1_thrift_binary">>,
                <<"ct">> => base64:encode(FragmentContent)
            }
        },
        unlimited
    ).

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

decode_bouncer_fragment(#bctx_ContextFragment{type = v1_thrift_binary, content = Content}) ->
    Type = {struct, struct, {bouncer_context_v1_thrift, 'ContextFragment'}},
    Codec = thrift_strict_binary_codec:new(Content),
    {ok, Fragment, _} = thrift_strict_binary_codec:read(Codec, Type),
    Fragment.

encode_context_fragment_content(ContextFragment) ->
    Type = {struct, struct, {bouncer_context_v1_thrift, 'ContextFragment'}},
    Codec = thrift_strict_binary_codec:new(),
    case thrift_strict_binary_codec:write(Codec, Type, ContextFragment) of
        {ok, Codec1} ->
            thrift_strict_binary_codec:close(Codec1)
    end.
