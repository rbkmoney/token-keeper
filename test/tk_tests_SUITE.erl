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
-export([cons_claim_passthrough_test/1]).
-export([invoice_template_access_token_ok_test/1]).
-export([invoice_template_access_token_no_access_test/1]).
-export([invoice_template_access_token_invalid_access_test/1]).
-export([basic_issuing_test/1]).
-export([jti_and_authority_blacklist_test/1]).

-type config() :: ct_helper:config().
-type group_name() :: atom().
-type test_case_name() :: atom().

-define(CONFIG(Key, C), (element(2, lists:keyfind(Key, 1, C)))).

-define(TK_META_NS_KEYCLOAK, <<"test.rbkmoney.token-keeper">>).
-define(TK_META_NS_APIKEYMGMT, <<"test.rbkmoney.apikeymgmt">>).

-define(TK_AUTHORITY_KEYCLOAK, <<"test.rbkmoney.keycloak">>).
-define(TK_AUTHORITY_CAPI, <<"test.rbkmoney.capi">>).

-define(TK_RESOURCE_DOMAIN, <<"test-domain">>).

-define(METADATA(Authority, Metadata), #{Authority := Metadata}).
-define(PARTY_METADATA(Authority, SubjectID), ?METADATA(Authority, #{<<"party_id">> := SubjectID})).
-define(USER_METADATA(Authority, SubjectID, Email),
    ?METADATA(Authority, #{<<"user_id">> := SubjectID, <<"user_email">> := Email})
).

-define(TOKEN_SOURCE_CONTEXT(), ?TOKEN_SOURCE_CONTEXT(<<"http://spanish.inquisition">>)).
-define(TOKEN_SOURCE_CONTEXT(SourceURL), #token_keeper_TokenSourceContext{request_origin = SourceURL}).

-define(USER_TOKEN_SOURCE, <<"https://dashboard.rbk.money">>).

-define(CTX_ENTITY(ID), #bctx_v1_Entity{id = ID}).

%%

-spec all() -> [atom()].

all() ->
    [
        {group, detect_token_type},
        {group, claim_only},
        {group, invoice_template_access_token},
        {group, issuing},
        {group, blacklist}
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
            bouncer_context_from_claims_test,
            cons_claim_passthrough_test
        ]},
        {invoice_template_access_token, [parallel], [
            invoice_template_access_token_ok_test,
            invoice_template_access_token_no_access_test,
            invoice_template_access_token_invalid_access_test
        ]},
        {issuing, [parallel], [
            basic_issuing_test
        ]},
        {blacklist, [parallel], [
            jti_and_authority_blacklist_test
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
        {jwt, #{
            keyset => #{
                test => #{
                    source => {pem_file, get_filename("keys/local/private.pem", C)},
                    authority => keycloak
                }
            }
        }},
        {authorities, #{
            keycloak => #{
                id => ?TK_AUTHORITY_KEYCLOAK,
                authdata_sources => [
                    {extract, #{
                        methods => [
                            {detect_token, #{
                                phony_api_key_opts => #{
                                    metadata_ns => ?TK_META_NS_APIKEYMGMT
                                },
                                user_session_token_opts => #{
                                    user_realm => <<"external">>,
                                    metadata_ns => ?TK_META_NS_KEYCLOAK
                                },
                                user_session_token_origins => [?USER_TOKEN_SOURCE]
                            }}
                        ]
                    }}
                ]
            }
        }}
    ]) ++
        [{groupname, Name} | C];
init_per_group(claim_only = Name, C) ->
    start_keeper([
        {jwt, #{
            keyset => #{
                test => #{
                    source => {pem_file, get_filename("keys/local/private.pem", C)},
                    authority => claim_only
                }
            }
        }},
        {authorities, #{
            claim_only => #{
                id => ?TK_AUTHORITY_CAPI,
                authdata_sources => [
                    {storage,
                        {claim, #{
                            compatability => {true, ?TK_META_NS_APIKEYMGMT}
                        }}}
                ]
            }
        }}
    ]) ++
        [{groupname, Name} | C];
init_per_group(invoice_template_access_token = Name, C) ->
    start_keeper([
        {jwt, #{
            keyset => #{
                test => #{
                    source => {pem_file, get_filename("keys/local/private.pem", C)},
                    authority => invoice_tpl_authority
                }
            }
        }},
        {authorities, #{
            invoice_tpl_authority => #{
                id => ?TK_AUTHORITY_CAPI,
                authdata_sources => [
                    {storage,
                        {claim, #{
                            compatability => {true, ?TK_META_NS_APIKEYMGMT}
                        }}},
                    {extract, #{
                        methods => [
                            {invoice_template_access_token, #{
                                domain => ?TK_RESOURCE_DOMAIN,
                                metadata_ns => ?TK_META_NS_APIKEYMGMT
                            }}
                        ]
                    }}
                ]
            }
        }}
    ]) ++
        [{groupname, Name} | C];
init_per_group(issuing = Name, C) ->
    start_keeper([
        {jwt, #{
            keyset => #{
                test => #{
                    source => {pem_file, get_filename("keys/local/private.pem", C)},
                    authority => issuing_authority
                }
            }
        }},
        {issuing, #{
            authority => issuing_authority
        }},
        {authorities, #{
            issuing_authority => #{
                id => ?TK_AUTHORITY_CAPI,
                signer => test,
                authdata_sources => [
                    {storage, claim}
                ]
            }
        }}
    ]) ++
        [{groupname, Name} | C];
init_per_group(blacklist = Name, C) ->
    start_keeper([
        {jwt, #{
            keyset => #{
                primary => #{
                    source => {pem_file, get_filename("keys/local/private.pem", C)},
                    authority => blacklisting_authority
                },
                secondary => #{
                    source => {pem_file, get_filename("keys/secondary/private.pem", C)},
                    authority => some_other_authority
                }
            }
        }},
        {blacklist, #{
            path => get_filename("blacklisted_keys.yaml", C)
        }},
        {authorities, #{
            blacklisting_authority => #{
                id => ?TK_AUTHORITY_CAPI,
                signer => primary,
                authdata_sources => []
            },
            some_other_authority => #{
                id => ?TK_AUTHORITY_CAPI,
                signer => secondary,
                authdata_sources => []
            }
        }}
    ]) ++
        [{groupname, Name} | C];
init_per_group(Name, C) ->
    [{groupname, Name} | C].

-spec end_per_group(group_name(), config()) -> _.
end_per_group(_GroupName, C) ->
    ok = stop_keeper(C),
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
    #token_keeper_AuthData{
        id = undefined,
        token = Token,
        status = active,
        context = Context,
        metadata = ?PARTY_METADATA(?TK_META_NS_APIKEYMGMT, SubjectID),
        authority = ?TK_AUTHORITY_KEYCLOAK
    } = call_get_by_token(Token, ?TOKEN_SOURCE_CONTEXT(), Client),
    _ = assert_context({api_key_token, JTI, SubjectID}, Context).

-spec detect_user_session_token_test(config()) -> ok.
detect_user_session_token_test(C) ->
    Client = mk_client(C),
    JTI = unique_id(),
    SubjectID = <<"TEST">>,
    SubjectEmail = <<"test@test.test">>,
    {ok, Token} = issue_token(JTI, #{<<"sub">> => SubjectID, <<"email">> => SubjectEmail}, unlimited),
    #token_keeper_AuthData{
        id = undefined,
        token = Token,
        status = active,
        context = Context,
        metadata = ?USER_METADATA(?TK_META_NS_KEYCLOAK, SubjectID, SubjectEmail),
        authority = ?TK_AUTHORITY_KEYCLOAK
    } = call_get_by_token(Token, ?TOKEN_SOURCE_CONTEXT(?USER_TOKEN_SOURCE), Client),
    _ = assert_context({user_session_token, JTI, SubjectID, SubjectEmail, unlimited}, Context).

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
    #token_keeper_AuthData{
        id = undefined,
        token = Token,
        status = active,
        context = Context,
        metadata = ?PARTY_METADATA(?TK_META_NS_APIKEYMGMT, SubjectID),
        authority = ?TK_AUTHORITY_CAPI
    } = call_get_by_token(Token, ?TOKEN_SOURCE_CONTEXT(), Client),
    _ = assert_context({claim_token, JTI}, Context).

-spec cons_claim_passthrough_test(config()) -> ok.
cons_claim_passthrough_test(C) ->
    Client = mk_client(C),
    JTI = unique_id(),
    SubjectID = <<"TEST">>,
    {ok, Token} = issue_token_with_context(JTI, SubjectID, #{<<"cons">> => <<"client">>}),
    #token_keeper_AuthData{
        id = undefined,
        token = Token,
        status = active,
        context = Context,
        metadata = ?METADATA(?TK_META_NS_APIKEYMGMT, #{<<"party_id">> := SubjectID, <<"cons">> := <<"client">>}),
        authority = ?TK_AUTHORITY_CAPI
    } = call_get_by_token(Token, ?TOKEN_SOURCE_CONTEXT(), Client),
    _ = assert_context({claim_token, JTI}, Context).

-spec invoice_template_access_token_ok_test(config()) -> ok.
invoice_template_access_token_ok_test(C) ->
    Client = mk_client(C),
    JTI = unique_id(),
    InvoiceTemplateID = unique_id(),
    SubjectID = <<"TEST">>,
    {ok, Token} = issue_token(
        JTI,
        #{
            <<"sub">> => SubjectID,
            <<"resource_access">> => #{
                ?TK_RESOURCE_DOMAIN => #{
                    <<"roles">> => [
                        <<"party.*.invoice_templates.", InvoiceTemplateID/binary, ".invoice_template_invoices:write">>,
                        <<"party.*.invoice_templates.", InvoiceTemplateID/binary, ":read">>
                    ]
                }
            }
        },
        unlimited
    ),
    #token_keeper_AuthData{
        id = undefined,
        token = Token,
        status = active,
        context = Context,
        metadata = ?PARTY_METADATA(?TK_META_NS_APIKEYMGMT, SubjectID),
        authority = ?TK_AUTHORITY_CAPI
    } = call_get_by_token(Token, ?TOKEN_SOURCE_CONTEXT(), Client),
    _ = assert_context({invoice_template_access_token, JTI, SubjectID, InvoiceTemplateID}, Context).

-spec invoice_template_access_token_no_access_test(config()) -> ok.
invoice_template_access_token_no_access_test(C) ->
    Client = mk_client(C),
    JTI = unique_id(),
    SubjectID = <<"TEST">>,
    {ok, Token} = issue_token(JTI, #{<<"sub">> => SubjectID, <<"resource_access">> => #{}}, unlimited),
    #token_keeper_AuthDataNotFound{} =
        (catch call_get_by_token(Token, ?TOKEN_SOURCE_CONTEXT(), Client)).

-spec invoice_template_access_token_invalid_access_test(config()) -> ok.
invoice_template_access_token_invalid_access_test(C) ->
    Client = mk_client(C),
    JTI = unique_id(),
    InvoiceID = unique_id(),
    SubjectID = <<"TEST">>,
    {ok, Token} = issue_token(
        JTI,
        #{
            <<"sub">> => SubjectID,
            <<"resource_access">> => #{
                ?TK_RESOURCE_DOMAIN => #{
                    <<"roles">> => [
                        <<"invoices.", InvoiceID/binary, ":read">>
                    ]
                }
            }
        },
        unlimited
    ),
    #token_keeper_AuthDataNotFound{} =
        (catch call_get_by_token(Token, ?TOKEN_SOURCE_CONTEXT(), Client)).

-spec basic_issuing_test(config()) -> ok.
basic_issuing_test(C) ->
    Client = mk_client(C),
    JTI = unique_id(),
    BinaryContextFragment = create_bouncer_context(JTI),
    Context = #bctx_ContextFragment{
        type = v1_thrift_binary,
        content = BinaryContextFragment
    },
    Metadata = #{<<"ns">> => #{<<"my">> => <<"metadata">>}},
    #token_keeper_AuthData{
        id = undefined,
        token = Token,
        status = active,
        context = Context,
        metadata = Metadata,
        authority = ?TK_AUTHORITY_CAPI
    } = AuthData = call_create_ephemeral(Context, Metadata, Client),
    ok = verify_token(Token, BinaryContextFragment, Metadata, JTI),
    AuthData = call_get_by_token(Token, ?TOKEN_SOURCE_CONTEXT(), Client).

-spec jti_and_authority_blacklist_test(config()) -> ok.
jti_and_authority_blacklist_test(C) ->
    Client = mk_client(C),
    JTI = <<"MYCOOLKEY">>,
    {ok, Token0} = issue_token(JTI, #{}, unlimited, primary),
    #token_keeper_AuthDataRevoked{} =
        (catch call_get_by_token(Token0, ?TOKEN_SOURCE_CONTEXT(), Client)),
    {ok, Token1} = issue_token(JTI, #{}, unlimited, secondary),
    #token_keeper_AuthDataNotFound{} =
        (catch call_get_by_token(Token1, ?TOKEN_SOURCE_CONTEXT(), Client)).

%%

mk_client(C) ->
    WoodyCtx = woody_context:new(genlib:to_binary(?CONFIG(testcase, C))),
    ServiceURLs = ?CONFIG(service_urls, C),
    {WoodyCtx, ServiceURLs}.

call_get_by_token(Token, TokenSourceContext, Client) ->
    call_token_keeper('GetByToken', {Token, TokenSourceContext}, Client).

call_create_ephemeral(ContextFragment, Metadata, Client) ->
    call_token_keeper('CreateEphemeral', {ContextFragment, Metadata}, Client).

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
    _ = assert_auth(TokenInfo, Auth),
    _ = assert_user(TokenInfo, User).

assert_auth({claim_token, JTI}, Auth) ->
    ?assertEqual(<<"ClaimToken">>, Auth#bctx_v1_Auth.method),
    ?assertMatch(#bctx_v1_Token{id = JTI}, Auth#bctx_v1_Auth.token);
assert_auth({api_key_token, JTI, SubjectID}, Auth) ->
    ?assertEqual(<<"ApiKeyToken">>, Auth#bctx_v1_Auth.method),
    ?assertMatch(#bctx_v1_Token{id = JTI}, Auth#bctx_v1_Auth.token),
    ?assertMatch([#bctx_v1_AuthScope{party = ?CTX_ENTITY(SubjectID)}], Auth#bctx_v1_Auth.scope);
assert_auth({invoice_template_access_token, JTI, SubjectID, InvoiceTemplateID}, Auth) ->
    ?assertEqual(<<"InvoiceTemplateAccessToken">>, Auth#bctx_v1_Auth.method),
    ?assertMatch(#bctx_v1_Token{id = JTI}, Auth#bctx_v1_Auth.token),
    ?assertMatch(
        [
            #bctx_v1_AuthScope{
                party = ?CTX_ENTITY(SubjectID),
                invoice_template = ?CTX_ENTITY(InvoiceTemplateID)
            }
        ],
        Auth#bctx_v1_Auth.scope
    );
assert_auth({user_session_token, JTI, _SubjectID, _SubjectEmail, Exp}, Auth) ->
    ?assertEqual(<<"SessionToken">>, Auth#bctx_v1_Auth.method),
    ?assertMatch(#bctx_v1_Token{id = JTI}, Auth#bctx_v1_Auth.token),
    ?assertEqual(make_auth_expiration(Exp), Auth#bctx_v1_Auth.expiration).

assert_user({claim_token, _}, undefined) ->
    ok;
assert_user({api_key_token, _, _}, undefined) ->
    ok;
assert_user({invoice_template_access_token, _, _, _}, undefined) ->
    ok;
assert_user({user_session_token, _JTI, SubjectID, SubjectEmail, _Exp}, User) ->
    ?assertEqual(SubjectID, User#bctx_v1_User.id),
    ?assertEqual(SubjectEmail, User#bctx_v1_User.email),
    ?assertEqual(?CTX_ENTITY(<<"external">>), User#bctx_v1_User.realm).

%%

verify_token(Token, BinaryContextFragment, Metadata, _JTI) ->
    EncodedContextFragment = base64:encode(BinaryContextFragment),
    case tk_token_jwt:verify(Token, #{}) of
        {ok, TokenInfo} ->
            #{
                %<<"jti">> := JTI, %% FIXME this will never match
                <<"bouncer_ctx">> := #{
                    <<"ty">> := <<"v1_thrift_binary">>,
                    <<"ct">> := EncodedContextFragment
                },
                <<"tk_metadata">> := Metadata
            } = tk_token_jwt:get_claims(TokenInfo),
            ok;
        Error ->
            Error
    end.

%%

make_auth_expiration(Timestamp) when is_integer(Timestamp) ->
    genlib_rfc3339:format(Timestamp, second);
make_auth_expiration(unlimited) ->
    undefined.

%%

create_bouncer_context(JTI) ->
    Acc0 = bouncer_context_helpers:empty(),
    Acc1 = bouncer_context_helpers:add_auth(
        #{
            method => <<"ClaimToken">>,
            token => #{id => JTI}
        },
        Acc0
    ),
    encode_context_fragment_content(Acc1).

issue_token(JTI, Claims0, Expiration) ->
    issue_token(JTI, Claims0, Expiration, test).

issue_token(JTI, Claims0, Expiration, Issuer) ->
    Claims1 = tk_token_jwt:create_claims(Claims0, Expiration),
    tk_token_jwt:issue(JTI, Claims1, Issuer).

issue_token_with_context(JTI, SubjectID) ->
    issue_token_with_context(JTI, SubjectID, #{}).

issue_token_with_context(JTI, SubjectID, AdditionalClaims) ->
    FragmentContent = create_bouncer_context(JTI),
    issue_token(
        JTI,
        AdditionalClaims#{
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
    BadPemFile = get_filename("keys/local/dummy.pem", Config),
    BadJWK = jose_jwk:from_pem_file(BadPemFile),
    GoodPemFile = get_filename("keys/local/private.pem", Config),
    GoodJWK = jose_jwk:from_pem_file(GoodPemFile),
    JWKPublic = jose_jwk:to_public(GoodJWK),
    {_Module, PublicKey} = JWKPublic#jose_jwk.kty,
    {_PemEntry, Data, _} = public_key:pem_entry_encode('SubjectPublicKeyInfo', PublicKey),
    KID = jose_base64url:encode(crypto:hash(sha256, Data)),
    JWT = jose_jwt:sign(BadJWK, #{<<"alg">> => <<"RS256">>, <<"kid">> => KID}, Claims),
    {_Modules, Token} = jose_jws:compact(JWT),
    {ok, Token}.

get_filename(Key, Config) ->
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
