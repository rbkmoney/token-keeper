-module(tk_token_jwt).

-include_lib("jose/include/jose_jwk.hrl").
-include_lib("jose/include/jose_jwt.hrl").

%% API

-export([issue/2]).
-export([verify/2]).

-export([get_token_id/1]).
-export([get_subject_id/1]).
-export([get_subject_email/1]).
-export([get_expires_at/1]).
-export([get_claims/1]).
-export([get_claim/2]).
-export([get_claim/3]).
-export([get_authority/1]).
-export([get_metadata/1]).
-export([get_source_context/1]).

-export([create_claims/2]).
-export([set_subject_email/2]).

-export([get_key_authority/1]).

%% Supervisor callbacks

-export([init/1]).
-export([child_spec/1]).

%% API types

-type t() :: {claims(), authority(), metadata()}.
-type claim() :: expiration() | term().
-type claims() :: #{binary() => claim()}.
-type token() :: binary().
-type expiration() :: unlimited | non_neg_integer().
-type options() :: #{
    %% The set of keys used to sign issued tokens and verify signatures on such
    %% tokens.
    keyset => keyset()
}.

-type metadata() :: #{
    source_context => source_context()
}.

-type keyname() :: term().

-export_type([t/0]).
-export_type([claim/0]).
-export_type([claims/0]).
-export_type([token/0]).
-export_type([expiration/0]).
-export_type([metadata/0]).
-export_type([options/0]).
-export_type([keyname/0]).

%% Internal types

-type kid() :: binary().
-type key() :: #jose_jwk{}.

-type subject_id() :: binary().
-type token_id() :: binary().

-type authority() :: atom().

%??
-type source_context() :: tk_extractor_detect_token:token_source().

-type keyset() :: #{
    keyname() => key_opts()
}.

-type key_opts() :: #{
    source := keysource(),
    authority := authority()
}.

-type keysource() ::
    {pem_file, file:filename()}.

%%

-define(CLAIM_TOKEN_ID, <<"jti">>).
-define(CLAIM_SUBJECT_ID, <<"sub">>).
-define(CLAIM_SUBJECT_EMAIL, <<"email">>).
-define(CLAIM_EXPIRES_AT, <<"exp">>).

%%
%% API functions
%%

-spec get_token_id(t()) -> token_id() | undefined.
get_token_id(T) ->
    get_claim(?CLAIM_TOKEN_ID, T, undefined).

-spec get_subject_id(t()) -> subject_id() | undefined.
get_subject_id(T) ->
    get_claim(?CLAIM_SUBJECT_ID, T, undefined).

-spec get_subject_email(t()) -> binary() | undefined.
get_subject_email(T) ->
    get_claim(?CLAIM_SUBJECT_EMAIL, T, undefined).

-spec get_expires_at(t()) -> expiration() | undefined.
get_expires_at(T) ->
    case get_claim(?CLAIM_EXPIRES_AT, T, undefined) of
        0 -> unlimited;
        V -> V
    end.

-spec get_claims(t()) -> claims().
get_claims({Claims, _Authority, _Metadata}) ->
    Claims.

-spec get_claim(binary(), t()) -> claim().
get_claim(ClaimName, {Claims, _Authority, _Metadata}) ->
    maps:get(ClaimName, Claims).

-spec get_claim(binary(), t(), claim()) -> claim().
get_claim(ClaimName, {Claims, _Authority, _Metadata}, Default) ->
    maps:get(ClaimName, Claims, Default).

-spec get_authority(t()) -> authority().
get_authority({_Claims, Authority, _Metadata}) ->
    Authority.

-spec get_metadata(t()) -> metadata().
get_metadata({_Claims, _Authority, Metadata}) ->
    Metadata.

-spec get_source_context(t()) -> source_context().
get_source_context({_Claims, _Authority, Metadata}) ->
    maps:get(source_context, Metadata).

-spec create_claims(claims(), expiration()) -> claims().
create_claims(Claims, Expiration) ->
    Claims#{?CLAIM_EXPIRES_AT => Expiration}.

-spec set_subject_email(binary(), claims()) -> claims().
set_subject_email(SubjectEmail, Claims) ->
    false = maps:is_key(?CLAIM_SUBJECT_EMAIL, Claims),
    Claims#{?CLAIM_SUBJECT_EMAIL => SubjectEmail}.

%%

-spec issue(claims(), keyname()) ->
    {ok, token()}
    | {error, nonexistent_key}
    | {error, {invalid_signee, Reason :: atom()}}.
issue(Claims, Signer) ->
    case try_get_key_for_sign(Signer) of
        {ok, Key} ->
            FinalClaims = construct_final_claims(Claims),
            sign(Key, FinalClaims);
        {error, Error} ->
            {error, Error}
    end.

try_get_key_for_sign(Keyname) ->
    case get_key_by_name(Keyname) of
        #{can_sign := true} = Key ->
            {ok, Key};
        #{} ->
            {error, {invalid_signee, signing_not_allowed}};
        undefined ->
            {error, nonexistent_key}
    end.

construct_final_claims(Claims) ->
    maps:map(fun encode_claim/2, Claims).

encode_claim(?CLAIM_EXPIRES_AT, Expiration) ->
    mk_expires_at(Expiration);
encode_claim(_, Value) ->
    Value.

mk_expires_at(unlimited) ->
    0;
mk_expires_at(Dl) ->
    Dl.

sign(#{kid := KID, jwk := JWK, signer := #{} = JWS}, Claims) ->
    JWT = jose_jwt:sign(JWK, JWS#{<<"kid">> => KID}, Claims),
    {_Modules, Token} = jose_jws:compact(JWT),
    {ok, Token}.

%%

-spec verify(token(), source_context()) ->
    {ok, t()}
    | {error,
        {invalid_token,
            badarg
            | {badarg, term()}
            | {missing, atom()}}
        | {nonexistent_key, kid()}
        | {invalid_operation, term()}
        | invalid_signature}.

verify(Token, SourceContext) ->
    try
        {_, ExpandedToken} = jose_jws:expand(Token),
        #{<<"protected">> := ProtectedHeader} = ExpandedToken,
        Header = base64url_to_map(ProtectedHeader),
        Alg = get_alg(Header),
        KID = get_kid(Header),
        verify(KID, Alg, ExpandedToken, SourceContext)
    catch
        %% from get_alg and get_kid
        throw:Reason ->
            {error, Reason};
        %% TODO we're losing error information here, e.g. stacktrace
        error:Reason ->
            {error, {invalid_token, Reason}}
    end.

base64url_to_map(Base64) when is_binary(Base64) ->
    {ok, Json} = jose_base64url:decode(Base64),
    jsx:decode(Json, [return_maps]).

verify(KID, Alg, ExpandedToken, SourceContext) ->
    case get_key_by_kid(KID) of
        #{jwk := JWK, verifier := Algs, authority := Authority} ->
            _ = lists:member(Alg, Algs) orelse throw({invalid_operation, Alg}),
            verify_with_key(JWK, ExpandedToken, Authority, make_metadata(SourceContext));
        undefined ->
            {error, {nonexistent_key, KID}}
    end.

make_metadata(SourceContext) ->
    #{source_context => SourceContext}.

verify_with_key(JWK, ExpandedToken, Authority, Metadata) ->
    case jose_jwt:verify(JWK, ExpandedToken) of
        {true, #jose_jwt{fields = Claims}, _JWS} ->
            {ok, {Claims, Authority, Metadata}};
        {false, _JWT, _JWS} ->
            {error, invalid_signature}
    end.

get_kid(#{<<"kid">> := KID}) when is_binary(KID) ->
    KID;
get_kid(#{}) ->
    throw({invalid_token, {missing, kid}}).

get_alg(#{<<"alg">> := Alg}) when is_binary(Alg) ->
    Alg;
get_alg(#{}) ->
    throw({invalid_token, {missing, alg}}).

%%

-spec get_key_authority(keyname()) -> {ok, authority()} | {error, {nonexistent_key, keyname()}}.
get_key_authority(KeyName) ->
    case get_key_by_name(KeyName) of
        #{authority := Authority} ->
            {ok, Authority};
        undefined ->
            {error, {nonexistent_key, KeyName}}
    end.

%%
%% Supervisor callbacks
%%

-spec child_spec(options()) -> supervisor:child_spec() | no_return().
child_spec(Options) ->
    #{
        id => ?MODULE,
        start => {supervisor, start_link, [?MODULE, parse_options(Options)]},
        type => supervisor
    }.

parse_options(Options) ->
    Keyset = maps:get(keyset, Options, #{}),
    _ = is_map(Keyset) orelse exit({invalid_option, keyset, Keyset}),
    _ = genlib_map:foreach(
        fun(KeyName, KeyOpts = #{source := Source}) ->
            Authority = maps:get(authority, KeyOpts),
            _ =
                is_keysource(Source) orelse
                    exit({invalid_source, KeyName, Source}),
            _ =
                is_atom(Authority) orelse
                    exit({invalid_authority, KeyName, Authority})
        end,
        Keyset
    ),
    Keyset.

is_keysource({pem_file, Fn}) ->
    is_list(Fn) orelse is_binary(Fn);
is_keysource(_) ->
    false.

%%

-spec init(keyset()) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init(Keyset) ->
    ok = create_table(),
    _ = maps:map(fun ensure_store_key/2, Keyset),
    {ok, {#{}, []}}.

ensure_store_key(KeyName, KeyOpts) ->
    Source = maps:get(source, KeyOpts),
    Authority = maps:get(authority, KeyOpts),
    case store_key(KeyName, Source, Authority) of
        ok ->
            ok;
        {error, Reason} ->
            exit({import_error, KeyName, Source, Reason})
    end.

-spec store_key(keyname(), {pem_file, file:filename()}, authority()) -> ok | {error, file:posix() | {unknown_key, _}}.
store_key(Keyname, {pem_file, Filename}, Authority) ->
    store_key(Keyname, {pem_file, Filename}, Authority, #{
        kid => fun derive_kid_from_public_key_pem_entry/1
    }).

derive_kid_from_public_key_pem_entry(JWK) ->
    JWKPublic = jose_jwk:to_public(JWK),
    {_Module, PublicKey} = JWKPublic#jose_jwk.kty,
    {_PemEntry, Data, _} = public_key:pem_entry_encode('SubjectPublicKeyInfo', PublicKey),
    jose_base64url:encode(crypto:hash(sha256, Data)).

-type store_opts() :: #{
    kid => fun((key()) -> kid())
}.

-spec store_key(keyname(), {pem_file, file:filename()}, authority(), store_opts()) ->
    ok | {error, file:posix() | {unknown_key, _}}.
store_key(Keyname, {pem_file, Filename}, Authority, Opts) ->
    case jose_jwk:from_pem_file(Filename) of
        JWK = #jose_jwk{} ->
            Key = construct_key(derive_kid(JWK, Opts), JWK),
            ok = insert_key(Keyname, Key#{authority => Authority});
        Error = {error, _} ->
            Error
    end.

derive_kid(JWK, #{kid := DeriveFun}) when is_function(DeriveFun, 1) ->
    DeriveFun(JWK).

construct_key(KID, JWK) ->
    Signer =
        try
            jose_jwk:signer(JWK)
        catch
            error:_ -> undefined
        end,
    Verifier =
        try
            jose_jwk:verifier(JWK)
        catch
            error:_ -> undefined
        end,
    #{
        jwk => JWK,
        kid => KID,
        signer => Signer,
        can_sign => Signer /= undefined,
        verifier => Verifier,
        can_verify => Verifier /= undefined
    }.

insert_key(Keyname, KeyInfo = #{kid := KID}) ->
    insert_values(#{
        {keyname, Keyname} => KeyInfo,
        {kid, KID} => KeyInfo
    }).

%%
%% Internal functions
%%

get_key_by_name(Keyname) ->
    lookup_value({keyname, Keyname}).

get_key_by_kid(KID) ->
    lookup_value({kid, KID}).

-define(TABLE, ?MODULE).

create_table() ->
    _ = ets:new(?TABLE, [set, public, named_table, {read_concurrency, true}]),
    ok.

insert_values(Values) ->
    true = ets:insert(?TABLE, maps:to_list(Values)),
    ok.

lookup_value(Key) ->
    case ets:lookup(?TABLE, Key) of
        [{Key, Value}] ->
            Value;
        [] ->
            undefined
    end.
