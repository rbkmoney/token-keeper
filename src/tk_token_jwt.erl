-module(tk_token_jwt).

-include_lib("jose/include/jose_jwk.hrl").
-include_lib("jose/include/jose_jwt.hrl").

%% API

-export([issue/3]).
-export([verify/1]).

-export([get_token_id/1]).
-export([get_subject_id/1]).
-export([get_subject_email/1]).
-export([get_expires_at/1]).
-export([get_claims/1]).
-export([get_claim/2]).
-export([get_claim/3]).
-export([get_metadata/1]).

-export([create_claims/2]).
-export([set_subject_email/2]).

%% Supervisor callbacks

-export([init/1]).
-export([child_spec/1]).

%% API types

-type t() :: {token_id(), claims(), metadata()}.
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
    type := atom()
}.

-export_type([t/0]).
-export_type([claim/0]).
-export_type([claims/0]).
-export_type([token/0]).
-export_type([expiration/0]).
-export_type([metadata/0]).
-export_type([options/0]).

%% Internal types

-type keyname() :: term().
-type kid() :: binary().
-type key() :: #jose_jwk{}.

-type subject_id() :: binary().
-type token_id() :: binary().

-type keyset() :: #{
    keyname() => key_opts()
}.

-type key_opts() :: #{
    source := keysource(),
    metadata => metadata()
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

-spec get_token_id(t()) -> token_id().
get_token_id({TokenId, _Claims, _Metadata}) ->
    TokenId.

-spec get_subject_id(t()) -> subject_id() | undefined.
get_subject_id(T) ->
    get_claim(?CLAIM_SUBJECT_ID, T, undefined).

-spec get_subject_email(t()) -> binary() | undefined.
get_subject_email(T) ->
    get_claim(?CLAIM_SUBJECT_EMAIL, T, undefined).

-spec get_expires_at(t()) -> expiration().
get_expires_at({_TokenId, Claims, _Metadata}) ->
    case maps:get(?CLAIM_EXPIRES_AT, Claims) of
        0 -> unlimited;
        V -> V
    end.

-spec get_claims(t()) -> claims().
get_claims({_TokenId, Claims, _Metadata}) ->
    Claims.

-spec get_claim(binary(), t()) -> claim().
get_claim(ClaimName, {_TokenId, Claims, _Metadata}) ->
    maps:get(ClaimName, Claims).

-spec get_claim(binary(), t(), claim()) -> claim().
get_claim(ClaimName, {_TokenId, Claims, _Metadata}, Default) ->
    maps:get(ClaimName, Claims, Default).

-spec get_metadata(t()) -> metadata().
get_metadata({_TokenId, _Claims, Metadata}) ->
    Metadata.

-spec create_claims(claims(), expiration()) -> claims().
create_claims(Claims, Expiration) ->
    Claims#{?CLAIM_EXPIRES_AT => Expiration}.

-spec set_subject_email(binary(), claims()) -> claims().
set_subject_email(SubjectEmail, Claims) ->
    false = maps:is_key(?CLAIM_SUBJECT_EMAIL, Claims),
    Claims#{?CLAIM_SUBJECT_EMAIL => SubjectEmail}.

%%

-spec issue(token_id(), claims(), keyname()) ->
    {ok, token()}
    | {error, nonexistent_key}
    | {error, {invalid_signee, Reason :: atom()}}.
issue(JTI, Claims, Signer) ->
    case try_get_key_for_sign(Signer) of
        {ok, Key} ->
            FinalClaims = construct_final_claims(Claims, JTI),
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

construct_final_claims(Claims, JTI) ->
    Token0 = #{?CLAIM_TOKEN_ID => JTI},
    EncodedClaims = maps:map(fun encode_claim/2, Claims),
    maps:merge(EncodedClaims, Token0).

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

-spec verify(token()) ->
    {ok, t()}
    | {error,
        {invalid_token,
            badarg
            | {badarg, term()}
            | {missing, atom()}}
        | {nonexistent_key, kid()}
        | {invalid_operation, term()}
        | invalid_signature}.

verify(Token) ->
    try
        {_, ExpandedToken} = jose_jws:expand(Token),
        #{<<"protected">> := ProtectedHeader} = ExpandedToken,
        Header = base64url_to_map(ProtectedHeader),
        Alg = get_alg(Header),
        KID = get_kid(Header),
        verify(KID, Alg, ExpandedToken)
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

verify(KID, Alg, ExpandedToken) ->
    case get_key_by_kid(KID) of
        #{jwk := JWK, verifier := Algs, metadata := Metadata} ->
            _ = lists:member(Alg, Algs) orelse throw({invalid_operation, Alg}),
            verify_with_key(JWK, ExpandedToken, Metadata);
        undefined ->
            {error, {nonexistent_key, KID}}
    end.

verify_with_key(JWK, ExpandedToken, Metadata) ->
    case jose_jwt:verify(JWK, ExpandedToken) of
        {true, #jose_jwt{fields = Claims}, _JWS} ->
            _ = validate_claims(Claims),
            get_result(Claims, Metadata);
        {false, _JWT, _JWS} ->
            {error, invalid_signature}
    end.

validate_claims(Claims) ->
    validate_claims(Claims, get_validators()).

validate_claims(Claims, [{Name, Claim, Validator} | Rest]) ->
    _ = Validator(Name, maps:get(Claim, Claims, undefined)),
    validate_claims(Claims, Rest);
validate_claims(Claims, []) ->
    Claims.

get_result(#{?CLAIM_TOKEN_ID := TokenID} = Claims, Metadata) ->
    {ok, {TokenID, maps:without([?CLAIM_TOKEN_ID], Claims), Metadata}}.

get_kid(#{<<"kid">> := KID}) when is_binary(KID) ->
    KID;
get_kid(#{}) ->
    throw({invalid_token, {missing, kid}}).

get_alg(#{<<"alg">> := Alg}) when is_binary(Alg) ->
    Alg;
get_alg(#{}) ->
    throw({invalid_token, {missing, alg}}).

get_validators() ->
    [
        {token_id, ?CLAIM_TOKEN_ID, fun check_presence/2},
        {expires_at, ?CLAIM_EXPIRES_AT, fun check_presence/2}
    ].

check_presence(_, V) when is_binary(V) ->
    V;
check_presence(_, V) when is_integer(V) ->
    V;
check_presence(C, undefined) ->
    throw({invalid_token, {missing, C}}).

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
            Metadata = maps:get(metadata, KeyOpts),
            Type = maps:get(type, Metadata),
            _ =
                is_keysource(Source) orelse
                    exit({invalid_source, KeyName, Source}),
            _ =
                is_atom(Type) orelse
                    exit({invalid_type, KeyName, Type})
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
    Metadata = maps:get(metadata, KeyOpts, #{}),
    case store_key(KeyName, Source, Metadata) of
        ok ->
            ok;
        {error, Reason} ->
            exit({import_error, KeyName, Source, Reason})
    end.

-spec store_key(keyname(), {pem_file, file:filename()}, metadata()) -> ok | {error, file:posix() | {unknown_key, _}}.
store_key(Keyname, {pem_file, Filename}, Metadata) ->
    store_key(Keyname, {pem_file, Filename}, Metadata, #{
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

-spec store_key(keyname(), {pem_file, file:filename()}, metadata(), store_opts()) ->
    ok | {error, file:posix() | {unknown_key, _}}.
store_key(Keyname, {pem_file, Filename}, Metadata, Opts) ->
    case jose_jwk:from_pem_file(Filename) of
        JWK = #jose_jwk{} ->
            Key = construct_key(derive_kid(JWK, Opts), JWK),
            ok = insert_key(Keyname, Key#{metadata => Metadata});
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
