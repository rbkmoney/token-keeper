-module(tk_token_compact).

-define(HDR_SIGN, "tkc1:").

%% API types
-type key() :: binary().
-type token() :: binary().
-type id() :: tk_authority:authdata_id().
-type options() :: #{
    signkey => key()
}.

%% API
-export([verify/2]).
-export([issue/2]).

%%-------------------------------------
%% API Implementation

-spec verify(token(), options()) -> {ok, id()} | {error, {invalid_token, wrong_format | wrong_header}} | no_return().
verify(<<?HDR_SIGN, TokenBody/binary>>, Opts) ->
    case Opts of
        #{signkey := Key} when is_binary(Key) ->
            try
                {ok, get_token_id(Key, TokenBody)}
            catch
                %% badarg | {badmatch, _}
                error:_Reason ->
                    {error, {invalid_token, wrong_format}}
            end;
        _ ->
            throw({misconfiguration, {error, nosignkey}})
    end;
verify(_, _) ->
    {error, {invalid_token, wrong_header}}.

-spec issue(key(), id()) -> token().
issue(Key, AuthDataID) when is_binary(Key), is_binary(AuthDataID) ->
    SaltedData = erlang:term_to_binary({AuthDataID, os:timestamp()}),
    EncryptedID = encrypt(Key, SaltedData, true),
    <<?HDR_SIGN, (base64:encode(EncryptedID))/binary>>.

%%-------------------------------------
%% private functions

-spec get_token_id(key(), token()) -> id().
get_token_id(Key, TokenBody) when is_binary(Key), is_binary(TokenBody) ->
    SaltedData = encrypt(Key, base64:decode(TokenBody), false),
    {AuthDataID, _Salt} = erlang:binary_to_term(SaltedData),
    AuthDataID.

encrypt(Key, Data, Encrypt) ->
    crypto:crypto_one_time(
        'aes_256_ecb',
        crypto:hash(sha256, Key),
        Data,
        [{encrypt, Encrypt}, {padding, pkcs_padding}]
    ).
