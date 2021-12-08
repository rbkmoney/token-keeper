-module(tk_handler_authority_ephemeral).

-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").
-include_lib("token_keeper_proto/include/tk_token_keeper_thrift.hrl").

-export([get_handler_spec/2]).

%% Woody handler

-behaviour(tk_handler).
-export([handle_function/4]).

-type handler_config() :: #{
    token := token_opts()
}.

-type opts() :: #{
    authority_id := tk_token:authority_id(),
    token_type := tk_token:token_type()
}.

-export_type([handler_config/0]).
-export_type([opts/0]).

%% Internal types

-type token_opts() :: #{
    type := tk_token:token_type()
}.

%%

-spec get_handler_spec(woody:func(), handler_config()) -> woody:th_handler().
get_handler_spec(AuthorityID, Config) ->
    Token = maps:get(token, Config),
    {
        {tk_token_keeper_thrift, 'EphemeralTokenAuthority'},
        {?MODULE, #{
            authority_id => AuthorityID,
            token_type => maps:get(type, Token)
        }}
    }.

%%

-spec handle_function(woody:func(), woody:args(), opts(), tk_handler:state()) -> {ok, woody:result()} | no_return().
handle_function('Create' = Op, {ContextFragment, Metadata}, Opts, State) ->
    _ = pulse_op_stated(Op, State),
    AuthDataPrototype = create_auth_data(ContextFragment, Metadata),
    Claims = tk_claim_utils:encode_authdata(AuthDataPrototype),
    {ok, Token} = tk_token_jwt:issue(create_token_data(Claims, Opts)),
    EncodedAuthData = encode_auth_data(AuthDataPrototype#{token => Token}),
    _ = pulse_op_succeeded(Op, State),
    {ok, EncodedAuthData}.

%% Internal functions

create_auth_data(ContextFragment, Metadata) ->
    tk_authdata:create_prototype(undefined, ContextFragment, Metadata).

%%

create_token_data(Claims, #{authority_id := AuthorityID, token_type := TokenType}) ->
    #{
        id => unique_id(),
        type => TokenType,
        authority_id => AuthorityID,
        expiration => unlimited,
        payload => Claims
    }.

unique_id() ->
    <<ID:64>> = snowflake:new(),
    genlib_format:format_int_base(ID, 62).

%%

encode_auth_data(
    #{
        token := Token,
        status := Status,
        context := Context
    } = AuthData
) ->
    #token_keeper_AuthData{
        token = Token,
        status = Status,
        context = Context,
        metadata = maps:get(metadata, AuthData, #{})
    }.

%%

pulse_op_stated(Op, State) ->
    handle_beat(Op, started, State).

pulse_op_succeeded(Op, State) ->
    handle_beat(Op, succeeded, State).

encode_beat_op('Create') ->
    {authority, {ephemeral, create}}.

handle_beat(Op, Event, #{pulse_metadata := PulseMetadata, pulse := Pulse}) ->
    tk_pulse:handle_beat({encode_beat_op(Op), Event}, PulseMetadata, Pulse).
