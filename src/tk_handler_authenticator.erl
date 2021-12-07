-module(tk_handler_authenticator).

-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").
-include_lib("token_keeper_proto/include/tk_token_keeper_thrift.hrl").

-export([get_handler_spec/1]).

%% Woody handler

-behaviour(tk_handler).
-export([handle_function/4]).

-type handler_opts() :: #{
    authorities := authorities()
}.

-export_type([handler_opts/0]).

%% Internal types

-type authority_id() :: tk_authdata:authority_id().
-type authorities() :: #{authority_id() => authority_opts()}.
-type authority_opts() :: ephemeral_authority_opts() | external_authority_opts() | offline_authority_opts().

-type ephemeral_authority_opts() :: {ephemeral, #{}}.
-type external_authority_opts() :: {external, #{sources := [tk_authdata_source:authdata_source()]}}.
-type offline_authority_opts() :: {offline, #{storage_name := tk_storage:storage_name()}}.

%%

-spec get_handler_spec(handler_opts()) -> woody:th_handler().
get_handler_spec(Opts) ->
    {
        {tk_token_keeper_thrift, 'TokenAuthenticator'},
        {?MODULE, Opts}
    }.

%%

-spec handle_function(woody:func(), woody:args(), handler_opts(), tk_handler:state()) ->
    {ok, woody:result()} | no_return().
handle_function('AddExistingToken', _Args, _Opts, _State) ->
    erlang:error(not_implemented);
handle_function('Authenticate' = Op, {Token, TokenSourceContext}, Opts, State) ->
    _ = pulse_op_stated(Op, State),
    case tk_token:verify(Token, decode_source_context(TokenSourceContext)) of
        {ok, TokenData} ->
            State1 = save_pulse_metadata(#{token => TokenData}, State),
            case get_authdata(TokenData, Opts, State) of
                {ok, #{status := Status} = AuthDataPrototype} when Status =/= revoked ->
                    EncodedAuthData = encode_auth_data(AuthDataPrototype#{token => Token}),
                    _ = pulse_op_succeeded(Op, State1),
                    {ok, EncodedAuthData};
                {ok, #{status := _}} ->
                    _ = pulse_op_failed(Op, authdata_revoked, State),
                    woody_error:raise(business, #token_keeper_AuthDataRevoked{});
                {error, Reason} ->
                    _ = pulse_op_failed(Op, Reason, State),
                    woody_error:raise(business, #token_keeper_AuthDataNotFound{})
            end;
        {error, {verification_failed, _} = Reason} ->
            _ = pulse_op_failed(Op, Reason, State),
            woody_error:raise(business, #token_keeper_InvalidToken{});
        {error, blacklisted = Reason} ->
            _ = pulse_op_failed(Op, Reason, State),
            woody_error:raise(business, #token_keeper_AuthDataRevoked{})
    end.

%% Internal functions

get_authdata(TokenData = #{authority_id := AuthorityID}, Opts, State) ->
    case get_authdata_by_authority(get_authority_config(AuthorityID, Opts), TokenData, State) of
        {ok, AuthData} ->
            {ok, maybe_add_authority_id(AuthData, AuthorityID)};
        {error, _} = Error ->
            Error
    end.

get_authdata_by_authority({external, #{sources := Sources}}, TokenData, _State) ->
    case get_authdata_from_external_sources(Sources, TokenData) of
        #{} = AuthData ->
            {ok, AuthData};
        undefined ->
            {error, {authdata_not_found, Sources}}
    end;
get_authdata_by_authority({ephemeral, _}, #{payload := TokenPayload}, _State) ->
    case tk_claim_utils:decode_authdata(TokenPayload) of
        {ok, AuthData} ->
            {ok, AuthData};
        {error, Reason} ->
            {error, Reason}
    end;
get_authdata_by_authority({offline, #{storage_name := StorageName}}, #{id := ID}, #{context := Context}) ->
    tk_storage:get(ID, StorageName, Context).

get_authdata_from_external_sources([], _TokenData) ->
    undefined;
get_authdata_from_external_sources([SourceOpts | Rest], TokenData) ->
    case tk_authdata_source:get_authdata(TokenData, SourceOpts) of
        undefined ->
            get_authdata_from_external_sources(Rest, TokenData);
        AuthData ->
            AuthData
    end.

get_authority_config(AuthorityID, #{authorities := Configs}) ->
    maps:get(AuthorityID, Configs).

maybe_add_authority_id(AuthData = #{authority := _}, _AuthorityID) ->
    AuthData;
maybe_add_authority_id(AuthData, AuthorityID) ->
    AuthData#{authority => AuthorityID}.

%%

decode_source_context(#token_keeper_TokenSourceContext{
    request_origin = RequestOrigin
}) ->
    genlib_map:compact(#{
        request_origin => RequestOrigin
    }).

encode_auth_data(
    #{
        token := Token,
        status := Status,
        context := Context,
        authority := Authority
    } = AuthData
) ->
    #token_keeper_AuthData{
        id = maps:get(id, AuthData, undefined),
        token = Token,
        status = Status,
        context = Context,
        metadata = maps:get(metadata, AuthData, #{}),
        authority = Authority
    }.

%%

save_pulse_metadata(Metadata, State = #{pulse_metadata := PulseMetadata}) ->
    State#{pulse_metadata => maps:merge(Metadata, PulseMetadata)}.

pulse_op_stated(Op, State) ->
    handle_beat(Op, started, State).

pulse_op_succeeded(Op, State) ->
    handle_beat(Op, succeeded, State).

pulse_op_failed(Op, Reason, State) ->
    handle_beat(Op, {failed, Reason}, State).

encode_beat_op('Authenticate') ->
    {authenticator, authenticate}.

handle_beat(Op, Event, #{pulse_metadata := PulseMetadata, pulse := Pulse}) ->
    tk_pulse:handle_beat({encode_beat_op(Op), Event}, PulseMetadata, Pulse).
