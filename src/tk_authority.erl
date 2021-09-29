-module(tk_authority).

-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").
-include_lib("token_keeper_proto/include/tk_token_keeper_thrift.hrl").

%% API functions

-export([get_id/1]).
-export([get_authdata_id/1]).
-export([get_signer/1]).
-export([set_status/2]).
-export([create_authdata/4]).
-export([get_authdata_by_token/2]).
-export([get_authdata_by_id/2]).
-export([store/2]).
-export([get_values/2]).

%% API Types

-type authority() :: #{
    id := autority_id(),
    signer => tk_token_jwt:keyname(),
    authdata_sources := [tk_authdata_source:authdata_source()]
}.

-type autority_id() :: binary().

-type authdata() :: #{
    id => authdata_id(),
    status := status(),
    context := encoded_context_fragment(),
    authority := autority_id(),
    metadata => metadata()
}.

-type authdata_id() :: binary().
-type status() :: active | revoked.
-type encoded_context_fragment() :: tk_context_thrift:'ContextFragment'().
-type metadata() :: #{binary() => binary()}.

-type authdata_keys() :: [atom()].

-export_type([authority/0]).

-export_type([authdata/0]).
-export_type([authdata_id/0]).
-export_type([status/0]).
-export_type([encoded_context_fragment/0]).
-export_type([metadata/0]).
-export_type([autority_id/0]).

%% API Functions

-spec get_id(authority()) -> autority_id().
get_id(Authority) ->
    maps:get(id, Authority).

-spec get_authdata_id(authdata()) -> authdata_id().
get_authdata_id(AuthData) ->
    maps:get(id, AuthData).

-spec get_signer(authority()) -> tk_token_jwt:keyname().
get_signer(Authority) ->
    maps:get(signer, Authority).

-spec set_status(authdata(), status()) -> authdata().
set_status(AuthData, Status) ->
    AuthData#{status => Status}.

-spec create_authdata(authdata_id() | undefined, encoded_context_fragment(), metadata(), authority() | autority_id()) ->
    authdata().
create_authdata(ID, ContextFragment, Metadata, Authority) ->
    AuthData = #{
        status => active,
        context => ContextFragment,
        metadata => Metadata
    },
    add_authority_id(add_id(AuthData, ID), Authority).

-spec get_authdata_by_token(tk_token_jwt:t(), authority()) ->
    {ok, authdata()} | {error, {authdata_not_found, _Sources}}.
get_authdata_by_token(Token, Authority) ->
    get_authdata({token, Token}, Authority).

-spec get_authdata_by_id(authdata_id(), authority()) -> {ok, authdata()} | {error, {authdata_not_found, _Sources}}.
get_authdata_by_id(ID, Authority) ->
    get_authdata({id, ID}, Authority).

-spec store(authdata(), authority()) -> {ok, tk_token_jwt:claims()} | {error, _Reason}.
store(AuthData, Authority) ->
    case get_storage_opts(Authority) of
        {_Source, Opts} ->
            tk_storage:store(AuthData, Opts);
        false ->
            {error, {misconfiguration, {no_storage_options, Authority}}}
    end.

-spec get_values(authdata_keys(), authdata()) -> #{atom() => any()}.
get_values(Keys, AuthData) ->
    maps:with(Keys, AuthData).

%%-------------------------------------
%% private functions

get_authdata(Selector, Authority) ->
    AuthDataSources = get_auth_data_sources(Authority),
    case get_authdata_from_sources(AuthDataSources, Selector) of
        undefined ->
            {error, {authdata_not_found, AuthDataSources}};
        AuthData ->
            {ok, maybe_add_authority_id(AuthData, Authority)}
    end.

get_auth_data_sources(Authority) ->
    case maps:get(authdata_sources, Authority, undefined) of
        Sources when Sources =/= undefined ->
            Sources;
        undefined ->
            throw({misconfiguration, {no_authdata_sources, Authority}})
    end.

get_authdata_from_sources([], _Selector) ->
    undefined;
get_authdata_from_sources([SourceOpts | Rest], Selector) ->
    case tk_authdata_source:get_authdata(SourceOpts, Selector) of
        undefined ->
            get_authdata_from_sources(Rest, Selector);
        AuthData ->
            AuthData
    end.

maybe_add_authority_id(AuthData = #{authority := _}, _Authority) ->
    AuthData;
maybe_add_authority_id(AuthData, Authority) ->
    add_authority_id(AuthData, Authority).

add_id(AuthData, undefined) ->
    AuthData;
add_id(AuthData, ID) ->
    AuthData#{id => ID}.

add_authority_id(AuthData, Authority) when is_map(Authority) ->
    AuthData#{authority => maps:get(id, Authority)};
add_authority_id(AuthData, Authority) when is_binary(Authority) ->
    AuthData#{authority => Authority}.

get_storage_opts(Authority) ->
    lists:keyfind(storage, 1, get_auth_data_sources(Authority)).
