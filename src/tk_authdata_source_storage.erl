-module(tk_authdata_source_storage).
-behaviour(tk_authdata_source).

%% Behaviour

-export([get_authdata/2]).

%% Behaviour functions

-spec get_authdata(tk_token_jwt:t(), tk_authdata_source:source_opts()) -> undefined.
get_authdata(_Token, _Opts) ->
    %@TODO: This is for when we actually have storage for authdata
    undefined.
