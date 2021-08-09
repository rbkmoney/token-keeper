-module(tk_token_blacklist).

-behaviour(supervisor).

%% API

-export([check/2]).

%% Supervisor callbacks

-export([init/1]).
-export([child_spec/1]).

%%

-type options() :: #{
    %% Path to blacklist file
    path := binary()
}.

-export_type([options/0]).

%%

-define(APP, token_keeper).
-define(TERM_KEY, {?MODULE, mappings}).

%%

-spec child_spec(options()) -> supervisor:child_spec() | no_return().
child_spec(Options) ->
    #{
        id => ?MODULE,
        start => {supervisor, start_link, [?MODULE, Options]},
        type => supervisor
    }.

-spec check(binary(), atom()) -> ok | {error, token_blacklisted}.
check(Token, AuthorityID) ->
    Entries = get_entires(),
    case match_entry(AuthorityID, Token, Entries) of
        false ->
            ok;
        true ->
            {error, token_blacklisted}
    end.

%%

match_entry(AuthorityID, Token, Entries) ->
    case maps:get(AuthorityID, Entries, undefined) of
        AuthorityEntries when AuthorityEntries =/= undefined ->
            lists:member(Token, AuthorityEntries);
        undefined ->
            false
    end.

%%

-spec init(options()) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init(Options) ->
    _ = load_blacklist_conf(maps:get(path, Options, get_default_path())),
    {ok, {#{}, []}}.

-define(ENTRIES_KEY, "entries").

load_blacklist_conf(Filename) ->
    [Mappings] = yamerl_constr:file(Filename),
    Entries = process_entries(proplists:get_value(?ENTRIES_KEY, Mappings)),
    put_entires(Entries).

get_default_path() ->
    filename:join([get_priv_dir(), "blacklisted_keys.yaml"]).

process_entries(Entries) ->
    lists:foldl(
        fun({K, V}, Acc) ->
            %% Would love to use list_to_existing_atom(K) here, but
            %% authority config does not create atoms for some reason
            Acc#{list_to_atom(K) => [list_to_binary(V0) || V0 <- V]}
        end,
        #{},
        Entries
    ).

get_priv_dir() ->
    case code:priv_dir(?APP) of
        {error, bad_name} ->
            exit({blacklist_load_failed, not_an_app});
        Filename ->
            Filename
    end.

%%

put_entires(Entries) ->
    persistent_term:put(?TERM_KEY, Entries).

get_entires() ->
    persistent_term:get(?TERM_KEY).
