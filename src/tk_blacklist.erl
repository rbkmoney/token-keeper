-module(tk_blacklist).

-behaviour(supervisor).

%% API

-export([is_blacklisted/2]).

%% Supervisor callbacks

-export([init/1]).
-export([child_spec/1]).

%%

-type options() :: #{
    %% Path to blacklist file
    path => binary()
}.

-export_type([options/0]).

%%

-define(TAB, ?MODULE).

%%

-spec child_spec(options()) -> supervisor:child_spec() | no_return().
child_spec(Options) ->
    #{
        id => ?MODULE,
        start => {supervisor, start_link, [?MODULE, Options]},
        type => supervisor
    }.

-spec is_blacklisted(tk_token:token_id(), tk_authdata:authority_id()) -> boolean().
is_blacklisted(TokenID, AuthorityID) ->
    check_entry({AuthorityID, TokenID}).

%%

-spec init(options()) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init(Options) ->
    _ = init_tab(),
    _ = load_blacklist_conf(maps:get(path, Options, undefined)),
    {ok, {#{}, []}}.

init_tab() ->
    ets:new(?TAB, [set, protected, named_table, {read_concurrency, true}]).

-define(ENTRIES_KEY, "entries").

load_blacklist_conf(undefined) ->
    _ = logger:warning("No token blacklist file specified! Blacklisting functionality will be disabled."),
    put_entires(#{});
load_blacklist_conf(Filename) ->
    [Mappings] = yamerl_constr:file(Filename),
    Entries = process_entries(proplists:get_value(?ENTRIES_KEY, Mappings)),
    put_entires(Entries).

process_entries(Entries) ->
    lists:foldl(
        fun({AuthorityID, TokenIDs}, Acc) ->
            Acc ++ [make_ets_entry(AuthorityID, ID) || ID <- TokenIDs]
        end,
        [],
        Entries
    ).

make_ets_entry(AuthorityID, TokenID) ->
    {{list_to_binary(AuthorityID), list_to_binary(TokenID)}, true}.

%%

put_entires(Entries) ->
    ets:insert_new(?TAB, Entries).

check_entry(Key) ->
    case ets:lookup(?TAB, Key) of
        [_Entry] -> true;
        [] -> false
    end.
