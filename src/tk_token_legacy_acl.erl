-module(tk_token_legacy_acl).

%%

-opaque t() :: [{{priority(), scope()}, [permission()]}].

-type priority() :: integer().
-type unknown_scope() :: {unknown, binary()}.
-type known_scope() :: [resource() | {resource(), resource_id()}, ...].
-type scope() :: known_scope() | unknown_scope().
-type resource() :: atom().
-type resource_id() :: binary().
-type permission() :: read | write.
-type resource_hierarchy() :: map().

-export_type([t/0]).
-export_type([scope/0]).
-export_type([known_scope/0]).
-export_type([resource/0]).
-export_type([permission/0]).
-export_type([resource_hierarchy/0]).

-export([to_list/1]).
-export([decode/2]).

%%

-spec to_list(t()) -> [{scope(), [permission()]}].
to_list(ACL) ->
    [{S, P} || {{_, S}, P} <- ACL].

%%

-spec decode([binary()], resource_hierarchy()) -> t().
decode(BinaryACL, ResourceHierarchy) ->
    lists:foldl(
        fun(V, ACL) ->
            decode_entry(V, ACL, ResourceHierarchy)
        end,
        [],
        BinaryACL
    ).

decode_entry(V, ACL, ResourceHierarchy) ->
    case binary:split(V, <<":">>, [global]) of
        [V1, V2] ->
            Scope = decode_scope(V1, ResourceHierarchy),
            Permission = decode_permission(V2),
            insert_scope(Scope, Permission, ACL, ResourceHierarchy);
        _ ->
            error({badarg, {role, V}})
    end.

decode_scope(V, ResourceHierarchy) ->
    try
        decode_scope_frags(binary:split(V, <<".">>, [global]), ResourceHierarchy)
    catch
        error:{badarg, _} ->
            {unknown, V}
    end.

decode_scope_frags([V1, V2 | Vs], H) ->
    {Resource, H1} = decode_scope_frag_resource(V1, V2, H),
    [Resource | decode_scope_frags(Vs, H1)];
decode_scope_frags([V], H) ->
    decode_scope_frags([V, <<"*">>], H);
decode_scope_frags([], _) ->
    [].

decode_scope_frag_resource(V, <<"*">>, H) ->
    R = decode_resource(V),
    {R, delve(R, H)};
decode_scope_frag_resource(V, ID, H) ->
    R = decode_resource(V),
    {{R, ID}, delve(R, H)}.

decode_resource(V) ->
    try
        binary_to_existing_atom(V, utf8)
    catch
        error:badarg ->
            error({badarg, {resource, V}})
    end.

decode_permission(<<"read">>) ->
    read;
decode_permission(<<"write">>) ->
    write;
decode_permission(V) ->
    error({badarg, {permission, V}}).

%%

-spec insert_scope(scope(), permission(), t(), resource_hierarchy()) -> t().
insert_scope({unknown, _} = Scope, Permission, ACL, _ResourceHierarchy) ->
    insert({{0, Scope}, [Permission]}, ACL);
insert_scope(Scope, Permission, ACL, ResourceHierarchy) ->
    Priority = compute_priority(Scope, ResourceHierarchy),
    insert({{Priority, Scope}, [Permission]}, ACL).

insert({PS, _} = V, [{PS0, _} = V0 | Vs]) when PS < PS0 ->
    [V0 | insert(V, Vs)];
insert({PS, Perms}, [{PS, Perms0} | Vs]) ->
    % NOTE squashing permissions of entries with the same scope
    [{PS, lists:usort(Perms ++ Perms0)} | Vs];
insert({PS, _} = V, [{PS0, _} | _] = Vs) when PS > PS0 ->
    [V | Vs];
insert(V, []) ->
    [V].

%%

compute_priority(Scope, ResourceHierarchy) ->
    % NOTE
    % Scope priority depends on the following attributes, in the order of decreasing
    % importance:
    % 1. Depth, deeper is more important
    % 2. Scope element specificity, element marked with an ID is more important
    compute_scope_priority(Scope, ResourceHierarchy).

compute_scope_priority(Scope, ResourceHierarchy) when length(Scope) > 0 ->
    compute_scope_priority(Scope, ResourceHierarchy, 0);
compute_scope_priority(Scope, _ResourceHierarchy) ->
    error({badarg, {scope, Scope}}).

compute_scope_priority([{Resource, _ID} | Rest], H, P) ->
    compute_scope_priority(Rest, delve(Resource, H), P * 10 + 2);
compute_scope_priority([Resource | Rest], H, P) ->
    compute_scope_priority(Rest, delve(Resource, H), P * 10 + 1);
compute_scope_priority([], _, P) ->
    P * 10.

%%

delve(Resource, Hierarchy) ->
    case maps:find(Resource, Hierarchy) of
        {ok, Sub} ->
            Sub;
        error ->
            error({badarg, {resource, Resource}})
    end.
