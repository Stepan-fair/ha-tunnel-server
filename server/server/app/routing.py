"""Server-only FRP routes prevent older preauthenticated pools serving a new binding."""


def upstream_domain(client_id, domain, generation):
    # Keep initial routes compatible with existing clients; rebound generations
    # use the reserved internal namespace, never accepted as a public relay Host.
    return domain if generation == 0 else f'{client_id}-g{generation}.ha-tunnel.invalid'
