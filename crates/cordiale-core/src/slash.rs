//! Slash commands typed in the compose line, following Cicchetto's grammar
//! (`cicchetto/src/lib/slashCommands.ts`). Views Cordiale answers locally
//! (`/links`, `/list`, `/archive`, ...) and the commands answered on the
//! reply screen (`/whois`, `/who`, ...) are recognized before this parser.
//! User aliases are expanded first, by [`expand_aliases`].

use std::collections::HashMap;

/// One parsed slash command. `None` from [`parse`] means the line isn't a
/// command at all and goes out as a plain message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlashCommand {
    /// `//text`: a message that starts with a slash, sent as typed minus
    /// the escaping one.
    Say(String),
    /// `/me <text>`: a CTCP ACTION in the open window.
    Action(String),
    /// `/msg <nick> <text>`, and the services shortcuts (`/ns identify`).
    Msg { target: String, text: String },
    /// `/notice <target> <text>`.
    Notice { target: String, text: String },
    /// `/query [nick]`: opens a private window, or closes the open one.
    Query(Option<String>),
    /// `/join <#chan>[,<#chan>...] [key]`.
    Join {
        channels: String,
        key: Option<String>,
    },
    /// `/part [#chan] [reason]`, the open channel by default.
    Part {
        channel: Option<String>,
        reason: Option<String>,
    },
    /// `/cycle [#chan] [reason]`: part, then join again.
    Cycle {
        channel: Option<String>,
        reason: Option<String>,
    },
    /// `/topic [#chan] <text>`.
    TopicSet {
        channel: Option<String>,
        text: String,
    },
    /// `/topic [#chan] -delete`.
    TopicClear { channel: Option<String> },
    /// `/topic [#chan]` with no text: shows the current topic.
    TopicShow { channel: Option<String> },
    /// `/mode [#chan]` with no modes: shows the channel's current modes.
    ModeShow { channel: Option<String> },
    /// `/nick <nick>`.
    Nick(String),
    /// `/away [reason]`: sets away with a reason, or comes back without.
    Away(Option<String>),
    /// `/ctcp <target> <VERB> [args]`, verb upper-cased.
    Ctcp {
        target: String,
        verb: String,
        args: Option<String>,
    },
    /// `/ping <target>`: a CTCP PING.
    Ping(String),
    /// `/op`, `/deop`, `/voice`, `/devoice` with one or more nicks.
    NickModes {
        verb: &'static str,
        nicks: Vec<String>,
    },
    /// `/kick <nick> [reason]`.
    Kick { nick: String, reason: String },
    /// `/kb <nick> [reason]` (`/kickban`): bans `*!*@host` when the host is
    /// known, and kicks either way.
    KickBan { nick: String, reason: String },
    /// `/ban <mask-or-nick>`.
    Ban(String),
    /// `/unban <mask>`.
    Unban(String),
    /// `/mode [target] <modes> [params]`, the open channel by default.
    Mode {
        target: Option<String>,
        modes: String,
        params: Vec<String>,
    },
    /// `/umode <modes>`.
    Umode(String),
    /// Bare `/umode`: opens the user-mode view of the active network.
    UmodeShow,
    /// `/names [#chan]`.
    Names(Option<String>),
    /// A raw IRC line: `/quote`, and the operator verbs built on it
    /// (`/kill`, `/stats`, `/rehash`).
    Raw(String),
    /// `/oper <name> <password>`. The password must never be logged.
    Oper { name: String, password: String },
    /// `/connect <network>`.
    Connect(String),
    /// `/disconnect [network] [reason]`: parks the network.
    Disconnect {
        network: Option<String>,
        reason: Option<String>,
    },
    /// `/reconnect [network] [reason]`: parks, then connects again.
    Reconnect {
        network: Option<String>,
        reason: Option<String>,
    },
    /// `/quit [reason]`: parks every network, then signs out.
    Quit(Option<String>),
    /// `/hilight <pattern>` or `/dehilight <pattern>`.
    Highlight { add: bool, pattern: String },
    /// `/ignore <mask>` or `/unignore <mask>`.
    Ignore { add: bool, mask: String },
    /// `/notify <nick...>`.
    Notify(Vec<String>),
    /// `/alias <name> <expansion>`: defines or replaces a user alias.
    AliasDefine { name: String, expansion: String },
    /// `/unalias <name>`.
    Unalias(String),
    /// `/ame <text>` (an action) or `/amsg <text>` in every joined channel
    /// of the network.
    FanOut { action: bool, text: String },
    /// A known command with missing or malformed arguments; carries its
    /// syntax for the hint.
    Usage(&'static str),
    /// A command Cordiale doesn't know, as typed (`/frobnicate`).
    Unknown(String),
}

/// Whether `name` is a channel rather than a nick.
pub fn is_channel(name: &str) -> bool {
    name.starts_with(['#', '&', '!', '+'])
}

/// Whether `nick` is an IRC services bot (`NickServ`, `ChanServ`, ...);
/// messages to them don't open a private window.
pub fn is_service_nick(nick: &str) -> bool {
    nick.len() > 4 && nick.to_ascii_lowercase().ends_with("serv")
}

/// Splits off the first word; the remainder keeps its inner spacing.
fn split_word(text: &str) -> (&str, &str) {
    let text = text.trim_start();
    match text.find(char::is_whitespace) {
        Some(end) => (&text[..end], text[end..].trim()),
        None => (text, ""),
    }
}

fn non_empty(text: &str) -> Option<String> {
    (!text.is_empty()).then(|| text.to_string())
}

/// `[#chan] [reason]`: a leading channel names the target, anything else
/// starts the reason.
fn channel_reason(args: &str) -> (Option<String>, Option<String>) {
    let (first, rest) = split_word(args);
    if is_channel(first) {
        (Some(first.to_string()), non_empty(rest))
    } else {
        (None, non_empty(args))
    }
}

/// `[network] [reason]`: the first word, when present, is always the
/// network.
fn network_reason(args: &str) -> (Option<String>, Option<String>) {
    let (first, rest) = split_word(args);
    (non_empty(first), non_empty(rest))
}

fn words(args: &str) -> Vec<String> {
    args.split_whitespace().map(str::to_string).collect()
}

/// `/join` targets: a bare head gets a `#`, further comma-separated
/// entries must carry their own sigil.
fn join_channels(list: &str) -> Option<String> {
    let mut channels = list.split(',');
    let head = channels.next().filter(|head| !head.is_empty())?;
    let mut joined = if is_channel(head) {
        head.to_string()
    } else {
        format!("#{head}")
    };
    for channel in channels {
        if !is_channel(channel) || channel.len() < 2 {
            return None;
        }
        joined.push(',');
        joined.push_str(channel);
    }
    Some(joined)
}

fn service_nick(verb: &str) -> Option<&'static str> {
    Some(match verb {
        "cs" => "ChanServ",
        "ns" => "NickServ",
        "ms" => "MemoServ",
        "os" => "OperServ",
        "hs" => "HelpServ",
        "rs" => "RootServ",
        _ => return None,
    })
}

/// Parses a compose-line entry. `None` for anything that isn't a slash
/// command.
pub fn parse(input: &str) -> Option<SlashCommand> {
    use SlashCommand::*;

    let line = input.trim();
    let rest = line.strip_prefix('/')?;
    if rest.starts_with('/') {
        return Some(Say(rest.to_string()));
    }
    let (verb, args) = split_word(rest);
    if verb.is_empty() {
        return None;
    }
    let verb = verb.to_ascii_lowercase();
    let command = match verb.as_str() {
        "me" => Action(args.to_string()),
        "msg" => {
            let (target, text) = split_word(args);
            if target.is_empty() || text.is_empty() || is_channel(target) {
                Usage("/msg <nick> <text>")
            } else {
                Msg {
                    target: target.to_string(),
                    text: text.to_string(),
                }
            }
        }
        "notice" => {
            let (target, text) = split_word(args);
            if target.is_empty() || text.is_empty() {
                Usage("/notice <target> <text>")
            } else {
                Notice {
                    target: target.to_string(),
                    text: text.to_string(),
                }
            }
        }
        "query" | "q" => match words(args).as_slice() {
            [] => Query(None),
            [nick] if !is_channel(nick) => Query(Some(nick.clone())),
            _ => Usage("/query <nick>"),
        },
        "join" | "j" => match args.split_whitespace().collect::<Vec<_>>().as_slice() {
            [list] => match join_channels(list) {
                Some(channels) => Join {
                    channels,
                    key: None,
                },
                None => Usage("/join <#channel>[,<#channel>] [key]"),
            },
            [list, key] => match join_channels(list) {
                Some(channels) => Join {
                    channels,
                    key: Some(key.to_string()),
                },
                None => Usage("/join <#channel>[,<#channel>] [key]"),
            },
            _ => Usage("/join <#channel>[,<#channel>] [key]"),
        },
        "part" => {
            let (channel, reason) = channel_reason(args);
            Part { channel, reason }
        }
        "cycle" => {
            let (channel, reason) = channel_reason(args);
            Cycle { channel, reason }
        }
        "topic" => {
            let (first, rest) = split_word(args);
            let (channel, text) = if is_channel(first) && first.len() > 1 {
                (Some(first.to_string()), rest)
            } else if first == "#" {
                // A bare `#` escapes a topic that starts with a channel name.
                (None, rest)
            } else {
                (None, args)
            };
            if text == "-delete" {
                TopicClear { channel }
            } else if text.is_empty() {
                TopicShow { channel }
            } else {
                TopicSet {
                    channel,
                    text: text.to_string(),
                }
            }
        }
        "nick" => match words(args).as_slice() {
            [nick] => Nick(nick.clone()),
            _ => Usage("/nick <nick>"),
        },
        "away" => {
            let reason = args.strip_prefix(':').unwrap_or(args).trim();
            Away(non_empty(reason))
        }
        "ctcp" => {
            let (target, rest) = split_word(args);
            let (ctcp_verb, ctcp_args) = split_word(rest);
            if target.is_empty() || ctcp_verb.is_empty() {
                Usage("/ctcp <target> <VERB> [args]")
            } else {
                Ctcp {
                    target: target.to_string(),
                    verb: ctcp_verb.to_ascii_uppercase(),
                    args: non_empty(ctcp_args),
                }
            }
        }
        "ping" => match words(args).as_slice() {
            [target] => Ping(target.clone()),
            _ => Usage("/ping <target>"),
        },
        "op" | "deop" | "voice" | "devoice" => {
            let nicks = words(args);
            let verb = match verb.as_str() {
                "op" => "op",
                "deop" => "deop",
                "voice" => "voice",
                _ => "devoice",
            };
            if nicks.is_empty() {
                Usage("/op <nick> [nick...]")
            } else {
                NickModes { verb, nicks }
            }
        }
        "kick" => {
            let (nick, reason) = split_word(args);
            if nick.is_empty() {
                Usage("/kick <nick> [reason]")
            } else {
                Kick {
                    nick: nick.to_string(),
                    reason: reason.to_string(),
                }
            }
        }
        "kb" | "kickban" => {
            let (nick, reason) = split_word(args);
            if nick.is_empty() {
                Usage("/kb <nick> [reason]")
            } else {
                KickBan {
                    nick: nick.to_string(),
                    reason: reason.to_string(),
                }
            }
        }
        "ban" | "unban" => match words(args).as_slice() {
            [mask] if verb == "ban" => Ban(mask.clone()),
            [mask] => Unban(mask.clone()),
            _ if verb == "ban" => Usage("/ban <nick-or-mask>"),
            _ => Usage("/unban <mask>"),
        },
        "mode" => {
            let parts = words(args);
            match parts.as_slice() {
                [first, rest @ ..] if first.starts_with(['+', '-']) => Mode {
                    target: None,
                    modes: first.clone(),
                    params: rest.to_vec(),
                },
                [target, modes, params @ ..] => Mode {
                    target: Some(target.clone()),
                    modes: modes.clone(),
                    params: params.to_vec(),
                },
                [] => ModeShow { channel: None },
                [channel] if is_channel(channel) => ModeShow {
                    channel: Some(channel.clone()),
                },
                _ => Usage("/mode [target] <modes> [params]"),
            }
        }
        "umode" => match words(args).as_slice() {
            [] => UmodeShow,
            [modes] => Umode(modes.clone()),
            _ => Usage("/umode [modes]"),
        },
        "names" => match words(args).as_slice() {
            [] => Names(None),
            [channel] => Names(Some(channel.clone())),
            _ => Usage("/names [#channel]"),
        },
        "quote" | "raw" => match non_empty(args) {
            Some(line) => Raw(line),
            None => Usage("/quote <raw IRC line>"),
        },
        "oper" => match words(args).as_slice() {
            [name, password] => Oper {
                name: name.clone(),
                password: password.clone(),
            },
            _ => Usage("/oper <name> <password>"),
        },
        "kill" => {
            let (nick, reason) = split_word(args);
            if nick.is_empty() {
                Usage("/kill <nick> [reason]")
            } else if reason.is_empty() {
                Raw(format!("KILL {nick}"))
            } else {
                Raw(format!("KILL {nick} :{reason}"))
            }
        }
        "stats" | "rehash" => {
            let raw_verb = verb.to_ascii_uppercase();
            let params = words(args);
            if params.is_empty() {
                Raw(raw_verb)
            } else {
                Raw(format!("{raw_verb} {}", params.join(" ")))
            }
        }
        "connect" => match words(args).as_slice() {
            [network] => Connect(network.clone()),
            _ => Usage("/connect <network>"),
        },
        "disconnect" => {
            let (network, reason) = network_reason(args);
            Disconnect { network, reason }
        }
        "reconnect" => {
            let (network, reason) = network_reason(args);
            Reconnect { network, reason }
        }
        "quit" => Quit(non_empty(args)),
        "hilight" | "highlight" | "dehilight" => match non_empty(args) {
            Some(pattern) => Highlight {
                add: verb != "dehilight",
                pattern,
            },
            None => Usage("/hilight <pattern>"),
        },
        "ignore" | "unignore" => match words(args).as_slice() {
            [mask] => Ignore {
                add: verb == "ignore",
                mask: mask.clone(),
            },
            _ => Usage("/ignore <nick!user@host>"),
        },
        "notify" | "watch" => {
            let nicks = words(args);
            if nicks.is_empty() {
                Usage("/notify <nick> [nick...]")
            } else {
                Notify(nicks)
            }
        }
        "alias" => {
            let (name, expansion) = split_word(args);
            let name = name.trim_start_matches('/').to_ascii_lowercase();
            let expansion = expansion.trim_start_matches('/');
            if name.is_empty() || expansion.is_empty() {
                Usage("/alias <name> <expansion>")
            } else {
                AliasDefine {
                    name,
                    expansion: expansion.to_string(),
                }
            }
        }
        "unalias" => match words(args).as_slice() {
            [name] => Unalias(name.trim_start_matches('/').to_ascii_lowercase()),
            _ => Usage("/unalias <name>"),
        },
        "ame" | "amsg" => match non_empty(args) {
            Some(text) => FanOut {
                action: verb == "ame",
                text,
            },
            None if verb == "ame" => Usage("/ame <text>"),
            None => Usage("/amsg <text>"),
        },
        other => match service_nick(other) {
            Some(service) if !args.is_empty() => Msg {
                target: service.to_string(),
                text: args.to_string(),
            },
            Some(_) => Usage("/ns <command>"),
            None => Unknown(format!("/{other}")),
        },
    };
    Some(command)
}

/// How many aliases may expand into one another before the chain is
/// refused, as in Cicchetto.
pub const MAX_ALIAS_DEPTH: usize = 5;

/// Expands the user's aliases (`name -> expansion`, names without the
/// slash) at the head of a slash command, the way Cicchetto does before
/// dispatching: `$1`..`$9` take one argument (missing ones are empty), `$N-`
/// the Nth argument and the rest joined by single spaces, `$*` the raw
/// argument text, and an expansion without placeholders gets the arguments
/// appended. `/alias` and `/unalias` are never expanded. The short forms
/// `/w` and `/n` become `/whois` and `/names`. Returns the line to parse, or
/// the alias chain when it runs deeper than [`MAX_ALIAS_DEPTH`].
pub fn expand_aliases(input: &str, aliases: &HashMap<String, String>) -> Result<String, String> {
    let line = input.trim();
    let Some(stripped) = line.strip_prefix('/') else {
        return Ok(input.to_string());
    };
    if stripped.starts_with('/') {
        return Ok(input.to_string());
    }
    let (first, first_rest) = split_word(stripped);
    let (mut verb, mut rest) = (first.to_string(), first_rest.to_string());
    let mut chain = vec![verb.to_ascii_lowercase()];
    let mut expanded_any = false;
    for depth in 0.. {
        let lower = verb.to_ascii_lowercase();
        if lower == "alias" || lower == "unalias" {
            break;
        }
        let Some(template) = aliases.iter().find_map(|(name, expansion)| {
            name.trim_start_matches('/')
                .eq_ignore_ascii_case(&lower)
                .then_some(expansion)
        }) else {
            break;
        };
        if depth >= MAX_ALIAS_DEPTH {
            return Err(chain.join(" → "));
        }
        let expanded = substitute_alias(template.trim_start_matches('/'), &rest);
        let (next_verb, next_rest) = split_word(expanded.trim());
        verb = next_verb.to_string();
        rest = next_rest.to_string();
        chain.push(verb.to_ascii_lowercase());
        expanded_any = true;
    }
    let short_form = match verb.to_ascii_lowercase().as_str() {
        "w" => Some("whois"),
        "n" => Some("names"),
        _ => None,
    };
    if !expanded_any && short_form.is_none() {
        return Ok(input.to_string());
    }
    let verb = short_form.map(str::to_string).unwrap_or(verb);
    Ok(if rest.is_empty() {
        format!("/{verb}")
    } else {
        format!("/{verb} {rest}")
    })
}

/// Fills an alias template from the arguments typed after it.
fn substitute_alias(template: &str, rest: &str) -> String {
    let args: Vec<&str> = rest.split_whitespace().collect();
    let bytes = template.as_bytes();
    let mut out = String::new();
    let mut substituted = false;
    let mut index = 0;
    while index < template.len() {
        if bytes[index] == b'$' {
            match bytes.get(index + 1).copied() {
                Some(b'*') => {
                    out.push_str(rest);
                    substituted = true;
                    index += 2;
                    continue;
                }
                Some(digit @ b'1'..=b'9') => {
                    let position = usize::from(digit - b'1');
                    if bytes.get(index + 2) == Some(&b'-') {
                        let tail = args.get(position..).unwrap_or_default();
                        out.push_str(&tail.join(" "));
                        index += 3;
                    } else {
                        out.push_str(args.get(position).copied().unwrap_or_default());
                        index += 2;
                    }
                    substituted = true;
                    continue;
                }
                _ => {}
            }
        }
        let character = template[index..].chars().next().unwrap_or_default();
        out.push(character);
        index += character.len_utf8();
    }
    if substituted {
        out
    } else if rest.is_empty() {
        template.to_string()
    } else {
        format!("{template} {rest}")
    }
}

#[cfg(test)]
mod tests {
    use super::SlashCommand::*;
    use super::*;

    #[test]
    fn plain_text_and_escapes() {
        assert_eq!(parse("hello"), None);
        assert_eq!(parse("/"), None);
        assert_eq!(parse("//etc/hosts"), Some(Say("/etc/hosts".to_string())));
        assert_eq!(parse("/frob x"), Some(Unknown("/frob".to_string())));
    }

    #[test]
    fn me_msg_notice_and_query() {
        assert_eq!(
            parse("/me waves  hi"),
            Some(Action("waves  hi".to_string()))
        );
        assert_eq!(
            parse("/MSG alice hi there"),
            Some(Msg {
                target: "alice".to_string(),
                text: "hi there".to_string()
            })
        );
        assert!(matches!(parse("/msg #rust hi"), Some(Usage(_))));
        assert!(matches!(parse("/msg alice"), Some(Usage(_))));
        assert_eq!(
            parse("/notice #rust heads up"),
            Some(Notice {
                target: "#rust".to_string(),
                text: "heads up".to_string()
            })
        );
        assert_eq!(parse("/q bob"), Some(Query(Some("bob".to_string()))));
        assert_eq!(parse("/query"), Some(Query(None)));
        assert_eq!(
            parse("/ns identify secret"),
            Some(Msg {
                target: "NickServ".to_string(),
                text: "identify secret".to_string()
            })
        );
        assert!(is_service_nick("ChanServ"));
        assert!(!is_service_nick("serv"));
    }

    #[test]
    fn join_part_cycle_and_topic() {
        assert_eq!(
            parse("/join rust"),
            Some(Join {
                channels: "#rust".to_string(),
                key: None
            })
        );
        assert_eq!(
            parse("/j #a,#b key"),
            Some(Join {
                channels: "#a,#b".to_string(),
                key: Some("key".to_string())
            })
        );
        assert!(matches!(parse("/join a,b"), Some(Usage(_))));
        assert!(matches!(parse("/join"), Some(Usage(_))));
        assert_eq!(
            parse("/part"),
            Some(Part {
                channel: None,
                reason: None
            })
        );
        assert_eq!(
            parse("/part #rust bye all"),
            Some(Part {
                channel: Some("#rust".to_string()),
                reason: Some("bye all".to_string())
            })
        );
        assert_eq!(
            parse("/cycle see you"),
            Some(Cycle {
                channel: None,
                reason: Some("see you".to_string())
            })
        );
        assert_eq!(
            parse("/topic new topic"),
            Some(TopicSet {
                channel: None,
                text: "new topic".to_string()
            })
        );
        assert_eq!(
            parse("/topic #rust -delete"),
            Some(TopicClear {
                channel: Some("#rust".to_string())
            })
        );
        assert_eq!(
            parse("/topic # #rust rocks"),
            Some(TopicSet {
                channel: None,
                text: "#rust rocks".to_string()
            })
        );
        assert_eq!(parse("/topic"), Some(TopicShow { channel: None }));
        assert_eq!(
            parse("/topic #rust"),
            Some(TopicShow {
                channel: Some("#rust".to_string())
            })
        );
    }

    #[test]
    fn session_verbs() {
        assert_eq!(parse("/nick neo"), Some(Nick("neo".to_string())));
        assert!(matches!(parse("/nick a b"), Some(Usage(_))));
        assert_eq!(parse("/away"), Some(Away(None)));
        assert_eq!(parse("/away :"), Some(Away(None)));
        assert_eq!(parse("/away :lunch"), Some(Away(Some("lunch".to_string()))));
        assert_eq!(
            parse("/disconnect libera going home"),
            Some(Disconnect {
                network: Some("libera".to_string()),
                reason: Some("going home".to_string())
            })
        );
        assert_eq!(
            parse("/reconnect"),
            Some(Reconnect {
                network: None,
                reason: None
            })
        );
        assert_eq!(
            parse("/connect libera"),
            Some(Connect("libera".to_string()))
        );
        assert_eq!(parse("/quit bye"), Some(Quit(Some("bye".to_string()))));
    }

    #[test]
    fn ctcp_and_ping() {
        assert_eq!(
            parse("/ctcp bob version"),
            Some(Ctcp {
                target: "bob".to_string(),
                verb: "VERSION".to_string(),
                args: None
            })
        );
        assert_eq!(parse("/ping bob"), Some(Ping("bob".to_string())));
        assert!(matches!(parse("/ctcp bob"), Some(Usage(_))));
    }

    #[test]
    fn operator_verbs() {
        assert_eq!(
            parse("/voice a b"),
            Some(NickModes {
                verb: "voice",
                nicks: vec!["a".to_string(), "b".to_string()]
            })
        );
        assert!(matches!(parse("/op"), Some(Usage(_))));
        assert_eq!(
            parse("/kick troll go away"),
            Some(Kick {
                nick: "troll".to_string(),
                reason: "go away".to_string()
            })
        );
        assert_eq!(
            parse("/kickban troll bye"),
            Some(KickBan {
                nick: "troll".to_string(),
                reason: "bye".to_string()
            })
        );
        assert!(matches!(parse("/kb"), Some(Usage(_))));
        assert_eq!(parse("/ban *!*@spam"), Some(Ban("*!*@spam".to_string())));
        assert_eq!(
            parse("/unban *!*@spam"),
            Some(Unban("*!*@spam".to_string()))
        );
        assert_eq!(
            parse("/mode +o alice"),
            Some(Mode {
                target: None,
                modes: "+o".to_string(),
                params: vec!["alice".to_string()]
            })
        );
        assert_eq!(
            parse("/mode #rust +k secret"),
            Some(Mode {
                target: Some("#rust".to_string()),
                modes: "+k".to_string(),
                params: vec!["secret".to_string()]
            })
        );
        assert_eq!(
            parse("/mode #rust"),
            Some(ModeShow {
                channel: Some("#rust".to_string())
            })
        );
        assert_eq!(parse("/mode"), Some(ModeShow { channel: None }));
        assert!(matches!(parse("/mode alice"), Some(Usage(_))));
        assert_eq!(parse("/umode +i"), Some(Umode("+i".to_string())));
        assert_eq!(parse("/umode"), Some(UmodeShow));
        assert_eq!(parse("/names"), Some(Names(None)));
        assert_eq!(
            parse("/quote PRIVMSG x :y"),
            Some(Raw("PRIVMSG x :y".to_string()))
        );
        assert_eq!(
            parse("/kill bot spam"),
            Some(Raw("KILL bot :spam".to_string()))
        );
        assert_eq!(parse("/stats u"), Some(Raw("STATS u".to_string())));
        assert_eq!(parse("/rehash"), Some(Raw("REHASH".to_string())));
        assert_eq!(
            parse("/oper admin hunter2"),
            Some(Oper {
                name: "admin".to_string(),
                password: "hunter2".to_string()
            })
        );
        assert!(matches!(parse("/oper admin"), Some(Usage(_))));
    }

    #[test]
    fn aliases_expand_like_cicchetto() {
        let aliases: HashMap<String, String> = [
            ("k", "kick $1 $2-"),
            ("wii", "/whois $1 $1"),
            ("hi", "msg $1 hello   there"),
            ("say", "me says $*"),
            ("j2", "join"),
            ("loop", "loop"),
        ]
        .into_iter()
        .map(|(name, expansion)| (name.to_string(), expansion.to_string()))
        .collect();
        let expand = |line: &str| expand_aliases(line, &aliases);
        assert_eq!(expand("hello"), Ok("hello".to_string()));
        assert_eq!(expand("//k x"), Ok("//k x".to_string()));
        assert_eq!(expand("/me waves"), Ok("/me waves".to_string()));
        assert_eq!(
            expand("/k troll go  away"),
            Ok("/kick troll go away".to_string())
        );
        assert_eq!(expand("/WII bob"), Ok("/whois bob bob".to_string()));
        assert_eq!(expand("/k"), Ok("/kick".to_string()));
        assert_eq!(expand("/say a  b"), Ok("/me says a  b".to_string()));
        assert_eq!(expand("/j2 #rust"), Ok("/join #rust".to_string()));
        assert_eq!(expand("/w alice"), Ok("/whois alice".to_string()));
        assert_eq!(expand("/n"), Ok("/names".to_string()));
        assert_eq!(expand("/alias k whois"), Ok("/alias k whois".to_string()));
        assert!(expand("/loop").is_err());
    }

    #[test]
    fn alias_and_fan_out_verbs() {
        assert_eq!(
            parse("/alias /K kick $1"),
            Some(AliasDefine {
                name: "k".to_string(),
                expansion: "kick $1".to_string()
            })
        );
        assert!(matches!(parse("/alias k"), Some(Usage(_))));
        assert_eq!(parse("/unalias K"), Some(Unalias("k".to_string())));
        assert_eq!(
            parse("/ame waves"),
            Some(FanOut {
                action: true,
                text: "waves".to_string()
            })
        );
        assert!(matches!(parse("/amsg"), Some(Usage(_))));
        assert_eq!(
            parse("/hs help"),
            Some(Msg {
                target: "HelpServ".to_string(),
                text: "help".to_string()
            })
        );
    }

    #[test]
    fn list_verbs() {
        assert_eq!(
            parse("/hilight rust*"),
            Some(Highlight {
                add: true,
                pattern: "rust*".to_string()
            })
        );
        assert_eq!(
            parse("/dehilight rust*"),
            Some(Highlight {
                add: false,
                pattern: "rust*".to_string()
            })
        );
        assert_eq!(
            parse("/unignore *!*@spam"),
            Some(Ignore {
                add: false,
                mask: "*!*@spam".to_string()
            })
        );
        assert_eq!(
            parse("/watch a b"),
            Some(Notify(vec!["a".to_string(), "b".to_string()]))
        );
        assert!(matches!(parse("/notify"), Some(Usage(_))));
    }
}
