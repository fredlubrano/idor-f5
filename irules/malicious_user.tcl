# malicious_user.tcl
# BIG-IP Malicious User - scoring + IDOR counters + cooling-off + mitigation
# Placeholders like POINTS_FORBIDDEN are filled by scripts/render_irule.py from config/default.yaml

when RULE_INIT {
    set static::mu_points_forbidden {{POINTS_FORBIDDEN}}
    set static::mu_points_failed_login {{POINTS_FAILED_LOGIN}}
    set static::mu_points_waf {{POINTS_WAF}}
    set static::mu_points_rate {{POINTS_RATE}}
    set static::mu_points_distinct {{POINTS_DISTINCT}}
    set static::mu_points_sequential {{POINTS_SEQUENTIAL}}
    set static::mu_points_forbid_ratio {{POINTS_FORBID_RATIO}}
    set static::mu_points_success_enum {{POINTS_SUCCESS_ENUM}}
    set static::mu_points_template_focus {{POINTS_TEMPLATE_FOCUS}}
    set static::mu_points_bytes {{POINTS_BYTES}}

    set static::mu_thresh_low {{THR_LOW}}
    set static::mu_thresh_med {{THR_MEDIUM}}
    set static::mu_thresh_high {{THR_HIGH}}

    set static::mu_cooling {{COOLING_OFF_SECONDS}}
    set static::mu_window {{WINDOW_SECONDS}}
    set static::mu_rate_limit_rps {{RATE_LIMIT_RPS}}
    set static::mu_block_ttl {{BLOCK_TTL_SECONDS}}
    set static::mu_score_ttl 86400
    set static::mu_table_prefix "mu:"

    set static::mu_idor_distinct_n {{IDOR_DISTINCT_THRESHOLD}}
    set static::mu_idor_seq_ratio {{IDOR_SEQUENTIAL_THRESHOLD}}
    set static::mu_idor_forbid_ratio {{IDOR_FORBID_THRESHOLD}}
    set static::mu_idor_success_ids {{IDOR_SUCCESS_ENUM_THRESHOLD}}
    set static::mu_idor_focus {{IDOR_TEMPLATE_FOCUS_THRESHOLD}}
    set static::mu_idor_bytes_n {{IDOR_BYTES_THRESHOLD}}

    set static::mu_w_distinct {{W_DISTINCT}}
    set static::mu_w_rate {{W_RATE}}
    set static::mu_w_seq {{W_SEQUENTIAL}}
    set static::mu_w_focus {{W_FOCUS}}
    set static::mu_w_bytes {{W_BYTES}}

    set static::mu_ai_enabled {{AI_ENABLED}}
    set static::mu_ai_amb_min {{AI_AMBIGUOUS_MIN}}
    set static::mu_ai_amb_max {{AI_AMBIGUOUS_MAX}}
    set static::mu_ai_sample_pct {{AI_SAMPLE_PERCENT}}
    set static::mu_ai_skip_high {{AI_SKIP_IF_HIGH}}
    set static::mu_ai_shadow {{AI_SHADOW}}
    set static::mu_ai_status_seq {{AI_FEATURE_STATUS_SEQ}}
    set static::mu_mit_shadow {{MITIGATION_SHADOW}}

    set static::mu_chal_cookie "{{CHALLENGE_COOKIE}}"
    set static::mu_identity_mode "{{IDENTITY_MODE}}"
    set static::mu_jwt_claim "{{JWT_CLAIM}}"
    set static::mu_cookie_name "{{COOKIE_NAME}}"
    set static::mu_header_name "{{HEADER_NAME}}"
    set static::mu_lx_plugin "{{LX_PLUGIN}}"
    set static::mu_lx_ext "{{LX_PLUGIN}}"
}

proc mu_user_key {} {
    switch -- $static::mu_identity_mode {
        jwt_sub {
            # Best-effort JWT payload claim (no signature verify in iRule MVP)
            if { [HTTP::header exists Authorization] } {
                set auth [HTTP::header Authorization]
                if { [regexp {(?i)^Bearer\s+([^\s]+)$} $auth -> tok] } {
                    set parts [split $tok "."]
                    if { [llength $parts] >= 2 } {
                        set payload [lindex $parts 1]
                        # base64url -> base64
                        set payload [string map {- + _ /} $payload]
                        set pad [expr { (4 - [string length $payload] % 4) % 4 }]
                        append payload [string repeat "=" $pad]
                        if { ![catch { b64decode $payload } json] } {
                            set claim $static::mu_jwt_claim
                            if { [regexp "\"$claim\"\\s*:\\s*\"(\[^\"\]+)\"" $json -> sub] } {
                                return "sub:$sub"
                            }
                        }
                    }
                }
            }
            return "ip:[IP::client_addr]"
        }
        cookie_header {
            if { $static::mu_cookie_name ne "" && [HTTP::cookie exists $static::mu_cookie_name] } {
                return "ck:[HTTP::cookie value $static::mu_cookie_name]"
            }
            if { $static::mu_header_name ne "" && [HTTP::header exists $static::mu_header_name] } {
                return "hdr:[HTTP::header value $static::mu_header_name]"
            }
            return "ip:[IP::client_addr]"
        }
        default {
            return "ip:[IP::client_addr]"
        }
    }
}

proc mu_tkey {suffix} {
    return "${static::mu_table_prefix}[call mu_user_key]:${suffix}"
}

proc mu_now {} {
    return [clock seconds]
}

proc mu_clamp_score {s} {
    if { $s < 0 } { return 0 }
    if { $s > 200 } { return 200 }
    return $s
}

proc mu_level_from_score {score} {
    if { $score >= $static::mu_thresh_high } { return "high" }
    if { $score >= $static::mu_thresh_med } { return "medium" }
    if { $score >= $static::mu_thresh_low } { return "low" }
    return "none"
}

proc mu_level_rank {level} {
    switch -- $level {
        high { return 3 }
        medium { return 2 }
        low { return 1 }
        default { return 0 }
    }
}

proc mu_rank_to_level {rank} {
    switch -- $rank {
        3 { return "high" }
        2 { return "medium" }
        1 { return "low" }
        default { return "none" }
    }
}

proc mu_table_get {key default} {
    set v [table lookup $key]
    if { $v eq "" } { return $default }
    return $v
}

proc mu_table_set {key value ttl} {
    table set $key $value $ttl $ttl
}

proc mu_incr {key ttl} {
    set n [table incr $key]
    if { $n == 1 } {
        table lifetime $key $ttl
    }
    return $n
}

proc mu_is_login_path {mu_path} {
    set mu_is_login 0
{{LOGIN_PATH_MATCH_BODY}}
    return $mu_is_login
}

proc mu_is_object_path {path} {
{{OBJECT_PATH_MATCH_BODY}}
    return 0
}

proc mu_extract_object_id {path} {
    if { [regexp {/([^/]+)$} $path -> id] } {
        return $id
    }
    return ""
}

proc mu_normalize_template {path} {
    regsub {/\d+$} $path {/{id}} path
    regsub {/[0-9a-fA-F-]{8,}$} $path {/{id}} path
    return $path
}

proc mu_apply_cooling {} {
    set last_abuse [call mu_table_get [call mu_tkey last_abuse] 0]
    set level [call mu_table_get [call mu_tkey level] "none"]
    set score [call mu_table_get [call mu_tkey score] 0]
    set now [call mu_now]

    if { $last_abuse == 0 || $level eq "none" } {
        return [list $score $level]
    }

    set idle [expr { $now - $last_abuse }]
    if { $idle < $static::mu_cooling } {
        return [list $score $level]
    }

    set steps [expr { int($idle / $static::mu_cooling) }]
    set rank [call mu_level_rank $level]
    set rank [expr { $rank - $steps }]
    if { $rank < 0 } { set rank 0 }
    set level [call mu_rank_to_level $rank]

    switch -- $level {
        high { set score $static::mu_thresh_high }
        medium { set score $static::mu_thresh_med }
        low { set score $static::mu_thresh_low }
        default { set score 0 }
    }

    call mu_table_set [call mu_tkey score] $score $static::mu_score_ttl
    call mu_table_set [call mu_tkey level] $level $static::mu_score_ttl
    call mu_table_set [call mu_tkey last_abuse] [expr { $last_abuse + ($steps * $static::mu_cooling) }] $static::mu_score_ttl
    return [list $score $level]
}

proc mu_add_points {pts reason} {
    set score [call mu_table_get [call mu_tkey score] 0]
    set score [call mu_clamp_score [expr { $score + $pts }]]
    set level [call mu_level_from_score $score]
    call mu_table_set [call mu_tkey score] $score $static::mu_score_ttl
    call mu_table_set [call mu_tkey level] $level $static::mu_score_ttl
    call mu_table_set [call mu_tkey last_abuse] [call mu_now] $static::mu_score_ttl
    call mu_table_set [call mu_tkey last_reason] $reason $static::mu_score_ttl
    return [list $score $level]
}

proc mu_norm {value cap} {
    if { $cap <= 0 } { return 0.0 }
    set n [expr { double($value) / double($cap) }]
    if { $n > 1.0 } { set n 1.0 }
    if { $n < 0.0 } { set n 0.0 }
    return $n
}

proc mu_idor_track_request {path} {
    if { ![call mu_is_object_path $path] } { return }

    set id [call mu_extract_object_id $path]
    set tmpl [call mu_normalize_template $path]

    call mu_incr [call mu_tkey idor_req] $static::mu_window

    if { $id ne "" } {
        set idkey [call mu_tkey "oid:$id"]
        if { [table lookup $idkey] eq "" } {
            call mu_table_set $idkey 1 $static::mu_window
            call mu_incr [call mu_tkey idor_distinct] $static::mu_window
        }
        if { [string is integer -strict $id] } {
            set last [call mu_table_get [call mu_tkey last_oid] ""]
            if { $last ne "" && [string is integer -strict $last] } {
                set delta [expr { abs($id - $last) }]
                if { $delta == 1 } {
                    call mu_incr [call mu_tkey idor_seq_hits] $static::mu_window
                }
                call mu_incr [call mu_tkey idor_seq_total] $static::mu_window
            }
            call mu_table_set [call mu_tkey last_oid] $id $static::mu_window
        }
    }

    if { $tmpl ne "" } {
        set tkey [call mu_tkey "tmpl:[string map {/ _ \{ _ \} _} $tmpl]"]
        call mu_incr $tkey $static::mu_window
        call mu_table_set [call mu_tkey last_tmpl] $tmpl $static::mu_window
    }
}

proc mu_idor_track_response {status bytes is_object} {
    if { !$is_object } {
        return [list [call mu_table_get [call mu_tkey score] 0] [call mu_table_get [call mu_tkey level] "none"]]
    }

    call mu_incr [call mu_tkey idor_resp] $static::mu_window
    if { $status == 200 } {
        call mu_incr [call mu_tkey idor_ok] $static::mu_window
    } elseif { $status == 403 || $status == 404 } {
        call mu_incr [call mu_tkey idor_forbid] $static::mu_window
    }

    # Optional status sequence ring (last few codes) for AI
    if { $static::mu_ai_status_seq } {
        set seq [call mu_table_get [call mu_tkey status_seq] ""]
        append seq "$status,"
        set parts [split $seq ","]
        if { [llength $parts] > 12 } {
            set parts [lrange $parts end-11 end]
            set seq [join $parts ","]
        }
        call mu_table_set [call mu_tkey status_seq] $seq $static::mu_window
    }

    if { $bytes > 0 } {
        set sum [expr { [call mu_table_get [call mu_tkey idor_bytes] 0] + $bytes }]
        call mu_table_set [call mu_tkey idor_bytes] $sum $static::mu_window
    }

    set distinct [call mu_table_get [call mu_tkey idor_distinct] 0]
    set reqs [call mu_table_get [call mu_tkey idor_req] 0]
    set resp [call mu_table_get [call mu_tkey idor_resp] 0]
    set ok [call mu_table_get [call mu_tkey idor_ok] 0]
    set forbid [call mu_table_get [call mu_tkey idor_forbid] 0]
    set seq_hits [call mu_table_get [call mu_tkey idor_seq_hits] 0]
    set seq_total [call mu_table_get [call mu_tkey idor_seq_total] 0]
    set bytesum [call mu_table_get [call mu_tkey idor_bytes] 0]

    set seq_ratio 0.0
    if { $seq_total > 0 } {
        set seq_ratio [expr { double($seq_hits) / double($seq_total) }]
    }
    set forbid_ratio 0.0
    if { $resp > 0 } {
        set forbid_ratio [expr { double($forbid) / double($resp) }]
    }
    set ok_ratio 0.0
    if { $resp > 0 } {
        set ok_ratio [expr { double($ok) / double($resp) }]
    }

    set focus 0.0
    set last_tmpl [call mu_table_get [call mu_tkey last_tmpl] ""]
    if { $last_tmpl ne "" && $reqs > 0 } {
        set tkey [call mu_tkey "tmpl:[string map {/ _ \{ _ \} _} $last_tmpl]"]
        set tcount [call mu_table_get $tkey 0]
        set focus [expr { double($tcount) / double($reqs) }]
    }

    set rate_cap 100
    if { $static::mu_window > 0 } {
        set rate_cap [expr { int($static::mu_window / 3) }]
        if { $rate_cap < 1 } { set rate_cap 1 }
    }
    set rate_norm [call mu_norm $reqs $rate_cap]
    set n_distinct [call mu_norm $distinct $static::mu_idor_distinct_n]
    set n_bytes [call mu_norm $bytesum $static::mu_idor_bytes_n]
    set aspiration [expr {
        $static::mu_w_distinct * $n_distinct +
        $static::mu_w_rate * $rate_norm +
        $static::mu_w_seq * $seq_ratio +
        $static::mu_w_focus * $focus +
        $static::mu_w_bytes * $n_bytes
    }]

    set added 0
    set reason ""

    if { $distinct >= $static::mu_idor_distinct_n } {
        set added [expr { $added + $static::mu_points_distinct }]
        append reason "distinct_ids;"
    }
    if { $seq_ratio >= $static::mu_idor_seq_ratio && $seq_total >= 5 } {
        set added [expr { $added + $static::mu_points_sequential }]
        append reason "sequential;"
    }
    if { $forbid_ratio >= $static::mu_idor_forbid_ratio && $resp >= 10 } {
        set added [expr { $added + $static::mu_points_forbid_ratio }]
        append reason "forbid_ratio;"
    }
    if { $distinct >= $static::mu_idor_success_ids && $ok_ratio >= 0.7 } {
        set added [expr { $added + $static::mu_points_success_enum }]
        append reason "success_enum;"
        call mu_table_set [call mu_tkey aspiration] 1 $static::mu_window
    }
    if { $focus >= $static::mu_idor_focus && $reqs >= 10 } {
        set added [expr { $added + $static::mu_points_template_focus }]
        append reason "template_focus;"
    }
    if { $bytesum >= $static::mu_idor_bytes_n } {
        set added [expr { $added + $static::mu_points_bytes }]
        append reason "bytes;"
    }
    if { $aspiration >= 0.55 } {
        call mu_table_set [call mu_tkey aspiration] 1 $static::mu_window
        append reason "aspiration;"
    }

    call mu_table_set [call mu_tkey feat_distinct] $distinct $static::mu_score_ttl
    call mu_table_set [call mu_tkey feat_seq_ratio] $seq_ratio $static::mu_score_ttl
    call mu_table_set [call mu_tkey feat_forbid_ratio] $forbid_ratio $static::mu_score_ttl
    call mu_table_set [call mu_tkey feat_ok_ratio] $ok_ratio $static::mu_score_ttl
    call mu_table_set [call mu_tkey feat_reqs] $reqs $static::mu_score_ttl
    call mu_table_set [call mu_tkey feat_bytes] $bytesum $static::mu_score_ttl
    call mu_table_set [call mu_tkey feat_focus] $focus $static::mu_score_ttl
    call mu_table_set [call mu_tkey feat_aspiration] $aspiration $static::mu_score_ttl
    call mu_table_set [call mu_tkey feat_template] $last_tmpl $static::mu_score_ttl

    if { $added > 0 } {
        return [call mu_add_points $added "idor:$reason"]
    }
    return [list [call mu_table_get [call mu_tkey score] 0] [call mu_table_get [call mu_tkey level] "none"]]
}

proc mu_ai_should_call {score level} {
    if { !$static::mu_ai_enabled } { return 0 }
    if { $static::mu_ai_skip_high && $level eq "high" } { return 0 }

    set ai_ts [call mu_table_get [call mu_tkey ai_ts] 0]
    set now [call mu_now]
    if { $ai_ts > 0 && [expr { $now - $ai_ts }] < 60 } {
        return 0
    }

    if { $score >= $static::mu_ai_amb_min && $score <= $static::mu_ai_amb_max } {
        return 1
    }
    if { $static::mu_ai_sample_pct > 0 } {
        if { [expr { int(rand() * 100) }] < $static::mu_ai_sample_pct } {
            return 1
        }
    }
    return 0
}

proc mu_ai_apply_result {action} {
    set score [call mu_table_get [call mu_tkey score] 0]
    set level [call mu_table_get [call mu_tkey level] "none"]

    if { $static::mu_ai_shadow } {
        call mu_table_set [call mu_tkey ai_shadow_action] $action $static::mu_score_ttl
        return [list $score $level]
    }

    switch -- $action {
        dismiss {
            set rank [expr { [call mu_level_rank $level] - 1 }]
            if { $rank < 0 } { set rank 0 }
            set level [call mu_rank_to_level $rank]
            switch -- $level {
                high { set score $static::mu_thresh_high }
                medium { set score $static::mu_thresh_med }
                low { set score $static::mu_thresh_low }
                default { set score 0 }
            }
        }
        boost {
            set rank [expr { [call mu_level_rank $level] + 1 }]
            if { $rank > 3 } { set rank 3 }
            set level [call mu_rank_to_level $rank]
            switch -- $level {
                high { set score $static::mu_thresh_high }
                medium { set score $static::mu_thresh_med }
                low { set score $static::mu_thresh_low }
                default { set score 0 }
            }
        }
        default {
            # confirm: keep
        }
    }

    call mu_table_set [call mu_tkey score] $score $static::mu_score_ttl
    call mu_table_set [call mu_tkey level] $level $static::mu_score_ttl
    call mu_table_set [call mu_tkey ai_action] $action $static::mu_score_ttl
    return [list $score $level]
}

proc mu_build_ai_payload {} {
    set user [call mu_user_key]
    set user_esc [string map {"\\" "\\\\" "\"" "\\\""} $user]
    set tmpl [call mu_table_get [call mu_tkey feat_template] ""]
    set tmpl_esc [string map {"\\" "\\\\" "\"" "\\\""} $tmpl]
    set status_seq [call mu_table_get [call mu_tkey status_seq] ""]
    set status_esc [string map {"\\" "\\\\" "\"" "\\\""} $status_seq]
    set auth 0
    if { [HTTP::header exists Authorization] || [HTTP::cookie names] ne "" } {
        set auth 1
    }

    set lb [format %c 123]
    set rb [format %c 125]
    set json $lb
    append json "\"user_id\":\"$user_esc\","
    append json "\"score\":[call mu_table_get [call mu_tkey score] 0],"
    append json "\"level\":\"[call mu_table_get [call mu_tkey level] none]\","
    append json "\"auth_present\":$auth,"
    append json "\"features\":$lb"
    append json "\"distinct_object_ids\":[call mu_table_get [call mu_tkey feat_distinct] 0],"
    append json "\"sequential_ratio\":[call mu_table_get [call mu_tkey feat_seq_ratio] 0],"
    append json "\"forbid_ratio\":[call mu_table_get [call mu_tkey feat_forbid_ratio] 0],"
    append json "\"ok_ratio\":[call mu_table_get [call mu_tkey feat_ok_ratio] 0],"
    append json "\"req_count\":[call mu_table_get [call mu_tkey feat_reqs] 0],"
    append json "\"response_bytes_sum\":[call mu_table_get [call mu_tkey feat_bytes] 0],"
    append json "\"template_focus\":[call mu_table_get [call mu_tkey feat_focus] 0],"
    append json "\"aspiration_score\":[call mu_table_get [call mu_tkey feat_aspiration] 0],"
    append json "\"path_template\":\"$tmpl_esc\","
    append json "\"status_seq\":\"$status_esc\""
    append json "$rb$rb"
    return $json
}

proc mu_js_challenge {hard} {
    set delay 0
    if { $hard } { set delay 1500 }
    set token [format %08x [expr { int(rand() * 0xffffffff) }]]
    call mu_table_set [call mu_tkey challenge] $token 300
    set cname $static::mu_chal_cookie

    set lb [format %c 123]
    set rb [format %c 125]
    set dq [format %c 34]
    set html "<!DOCTYPE html><html><head><meta charset=${dq}utf-8${dq}><title>Checking your browser</title>"
    append html "<script>(function()${lb}var t='$token';var d=$delay;var c='$cname';"
    append html "setTimeout(function()${lb}document.cookie=c+'='+t+'; Path=/';location.reload();${rb},d);"
    append html "${rb})();</script></head><body><p>Verifying your session...</p></body></html>"

    HTTP::respond 503 content $html Content-Type "text/html; charset=utf-8" Retry-After 2 noserver
}

proc mu_challenge_passed {} {
    set expect [call mu_table_get [call mu_tkey challenge] ""]
    if { $expect eq "" } { return 0 }
    set cname $static::mu_chal_cookie
    if { [HTTP::cookie exists $cname] && [HTTP::cookie value $cname] eq $expect } {
        table delete [call mu_tkey challenge]
        return 1
    }
    return 0
}

proc mu_apply_mitigation {level} {
    upvar 1 mu_mit_action mu_mit_action
    if { ![info exists mu_mit_action] } { set mu_mit_action "-" }
    if { $static::mu_mit_shadow || $static::mu_ai_shadow } {
        log local0. "mu shadow mitigate level=$level score=[call mu_table_get [call mu_tkey score] 0]"
        return 0
    }
    set aspiration [call mu_table_get [call mu_tkey aspiration] 0]
    if { [call mu_table_get [call mu_tkey blocked] 0] } {
        set mu_mit_action "block"
        reject
        return 1
    }
    if { [call mu_challenge_passed] } { return 0 }

    switch -- $level {
        high {
            if { $aspiration } {
                set rl [call mu_incr [call mu_tkey rl_sec] 1]
                if { $rl > $static::mu_rate_limit_rps } {
                    set mu_mit_action "rate"
                    HTTP::respond 429 content "Too Many Requests" noserver
                    return 1
                }
                set hits [call mu_incr [call mu_tkey aspir_block_hits] 60]
                if { $hits > 20 } {
                    call mu_table_set [call mu_tkey blocked] 1 $static::mu_block_ttl
                    set mu_mit_action "block"
                    reject
                    return 1
                }
            } else {
                call mu_table_set [call mu_tkey blocked] 1 $static::mu_block_ttl
                set mu_mit_action "block"
                reject
                return 1
            }
        }
        medium {
            set mu_mit_action "challenge"
            call mu_js_challenge 1
            return 1
        }
        low {
            set mu_mit_action "challenge"
            call mu_js_challenge 0
            return 1
        }
        default { return 0 }
    }
    return 0
}

when HTTP_REQUEST {
    set mu_path [HTTP::path]
    set mu_is_object [call mu_is_object_path $mu_path]
    set mu_is_login [call mu_is_login_path $mu_path]
    set mu_log_req "[HTTP::method] [HTTP::uri]"
    set mu_log_client [IP::client_addr]
    set mu_mit_action "-"
    set mu_idor_logged 0

    set cooled [call mu_apply_cooling]
    set score [lindex $cooled 0]
    set level [lindex $cooled 1]

    set rate [call mu_incr [call mu_tkey req_rate] $static::mu_window]
    # ~2 rps average over window -> trip (tunable via YAML rate signal)
    if { $rate > [expr { $static::mu_window * 2 }] } {
        set r [call mu_add_points $static::mu_points_rate "rate_limit"]
        set score [lindex $r 0]
        set level [lindex $r 1]
    }

    call mu_idor_track_request $mu_path

    set pending [call mu_table_get [call mu_tkey ai_pending_action] ""]
    if { $pending ne "" } {
        set r [call mu_ai_apply_result $pending]
        set score [lindex $r 0]
        set level [lindex $r 1]
        table delete [call mu_tkey ai_pending_action]
    }

    if { [call mu_apply_mitigation $level] } {
        log local0.warn "MU-IDOR-ACT client=$mu_log_client req=\"$mu_log_req\" action=$mu_mit_action level=$level score=$score"
        set mu_idor_logged 1
        return
    }
    set mu_log_score $score
    set mu_log_level $level
}

when HTTP_RESPONSE {
    if { [info exists mu_idor_logged] && $mu_idor_logged } {
        return
    }
    if { ![info exists mu_is_login] } {
        set mu_is_login 0
    }
    if { ![info exists mu_is_object] } {
        set mu_is_object 0
    }
    if { ![info exists mu_log_req] } {
        set mu_log_req "-"
    }
    if { ![info exists mu_log_client] } {
        set mu_log_client "-"
    }

    set status [HTTP::status]
    set bytes 0
    if { [HTTP::header exists Content-Length] } {
        set bytes [HTTP::header Content-Length]
    }

    if { $mu_is_login && ($status == 401 || $status == 403) } {
        call mu_add_points $static::mu_points_failed_login "failed_login"
    }
    if { $status == 403 && !$mu_is_login } {
        call mu_add_points $static::mu_points_forbidden "forbidden"
    }

    set idor [call mu_idor_track_response $status $bytes $mu_is_object]
    set score [lindex $idor 0]
    set level [lindex $idor 1]
    set ai_action "-"

    # AI enrich via iRulesLX - fail-open
    if { [call mu_ai_should_call $score $level] } {
        set payload [call mu_build_ai_payload]
        set ai_action "confirm"
        if { [catch {
            set handle [ILX::init $static::mu_lx_plugin $static::mu_lx_ext]
            set rpc_resp [ILX::call $handle enrich $payload]
            if { [regexp {"action"\s*:\s*"(confirm|dismiss|boost)"} $rpc_resp -> a] } {
                set ai_action $a
            } elseif { $rpc_resp eq "confirm" || $rpc_resp eq "dismiss" || $rpc_resp eq "boost" } {
                set ai_action $rpc_resp
            }
        } err] } {
            log local0. "mu_ai fail-open: $err"
            set ai_action "fail-open"
        }
        call mu_table_set [call mu_tkey ai_ts] [call mu_now] $static::mu_score_ttl
        if { $ai_action ne "fail-open" } {
            call mu_table_set [call mu_tkey ai_pending_action] $ai_action $static::mu_score_ttl
            set r [call mu_ai_apply_result $ai_action]
            set score [lindex $r 0]
            set level [lindex $r 1]
        }
    }

    log local0.warn "MU-IDOR client=$mu_log_client req=\"$mu_log_req\" path_kind=$mu_is_object score=$score level=$level status=[HTTP::status] ai=$ai_action"
    set mu_idor_logged 1
}

# PRP Reject skips HTTP_RESPONSE (api-protection VS has no LTM access profile).
# ACCESS_* events need an ACCESS profile and fail verify (01071912). after is cancelled on TCP close.
when CLIENT_CLOSED {
    if { [info exists mu_idor_logged] && $mu_idor_logged } { return }
    if { ![info exists mu_log_req] } { return }
    if { ![info exists mu_is_object] } { set mu_is_object 0 }
    if { ![info exists mu_log_client] } { set mu_log_client "-" }
    if { ![info exists mu_log_score] } { set mu_log_score 0 }
    if { ![info exists mu_log_level] } { set mu_log_level none }
    log local0.warn "MU-IDOR client=$mu_log_client req=\"$mu_log_req\" path_kind=$mu_is_object score=$mu_log_score level=$mu_log_level status=403 ai=-"
    set mu_idor_logged 1
}

when ASM_REQUEST_DONE {
    if { [catch { ASM::violation count } vcount] } { return }
    if { $vcount > 0 } {
        call mu_add_points $static::mu_points_waf "waf_hit"
    }
}

when ASM_REQUEST_BLOCKING {
    call mu_add_points $static::mu_points_forbidden "asm_deny"
}
