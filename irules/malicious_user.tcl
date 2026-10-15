# =============================================================================
# BIG-IP Malicious User / Authenticated IDOR Aspiration Detection (malicious_user.tcl)
# Rendered by scripts/render_irule.py from config/default.yaml
# =============================================================================

when RULE_INIT {
    set static::mu_pts_forbidden {{POINTS_FORBIDDEN}}
    set static::mu_pts_failed_login {{POINTS_FAILED_LOGIN}}
    set static::mu_pts_waf {{POINTS_WAF}}
    set static::mu_pts_rate {{POINTS_RATE}}
    set static::mu_pts_distinct {{POINTS_DISTINCT}}
    set static::mu_pts_sequential {{POINTS_SEQUENTIAL}}
    set static::mu_pts_forbid_ratio {{POINTS_FORBID_RATIO}}
    set static::mu_pts_success_enum {{POINTS_SUCCESS_ENUM}}
    set static::mu_pts_template_focus {{POINTS_TEMPLATE_FOCUS}}
    set static::mu_pts_bytes {{POINTS_BYTES}}

    set static::mu_thresh_low {{THR_LOW}}
    set static::mu_thresh_med {{THR_MEDIUM}}
    set static::mu_thresh_high {{THR_HIGH}}
    set static::mu_cooling {{COOLING_OFF_SECONDS}}
    set static::mu_window {{WINDOW_SECONDS}}
    set static::mu_rate_rps {{RATE_LIMIT_RPS}}
    set static::mu_block_ttl {{BLOCK_TTL_SECONDS}}

    set static::mu_idor_distinct_thr {{IDOR_DISTINCT_THRESHOLD}}
    set static::mu_idor_seq_thr {{IDOR_SEQUENTIAL_THRESHOLD}}
    set static::mu_idor_forbid_thr {{IDOR_FORBID_THRESHOLD}}
    set static::mu_idor_success_thr {{IDOR_SUCCESS_ENUM_THRESHOLD}}
    set static::mu_idor_focus_thr {{IDOR_TEMPLATE_FOCUS_THRESHOLD}}
    set static::mu_idor_bytes_thr {{IDOR_BYTES_THRESHOLD}}
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
    set static::mu_mit_shadow {{MITIGATION_SHADOW}}
    set static::mu_ai_status_seq {{AI_FEATURE_STATUS_SEQ}}

    set static::mu_chal_cookie "{{CHALLENGE_COOKIE}}"
    set static::mu_identity_mode "{{IDENTITY_MODE}}"
    set static::mu_jwt_claim "{{JWT_CLAIM}}"
    set static::mu_cookie_name "{{COOKIE_NAME}}"
    set static::mu_header_name "{{HEADER_NAME}}"
    set static::mu_lx_plugin "{{LX_PLUGIN}}"
}

proc mu_is_object_path { path } {
{{OBJECT_PATH_MATCH_BODY}}
    return 0
}

proc mu_extract_object_id { path } {
    if { [regexp {/([0-9a-fA-F-]{1,64})$} $path -> oid] } {
        return $oid
    }
    return ""
}

proc mu_normalize_template { path } {
    regsub -all {/\d+} $path "/{id}" t
    regsub -all {/[0-9a-fA-F-]{8,}} $t "/{id}" t
    return $t
}

proc mu_level_from_score { score } {
    if { $score >= $static::mu_thresh_high } { return "high" }
    if { $score >= $static::mu_thresh_med } { return "medium" }
    if { $score >= $static::mu_thresh_low } { return "low" }
    return "none"
}

proc mu_level_rank { level } {
    switch -exact -- $level {
        "low"    { return 1 }
        "medium" { return 2 }
        "high"   { return 3 }
        default  { return 0 }
    }
}

proc mu_rank_to_level { rank } {
    if { $rank <= 0 } { return "none" }
    if { $rank == 1 } { return "low" }
    if { $rank == 2 } { return "medium" }
    return "high"
}

proc mu_apply_cooling { user_key now_ts } {
    set level [table lookup -notouch "mu:level:$user_key"]
    if { $level eq "" || $level eq "none" } {
        return "none"
    }
    set last_ts [table lookup -notouch "mu:last_abuse:$user_key"]
    if { $last_ts eq "" || $static::mu_cooling <= 0 } {
        return $level
    }
    set elapsed [expr { $now_ts - $last_ts }]
    if { $elapsed < $static::mu_cooling } {
        return $level
    }
    set steps [expr { int($elapsed / $static::mu_cooling) }]
    set rank [call mu_level_rank $level]
    set new_rank [expr { $rank - $steps }]
    set new_level [call mu_rank_to_level $new_rank]
    set new_last [expr { $last_ts + ($steps * $static::mu_cooling) }]

    table set "mu:level:$user_key" $new_level $static::mu_window 3600
    table set "mu:last_abuse:$user_key" $new_last $static::mu_window 3600

    if { $new_level eq "none" } {
        table set "mu:score:$user_key" 0 $static::mu_window 3600
    } elseif { $new_level eq "low" } {
        table set "mu:score:$user_key" $static::mu_thresh_low $static::mu_window 3600
    } elseif { $new_level eq "medium" } {
        table set "mu:score:$user_key" $static::mu_thresh_med $static::mu_window 3600
    }
    return $new_level
}

proc mu_add_points { user_key pts now_ts } {
    if { $pts <= 0 } {
        set cur [table lookup -notouch "mu:score:$user_key"]
        return [expr { $cur eq "" ? 0 : $cur }]
    }
    set cur [table lookup -notouch "mu:score:$user_key"]
    if { $cur eq "" } { set cur 0 }
    set next [expr { $cur + $pts }]
    if { $next > 200 } { set next 200 }
    table set "mu:score:$user_key" $next $static::mu_window 3600
    table set "mu:last_abuse:$user_key" $now_ts $static::mu_window 3600
    set lvl [call mu_level_from_score $next]
    table set "mu:level:$user_key" $lvl $static::mu_window 3600
    return $next
}

proc mu_award_once { user_key signal_name pts now_ts } {
    set latch_key "mu:latch:${signal_name}:${user_key}"
    if { [table lookup -notouch -- $latch_key] ne "" } {
        return 0
    }
    table set -- $latch_key 1 $static::mu_window $static::mu_window
    call mu_add_points $user_key $pts $now_ts
    return $pts
}

proc mu_ai_apply_result { user_key action } {
    if { $static::mu_ai_shadow } {
        table set "mu:ai_shadow_action:$user_key" $action $static::mu_window 3600
        return [table lookup -notouch "mu:level:$user_key"]
    }
    set level [table lookup -notouch "mu:level:$user_key"]
    if { $level eq "" } { set level "none" }
    set rank [call mu_level_rank $level]
    if { $action eq "boost" } {
        set rank [expr { $rank < 3 ? ($rank + 1) : 3 }]
    } elseif { $action eq "dismiss" } {
        set rank [expr { $rank > 0 ? ($rank - 1) : 0 }]
    }
    set new_level [call mu_rank_to_level $rank]
    table set "mu:level:$user_key" $new_level $static::mu_window 3600
    table set "mu:ai_last_action:$user_key" $action $static::mu_window 3600
    return $new_level
}

proc mu_apply_mitigation { user_key level has_chal_cookie is_obj_path } {
    if { $static::mu_mit_shadow || $level eq "" || $level eq "none" } {
        return "none"
    }
    if { $level eq "high" } {
        if { $is_obj_path } {
            set rkey "mu:high_rl:$user_key"
            set rcnt [table incr -notouch $rkey]
            if { $rcnt == 1 } {
                table timeout $rkey 1
                table lifetime $rkey 1
            }
            if { $rcnt > $static::mu_rate_rps } {
                return "rate"
            }
        }
        return "block"
    }
    if { !$has_chal_cookie } {
        return "challenge"
    }
    return "none"
}

when HTTP_REQUEST {
    set mu_now [clock seconds]
    set mu_path [HTTP::path]
    set mu_log_client [IP::client_addr]
    set mu_log_req "[HTTP::method] [HTTP::uri]"
    set mu_resp_seen 0

    set mu_is_login 0
{{LOGIN_PATH_MATCH_BODY}}

    set mu_path_kind [call mu_is_object_path $mu_path]
    set mu_obj_id ""
    set mu_tmpl ""
    if { $mu_path_kind } {
        set mu_obj_id [call mu_extract_object_id $mu_path]
        set mu_tmpl [call mu_normalize_template $mu_path]
    }

    set mu_user_key "ip:$mu_log_client"
    set mu_auth_present 0
    if { [HTTP::header exists "Authorization"] } {
        set mu_auth_present 1
    }
    if { $static::mu_identity_mode eq "jwt_sub" } {
        set mu_verified_sub ""
        if { [HTTP::header exists "X-Authenticated-Sub"] } {
            set mu_verified_sub [HTTP::header "X-Authenticated-Sub"]
        }
        if { $mu_verified_sub ne "" } {
            set mu_user_key "sub:$mu_verified_sub"
            set mu_auth_present 1
        }
    } elseif { $static::mu_identity_mode eq "cookie_header" } {
        if { $static::mu_cookie_name ne "" && [HTTP::cookie exists $static::mu_cookie_name] } {
            set mu_user_key "ck:[HTTP::cookie value $static::mu_cookie_name]"
            set mu_auth_present 1
        } elseif { $static::mu_header_name ne "" && [HTTP::header exists $static::mu_header_name] } {
            set mu_user_key "hdr:[HTTP::header $static::mu_header_name]"
            set mu_auth_present 1
        }
    }

    set mu_level [call mu_apply_cooling $mu_user_key $mu_now]
    set mu_score [table lookup -notouch "mu:score:$mu_user_key"]
    if { $mu_score eq "" } { set mu_score 0 }

    set mu_req_cnt [table incr -notouch "mu:req_cnt:$mu_user_key"]
    if { $mu_req_cnt == 1 } {
        table timeout "mu:req_cnt:$mu_user_key" $static::mu_window
        table lifetime "mu:req_cnt:$mu_user_key" $static::mu_window
    }
    if { $mu_req_cnt > [expr { $static::mu_rate_rps * 60 }] } {
        call mu_award_once $mu_user_key "rate_limit" $static::mu_pts_rate $mu_now
        set mu_score [table lookup -notouch "mu:score:$mu_user_key"]
        set mu_level [table lookup -notouch "mu:level:$mu_user_key"]
    }

    if { $mu_path_kind && $mu_obj_id ne "" } {
        set id_seen_key "mu:oid:${mu_user_key}:${mu_obj_id}"
        if { [table lookup -notouch $id_seen_key] eq "" } {
            table set $id_seen_key 1 $static::mu_window $static::mu_window
            set d_cnt [table incr -notouch "mu:distinct_ids:$mu_user_key"]
            if { $d_cnt == 1 } {
                table timeout "mu:distinct_ids:$mu_user_key" $static::mu_window
                table lifetime "mu:distinct_ids:$mu_user_key" $static::mu_window
            }
        }
        if { [string is integer -strict $mu_obj_id] } {
            set prev_id [table lookup -notouch "mu:last_oid:$mu_user_key"]
            if { $prev_id ne "" && [expr { abs($mu_obj_id - $prev_id) }] == 1 } {
                set s_hits [table incr -notouch "mu:seq_hits:$mu_user_key"]
                if { $s_hits == 1 } {
                    table timeout "mu:seq_hits:$mu_user_key" $static::mu_window
                    table lifetime "mu:seq_hits:$mu_user_key" $static::mu_window
                }
            }
            table set "mu:last_oid:$mu_user_key" $mu_obj_id $static::mu_window $static::mu_window
        }
        set o_req [table incr -notouch "mu:obj_reqs:$mu_user_key"]
        if { $o_req == 1 } {
            table timeout "mu:obj_reqs:$mu_user_key" $static::mu_window
            table lifetime "mu:obj_reqs:$mu_user_key" $static::mu_window
        }
    }

    set mu_has_chal [HTTP::cookie exists $static::mu_chal_cookie]
    set mu_act [call mu_apply_mitigation $mu_user_key $mu_level $mu_has_chal $mu_path_kind]
    if { $mu_act ne "none" } {
        log local0.warn "MU-IDOR-ACT client=$mu_log_client req=\"$mu_log_req\" action=$mu_act level=$mu_level score=$mu_score"
        if { $mu_act eq "challenge" } {
            HTTP::respond 503 content "<html><head><title>Checking your browser</title><script>document.cookie='${static::mu_chal_cookie}=1; path=/; max-age=300';location.reload();</script></head><body>Checking your browser...</body></html>" "Content-Type" "text/html" "Cache-Control" "no-store"
            return
        } elseif { $mu_act eq "rate" } {
            HTTP::respond 429 content "{\"error\":\"too_many_requests\"}" "Content-Type" "application/json" "Retry-After" "5"
            return
        } elseif { $mu_act eq "block" } {
            HTTP::respond 403 content "{\"error\":\"forbidden\"}" "Content-Type" "application/json"
            return
        }
    }
}

when HTTP_RESPONSE {
    set mu_resp_seen 1
    if { ![info exists mu_user_key] || $mu_user_key eq "" } {
        return
    }
    set mu_now [clock seconds]
    set mu_status [HTTP::status]
    set mu_ai_tag "-"

    if { $mu_is_login && $mu_status == 401 } {
        call mu_add_points $mu_user_key $static::mu_pts_failed_login $mu_now
    } elseif { !$mu_is_login && $mu_status == 403 } {
        call mu_add_points $mu_user_key $static::mu_pts_forbidden $mu_now
    }

    if { $mu_path_kind } {
        if { $mu_status == 200 } {
            set ok_cnt [table incr -notouch "mu:ok_cnt:$mu_user_key"]
            if { $ok_cnt == 1 } {
                table timeout "mu:ok_cnt:$mu_user_key" $static::mu_window
                table lifetime "mu:ok_cnt:$mu_user_key" $static::mu_window
            }
            if { [HTTP::header exists "Content-Length"] } {
                set clen [HTTP::header "Content-Length"]
                if { [string is integer -strict $clen] && $clen > 0 } {
                    set b_sum [table incr -notouch "mu:bytes_sum:$mu_user_key" $clen]
                    if { $b_sum == $clen } {
                        table timeout "mu:bytes_sum:$mu_user_key" $static::mu_window
                        table lifetime "mu:bytes_sum:$mu_user_key" $static::mu_window
                    }
                }
            }
        } elseif { $mu_status == 403 || $mu_status == 404 } {
            set fb_cnt [table incr -notouch "mu:forbid_cnt:$mu_user_key"]
            if { $fb_cnt == 1 } {
                table timeout "mu:forbid_cnt:$mu_user_key" $static::mu_window
                table lifetime "mu:forbid_cnt:$mu_user_key" $static::mu_window
            }
        }

        set d_cnt [table lookup -notouch "mu:distinct_ids:$mu_user_key"]
        if { $d_cnt eq "" } { set d_cnt 0 }
        set o_req [table lookup -notouch "mu:obj_reqs:$mu_user_key"]
        if { $o_req eq "" } { set o_req 1 }
        set s_hits [table lookup -notouch "mu:seq_hits:$mu_user_key"]
        if { $s_hits eq "" } { set s_hits 0 }
        set ok_cnt [table lookup -notouch "mu:ok_cnt:$mu_user_key"]
        if { $ok_cnt eq "" } { set ok_cnt 0 }
        set fb_cnt [table lookup -notouch "mu:forbid_cnt:$mu_user_key"]
        if { $fb_cnt eq "" } { set fb_cnt 0 }
        set b_sum [table lookup -notouch "mu:bytes_sum:$mu_user_key"]
        if { $b_sum eq "" } { set b_sum 0 }

        set seq_ratio [expr { $o_req > 1 ? (double($s_hits) / double($o_req - 1)) : 0.0 }]
        set fb_ratio [expr { $o_req > 0 ? (double($fb_cnt) / double($o_req)) : 0.0 }]
        set ok_ratio [expr { $o_req > 0 ? (double($ok_cnt) / double($o_req)) : 0.0 }]

        if { $d_cnt >= $static::mu_idor_distinct_thr } {
            call mu_award_once $mu_user_key "distinct_ids" $static::mu_pts_distinct $mu_now
        }
        if { $o_req >= 5 && $seq_ratio >= $static::mu_idor_seq_thr } {
            call mu_award_once $mu_user_key "seq_ratio" $static::mu_pts_sequential $mu_now
        }
        if { $o_req >= 10 && $fb_ratio >= $static::mu_idor_forbid_thr } {
            call mu_award_once $mu_user_key "forbid_ratio" $static::mu_pts_forbid_ratio $mu_now
        }
        if { $ok_cnt >= $static::mu_idor_success_thr && $d_cnt >= [expr { $static::mu_idor_distinct_thr / 2 }] && $ok_ratio >= 0.7 } {
            call mu_award_once $mu_user_key "success_enum" $static::mu_pts_success_enum $mu_now
        }
        if { $b_sum >= $static::mu_idor_bytes_thr } {
            call mu_award_once $mu_user_key "resp_bytes" $static::mu_pts_bytes $mu_now
        }
    }

    set mu_score [table lookup -notouch "mu:score:$mu_user_key"]
    if { $mu_score eq "" } { set mu_score 0 }
    set mu_level [call mu_level_from_score $mu_score]
    table set "mu:level:$mu_user_key" $mu_level $static::mu_window 3600

    if { $static::mu_ai_enabled && $mu_path_kind } {
        set skip_ai [expr { $static::mu_ai_skip_high && $mu_level eq "high" }]
        set in_amb [expr { $mu_score >= $static::mu_ai_amb_min && $mu_score <= $static::mu_ai_amb_max }]
        set ai_cool [table lookup -notouch "mu:ai_called:$mu_user_key"]
        if { !$skip_ai && $in_amb && $ai_cool eq "" } {
            table set "mu:ai_called:$mu_user_key" 1 $static::mu_window $static::mu_window
            set payload [format "{\"user_id\":\"%s\",\"score\":%d,\"level\":\"%s\",\"auth_present\":%s,\"features\":{\"distinct_object_ids\":%d,\"sequential_ratio\":%.2f,\"forbid_ratio\":%.2f,\"ok_ratio\":%.2f,\"req_count\":%d,\"response_bytes_sum\":%d,\"path_template\":\"%s\"}}" $mu_user_key $mu_score $mu_level [expr {$mu_auth_present ? "true" : "false"}] $d_cnt $seq_ratio $fb_ratio $ok_ratio $o_req $b_sum $mu_tmpl]
            if { [catch {
                set ilx_h [ILX::init $static::mu_lx_plugin $static::mu_lx_plugin]
                set raw_ai [ILX::call $ilx_h -timeout 800 enrich $payload]
            } err] } {
                log local0. "mu_ai fail-open: $err"
                set mu_ai_tag "fail-open"
            } else {
                if { [regexp {"fail_open"\s*:\s*true} $raw_ai] } {
                    log local0. "mu_ai fail-open: $raw_ai"
                    set mu_ai_tag "fail-open"
                } elseif { [regexp {"action"\s*:\s*"(confirm|dismiss|boost)"} $raw_ai -> ai_act] } {
                    set mu_ai_tag $ai_act
                    set mu_level [call mu_ai_apply_result $mu_user_key $ai_act]
                }
            }
        }
    }

    log local0.warn "MU-IDOR client=$mu_log_client req=\"$mu_log_req\" path_kind=$mu_path_kind score=$mu_score level=$mu_level status=$mu_status ai=$mu_ai_tag"
}

when CLIENT_CLOSED {
    if { [info exists mu_resp_seen] && !$mu_resp_seen && [info exists mu_log_client] && [info exists mu_log_req] } {
        set mu_score 0
        set mu_level "none"
        if { [info exists mu_user_key] && $mu_user_key ne "" } {
            set s [table lookup -notouch "mu:score:$mu_user_key"]
            if { $s ne "" } { set mu_score $s }
            set l [table lookup -notouch "mu:level:$mu_user_key"]
            if { $l ne "" } { set mu_level $l }
        }
        set pk [expr { [info exists mu_path_kind] ? $mu_path_kind : 0 }]
        log local0.warn "MU-IDOR client=$mu_log_client req=\"$mu_log_req\" path_kind=$pk score=$mu_score level=$mu_level status=403 ai=-"
    }
}

when ASM_REQUEST_DONE {
    if { ![info exists mu_user_key] || $mu_user_key eq "" } { return }
    if { [catch { ASM::violation count } vcount] } { return }
    if { $vcount > 0 } {
        call mu_award_once $mu_user_key "waf_hit" $static::mu_pts_waf [clock seconds]
    }
}

when ASM_REQUEST_BLOCKING {
    if { ![info exists mu_user_key] || $mu_user_key eq "" } { return }
    call mu_award_once $mu_user_key "asm_deny" $static::mu_pts_forbidden [clock seconds]
}
