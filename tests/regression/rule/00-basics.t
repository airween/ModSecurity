### Tests for basic rule components

# SecAction
{
	type => "rule",
	comment => "SecAction (override default)",
	conf => qq(
		SecRuleEngine On
		SecDebugLog $ENV{DEBUG_LOG}
		SecDebugLogLevel 4
		SecAction "nolog,id:500001"
	),
	match_log => {
		-error => [ qr/500001/, 1 ],
		-audit => [ qr/./, 1 ],
		debug => [ qr/Warning\. Unconditional match in SecAction\./, 1 ],
	},
	match_response => {
		status => qr/^200$/,
	},
	request => new HTTP::Request(
		GET => "http://$ENV{SERVER_NAME}:$ENV{SERVER_PORT}/test.txt",
	),
},

# SecRule
{
	type => "rule",
	comment => "SecRule (no action)",
	conf => qq(
		SecRuleEngine On
		SecDebugLog $ENV{DEBUG_LOG}
		SecDebugLogLevel 5
        SecDefaultAction "phase:2,deny,status:403"
        SecRule ARGS:test "value" "id:500032"
	),
	match_log => {
		error => [ qr/500032/, 1 ],
		debug => [ qr/Rule [0-9a-f]+: SecRule "ARGS:test" "\@rx value" "phase:2,deny,status:403,id:500032"$/m, 1 ],
	},
	match_response => {
		status => qr/^403$/,
	},
	request => new HTTP::Request(
		GET => "http://$ENV{SERVER_NAME}:$ENV{SERVER_PORT}/test.txt?test=value",
	),
},
{
	type => "rule",
	comment => "SecRule (action)",
	conf => qq(
		SecRuleEngine On
		SecDebugLog $ENV{DEBUG_LOG}
		SecDebugLogLevel 5
        SecDefaultAction "phase:2,pass"
        SecRule ARGS:test "value" "deny,status:403,id:500033"
	),
	match_log => {
		error => [ qr/ModSecurity: /, 1 ],
		debug => [ qr/Rule [0-9a-f]+: SecRule "ARGS:test" "\@rx value" "phase:2,deny,status:403,id:500033"$/m, 1 ],
	},
	match_response => {
		status => qr/^403$/,
	},
	request => new HTTP::Request(
		GET => "http://$ENV{SERVER_NAME}:$ENV{SERVER_PORT}/test.txt?test=value",
	),
},
{
	type => "rule",
	comment => "SecRule (chain)",
	conf => qq(
		SecRuleEngine On
		SecDebugLog $ENV{DEBUG_LOG}
		SecDebugLogLevel 5
        SecDefaultAction "phase:2,log,noauditlog,pass,tag:foo"
        SecRule ARGS:test "value" "chain,phase:2,deny,status:403,id:500034"
        SecRule &ARGS "\@eq 1" "chain,setenv:tx.foo=bar"
        SecRule REQUEST_METHOD "\@streq GET"
	),
	match_log => {
		error => [ qr/ModSecurity: /, 1 ],
		debug => [ qr/Rule [0-9a-f]+: SecRule "ARGS:test" "\@rx value" "phase:2,log,noauditlog,tag:foo,chain,deny,status:403,id:500034"\r?\n.*Rule [0-9a-f]+: SecRule "&ARGS" "\@eq 1" "chain,setenv:tx.foo=bar"\r?\n.*Rule [0-9a-f]+: SecRule "REQUEST_METHOD" "\@streq GET"\r?\n/s, 1 ],
	},
	match_response => {
		status => qr/^403$/,
	},
	request => new HTTP::Request(
		GET => "http://$ENV{SERVER_NAME}:$ENV{SERVER_PORT}/test.txt?test=value",
	),
},
{
	type => "rule",
	comment => "SecRule (chain) with nested macro",
	conf => qq(
	    SecRuleEngine On
	    SecDebugLog $ENV{DEBUG_LOG}
	    SecDebugLogLevel 9
	    SecAction "id:10000,phase:1,t:none,setvar:tx.10001_counter=1,setvar:tx.10001_counter2=1"
	    SecRule ARGS "\@rx (\\\d+)=(\\\d+)" "id:10001,phase:2,deny,nolog,t:none,capture,setvar:'tx.10001_%{tx.10001_counter}_lval=%{tx.1}',setvar:'tx.10001_%{tx.10001_counter}_rval=%{tx.2}',setvar:'tx.10001_counter=+1',chain"
	    SecRule TX:/10001_\\\d+_lval/ "\@streq %{tx.10001_%{tx.10001_counter2}_rval}" "setvar:'tx.10001_counter2=+1'"
	),
	match_log => {
	    error => [ qr/ModSecurity: /, 1 ],
	    debug => [ qr/Set variable "tx.10001_1_rval" to "1"\..*Resolved macro \%\{tx.10001_counter\} to: 2.*Set variable "tx.10001_2_rval" to "1"/s, 1 ],
	},
	match_response => {
	    status => qr/^403$/,
	},
	request => new HTTP::Request(
	    GET => "http://$ENV{SERVER_NAME}:$ENV{SERVER_PORT}/test.txt?a=1=1&b=2=1",
	),
},
