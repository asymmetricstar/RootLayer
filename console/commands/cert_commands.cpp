// console/commands/cert_commands.cpp
//
// cert issue <name> [--out DIR] [--days N]
// cert list
// cert del <cn>
#include <string>
#include <vector>

#include "commands/registry.h"
#include "core/exit_codes.h"
#include "core/files.h"
#include "core/output.h"
#include "core/text.h"

namespace {

// A file name the console can use for the certificate of `name`.
std::string file_stem(const std::string& name) {
    std::string out;
    out.reserve(name.size());
    for (char c : name) {
        const bool safe = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                          (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
        out.push_back(safe ? c : '_');
    }
    return out.empty() ? std::string("certificate") : out;
}

class CertIssueCommand : public Command {
public:
    std::string name() const override { return "cert issue"; }
    std::string usage() const override {
        return "cert issue <name> [--out DIR] [--days N]\n"
               "                    [--name \"Full Name\"] [--mail user@mail.tld]\n"
               "                    [--city City] [--country Country] [--cc TR]";
    }
    std::string summary() const override {
        return "issue the TLS server certificate for a registered name (SAN + www); "
               "subject fields are optional and only written into the certificate";
    }

    int run(CommandContext& ctx) override {
        const std::vector<std::string> required = positional_args(ctx.args);
        if (required.empty()) {
            print_usage(*this);
            return kExitUsage;
        }

        int days = 397;
        std::string value;
        const bool has_days = find_option(ctx.args, "--days", value);
        if (has_days && !parse_int(value, &days)) {
            print_error("--days must be a number");
            return kExitUsage;
        }

        std::string out_dir = ".";
        find_option(ctx.args, "--out", out_dir);

        std::string request = "ADMIN CERT_ISSUE NAME:" + required[0];
        if (has_days) {
            request += " DAYS:" + std::to_string(days);
        }

        // Optional subject fields (E, O, L, S, C). Nothing has a default: an
        // option that is missing - or given empty - leaves the field out of the
        // certificate. The values are typed on the command line, they are not
        // stored anywhere and only travel into the certificate written below.
        struct SubjectOption {
            const char* option;
            const char* token;
            const char* label;
        };
        const SubjectOption subject_options[] = {
            {"--name", "SUBJ_O", "name"},
            {"--mail", "SUBJ_E", "mail"},
            {"--city", "SUBJ_L", "city"},
            {"--country", "SUBJ_S", "country"},
            {"--cc", "SUBJ_C", "cc"},
        };
        std::string subject_line;
        for (const auto& subject_option : subject_options) {
            std::string value;
            if (!find_option(ctx.args, subject_option.option, value)) continue;
            value = trim(value);
            if (value.empty()) continue;  // explicit empty = field omitted
            // base64 keeps spaces ("Full Name") and non-ASCII out of the
            // whitespace separated token format.
            request += " ";
            request += subject_option.token;
            request += ":";
            request += base64_encode(value);
            if (!subject_line.empty()) subject_line += ", ";
            subject_line += std::string(subject_option.label) + "=" + value;
        }

        const AdminResult result = ctx.client.call(request);
        if (!result.ok) {
            return report_failure(result);
        }

        const std::string cert_pem = base64_decode(token_value(result.response, "CERT"));
        const std::string key_pem = base64_decode(token_value(result.response, "KEY"));
        const std::string ca_pem = base64_decode(token_value(result.response, "CACERT"));
        if (cert_pem.empty() || key_pem.empty()) {
            print_error("the server answer carried no certificate");
            return kExitServer;
        }

        if (!ensure_directory(out_dir)) {
            print_error("cannot create " + out_dir);
            return kExitUsage;
        }

        const std::string stem = file_stem(required[0]);
        const std::string cert_path = join_path(out_dir, stem + ".crt");
        const std::string key_path = join_path(out_dir, stem + ".key");
        const std::string ca_path = join_path(out_dir, "rootlayer-ca.crt");

        if (!write_file(cert_path, cert_pem) || !write_file(key_path, key_pem)) {
            print_error("cannot write the certificate files in " + out_dir);
            return kExitUsage;
        }
        if (!ca_pem.empty()) {
            write_file(ca_path, ca_pem);
        }

        print_ok("certificate for " + token_value(result.response, "NAME") + " (" +
                 token_value(result.response, "DAYS") + " days)");
        print_info("certificate: " + cert_path);
        print_info("private key: " + key_path);
        if (!ca_pem.empty()) {
            print_info("CA:          " + ca_path);
        }
        if (!subject_line.empty()) {
            print_info("subject:     " + subject_line);
        }
        return kExitOk;
    }
};

class CertListCommand : public Command {
public:
    std::string name() const override { return "cert list"; }
    std::string usage() const override { return "cert list"; }
    std::string summary() const override { return "list the certificates the server CA signed"; }

    int run(CommandContext& ctx) override {
        const AdminResult result = ctx.client.call("ADMIN CERT_LIST");
        if (!result.ok) {
            return report_failure(result);
        }

        std::vector<std::vector<std::string>> rows;
        for (const auto& record : token_records(result.response, "CERTS")) {
            const std::vector<std::string> fields = split_fields(record);
            if (fields.size() < 2) continue;
            rows.push_back({fields[0], fields[1]});
        }

        print_table({"SUBJECT", "STATUS"}, rows);
        print_info(token_value(result.response, "COUNT") + " certificate(s)");
        return kExitOk;
    }
};

class CertDelCommand : public Command {
public:
    std::string name() const override { return "cert del"; }
    std::string usage() const override { return "cert del <subject-cn>"; }
    std::string summary() const override {
        return "drop a certificate from the server record (the CA keeps no CRL)";
    }

    int run(CommandContext& ctx) override {
        const std::vector<std::string> required = positional_args(ctx.args);
        if (required.empty()) {
            print_usage(*this);
            return kExitUsage;
        }

        const AdminResult result = ctx.client.call("ADMIN CERT_DEL CN:" + required[0]);
        if (!result.ok) {
            return report_failure(result);
        }
        print_ok("certificate " + token_value(result.response, "CN") + " forgotten");
        print_info("a copy already handed out stays valid until it expires");
        return kExitOk;
    }
};

}  // namespace

void register_cert_commands() {
    command_registry().push_back(new CertIssueCommand());
    command_registry().push_back(new CertListCommand());
    command_registry().push_back(new CertDelCommand());
}
