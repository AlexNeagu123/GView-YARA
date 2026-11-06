#include "../include/GView.hpp"

#include <yara.h>

namespace GView::Yara
{

namespace
{
    struct CompileContext {
        YaraCompilerCallback onError;
        void* userData;
    };

    void ForwardCompilerError(int error_level, const char* file_name, int line_number, const YR_RULE* rule, const char* message, void* user_data)
    {
        const char* level_str = (error_level == YARA_ERROR_LEVEL_ERROR) ? "ERROR" : "WARNING";
        if (file_name != nullptr) {
            LOG_ERROR("[YARA %s] %s:%d: %s", level_str, file_name, line_number, message);
        } else {
            LOG_ERROR("[YARA %s] line %d: %s", level_str, line_number, message);
        }

        const auto* ctx = static_cast<const CompileContext*>(user_data);
        if (ctx == nullptr || ctx->onError == nullptr) {
            return;
        }

        YaraCompilerError err;
        err.message   = (message != nullptr) ? message : "";
        err.file      = (file_name != nullptr) ? file_name : "";
        err.rule      = (rule != nullptr && rule->identifier != nullptr) ? rule->identifier : "";
        err.line      = line_number;
        err.isWarning = (error_level != YARA_ERROR_LEVEL_ERROR);
        try {
            ctx->onError(err, ctx->userData);
        } catch (...) {
        }
    }

    struct ScanContext {
        YaraMatchCallback onMatch;
        void* userData;
        bool tooManyMatches = false;
    };

    int ForwardMatches(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data)
    {
        auto* ctx = static_cast<ScanContext*>(user_data);
        if (ctx == nullptr) {
            return CALLBACK_CONTINUE;
        }

        if (message == CALLBACK_MSG_TOO_MANY_MATCHES) {
            ctx->tooManyMatches = true;
            return CALLBACK_CONTINUE;
        }
        
        if (message != CALLBACK_MSG_RULE_MATCHING || ctx->onMatch == nullptr) {
            return CALLBACK_CONTINUE;
        }

        YR_RULE* rule                 = static_cast<YR_RULE*>(message_data);
        const std::string_view ruleId = (rule->identifier != nullptr) ? rule->identifier : "";
        const std::string_view ruleNs = (rule->ns != nullptr && rule->ns->name != nullptr) ? rule->ns->name : "";
        bool reported                 = false;

        try {
            YR_STRING* string;
            yr_rule_strings_foreach(rule, string)
            {
                YR_MATCH* match;
                yr_string_matches_foreach(context, string, match)
                {
                    YaraMatch m;
                    m.rule       = ruleId;
                    m.ns         = ruleNs;
                    m.identifier = (string->identifier != nullptr) ? string->identifier : "";
                    m.offset     = static_cast<uint64>(match->base + match->offset);
                    m.length     = static_cast<uint32>(match->match_length);
                    m.data       = BufferView(match->data, static_cast<size_t>(match->data_length));
                    ctx->onMatch(m, ctx->userData);
                    reported = true;
                }
            }

            // matched on the condition alone: no strings, or none of them hit
            if (!reported) {
                ctx->onMatch(YaraMatch{ ruleId, ruleNs }, ctx->userData);
            }
        } catch (...) {
            return CALLBACK_ERROR;
        }

        return CALLBACK_CONTINUE;
    }
} // namespace

// ============================================================================
// YaraRules
// ============================================================================
YaraRules::~YaraRules()
{
    if (rules != nullptr) {
        yr_rules_destroy(static_cast<YR_RULES*>(rules));
        rules = nullptr;
    }
}

void* YaraRules::Handle() const
{
    return rules;
}

bool YaraRules::SaveToFile(const std::filesystem::path& filePath) const
{
    CHECK(rules != nullptr, false, "No rules to save");
    std::string path = filePath.string();
    CHECK(yr_rules_save(static_cast<YR_RULES*>(rules), path.c_str()) == ERROR_SUCCESS, false, "Failed to save rules to file: %s", path.c_str());
    return true;
}

// ============================================================================
// YaraCompiler
// ============================================================================
YaraCompiler::YaraCompiler()
{
    compiler                      = nullptr;
    YR_COMPILER** ptr_yr_compiler = reinterpret_cast<YR_COMPILER**>(&compiler);
    int result                    = yr_compiler_create(ptr_yr_compiler);
    CHECKRET(result == ERROR_SUCCESS, "Failed to create YARA compiler: %d", result);
}

YaraCompiler::~YaraCompiler()
{
    if (compiler != nullptr) {
        yr_compiler_destroy(static_cast<YR_COMPILER*>(compiler));
        compiler = nullptr;
    }
}

bool YaraCompiler::AddRules(const std::filesystem::path& filePath, const std::string& nameSpace, YaraCompilerCallback onError, void* userData)
{
    CHECK(compiler != nullptr, false, "Compiler not created");
    CHECK(status == CompilerStatus::Initial, false, "Can only add rules in the initial state");

    std::string path = filePath.string();
    FILE* file       = fopen(path.c_str(), "rb");
    if (file == nullptr) {
        if (onError != nullptr) {
            onError(YaraCompilerError{ "cannot open file", path }, userData);
        }
        RETURNERROR(false, "Failed to open file: %s", path.c_str());
    }

    YR_COMPILER* yr_compiler = static_cast<YR_COMPILER*>(compiler);
    CompileContext ctx{ onError, userData };
    yr_compiler_set_callback(yr_compiler, ForwardCompilerError, &ctx);

    const char* ns = nameSpace.empty() ? nullptr : nameSpace.c_str();

    int errors = yr_compiler_add_file(yr_compiler, file, ns, path.c_str());
    fclose(file);

    if (errors != 0) {
        status = CompilerStatus::Broken;
        RETURNERROR(false, "Compilation of %s failed with %d error(s)", path.c_str(), errors);
    }

    return true;
}

std::shared_ptr<YaraRules> YaraCompiler::Compile()
{
    CHECK(compiler != nullptr, nullptr, "Compiler not created");
    CHECK(status != CompilerStatus::Broken, nullptr, "Compiler is unusable after a failed AddRules call");

    if (compiledRules != nullptr) {
        return compiledRules;
    }

    YR_RULES* yr_rules = nullptr;
    int result         = yr_compiler_get_rules(static_cast<YR_COMPILER*>(compiler), &yr_rules);
    CHECK(result == ERROR_SUCCESS, nullptr, "Failed to compile rules: %d", result);

    status        = CompilerStatus::Compiled;
    compiledRules = std::shared_ptr<YaraRules>(new YaraRules(yr_rules));
    return compiledRules;
}

// ============================================================================
// YaraScanner
// ============================================================================
YaraScanner::YaraScanner(std::shared_ptr<YaraRules> rules_ptr) : rules(std::move(rules_ptr))
{
    CHECKRET(rules != nullptr, "YaraRules cannot be null");

    YR_SCANNER** ptr_yr_scanner = reinterpret_cast<YR_SCANNER**>(&scanner);
    YR_RULES* yr_rules          = static_cast<YR_RULES*>(rules->Handle());
    int result                  = yr_scanner_create(yr_rules, ptr_yr_scanner);
    CHECKRET(result == ERROR_SUCCESS, "Failed to create YARA scanner: %d", result);

    yr_scanner_set_timeout(*ptr_yr_scanner, 0);

    yr_scanner_set_flags(*ptr_yr_scanner, SCAN_FLAGS_REPORT_RULES_MATCHING);
}

YaraScanner::~YaraScanner()
{
    if (scanner != nullptr) {
        yr_scanner_destroy(static_cast<YR_SCANNER*>(scanner));
        scanner = nullptr;
    }
}

YaraScanner::YaraScanner(YaraScanner&& other) noexcept : scanner(other.scanner), rules(std::move(other.rules))
{
    other.scanner = nullptr;
}

YaraScanner& YaraScanner::operator=(YaraScanner&& other) noexcept
{
    if (this != &other) {
        if (scanner != nullptr) {
            yr_scanner_destroy(static_cast<YR_SCANNER*>(scanner));
        }

        scanner       = other.scanner;
        rules         = std::move(other.rules);
        other.scanner = nullptr;
    }
    return *this;
}

bool YaraScanner::ScanFile(const std::filesystem::path& filePath, YaraMatchCallback onMatch, void* userData)
{
    CHECK(scanner != nullptr, false, "Scanner not created");

    YR_SCANNER* yr_scanner = static_cast<YR_SCANNER*>(scanner);
    ScanContext ctx{ onMatch, userData };
    yr_scanner_set_callback(yr_scanner, ForwardMatches, &ctx);
    yr_scanner->entry_point = YR_UNDEFINED;

    std::string path = filePath.string();
    int result       = yr_scanner_scan_file(yr_scanner, path.c_str());
    CHECK(result == ERROR_SUCCESS, false, "Failed to scan file: %s, error: %d", path.c_str(), result);
    CHECK(!ctx.tooManyMatches, false, "Too many matches in %s, results may be incomplete", path.c_str());
    return true;
}

bool YaraScanner::ScanBuffer(const BufferView& buffer, YaraMatchCallback onMatch, void* userData)
{
    CHECK(scanner != nullptr, false, "Scanner not created");

    YR_SCANNER* yr_scanner = static_cast<YR_SCANNER*>(scanner);
    ScanContext ctx{ onMatch, userData };
    yr_scanner_set_callback(yr_scanner, ForwardMatches, &ctx);
    yr_scanner->entry_point = YR_UNDEFINED;

    int result = yr_scanner_scan_mem(yr_scanner, buffer.GetData(), buffer.GetLength());
    CHECK(result == ERROR_SUCCESS, false, "Failed to scan buffer, error: %d", result);
    CHECK(!ctx.tooManyMatches, false, "Too many matches in buffer, results may be incomplete");
    return true;
}

// ============================================================================
// YaraManager
// ============================================================================
YaraManager::~YaraManager()
{
    Finalize();
}

YaraManager& YaraManager::GetInstance()
{
    static YaraManager instance;
    return instance;
}

bool YaraManager::Initialize()
{
    if (!initialized) {
        int result = yr_initialize();
        CHECK(result == ERROR_SUCCESS, false, "Failed to initialize YARA: %d", result);
        initialized = true;
    }
    return true;
}

void YaraManager::Finalize()
{
    if (initialized) {
        yr_finalize();
        initialized = false;
    }
}

std::unique_ptr<YaraCompiler> YaraManager::GetNewCompiler() const
{
    CHECK(initialized, nullptr, "YARA not initialized");
    return std::unique_ptr<YaraCompiler>(new YaraCompiler());
}

std::shared_ptr<YaraRules> YaraManager::LoadRules(const std::filesystem::path& filePath)
{
    CHECK(initialized, nullptr, "YARA not initialized");

    std::string path   = filePath.string();
    YR_RULES* yr_rules = nullptr;
    int result         = yr_rules_load(path.c_str(), &yr_rules);
    CHECK(result == ERROR_SUCCESS, nullptr, "Failed to load rules from file: %s", path.c_str());
    return std::shared_ptr<YaraRules>(new YaraRules(yr_rules));
}

} // namespace GView::Yara