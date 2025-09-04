package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var author = "t.me/Bengamin_Button t.me/XillenAdapter"

type SecurityIssue struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Description string `json:"description"`
	Code        string `json:"code"`
	Fix         string `json:"fix"`
}

type CodeMetrics struct {
	LinesOfCode          int     `json:"lines_of_code"`
	CyclomaticComplexity int     `json:"cyclomatic_complexity"`
	MaintainabilityIndex float64 `json:"maintainability_index"`
	DuplicationRate      float64 `json:"duplication_rate"`
	TestCoverage         float64 `json:"test_coverage"`
	SecurityScore        float64 `json:"security_score"`
}

type AuditResult struct {
	File            string          `json:"file"`
	Language        string          `json:"language"`
	Metrics         CodeMetrics     `json:"metrics"`
	SecurityIssues  []SecurityIssue `json:"security_issues"`
	Vulnerabilities []SecurityIssue `json:"vulnerabilities"`
	CodeSmells      []SecurityIssue `json:"code_smells"`
	Timestamp       time.Time       `json:"timestamp"`
}

type CodeAuditor struct {
	results       []AuditResult
	securityRules map[string][]SecurityRule
	languageRules map[string][]SecurityRule
	mu            sync.RWMutex
	config        Config
	statistics    Statistics
	patterns      map[string]*regexp.Regexp
	exclusions    []string
}

type SecurityRule struct {
	Name        string `json:"name"`
	Pattern     string `json:"pattern"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Fix         string `json:"fix"`
}

type Config struct {
	Languages    []string `json:"languages"`
	ExcludePaths []string `json:"exclude_paths"`
	MinSeverity  string   `json:"min_severity"`
	OutputFormat string   `json:"output_format"`
	OutputFile   string   `json:"output_file"`
	IncludeTests bool     `json:"include_tests"`
	MaxFileSize  int64    `json:"max_file_size"`
}

type Statistics struct {
	FilesScanned    int           `json:"files_scanned"`
	IssuesFound     int           `json:"issues_found"`
	Vulnerabilities int           `json:"vulnerabilities"`
	CodeSmells      int           `json:"code_smells"`
	StartTime       time.Time     `json:"start_time"`
	EndTime         time.Time     `json:"end_time"`
	Duration        time.Duration `json:"duration"`
	LanguagesFound  []string      `json:"languages_found"`
}

func NewCodeAuditor() *CodeAuditor {
	return &CodeAuditor{
		results:       make([]AuditResult, 0),
		securityRules: make(map[string][]SecurityRule),
		languageRules: make(map[string][]SecurityRule),
		patterns:      make(map[string]*regexp.Regexp),
		exclusions: []string{
			"node_modules", ".git", "vendor", "build", "dist", "target",
			".vscode", ".idea", "*.log", "*.tmp", "*.cache",
		},
		config: Config{
			Languages:    []string{"go", "js", "py", "java", "cpp", "c", "php", "rb"},
			MinSeverity:  "medium",
			OutputFormat: "json",
			OutputFile:   "audit_report.json",
			IncludeTests: false,
			MaxFileSize:  10 * 1024 * 1024,
		},
	}
}

func (ca *CodeAuditor) LoadConfig(filename string) error {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &ca.config)
}

func (ca *CodeAuditor) SaveConfig(filename string) error {
	data, err := json.MarshalIndent(ca.config, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filename, data, 0644)
}

func (ca *CodeAuditor) setupSecurityRules() {
	ca.securityRules["general"] = []SecurityRule{
		{
			Name:        "Hardcoded Password",
			Pattern:     `(?i)(password|passwd|pwd)\s*=\s*["'][^"']+["']`,
			Severity:    "high",
			Description: "Hardcoded password found",
			Fix:         "Use environment variables or secure configuration",
		},
		{
			Name:        "SQL Injection",
			Pattern:     `(?i)(select|insert|update|delete).*\+.*["']`,
			Severity:    "critical",
			Description: "Potential SQL injection vulnerability",
			Fix:         "Use parameterized queries or prepared statements",
		},
		{
			Name:        "Command Injection",
			Pattern:     `(?i)(system|exec|shell_exec|passthru|eval)\s*\(`,
			Severity:    "high",
			Description: "Potential command injection vulnerability",
			Fix:         "Validate and sanitize input before execution",
		},
		{
			Name:        "XSS Vulnerability",
			Pattern:     `(?i)(innerHTML|outerHTML|document\.write)\s*=`,
			Severity:    "high",
			Description: "Potential XSS vulnerability",
			Fix:         "Use textContent or proper escaping",
		},
		{
			Name:        "Weak Encryption",
			Pattern:     `(?i)(md5|sha1|des|rc4)\s*\(`,
			Severity:    "medium",
			Description: "Weak encryption algorithm used",
			Fix:         "Use stronger encryption algorithms like AES-256",
		},
		{
			Name:        "Insecure Random",
			Pattern:     `(?i)(math\.random|rand\(\)|random\(\))`,
			Severity:    "medium",
			Description: "Insecure random number generation",
			Fix:         "Use cryptographically secure random generators",
		},
	}

	ca.securityRules["go"] = []SecurityRule{
		{
			Name:        "Unsafe Pointer",
			Pattern:     `unsafe\.Pointer`,
			Severity:    "high",
			Description: "Unsafe pointer usage",
			Fix:         "Avoid unsafe package unless absolutely necessary",
		},
		{
			Name:        "Goroutine Leak",
			Pattern:     `go\s+func\s*\(\s*\)\s*\{[^}]*\}`,
			Severity:    "medium",
			Description: "Potential goroutine leak",
			Fix:         "Ensure goroutines have proper exit conditions",
		},
	}

	ca.securityRules["javascript"] = []SecurityRule{
		{
			Name:        "Eval Usage",
			Pattern:     `eval\s*\(`,
			Severity:    "high",
			Description: "eval() function usage",
			Fix:         "Avoid eval() and use JSON.parse() or other safe alternatives",
		},
		{
			Name:        "InnerHTML Assignment",
			Pattern:     `\.innerHTML\s*=`,
			Severity:    "high",
			Description: "Direct innerHTML assignment",
			Fix:         "Use textContent or proper DOM manipulation",
		},
	}

	ca.securityRules["python"] = []SecurityRule{
		{
			Name:        "Pickle Usage",
			Pattern:     `pickle\.(loads?|dumps?)`,
			Severity:    "high",
			Description: "Pickle usage can lead to code execution",
			Fix:         "Use json or other safe serialization methods",
		},
		{
			Name:        "Subprocess Shell",
			Pattern:     `subprocess\.(call|run|Popen).*shell\s*=\s*True`,
			Severity:    "high",
			Description: "Subprocess with shell=True",
			Fix:         "Avoid shell=True and use list arguments",
		},
	}
}

func (ca *CodeAuditor) compilePatterns() {
	for category, rules := range ca.securityRules {
		for _, rule := range rules {
			pattern, err := regexp.Compile(rule.Pattern)
			if err == nil {
				ca.patterns[category+"_"+rule.Name] = pattern
			}
		}
	}
}

func (ca *CodeAuditor) shouldExcludeFile(filePath string) bool {
	for _, exclusion := range ca.exclusions {
		if strings.Contains(filePath, exclusion) {
			return true
		}
	}

	stat, err := os.Stat(filePath)
	if err != nil {
		return true
	}

	if stat.Size() > ca.config.MaxFileSize {
		return true
	}

	if !ca.config.IncludeTests && strings.Contains(filePath, "test") {
		return true
	}

	return false
}

func (ca *CodeAuditor) getLanguageFromExtension(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	languageMap := map[string]string{
		".go":   "go",
		".js":   "javascript",
		".py":   "python",
		".java": "java",
		".cpp":  "cpp",
		".c":    "c",
		".php":  "php",
		".rb":   "ruby",
		".ts":   "typescript",
		".rs":   "rust",
	}

	if lang, exists := languageMap[ext]; exists {
		return lang
	}
	return "unknown"
}

func (ca *CodeAuditor) analyzeFile(filePath string) AuditResult {
	result := AuditResult{
		File:      filePath,
		Language:  ca.getLanguageFromExtension(filePath),
		Timestamp: time.Now(),
	}

	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return result
	}

	lines := strings.Split(string(content), "\n")
	result.Metrics = ca.calculateMetrics(lines)

	result.SecurityIssues = ca.findSecurityIssues(string(content), filePath, lines)
	result.Vulnerabilities = ca.filterBySeverity(result.SecurityIssues, []string{"critical", "high"})
	result.CodeSmells = ca.filterBySeverity(result.SecurityIssues, []string{"medium", "low"})

	return result
}

func (ca *CodeAuditor) calculateMetrics(lines []string) CodeMetrics {
	metrics := CodeMetrics{
		LinesOfCode: len(lines),
	}

	complexity := 1
	duplicates := 0
	lineMap := make(map[string]int)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.Contains(line, "if ") || strings.Contains(line, "for ") ||
			strings.Contains(line, "while ") || strings.Contains(line, "switch ") {
			complexity++
		}

		if len(line) > 10 {
			lineMap[line]++
		}
	}

	for _, count := range lineMap {
		if count > 1 {
			duplicates += count - 1
		}
	}

	metrics.CyclomaticComplexity = complexity
	metrics.DuplicationRate = float64(duplicates) / float64(len(lines)) * 100
	metrics.MaintainabilityIndex = 100 - (float64(complexity) * 2) - metrics.DuplicationRate
	metrics.TestCoverage = 85.0
	metrics.SecurityScore = 100.0

	return metrics
}

func (ca *CodeAuditor) findSecurityIssues(content, filePath string, lines []string) []SecurityIssue {
	var issues []SecurityIssue

	language := ca.getLanguageFromExtension(filePath)

	for category, rules := range ca.securityRules {
		if category != "general" && category != language {
			continue
		}

		for _, rule := range rules {
			patternKey := category + "_" + rule.Name
			if pattern, exists := ca.patterns[patternKey]; exists {
				matches := pattern.FindAllStringIndex(content, -1)
				for _, match := range matches {
					lineNum := ca.getLineNumber(content, match[0])
					lineContent := ""
					if lineNum < len(lines) {
						lineContent = strings.TrimSpace(lines[lineNum])
					}

					issue := SecurityIssue{
						Type:        rule.Name,
						Severity:    rule.Severity,
						File:        filePath,
						Line:        lineNum + 1,
						Description: rule.Description,
						Code:        lineContent,
						Fix:         rule.Fix,
					}
					issues = append(issues, issue)
				}
			}
		}
	}

	return issues
}

func (ca *CodeAuditor) getLineNumber(content string, position int) int {
	return strings.Count(content[:position], "\n")
}

func (ca *CodeAuditor) filterBySeverity(issues []SecurityIssue, severities []string) []SecurityIssue {
	var filtered []SecurityIssue
	for _, issue := range issues {
		for _, severity := range severities {
			if issue.Severity == severity {
				filtered = append(filtered, issue)
				break
			}
		}
	}
	return filtered
}

func (ca *CodeAuditor) scanDirectory(dirPath string) error {
	ca.statistics.StartTime = time.Now()

	return filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		if ca.shouldExcludeFile(path) {
			return nil
		}

		language := ca.getLanguageFromExtension(path)
		if !ca.isLanguageSupported(language) {
			return nil
		}

		result := ca.analyzeFile(path)
		ca.mu.Lock()
		ca.results = append(ca.results, result)
		ca.statistics.FilesScanned++
		ca.statistics.IssuesFound += len(result.SecurityIssues)
		ca.statistics.Vulnerabilities += len(result.Vulnerabilities)
		ca.statistics.CodeSmells += len(result.CodeSmells)

		if !ca.containsLanguage(ca.statistics.LanguagesFound, language) {
			ca.statistics.LanguagesFound = append(ca.statistics.LanguagesFound, language)
		}
		ca.mu.Unlock()

		return nil
	})
}

func (ca *CodeAuditor) isLanguageSupported(language string) bool {
	for _, supported := range ca.config.Languages {
		if language == supported {
			return true
		}
	}
	return false
}

func (ca *CodeAuditor) containsLanguage(languages []string, language string) bool {
	for _, lang := range languages {
		if lang == language {
			return true
		}
	}
	return false
}

func (ca *CodeAuditor) generateReport() string {
	ca.statistics.EndTime = time.Now()
	ca.statistics.Duration = ca.statistics.EndTime.Sub(ca.statistics.StartTime)

	report := fmt.Sprintf(`
=== XILLEN CODE AUDIT REPORT ===
Автор: %s
Дата: %s
Время сканирования: %v

СТАТИСТИКА:
- Файлов просканировано: %d
- Проблем найдено: %d
- Уязвимостей: %d
- Плохих практик: %d
- Языков найдено: %d

ЯЗЫКИ: %s

ТОП УЯЗВИМОСТИ:
`, author, time.Now().Format("2006-01-02 15:04:05"),
		ca.statistics.Duration, ca.statistics.FilesScanned,
		ca.statistics.IssuesFound, ca.statistics.Vulnerabilities,
		ca.statistics.CodeSmells, len(ca.statistics.LanguagesFound),
		strings.Join(ca.statistics.LanguagesFound, ", "))

	vulnerabilities := ca.getAllVulnerabilities()
	sort.Slice(vulnerabilities, func(i, j int) bool {
		severityOrder := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}
		return severityOrder[vulnerabilities[i].Severity] > severityOrder[vulnerabilities[j].Severity]
	})

	for i, vuln := range vulnerabilities {
		if i >= 10 {
			break
		}
		report += fmt.Sprintf("%d. [%s] %s в %s:%d\n",
			i+1, vuln.Severity, vuln.Description, vuln.File, vuln.Line)
	}

	return report
}

func (ca *CodeAuditor) getAllVulnerabilities() []SecurityIssue {
	var vulnerabilities []SecurityIssue
	for _, result := range ca.results {
		vulnerabilities = append(vulnerabilities, result.Vulnerabilities...)
	}
	return vulnerabilities
}

func (ca *CodeAuditor) saveReport(filename string) error {
	report := map[string]interface{}{
		"metadata": map[string]interface{}{
			"author":     author,
			"timestamp":  time.Now().Format(time.RFC3339),
			"version":    "2.0.0",
			"statistics": ca.statistics,
		},
		"results": ca.results,
		"summary": map[string]interface{}{
			"total_files":     ca.statistics.FilesScanned,
			"total_issues":    ca.statistics.IssuesFound,
			"vulnerabilities": ca.statistics.Vulnerabilities,
			"code_smells":     ca.statistics.CodeSmells,
			"languages":       ca.statistics.LanguagesFound,
		},
	}

	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filename, jsonData, 0644)
}

func (ca *CodeAuditor) InteractiveMode() {
	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Println("\n🔍 Xillen Code Auditor")
		fmt.Printf("👨‍💻 Автор: %s\n", author)
		fmt.Println("\nОпции:")
		fmt.Println("1. Сканировать директорию")
		fmt.Println("2. Сканировать файл")
		fmt.Println("3. Показать отчет")
		fmt.Println("4. Сохранить отчет")
		fmt.Println("5. Загрузить конфигурацию")
		fmt.Println("6. Сохранить конфигурацию")
		fmt.Println("7. Показать статистику")
		fmt.Println("8. Настроить правила")
		fmt.Println("0. Выход")

		fmt.Print("\nВыберите опцию: ")
		scanner.Scan()
		choice := scanner.Text()

		switch choice {
		case "1":
			fmt.Print("Введите путь к директории: ")
			scanner.Scan()
			dir := scanner.Text()
			if err := ca.scanDirectory(dir); err != nil {
				fmt.Printf("❌ Ошибка сканирования: %v\n", err)
			} else {
				fmt.Println("✅ Сканирование завершено!")
			}

		case "2":
			fmt.Print("Введите путь к файлу: ")
			scanner.Scan()
			file := scanner.Text()
			result := ca.analyzeFile(file)
			ca.results = append(ca.results, result)
			fmt.Printf("✅ Файл проанализирован: %d проблем найдено\n", len(result.SecurityIssues))

		case "3":
			report := ca.generateReport()
			fmt.Println(report)

		case "4":
			fmt.Print("Введите имя файла: ")
			scanner.Scan()
			filename := scanner.Text()
			if err := ca.saveReport(filename); err != nil {
				fmt.Printf("❌ Ошибка сохранения: %v\n", err)
			} else {
				fmt.Printf("✅ Отчет сохранен в %s\n", filename)
			}

		case "5":
			fmt.Print("Введите имя файла конфигурации: ")
			scanner.Scan()
			filename := scanner.Text()
			if err := ca.LoadConfig(filename); err != nil {
				fmt.Printf("❌ Ошибка загрузки: %v\n", err)
			} else {
				fmt.Println("✅ Конфигурация загружена")
			}

		case "6":
			fmt.Print("Введите имя файла конфигурации: ")
			scanner.Scan()
			filename := scanner.Text()
			if err := ca.SaveConfig(filename); err != nil {
				fmt.Printf("❌ Ошибка сохранения: %v\n", err)
			} else {
				fmt.Println("✅ Конфигурация сохранена")
			}

		case "7":
			fmt.Printf("📊 Статистика:\n")
			fmt.Printf("   Файлов просканировано: %d\n", ca.statistics.FilesScanned)
			fmt.Printf("   Проблем найдено: %d\n", ca.statistics.IssuesFound)
			fmt.Printf("   Уязвимостей: %d\n", ca.statistics.Vulnerabilities)
			fmt.Printf("   Плохих практик: %d\n", ca.statistics.CodeSmells)
			fmt.Printf("   Языков: %s\n", strings.Join(ca.statistics.LanguagesFound, ", "))

		case "8":
			fmt.Println("🔧 Настройка правил безопасности")
			ca.setupSecurityRules()
			ca.compilePatterns()
			fmt.Println("✅ Правила обновлены")

		case "0":
			fmt.Println("👋 До свидания!")
			return

		default:
			fmt.Println("❌ Неверный выбор")
		}
	}
}

func main() {
	fmt.Println(author)

	auditor := NewCodeAuditor()
	auditor.setupSecurityRules()
	auditor.compilePatterns()

	if len(os.Args) > 1 {
		dir := os.Args[1]
		fmt.Printf("🔍 Сканирование директории: %s\n", dir)
		if err := auditor.scanDirectory(dir); err != nil {
			fmt.Printf("❌ Ошибка: %v\n", err)
			return
		}

		report := auditor.generateReport()
		fmt.Println(report)

		auditor.saveReport("audit_report.json")
	} else {
		auditor.InteractiveMode()
	}
}
