package main

// 用户管理子命令：user / passwd / del / 2fa-reset 与密码输入。

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/seqyuan/goprox/internal/auth"
	"github.com/seqyuan/goprox/internal/config"
)

func runUserAdd(opts options, username string) {
	configPath := config.UserConfigPath(opts.configDir, username)
	if _, err := os.Stat(configPath); err == nil {
		log.Fatalf("user %s already exists (%s)", username, configPath)
	}

	// Prompt before touching disk, then create the account (with the password
	// hash) in one locked, atomic step. This avoids leaving a placeholder
	// account if the prompt is aborted, and refuses to overwrite an account
	// created concurrently by another CLI process.
	password, err := promptNewPassword()
	if err != nil {
		log.Fatalf("%v", err)
	}
	if err := config.CreateUserConfig(configPath, auth.HashPassword(password)); err != nil {
		log.Fatalf("create user: %v", err)
	}
	fmt.Printf("[goprox] user %s created (%s)\n", username, configPath)
}

func runUserPasswd(opts options, username string) {
	configPath := config.UserConfigPath(opts.configDir, username)
	if _, err := os.Stat(configPath); err != nil {
		log.Fatalf("user %s does not exist (%s)", username, configPath)
	}

	password, err := promptNewPassword()
	if err != nil {
		log.Fatalf("%v", err)
	}
	if err := config.UpdatePasswordHash(configPath, auth.HashPassword(password)); err != nil {
		log.Fatalf("update password: %v", err)
	}
	fmt.Printf("[goprox] password updated for %s\n", username)
}

func runUserDel(opts options, username string) {
	configPath := config.UserConfigPath(opts.configDir, username)
	if _, err := os.Stat(configPath); err != nil {
		log.Fatalf("user %s does not exist (%s)", username, configPath)
	}
	if err := config.RemoveUserConfig(configPath); err != nil {
		log.Fatalf("remove config: %v", err)
	}
	fmt.Printf("[goprox] user %s deleted\n", username)
}

func runTOTPReset(opts options, username string) {
	configPath := config.UserConfigPath(opts.configDir, username)
	if _, err := os.Stat(configPath); err != nil {
		log.Fatalf("user %s does not exist (%s)", username, configPath)
	}
	if err := config.UpdateTOTPSecret(configPath, ""); err != nil {
		log.Fatalf("reset 2FA: %v", err)
	}
	fmt.Printf("[goprox] 2FA disabled for %s\n", username)
}

// ---- lightweight SSO (admin CLI) ----

// ssoArgs holds the parsed `goprox sso` options.

var passwordReader = bufio.NewReader(os.Stdin)

func promptNewPassword() (string, error) {
	fmt.Print("Enter password: ")
	password, err := readPassword()
	if err != nil {
		return "", err
	}
	fmt.Print("Confirm password: ")
	confirm, err := readPassword()
	if err != nil {
		return "", err
	}
	if password == "" {
		return "", fmt.Errorf("password cannot be empty")
	}
	if password != confirm {
		return "", fmt.Errorf("passwords do not match")
	}
	return password, nil
}

func readPassword() (string, error) {
	// Disable echo
	termios, err := makeRaw(0)
	if err == nil {
		defer restore(0, termios)
	}

	password, err := passwordReader.ReadString('\n')
	if err != nil {
		return "", err
	}
	fmt.Println() // newline after password input
	// Strip the line ending only, preserving any intentional whitespace.
	return strings.TrimSuffix(strings.TrimSuffix(password, "\n"), "\r"), nil
}
