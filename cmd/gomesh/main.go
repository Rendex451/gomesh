// Команда gomesh — mesh VPN поверх TUN.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Rendex451/gomesh/internal/config"
	"github.com/Rendex451/gomesh/internal/crypto"
)

const usage = `usage:
  gomesh genkey               сгенерировать приватный ключ
  gomesh pubkey < private     вывести публичный ключ для приватного
  gomesh check -config FILE   проверить конфиг`

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "gomesh:", err)
		os.Exit(1)
	}
}

// run содержит всю логику main. Ввод-вывод передаётся явно,
// поэтому команды тестируются без запуска бинарника.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("no command\n" + usage)
	}
	switch args[0] {
	case "genkey":
		return cmdGenkey(stdout)
	case "pubkey":
		return cmdPubkey(stdin, stdout)
	case "check":
		return cmdCheck(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		_, err := fmt.Fprintln(stdout, usage)
		return err
	default:
		return fmt.Errorf("unknown command %q\n%s", args[0], usage)
	}
}

func cmdGenkey(stdout io.Writer) error {
	k, err := crypto.GeneratePrivateKey()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, k.Base64())
	return err
}

func cmdPubkey(stdin io.Reader, stdout io.Writer) error {
	// Ключ — 44 символа; лимит защищает от случайного `gomesh pubkey < /dev/zero`.
	data, err := io.ReadAll(io.LimitReader(stdin, 1024))
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}
	priv, err := crypto.ParsePrivateKey(strings.TrimSpace(string(data)))
	if err != nil {
		return err
	}
	pub, err := priv.PublicKey()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, pub)
	return err
}

func cmdCheck(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("check", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("config", "", "путь к конфигу ноды")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *path == "" {
		return errors.New("check: -config is required")
	}

	if err := config.CheckPermissions(*path); err != nil {
		fmt.Fprintln(stderr, "warning:", err)
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	pub, err := cfg.PrivateKey.PublicKey()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "ok: %s — public key %s, subnet %s, tun %s, %d static peers\n",
		*path, pub, cfg.Subnet, cfg.TunAddress, len(cfg.Peers))
	return err
}
