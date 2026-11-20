// Command uppid is the local identity prototype CLI for Open UPP.
// It creates, inspects, rotates and revokes local identities and produces or
// verifies proof-of-possession signatures. It does not implement discovery,
// transport, handshake, authorization or a wire protocol.
package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/IFindMe/open-upp/identity"
)

const usage = `uppid — local Open UPP identity prototype

Usage:
  uppid generate [-class CLASS] [-out PATH]   create a new identity
  uppid show -in PATH                         show non-secret identity details
  uppid sign -in PATH -challenge TEXT         sign a fresh challenge
  uppid verify -in PATH -challenge TEXT -signature B64 [-public-key B64]
  uppid rotate -in PATH                       append a successor key
  uppid revoke -in PATH -key B64              add a key to the local deny list

Commands never print private key material. Identity files are written with
mode 0600 and are a prototype local format, not a protocol wire format.
The "safety number" printed by generate/show/rotate is a display form of this
identity's own fingerprint, not the pairwise safety number in the design doc.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "generate":
		err = generate(os.Args[2:])
	case "show":
		err = show(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	case "rotate":
		err = rotate(os.Args[2:])
	case "revoke":
		err = revoke(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "uppid:", err)
		os.Exit(1)
	}
}

func generate(args []string) error {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	class := fs.String("class", "", "optional class hint (device, service, application, agent, principal)")
	out := fs.String("out", "identity.json", "output path (mode 0600)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	id, err := identity.Create(*class)
	if err != nil {
		return err
	}
	if err := identity.Save(*out, id); err != nil {
		return err
	}
	fmt.Print(id.Display())
	fmt.Println()
	fmt.Println("saved:", *out)
	return nil
}

func show(args []string) error {
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	in := fs.String("in", "identity.json", "identity file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	id, err := identity.Load(*in)
	if err != nil {
		return err
	}
	fmt.Print(id.Display())
	fmt.Println()
	return nil
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	in := fs.String("in", "identity.json", "identity file")
	challenge := fs.String("challenge", "", "fresh challenge text")
	if err := fs.Parse(args); err != nil {
		return err
	}
	id, err := identity.Load(*in)
	if err != nil {
		return err
	}
	sig, err := id.SignChallenge([]byte(*challenge))
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{
		"public_key": base64.StdEncoding.EncodeToString(id.CurrentKey()),
		"signature":  base64.StdEncoding.EncodeToString(sig),
	})
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	in := fs.String("in", "identity.json", "identity file")
	challenge := fs.String("challenge", "", "fresh challenge text")
	signature := fs.String("signature", "", "base64 signature from sign")
	key := fs.String("public-key", "", "base64 public key (default: current key in identity file)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	id, err := identity.Load(*in)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(*signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	pub := id.CurrentKey()
	if *key != "" {
		pub, err = base64.StdEncoding.DecodeString(*key)
		if err != nil {
			return fmt.Errorf("decode public key: %w", err)
		}
	}
	if !id.VerifyChallenge(pub, []byte(*challenge), sig) {
		return errors.New("proof of possession invalid")
	}
	fmt.Println("valid")
	return nil
}

func rotate(args []string) error {
	fs := flag.NewFlagSet("rotate", flag.ContinueOnError)
	in := fs.String("in", "identity.json", "identity file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	id, err := identity.Load(*in)
	if err != nil {
		return err
	}
	if err := id.Rotate(); err != nil {
		return err
	}
	if err := identity.Save(*in, id); err != nil {
		return err
	}
	fmt.Print(id.Display())
	fmt.Println()
	return nil
}

func revoke(args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	in := fs.String("in", "identity.json", "identity file")
	key := fs.String("key", "", "base64 public key to add to the local deny list")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pub, err := base64.StdEncoding.DecodeString(*key)
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}
	id, err := identity.Load(*in)
	if err != nil {
		return err
	}
	if err := id.RevokeKey(pub); err != nil {
		return err
	}
	if err := identity.Save(*in, id); err != nil {
		return err
	}
	fmt.Println("key added to local deny list")
	return nil
}
