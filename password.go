package main

import (
	"bufio"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func readPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	termios, err := unix.IoctlGetTermios(syscall.Stdin, unix.TCGETS)
	if err != nil {
		return "", err
	}

	termios.Lflag &^= unix.ECHO

	err = unix.IoctlSetTermios(syscall.Stdin, unix.TCSETS, termios)
	if err != nil {
		return "", err
	}

	defer func() {
		termios.Lflag |= unix.ECHO
		unix.IoctlSetTermios(syscall.Stdin, unix.TCSETS, termios)
		fmt.Println("")
	}()

	lineReader := bufio.NewReader(os.Stdin)

	passwordBytes, _, err := lineReader.ReadLine()
	if err != nil {
		return "", err
	}

	return string(passwordBytes), nil
}
