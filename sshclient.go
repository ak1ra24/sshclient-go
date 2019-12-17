package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"github.com/BurntSushi/toml"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/terminal"
)

type Config struct {
	Server ServerConfig
}

type ServerConfig struct {
	Host       string        `toml:"host"`
	Port       string        `toml:"port"`
	User       string        `toml:"user"`
	Pass       string        `toml:"pass"`
	Key        string        `toml:"key"`
	LocalPort  string        `toml:"localport"`
	RemotePort string        `toml:"remoteport"`
	Proxy      DefaultConfig `toml:"proxy"`
}

type DefaultConfig struct {
	Host string `toml:"host"`
	Port string `toml:"port"`
	User string `toml:"user"`
	Pass string `toml:"pass"`
	Key  string `toml:"key"`
}

func getTomlConfig(filename string) (config *Config, err error) {
	_, err = toml.DecodeFile(filename, &config)
	if err != nil {
		return nil, err
	}

	return config, nil
}

func getSSHConfig(config *DefaultConfig) (sshConfig *ssh.ClientConfig, sshAgent io.Closer) {

	auth := []ssh.AuthMethod{}

	if config.Key != "" {
		key, err := ioutil.ReadFile(config.Key)
		if err != nil {
			panic(err)
		}

		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			fmt.Print("Key Password: ")
			keyPasswd, err := terminal.ReadPassword(int(syscall.Stdin))
			if err != nil {
				panic(err)
			}
			signer, err = ssh.ParsePrivateKeyWithPassphrase(key, keyPasswd)
			if err != nil {
				panic(err)
			}
		}

		auth = append(auth, ssh.PublicKeys(signer))
	} else if config.Pass != "" {
		// fmt.Print("Password: ")
		// inPasswd, err := terminal.ReadPassword(int(syscall.Stdin))
		// if err != nil {
		// 	panic(err)
		// }
		// passwd := string(inPasswd)
		auth = append(auth, ssh.Password(config.Pass))
	}

	if sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err != nil {
		auth = append(auth, ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers))
	}

	// set ssh config.
	sshConfig = &ssh.ClientConfig{
		User:            config.User,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	return sshConfig, sshAgent

}

// func (config *ServerConfig) Connect() (session *ssh.Session, err error) {
func (config *ServerConfig) Connect() (client *ssh.Client, err error) {
	sshConfig, closer := getSSHConfig(&DefaultConfig{
		Host: config.Host,
		Port: config.Port,
		User: config.User,
		Pass: config.Pass,
		Key:  config.Key,
	})

	if closer != nil {
		defer closer.Close()
	}

	// SSH connect.
	client, err = ssh.Dial("tcp", net.JoinHostPort(config.Host, config.Port), sshConfig)
	if err != nil {
		panic(err)
	}

	if config.Proxy.Host != "" {
		proxy := config.Proxy
		proxyConfig, closer := getSSHConfig(&proxy)
		if closer != nil {
			defer closer.Close()
		}
		conn, err := client.Dial("tcp", net.JoinHostPort(proxy.Host, proxy.Port))
		if err != nil {
			panic(err)
		}

		ncc, chans, reqs, err := ssh.NewClientConn(conn, net.JoinHostPort(proxy.Host, proxy.Port), proxyConfig)
		if err != nil {
			panic(err)
		}

		client = ssh.NewClient(ncc, chans, reqs)
	}

	return client, nil
	// session, err = client.NewSession()
	// if err != nil {
	// 	return nil, err
	// }
	//
	// return session, nil

}

func Session(client *ssh.Client) (session *ssh.Session, err error) {
	session, err = client.NewSession()
	if err != nil {
		return nil, err
	}

	return session, nil
}

func Run(session *ssh.Session) (err error) {
	// キー入力を接続先が認識できる形式に変換する(ここがキモ)
	fd := int(os.Stdin.Fd())
	state, err := terminal.MakeRaw(fd)
	if err != nil {
		return err
	}
	defer terminal.Restore(fd, state)

	// ターミナルサイズの取得
	w, h, err := terminal.GetSize(fd)
	if err != nil {
		return err
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	term := os.Getenv("TERM")
	err = session.RequestPty(term, h, w, modes)
	if err != nil {
		return err
	}

	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin

	err = session.Shell()
	if err != nil {
		return err
	}

	err = session.Wait()
	if err != nil {
		return err
	}
	// ターミナルサイズの変更検知・処理
	// signal_chan := make(chan os.Signal, 1)
	// signal.Notify(signal_chan, syscall.SIGWINCH)
	// go func() {
	// 	for {
	// 		s := <-signal_chan
	// 		switch s {
	// 		case syscall.SIGWINCH:
	// 			fd := int(os.Stdout.Fd())
	// 			w, h, _ = terminal.GetSize(fd)
	// 			session.WindowChange(h, w)
	// 		}
	// 	}
	// }()

	return nil
}

func (config *ServerConfig) Forward() {
	fmt.Println(config)
	fmt.Printf("LOCALPORT: localhost:%s listening...\n", config.LocalPort)
	client, err := config.Connect()
	if err != nil {
		panic(err)
	}
	localListener, err := net.Listen("tcp", net.JoinHostPort("localhost", config.LocalPort))
	if err != nil {
		log.Fatal(err)
	} else {
		go func() {
			defer localListener.Close()
			defer client.ClientVersion()
			for {
				localConn, err := localListener.Accept()
				if err != nil {
					fmt.Printf("listen.Accept failed: %v\n", err)
				}
				fmt.Println("before _forward")

				go _forward(localConn, client, config.RemotePort)
			}
		}()
	}

	session, err := Session(client)
	if err != nil {
		panic(err)
	}

	defer session.Close()

	if err := Run(session); err != nil {
		panic(err)
	}
}

func _forward(localConn net.Conn, client *ssh.Client, remotePort string) {
	// Setup sshConn (type net.Conn)
	fmt.Printf("REMOTEPORT: %s:%s listening...\n", "localhost", remotePort)
	sshConn, err := client.Dial("tcp", net.JoinHostPort("localhost", remotePort))
	// Copy localConn.Reader to sshConn.Writer
	go func() {
		_, err = io.Copy(sshConn, localConn)
		if err != nil {
			fmt.Printf("io.Copy failed: %v\n", err)
		}
	}()
	// Copy sshConn.Reader to localConn.Writer
	go func() {
		_, err = io.Copy(localConn, sshConn)
		if err != nil {
			fmt.Printf("io.Copy failed: %v\n", err)
		}
	}()
}

func (config *ServerConfig) Scp(sourceFile string, targetFile string) (err error) {
	client, err := config.Connect()
	if err != nil {
		return err
	}
	session, err := Session(client)
	if err != nil {
		return err
	}
	defer session.Close()

	target := filepath.Base(targetFile)

	srcFile, err := os.Open(sourceFile)
	if err != nil {
		return err
	}

	srcStat, err := srcFile.Stat()
	if err != nil {
		return err
	}

	go func() {
		w, err := session.StdinPipe()
		if err != nil {
			return
		}
		defer w.Close()

		fmt.Fprintln(w, "C0644", srcStat.Size(), target)

		if srcStat.Size() > 0 {
			io.Copy(w, srcFile)
			fmt.Fprint(w, "\x00")
		} else {
			fmt.Fprint(w, "\x00")
		}
	}()

	return session.Run(fmt.Sprintf("scp -tr %s", targetFile))
}

func sshconnect() {
	filename := "config.toml"
	config, err := getTomlConfig(filename)
	if err != nil {
		log.Fatal(err)
	}

	client, err := config.Server.Connect()
	if err != nil {
		log.Fatal(err)
	}
	session, err := Session(client)
	defer session.Close()

	if err := Run(session); err != nil {
		log.Fatal(err)
	}
}

func portforward() {
	filename := "config.toml"
	config, err := getTomlConfig(filename)
	if err != nil {
		log.Fatal(err)
	}

	config.Server.Forward()

	fmt.Println("FINISH")
}

func main() {
	sshconnect()
}
