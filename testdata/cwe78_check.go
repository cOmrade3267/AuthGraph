package testdata

import "os/exec"

func vulnerable(someVar string) {
	exec.Command("sh", "-c", someVar).Run()
}
