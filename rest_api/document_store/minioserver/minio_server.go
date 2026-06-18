package minioserver

import (
	"fmt"
	"log"
	"os"
	"os/exec"
)

func RunServer() {
	// 1. Set environment variables for authentication
	os.Setenv("MINIO_ROOT_USER", "minioadmin")
	os.Setenv("MINIO_ROOT_PASSWORD", "minioadmin")

	// 2. Prepare the command
	// Ensure the 'minio' binary is in your PATH or the current working directory
	cmd := exec.Command("minio", "server", "./data", "--console-address", ":9001")

	// 3. Pipe the command's output to the console to monitor server logs
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Println("Starting MinIO server...")

	// 4. Start the process
	err := cmd.Start()
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	fmt.Printf("MinIO server started with PID: %d\n", cmd.Process.Pid)

	// Wait for the process to finish
	err = cmd.Wait()
	if err != nil {
		log.Fatalf("Server stopped with an error: %v", err)
	}
}
