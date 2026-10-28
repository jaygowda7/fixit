
package com.fixit.scanner;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;

import com.fixit.model.CommandExecutionResult;
import com.fixit.model.ExecutionStatus;
import com.fixit.model.ScannerType;

public class ScannerCommandRunner {

    public CommandExecutionResult run(
            ScannerType scanner,
            List<String> command,
            Path workingDirectory,
            long timeoutSeconds) {

        if (scanner == null) {
            throw new IllegalArgumentException(
                    "Scanner type cannot be null"
            );
        }

        if (command == null || command.isEmpty()) {
            throw new IllegalArgumentException(
                    "Command cannot be null or empty"
            );
        }

        if (workingDirectory == null
                || !workingDirectory.toFile().isDirectory()) {
            throw new IllegalArgumentException(
                    "Working directory must exist: " + workingDirectory
            );
        }

        if (timeoutSeconds <= 0) {
            throw new IllegalArgumentException(
                    "Timeout must be greater than zero"
            );
        }

        long startTime = System.nanoTime();

        CommandExecutionResult result = new CommandExecutionResult();
        result.setScanner(scanner);

        Process process = null;

        try {
            ProcessBuilder processBuilder = new ProcessBuilder(command);
            processBuilder.directory(workingDirectory.toFile());
            processBuilder.redirectErrorStream(true);

            process = processBuilder.start();

            Process runningProcess = process;

            java.util.concurrent.CompletableFuture<String> outputFuture =
                    java.util.concurrent.CompletableFuture.supplyAsync(() -> {
                        try {
                            return new String(
                                    runningProcess.getInputStream().readAllBytes(),
                                    java.nio.charset.StandardCharsets.UTF_8
                            );
                        } catch (IOException e) {
                            throw new java.util.concurrent.CompletionException(e);
                        }
                    });

            boolean completed = process.waitFor(
                    timeoutSeconds,
                    TimeUnit.SECONDS
            );

            if (!completed) {
                process.descendants().forEach(ProcessHandle::destroyForcibly);
                process.destroyForcibly();
                process.waitFor();

                result.setStatus(ExecutionStatus.TIMED_OUT);
                result.setExitCode(null);
                result.setStandardOutput(outputFuture.get(5, TimeUnit.SECONDS));
                result.setErrorOutput(
                        "Scanner command exceeded timeout of "
                                + timeoutSeconds + " seconds"
                );

                return result;
            }

            result.setStandardOutput(outputFuture.get(5, TimeUnit.SECONDS));

            int exitCode = process.exitValue();
            result.setExitCode(exitCode);
            result.setStatus(
                    exitCode == 0
                            ? ExecutionStatus.SUCCESS
                            : ExecutionStatus.FAILED
            );
            result.setErrorOutput("");

            return result;

        } catch (IOException e) {
            result.setStatus(ExecutionStatus.FAILED);
            result.setExitCode(null);
            result.setStandardOutput("");
            result.setErrorOutput(
                    "Failed to start scanner command: " + e.getMessage()
            );

            return result;

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();

            if (process != null && process.isAlive()) {
                process.destroyForcibly();
            }

            result.setStatus(ExecutionStatus.FAILED);
            result.setExitCode(null);
            result.setStandardOutput("");
            result.setErrorOutput("Scanner execution was interrupted");

            return result;

        } catch (java.util.concurrent.ExecutionException
                | java.util.concurrent.TimeoutException e) {

            if (process != null && process.isAlive()) {
                process.destroyForcibly();
            }

            result.setStatus(ExecutionStatus.FAILED);
            result.setExitCode(null);
            result.setStandardOutput("");
            result.setErrorOutput(
                    "Failed to capture scanner output: " + e.getMessage()
            );

            return result;

        } finally {
            result.setDurationMillis(
                    TimeUnit.NANOSECONDS.toMillis(
                            System.nanoTime() - startTime
                    )
            );
        }
    }
}
