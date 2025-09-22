# A golang library to run a process with elevated privileges.

This library provides some easy wrappers for the Win32 `ShellExecuteEx` function to be executed with the `runas` "verb" (it will prompt the user, with a UAC dialog, to allow admin privileges).

The provided API, are just two, self-explanatory, functions:

```go
// RunElevated starts the given process with elevated priviledges.
// An UAC prompt is displayed to the user to confirm the action.
func RunElevated(executable, workingDir string, args []string, awaitProcCompletion bool) (int, error)
```

and

```go
// IsAdminProcess returns true if the current process already
// runs as admin.
func IsAdminProcess() (bool, error)
```

The same functions called from non-Windows OS, will return an "unimplemented function" error.

### LICENSE

Copyright (c) 2025, ARDUINO SA.
All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the “Software”), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is furnished
to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE
