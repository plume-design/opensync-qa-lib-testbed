class SshException(Exception):
    def __init__(self, message=None, cmd=None, name=None, ret=None, stdout=None, stderr=None):
        """Exception contains all the details that may be needed later.
           Except the message, all other arguments are optional.
        Args:
            message (str, optional): Exception message
            cmd (str, optional): Executed command
            name ([str], optional): Device name
            ret ([int], optional): Return value from command line
            stdout ([str], optional): Output messages from command line
            stderr ([str], optional): Error messages from command line
        """
        self.message = message
        self.cmd = cmd
        self.name = name
        self.ret = ret
        self.stdout = stdout
        self.stderr = stderr
        if self.message is None:
            self.message = ""
            if self.name is not None:
                self.message = f"{self.name}: "
            self.message += "Failed to execute shell command"
            if self.cmd is not None:
                self.message += f": `{self.cmd}`"
            if self.ret:
                self.message += f", ret: {self.ret}"
            if self.stdout:
                self.message += f", stdout: {self.stdout}"
            if self.stderr:
                self.message += f", stderr: {self.stderr}"
        super().__init__(self.message)
