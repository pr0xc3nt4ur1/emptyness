rule cs_job_pipe
{
    meta:
        description = "Detects CobaltStrike Post Exploitation Named Pipes"
        author = "Riccardo Ancarani & Jon Cave"
        date = "2020-10-04"
    strings:
        $pipe = /msagent_.{1,9}/ ascii wide
    condition:
        $pipe
}

rule cs_job_pipe_two
{
    meta:
        description = "Detects CobaltStrike Post Exploitation Named Pipes"
        author = "Riccardo Ancarani & Jon Cave"
        date = "2020-10-04"
    strings:
        $pipe = /\\\\\.\\pipe\\[0-9a-f]{7,10}/ ascii wide fullword
        $guidPipe = /\\\\\.\\pipe\\[0-9a-f]{8}\-/ ascii wide
    condition:
        $pipe and not ($guidPipe)
}
