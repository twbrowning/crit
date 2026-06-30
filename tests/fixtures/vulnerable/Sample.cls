Class Demo.Sample Extends %RegisteredObject
{

Parameter SECRETKEY = "abc123hardcoded";

Property Token As %String [ InitialExpression = "deadbeef" ];

ClassMethod Login(name As %String) As %Status
{
    set pwd = "letmein"
    set query = "SELECT id FROM Demo.Users WHERE name = '"_name_"'"
    set rs = ##class(%SQL.Statement).%ExecDirect(, query)
    set cmd = "set ^x=1"
    xecute cmd
    set rc = $ZF(-1, "rm -rf /tmp/"_name)
    quit $$$OK
}

}
