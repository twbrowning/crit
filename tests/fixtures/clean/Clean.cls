Class Demo.Clean Extends %RegisteredObject
{

Parameter MAXROWS = 100;

ClassMethod Login(name As %String) As %Status
{
    // Parameterised embedded SQL with a host variable is safe.
    &sql(SELECT id INTO :id FROM Demo.Users WHERE name = :name)
    set greeting = "Hello "_name
    quit $$$OK
}

}
