// Command schemacheck validates an inventory JSON document against a schema.
//
// Usage: schemacheck <schema.json> <instance.json>
package main

import (
	"fmt"
	"os"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: schemacheck <schema.json> <instance.json>")
		os.Exit(2)
	}

	schemaFile, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "schema:", err)
		os.Exit(2)
	}
	defer schemaFile.Close()
	schemaDoc, err := jsonschema.UnmarshalJSON(schemaFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "schema parse:", err)
		os.Exit(2)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("schema.json", schemaDoc); err != nil {
		fmt.Fprintln(os.Stderr, "schema add:", err)
		os.Exit(2)
	}
	compiled, err := compiler.Compile("schema.json")
	if err != nil {
		fmt.Fprintln(os.Stderr, "schema compile:", err)
		os.Exit(2)
	}

	instanceFile, err := os.Open(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "instance:", err)
		os.Exit(2)
	}
	defer instanceFile.Close()
	instance, err := jsonschema.UnmarshalJSON(instanceFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "instance parse:", err)
		os.Exit(2)
	}

	if err := compiled.Validate(instance); err != nil {
		fmt.Fprintln(os.Stderr, "INVALID:", err)
		os.Exit(1)
	}
	fmt.Println("valid")
}
