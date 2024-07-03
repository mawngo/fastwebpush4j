# Java Library Template

Template for creating java library.

## Publishing

Run:

```shell
./gradlew publish
```

Will publish into `build/repos/releases`

## Optional plugin

```groovy
plugins {
    id 'nebula.provided-base' version '7.0.0' // Allow provided dependencies
    id 'nebula.optional-base' version '7.0.0' // Allow optional dependencies
    id 'java-library' // Allow dependencies with api scope (scope compile in pom when publish)
}
```
