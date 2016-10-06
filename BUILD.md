
## Build

```
mvn clean compile assembly:single
```

## Debug

To Set Debug Mode:
locate log4j.properties where json-pretty-n.n.n-SNAPSHOT.jar located,

change the file following 
````
log4j.rootLogger = INFO, A1
````
to
````
log4j.rootLogger = DEBUG, A1
````