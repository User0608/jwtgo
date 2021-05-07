# JWT, Generar RSA Keys

Genera la llave privada rsa, con la que se firmara los tokens
entregados a lo clientes del servicio
```bash
    > openssl genrsa -out app.rsa 1024
```
Usando la llave privada generamos la llave publica, con la que el
cliente podrá, validar que el toquen es valido

```bash
    > openssl rsa -in app.rsa -pubout > app.rsa.pub
```