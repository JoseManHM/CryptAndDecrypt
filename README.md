# Programa de encriptación y desencriptación
### Descripción
#### Encriptación / Desencriptación
Este programa utiliza el algoritmo AES para realizar la encriptación y desencriptacíón de cadenas pasadas por el usuario, para realizar la encriptación necesita una llave y un salt, para la desencriptación solo necesita la llave, estos valores pueden ser pasados manualmente por el usuario o se pueden configurar como variables de entorno del sistema, en el caso de que se configuren como variables de entorno deben de tener el nombre 'AES_256_PASS' para la llave y 'AES_256_SALT' para el salt.
#### Generación de cadenas con valores aleatorios
Para la generación de cadenas aleatorias se hace uso de la clase SecureRandom de Java para mayor seguridad en las cadenas generadas, el tamaño de la cadena generada es dinámico y se define por el usuario