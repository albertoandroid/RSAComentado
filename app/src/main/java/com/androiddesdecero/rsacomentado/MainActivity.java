package com.androiddesdecero.rsacomentado;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/*
    RSA:  Es un sistema de Criptografia Asimetrica. Es decir que dispones de una Llave Publica y otra Llave Privada.
    Los datos son encriptados a través de una llave pública
    Los datos son desencriptados a través de una llave privada
    El objetivo es ofrecer la llave pública a todos los que nos envien información y guardar la clave privada en el servidor
    Ejenplo vida Real:
    Yo envio una caja con una cerradura abierta de la que yo solo tengo la cerradura a mi amigo. Mi amigo recibe la caja y escribe un mensaje, lo guarda en la caja y la cierra.
    Mi amigo ya no puede leer el mensaje. Mi amigo me envia la caja y yo la abor con la llave.
    Clave Publica la caja.
    Clave Privada la llave de la cerradura.
     */

public class MainActivity extends AppCompatActivity {

    //La clase KeyPairGenerator se utiliza para generar
    //pares de claves pública y privadas.
    KeyPairGenerator kpg;
    //Esta clase es un holder para un par de claves (una publica
    // la otra privada). No da ninguna seguridad, solo es un holder.
    KeyPair kp;
    //Esta interfaz nos proporicona seguridad para nuestra clave pública.
    PublicKey publicKey;
    //Esta interfaz nos proporicona seguridad para nuestra clave pública.
    PrivateKey privateKey;

    String encryptedString, decryptedString;
    byte[] encryptedBytes, decryptedBytes;
    Cipher cipher, cipher1;

    private final static String CRYPTO_METHOD = "RSA";
    private final static int CRYPTO_BITS = 2048;
    private String message = "Este mensaje es secreto, por ello va encriptado";


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        try {
            generateKeyPair();
            String mensajeEncriptado = encrypt(message);
            Log.d("TAG1", "Mensaje Encriptado -> " + mensajeEncriptado);
            String mensajeDesencriptado = decrypt(mensajeEncriptado);
            Log.d("TAG1", "Mensaje DesEncriptado -> " + mensajeDesencriptado);


        }catch (Exception e){

        }
    }

    private void generateKeyPair()
            throws NoSuchAlgorithmException {

        kpg = KeyPairGenerator.getInstance(CRYPTO_METHOD);
        kpg.initialize(CRYPTO_BITS);
        kp = kpg.genKeyPair();
        publicKey = kp.getPublic();
        Log.d("TAG1","public key: " + publicKey.toString());

        privateKey = kp.getPrivate();
        Log.d("TAG1","private key: " + privateKey.toString());
    }

    public String encrypt(String mensajeAEncriptar)
            throws NoSuchAlgorithmException,
            NoSuchPaddingException,
            InvalidKeyException,
            IllegalBlockSizeException,
            BadPaddingException {

        PublicKey rsaPublicKey;
        rsaPublicKey = publicKey;
        //Esta clase proporciona la funcionalidad de un cifrado criptográfico el cifrado y descifrado.
        //Con getInstance le indicamos el cifrado escogido en este caso RSA
        //ECB-> Es un modo de operación de cifrado por bloques, que simplemente
        //significa que si los datos cifrados son más largos que lo que se puede ingresar en una
        //sola operación de cifrado RSA se ejecutan operaciones RSA repetidas y la salida se concatena
        //OAEPWithSHA1AndMGF1Padding-> Indica que antes de cada cifrado RSA el texto plano
        //esta sujeto al método de codificación OAEP. Básicamente lo que nos ofrece OAEP con los
        //parametros adecuados es que no puede alterarse sin que el destinatario lo detecte
        //durante el proceso de descfirado. Es decir lo que nos ofrece es Integridad el OAEP

        //Simplemente tienes que saber que puede haber diferences opciones de RSA pero que la base
        //de cifrado es la misma, clave publica y clave privada.
        cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
        //Inicializamos Cipher en modo encriptación con la clave publica.
        cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
        //doFinal-> hace una operación de encritado o desemcriptado según lo hayamos inicializado.
        encryptedBytes = cipher.doFinal(mensajeAEncriptar.getBytes());



        /*
        Dato que una clave o mensaje encriptado no suele ser texto, sino que esta en bytes en bruto, se suele almacenar en base64.
        Base64 no ofrece ningún tipo de seguridad en encriptación. Cualquiera puede convertir una cadena de texto a base64 y viceversa.
        Base64 no protege, solo es para mostrar y almacenar bytes sin formato de forma sencilla.
         */
        return Base64.encodeToString(encryptedBytes, Base64.DEFAULT);
    }

    public String decrypt(String result)
            throws NoSuchAlgorithmException,
            NoSuchPaddingException,
            InvalidKeyException,
            IllegalBlockSizeException,
            BadPaddingException {

        cipher1 = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
        cipher1.init(Cipher.DECRYPT_MODE, privateKey);
        decryptedBytes = cipher1.doFinal(Base64.decode(result, Base64.DEFAULT));
        decryptedString = new String(decryptedBytes);

        return decryptedString;
    }
}
