<div id="user-content-toc" align="center">
  <ul>
    <summary>
      <h1 style="display: inline-block;">Cryptography-RSA</h1><br/>
      <h3 style="display: inline-block;">José Benavente & Daniel Aguayo</h3>
    </summary>
  </ul>
</div>

<hr/>

This is a small project made for an applied cryptography class. It consists of three scripts written in Python which
aim to implement RSA encryption in a practical context.

The repository has been cleaned up and uploaded here as an academic resource for anybody to peek into.

## Use
```
python keygen.py
python cipher.py --private-key alice.pem --public-key bob.pub -p [password]
python decipher.py --public-key alice.pub --private-key bob.pem -p [password]
```

## Learn
You may find a very detailed explanation on how this project works in real time by reading the [LEARN.md](./LEARN.md)
file.
