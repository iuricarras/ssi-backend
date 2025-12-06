# Vulnerabilidades no BitsOfMe

Este documento descreve vulnerabilidades identificadas no BitsOfMe.

## Account Enumeration

O endpoint `/auth/start` retorna respostas **diferentes** dependendo se o e-mail existe ou não:

* **Email existe** → responde com `challenge_id`.
* **Email não existe** → responde apenas `"status": "ok"`.

Um atacante pode testar listas de e-mails e descobrir quem possui conta no sistema.

```mermaid
graph TD

    A[Objetivo: descobrir se o e-mail está registado]
    A --> B[Enviar pedido para /auth/start com o e-mail alvo]
    B --> C[Resposta inclui challenge_id]
    B --> D[Resposta não inclui challenge_id]
    C --> E[Conclusão: e-mail existe no sistema]
    D --> F[Conclusão: e-mail não existe]

    classDef objetivo fill:#ff6666,stroke:#b30000,stroke-width:2px,color:#ffffff;
    classDef ataque fill:#ffcc00,stroke:#b38600,stroke-width:2px,color:#000000;
    classDef passo fill:#99ccff,stroke:#0066cc,stroke-width:2px,color:#000000;
    classDef sucesso fill:#66cc66,stroke:#2d862d,stroke-width:2px,color:#000000;

    class A objetivo;
    class B passo;
    class C,D passo;
    class E,F sucesso;
```

---

##  OTP Guessing Attack

O OTP possui:

* Apenas **6 dígitos** (900.000 possibilidades).
* **Nenhum rate limit** no endpoint `/auth/verify`.
* **TTL de 5 minutos**, proporcionando tempo suficiente para automatizar tentativas.

Com e-mail + challenge_id, um atacante pode testar códigos até acertar.

```mermaid
graph TD

    A[Objetivo: autenticar-se adivinhando o código OTP]

    A --> B[OTP de 6 dígitos tem poucas combinações]
    A --> C[Não existe limite de tentativas no /auth/verify]
    A --> D[O OTP é válido durante vários minutos]

    B --> E[Atacante gera possíveis códigos]
    C --> E
    D --> F[Há tempo suficiente para múltiplas tentativas]

    E --> G[Atacante envia muitas tentativas para /auth/verify]
    F --> G

    G --> H[Código correto eventualmente encontrado]
    H --> I[Sucesso: autenticação indevida]

    classDef objetivo fill:#ff6666,stroke:#b30000,stroke-width:2px,color:#ffffff;
    classDef ataque fill:#ffcc00,stroke:#b38600,stroke-width:2px,color:#000000;
    classDef passo fill:#99ccff,stroke:#0066cc,stroke-width:2px,color:#000000;
    classDef sucesso fill:#66cc66,stroke:#2d862d,stroke-width:2px,color:#000000;

    class A objetivo;
    class B,C,D ataque;
    class E,F,G passo;
    class H,I sucesso;
```

---

## OTP Flooding

O endpoint `/auth/start`:

* Não possui rate limit.
* Invalida o OTP anterior sempre que é chamado.
* Envia um novo email a cada chamada.

Assim, um atacante pode:

1. Disparar centenas de OTPs para a vítima.
2. Tornar impossível saber qual OTP é o válido.
3. Impedir a vítima de concluir o login.

```mermaid
graph TD

    A[Objetivo: impedir o utilizador de efetuar login]
    A --> B[O endpoint /auth/start pode ser chamado sem limites]
    A --> C[Não existe rate limit por e-mail ou por IP]

    B --> D[Cada chamada elimina o OTP anterior]
    D --> E[Um novo OTP é enviado ao utilizador]

    C --> F[Atacante automatiza chamadas sucessivas para /auth/start]
    F --> E

    E --> G[Utilizador recebe muitos códigos diferentes]
    G --> H[Utilizador não consegue identificar o código válido]
    H --> I[Sucesso: negação de serviço no processo de autenticação]

    classDef objetivo fill:#ff6666,stroke:#b30000,stroke-width:2px,color:#ffffff;
    classDef ataque fill:#ffcc00,stroke:#b38600,stroke-width:2px,color:#000000;
    classDef passo fill:#99ccff,stroke:#0066cc,stroke-width:2px,color:#000000;
    classDef sucesso fill:#66cc66,stroke:#2d862d,stroke-width:2px,color:#000000;

    class A objetivo;
    class B,C ataque;
    class D,E,F,G passo;
    class H,I sucesso;

```

---

## Session Hijacking via JWT Cookie

A configuração atual inclui:

```python
JWT_COOKIE_SECURE = False
```

Isto significa que **o cookie pode ser enviado em conexões HTTP inseguras**.

Em uma rede Wi-Fi pública, um atacante pode:

* Farejar o tráfego,
* Capturar o cookie de sessão (JWT),
* Assumir a identidade da vítima.

```mermaid
graph TD

    A[Objetivo: assumir a sessão de outro utilizador]

    A --> B[O cookie JWT não utiliza a flag Secure]
    B --> C[A aplicação é acedida através de HTTP inseguro]
    C --> D[Atacante captura o cookie na rede]
    D --> E[Atacante envia pedidos autenticados com o cookie roubado]
    E --> F[Servidor aceita o JWT como válido]
    F --> G[Sucesso: sequestro de sessão]

    classDef objetivo fill:#ff6666,stroke:#b30000,stroke-width:2px,color:#ffffff;
    classDef ataque fill:#ffcc00,stroke:#b38600,stroke-width:2px,color:#000000;
    classDef passo fill:#99ccff,stroke:#0066cc,stroke-width:2px,color:#000000;
    classDef sucesso fill:#66cc66,stroke:#2d862d,stroke-width:2px,color:#000000;

    class A objetivo;
    class B,C ataque;
    class D,E,F passo;
    class G sucesso;
```