# Especificações — Requisitos Funcionais

## RF01 — Cadastro de usuário

O sistema deve permitir o cadastro de novos usuários utilizando nome, e-mail e senha.

## RF02 — Autenticação de usuário

O sistema deve permitir que usuários cadastrados realizem autenticação utilizando e-mail e senha. Após uma autenticação válida, o sistema deverá estabelecer a sessão autenticada utilizando um token de acesso e um refresh token.

## RF03 — Validação de credenciais

O sistema deve verificar se as credenciais informadas correspondem a um usuário cadastrado antes de permitir o acesso ao sistema.

## RF04 — Controle de acesso

O sistema deve possuir rotas protegidas e restringir seu acesso a usuários autenticados.

## RF05 — Autorização de usuários

O sistema deve verificar a identidade do usuário autenticado em rotas protegidas e garantir que ele tenha permissão para acessar ou realizar operações sobre os recursos solicitados.

## RF06 — Encerramento de sessão

O sistema deve permitir que o usuário encerre sua sessão.

## RF07 — Perfil do usuário

O sistema deve permitir a consulta das informações do usuário autenticado.
