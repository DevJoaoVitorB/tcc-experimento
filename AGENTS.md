# Instruções Gerais do Projeto

## 1. Documentação

Antes de iniciar o desenvolvimento, leia todos os documentos disponíveis na pasta `docs/` e considere as instruções e especificações neles contidas durante a implementação da aplicação.

## 2. Tecnologias

Utilize as seguintes tecnologias no desenvolvimento:

- **Express** para desenvolvimento da API;
- **TypeScript** como linguagem de desenvolvimento;
- **Prisma** para gerenciamento e acesso ao banco de dados;
- **SQLite** como banco de dados.

## 3. Arquitetura e implementação

Defina livremente a arquitetura, a organização dos arquivos, os componentes internos e as estratégias de implementação necessárias para atender às especificações, respeitando as tecnologias especificadas.

## 4. Modelagem de dados

Defina a modelagem de dados com base nos requisitos funcionais especificados, contemplando os dados necessários para o funcionamento da aplicação, com liberdade para determinar sua estrutura e organização.

## 5. Configuração e execução

Crie os arquivos de configuração e os componentes necessários para instalar, executar e testar a aplicação, incluindo os arquivos necessários para construir uma imagem Docker e executar a aplicação em um container.

## 6. Verificação

Execute as verificações e os testes pertinentes ao funcionamento da aplicação, quando houver condições para executá-los, e corrija os erros funcionais identificados em relação aos requisitos especificados.

## 7. Documentação da API

Disponibilize a especificação da API em formato OpenAPI JSON, acessível durante a execução da aplicação pelo caminho `/openapi.json`, para permitir seu consumo automatizado por pipelines de CI/CD.

A especificação deve contemplar as rotas implementadas, os métodos HTTP, os parâmetros, os dados de entrada e saída e as respostas correspondentes ao comportamento implementado.

Mantenha a especificação consistente com a implementação, atualizando-a quando houver alterações nos elementos documentados.

A implementação poderá utilizar qualquer mecanismo compatível com esses requisitos, sem impor uma biblioteca específica ou uma estrutura de arquivos predeterminada para isso.

## 8. Escopo

Implemente todos os requisitos funcionais especificados, tomando as decisões técnicas necessárias para atender ao comportamento esperado da aplicação.

Não considere funcionalidades, mecanismos ou requisitos adicionais como obrigatórios, exceto quando forem necessários para implementar os requisitos especificados ou garantir o funcionamento da aplicação.
