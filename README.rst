Keystone role assignments backend plugin OpenFGA
================================================

This project implements a backend plugin for Keystone to manage role
assignments not in the Keystone database, but in the `OpenFGA
<https://openfga.dev/>`_.

It is expected that every role assignment in Keystone context is represented by
a relation in the OpenFGA (ReBAC) between user/group and project/domain.

.. code-block::

   model
     schema 1.1

   type domain

   type user
     relations
       define owner: [domain]

   type group
     relations
       define member: [user, group#member]
       define owner: [domain]

   type project
     relations
       define admin: [user, group#member]
       define manager: [user, group#member] or admin
       define member: [user, group#member] or admin or manager
       define owner: [domain]
       define reader: [user, group#member] or member or admin
       define service: [system]

   type system
     relations
       define admin: [user, group#member]
       define member: [user, group#member] or admin
       define reader: [user, group#member] or member or admin
       define system: [user, group#member]

Delegating role assignments to the OpenFGA allows to improve integration of
OpenStack with the external IdP and authorization system to centrally manage
user authorizations for different service providers (improves service provider
role of OpenStack).

Installation
------------

For the moment the project is not being published to the PyPi so you can
install it from git repository.

Install the project into the virtual environment with the Keystone using `pip
install .`

Configuration
-------------

In order to enable the integration it is necessary to make few changes in the `keystone.conf`

.. code-block:: ini

   [fga]
   api_url = <OPEN_FGA_URL>
   store_id = <OPENFGA_STORE_ID>
   model_id = <OPENFGA_MODEL_ID>

   ...

   [assignment]
   driver = openfga


Additional considerations
-------------------------

1. OpenFGA must be highly available. In this deployment style OpenStack will
   query OpenFGA for at least every authentication request.

2. Having many roles requires expanding OpenFGA authorization model to define
   every role as a relation. This is not very scalable but at the same time
   unavoidable due to the nature of role assignments in OpenStack being a
   triplets (actor-role-object).

3. Keystone and OpenFGA both have methods of inheriting/inferring roles through
   role inferrence, group membership, domain to project delegation and so on.
   Currently Keystone does not support delegating such decisions to the backend
   and instead reimplements it internally. This has an effect that when certain
   role is granted between assignee and the object it is not possible to learn
   how is this achieved (as a direct assignment of through inheritance). It is
   strongly advised to keep role inferrence and user/group relations in sync
   between Keystone and OpenFGA to reduce confusion.

