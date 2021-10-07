======
Source
======

The source for this project is available `here <>`_.

------------
Requirements
------------

* Java JDK 8
* `Apache Maven <https://maven.apache.org/>`_
* `Confluent Open Source <https://www.confluent.io/download/>`_
* `Docker <https://www.docker.com/get-docker>`_

.. NOTE::
    Confluent Open Source is not a hard requirement to run this connector. Most of the scripts and configurations that are
    stored in the repository utilize the `Confluent Schema Registry <https://github.com/confluentinc/schema-registry>`_ as
    the preferred method of serialization.


----------------------------
Building on your workstation
----------------------------

    cd EncryptFieldTest
    mvn clean package

-------------------------------------
Setting up docker on your workstation
-------------------------------------

The following entries need to be added to the hosts file on your workstation.

.. code-block:: text

    127.0.0.1 zookeeper
    127.0.0.1 kafka
    127.0.0.1 schema-registry

Start kafka on your workstation

.. code-block:: bash

    docker-compose up -d

-----------------------------
Debugging on your workstation
-----------------------------

.. code-block:: bash

    ./bin/debug.sh

^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Suspend until a debugger is attached
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

    export SUSPEND='y'
    ./bin/debug.sh


Attach your debugger to port 5005.