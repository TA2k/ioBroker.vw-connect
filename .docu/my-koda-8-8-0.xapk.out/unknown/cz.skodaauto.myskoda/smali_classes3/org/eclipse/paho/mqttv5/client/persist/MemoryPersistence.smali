.class public Lorg/eclipse/paho/mqttv5/client/persist/MemoryPersistence;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;


# instance fields
.field private data:Ljava/util/Hashtable;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Hashtable<",
            "Ljava/lang/String;",
            "Lorg/eclipse/paho/mqttv5/common/MqttPersistable;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private checkIsOpen()V
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/persist/MemoryPersistence;->data:Ljava/util/Hashtable;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/MqttPersistenceException;

    .line 7
    .line 8
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/common/MqttPersistenceException;-><init>()V

    .line 9
    .line 10
    .line 11
    throw p0
.end method


# virtual methods
.method public clear()V
    .locals 0

    .line 1
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/client/persist/MemoryPersistence;->checkIsOpen()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/persist/MemoryPersistence;->data:Ljava/util/Hashtable;

    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/util/Hashtable;->clear()V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public close()V
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/persist/MemoryPersistence;->data:Ljava/util/Hashtable;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/util/Hashtable;->clear()V

    .line 6
    .line 7
    .line 8
    :cond_0
    return-void
.end method

.method public containsKey(Ljava/lang/String;)Z
    .locals 0

    .line 1
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/client/persist/MemoryPersistence;->checkIsOpen()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/persist/MemoryPersistence;->data:Ljava/util/Hashtable;

    .line 5
    .line 6
    invoke-virtual {p0, p1}, Ljava/util/Hashtable;->containsKey(Ljava/lang/Object;)Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method

.method public get(Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/common/MqttPersistable;
    .locals 0

    .line 1
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/client/persist/MemoryPersistence;->checkIsOpen()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/persist/MemoryPersistence;->data:Ljava/util/Hashtable;

    .line 5
    .line 6
    invoke-virtual {p0, p1}, Ljava/util/Hashtable;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    check-cast p0, Lorg/eclipse/paho/mqttv5/common/MqttPersistable;

    .line 11
    .line 12
    return-object p0
.end method

.method public keys()Ljava/util/Enumeration;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Enumeration<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/client/persist/MemoryPersistence;->checkIsOpen()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/persist/MemoryPersistence;->data:Ljava/util/Hashtable;

    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/util/Hashtable;->keys()Ljava/util/Enumeration;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0
.end method

.method public open(Ljava/lang/String;)V
    .locals 0

    .line 1
    new-instance p1, Ljava/util/Hashtable;

    .line 2
    .line 3
    invoke-direct {p1}, Ljava/util/Hashtable;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/persist/MemoryPersistence;->data:Ljava/util/Hashtable;

    .line 7
    .line 8
    return-void
.end method

.method public put(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/common/MqttPersistable;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/client/persist/MemoryPersistence;->checkIsOpen()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/persist/MemoryPersistence;->data:Ljava/util/Hashtable;

    .line 5
    .line 6
    invoke-virtual {p0, p1, p2}, Ljava/util/Hashtable;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public remove(Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/client/persist/MemoryPersistence;->checkIsOpen()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/persist/MemoryPersistence;->data:Ljava/util/Hashtable;

    .line 5
    .line 6
    invoke-virtual {p0, p1}, Ljava/util/Hashtable;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    return-void
.end method
