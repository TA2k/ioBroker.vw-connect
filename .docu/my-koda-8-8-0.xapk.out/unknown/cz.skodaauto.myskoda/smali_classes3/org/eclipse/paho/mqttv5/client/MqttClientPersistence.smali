.class public interface abstract Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public abstract clear()V
.end method

.method public abstract close()V
.end method

.method public abstract containsKey(Ljava/lang/String;)Z
.end method

.method public abstract get(Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/common/MqttPersistable;
.end method

.method public abstract keys()Ljava/util/Enumeration;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Enumeration<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end method

.method public abstract open(Ljava/lang/String;)V
.end method

.method public abstract put(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/common/MqttPersistable;)V
.end method

.method public abstract remove(Ljava/lang/String;)V
.end method
