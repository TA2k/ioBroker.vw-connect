.class public interface abstract Lorg/eclipse/paho/mqttv5/client/spi/NetworkModuleFactory;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public abstract createNetworkModule(Ljava/net/URI;Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/internal/NetworkModule;
.end method

.method public abstract getSupportedUriSchemes()Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end method

.method public abstract validateURI(Ljava/net/URI;)V
.end method
