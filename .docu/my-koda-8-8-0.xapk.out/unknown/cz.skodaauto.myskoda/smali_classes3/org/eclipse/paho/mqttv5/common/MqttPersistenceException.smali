.class public Lorg/eclipse/paho/mqttv5/common/MqttPersistenceException;
.super Lorg/eclipse/paho/mqttv5/common/MqttException;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final REASON_CODE_PERSISTENCE_IN_USE:S = 0x7dc8s

.field private static final serialVersionUID:J = 0x12cL


# direct methods
.method public constructor <init>()V
    .locals 1

    const/4 v0, 0x0

    .line 1
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(I)V

    return-void
.end method

.method public constructor <init>(I)V
    .locals 0

    .line 2
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(I)V

    return-void
.end method

.method public constructor <init>(ILjava/lang/Throwable;)V
    .locals 0

    .line 4
    invoke-direct {p0, p1, p2}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(ILjava/lang/Throwable;)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/Throwable;)V
    .locals 0

    .line 3
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(Ljava/lang/Throwable;)V

    return-void
.end method
