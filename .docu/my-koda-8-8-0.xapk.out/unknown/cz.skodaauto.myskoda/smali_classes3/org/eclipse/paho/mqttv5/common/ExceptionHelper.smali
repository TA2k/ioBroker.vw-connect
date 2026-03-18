.class public Lorg/eclipse/paho/mqttv5/common/ExceptionHelper;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static createMqttException(I)Lorg/eclipse/paho/mqttv5/common/MqttException;
    .locals 1

    .line 1
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    invoke-direct {v0, p0}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(I)V

    return-object v0
.end method

.method public static createMqttException(Ljava/lang/Throwable;)Lorg/eclipse/paho/mqttv5/common/MqttException;
    .locals 1

    .line 2
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    invoke-direct {v0, p0}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(Ljava/lang/Throwable;)V

    return-object v0
.end method

.method public static isClassAvailable(Ljava/lang/String;)Z
    .locals 0

    .line 1
    :try_start_0
    invoke-static {p0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;
    :try_end_0
    .catch Ljava/lang/ClassNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 2
    .line 3
    .line 4
    const/4 p0, 0x1

    .line 5
    return p0

    .line 6
    :catch_0
    const/4 p0, 0x0

    .line 7
    return p0
.end method
