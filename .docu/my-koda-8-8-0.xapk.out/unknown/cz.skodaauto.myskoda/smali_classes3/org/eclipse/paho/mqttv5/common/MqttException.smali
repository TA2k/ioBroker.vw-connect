.class public Lorg/eclipse/paho/mqttv5/common/MqttException;
.super Ljava/lang/Exception;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final REASON_CODE_CLIENT_EXCEPTION:S = 0x0s

.field public static final REASON_CODE_DUPLICATE_PROPERTY:I = 0xc355

.field public static final REASON_CODE_INVALID_IDENTIFIER:I = 0xc350

.field public static final REASON_CODE_INVALID_RETURN_CODE:I = 0xc351

.field public static final REASON_CODE_INVALID_TOPIC_ALAS:I = 0xc354

.field public static final REASON_CODE_MALFORMED_PACKET:I = 0xc352

.field public static final REASON_CODE_UNSUPPORTED_PROTOCOL_VERSION:I = 0xc353

.field private static final serialVersionUID:J = 0x1L


# instance fields
.field private cause:Ljava/lang/Throwable;

.field private disconnectReasonCode:I

.field private disconnectReasonString:Ljava/lang/String;

.field private reasonCode:I


# direct methods
.method public constructor <init>(I)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Exception;-><init>()V

    const/4 v0, 0x0

    .line 2
    iput v0, p0, Lorg/eclipse/paho/mqttv5/common/MqttException;->disconnectReasonCode:I

    .line 3
    iput p1, p0, Lorg/eclipse/paho/mqttv5/common/MqttException;->reasonCode:I

    return-void
.end method

.method public constructor <init>(ILjava/lang/Throwable;)V
    .locals 1

    .line 14
    invoke-direct {p0}, Ljava/lang/Exception;-><init>()V

    const/4 v0, 0x0

    .line 15
    iput v0, p0, Lorg/eclipse/paho/mqttv5/common/MqttException;->disconnectReasonCode:I

    .line 16
    iput p1, p0, Lorg/eclipse/paho/mqttv5/common/MqttException;->reasonCode:I

    .line 17
    iput-object p2, p0, Lorg/eclipse/paho/mqttv5/common/MqttException;->cause:Ljava/lang/Throwable;

    return-void
.end method

.method public constructor <init>(ILorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;)V
    .locals 1

    .line 4
    invoke-direct {p0}, Ljava/lang/Exception;-><init>()V

    const/4 v0, 0x0

    .line 5
    iput v0, p0, Lorg/eclipse/paho/mqttv5/common/MqttException;->disconnectReasonCode:I

    .line 6
    iput p1, p0, Lorg/eclipse/paho/mqttv5/common/MqttException;->reasonCode:I

    if-eqz p2, :cond_0

    .line 7
    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;->getReturnCode()I

    move-result p1

    iput p1, p0, Lorg/eclipse/paho/mqttv5/common/MqttException;->disconnectReasonCode:I

    .line 8
    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;->getProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    move-result-object p1

    if-eqz p1, :cond_0

    .line 9
    invoke-virtual {p2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDisconnect;->getProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    move-result-object p1

    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->getReasonString()Ljava/lang/String;

    move-result-object p1

    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/MqttException;->disconnectReasonString:Ljava/lang/String;

    :cond_0
    return-void
.end method

.method public constructor <init>(Ljava/lang/Throwable;)V
    .locals 1

    .line 10
    invoke-direct {p0}, Ljava/lang/Exception;-><init>()V

    const/4 v0, 0x0

    .line 11
    iput v0, p0, Lorg/eclipse/paho/mqttv5/common/MqttException;->disconnectReasonCode:I

    .line 12
    iput v0, p0, Lorg/eclipse/paho/mqttv5/common/MqttException;->reasonCode:I

    .line 13
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/MqttException;->cause:Ljava/lang/Throwable;

    return-void
.end method


# virtual methods
.method public getCause()Ljava/lang/Throwable;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/MqttException;->cause:Ljava/lang/Throwable;

    .line 2
    .line 3
    return-object p0
.end method

.method public getMessage()Ljava/lang/String;
    .locals 2

    .line 1
    const-string v0, "org.eclipse.paho.mqttv5.common.nls.messages"

    .line 2
    .line 3
    invoke-static {v0}, Ljava/util/ResourceBundle;->getBundle(Ljava/lang/String;)Ljava/util/ResourceBundle;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    :try_start_0
    iget v1, p0, Lorg/eclipse/paho/mqttv5/common/MqttException;->reasonCode:I

    .line 8
    .line 9
    invoke-static {v1}, Ljava/lang/Integer;->toString(I)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    invoke-virtual {v0, v1}, Ljava/util/ResourceBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v0
    :try_end_0
    .catch Ljava/util/MissingResourceException; {:try_start_0 .. :try_end_0} :catch_0

    .line 17
    goto :goto_0

    .line 18
    :catch_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 19
    .line 20
    const-string v1, "Untranslated MqttException - RC: "

    .line 21
    .line 22
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    iget v1, p0, Lorg/eclipse/paho/mqttv5/common/MqttException;->reasonCode:I

    .line 26
    .line 27
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    :goto_0
    iget v1, p0, Lorg/eclipse/paho/mqttv5/common/MqttException;->disconnectReasonCode:I

    .line 35
    .line 36
    if-eqz v1, :cond_0

    .line 37
    .line 38
    new-instance v1, Ljava/lang/StringBuilder;

    .line 39
    .line 40
    invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    invoke-direct {v1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    const-string v0, " Disconnect RC: "

    .line 48
    .line 49
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    iget v0, p0, Lorg/eclipse/paho/mqttv5/common/MqttException;->disconnectReasonCode:I

    .line 53
    .line 54
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    :cond_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/MqttException;->disconnectReasonString:Ljava/lang/String;

    .line 62
    .line 63
    if-eqz v1, :cond_1

    .line 64
    .line 65
    new-instance v1, Ljava/lang/StringBuilder;

    .line 66
    .line 67
    invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    invoke-direct {v1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    const-string v0, " Disconnect Reason: "

    .line 75
    .line 76
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/MqttException;->disconnectReasonString:Ljava/lang/String;

    .line 80
    .line 81
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object v0

    .line 88
    :cond_1
    return-object v0
.end method

.method public getReasonCode()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/eclipse/paho/mqttv5/common/MqttException;->reasonCode:I

    .line 2
    .line 3
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/common/MqttException;->getMessage()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-static {v1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    const-string v1, " ("

    .line 15
    .line 16
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    iget v1, p0, Lorg/eclipse/paho/mqttv5/common/MqttException;->reasonCode:I

    .line 20
    .line 21
    const-string v2, ")"

    .line 22
    .line 23
    invoke-static {v1, v2, v0}, Lu/w;->d(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/MqttException;->cause:Ljava/lang/Throwable;

    .line 28
    .line 29
    if-eqz v1, :cond_0

    .line 30
    .line 31
    new-instance v1, Ljava/lang/StringBuilder;

    .line 32
    .line 33
    invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    invoke-direct {v1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    const-string v0, " - "

    .line 41
    .line 42
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/MqttException;->cause:Ljava/lang/Throwable;

    .line 46
    .line 47
    invoke-virtual {p0}, Ljava/lang/Throwable;->toString()Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    return-object p0

    .line 59
    :cond_0
    return-object v0
.end method
