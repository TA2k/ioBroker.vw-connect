.class public Lorg/eclipse/paho/mqttv5/client/MqttToken;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lorg/eclipse/paho/mqttv5/client/IMqttToken;


# instance fields
.field private client:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

.field public internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 2
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->client:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 3
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;)V
    .locals 1

    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 8
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->client:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 9
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 10
    new-instance v0, Lorg/eclipse/paho/mqttv5/client/internal/Token;

    invoke-direct {v0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/Token;-><init>(Ljava/lang/String;)V

    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    return-void
.end method

.method public constructor <init>(Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;)V
    .locals 1

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 5
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 6
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->client:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    return-void
.end method


# virtual methods
.method public getActionCallback()Lorg/eclipse/paho/mqttv5/client/MqttActionListener;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 2
    .line 3
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getActionCallback()Lorg/eclipse/paho/mqttv5/client/MqttActionListener;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getClient()Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 2
    .line 3
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getClient()Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getException()Lorg/eclipse/paho/mqttv5/common/MqttException;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 2
    .line 3
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getException()Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getGrantedQos()[I
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 2
    .line 3
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getGrantedQos()[I

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getMessage()Lorg/eclipse/paho/mqttv5/common/MqttMessage;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 2
    .line 3
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getMessage()Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getMessageId()I
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 2
    .line 3
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getMessageID()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public getReasonCodes()[I
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 2
    .line 3
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getReasonCodes()[I

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getRequestMessage()Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 2
    .line 3
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getRequestMessage()Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getRequestProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 2
    .line 3
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getRequestMessage()Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    return-object p0

    .line 11
    :cond_0
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 12
    .line 13
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getRequestMessage()Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0
.end method

.method public getResponse()Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 2
    .line 3
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getResponse()Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getResponseProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 2
    .line 3
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getWireMessage()Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    return-object p0

    .line 11
    :cond_0
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 12
    .line 13
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getWireMessage()Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0
.end method

.method public getSessionPresent()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 2
    .line 3
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getSessionPresent()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public getTopics()[Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 2
    .line 3
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getTopics()[Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getUserContext()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 2
    .line 3
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getUserContext()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public isComplete()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 2
    .line 3
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->isComplete()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public setActionCallback(Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->setActionCallback(Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public setMessage(Lorg/eclipse/paho/mqttv5/common/MqttMessage;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->setMessage(Lorg/eclipse/paho/mqttv5/common/MqttMessage;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public setRequestMessage(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->setRequestMessage(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public setUserContext(Ljava/lang/Object;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->setUserContext(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public waitForCompletion()V
    .locals 2

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    const-wide/16 v0, -0x1

    invoke-virtual {p0, v0, v1}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->waitForCompletion(J)V

    return-void
.end method

.method public waitForCompletion(J)V
    .locals 0

    .line 2
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    invoke-virtual {p0, p1, p2}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->waitForCompletion(J)V

    return-void
.end method
