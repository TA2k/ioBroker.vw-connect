.class public Lorg/eclipse/paho/mqttv5/client/websocket/Base64$Base64Encoder;
.super Ljava/util/prefs/AbstractPreferences;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lorg/eclipse/paho/mqttv5/client/websocket/Base64;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "Base64Encoder"
.end annotation


# instance fields
.field private base64String:Ljava/lang/String;

.field final synthetic this$0:Lorg/eclipse/paho/mqttv5/client/websocket/Base64;


# direct methods
.method public constructor <init>(Lorg/eclipse/paho/mqttv5/client/websocket/Base64;)V
    .locals 1

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/websocket/Base64$Base64Encoder;->this$0:Lorg/eclipse/paho/mqttv5/client/websocket/Base64;

    .line 2
    .line 3
    const-string p1, ""

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    invoke-direct {p0, v0, p1}, Ljava/util/prefs/AbstractPreferences;-><init>(Ljava/util/prefs/AbstractPreferences;Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/websocket/Base64$Base64Encoder;->base64String:Ljava/lang/String;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public childSpi(Ljava/lang/String;)Ljava/util/prefs/AbstractPreferences;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method

.method public childrenNamesSpi()[Ljava/lang/String;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method

.method public flushSpi()V
    .locals 0

    .line 1
    return-void
.end method

.method public getBase64String()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/websocket/Base64$Base64Encoder;->base64String:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getSpi(Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method

.method public keysSpi()[Ljava/lang/String;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method

.method public putSpi(Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p2, p0, Lorg/eclipse/paho/mqttv5/client/websocket/Base64$Base64Encoder;->base64String:Ljava/lang/String;

    .line 2
    .line 3
    return-void
.end method

.method public removeNodeSpi()V
    .locals 0

    .line 1
    return-void
.end method

.method public removeSpi(Ljava/lang/String;)V
    .locals 0

    .line 1
    return-void
.end method

.method public syncSpi()V
    .locals 0

    .line 1
    return-void
.end method
