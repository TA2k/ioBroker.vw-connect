.class public Lorg/eclipse/paho/mqttv5/client/internal/ResourceBundleCatalog;
.super Lorg/eclipse/paho/mqttv5/client/internal/MessageCatalog;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private bundle:Ljava/util/ResourceBundle;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/client/internal/MessageCatalog;-><init>()V

    .line 2
    .line 3
    .line 4
    const-string v0, "org.eclipse.paho.mqttv5.client.internal.nls.messages"

    .line 5
    .line 6
    invoke-static {v0}, Ljava/util/ResourceBundle;->getBundle(Ljava/lang/String;)Ljava/util/ResourceBundle;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ResourceBundleCatalog;->bundle:Ljava/util/ResourceBundle;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public getLocalizedMessage(I)Ljava/lang/String;
    .locals 0

    .line 1
    :try_start_0
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ResourceBundleCatalog;->bundle:Ljava/util/ResourceBundle;

    .line 2
    .line 3
    invoke-static {p1}, Ljava/lang/Integer;->toString(I)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p0, p1}, Ljava/util/ResourceBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0
    :try_end_0
    .catch Ljava/util/MissingResourceException; {:try_start_0 .. :try_end_0} :catch_0

    .line 11
    return-object p0

    .line 12
    :catch_0
    const-string p0, "MqttException"

    .line 13
    .line 14
    return-object p0
.end method
