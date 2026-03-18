.class public abstract Lorg/eclipse/paho/mqttv5/client/internal/MessageCatalog;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static INSTANCE:Lorg/eclipse/paho/mqttv5/client/internal/MessageCatalog;


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

.method public static final getMessage(I)Ljava/lang/String;
    .locals 3

    .line 1
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/internal/MessageCatalog;->INSTANCE:Lorg/eclipse/paho/mqttv5/client/internal/MessageCatalog;

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    const-string v0, "java.util.ResourceBundle"

    .line 6
    .line 7
    invoke-static {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ExceptionHelper;->isClassAvailable(Ljava/lang/String;)Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    const-string v1, ""

    .line 12
    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    :try_start_0
    const-class v0, Lorg/eclipse/paho/mqttv5/client/internal/ResourceBundleCatalog;

    .line 16
    .line 17
    invoke-virtual {v0}, Ljava/lang/Class;->newInstance()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    check-cast v0, Lorg/eclipse/paho/mqttv5/client/internal/MessageCatalog;

    .line 22
    .line 23
    sput-object v0, Lorg/eclipse/paho/mqttv5/client/internal/MessageCatalog;->INSTANCE:Lorg/eclipse/paho/mqttv5/client/internal/MessageCatalog;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :catch_0
    return-object v1

    .line 27
    :cond_0
    const-string v0, "org.eclipse.paho.mqttv5.client.internal.MIDPCatalog"

    .line 28
    .line 29
    invoke-static {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ExceptionHelper;->isClassAvailable(Ljava/lang/String;)Z

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    if-eqz v2, :cond_1

    .line 34
    .line 35
    :try_start_1
    invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    invoke-virtual {v0}, Ljava/lang/Class;->newInstance()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    check-cast v0, Lorg/eclipse/paho/mqttv5/client/internal/MessageCatalog;

    .line 44
    .line 45
    sput-object v0, Lorg/eclipse/paho/mqttv5/client/internal/MessageCatalog;->INSTANCE:Lorg/eclipse/paho/mqttv5/client/internal/MessageCatalog;
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :catch_1
    return-object v1

    .line 49
    :cond_1
    :goto_0
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/internal/MessageCatalog;->INSTANCE:Lorg/eclipse/paho/mqttv5/client/internal/MessageCatalog;

    .line 50
    .line 51
    invoke-virtual {v0, p0}, Lorg/eclipse/paho/mqttv5/client/internal/MessageCatalog;->getLocalizedMessage(I)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    return-object p0
.end method


# virtual methods
.method public abstract getLocalizedMessage(I)Ljava/lang/String;
.end method
