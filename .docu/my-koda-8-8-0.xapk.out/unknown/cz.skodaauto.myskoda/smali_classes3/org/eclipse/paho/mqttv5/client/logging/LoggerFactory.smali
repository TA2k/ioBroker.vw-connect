.class public Lorg/eclipse/paho/mqttv5/client/logging/LoggerFactory;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final CLASS_NAME:Ljava/lang/String; = "org.eclipse.paho.mqttv5.client.logging.LoggerFactory"

.field public static final MQTT_CLIENT_MSG_CAT:Ljava/lang/String; = "org.eclipse.paho.mqttv5.client.internal.nls.logcat"

.field private static jsr47LoggerClassName:Ljava/lang/String;

.field private static overrideloggerClassName:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-class v0, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lorg/eclipse/paho/mqttv5/client/logging/LoggerFactory;->jsr47LoggerClassName:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static getLogger(Ljava/lang/String;Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/logging/Logger;
    .locals 2

    .line 1
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/logging/LoggerFactory;->overrideloggerClassName:Ljava/lang/String;

    if-nez v0, :cond_0

    .line 2
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/logging/LoggerFactory;->jsr47LoggerClassName:Ljava/lang/String;

    .line 3
    :cond_0
    invoke-static {p0}, Ljava/util/ResourceBundle;->getBundle(Ljava/lang/String;)Ljava/util/ResourceBundle;

    move-result-object p0

    const/4 v1, 0x0

    invoke-static {v0, p0, p1, v1}, Lorg/eclipse/paho/mqttv5/client/logging/LoggerFactory;->getLogger(Ljava/lang/String;Ljava/util/ResourceBundle;Ljava/lang/String;Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    move-result-object p0

    if-eqz p0, :cond_1

    return-object p0

    .line 4
    :cond_1
    new-instance p0, Ljava/util/MissingResourceException;

    const-string v0, "Error locating the logging class"

    sget-object v1, Lorg/eclipse/paho/mqttv5/client/logging/LoggerFactory;->CLASS_NAME:Ljava/lang/String;

    invoke-direct {p0, v0, v1, p1}, Ljava/util/MissingResourceException;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    throw p0
.end method

.method private static getLogger(Ljava/lang/String;Ljava/util/ResourceBundle;Ljava/lang/String;Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/logging/Logger;
    .locals 1

    const/4 v0, 0x0

    .line 5
    :try_start_0
    invoke-static {p0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    move-result-object p0
    :try_end_0
    .catch Ljava/lang/NoClassDefFoundError; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/ClassNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 6
    :try_start_1
    invoke-virtual {p0}, Ljava/lang/Class;->newInstance()Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Lorg/eclipse/paho/mqttv5/client/logging/Logger;
    :try_end_1
    .catch Ljava/lang/IllegalAccessException; {:try_start_1 .. :try_end_1} :catch_0
    .catch Ljava/lang/InstantiationException; {:try_start_1 .. :try_end_1} :catch_0
    .catch Ljava/lang/ExceptionInInitializerError; {:try_start_1 .. :try_end_1} :catch_0
    .catch Ljava/lang/SecurityException; {:try_start_1 .. :try_end_1} :catch_0

    .line 7
    invoke-interface {p0, p1, p2, p3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->initialise(Ljava/util/ResourceBundle;Ljava/lang/String;Ljava/lang/String;)V

    return-object p0

    :catch_0
    return-object v0
.end method

.method public static getLoggingProperty(Ljava/lang/String;)Ljava/lang/String;
    .locals 5

    .line 1
    const/4 v0, 0x0

    .line 2
    :try_start_0
    const-string v1, "java.util.logging.LogManager"

    .line 3
    .line 4
    invoke-static {v1}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    .line 5
    .line 6
    .line 7
    move-result-object v1

    .line 8
    const-string v2, "getLogManager"

    .line 9
    .line 10
    invoke-virtual {v1, v2, v0}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    invoke-virtual {v2, v0, v0}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    const-string v3, "getProperty"

    .line 19
    .line 20
    const-class v4, Ljava/lang/String;

    .line 21
    .line 22
    filled-new-array {v4}, [Ljava/lang/Class;

    .line 23
    .line 24
    .line 25
    move-result-object v4

    .line 26
    invoke-virtual {v1, v3, v4}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    invoke-virtual {v1, v2, p0}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    check-cast p0, Ljava/lang/String;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 39
    .line 40
    return-object p0

    .line 41
    :catch_0
    return-object v0
.end method

.method public static setLogger(Ljava/lang/String;)V
    .locals 0

    .line 1
    sput-object p0, Lorg/eclipse/paho/mqttv5/client/logging/LoggerFactory;->overrideloggerClassName:Ljava/lang/String;

    .line 2
    .line 3
    return-void
.end method
