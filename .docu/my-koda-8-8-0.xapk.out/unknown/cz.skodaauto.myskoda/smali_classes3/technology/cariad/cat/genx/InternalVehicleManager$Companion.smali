.class public final Ltechnology/cariad/cat/genx/InternalVehicleManager$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/genx/InternalVehicleManager;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000V\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0008\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\"\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0008\u0086\u0003\u0018\u00002\u00020\u0001B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J|\u0010\u001b\u001a\u00020\u001a2\u0006\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0007\u001a\u00020\u00062\u0006\u0010\t\u001a\u00020\u00082\u0006\u0010\u000b\u001a\u00020\n2\u0008\u0008\u0002\u0010\r\u001a\u00020\u000c2\u0008\u0008\u0002\u0010\u000f\u001a\u00020\u000e2\u0008\u0008\u0002\u0010\u0010\u001a\u00020\u000e2\u0008\u0008\u0002\u0010\u0012\u001a\u00020\u00112\u0008\u0008\u0002\u0010\u0014\u001a\u00020\u00132\u0008\u0008\u0002\u0010\u0016\u001a\u00020\u00152\u000e\u0008\u0002\u0010\u0019\u001a\u0008\u0012\u0004\u0012\u00020\u00180\u0017H\u0086\u0002\u00a2\u0006\u0004\u0008\u001b\u0010\u001c\u00a8\u0006\u001d"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/InternalVehicleManager$Companion;",
        "",
        "<init>",
        "()V",
        "Landroid/content/Context;",
        "context",
        "Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;",
        "keyPair",
        "Ltechnology/cariad/cat/genx/DeviceInformation;",
        "deviceInformation",
        "Lu51/g;",
        "secureStorage",
        "Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;",
        "bluetoothScanMode",
        "",
        "bluetoothConnectRetryCount",
        "bluetoothConnectRetryDelay",
        "Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;",
        "linkedParameters",
        "Lvy0/i1;",
        "supervisorJob",
        "Lvy0/x;",
        "ioDispatcher",
        "",
        "Ltechnology/cariad/cat/genx/TransportType;",
        "supportedTransportTypes",
        "Ltechnology/cariad/cat/genx/VehicleManager;",
        "invoke",
        "(Landroid/content/Context;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;Ltechnology/cariad/cat/genx/DeviceInformation;Lu51/g;Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;IILtechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Lvy0/i1;Lvy0/x;Ljava/util/Set;)Ltechnology/cariad/cat/genx/VehicleManager;",
        "genx_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field static final synthetic $$INSTANCE:Ltechnology/cariad/cat/genx/InternalVehicleManager$Companion;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/InternalVehicleManager$Companion;

    .line 2
    .line 3
    invoke-direct {v0}, Ltechnology/cariad/cat/genx/InternalVehicleManager$Companion;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Ltechnology/cariad/cat/genx/InternalVehicleManager$Companion;->$$INSTANCE:Ltechnology/cariad/cat/genx/InternalVehicleManager$Companion;

    .line 7
    .line 8
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic a(Ljava/util/ArrayList;Lvy0/x;Landroid/content/Context;Lvy0/i1;Ltechnology/cariad/cat/genx/GenXDispatcher;)Ltechnology/cariad/cat/genx/ClientManager;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3, p4}, Ltechnology/cariad/cat/genx/InternalVehicleManager$Companion;->invoke$lambda$0$1(Ljava/util/List;Lvy0/x;Landroid/content/Context;Lvy0/i1;Ltechnology/cariad/cat/genx/GenXDispatcher;)Ltechnology/cariad/cat/genx/ClientManager;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic b()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/InternalVehicleManager$Companion;->invoke$lambda$0$0$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic c(Ljava/util/ArrayList;Landroid/content/Context;Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;IILtechnology/cariad/cat/genx/GenXDispatcher;)Ltechnology/cariad/cat/genx/ClientManager;
    .locals 0

    .line 1
    invoke-static/range {p0 .. p5}, Ltechnology/cariad/cat/genx/InternalVehicleManager$Companion;->invoke$lambda$0$0(Ljava/util/List;Landroid/content/Context;Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;IILtechnology/cariad/cat/genx/GenXDispatcher;)Ltechnology/cariad/cat/genx/ClientManager;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic d()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/InternalVehicleManager$Companion;->invoke$lambda$0$1$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static invoke$default(Ltechnology/cariad/cat/genx/InternalVehicleManager$Companion;Landroid/content/Context;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;Ltechnology/cariad/cat/genx/DeviceInformation;Lu51/g;Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;IILtechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Lvy0/i1;Lvy0/x;Ljava/util/Set;ILjava/lang/Object;)Ltechnology/cariad/cat/genx/VehicleManager;
    .locals 17

    .line 1
    move/from16 v0, p12

    .line 2
    .line 3
    and-int/lit8 v1, v0, 0x10

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    sget-object v1, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;->BALANCED:Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;

    .line 8
    .line 9
    move-object v7, v1

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    move-object/from16 v7, p5

    .line 12
    .line 13
    :goto_0
    and-int/lit8 v1, v0, 0x20

    .line 14
    .line 15
    if-eqz v1, :cond_1

    .line 16
    .line 17
    const/4 v1, 0x3

    .line 18
    move v8, v1

    .line 19
    goto :goto_1

    .line 20
    :cond_1
    move/from16 v8, p6

    .line 21
    .line 22
    :goto_1
    and-int/lit8 v1, v0, 0x40

    .line 23
    .line 24
    if-eqz v1, :cond_2

    .line 25
    .line 26
    const/16 v1, 0x64

    .line 27
    .line 28
    move v9, v1

    .line 29
    goto :goto_2

    .line 30
    :cond_2
    move/from16 v9, p7

    .line 31
    .line 32
    :goto_2
    and-int/lit16 v1, v0, 0x80

    .line 33
    .line 34
    if-eqz v1, :cond_3

    .line 35
    .line 36
    new-instance v10, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;

    .line 37
    .line 38
    const/16 v15, 0xf

    .line 39
    .line 40
    const/16 v16, 0x0

    .line 41
    .line 42
    const/4 v11, 0x0

    .line 43
    const/4 v12, 0x0

    .line 44
    const/4 v13, 0x0

    .line 45
    const/4 v14, 0x0

    .line 46
    invoke-direct/range {v10 .. v16}, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;-><init>(IIIIILkotlin/jvm/internal/g;)V

    .line 47
    .line 48
    .line 49
    goto :goto_3

    .line 50
    :cond_3
    move-object/from16 v10, p8

    .line 51
    .line 52
    :goto_3
    and-int/lit16 v1, v0, 0x100

    .line 53
    .line 54
    if-eqz v1, :cond_4

    .line 55
    .line 56
    invoke-static {}, Lvy0/e0;->f()Lvy0/z1;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    move-object v11, v1

    .line 61
    goto :goto_4

    .line 62
    :cond_4
    move-object/from16 v11, p9

    .line 63
    .line 64
    :goto_4
    and-int/lit16 v1, v0, 0x200

    .line 65
    .line 66
    if-eqz v1, :cond_5

    .line 67
    .line 68
    sget-object v1, Lvy0/p0;->a:Lcz0/e;

    .line 69
    .line 70
    sget-object v1, Lcz0/d;->e:Lcz0/d;

    .line 71
    .line 72
    move-object v12, v1

    .line 73
    goto :goto_5

    .line 74
    :cond_5
    move-object/from16 v12, p10

    .line 75
    .line 76
    :goto_5
    and-int/lit16 v0, v0, 0x400

    .line 77
    .line 78
    if-eqz v0, :cond_6

    .line 79
    .line 80
    sget-object v0, Ltechnology/cariad/cat/genx/TransportType;->BLE:Ltechnology/cariad/cat/genx/TransportType;

    .line 81
    .line 82
    sget-object v1, Ltechnology/cariad/cat/genx/TransportType;->WiFi:Ltechnology/cariad/cat/genx/TransportType;

    .line 83
    .line 84
    filled-new-array {v0, v1}, [Ltechnology/cariad/cat/genx/TransportType;

    .line 85
    .line 86
    .line 87
    move-result-object v0

    .line 88
    invoke-static {v0}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 89
    .line 90
    .line 91
    move-result-object v0

    .line 92
    move-object v13, v0

    .line 93
    :goto_6
    move-object/from16 v2, p0

    .line 94
    .line 95
    move-object/from16 v3, p1

    .line 96
    .line 97
    move-object/from16 v4, p2

    .line 98
    .line 99
    move-object/from16 v5, p3

    .line 100
    .line 101
    move-object/from16 v6, p4

    .line 102
    .line 103
    goto :goto_7

    .line 104
    :cond_6
    move-object/from16 v13, p11

    .line 105
    .line 106
    goto :goto_6

    .line 107
    :goto_7
    invoke-virtual/range {v2 .. v13}, Ltechnology/cariad/cat/genx/InternalVehicleManager$Companion;->invoke(Landroid/content/Context;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;Ltechnology/cariad/cat/genx/DeviceInformation;Lu51/g;Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;IILtechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Lvy0/i1;Lvy0/x;Ljava/util/Set;)Ltechnology/cariad/cat/genx/VehicleManager;

    .line 108
    .line 109
    .line 110
    move-result-object v0

    .line 111
    return-object v0
.end method

.method private static final invoke$lambda$0$0(Ljava/util/List;Landroid/content/Context;Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;IILtechnology/cariad/cat/genx/GenXDispatcher;)Ltechnology/cariad/cat/genx/ClientManager;
    .locals 9

    .line 1
    const-string v0, "genXDispatcher"

    .line 2
    .line 3
    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v4, Ltechnology/cariad/cat/genx/s0;

    .line 7
    .line 8
    const/16 v0, 0xb

    .line 9
    .line 10
    invoke-direct {v4, v0}, Ltechnology/cariad/cat/genx/s0;-><init>(I)V

    .line 11
    .line 12
    .line 13
    new-instance v1, Lt51/j;

    .line 14
    .line 15
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v6

    .line 19
    const-string p0, "getName(...)"

    .line 20
    .line 21
    invoke-static {p0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v7

    .line 25
    const-string v2, "GenX"

    .line 26
    .line 27
    sget-object v3, Lt51/g;->a:Lt51/g;

    .line 28
    .line 29
    const/4 v5, 0x0

    .line 30
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 34
    .line 35
    .line 36
    new-instance p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 37
    .line 38
    move v8, p4

    .line 39
    move p4, p3

    .line 40
    move-object p3, p5

    .line 41
    move p5, v8

    .line 42
    invoke-direct/range {p0 .. p5}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;-><init>(Landroid/content/Context;Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;Ltechnology/cariad/cat/genx/GenXDispatcher;II)V

    .line 43
    .line 44
    .line 45
    return-object p0
.end method

.method private static final invoke$lambda$0$0$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "clientManagerProvider(): Provide BluetoothClientManager"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final invoke$lambda$0$1(Ljava/util/List;Lvy0/x;Landroid/content/Context;Lvy0/i1;Ltechnology/cariad/cat/genx/GenXDispatcher;)Ltechnology/cariad/cat/genx/ClientManager;
    .locals 8

    .line 1
    const-string v0, "genXDispatcher"

    .line 2
    .line 3
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v4, Ltechnology/cariad/cat/genx/s0;

    .line 7
    .line 8
    const/16 v0, 0xc

    .line 9
    .line 10
    invoke-direct {v4, v0}, Ltechnology/cariad/cat/genx/s0;-><init>(I)V

    .line 11
    .line 12
    .line 13
    new-instance v1, Lt51/j;

    .line 14
    .line 15
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v6

    .line 19
    const-string p0, "getName(...)"

    .line 20
    .line 21
    invoke-static {p0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v7

    .line 25
    const-string v2, "GenX"

    .line 26
    .line 27
    sget-object v3, Lt51/g;->a:Lt51/g;

    .line 28
    .line 29
    const/4 v5, 0x0

    .line 30
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 34
    .line 35
    .line 36
    new-instance v7, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;

    .line 37
    .line 38
    invoke-static {}, Lvy0/e0;->f()Lvy0/z1;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    invoke-virtual {p1, p0}, Lpx0/a;->plus(Lpx0/g;)Lpx0/g;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    invoke-static {p0}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    sget-object v0, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;->Companion:Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState$Companion;

    .line 51
    .line 52
    invoke-virtual {v0, p2}, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState$Companion;->getWifiState$genx_release(Landroid/content/Context;)Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    sget-object v1, Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;->Companion:Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState$Companion;

    .line 57
    .line 58
    invoke-virtual {v1, p2}, Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState$Companion;->getAccessPointState$genx_release(Landroid/content/Context;)Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;

    .line 59
    .line 60
    .line 61
    move-result-object v1

    .line 62
    invoke-direct {v7, p0, v0, v1}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;-><init>(Lvy0/b0;Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;)V

    .line 63
    .line 64
    .line 65
    new-instance v2, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;

    .line 66
    .line 67
    invoke-virtual {p1, p3}, Lpx0/a;->plus(Lpx0/g;)Lpx0/g;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    invoke-static {p0}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 72
    .line 73
    .line 74
    move-result-object v5

    .line 75
    new-instance v6, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;

    .line 76
    .line 77
    sget-object p0, Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade;->Companion:Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade$Companion;

    .line 78
    .line 79
    invoke-virtual {p0, p2}, Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade$Companion;->invoke(Landroid/content/Context;)Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    invoke-direct {v6, p2, p0, v7}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;-><init>(Landroid/content/Context;Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade;Ltechnology/cariad/cat/genx/wifi/WifiManager;)V

    .line 84
    .line 85
    .line 86
    move-object v3, p2

    .line 87
    move-object v4, p4

    .line 88
    invoke-direct/range {v2 .. v7}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;-><init>(Landroid/content/Context;Ltechnology/cariad/cat/genx/GenXDispatcher;Lvy0/b0;Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManager;Ltechnology/cariad/cat/genx/wifi/WifiManager;)V

    .line 89
    .line 90
    .line 91
    return-object v2
.end method

.method private static final invoke$lambda$0$1$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "clientManagerProvider(): Provide WifiConnectionManager"

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public final invoke(Landroid/content/Context;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;Ltechnology/cariad/cat/genx/DeviceInformation;Lu51/g;Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;IILtechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Lvy0/i1;Lvy0/x;Ljava/util/Set;)Ltechnology/cariad/cat/genx/VehicleManager;
    .locals 17
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Landroid/content/Context;",
            "Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;",
            "Ltechnology/cariad/cat/genx/DeviceInformation;",
            "Lu51/g;",
            "Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;",
            "II",
            "Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;",
            "Lvy0/i1;",
            "Lvy0/x;",
            "Ljava/util/Set<",
            "+",
            "Ltechnology/cariad/cat/genx/TransportType;",
            ">;)",
            "Ltechnology/cariad/cat/genx/VehicleManager;"
        }
    .end annotation

    .line 1
    move-object/from16 v0, p4

    .line 2
    .line 3
    move-object/from16 v1, p11

    .line 4
    .line 5
    const-string v2, "context"

    .line 6
    .line 7
    move-object/from16 v4, p1

    .line 8
    .line 9
    invoke-static {v4, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v2, "keyPair"

    .line 13
    .line 14
    move-object/from16 v9, p2

    .line 15
    .line 16
    invoke-static {v9, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    const-string v2, "deviceInformation"

    .line 20
    .line 21
    move-object/from16 v10, p3

    .line 22
    .line 23
    invoke-static {v10, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string v2, "secureStorage"

    .line 27
    .line 28
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    const-string v2, "bluetoothScanMode"

    .line 32
    .line 33
    move-object/from16 v6, p5

    .line 34
    .line 35
    invoke-static {v6, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    const-string v2, "linkedParameters"

    .line 39
    .line 40
    move-object/from16 v11, p8

    .line 41
    .line 42
    invoke-static {v11, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    const-string v2, "supervisorJob"

    .line 46
    .line 47
    move-object/from16 v13, p9

    .line 48
    .line 49
    invoke-static {v13, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    const-string v2, "ioDispatcher"

    .line 53
    .line 54
    move-object/from16 v14, p10

    .line 55
    .line 56
    invoke-static {v14, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    const-string v2, "supportedTransportTypes"

    .line 60
    .line 61
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    new-instance v5, Ljava/util/ArrayList;

    .line 65
    .line 66
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 67
    .line 68
    .line 69
    sget-object v2, Ltechnology/cariad/cat/genx/TransportType;->BLE:Ltechnology/cariad/cat/genx/TransportType;

    .line 70
    .line 71
    invoke-interface {v1, v2}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move-result v2

    .line 75
    if-eqz v2, :cond_0

    .line 76
    .line 77
    new-instance v3, Lk1/f1;

    .line 78
    .line 79
    move-object v7, v5

    .line 80
    move-object v5, v4

    .line 81
    move-object v4, v7

    .line 82
    move/from16 v7, p6

    .line 83
    .line 84
    move/from16 v8, p7

    .line 85
    .line 86
    invoke-direct/range {v3 .. v8}, Lk1/f1;-><init>(Ljava/util/ArrayList;Landroid/content/Context;Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;II)V

    .line 87
    .line 88
    .line 89
    invoke-virtual {v4, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    goto :goto_0

    .line 93
    :cond_0
    move-object v4, v5

    .line 94
    :goto_0
    sget-object v2, Ltechnology/cariad/cat/genx/TransportType;->WiFi:Ltechnology/cariad/cat/genx/TransportType;

    .line 95
    .line 96
    invoke-interface {v1, v2}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    move-result v1

    .line 100
    if-eqz v1, :cond_1

    .line 101
    .line 102
    new-instance v3, Lbg/a;

    .line 103
    .line 104
    const/16 v8, 0x13

    .line 105
    .line 106
    move-object/from16 v6, p1

    .line 107
    .line 108
    move-object v7, v13

    .line 109
    move-object v5, v14

    .line 110
    invoke-direct/range {v3 .. v8}, Lbg/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 111
    .line 112
    .line 113
    invoke-virtual {v4, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 114
    .line 115
    .line 116
    :cond_1
    sget-object v1, Ltechnology/cariad/cat/genx/GenXDispatcher;->Companion:Ltechnology/cariad/cat/genx/GenXDispatcher$Companion;

    .line 117
    .line 118
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/GenXDispatcher$Companion;->invoke()Ltechnology/cariad/cat/genx/GenXDispatcherImpl;

    .line 119
    .line 120
    .line 121
    move-result-object v12

    .line 122
    new-instance v9, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage;

    .line 123
    .line 124
    invoke-direct {v9, v0}, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage;-><init>(Lu51/g;)V

    .line 125
    .line 126
    .line 127
    mul-int v6, p6, p7

    .line 128
    .line 129
    new-instance v3, Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 130
    .line 131
    const/16 v15, 0x8

    .line 132
    .line 133
    const/16 v16, 0x0

    .line 134
    .line 135
    const/4 v7, 0x0

    .line 136
    move-object/from16 v8, p2

    .line 137
    .line 138
    move-object/from16 v13, p9

    .line 139
    .line 140
    move-object/from16 v14, p10

    .line 141
    .line 142
    move-object v5, v4

    .line 143
    move-object/from16 v4, p1

    .line 144
    .line 145
    invoke-direct/range {v3 .. v16}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;-><init>(Landroid/content/Context;Ljava/util/List;ILt41/o;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;Ltechnology/cariad/cat/genx/crypto/CredentialStore;Ltechnology/cariad/cat/genx/DeviceInformation;Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Ltechnology/cariad/cat/genx/GenXDispatcher;Lvy0/i1;Lvy0/x;ILkotlin/jvm/internal/g;)V

    .line 146
    .line 147
    .line 148
    return-object v3
.end method
