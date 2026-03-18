.class public final Ltechnology/cariad/cat/genx/VehicleManager$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/genx/VehicleManager;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000f\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0008\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\"\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u000e\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\n\u0008\u0086\u0003\u0018\u00002\u00020\u0001B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003Jz\u0010\u001b\u001a\u00020\u001a2\u0006\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0007\u001a\u00020\u00062\u0006\u0010\t\u001a\u00020\u00082\u0006\u0010\u000b\u001a\u00020\n2\u0008\u0008\u0002\u0010\r\u001a\u00020\u000c2\u0008\u0008\u0002\u0010\u000f\u001a\u00020\u000e2\u0008\u0008\u0002\u0010\u0010\u001a\u00020\u000e2\u0006\u0010\u0012\u001a\u00020\u00112\u0008\u0008\u0002\u0010\u0014\u001a\u00020\u00132\u0008\u0008\u0002\u0010\u0016\u001a\u00020\u00152\u000e\u0008\u0002\u0010\u0019\u001a\u0008\u0012\u0004\u0012\u00020\u00180\u0017H\u0086\u0002\u00a2\u0006\u0004\u0008\u001b\u0010\u001cR\u0014\u0010\u001e\u001a\u00020\u001d8\u0006X\u0086T\u00a2\u0006\u0006\n\u0004\u0008\u001e\u0010\u001fR\u0014\u0010 \u001a\u00020\u001d8\u0006X\u0086T\u00a2\u0006\u0006\n\u0004\u0008 \u0010\u001fR\u0011\u0010#\u001a\u00020\u001d8F\u00a2\u0006\u0006\u001a\u0004\u0008!\u0010\"R\u0011\u0010\'\u001a\u00020$8F\u00a2\u0006\u0006\u001a\u0004\u0008%\u0010&R\u0011\u0010)\u001a\u00020$8F\u00a2\u0006\u0006\u001a\u0004\u0008(\u0010&R\u0011\u0010+\u001a\u00020$8F\u00a2\u0006\u0006\u001a\u0004\u0008*\u0010&R\u0011\u0010-\u001a\u00020$8F\u00a2\u0006\u0006\u001a\u0004\u0008,\u0010&\u00a8\u0006."
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/VehicleManager$Companion;",
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
        "",
        "ACTION_BEACON_IN_RANGE",
        "Ljava/lang/String;",
        "ACTION_BEACON_OUT_OF_RANGE",
        "getINTENT_EXTRAS_BEACON",
        "()Ljava/lang/String;",
        "INTENT_EXTRAS_BEACON",
        "Ljava/util/UUID;",
        "getLegacyBeaconUUID",
        "()Ljava/util/UUID;",
        "legacyBeaconUUID",
        "getStandardBeaconUUID",
        "standardBeaconUUID",
        "getPairingBeaconUUID",
        "pairingBeaconUUID",
        "getAlertBeaconUUID",
        "alertBeaconUUID",
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
.field static final synthetic $$INSTANCE:Ltechnology/cariad/cat/genx/VehicleManager$Companion;

.field public static final ACTION_BEACON_IN_RANGE:Ljava/lang/String; = "technology.cariad.cat.genx.action.BEACON_IN_RANGE"

.field public static final ACTION_BEACON_OUT_OF_RANGE:Ljava/lang/String; = "technology.cariad.cat.genx.action.BEACON_OUT_OF_RANGE"


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/VehicleManager$Companion;

    .line 2
    .line 3
    invoke-direct {v0}, Ltechnology/cariad/cat/genx/VehicleManager$Companion;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Ltechnology/cariad/cat/genx/VehicleManager$Companion;->$$INSTANCE:Ltechnology/cariad/cat/genx/VehicleManager$Companion;

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

.method public static invoke$default(Ltechnology/cariad/cat/genx/VehicleManager$Companion;Landroid/content/Context;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;Ltechnology/cariad/cat/genx/DeviceInformation;Lu51/g;Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;IILtechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Lvy0/i1;Lvy0/x;Ljava/util/Set;ILjava/lang/Object;)Ltechnology/cariad/cat/genx/VehicleManager;
    .locals 14

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
    and-int/lit16 v1, v0, 0x100

    .line 33
    .line 34
    if-eqz v1, :cond_3

    .line 35
    .line 36
    invoke-static {}, Lvy0/e0;->f()Lvy0/z1;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    move-object v11, v1

    .line 41
    goto :goto_3

    .line 42
    :cond_3
    move-object/from16 v11, p9

    .line 43
    .line 44
    :goto_3
    and-int/lit16 v1, v0, 0x200

    .line 45
    .line 46
    if-eqz v1, :cond_4

    .line 47
    .line 48
    sget-object v1, Lvy0/p0;->a:Lcz0/e;

    .line 49
    .line 50
    sget-object v1, Lcz0/d;->e:Lcz0/d;

    .line 51
    .line 52
    move-object v12, v1

    .line 53
    goto :goto_4

    .line 54
    :cond_4
    move-object/from16 v12, p10

    .line 55
    .line 56
    :goto_4
    and-int/lit16 v0, v0, 0x400

    .line 57
    .line 58
    if-eqz v0, :cond_5

    .line 59
    .line 60
    sget-object v0, Ltechnology/cariad/cat/genx/TransportType;->BLE:Ltechnology/cariad/cat/genx/TransportType;

    .line 61
    .line 62
    invoke-static {v0}, Ljp/m1;->k(Ljava/lang/Object;)Ljava/util/Set;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    move-object v13, v0

    .line 67
    :goto_5
    move-object v2, p0

    .line 68
    move-object v3, p1

    .line 69
    move-object/from16 v4, p2

    .line 70
    .line 71
    move-object/from16 v5, p3

    .line 72
    .line 73
    move-object/from16 v6, p4

    .line 74
    .line 75
    move-object/from16 v10, p8

    .line 76
    .line 77
    goto :goto_6

    .line 78
    :cond_5
    move-object/from16 v13, p11

    .line 79
    .line 80
    goto :goto_5

    .line 81
    :goto_6
    invoke-virtual/range {v2 .. v13}, Ltechnology/cariad/cat/genx/VehicleManager$Companion;->invoke(Landroid/content/Context;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;Ltechnology/cariad/cat/genx/DeviceInformation;Lu51/g;Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;IILtechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Lvy0/i1;Lvy0/x;Ljava/util/Set;)Ltechnology/cariad/cat/genx/VehicleManager;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    return-object p0
.end method


# virtual methods
.method public final getAlertBeaconUUID()Ljava/util/UUID;
    .locals 1

    .line 1
    const-string p0, "56574147-677e-4f38-8372-414c45525421"

    .line 2
    .line 3
    invoke-static {p0}, Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const-string v0, "fromString(...)"

    .line 8
    .line 9
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    return-object p0
.end method

.method public final getINTENT_EXTRAS_BEACON()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "EXTRA_BEACON"

    .line 2
    .line 3
    return-object p0
.end method

.method public final getLegacyBeaconUUID()Ljava/util/UUID;
    .locals 1

    .line 1
    const-string p0, "E2C56DB5-DFFB-48D2-B060-D0F5A71096E0"

    .line 2
    .line 3
    invoke-static {p0}, Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const-string v0, "fromString(...)"

    .line 8
    .line 9
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    return-object p0
.end method

.method public final getPairingBeaconUUID()Ljava/util/UUID;
    .locals 1

    .line 1
    const-string p0, "56574147-677e-4f38-8372-50414952494e"

    .line 2
    .line 3
    invoke-static {p0}, Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const-string v0, "fromString(...)"

    .line 8
    .line 9
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    return-object p0
.end method

.method public final getStandardBeaconUUID()Ljava/util/UUID;
    .locals 1

    .line 1
    const-string p0, "56574147-677e-4f38-8372-424541434f4e"

    .line 2
    .line 3
    invoke-static {p0}, Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const-string v0, "fromString(...)"

    .line 8
    .line 9
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    return-object p0
.end method

.method public final invoke(Landroid/content/Context;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;Ltechnology/cariad/cat/genx/DeviceInformation;Lu51/g;Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;IILtechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Lvy0/i1;Lvy0/x;Ljava/util/Set;)Ltechnology/cariad/cat/genx/VehicleManager;
    .locals 12
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
    const-string p0, "context"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "keyPair"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string p0, "deviceInformation"

    .line 12
    .line 13
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string p0, "secureStorage"

    .line 17
    .line 18
    move-object/from16 v4, p4

    .line 19
    .line 20
    invoke-static {v4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    const-string p0, "bluetoothScanMode"

    .line 24
    .line 25
    move-object/from16 v5, p5

    .line 26
    .line 27
    invoke-static {v5, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    const-string p0, "linkedParameters"

    .line 31
    .line 32
    move-object/from16 v8, p8

    .line 33
    .line 34
    invoke-static {v8, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    const-string p0, "supervisorJob"

    .line 38
    .line 39
    move-object/from16 v9, p9

    .line 40
    .line 41
    invoke-static {v9, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    const-string p0, "ioDispatcher"

    .line 45
    .line 46
    move-object/from16 v10, p10

    .line 47
    .line 48
    invoke-static {v10, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    const-string p0, "supportedTransportTypes"

    .line 52
    .line 53
    move-object/from16 v11, p11

    .line 54
    .line 55
    invoke-static {v11, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    sget-object v0, Ltechnology/cariad/cat/genx/InternalVehicleManager;->Companion:Ltechnology/cariad/cat/genx/InternalVehicleManager$Companion;

    .line 59
    .line 60
    move-object v1, p1

    .line 61
    move-object v2, p2

    .line 62
    move-object v3, p3

    .line 63
    move/from16 v6, p6

    .line 64
    .line 65
    move/from16 v7, p7

    .line 66
    .line 67
    invoke-virtual/range {v0 .. v11}, Ltechnology/cariad/cat/genx/InternalVehicleManager$Companion;->invoke(Landroid/content/Context;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;Ltechnology/cariad/cat/genx/DeviceInformation;Lu51/g;Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;IILtechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Lvy0/i1;Lvy0/x;Ljava/util/Set;)Ltechnology/cariad/cat/genx/VehicleManager;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    return-object p0
.end method
