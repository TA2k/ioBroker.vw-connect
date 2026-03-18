.class public final Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00006\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\t\n\u0002\u0018\u0002\n\u0002\u0008\t\n\u0002\u0010\t\n\u0000\n\u0002\u0010\u0008\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0006\u0008\u00c6\u0002\u0018\u00002\u00020\u0001:\u0001$B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\u000e\u0010\u001c\u001a\u00020\u001d2\u0006\u0010\u001e\u001a\u00020\u001fJ\u000e\u0010 \u001a\u00020\u001d2\u0006\u0010\u001e\u001a\u00020\u001fJ\u000e\u0010!\u001a\u00020\u001d2\u0006\u0010\u001e\u001a\u00020\u001fJ\u000e\u0010\"\u001a\u00020\u001d2\u0006\u0010\u001e\u001a\u00020\u001fJ\u000e\u0010#\u001a\u00020\u001d2\u0006\u0010\u001e\u001a\u00020\u001fR\u0014\u0010\u0004\u001a\u00020\u0005X\u0080\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0006\u0010\u0007R\u0014\u0010\u0008\u001a\u00020\u0005X\u0080\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\t\u0010\u0007R\u0014\u0010\n\u001a\u00020\u0005X\u0080\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000b\u0010\u0007R\u0014\u0010\u000c\u001a\u00020\u0005X\u0080\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\r\u0010\u0007R\u0014\u0010\u000e\u001a\u00020\u000fX\u0080\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0010\u0010\u0011R\u0014\u0010\u0012\u001a\u00020\u000fX\u0080\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0013\u0010\u0011R\u0014\u0010\u0014\u001a\u00020\u000fX\u0080\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0015\u0010\u0011R\u0014\u0010\u0016\u001a\u00020\u000fX\u0080\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0017\u0010\u0011R\u000e\u0010\u0018\u001a\u00020\u0019X\u0080T\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u001a\u001a\u00020\u001bX\u0080T\u00a2\u0006\u0002\n\u0000\u00a8\u0006%"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;",
        "",
        "<init>",
        "()V",
        "outerAntennaServiceUUID",
        "Landroid/os/ParcelUuid;",
        "getOuterAntennaServiceUUID$genx_release",
        "()Landroid/os/ParcelUuid;",
        "outerAntennaServiceDataUUID",
        "getOuterAntennaServiceDataUUID$genx_release",
        "innerAntennaServiceUUID",
        "getInnerAntennaServiceUUID$genx_release",
        "innerAntennaServiceDataUUID",
        "getInnerAntennaServiceDataUUID$genx_release",
        "handshakeNotifyCharacteristicUUID",
        "Ljava/util/UUID;",
        "getHandshakeNotifyCharacteristicUUID$genx_release",
        "()Ljava/util/UUID;",
        "handshakeWriteCharacteristicUUID",
        "getHandshakeWriteCharacteristicUUID$genx_release",
        "dataNotifyCharacteristicUUID",
        "getDataNotifyCharacteristicUUID$genx_release",
        "dataWriteCharacteristicUUID",
        "getDataWriteCharacteristicUUID$genx_release",
        "ADVERTISEMENT_TIMEOUT_MS",
        "",
        "ATT_HEADER_SIZE_IN_BYTES",
        "",
        "isBleSupported",
        "",
        "context",
        "Landroid/content/Context;",
        "isBleEnabled",
        "isFineLocationPermissionRequiredAndGranted",
        "isBluetoothScanPermissionRequiredAndGranted",
        "isBluetoothConnectPermissionRequiredAndGranted",
        "ScanMode",
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
.field public static final ADVERTISEMENT_TIMEOUT_MS:J = 0x1388L

.field public static final ATT_HEADER_SIZE_IN_BYTES:I = 0x5

.field public static final INSTANCE:Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;

.field private static final dataNotifyCharacteristicUUID:Ljava/util/UUID;

.field private static final dataWriteCharacteristicUUID:Ljava/util/UUID;

.field private static final handshakeNotifyCharacteristicUUID:Ljava/util/UUID;

.field private static final handshakeWriteCharacteristicUUID:Ljava/util/UUID;

.field private static final innerAntennaServiceDataUUID:Landroid/os/ParcelUuid;

.field private static final innerAntennaServiceUUID:Landroid/os/ParcelUuid;

.field private static final outerAntennaServiceDataUUID:Landroid/os/ParcelUuid;

.field private static final outerAntennaServiceUUID:Landroid/os/ParcelUuid;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;

    .line 2
    .line 3
    invoke-direct {v0}, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->INSTANCE:Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;

    .line 7
    .line 8
    const-string v0, "0000FE30-0000-1000-8000-00805F9B34FB"

    .line 9
    .line 10
    invoke-static {v0}, Landroid/os/ParcelUuid;->fromString(Ljava/lang/String;)Landroid/os/ParcelUuid;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    const-string v2, "fromString(...)"

    .line 15
    .line 16
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    sput-object v1, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->outerAntennaServiceUUID:Landroid/os/ParcelUuid;

    .line 20
    .line 21
    invoke-static {v0}, Landroid/os/ParcelUuid;->fromString(Ljava/lang/String;)Landroid/os/ParcelUuid;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    sput-object v0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->outerAntennaServiceDataUUID:Landroid/os/ParcelUuid;

    .line 29
    .line 30
    const-string v0, "0000FE31-0000-1000-8000-00805F9B34FB"

    .line 31
    .line 32
    invoke-static {v0}, Landroid/os/ParcelUuid;->fromString(Ljava/lang/String;)Landroid/os/ParcelUuid;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    sput-object v1, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->innerAntennaServiceUUID:Landroid/os/ParcelUuid;

    .line 40
    .line 41
    invoke-static {v0}, Landroid/os/ParcelUuid;->fromString(Ljava/lang/String;)Landroid/os/ParcelUuid;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    sput-object v0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->innerAntennaServiceDataUUID:Landroid/os/ParcelUuid;

    .line 49
    .line 50
    const-string v0, "49A889AB-6C81-2683-4C42-ADBFDB9CA383"

    .line 51
    .line 52
    invoke-static {v0}, Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    sput-object v0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->handshakeNotifyCharacteristicUUID:Ljava/util/UUID;

    .line 60
    .line 61
    const-string v0, "D8B1F402-064B-7792-6641-FBF1DD806F4C"

    .line 62
    .line 63
    invoke-static {v0}, Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    sput-object v0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->handshakeWriteCharacteristicUUID:Ljava/util/UUID;

    .line 71
    .line 72
    const-string v0, "474BBEB3-64FC-6189-A84D-D04ED241AAA8"

    .line 73
    .line 74
    invoke-static {v0}, Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    sput-object v0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->dataNotifyCharacteristicUUID:Ljava/util/UUID;

    .line 82
    .line 83
    const-string v0, "42A9CC2C-9887-2990-2A49-1E8C3FADF07F"

    .line 84
    .line 85
    invoke-static {v0}, Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;

    .line 86
    .line 87
    .line 88
    move-result-object v0

    .line 89
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    sput-object v0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->dataWriteCharacteristicUUID:Ljava/util/UUID;

    .line 93
    .line 94
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


# virtual methods
.method public final getDataNotifyCharacteristicUUID$genx_release()Ljava/util/UUID;
    .locals 0

    .line 1
    sget-object p0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->dataNotifyCharacteristicUUID:Ljava/util/UUID;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getDataWriteCharacteristicUUID$genx_release()Ljava/util/UUID;
    .locals 0

    .line 1
    sget-object p0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->dataWriteCharacteristicUUID:Ljava/util/UUID;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getHandshakeNotifyCharacteristicUUID$genx_release()Ljava/util/UUID;
    .locals 0

    .line 1
    sget-object p0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->handshakeNotifyCharacteristicUUID:Ljava/util/UUID;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getHandshakeWriteCharacteristicUUID$genx_release()Ljava/util/UUID;
    .locals 0

    .line 1
    sget-object p0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->handshakeWriteCharacteristicUUID:Ljava/util/UUID;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getInnerAntennaServiceDataUUID$genx_release()Landroid/os/ParcelUuid;
    .locals 0

    .line 1
    sget-object p0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->innerAntennaServiceDataUUID:Landroid/os/ParcelUuid;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getInnerAntennaServiceUUID$genx_release()Landroid/os/ParcelUuid;
    .locals 0

    .line 1
    sget-object p0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->innerAntennaServiceUUID:Landroid/os/ParcelUuid;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getOuterAntennaServiceDataUUID$genx_release()Landroid/os/ParcelUuid;
    .locals 0

    .line 1
    sget-object p0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->outerAntennaServiceDataUUID:Landroid/os/ParcelUuid;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getOuterAntennaServiceUUID$genx_release()Landroid/os/ParcelUuid;
    .locals 0

    .line 1
    sget-object p0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->outerAntennaServiceUUID:Landroid/os/ParcelUuid;

    .line 2
    .line 3
    return-object p0
.end method

.method public final isBleEnabled(Landroid/content/Context;)Z
    .locals 1

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->isBleSupported(Landroid/content/Context;)Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    if-eqz p0, :cond_0

    .line 11
    .line 12
    invoke-static {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothKt;->getBluetoothManager(Landroid/content/Context;)Landroid/bluetooth/BluetoothManager;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    if-eqz p0, :cond_0

    .line 17
    .line 18
    invoke-virtual {p0}, Landroid/bluetooth/BluetoothManager;->getAdapter()Landroid/bluetooth/BluetoothAdapter;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    if-eqz p0, :cond_0

    .line 23
    .line 24
    invoke-virtual {p0}, Landroid/bluetooth/BluetoothAdapter;->isEnabled()Z

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    const/4 p1, 0x1

    .line 29
    if-ne p0, p1, :cond_0

    .line 30
    .line 31
    return p1

    .line 32
    :cond_0
    const/4 p0, 0x0

    .line 33
    return p0
.end method

.method public final isBleSupported(Landroid/content/Context;)Z
    .locals 0

    .line 1
    const-string p0, "context"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    const-string p1, "android.hardware.bluetooth_le"

    .line 11
    .line 12
    invoke-virtual {p0, p1}, Landroid/content/pm/PackageManager;->hasSystemFeature(Ljava/lang/String;)Z

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    return p0
.end method

.method public final isBluetoothConnectPermissionRequiredAndGranted(Landroid/content/Context;)Z
    .locals 1

    .line 1
    const-string p0, "context"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget p0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 7
    .line 8
    const/16 v0, 0x1f

    .line 9
    .line 10
    if-lt p0, v0, :cond_1

    .line 11
    .line 12
    const-string p0, "android.permission.BLUETOOTH_CONNECT"

    .line 13
    .line 14
    invoke-static {p1, p0}, Ln5/a;->a(Landroid/content/Context;Ljava/lang/String;)I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    if-nez p0, :cond_0

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 p0, 0x0

    .line 22
    return p0

    .line 23
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 24
    return p0
.end method

.method public final isBluetoothScanPermissionRequiredAndGranted(Landroid/content/Context;)Z
    .locals 1

    .line 1
    const-string p0, "context"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget p0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 7
    .line 8
    const/16 v0, 0x1f

    .line 9
    .line 10
    if-lt p0, v0, :cond_1

    .line 11
    .line 12
    const-string p0, "android.permission.BLUETOOTH_SCAN"

    .line 13
    .line 14
    invoke-static {p1, p0}, Ln5/a;->a(Landroid/content/Context;Ljava/lang/String;)I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    if-nez p0, :cond_0

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 p0, 0x0

    .line 22
    return p0

    .line 23
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 24
    return p0
.end method

.method public final isFineLocationPermissionRequiredAndGranted(Landroid/content/Context;)Z
    .locals 1

    .line 1
    const-string p0, "context"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget p0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 7
    .line 8
    const/16 v0, 0x1f

    .line 9
    .line 10
    if-ge p0, v0, :cond_1

    .line 11
    .line 12
    const-string p0, "android.permission.ACCESS_FINE_LOCATION"

    .line 13
    .line 14
    invoke-static {p1, p0}, Ln5/a;->a(Landroid/content/Context;Ljava/lang/String;)I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    if-nez p0, :cond_0

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 p0, 0x0

    .line 22
    return p0

    .line 23
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 24
    return p0
.end method
