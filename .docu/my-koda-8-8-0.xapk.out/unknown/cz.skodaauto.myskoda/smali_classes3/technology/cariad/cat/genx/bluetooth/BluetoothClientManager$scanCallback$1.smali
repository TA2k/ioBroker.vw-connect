.class public final Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;
.super Landroid/bluetooth/le/ScanCallback;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;-><init>(Landroid/content/Context;Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;Ltechnology/cariad/cat/genx/GenXDispatcher;II)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u001d\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0008\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0006*\u0001\u0000\u0008\n\u0018\u00002\u00020\u0001J!\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0008\u0010\u0005\u001a\u0004\u0018\u00010\u0004H\u0016\u00a2\u0006\u0004\u0008\u0007\u0010\u0008J\u0017\u0010\n\u001a\u00020\u00062\u0006\u0010\t\u001a\u00020\u0002H\u0016\u00a2\u0006\u0004\u0008\n\u0010\u000b\u00a8\u0006\u000c"
    }
    d2 = {
        "technology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1",
        "Landroid/bluetooth/le/ScanCallback;",
        "",
        "callbackType",
        "Landroid/bluetooth/le/ScanResult;",
        "result",
        "Llx0/b0;",
        "onScanResult",
        "(ILandroid/bluetooth/le/ScanResult;)V",
        "errorCode",
        "onScanFailed",
        "(I)V",
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


# instance fields
.field final synthetic this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 2
    .line 3
    invoke-direct {p0}, Landroid/bluetooth/le/ScanCallback;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public static synthetic a(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;->onScanResult$lambda$4$1$3$0(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic b(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;->onScanResult$lambda$4$1$2$0(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic c(ILandroid/bluetooth/le/ScanResult;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;->onScanResult$lambda$3(ILandroid/bluetooth/le/ScanResult;)Ljava/lang/String;

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
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;->onScanResult$lambda$1()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic e(I)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;->onScanFailed$lambda$8(I)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic f(I)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;->onScanFailed$lambda$6(I)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic g(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;->onScanResult$lambda$4$1$1(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic h(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;->onScanResult$lambda$4$1$3$1(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic i()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;->onScanResult$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic j([BLandroid/bluetooth/le/ScanResult;Landroid/bluetooth/BluetoothDevice;Ltechnology/cariad/cat/genx/Antenna;Ljava/time/Instant;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3, p4}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;->onScanResult$lambda$4$1$0([BLandroid/bluetooth/le/ScanResult;Landroid/bluetooth/BluetoothDevice;Ltechnology/cariad/cat/genx/Antenna;Ljava/time/Instant;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic k()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;->onScanFailed$lambda$5()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic l(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;[BLtechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;Landroid/bluetooth/BluetoothDevice;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3, p4}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;->onScanResult$lambda$4$1$2(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;[BLtechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;Landroid/bluetooth/BluetoothDevice;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic m()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;->onScanResult$lambda$2()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private static final onScanFailed$lambda$5()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "onScanFailed(): Scanning already started with the same settings."

    .line 2
    .line 3
    return-object v0
.end method

.method private static final onScanFailed$lambda$6(I)Ljava/lang/String;
    .locals 3

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManagerKt;->readableScanError(I)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v1, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v2, "onScanFailed(): errorCode = "

    .line 8
    .line 9
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    const-string v0, " ("

    .line 16
    .line 17
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string p0, ")"

    .line 24
    .line 25
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0
.end method

.method private static final onScanFailed$lambda$8(I)Ljava/lang/String;
    .locals 3

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManagerKt;->readableScanError(I)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v1, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v2, "onScanFailed(): Failed to delegate the scan failure (errorCode = "

    .line 8
    .line 9
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    const-string v0, " ("

    .line 16
    .line 17
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string p0, ")) due to missing delegate."

    .line 24
    .line 25
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0
.end method

.method private static final onScanResult$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "onScanResult(): Received Scan result came in before BT got turned \'OFF\' -> Ignore Scan result"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final onScanResult$lambda$1()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "onScanResult(): Received Scan result but scanning was not requested"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final onScanResult$lambda$2()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "onScanResult(): Scanning started."

    .line 2
    .line 3
    return-object v0
.end method

.method private static final onScanResult$lambda$3(ILandroid/bluetooth/le/ScanResult;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "onScanResult(): callbackType = "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    const-string p0, ", result = "

    .line 12
    .line 13
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method

.method private static final onScanResult$lambda$4$1$0([BLandroid/bluetooth/le/ScanResult;Landroid/bluetooth/BluetoothDevice;Ltechnology/cariad/cat/genx/Antenna;Ljava/time/Instant;)Ljava/lang/String;
    .locals 3

    .line 1
    invoke-static {p0}, Lly0/d;->l([B)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p1}, Landroid/bluetooth/le/ScanResult;->getRssi()I

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    invoke-static {p2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    invoke-static {p2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p2

    .line 16
    const-string v0, ", RSSI: "

    .line 17
    .line 18
    const-string v1, ", Device ID: "

    .line 19
    .line 20
    const-string v2, "onScanResult(): Advertisement Data: "

    .line 21
    .line 22
    invoke-static {v2, p1, p0, v0, v1}, La7/g0;->m(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    const-string p1, ", Antenna: "

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    invoke-virtual {p0, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    const-string p1, ", Timestamp: "

    .line 38
    .line 39
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    invoke-virtual {p0, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    return-object p0
.end method

.method private static final onScanResult$lambda$4$1$1(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    const-string v0, "onScanResult(): Discovered potential new client - device = "

    .line 9
    .line 10
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method

.method private static final onScanResult$lambda$4$1$2(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;[BLtechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;Landroid/bluetooth/BluetoothDevice;)Llx0/b0;
    .locals 8

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->getDelegate()Ltechnology/cariad/cat/genx/ClientManagerDelegate;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-interface {v0, p1, p2}, Ltechnology/cariad/cat/genx/ClientManagerDelegate;->clientManagerDidDiscoverClient(Ltechnology/cariad/cat/genx/Client;[B)Z

    .line 8
    .line 9
    .line 10
    move-result p2

    .line 11
    const/4 v0, 0x1

    .line 12
    if-ne p2, v0, :cond_0

    .line 13
    .line 14
    new-instance v4, Ltechnology/cariad/cat/genx/bluetooth/c;

    .line 15
    .line 16
    const/16 p2, 0xb

    .line 17
    .line 18
    invoke-direct {v4, p2, p4}, Ltechnology/cariad/cat/genx/bluetooth/c;-><init>(ILandroid/bluetooth/BluetoothDevice;)V

    .line 19
    .line 20
    .line 21
    new-instance v1, Lt51/j;

    .line 22
    .line 23
    invoke-static {p3}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v6

    .line 27
    const-string p2, "getName(...)"

    .line 28
    .line 29
    invoke-static {p2}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v7

    .line 33
    const-string v2, "GenX"

    .line 34
    .line 35
    sget-object v3, Lt51/f;->a:Lt51/f;

    .line 36
    .line 37
    const/4 v5, 0x0

    .line 38
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->getClients$genx_release()Ljava/util/concurrent/ConcurrentHashMap;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    invoke-virtual {p4}, Landroid/bluetooth/BluetoothDevice;->getAddress()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p2

    .line 52
    invoke-interface {p0, p2, p1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_0
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->close()V

    .line 57
    .line 58
    .line 59
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 60
    .line 61
    return-object p0
.end method

.method private static final onScanResult$lambda$4$1$2$0(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    const-string v0, "onScanResult(): Discovered new bluetooth client - device = "

    .line 9
    .line 10
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method

.method private static final onScanResult$lambda$4$1$3$0(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    const-string v0, "onScanResult(): Discovered existing client and forwarded advertisement - device = "

    .line 9
    .line 10
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method

.method private static final onScanResult$lambda$4$1$3$1(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    const-string v0, "onScanResult(): remove BluetoothClient after failed attempt to forward advertisement - device = "

    .line 9
    .line 10
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method


# virtual methods
.method public onScanFailed(I)V
    .locals 8

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 2
    .line 3
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->cancelNoResponseCancellationJob$genx_release()V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x1

    .line 7
    if-ne p1, v0, :cond_0

    .line 8
    .line 9
    new-instance v4, Ltechnology/cariad/cat/genx/bluetooth/t;

    .line 10
    .line 11
    const/16 p1, 0xe

    .line 12
    .line 13
    invoke-direct {v4, p1}, Ltechnology/cariad/cat/genx/bluetooth/t;-><init>(I)V

    .line 14
    .line 15
    .line 16
    new-instance v1, Lt51/j;

    .line 17
    .line 18
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v6

    .line 22
    const-string p1, "getName(...)"

    .line 23
    .line 24
    invoke-static {p1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v7

    .line 28
    const-string v2, "GenX"

    .line 29
    .line 30
    sget-object v3, Lt51/d;->a:Lt51/d;

    .line 31
    .line 32
    const/4 v5, 0x0

    .line 33
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 37
    .line 38
    .line 39
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 40
    .line 41
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->getScanning$genx_release()Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    invoke-virtual {p0, v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 46
    .line 47
    .line 48
    return-void

    .line 49
    :cond_0
    new-instance v0, Le1/h1;

    .line 50
    .line 51
    const/4 v1, 0x7

    .line 52
    invoke-direct {v0, p1, v1}, Le1/h1;-><init>(II)V

    .line 53
    .line 54
    .line 55
    const-string v1, "GenX"

    .line 56
    .line 57
    const/4 v2, 0x0

    .line 58
    invoke-static {p0, v1, v2, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 59
    .line 60
    .line 61
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 62
    .line 63
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->getScanning$genx_release()Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    const/4 v3, 0x0

    .line 68
    invoke-virtual {v0, v3}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 69
    .line 70
    .line 71
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 72
    .line 73
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->getDelegate()Ltechnology/cariad/cat/genx/ClientManagerDelegate;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    if-eqz v0, :cond_1

    .line 78
    .line 79
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 80
    .line 81
    sget-object v0, Ltechnology/cariad/cat/genx/CoreGenXStatus;->Companion:Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;

    .line 82
    .line 83
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getClientScanFailed()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 84
    .line 85
    .line 86
    move-result-object v0

    .line 87
    invoke-static {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManagerKt;->readableScanError(I)Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object v1

    .line 91
    new-instance v2, Ljava/lang/StringBuilder;

    .line 92
    .line 93
    const-string v3, "errorCode = "

    .line 94
    .line 95
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 99
    .line 100
    .line 101
    const-string v1, " ("

    .line 102
    .line 103
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 104
    .line 105
    .line 106
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 107
    .line 108
    .line 109
    const-string p1, ")."

    .line 110
    .line 111
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 112
    .line 113
    .line 114
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object p1

    .line 118
    invoke-virtual {p0, v0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->reportCoreGenXScanError$genx_release(Ltechnology/cariad/cat/genx/CoreGenXStatus;Ljava/lang/String;)V

    .line 119
    .line 120
    .line 121
    return-void

    .line 122
    :cond_1
    new-instance v0, Le1/h1;

    .line 123
    .line 124
    const/16 v3, 0x8

    .line 125
    .line 126
    invoke-direct {v0, p1, v3}, Le1/h1;-><init>(II)V

    .line 127
    .line 128
    .line 129
    invoke-static {p0, v1, v2, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 130
    .line 131
    .line 132
    return-void
.end method

.method public onScanResult(ILandroid/bluetooth/le/ScanResult;)V
    .locals 20

    .line 1
    move-object/from16 v4, p0

    .line 2
    .line 3
    move-object/from16 v7, p2

    .line 4
    .line 5
    iget-object v0, v4, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 6
    .line 7
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->cancelNoResponseCancellationJob$genx_release()V

    .line 8
    .line 9
    .line 10
    invoke-static {}, Ljava/time/Instant;->now()Ljava/time/Instant;

    .line 11
    .line 12
    .line 13
    move-result-object v10

    .line 14
    iget-object v0, v4, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 15
    .line 16
    invoke-static {v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->access$getScanResultSemaphore$p(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)Ljava/util/concurrent/Semaphore;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-virtual {v0}, Ljava/util/concurrent/Semaphore;->acquire()V

    .line 21
    .line 22
    .line 23
    iget-object v0, v4, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 24
    .line 25
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->isEnabled()Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    const-string v1, "GenX"

    .line 30
    .line 31
    const/4 v2, 0x0

    .line 32
    if-nez v0, :cond_0

    .line 33
    .line 34
    new-instance v0, Ltechnology/cariad/cat/genx/bluetooth/t;

    .line 35
    .line 36
    const/16 v3, 0xd

    .line 37
    .line 38
    invoke-direct {v0, v3}, Ltechnology/cariad/cat/genx/bluetooth/t;-><init>(I)V

    .line 39
    .line 40
    .line 41
    invoke-static {v4, v1, v2, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 42
    .line 43
    .line 44
    iget-object v0, v4, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 45
    .line 46
    invoke-static {v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->access$getScanResultSemaphore$p(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)Ljava/util/concurrent/Semaphore;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    invoke-virtual {v0}, Ljava/util/concurrent/Semaphore;->release()V

    .line 51
    .line 52
    .line 53
    return-void

    .line 54
    :cond_0
    iget-object v0, v4, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 55
    .line 56
    invoke-static {v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->access$getScanningWasRequested$p(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)Z

    .line 57
    .line 58
    .line 59
    move-result v0

    .line 60
    if-nez v0, :cond_1

    .line 61
    .line 62
    new-instance v0, Ltechnology/cariad/cat/genx/bluetooth/t;

    .line 63
    .line 64
    const/16 v3, 0xf

    .line 65
    .line 66
    invoke-direct {v0, v3}, Ltechnology/cariad/cat/genx/bluetooth/t;-><init>(I)V

    .line 67
    .line 68
    .line 69
    invoke-static {v4, v1, v2, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 70
    .line 71
    .line 72
    return-void

    .line 73
    :cond_1
    iget-object v0, v4, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 74
    .line 75
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->getScanning$genx_release()Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 76
    .line 77
    .line 78
    move-result-object v0

    .line 79
    const/4 v3, 0x1

    .line 80
    invoke-virtual {v0, v3}, Ljava/util/concurrent/atomic/AtomicBoolean;->getAndSet(Z)Z

    .line 81
    .line 82
    .line 83
    move-result v0

    .line 84
    if-nez v0, :cond_2

    .line 85
    .line 86
    new-instance v14, Ltechnology/cariad/cat/genx/bluetooth/t;

    .line 87
    .line 88
    const/16 v0, 0x10

    .line 89
    .line 90
    invoke-direct {v14, v0}, Ltechnology/cariad/cat/genx/bluetooth/t;-><init>(I)V

    .line 91
    .line 92
    .line 93
    new-instance v11, Lt51/j;

    .line 94
    .line 95
    invoke-static {v4}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 96
    .line 97
    .line 98
    move-result-object v16

    .line 99
    const-string v0, "getName(...)"

    .line 100
    .line 101
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 102
    .line 103
    .line 104
    move-result-object v17

    .line 105
    const-string v12, "GenX"

    .line 106
    .line 107
    sget-object v13, Lt51/d;->a:Lt51/d;

    .line 108
    .line 109
    const/4 v15, 0x0

    .line 110
    invoke-direct/range {v11 .. v17}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 111
    .line 112
    .line 113
    invoke-static {v11}, Lt51/a;->a(Lt51/j;)V

    .line 114
    .line 115
    .line 116
    :cond_2
    iget-object v0, v4, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 117
    .line 118
    new-instance v3, Ltechnology/cariad/cat/genx/bluetooth/i;

    .line 119
    .line 120
    const/4 v5, 0x6

    .line 121
    move/from16 v6, p1

    .line 122
    .line 123
    invoke-direct {v3, v6, v7, v5}, Ltechnology/cariad/cat/genx/bluetooth/i;-><init>(ILandroid/os/Parcelable;I)V

    .line 124
    .line 125
    .line 126
    invoke-virtual {v0, v3}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->logScanning$genx_release(Lay0/a;)V

    .line 127
    .line 128
    .line 129
    if-eqz v7, :cond_8

    .line 130
    .line 131
    invoke-virtual {v7}, Landroid/bluetooth/le/ScanResult;->getScanRecord()Landroid/bluetooth/le/ScanRecord;

    .line 132
    .line 133
    .line 134
    move-result-object v0

    .line 135
    if-eqz v0, :cond_8

    .line 136
    .line 137
    iget-object v13, v4, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 138
    .line 139
    invoke-virtual {v0}, Landroid/bluetooth/le/ScanRecord;->getServiceData()Ljava/util/Map;

    .line 140
    .line 141
    .line 142
    move-result-object v3

    .line 143
    sget-object v5, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->INSTANCE:Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;

    .line 144
    .line 145
    invoke-virtual {v5}, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->getInnerAntennaServiceDataUUID$genx_release()Landroid/os/ParcelUuid;

    .line 146
    .line 147
    .line 148
    move-result-object v6

    .line 149
    invoke-interface {v3, v6}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object v3

    .line 153
    check-cast v3, [B

    .line 154
    .line 155
    invoke-virtual {v0}, Landroid/bluetooth/le/ScanRecord;->getServiceData()Ljava/util/Map;

    .line 156
    .line 157
    .line 158
    move-result-object v0

    .line 159
    invoke-virtual {v5}, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->getOuterAntennaServiceDataUUID$genx_release()Landroid/os/ParcelUuid;

    .line 160
    .line 161
    .line 162
    move-result-object v6

    .line 163
    invoke-interface {v0, v6}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 164
    .line 165
    .line 166
    move-result-object v0

    .line 167
    check-cast v0, [B

    .line 168
    .line 169
    if-nez v3, :cond_3

    .line 170
    .line 171
    goto :goto_0

    .line 172
    :cond_3
    move-object v0, v3

    .line 173
    :goto_0
    if-eqz v0, :cond_8

    .line 174
    .line 175
    array-length v6, v0

    .line 176
    if-nez v6, :cond_4

    .line 177
    .line 178
    move-object v6, v2

    .line 179
    goto :goto_1

    .line 180
    :cond_4
    move-object v6, v0

    .line 181
    :goto_1
    if-eqz v6, :cond_8

    .line 182
    .line 183
    const-string v0, "getUuid(...)"

    .line 184
    .line 185
    if-eqz v3, :cond_5

    .line 186
    .line 187
    invoke-virtual {v5}, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->getInnerAntennaServiceUUID$genx_release()Landroid/os/ParcelUuid;

    .line 188
    .line 189
    .line 190
    move-result-object v3

    .line 191
    invoke-virtual {v3}, Landroid/os/ParcelUuid;->getUuid()Ljava/util/UUID;

    .line 192
    .line 193
    .line 194
    move-result-object v3

    .line 195
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 196
    .line 197
    .line 198
    sget-object v0, Ltechnology/cariad/cat/genx/Antenna;->INNER:Ltechnology/cariad/cat/genx/Antenna;

    .line 199
    .line 200
    :goto_2
    move-object v15, v0

    .line 201
    move-object/from16 v16, v3

    .line 202
    .line 203
    goto :goto_3

    .line 204
    :cond_5
    invoke-virtual {v5}, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->getOuterAntennaServiceUUID$genx_release()Landroid/os/ParcelUuid;

    .line 205
    .line 206
    .line 207
    move-result-object v3

    .line 208
    invoke-virtual {v3}, Landroid/os/ParcelUuid;->getUuid()Ljava/util/UUID;

    .line 209
    .line 210
    .line 211
    move-result-object v3

    .line 212
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 213
    .line 214
    .line 215
    sget-object v0, Ltechnology/cariad/cat/genx/Antenna;->OUTER:Ltechnology/cariad/cat/genx/Antenna;

    .line 216
    .line 217
    goto :goto_2

    .line 218
    :goto_3
    invoke-virtual {v7}, Landroid/bluetooth/le/ScanResult;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 219
    .line 220
    .line 221
    move-result-object v17

    .line 222
    new-instance v5, Lh2/j2;

    .line 223
    .line 224
    const/4 v11, 0x2

    .line 225
    move-object v9, v15

    .line 226
    move-object/from16 v8, v17

    .line 227
    .line 228
    invoke-direct/range {v5 .. v11}, Lh2/j2;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 229
    .line 230
    .line 231
    move-object v0, v5

    .line 232
    move-object v3, v6

    .line 233
    move-object v5, v8

    .line 234
    invoke-virtual {v13, v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->logScanning$genx_release(Lay0/a;)V

    .line 235
    .line 236
    .line 237
    invoke-virtual {v13}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->getClients$genx_release()Ljava/util/concurrent/ConcurrentHashMap;

    .line 238
    .line 239
    .line 240
    move-result-object v0

    .line 241
    invoke-virtual {v5}, Landroid/bluetooth/BluetoothDevice;->getAddress()Ljava/lang/String;

    .line 242
    .line 243
    .line 244
    move-result-object v6

    .line 245
    invoke-virtual {v0, v6}, Ljava/util/concurrent/ConcurrentHashMap;->containsKey(Ljava/lang/Object;)Z

    .line 246
    .line 247
    .line 248
    move-result v0

    .line 249
    if-nez v0, :cond_6

    .line 250
    .line 251
    new-instance v0, Ltechnology/cariad/cat/genx/bluetooth/c;

    .line 252
    .line 253
    const/16 v1, 0x8

    .line 254
    .line 255
    invoke-direct {v0, v1, v5}, Ltechnology/cariad/cat/genx/bluetooth/c;-><init>(ILandroid/bluetooth/BluetoothDevice;)V

    .line 256
    .line 257
    .line 258
    invoke-virtual {v13, v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->logScanning$genx_release(Lay0/a;)V

    .line 259
    .line 260
    .line 261
    invoke-virtual {v13}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->getContext()Landroid/content/Context;

    .line 262
    .line 263
    .line 264
    move-result-object v12

    .line 265
    invoke-virtual {v13}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->getGenXDispatcher()Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 266
    .line 267
    .line 268
    move-result-object v14

    .line 269
    invoke-virtual {v13}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->getBluetoothConnectRetryCount()I

    .line 270
    .line 271
    .line 272
    move-result v18

    .line 273
    invoke-virtual {v13}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->getBluetoothConnectRetryDelay()I

    .line 274
    .line 275
    .line 276
    move-result v19

    .line 277
    new-instance v2, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 278
    .line 279
    move-object v11, v2

    .line 280
    move-object/from16 v17, v5

    .line 281
    .line 282
    invoke-direct/range {v11 .. v19}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;-><init>(Landroid/content/Context;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;Ltechnology/cariad/cat/genx/GenXDispatcher;Ltechnology/cariad/cat/genx/Antenna;Ljava/util/UUID;Landroid/bluetooth/BluetoothDevice;II)V

    .line 283
    .line 284
    .line 285
    invoke-virtual {v13}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->getGenXDispatcher()Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 286
    .line 287
    .line 288
    move-result-object v7

    .line 289
    new-instance v0, Lh2/j2;

    .line 290
    .line 291
    const/4 v6, 0x3

    .line 292
    move-object v1, v13

    .line 293
    invoke-direct/range {v0 .. v6}, Lh2/j2;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 294
    .line 295
    .line 296
    invoke-interface {v7, v0}, Ltechnology/cariad/cat/genx/GenXDispatcher;->dispatch(Lay0/a;)V

    .line 297
    .line 298
    .line 299
    goto :goto_4

    .line 300
    :cond_6
    invoke-virtual {v13}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->getClients$genx_release()Ljava/util/concurrent/ConcurrentHashMap;

    .line 301
    .line 302
    .line 303
    move-result-object v0

    .line 304
    invoke-virtual {v5}, Landroid/bluetooth/BluetoothDevice;->getAddress()Ljava/lang/String;

    .line 305
    .line 306
    .line 307
    move-result-object v6

    .line 308
    invoke-virtual {v0, v6}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 309
    .line 310
    .line 311
    move-result-object v0

    .line 312
    check-cast v0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 313
    .line 314
    if-eqz v0, :cond_8

    .line 315
    .line 316
    new-instance v6, Ltechnology/cariad/cat/genx/TypedFrame;

    .line 317
    .line 318
    sget-object v7, Ltechnology/cariad/cat/genx/TypedFrameType;->Advertisement:Ltechnology/cariad/cat/genx/TypedFrameType;

    .line 319
    .line 320
    invoke-direct {v6, v7, v3}, Ltechnology/cariad/cat/genx/TypedFrame;-><init>(Ltechnology/cariad/cat/genx/TypedFrameType;[B)V

    .line 321
    .line 322
    .line 323
    invoke-static {v10}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 324
    .line 325
    .line 326
    invoke-virtual {v0, v6, v10}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->updateAdvertisement$genx_release(Ltechnology/cariad/cat/genx/TypedFrame;Ljava/time/Instant;)Z

    .line 327
    .line 328
    .line 329
    move-result v0

    .line 330
    if-eqz v0, :cond_7

    .line 331
    .line 332
    new-instance v0, Ltechnology/cariad/cat/genx/bluetooth/c;

    .line 333
    .line 334
    const/16 v1, 0x9

    .line 335
    .line 336
    invoke-direct {v0, v1, v5}, Ltechnology/cariad/cat/genx/bluetooth/c;-><init>(ILandroid/bluetooth/BluetoothDevice;)V

    .line 337
    .line 338
    .line 339
    invoke-virtual {v13, v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->logScanning$genx_release(Lay0/a;)V

    .line 340
    .line 341
    .line 342
    goto :goto_4

    .line 343
    :cond_7
    new-instance v0, Ltechnology/cariad/cat/genx/bluetooth/c;

    .line 344
    .line 345
    const/16 v3, 0xa

    .line 346
    .line 347
    invoke-direct {v0, v3, v5}, Ltechnology/cariad/cat/genx/bluetooth/c;-><init>(ILandroid/bluetooth/BluetoothDevice;)V

    .line 348
    .line 349
    .line 350
    invoke-static {v4, v1, v2, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 351
    .line 352
    .line 353
    invoke-virtual {v5}, Landroid/bluetooth/BluetoothDevice;->getAddress()Ljava/lang/String;

    .line 354
    .line 355
    .line 356
    move-result-object v0

    .line 357
    const-string v1, "getAddress(...)"

    .line 358
    .line 359
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 360
    .line 361
    .line 362
    invoke-virtual {v13, v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->removeClient(Ljava/lang/String;)V

    .line 363
    .line 364
    .line 365
    :cond_8
    :goto_4
    iget-object v0, v4, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 366
    .line 367
    invoke-static {v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->access$getScanResultSemaphore$p(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)Ljava/util/concurrent/Semaphore;

    .line 368
    .line 369
    .line 370
    move-result-object v0

    .line 371
    invoke-virtual {v0}, Ljava/util/concurrent/Semaphore;->release()V

    .line 372
    .line 373
    .line 374
    return-void
.end method
