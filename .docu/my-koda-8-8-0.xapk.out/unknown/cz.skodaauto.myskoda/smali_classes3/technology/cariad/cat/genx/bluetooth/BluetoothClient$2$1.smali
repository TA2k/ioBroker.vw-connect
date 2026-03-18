.class public final Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$2$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lb01/b;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;-><init>(Landroid/content/Context;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;Ltechnology/cariad/cat/genx/GenXDispatcher;Ltechnology/cariad/cat/genx/Antenna;Ljava/util/UUID;Landroid/bluetooth/BluetoothDevice;II)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u001f\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0008\n\u0002\u0008\u0007*\u0001\u0000\u0008\n\u0018\u00002\u00020\u0001J\u0017\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H\u0016\u00a2\u0006\u0004\u0008\u0005\u0010\u0006J\u0017\u0010\u0007\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H\u0016\u00a2\u0006\u0004\u0008\u0007\u0010\u0006J\u001f\u0010\n\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\t\u001a\u00020\u0008H\u0016\u00a2\u0006\u0004\u0008\n\u0010\u000bJ\u0017\u0010\u000c\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H\u0016\u00a2\u0006\u0004\u0008\u000c\u0010\u0006J\u0017\u0010\r\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H\u0016\u00a2\u0006\u0004\u0008\r\u0010\u0006J\u001f\u0010\u000e\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\t\u001a\u00020\u0008H\u0016\u00a2\u0006\u0004\u0008\u000e\u0010\u000b\u00a8\u0006\u000f"
    }
    d2 = {
        "technology/cariad/cat/genx/bluetooth/BluetoothClient$2$1",
        "Lb01/b;",
        "Landroid/bluetooth/BluetoothDevice;",
        "device",
        "Llx0/b0;",
        "onDeviceConnecting",
        "(Landroid/bluetooth/BluetoothDevice;)V",
        "onDeviceConnected",
        "",
        "reason",
        "onDeviceFailedToConnect",
        "(Landroid/bluetooth/BluetoothDevice;I)V",
        "onDeviceReady",
        "onDeviceDisconnecting",
        "onDeviceDisconnected",
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
.field final synthetic this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$2$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public static synthetic a(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$2$1;->onDeviceDisconnecting$lambda$4(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic b(ILandroid/bluetooth/BluetoothDevice;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p1, p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$2$1;->onDeviceFailedToConnect$lambda$2(Landroid/bluetooth/BluetoothDevice;I)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic c(ILandroid/bluetooth/BluetoothDevice;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p1, p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$2$1;->onDeviceDisconnected$lambda$5(Landroid/bluetooth/BluetoothDevice;I)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic d(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$2$1;->onDeviceConnecting$lambda$0(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic e(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$2$1;->onDeviceConnected$lambda$1(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic f(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$2$1;->onDeviceReady$lambda$3(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final onDeviceConnected$lambda$1(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const-string v0, "connectionObserver.onDeviceConnected(): device = "

    .line 6
    .line 7
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method private static final onDeviceConnecting$lambda$0(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const-string v0, "connectionObserver.onDeviceConnecting(): device = "

    .line 6
    .line 7
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method private static final onDeviceDisconnected$lambda$5(Landroid/bluetooth/BluetoothDevice;I)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getDisconnectionReasonDescription(I)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    const-string v0, "connectionObserver.onDeviceDisconnected(): device = "

    .line 10
    .line 11
    const-string v1, ", reason = "

    .line 12
    .line 13
    invoke-static {v0, p0, v1, p1}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method private static final onDeviceDisconnecting$lambda$4(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const-string v0, "connectionObserver.onDeviceDisconnecting(): device = "

    .line 6
    .line 7
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method private static final onDeviceFailedToConnect$lambda$2(Landroid/bluetooth/BluetoothDevice;I)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getDisconnectionReasonDescription(I)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    const-string v0, "connectionObserver.onDeviceFailedToConnect(): device = "

    .line 10
    .line 11
    const-string v1, ", reason = "

    .line 12
    .line 13
    invoke-static {v0, p0, v1, p1}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method private static final onDeviceReady$lambda$3(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const-string v0, "connectionObserver.onDeviceReady(): device = "

    .line 6
    .line 7
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method


# virtual methods
.method public onDeviceConnected(Landroid/bluetooth/BluetoothDevice;)V
    .locals 8

    .line 1
    const-string v0, "device"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v4, Ltechnology/cariad/cat/genx/bluetooth/c;

    .line 7
    .line 8
    const/4 v0, 0x2

    .line 9
    invoke-direct {v4, v0, p1}, Ltechnology/cariad/cat/genx/bluetooth/c;-><init>(ILandroid/bluetooth/BluetoothDevice;)V

    .line 10
    .line 11
    .line 12
    new-instance v1, Lt51/j;

    .line 13
    .line 14
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v6

    .line 18
    const-string p1, "getName(...)"

    .line 19
    .line 20
    invoke-static {p1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v7

    .line 24
    const-string v2, "GenX"

    .line 25
    .line 26
    sget-object v3, Lt51/f;->a:Lt51/f;

    .line 27
    .line 28
    const/4 v5, 0x0

    .line 29
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 33
    .line 34
    .line 35
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$2$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 36
    .line 37
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->onDeviceConnected$genx_release()V

    .line 38
    .line 39
    .line 40
    return-void
.end method

.method public onDeviceConnecting(Landroid/bluetooth/BluetoothDevice;)V
    .locals 8

    .line 1
    const-string v0, "device"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v4, Ltechnology/cariad/cat/genx/bluetooth/c;

    .line 7
    .line 8
    const/4 v0, 0x5

    .line 9
    invoke-direct {v4, v0, p1}, Ltechnology/cariad/cat/genx/bluetooth/c;-><init>(ILandroid/bluetooth/BluetoothDevice;)V

    .line 10
    .line 11
    .line 12
    new-instance v1, Lt51/j;

    .line 13
    .line 14
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v6

    .line 18
    const-string p0, "getName(...)"

    .line 19
    .line 20
    invoke-static {p0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v7

    .line 24
    const-string v2, "GenX"

    .line 25
    .line 26
    sget-object v3, Lt51/g;->a:Lt51/g;

    .line 27
    .line 28
    const/4 v5, 0x0

    .line 29
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 33
    .line 34
    .line 35
    return-void
.end method

.method public onDeviceDisconnected(Landroid/bluetooth/BluetoothDevice;I)V
    .locals 8

    .line 1
    const-string v0, "device"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v4, Ltechnology/cariad/cat/genx/bluetooth/i;

    .line 7
    .line 8
    const/4 v0, 0x4

    .line 9
    invoke-direct {v4, p2, v0, p1}, Ltechnology/cariad/cat/genx/bluetooth/i;-><init>(IILandroid/bluetooth/BluetoothDevice;)V

    .line 10
    .line 11
    .line 12
    new-instance v1, Lt51/j;

    .line 13
    .line 14
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v6

    .line 18
    const-string p1, "getName(...)"

    .line 19
    .line 20
    invoke-static {p1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v7

    .line 24
    const-string v2, "GenX"

    .line 25
    .line 26
    sget-object v3, Lt51/f;->a:Lt51/f;

    .line 27
    .line 28
    const/4 v5, 0x0

    .line 29
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 33
    .line 34
    .line 35
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$2$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 36
    .line 37
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->onDeviceDisconnected$genx_release()V

    .line 38
    .line 39
    .line 40
    return-void
.end method

.method public onDeviceDisconnecting(Landroid/bluetooth/BluetoothDevice;)V
    .locals 8

    .line 1
    const-string v0, "device"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v4, Ltechnology/cariad/cat/genx/bluetooth/c;

    .line 7
    .line 8
    const/4 v0, 0x3

    .line 9
    invoke-direct {v4, v0, p1}, Ltechnology/cariad/cat/genx/bluetooth/c;-><init>(ILandroid/bluetooth/BluetoothDevice;)V

    .line 10
    .line 11
    .line 12
    new-instance v1, Lt51/j;

    .line 13
    .line 14
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v6

    .line 18
    const-string p0, "getName(...)"

    .line 19
    .line 20
    invoke-static {p0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v7

    .line 24
    const-string v2, "GenX"

    .line 25
    .line 26
    sget-object v3, Lt51/g;->a:Lt51/g;

    .line 27
    .line 28
    const/4 v5, 0x0

    .line 29
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 33
    .line 34
    .line 35
    return-void
.end method

.method public onDeviceFailedToConnect(Landroid/bluetooth/BluetoothDevice;I)V
    .locals 2

    .line 1
    const-string v0, "device"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Ltechnology/cariad/cat/genx/bluetooth/i;

    .line 7
    .line 8
    const/4 v1, 0x5

    .line 9
    invoke-direct {v0, p2, v1, p1}, Ltechnology/cariad/cat/genx/bluetooth/i;-><init>(IILandroid/bluetooth/BluetoothDevice;)V

    .line 10
    .line 11
    .line 12
    const/4 p1, 0x0

    .line 13
    const-string p2, "GenX"

    .line 14
    .line 15
    invoke-static {p0, p2, p1, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 16
    .line 17
    .line 18
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$2$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 19
    .line 20
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->disconnect()V

    .line 21
    .line 22
    .line 23
    return-void
.end method

.method public onDeviceReady(Landroid/bluetooth/BluetoothDevice;)V
    .locals 8

    .line 1
    const-string v0, "device"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v4, Ltechnology/cariad/cat/genx/bluetooth/c;

    .line 7
    .line 8
    const/4 v0, 0x4

    .line 9
    invoke-direct {v4, v0, p1}, Ltechnology/cariad/cat/genx/bluetooth/c;-><init>(ILandroid/bluetooth/BluetoothDevice;)V

    .line 10
    .line 11
    .line 12
    new-instance v1, Lt51/j;

    .line 13
    .line 14
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v6

    .line 18
    const-string p0, "getName(...)"

    .line 19
    .line 20
    invoke-static {p0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v7

    .line 24
    const-string v2, "GenX"

    .line 25
    .line 26
    sget-object v3, Lt51/g;->a:Lt51/g;

    .line 27
    .line 28
    const/4 v5, 0x0

    .line 29
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 33
    .line 34
    .line 35
    return-void
.end method
