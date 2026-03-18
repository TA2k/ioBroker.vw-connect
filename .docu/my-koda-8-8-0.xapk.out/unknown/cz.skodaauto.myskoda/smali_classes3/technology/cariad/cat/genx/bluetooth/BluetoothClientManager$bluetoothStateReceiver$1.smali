.class public final Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$bluetoothStateReceiver$1;
.super Landroid/content/BroadcastReceiver;
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
        "\u0000\u001f\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0004*\u0001\u0000\u0008\n\u0018\u00002\u00020\u0001J\u000f\u0010\u0003\u001a\u00020\u0002H\u0002\u00a2\u0006\u0004\u0008\u0003\u0010\u0004J\u000f\u0010\u0005\u001a\u00020\u0002H\u0002\u00a2\u0006\u0004\u0008\u0005\u0010\u0004J#\u0010\n\u001a\u00020\u00022\u0008\u0010\u0007\u001a\u0004\u0018\u00010\u00062\u0008\u0010\t\u001a\u0004\u0018\u00010\u0008H\u0016\u00a2\u0006\u0004\u0008\n\u0010\u000b\u00a8\u0006\u000c"
    }
    d2 = {
        "technology/cariad/cat/genx/bluetooth/BluetoothClientManager$bluetoothStateReceiver$1",
        "Landroid/content/BroadcastReceiver;",
        "Llx0/b0;",
        "onBluetoothTurnedOn",
        "()V",
        "onBluetoothTurnedOff",
        "Landroid/content/Context;",
        "context",
        "Landroid/content/Intent;",
        "intent",
        "onReceive",
        "(Landroid/content/Context;Landroid/content/Intent;)V",
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
    iput-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$bluetoothStateReceiver$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 2
    .line 3
    invoke-direct {p0}, Landroid/content/BroadcastReceiver;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public static synthetic a(II)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$bluetoothStateReceiver$1;->onReceive$lambda$5$0(II)Ljava/lang/String;

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
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$bluetoothStateReceiver$1;->onBluetoothTurnedOn$lambda$2$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic c()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$bluetoothStateReceiver$1;->onBluetoothTurnedOff$lambda$3()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic d()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$bluetoothStateReceiver$1;->onBluetoothTurnedOff$lambda$4()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic e()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$bluetoothStateReceiver$1;->onBluetoothTurnedOn$lambda$1()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic f()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$bluetoothStateReceiver$1;->onBluetoothTurnedOn$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private final onBluetoothTurnedOff()V
    .locals 15

    .line 1
    new-instance v3, Ltechnology/cariad/cat/genx/bluetooth/t;

    .line 2
    .line 3
    const/16 v0, 0xb

    .line 4
    .line 5
    invoke-direct {v3, v0}, Ltechnology/cariad/cat/genx/bluetooth/t;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v0, Lt51/j;

    .line 9
    .line 10
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v5

    .line 14
    const-string v7, "getName(...)"

    .line 15
    .line 16
    invoke-static {v7}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v6

    .line 20
    const-string v1, "GenX"

    .line 21
    .line 22
    sget-object v2, Lt51/f;->a:Lt51/f;

    .line 23
    .line 24
    const/4 v4, 0x0

    .line 25
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 29
    .line 30
    .line 31
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$bluetoothStateReceiver$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 32
    .line 33
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->isBleEnabled$genx_release()Lyy0/j1;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 38
    .line 39
    check-cast v0, Lyy0/c2;

    .line 40
    .line 41
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 42
    .line 43
    .line 44
    const/4 v2, 0x0

    .line 45
    invoke-virtual {v0, v2, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$bluetoothStateReceiver$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 49
    .line 50
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->getScanning$genx_release()Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    if-eqz v0, :cond_0

    .line 59
    .line 60
    new-instance v11, Ltechnology/cariad/cat/genx/bluetooth/t;

    .line 61
    .line 62
    const/16 v0, 0xc

    .line 63
    .line 64
    invoke-direct {v11, v0}, Ltechnology/cariad/cat/genx/bluetooth/t;-><init>(I)V

    .line 65
    .line 66
    .line 67
    new-instance v8, Lt51/j;

    .line 68
    .line 69
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object v13

    .line 73
    invoke-static {v7}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object v14

    .line 77
    const-string v9, "GenX"

    .line 78
    .line 79
    sget-object v10, Lt51/g;->a:Lt51/g;

    .line 80
    .line 81
    const/4 v12, 0x0

    .line 82
    invoke-direct/range {v8 .. v14}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    invoke-static {v8}, Lt51/a;->a(Lt51/j;)V

    .line 86
    .line 87
    .line 88
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$bluetoothStateReceiver$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 89
    .line 90
    invoke-static {v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->access$getScanningSemaphore$p(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)Ljava/util/concurrent/Semaphore;

    .line 91
    .line 92
    .line 93
    move-result-object v0

    .line 94
    invoke-virtual {v0}, Ljava/util/concurrent/Semaphore;->acquireUninterruptibly()V

    .line 95
    .line 96
    .line 97
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$bluetoothStateReceiver$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 98
    .line 99
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->stopScan$genx_release()V

    .line 100
    .line 101
    .line 102
    :cond_0
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$bluetoothStateReceiver$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 103
    .line 104
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->removeAllClientsThatShouldBeRemoved$genx_release()V

    .line 105
    .line 106
    .line 107
    return-void
.end method

.method private static final onBluetoothTurnedOff$lambda$3()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "onBluetoothTurnedOff(): Bluetooth state turned \'OFF\'."

    .line 2
    .line 3
    return-object v0
.end method

.method private static final onBluetoothTurnedOff$lambda$4()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "onBluetoothTurnedOff(): Stop scanning"

    .line 2
    .line 3
    return-object v0
.end method

.method private final onBluetoothTurnedOn()V
    .locals 15

    .line 1
    new-instance v3, Ltechnology/cariad/cat/genx/bluetooth/t;

    .line 2
    .line 3
    const/16 v0, 0x8

    .line 4
    .line 5
    invoke-direct {v3, v0}, Ltechnology/cariad/cat/genx/bluetooth/t;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v0, Lt51/j;

    .line 9
    .line 10
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v5

    .line 14
    const-string v7, "getName(...)"

    .line 15
    .line 16
    invoke-static {v7}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v6

    .line 20
    const-string v1, "GenX"

    .line 21
    .line 22
    sget-object v2, Lt51/f;->a:Lt51/f;

    .line 23
    .line 24
    const/4 v4, 0x0

    .line 25
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 29
    .line 30
    .line 31
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$bluetoothStateReceiver$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 32
    .line 33
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->isBleEnabled$genx_release()Lyy0/j1;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 38
    .line 39
    check-cast v0, Lyy0/c2;

    .line 40
    .line 41
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 42
    .line 43
    .line 44
    const/4 v3, 0x0

    .line 45
    invoke-virtual {v0, v3, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$bluetoothStateReceiver$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 49
    .line 50
    invoke-static {v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->access$getScanningWasRequested$p(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)Z

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    if-eqz v0, :cond_0

    .line 55
    .line 56
    new-instance v11, Ltechnology/cariad/cat/genx/bluetooth/t;

    .line 57
    .line 58
    const/16 v0, 0x9

    .line 59
    .line 60
    invoke-direct {v11, v0}, Ltechnology/cariad/cat/genx/bluetooth/t;-><init>(I)V

    .line 61
    .line 62
    .line 63
    new-instance v8, Lt51/j;

    .line 64
    .line 65
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v13

    .line 69
    invoke-static {v7}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object v14

    .line 73
    const-string v9, "GenX"

    .line 74
    .line 75
    const/4 v12, 0x0

    .line 76
    move-object v10, v2

    .line 77
    invoke-direct/range {v8 .. v14}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    invoke-static {v8}, Lt51/a;->a(Lt51/j;)V

    .line 81
    .line 82
    .line 83
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$bluetoothStateReceiver$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 84
    .line 85
    const/4 v1, 0x1

    .line 86
    invoke-virtual {v0, v1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->startScanningForClients$genx_release(Z)Ltechnology/cariad/cat/genx/GenXError;

    .line 87
    .line 88
    .line 89
    move-result-object v0

    .line 90
    if-eqz v0, :cond_0

    .line 91
    .line 92
    new-instance v1, Ltechnology/cariad/cat/genx/bluetooth/t;

    .line 93
    .line 94
    const/16 v2, 0xa

    .line 95
    .line 96
    invoke-direct {v1, v2}, Ltechnology/cariad/cat/genx/bluetooth/t;-><init>(I)V

    .line 97
    .line 98
    .line 99
    const-string v2, "GenX"

    .line 100
    .line 101
    invoke-static {p0, v2, v0, v1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 102
    .line 103
    .line 104
    :cond_0
    return-void
.end method

.method private static final onBluetoothTurnedOn$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "onBluetoothTurnedOn(): Bluetooth state turned \'ON\'."

    .line 2
    .line 3
    return-object v0
.end method

.method private static final onBluetoothTurnedOn$lambda$1()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "onBluetoothTurnedOn(): Bluetooth state turned \'ON\' while already scanning. -> Start scanning again"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final onBluetoothTurnedOn$lambda$2$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "onBluetoothTurnedOn(): Failed to restart scanning after state turned \'ON\'"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final onReceive$lambda$5$0(II)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManagerKt;->readableBluetoothState(I)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManagerKt;->readableBluetoothState(I)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    const-string v0, "onReceive(): Bluetooth state switched from "

    .line 10
    .line 11
    const-string v1, " to "

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


# virtual methods
.method public onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .locals 8

    .line 1
    if-eqz p2, :cond_2

    .line 2
    .line 3
    iget-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$bluetoothStateReceiver$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 4
    .line 5
    const-string v0, "android.bluetooth.adapter.extra.STATE"

    .line 6
    .line 7
    const/16 v1, 0xa

    .line 8
    .line 9
    invoke-virtual {p2, v0, v1}, Landroid/content/Intent;->getIntExtra(Ljava/lang/String;I)I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    const-string v2, "android.bluetooth.adapter.extra.PREVIOUS_STATE"

    .line 14
    .line 15
    invoke-virtual {p2, v2, v1}, Landroid/content/Intent;->getIntExtra(Ljava/lang/String;I)I

    .line 16
    .line 17
    .line 18
    move-result p2

    .line 19
    new-instance v4, Lk61/a;

    .line 20
    .line 21
    const/4 v1, 0x1

    .line 22
    invoke-direct {v4, p2, v0, v1}, Lk61/a;-><init>(III)V

    .line 23
    .line 24
    .line 25
    new-instance v1, Lt51/j;

    .line 26
    .line 27
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v6

    .line 31
    const-string p2, "getName(...)"

    .line 32
    .line 33
    invoke-static {p2}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v7

    .line 37
    const-string v2, "GenX"

    .line 38
    .line 39
    sget-object v3, Lt51/d;->a:Lt51/d;

    .line 40
    .line 41
    const/4 v5, 0x0

    .line 42
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->propagateClientManagerState$genx_release()V

    .line 49
    .line 50
    .line 51
    const/16 p1, 0xc

    .line 52
    .line 53
    if-eq v0, p1, :cond_1

    .line 54
    .line 55
    const/16 p1, 0xd

    .line 56
    .line 57
    if-eq v0, p1, :cond_0

    .line 58
    .line 59
    goto :goto_0

    .line 60
    :cond_0
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$bluetoothStateReceiver$1;->onBluetoothTurnedOff()V

    .line 61
    .line 62
    .line 63
    return-void

    .line 64
    :cond_1
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$bluetoothStateReceiver$1;->onBluetoothTurnedOn()V

    .line 65
    .line 66
    .line 67
    :cond_2
    :goto_0
    return-void
.end method
