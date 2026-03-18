.class final Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$stopScan$2;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->stopScan$genx_release()V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lrx0/i;",
        "Lay0/n;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000c\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\u0010\u0002\u001a\u00020\u0001*\u00020\u0000H\n\u00a2\u0006\u0004\u0008\u0002\u0010\u0003"
    }
    d2 = {
        "Lvy0/b0;",
        "Llx0/b0;",
        "<anonymous>",
        "(Lvy0/b0;)V"
    }
    k = 0x3
    mv = {
        0x2,
        0x2,
        0x0
    }
.end annotation

.annotation runtime Lrx0/e;
    c = "technology.cariad.cat.genx.bluetooth.BluetoothClientManager$stopScan$2"
    f = "BluetoothClientManager.kt"
    l = {}
    m = "invokeSuspend"
    v = 0x1
.end annotation


# instance fields
.field label:I

.field final synthetic this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;Lkotlin/coroutines/Continuation;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$stopScan$2;",
            ">;)V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$stopScan$2;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 2
    .line 3
    const/4 p1, 0x2

    .line 4
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public static synthetic b()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$stopScan$2;->invokeSuspend$lambda$2()Ljava/lang/String;

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
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$stopScan$2;->invokeSuspend$lambda$4()Ljava/lang/String;

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
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$stopScan$2;->invokeSuspend$lambda$1()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private static final invokeSuspend$lambda$1()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "stopScan(): Scanning stopped."

    .line 2
    .line 3
    return-object v0
.end method

.method private static final invokeSuspend$lambda$2()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "stopScan(): BLE has been disabled while scheduling \'stopScan\'. -> Propagate state change and notify error."

    .line 2
    .line 3
    return-object v0
.end method

.method private static final invokeSuspend$lambda$4()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "stopScan(): Failed to delegate the scan failure (message = \'BLE disabled while scheduling \'stopScan\'\') due to missing delegate."

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/Object;",
            "Lkotlin/coroutines/Continuation<",
            "*>;)",
            "Lkotlin/coroutines/Continuation<",
            "Llx0/b0;",
            ">;"
        }
    .end annotation

    .line 1
    new-instance p1, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$stopScan$2;

    .line 2
    .line 3
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$stopScan$2;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 4
    .line 5
    invoke-direct {p1, p0, p2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$stopScan$2;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;Lkotlin/coroutines/Continuation;)V

    .line 6
    .line 7
    .line 8
    return-object p1
.end method

.method public bridge synthetic invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lvy0/b0;

    check-cast p2, Lkotlin/coroutines/Continuation;

    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$stopScan$2;->invoke(Lvy0/b0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invoke(Lvy0/b0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lvy0/b0;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Llx0/b0;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 2
    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$stopScan$2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    move-result-object p0

    check-cast p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$stopScan$2;

    sget-object p1, Llx0/b0;->a:Llx0/b0;

    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$stopScan$2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$stopScan$2;->label:I

    .line 4
    .line 5
    if-nez v0, :cond_3

    .line 6
    .line 7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    :try_start_0
    sget-object p1, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->INSTANCE:Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;

    .line 11
    .line 12
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$stopScan$2;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 13
    .line 14
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->getContext()Landroid/content/Context;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    invoke-virtual {p1, v0}, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->isBluetoothScanPermissionRequiredAndGranted(Landroid/content/Context;)Z

    .line 19
    .line 20
    .line 21
    move-result p1

    .line 22
    if-eqz p1, :cond_1

    .line 23
    .line 24
    iget-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$stopScan$2;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 25
    .line 26
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->getContext()Landroid/content/Context;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    invoke-static {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothKt;->getBluetoothAdapter(Landroid/content/Context;)Landroid/bluetooth/BluetoothAdapter;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    if-eqz p1, :cond_0

    .line 35
    .line 36
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothAdapter;->getBluetoothLeScanner()Landroid/bluetooth/le/BluetoothLeScanner;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    if-eqz p1, :cond_0

    .line 41
    .line 42
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$stopScan$2;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 43
    .line 44
    invoke-static {v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->access$getScanCallback$p(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)Landroid/bluetooth/le/ScanCallback;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    invoke-virtual {p1, v0}, Landroid/bluetooth/le/BluetoothLeScanner;->stopScan(Landroid/bluetooth/le/ScanCallback;)V

    .line 49
    .line 50
    .line 51
    goto :goto_0

    .line 52
    :catch_0
    move-exception v0

    .line 53
    move-object p1, v0

    .line 54
    goto :goto_1

    .line 55
    :cond_0
    :goto_0
    iget-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$stopScan$2;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 56
    .line 57
    new-instance v3, Ltechnology/cariad/cat/genx/bluetooth/m;

    .line 58
    .line 59
    const/16 v0, 0xc

    .line 60
    .line 61
    invoke-direct {v3, v0}, Ltechnology/cariad/cat/genx/bluetooth/m;-><init>(I)V

    .line 62
    .line 63
    .line 64
    const-string v1, "GenX"

    .line 65
    .line 66
    new-instance v0, Lt51/j;

    .line 67
    .line 68
    sget-object v2, Lt51/d;->a:Lt51/d;

    .line 69
    .line 70
    invoke-static {p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object v5

    .line 74
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 75
    .line 76
    .line 77
    move-result-object p1

    .line 78
    invoke-virtual {p1}, Ljava/lang/Thread;->getName()Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object v6

    .line 82
    const-string p1, "getName(...)"

    .line 83
    .line 84
    invoke-static {v6, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    const/4 v4, 0x0

    .line 88
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 92
    .line 93
    .line 94
    goto :goto_2

    .line 95
    :cond_1
    const-string p1, "\'Bluetooth.isBluetoothScanPermissionRequiredAndGranted(context)\' returned false. -> Missing check?"

    .line 96
    .line 97
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 98
    .line 99
    invoke-direct {v0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    throw v0
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0

    .line 103
    :goto_1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$stopScan$2;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 104
    .line 105
    new-instance v1, Ltechnology/cariad/cat/genx/bluetooth/m;

    .line 106
    .line 107
    const/16 v2, 0xd

    .line 108
    .line 109
    invoke-direct {v1, v2}, Ltechnology/cariad/cat/genx/bluetooth/m;-><init>(I)V

    .line 110
    .line 111
    .line 112
    const-string v2, "GenX"

    .line 113
    .line 114
    invoke-static {v0, v2, p1, v1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 115
    .line 116
    .line 117
    iget-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$stopScan$2;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 118
    .line 119
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->propagateClientManagerState$genx_release()V

    .line 120
    .line 121
    .line 122
    iget-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$stopScan$2;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 123
    .line 124
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->getDelegate()Ltechnology/cariad/cat/genx/ClientManagerDelegate;

    .line 125
    .line 126
    .line 127
    move-result-object p1

    .line 128
    if-eqz p1, :cond_2

    .line 129
    .line 130
    iget-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$stopScan$2;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 131
    .line 132
    sget-object v0, Ltechnology/cariad/cat/genx/CoreGenXStatus;->Companion:Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;

    .line 133
    .line 134
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getClientDisabled()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 135
    .line 136
    .line 137
    move-result-object v0

    .line 138
    const-string v1, "BLE disabled while scheduling \'stopScan\'"

    .line 139
    .line 140
    invoke-virtual {p1, v0, v1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->reportCoreGenXScanError$genx_release(Ltechnology/cariad/cat/genx/CoreGenXStatus;Ljava/lang/String;)V

    .line 141
    .line 142
    .line 143
    goto :goto_2

    .line 144
    :cond_2
    iget-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$stopScan$2;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 145
    .line 146
    new-instance v0, Ltechnology/cariad/cat/genx/bluetooth/m;

    .line 147
    .line 148
    const/16 v1, 0xe

    .line 149
    .line 150
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/bluetooth/m;-><init>(I)V

    .line 151
    .line 152
    .line 153
    const/4 v1, 0x0

    .line 154
    invoke-static {p1, v2, v1, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 155
    .line 156
    .line 157
    :goto_2
    iget-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$stopScan$2;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 158
    .line 159
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->getScanning$genx_release()Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 160
    .line 161
    .line 162
    move-result-object p1

    .line 163
    const/4 v0, 0x0

    .line 164
    invoke-virtual {p1, v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 165
    .line 166
    .line 167
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$stopScan$2;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 168
    .line 169
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->access$getScanningSemaphore$p(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)Ljava/util/concurrent/Semaphore;

    .line 170
    .line 171
    .line 172
    move-result-object p0

    .line 173
    invoke-virtual {p0}, Ljava/util/concurrent/Semaphore;->release()V

    .line 174
    .line 175
    .line 176
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 177
    .line 178
    return-object p0

    .line 179
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 180
    .line 181
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 182
    .line 183
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 184
    .line 185
    .line 186
    throw p0
.end method
