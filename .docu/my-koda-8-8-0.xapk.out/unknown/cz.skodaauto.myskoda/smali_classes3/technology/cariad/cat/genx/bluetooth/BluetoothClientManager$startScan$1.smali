.class final Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startScan$1;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->startScan(Ljava/util/List;Landroid/bluetooth/le/ScanSettings;)V
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
    c = "technology.cariad.cat.genx.bluetooth.BluetoothClientManager$startScan$1"
    f = "BluetoothClientManager.kt"
    l = {}
    m = "invokeSuspend"
    v = 0x1
.end annotation


# instance fields
.field final synthetic $scanFilters:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Landroid/bluetooth/le/ScanFilter;",
            ">;"
        }
    .end annotation
.end field

.field final synthetic $settings:Landroid/bluetooth/le/ScanSettings;

.field label:I

.field final synthetic this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;Ljava/util/List;Landroid/bluetooth/le/ScanSettings;Lkotlin/coroutines/Continuation;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;",
            "Ljava/util/List<",
            "Landroid/bluetooth/le/ScanFilter;",
            ">;",
            "Landroid/bluetooth/le/ScanSettings;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startScan$1;",
            ">;)V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startScan$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 2
    .line 3
    iput-object p2, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startScan$1;->$scanFilters:Ljava/util/List;

    .line 4
    .line 5
    iput-object p3, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startScan$1;->$settings:Landroid/bluetooth/le/ScanSettings;

    .line 6
    .line 7
    const/4 p1, 0x2

    .line 8
    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public static synthetic b()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startScan$1;->invokeSuspend$lambda$2()Ljava/lang/String;

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
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startScan$1;->invokeSuspend$lambda$1()Ljava/lang/String;

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
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startScan$1;->invokeSuspend$lambda$4()Ljava/lang/String;

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
    const-string v0, "startScan(): triggering coroutine job to observe the ScanCallback response"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final invokeSuspend$lambda$2()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "startScanningForClients(): BLE has been disabled while scheduling \'startScan\'. -> Propagate state change and notify error."

    .line 2
    .line 3
    return-object v0
.end method

.method private static final invokeSuspend$lambda$4()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "startScanningForClients(): Failed to delegate the scan failure (message = \'BLE disabled while scheduling \'startScan\'\') due to missing delegate."

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2
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
    new-instance p1, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startScan$1;

    .line 2
    .line 3
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startScan$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 4
    .line 5
    iget-object v1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startScan$1;->$scanFilters:Ljava/util/List;

    .line 6
    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startScan$1;->$settings:Landroid/bluetooth/le/ScanSettings;

    .line 8
    .line 9
    invoke-direct {p1, v0, v1, p0, p2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startScan$1;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;Ljava/util/List;Landroid/bluetooth/le/ScanSettings;Lkotlin/coroutines/Continuation;)V

    .line 10
    .line 11
    .line 12
    return-object p1
.end method

.method public bridge synthetic invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lvy0/b0;

    check-cast p2, Lkotlin/coroutines/Continuation;

    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startScan$1;->invoke(Lvy0/b0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startScan$1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    move-result-object p0

    check-cast p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startScan$1;

    sget-object p1, Llx0/b0;->a:Llx0/b0;

    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startScan$1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startScan$1;->label:I

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
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startScan$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

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
    iget-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startScan$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

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
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startScan$1;->$scanFilters:Ljava/util/List;

    .line 43
    .line 44
    iget-object v1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startScan$1;->$settings:Landroid/bluetooth/le/ScanSettings;

    .line 45
    .line 46
    iget-object v2, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startScan$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 47
    .line 48
    invoke-static {v2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->access$getScanCallback$p(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)Landroid/bluetooth/le/ScanCallback;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    invoke-virtual {p1, v0, v1, v2}, Landroid/bluetooth/le/BluetoothLeScanner;->startScan(Ljava/util/List;Landroid/bluetooth/le/ScanSettings;Landroid/bluetooth/le/ScanCallback;)V

    .line 53
    .line 54
    .line 55
    goto :goto_0

    .line 56
    :catch_0
    move-exception v0

    .line 57
    move-object p1, v0

    .line 58
    goto :goto_1

    .line 59
    :cond_0
    :goto_0
    iget-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startScan$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 60
    .line 61
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startScan$1;->$scanFilters:Ljava/util/List;

    .line 62
    .line 63
    iget-object v1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startScan$1;->$settings:Landroid/bluetooth/le/ScanSettings;

    .line 64
    .line 65
    invoke-static {p1, v0, v1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->access$startTimerToRestartScanIfNotResponsive(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;Ljava/util/List;Landroid/bluetooth/le/ScanSettings;)V

    .line 66
    .line 67
    .line 68
    iget-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startScan$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 69
    .line 70
    new-instance v3, Ltechnology/cariad/cat/genx/bluetooth/m;

    .line 71
    .line 72
    const/4 v0, 0x5

    .line 73
    invoke-direct {v3, v0}, Ltechnology/cariad/cat/genx/bluetooth/m;-><init>(I)V

    .line 74
    .line 75
    .line 76
    const-string v1, "GenX"

    .line 77
    .line 78
    new-instance v0, Lt51/j;

    .line 79
    .line 80
    sget-object v2, Lt51/d;->a:Lt51/d;

    .line 81
    .line 82
    invoke-static {p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object v5

    .line 86
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 87
    .line 88
    .line 89
    move-result-object p1

    .line 90
    invoke-virtual {p1}, Ljava/lang/Thread;->getName()Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object v6

    .line 94
    const-string p1, "getName(...)"

    .line 95
    .line 96
    invoke-static {v6, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    const/4 v4, 0x0

    .line 100
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 104
    .line 105
    .line 106
    goto :goto_2

    .line 107
    :cond_1
    const-string p1, "\'Bluetooth.isBluetoothScanPermissionRequiredAndGranted(context)\' returned false. -> Missing check?"

    .line 108
    .line 109
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 110
    .line 111
    invoke-direct {v0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 112
    .line 113
    .line 114
    throw v0
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0

    .line 115
    :goto_1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startScan$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 116
    .line 117
    new-instance v1, Ltechnology/cariad/cat/genx/bluetooth/m;

    .line 118
    .line 119
    const/4 v2, 0x6

    .line 120
    invoke-direct {v1, v2}, Ltechnology/cariad/cat/genx/bluetooth/m;-><init>(I)V

    .line 121
    .line 122
    .line 123
    const-string v2, "GenX"

    .line 124
    .line 125
    invoke-static {v0, v2, p1, v1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 126
    .line 127
    .line 128
    iget-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startScan$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 129
    .line 130
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->propagateClientManagerState$genx_release()V

    .line 131
    .line 132
    .line 133
    iget-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startScan$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 134
    .line 135
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->getScanning$genx_release()Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 136
    .line 137
    .line 138
    move-result-object p1

    .line 139
    const/4 v0, 0x0

    .line 140
    invoke-virtual {p1, v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 141
    .line 142
    .line 143
    iget-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startScan$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 144
    .line 145
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->getDelegate()Ltechnology/cariad/cat/genx/ClientManagerDelegate;

    .line 146
    .line 147
    .line 148
    move-result-object p1

    .line 149
    if-eqz p1, :cond_2

    .line 150
    .line 151
    iget-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startScan$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 152
    .line 153
    sget-object v0, Ltechnology/cariad/cat/genx/CoreGenXStatus;->Companion:Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;

    .line 154
    .line 155
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getClientScanFailed()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 156
    .line 157
    .line 158
    move-result-object v0

    .line 159
    const-string v1, "BLE disabled while scheduling \'startScan\'"

    .line 160
    .line 161
    invoke-virtual {p1, v0, v1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->reportCoreGenXScanError$genx_release(Ltechnology/cariad/cat/genx/CoreGenXStatus;Ljava/lang/String;)V

    .line 162
    .line 163
    .line 164
    goto :goto_2

    .line 165
    :cond_2
    iget-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startScan$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 166
    .line 167
    new-instance v0, Ltechnology/cariad/cat/genx/bluetooth/m;

    .line 168
    .line 169
    const/4 v1, 0x7

    .line 170
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/bluetooth/m;-><init>(I)V

    .line 171
    .line 172
    .line 173
    const/4 v1, 0x0

    .line 174
    invoke-static {p1, v2, v1, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 175
    .line 176
    .line 177
    :goto_2
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startScan$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 178
    .line 179
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->access$getScanningSemaphore$p(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)Ljava/util/concurrent/Semaphore;

    .line 180
    .line 181
    .line 182
    move-result-object p0

    .line 183
    invoke-virtual {p0}, Ljava/util/concurrent/Semaphore;->release()V

    .line 184
    .line 185
    .line 186
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 187
    .line 188
    return-object p0

    .line 189
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 190
    .line 191
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 192
    .line 193
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 194
    .line 195
    .line 196
    throw p0
.end method
