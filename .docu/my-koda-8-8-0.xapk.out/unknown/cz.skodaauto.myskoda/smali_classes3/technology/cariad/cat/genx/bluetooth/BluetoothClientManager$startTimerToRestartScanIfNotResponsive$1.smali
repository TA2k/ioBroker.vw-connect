.class final Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startTimerToRestartScanIfNotResponsive$1;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->startTimerToRestartScanIfNotResponsive(Ljava/util/List;Landroid/bluetooth/le/ScanSettings;)V
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
    c = "technology.cariad.cat.genx.bluetooth.BluetoothClientManager$startTimerToRestartScanIfNotResponsive$1"
    f = "BluetoothClientManager.kt"
    l = {
        0x166
    }
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
            "Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startTimerToRestartScanIfNotResponsive$1;",
            ">;)V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startTimerToRestartScanIfNotResponsive$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 2
    .line 3
    iput-object p2, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startTimerToRestartScanIfNotResponsive$1;->$scanFilters:Ljava/util/List;

    .line 4
    .line 5
    iput-object p3, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startTimerToRestartScanIfNotResponsive$1;->$settings:Landroid/bluetooth/le/ScanSettings;

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
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startTimerToRestartScanIfNotResponsive$1;->invokeSuspend$lambda$2()Ljava/lang/String;

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
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startTimerToRestartScanIfNotResponsive$1;->invokeSuspend$lambda$1()Ljava/lang/String;

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
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startTimerToRestartScanIfNotResponsive$1;->invokeSuspend$lambda$3()Ljava/lang/String;

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
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startTimerToRestartScanIfNotResponsive$1;->invokeSuspend$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private static final invokeSuspend$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "startTimerToRestartScanIfNotResponsive(): Job started to listen to BLE ScanCallback response"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final invokeSuspend$lambda$1()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "startTimerToRestartScanIfNotResponsive(): no response to the BLE ScanCallback response after 30s"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final invokeSuspend$lambda$2()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "startTimerToRestartScanIfNotResponsive(): stopping the scan after 30 seconds of no response for the BLE ScanCallback"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final invokeSuspend$lambda$3()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "startTimerToRestartScanIfNotResponsive(): re-starting the scan after 30 seconds of no response for the BLE ScanCallback"

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
    new-instance p1, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startTimerToRestartScanIfNotResponsive$1;

    .line 2
    .line 3
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startTimerToRestartScanIfNotResponsive$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 4
    .line 5
    iget-object v1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startTimerToRestartScanIfNotResponsive$1;->$scanFilters:Ljava/util/List;

    .line 6
    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startTimerToRestartScanIfNotResponsive$1;->$settings:Landroid/bluetooth/le/ScanSettings;

    .line 8
    .line 9
    invoke-direct {p1, v0, v1, p0, p2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startTimerToRestartScanIfNotResponsive$1;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;Ljava/util/List;Landroid/bluetooth/le/ScanSettings;Lkotlin/coroutines/Continuation;)V

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

    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startTimerToRestartScanIfNotResponsive$1;->invoke(Lvy0/b0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startTimerToRestartScanIfNotResponsive$1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    move-result-object p0

    check-cast p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startTimerToRestartScanIfNotResponsive$1;

    sget-object p1, Llx0/b0;->a:Llx0/b0;

    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startTimerToRestartScanIfNotResponsive$1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startTimerToRestartScanIfNotResponsive$1;->label:I

    .line 4
    .line 5
    sget-object v4, Lt51/g;->a:Lt51/g;

    .line 6
    .line 7
    const/4 v9, 0x1

    .line 8
    const-string v10, "getName(...)"

    .line 9
    .line 10
    if-eqz v1, :cond_1

    .line 11
    .line 12
    if-ne v1, v9, :cond_0

    .line 13
    .line 14
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 19
    .line 20
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 21
    .line 22
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    throw p0

    .line 26
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    iget-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startTimerToRestartScanIfNotResponsive$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 30
    .line 31
    new-instance v5, Ltechnology/cariad/cat/genx/bluetooth/m;

    .line 32
    .line 33
    const/16 v1, 0x8

    .line 34
    .line 35
    invoke-direct {v5, v1}, Ltechnology/cariad/cat/genx/bluetooth/m;-><init>(I)V

    .line 36
    .line 37
    .line 38
    new-instance v2, Lt51/j;

    .line 39
    .line 40
    invoke-static {p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object v7

    .line 44
    invoke-static {v10}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v8

    .line 48
    const-string v3, "GenX"

    .line 49
    .line 50
    const/4 v6, 0x0

    .line 51
    invoke-direct/range {v2 .. v8}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    invoke-static {v2}, Lt51/a;->a(Lt51/j;)V

    .line 55
    .line 56
    .line 57
    sget p1, Lmy0/c;->g:I

    .line 58
    .line 59
    const/16 p1, 0x1e

    .line 60
    .line 61
    sget-object v1, Lmy0/e;->h:Lmy0/e;

    .line 62
    .line 63
    invoke-static {p1, v1}, Lmy0/h;->s(ILmy0/e;)J

    .line 64
    .line 65
    .line 66
    move-result-wide v1

    .line 67
    iput v9, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startTimerToRestartScanIfNotResponsive$1;->label:I

    .line 68
    .line 69
    invoke-static {v1, v2, p0}, Lvy0/e0;->q(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    if-ne p1, v0, :cond_2

    .line 74
    .line 75
    return-object v0

    .line 76
    :cond_2
    :goto_0
    iget-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startTimerToRestartScanIfNotResponsive$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 77
    .line 78
    new-instance v5, Ltechnology/cariad/cat/genx/bluetooth/m;

    .line 79
    .line 80
    const/16 v0, 0x9

    .line 81
    .line 82
    invoke-direct {v5, v0}, Ltechnology/cariad/cat/genx/bluetooth/m;-><init>(I)V

    .line 83
    .line 84
    .line 85
    new-instance v2, Lt51/j;

    .line 86
    .line 87
    invoke-static {p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object v7

    .line 91
    invoke-static {v10}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object v8

    .line 95
    const-string v3, "GenX"

    .line 96
    .line 97
    const/4 v6, 0x0

    .line 98
    invoke-direct/range {v2 .. v8}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    invoke-static {v2}, Lt51/a;->a(Lt51/j;)V

    .line 102
    .line 103
    .line 104
    iget-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startTimerToRestartScanIfNotResponsive$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 105
    .line 106
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->getContext()Landroid/content/Context;

    .line 107
    .line 108
    .line 109
    move-result-object p1

    .line 110
    invoke-static {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothKt;->getBluetoothAdapter(Landroid/content/Context;)Landroid/bluetooth/BluetoothAdapter;

    .line 111
    .line 112
    .line 113
    move-result-object p1

    .line 114
    if-eqz p1, :cond_3

    .line 115
    .line 116
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothAdapter;->getBluetoothLeScanner()Landroid/bluetooth/le/BluetoothLeScanner;

    .line 117
    .line 118
    .line 119
    move-result-object p1

    .line 120
    if-eqz p1, :cond_3

    .line 121
    .line 122
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startTimerToRestartScanIfNotResponsive$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 123
    .line 124
    invoke-static {v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->access$getScanCallback$p(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)Landroid/bluetooth/le/ScanCallback;

    .line 125
    .line 126
    .line 127
    move-result-object v0

    .line 128
    invoke-virtual {p1, v0}, Landroid/bluetooth/le/BluetoothLeScanner;->stopScan(Landroid/bluetooth/le/ScanCallback;)V

    .line 129
    .line 130
    .line 131
    :cond_3
    iget-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startTimerToRestartScanIfNotResponsive$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 132
    .line 133
    new-instance v5, Ltechnology/cariad/cat/genx/bluetooth/m;

    .line 134
    .line 135
    const/16 v0, 0xa

    .line 136
    .line 137
    invoke-direct {v5, v0}, Ltechnology/cariad/cat/genx/bluetooth/m;-><init>(I)V

    .line 138
    .line 139
    .line 140
    new-instance v2, Lt51/j;

    .line 141
    .line 142
    invoke-static {p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 143
    .line 144
    .line 145
    move-result-object v7

    .line 146
    invoke-static {v10}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 147
    .line 148
    .line 149
    move-result-object v8

    .line 150
    const-string v3, "GenX"

    .line 151
    .line 152
    const/4 v6, 0x0

    .line 153
    invoke-direct/range {v2 .. v8}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 154
    .line 155
    .line 156
    invoke-static {v2}, Lt51/a;->a(Lt51/j;)V

    .line 157
    .line 158
    .line 159
    iget-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startTimerToRestartScanIfNotResponsive$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 160
    .line 161
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->getContext()Landroid/content/Context;

    .line 162
    .line 163
    .line 164
    move-result-object p1

    .line 165
    invoke-static {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothKt;->getBluetoothAdapter(Landroid/content/Context;)Landroid/bluetooth/BluetoothAdapter;

    .line 166
    .line 167
    .line 168
    move-result-object p1

    .line 169
    if-eqz p1, :cond_4

    .line 170
    .line 171
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothAdapter;->getBluetoothLeScanner()Landroid/bluetooth/le/BluetoothLeScanner;

    .line 172
    .line 173
    .line 174
    move-result-object p1

    .line 175
    if-eqz p1, :cond_4

    .line 176
    .line 177
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startTimerToRestartScanIfNotResponsive$1;->$scanFilters:Ljava/util/List;

    .line 178
    .line 179
    iget-object v1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startTimerToRestartScanIfNotResponsive$1;->$settings:Landroid/bluetooth/le/ScanSettings;

    .line 180
    .line 181
    iget-object v2, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startTimerToRestartScanIfNotResponsive$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 182
    .line 183
    invoke-static {v2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->access$getScanCallback$p(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)Landroid/bluetooth/le/ScanCallback;

    .line 184
    .line 185
    .line 186
    move-result-object v2

    .line 187
    invoke-virtual {p1, v0, v1, v2}, Landroid/bluetooth/le/BluetoothLeScanner;->startScan(Ljava/util/List;Landroid/bluetooth/le/ScanSettings;Landroid/bluetooth/le/ScanCallback;)V

    .line 188
    .line 189
    .line 190
    :cond_4
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startTimerToRestartScanIfNotResponsive$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 191
    .line 192
    new-instance v5, Ltechnology/cariad/cat/genx/bluetooth/m;

    .line 193
    .line 194
    const/16 p1, 0xb

    .line 195
    .line 196
    invoke-direct {v5, p1}, Ltechnology/cariad/cat/genx/bluetooth/m;-><init>(I)V

    .line 197
    .line 198
    .line 199
    new-instance v2, Lt51/j;

    .line 200
    .line 201
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 202
    .line 203
    .line 204
    move-result-object v7

    .line 205
    invoke-static {v10}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 206
    .line 207
    .line 208
    move-result-object v8

    .line 209
    const-string v3, "GenX"

    .line 210
    .line 211
    const/4 v6, 0x0

    .line 212
    invoke-direct/range {v2 .. v8}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 213
    .line 214
    .line 215
    invoke-static {v2}, Lt51/a;->a(Lt51/j;)V

    .line 216
    .line 217
    .line 218
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 219
    .line 220
    return-object p0
.end method
