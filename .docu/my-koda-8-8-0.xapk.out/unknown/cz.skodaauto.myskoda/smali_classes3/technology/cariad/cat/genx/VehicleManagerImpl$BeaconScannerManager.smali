.class public final Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/genx/VehicleManagerImpl;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x11
    name = "BeaconScannerManager"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000T\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\"\n\u0002\u0018\u0002\n\u0002\u0008\u0007\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u000b\n\u0002\u0008\u0007\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0008\u0080\u0004\u0018\u00002\u00020\u0001B\u0011\u0008\u0000\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u00a2\u0006\u0004\u0008\u0004\u0010\u0005J\u000f\u0010\u0007\u001a\u00020\u0006H\u0002\u00a2\u0006\u0004\u0008\u0007\u0010\u0008J\u001d\u0010\u000c\u001a\u00020\u00062\u000c\u0010\u000b\u001a\u0008\u0012\u0004\u0012\u00020\n0\tH\u0002\u00a2\u0006\u0004\u0008\u000c\u0010\rJ\u0010\u0010\u000e\u001a\u00020\u0006H\u0082@\u00a2\u0006\u0004\u0008\u000e\u0010\u000fJ\u000f\u0010\u0011\u001a\u00020\u0006H\u0000\u00a2\u0006\u0004\u0008\u0010\u0010\u0008J\u001b\u0010\u0016\u001a\u000e\u0012\n\u0012\u0008\u0012\u0004\u0012\u00020\u00060\u00130\u0012H\u0000\u00a2\u0006\u0004\u0008\u0014\u0010\u0015J\u0017\u0010\u001b\u001a\u00020\u00062\u0006\u0010\u0018\u001a\u00020\u0017H\u0000\u00a2\u0006\u0004\u0008\u0019\u0010\u001aJ\u000f\u0010\u001d\u001a\u00020\u0006H\u0000\u00a2\u0006\u0004\u0008\u001c\u0010\u0008R\u0014\u0010\u0003\u001a\u00020\u00028\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0003\u0010\u001eR\u0018\u0010 \u001a\u0004\u0018\u00010\u001f8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008 \u0010!R\u0018\u0010#\u001a\u0004\u0018\u00010\"8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008#\u0010$R\u001a\u0010\'\u001a\u0008\u0012\u0004\u0012\u00020&0%8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\'\u0010(\u00a8\u0006)"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;",
        "",
        "Lt41/o;",
        "beaconScanner",
        "<init>",
        "(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Lt41/o;)V",
        "Llx0/b0;",
        "resetScanningState",
        "()V",
        "",
        "Lt41/g;",
        "proximities",
        "onBeaconsUpdated",
        "(Ljava/util/Set;)V",
        "fetchScannerTokenIfInvalid",
        "(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "reloadBeacons$genx_release",
        "reloadBeacons",
        "Lvy0/h0;",
        "Llx0/o;",
        "startScanning$genx_release",
        "()Lvy0/h0;",
        "startScanning",
        "",
        "noVehicleRegistered",
        "stopScanning$genx_release",
        "(Z)V",
        "stopScanning",
        "close$genx_release",
        "close",
        "Lt41/o;",
        "Lvy0/i1;",
        "beaconProximityCollectJob",
        "Lvy0/i1;",
        "Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;",
        "beaconScannerToken",
        "Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;",
        "Ljava/util/concurrent/CopyOnWriteArraySet;",
        "Lt41/b;",
        "foundBeacons",
        "Ljava/util/concurrent/CopyOnWriteArraySet;",
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
.field private beaconProximityCollectJob:Lvy0/i1;

.field private final beaconScanner:Lt41/o;

.field private beaconScannerToken:Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;

.field private final foundBeacons:Ljava/util/concurrent/CopyOnWriteArraySet;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/CopyOnWriteArraySet<",
            "Lt41/b;",
            ">;"
        }
    .end annotation
.end field

.field final synthetic this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Lt41/o;)V
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lt41/o;",
            ")V"
        }
    .end annotation

    .line 1
    const-string v0, "beaconScanner"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 7
    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 9
    .line 10
    .line 11
    iput-object p2, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->beaconScanner:Lt41/o;

    .line 12
    .line 13
    new-instance v0, Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 14
    .line 15
    invoke-direct {v0}, Ljava/util/concurrent/CopyOnWriteArraySet;-><init>()V

    .line 16
    .line 17
    .line 18
    iput-object v0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->foundBeacons:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 19
    .line 20
    check-cast p2, Lt41/z;

    .line 21
    .line 22
    iget-object p2, p2, Lt41/z;->h:Lyy0/l1;

    .line 23
    .line 24
    new-instance v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$1;

    .line 25
    .line 26
    const/4 v1, 0x0

    .line 27
    invoke-direct {v0, p0, v1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$1;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;Lkotlin/coroutines/Continuation;)V

    .line 28
    .line 29
    .line 30
    new-instance v1, Lne0/n;

    .line 31
    .line 32
    const/4 v2, 0x5

    .line 33
    invoke-direct {v1, p2, v0, v2}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 34
    .line 35
    .line 36
    invoke-static {v1, p1}, Lyy0/u;->B(Lyy0/i;Lvy0/b0;)Lvy0/x1;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    iput-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->beaconProximityCollectJob:Lvy0/i1;

    .line 41
    .line 42
    return-void
.end method

.method public static synthetic a(Ljava/util/Set;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->onBeaconsUpdated$lambda$0(Ljava/util/Set;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static final synthetic access$fetchScannerTokenIfInvalid(Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->fetchScannerTokenIfInvalid(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static final synthetic access$getBeaconScanner$p(Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;)Lt41/o;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->beaconScanner:Lt41/o;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$onBeaconsUpdated(Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;Ljava/util/Set;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->onBeaconsUpdated(Ljava/util/Set;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static final synthetic access$resetScanningState(Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->resetScanningState()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic b()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->fetchScannerTokenIfInvalid$lambda$0()Ljava/lang/String;

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
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->fetchScannerTokenIfInvalid$lambda$2$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private static final close$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "close()"

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic d()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->reloadBeacons$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic e(Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->fetchScannerTokenIfInvalid$lambda$1$0(Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic f()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->resetScanningState$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private final fetchScannerTokenIfInvalid(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 12
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Llx0/b0;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 1
    instance-of v0, p1, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$fetchScannerTokenIfInvalid$1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$fetchScannerTokenIfInvalid$1;

    .line 7
    .line 8
    iget v1, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$fetchScannerTokenIfInvalid$1;->label:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$fetchScannerTokenIfInvalid$1;->label:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$fetchScannerTokenIfInvalid$1;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$fetchScannerTokenIfInvalid$1;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$fetchScannerTokenIfInvalid$1;->result:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$fetchScannerTokenIfInvalid$1;->label:I

    .line 30
    .line 31
    const-string v3, "getName(...)"

    .line 32
    .line 33
    const/4 v4, 0x1

    .line 34
    if-eqz v2, :cond_2

    .line 35
    .line 36
    if-ne v2, v4, :cond_1

    .line 37
    .line 38
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    check-cast p1, Llx0/o;

    .line 42
    .line 43
    iget-object p1, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 47
    .line 48
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 49
    .line 50
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    iget-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->beaconScannerToken:Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;

    .line 58
    .line 59
    if-eqz p1, :cond_3

    .line 60
    .line 61
    invoke-interface {p1}, Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;->isValid()Z

    .line 62
    .line 63
    .line 64
    move-result p1

    .line 65
    if-ne p1, v4, :cond_3

    .line 66
    .line 67
    goto :goto_2

    .line 68
    :cond_3
    new-instance v8, Ltechnology/cariad/cat/genx/o0;

    .line 69
    .line 70
    const/16 p1, 0xb

    .line 71
    .line 72
    invoke-direct {v8, p1}, Ltechnology/cariad/cat/genx/o0;-><init>(I)V

    .line 73
    .line 74
    .line 75
    new-instance v5, Lt51/j;

    .line 76
    .line 77
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object v10

    .line 81
    invoke-static {v3}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object v11

    .line 85
    const-string v6, "GenX"

    .line 86
    .line 87
    sget-object v7, Lt51/f;->a:Lt51/f;

    .line 88
    .line 89
    const/4 v9, 0x0

    .line 90
    invoke-direct/range {v5 .. v11}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    invoke-static {v5}, Lt51/a;->a(Lt51/j;)V

    .line 94
    .line 95
    .line 96
    iget-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 97
    .line 98
    iput v4, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$fetchScannerTokenIfInvalid$1;->label:I

    .line 99
    .line 100
    invoke-virtual {p1, v0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->startScanningForClients-IoAF18A(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object p1

    .line 104
    if-ne p1, v1, :cond_4

    .line 105
    .line 106
    return-object v1

    .line 107
    :cond_4
    :goto_1
    invoke-static {p1}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 108
    .line 109
    .line 110
    move-result-object v8

    .line 111
    if-nez v8, :cond_5

    .line 112
    .line 113
    check-cast p1, Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;

    .line 114
    .line 115
    new-instance v7, Ltechnology/cariad/cat/genx/t0;

    .line 116
    .line 117
    const/4 v0, 0x6

    .line 118
    invoke-direct {v7, p1, v0}, Ltechnology/cariad/cat/genx/t0;-><init>(Ljava/lang/Object;I)V

    .line 119
    .line 120
    .line 121
    new-instance v4, Lt51/j;

    .line 122
    .line 123
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 124
    .line 125
    .line 126
    move-result-object v9

    .line 127
    invoke-static {v3}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 128
    .line 129
    .line 130
    move-result-object v10

    .line 131
    const-string v5, "GenX"

    .line 132
    .line 133
    sget-object v6, Lt51/g;->a:Lt51/g;

    .line 134
    .line 135
    const/4 v8, 0x0

    .line 136
    invoke-direct/range {v4 .. v10}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    invoke-static {v4}, Lt51/a;->a(Lt51/j;)V

    .line 140
    .line 141
    .line 142
    iput-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->beaconScannerToken:Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;

    .line 143
    .line 144
    goto :goto_2

    .line 145
    :cond_5
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->resetScanningState()V

    .line 146
    .line 147
    .line 148
    new-instance v7, Ltechnology/cariad/cat/genx/o0;

    .line 149
    .line 150
    const/16 p1, 0xc

    .line 151
    .line 152
    invoke-direct {v7, p1}, Ltechnology/cariad/cat/genx/o0;-><init>(I)V

    .line 153
    .line 154
    .line 155
    new-instance v4, Lt51/j;

    .line 156
    .line 157
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 158
    .line 159
    .line 160
    move-result-object v9

    .line 161
    invoke-static {v3}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 162
    .line 163
    .line 164
    move-result-object v10

    .line 165
    const-string v5, "GenX"

    .line 166
    .line 167
    sget-object v6, Lt51/e;->a:Lt51/e;

    .line 168
    .line 169
    invoke-direct/range {v4 .. v10}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 170
    .line 171
    .line 172
    invoke-static {v4}, Lt51/a;->a(Lt51/j;)V

    .line 173
    .line 174
    .line 175
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 176
    .line 177
    return-object p0
.end method

.method private static final fetchScannerTokenIfInvalid$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "updateFoundBeacons(): Start scanning"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final fetchScannerTokenIfInvalid$lambda$1$0(Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "updateFoundBeacons(): Received scanning token = "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method private static final fetchScannerTokenIfInvalid$lambda$2$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "updateFoundBeacons(): Failed to start scanning."

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic g()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->close$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private final onBeaconsUpdated(Ljava/util/Set;)V
    .locals 7
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Set<",
            "+",
            "Lt41/g;",
            ">;)V"
        }
    .end annotation

    .line 1
    new-instance v3, Ltechnology/cariad/cat/genx/m;

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    invoke-direct {v3, v0, p1}, Ltechnology/cariad/cat/genx/m;-><init>(ILjava/util/Set;)V

    .line 5
    .line 6
    .line 7
    new-instance v0, Lt51/j;

    .line 8
    .line 9
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v5

    .line 13
    const-string v1, "getName(...)"

    .line 14
    .line 15
    invoke-static {v1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v6

    .line 19
    const-string v1, "GenX"

    .line 20
    .line 21
    sget-object v2, Lt51/f;->a:Lt51/f;

    .line 22
    .line 23
    const/4 v4, 0x0

    .line 24
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 28
    .line 29
    .line 30
    check-cast p1, Ljava/lang/Iterable;

    .line 31
    .line 32
    new-instance v0, Ljava/util/ArrayList;

    .line 33
    .line 34
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 35
    .line 36
    .line 37
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    :cond_0
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 42
    .line 43
    .line 44
    move-result v1

    .line 45
    if-eqz v1, :cond_2

    .line 46
    .line 47
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    move-object v2, v1

    .line 52
    check-cast v2, Lt41/g;

    .line 53
    .line 54
    instance-of v3, v2, Lt41/d;

    .line 55
    .line 56
    if-nez v3, :cond_1

    .line 57
    .line 58
    instance-of v2, v2, Lt41/e;

    .line 59
    .line 60
    if-eqz v2, :cond_0

    .line 61
    .line 62
    :cond_1
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_2
    new-instance p1, Ljava/util/ArrayList;

    .line 67
    .line 68
    const/16 v1, 0xa

    .line 69
    .line 70
    invoke-static {v0, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 71
    .line 72
    .line 73
    move-result v1

    .line 74
    invoke-direct {p1, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 75
    .line 76
    .line 77
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 78
    .line 79
    .line 80
    move-result-object v1

    .line 81
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 82
    .line 83
    .line 84
    move-result v2

    .line 85
    if-eqz v2, :cond_3

    .line 86
    .line 87
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v2

    .line 91
    check-cast v2, Lt41/g;

    .line 92
    .line 93
    invoke-virtual {v2}, Lt41/g;->a()Lt41/b;

    .line 94
    .line 95
    .line 96
    move-result-object v2

    .line 97
    invoke-virtual {p1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    goto :goto_1

    .line 101
    :cond_3
    iget-object v1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->foundBeacons:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 102
    .line 103
    invoke-virtual {v1}, Ljava/util/concurrent/CopyOnWriteArraySet;->clear()V

    .line 104
    .line 105
    .line 106
    iget-object v1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->foundBeacons:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 107
    .line 108
    invoke-virtual {v1, p1}, Ljava/util/concurrent/CopyOnWriteArraySet;->addAll(Ljava/util/Collection;)Z

    .line 109
    .line 110
    .line 111
    iget-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->foundBeacons:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 112
    .line 113
    invoke-interface {p1}, Ljava/util/Collection;->isEmpty()Z

    .line 114
    .line 115
    .line 116
    move-result p1

    .line 117
    if-nez p1, :cond_4

    .line 118
    .line 119
    iget-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 120
    .line 121
    new-instance v1, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$onBeaconsUpdated$2;

    .line 122
    .line 123
    const/4 v2, 0x0

    .line 124
    invoke-direct {v1, p0, v2}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$onBeaconsUpdated$2;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;Lkotlin/coroutines/Continuation;)V

    .line 125
    .line 126
    .line 127
    const/4 v3, 0x3

    .line 128
    invoke-static {p1, v2, v2, v1, v3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 129
    .line 130
    .line 131
    :cond_4
    iget-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 132
    .line 133
    invoke-static {p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->access$getVehiclesLock$p(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Ljava/util/concurrent/locks/ReentrantLock;

    .line 134
    .line 135
    .line 136
    move-result-object p1

    .line 137
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 138
    .line 139
    invoke-interface {p1}, Ljava/util/concurrent/locks/Lock;->lock()V

    .line 140
    .line 141
    .line 142
    :try_start_0
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->access$getVehicles$p(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Ljava/util/Map;

    .line 143
    .line 144
    .line 145
    move-result-object p0

    .line 146
    invoke-interface {p0}, Ljava/util/Map;->values()Ljava/util/Collection;

    .line 147
    .line 148
    .line 149
    move-result-object p0

    .line 150
    check-cast p0, Ljava/lang/Iterable;

    .line 151
    .line 152
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 153
    .line 154
    .line 155
    move-result-object p0

    .line 156
    :cond_5
    :goto_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 157
    .line 158
    .line 159
    move-result v1

    .line 160
    if-eqz v1, :cond_7

    .line 161
    .line 162
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    move-result-object v1

    .line 166
    check-cast v1, Ltechnology/cariad/cat/genx/InternalVehicle;

    .line 167
    .line 168
    invoke-interface {v1}, Ltechnology/cariad/cat/genx/InternalVehicle;->getInnerAntenna()Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Inner;

    .line 169
    .line 170
    .line 171
    move-result-object v2

    .line 172
    if-eqz v2, :cond_6

    .line 173
    .line 174
    invoke-static {v0}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 175
    .line 176
    .line 177
    move-result-object v3

    .line 178
    invoke-interface {v2, v3}, Ltechnology/cariad/cat/genx/InternalVehicleAntenna;->updateBeaconProximities(Ljava/util/Set;)V

    .line 179
    .line 180
    .line 181
    goto :goto_3

    .line 182
    :catchall_0
    move-exception v0

    .line 183
    move-object p0, v0

    .line 184
    goto :goto_4

    .line 185
    :cond_6
    :goto_3
    invoke-interface {v1}, Ltechnology/cariad/cat/genx/InternalVehicle;->getOuterAntenna()Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Outer;

    .line 186
    .line 187
    .line 188
    move-result-object v1

    .line 189
    if-eqz v1, :cond_5

    .line 190
    .line 191
    invoke-static {v0}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 192
    .line 193
    .line 194
    move-result-object v2

    .line 195
    invoke-interface {v1, v2}, Ltechnology/cariad/cat/genx/InternalVehicleAntenna;->updateBeaconProximities(Ljava/util/Set;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 196
    .line 197
    .line 198
    goto :goto_2

    .line 199
    :cond_7
    invoke-interface {p1}, Ljava/util/concurrent/locks/Lock;->unlock()V

    .line 200
    .line 201
    .line 202
    return-void

    .line 203
    :goto_4
    invoke-interface {p1}, Ljava/util/concurrent/locks/Lock;->unlock()V

    .line 204
    .line 205
    .line 206
    throw p0
.end method

.method private static final onBeaconsUpdated$lambda$0(Ljava/util/Set;)Ljava/lang/String;
    .locals 6

    .line 1
    move-object v0, p0

    .line 2
    check-cast v0, Ljava/lang/Iterable;

    .line 3
    .line 4
    const/4 v4, 0x0

    .line 5
    const/16 v5, 0x3f

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    const/4 v2, 0x0

    .line 9
    const/4 v3, 0x0

    .line 10
    invoke-static/range {v0 .. v5}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    const-string v0, "onBeaconsUpdated(): proximities = "

    .line 15
    .line 16
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method

.method private static final reloadBeacons$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "reloadBeacons()"

    .line 2
    .line 3
    return-object v0
.end method

.method private final resetScanningState()V
    .locals 7

    .line 1
    new-instance v3, Ltechnology/cariad/cat/genx/o0;

    .line 2
    .line 3
    const/16 v0, 0xa

    .line 4
    .line 5
    invoke-direct {v3, v0}, Ltechnology/cariad/cat/genx/o0;-><init>(I)V

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
    const-string v1, "getName(...)"

    .line 15
    .line 16
    invoke-static {v1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v6

    .line 20
    const-string v1, "GenX"

    .line 21
    .line 22
    sget-object v2, Lt51/g;->a:Lt51/g;

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
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->beaconScannerToken:Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;

    .line 32
    .line 33
    const/4 v1, 0x0

    .line 34
    if-eqz v0, :cond_1

    .line 35
    .line 36
    invoke-interface {v0}, Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;->isValid()Z

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    const/4 v2, 0x1

    .line 41
    if-ne v0, v2, :cond_1

    .line 42
    .line 43
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->beaconScannerToken:Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;

    .line 44
    .line 45
    if-eqz v0, :cond_0

    .line 46
    .line 47
    invoke-interface {v0}, Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;->close()V

    .line 48
    .line 49
    .line 50
    :cond_0
    iput-object v1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->beaconScannerToken:Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_1
    iput-object v1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->beaconScannerToken:Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;

    .line 54
    .line 55
    :goto_0
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->foundBeacons:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 56
    .line 57
    invoke-virtual {v0}, Ljava/util/concurrent/CopyOnWriteArraySet;->clear()V

    .line 58
    .line 59
    .line 60
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 61
    .line 62
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->access$getVehicles$p(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Ljava/util/Map;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    invoke-interface {p0}, Ljava/util/Map;->values()Ljava/util/Collection;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    check-cast p0, Ljava/lang/Iterable;

    .line 71
    .line 72
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    :cond_2
    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 77
    .line 78
    .line 79
    move-result v0

    .line 80
    if-eqz v0, :cond_4

    .line 81
    .line 82
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v0

    .line 86
    check-cast v0, Ltechnology/cariad/cat/genx/InternalVehicle;

    .line 87
    .line 88
    invoke-interface {v0}, Ltechnology/cariad/cat/genx/InternalVehicle;->getInnerAntenna()Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Inner;

    .line 89
    .line 90
    .line 91
    move-result-object v1

    .line 92
    sget-object v2, Lmx0/u;->d:Lmx0/u;

    .line 93
    .line 94
    if-eqz v1, :cond_3

    .line 95
    .line 96
    invoke-interface {v1, v2}, Ltechnology/cariad/cat/genx/InternalVehicleAntenna;->updateBeaconProximities(Ljava/util/Set;)V

    .line 97
    .line 98
    .line 99
    :cond_3
    invoke-interface {v0}, Ltechnology/cariad/cat/genx/InternalVehicle;->getOuterAntenna()Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Outer;

    .line 100
    .line 101
    .line 102
    move-result-object v0

    .line 103
    if-eqz v0, :cond_2

    .line 104
    .line 105
    invoke-interface {v0, v2}, Ltechnology/cariad/cat/genx/InternalVehicleAntenna;->updateBeaconProximities(Ljava/util/Set;)V

    .line 106
    .line 107
    .line 108
    goto :goto_1

    .line 109
    :cond_4
    return-void
.end method

.method private static final resetScanningState$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "resetScanningState()"

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public final close$genx_release()V
    .locals 7

    .line 1
    new-instance v3, Ltechnology/cariad/cat/genx/o0;

    .line 2
    .line 3
    const/16 v0, 0x9

    .line 4
    .line 5
    invoke-direct {v3, v0}, Ltechnology/cariad/cat/genx/o0;-><init>(I)V

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
    const-string v1, "getName(...)"

    .line 15
    .line 16
    invoke-static {v1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v6

    .line 20
    const-string v1, "GenX"

    .line 21
    .line 22
    sget-object v2, Lt51/g;->a:Lt51/g;

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
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->beaconProximityCollectJob:Lvy0/i1;

    .line 32
    .line 33
    if-eqz v0, :cond_0

    .line 34
    .line 35
    const-string v1, "close()"

    .line 36
    .line 37
    invoke-static {v1, v0}, Lvy0/e0;->k(Ljava/lang/String;Lvy0/i1;)V

    .line 38
    .line 39
    .line 40
    :cond_0
    const/4 v0, 0x0

    .line 41
    iput-object v0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->beaconProximityCollectJob:Lvy0/i1;

    .line 42
    .line 43
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->resetScanningState()V

    .line 44
    .line 45
    .line 46
    iget-object v1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->beaconScanner:Lt41/o;

    .line 47
    .line 48
    check-cast v1, Lt41/z;

    .line 49
    .line 50
    invoke-virtual {v1}, Lt41/z;->f()Z

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    if-eqz v1, :cond_1

    .line 55
    .line 56
    iget-object v1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 57
    .line 58
    invoke-static {v1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->access$getIoDispatcher$p(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Lvy0/x;

    .line 59
    .line 60
    .line 61
    move-result-object v1

    .line 62
    new-instance v2, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$close$2;

    .line 63
    .line 64
    invoke-direct {v2, p0, v0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$close$2;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;Lkotlin/coroutines/Continuation;)V

    .line 65
    .line 66
    .line 67
    invoke-static {v1, v2}, Lvy0/e0;->K(Lpx0/g;Lay0/n;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    :cond_1
    return-void
.end method

.method public final reloadBeacons$genx_release()V
    .locals 7

    .line 1
    new-instance v3, Ltechnology/cariad/cat/genx/o0;

    .line 2
    .line 3
    const/16 v0, 0xd

    .line 4
    .line 5
    invoke-direct {v3, v0}, Ltechnology/cariad/cat/genx/o0;-><init>(I)V

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
    const-string v1, "getName(...)"

    .line 15
    .line 16
    invoke-static {v1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

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
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 32
    .line 33
    new-instance v1, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$reloadBeacons$2;

    .line 34
    .line 35
    const/4 v2, 0x0

    .line 36
    invoke-direct {v1, v0, p0, v2}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$reloadBeacons$2;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;Lkotlin/coroutines/Continuation;)V

    .line 37
    .line 38
    .line 39
    const/4 p0, 0x3

    .line 40
    invoke-static {v0, v2, v2, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 41
    .line 42
    .line 43
    return-void
.end method

.method public final startScanning$genx_release()Lvy0/h0;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lvy0/h0;"
        }
    .end annotation

    .line 1
    invoke-static {}, Lvy0/e0;->b()Lvy0/r;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object v1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 6
    .line 7
    new-instance v2, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$startScanning$1;

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    invoke-direct {v2, p0, v1, v0, v3}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$startScanning$1;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;Ltechnology/cariad/cat/genx/VehicleManagerImpl;Lvy0/q;Lkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    const/4 p0, 0x3

    .line 14
    invoke-static {v1, v3, v3, v2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 15
    .line 16
    .line 17
    return-object v0
.end method

.method public final stopScanning$genx_release(Z)V
    .locals 3

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 2
    .line 3
    new-instance v1, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$stopScanning$1;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v1, p1, p0, v2}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$stopScanning$1;-><init>(ZLtechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;Lkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    const/4 p0, 0x3

    .line 10
    invoke-static {v0, v2, v2, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 11
    .line 12
    .line 13
    return-void
.end method
