.class final Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$3$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;-><init>(Landroid/content/Context;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;Ltechnology/cariad/cat/genx/GenXDispatcher;Ltechnology/cariad/cat/genx/Antenna;Ljava/util/UUID;Landroid/bluetooth/BluetoothDevice;II)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lay0/a;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    k = 0x3
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field final synthetic $lastAdvertisement:Ljava/time/Instant;

.field final synthetic $this_fixedRateTimer:Ljava/util/TimerTask;

.field final synthetic this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ljava/util/TimerTask;Ljava/time/Instant;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$3$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 2
    .line 3
    iput-object p2, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$3$1;->$this_fixedRateTimer:Ljava/util/TimerTask;

    .line 4
    .line 5
    iput-object p3, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$3$1;->$lastAdvertisement:Ljava/time/Instant;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public bridge synthetic invoke()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$3$1;->invoke()V

    sget-object p0, Llx0/b0;->a:Llx0/b0;

    return-object p0
.end method

.method public final invoke()V
    .locals 8

    .line 2
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$3$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->getDelegate()Ltechnology/cariad/cat/genx/ClientDelegate;

    move-result-object v0

    if-nez v0, :cond_0

    .line 3
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$3$1;->$this_fixedRateTimer:Ljava/util/TimerTask;

    new-instance v1, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$3$1$1;

    iget-object v2, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$3$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    invoke-direct {v1, v2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$3$1$1;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)V

    const/4 v2, 0x0

    .line 4
    const-string v3, "GenX"

    invoke-static {v0, v3, v2, v1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 5
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$3$1;->$this_fixedRateTimer:Ljava/util/TimerTask;

    invoke-virtual {p0}, Ljava/util/TimerTask;->cancel()Z

    return-void

    .line 6
    :cond_0
    invoke-interface {v0}, Ltechnology/cariad/cat/genx/ClientDelegate;->shouldClientBeRemovedAfterAdvertisementStopped()Z

    move-result v0

    if-eqz v0, :cond_1

    .line 7
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$3$1;->$this_fixedRateTimer:Ljava/util/TimerTask;

    new-instance v4, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$3$1$2;

    iget-object v1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$3$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    iget-object v2, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$3$1;->$lastAdvertisement:Ljava/time/Instant;

    invoke-direct {v4, v1, v2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$3$1$2;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ljava/time/Instant;)V

    .line 8
    new-instance v1, Lt51/j;

    .line 9
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v6

    .line 10
    const-string v0, "getName(...)"

    .line 11
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v7

    .line 12
    const-string v2, "GenX"

    sget-object v3, Lt51/g;->a:Lt51/g;

    const/4 v5, 0x0

    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 13
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 14
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$3$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->getClientManager()Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    move-result-object v0

    iget-object v1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$3$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    invoke-virtual {v0, v1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->deviceShouldBeRemovedAfterAdvertisementStopped$genx_release(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)V

    .line 15
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$3$1;->$this_fixedRateTimer:Ljava/util/TimerTask;

    invoke-virtual {p0}, Ljava/util/TimerTask;->cancel()Z

    :cond_1
    return-void
.end method
