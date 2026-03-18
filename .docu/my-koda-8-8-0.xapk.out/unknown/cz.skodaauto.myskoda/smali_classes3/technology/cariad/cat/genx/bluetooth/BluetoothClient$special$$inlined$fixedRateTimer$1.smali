.class public final Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$special$$inlined$fixedRateTimer$1;
.super Ljava/util/TimerTask;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


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
        "\u0000\u0011\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003*\u0001\u0000\u0008\n\u0018\u00002\u00020\u0001J\u000f\u0010\u0003\u001a\u00020\u0002H\u0016\u00a2\u0006\u0004\u0008\u0003\u0010\u0004\u00a8\u0006\u0005"
    }
    d2 = {
        "technology/cariad/cat/genx/bluetooth/BluetoothClient$special$$inlined$fixedRateTimer$1",
        "Ljava/util/TimerTask;",
        "Llx0/b0;",
        "run",
        "()V",
        "kotlin-stdlib"
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
    iput-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$special$$inlined$fixedRateTimer$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/util/TimerTask;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public run()V
    .locals 4

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$special$$inlined$fixedRateTimer$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 2
    .line 3
    invoke-static {v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->access$getLastAdvertisementLock$p(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/util/concurrent/locks/ReentrantLock;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-interface {v0}, Ljava/util/concurrent/locks/Lock;->lock()V

    .line 8
    .line 9
    .line 10
    :try_start_0
    iget-object v1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$special$$inlined$fixedRateTimer$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 11
    .line 12
    invoke-static {v1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->access$getLastAdvertisement$p(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/time/Instant;

    .line 13
    .line 14
    .line 15
    move-result-object v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 16
    invoke-interface {v0}, Ljava/util/concurrent/locks/Lock;->unlock()V

    .line 17
    .line 18
    .line 19
    invoke-static {}, Ljava/time/Instant;->now()Ljava/time/Instant;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    const-wide/16 v2, 0x1388

    .line 24
    .line 25
    invoke-virtual {v1, v2, v3}, Ljava/time/Instant;->plusMillis(J)Ljava/time/Instant;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    invoke-virtual {v0, v2}, Ljava/time/Instant;->compareTo(Ljava/time/Instant;)I

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    if-lez v0, :cond_0

    .line 34
    .line 35
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$special$$inlined$fixedRateTimer$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 36
    .line 37
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->getGenXDispatcher()Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    new-instance v2, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$3$1;

    .line 42
    .line 43
    iget-object v3, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$special$$inlined$fixedRateTimer$1;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 44
    .line 45
    invoke-direct {v2, v3, p0, v1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$3$1;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ljava/util/TimerTask;Ljava/time/Instant;)V

    .line 46
    .line 47
    .line 48
    invoke-interface {v0, v2}, Ltechnology/cariad/cat/genx/GenXDispatcher;->dispatch(Lay0/a;)V

    .line 49
    .line 50
    .line 51
    :cond_0
    return-void

    .line 52
    :catchall_0
    move-exception p0

    .line 53
    invoke-interface {v0}, Ljava/util/concurrent/locks/Lock;->unlock()V

    .line 54
    .line 55
    .line 56
    throw p0
.end method
