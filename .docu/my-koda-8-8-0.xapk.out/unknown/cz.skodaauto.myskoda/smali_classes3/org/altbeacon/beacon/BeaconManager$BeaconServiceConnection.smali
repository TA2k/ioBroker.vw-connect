.class Lorg/altbeacon/beacon/BeaconManager$BeaconServiceConnection;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/content/ServiceConnection;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lorg/altbeacon/beacon/BeaconManager;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "BeaconServiceConnection"
.end annotation


# instance fields
.field final synthetic this$0:Lorg/altbeacon/beacon/BeaconManager;


# direct methods
.method private constructor <init>(Lorg/altbeacon/beacon/BeaconManager;)V
    .locals 0

    .line 2
    iput-object p1, p0, Lorg/altbeacon/beacon/BeaconManager$BeaconServiceConnection;->this$0:Lorg/altbeacon/beacon/BeaconManager;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lorg/altbeacon/beacon/BeaconManager;I)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lorg/altbeacon/beacon/BeaconManager$BeaconServiceConnection;-><init>(Lorg/altbeacon/beacon/BeaconManager;)V

    return-void
.end method


# virtual methods
.method public onServiceConnected(Landroid/content/ComponentName;Landroid/os/IBinder;)V
    .locals 2

    .line 1
    const-string p1, "BeaconManager"

    .line 2
    .line 3
    const-string v0, "we have a connection to the service now"

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    new-array v1, v1, [Ljava/lang/Object;

    .line 7
    .line 8
    invoke-static {p1, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    iget-object p1, p0, Lorg/altbeacon/beacon/BeaconManager$BeaconServiceConnection;->this$0:Lorg/altbeacon/beacon/BeaconManager;

    .line 12
    .line 13
    invoke-static {p1}, Lorg/altbeacon/beacon/BeaconManager;->e(Lorg/altbeacon/beacon/BeaconManager;)Ljava/lang/Boolean;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    if-nez p1, :cond_0

    .line 18
    .line 19
    iget-object p1, p0, Lorg/altbeacon/beacon/BeaconManager$BeaconServiceConnection;->this$0:Lorg/altbeacon/beacon/BeaconManager;

    .line 20
    .line 21
    invoke-static {p1}, Lorg/altbeacon/beacon/BeaconManager;->f(Lorg/altbeacon/beacon/BeaconManager;)V

    .line 22
    .line 23
    .line 24
    :cond_0
    iget-object p1, p0, Lorg/altbeacon/beacon/BeaconManager$BeaconServiceConnection;->this$0:Lorg/altbeacon/beacon/BeaconManager;

    .line 25
    .line 26
    new-instance v0, Landroid/os/Messenger;

    .line 27
    .line 28
    invoke-direct {v0, p2}, Landroid/os/Messenger;-><init>(Landroid/os/IBinder;)V

    .line 29
    .line 30
    .line 31
    invoke-static {p1, v0}, Lorg/altbeacon/beacon/BeaconManager;->h(Lorg/altbeacon/beacon/BeaconManager;Landroid/os/Messenger;)V

    .line 32
    .line 33
    .line 34
    iget-object p1, p0, Lorg/altbeacon/beacon/BeaconManager$BeaconServiceConnection;->this$0:Lorg/altbeacon/beacon/BeaconManager;

    .line 35
    .line 36
    invoke-virtual {p1}, Lorg/altbeacon/beacon/BeaconManager;->applySettings()V

    .line 37
    .line 38
    .line 39
    iget-object p1, p0, Lorg/altbeacon/beacon/BeaconManager$BeaconServiceConnection;->this$0:Lorg/altbeacon/beacon/BeaconManager;

    .line 40
    .line 41
    invoke-static {p1}, Lorg/altbeacon/beacon/BeaconManager;->c(Lorg/altbeacon/beacon/BeaconManager;)Ljava/util/concurrent/ConcurrentMap;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    monitor-enter p1

    .line 46
    :try_start_0
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager$BeaconServiceConnection;->this$0:Lorg/altbeacon/beacon/BeaconManager;

    .line 47
    .line 48
    invoke-static {p0}, Lorg/altbeacon/beacon/BeaconManager;->c(Lorg/altbeacon/beacon/BeaconManager;)Ljava/util/concurrent/ConcurrentMap;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    invoke-interface {p0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    :cond_1
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 61
    .line 62
    .line 63
    move-result p2

    .line 64
    if-eqz p2, :cond_2

    .line 65
    .line 66
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p2

    .line 70
    check-cast p2, Ljava/util/Map$Entry;

    .line 71
    .line 72
    invoke-interface {p2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    check-cast v0, Lorg/altbeacon/beacon/BeaconManager$ConsumerInfo;

    .line 77
    .line 78
    iget-boolean v0, v0, Lorg/altbeacon/beacon/BeaconManager$ConsumerInfo;->isConnected:Z

    .line 79
    .line 80
    if-nez v0, :cond_1

    .line 81
    .line 82
    invoke-interface {p2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v0

    .line 86
    check-cast v0, Lorg/altbeacon/beacon/InternalBeaconConsumer;

    .line 87
    .line 88
    invoke-interface {v0}, Lorg/altbeacon/beacon/InternalBeaconConsumer;->onBeaconServiceConnect()V

    .line 89
    .line 90
    .line 91
    invoke-interface {p2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object p2

    .line 95
    check-cast p2, Lorg/altbeacon/beacon/BeaconManager$ConsumerInfo;

    .line 96
    .line 97
    const/4 v0, 0x1

    .line 98
    iput-boolean v0, p2, Lorg/altbeacon/beacon/BeaconManager$ConsumerInfo;->isConnected:Z

    .line 99
    .line 100
    goto :goto_0

    .line 101
    :catchall_0
    move-exception p0

    .line 102
    goto :goto_1

    .line 103
    :cond_2
    monitor-exit p1

    .line 104
    return-void

    .line 105
    :goto_1
    monitor-exit p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 106
    throw p0
.end method

.method public onServiceDisconnected(Landroid/content/ComponentName;)V
    .locals 2

    .line 1
    const/4 p1, 0x0

    .line 2
    new-array p1, p1, [Ljava/lang/Object;

    .line 3
    .line 4
    const-string v0, "BeaconManager"

    .line 5
    .line 6
    const-string v1, "onServiceDisconnected"

    .line 7
    .line 8
    invoke-static {v0, v1, p1}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager$BeaconServiceConnection;->this$0:Lorg/altbeacon/beacon/BeaconManager;

    .line 12
    .line 13
    const/4 p1, 0x0

    .line 14
    invoke-static {p0, p1}, Lorg/altbeacon/beacon/BeaconManager;->h(Lorg/altbeacon/beacon/BeaconManager;Landroid/os/Messenger;)V

    .line 15
    .line 16
    .line 17
    return-void
.end method
