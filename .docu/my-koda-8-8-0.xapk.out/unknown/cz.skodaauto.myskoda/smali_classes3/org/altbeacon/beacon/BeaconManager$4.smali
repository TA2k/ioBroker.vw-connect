.class Lorg/altbeacon/beacon/BeaconManager$4;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lorg/altbeacon/beacon/BeaconConsumer;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lorg/altbeacon/beacon/BeaconManager;->autoBind()V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic this$0:Lorg/altbeacon/beacon/BeaconManager;


# direct methods
.method public constructor <init>(Lorg/altbeacon/beacon/BeaconManager;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/BeaconManager$4;->this$0:Lorg/altbeacon/beacon/BeaconManager;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public bindService(Landroid/content/Intent;Landroid/content/ServiceConnection;I)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager$4;->this$0:Lorg/altbeacon/beacon/BeaconManager;

    .line 2
    .line 3
    invoke-static {p0}, Lorg/altbeacon/beacon/BeaconManager;->d(Lorg/altbeacon/beacon/BeaconManager;)Landroid/content/Context;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-virtual {p0, p1, p2, p3}, Landroid/content/Context;->bindService(Landroid/content/Intent;Landroid/content/ServiceConnection;I)Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method

.method public getApplicationContext()Landroid/content/Context;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager$4;->this$0:Lorg/altbeacon/beacon/BeaconManager;

    .line 2
    .line 3
    invoke-static {p0}, Lorg/altbeacon/beacon/BeaconManager;->d(Lorg/altbeacon/beacon/BeaconManager;)Landroid/content/Context;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public onBeaconServiceConnect()V
    .locals 5

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager$4;->this$0:Lorg/altbeacon/beacon/BeaconManager;

    .line 2
    .line 3
    invoke-static {v0}, Lorg/altbeacon/beacon/BeaconManager;->k(Lorg/altbeacon/beacon/BeaconManager;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    const-string p0, "BeaconManager"

    .line 10
    .line 11
    const-string v0, "Method invocation will be ignored -- no BLE."

    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    new-array v1, v1, [Ljava/lang/Object;

    .line 15
    .line 16
    invoke-static {p0, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    return-void

    .line 20
    :cond_0
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager$4;->this$0:Lorg/altbeacon/beacon/BeaconManager;

    .line 21
    .line 22
    invoke-static {v0}, Lorg/altbeacon/beacon/BeaconManager;->b(Lorg/altbeacon/beacon/BeaconManager;)Ljava/util/Set;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    monitor-enter v0

    .line 27
    :try_start_0
    iget-object v1, p0, Lorg/altbeacon/beacon/BeaconManager$4;->this$0:Lorg/altbeacon/beacon/BeaconManager;

    .line 28
    .line 29
    invoke-static {v1}, Lorg/altbeacon/beacon/BeaconManager;->b(Lorg/altbeacon/beacon/BeaconManager;)Ljava/util/Set;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 38
    .line 39
    .line 40
    move-result v2

    .line 41
    if-eqz v2, :cond_1

    .line 42
    .line 43
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v2

    .line 47
    check-cast v2, Lorg/altbeacon/beacon/Region;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 48
    .line 49
    :try_start_1
    iget-object v3, p0, Lorg/altbeacon/beacon/BeaconManager$4;->this$0:Lorg/altbeacon/beacon/BeaconManager;

    .line 50
    .line 51
    invoke-virtual {v3, v2}, Lorg/altbeacon/beacon/BeaconManager;->startRangingBeaconsInRegion(Lorg/altbeacon/beacon/Region;)V
    :try_end_1
    .catch Landroid/os/RemoteException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 52
    .line 53
    .line 54
    goto :goto_0

    .line 55
    :catchall_0
    move-exception p0

    .line 56
    goto :goto_3

    .line 57
    :catch_0
    move-exception v2

    .line 58
    :try_start_2
    const-string v3, "BeaconManager"

    .line 59
    .line 60
    const-string v4, "Failed to start ranging"

    .line 61
    .line 62
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v2

    .line 66
    invoke-static {v3, v4, v2}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    goto :goto_0

    .line 70
    :cond_1
    iget-object v1, p0, Lorg/altbeacon/beacon/BeaconManager$4;->this$0:Lorg/altbeacon/beacon/BeaconManager;

    .line 71
    .line 72
    invoke-static {v1}, Lorg/altbeacon/beacon/BeaconManager;->b(Lorg/altbeacon/beacon/BeaconManager;)Ljava/util/Set;

    .line 73
    .line 74
    .line 75
    move-result-object v1

    .line 76
    invoke-interface {v1}, Ljava/util/Set;->clear()V

    .line 77
    .line 78
    .line 79
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 80
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager$4;->this$0:Lorg/altbeacon/beacon/BeaconManager;

    .line 81
    .line 82
    invoke-static {v0}, Lorg/altbeacon/beacon/BeaconManager;->a(Lorg/altbeacon/beacon/BeaconManager;)Ljava/util/Set;

    .line 83
    .line 84
    .line 85
    move-result-object v1

    .line 86
    monitor-enter v1

    .line 87
    :try_start_3
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager$4;->this$0:Lorg/altbeacon/beacon/BeaconManager;

    .line 88
    .line 89
    invoke-static {v0}, Lorg/altbeacon/beacon/BeaconManager;->a(Lorg/altbeacon/beacon/BeaconManager;)Ljava/util/Set;

    .line 90
    .line 91
    .line 92
    move-result-object v0

    .line 93
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 94
    .line 95
    .line 96
    move-result-object v0

    .line 97
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 98
    .line 99
    .line 100
    move-result v2

    .line 101
    if-eqz v2, :cond_2

    .line 102
    .line 103
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v2

    .line 107
    check-cast v2, Lorg/altbeacon/beacon/Region;
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 108
    .line 109
    :try_start_4
    iget-object v3, p0, Lorg/altbeacon/beacon/BeaconManager$4;->this$0:Lorg/altbeacon/beacon/BeaconManager;

    .line 110
    .line 111
    invoke-virtual {v3, v2}, Lorg/altbeacon/beacon/BeaconManager;->startMonitoringBeaconsInRegion(Lorg/altbeacon/beacon/Region;)V
    :try_end_4
    .catch Landroid/os/RemoteException; {:try_start_4 .. :try_end_4} :catch_1
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 112
    .line 113
    .line 114
    goto :goto_1

    .line 115
    :catchall_1
    move-exception p0

    .line 116
    goto :goto_2

    .line 117
    :catch_1
    move-exception v2

    .line 118
    :try_start_5
    const-string v3, "BeaconManager"

    .line 119
    .line 120
    const-string v4, "Failed to start monitoring"

    .line 121
    .line 122
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object v2

    .line 126
    invoke-static {v3, v4, v2}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 127
    .line 128
    .line 129
    goto :goto_1

    .line 130
    :cond_2
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager$4;->this$0:Lorg/altbeacon/beacon/BeaconManager;

    .line 131
    .line 132
    invoke-static {p0}, Lorg/altbeacon/beacon/BeaconManager;->a(Lorg/altbeacon/beacon/BeaconManager;)Ljava/util/Set;

    .line 133
    .line 134
    .line 135
    move-result-object p0

    .line 136
    invoke-interface {p0}, Ljava/util/Set;->clear()V

    .line 137
    .line 138
    .line 139
    monitor-exit v1

    .line 140
    return-void

    .line 141
    :goto_2
    monitor-exit v1
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 142
    throw p0

    .line 143
    :goto_3
    :try_start_6
    monitor-exit v0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 144
    throw p0
.end method

.method public unbindService(Landroid/content/ServiceConnection;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager$4;->this$0:Lorg/altbeacon/beacon/BeaconManager;

    .line 2
    .line 3
    invoke-static {p0}, Lorg/altbeacon/beacon/BeaconManager;->d(Lorg/altbeacon/beacon/BeaconManager;)Landroid/content/Context;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-virtual {p0, p1}, Landroid/content/Context;->unbindService(Landroid/content/ServiceConnection;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method
