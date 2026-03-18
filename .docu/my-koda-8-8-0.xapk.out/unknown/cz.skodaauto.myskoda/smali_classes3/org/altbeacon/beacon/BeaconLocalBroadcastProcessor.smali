.class public Lorg/altbeacon/beacon/BeaconLocalBroadcastProcessor;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final MONITOR_NOTIFICATION:Ljava/lang/String; = "org.altbeacon.beacon.monitor_notification"

.field public static final RANGE_NOTIFICATION:Ljava/lang/String; = "org.altbeacon.beacon.range_notification"

.field private static final TAG:Ljava/lang/String; = "BeaconLocalBroadcastProcessor"

.field private static mInstance:Lorg/altbeacon/beacon/BeaconLocalBroadcastProcessor;


# instance fields
.field private mContext:Landroid/content/Context;

.field registerCallCount:I


# direct methods
.method private constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 2
    iput v0, p0, Lorg/altbeacon/beacon/BeaconLocalBroadcastProcessor;->registerCallCount:I

    return-void
.end method

.method private constructor <init>(Landroid/content/Context;)V
    .locals 1

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 4
    iput v0, p0, Lorg/altbeacon/beacon/BeaconLocalBroadcastProcessor;->registerCallCount:I

    .line 5
    iput-object p1, p0, Lorg/altbeacon/beacon/BeaconLocalBroadcastProcessor;->mContext:Landroid/content/Context;

    return-void
.end method

.method public static declared-synchronized getInstance(Landroid/content/Context;)Lorg/altbeacon/beacon/BeaconLocalBroadcastProcessor;
    .locals 2

    .line 1
    const-class v0, Lorg/altbeacon/beacon/BeaconLocalBroadcastProcessor;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    sget-object v1, Lorg/altbeacon/beacon/BeaconLocalBroadcastProcessor;->mInstance:Lorg/altbeacon/beacon/BeaconLocalBroadcastProcessor;

    .line 5
    .line 6
    if-nez v1, :cond_0

    .line 7
    .line 8
    new-instance v1, Lorg/altbeacon/beacon/BeaconLocalBroadcastProcessor;

    .line 9
    .line 10
    invoke-direct {v1, p0}, Lorg/altbeacon/beacon/BeaconLocalBroadcastProcessor;-><init>(Landroid/content/Context;)V

    .line 11
    .line 12
    .line 13
    sput-object v1, Lorg/altbeacon/beacon/BeaconLocalBroadcastProcessor;->mInstance:Lorg/altbeacon/beacon/BeaconLocalBroadcastProcessor;

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :catchall_0
    move-exception p0

    .line 17
    goto :goto_1

    .line 18
    :cond_0
    :goto_0
    sget-object p0, Lorg/altbeacon/beacon/BeaconLocalBroadcastProcessor;->mInstance:Lorg/altbeacon/beacon/BeaconLocalBroadcastProcessor;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 19
    .line 20
    monitor-exit v0

    .line 21
    return-object p0

    .line 22
    :goto_1
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 23
    throw p0
.end method


# virtual methods
.method public onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .locals 0

    .line 1
    iget p0, p0, Lorg/altbeacon/beacon/BeaconLocalBroadcastProcessor;->registerCallCount:I

    .line 2
    .line 3
    if-lez p0, :cond_0

    .line 4
    .line 5
    new-instance p0, Lorg/altbeacon/beacon/IntentHandler;

    .line 6
    .line 7
    invoke-direct {p0}, Lorg/altbeacon/beacon/IntentHandler;-><init>()V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lorg/altbeacon/beacon/IntentHandler;->convertIntentsToCallbacks(Landroid/content/Context;Landroid/content/Intent;)V

    .line 11
    .line 12
    .line 13
    :cond_0
    return-void
.end method

.method public register()V
    .locals 3

    .line 1
    iget v0, p0, Lorg/altbeacon/beacon/BeaconLocalBroadcastProcessor;->registerCallCount:I

    .line 2
    .line 3
    add-int/lit8 v0, v0, 0x1

    .line 4
    .line 5
    iput v0, p0, Lorg/altbeacon/beacon/BeaconLocalBroadcastProcessor;->registerCallCount:I

    .line 6
    .line 7
    new-instance v0, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v1, "Register calls: global="

    .line 10
    .line 11
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    iget v1, p0, Lorg/altbeacon/beacon/BeaconLocalBroadcastProcessor;->registerCallCount:I

    .line 15
    .line 16
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    const/4 v1, 0x0

    .line 24
    new-array v1, v1, [Ljava/lang/Object;

    .line 25
    .line 26
    const-string v2, "BeaconLocalBroadcastProcessor"

    .line 27
    .line 28
    invoke-static {v2, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconLocalBroadcastProcessor;->unregister()V

    .line 32
    .line 33
    .line 34
    return-void
.end method

.method public unregister()V
    .locals 1

    .line 1
    iget v0, p0, Lorg/altbeacon/beacon/BeaconLocalBroadcastProcessor;->registerCallCount:I

    .line 2
    .line 3
    add-int/lit8 v0, v0, -0x1

    .line 4
    .line 5
    iput v0, p0, Lorg/altbeacon/beacon/BeaconLocalBroadcastProcessor;->registerCallCount:I

    .line 6
    .line 7
    return-void
.end method
