.class public Lorg/altbeacon/beacon/BeaconManager;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lorg/altbeacon/beacon/BeaconManager$ConsumerInfo;,
        Lorg/altbeacon/beacon/BeaconManager$BeaconServiceConnection;,
        Lorg/altbeacon/beacon/BeaconManager$ServiceNotDeclaredException;
    }
.end annotation


# static fields
.field public static final DEFAULT_BACKGROUND_BETWEEN_SCAN_PERIOD:J = 0x493e0L

.field public static final DEFAULT_BACKGROUND_SCAN_PERIOD:J = 0x2710L

.field public static final DEFAULT_EXIT_PERIOD:J = 0x2710L

.field public static final DEFAULT_FOREGROUND_BETWEEN_SCAN_PERIOD:J = 0x0L

.field public static final DEFAULT_FOREGROUND_SCAN_PERIOD:J = 0x44cL

.field private static final SINGLETON_LOCK:Ljava/lang/Object;

.field private static final TAG:Ljava/lang/String; = "BeaconManager"

.field public static final synthetic a:I = 0x0

.field protected static beaconSimulator:Lorg/altbeacon/beacon/simulator/BeaconSimulator; = null

.field protected static distanceModelUpdateUrl:Ljava/lang/String; = null

.field protected static rssiFilterImplClass:Ljava/lang/Class; = null

.field private static sAndroidLScanningDisabled:Z = false

.field private static sExitRegionPeriod:J = 0x2710L

.field protected static volatile sInstance:Lorg/altbeacon/beacon/BeaconManager; = null

.field private static sManifestCheckingDisabled:Z = false


# instance fields
.field private autoBindConsumer:Lorg/altbeacon/beacon/BeaconConsumer;

.field private final autoBindMonitoredRegions:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Lorg/altbeacon/beacon/Region;",
            ">;"
        }
    .end annotation
.end field

.field private final autoBindRangedRegions:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Lorg/altbeacon/beacon/Region;",
            ">;"
        }
    .end annotation
.end field

.field private backgroundBetweenScanPeriod:J

.field private backgroundScanPeriod:J

.field private final beaconParsers:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lorg/altbeacon/beacon/BeaconParser;",
            ">;"
        }
    .end annotation
.end field

.field private final consumers:Ljava/util/concurrent/ConcurrentMap;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/ConcurrentMap<",
            "Lorg/altbeacon/beacon/InternalBeaconConsumer;",
            "Lorg/altbeacon/beacon/BeaconManager$ConsumerInfo;",
            ">;"
        }
    .end annotation
.end field

.field protected dataRequestNotifier:Lorg/altbeacon/beacon/RangeNotifier;

.field private foregroundBetweenScanPeriod:J

.field private foregroundScanPeriod:J

.field private mBackgroundMode:Z

.field private mBackgroundModeUninitialized:Z

.field private final mContext:Landroid/content/Context;

.field private mForegroundServiceNotification:Landroid/app/Notification;

.field private mForegroundServiceNotificationId:I

.field private mIntentScanStrategyCoordinator:Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;

.field mInternalBackgroundPowerSaver:Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;

.field private mMainProcess:Z

.field private mNonBeaconLeScanCallback:Lorg/altbeacon/beacon/service/scanner/NonBeaconLeScanCallback;

.field private mRegionStatePersistenceEnabled:Z

.field private mRegionViewModels:Ljava/util/HashMap;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/HashMap<",
            "Lorg/altbeacon/beacon/Region;",
            "Lorg/altbeacon/beacon/RegionViewModel;",
            ">;"
        }
    .end annotation
.end field

.field private mScannerInSameProcess:Ljava/lang/Boolean;

.field private mScheduledScanJobsEnabled:Z

.field private mScheduledScanJobsEnabledByFallback:Z

.field private mServiceSyncHandler:Landroid/os/Handler;

.field private mServiceSyncScheduled:Z

.field protected final monitorNotifiers:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Lorg/altbeacon/beacon/MonitorNotifier;",
            ">;"
        }
    .end annotation
.end field

.field protected final rangeNotifiers:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Lorg/altbeacon/beacon/RangeNotifier;",
            ">;"
        }
    .end annotation
.end field

.field private final rangedRegions:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Lorg/altbeacon/beacon/Region;",
            ">;"
        }
    .end annotation
.end field

.field private serviceMessenger:Landroid/os/Messenger;

.field private settings:Lorg/altbeacon/beacon/AppliedSettings;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ljava/lang/Object;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lorg/altbeacon/beacon/BeaconManager;->SINGLETON_LOCK:Ljava/lang/Object;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;)V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->consumers:Ljava/util/concurrent/ConcurrentMap;

    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    iput-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->serviceMessenger:Landroid/os/Messenger;

    .line 13
    .line 14
    new-instance v1, Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 15
    .line 16
    invoke-direct {v1}, Ljava/util/concurrent/CopyOnWriteArraySet;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object v1, p0, Lorg/altbeacon/beacon/BeaconManager;->rangeNotifiers:Ljava/util/Set;

    .line 20
    .line 21
    iput-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->dataRequestNotifier:Lorg/altbeacon/beacon/RangeNotifier;

    .line 22
    .line 23
    new-instance v1, Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 24
    .line 25
    invoke-direct {v1}, Ljava/util/concurrent/CopyOnWriteArraySet;-><init>()V

    .line 26
    .line 27
    .line 28
    iput-object v1, p0, Lorg/altbeacon/beacon/BeaconManager;->monitorNotifiers:Ljava/util/Set;

    .line 29
    .line 30
    new-instance v1, Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 31
    .line 32
    invoke-direct {v1}, Ljava/util/concurrent/CopyOnWriteArraySet;-><init>()V

    .line 33
    .line 34
    .line 35
    iput-object v1, p0, Lorg/altbeacon/beacon/BeaconManager;->rangedRegions:Ljava/util/Set;

    .line 36
    .line 37
    new-instance v1, Ljava/util/HashSet;

    .line 38
    .line 39
    invoke-direct {v1}, Ljava/util/HashSet;-><init>()V

    .line 40
    .line 41
    .line 42
    iput-object v1, p0, Lorg/altbeacon/beacon/BeaconManager;->autoBindRangedRegions:Ljava/util/Set;

    .line 43
    .line 44
    new-instance v1, Ljava/util/HashSet;

    .line 45
    .line 46
    invoke-direct {v1}, Ljava/util/HashSet;-><init>()V

    .line 47
    .line 48
    .line 49
    iput-object v1, p0, Lorg/altbeacon/beacon/BeaconManager;->autoBindMonitoredRegions:Ljava/util/Set;

    .line 50
    .line 51
    const/4 v1, 0x1

    .line 52
    iput-boolean v1, p0, Lorg/altbeacon/beacon/BeaconManager;->mRegionStatePersistenceEnabled:Z

    .line 53
    .line 54
    const/4 v2, 0x0

    .line 55
    iput-boolean v2, p0, Lorg/altbeacon/beacon/BeaconManager;->mBackgroundMode:Z

    .line 56
    .line 57
    iput-boolean v1, p0, Lorg/altbeacon/beacon/BeaconManager;->mBackgroundModeUninitialized:Z

    .line 58
    .line 59
    iput-boolean v2, p0, Lorg/altbeacon/beacon/BeaconManager;->mMainProcess:Z

    .line 60
    .line 61
    iput-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mScannerInSameProcess:Ljava/lang/Boolean;

    .line 62
    .line 63
    iput-boolean v2, p0, Lorg/altbeacon/beacon/BeaconManager;->mScheduledScanJobsEnabled:Z

    .line 64
    .line 65
    iput-boolean v2, p0, Lorg/altbeacon/beacon/BeaconManager;->mScheduledScanJobsEnabledByFallback:Z

    .line 66
    .line 67
    iput-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mIntentScanStrategyCoordinator:Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;

    .line 68
    .line 69
    iput-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mForegroundServiceNotification:Landroid/app/Notification;

    .line 70
    .line 71
    const/4 v1, -0x1

    .line 72
    iput v1, p0, Lorg/altbeacon/beacon/BeaconManager;->mForegroundServiceNotificationId:I

    .line 73
    .line 74
    new-instance v1, Landroid/os/Handler;

    .line 75
    .line 76
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 77
    .line 78
    .line 79
    move-result-object v3

    .line 80
    invoke-direct {v1, v3}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 81
    .line 82
    .line 83
    iput-object v1, p0, Lorg/altbeacon/beacon/BeaconManager;->mServiceSyncHandler:Landroid/os/Handler;

    .line 84
    .line 85
    iput-boolean v2, p0, Lorg/altbeacon/beacon/BeaconManager;->mServiceSyncScheduled:Z

    .line 86
    .line 87
    const-wide/16 v1, 0x44c

    .line 88
    .line 89
    iput-wide v1, p0, Lorg/altbeacon/beacon/BeaconManager;->foregroundScanPeriod:J

    .line 90
    .line 91
    const-wide/16 v1, 0x0

    .line 92
    .line 93
    iput-wide v1, p0, Lorg/altbeacon/beacon/BeaconManager;->foregroundBetweenScanPeriod:J

    .line 94
    .line 95
    const-wide/16 v1, 0x2710

    .line 96
    .line 97
    iput-wide v1, p0, Lorg/altbeacon/beacon/BeaconManager;->backgroundScanPeriod:J

    .line 98
    .line 99
    const-wide/32 v1, 0x493e0

    .line 100
    .line 101
    .line 102
    iput-wide v1, p0, Lorg/altbeacon/beacon/BeaconManager;->backgroundBetweenScanPeriod:J

    .line 103
    .line 104
    new-instance v1, Ljava/util/HashMap;

    .line 105
    .line 106
    invoke-direct {v1}, Ljava/util/HashMap;-><init>()V

    .line 107
    .line 108
    .line 109
    iput-object v1, p0, Lorg/altbeacon/beacon/BeaconManager;->mRegionViewModels:Ljava/util/HashMap;

    .line 110
    .line 111
    sget-object v1, Lorg/altbeacon/beacon/AppliedSettings;->Companion:Lorg/altbeacon/beacon/AppliedSettings$Companion;

    .line 112
    .line 113
    invoke-virtual {v1}, Lorg/altbeacon/beacon/AppliedSettings$Companion;->withDefaultValues()Lorg/altbeacon/beacon/AppliedSettings;

    .line 114
    .line 115
    .line 116
    move-result-object v1

    .line 117
    iput-object v1, p0, Lorg/altbeacon/beacon/BeaconManager;->settings:Lorg/altbeacon/beacon/AppliedSettings;

    .line 118
    .line 119
    iput-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->autoBindConsumer:Lorg/altbeacon/beacon/BeaconConsumer;

    .line 120
    .line 121
    iput-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mInternalBackgroundPowerSaver:Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;

    .line 122
    .line 123
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 124
    .line 125
    .line 126
    move-result-object p1

    .line 127
    iput-object p1, p0, Lorg/altbeacon/beacon/BeaconManager;->mContext:Landroid/content/Context;

    .line 128
    .line 129
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->checkIfMainProcess()V

    .line 130
    .line 131
    .line 132
    sget-boolean p1, Lorg/altbeacon/beacon/BeaconManager;->sManifestCheckingDisabled:Z

    .line 133
    .line 134
    if-nez p1, :cond_0

    .line 135
    .line 136
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->verifyServiceDeclaration()V

    .line 137
    .line 138
    .line 139
    :cond_0
    new-instance p1, Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayList;

    .line 140
    .line 141
    invoke-direct {p1}, Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayList;-><init>()V

    .line 142
    .line 143
    .line 144
    new-instance v0, Lorg/altbeacon/beacon/BeaconManager$2;

    .line 145
    .line 146
    invoke-direct {v0, p0}, Lorg/altbeacon/beacon/BeaconManager$2;-><init>(Lorg/altbeacon/beacon/BeaconManager;)V

    .line 147
    .line 148
    .line 149
    invoke-virtual {p1, v0}, Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayList;->setNotifier(Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayListNotifier;)V

    .line 150
    .line 151
    .line 152
    iput-object p1, p0, Lorg/altbeacon/beacon/BeaconManager;->beaconParsers:Ljava/util/List;

    .line 153
    .line 154
    new-instance v0, Lorg/altbeacon/beacon/AltBeaconParser;

    .line 155
    .line 156
    invoke-direct {v0}, Lorg/altbeacon/beacon/AltBeaconParser;-><init>()V

    .line 157
    .line 158
    .line 159
    invoke-interface {p1, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 160
    .line 161
    .line 162
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->setScheduledScanJobsEnabledDefault()V

    .line 163
    .line 164
    .line 165
    return-void
.end method

.method public static bridge synthetic a(Lorg/altbeacon/beacon/BeaconManager;)Ljava/util/Set;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->autoBindMonitoredRegions:Ljava/util/Set;

    .line 2
    .line 3
    return-object p0
.end method

.method private applyChangesToServices(ILorg/altbeacon/beacon/Region;)V
    .locals 9
    .annotation build Landroid/annotation/TargetApi;
        value = 0x12
    .end annotation

    .line 1
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->isAnyConsumerBound()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-nez v0, :cond_0

    .line 7
    .line 8
    const-string p0, "The BeaconManager is not bound to the service.  Call beaconManager.bind(BeaconConsumer consumer) and wait for a callback to onBeaconServiceConnect()"

    .line 9
    .line 10
    new-array p1, v1, [Ljava/lang/Object;

    .line 11
    .line 12
    const-string p2, "BeaconManager"

    .line 13
    .line 14
    invoke-static {p2, p0, p1}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->settings:Lorg/altbeacon/beacon/AppliedSettings;

    .line 19
    .line 20
    invoke-virtual {v0}, Lorg/altbeacon/beacon/AppliedSettings;->getDistanceCalculatorFactory()Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    iget-object v2, p0, Lorg/altbeacon/beacon/BeaconManager;->mContext:Landroid/content/Context;

    .line 25
    .line 26
    invoke-interface {v0, v2}, Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;->getInstance(Landroid/content/Context;)Lorg/altbeacon/beacon/distance/DistanceCalculator;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    invoke-static {v0}, Lorg/altbeacon/beacon/Beacon;->setDistanceCalculatorInternal(Lorg/altbeacon/beacon/distance/DistanceCalculator;)V

    .line 31
    .line 32
    .line 33
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mIntentScanStrategyCoordinator:Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;

    .line 34
    .line 35
    if-eqz v0, :cond_1

    .line 36
    .line 37
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->applySettings()V

    .line 38
    .line 39
    .line 40
    return-void

    .line 41
    :cond_1
    iget-boolean v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mScheduledScanJobsEnabled:Z

    .line 42
    .line 43
    if-nez v0, :cond_5

    .line 44
    .line 45
    iget-boolean v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mScheduledScanJobsEnabledByFallback:Z

    .line 46
    .line 47
    if-eqz v0, :cond_2

    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_2
    const/4 v0, 0x0

    .line 51
    invoke-static {v0, p1, v1, v1}, Landroid/os/Message;->obtain(Landroid/os/Handler;III)Landroid/os/Message;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    const/4 v1, 0x6

    .line 56
    if-ne p1, v1, :cond_3

    .line 57
    .line 58
    new-instance v2, Lorg/altbeacon/beacon/service/StartRMData;

    .line 59
    .line 60
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->getScanPeriod()J

    .line 61
    .line 62
    .line 63
    move-result-wide v3

    .line 64
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->getBetweenScanPeriod()J

    .line 65
    .line 66
    .line 67
    move-result-wide v5

    .line 68
    iget-boolean v7, p0, Lorg/altbeacon/beacon/BeaconManager;->mBackgroundMode:Z

    .line 69
    .line 70
    invoke-direct/range {v2 .. v7}, Lorg/altbeacon/beacon/service/StartRMData;-><init>(JJZ)V

    .line 71
    .line 72
    .line 73
    invoke-virtual {v2}, Lorg/altbeacon/beacon/service/StartRMData;->toBundle()Landroid/os/Bundle;

    .line 74
    .line 75
    .line 76
    move-result-object p1

    .line 77
    invoke-virtual {v0, p1}, Landroid/os/Message;->setData(Landroid/os/Bundle;)V

    .line 78
    .line 79
    .line 80
    goto :goto_0

    .line 81
    :cond_3
    const/4 v1, 0x7

    .line 82
    if-ne p1, v1, :cond_4

    .line 83
    .line 84
    new-instance p1, Lorg/altbeacon/beacon/service/SettingsData;

    .line 85
    .line 86
    invoke-direct {p1}, Lorg/altbeacon/beacon/service/SettingsData;-><init>()V

    .line 87
    .line 88
    .line 89
    iget-object p2, p0, Lorg/altbeacon/beacon/BeaconManager;->mContext:Landroid/content/Context;

    .line 90
    .line 91
    invoke-virtual {p1, p2}, Lorg/altbeacon/beacon/service/SettingsData;->collect(Landroid/content/Context;)Lorg/altbeacon/beacon/service/SettingsData;

    .line 92
    .line 93
    .line 94
    move-result-object p1

    .line 95
    invoke-virtual {p1}, Lorg/altbeacon/beacon/service/SettingsData;->toBundle()Landroid/os/Bundle;

    .line 96
    .line 97
    .line 98
    move-result-object p1

    .line 99
    invoke-virtual {v0, p1}, Landroid/os/Message;->setData(Landroid/os/Bundle;)V

    .line 100
    .line 101
    .line 102
    goto :goto_0

    .line 103
    :cond_4
    new-instance v1, Lorg/altbeacon/beacon/service/StartRMData;

    .line 104
    .line 105
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->callbackPackageName()Ljava/lang/String;

    .line 106
    .line 107
    .line 108
    move-result-object v3

    .line 109
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->getScanPeriod()J

    .line 110
    .line 111
    .line 112
    move-result-wide v4

    .line 113
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->getBetweenScanPeriod()J

    .line 114
    .line 115
    .line 116
    move-result-wide v6

    .line 117
    iget-boolean v8, p0, Lorg/altbeacon/beacon/BeaconManager;->mBackgroundMode:Z

    .line 118
    .line 119
    move-object v2, p2

    .line 120
    invoke-direct/range {v1 .. v8}, Lorg/altbeacon/beacon/service/StartRMData;-><init>(Lorg/altbeacon/beacon/Region;Ljava/lang/String;JJZ)V

    .line 121
    .line 122
    .line 123
    invoke-virtual {v1}, Lorg/altbeacon/beacon/service/StartRMData;->toBundle()Landroid/os/Bundle;

    .line 124
    .line 125
    .line 126
    move-result-object p1

    .line 127
    invoke-virtual {v0, p1}, Landroid/os/Message;->setData(Landroid/os/Bundle;)V

    .line 128
    .line 129
    .line 130
    :goto_0
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->serviceMessenger:Landroid/os/Messenger;

    .line 131
    .line 132
    invoke-virtual {p0, v0}, Landroid/os/Messenger;->send(Landroid/os/Message;)V

    .line 133
    .line 134
    .line 135
    return-void

    .line 136
    :cond_5
    :goto_1
    invoke-static {}, Lorg/altbeacon/beacon/service/ScanJobScheduler;->getInstance()Lorg/altbeacon/beacon/service/ScanJobScheduler;

    .line 137
    .line 138
    .line 139
    move-result-object p1

    .line 140
    iget-object p2, p0, Lorg/altbeacon/beacon/BeaconManager;->mContext:Landroid/content/Context;

    .line 141
    .line 142
    invoke-virtual {p1, p2, p0}, Lorg/altbeacon/beacon/service/ScanJobScheduler;->applySettingsToScheduledJob(Landroid/content/Context;Lorg/altbeacon/beacon/BeaconManager;)V

    .line 143
    .line 144
    .line 145
    return-void
.end method

.method private applySettingsChange(Lorg/altbeacon/beacon/AppliedSettings;)V
    .locals 7

    .line 1
    const-string v0, "ScanStrategy has changed. Unbinding and rebinding consumers.  Old strategry: "

    .line 2
    .line 3
    iget-object v1, p0, Lorg/altbeacon/beacon/BeaconManager;->settings:Lorg/altbeacon/beacon/AppliedSettings;

    .line 4
    .line 5
    iput-object p1, p0, Lorg/altbeacon/beacon/BeaconManager;->settings:Lorg/altbeacon/beacon/AppliedSettings;

    .line 6
    .line 7
    sget-object v2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 8
    .line 9
    invoke-virtual {p1}, Lorg/altbeacon/beacon/AppliedSettings;->getHardwareEqualityEnforced()Z

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    invoke-virtual {v2, p1}, Ljava/lang/Boolean;->equals(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result p1

    .line 21
    invoke-static {p1}, Lorg/altbeacon/beacon/Beacon;->setHardwareEqualityEnforced(Z)V

    .line 22
    .line 23
    .line 24
    iget-object p1, p0, Lorg/altbeacon/beacon/BeaconManager;->settings:Lorg/altbeacon/beacon/AppliedSettings;

    .line 25
    .line 26
    invoke-virtual {p1}, Lorg/altbeacon/beacon/AppliedSettings;->getDistanceModelUpdateUrl()Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    invoke-static {p1}, Lorg/altbeacon/beacon/BeaconManager;->setDistanceModelUpdateUrl(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    iget-object p1, p0, Lorg/altbeacon/beacon/BeaconManager;->settings:Lorg/altbeacon/beacon/AppliedSettings;

    .line 37
    .line 38
    invoke-virtual {p1}, Lorg/altbeacon/beacon/AppliedSettings;->getScanPeriods()Lorg/altbeacon/beacon/Settings$ScanPeriods;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    invoke-virtual {p1}, Lorg/altbeacon/beacon/Settings$ScanPeriods;->getBackgroundBetweenScanPeriodMillis()J

    .line 43
    .line 44
    .line 45
    move-result-wide v3

    .line 46
    const-wide/32 v5, 0xdbba0

    .line 47
    .line 48
    .line 49
    cmp-long p1, v3, v5

    .line 50
    .line 51
    const/4 v3, 0x0

    .line 52
    if-gez p1, :cond_0

    .line 53
    .line 54
    iget-object p1, p0, Lorg/altbeacon/beacon/BeaconManager;->settings:Lorg/altbeacon/beacon/AppliedSettings;

    .line 55
    .line 56
    invoke-virtual {p1}, Lorg/altbeacon/beacon/AppliedSettings;->getScanStrategy()Lorg/altbeacon/beacon/Settings$ScanStrategy;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    instance-of p1, p1, Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;

    .line 61
    .line 62
    if-eqz p1, :cond_0

    .line 63
    .line 64
    const-string p1, "BeaconManager"

    .line 65
    .line 66
    const-string v4, "Setting a short backgroundBetweenScanPeriod has no effect on Android 8+, which is limited to scanning every ~15 minutes"

    .line 67
    .line 68
    new-array v5, v3, [Ljava/lang/Object;

    .line 69
    .line 70
    invoke-static {p1, v4, v5}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    :cond_0
    iget-object p1, p0, Lorg/altbeacon/beacon/BeaconManager;->settings:Lorg/altbeacon/beacon/AppliedSettings;

    .line 74
    .line 75
    invoke-virtual {p1}, Lorg/altbeacon/beacon/AppliedSettings;->getBeaconSimulator()Lorg/altbeacon/beacon/simulator/BeaconSimulator;

    .line 76
    .line 77
    .line 78
    move-result-object p1

    .line 79
    if-eqz p1, :cond_2

    .line 80
    .line 81
    iget-object p1, p0, Lorg/altbeacon/beacon/BeaconManager;->settings:Lorg/altbeacon/beacon/AppliedSettings;

    .line 82
    .line 83
    invoke-virtual {p1}, Lorg/altbeacon/beacon/AppliedSettings;->getBeaconSimulator()Lorg/altbeacon/beacon/simulator/BeaconSimulator;

    .line 84
    .line 85
    .line 86
    move-result-object p1

    .line 87
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 88
    .line 89
    .line 90
    move-result-object p1

    .line 91
    const-class v4, Lorg/altbeacon/beacon/Settings$DisabledBeaconSimulator;

    .line 92
    .line 93
    if-ne p1, v4, :cond_1

    .line 94
    .line 95
    goto :goto_0

    .line 96
    :cond_1
    iget-object p1, p0, Lorg/altbeacon/beacon/BeaconManager;->settings:Lorg/altbeacon/beacon/AppliedSettings;

    .line 97
    .line 98
    invoke-virtual {p1}, Lorg/altbeacon/beacon/AppliedSettings;->getBeaconSimulator()Lorg/altbeacon/beacon/simulator/BeaconSimulator;

    .line 99
    .line 100
    .line 101
    move-result-object p1

    .line 102
    invoke-static {p1}, Lorg/altbeacon/beacon/BeaconManager;->setBeaconSimulator(Lorg/altbeacon/beacon/simulator/BeaconSimulator;)V

    .line 103
    .line 104
    .line 105
    goto :goto_1

    .line 106
    :cond_2
    :goto_0
    const/4 p1, 0x0

    .line 107
    invoke-static {p1}, Lorg/altbeacon/beacon/BeaconManager;->setBeaconSimulator(Lorg/altbeacon/beacon/simulator/BeaconSimulator;)V

    .line 108
    .line 109
    .line 110
    :goto_1
    iget-object p1, p0, Lorg/altbeacon/beacon/BeaconManager;->settings:Lorg/altbeacon/beacon/AppliedSettings;

    .line 111
    .line 112
    invoke-virtual {p1}, Lorg/altbeacon/beacon/AppliedSettings;->getRssiFilterImplClass()Ljava/lang/Class;

    .line 113
    .line 114
    .line 115
    move-result-object p1

    .line 116
    if-eqz p1, :cond_3

    .line 117
    .line 118
    iget-object p1, p0, Lorg/altbeacon/beacon/BeaconManager;->settings:Lorg/altbeacon/beacon/AppliedSettings;

    .line 119
    .line 120
    invoke-virtual {p1}, Lorg/altbeacon/beacon/AppliedSettings;->getRssiFilterImplClass()Ljava/lang/Class;

    .line 121
    .line 122
    .line 123
    move-result-object p1

    .line 124
    sput-object p1, Lorg/altbeacon/beacon/BeaconManager;->rssiFilterImplClass:Ljava/lang/Class;

    .line 125
    .line 126
    :cond_3
    iget-object p1, p0, Lorg/altbeacon/beacon/BeaconManager;->settings:Lorg/altbeacon/beacon/AppliedSettings;

    .line 127
    .line 128
    invoke-virtual {p1}, Lorg/altbeacon/beacon/AppliedSettings;->getHardwareEqualityEnforced()Z

    .line 129
    .line 130
    .line 131
    move-result p1

    .line 132
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 133
    .line 134
    .line 135
    move-result-object p1

    .line 136
    invoke-virtual {v2, p1}, Ljava/lang/Boolean;->equals(Ljava/lang/Object;)Z

    .line 137
    .line 138
    .line 139
    move-result p1

    .line 140
    invoke-static {p1}, Lorg/altbeacon/beacon/Beacon;->setHardwareEqualityEnforced(Z)V

    .line 141
    .line 142
    .line 143
    iget-object p1, p0, Lorg/altbeacon/beacon/BeaconManager;->settings:Lorg/altbeacon/beacon/AppliedSettings;

    .line 144
    .line 145
    invoke-virtual {p1}, Lorg/altbeacon/beacon/AppliedSettings;->getDebug()Z

    .line 146
    .line 147
    .line 148
    move-result p1

    .line 149
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 150
    .line 151
    .line 152
    move-result-object p1

    .line 153
    invoke-virtual {v2, p1}, Ljava/lang/Boolean;->equals(Ljava/lang/Object;)Z

    .line 154
    .line 155
    .line 156
    move-result p1

    .line 157
    invoke-static {p1}, Lorg/altbeacon/beacon/BeaconManager;->setDebug(Z)V

    .line 158
    .line 159
    .line 160
    iget-object p1, p0, Lorg/altbeacon/beacon/BeaconManager;->settings:Lorg/altbeacon/beacon/AppliedSettings;

    .line 161
    .line 162
    invoke-virtual {p1}, Lorg/altbeacon/beacon/AppliedSettings;->getScanPeriods()Lorg/altbeacon/beacon/Settings$ScanPeriods;

    .line 163
    .line 164
    .line 165
    move-result-object p1

    .line 166
    if-eqz p1, :cond_4

    .line 167
    .line 168
    invoke-virtual {p1}, Lorg/altbeacon/beacon/Settings$ScanPeriods;->getBackgroundBetweenScanPeriodMillis()J

    .line 169
    .line 170
    .line 171
    move-result-wide v4

    .line 172
    invoke-virtual {p0, v4, v5}, Lorg/altbeacon/beacon/BeaconManager;->setBackgroundBetweenScanPeriod(J)V

    .line 173
    .line 174
    .line 175
    invoke-virtual {p1}, Lorg/altbeacon/beacon/Settings$ScanPeriods;->getBackgroundScanPeriodMillis()J

    .line 176
    .line 177
    .line 178
    move-result-wide v4

    .line 179
    invoke-virtual {p0, v4, v5}, Lorg/altbeacon/beacon/BeaconManager;->setBackgroundScanPeriod(J)V

    .line 180
    .line 181
    .line 182
    invoke-virtual {p1}, Lorg/altbeacon/beacon/Settings$ScanPeriods;->getForegroundBetweenScanPeriodMillis()J

    .line 183
    .line 184
    .line 185
    move-result-wide v4

    .line 186
    invoke-virtual {p0, v4, v5}, Lorg/altbeacon/beacon/BeaconManager;->setForegroundBetweenScanPeriod(J)V

    .line 187
    .line 188
    .line 189
    invoke-virtual {p1}, Lorg/altbeacon/beacon/Settings$ScanPeriods;->getForegroundScanPeriodMillis()J

    .line 190
    .line 191
    .line 192
    move-result-wide v4

    .line 193
    invoke-virtual {p0, v4, v5}, Lorg/altbeacon/beacon/BeaconManager;->setForegroundScanPeriod(J)V

    .line 194
    .line 195
    .line 196
    :cond_4
    iget-object p1, p0, Lorg/altbeacon/beacon/BeaconManager;->settings:Lorg/altbeacon/beacon/AppliedSettings;

    .line 197
    .line 198
    invoke-virtual {p1}, Lorg/altbeacon/beacon/AppliedSettings;->getManifestCheckingDisabled()Z

    .line 199
    .line 200
    .line 201
    move-result p1

    .line 202
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 203
    .line 204
    .line 205
    move-result-object p1

    .line 206
    invoke-virtual {v2, p1}, Ljava/lang/Boolean;->equals(Ljava/lang/Object;)Z

    .line 207
    .line 208
    .line 209
    move-result p1

    .line 210
    invoke-static {p1}, Lorg/altbeacon/beacon/BeaconManager;->setManifestCheckingDisabled(Z)V

    .line 211
    .line 212
    .line 213
    iget-object p1, p0, Lorg/altbeacon/beacon/BeaconManager;->settings:Lorg/altbeacon/beacon/AppliedSettings;

    .line 214
    .line 215
    invoke-virtual {p1}, Lorg/altbeacon/beacon/AppliedSettings;->getRegionExitPeriodMillis()I

    .line 216
    .line 217
    .line 218
    move-result p1

    .line 219
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 220
    .line 221
    .line 222
    move-result-object p1

    .line 223
    invoke-virtual {p1}, Ljava/lang/Integer;->longValue()J

    .line 224
    .line 225
    .line 226
    move-result-wide v4

    .line 227
    invoke-static {v4, v5}, Lorg/altbeacon/beacon/BeaconManager;->setRegionExitPeriod(J)V

    .line 228
    .line 229
    .line 230
    iget-object p1, p0, Lorg/altbeacon/beacon/BeaconManager;->settings:Lorg/altbeacon/beacon/AppliedSettings;

    .line 231
    .line 232
    invoke-virtual {p1}, Lorg/altbeacon/beacon/AppliedSettings;->getRegionStatePersistenceEnabled()Z

    .line 233
    .line 234
    .line 235
    move-result p1

    .line 236
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 237
    .line 238
    .line 239
    move-result-object p1

    .line 240
    invoke-virtual {v2, p1}, Ljava/lang/Boolean;->equals(Ljava/lang/Object;)Z

    .line 241
    .line 242
    .line 243
    move-result p1

    .line 244
    invoke-virtual {p0, p1}, Lorg/altbeacon/beacon/BeaconManager;->setRegionStatePersistenceEnabled(Z)V

    .line 245
    .line 246
    .line 247
    invoke-virtual {v1}, Lorg/altbeacon/beacon/AppliedSettings;->getScanStrategy()Lorg/altbeacon/beacon/Settings$ScanStrategy;

    .line 248
    .line 249
    .line 250
    move-result-object p1

    .line 251
    iget-object v2, p0, Lorg/altbeacon/beacon/BeaconManager;->settings:Lorg/altbeacon/beacon/AppliedSettings;

    .line 252
    .line 253
    invoke-virtual {v2}, Lorg/altbeacon/beacon/AppliedSettings;->getScanStrategy()Lorg/altbeacon/beacon/Settings$ScanStrategy;

    .line 254
    .line 255
    .line 256
    move-result-object v2

    .line 257
    invoke-interface {p1, v2}, Ljava/lang/Comparable;->compareTo(Ljava/lang/Object;)I

    .line 258
    .line 259
    .line 260
    move-result p1

    .line 261
    if-eqz p1, :cond_5

    .line 262
    .line 263
    const/4 p1, 0x1

    .line 264
    goto :goto_2

    .line 265
    :cond_5
    move p1, v3

    .line 266
    :goto_2
    iget-object v2, p0, Lorg/altbeacon/beacon/BeaconManager;->consumers:Ljava/util/concurrent/ConcurrentMap;

    .line 267
    .line 268
    monitor-enter v2

    .line 269
    if-eqz p1, :cond_7

    .line 270
    .line 271
    :try_start_0
    iget-object p1, p0, Lorg/altbeacon/beacon/BeaconManager;->consumers:Ljava/util/concurrent/ConcurrentMap;

    .line 272
    .line 273
    invoke-interface {p1}, Ljava/util/Map;->size()I

    .line 274
    .line 275
    .line 276
    move-result p1

    .line 277
    if-lez p1, :cond_7

    .line 278
    .line 279
    const-string p1, "BeaconManager"

    .line 280
    .line 281
    new-instance v4, Ljava/lang/StringBuilder;

    .line 282
    .line 283
    invoke-direct {v4, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 284
    .line 285
    .line 286
    invoke-virtual {v1}, Lorg/altbeacon/beacon/AppliedSettings;->getScanStrategy()Lorg/altbeacon/beacon/Settings$ScanStrategy;

    .line 287
    .line 288
    .line 289
    move-result-object v0

    .line 290
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 291
    .line 292
    .line 293
    const-string v0, ", new strategy: "

    .line 294
    .line 295
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 296
    .line 297
    .line 298
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->settings:Lorg/altbeacon/beacon/AppliedSettings;

    .line 299
    .line 300
    invoke-virtual {v0}, Lorg/altbeacon/beacon/AppliedSettings;->getScanStrategy()Lorg/altbeacon/beacon/Settings$ScanStrategy;

    .line 301
    .line 302
    .line 303
    move-result-object v0

    .line 304
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 305
    .line 306
    .line 307
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 308
    .line 309
    .line 310
    move-result-object v0

    .line 311
    new-array v1, v3, [Ljava/lang/Object;

    .line 312
    .line 313
    invoke-static {p1, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 314
    .line 315
    .line 316
    const-string p1, "BeaconManager"

    .line 317
    .line 318
    const-string v0, "unbinding all consumers for strategy change"

    .line 319
    .line 320
    new-array v1, v3, [Ljava/lang/Object;

    .line 321
    .line 322
    invoke-static {p1, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 323
    .line 324
    .line 325
    new-instance p1, Ljava/util/ArrayList;

    .line 326
    .line 327
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->consumers:Ljava/util/concurrent/ConcurrentMap;

    .line 328
    .line 329
    invoke-interface {v0}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 330
    .line 331
    .line 332
    move-result-object v0

    .line 333
    invoke-direct {p1, v0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 334
    .line 335
    .line 336
    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 337
    .line 338
    .line 339
    move-result-object v0

    .line 340
    :goto_3
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 341
    .line 342
    .line 343
    move-result v1

    .line 344
    if-eqz v1, :cond_6

    .line 345
    .line 346
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 347
    .line 348
    .line 349
    move-result-object v1

    .line 350
    check-cast v1, Lorg/altbeacon/beacon/InternalBeaconConsumer;

    .line 351
    .line 352
    invoke-virtual {p0, v1}, Lorg/altbeacon/beacon/BeaconManager;->unbindInternal(Lorg/altbeacon/beacon/InternalBeaconConsumer;)V

    .line 353
    .line 354
    .line 355
    goto :goto_3

    .line 356
    :catchall_0
    move-exception p0

    .line 357
    goto :goto_5

    .line 358
    :cond_6
    iput-boolean v3, p0, Lorg/altbeacon/beacon/BeaconManager;->mScheduledScanJobsEnabledByFallback:Z

    .line 359
    .line 360
    invoke-direct {p0, p1}, Lorg/altbeacon/beacon/BeaconManager;->configureScanStrategyWhenConsumersUnbound(Ljava/util/List;)V

    .line 361
    .line 362
    .line 363
    goto :goto_4

    .line 364
    :cond_7
    iget-object p1, p0, Lorg/altbeacon/beacon/BeaconManager;->consumers:Ljava/util/concurrent/ConcurrentMap;

    .line 365
    .line 366
    invoke-interface {p1}, Ljava/util/Map;->size()I

    .line 367
    .line 368
    .line 369
    move-result p1

    .line 370
    if-nez p1, :cond_8

    .line 371
    .line 372
    iget-object p1, p0, Lorg/altbeacon/beacon/BeaconManager;->settings:Lorg/altbeacon/beacon/AppliedSettings;

    .line 373
    .line 374
    invoke-virtual {p1}, Lorg/altbeacon/beacon/AppliedSettings;->getScanStrategy()Lorg/altbeacon/beacon/Settings$ScanStrategy;

    .line 375
    .line 376
    .line 377
    move-result-object p1

    .line 378
    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 379
    .line 380
    .line 381
    check-cast p1, Lorg/altbeacon/beacon/Settings$ScanStrategy;

    .line 382
    .line 383
    invoke-interface {p1, p0}, Lorg/altbeacon/beacon/Settings$ScanStrategy;->configure(Lorg/altbeacon/beacon/BeaconManager;)V

    .line 384
    .line 385
    .line 386
    :cond_8
    :goto_4
    monitor-exit v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 387
    iget-object p1, p0, Lorg/altbeacon/beacon/BeaconManager;->settings:Lorg/altbeacon/beacon/AppliedSettings;

    .line 388
    .line 389
    invoke-virtual {p1}, Lorg/altbeacon/beacon/AppliedSettings;->getDistanceCalculatorFactory()Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;

    .line 390
    .line 391
    .line 392
    move-result-object p1

    .line 393
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mContext:Landroid/content/Context;

    .line 394
    .line 395
    invoke-interface {p1, v0}, Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;->getInstance(Landroid/content/Context;)Lorg/altbeacon/beacon/distance/DistanceCalculator;

    .line 396
    .line 397
    .line 398
    move-result-object p1

    .line 399
    invoke-static {p1}, Lorg/altbeacon/beacon/Beacon;->setDistanceCalculatorInternal(Lorg/altbeacon/beacon/distance/DistanceCalculator;)V

    .line 400
    .line 401
    .line 402
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->applySettings()V

    .line 403
    .line 404
    .line 405
    return-void

    .line 406
    :goto_5
    :try_start_1
    monitor-exit v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 407
    throw p0
.end method

.method private declared-synchronized autoBind()V
    .locals 1

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->autoBindConsumer:Lorg/altbeacon/beacon/BeaconConsumer;

    .line 3
    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    new-instance v0, Lorg/altbeacon/beacon/BeaconManager$4;

    .line 7
    .line 8
    invoke-direct {v0, p0}, Lorg/altbeacon/beacon/BeaconManager$4;-><init>(Lorg/altbeacon/beacon/BeaconManager;)V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->autoBindConsumer:Lorg/altbeacon/beacon/BeaconConsumer;

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :catchall_0
    move-exception v0

    .line 15
    goto :goto_1

    .line 16
    :cond_0
    :goto_0
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->autoBindConsumer:Lorg/altbeacon/beacon/BeaconConsumer;

    .line 17
    .line 18
    invoke-virtual {p0, v0}, Lorg/altbeacon/beacon/BeaconManager;->bindInternal(Lorg/altbeacon/beacon/InternalBeaconConsumer;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 19
    .line 20
    .line 21
    monitor-exit p0

    .line 22
    return-void

    .line 23
    :goto_1
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 24
    throw v0
.end method

.method private autoUnbindIfNeeded()V
    .locals 1

    .line 1
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->getMonitoredRegions()Ljava/util/Collection;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->getRangedRegions()Ljava/util/Collection;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-nez v0, :cond_0

    .line 20
    .line 21
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->autoBindConsumer:Lorg/altbeacon/beacon/BeaconConsumer;

    .line 22
    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    invoke-virtual {p0, v0}, Lorg/altbeacon/beacon/BeaconManager;->unbindInternal(Lorg/altbeacon/beacon/InternalBeaconConsumer;)V

    .line 26
    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    iput-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->autoBindConsumer:Lorg/altbeacon/beacon/BeaconConsumer;

    .line 30
    .line 31
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->autoBindRangedRegions:Ljava/util/Set;

    .line 32
    .line 33
    invoke-interface {v0}, Ljava/util/Set;->clear()V

    .line 34
    .line 35
    .line 36
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->autoBindMonitoredRegions:Ljava/util/Set;

    .line 37
    .line 38
    invoke-interface {p0}, Ljava/util/Set;->clear()V

    .line 39
    .line 40
    .line 41
    :cond_0
    return-void
.end method

.method public static bridge synthetic b(Lorg/altbeacon/beacon/BeaconManager;)Ljava/util/Set;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->autoBindRangedRegions:Ljava/util/Set;

    .line 2
    .line 3
    return-object p0
.end method

.method public static bridge synthetic c(Lorg/altbeacon/beacon/BeaconManager;)Ljava/util/concurrent/ConcurrentMap;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->consumers:Ljava/util/concurrent/ConcurrentMap;

    .line 2
    .line 3
    return-object p0
.end method

.method private callbackPackageName()Ljava/lang/String;
    .locals 3

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->mContext:Landroid/content/Context;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const-string v0, "callback packageName: %s"

    .line 8
    .line 9
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    const-string v2, "BeaconManager"

    .line 14
    .line 15
    invoke-static {v2, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    return-object p0
.end method

.method private configureScanStrategyWhenConsumersUnbound(Ljava/util/List;)V
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lorg/altbeacon/beacon/InternalBeaconConsumer;",
            ">;)V"
        }
    .end annotation

    .line 1
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->isAnyConsumerBound()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    new-instance v0, Landroid/os/Handler;

    .line 8
    .line 9
    invoke-direct {v0}, Landroid/os/Handler;-><init>()V

    .line 10
    .line 11
    .line 12
    new-instance v1, Lorg/altbeacon/beacon/BeaconManager$1;

    .line 13
    .line 14
    invoke-direct {v1, p0, p1}, Lorg/altbeacon/beacon/BeaconManager$1;-><init>(Lorg/altbeacon/beacon/BeaconManager;Ljava/util/List;)V

    .line 15
    .line 16
    .line 17
    const-wide/16 p0, 0x64

    .line 18
    .line 19
    invoke-virtual {v0, v1, p0, p1}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 20
    .line 21
    .line 22
    return-void

    .line 23
    :cond_0
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->settings:Lorg/altbeacon/beacon/AppliedSettings;

    .line 24
    .line 25
    invoke-virtual {v0}, Lorg/altbeacon/beacon/AppliedSettings;->getScanStrategy()Lorg/altbeacon/beacon/Settings$ScanStrategy;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    check-cast v0, Lorg/altbeacon/beacon/Settings$ScanStrategy;

    .line 33
    .line 34
    invoke-interface {v0, p0}, Lorg/altbeacon/beacon/Settings$ScanStrategy;->configure(Lorg/altbeacon/beacon/BeaconManager;)V

    .line 35
    .line 36
    .line 37
    const-string v0, "binding all consumers for strategy change"

    .line 38
    .line 39
    const/4 v1, 0x0

    .line 40
    new-array v2, v1, [Ljava/lang/Object;

    .line 41
    .line 42
    const-string v3, "BeaconManager"

    .line 43
    .line 44
    invoke-static {v3, v0, v2}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 48
    .line 49
    .line 50
    move-result-object p1

    .line 51
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 52
    .line 53
    .line 54
    move-result v0

    .line 55
    if-eqz v0, :cond_1

    .line 56
    .line 57
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    check-cast v0, Lorg/altbeacon/beacon/InternalBeaconConsumer;

    .line 62
    .line 63
    invoke-virtual {p0, v0}, Lorg/altbeacon/beacon/BeaconManager;->bindInternal(Lorg/altbeacon/beacon/InternalBeaconConsumer;)V

    .line 64
    .line 65
    .line 66
    goto :goto_0

    .line 67
    :cond_1
    const-string p0, "Done with scan strategy change"

    .line 68
    .line 69
    new-array p1, v1, [Ljava/lang/Object;

    .line 70
    .line 71
    invoke-static {v3, p0, p1}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    return-void
.end method

.method public static bridge synthetic d(Lorg/altbeacon/beacon/BeaconManager;)Landroid/content/Context;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->mContext:Landroid/content/Context;

    .line 2
    .line 3
    return-object p0
.end method

.method private determineIfCalledFromSeparateScannerProcess()Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->isScannerInDifferentProcess()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->isMainProcess()Z

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    if-nez p0, :cond_0

    .line 13
    .line 14
    const-string p0, "Ranging/Monitoring may not be controlled from a separate BeaconScanner process.  To remove this warning, please wrap this call in: if (beaconManager.isMainProcess())"

    .line 15
    .line 16
    new-array v0, v1, [Ljava/lang/Object;

    .line 17
    .line 18
    const-string v1, "BeaconManager"

    .line 19
    .line 20
    invoke-static {v1, p0, v0}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    const/4 p0, 0x1

    .line 24
    return p0

    .line 25
    :cond_0
    return v1
.end method

.method public static bridge synthetic e(Lorg/altbeacon/beacon/BeaconManager;)Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->mScannerInSameProcess:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-object p0
.end method

.method private ensureBackgroundPowerSaver()V
    .locals 2

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mInternalBackgroundPowerSaver:Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;

    .line 6
    .line 7
    iget-object v1, p0, Lorg/altbeacon/beacon/BeaconManager;->mContext:Landroid/content/Context;

    .line 8
    .line 9
    invoke-direct {v0, v1}, Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;-><init>(Landroid/content/Context;)V

    .line 10
    .line 11
    .line 12
    iput-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mInternalBackgroundPowerSaver:Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;

    .line 13
    .line 14
    invoke-virtual {v0}, Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;->enableDefaultBackgroundStateInference()V

    .line 15
    .line 16
    .line 17
    :cond_0
    return-void
.end method

.method public static bridge synthetic f(Lorg/altbeacon/beacon/BeaconManager;)V
    .locals 1

    .line 1
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 2
    .line 3
    iput-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mScannerInSameProcess:Ljava/lang/Boolean;

    .line 4
    .line 5
    return-void
.end method

.method public static bridge synthetic g(Lorg/altbeacon/beacon/BeaconManager;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-boolean v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mServiceSyncScheduled:Z

    .line 3
    .line 4
    return-void
.end method

.method public static getBeaconSimulator()Lorg/altbeacon/beacon/simulator/BeaconSimulator;
    .locals 1

    .line 1
    sget-object v0, Lorg/altbeacon/beacon/BeaconManager;->beaconSimulator:Lorg/altbeacon/beacon/simulator/BeaconSimulator;

    .line 2
    .line 3
    return-object v0
.end method

.method private getBetweenScanPeriod()J
    .locals 2

    .line 1
    iget-boolean v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mBackgroundMode:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-wide v0, p0, Lorg/altbeacon/beacon/BeaconManager;->backgroundBetweenScanPeriod:J

    .line 6
    .line 7
    return-wide v0

    .line 8
    :cond_0
    iget-wide v0, p0, Lorg/altbeacon/beacon/BeaconManager;->foregroundBetweenScanPeriod:J

    .line 9
    .line 10
    return-wide v0
.end method

.method public static getDistanceModelUpdateUrl()Ljava/lang/String;
    .locals 1

    .line 1
    sget-object v0, Lorg/altbeacon/beacon/BeaconManager;->distanceModelUpdateUrl:Ljava/lang/String;

    .line 2
    .line 3
    return-object v0
.end method

.method public static getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/BeaconManager;
    .locals 4

    .line 1
    sget-object v0, Lorg/altbeacon/beacon/BeaconManager;->sInstance:Lorg/altbeacon/beacon/BeaconManager;

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    sget-object v1, Lorg/altbeacon/beacon/BeaconManager;->SINGLETON_LOCK:Ljava/lang/Object;

    .line 6
    .line 7
    monitor-enter v1

    .line 8
    :try_start_0
    sget-object v0, Lorg/altbeacon/beacon/BeaconManager;->sInstance:Lorg/altbeacon/beacon/BeaconManager;

    .line 9
    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    new-instance v0, Lorg/altbeacon/beacon/BeaconManager;

    .line 13
    .line 14
    invoke-direct {v0, p0}, Lorg/altbeacon/beacon/BeaconManager;-><init>(Landroid/content/Context;)V

    .line 15
    .line 16
    .line 17
    sput-object v0, Lorg/altbeacon/beacon/BeaconManager;->sInstance:Lorg/altbeacon/beacon/BeaconManager;

    .line 18
    .line 19
    const-string p0, "BeaconManager"

    .line 20
    .line 21
    const-string v2, "API BeaconManager constructed "

    .line 22
    .line 23
    const/4 v3, 0x0

    .line 24
    new-array v3, v3, [Ljava/lang/Object;

    .line 25
    .line 26
    invoke-static {p0, v2, v3}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    goto :goto_0

    .line 30
    :catchall_0
    move-exception p0

    .line 31
    goto :goto_1

    .line 32
    :cond_0
    :goto_0
    monitor-exit v1

    .line 33
    return-object v0

    .line 34
    :goto_1
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 35
    throw p0

    .line 36
    :cond_1
    return-object v0
.end method

.method public static getManifestCheckingDisabled()Z
    .locals 1

    .line 1
    sget-boolean v0, Lorg/altbeacon/beacon/BeaconManager;->sManifestCheckingDisabled:Z

    .line 2
    .line 3
    return v0
.end method

.method public static getRegionExitPeriod()J
    .locals 2

    .line 1
    sget-wide v0, Lorg/altbeacon/beacon/BeaconManager;->sExitRegionPeriod:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public static getRssiFilterImplClass()Ljava/lang/Class;
    .locals 1

    .line 1
    sget-object v0, Lorg/altbeacon/beacon/BeaconManager;->rssiFilterImplClass:Ljava/lang/Class;

    .line 2
    .line 3
    return-object v0
.end method

.method private getScanPeriod()J
    .locals 2

    .line 1
    iget-boolean v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mBackgroundMode:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-wide v0, p0, Lorg/altbeacon/beacon/BeaconManager;->backgroundScanPeriod:J

    .line 6
    .line 7
    return-wide v0

    .line 8
    :cond_0
    iget-wide v0, p0, Lorg/altbeacon/beacon/BeaconManager;->foregroundScanPeriod:J

    .line 9
    .line 10
    return-wide v0
.end method

.method public static bridge synthetic h(Lorg/altbeacon/beacon/BeaconManager;Landroid/os/Messenger;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/BeaconManager;->serviceMessenger:Landroid/os/Messenger;

    .line 2
    .line 3
    return-void
.end method

.method public static bridge synthetic i(Lorg/altbeacon/beacon/BeaconManager;)V
    .locals 2

    .line 1
    const/4 v0, 0x7

    .line 2
    const/4 v1, 0x0

    .line 3
    invoke-direct {p0, v0, v1}, Lorg/altbeacon/beacon/BeaconManager;->applyChangesToServices(ILorg/altbeacon/beacon/Region;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public static isAndroidLScanningDisabled()Z
    .locals 1

    .line 1
    sget-boolean v0, Lorg/altbeacon/beacon/BeaconManager;->sAndroidLScanningDisabled:Z

    .line 2
    .line 3
    return v0
.end method

.method private isBleAvailable()Z
    .locals 3

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->mContext:Landroid/content/Context;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const-string v0, "android.hardware.bluetooth_le"

    .line 8
    .line 9
    invoke-virtual {p0, v0}, Landroid/content/pm/PackageManager;->hasSystemFeature(Ljava/lang/String;)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    if-nez p0, :cond_0

    .line 14
    .line 15
    const-string p0, "This device does not support bluetooth LE."

    .line 16
    .line 17
    const/4 v0, 0x0

    .line 18
    new-array v1, v0, [Ljava/lang/Object;

    .line 19
    .line 20
    const-string v2, "BeaconManager"

    .line 21
    .line 22
    invoke-static {v2, p0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    return v0

    .line 26
    :cond_0
    const/4 p0, 0x1

    .line 27
    return p0
.end method

.method private isBleAvailableOrSimulated()Z
    .locals 1

    .line 1
    invoke-static {}, Lorg/altbeacon/beacon/BeaconManager;->getBeaconSimulator()Lorg/altbeacon/beacon/simulator/BeaconSimulator;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x1

    .line 8
    return p0

    .line 9
    :cond_0
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->isBleAvailable()Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public static bridge synthetic j(Lorg/altbeacon/beacon/BeaconManager;Ljava/util/List;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lorg/altbeacon/beacon/BeaconManager;->configureScanStrategyWhenConsumersUnbound(Ljava/util/List;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic k(Lorg/altbeacon/beacon/BeaconManager;)Z
    .locals 0

    .line 1
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->isBleAvailableOrSimulated()Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public static logDebug(Ljava/lang/String;Ljava/lang/String;)V
    .locals 1
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    const/4 v0, 0x0

    .line 1
    new-array v0, v0, [Ljava/lang/Object;

    invoke-static {p0, p1, v0}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public static logDebug(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V
    .locals 1
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    const/4 v0, 0x0

    .line 2
    new-array v0, v0, [Ljava/lang/Object;

    invoke-static {p2, p0, p1, v0}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public static setAndroidLScanningDisabled(Z)V
    .locals 3
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "API setAndroidLScanningDisabled "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const/4 v1, 0x0

    .line 16
    new-array v1, v1, [Ljava/lang/Object;

    .line 17
    .line 18
    const-string v2, "BeaconManager"

    .line 19
    .line 20
    invoke-static {v2, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    sput-boolean p0, Lorg/altbeacon/beacon/BeaconManager;->sAndroidLScanningDisabled:Z

    .line 24
    .line 25
    sget-object p0, Lorg/altbeacon/beacon/BeaconManager;->sInstance:Lorg/altbeacon/beacon/BeaconManager;

    .line 26
    .line 27
    if-eqz p0, :cond_0

    .line 28
    .line 29
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->applySettings()V

    .line 30
    .line 31
    .line 32
    :cond_0
    return-void
.end method

.method public static setBeaconSimulator(Lorg/altbeacon/beacon/simulator/BeaconSimulator;)V
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "API setBeaconSimulator "

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
    move-result-object v0

    .line 15
    const/4 v1, 0x0

    .line 16
    new-array v1, v1, [Ljava/lang/Object;

    .line 17
    .line 18
    const-string v2, "BeaconManager"

    .line 19
    .line 20
    invoke-static {v2, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    invoke-static {}, Lorg/altbeacon/beacon/BeaconManager;->warnIfScannerNotInSameProcess()V

    .line 24
    .line 25
    .line 26
    sput-object p0, Lorg/altbeacon/beacon/BeaconManager;->beaconSimulator:Lorg/altbeacon/beacon/simulator/BeaconSimulator;

    .line 27
    .line 28
    return-void
.end method

.method public static setDebug(Z)V
    .locals 0

    .line 1
    if-eqz p0, :cond_0

    .line 2
    .line 3
    invoke-static {}, Lorg/altbeacon/beacon/logging/Loggers;->verboseLogger()Lorg/altbeacon/beacon/logging/Logger;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-static {p0}, Lorg/altbeacon/beacon/logging/LogManager;->setLogger(Lorg/altbeacon/beacon/logging/Logger;)V

    .line 8
    .line 9
    .line 10
    const/4 p0, 0x1

    .line 11
    invoke-static {p0}, Lorg/altbeacon/beacon/logging/LogManager;->setVerboseLoggingEnabled(Z)V

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :cond_0
    invoke-static {}, Lorg/altbeacon/beacon/logging/Loggers;->infoLogger()Lorg/altbeacon/beacon/logging/Logger;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    invoke-static {p0}, Lorg/altbeacon/beacon/logging/LogManager;->setLogger(Lorg/altbeacon/beacon/logging/Logger;)V

    .line 20
    .line 21
    .line 22
    const/4 p0, 0x0

    .line 23
    invoke-static {p0}, Lorg/altbeacon/beacon/logging/LogManager;->setVerboseLoggingEnabled(Z)V

    .line 24
    .line 25
    .line 26
    return-void
.end method

.method public static setDistanceModelUpdateUrl(Ljava/lang/String;)V
    .locals 0
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    invoke-static {}, Lorg/altbeacon/beacon/BeaconManager;->warnIfScannerNotInSameProcess()V

    .line 2
    .line 3
    .line 4
    sput-object p0, Lorg/altbeacon/beacon/BeaconManager;->distanceModelUpdateUrl:Ljava/lang/String;

    .line 5
    .line 6
    return-void
.end method

.method public static setManifestCheckingDisabled(Z)V
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "API setManifestCheckingDisabled "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const/4 v1, 0x0

    .line 16
    new-array v1, v1, [Ljava/lang/Object;

    .line 17
    .line 18
    const-string v2, "BeaconManager"

    .line 19
    .line 20
    invoke-static {v2, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    sput-boolean p0, Lorg/altbeacon/beacon/BeaconManager;->sManifestCheckingDisabled:Z

    .line 24
    .line 25
    return-void
.end method

.method public static setRegionExitPeriod(J)V
    .locals 3

    .line 1
    const-string v0, "API setRegionExitPeriod "

    .line 2
    .line 3
    invoke-static {p0, p1, v0}, Lp3/m;->f(JLjava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const/4 v1, 0x0

    .line 8
    new-array v1, v1, [Ljava/lang/Object;

    .line 9
    .line 10
    const-string v2, "BeaconManager"

    .line 11
    .line 12
    invoke-static {v2, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    sput-wide p0, Lorg/altbeacon/beacon/BeaconManager;->sExitRegionPeriod:J

    .line 16
    .line 17
    sget-object p0, Lorg/altbeacon/beacon/BeaconManager;->sInstance:Lorg/altbeacon/beacon/BeaconManager;

    .line 18
    .line 19
    if-eqz p0, :cond_0

    .line 20
    .line 21
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->applySettings()V

    .line 22
    .line 23
    .line 24
    :cond_0
    return-void
.end method

.method public static setRssiFilterImplClass(Ljava/lang/Class;)V
    .locals 0

    .line 1
    invoke-static {}, Lorg/altbeacon/beacon/BeaconManager;->warnIfScannerNotInSameProcess()V

    .line 2
    .line 3
    .line 4
    sput-object p0, Lorg/altbeacon/beacon/BeaconManager;->rssiFilterImplClass:Ljava/lang/Class;

    .line 5
    .line 6
    return-void
.end method

.method private setScheduledScanJobsEnabledDefault()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mScheduledScanJobsEnabled:Z

    .line 3
    .line 4
    return-void
.end method

.method public static setUseTrackingCache(Z)V
    .locals 0

    .line 1
    invoke-static {p0}, Lorg/altbeacon/beacon/service/RangeState;->setUseTrackingCache(Z)V

    .line 2
    .line 3
    .line 4
    sget-object p0, Lorg/altbeacon/beacon/BeaconManager;->sInstance:Lorg/altbeacon/beacon/BeaconManager;

    .line 5
    .line 6
    if-eqz p0, :cond_0

    .line 7
    .line 8
    sget-object p0, Lorg/altbeacon/beacon/BeaconManager;->sInstance:Lorg/altbeacon/beacon/BeaconManager;

    .line 9
    .line 10
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->applySettings()V

    .line 11
    .line 12
    .line 13
    :cond_0
    return-void
.end method

.method public static setsManifestCheckingDisabled(Z)V
    .locals 0
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    sput-boolean p0, Lorg/altbeacon/beacon/BeaconManager;->sManifestCheckingDisabled:Z

    .line 2
    .line 3
    return-void
.end method

.method private verifyLocationPermissionGrantedForForegroundService()V
    .locals 6

    .line 1
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    const/4 v2, 0x0

    .line 5
    const/16 v3, 0x22

    .line 6
    .line 7
    if-lt v0, v3, :cond_0

    .line 8
    .line 9
    move v4, v1

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    move v4, v2

    .line 12
    :goto_0
    invoke-static {v4}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 13
    .line 14
    .line 15
    move-result-object v4

    .line 16
    iget-object v5, p0, Lorg/altbeacon/beacon/BeaconManager;->mContext:Landroid/content/Context;

    .line 17
    .line 18
    invoke-virtual {v5}, Landroid/content/Context;->getApplicationInfo()Landroid/content/pm/ApplicationInfo;

    .line 19
    .line 20
    .line 21
    move-result-object v5

    .line 22
    iget v5, v5, Landroid/content/pm/ApplicationInfo;->targetSdkVersion:I

    .line 23
    .line 24
    if-lt v5, v3, :cond_1

    .line 25
    .line 26
    goto :goto_1

    .line 27
    :cond_1
    move v1, v2

    .line 28
    :goto_1
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    filled-new-array {v4, v1}, [Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    const-string v4, "BeaconManager"

    .line 37
    .line 38
    const-string v5, "Running SDK 34? %b.  Targeting SDK 34? %b"

    .line 39
    .line 40
    invoke-static {v4, v5, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    if-lt v0, v3, :cond_3

    .line 44
    .line 45
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mContext:Landroid/content/Context;

    .line 46
    .line 47
    invoke-virtual {v0}, Landroid/content/Context;->getApplicationInfo()Landroid/content/pm/ApplicationInfo;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    iget v0, v0, Landroid/content/pm/ApplicationInfo;->targetSdkVersion:I

    .line 52
    .line 53
    if-lt v0, v3, :cond_3

    .line 54
    .line 55
    const-string v0, "Checking fine location permission as required for foreground service"

    .line 56
    .line 57
    new-array v1, v2, [Ljava/lang/Object;

    .line 58
    .line 59
    invoke-static {v4, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->mContext:Landroid/content/Context;

    .line 63
    .line 64
    const-string v0, "android.permission.ACCESS_FINE_LOCATION"

    .line 65
    .line 66
    invoke-virtual {p0, v0}, Landroid/content/Context;->checkSelfPermission(Ljava/lang/String;)I

    .line 67
    .line 68
    .line 69
    move-result p0

    .line 70
    if-nez p0, :cond_2

    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_2
    new-instance p0, Ljava/lang/SecurityException;

    .line 74
    .line 75
    const-string v0, "Foreground service may not be enabled until after user grants Manifest.permission.ACCESS_FINE_LOCATION when target SdkVersion is set to SDK 34 or above.  See: https://altbeacon.github.io/android-beacon-library/foreground-service.html"

    .line 76
    .line 77
    invoke-direct {p0, v0}, Ljava/lang/SecurityException;-><init>(Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    throw p0

    .line 81
    :cond_3
    :goto_2
    return-void
.end method

.method private verifyServiceDeclaration()V
    .locals 4

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mContext:Landroid/content/Context;

    .line 2
    .line 3
    invoke-virtual {v0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    new-instance v1, Landroid/content/Intent;

    .line 8
    .line 9
    iget-object v2, p0, Lorg/altbeacon/beacon/BeaconManager;->mContext:Landroid/content/Context;

    .line 10
    .line 11
    const-class v3, Lorg/altbeacon/beacon/service/BeaconService;

    .line 12
    .line 13
    invoke-direct {v1, v2, v3}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 14
    .line 15
    .line 16
    const/high16 v2, 0x10000

    .line 17
    .line 18
    invoke-virtual {v0, v1, v2}, Landroid/content/pm/PackageManager;->queryIntentServices(Landroid/content/Intent;I)Ljava/util/List;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    if-eqz v0, :cond_1

    .line 23
    .line 24
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    if-nez v0, :cond_0

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    new-instance v0, Lorg/altbeacon/beacon/BeaconManager$ServiceNotDeclaredException;

    .line 32
    .line 33
    invoke-direct {v0, p0}, Lorg/altbeacon/beacon/BeaconManager$ServiceNotDeclaredException;-><init>(Lorg/altbeacon/beacon/BeaconManager;)V

    .line 34
    .line 35
    .line 36
    throw v0

    .line 37
    :cond_1
    :goto_0
    return-void
.end method

.method private static warnIfScannerNotInSameProcess()V
    .locals 3

    .line 1
    sget-object v0, Lorg/altbeacon/beacon/BeaconManager;->sInstance:Lorg/altbeacon/beacon/BeaconManager;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0}, Lorg/altbeacon/beacon/BeaconManager;->isScannerInDifferentProcess()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    new-array v0, v0, [Ljava/lang/Object;

    .line 13
    .line 14
    const-string v1, "BeaconManager"

    .line 15
    .line 16
    const-string v2, "Unsupported configuration change made for BeaconScanner in separate process"

    .line 17
    .line 18
    invoke-static {v1, v2, v0}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    :cond_0
    return-void
.end method


# virtual methods
.method public addMonitorNotifier(Lorg/altbeacon/beacon/MonitorNotifier;)V
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "API addMonitorNotifier "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const/4 v1, 0x0

    .line 16
    new-array v1, v1, [Ljava/lang/Object;

    .line 17
    .line 18
    const-string v2, "BeaconManager"

    .line 19
    .line 20
    invoke-static {v2, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->determineIfCalledFromSeparateScannerProcess()Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    if-eqz p1, :cond_1

    .line 31
    .line 32
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->monitorNotifiers:Ljava/util/Set;

    .line 33
    .line 34
    invoke-interface {p0, p1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    :cond_1
    :goto_0
    return-void
.end method

.method public addRangeNotifier(Lorg/altbeacon/beacon/RangeNotifier;)V
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "API addRangeNotifier "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const/4 v1, 0x0

    .line 16
    new-array v1, v1, [Ljava/lang/Object;

    .line 17
    .line 18
    const-string v2, "BeaconManager"

    .line 19
    .line 20
    invoke-static {v2, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    if-eqz p1, :cond_0

    .line 24
    .line 25
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->rangeNotifiers:Ljava/util/Set;

    .line 26
    .line 27
    invoke-interface {p0, p1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    :cond_0
    return-void
.end method

.method public adjustSettings(Lorg/altbeacon/beacon/Settings;)V
    .locals 2

    .line 1
    sget-object v0, Lorg/altbeacon/beacon/AppliedSettings;->Companion:Lorg/altbeacon/beacon/AppliedSettings$Companion;

    .line 2
    .line 3
    iget-object v1, p0, Lorg/altbeacon/beacon/BeaconManager;->settings:Lorg/altbeacon/beacon/AppliedSettings;

    .line 4
    .line 5
    invoke-virtual {v0, v1, p1}, Lorg/altbeacon/beacon/AppliedSettings$Companion;->fromDeltaSettings(Lorg/altbeacon/beacon/AppliedSettings;Lorg/altbeacon/beacon/Settings;)Lorg/altbeacon/beacon/AppliedSettings;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    invoke-direct {p0, p1}, Lorg/altbeacon/beacon/BeaconManager;->applySettingsChange(Lorg/altbeacon/beacon/AppliedSettings;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public applySettings()V
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    new-array v1, v0, [Ljava/lang/Object;

    .line 3
    .line 4
    const-string v2, "BeaconManager"

    .line 5
    .line 6
    const-string v3, "API applySettings"

    .line 7
    .line 8
    invoke-static {v2, v3, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->determineIfCalledFromSeparateScannerProcess()Z

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-eqz v1, :cond_0

    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->isAnyConsumerBound()Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-nez v1, :cond_1

    .line 23
    .line 24
    const-string p0, "Not synchronizing settings to service, as it has not started up yet"

    .line 25
    .line 26
    new-array v0, v0, [Ljava/lang/Object;

    .line 27
    .line 28
    invoke-static {v2, p0, v0}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    return-void

    .line 32
    :cond_1
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->syncSettingsToService()V

    .line 33
    .line 34
    .line 35
    return-void
.end method

.method public bind(Lorg/altbeacon/beacon/BeaconConsumer;)V
    .locals 3
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    const/4 v0, 0x0

    .line 2
    new-array v0, v0, [Ljava/lang/Object;

    .line 3
    .line 4
    const-string v1, "BeaconManager"

    .line 5
    .line 6
    const-string v2, "API bind"

    .line 7
    .line 8
    invoke-static {v1, v2, v0}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0, p1}, Lorg/altbeacon/beacon/BeaconManager;->bindInternal(Lorg/altbeacon/beacon/InternalBeaconConsumer;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public bindInternal(Lorg/altbeacon/beacon/InternalBeaconConsumer;)V
    .locals 8

    .line 1
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->isBleAvailableOrSimulated()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-nez v0, :cond_0

    .line 7
    .line 8
    const-string p0, "BeaconManager"

    .line 9
    .line 10
    const-string p1, "Method invocation will be ignored."

    .line 11
    .line 12
    new-array v0, v1, [Ljava/lang/Object;

    .line 13
    .line 14
    invoke-static {p0, p1, v0}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->consumers:Ljava/util/concurrent/ConcurrentMap;

    .line 19
    .line 20
    monitor-enter v0

    .line 21
    :try_start_0
    new-instance v2, Lorg/altbeacon/beacon/BeaconManager$ConsumerInfo;

    .line 22
    .line 23
    invoke-direct {v2, p0}, Lorg/altbeacon/beacon/BeaconManager$ConsumerInfo;-><init>(Lorg/altbeacon/beacon/BeaconManager;)V

    .line 24
    .line 25
    .line 26
    iget-object v3, p0, Lorg/altbeacon/beacon/BeaconManager;->consumers:Ljava/util/concurrent/ConcurrentMap;

    .line 27
    .line 28
    invoke-interface {v3, p1, v2}, Ljava/util/concurrent/ConcurrentMap;->putIfAbsent(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v3

    .line 32
    check-cast v3, Lorg/altbeacon/beacon/BeaconManager$ConsumerInfo;

    .line 33
    .line 34
    iget-boolean v4, p0, Lorg/altbeacon/beacon/BeaconManager;->mScheduledScanJobsEnabledByFallback:Z

    .line 35
    .line 36
    if-nez v4, :cond_2

    .line 37
    .line 38
    if-nez v3, :cond_1

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_1
    const-string p0, "BeaconManager"

    .line 42
    .line 43
    const-string p1, "This consumer is already bound"

    .line 44
    .line 45
    new-array v1, v1, [Ljava/lang/Object;

    .line 46
    .line 47
    invoke-static {p0, p1, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    goto/16 :goto_4

    .line 51
    .line 52
    :catchall_0
    move-exception p0

    .line 53
    goto/16 :goto_5

    .line 54
    .line 55
    :cond_2
    :goto_0
    const-string v3, "BeaconManager"

    .line 56
    .line 57
    const-string v4, "bindInternal active"

    .line 58
    .line 59
    new-array v5, v1, [Ljava/lang/Object;

    .line 60
    .line 61
    invoke-static {v3, v4, v5}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    iget-boolean v3, p0, Lorg/altbeacon/beacon/BeaconManager;->mScheduledScanJobsEnabledByFallback:Z

    .line 65
    .line 66
    if-eqz v3, :cond_3

    .line 67
    .line 68
    const-string v3, "BeaconManager"

    .line 69
    .line 70
    const-string v4, "Need to rebind for switch to foreground service"

    .line 71
    .line 72
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object v5

    .line 76
    invoke-static {v3, v4, v5}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    iput-boolean v1, p0, Lorg/altbeacon/beacon/BeaconManager;->mScheduledScanJobsEnabledByFallback:Z

    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_3
    const-string v3, "BeaconManager"

    .line 83
    .line 84
    const-string v4, "This consumer is not bound.  Binding now: %s"

    .line 85
    .line 86
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v5

    .line 90
    invoke-static {v3, v4, v5}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    :goto_1
    iget-object v3, p0, Lorg/altbeacon/beacon/BeaconManager;->mIntentScanStrategyCoordinator:Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;

    .line 94
    .line 95
    if-eqz v3, :cond_4

    .line 96
    .line 97
    const-string v2, "BeaconManager"

    .line 98
    .line 99
    const-string v3, "Using intent scan strategy"

    .line 100
    .line 101
    new-array v1, v1, [Ljava/lang/Object;

    .line 102
    .line 103
    invoke-static {v2, v3, v1}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 104
    .line 105
    .line 106
    iget-object v1, p0, Lorg/altbeacon/beacon/BeaconManager;->mIntentScanStrategyCoordinator:Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;

    .line 107
    .line 108
    invoke-virtual {v1}, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->start()V

    .line 109
    .line 110
    .line 111
    invoke-interface {p1}, Lorg/altbeacon/beacon/InternalBeaconConsumer;->onBeaconServiceConnect()V

    .line 112
    .line 113
    .line 114
    goto/16 :goto_3

    .line 115
    .line 116
    :cond_4
    iget-boolean v3, p0, Lorg/altbeacon/beacon/BeaconManager;->mScheduledScanJobsEnabled:Z

    .line 117
    .line 118
    if-eqz v3, :cond_5

    .line 119
    .line 120
    const-string v2, "BeaconManager"

    .line 121
    .line 122
    const-string v3, "Not starting beacon scanning service. Using scheduled jobs"

    .line 123
    .line 124
    new-array v1, v1, [Ljava/lang/Object;

    .line 125
    .line 126
    invoke-static {v2, v3, v1}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 127
    .line 128
    .line 129
    invoke-interface {p1}, Lorg/altbeacon/beacon/InternalBeaconConsumer;->onBeaconServiceConnect()V

    .line 130
    .line 131
    .line 132
    goto/16 :goto_3

    .line 133
    .line 134
    :cond_5
    const-string v3, "BeaconManager"

    .line 135
    .line 136
    const-string v4, "Using BeaconService to scan. Binding to service"

    .line 137
    .line 138
    new-array v5, v1, [Ljava/lang/Object;

    .line 139
    .line 140
    invoke-static {v3, v4, v5}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 141
    .line 142
    .line 143
    new-instance v3, Landroid/content/Intent;

    .line 144
    .line 145
    invoke-interface {p1}, Lorg/altbeacon/beacon/InternalBeaconConsumer;->getApplicationContext()Landroid/content/Context;

    .line 146
    .line 147
    .line 148
    move-result-object v4

    .line 149
    const-class v5, Lorg/altbeacon/beacon/service/BeaconService;

    .line 150
    .line 151
    invoke-direct {v3, v4, v5}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 152
    .line 153
    .line 154
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->getForegroundServiceNotification()Landroid/app/Notification;

    .line 155
    .line 156
    .line 157
    move-result-object v4

    .line 158
    const/4 v5, 0x1

    .line 159
    if-eqz v4, :cond_8

    .line 160
    .line 161
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->isAnyConsumerBound()Z

    .line 162
    .line 163
    .line 164
    move-result v4

    .line 165
    if-eqz v4, :cond_6

    .line 166
    .line 167
    iget-boolean v4, p0, Lorg/altbeacon/beacon/BeaconManager;->mScheduledScanJobsEnabledByFallback:Z

    .line 168
    .line 169
    if-nez v4, :cond_6

    .line 170
    .line 171
    const-string v4, "BeaconManager"

    .line 172
    .line 173
    const-string v6, "Not starting foreground beacon scanning service.  A consumer is already bound, so it should be started"

    .line 174
    .line 175
    new-array v1, v1, [Ljava/lang/Object;

    .line 176
    .line 177
    invoke-static {v4, v6, v1}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 178
    .line 179
    .line 180
    goto :goto_2

    .line 181
    :cond_6
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->verifyLocationPermissionGrantedForForegroundService()V

    .line 182
    .line 183
    .line 184
    const-string v4, "BeaconManager"

    .line 185
    .line 186
    const-string v6, "Attempting to starting foreground beacon scanning service."

    .line 187
    .line 188
    new-array v7, v1, [Ljava/lang/Object;

    .line 189
    .line 190
    invoke-static {v4, v6, v7}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 191
    .line 192
    .line 193
    :try_start_1
    iget-object v4, p0, Lorg/altbeacon/beacon/BeaconManager;->mContext:Landroid/content/Context;

    .line 194
    .line 195
    invoke-virtual {v4, v3}, Landroid/content/Context;->startForegroundService(Landroid/content/Intent;)Landroid/content/ComponentName;

    .line 196
    .line 197
    .line 198
    iget-boolean v4, p0, Lorg/altbeacon/beacon/BeaconManager;->mScheduledScanJobsEnabledByFallback:Z

    .line 199
    .line 200
    if-eqz v4, :cond_7

    .line 201
    .line 202
    const-string v4, "BeaconManager"

    .line 203
    .line 204
    const-string v6, "Successfully switched to foreground service from fallback"

    .line 205
    .line 206
    new-array v7, v1, [Ljava/lang/Object;

    .line 207
    .line 208
    invoke-static {v4, v6, v7}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 209
    .line 210
    .line 211
    iput-boolean v1, p0, Lorg/altbeacon/beacon/BeaconManager;->mScheduledScanJobsEnabledByFallback:Z

    .line 212
    .line 213
    invoke-static {}, Lorg/altbeacon/beacon/service/ScanJobScheduler;->getInstance()Lorg/altbeacon/beacon/service/ScanJobScheduler;

    .line 214
    .line 215
    .line 216
    move-result-object v4

    .line 217
    iget-object v6, p0, Lorg/altbeacon/beacon/BeaconManager;->mContext:Landroid/content/Context;

    .line 218
    .line 219
    invoke-virtual {v4, v6}, Lorg/altbeacon/beacon/service/ScanJobScheduler;->cancelSchedule(Landroid/content/Context;)V

    .line 220
    .line 221
    .line 222
    goto :goto_2

    .line 223
    :cond_7
    const-string v4, "BeaconManager"

    .line 224
    .line 225
    const-string v6, "successfully started foreground beacon scanning service."

    .line 226
    .line 227
    new-array v7, v1, [Ljava/lang/Object;

    .line 228
    .line 229
    invoke-static {v4, v6, v7}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_1
    .catch Landroid/app/ServiceStartNotAllowedException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 230
    .line 231
    .line 232
    goto :goto_2

    .line 233
    :catch_0
    :try_start_2
    const-string p1, "BeaconManager"

    .line 234
    .line 235
    const-string v2, "Foreground service blocked by ServiceStartNotAllowedException.  Falling back to job scheduler"

    .line 236
    .line 237
    new-array v1, v1, [Ljava/lang/Object;

    .line 238
    .line 239
    invoke-static {p1, v2, v1}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 240
    .line 241
    .line 242
    iput-boolean v5, p0, Lorg/altbeacon/beacon/BeaconManager;->mScheduledScanJobsEnabledByFallback:Z

    .line 243
    .line 244
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->syncSettingsToService()V

    .line 245
    .line 246
    .line 247
    monitor-exit v0

    .line 248
    return-void

    .line 249
    :cond_8
    :goto_2
    iget-object v1, v2, Lorg/altbeacon/beacon/BeaconManager$ConsumerInfo;->beaconServiceConnection:Lorg/altbeacon/beacon/BeaconManager$BeaconServiceConnection;

    .line 250
    .line 251
    invoke-interface {p1, v3, v1, v5}, Lorg/altbeacon/beacon/InternalBeaconConsumer;->bindService(Landroid/content/Intent;Landroid/content/ServiceConnection;I)Z

    .line 252
    .line 253
    .line 254
    :goto_3
    const-string p1, "BeaconManager"

    .line 255
    .line 256
    const-string v1, "consumer count is now: %s"

    .line 257
    .line 258
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->consumers:Ljava/util/concurrent/ConcurrentMap;

    .line 259
    .line 260
    invoke-interface {p0}, Ljava/util/Map;->size()I

    .line 261
    .line 262
    .line 263
    move-result p0

    .line 264
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 265
    .line 266
    .line 267
    move-result-object p0

    .line 268
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 269
    .line 270
    .line 271
    move-result-object p0

    .line 272
    invoke-static {p1, v1, p0}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 273
    .line 274
    .line 275
    :goto_4
    monitor-exit v0

    .line 276
    return-void

    .line 277
    :goto_5
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 278
    throw p0
.end method

.method public checkAvailability()Z
    .locals 1
    .annotation build Landroid/annotation/TargetApi;
        value = 0x12
    .end annotation

    .line 1
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->isBleAvailableOrSimulated()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->mContext:Landroid/content/Context;

    .line 8
    .line 9
    const-string v0, "bluetooth"

    .line 10
    .line 11
    invoke-virtual {p0, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    check-cast p0, Landroid/bluetooth/BluetoothManager;

    .line 16
    .line 17
    invoke-virtual {p0}, Landroid/bluetooth/BluetoothManager;->getAdapter()Landroid/bluetooth/BluetoothAdapter;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    invoke-virtual {p0}, Landroid/bluetooth/BluetoothAdapter;->isEnabled()Z

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    return p0

    .line 26
    :cond_0
    new-instance p0, Lorg/altbeacon/beacon/BleNotAvailableException;

    .line 27
    .line 28
    const-string v0, "Bluetooth LE not supported by this device"

    .line 29
    .line 30
    invoke-direct {p0, v0}, Lorg/altbeacon/beacon/BleNotAvailableException;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    throw p0
.end method

.method public checkIfMainProcess()V
    .locals 6

    .line 1
    new-instance v0, Lorg/altbeacon/beacon/utils/ProcessUtils;

    .line 2
    .line 3
    iget-object v1, p0, Lorg/altbeacon/beacon/BeaconManager;->mContext:Landroid/content/Context;

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lorg/altbeacon/beacon/utils/ProcessUtils;-><init>(Landroid/content/Context;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lorg/altbeacon/beacon/utils/ProcessUtils;->getProcessName()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    invoke-virtual {v0}, Lorg/altbeacon/beacon/utils/ProcessUtils;->getPackageName()Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    invoke-virtual {v0}, Lorg/altbeacon/beacon/utils/ProcessUtils;->getPid()I

    .line 17
    .line 18
    .line 19
    move-result v3

    .line 20
    invoke-virtual {v0}, Lorg/altbeacon/beacon/utils/ProcessUtils;->isMainProcess()Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    iput-boolean v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mMainProcess:Z

    .line 25
    .line 26
    const-string v0, " named \'"

    .line 27
    .line 28
    const-string v4, "\' for application package \'"

    .line 29
    .line 30
    const-string v5, "BeaconManager started up on pid "

    .line 31
    .line 32
    invoke-static {v5, v3, v0, v1, v4}, Lf2/m0;->o(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    const-string v1, "\'.  isMainProcess="

    .line 40
    .line 41
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    iget-boolean p0, p0, Lorg/altbeacon/beacon/BeaconManager;->mMainProcess:Z

    .line 45
    .line 46
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    const/4 v0, 0x0

    .line 54
    new-array v0, v0, [Ljava/lang/Object;

    .line 55
    .line 56
    const-string v1, "BeaconManager"

    .line 57
    .line 58
    invoke-static {v1, p0, v0}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    return-void
.end method

.method public disableForegroundServiceScanning()V
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    new-array v0, v0, [Ljava/lang/Object;

    .line 3
    .line 4
    const-string v1, "BeaconManager"

    .line 5
    .line 6
    const-string v2, "API disableForegroundServiceScanning"

    .line 7
    .line 8
    invoke-static {v1, v2, v0}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->isAnyConsumerBound()Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    const/4 v0, 0x0

    .line 18
    iput-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mForegroundServiceNotification:Landroid/app/Notification;

    .line 19
    .line 20
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->setScheduledScanJobsEnabledDefault()V

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 25
    .line 26
    const-string v0, "May not be called after consumers are already bound"

    .line 27
    .line 28
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    throw p0
.end method

.method public enableForegroundServiceScanning(Landroid/app/Notification;I)V
    .locals 4

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "API enableForegroundServiceScanning "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const/4 v1, 0x0

    .line 16
    new-array v2, v1, [Ljava/lang/Object;

    .line 17
    .line 18
    const-string v3, "BeaconManager"

    .line 19
    .line 20
    invoke-static {v3, v0, v2}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->isAnyConsumerBound()Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-nez v0, :cond_1

    .line 28
    .line 29
    if-eqz p1, :cond_0

    .line 30
    .line 31
    invoke-virtual {p0, v1}, Lorg/altbeacon/beacon/BeaconManager;->setEnableScheduledScanJobs(Z)V

    .line 32
    .line 33
    .line 34
    iput-object p1, p0, Lorg/altbeacon/beacon/BeaconManager;->mForegroundServiceNotification:Landroid/app/Notification;

    .line 35
    .line 36
    iput p2, p0, Lorg/altbeacon/beacon/BeaconManager;->mForegroundServiceNotificationId:I

    .line 37
    .line 38
    return-void

    .line 39
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    .line 40
    .line 41
    const-string p1, "Notification cannot be null"

    .line 42
    .line 43
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    throw p0

    .line 47
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 48
    .line 49
    const-string p1, "May not be called after consumers are already bound."

    .line 50
    .line 51
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw p0
.end method

.method public foregroundServiceStartFailed()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/altbeacon/beacon/BeaconManager;->mScheduledScanJobsEnabledByFallback:Z

    .line 2
    .line 3
    return p0
.end method

.method public getActiveSettings()Lorg/altbeacon/beacon/AppliedSettings;
    .locals 1

    .line 1
    sget-object v0, Lorg/altbeacon/beacon/AppliedSettings;->Companion:Lorg/altbeacon/beacon/AppliedSettings$Companion;

    .line 2
    .line 3
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->settings:Lorg/altbeacon/beacon/AppliedSettings;

    .line 4
    .line 5
    invoke-virtual {v0, p0}, Lorg/altbeacon/beacon/AppliedSettings$Companion;->fromSettings(Lorg/altbeacon/beacon/AppliedSettings;)Lorg/altbeacon/beacon/AppliedSettings;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public getBackgroundBetweenScanPeriod()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lorg/altbeacon/beacon/BeaconManager;->backgroundBetweenScanPeriod:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public getBackgroundMode()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/altbeacon/beacon/BeaconManager;->mBackgroundMode:Z

    .line 2
    .line 3
    return p0
.end method

.method public getBackgroundScanPeriod()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lorg/altbeacon/beacon/BeaconManager;->backgroundScanPeriod:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public getBeaconParsers()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lorg/altbeacon/beacon/BeaconParser;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->beaconParsers:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public getDataRequestNotifier()Lorg/altbeacon/beacon/RangeNotifier;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->dataRequestNotifier:Lorg/altbeacon/beacon/RangeNotifier;

    .line 2
    .line 3
    return-object p0
.end method

.method public getForegroundBetweenScanPeriod()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lorg/altbeacon/beacon/BeaconManager;->foregroundBetweenScanPeriod:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public getForegroundScanPeriod()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lorg/altbeacon/beacon/BeaconManager;->foregroundScanPeriod:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public getForegroundServiceNotification()Landroid/app/Notification;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->mForegroundServiceNotification:Landroid/app/Notification;

    .line 2
    .line 3
    return-object p0
.end method

.method public getForegroundServiceNotificationId()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/altbeacon/beacon/BeaconManager;->mForegroundServiceNotificationId:I

    .line 2
    .line 3
    return p0
.end method

.method public getIntentScanStrategyCoordinator()Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->mIntentScanStrategyCoordinator:Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;

    .line 2
    .line 3
    return-object p0
.end method

.method public getMonitoredRegions()Ljava/util/Collection;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Collection<",
            "Lorg/altbeacon/beacon/Region;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->mContext:Landroid/content/Context;

    .line 2
    .line 3
    invoke-static {p0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/service/MonitoringStatus;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->getActiveRegions()Ljava/util/Set;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public getMonitoringNotifier()Lorg/altbeacon/beacon/MonitorNotifier;
    .locals 1
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->monitorNotifiers:Ljava/util/Set;

    .line 2
    .line 3
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    check-cast p0, Lorg/altbeacon/beacon/MonitorNotifier;

    .line 18
    .line 19
    return-object p0

    .line 20
    :cond_0
    const/4 p0, 0x0

    .line 21
    return-object p0
.end method

.method public getMonitoringNotifiers()Ljava/util/Set;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Set<",
            "Lorg/altbeacon/beacon/MonitorNotifier;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->monitorNotifiers:Ljava/util/Set;

    .line 2
    .line 3
    invoke-static {p0}, Ljava/util/Collections;->unmodifiableSet(Ljava/util/Set;)Ljava/util/Set;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getNonBeaconLeScanCallback()Lorg/altbeacon/beacon/service/scanner/NonBeaconLeScanCallback;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->mNonBeaconLeScanCallback:Lorg/altbeacon/beacon/service/scanner/NonBeaconLeScanCallback;

    .line 2
    .line 3
    return-object p0
.end method

.method public getRangedRegions()Ljava/util/Collection;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Collection<",
            "Lorg/altbeacon/beacon/Region;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->rangedRegions:Ljava/util/Set;

    .line 2
    .line 3
    invoke-static {p0}, Ljava/util/Collections;->unmodifiableSet(Ljava/util/Set;)Ljava/util/Set;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getRangingNotifier()Lorg/altbeacon/beacon/RangeNotifier;
    .locals 1
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->rangeNotifiers:Ljava/util/Set;

    .line 2
    .line 3
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    check-cast p0, Lorg/altbeacon/beacon/RangeNotifier;

    .line 18
    .line 19
    return-object p0

    .line 20
    :cond_0
    const/4 p0, 0x0

    .line 21
    return-object p0
.end method

.method public getRangingNotifiers()Ljava/util/Set;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Set<",
            "Lorg/altbeacon/beacon/RangeNotifier;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->rangeNotifiers:Ljava/util/Set;

    .line 2
    .line 3
    invoke-static {p0}, Ljava/util/Collections;->unmodifiableSet(Ljava/util/Set;)Ljava/util/Set;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getRegionViewModel(Lorg/altbeacon/beacon/Region;)Lorg/altbeacon/beacon/RegionViewModel;
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mRegionViewModels:Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lorg/altbeacon/beacon/RegionViewModel;

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    return-object v0

    .line 12
    :cond_0
    new-instance v0, Lorg/altbeacon/beacon/RegionViewModel;

    .line 13
    .line 14
    invoke-direct {v0}, Lorg/altbeacon/beacon/RegionViewModel;-><init>()V

    .line 15
    .line 16
    .line 17
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->mRegionViewModels:Ljava/util/HashMap;

    .line 18
    .line 19
    invoke-virtual {p0, p1, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    return-object v0
.end method

.method public getScheduledScanJobsEnabled()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/altbeacon/beacon/BeaconManager;->mScheduledScanJobsEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public handleStategyFailover()V
    .locals 5

    .line 1
    iget-boolean v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mScheduledScanJobsEnabledByFallback:Z

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    const/4 v2, 0x0

    .line 5
    if-eqz v0, :cond_1

    .line 6
    .line 7
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->isAnyConsumerBound()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    move v0, v1

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    iput-boolean v2, p0, Lorg/altbeacon/beacon/BeaconManager;->mScheduledScanJobsEnabledByFallback:Z

    .line 16
    .line 17
    :cond_1
    move v0, v2

    .line 18
    :goto_0
    iget-object v3, p0, Lorg/altbeacon/beacon/BeaconManager;->mIntentScanStrategyCoordinator:Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;

    .line 19
    .line 20
    if-eqz v3, :cond_2

    .line 21
    .line 22
    invoke-virtual {v3}, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->getDisableOnFailure()Z

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    if-eqz v3, :cond_2

    .line 27
    .line 28
    iget-object v3, p0, Lorg/altbeacon/beacon/BeaconManager;->mIntentScanStrategyCoordinator:Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;

    .line 29
    .line 30
    invoke-virtual {v3}, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->getLastStrategyFailureDetectionCount()I

    .line 31
    .line 32
    .line 33
    move-result v3

    .line 34
    if-lez v3, :cond_2

    .line 35
    .line 36
    const/4 v0, 0x0

    .line 37
    iput-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mIntentScanStrategyCoordinator:Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;

    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_2
    move v1, v0

    .line 41
    :goto_1
    if-eqz v1, :cond_5

    .line 42
    .line 43
    const-string v0, "unbinding all consumers for stategy failover"

    .line 44
    .line 45
    new-array v1, v2, [Ljava/lang/Object;

    .line 46
    .line 47
    const-string v3, "BeaconManager"

    .line 48
    .line 49
    invoke-static {v3, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    new-instance v0, Ljava/util/ArrayList;

    .line 53
    .line 54
    iget-object v1, p0, Lorg/altbeacon/beacon/BeaconManager;->consumers:Ljava/util/concurrent/ConcurrentMap;

    .line 55
    .line 56
    invoke-interface {v1}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 61
    .line 62
    .line 63
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    :goto_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 68
    .line 69
    .line 70
    move-result v4

    .line 71
    if-eqz v4, :cond_3

    .line 72
    .line 73
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v4

    .line 77
    check-cast v4, Lorg/altbeacon/beacon/InternalBeaconConsumer;

    .line 78
    .line 79
    invoke-virtual {p0, v4}, Lorg/altbeacon/beacon/BeaconManager;->unbindInternal(Lorg/altbeacon/beacon/InternalBeaconConsumer;)V

    .line 80
    .line 81
    .line 82
    goto :goto_2

    .line 83
    :cond_3
    const-string v1, "binding all consumers for strategy failover"

    .line 84
    .line 85
    new-array v4, v2, [Ljava/lang/Object;

    .line 86
    .line 87
    invoke-static {v3, v1, v4}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 88
    .line 89
    .line 90
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 91
    .line 92
    .line 93
    move-result-object v0

    .line 94
    :goto_3
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 95
    .line 96
    .line 97
    move-result v1

    .line 98
    if-eqz v1, :cond_4

    .line 99
    .line 100
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v1

    .line 104
    check-cast v1, Lorg/altbeacon/beacon/InternalBeaconConsumer;

    .line 105
    .line 106
    invoke-virtual {p0, v1}, Lorg/altbeacon/beacon/BeaconManager;->bindInternal(Lorg/altbeacon/beacon/InternalBeaconConsumer;)V

    .line 107
    .line 108
    .line 109
    goto :goto_3

    .line 110
    :cond_4
    const-string p0, "Done with failover"

    .line 111
    .line 112
    new-array v0, v2, [Ljava/lang/Object;

    .line 113
    .line 114
    invoke-static {v3, p0, v0}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 115
    .line 116
    .line 117
    :cond_5
    return-void
.end method

.method public isAnyConsumerBound()Z
    .locals 2

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->consumers:Ljava/util/concurrent/ConcurrentMap;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lorg/altbeacon/beacon/BeaconManager;->consumers:Ljava/util/concurrent/ConcurrentMap;

    .line 5
    .line 6
    invoke-interface {v1}, Ljava/util/Map;->isEmpty()Z

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    if-nez v1, :cond_1

    .line 11
    .line 12
    iget-object v1, p0, Lorg/altbeacon/beacon/BeaconManager;->mIntentScanStrategyCoordinator:Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;

    .line 13
    .line 14
    if-nez v1, :cond_0

    .line 15
    .line 16
    iget-boolean v1, p0, Lorg/altbeacon/beacon/BeaconManager;->mScheduledScanJobsEnabled:Z

    .line 17
    .line 18
    if-nez v1, :cond_0

    .line 19
    .line 20
    iget-boolean v1, p0, Lorg/altbeacon/beacon/BeaconManager;->mScheduledScanJobsEnabledByFallback:Z

    .line 21
    .line 22
    if-nez v1, :cond_0

    .line 23
    .line 24
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->serviceMessenger:Landroid/os/Messenger;

    .line 25
    .line 26
    if-eqz p0, :cond_1

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :catchall_0
    move-exception p0

    .line 30
    goto :goto_2

    .line 31
    :cond_0
    :goto_0
    const/4 p0, 0x1

    .line 32
    goto :goto_1

    .line 33
    :cond_1
    const/4 p0, 0x0

    .line 34
    :goto_1
    monitor-exit v0

    .line 35
    return p0

    .line 36
    :goto_2
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 37
    throw p0
.end method

.method public isAutoBindActive()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->autoBindConsumer:Lorg/altbeacon/beacon/BeaconConsumer;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method

.method public isBackgroundModeUninitialized()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/altbeacon/beacon/BeaconManager;->mBackgroundModeUninitialized:Z

    .line 2
    .line 3
    return p0
.end method

.method public isBound(Lorg/altbeacon/beacon/BeaconConsumer;)Z
    .locals 2
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->consumers:Ljava/util/concurrent/ConcurrentMap;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    if-eqz p1, :cond_1

    .line 5
    .line 6
    :try_start_0
    iget-object v1, p0, Lorg/altbeacon/beacon/BeaconManager;->consumers:Ljava/util/concurrent/ConcurrentMap;

    .line 7
    .line 8
    invoke-interface {v1, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    if-eqz p1, :cond_1

    .line 13
    .line 14
    iget-boolean p1, p0, Lorg/altbeacon/beacon/BeaconManager;->mScheduledScanJobsEnabled:Z

    .line 15
    .line 16
    if-nez p1, :cond_0

    .line 17
    .line 18
    iget-boolean p1, p0, Lorg/altbeacon/beacon/BeaconManager;->mScheduledScanJobsEnabledByFallback:Z

    .line 19
    .line 20
    if-nez p1, :cond_0

    .line 21
    .line 22
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->serviceMessenger:Landroid/os/Messenger;

    .line 23
    .line 24
    if-eqz p0, :cond_1

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :catchall_0
    move-exception p0

    .line 28
    goto :goto_2

    .line 29
    :cond_0
    :goto_0
    const/4 p0, 0x1

    .line 30
    goto :goto_1

    .line 31
    :cond_1
    const/4 p0, 0x0

    .line 32
    :goto_1
    monitor-exit v0

    .line 33
    return p0

    .line 34
    :goto_2
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 35
    throw p0
.end method

.method public isMainProcess()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/altbeacon/beacon/BeaconManager;->mMainProcess:Z

    .line 2
    .line 3
    return p0
.end method

.method public isRegionStatePersistenceEnabled()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/altbeacon/beacon/BeaconManager;->mRegionStatePersistenceEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public isRegionViewModelInitialized(Lorg/altbeacon/beacon/Region;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->mRegionViewModels:Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x1

    .line 10
    return p0

    .line 11
    :cond_0
    const/4 p0, 0x0

    .line 12
    return p0
.end method

.method public isScannerInDifferentProcess()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->mScannerInSameProcess:Ljava/lang/Boolean;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    if-nez p0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0
.end method

.method public removeAllMonitorNotifiers()V
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    new-array v0, v0, [Ljava/lang/Object;

    .line 3
    .line 4
    const-string v1, "BeaconManager"

    .line 5
    .line 6
    const-string v2, "API removeAllMonitorNotifiers"

    .line 7
    .line 8
    invoke-static {v1, v2, v0}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->determineIfCalledFromSeparateScannerProcess()Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->monitorNotifiers:Ljava/util/Set;

    .line 19
    .line 20
    invoke-interface {p0}, Ljava/util/Set;->clear()V

    .line 21
    .line 22
    .line 23
    return-void
.end method

.method public removeAllRangeNotifiers()V
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    new-array v0, v0, [Ljava/lang/Object;

    .line 3
    .line 4
    const-string v1, "BeaconManager"

    .line 5
    .line 6
    const-string v2, "API removeAllRangeNotifiers"

    .line 7
    .line 8
    invoke-static {v1, v2, v0}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->rangeNotifiers:Ljava/util/Set;

    .line 12
    .line 13
    invoke-interface {p0}, Ljava/util/Set;->clear()V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public removeMonitorNotifier(Lorg/altbeacon/beacon/MonitorNotifier;)Z
    .locals 4

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "API removeMonitorNotifier "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const/4 v1, 0x0

    .line 16
    new-array v2, v1, [Ljava/lang/Object;

    .line 17
    .line 18
    const-string v3, "BeaconManager"

    .line 19
    .line 20
    invoke-static {v3, v0, v2}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->determineIfCalledFromSeparateScannerProcess()Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    return v1

    .line 30
    :cond_0
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->monitorNotifiers:Ljava/util/Set;

    .line 31
    .line 32
    invoke-interface {p0, p1}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    return p0
.end method

.method public removeMonitoreNotifier(Lorg/altbeacon/beacon/MonitorNotifier;)Z
    .locals 0
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    invoke-virtual {p0, p1}, Lorg/altbeacon/beacon/BeaconManager;->removeMonitorNotifier(Lorg/altbeacon/beacon/MonitorNotifier;)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public removeRangeNotifier(Lorg/altbeacon/beacon/RangeNotifier;)Z
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "API removeRangeNotifier "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const/4 v1, 0x0

    .line 16
    new-array v1, v1, [Ljava/lang/Object;

    .line 17
    .line 18
    const-string v2, "BeaconManager"

    .line 19
    .line 20
    invoke-static {v2, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->rangeNotifiers:Ljava/util/Set;

    .line 24
    .line 25
    invoke-interface {p0, p1}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    return p0
.end method

.method public replaceSettings(Lorg/altbeacon/beacon/Settings;)V
    .locals 2

    .line 1
    sget-object v0, Lorg/altbeacon/beacon/AppliedSettings;->Companion:Lorg/altbeacon/beacon/AppliedSettings$Companion;

    .line 2
    .line 3
    iget-object v1, p0, Lorg/altbeacon/beacon/BeaconManager;->settings:Lorg/altbeacon/beacon/AppliedSettings;

    .line 4
    .line 5
    invoke-virtual {v0, v1, p1}, Lorg/altbeacon/beacon/AppliedSettings$Companion;->fromDeltaSettings(Lorg/altbeacon/beacon/AppliedSettings;Lorg/altbeacon/beacon/Settings;)Lorg/altbeacon/beacon/AppliedSettings;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    invoke-direct {p0, p1}, Lorg/altbeacon/beacon/BeaconManager;->applySettingsChange(Lorg/altbeacon/beacon/AppliedSettings;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public requestStateForRegion(Lorg/altbeacon/beacon/Region;)V
    .locals 4

    .line 1
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->determineIfCalledFromSeparateScannerProcess()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    goto :goto_1

    .line 8
    :cond_0
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mIntentScanStrategyCoordinator:Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;

    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    if-eqz v0, :cond_1

    .line 12
    .line 13
    const-string v0, "Forcing IntentScanStrategyCoordinator to update state on requestStateForRegion"

    .line 14
    .line 15
    new-array v2, v1, [Ljava/lang/Object;

    .line 16
    .line 17
    const-string v3, "BeaconManager"

    .line 18
    .line 19
    invoke-static {v3, v0, v2}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mIntentScanStrategyCoordinator:Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;

    .line 23
    .line 24
    new-instance v2, Ljava/util/ArrayList;

    .line 25
    .line 26
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0, v2}, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->processScanResults(Ljava/util/ArrayList;)V

    .line 30
    .line 31
    .line 32
    :cond_1
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mContext:Landroid/content/Context;

    .line 33
    .line 34
    invoke-static {v0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/service/MonitoringStatus;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    invoke-virtual {v0, p1}, Lorg/altbeacon/beacon/service/MonitoringStatus;->stateOf(Lorg/altbeacon/beacon/Region;)Lorg/altbeacon/beacon/service/RegionMonitoringState;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    if-eqz v0, :cond_2

    .line 43
    .line 44
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/RegionMonitoringState;->getInside()Z

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    if-eqz v0, :cond_2

    .line 49
    .line 50
    const/4 v1, 0x1

    .line 51
    :cond_2
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->monitorNotifiers:Ljava/util/Set;

    .line 52
    .line 53
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 58
    .line 59
    .line 60
    move-result v0

    .line 61
    if-eqz v0, :cond_3

    .line 62
    .line 63
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    check-cast v0, Lorg/altbeacon/beacon/MonitorNotifier;

    .line 68
    .line 69
    invoke-interface {v0, v1, p1}, Lorg/altbeacon/beacon/MonitorNotifier;->didDetermineStateForRegion(ILorg/altbeacon/beacon/Region;)V

    .line 70
    .line 71
    .line 72
    goto :goto_0

    .line 73
    :cond_3
    :goto_1
    return-void
.end method

.method public retryForegroundServiceScanning()V
    .locals 1

    .line 1
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->foregroundServiceStartFailed()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->handleStategyFailover()V

    .line 8
    .line 9
    .line 10
    :cond_0
    return-void
.end method

.method public revertSettings()V
    .locals 1

    .line 1
    sget-object v0, Lorg/altbeacon/beacon/AppliedSettings;->Companion:Lorg/altbeacon/beacon/AppliedSettings$Companion;

    .line 2
    .line 3
    invoke-virtual {v0}, Lorg/altbeacon/beacon/AppliedSettings$Companion;->withDefaultValues()Lorg/altbeacon/beacon/AppliedSettings;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-direct {p0, v0}, Lorg/altbeacon/beacon/BeaconManager;->applySettingsChange(Lorg/altbeacon/beacon/AppliedSettings;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public setBackgroundBetweenScanPeriod(J)V
    .locals 3

    .line 1
    const-string v0, "API setBackgroundBetweenScanPeriod "

    .line 2
    .line 3
    invoke-static {p1, p2, v0}, Lp3/m;->f(JLjava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const/4 v1, 0x0

    .line 8
    new-array v1, v1, [Ljava/lang/Object;

    .line 9
    .line 10
    const-string v2, "BeaconManager"

    .line 11
    .line 12
    invoke-static {v2, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    iput-wide p1, p0, Lorg/altbeacon/beacon/BeaconManager;->backgroundBetweenScanPeriod:J

    .line 16
    .line 17
    return-void
.end method

.method public setBackgroundMode(Z)V
    .locals 3
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "API setBackgroundMode "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const/4 v1, 0x0

    .line 16
    new-array v1, v1, [Ljava/lang/Object;

    .line 17
    .line 18
    const-string v2, "BeaconManager"

    .line 19
    .line 20
    invoke-static {v2, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p0, p1}, Lorg/altbeacon/beacon/BeaconManager;->setBackgroundModeInternal(Z)V

    .line 24
    .line 25
    .line 26
    return-void
.end method

.method public setBackgroundModeInternal(Z)V
    .locals 4

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "API setBackgroundModeIternal "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const/4 v1, 0x0

    .line 16
    new-array v2, v1, [Ljava/lang/Object;

    .line 17
    .line 18
    const-string v3, "BeaconManager"

    .line 19
    .line 20
    invoke-static {v3, v0, v2}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->isBleAvailableOrSimulated()Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-nez v0, :cond_0

    .line 28
    .line 29
    const-string p0, "Method invocation will be ignored."

    .line 30
    .line 31
    new-array p1, v1, [Ljava/lang/Object;

    .line 32
    .line 33
    invoke-static {v3, p0, p1}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    return-void

    .line 37
    :cond_0
    iput-boolean v1, p0, Lorg/altbeacon/beacon/BeaconManager;->mBackgroundModeUninitialized:Z

    .line 38
    .line 39
    iget-boolean v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mBackgroundMode:Z

    .line 40
    .line 41
    if-eq p1, v0, :cond_2

    .line 42
    .line 43
    if-nez p1, :cond_1

    .line 44
    .line 45
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->getIntentScanStrategyCoordinator()Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    if-eqz v0, :cond_1

    .line 50
    .line 51
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->getIntentScanStrategyCoordinator()Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    iget-object v2, p0, Lorg/altbeacon/beacon/BeaconManager;->mContext:Landroid/content/Context;

    .line 56
    .line 57
    invoke-virtual {v0, v2}, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->performPeriodicProcessing(Landroid/content/Context;)V

    .line 58
    .line 59
    .line 60
    :cond_1
    iput-boolean p1, p0, Lorg/altbeacon/beacon/BeaconManager;->mBackgroundMode:Z

    .line 61
    .line 62
    :try_start_0
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->updateScanPeriods()V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 63
    .line 64
    .line 65
    return-void

    .line 66
    :catch_0
    const-string p0, "Cannot contact service to set scan periods"

    .line 67
    .line 68
    new-array p1, v1, [Ljava/lang/Object;

    .line 69
    .line 70
    invoke-static {v3, p0, p1}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    :cond_2
    return-void
.end method

.method public setBackgroundScanPeriod(J)V
    .locals 3

    .line 1
    const-string v0, "API setBackgroundScanPeriod "

    .line 2
    .line 3
    invoke-static {p1, p2, v0}, Lp3/m;->f(JLjava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const/4 v1, 0x0

    .line 8
    new-array v1, v1, [Ljava/lang/Object;

    .line 9
    .line 10
    const-string v2, "BeaconManager"

    .line 11
    .line 12
    invoke-static {v2, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    iput-wide p1, p0, Lorg/altbeacon/beacon/BeaconManager;->backgroundScanPeriod:J

    .line 16
    .line 17
    return-void
.end method

.method public setDataRequestNotifier(Lorg/altbeacon/beacon/RangeNotifier;)V
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "API setDataRequestNotifier "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const/4 v1, 0x0

    .line 16
    new-array v1, v1, [Ljava/lang/Object;

    .line 17
    .line 18
    const-string v2, "BeaconManager"

    .line 19
    .line 20
    invoke-static {v2, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    iput-object p1, p0, Lorg/altbeacon/beacon/BeaconManager;->dataRequestNotifier:Lorg/altbeacon/beacon/RangeNotifier;

    .line 24
    .line 25
    return-void
.end method

.method public setEnableScheduledScanJobs(Z)V
    .locals 4

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "API setEnableScheduledScanJobs "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const/4 v1, 0x0

    .line 16
    new-array v2, v1, [Ljava/lang/Object;

    .line 17
    .line 18
    const-string v3, "BeaconManager"

    .line 19
    .line 20
    invoke-static {v3, v0, v2}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->isAnyConsumerBound()Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-nez v0, :cond_2

    .line 28
    .line 29
    if-eqz p1, :cond_0

    .line 30
    .line 31
    iput-boolean v1, p0, Lorg/altbeacon/beacon/BeaconManager;->mScheduledScanJobsEnabledByFallback:Z

    .line 32
    .line 33
    :cond_0
    iput-boolean p1, p0, Lorg/altbeacon/beacon/BeaconManager;->mScheduledScanJobsEnabled:Z

    .line 34
    .line 35
    if-nez p1, :cond_1

    .line 36
    .line 37
    iget-boolean p1, p0, Lorg/altbeacon/beacon/BeaconManager;->mScheduledScanJobsEnabledByFallback:Z

    .line 38
    .line 39
    if-nez p1, :cond_1

    .line 40
    .line 41
    invoke-static {}, Lorg/altbeacon/beacon/service/ScanJobScheduler;->getInstance()Lorg/altbeacon/beacon/service/ScanJobScheduler;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->mContext:Landroid/content/Context;

    .line 46
    .line 47
    invoke-virtual {p1, p0}, Lorg/altbeacon/beacon/service/ScanJobScheduler;->cancelSchedule(Landroid/content/Context;)V

    .line 48
    .line 49
    .line 50
    :cond_1
    return-void

    .line 51
    :cond_2
    const-string p0, "ScanJob may not be configured because a consumer is already bound."

    .line 52
    .line 53
    new-array p1, v1, [Ljava/lang/Object;

    .line 54
    .line 55
    invoke-static {v3, p0, p1}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 59
    .line 60
    const-string p1, "Method must be called before starting ranging or monitoring"

    .line 61
    .line 62
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    throw p0
.end method

.method public setForegroundBetweenScanPeriod(J)V
    .locals 3

    .line 1
    const-string v0, "API setForegroundBetweenScanPeriod "

    .line 2
    .line 3
    invoke-static {p1, p2, v0}, Lp3/m;->f(JLjava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const/4 v1, 0x0

    .line 8
    new-array v1, v1, [Ljava/lang/Object;

    .line 9
    .line 10
    const-string v2, "BeaconManager"

    .line 11
    .line 12
    invoke-static {v2, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    iput-wide p1, p0, Lorg/altbeacon/beacon/BeaconManager;->foregroundBetweenScanPeriod:J

    .line 16
    .line 17
    return-void
.end method

.method public setForegroundScanPeriod(J)V
    .locals 3

    .line 1
    const-string v0, "API setForegroundScanPeriod "

    .line 2
    .line 3
    invoke-static {p1, p2, v0}, Lp3/m;->f(JLjava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const/4 v1, 0x0

    .line 8
    new-array v1, v1, [Ljava/lang/Object;

    .line 9
    .line 10
    const-string v2, "BeaconManager"

    .line 11
    .line 12
    invoke-static {v2, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    iput-wide p1, p0, Lorg/altbeacon/beacon/BeaconManager;->foregroundScanPeriod:J

    .line 16
    .line 17
    return-void
.end method

.method public setIntentScanningStrategyEnabled(Z)V
    .locals 4

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "API setIntentScanningStrategyEnabled "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const/4 v1, 0x0

    .line 16
    new-array v2, v1, [Ljava/lang/Object;

    .line 17
    .line 18
    const-string v3, "BeaconManager"

    .line 19
    .line 20
    invoke-static {v3, v0, v2}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->isAnyConsumerBound()Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-nez v0, :cond_1

    .line 28
    .line 29
    if-eqz p1, :cond_0

    .line 30
    .line 31
    iput-boolean v1, p0, Lorg/altbeacon/beacon/BeaconManager;->mScheduledScanJobsEnabled:Z

    .line 32
    .line 33
    iput-boolean v1, p0, Lorg/altbeacon/beacon/BeaconManager;->mScheduledScanJobsEnabledByFallback:Z

    .line 34
    .line 35
    invoke-static {}, Lorg/altbeacon/beacon/service/ScanJobScheduler;->getInstance()Lorg/altbeacon/beacon/service/ScanJobScheduler;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mContext:Landroid/content/Context;

    .line 40
    .line 41
    invoke-virtual {p1, v0}, Lorg/altbeacon/beacon/service/ScanJobScheduler;->cancelSchedule(Landroid/content/Context;)V

    .line 42
    .line 43
    .line 44
    new-instance p1, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;

    .line 45
    .line 46
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mContext:Landroid/content/Context;

    .line 47
    .line 48
    invoke-direct {p1, v0}, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;-><init>(Landroid/content/Context;)V

    .line 49
    .line 50
    .line 51
    iput-object p1, p0, Lorg/altbeacon/beacon/BeaconManager;->mIntentScanStrategyCoordinator:Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;

    .line 52
    .line 53
    return-void

    .line 54
    :cond_0
    const/4 p1, 0x0

    .line 55
    iput-object p1, p0, Lorg/altbeacon/beacon/BeaconManager;->mIntentScanStrategyCoordinator:Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;

    .line 56
    .line 57
    return-void

    .line 58
    :cond_1
    const-string p0, "IntentScanningStrategy may not be configured because a consumer is already bound."

    .line 59
    .line 60
    new-array p1, v1, [Ljava/lang/Object;

    .line 61
    .line 62
    invoke-static {v3, p0, p1}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 66
    .line 67
    const-string p1, "Method must be called before starting ranging or monitoring"

    .line 68
    .line 69
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    throw p0
.end method

.method public setMaxTrackingAge(I)V
    .locals 2

    .line 1
    const-string p0, "API setMaxTrackingAge "

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const/4 v0, 0x0

    .line 8
    new-array v0, v0, [Ljava/lang/Object;

    .line 9
    .line 10
    const-string v1, "BeaconManager"

    .line 11
    .line 12
    invoke-static {v1, p0, v0}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    invoke-static {p1}, Lorg/altbeacon/beacon/service/RangedBeacon;->setMaxTrackinAge(I)V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public setMonitorNotifier(Lorg/altbeacon/beacon/MonitorNotifier;)V
    .locals 3
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "API setMonitorNotifier "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const/4 v1, 0x0

    .line 16
    new-array v1, v1, [Ljava/lang/Object;

    .line 17
    .line 18
    const-string v2, "BeaconManager"

    .line 19
    .line 20
    invoke-static {v2, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->determineIfCalledFromSeparateScannerProcess()Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->monitorNotifiers:Ljava/util/Set;

    .line 31
    .line 32
    invoke-interface {v0}, Ljava/util/Set;->clear()V

    .line 33
    .line 34
    .line 35
    if-eqz p1, :cond_1

    .line 36
    .line 37
    invoke-virtual {p0, p1}, Lorg/altbeacon/beacon/BeaconManager;->addMonitorNotifier(Lorg/altbeacon/beacon/MonitorNotifier;)V

    .line 38
    .line 39
    .line 40
    :cond_1
    :goto_0
    return-void
.end method

.method public setNonBeaconLeScanCallback(Lorg/altbeacon/beacon/service/scanner/NonBeaconLeScanCallback;)V
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "API setNonBeaconLeScanCallback "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const/4 v1, 0x0

    .line 16
    new-array v1, v1, [Ljava/lang/Object;

    .line 17
    .line 18
    const-string v2, "BeaconManager"

    .line 19
    .line 20
    invoke-static {v2, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    iput-object p1, p0, Lorg/altbeacon/beacon/BeaconManager;->mNonBeaconLeScanCallback:Lorg/altbeacon/beacon/service/scanner/NonBeaconLeScanCallback;

    .line 24
    .line 25
    return-void
.end method

.method public setRangeNotifier(Lorg/altbeacon/beacon/RangeNotifier;)V
    .locals 3
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "API setRangeNotifier "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const/4 v1, 0x0

    .line 16
    new-array v1, v1, [Ljava/lang/Object;

    .line 17
    .line 18
    const-string v2, "BeaconManager"

    .line 19
    .line 20
    invoke-static {v2, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->rangeNotifiers:Ljava/util/Set;

    .line 24
    .line 25
    invoke-interface {v0}, Ljava/util/Set;->clear()V

    .line 26
    .line 27
    .line 28
    if-eqz p1, :cond_0

    .line 29
    .line 30
    invoke-virtual {p0, p1}, Lorg/altbeacon/beacon/BeaconManager;->addRangeNotifier(Lorg/altbeacon/beacon/RangeNotifier;)V

    .line 31
    .line 32
    .line 33
    :cond_0
    return-void
.end method

.method public setRegionStatePeristenceEnabled(Z)V
    .locals 0
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    invoke-virtual {p0, p1}, Lorg/altbeacon/beacon/BeaconManager;->setRegionStatePersistenceEnabled(Z)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public setRegionStatePersistenceEnabled(Z)V
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "API setRegionStatePerisistenceEnabled "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const/4 v1, 0x0

    .line 16
    new-array v1, v1, [Ljava/lang/Object;

    .line 17
    .line 18
    const-string v2, "BeaconManager"

    .line 19
    .line 20
    invoke-static {v2, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    iput-boolean p1, p0, Lorg/altbeacon/beacon/BeaconManager;->mRegionStatePersistenceEnabled:Z

    .line 24
    .line 25
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->isScannerInDifferentProcess()Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-nez v0, :cond_1

    .line 30
    .line 31
    if-eqz p1, :cond_0

    .line 32
    .line 33
    iget-object p1, p0, Lorg/altbeacon/beacon/BeaconManager;->mContext:Landroid/content/Context;

    .line 34
    .line 35
    invoke-static {p1}, Lorg/altbeacon/beacon/service/MonitoringStatus;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/service/MonitoringStatus;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    invoke-virtual {p1}, Lorg/altbeacon/beacon/service/MonitoringStatus;->startStatusPreservation()V

    .line 40
    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_0
    iget-object p1, p0, Lorg/altbeacon/beacon/BeaconManager;->mContext:Landroid/content/Context;

    .line 44
    .line 45
    invoke-static {p1}, Lorg/altbeacon/beacon/service/MonitoringStatus;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/service/MonitoringStatus;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    invoke-virtual {p1}, Lorg/altbeacon/beacon/service/MonitoringStatus;->stopStatusPreservation()V

    .line 50
    .line 51
    .line 52
    :cond_1
    :goto_0
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->applySettings()V

    .line 53
    .line 54
    .line 55
    return-void
.end method

.method public setScannerInSameProcess(Z)V
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "API setScannerInSameProcess "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const/4 v1, 0x0

    .line 16
    new-array v1, v1, [Ljava/lang/Object;

    .line 17
    .line 18
    const-string v2, "BeaconManager"

    .line 19
    .line 20
    invoke-static {v2, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    iput-object p1, p0, Lorg/altbeacon/beacon/BeaconManager;->mScannerInSameProcess:Ljava/lang/Boolean;

    .line 28
    .line 29
    return-void
.end method

.method public shutdownIfIdle()Z
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->autoBindConsumer:Lorg/altbeacon/beacon/BeaconConsumer;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->rangedRegions:Ljava/util/Set;

    .line 6
    .line 7
    invoke-interface {v0}, Ljava/util/Set;->size()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->getMonitoredRegions()Ljava/util/Collection;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-nez v0, :cond_0

    .line 22
    .line 23
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->autoBindConsumer:Lorg/altbeacon/beacon/BeaconConsumer;

    .line 24
    .line 25
    if-eqz v0, :cond_0

    .line 26
    .line 27
    invoke-virtual {p0, v0}, Lorg/altbeacon/beacon/BeaconManager;->unbindInternal(Lorg/altbeacon/beacon/InternalBeaconConsumer;)V

    .line 28
    .line 29
    .line 30
    const/4 v0, 0x0

    .line 31
    iput-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->autoBindConsumer:Lorg/altbeacon/beacon/BeaconConsumer;

    .line 32
    .line 33
    const/4 p0, 0x1

    .line 34
    return p0

    .line 35
    :cond_0
    const/4 p0, 0x0

    .line 36
    return p0
.end method

.method public startMonitoring(Lorg/altbeacon/beacon/Region;)V
    .locals 3
    .annotation build Landroid/annotation/TargetApi;
        value = 0x12
    .end annotation

    .line 1
    const-string v0, "BeaconManager"

    .line 2
    .line 3
    new-instance v1, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v2, "API startMonitoring "

    .line 6
    .line 7
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    const/4 v2, 0x0

    .line 18
    new-array v2, v2, [Ljava/lang/Object;

    .line 19
    .line 20
    invoke-static {v0, v1, v2}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    iget-object v0, p1, Lorg/altbeacon/beacon/Region;->mBeaconParser:Lorg/altbeacon/beacon/BeaconParser;

    .line 24
    .line 25
    if-eqz v0, :cond_2

    .line 26
    .line 27
    invoke-virtual {v0}, Lorg/altbeacon/beacon/BeaconParser;->getIdentifier()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    if-eqz v0, :cond_2

    .line 32
    .line 33
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->getBeaconParsers()Ljava/util/List;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 42
    .line 43
    .line 44
    move-result v1

    .line 45
    if-eqz v1, :cond_1

    .line 46
    .line 47
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    check-cast v1, Lorg/altbeacon/beacon/BeaconParser;

    .line 52
    .line 53
    iget-object v2, p1, Lorg/altbeacon/beacon/Region;->mBeaconParser:Lorg/altbeacon/beacon/BeaconParser;

    .line 54
    .line 55
    invoke-virtual {v2}, Lorg/altbeacon/beacon/BeaconParser;->getIdentifier()Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object v2

    .line 59
    invoke-virtual {v1}, Lorg/altbeacon/beacon/BeaconParser;->getIdentifier()Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object v1

    .line 63
    invoke-virtual {v2, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    move-result v1

    .line 67
    if-eqz v1, :cond_0

    .line 68
    .line 69
    goto :goto_0

    .line 70
    :cond_1
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->getBeaconParsers()Ljava/util/List;

    .line 71
    .line 72
    .line 73
    move-result-object v0

    .line 74
    iget-object v1, p1, Lorg/altbeacon/beacon/Region;->mBeaconParser:Lorg/altbeacon/beacon/BeaconParser;

    .line 75
    .line 76
    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    :cond_2
    :goto_0
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->ensureBackgroundPowerSaver()V

    .line 80
    .line 81
    .line 82
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->isAnyConsumerBound()Z

    .line 83
    .line 84
    .line 85
    move-result v0

    .line 86
    if-eqz v0, :cond_3

    .line 87
    .line 88
    :try_start_0
    invoke-virtual {p0, p1}, Lorg/altbeacon/beacon/BeaconManager;->startMonitoringBeaconsInRegion(Lorg/altbeacon/beacon/Region;)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 89
    .line 90
    .line 91
    return-void

    .line 92
    :catch_0
    move-exception p0

    .line 93
    const-string p1, "BeaconManager"

    .line 94
    .line 95
    const-string v0, "Failed to start monitoring"

    .line 96
    .line 97
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    invoke-static {p1, v0, p0}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 102
    .line 103
    .line 104
    return-void

    .line 105
    :cond_3
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->autoBindMonitoredRegions:Ljava/util/Set;

    .line 106
    .line 107
    monitor-enter v0

    .line 108
    :try_start_1
    iget-object v1, p0, Lorg/altbeacon/beacon/BeaconManager;->autoBindMonitoredRegions:Ljava/util/Set;

    .line 109
    .line 110
    invoke-interface {v1, p1}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z

    .line 111
    .line 112
    .line 113
    iget-object v1, p0, Lorg/altbeacon/beacon/BeaconManager;->autoBindMonitoredRegions:Ljava/util/Set;

    .line 114
    .line 115
    invoke-interface {v1, p1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 119
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->autoBind()V

    .line 120
    .line 121
    .line 122
    return-void

    .line 123
    :catchall_0
    move-exception p0

    .line 124
    :try_start_2
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 125
    throw p0
.end method

.method public startMonitoringBeaconsInRegion(Lorg/altbeacon/beacon/Region;)V
    .locals 4
    .annotation build Landroid/annotation/TargetApi;
        value = 0x12
    .end annotation

    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "API startMonitoringBeaconsInRegion "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const/4 v1, 0x0

    .line 16
    new-array v2, v1, [Ljava/lang/Object;

    .line 17
    .line 18
    const-string v3, "BeaconManager"

    .line 19
    .line 20
    invoke-static {v3, v0, v2}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->isBleAvailableOrSimulated()Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-nez v0, :cond_0

    .line 28
    .line 29
    const-string p0, "Method invocation will be ignored."

    .line 30
    .line 31
    new-array p1, v1, [Ljava/lang/Object;

    .line 32
    .line 33
    invoke-static {v3, p0, p1}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    return-void

    .line 37
    :cond_0
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->determineIfCalledFromSeparateScannerProcess()Z

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    if-eqz v0, :cond_1

    .line 42
    .line 43
    return-void

    .line 44
    :cond_1
    new-instance v0, Lorg/altbeacon/beacon/utils/PermissionsInspector;

    .line 45
    .line 46
    iget-object v1, p0, Lorg/altbeacon/beacon/BeaconManager;->mContext:Landroid/content/Context;

    .line 47
    .line 48
    invoke-direct {v0, v1}, Lorg/altbeacon/beacon/utils/PermissionsInspector;-><init>(Landroid/content/Context;)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {v0}, Lorg/altbeacon/beacon/utils/PermissionsInspector;->hasDeclaredBluetoothScanPermissions()Z

    .line 52
    .line 53
    .line 54
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->isScannerInDifferentProcess()Z

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    if-nez v0, :cond_2

    .line 59
    .line 60
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mContext:Landroid/content/Context;

    .line 61
    .line 62
    invoke-static {v0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/service/MonitoringStatus;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    new-instance v1, Lorg/altbeacon/beacon/service/Callback;

    .line 67
    .line 68
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->callbackPackageName()Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object v2

    .line 72
    invoke-direct {v1, v2}, Lorg/altbeacon/beacon/service/Callback;-><init>(Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    invoke-virtual {v0, p1, v1}, Lorg/altbeacon/beacon/service/MonitoringStatus;->addRegion(Lorg/altbeacon/beacon/Region;Lorg/altbeacon/beacon/service/Callback;)V

    .line 76
    .line 77
    .line 78
    :cond_2
    const/4 v0, 0x4

    .line 79
    invoke-direct {p0, v0, p1}, Lorg/altbeacon/beacon/BeaconManager;->applyChangesToServices(ILorg/altbeacon/beacon/Region;)V

    .line 80
    .line 81
    .line 82
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->isScannerInDifferentProcess()Z

    .line 83
    .line 84
    .line 85
    move-result v0

    .line 86
    if-eqz v0, :cond_3

    .line 87
    .line 88
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mContext:Landroid/content/Context;

    .line 89
    .line 90
    invoke-static {v0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/service/MonitoringStatus;

    .line 91
    .line 92
    .line 93
    move-result-object v0

    .line 94
    invoke-virtual {v0, p1}, Lorg/altbeacon/beacon/service/MonitoringStatus;->addLocalRegion(Lorg/altbeacon/beacon/Region;)Lorg/altbeacon/beacon/service/RegionMonitoringState;

    .line 95
    .line 96
    .line 97
    :cond_3
    invoke-virtual {p0, p1}, Lorg/altbeacon/beacon/BeaconManager;->requestStateForRegion(Lorg/altbeacon/beacon/Region;)V

    .line 98
    .line 99
    .line 100
    return-void
.end method

.method public startRangingBeacons(Lorg/altbeacon/beacon/Region;)V
    .locals 4
    .annotation build Landroid/annotation/TargetApi;
        value = 0x12
    .end annotation

    .line 1
    const-string v0, "BeaconManager"

    .line 2
    .line 3
    new-instance v1, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v2, "API startRangingBeacons "

    .line 6
    .line 7
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    const/4 v2, 0x0

    .line 18
    new-array v3, v2, [Ljava/lang/Object;

    .line 19
    .line 20
    invoke-static {v0, v1, v3}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    const-string v0, "BeaconManager"

    .line 24
    .line 25
    const-string v1, "startRanging"

    .line 26
    .line 27
    new-array v2, v2, [Ljava/lang/Object;

    .line 28
    .line 29
    invoke-static {v0, v1, v2}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    iget-object v0, p1, Lorg/altbeacon/beacon/Region;->mBeaconParser:Lorg/altbeacon/beacon/BeaconParser;

    .line 33
    .line 34
    if-eqz v0, :cond_2

    .line 35
    .line 36
    invoke-virtual {v0}, Lorg/altbeacon/beacon/BeaconParser;->getIdentifier()Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    if-eqz v0, :cond_2

    .line 41
    .line 42
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->getBeaconParsers()Ljava/util/List;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    if-eqz v1, :cond_1

    .line 55
    .line 56
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    check-cast v1, Lorg/altbeacon/beacon/BeaconParser;

    .line 61
    .line 62
    iget-object v2, p1, Lorg/altbeacon/beacon/Region;->mBeaconParser:Lorg/altbeacon/beacon/BeaconParser;

    .line 63
    .line 64
    invoke-virtual {v2}, Lorg/altbeacon/beacon/BeaconParser;->getIdentifier()Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object v2

    .line 68
    invoke-virtual {v1}, Lorg/altbeacon/beacon/BeaconParser;->getIdentifier()Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    invoke-virtual {v2, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result v1

    .line 76
    if-eqz v1, :cond_0

    .line 77
    .line 78
    goto :goto_0

    .line 79
    :cond_1
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->getBeaconParsers()Ljava/util/List;

    .line 80
    .line 81
    .line 82
    move-result-object v0

    .line 83
    iget-object v1, p1, Lorg/altbeacon/beacon/Region;->mBeaconParser:Lorg/altbeacon/beacon/BeaconParser;

    .line 84
    .line 85
    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    :cond_2
    :goto_0
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->ensureBackgroundPowerSaver()V

    .line 89
    .line 90
    .line 91
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->isAnyConsumerBound()Z

    .line 92
    .line 93
    .line 94
    move-result v0

    .line 95
    if-eqz v0, :cond_3

    .line 96
    .line 97
    :try_start_0
    invoke-virtual {p0, p1}, Lorg/altbeacon/beacon/BeaconManager;->startRangingBeaconsInRegion(Lorg/altbeacon/beacon/Region;)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 98
    .line 99
    .line 100
    return-void

    .line 101
    :catch_0
    move-exception p0

    .line 102
    const-string p1, "BeaconManager"

    .line 103
    .line 104
    const-string v0, "Failed to start ranging"

    .line 105
    .line 106
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    invoke-static {p1, v0, p0}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 111
    .line 112
    .line 113
    return-void

    .line 114
    :cond_3
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->autoBindRangedRegions:Ljava/util/Set;

    .line 115
    .line 116
    monitor-enter v0

    .line 117
    :try_start_1
    iget-object v1, p0, Lorg/altbeacon/beacon/BeaconManager;->autoBindRangedRegions:Ljava/util/Set;

    .line 118
    .line 119
    invoke-interface {v1, p1}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z

    .line 120
    .line 121
    .line 122
    iget-object v1, p0, Lorg/altbeacon/beacon/BeaconManager;->autoBindRangedRegions:Ljava/util/Set;

    .line 123
    .line 124
    invoke-interface {v1, p1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 125
    .line 126
    .line 127
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 128
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->autoBind()V

    .line 129
    .line 130
    .line 131
    return-void

    .line 132
    :catchall_0
    move-exception p0

    .line 133
    :try_start_2
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 134
    throw p0
.end method

.method public startRangingBeaconsInRegion(Lorg/altbeacon/beacon/Region;)V
    .locals 4
    .annotation build Landroid/annotation/TargetApi;
        value = 0x12
    .end annotation

    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "API startRangingBeaconsInRegion "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const/4 v1, 0x0

    .line 16
    new-array v2, v1, [Ljava/lang/Object;

    .line 17
    .line 18
    const-string v3, "BeaconManager"

    .line 19
    .line 20
    invoke-static {v3, v0, v2}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    const-string v0, "startRangingBeaconsInRegion"

    .line 24
    .line 25
    new-array v2, v1, [Ljava/lang/Object;

    .line 26
    .line 27
    invoke-static {v3, v0, v2}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->isBleAvailableOrSimulated()Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-nez v0, :cond_0

    .line 35
    .line 36
    const-string p0, "Method invocation will be ignored."

    .line 37
    .line 38
    new-array p1, v1, [Ljava/lang/Object;

    .line 39
    .line 40
    invoke-static {v3, p0, p1}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    return-void

    .line 44
    :cond_0
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->determineIfCalledFromSeparateScannerProcess()Z

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    if-eqz v0, :cond_1

    .line 49
    .line 50
    return-void

    .line 51
    :cond_1
    new-instance v0, Lorg/altbeacon/beacon/utils/PermissionsInspector;

    .line 52
    .line 53
    iget-object v1, p0, Lorg/altbeacon/beacon/BeaconManager;->mContext:Landroid/content/Context;

    .line 54
    .line 55
    invoke-direct {v0, v1}, Lorg/altbeacon/beacon/utils/PermissionsInspector;-><init>(Landroid/content/Context;)V

    .line 56
    .line 57
    .line 58
    invoke-virtual {v0}, Lorg/altbeacon/beacon/utils/PermissionsInspector;->hasDeclaredBluetoothScanPermissions()Z

    .line 59
    .line 60
    .line 61
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->rangedRegions:Ljava/util/Set;

    .line 62
    .line 63
    invoke-interface {v0, p1}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->rangedRegions:Ljava/util/Set;

    .line 67
    .line 68
    invoke-interface {v0, p1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    const/4 v0, 0x2

    .line 72
    invoke-direct {p0, v0, p1}, Lorg/altbeacon/beacon/BeaconManager;->applyChangesToServices(ILorg/altbeacon/beacon/Region;)V

    .line 73
    .line 74
    .line 75
    return-void
.end method

.method public stopMonitoring(Lorg/altbeacon/beacon/Region;)V
    .locals 3
    .annotation build Landroid/annotation/TargetApi;
        value = 0x12
    .end annotation

    .line 1
    const-string v0, "BeaconManager"

    .line 2
    .line 3
    new-instance v1, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v2, "API stopMonitoring "

    .line 6
    .line 7
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    const/4 v2, 0x0

    .line 18
    new-array v2, v2, [Ljava/lang/Object;

    .line 19
    .line 20
    invoke-static {v0, v1, v2}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->ensureBackgroundPowerSaver()V

    .line 24
    .line 25
    .line 26
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->isAnyConsumerBound()Z

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    if-eqz v0, :cond_0

    .line 31
    .line 32
    :try_start_0
    invoke-virtual {p0, p1}, Lorg/altbeacon/beacon/BeaconManager;->stopMonitoringBeaconsInRegion(Lorg/altbeacon/beacon/Region;)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 33
    .line 34
    .line 35
    return-void

    .line 36
    :catch_0
    move-exception p0

    .line 37
    const-string p1, "BeaconManager"

    .line 38
    .line 39
    const-string v0, "Failed to stop monitoring"

    .line 40
    .line 41
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    invoke-static {p1, v0, p0}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    return-void

    .line 49
    :cond_0
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->autoBindMonitoredRegions:Ljava/util/Set;

    .line 50
    .line 51
    monitor-enter v0

    .line 52
    :try_start_1
    iget-object v1, p0, Lorg/altbeacon/beacon/BeaconManager;->autoBindMonitoredRegions:Ljava/util/Set;

    .line 53
    .line 54
    invoke-interface {v1, p1}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->mContext:Landroid/content/Context;

    .line 58
    .line 59
    invoke-static {p0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/service/MonitoringStatus;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    invoke-virtual {p0, p1}, Lorg/altbeacon/beacon/service/MonitoringStatus;->removeRegion(Lorg/altbeacon/beacon/Region;)V

    .line 64
    .line 65
    .line 66
    monitor-exit v0

    .line 67
    return-void

    .line 68
    :catchall_0
    move-exception p0

    .line 69
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 70
    throw p0
.end method

.method public stopMonitoringBeaconsInRegion(Lorg/altbeacon/beacon/Region;)V
    .locals 4
    .annotation build Landroid/annotation/TargetApi;
        value = 0x12
    .end annotation

    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "API stopMonitoringBeaconsInRegion "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const/4 v1, 0x0

    .line 16
    new-array v2, v1, [Ljava/lang/Object;

    .line 17
    .line 18
    const-string v3, "BeaconManager"

    .line 19
    .line 20
    invoke-static {v3, v0, v2}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->isBleAvailableOrSimulated()Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-nez v0, :cond_0

    .line 28
    .line 29
    const-string p0, "Method invocation will be ignored."

    .line 30
    .line 31
    new-array p1, v1, [Ljava/lang/Object;

    .line 32
    .line 33
    invoke-static {v3, p0, p1}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    return-void

    .line 37
    :cond_0
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->determineIfCalledFromSeparateScannerProcess()Z

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    if-eqz v0, :cond_1

    .line 42
    .line 43
    return-void

    .line 44
    :cond_1
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->isScannerInDifferentProcess()Z

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    if-nez v0, :cond_2

    .line 49
    .line 50
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mContext:Landroid/content/Context;

    .line 51
    .line 52
    invoke-static {v0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/service/MonitoringStatus;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    invoke-virtual {v0, p1}, Lorg/altbeacon/beacon/service/MonitoringStatus;->removeRegion(Lorg/altbeacon/beacon/Region;)V

    .line 57
    .line 58
    .line 59
    :cond_2
    const/4 v0, 0x5

    .line 60
    invoke-direct {p0, v0, p1}, Lorg/altbeacon/beacon/BeaconManager;->applyChangesToServices(ILorg/altbeacon/beacon/Region;)V

    .line 61
    .line 62
    .line 63
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->isScannerInDifferentProcess()Z

    .line 64
    .line 65
    .line 66
    move-result v0

    .line 67
    if-eqz v0, :cond_3

    .line 68
    .line 69
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mContext:Landroid/content/Context;

    .line 70
    .line 71
    invoke-static {v0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/service/MonitoringStatus;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    invoke-virtual {v0, p1}, Lorg/altbeacon/beacon/service/MonitoringStatus;->removeLocalRegion(Lorg/altbeacon/beacon/Region;)V

    .line 76
    .line 77
    .line 78
    :cond_3
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->autoUnbindIfNeeded()V

    .line 79
    .line 80
    .line 81
    return-void
.end method

.method public stopRangingBeacons(Lorg/altbeacon/beacon/Region;)V
    .locals 4
    .annotation build Landroid/annotation/TargetApi;
        value = 0x12
    .end annotation

    .line 1
    const-string v0, "BeaconManager"

    .line 2
    .line 3
    new-instance v1, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v2, "API stopRangingBeacons "

    .line 6
    .line 7
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    const/4 v2, 0x0

    .line 18
    new-array v3, v2, [Ljava/lang/Object;

    .line 19
    .line 20
    invoke-static {v0, v1, v3}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    const-string v0, "BeaconManager"

    .line 24
    .line 25
    const-string v1, "stopRangingBeacons"

    .line 26
    .line 27
    new-array v2, v2, [Ljava/lang/Object;

    .line 28
    .line 29
    invoke-static {v0, v1, v2}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->ensureBackgroundPowerSaver()V

    .line 33
    .line 34
    .line 35
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->isAnyConsumerBound()Z

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    if-eqz v0, :cond_0

    .line 40
    .line 41
    :try_start_0
    invoke-virtual {p0, p1}, Lorg/altbeacon/beacon/BeaconManager;->stopRangingBeaconsInRegion(Lorg/altbeacon/beacon/Region;)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 42
    .line 43
    .line 44
    goto :goto_0

    .line 45
    :catch_0
    move-exception p1

    .line 46
    const-string v0, "BeaconManager"

    .line 47
    .line 48
    const-string v1, "Cannot stop ranging"

    .line 49
    .line 50
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object p1

    .line 54
    invoke-static {v0, v1, p1}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_0
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->autoBindMonitoredRegions:Ljava/util/Set;

    .line 59
    .line 60
    monitor-enter v0

    .line 61
    :try_start_1
    iget-object v1, p0, Lorg/altbeacon/beacon/BeaconManager;->autoBindRangedRegions:Ljava/util/Set;

    .line 62
    .line 63
    invoke-interface {v1, p1}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 67
    :goto_0
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->autoUnbindIfNeeded()V

    .line 68
    .line 69
    .line 70
    return-void

    .line 71
    :catchall_0
    move-exception p0

    .line 72
    :try_start_2
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 73
    throw p0
.end method

.method public stopRangingBeaconsInRegion(Lorg/altbeacon/beacon/Region;)V
    .locals 4
    .annotation build Landroid/annotation/TargetApi;
        value = 0x12
    .end annotation

    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "API stopRangingBeacons "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const/4 v1, 0x0

    .line 16
    new-array v2, v1, [Ljava/lang/Object;

    .line 17
    .line 18
    const-string v3, "BeaconManager"

    .line 19
    .line 20
    invoke-static {v3, v0, v2}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    const-string v0, "stopRangingBeaconsInRegion"

    .line 24
    .line 25
    new-array v2, v1, [Ljava/lang/Object;

    .line 26
    .line 27
    invoke-static {v3, v0, v2}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->isBleAvailableOrSimulated()Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-nez v0, :cond_0

    .line 35
    .line 36
    const-string p0, "Method invocation will be ignored."

    .line 37
    .line 38
    new-array p1, v1, [Ljava/lang/Object;

    .line 39
    .line 40
    invoke-static {v3, p0, p1}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    return-void

    .line 44
    :cond_0
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->determineIfCalledFromSeparateScannerProcess()Z

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    if-eqz v0, :cond_1

    .line 49
    .line 50
    return-void

    .line 51
    :cond_1
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->rangedRegions:Ljava/util/Set;

    .line 52
    .line 53
    invoke-interface {v0, p1}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    const/4 v0, 0x3

    .line 57
    invoke-direct {p0, v0, p1}, Lorg/altbeacon/beacon/BeaconManager;->applyChangesToServices(ILorg/altbeacon/beacon/Region;)V

    .line 58
    .line 59
    .line 60
    return-void
.end method

.method public declared-synchronized syncSettingsToService()V
    .locals 4

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mIntentScanStrategyCoordinator:Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;

    .line 3
    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->applySettings()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 7
    .line 8
    .line 9
    monitor-exit p0

    .line 10
    return-void

    .line 11
    :catchall_0
    move-exception v0

    .line 12
    goto :goto_2

    .line 13
    :cond_0
    :try_start_1
    iget-boolean v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mScheduledScanJobsEnabled:Z

    .line 14
    .line 15
    if-nez v0, :cond_4

    .line 16
    .line 17
    iget-boolean v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mScheduledScanJobsEnabledByFallback:Z

    .line 18
    .line 19
    if-eqz v0, :cond_1

    .line 20
    .line 21
    goto :goto_1

    .line 22
    :cond_1
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->isAnyConsumerBound()Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    const/4 v1, 0x0

    .line 27
    if-nez v0, :cond_2

    .line 28
    .line 29
    const-string v0, "BeaconManager"

    .line 30
    .line 31
    const-string v2, "No settings sync to running service -- service not bound"

    .line 32
    .line 33
    new-array v1, v1, [Ljava/lang/Object;

    .line 34
    .line 35
    invoke-static {v0, v2, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 36
    .line 37
    .line 38
    monitor-exit p0

    .line 39
    return-void

    .line 40
    :cond_2
    :try_start_2
    iget-boolean v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mServiceSyncScheduled:Z

    .line 41
    .line 42
    if-nez v0, :cond_3

    .line 43
    .line 44
    const/4 v0, 0x1

    .line 45
    iput-boolean v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mServiceSyncScheduled:Z

    .line 46
    .line 47
    const-string v0, "BeaconManager"

    .line 48
    .line 49
    const-string v2, "API Scheduling settings sync to running service."

    .line 50
    .line 51
    new-array v1, v1, [Ljava/lang/Object;

    .line 52
    .line 53
    invoke-static {v0, v2, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mServiceSyncHandler:Landroid/os/Handler;

    .line 57
    .line 58
    new-instance v1, Lorg/altbeacon/beacon/BeaconManager$3;

    .line 59
    .line 60
    invoke-direct {v1, p0}, Lorg/altbeacon/beacon/BeaconManager$3;-><init>(Lorg/altbeacon/beacon/BeaconManager;)V

    .line 61
    .line 62
    .line 63
    const-wide/16 v2, 0x64

    .line 64
    .line 65
    invoke-virtual {v0, v1, v2, v3}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 66
    .line 67
    .line 68
    goto :goto_0

    .line 69
    :cond_3
    const-string v0, "BeaconManager"

    .line 70
    .line 71
    const-string v2, "Already scheduled settings sync to running service."

    .line 72
    .line 73
    new-array v1, v1, [Ljava/lang/Object;

    .line 74
    .line 75
    invoke-static {v0, v2, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 76
    .line 77
    .line 78
    :goto_0
    monitor-exit p0

    .line 79
    return-void

    .line 80
    :cond_4
    :goto_1
    :try_start_3
    invoke-static {}, Lorg/altbeacon/beacon/service/ScanJobScheduler;->getInstance()Lorg/altbeacon/beacon/service/ScanJobScheduler;

    .line 81
    .line 82
    .line 83
    move-result-object v0

    .line 84
    iget-object v1, p0, Lorg/altbeacon/beacon/BeaconManager;->mContext:Landroid/content/Context;

    .line 85
    .line 86
    invoke-virtual {v0, v1, p0}, Lorg/altbeacon/beacon/service/ScanJobScheduler;->applySettingsToScheduledJob(Landroid/content/Context;Lorg/altbeacon/beacon/BeaconManager;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 87
    .line 88
    .line 89
    monitor-exit p0

    .line 90
    return-void

    .line 91
    :goto_2
    :try_start_4
    monitor-exit p0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 92
    throw v0
.end method

.method public unbind(Lorg/altbeacon/beacon/BeaconConsumer;)V
    .locals 3
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    const/4 v0, 0x0

    .line 2
    new-array v0, v0, [Ljava/lang/Object;

    .line 3
    .line 4
    const-string v1, "BeaconManager"

    .line 5
    .line 6
    const-string v2, "API unbind"

    .line 7
    .line 8
    invoke-static {v1, v2, v0}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0, p1}, Lorg/altbeacon/beacon/BeaconManager;->unbindInternal(Lorg/altbeacon/beacon/InternalBeaconConsumer;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public unbindInternal(Lorg/altbeacon/beacon/InternalBeaconConsumer;)V
    .locals 7

    .line 1
    const-string v0, "After unbind, consumer count is "

    .line 2
    .line 3
    const-string v1, "Before unbind, consumer count is "

    .line 4
    .line 5
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->isBleAvailableOrSimulated()Z

    .line 6
    .line 7
    .line 8
    move-result v2

    .line 9
    const/4 v3, 0x0

    .line 10
    if-nez v2, :cond_0

    .line 11
    .line 12
    const-string p0, "BeaconManager"

    .line 13
    .line 14
    const-string p1, "Method invocation will be ignored."

    .line 15
    .line 16
    new-array v0, v3, [Ljava/lang/Object;

    .line 17
    .line 18
    invoke-static {p0, p1, v0}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    :cond_0
    iget-object v2, p0, Lorg/altbeacon/beacon/BeaconManager;->consumers:Ljava/util/concurrent/ConcurrentMap;

    .line 23
    .line 24
    monitor-enter v2

    .line 25
    :try_start_0
    iget-object v4, p0, Lorg/altbeacon/beacon/BeaconManager;->consumers:Ljava/util/concurrent/ConcurrentMap;

    .line 26
    .line 27
    invoke-interface {v4, p1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v4

    .line 31
    if-eqz v4, :cond_5

    .line 32
    .line 33
    const-string v4, "BeaconManager"

    .line 34
    .line 35
    const-string v5, "Unbinding"

    .line 36
    .line 37
    new-array v6, v3, [Ljava/lang/Object;

    .line 38
    .line 39
    invoke-static {v4, v5, v6}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    iget-object v4, p0, Lorg/altbeacon/beacon/BeaconManager;->mIntentScanStrategyCoordinator:Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;

    .line 43
    .line 44
    if-eqz v4, :cond_1

    .line 45
    .line 46
    const-string v4, "BeaconManager"

    .line 47
    .line 48
    const-string v5, "Not unbinding as we are using intent scanning strategy"

    .line 49
    .line 50
    new-array v6, v3, [Ljava/lang/Object;

    .line 51
    .line 52
    invoke-static {v4, v5, v6}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    goto :goto_1

    .line 56
    :catchall_0
    move-exception p0

    .line 57
    goto/16 :goto_4

    .line 58
    .line 59
    :cond_1
    iget-boolean v4, p0, Lorg/altbeacon/beacon/BeaconManager;->mScheduledScanJobsEnabled:Z

    .line 60
    .line 61
    if-nez v4, :cond_3

    .line 62
    .line 63
    iget-boolean v4, p0, Lorg/altbeacon/beacon/BeaconManager;->mScheduledScanJobsEnabledByFallback:Z

    .line 64
    .line 65
    if-eqz v4, :cond_2

    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_2
    iget-object v4, p0, Lorg/altbeacon/beacon/BeaconManager;->consumers:Ljava/util/concurrent/ConcurrentMap;

    .line 69
    .line 70
    invoke-interface {v4, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v4

    .line 74
    check-cast v4, Lorg/altbeacon/beacon/BeaconManager$ConsumerInfo;

    .line 75
    .line 76
    iget-object v4, v4, Lorg/altbeacon/beacon/BeaconManager$ConsumerInfo;->beaconServiceConnection:Lorg/altbeacon/beacon/BeaconManager$BeaconServiceConnection;

    .line 77
    .line 78
    invoke-interface {p1, v4}, Lorg/altbeacon/beacon/InternalBeaconConsumer;->unbindService(Landroid/content/ServiceConnection;)V

    .line 79
    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_3
    :goto_0
    const-string v4, "BeaconManager"

    .line 83
    .line 84
    const-string v5, "Not unbinding from scanning service as we are using scan jobs."

    .line 85
    .line 86
    new-array v6, v3, [Ljava/lang/Object;

    .line 87
    .line 88
    invoke-static {v4, v5, v6}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    :goto_1
    const-string v4, "BeaconManager"

    .line 92
    .line 93
    new-instance v5, Ljava/lang/StringBuilder;

    .line 94
    .line 95
    invoke-direct {v5, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    iget-object v1, p0, Lorg/altbeacon/beacon/BeaconManager;->consumers:Ljava/util/concurrent/ConcurrentMap;

    .line 99
    .line 100
    invoke-interface {v1}, Ljava/util/Map;->size()I

    .line 101
    .line 102
    .line 103
    move-result v1

    .line 104
    invoke-virtual {v5, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 105
    .line 106
    .line 107
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object v1

    .line 111
    new-array v5, v3, [Ljava/lang/Object;

    .line 112
    .line 113
    invoke-static {v4, v1, v5}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    iget-object v1, p0, Lorg/altbeacon/beacon/BeaconManager;->consumers:Ljava/util/concurrent/ConcurrentMap;

    .line 117
    .line 118
    invoke-interface {v1, p1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    const-string p1, "BeaconManager"

    .line 122
    .line 123
    new-instance v1, Ljava/lang/StringBuilder;

    .line 124
    .line 125
    invoke-direct {v1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 126
    .line 127
    .line 128
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager;->consumers:Ljava/util/concurrent/ConcurrentMap;

    .line 129
    .line 130
    invoke-interface {v0}, Ljava/util/Map;->size()I

    .line 131
    .line 132
    .line 133
    move-result v0

    .line 134
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 135
    .line 136
    .line 137
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 138
    .line 139
    .line 140
    move-result-object v0

    .line 141
    new-array v1, v3, [Ljava/lang/Object;

    .line 142
    .line 143
    invoke-static {p1, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 144
    .line 145
    .line 146
    iget-object p1, p0, Lorg/altbeacon/beacon/BeaconManager;->consumers:Ljava/util/concurrent/ConcurrentMap;

    .line 147
    .line 148
    invoke-interface {p1}, Ljava/util/Map;->size()I

    .line 149
    .line 150
    .line 151
    move-result p1

    .line 152
    if-nez p1, :cond_6

    .line 153
    .line 154
    const/4 p1, 0x0

    .line 155
    iput-object p1, p0, Lorg/altbeacon/beacon/BeaconManager;->serviceMessenger:Landroid/os/Messenger;

    .line 156
    .line 157
    iget-boolean p1, p0, Lorg/altbeacon/beacon/BeaconManager;->mScheduledScanJobsEnabled:Z

    .line 158
    .line 159
    if-nez p1, :cond_4

    .line 160
    .line 161
    iget-boolean p1, p0, Lorg/altbeacon/beacon/BeaconManager;->mScheduledScanJobsEnabledByFallback:Z

    .line 162
    .line 163
    if-nez p1, :cond_4

    .line 164
    .line 165
    iget-object p1, p0, Lorg/altbeacon/beacon/BeaconManager;->mIntentScanStrategyCoordinator:Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;

    .line 166
    .line 167
    if-eqz p1, :cond_6

    .line 168
    .line 169
    :cond_4
    const-string p1, "BeaconManager"

    .line 170
    .line 171
    const-string v0, "Cancelling scheduled jobs after unbind of last consumer."

    .line 172
    .line 173
    new-array v1, v3, [Ljava/lang/Object;

    .line 174
    .line 175
    invoke-static {p1, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 176
    .line 177
    .line 178
    invoke-static {}, Lorg/altbeacon/beacon/service/ScanJobScheduler;->getInstance()Lorg/altbeacon/beacon/service/ScanJobScheduler;

    .line 179
    .line 180
    .line 181
    move-result-object p1

    .line 182
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->mContext:Landroid/content/Context;

    .line 183
    .line 184
    invoke-virtual {p1, p0}, Lorg/altbeacon/beacon/service/ScanJobScheduler;->cancelSchedule(Landroid/content/Context;)V

    .line 185
    .line 186
    .line 187
    goto :goto_3

    .line 188
    :cond_5
    const-string v0, "BeaconManager"

    .line 189
    .line 190
    const-string v1, "This consumer is not bound to: %s"

    .line 191
    .line 192
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    move-result-object p1

    .line 196
    invoke-static {v0, v1, p1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 197
    .line 198
    .line 199
    const-string p1, "BeaconManager"

    .line 200
    .line 201
    const-string v0, "Bound consumers: "

    .line 202
    .line 203
    new-array v1, v3, [Ljava/lang/Object;

    .line 204
    .line 205
    invoke-static {p1, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 206
    .line 207
    .line 208
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager;->consumers:Ljava/util/concurrent/ConcurrentMap;

    .line 209
    .line 210
    invoke-interface {p0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 211
    .line 212
    .line 213
    move-result-object p0

    .line 214
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 215
    .line 216
    .line 217
    move-result-object p0

    .line 218
    :goto_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 219
    .line 220
    .line 221
    move-result p1

    .line 222
    if-eqz p1, :cond_6

    .line 223
    .line 224
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 225
    .line 226
    .line 227
    move-result-object p1

    .line 228
    check-cast p1, Ljava/util/Map$Entry;

    .line 229
    .line 230
    const-string v0, "BeaconManager"

    .line 231
    .line 232
    invoke-interface {p1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 233
    .line 234
    .line 235
    move-result-object p1

    .line 236
    invoke-static {p1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 237
    .line 238
    .line 239
    move-result-object p1

    .line 240
    new-array v1, v3, [Ljava/lang/Object;

    .line 241
    .line 242
    invoke-static {v0, p1, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 243
    .line 244
    .line 245
    goto :goto_2

    .line 246
    :cond_6
    :goto_3
    monitor-exit v2

    .line 247
    return-void

    .line 248
    :goto_4
    monitor-exit v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 249
    throw p0
.end method

.method public updateScanPeriods()V
    .locals 5
    .annotation build Landroid/annotation/TargetApi;
        value = 0x12
    .end annotation

    .line 1
    const/4 v0, 0x0

    .line 2
    new-array v1, v0, [Ljava/lang/Object;

    .line 3
    .line 4
    const-string v2, "BeaconManager"

    .line 5
    .line 6
    const-string v3, "API updateScanPeriods"

    .line 7
    .line 8
    invoke-static {v2, v3, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->isBleAvailableOrSimulated()Z

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-nez v1, :cond_0

    .line 16
    .line 17
    const-string p0, "Method invocation will be ignored."

    .line 18
    .line 19
    new-array v0, v0, [Ljava/lang/Object;

    .line 20
    .line 21
    invoke-static {v2, p0, v0}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    return-void

    .line 25
    :cond_0
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->determineIfCalledFromSeparateScannerProcess()Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-eqz v0, :cond_1

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_1
    iget-boolean v0, p0, Lorg/altbeacon/beacon/BeaconManager;->mBackgroundMode:Z

    .line 33
    .line 34
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    const-string v1, "updating background flag to %s"

    .line 43
    .line 44
    invoke-static {v2, v1, v0}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->getScanPeriod()J

    .line 48
    .line 49
    .line 50
    move-result-wide v0

    .line 51
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    invoke-direct {p0}, Lorg/altbeacon/beacon/BeaconManager;->getBetweenScanPeriod()J

    .line 56
    .line 57
    .line 58
    move-result-wide v3

    .line 59
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 60
    .line 61
    .line 62
    move-result-object v1

    .line 63
    filled-new-array {v0, v1}, [Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    const-string v1, "updating scan periods to %s, %s"

    .line 68
    .line 69
    invoke-static {v2, v1, v0}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->isAnyConsumerBound()Z

    .line 73
    .line 74
    .line 75
    move-result v0

    .line 76
    if-eqz v0, :cond_2

    .line 77
    .line 78
    const/4 v0, 0x6

    .line 79
    const/4 v1, 0x0

    .line 80
    invoke-direct {p0, v0, v1}, Lorg/altbeacon/beacon/BeaconManager;->applyChangesToServices(ILorg/altbeacon/beacon/Region;)V

    .line 81
    .line 82
    .line 83
    :cond_2
    :goto_0
    return-void
.end method
