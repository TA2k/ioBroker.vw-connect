.class public final Lorg/altbeacon/beacon/Settings;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lorg/altbeacon/beacon/Settings$ScanPeriods;,
        Lorg/altbeacon/beacon/Settings$ScanStrategy;,
        Lorg/altbeacon/beacon/Settings$Companion;,
        Lorg/altbeacon/beacon/Settings$Defaults;,
        Lorg/altbeacon/beacon/Settings$Builder;,
        Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;,
        Lorg/altbeacon/beacon/Settings$BackgroundServiceScanStrategy;,
        Lorg/altbeacon/beacon/Settings$ForegroundServiceScanStrategy;,
        Lorg/altbeacon/beacon/Settings$IntentScanStrategy;,
        Lorg/altbeacon/beacon/Settings$DisabledBeaconSimulator;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000@\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0008\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u00089\u0008\u0086\u0008\u0018\u0000 G2\u00020\u0001:\nEFGHIJKLMNB\u00b1\u0001\u0012\n\u0008\u0002\u0010\u0002\u001a\u0004\u0018\u00010\u0003\u0012\n\u0008\u0002\u0010\u0004\u001a\u0004\u0018\u00010\u0003\u0012\n\u0008\u0002\u0010\u0005\u001a\u0004\u0018\u00010\u0003\u0012\n\u0008\u0002\u0010\u0006\u001a\u0004\u0018\u00010\u0007\u0012\n\u0008\u0002\u0010\u0008\u001a\u0004\u0018\u00010\t\u0012\n\u0008\u0002\u0010\n\u001a\u0004\u0018\u00010\u0003\u0012\n\u0008\u0002\u0010\u000b\u001a\u0004\u0018\u00010\t\u0012\n\u0008\u0002\u0010\u000c\u001a\u0004\u0018\u00010\u0003\u0012\n\u0008\u0002\u0010\r\u001a\u0004\u0018\u00010\u000e\u0012\u000e\u0008\u0002\u0010\u000f\u001a\u0008\u0012\u0002\u0008\u0003\u0018\u00010\u0010\u0012\n\u0008\u0002\u0010\u0011\u001a\u0004\u0018\u00010\u0012\u0012\n\u0008\u0002\u0010\u0013\u001a\u0004\u0018\u00010\u0014\u0012\n\u0008\u0002\u0010\u0015\u001a\u0004\u0018\u00010\u0016\u0012\n\u0008\u0002\u0010\u0017\u001a\u0004\u0018\u00010\u0003\u00a2\u0006\u0002\u0010\u0018J\u0010\u00101\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003\u00a2\u0006\u0002\u0010\u001cJ\u000f\u00102\u001a\u0008\u0012\u0002\u0008\u0003\u0018\u00010\u0010H\u00c6\u0003J\u000b\u00103\u001a\u0004\u0018\u00010\u0012H\u00c6\u0003J\u000b\u00104\u001a\u0004\u0018\u00010\u0014H\u00c6\u0003J\u000b\u00105\u001a\u0004\u0018\u00010\u0016H\u00c6\u0003J\u0010\u00106\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003\u00a2\u0006\u0002\u0010\u001cJ\u0010\u00107\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003\u00a2\u0006\u0002\u0010\u001cJ\u0010\u00108\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003\u00a2\u0006\u0002\u0010\u001cJ\u000b\u00109\u001a\u0004\u0018\u00010\u0007H\u00c6\u0003J\u0010\u0010:\u001a\u0004\u0018\u00010\tH\u00c6\u0003\u00a2\u0006\u0002\u0010&J\u0010\u0010;\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003\u00a2\u0006\u0002\u0010\u001cJ\u0010\u0010<\u001a\u0004\u0018\u00010\tH\u00c6\u0003\u00a2\u0006\u0002\u0010&J\u0010\u0010=\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003\u00a2\u0006\u0002\u0010\u001cJ\u000b\u0010>\u001a\u0004\u0018\u00010\u000eH\u00c6\u0003J\u00ba\u0001\u0010?\u001a\u00020\u00002\n\u0008\u0002\u0010\u0002\u001a\u0004\u0018\u00010\u00032\n\u0008\u0002\u0010\u0004\u001a\u0004\u0018\u00010\u00032\n\u0008\u0002\u0010\u0005\u001a\u0004\u0018\u00010\u00032\n\u0008\u0002\u0010\u0006\u001a\u0004\u0018\u00010\u00072\n\u0008\u0002\u0010\u0008\u001a\u0004\u0018\u00010\t2\n\u0008\u0002\u0010\n\u001a\u0004\u0018\u00010\u00032\n\u0008\u0002\u0010\u000b\u001a\u0004\u0018\u00010\t2\n\u0008\u0002\u0010\u000c\u001a\u0004\u0018\u00010\u00032\n\u0008\u0002\u0010\r\u001a\u0004\u0018\u00010\u000e2\u000e\u0008\u0002\u0010\u000f\u001a\u0008\u0012\u0002\u0008\u0003\u0018\u00010\u00102\n\u0008\u0002\u0010\u0011\u001a\u0004\u0018\u00010\u00122\n\u0008\u0002\u0010\u0013\u001a\u0004\u0018\u00010\u00142\n\u0008\u0002\u0010\u0015\u001a\u0004\u0018\u00010\u00162\n\u0008\u0002\u0010\u0017\u001a\u0004\u0018\u00010\u0003H\u00c6\u0001\u00a2\u0006\u0002\u0010@J\u0013\u0010A\u001a\u00020\u00032\u0008\u0010B\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010C\u001a\u00020\tH\u00d6\u0001J\t\u0010D\u001a\u00020\u0012H\u00d6\u0001R\u0013\u0010\r\u001a\u0004\u0018\u00010\u000e\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0019\u0010\u001aR\u0015\u0010\u0002\u001a\u0004\u0018\u00010\u0003\u00a2\u0006\n\n\u0002\u0010\u001d\u001a\u0004\u0008\u001b\u0010\u001cR\u0013\u0010\u0013\u001a\u0004\u0018\u00010\u0014\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u001e\u0010\u001fR\u0013\u0010\u0011\u001a\u0004\u0018\u00010\u0012\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008 \u0010!R\u0015\u0010\u0005\u001a\u0004\u0018\u00010\u0003\u00a2\u0006\n\n\u0002\u0010\u001d\u001a\u0004\u0008\"\u0010\u001cR\u0015\u0010\u0017\u001a\u0004\u0018\u00010\u0003\u00a2\u0006\n\n\u0002\u0010\u001d\u001a\u0004\u0008#\u0010\u001cR\u0015\u0010\u000c\u001a\u0004\u0018\u00010\u0003\u00a2\u0006\n\n\u0002\u0010\u001d\u001a\u0004\u0008$\u0010\u001cR\u0015\u0010\u000b\u001a\u0004\u0018\u00010\t\u00a2\u0006\n\n\u0002\u0010\'\u001a\u0004\u0008%\u0010&R\u0015\u0010\u0008\u001a\u0004\u0018\u00010\t\u00a2\u0006\n\n\u0002\u0010\'\u001a\u0004\u0008(\u0010&R\u0015\u0010\u0004\u001a\u0004\u0018\u00010\u0003\u00a2\u0006\n\n\u0002\u0010\u001d\u001a\u0004\u0008)\u0010\u001cR\u0017\u0010\u000f\u001a\u0008\u0012\u0002\u0008\u0003\u0018\u00010\u0010\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008*\u0010+R\u0013\u0010\u0006\u001a\u0004\u0018\u00010\u0007\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008,\u0010-R\u0013\u0010\u0015\u001a\u0004\u0018\u00010\u0016\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008.\u0010/R\u0015\u0010\n\u001a\u0004\u0018\u00010\u0003\u00a2\u0006\n\n\u0002\u0010\u001d\u001a\u0004\u00080\u0010\u001c\u00a8\u0006O"
    }
    d2 = {
        "Lorg/altbeacon/beacon/Settings;",
        "",
        "debug",
        "",
        "regionStatePersistenceEnabled",
        "hardwareEqualityEnforced",
        "scanPeriods",
        "Lorg/altbeacon/beacon/Settings$ScanPeriods;",
        "regionExitPeriodMillis",
        "",
        "useTrackingCache",
        "maxTrackingAgeMillis",
        "manifestCheckingDisabled",
        "beaconSimulator",
        "Lorg/altbeacon/beacon/simulator/BeaconSimulator;",
        "rssiFilterClass",
        "Ljava/lang/Class;",
        "distanceModelUpdateUrl",
        "",
        "distanceCalculatorFactory",
        "Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;",
        "scanStrategy",
        "Lorg/altbeacon/beacon/Settings$ScanStrategy;",
        "longScanForcingEnabled",
        "(Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Lorg/altbeacon/beacon/Settings$ScanPeriods;Ljava/lang/Integer;Ljava/lang/Boolean;Ljava/lang/Integer;Ljava/lang/Boolean;Lorg/altbeacon/beacon/simulator/BeaconSimulator;Ljava/lang/Class;Ljava/lang/String;Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;Lorg/altbeacon/beacon/Settings$ScanStrategy;Ljava/lang/Boolean;)V",
        "getBeaconSimulator",
        "()Lorg/altbeacon/beacon/simulator/BeaconSimulator;",
        "getDebug",
        "()Ljava/lang/Boolean;",
        "Ljava/lang/Boolean;",
        "getDistanceCalculatorFactory",
        "()Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;",
        "getDistanceModelUpdateUrl",
        "()Ljava/lang/String;",
        "getHardwareEqualityEnforced",
        "getLongScanForcingEnabled",
        "getManifestCheckingDisabled",
        "getMaxTrackingAgeMillis",
        "()Ljava/lang/Integer;",
        "Ljava/lang/Integer;",
        "getRegionExitPeriodMillis",
        "getRegionStatePersistenceEnabled",
        "getRssiFilterClass",
        "()Ljava/lang/Class;",
        "getScanPeriods",
        "()Lorg/altbeacon/beacon/Settings$ScanPeriods;",
        "getScanStrategy",
        "()Lorg/altbeacon/beacon/Settings$ScanStrategy;",
        "getUseTrackingCache",
        "component1",
        "component10",
        "component11",
        "component12",
        "component13",
        "component14",
        "component2",
        "component3",
        "component4",
        "component5",
        "component6",
        "component7",
        "component8",
        "component9",
        "copy",
        "(Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Lorg/altbeacon/beacon/Settings$ScanPeriods;Ljava/lang/Integer;Ljava/lang/Boolean;Ljava/lang/Integer;Ljava/lang/Boolean;Lorg/altbeacon/beacon/simulator/BeaconSimulator;Ljava/lang/Class;Ljava/lang/String;Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;Lorg/altbeacon/beacon/Settings$ScanStrategy;Ljava/lang/Boolean;)Lorg/altbeacon/beacon/Settings;",
        "equals",
        "other",
        "hashCode",
        "toString",
        "BackgroundServiceScanStrategy",
        "Builder",
        "Companion",
        "Defaults",
        "DisabledBeaconSimulator",
        "ForegroundServiceScanStrategy",
        "IntentScanStrategy",
        "JobServiceScanStrategy",
        "ScanPeriods",
        "ScanStrategy",
        "android-beacon-library_release"
    }
    k = 0x1
    mv = {
        0x1,
        0x8,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final Companion:Lorg/altbeacon/beacon/Settings$Companion;


# instance fields
.field private final beaconSimulator:Lorg/altbeacon/beacon/simulator/BeaconSimulator;

.field private final debug:Ljava/lang/Boolean;

.field private final distanceCalculatorFactory:Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;

.field private final distanceModelUpdateUrl:Ljava/lang/String;

.field private final hardwareEqualityEnforced:Ljava/lang/Boolean;

.field private final longScanForcingEnabled:Ljava/lang/Boolean;

.field private final manifestCheckingDisabled:Ljava/lang/Boolean;

.field private final maxTrackingAgeMillis:Ljava/lang/Integer;

.field private final regionExitPeriodMillis:Ljava/lang/Integer;

.field private final regionStatePersistenceEnabled:Ljava/lang/Boolean;

.field private final rssiFilterClass:Ljava/lang/Class;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/Class<",
            "*>;"
        }
    .end annotation
.end field

.field private final scanPeriods:Lorg/altbeacon/beacon/Settings$ScanPeriods;

.field private final scanStrategy:Lorg/altbeacon/beacon/Settings$ScanStrategy;

.field private final useTrackingCache:Ljava/lang/Boolean;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lorg/altbeacon/beacon/Settings$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lorg/altbeacon/beacon/Settings$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lorg/altbeacon/beacon/Settings;->Companion:Lorg/altbeacon/beacon/Settings$Companion;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>()V
    .locals 17

    .line 1
    const/16 v15, 0x3fff

    const/16 v16, 0x0

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    move-object/from16 v0, p0

    invoke-direct/range {v0 .. v16}, Lorg/altbeacon/beacon/Settings;-><init>(Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Lorg/altbeacon/beacon/Settings$ScanPeriods;Ljava/lang/Integer;Ljava/lang/Boolean;Ljava/lang/Integer;Ljava/lang/Boolean;Lorg/altbeacon/beacon/simulator/BeaconSimulator;Ljava/lang/Class;Ljava/lang/String;Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;Lorg/altbeacon/beacon/Settings$ScanStrategy;Ljava/lang/Boolean;ILkotlin/jvm/internal/g;)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Lorg/altbeacon/beacon/Settings$ScanPeriods;Ljava/lang/Integer;Ljava/lang/Boolean;Ljava/lang/Integer;Ljava/lang/Boolean;Lorg/altbeacon/beacon/simulator/BeaconSimulator;Ljava/lang/Class;Ljava/lang/String;Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;Lorg/altbeacon/beacon/Settings$ScanStrategy;Ljava/lang/Boolean;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/Boolean;",
            "Ljava/lang/Boolean;",
            "Ljava/lang/Boolean;",
            "Lorg/altbeacon/beacon/Settings$ScanPeriods;",
            "Ljava/lang/Integer;",
            "Ljava/lang/Boolean;",
            "Ljava/lang/Integer;",
            "Ljava/lang/Boolean;",
            "Lorg/altbeacon/beacon/simulator/BeaconSimulator;",
            "Ljava/lang/Class<",
            "*>;",
            "Ljava/lang/String;",
            "Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;",
            "Lorg/altbeacon/beacon/Settings$ScanStrategy;",
            "Ljava/lang/Boolean;",
            ")V"
        }
    .end annotation

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lorg/altbeacon/beacon/Settings;->debug:Ljava/lang/Boolean;

    .line 4
    iput-object p2, p0, Lorg/altbeacon/beacon/Settings;->regionStatePersistenceEnabled:Ljava/lang/Boolean;

    .line 5
    iput-object p3, p0, Lorg/altbeacon/beacon/Settings;->hardwareEqualityEnforced:Ljava/lang/Boolean;

    .line 6
    iput-object p4, p0, Lorg/altbeacon/beacon/Settings;->scanPeriods:Lorg/altbeacon/beacon/Settings$ScanPeriods;

    .line 7
    iput-object p5, p0, Lorg/altbeacon/beacon/Settings;->regionExitPeriodMillis:Ljava/lang/Integer;

    .line 8
    iput-object p6, p0, Lorg/altbeacon/beacon/Settings;->useTrackingCache:Ljava/lang/Boolean;

    .line 9
    iput-object p7, p0, Lorg/altbeacon/beacon/Settings;->maxTrackingAgeMillis:Ljava/lang/Integer;

    .line 10
    iput-object p8, p0, Lorg/altbeacon/beacon/Settings;->manifestCheckingDisabled:Ljava/lang/Boolean;

    .line 11
    iput-object p9, p0, Lorg/altbeacon/beacon/Settings;->beaconSimulator:Lorg/altbeacon/beacon/simulator/BeaconSimulator;

    .line 12
    iput-object p10, p0, Lorg/altbeacon/beacon/Settings;->rssiFilterClass:Ljava/lang/Class;

    .line 13
    iput-object p11, p0, Lorg/altbeacon/beacon/Settings;->distanceModelUpdateUrl:Ljava/lang/String;

    .line 14
    iput-object p12, p0, Lorg/altbeacon/beacon/Settings;->distanceCalculatorFactory:Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;

    .line 15
    iput-object p13, p0, Lorg/altbeacon/beacon/Settings;->scanStrategy:Lorg/altbeacon/beacon/Settings$ScanStrategy;

    .line 16
    iput-object p14, p0, Lorg/altbeacon/beacon/Settings;->longScanForcingEnabled:Ljava/lang/Boolean;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Lorg/altbeacon/beacon/Settings$ScanPeriods;Ljava/lang/Integer;Ljava/lang/Boolean;Ljava/lang/Integer;Ljava/lang/Boolean;Lorg/altbeacon/beacon/simulator/BeaconSimulator;Ljava/lang/Class;Ljava/lang/String;Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;Lorg/altbeacon/beacon/Settings$ScanStrategy;Ljava/lang/Boolean;ILkotlin/jvm/internal/g;)V
    .locals 15

    move/from16 v0, p15

    and-int/lit8 v1, v0, 0x1

    const/4 v2, 0x0

    if-eqz v1, :cond_0

    move-object v1, v2

    goto :goto_0

    :cond_0
    move-object/from16 v1, p1

    :goto_0
    and-int/lit8 v3, v0, 0x2

    if-eqz v3, :cond_1

    move-object v3, v2

    goto :goto_1

    :cond_1
    move-object/from16 v3, p2

    :goto_1
    and-int/lit8 v4, v0, 0x4

    if-eqz v4, :cond_2

    move-object v4, v2

    goto :goto_2

    :cond_2
    move-object/from16 v4, p3

    :goto_2
    and-int/lit8 v5, v0, 0x8

    if-eqz v5, :cond_3

    move-object v5, v2

    goto :goto_3

    :cond_3
    move-object/from16 v5, p4

    :goto_3
    and-int/lit8 v6, v0, 0x10

    if-eqz v6, :cond_4

    move-object v6, v2

    goto :goto_4

    :cond_4
    move-object/from16 v6, p5

    :goto_4
    and-int/lit8 v7, v0, 0x20

    if-eqz v7, :cond_5

    move-object v7, v2

    goto :goto_5

    :cond_5
    move-object/from16 v7, p6

    :goto_5
    and-int/lit8 v8, v0, 0x40

    if-eqz v8, :cond_6

    move-object v8, v2

    goto :goto_6

    :cond_6
    move-object/from16 v8, p7

    :goto_6
    and-int/lit16 v9, v0, 0x80

    if-eqz v9, :cond_7

    move-object v9, v2

    goto :goto_7

    :cond_7
    move-object/from16 v9, p8

    :goto_7
    and-int/lit16 v10, v0, 0x100

    if-eqz v10, :cond_8

    move-object v10, v2

    goto :goto_8

    :cond_8
    move-object/from16 v10, p9

    :goto_8
    and-int/lit16 v11, v0, 0x200

    if-eqz v11, :cond_9

    move-object v11, v2

    goto :goto_9

    :cond_9
    move-object/from16 v11, p10

    :goto_9
    and-int/lit16 v12, v0, 0x400

    if-eqz v12, :cond_a

    move-object v12, v2

    goto :goto_a

    :cond_a
    move-object/from16 v12, p11

    :goto_a
    and-int/lit16 v13, v0, 0x800

    if-eqz v13, :cond_b

    move-object v13, v2

    goto :goto_b

    :cond_b
    move-object/from16 v13, p12

    :goto_b
    and-int/lit16 v14, v0, 0x1000

    if-eqz v14, :cond_c

    move-object v14, v2

    goto :goto_c

    :cond_c
    move-object/from16 v14, p13

    :goto_c
    and-int/lit16 v0, v0, 0x2000

    if-eqz v0, :cond_d

    move-object/from16 p15, v2

    :goto_d
    move-object/from16 p1, p0

    move-object/from16 p2, v1

    move-object/from16 p3, v3

    move-object/from16 p4, v4

    move-object/from16 p5, v5

    move-object/from16 p6, v6

    move-object/from16 p7, v7

    move-object/from16 p8, v8

    move-object/from16 p9, v9

    move-object/from16 p10, v10

    move-object/from16 p11, v11

    move-object/from16 p12, v12

    move-object/from16 p13, v13

    move-object/from16 p14, v14

    goto :goto_e

    :cond_d
    move-object/from16 p15, p14

    goto :goto_d

    .line 17
    :goto_e
    invoke-direct/range {p1 .. p15}, Lorg/altbeacon/beacon/Settings;-><init>(Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Lorg/altbeacon/beacon/Settings$ScanPeriods;Ljava/lang/Integer;Ljava/lang/Boolean;Ljava/lang/Integer;Ljava/lang/Boolean;Lorg/altbeacon/beacon/simulator/BeaconSimulator;Ljava/lang/Class;Ljava/lang/String;Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;Lorg/altbeacon/beacon/Settings$ScanStrategy;Ljava/lang/Boolean;)V

    return-void
.end method

.method public static synthetic copy$default(Lorg/altbeacon/beacon/Settings;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Lorg/altbeacon/beacon/Settings$ScanPeriods;Ljava/lang/Integer;Ljava/lang/Boolean;Ljava/lang/Integer;Ljava/lang/Boolean;Lorg/altbeacon/beacon/simulator/BeaconSimulator;Ljava/lang/Class;Ljava/lang/String;Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;Lorg/altbeacon/beacon/Settings$ScanStrategy;Ljava/lang/Boolean;ILjava/lang/Object;)Lorg/altbeacon/beacon/Settings;
    .locals 14

    .line 1
    move/from16 v0, p15

    and-int/lit8 v1, v0, 0x1

    if-eqz v1, :cond_0

    iget-object v1, p0, Lorg/altbeacon/beacon/Settings;->debug:Ljava/lang/Boolean;

    goto :goto_0

    :cond_0
    move-object v1, p1

    :goto_0
    and-int/lit8 v2, v0, 0x2

    if-eqz v2, :cond_1

    iget-object v2, p0, Lorg/altbeacon/beacon/Settings;->regionStatePersistenceEnabled:Ljava/lang/Boolean;

    goto :goto_1

    :cond_1
    move-object/from16 v2, p2

    :goto_1
    and-int/lit8 v3, v0, 0x4

    if-eqz v3, :cond_2

    iget-object v3, p0, Lorg/altbeacon/beacon/Settings;->hardwareEqualityEnforced:Ljava/lang/Boolean;

    goto :goto_2

    :cond_2
    move-object/from16 v3, p3

    :goto_2
    and-int/lit8 v4, v0, 0x8

    if-eqz v4, :cond_3

    iget-object v4, p0, Lorg/altbeacon/beacon/Settings;->scanPeriods:Lorg/altbeacon/beacon/Settings$ScanPeriods;

    goto :goto_3

    :cond_3
    move-object/from16 v4, p4

    :goto_3
    and-int/lit8 v5, v0, 0x10

    if-eqz v5, :cond_4

    iget-object v5, p0, Lorg/altbeacon/beacon/Settings;->regionExitPeriodMillis:Ljava/lang/Integer;

    goto :goto_4

    :cond_4
    move-object/from16 v5, p5

    :goto_4
    and-int/lit8 v6, v0, 0x20

    if-eqz v6, :cond_5

    iget-object v6, p0, Lorg/altbeacon/beacon/Settings;->useTrackingCache:Ljava/lang/Boolean;

    goto :goto_5

    :cond_5
    move-object/from16 v6, p6

    :goto_5
    and-int/lit8 v7, v0, 0x40

    if-eqz v7, :cond_6

    iget-object v7, p0, Lorg/altbeacon/beacon/Settings;->maxTrackingAgeMillis:Ljava/lang/Integer;

    goto :goto_6

    :cond_6
    move-object/from16 v7, p7

    :goto_6
    and-int/lit16 v8, v0, 0x80

    if-eqz v8, :cond_7

    iget-object v8, p0, Lorg/altbeacon/beacon/Settings;->manifestCheckingDisabled:Ljava/lang/Boolean;

    goto :goto_7

    :cond_7
    move-object/from16 v8, p8

    :goto_7
    and-int/lit16 v9, v0, 0x100

    if-eqz v9, :cond_8

    iget-object v9, p0, Lorg/altbeacon/beacon/Settings;->beaconSimulator:Lorg/altbeacon/beacon/simulator/BeaconSimulator;

    goto :goto_8

    :cond_8
    move-object/from16 v9, p9

    :goto_8
    and-int/lit16 v10, v0, 0x200

    if-eqz v10, :cond_9

    iget-object v10, p0, Lorg/altbeacon/beacon/Settings;->rssiFilterClass:Ljava/lang/Class;

    goto :goto_9

    :cond_9
    move-object/from16 v10, p10

    :goto_9
    and-int/lit16 v11, v0, 0x400

    if-eqz v11, :cond_a

    iget-object v11, p0, Lorg/altbeacon/beacon/Settings;->distanceModelUpdateUrl:Ljava/lang/String;

    goto :goto_a

    :cond_a
    move-object/from16 v11, p11

    :goto_a
    and-int/lit16 v12, v0, 0x800

    if-eqz v12, :cond_b

    iget-object v12, p0, Lorg/altbeacon/beacon/Settings;->distanceCalculatorFactory:Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;

    goto :goto_b

    :cond_b
    move-object/from16 v12, p12

    :goto_b
    and-int/lit16 v13, v0, 0x1000

    if-eqz v13, :cond_c

    iget-object v13, p0, Lorg/altbeacon/beacon/Settings;->scanStrategy:Lorg/altbeacon/beacon/Settings$ScanStrategy;

    goto :goto_c

    :cond_c
    move-object/from16 v13, p13

    :goto_c
    and-int/lit16 v0, v0, 0x2000

    if-eqz v0, :cond_d

    iget-object v0, p0, Lorg/altbeacon/beacon/Settings;->longScanForcingEnabled:Ljava/lang/Boolean;

    move-object/from16 p15, v0

    :goto_d
    move-object p1, p0

    move-object/from16 p2, v1

    move-object/from16 p3, v2

    move-object/from16 p4, v3

    move-object/from16 p5, v4

    move-object/from16 p6, v5

    move-object/from16 p7, v6

    move-object/from16 p8, v7

    move-object/from16 p9, v8

    move-object/from16 p10, v9

    move-object/from16 p11, v10

    move-object/from16 p12, v11

    move-object/from16 p13, v12

    move-object/from16 p14, v13

    goto :goto_e

    :cond_d
    move-object/from16 p15, p14

    goto :goto_d

    :goto_e
    invoke-virtual/range {p1 .. p15}, Lorg/altbeacon/beacon/Settings;->copy(Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Lorg/altbeacon/beacon/Settings$ScanPeriods;Ljava/lang/Integer;Ljava/lang/Boolean;Ljava/lang/Integer;Ljava/lang/Boolean;Lorg/altbeacon/beacon/simulator/BeaconSimulator;Ljava/lang/Class;Ljava/lang/String;Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;Lorg/altbeacon/beacon/Settings$ScanStrategy;Ljava/lang/Boolean;)Lorg/altbeacon/beacon/Settings;

    move-result-object p0

    return-object p0
.end method


# virtual methods
.method public final component1()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings;->debug:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component10()Ljava/lang/Class;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/lang/Class<",
            "*>;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings;->rssiFilterClass:Ljava/lang/Class;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component11()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings;->distanceModelUpdateUrl:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component12()Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings;->distanceCalculatorFactory:Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component13()Lorg/altbeacon/beacon/Settings$ScanStrategy;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings;->scanStrategy:Lorg/altbeacon/beacon/Settings$ScanStrategy;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component14()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings;->longScanForcingEnabled:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings;->regionStatePersistenceEnabled:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings;->hardwareEqualityEnforced:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component4()Lorg/altbeacon/beacon/Settings$ScanPeriods;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings;->scanPeriods:Lorg/altbeacon/beacon/Settings$ScanPeriods;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component5()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings;->regionExitPeriodMillis:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component6()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings;->useTrackingCache:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component7()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings;->maxTrackingAgeMillis:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component8()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings;->manifestCheckingDisabled:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component9()Lorg/altbeacon/beacon/simulator/BeaconSimulator;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings;->beaconSimulator:Lorg/altbeacon/beacon/simulator/BeaconSimulator;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Lorg/altbeacon/beacon/Settings$ScanPeriods;Ljava/lang/Integer;Ljava/lang/Boolean;Ljava/lang/Integer;Ljava/lang/Boolean;Lorg/altbeacon/beacon/simulator/BeaconSimulator;Ljava/lang/Class;Ljava/lang/String;Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;Lorg/altbeacon/beacon/Settings$ScanStrategy;Ljava/lang/Boolean;)Lorg/altbeacon/beacon/Settings;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/Boolean;",
            "Ljava/lang/Boolean;",
            "Ljava/lang/Boolean;",
            "Lorg/altbeacon/beacon/Settings$ScanPeriods;",
            "Ljava/lang/Integer;",
            "Ljava/lang/Boolean;",
            "Ljava/lang/Integer;",
            "Ljava/lang/Boolean;",
            "Lorg/altbeacon/beacon/simulator/BeaconSimulator;",
            "Ljava/lang/Class<",
            "*>;",
            "Ljava/lang/String;",
            "Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;",
            "Lorg/altbeacon/beacon/Settings$ScanStrategy;",
            "Ljava/lang/Boolean;",
            ")",
            "Lorg/altbeacon/beacon/Settings;"
        }
    .end annotation

    .line 1
    new-instance p0, Lorg/altbeacon/beacon/Settings;

    .line 2
    .line 3
    invoke-direct/range {p0 .. p14}, Lorg/altbeacon/beacon/Settings;-><init>(Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Lorg/altbeacon/beacon/Settings$ScanPeriods;Ljava/lang/Integer;Ljava/lang/Boolean;Ljava/lang/Integer;Ljava/lang/Boolean;Lorg/altbeacon/beacon/simulator/BeaconSimulator;Ljava/lang/Class;Ljava/lang/String;Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;Lorg/altbeacon/beacon/Settings$ScanStrategy;Ljava/lang/Boolean;)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lorg/altbeacon/beacon/Settings;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Lorg/altbeacon/beacon/Settings;

    .line 12
    .line 13
    iget-object v1, p0, Lorg/altbeacon/beacon/Settings;->debug:Ljava/lang/Boolean;

    .line 14
    .line 15
    iget-object v3, p1, Lorg/altbeacon/beacon/Settings;->debug:Ljava/lang/Boolean;

    .line 16
    .line 17
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-object v1, p0, Lorg/altbeacon/beacon/Settings;->regionStatePersistenceEnabled:Ljava/lang/Boolean;

    .line 25
    .line 26
    iget-object v3, p1, Lorg/altbeacon/beacon/Settings;->regionStatePersistenceEnabled:Ljava/lang/Boolean;

    .line 27
    .line 28
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-nez v1, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    iget-object v1, p0, Lorg/altbeacon/beacon/Settings;->hardwareEqualityEnforced:Ljava/lang/Boolean;

    .line 36
    .line 37
    iget-object v3, p1, Lorg/altbeacon/beacon/Settings;->hardwareEqualityEnforced:Ljava/lang/Boolean;

    .line 38
    .line 39
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-nez v1, :cond_4

    .line 44
    .line 45
    return v2

    .line 46
    :cond_4
    iget-object v1, p0, Lorg/altbeacon/beacon/Settings;->scanPeriods:Lorg/altbeacon/beacon/Settings$ScanPeriods;

    .line 47
    .line 48
    iget-object v3, p1, Lorg/altbeacon/beacon/Settings;->scanPeriods:Lorg/altbeacon/beacon/Settings$ScanPeriods;

    .line 49
    .line 50
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    if-nez v1, :cond_5

    .line 55
    .line 56
    return v2

    .line 57
    :cond_5
    iget-object v1, p0, Lorg/altbeacon/beacon/Settings;->regionExitPeriodMillis:Ljava/lang/Integer;

    .line 58
    .line 59
    iget-object v3, p1, Lorg/altbeacon/beacon/Settings;->regionExitPeriodMillis:Ljava/lang/Integer;

    .line 60
    .line 61
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    if-nez v1, :cond_6

    .line 66
    .line 67
    return v2

    .line 68
    :cond_6
    iget-object v1, p0, Lorg/altbeacon/beacon/Settings;->useTrackingCache:Ljava/lang/Boolean;

    .line 69
    .line 70
    iget-object v3, p1, Lorg/altbeacon/beacon/Settings;->useTrackingCache:Ljava/lang/Boolean;

    .line 71
    .line 72
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result v1

    .line 76
    if-nez v1, :cond_7

    .line 77
    .line 78
    return v2

    .line 79
    :cond_7
    iget-object v1, p0, Lorg/altbeacon/beacon/Settings;->maxTrackingAgeMillis:Ljava/lang/Integer;

    .line 80
    .line 81
    iget-object v3, p1, Lorg/altbeacon/beacon/Settings;->maxTrackingAgeMillis:Ljava/lang/Integer;

    .line 82
    .line 83
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 84
    .line 85
    .line 86
    move-result v1

    .line 87
    if-nez v1, :cond_8

    .line 88
    .line 89
    return v2

    .line 90
    :cond_8
    iget-object v1, p0, Lorg/altbeacon/beacon/Settings;->manifestCheckingDisabled:Ljava/lang/Boolean;

    .line 91
    .line 92
    iget-object v3, p1, Lorg/altbeacon/beacon/Settings;->manifestCheckingDisabled:Ljava/lang/Boolean;

    .line 93
    .line 94
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 95
    .line 96
    .line 97
    move-result v1

    .line 98
    if-nez v1, :cond_9

    .line 99
    .line 100
    return v2

    .line 101
    :cond_9
    iget-object v1, p0, Lorg/altbeacon/beacon/Settings;->beaconSimulator:Lorg/altbeacon/beacon/simulator/BeaconSimulator;

    .line 102
    .line 103
    iget-object v3, p1, Lorg/altbeacon/beacon/Settings;->beaconSimulator:Lorg/altbeacon/beacon/simulator/BeaconSimulator;

    .line 104
    .line 105
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 106
    .line 107
    .line 108
    move-result v1

    .line 109
    if-nez v1, :cond_a

    .line 110
    .line 111
    return v2

    .line 112
    :cond_a
    iget-object v1, p0, Lorg/altbeacon/beacon/Settings;->rssiFilterClass:Ljava/lang/Class;

    .line 113
    .line 114
    iget-object v3, p1, Lorg/altbeacon/beacon/Settings;->rssiFilterClass:Ljava/lang/Class;

    .line 115
    .line 116
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 117
    .line 118
    .line 119
    move-result v1

    .line 120
    if-nez v1, :cond_b

    .line 121
    .line 122
    return v2

    .line 123
    :cond_b
    iget-object v1, p0, Lorg/altbeacon/beacon/Settings;->distanceModelUpdateUrl:Ljava/lang/String;

    .line 124
    .line 125
    iget-object v3, p1, Lorg/altbeacon/beacon/Settings;->distanceModelUpdateUrl:Ljava/lang/String;

    .line 126
    .line 127
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 128
    .line 129
    .line 130
    move-result v1

    .line 131
    if-nez v1, :cond_c

    .line 132
    .line 133
    return v2

    .line 134
    :cond_c
    iget-object v1, p0, Lorg/altbeacon/beacon/Settings;->distanceCalculatorFactory:Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;

    .line 135
    .line 136
    iget-object v3, p1, Lorg/altbeacon/beacon/Settings;->distanceCalculatorFactory:Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;

    .line 137
    .line 138
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 139
    .line 140
    .line 141
    move-result v1

    .line 142
    if-nez v1, :cond_d

    .line 143
    .line 144
    return v2

    .line 145
    :cond_d
    iget-object v1, p0, Lorg/altbeacon/beacon/Settings;->scanStrategy:Lorg/altbeacon/beacon/Settings$ScanStrategy;

    .line 146
    .line 147
    iget-object v3, p1, Lorg/altbeacon/beacon/Settings;->scanStrategy:Lorg/altbeacon/beacon/Settings$ScanStrategy;

    .line 148
    .line 149
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 150
    .line 151
    .line 152
    move-result v1

    .line 153
    if-nez v1, :cond_e

    .line 154
    .line 155
    return v2

    .line 156
    :cond_e
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings;->longScanForcingEnabled:Ljava/lang/Boolean;

    .line 157
    .line 158
    iget-object p1, p1, Lorg/altbeacon/beacon/Settings;->longScanForcingEnabled:Ljava/lang/Boolean;

    .line 159
    .line 160
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 161
    .line 162
    .line 163
    move-result p0

    .line 164
    if-nez p0, :cond_f

    .line 165
    .line 166
    return v2

    .line 167
    :cond_f
    return v0
.end method

.method public final getBeaconSimulator()Lorg/altbeacon/beacon/simulator/BeaconSimulator;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings;->beaconSimulator:Lorg/altbeacon/beacon/simulator/BeaconSimulator;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getDebug()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings;->debug:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getDistanceCalculatorFactory()Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings;->distanceCalculatorFactory:Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getDistanceModelUpdateUrl()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings;->distanceModelUpdateUrl:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getHardwareEqualityEnforced()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings;->hardwareEqualityEnforced:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getLongScanForcingEnabled()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings;->longScanForcingEnabled:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getManifestCheckingDisabled()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings;->manifestCheckingDisabled:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getMaxTrackingAgeMillis()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings;->maxTrackingAgeMillis:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getRegionExitPeriodMillis()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings;->regionExitPeriodMillis:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getRegionStatePersistenceEnabled()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings;->regionStatePersistenceEnabled:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getRssiFilterClass()Ljava/lang/Class;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/lang/Class<",
            "*>;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings;->rssiFilterClass:Ljava/lang/Class;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getScanPeriods()Lorg/altbeacon/beacon/Settings$ScanPeriods;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings;->scanPeriods:Lorg/altbeacon/beacon/Settings$ScanPeriods;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getScanStrategy()Lorg/altbeacon/beacon/Settings$ScanStrategy;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings;->scanStrategy:Lorg/altbeacon/beacon/Settings$ScanStrategy;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getUseTrackingCache()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings;->useTrackingCache:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/Settings;->debug:Ljava/lang/Boolean;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    move v0, v1

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    :goto_0
    mul-int/lit8 v0, v0, 0x1f

    .line 13
    .line 14
    iget-object v2, p0, Lorg/altbeacon/beacon/Settings;->regionStatePersistenceEnabled:Ljava/lang/Boolean;

    .line 15
    .line 16
    if-nez v2, :cond_1

    .line 17
    .line 18
    move v2, v1

    .line 19
    goto :goto_1

    .line 20
    :cond_1
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    :goto_1
    add-int/2addr v0, v2

    .line 25
    mul-int/lit8 v0, v0, 0x1f

    .line 26
    .line 27
    iget-object v2, p0, Lorg/altbeacon/beacon/Settings;->hardwareEqualityEnforced:Ljava/lang/Boolean;

    .line 28
    .line 29
    if-nez v2, :cond_2

    .line 30
    .line 31
    move v2, v1

    .line 32
    goto :goto_2

    .line 33
    :cond_2
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    :goto_2
    add-int/2addr v0, v2

    .line 38
    mul-int/lit8 v0, v0, 0x1f

    .line 39
    .line 40
    iget-object v2, p0, Lorg/altbeacon/beacon/Settings;->scanPeriods:Lorg/altbeacon/beacon/Settings$ScanPeriods;

    .line 41
    .line 42
    if-nez v2, :cond_3

    .line 43
    .line 44
    move v2, v1

    .line 45
    goto :goto_3

    .line 46
    :cond_3
    invoke-virtual {v2}, Lorg/altbeacon/beacon/Settings$ScanPeriods;->hashCode()I

    .line 47
    .line 48
    .line 49
    move-result v2

    .line 50
    :goto_3
    add-int/2addr v0, v2

    .line 51
    mul-int/lit8 v0, v0, 0x1f

    .line 52
    .line 53
    iget-object v2, p0, Lorg/altbeacon/beacon/Settings;->regionExitPeriodMillis:Ljava/lang/Integer;

    .line 54
    .line 55
    if-nez v2, :cond_4

    .line 56
    .line 57
    move v2, v1

    .line 58
    goto :goto_4

    .line 59
    :cond_4
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 60
    .line 61
    .line 62
    move-result v2

    .line 63
    :goto_4
    add-int/2addr v0, v2

    .line 64
    mul-int/lit8 v0, v0, 0x1f

    .line 65
    .line 66
    iget-object v2, p0, Lorg/altbeacon/beacon/Settings;->useTrackingCache:Ljava/lang/Boolean;

    .line 67
    .line 68
    if-nez v2, :cond_5

    .line 69
    .line 70
    move v2, v1

    .line 71
    goto :goto_5

    .line 72
    :cond_5
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 73
    .line 74
    .line 75
    move-result v2

    .line 76
    :goto_5
    add-int/2addr v0, v2

    .line 77
    mul-int/lit8 v0, v0, 0x1f

    .line 78
    .line 79
    iget-object v2, p0, Lorg/altbeacon/beacon/Settings;->maxTrackingAgeMillis:Ljava/lang/Integer;

    .line 80
    .line 81
    if-nez v2, :cond_6

    .line 82
    .line 83
    move v2, v1

    .line 84
    goto :goto_6

    .line 85
    :cond_6
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 86
    .line 87
    .line 88
    move-result v2

    .line 89
    :goto_6
    add-int/2addr v0, v2

    .line 90
    mul-int/lit8 v0, v0, 0x1f

    .line 91
    .line 92
    iget-object v2, p0, Lorg/altbeacon/beacon/Settings;->manifestCheckingDisabled:Ljava/lang/Boolean;

    .line 93
    .line 94
    if-nez v2, :cond_7

    .line 95
    .line 96
    move v2, v1

    .line 97
    goto :goto_7

    .line 98
    :cond_7
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 99
    .line 100
    .line 101
    move-result v2

    .line 102
    :goto_7
    add-int/2addr v0, v2

    .line 103
    mul-int/lit8 v0, v0, 0x1f

    .line 104
    .line 105
    iget-object v2, p0, Lorg/altbeacon/beacon/Settings;->beaconSimulator:Lorg/altbeacon/beacon/simulator/BeaconSimulator;

    .line 106
    .line 107
    if-nez v2, :cond_8

    .line 108
    .line 109
    move v2, v1

    .line 110
    goto :goto_8

    .line 111
    :cond_8
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 112
    .line 113
    .line 114
    move-result v2

    .line 115
    :goto_8
    add-int/2addr v0, v2

    .line 116
    mul-int/lit8 v0, v0, 0x1f

    .line 117
    .line 118
    iget-object v2, p0, Lorg/altbeacon/beacon/Settings;->rssiFilterClass:Ljava/lang/Class;

    .line 119
    .line 120
    if-nez v2, :cond_9

    .line 121
    .line 122
    move v2, v1

    .line 123
    goto :goto_9

    .line 124
    :cond_9
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 125
    .line 126
    .line 127
    move-result v2

    .line 128
    :goto_9
    add-int/2addr v0, v2

    .line 129
    mul-int/lit8 v0, v0, 0x1f

    .line 130
    .line 131
    iget-object v2, p0, Lorg/altbeacon/beacon/Settings;->distanceModelUpdateUrl:Ljava/lang/String;

    .line 132
    .line 133
    if-nez v2, :cond_a

    .line 134
    .line 135
    move v2, v1

    .line 136
    goto :goto_a

    .line 137
    :cond_a
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 138
    .line 139
    .line 140
    move-result v2

    .line 141
    :goto_a
    add-int/2addr v0, v2

    .line 142
    mul-int/lit8 v0, v0, 0x1f

    .line 143
    .line 144
    iget-object v2, p0, Lorg/altbeacon/beacon/Settings;->distanceCalculatorFactory:Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;

    .line 145
    .line 146
    if-nez v2, :cond_b

    .line 147
    .line 148
    move v2, v1

    .line 149
    goto :goto_b

    .line 150
    :cond_b
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 151
    .line 152
    .line 153
    move-result v2

    .line 154
    :goto_b
    add-int/2addr v0, v2

    .line 155
    mul-int/lit8 v0, v0, 0x1f

    .line 156
    .line 157
    iget-object v2, p0, Lorg/altbeacon/beacon/Settings;->scanStrategy:Lorg/altbeacon/beacon/Settings$ScanStrategy;

    .line 158
    .line 159
    if-nez v2, :cond_c

    .line 160
    .line 161
    move v2, v1

    .line 162
    goto :goto_c

    .line 163
    :cond_c
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 164
    .line 165
    .line 166
    move-result v2

    .line 167
    :goto_c
    add-int/2addr v0, v2

    .line 168
    mul-int/lit8 v0, v0, 0x1f

    .line 169
    .line 170
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings;->longScanForcingEnabled:Ljava/lang/Boolean;

    .line 171
    .line 172
    if-nez p0, :cond_d

    .line 173
    .line 174
    goto :goto_d

    .line 175
    :cond_d
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 176
    .line 177
    .line 178
    move-result v1

    .line 179
    :goto_d
    add-int/2addr v0, v1

    .line 180
    return v0
.end method

.method public toString()Ljava/lang/String;
    .locals 15

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/Settings;->debug:Ljava/lang/Boolean;

    .line 2
    .line 3
    iget-object v1, p0, Lorg/altbeacon/beacon/Settings;->regionStatePersistenceEnabled:Ljava/lang/Boolean;

    .line 4
    .line 5
    iget-object v2, p0, Lorg/altbeacon/beacon/Settings;->hardwareEqualityEnforced:Ljava/lang/Boolean;

    .line 6
    .line 7
    iget-object v3, p0, Lorg/altbeacon/beacon/Settings;->scanPeriods:Lorg/altbeacon/beacon/Settings$ScanPeriods;

    .line 8
    .line 9
    iget-object v4, p0, Lorg/altbeacon/beacon/Settings;->regionExitPeriodMillis:Ljava/lang/Integer;

    .line 10
    .line 11
    iget-object v5, p0, Lorg/altbeacon/beacon/Settings;->useTrackingCache:Ljava/lang/Boolean;

    .line 12
    .line 13
    iget-object v6, p0, Lorg/altbeacon/beacon/Settings;->maxTrackingAgeMillis:Ljava/lang/Integer;

    .line 14
    .line 15
    iget-object v7, p0, Lorg/altbeacon/beacon/Settings;->manifestCheckingDisabled:Ljava/lang/Boolean;

    .line 16
    .line 17
    iget-object v8, p0, Lorg/altbeacon/beacon/Settings;->beaconSimulator:Lorg/altbeacon/beacon/simulator/BeaconSimulator;

    .line 18
    .line 19
    iget-object v9, p0, Lorg/altbeacon/beacon/Settings;->rssiFilterClass:Ljava/lang/Class;

    .line 20
    .line 21
    iget-object v10, p0, Lorg/altbeacon/beacon/Settings;->distanceModelUpdateUrl:Ljava/lang/String;

    .line 22
    .line 23
    iget-object v11, p0, Lorg/altbeacon/beacon/Settings;->distanceCalculatorFactory:Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;

    .line 24
    .line 25
    iget-object v12, p0, Lorg/altbeacon/beacon/Settings;->scanStrategy:Lorg/altbeacon/beacon/Settings$ScanStrategy;

    .line 26
    .line 27
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings;->longScanForcingEnabled:Ljava/lang/Boolean;

    .line 28
    .line 29
    new-instance v13, Ljava/lang/StringBuilder;

    .line 30
    .line 31
    const-string v14, "Settings(debug="

    .line 32
    .line 33
    invoke-direct {v13, v14}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {v13, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    const-string v0, ", regionStatePersistenceEnabled="

    .line 40
    .line 41
    invoke-virtual {v13, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    invoke-virtual {v13, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    const-string v0, ", hardwareEqualityEnforced="

    .line 48
    .line 49
    invoke-virtual {v13, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    invoke-virtual {v13, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    const-string v0, ", scanPeriods="

    .line 56
    .line 57
    invoke-virtual {v13, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    invoke-virtual {v13, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v0, ", regionExitPeriodMillis="

    .line 64
    .line 65
    invoke-virtual {v13, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    invoke-virtual {v13, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 69
    .line 70
    .line 71
    const-string v0, ", useTrackingCache="

    .line 72
    .line 73
    invoke-virtual {v13, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    invoke-virtual {v13, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    const-string v0, ", maxTrackingAgeMillis="

    .line 80
    .line 81
    invoke-virtual {v13, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    invoke-virtual {v13, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    const-string v0, ", manifestCheckingDisabled="

    .line 88
    .line 89
    invoke-virtual {v13, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    invoke-virtual {v13, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 93
    .line 94
    .line 95
    const-string v0, ", beaconSimulator="

    .line 96
    .line 97
    invoke-virtual {v13, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 98
    .line 99
    .line 100
    invoke-virtual {v13, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    const-string v0, ", rssiFilterClass="

    .line 104
    .line 105
    invoke-virtual {v13, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    invoke-virtual {v13, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 109
    .line 110
    .line 111
    const-string v0, ", distanceModelUpdateUrl="

    .line 112
    .line 113
    invoke-virtual {v13, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 114
    .line 115
    .line 116
    invoke-virtual {v13, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 117
    .line 118
    .line 119
    const-string v0, ", distanceCalculatorFactory="

    .line 120
    .line 121
    invoke-virtual {v13, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 122
    .line 123
    .line 124
    invoke-virtual {v13, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 125
    .line 126
    .line 127
    const-string v0, ", scanStrategy="

    .line 128
    .line 129
    invoke-virtual {v13, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 130
    .line 131
    .line 132
    invoke-virtual {v13, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 133
    .line 134
    .line 135
    const-string v0, ", longScanForcingEnabled="

    .line 136
    .line 137
    invoke-virtual {v13, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 138
    .line 139
    .line 140
    invoke-virtual {v13, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 141
    .line 142
    .line 143
    const-string p0, ")"

    .line 144
    .line 145
    invoke-virtual {v13, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 146
    .line 147
    .line 148
    invoke-virtual {v13}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 149
    .line 150
    .line 151
    move-result-object p0

    .line 152
    return-object p0
.end method
