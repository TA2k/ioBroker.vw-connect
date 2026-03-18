.class public final Lorg/altbeacon/beacon/Settings$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lorg/altbeacon/beacon/Settings;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u001a\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0008\u0086\u0003\u0018\u00002\u00020\u0001B\u0007\u0008\u0002\u00a2\u0006\u0002\u0010\u0002J\u000e\u0010\u0003\u001a\u00020\u00042\u0006\u0010\u0005\u001a\u00020\u0006J\u000e\u0010\u0007\u001a\u00020\u00042\u0006\u0010\u0008\u001a\u00020\u0004\u00a8\u0006\t"
    }
    d2 = {
        "Lorg/altbeacon/beacon/Settings$Companion;",
        "",
        "()V",
        "fromBuilder",
        "Lorg/altbeacon/beacon/Settings;",
        "builder",
        "Lorg/altbeacon/beacon/Settings$Builder;",
        "fromSettings",
        "other",
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


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lorg/altbeacon/beacon/Settings$Companion;-><init>()V

    return-void
.end method


# virtual methods
.method public final fromBuilder(Lorg/altbeacon/beacon/Settings$Builder;)Lorg/altbeacon/beacon/Settings;
    .locals 16

    .line 1
    const-string v0, "builder"

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v1}, Lorg/altbeacon/beacon/Settings$Builder;->get_scanPeriods$android_beacon_library_release()Lorg/altbeacon/beacon/Settings$ScanPeriods;

    .line 9
    .line 10
    .line 11
    move-result-object v5

    .line 12
    invoke-virtual {v1}, Lorg/altbeacon/beacon/Settings$Builder;->get_debug$android_beacon_library_release()Ljava/lang/Boolean;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    invoke-virtual {v1}, Lorg/altbeacon/beacon/Settings$Builder;->get_regionStatePeristenceEnabled$android_beacon_library_release()Ljava/lang/Boolean;

    .line 17
    .line 18
    .line 19
    move-result-object v3

    .line 20
    invoke-virtual {v1}, Lorg/altbeacon/beacon/Settings$Builder;->get_useTrackingCache$android_beacon_library_release()Ljava/lang/Boolean;

    .line 21
    .line 22
    .line 23
    move-result-object v7

    .line 24
    invoke-virtual {v1}, Lorg/altbeacon/beacon/Settings$Builder;->get_hardwareEqualityEnforced$android_beacon_library_release()Ljava/lang/Boolean;

    .line 25
    .line 26
    .line 27
    move-result-object v4

    .line 28
    invoke-virtual {v1}, Lorg/altbeacon/beacon/Settings$Builder;->get_regionExitPeriodMillis$android_beacon_library_release()Ljava/lang/Integer;

    .line 29
    .line 30
    .line 31
    move-result-object v6

    .line 32
    invoke-virtual {v1}, Lorg/altbeacon/beacon/Settings$Builder;->get_maxTrackingAgeMillis$android_beacon_library_release()Ljava/lang/Integer;

    .line 33
    .line 34
    .line 35
    move-result-object v8

    .line 36
    invoke-virtual {v1}, Lorg/altbeacon/beacon/Settings$Builder;->get_manifestCheckingDisabled$android_beacon_library_release()Ljava/lang/Boolean;

    .line 37
    .line 38
    .line 39
    move-result-object v9

    .line 40
    invoke-virtual {v1}, Lorg/altbeacon/beacon/Settings$Builder;->get_beaconSimulator$android_beacon_library_release()Lorg/altbeacon/beacon/simulator/BeaconSimulator;

    .line 41
    .line 42
    .line 43
    move-result-object v10

    .line 44
    invoke-virtual {v1}, Lorg/altbeacon/beacon/Settings$Builder;->get_rssiFilterClass$android_beacon_library_release()Ljava/lang/Class;

    .line 45
    .line 46
    .line 47
    move-result-object v11

    .line 48
    invoke-virtual {v1}, Lorg/altbeacon/beacon/Settings$Builder;->get_scanStrategy$android_beacon_library_release()Lorg/altbeacon/beacon/Settings$ScanStrategy;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    if-eqz v0, :cond_0

    .line 53
    .line 54
    invoke-interface {v0}, Lorg/altbeacon/beacon/Settings$ScanStrategy;->clone()Lorg/altbeacon/beacon/Settings$ScanStrategy;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    :goto_0
    move-object v14, v0

    .line 59
    goto :goto_1

    .line 60
    :cond_0
    const/4 v0, 0x0

    .line 61
    goto :goto_0

    .line 62
    :goto_1
    invoke-virtual {v1}, Lorg/altbeacon/beacon/Settings$Builder;->get_longScanForcingEnabled$android_beacon_library_release()Ljava/lang/Boolean;

    .line 63
    .line 64
    .line 65
    move-result-object v15

    .line 66
    invoke-virtual {v1}, Lorg/altbeacon/beacon/Settings$Builder;->get_distanceModelUpdateUrl$android_beacon_library_release()Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v12

    .line 70
    invoke-virtual {v1}, Lorg/altbeacon/beacon/Settings$Builder;->get_distanceCalculatorFactory$android_beacon_library_release()Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;

    .line 71
    .line 72
    .line 73
    move-result-object v13

    .line 74
    new-instance v1, Lorg/altbeacon/beacon/Settings;

    .line 75
    .line 76
    invoke-direct/range {v1 .. v15}, Lorg/altbeacon/beacon/Settings;-><init>(Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Lorg/altbeacon/beacon/Settings$ScanPeriods;Ljava/lang/Integer;Ljava/lang/Boolean;Ljava/lang/Integer;Ljava/lang/Boolean;Lorg/altbeacon/beacon/simulator/BeaconSimulator;Ljava/lang/Class;Ljava/lang/String;Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;Lorg/altbeacon/beacon/Settings$ScanStrategy;Ljava/lang/Boolean;)V

    .line 77
    .line 78
    .line 79
    return-object v1
.end method

.method public final fromSettings(Lorg/altbeacon/beacon/Settings;)Lorg/altbeacon/beacon/Settings;
    .locals 16

    .line 1
    const-string v0, "other"

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v1}, Lorg/altbeacon/beacon/Settings;->getScanPeriods()Lorg/altbeacon/beacon/Settings$ScanPeriods;

    .line 9
    .line 10
    .line 11
    move-result-object v5

    .line 12
    invoke-virtual {v1}, Lorg/altbeacon/beacon/Settings;->getDebug()Ljava/lang/Boolean;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    invoke-virtual {v1}, Lorg/altbeacon/beacon/Settings;->getRegionStatePersistenceEnabled()Ljava/lang/Boolean;

    .line 17
    .line 18
    .line 19
    move-result-object v3

    .line 20
    invoke-virtual {v1}, Lorg/altbeacon/beacon/Settings;->getUseTrackingCache()Ljava/lang/Boolean;

    .line 21
    .line 22
    .line 23
    move-result-object v7

    .line 24
    invoke-virtual {v1}, Lorg/altbeacon/beacon/Settings;->getHardwareEqualityEnforced()Ljava/lang/Boolean;

    .line 25
    .line 26
    .line 27
    move-result-object v4

    .line 28
    invoke-virtual {v1}, Lorg/altbeacon/beacon/Settings;->getRegionExitPeriodMillis()Ljava/lang/Integer;

    .line 29
    .line 30
    .line 31
    move-result-object v6

    .line 32
    invoke-virtual {v1}, Lorg/altbeacon/beacon/Settings;->getMaxTrackingAgeMillis()Ljava/lang/Integer;

    .line 33
    .line 34
    .line 35
    move-result-object v8

    .line 36
    invoke-virtual {v1}, Lorg/altbeacon/beacon/Settings;->getManifestCheckingDisabled()Ljava/lang/Boolean;

    .line 37
    .line 38
    .line 39
    move-result-object v9

    .line 40
    invoke-virtual {v1}, Lorg/altbeacon/beacon/Settings;->getBeaconSimulator()Lorg/altbeacon/beacon/simulator/BeaconSimulator;

    .line 41
    .line 42
    .line 43
    move-result-object v10

    .line 44
    invoke-virtual {v1}, Lorg/altbeacon/beacon/Settings;->getRssiFilterClass()Ljava/lang/Class;

    .line 45
    .line 46
    .line 47
    move-result-object v11

    .line 48
    invoke-virtual {v1}, Lorg/altbeacon/beacon/Settings;->getScanStrategy()Lorg/altbeacon/beacon/Settings$ScanStrategy;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    if-eqz v0, :cond_0

    .line 53
    .line 54
    invoke-interface {v0}, Lorg/altbeacon/beacon/Settings$ScanStrategy;->clone()Lorg/altbeacon/beacon/Settings$ScanStrategy;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    :goto_0
    move-object v14, v0

    .line 59
    goto :goto_1

    .line 60
    :cond_0
    const/4 v0, 0x0

    .line 61
    goto :goto_0

    .line 62
    :goto_1
    invoke-virtual {v1}, Lorg/altbeacon/beacon/Settings;->getLongScanForcingEnabled()Ljava/lang/Boolean;

    .line 63
    .line 64
    .line 65
    move-result-object v15

    .line 66
    invoke-virtual {v1}, Lorg/altbeacon/beacon/Settings;->getDistanceModelUpdateUrl()Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v12

    .line 70
    invoke-virtual {v1}, Lorg/altbeacon/beacon/Settings;->getDistanceCalculatorFactory()Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;

    .line 71
    .line 72
    .line 73
    move-result-object v13

    .line 74
    new-instance v1, Lorg/altbeacon/beacon/Settings;

    .line 75
    .line 76
    invoke-direct/range {v1 .. v15}, Lorg/altbeacon/beacon/Settings;-><init>(Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Lorg/altbeacon/beacon/Settings$ScanPeriods;Ljava/lang/Integer;Ljava/lang/Boolean;Ljava/lang/Integer;Ljava/lang/Boolean;Lorg/altbeacon/beacon/simulator/BeaconSimulator;Ljava/lang/Class;Ljava/lang/String;Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;Lorg/altbeacon/beacon/Settings$ScanStrategy;Ljava/lang/Boolean;)V

    .line 77
    .line 78
    .line 79
    return-object v1
.end method
