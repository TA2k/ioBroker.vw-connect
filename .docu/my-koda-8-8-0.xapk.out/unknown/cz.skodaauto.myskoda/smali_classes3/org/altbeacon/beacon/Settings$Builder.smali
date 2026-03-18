.class public final Lorg/altbeacon/beacon/Settings$Builder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lorg/altbeacon/beacon/Settings;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Builder"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000T\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0010\u000b\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0010\u000e\n\u0002\u0008\u000e\n\u0002\u0010\u0008\n\u0002\u0008\u000c\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u0008\n\u0002\u0018\u0002\n\u0002\u0008\u0011\u0018\u00002\u00020\u0001B\u0005\u00a2\u0006\u0002\u0010\u0002J\u0006\u0010G\u001a\u00020HJ\u000e\u0010I\u001a\u00020\u00002\u0006\u0010J\u001a\u00020\u0004J\u000e\u0010K\u001a\u00020\u00002\u0006\u0010L\u001a\u00020\nJ\u000e\u0010M\u001a\u00020\u00002\u0006\u0010N\u001a\u00020\u0011J\u000e\u0010O\u001a\u00020\u00002\u0006\u0010P\u001a\u00020\u0017J\u000e\u0010Q\u001a\u00020\u00002\u0006\u0010R\u001a\u00020\nJ\u0012\u0010S\u001a\u00020\u00002\n\u0010T\u001a\u0006\u0012\u0002\u0008\u000303J\u000e\u0010U\u001a\u00020\u00002\u0006\u0010V\u001a\u000209J\u000e\u0010W\u001a\u00020\u00002\u0006\u0010X\u001a\u00020?R\u001c\u0010\u0003\u001a\u0004\u0018\u00010\u0004X\u0080\u000e\u00a2\u0006\u000e\n\u0000\u001a\u0004\u0008\u0005\u0010\u0006\"\u0004\u0008\u0007\u0010\u0008R\u001e\u0010\t\u001a\u0004\u0018\u00010\nX\u0080\u000e\u00a2\u0006\u0010\n\u0002\u0010\u000f\u001a\u0004\u0008\u000b\u0010\u000c\"\u0004\u0008\r\u0010\u000eR\u001c\u0010\u0010\u001a\u0004\u0018\u00010\u0011X\u0080\u000e\u00a2\u0006\u000e\n\u0000\u001a\u0004\u0008\u0012\u0010\u0013\"\u0004\u0008\u0014\u0010\u0015R\u001c\u0010\u0016\u001a\u0004\u0018\u00010\u0017X\u0080\u000e\u00a2\u0006\u000e\n\u0000\u001a\u0004\u0008\u0018\u0010\u0019\"\u0004\u0008\u001a\u0010\u001bR\u001e\u0010\u001c\u001a\u0004\u0018\u00010\nX\u0080\u000e\u00a2\u0006\u0010\n\u0002\u0010\u000f\u001a\u0004\u0008\u001d\u0010\u000c\"\u0004\u0008\u001e\u0010\u000eR\u001e\u0010\u001f\u001a\u0004\u0018\u00010\nX\u0080\u000e\u00a2\u0006\u0010\n\u0002\u0010\u000f\u001a\u0004\u0008 \u0010\u000c\"\u0004\u0008!\u0010\u000eR\u001e\u0010\"\u001a\u0004\u0018\u00010\nX\u0080\u000e\u00a2\u0006\u0010\n\u0002\u0010\u000f\u001a\u0004\u0008#\u0010\u000c\"\u0004\u0008$\u0010\u000eR\u001e\u0010%\u001a\u0004\u0018\u00010&X\u0080\u000e\u00a2\u0006\u0010\n\u0002\u0010+\u001a\u0004\u0008\'\u0010(\"\u0004\u0008)\u0010*R\u001e\u0010,\u001a\u0004\u0018\u00010&X\u0080\u000e\u00a2\u0006\u0010\n\u0002\u0010+\u001a\u0004\u0008-\u0010(\"\u0004\u0008.\u0010*R\u001e\u0010/\u001a\u0004\u0018\u00010\nX\u0080\u000e\u00a2\u0006\u0010\n\u0002\u0010\u000f\u001a\u0004\u00080\u0010\u000c\"\u0004\u00081\u0010\u000eR \u00102\u001a\u0008\u0012\u0002\u0008\u0003\u0018\u000103X\u0080\u000e\u00a2\u0006\u000e\n\u0000\u001a\u0004\u00084\u00105\"\u0004\u00086\u00107R\u001c\u00108\u001a\u0004\u0018\u000109X\u0080\u000e\u00a2\u0006\u000e\n\u0000\u001a\u0004\u0008:\u0010;\"\u0004\u0008<\u0010=R\u001c\u0010>\u001a\u0004\u0018\u00010?X\u0080\u000e\u00a2\u0006\u000e\n\u0000\u001a\u0004\u0008@\u0010A\"\u0004\u0008B\u0010CR\u001e\u0010D\u001a\u0004\u0018\u00010\nX\u0080\u000e\u00a2\u0006\u0010\n\u0002\u0010\u000f\u001a\u0004\u0008E\u0010\u000c\"\u0004\u0008F\u0010\u000e\u00a8\u0006Y"
    }
    d2 = {
        "Lorg/altbeacon/beacon/Settings$Builder;",
        "",
        "()V",
        "_beaconSimulator",
        "Lorg/altbeacon/beacon/simulator/BeaconSimulator;",
        "get_beaconSimulator$android_beacon_library_release",
        "()Lorg/altbeacon/beacon/simulator/BeaconSimulator;",
        "set_beaconSimulator$android_beacon_library_release",
        "(Lorg/altbeacon/beacon/simulator/BeaconSimulator;)V",
        "_debug",
        "",
        "get_debug$android_beacon_library_release",
        "()Ljava/lang/Boolean;",
        "set_debug$android_beacon_library_release",
        "(Ljava/lang/Boolean;)V",
        "Ljava/lang/Boolean;",
        "_distanceCalculatorFactory",
        "Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;",
        "get_distanceCalculatorFactory$android_beacon_library_release",
        "()Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;",
        "set_distanceCalculatorFactory$android_beacon_library_release",
        "(Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;)V",
        "_distanceModelUpdateUrl",
        "",
        "get_distanceModelUpdateUrl$android_beacon_library_release",
        "()Ljava/lang/String;",
        "set_distanceModelUpdateUrl$android_beacon_library_release",
        "(Ljava/lang/String;)V",
        "_hardwareEqualityEnforced",
        "get_hardwareEqualityEnforced$android_beacon_library_release",
        "set_hardwareEqualityEnforced$android_beacon_library_release",
        "_longScanForcingEnabled",
        "get_longScanForcingEnabled$android_beacon_library_release",
        "set_longScanForcingEnabled$android_beacon_library_release",
        "_manifestCheckingDisabled",
        "get_manifestCheckingDisabled$android_beacon_library_release",
        "set_manifestCheckingDisabled$android_beacon_library_release",
        "_maxTrackingAgeMillis",
        "",
        "get_maxTrackingAgeMillis$android_beacon_library_release",
        "()Ljava/lang/Integer;",
        "set_maxTrackingAgeMillis$android_beacon_library_release",
        "(Ljava/lang/Integer;)V",
        "Ljava/lang/Integer;",
        "_regionExitPeriodMillis",
        "get_regionExitPeriodMillis$android_beacon_library_release",
        "set_regionExitPeriodMillis$android_beacon_library_release",
        "_regionStatePeristenceEnabled",
        "get_regionStatePeristenceEnabled$android_beacon_library_release",
        "set_regionStatePeristenceEnabled$android_beacon_library_release",
        "_rssiFilterClass",
        "Ljava/lang/Class;",
        "get_rssiFilterClass$android_beacon_library_release",
        "()Ljava/lang/Class;",
        "set_rssiFilterClass$android_beacon_library_release",
        "(Ljava/lang/Class;)V",
        "_scanPeriods",
        "Lorg/altbeacon/beacon/Settings$ScanPeriods;",
        "get_scanPeriods$android_beacon_library_release",
        "()Lorg/altbeacon/beacon/Settings$ScanPeriods;",
        "set_scanPeriods$android_beacon_library_release",
        "(Lorg/altbeacon/beacon/Settings$ScanPeriods;)V",
        "_scanStrategy",
        "Lorg/altbeacon/beacon/Settings$ScanStrategy;",
        "get_scanStrategy$android_beacon_library_release",
        "()Lorg/altbeacon/beacon/Settings$ScanStrategy;",
        "set_scanStrategy$android_beacon_library_release",
        "(Lorg/altbeacon/beacon/Settings$ScanStrategy;)V",
        "_useTrackingCache",
        "get_useTrackingCache$android_beacon_library_release",
        "set_useTrackingCache$android_beacon_library_release",
        "build",
        "Lorg/altbeacon/beacon/Settings;",
        "setBeaconSimulator",
        "beaconSimulator",
        "setDebug",
        "debug",
        "setDistanceCalculatorFactory",
        "factory",
        "setDistanceModelUpdateUrl",
        "url",
        "setLongScanForcingEnabled",
        "longScanForcingEnabled",
        "setRssiFilterClass",
        "rssiFilterClass",
        "setScanPeriods",
        "scanPeriods",
        "setScanStrategy",
        "scanStrategy",
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


# instance fields
.field private _beaconSimulator:Lorg/altbeacon/beacon/simulator/BeaconSimulator;

.field private _debug:Ljava/lang/Boolean;

.field private _distanceCalculatorFactory:Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;

.field private _distanceModelUpdateUrl:Ljava/lang/String;

.field private _hardwareEqualityEnforced:Ljava/lang/Boolean;

.field private _longScanForcingEnabled:Ljava/lang/Boolean;

.field private _manifestCheckingDisabled:Ljava/lang/Boolean;

.field private _maxTrackingAgeMillis:Ljava/lang/Integer;

.field private _regionExitPeriodMillis:Ljava/lang/Integer;

.field private _regionStatePeristenceEnabled:Ljava/lang/Boolean;

.field private _rssiFilterClass:Ljava/lang/Class;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/Class<",
            "*>;"
        }
    .end annotation
.end field

.field private _scanPeriods:Lorg/altbeacon/beacon/Settings$ScanPeriods;

.field private _scanStrategy:Lorg/altbeacon/beacon/Settings$ScanStrategy;

.field private _useTrackingCache:Ljava/lang/Boolean;


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public final build()Lorg/altbeacon/beacon/Settings;
    .locals 1

    .line 1
    sget-object v0, Lorg/altbeacon/beacon/Settings;->Companion:Lorg/altbeacon/beacon/Settings$Companion;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lorg/altbeacon/beacon/Settings$Companion;->fromBuilder(Lorg/altbeacon/beacon/Settings$Builder;)Lorg/altbeacon/beacon/Settings;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final get_beaconSimulator$android_beacon_library_release()Lorg/altbeacon/beacon/simulator/BeaconSimulator;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings$Builder;->_beaconSimulator:Lorg/altbeacon/beacon/simulator/BeaconSimulator;

    .line 2
    .line 3
    return-object p0
.end method

.method public final get_debug$android_beacon_library_release()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings$Builder;->_debug:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-object p0
.end method

.method public final get_distanceCalculatorFactory$android_beacon_library_release()Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings$Builder;->_distanceCalculatorFactory:Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;

    .line 2
    .line 3
    return-object p0
.end method

.method public final get_distanceModelUpdateUrl$android_beacon_library_release()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings$Builder;->_distanceModelUpdateUrl:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final get_hardwareEqualityEnforced$android_beacon_library_release()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings$Builder;->_hardwareEqualityEnforced:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-object p0
.end method

.method public final get_longScanForcingEnabled$android_beacon_library_release()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings$Builder;->_longScanForcingEnabled:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-object p0
.end method

.method public final get_manifestCheckingDisabled$android_beacon_library_release()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings$Builder;->_manifestCheckingDisabled:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-object p0
.end method

.method public final get_maxTrackingAgeMillis$android_beacon_library_release()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings$Builder;->_maxTrackingAgeMillis:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public final get_regionExitPeriodMillis$android_beacon_library_release()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings$Builder;->_regionExitPeriodMillis:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public final get_regionStatePeristenceEnabled$android_beacon_library_release()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings$Builder;->_regionStatePeristenceEnabled:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-object p0
.end method

.method public final get_rssiFilterClass$android_beacon_library_release()Ljava/lang/Class;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/lang/Class<",
            "*>;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings$Builder;->_rssiFilterClass:Ljava/lang/Class;

    .line 2
    .line 3
    return-object p0
.end method

.method public final get_scanPeriods$android_beacon_library_release()Lorg/altbeacon/beacon/Settings$ScanPeriods;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings$Builder;->_scanPeriods:Lorg/altbeacon/beacon/Settings$ScanPeriods;

    .line 2
    .line 3
    return-object p0
.end method

.method public final get_scanStrategy$android_beacon_library_release()Lorg/altbeacon/beacon/Settings$ScanStrategy;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings$Builder;->_scanStrategy:Lorg/altbeacon/beacon/Settings$ScanStrategy;

    .line 2
    .line 3
    return-object p0
.end method

.method public final get_useTrackingCache$android_beacon_library_release()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings$Builder;->_useTrackingCache:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-object p0
.end method

.method public final setBeaconSimulator(Lorg/altbeacon/beacon/simulator/BeaconSimulator;)Lorg/altbeacon/beacon/Settings$Builder;
    .locals 1

    .line 1
    const-string v0, "beaconSimulator"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lorg/altbeacon/beacon/Settings$Builder;->_beaconSimulator:Lorg/altbeacon/beacon/simulator/BeaconSimulator;

    .line 7
    .line 8
    return-object p0
.end method

.method public final setDebug(Z)Lorg/altbeacon/beacon/Settings$Builder;
    .locals 0

    .line 1
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    iput-object p1, p0, Lorg/altbeacon/beacon/Settings$Builder;->_debug:Ljava/lang/Boolean;

    .line 6
    .line 7
    return-object p0
.end method

.method public final setDistanceCalculatorFactory(Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;)Lorg/altbeacon/beacon/Settings$Builder;
    .locals 1

    .line 1
    const-string v0, "factory"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lorg/altbeacon/beacon/Settings$Builder;->_distanceCalculatorFactory:Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;

    .line 7
    .line 8
    return-object p0
.end method

.method public final setDistanceModelUpdateUrl(Ljava/lang/String;)Lorg/altbeacon/beacon/Settings$Builder;
    .locals 1

    .line 1
    const-string v0, "url"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lorg/altbeacon/beacon/Settings$Builder;->_distanceModelUpdateUrl:Ljava/lang/String;

    .line 7
    .line 8
    return-object p0
.end method

.method public final setLongScanForcingEnabled(Z)Lorg/altbeacon/beacon/Settings$Builder;
    .locals 0

    .line 1
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    iput-object p1, p0, Lorg/altbeacon/beacon/Settings$Builder;->_longScanForcingEnabled:Ljava/lang/Boolean;

    .line 6
    .line 7
    return-object p0
.end method

.method public final setRssiFilterClass(Ljava/lang/Class;)Lorg/altbeacon/beacon/Settings$Builder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/Class<",
            "*>;)",
            "Lorg/altbeacon/beacon/Settings$Builder;"
        }
    .end annotation

    .line 1
    const-string v0, "rssiFilterClass"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lorg/altbeacon/beacon/Settings$Builder;->_rssiFilterClass:Ljava/lang/Class;

    .line 7
    .line 8
    return-object p0
.end method

.method public final setScanPeriods(Lorg/altbeacon/beacon/Settings$ScanPeriods;)Lorg/altbeacon/beacon/Settings$Builder;
    .locals 1

    .line 1
    const-string v0, "scanPeriods"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lorg/altbeacon/beacon/Settings$Builder;->_scanPeriods:Lorg/altbeacon/beacon/Settings$ScanPeriods;

    .line 7
    .line 8
    return-object p0
.end method

.method public final setScanStrategy(Lorg/altbeacon/beacon/Settings$ScanStrategy;)Lorg/altbeacon/beacon/Settings$Builder;
    .locals 1

    .line 1
    const-string v0, "scanStrategy"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lorg/altbeacon/beacon/Settings$Builder;->_scanStrategy:Lorg/altbeacon/beacon/Settings$ScanStrategy;

    .line 7
    .line 8
    return-object p0
.end method

.method public final set_beaconSimulator$android_beacon_library_release(Lorg/altbeacon/beacon/simulator/BeaconSimulator;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/Settings$Builder;->_beaconSimulator:Lorg/altbeacon/beacon/simulator/BeaconSimulator;

    .line 2
    .line 3
    return-void
.end method

.method public final set_debug$android_beacon_library_release(Ljava/lang/Boolean;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/Settings$Builder;->_debug:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-void
.end method

.method public final set_distanceCalculatorFactory$android_beacon_library_release(Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/Settings$Builder;->_distanceCalculatorFactory:Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;

    .line 2
    .line 3
    return-void
.end method

.method public final set_distanceModelUpdateUrl$android_beacon_library_release(Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/Settings$Builder;->_distanceModelUpdateUrl:Ljava/lang/String;

    .line 2
    .line 3
    return-void
.end method

.method public final set_hardwareEqualityEnforced$android_beacon_library_release(Ljava/lang/Boolean;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/Settings$Builder;->_hardwareEqualityEnforced:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-void
.end method

.method public final set_longScanForcingEnabled$android_beacon_library_release(Ljava/lang/Boolean;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/Settings$Builder;->_longScanForcingEnabled:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-void
.end method

.method public final set_manifestCheckingDisabled$android_beacon_library_release(Ljava/lang/Boolean;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/Settings$Builder;->_manifestCheckingDisabled:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-void
.end method

.method public final set_maxTrackingAgeMillis$android_beacon_library_release(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/Settings$Builder;->_maxTrackingAgeMillis:Ljava/lang/Integer;

    .line 2
    .line 3
    return-void
.end method

.method public final set_regionExitPeriodMillis$android_beacon_library_release(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/Settings$Builder;->_regionExitPeriodMillis:Ljava/lang/Integer;

    .line 2
    .line 3
    return-void
.end method

.method public final set_regionStatePeristenceEnabled$android_beacon_library_release(Ljava/lang/Boolean;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/Settings$Builder;->_regionStatePeristenceEnabled:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-void
.end method

.method public final set_rssiFilterClass$android_beacon_library_release(Ljava/lang/Class;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/Class<",
            "*>;)V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/Settings$Builder;->_rssiFilterClass:Ljava/lang/Class;

    .line 2
    .line 3
    return-void
.end method

.method public final set_scanPeriods$android_beacon_library_release(Lorg/altbeacon/beacon/Settings$ScanPeriods;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/Settings$Builder;->_scanPeriods:Lorg/altbeacon/beacon/Settings$ScanPeriods;

    .line 2
    .line 3
    return-void
.end method

.method public final set_scanStrategy$android_beacon_library_release(Lorg/altbeacon/beacon/Settings$ScanStrategy;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/Settings$Builder;->_scanStrategy:Lorg/altbeacon/beacon/Settings$ScanStrategy;

    .line 2
    .line 3
    return-void
.end method

.method public final set_useTrackingCache$android_beacon_library_release(Ljava/lang/Boolean;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/Settings$Builder;->_useTrackingCache:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-void
.end method
