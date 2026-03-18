.class public final Lorg/altbeacon/beacon/Settings$Defaults;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lorg/altbeacon/beacon/Settings;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Defaults"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000J\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u000e\n\u0002\u0008\u0004\n\u0002\u0010\u0008\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0004\u0008\u00c6\u0002\u0018\u00002\u00020\u0001B\u0007\u0008\u0002\u00a2\u0006\u0002\u0010\u0002R\u0011\u0010\u0003\u001a\u00020\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0005\u0010\u0006R\u000e\u0010\u0007\u001a\u00020\u0008X\u0086T\u00a2\u0006\u0002\n\u0000R\u0011\u0010\t\u001a\u00020\n\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000b\u0010\u000cR\u000e\u0010\r\u001a\u00020\u000eX\u0086T\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u000f\u001a\u00020\u0008X\u0086T\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0010\u001a\u00020\u0008X\u0086T\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0011\u001a\u00020\u0008X\u0086T\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0012\u001a\u00020\u0013X\u0086T\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0014\u001a\u00020\u0013X\u0086T\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0015\u001a\u00020\u0008X\u0086T\u00a2\u0006\u0002\n\u0000R\u0015\u0010\u0016\u001a\u0006\u0012\u0002\u0008\u00030\u0017\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0018\u0010\u0019R\u0011\u0010\u001a\u001a\u00020\u001b\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u001c\u0010\u001dR\u0011\u0010\u001e\u001a\u00020\u001f\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008 \u0010!R\u000e\u0010\"\u001a\u00020\u0008X\u0086T\u00a2\u0006\u0002\n\u0000\u00a8\u0006#"
    }
    d2 = {
        "Lorg/altbeacon/beacon/Settings$Defaults;",
        "",
        "()V",
        "beaconSimulator",
        "Lorg/altbeacon/beacon/Settings$DisabledBeaconSimulator;",
        "getBeaconSimulator",
        "()Lorg/altbeacon/beacon/Settings$DisabledBeaconSimulator;",
        "debug",
        "",
        "distanceCalculatorFactory",
        "Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculatorFactory;",
        "getDistanceCalculatorFactory",
        "()Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculatorFactory;",
        "distanceModelUpdateUrl",
        "",
        "hardwareEqualityEnforced",
        "longScanForcingEnabled",
        "manifestCheckingDisabled",
        "maxTrackingAgeMillis",
        "",
        "regionExitPeriodMillis",
        "regionStatePeristenceEnabled",
        "rssiFilterImplClass",
        "Ljava/lang/Class;",
        "getRssiFilterImplClass",
        "()Ljava/lang/Class;",
        "scanPeriods",
        "Lorg/altbeacon/beacon/Settings$ScanPeriods;",
        "getScanPeriods",
        "()Lorg/altbeacon/beacon/Settings$ScanPeriods;",
        "scanStrategy",
        "Lorg/altbeacon/beacon/Settings$ScanStrategy;",
        "getScanStrategy",
        "()Lorg/altbeacon/beacon/Settings$ScanStrategy;",
        "useTrackingCache",
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
.field public static final INSTANCE:Lorg/altbeacon/beacon/Settings$Defaults;

.field private static final beaconSimulator:Lorg/altbeacon/beacon/Settings$DisabledBeaconSimulator;

.field public static final debug:Z = false

.field private static final distanceCalculatorFactory:Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculatorFactory;

.field public static final distanceModelUpdateUrl:Ljava/lang/String; = ""

.field public static final hardwareEqualityEnforced:Z = false

.field public static final longScanForcingEnabled:Z = false

.field public static final manifestCheckingDisabled:Z = false

.field public static final maxTrackingAgeMillis:I = 0x2710

.field public static final regionExitPeriodMillis:I = 0x7530

.field public static final regionStatePeristenceEnabled:Z = true

.field private static final rssiFilterImplClass:Ljava/lang/Class;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/Class<",
            "*>;"
        }
    .end annotation
.end field

.field private static final scanPeriods:Lorg/altbeacon/beacon/Settings$ScanPeriods;

.field private static final scanStrategy:Lorg/altbeacon/beacon/Settings$ScanStrategy;

.field public static final useTrackingCache:Z = true


# direct methods
.method static constructor <clinit>()V
    .locals 12

    .line 1
    new-instance v0, Lorg/altbeacon/beacon/Settings$Defaults;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/altbeacon/beacon/Settings$Defaults;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lorg/altbeacon/beacon/Settings$Defaults;->INSTANCE:Lorg/altbeacon/beacon/Settings$Defaults;

    .line 7
    .line 8
    new-instance v1, Lorg/altbeacon/beacon/Settings$ScanPeriods;

    .line 9
    .line 10
    const/16 v10, 0xf

    .line 11
    .line 12
    const/4 v11, 0x0

    .line 13
    const-wide/16 v2, 0x0

    .line 14
    .line 15
    const-wide/16 v4, 0x0

    .line 16
    .line 17
    const-wide/16 v6, 0x0

    .line 18
    .line 19
    const-wide/16 v8, 0x0

    .line 20
    .line 21
    invoke-direct/range {v1 .. v11}, Lorg/altbeacon/beacon/Settings$ScanPeriods;-><init>(JJJJILkotlin/jvm/internal/g;)V

    .line 22
    .line 23
    .line 24
    sput-object v1, Lorg/altbeacon/beacon/Settings$Defaults;->scanPeriods:Lorg/altbeacon/beacon/Settings$ScanPeriods;

    .line 25
    .line 26
    new-instance v0, Lorg/altbeacon/beacon/Settings$DisabledBeaconSimulator;

    .line 27
    .line 28
    invoke-direct {v0}, Lorg/altbeacon/beacon/Settings$DisabledBeaconSimulator;-><init>()V

    .line 29
    .line 30
    .line 31
    sput-object v0, Lorg/altbeacon/beacon/Settings$Defaults;->beaconSimulator:Lorg/altbeacon/beacon/Settings$DisabledBeaconSimulator;

    .line 32
    .line 33
    const-class v0, Lorg/altbeacon/beacon/service/RunningAverageRssiFilter;

    .line 34
    .line 35
    sput-object v0, Lorg/altbeacon/beacon/Settings$Defaults;->rssiFilterImplClass:Ljava/lang/Class;

    .line 36
    .line 37
    new-instance v0, Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculatorFactory;

    .line 38
    .line 39
    invoke-direct {v0}, Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculatorFactory;-><init>()V

    .line 40
    .line 41
    .line 42
    sput-object v0, Lorg/altbeacon/beacon/Settings$Defaults;->distanceCalculatorFactory:Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculatorFactory;

    .line 43
    .line 44
    new-instance v1, Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;

    .line 45
    .line 46
    const/4 v7, 0x7

    .line 47
    const/4 v8, 0x0

    .line 48
    const/4 v6, 0x0

    .line 49
    invoke-direct/range {v1 .. v8}, Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;-><init>(JJZILkotlin/jvm/internal/g;)V

    .line 50
    .line 51
    .line 52
    sput-object v1, Lorg/altbeacon/beacon/Settings$Defaults;->scanStrategy:Lorg/altbeacon/beacon/Settings$ScanStrategy;

    .line 53
    .line 54
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public final getBeaconSimulator()Lorg/altbeacon/beacon/Settings$DisabledBeaconSimulator;
    .locals 0

    .line 1
    sget-object p0, Lorg/altbeacon/beacon/Settings$Defaults;->beaconSimulator:Lorg/altbeacon/beacon/Settings$DisabledBeaconSimulator;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getDistanceCalculatorFactory()Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculatorFactory;
    .locals 0

    .line 1
    sget-object p0, Lorg/altbeacon/beacon/Settings$Defaults;->distanceCalculatorFactory:Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculatorFactory;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getRssiFilterImplClass()Ljava/lang/Class;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/lang/Class<",
            "*>;"
        }
    .end annotation

    .line 1
    sget-object p0, Lorg/altbeacon/beacon/Settings$Defaults;->rssiFilterImplClass:Ljava/lang/Class;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getScanPeriods()Lorg/altbeacon/beacon/Settings$ScanPeriods;
    .locals 0

    .line 1
    sget-object p0, Lorg/altbeacon/beacon/Settings$Defaults;->scanPeriods:Lorg/altbeacon/beacon/Settings$ScanPeriods;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getScanStrategy()Lorg/altbeacon/beacon/Settings$ScanStrategy;
    .locals 0

    .line 1
    sget-object p0, Lorg/altbeacon/beacon/Settings$Defaults;->scanStrategy:Lorg/altbeacon/beacon/Settings$ScanStrategy;

    .line 2
    .line 3
    return-object p0
.end method
