.class public Lorg/altbeacon/beacon/service/ArmaRssiFilter;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lorg/altbeacon/beacon/service/RssiFilter;


# static fields
.field private static DEFAULT_ARMA_SPEED:D = 0.1

.field private static final TAG:Ljava/lang/String; = "ArmaRssiFilter"


# instance fields
.field private armaMeasurement:I

.field private armaSpeed:D

.field private isInitialized:Z


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput-boolean v0, p0, Lorg/altbeacon/beacon/service/ArmaRssiFilter;->isInitialized:Z

    .line 6
    .line 7
    sget-wide v0, Lorg/altbeacon/beacon/service/ArmaRssiFilter;->DEFAULT_ARMA_SPEED:D

    .line 8
    .line 9
    iput-wide v0, p0, Lorg/altbeacon/beacon/service/ArmaRssiFilter;->armaSpeed:D

    .line 10
    .line 11
    return-void
.end method

.method public static setDEFAULT_ARMA_SPEED(D)V
    .locals 0

    .line 1
    sput-wide p0, Lorg/altbeacon/beacon/service/ArmaRssiFilter;->DEFAULT_ARMA_SPEED:D

    .line 2
    .line 3
    return-void
.end method


# virtual methods
.method public addMeasurement(Ljava/lang/Integer;)V
    .locals 7

    .line 1
    const-string v0, "adding rssi: %s"

    .line 2
    .line 3
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    const-string v2, "ArmaRssiFilter"

    .line 8
    .line 9
    invoke-static {v2, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    iget-boolean v0, p0, Lorg/altbeacon/beacon/service/ArmaRssiFilter;->isInitialized:Z

    .line 13
    .line 14
    if-nez v0, :cond_0

    .line 15
    .line 16
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    iput v0, p0, Lorg/altbeacon/beacon/service/ArmaRssiFilter;->armaMeasurement:I

    .line 21
    .line 22
    const/4 v0, 0x1

    .line 23
    iput-boolean v0, p0, Lorg/altbeacon/beacon/service/ArmaRssiFilter;->isInitialized:Z

    .line 24
    .line 25
    :cond_0
    iget v0, p0, Lorg/altbeacon/beacon/service/ArmaRssiFilter;->armaMeasurement:I

    .line 26
    .line 27
    int-to-double v3, v0

    .line 28
    iget-wide v5, p0, Lorg/altbeacon/beacon/service/ArmaRssiFilter;->armaSpeed:D

    .line 29
    .line 30
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 31
    .line 32
    .line 33
    move-result p1

    .line 34
    sub-int/2addr v0, p1

    .line 35
    int-to-double v0, v0

    .line 36
    mul-double/2addr v5, v0

    .line 37
    sub-double/2addr v3, v5

    .line 38
    invoke-static {v3, v4}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    invoke-virtual {p1}, Ljava/lang/Double;->intValue()I

    .line 43
    .line 44
    .line 45
    move-result p1

    .line 46
    iput p1, p0, Lorg/altbeacon/beacon/service/ArmaRssiFilter;->armaMeasurement:I

    .line 47
    .line 48
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    const-string p1, "armaMeasurement: %s"

    .line 57
    .line 58
    invoke-static {v2, p1, p0}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    return-void
.end method

.method public calculateRssi()D
    .locals 2

    .line 1
    iget p0, p0, Lorg/altbeacon/beacon/service/ArmaRssiFilter;->armaMeasurement:I

    .line 2
    .line 3
    int-to-double v0, p0

    .line 4
    return-wide v0
.end method

.method public getMeasurementCount()I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public noMeasurementsAvailable()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method
