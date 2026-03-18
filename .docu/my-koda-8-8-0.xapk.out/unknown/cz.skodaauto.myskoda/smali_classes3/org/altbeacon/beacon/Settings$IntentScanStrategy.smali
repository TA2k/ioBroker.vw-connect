.class public final Lorg/altbeacon/beacon/Settings$IntentScanStrategy;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lorg/altbeacon/beacon/Settings$ScanStrategy;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lorg/altbeacon/beacon/Settings;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "IntentScanStrategy"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0005\u0018\u00002\u00020\u0001B\u0007\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\u000f\u0010\u0004\u001a\u00020\u0000H\u0016\u00a2\u0006\u0004\u0008\u0004\u0010\u0005J\u001a\u0010\t\u001a\u00020\u00082\u0008\u0010\u0007\u001a\u0004\u0018\u00010\u0006H\u0096\u0002\u00a2\u0006\u0004\u0008\t\u0010\nJ\u000f\u0010\u000c\u001a\u00020\u000bH\u0016\u00a2\u0006\u0004\u0008\u000c\u0010\rJ\u0017\u0010\u0011\u001a\u00020\u00102\u0006\u0010\u000f\u001a\u00020\u000eH\u0016\u00a2\u0006\u0004\u0008\u0011\u0010\u0012J\u0018\u0010\u0013\u001a\u00020\u000b2\u0006\u0010\u0007\u001a\u00020\u0001H\u0096\u0002\u00a2\u0006\u0004\u0008\u0013\u0010\u0014\u00a8\u0006\u0015"
    }
    d2 = {
        "Lorg/altbeacon/beacon/Settings$IntentScanStrategy;",
        "Lorg/altbeacon/beacon/Settings$ScanStrategy;",
        "<init>",
        "()V",
        "clone",
        "()Lorg/altbeacon/beacon/Settings$IntentScanStrategy;",
        "",
        "other",
        "",
        "equals",
        "(Ljava/lang/Object;)Z",
        "",
        "hashCode",
        "()I",
        "Lorg/altbeacon/beacon/BeaconManager;",
        "beaconManager",
        "Llx0/b0;",
        "configure",
        "(Lorg/altbeacon/beacon/BeaconManager;)V",
        "compareTo",
        "(Lorg/altbeacon/beacon/Settings$ScanStrategy;)I",
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
.method public clone()Lorg/altbeacon/beacon/Settings$IntentScanStrategy;
    .locals 0

    .line 2
    new-instance p0, Lorg/altbeacon/beacon/Settings$IntentScanStrategy;

    invoke-direct {p0}, Lorg/altbeacon/beacon/Settings$IntentScanStrategy;-><init>()V

    return-object p0
.end method

.method public bridge synthetic clone()Lorg/altbeacon/beacon/Settings$ScanStrategy;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lorg/altbeacon/beacon/Settings$IntentScanStrategy;->clone()Lorg/altbeacon/beacon/Settings$IntentScanStrategy;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic compareTo(Ljava/lang/Object;)I
    .locals 0

    .line 1
    check-cast p1, Lorg/altbeacon/beacon/Settings$ScanStrategy;

    invoke-virtual {p0, p1}, Lorg/altbeacon/beacon/Settings$IntentScanStrategy;->compareTo(Lorg/altbeacon/beacon/Settings$ScanStrategy;)I

    move-result p0

    return p0
.end method

.method public compareTo(Lorg/altbeacon/beacon/Settings$ScanStrategy;)I
    .locals 0

    const-string p0, "other"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    instance-of p0, p1, Lorg/altbeacon/beacon/Settings$IntentScanStrategy;

    if-eqz p0, :cond_0

    const/4 p0, 0x0

    return p0

    :cond_0
    const/4 p0, -0x1

    return p0
.end method

.method public configure(Lorg/altbeacon/beacon/BeaconManager;)V
    .locals 0

    .line 1
    const-string p0, "beaconManager"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/4 p0, 0x0

    .line 7
    invoke-virtual {p1, p0}, Lorg/altbeacon/beacon/BeaconManager;->setEnableScheduledScanJobs(Z)V

    .line 8
    .line 9
    .line 10
    const/4 p0, 0x1

    .line 11
    invoke-virtual {p1, p0}, Lorg/altbeacon/beacon/BeaconManager;->setIntentScanningStrategyEnabled(Z)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 0

    .line 1
    instance-of p0, p1, Lorg/altbeacon/beacon/Settings$IntentScanStrategy;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    check-cast p1, Lorg/altbeacon/beacon/Settings$IntentScanStrategy;

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    const/4 p1, 0x0

    .line 9
    :goto_0
    if-eqz p1, :cond_1

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :cond_1
    const/4 p0, 0x0

    .line 14
    return p0
.end method

.method public hashCode()I
    .locals 0

    .line 1
    const-class p0, Lorg/altbeacon/beacon/Settings$IntentScanStrategy;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method
