.class public final Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;
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
    name = "JobServiceScanStrategy"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00006\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\t\n\u0002\u0008\u0002\n\u0002\u0010\u000b\n\u0002\u0008\u0005\n\u0002\u0010\u0000\n\u0002\u0008\u0003\n\u0002\u0010\u0008\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u000c\u0018\u00002\u00020\u0001B%\u0012\u0008\u0008\u0002\u0010\u0003\u001a\u00020\u0002\u0012\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u0002\u0012\u0008\u0008\u0002\u0010\u0006\u001a\u00020\u0005\u00a2\u0006\u0004\u0008\u0007\u0010\u0008J\u000f\u0010\t\u001a\u00020\u0000H\u0016\u00a2\u0006\u0004\u0008\t\u0010\nJ\u001a\u0010\r\u001a\u00020\u00052\u0008\u0010\u000c\u001a\u0004\u0018\u00010\u000bH\u0096\u0002\u00a2\u0006\u0004\u0008\r\u0010\u000eJ\u000f\u0010\u0010\u001a\u00020\u000fH\u0016\u00a2\u0006\u0004\u0008\u0010\u0010\u0011J\u0017\u0010\u0015\u001a\u00020\u00142\u0006\u0010\u0013\u001a\u00020\u0012H\u0016\u00a2\u0006\u0004\u0008\u0015\u0010\u0016J\u0018\u0010\u0017\u001a\u00020\u000f2\u0006\u0010\u000c\u001a\u00020\u0001H\u0096\u0002\u00a2\u0006\u0004\u0008\u0017\u0010\u0018R\u0017\u0010\u0003\u001a\u00020\u00028\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0003\u0010\u0019\u001a\u0004\u0008\u001a\u0010\u001bR\u0017\u0010\u0004\u001a\u00020\u00028\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0004\u0010\u0019\u001a\u0004\u0008\u001c\u0010\u001bR\u0017\u0010\u0006\u001a\u00020\u00058\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0006\u0010\u001d\u001a\u0004\u0008\u001e\u0010\u001f\u00a8\u0006 "
    }
    d2 = {
        "Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;",
        "Lorg/altbeacon/beacon/Settings$ScanStrategy;",
        "",
        "immediateJobId",
        "periodicJobId",
        "",
        "jobPersistenceEnabled",
        "<init>",
        "(JJZ)V",
        "clone",
        "()Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;",
        "",
        "other",
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
        "J",
        "getImmediateJobId",
        "()J",
        "getPeriodicJobId",
        "Z",
        "getJobPersistenceEnabled",
        "()Z",
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
.field private final immediateJobId:J

.field private final jobPersistenceEnabled:Z

.field private final periodicJobId:J


# direct methods
.method public constructor <init>()V
    .locals 8

    .line 1
    const/4 v6, 0x7

    const/4 v7, 0x0

    const-wide/16 v1, 0x0

    const-wide/16 v3, 0x0

    const/4 v5, 0x0

    move-object v0, p0

    invoke-direct/range {v0 .. v7}, Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;-><init>(JJZILkotlin/jvm/internal/g;)V

    return-void
.end method

.method public constructor <init>(JJZ)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-wide p1, p0, Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;->immediateJobId:J

    iput-wide p3, p0, Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;->periodicJobId:J

    iput-boolean p5, p0, Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;->jobPersistenceEnabled:Z

    return-void
.end method

.method public synthetic constructor <init>(JJZILkotlin/jvm/internal/g;)V
    .locals 6

    and-int/lit8 p7, p6, 0x1

    if-eqz p7, :cond_0

    const-wide/32 p1, 0xc6b36ab

    :cond_0
    move-wide v1, p1

    and-int/lit8 p1, p6, 0x2

    if-eqz p1, :cond_1

    const-wide/32 p3, 0xc6b36ac

    :cond_1
    move-wide v3, p3

    and-int/lit8 p1, p6, 0x4

    if-eqz p1, :cond_2

    const/4 p5, 0x1

    :cond_2
    move-object v0, p0

    move v5, p5

    .line 3
    invoke-direct/range {v0 .. v5}, Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;-><init>(JJZ)V

    return-void
.end method


# virtual methods
.method public clone()Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;
    .locals 6

    .line 2
    new-instance v0, Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;

    iget-wide v1, p0, Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;->immediateJobId:J

    iget-wide v3, p0, Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;->periodicJobId:J

    iget-boolean v5, p0, Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;->jobPersistenceEnabled:Z

    invoke-direct/range {v0 .. v5}, Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;-><init>(JJZ)V

    return-object v0
.end method

.method public bridge synthetic clone()Lorg/altbeacon/beacon/Settings$ScanStrategy;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;->clone()Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic compareTo(Ljava/lang/Object;)I
    .locals 0

    .line 1
    check-cast p1, Lorg/altbeacon/beacon/Settings$ScanStrategy;

    invoke-virtual {p0, p1}, Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;->compareTo(Lorg/altbeacon/beacon/Settings$ScanStrategy;)I

    move-result p0

    return p0
.end method

.method public compareTo(Lorg/altbeacon/beacon/Settings$ScanStrategy;)I
    .locals 6

    const-string v0, "other"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    instance-of v0, p1, Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;

    const/4 v1, -0x1

    if-eqz v0, :cond_0

    .line 3
    iget-wide v2, p0, Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;->immediateJobId:J

    check-cast p1, Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;

    iget-wide v4, p1, Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;->immediateJobId:J

    cmp-long v0, v2, v4

    if-nez v0, :cond_0

    .line 4
    iget-wide v2, p0, Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;->periodicJobId:J

    iget-wide v4, p1, Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;->periodicJobId:J

    cmp-long v0, v2, v4

    if-nez v0, :cond_0

    .line 5
    iget-boolean p0, p0, Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;->jobPersistenceEnabled:Z

    iget-boolean p1, p1, Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;->jobPersistenceEnabled:Z

    if-ne p0, p1, :cond_0

    const/4 p0, 0x0

    return p0

    :cond_0
    return v1
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
    const/4 p0, 0x1

    .line 7
    invoke-virtual {p1, p0}, Lorg/altbeacon/beacon/BeaconManager;->setEnableScheduledScanJobs(Z)V

    .line 8
    .line 9
    .line 10
    const/4 p0, 0x0

    .line 11
    invoke-virtual {p1, p0}, Lorg/altbeacon/beacon/BeaconManager;->setIntentScanningStrategyEnabled(Z)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 5

    .line 1
    instance-of v0, p1, Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p1, Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    const/4 p1, 0x0

    .line 9
    :goto_0
    const/4 v0, 0x0

    .line 10
    if-eqz p1, :cond_1

    .line 11
    .line 12
    iget-wide v1, p0, Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;->immediateJobId:J

    .line 13
    .line 14
    iget-wide v3, p1, Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;->immediateJobId:J

    .line 15
    .line 16
    cmp-long v1, v1, v3

    .line 17
    .line 18
    if-nez v1, :cond_1

    .line 19
    .line 20
    iget-wide v1, p0, Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;->periodicJobId:J

    .line 21
    .line 22
    iget-wide v3, p1, Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;->periodicJobId:J

    .line 23
    .line 24
    cmp-long v1, v1, v3

    .line 25
    .line 26
    if-nez v1, :cond_1

    .line 27
    .line 28
    iget-boolean p0, p0, Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;->jobPersistenceEnabled:Z

    .line 29
    .line 30
    iget-boolean p1, p1, Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;->jobPersistenceEnabled:Z

    .line 31
    .line 32
    if-ne p0, p1, :cond_1

    .line 33
    .line 34
    const/4 p0, 0x1

    .line 35
    return p0

    .line 36
    :cond_1
    return v0
.end method

.method public final getImmediateJobId()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;->immediateJobId:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final getJobPersistenceEnabled()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;->jobPersistenceEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public final getPeriodicJobId()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;->periodicJobId:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public hashCode()I
    .locals 0

    .line 1
    const-class p0, Lorg/altbeacon/beacon/Settings$JobServiceScanStrategy;

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
