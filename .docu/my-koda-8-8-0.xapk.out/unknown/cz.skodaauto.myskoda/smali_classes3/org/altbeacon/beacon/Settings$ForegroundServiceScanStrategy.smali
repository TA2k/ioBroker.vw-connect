.class public final Lorg/altbeacon/beacon/Settings$ForegroundServiceScanStrategy;
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
    name = "ForegroundServiceScanStrategy"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0008\n\u0002\u0008\u0005\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0010\u0018\u00002\u00020\u0001B\u0017\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u0012\u0006\u0010\u0005\u001a\u00020\u0004\u00a2\u0006\u0004\u0008\u0006\u0010\u0007J\u000f\u0010\u0008\u001a\u00020\u0000H\u0016\u00a2\u0006\u0004\u0008\u0008\u0010\tJ\u001a\u0010\r\u001a\u00020\u000c2\u0008\u0010\u000b\u001a\u0004\u0018\u00010\nH\u0096\u0002\u00a2\u0006\u0004\u0008\r\u0010\u000eJ\u000f\u0010\u000f\u001a\u00020\u0004H\u0016\u00a2\u0006\u0004\u0008\u000f\u0010\u0010J\u0017\u0010\u0014\u001a\u00020\u00132\u0006\u0010\u0012\u001a\u00020\u0011H\u0016\u00a2\u0006\u0004\u0008\u0014\u0010\u0015J\u0018\u0010\u0016\u001a\u00020\u00042\u0006\u0010\u000b\u001a\u00020\u0001H\u0096\u0002\u00a2\u0006\u0004\u0008\u0016\u0010\u0017R\u0017\u0010\u0003\u001a\u00020\u00028\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0003\u0010\u0018\u001a\u0004\u0008\u0019\u0010\u001aR\u0017\u0010\u0005\u001a\u00020\u00048\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0005\u0010\u001b\u001a\u0004\u0008\u001c\u0010\u0010R\"\u0010\u001d\u001a\u00020\u000c8\u0006@\u0006X\u0086\u000e\u00a2\u0006\u0012\n\u0004\u0008\u001d\u0010\u001e\u001a\u0004\u0008\u001f\u0010 \"\u0004\u0008!\u0010\"\u00a8\u0006#"
    }
    d2 = {
        "Lorg/altbeacon/beacon/Settings$ForegroundServiceScanStrategy;",
        "Lorg/altbeacon/beacon/Settings$ScanStrategy;",
        "Landroid/app/Notification;",
        "notification",
        "",
        "notificationId",
        "<init>",
        "(Landroid/app/Notification;I)V",
        "clone",
        "()Lorg/altbeacon/beacon/Settings$ForegroundServiceScanStrategy;",
        "",
        "other",
        "",
        "equals",
        "(Ljava/lang/Object;)Z",
        "hashCode",
        "()I",
        "Lorg/altbeacon/beacon/BeaconManager;",
        "beaconManager",
        "Llx0/b0;",
        "configure",
        "(Lorg/altbeacon/beacon/BeaconManager;)V",
        "compareTo",
        "(Lorg/altbeacon/beacon/Settings$ScanStrategy;)I",
        "Landroid/app/Notification;",
        "getNotification",
        "()Landroid/app/Notification;",
        "I",
        "getNotificationId",
        "androidLScanningDisabled",
        "Z",
        "getAndroidLScanningDisabled",
        "()Z",
        "setAndroidLScanningDisabled",
        "(Z)V",
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
.field private androidLScanningDisabled:Z

.field private final notification:Landroid/app/Notification;

.field private final notificationId:I


# direct methods
.method public constructor <init>(Landroid/app/Notification;I)V
    .locals 1

    .line 1
    const-string v0, "notification"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lorg/altbeacon/beacon/Settings$ForegroundServiceScanStrategy;->notification:Landroid/app/Notification;

    .line 10
    .line 11
    iput p2, p0, Lorg/altbeacon/beacon/Settings$ForegroundServiceScanStrategy;->notificationId:I

    .line 12
    .line 13
    const/4 p1, 0x1

    .line 14
    iput-boolean p1, p0, Lorg/altbeacon/beacon/Settings$ForegroundServiceScanStrategy;->androidLScanningDisabled:Z

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public clone()Lorg/altbeacon/beacon/Settings$ForegroundServiceScanStrategy;
    .locals 2

    .line 2
    new-instance v0, Lorg/altbeacon/beacon/Settings$ForegroundServiceScanStrategy;

    iget-object v1, p0, Lorg/altbeacon/beacon/Settings$ForegroundServiceScanStrategy;->notification:Landroid/app/Notification;

    iget p0, p0, Lorg/altbeacon/beacon/Settings$ForegroundServiceScanStrategy;->notificationId:I

    invoke-direct {v0, v1, p0}, Lorg/altbeacon/beacon/Settings$ForegroundServiceScanStrategy;-><init>(Landroid/app/Notification;I)V

    return-object v0
.end method

.method public bridge synthetic clone()Lorg/altbeacon/beacon/Settings$ScanStrategy;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lorg/altbeacon/beacon/Settings$ForegroundServiceScanStrategy;->clone()Lorg/altbeacon/beacon/Settings$ForegroundServiceScanStrategy;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic compareTo(Ljava/lang/Object;)I
    .locals 0

    .line 1
    check-cast p1, Lorg/altbeacon/beacon/Settings$ScanStrategy;

    invoke-virtual {p0, p1}, Lorg/altbeacon/beacon/Settings$ForegroundServiceScanStrategy;->compareTo(Lorg/altbeacon/beacon/Settings$ScanStrategy;)I

    move-result p0

    return p0
.end method

.method public compareTo(Lorg/altbeacon/beacon/Settings$ScanStrategy;)I
    .locals 3

    const-string v0, "other"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    instance-of v0, p1, Lorg/altbeacon/beacon/Settings$ForegroundServiceScanStrategy;

    const/4 v1, -0x1

    if-eqz v0, :cond_0

    .line 3
    iget v0, p0, Lorg/altbeacon/beacon/Settings$ForegroundServiceScanStrategy;->notificationId:I

    check-cast p1, Lorg/altbeacon/beacon/Settings$ForegroundServiceScanStrategy;

    iget v2, p1, Lorg/altbeacon/beacon/Settings$ForegroundServiceScanStrategy;->notificationId:I

    if-ne v0, v2, :cond_0

    .line 4
    iget-boolean p0, p0, Lorg/altbeacon/beacon/Settings$ForegroundServiceScanStrategy;->androidLScanningDisabled:Z

    iget-boolean p1, p1, Lorg/altbeacon/beacon/Settings$ForegroundServiceScanStrategy;->androidLScanningDisabled:Z

    if-ne p0, p1, :cond_0

    const/4 p0, 0x0

    return p0

    :cond_0
    return v1
.end method

.method public configure(Lorg/altbeacon/beacon/BeaconManager;)V
    .locals 1

    .line 1
    const-string v0, "beaconManager"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    invoke-virtual {p1, v0}, Lorg/altbeacon/beacon/BeaconManager;->setEnableScheduledScanJobs(Z)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p1, v0}, Lorg/altbeacon/beacon/BeaconManager;->setIntentScanningStrategyEnabled(Z)V

    .line 11
    .line 12
    .line 13
    iget-object v0, p0, Lorg/altbeacon/beacon/Settings$ForegroundServiceScanStrategy;->notification:Landroid/app/Notification;

    .line 14
    .line 15
    iget p0, p0, Lorg/altbeacon/beacon/Settings$ForegroundServiceScanStrategy;->notificationId:I

    .line 16
    .line 17
    invoke-virtual {p1, v0, p0}, Lorg/altbeacon/beacon/BeaconManager;->enableForegroundServiceScanning(Landroid/app/Notification;I)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    instance-of v0, p1, Lorg/altbeacon/beacon/Settings$ForegroundServiceScanStrategy;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p1, Lorg/altbeacon/beacon/Settings$ForegroundServiceScanStrategy;

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
    iget v1, p0, Lorg/altbeacon/beacon/Settings$ForegroundServiceScanStrategy;->notificationId:I

    .line 13
    .line 14
    iget v2, p1, Lorg/altbeacon/beacon/Settings$ForegroundServiceScanStrategy;->notificationId:I

    .line 15
    .line 16
    if-ne v1, v2, :cond_1

    .line 17
    .line 18
    iget-boolean p0, p0, Lorg/altbeacon/beacon/Settings$ForegroundServiceScanStrategy;->androidLScanningDisabled:Z

    .line 19
    .line 20
    iget-boolean p1, p1, Lorg/altbeacon/beacon/Settings$ForegroundServiceScanStrategy;->androidLScanningDisabled:Z

    .line 21
    .line 22
    if-ne p0, p1, :cond_1

    .line 23
    .line 24
    const/4 p0, 0x1

    .line 25
    return p0

    .line 26
    :cond_1
    return v0
.end method

.method public final getAndroidLScanningDisabled()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/altbeacon/beacon/Settings$ForegroundServiceScanStrategy;->androidLScanningDisabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public final getNotification()Landroid/app/Notification;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Settings$ForegroundServiceScanStrategy;->notification:Landroid/app/Notification;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getNotificationId()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/altbeacon/beacon/Settings$ForegroundServiceScanStrategy;->notificationId:I

    .line 2
    .line 3
    return p0
.end method

.method public hashCode()I
    .locals 0

    .line 1
    const-class p0, Lorg/altbeacon/beacon/Settings$ForegroundServiceScanStrategy;

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

.method public final setAndroidLScanningDisabled(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lorg/altbeacon/beacon/Settings$ForegroundServiceScanStrategy;->androidLScanningDisabled:Z

    .line 2
    .line 3
    return-void
.end method
