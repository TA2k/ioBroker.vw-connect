.class public Lcom/salesforce/marketingcloud/messages/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/e;
.implements Lcom/salesforce/marketingcloud/messages/RegionMessageManager;
.implements Lcom/salesforce/marketingcloud/alarms/b$b;
.implements Lcom/salesforce/marketingcloud/location/e;
.implements Lcom/salesforce/marketingcloud/behaviors/b;
.implements Lcom/salesforce/marketingcloud/messages/c$b;
.implements Lcom/salesforce/marketingcloud/messages/c$a;
.implements Lcom/salesforce/marketingcloud/location/c;


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation


# static fields
.field private static final A:Ljava/lang/String; = "RegionMessageManager"

.field static final B:Ljava/lang/String;

.field private static final C:F = 0.8f

.field static final w:Ljava/lang/String; = "et_geo_enabled_key"

.field static final x:Ljava/lang/String; = "et_region_message_toggled_key"

.field static final y:Ljava/lang/String; = "et_proximity_enabled_key"

.field static final z:I = 0x1388


# instance fields
.field final d:Lcom/salesforce/marketingcloud/storage/h;

.field private final e:Lcom/salesforce/marketingcloud/alarms/b;

.field private final f:Lcom/salesforce/marketingcloud/location/f;

.field private final g:Lcom/salesforce/marketingcloud/proximity/e;

.field private final h:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

.field private final i:Ljava/lang/String;

.field private final j:Landroid/content/Context;

.field private final k:Lcom/salesforce/marketingcloud/notifications/a;

.field private final l:Lcom/salesforce/marketingcloud/behaviors/c;

.field private final m:Lcom/salesforce/marketingcloud/http/e;

.field private final n:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Lcom/salesforce/marketingcloud/messages/RegionMessageManager$GeofenceMessageResponseListener;",
            ">;"
        }
    .end annotation
.end field

.field private final o:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Lcom/salesforce/marketingcloud/messages/RegionMessageManager$ProximityMessageResponseListener;",
            ">;"
        }
    .end annotation
.end field

.field private final p:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Lcom/salesforce/marketingcloud/messages/RegionMessageManager$RegionTransitionEventListener;",
            ">;"
        }
    .end annotation
.end field

.field private final q:Ljava/util/concurrent/atomic/AtomicBoolean;

.field private final r:Lcom/salesforce/marketingcloud/internal/n;

.field private s:Lcom/salesforce/marketingcloud/messages/geofence/a;

.field private t:Lcom/salesforce/marketingcloud/messages/proximity/a;

.field private u:Lcom/salesforce/marketingcloud/toggles/a;

.field private v:Lcom/salesforce/marketingcloud/toggles/a;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "RegionMessageManager"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/messages/d;->B:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/h;Ljava/lang/String;Lcom/salesforce/marketingcloud/location/f;Lcom/salesforce/marketingcloud/proximity/e;Lcom/salesforce/marketingcloud/behaviors/c;Lcom/salesforce/marketingcloud/alarms/b;Lcom/salesforce/marketingcloud/http/e;Lcom/salesforce/marketingcloud/notifications/a;Lcom/salesforce/marketingcloud/internal/n;Lcom/salesforce/marketingcloud/messages/RegionMessageManager$RegionTransitionEventListener;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Landroidx/collection/g;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-direct {v0, v1}, Landroidx/collection/g;-><init>(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->n:Ljava/util/Set;

    .line 11
    .line 12
    new-instance v0, Landroidx/collection/g;

    .line 13
    .line 14
    invoke-direct {v0, v1}, Landroidx/collection/g;-><init>(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->o:Ljava/util/Set;

    .line 18
    .line 19
    new-instance v0, Landroidx/collection/g;

    .line 20
    .line 21
    invoke-direct {v0, v1}, Landroidx/collection/g;-><init>(Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->p:Ljava/util/Set;

    .line 25
    .line 26
    new-instance v1, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 27
    .line 28
    const/4 v2, 0x0

    .line 29
    invoke-direct {v1, v2}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    .line 30
    .line 31
    .line 32
    iput-object v1, p0, Lcom/salesforce/marketingcloud/messages/d;->q:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 33
    .line 34
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/d;->j:Landroid/content/Context;

    .line 35
    .line 36
    iput-object p3, p0, Lcom/salesforce/marketingcloud/messages/d;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 37
    .line 38
    iput-object p5, p0, Lcom/salesforce/marketingcloud/messages/d;->f:Lcom/salesforce/marketingcloud/location/f;

    .line 39
    .line 40
    iput-object p6, p0, Lcom/salesforce/marketingcloud/messages/d;->g:Lcom/salesforce/marketingcloud/proximity/e;

    .line 41
    .line 42
    iput-object p10, p0, Lcom/salesforce/marketingcloud/messages/d;->k:Lcom/salesforce/marketingcloud/notifications/a;

    .line 43
    .line 44
    iput-object p8, p0, Lcom/salesforce/marketingcloud/messages/d;->e:Lcom/salesforce/marketingcloud/alarms/b;

    .line 45
    .line 46
    iput-object p7, p0, Lcom/salesforce/marketingcloud/messages/d;->l:Lcom/salesforce/marketingcloud/behaviors/c;

    .line 47
    .line 48
    iput-object p9, p0, Lcom/salesforce/marketingcloud/messages/d;->m:Lcom/salesforce/marketingcloud/http/e;

    .line 49
    .line 50
    iput-object p4, p0, Lcom/salesforce/marketingcloud/messages/d;->i:Ljava/lang/String;

    .line 51
    .line 52
    iput-object p2, p0, Lcom/salesforce/marketingcloud/messages/d;->h:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 53
    .line 54
    invoke-virtual {v0, p12}, Landroidx/collection/g;->add(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    iput-object p11, p0, Lcom/salesforce/marketingcloud/messages/d;->r:Lcom/salesforce/marketingcloud/internal/n;

    .line 58
    .line 59
    return-void
.end method

.method private a(Ljava/lang/String;Lcom/salesforce/marketingcloud/toggles/a;)Lcom/salesforce/marketingcloud/toggles/a;
    .locals 0

    if-nez p2, :cond_1

    .line 17
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/d;->d:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    move-result-object p0

    const/4 p2, 0x0

    invoke-interface {p0, p1, p2}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    move-result p0

    if-eqz p0, :cond_0

    .line 18
    sget-object p0, Lcom/salesforce/marketingcloud/toggles/a;->c:Lcom/salesforce/marketingcloud/toggles/a;

    return-object p0

    .line 19
    :cond_0
    sget-object p0, Lcom/salesforce/marketingcloud/toggles/a;->d:Lcom/salesforce/marketingcloud/toggles/a;

    return-object p0

    :cond_1
    return-object p2
.end method

.method private a()V
    .locals 1

    .line 15
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/d;->isProximityMessagingEnabled()Z

    move-result v0

    if-nez v0, :cond_0

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/d;->isGeofenceMessagingEnabled()Z

    move-result v0

    if-nez v0, :cond_0

    .line 16
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/d;->e:Lcom/salesforce/marketingcloud/alarms/b;

    sget-object v0, Lcom/salesforce/marketingcloud/alarms/a$a;->e:Lcom/salesforce/marketingcloud/alarms/a$a;

    filled-new-array {v0}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/alarms/b;->d([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    :cond_0
    return-void
.end method

.method private a(ILcom/salesforce/marketingcloud/messages/Region;)V
    .locals 7

    .line 64
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->p:Ljava/util/Set;

    monitor-enter v0

    .line 65
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/d;->p:Ljava/util/Set;

    invoke-interface {v1}, Ljava/util/Set;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_1

    .line 66
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/d;->p:Ljava/util/Set;

    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lcom/salesforce/marketingcloud/messages/RegionMessageManager$RegionTransitionEventListener;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-eqz v1, :cond_0

    .line 67
    :try_start_1
    invoke-interface {v1, p1, p2}, Lcom/salesforce/marketingcloud/messages/RegionMessageManager$RegionTransitionEventListener;->onTransitionEvent(ILcom/salesforce/marketingcloud/messages/Region;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    :catch_0
    move-exception v2

    .line 68
    :try_start_2
    sget-object v3, Lcom/salesforce/marketingcloud/messages/d;->B:Ljava/lang/String;

    const-string v4, "%s threw an exception while processing the region (%s) transition (%d)"

    .line 69
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/messages/Region;->id()Ljava/lang/String;

    move-result-object v5

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    filled-new-array {v1, v5, v6}, [Ljava/lang/Object;

    move-result-object v1

    .line 70
    invoke-static {v3, v2, v4, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    goto :goto_0

    .line 71
    :cond_1
    monitor-exit v0

    return-void

    .line 72
    :goto_1
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    throw p0
.end method

.method private a(Lcom/salesforce/marketingcloud/InitializationStatus$a;I)V
    .locals 6

    const/16 v0, 0x20

    .line 1
    invoke-static {p2, v0}, Lcom/salesforce/marketingcloud/b;->a(II)Z

    move-result p2

    if-eqz p2, :cond_0

    goto :goto_0

    .line 2
    :cond_0
    new-instance v0, Lcom/salesforce/marketingcloud/messages/geofence/a;

    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/d;->d:Lcom/salesforce/marketingcloud/storage/h;

    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/d;->f:Lcom/salesforce/marketingcloud/location/f;

    iget-object v3, p0, Lcom/salesforce/marketingcloud/messages/d;->m:Lcom/salesforce/marketingcloud/http/e;

    iget-object v4, p0, Lcom/salesforce/marketingcloud/messages/d;->r:Lcom/salesforce/marketingcloud/internal/n;

    move-object v5, p0

    invoke-direct/range {v0 .. v5}, Lcom/salesforce/marketingcloud/messages/geofence/a;-><init>(Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/location/f;Lcom/salesforce/marketingcloud/http/e;Lcom/salesforce/marketingcloud/internal/n;Lcom/salesforce/marketingcloud/messages/c$a;)V

    iput-object v0, v5, Lcom/salesforce/marketingcloud/messages/d;->s:Lcom/salesforce/marketingcloud/messages/geofence/a;

    .line 3
    iget-object p0, v5, Lcom/salesforce/marketingcloud/messages/d;->e:Lcom/salesforce/marketingcloud/alarms/b;

    sget-object p2, Lcom/salesforce/marketingcloud/alarms/a$a;->e:Lcom/salesforce/marketingcloud/alarms/a$a;

    filled-new-array {p2}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    move-result-object p2

    invoke-virtual {p0, v5, p2}, Lcom/salesforce/marketingcloud/alarms/b;->a(Lcom/salesforce/marketingcloud/alarms/b$b;[Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 4
    invoke-virtual {v5}, Lcom/salesforce/marketingcloud/messages/d;->isGeofenceMessagingEnabled()Z

    move-result p0

    if-eqz p0, :cond_2

    const/4 p0, 0x1

    .line 5
    invoke-direct {v5, p0}, Lcom/salesforce/marketingcloud/messages/d;->c(Z)Z

    move-result p2

    if-nez p2, :cond_1

    .line 6
    invoke-virtual {v5}, Lcom/salesforce/marketingcloud/messages/d;->disableGeofenceMessaging()V

    :cond_1
    if-eqz p1, :cond_2

    .line 7
    iget-object p2, v5, Lcom/salesforce/marketingcloud/messages/d;->j:Landroid/content/Context;

    invoke-static {p2}, Lcom/salesforce/marketingcloud/util/f;->b(Landroid/content/Context;)Z

    move-result p2

    xor-int/2addr p0, p2

    invoke-virtual {p1, p0}, Lcom/salesforce/marketingcloud/InitializationStatus$a;->c(Z)V

    :cond_2
    :goto_0
    return-void
.end method

.method private a(Z)Z
    .locals 2

    .line 8
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->d:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->j()Lcom/salesforce/marketingcloud/storage/d;

    move-result-object v0

    invoke-static {v0}, Lcom/salesforce/marketingcloud/b;->a(Lcom/salesforce/marketingcloud/storage/d;)I

    move-result v0

    const/16 v1, 0x20

    invoke-static {v0, v1}, Lcom/salesforce/marketingcloud/b;->a(II)Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    return v1

    :cond_0
    if-nez p1, :cond_1

    .line 9
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/d;->isGeofenceMessagingEnabled()Z

    move-result p1

    if-eqz p1, :cond_1

    .line 10
    sget-object p0, Lcom/salesforce/marketingcloud/messages/d;->B:Ljava/lang/String;

    new-array p1, v1, [Ljava/lang/Object;

    const-string v0, "Geofence messaging is already enabled"

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return v1

    .line 11
    :cond_1
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/d;->s:Lcom/salesforce/marketingcloud/messages/geofence/a;

    if-eqz p1, :cond_2

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/geofence/a;->d()Z

    move-result p1

    if-nez p1, :cond_2

    .line 12
    sget-object p0, Lcom/salesforce/marketingcloud/messages/d;->B:Ljava/lang/String;

    new-array p1, v1, [Ljava/lang/Object;

    const-string v0, "Geofence messaging was not enabled due to device limitation."

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return v1

    .line 13
    :cond_2
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/d;->j:Landroid/content/Context;

    invoke-static {p1}, Lcom/salesforce/marketingcloud/util/f;->b(Landroid/content/Context;)Z

    move-result p1

    if-nez p1, :cond_3

    .line 14
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/d;->f()V

    return v1

    :cond_3
    const/4 p0, 0x1

    return p0
.end method

.method private b()V
    .locals 0

    .line 22
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/d;->disableProximityMessaging()V

    .line 23
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/d;->disableGeofenceMessaging()V

    return-void
.end method

.method private b(Lcom/salesforce/marketingcloud/InitializationStatus$a;I)V
    .locals 6

    const/16 v0, 0x40

    .line 1
    invoke-static {p2, v0}, Lcom/salesforce/marketingcloud/b;->a(II)Z

    move-result p2

    if-eqz p2, :cond_0

    goto :goto_0

    .line 2
    :cond_0
    new-instance v0, Lcom/salesforce/marketingcloud/messages/proximity/a;

    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/d;->d:Lcom/salesforce/marketingcloud/storage/h;

    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/d;->g:Lcom/salesforce/marketingcloud/proximity/e;

    iget-object v3, p0, Lcom/salesforce/marketingcloud/messages/d;->m:Lcom/salesforce/marketingcloud/http/e;

    iget-object v4, p0, Lcom/salesforce/marketingcloud/messages/d;->r:Lcom/salesforce/marketingcloud/internal/n;

    move-object v5, p0

    invoke-direct/range {v0 .. v5}, Lcom/salesforce/marketingcloud/messages/proximity/a;-><init>(Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/proximity/e;Lcom/salesforce/marketingcloud/http/e;Lcom/salesforce/marketingcloud/internal/n;Lcom/salesforce/marketingcloud/messages/c$a;)V

    iput-object v0, v5, Lcom/salesforce/marketingcloud/messages/d;->t:Lcom/salesforce/marketingcloud/messages/proximity/a;

    .line 3
    iget-object p0, v5, Lcom/salesforce/marketingcloud/messages/d;->e:Lcom/salesforce/marketingcloud/alarms/b;

    sget-object p2, Lcom/salesforce/marketingcloud/alarms/a$a;->e:Lcom/salesforce/marketingcloud/alarms/a$a;

    filled-new-array {p2}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    move-result-object p2

    invoke-virtual {p0, v5, p2}, Lcom/salesforce/marketingcloud/alarms/b;->a(Lcom/salesforce/marketingcloud/alarms/b$b;[Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 4
    invoke-virtual {v5}, Lcom/salesforce/marketingcloud/messages/d;->isProximityMessagingEnabled()Z

    move-result p0

    if-eqz p0, :cond_2

    const/4 p0, 0x1

    .line 5
    invoke-direct {v5, p0}, Lcom/salesforce/marketingcloud/messages/d;->d(Z)Z

    move-result p2

    if-nez p2, :cond_1

    .line 6
    invoke-virtual {v5}, Lcom/salesforce/marketingcloud/messages/d;->disableProximityMessaging()V

    :cond_1
    if-eqz p1, :cond_2

    .line 7
    iget-object p2, v5, Lcom/salesforce/marketingcloud/messages/d;->j:Landroid/content/Context;

    invoke-static {p2}, Lcom/salesforce/marketingcloud/util/f;->b(Landroid/content/Context;)Z

    move-result p2

    xor-int/2addr p0, p2

    invoke-virtual {p1, p0}, Lcom/salesforce/marketingcloud/InitializationStatus$a;->c(Z)V

    :cond_2
    :goto_0
    return-void
.end method

.method private b(Lcom/salesforce/marketingcloud/messages/MessageResponse;)V
    .locals 5

    .line 27
    instance-of v0, p1, Lcom/salesforce/marketingcloud/messages/geofence/GeofenceMessageResponse;

    if-eqz v0, :cond_2

    .line 28
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->n:Ljava/util/Set;

    monitor-enter v0

    .line 29
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/d;->n:Ljava/util/Set;

    invoke-interface {v1}, Ljava/util/Set;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_1

    .line 30
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/d;->n:Ljava/util/Set;

    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lcom/salesforce/marketingcloud/messages/RegionMessageManager$GeofenceMessageResponseListener;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-eqz v1, :cond_0

    .line 31
    :try_start_1
    move-object v2, p1

    check-cast v2, Lcom/salesforce/marketingcloud/messages/geofence/GeofenceMessageResponse;

    invoke-interface {v1, v2}, Lcom/salesforce/marketingcloud/messages/RegionMessageManager$GeofenceMessageResponseListener;->onGeofenceMessageResponse(Lcom/salesforce/marketingcloud/messages/geofence/GeofenceMessageResponse;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    :catch_0
    move-exception v2

    .line 32
    :try_start_2
    sget-object v3, Lcom/salesforce/marketingcloud/messages/d;->B:Ljava/lang/String;

    const-string v4, "%s threw an exception while processing the geofence response"

    .line 33
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v1

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    .line 34
    invoke-static {v3, v2, v4, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    goto :goto_0

    .line 35
    :cond_1
    monitor-exit v0

    goto :goto_4

    :goto_1
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    throw p0

    .line 36
    :cond_2
    instance-of v0, p1, Lcom/salesforce/marketingcloud/messages/proximity/ProximityMessageResponse;

    if-eqz v0, :cond_5

    .line 37
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->o:Ljava/util/Set;

    monitor-enter v0

    .line 38
    :try_start_3
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/d;->o:Ljava/util/Set;

    invoke-interface {v1}, Ljava/util/Set;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_4

    .line 39
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/d;->o:Ljava/util/Set;

    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :cond_3
    :goto_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_4

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lcom/salesforce/marketingcloud/messages/RegionMessageManager$ProximityMessageResponseListener;
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    if-eqz v1, :cond_3

    .line 40
    :try_start_4
    move-object v2, p1

    check-cast v2, Lcom/salesforce/marketingcloud/messages/proximity/ProximityMessageResponse;

    invoke-interface {v1, v2}, Lcom/salesforce/marketingcloud/messages/RegionMessageManager$ProximityMessageResponseListener;->onProximityMessageResponse(Lcom/salesforce/marketingcloud/messages/proximity/ProximityMessageResponse;)V
    :try_end_4
    .catch Ljava/lang/Exception; {:try_start_4 .. :try_end_4} :catch_1
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    goto :goto_2

    :catchall_1
    move-exception p0

    goto :goto_3

    :catch_1
    move-exception v2

    .line 41
    :try_start_5
    sget-object v3, Lcom/salesforce/marketingcloud/messages/d;->B:Ljava/lang/String;

    const-string v4, "%s threw an exception while processing the proximity response"

    .line 42
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v1

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    .line 43
    invoke-static {v3, v2, v4, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    goto :goto_2

    .line 44
    :cond_4
    monitor-exit v0

    goto :goto_4

    :goto_3
    monitor-exit v0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    throw p0

    :cond_5
    :goto_4
    return-void
.end method

.method private b(Z)Z
    .locals 2

    .line 8
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->d:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->j()Lcom/salesforce/marketingcloud/storage/d;

    move-result-object v0

    invoke-static {v0}, Lcom/salesforce/marketingcloud/b;->a(Lcom/salesforce/marketingcloud/storage/d;)I

    move-result v0

    const/16 v1, 0x40

    invoke-static {v0, v1}, Lcom/salesforce/marketingcloud/b;->a(II)Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    return v1

    :cond_0
    if-nez p1, :cond_1

    .line 9
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/d;->isProximityMessagingEnabled()Z

    move-result p1

    if-eqz p1, :cond_1

    .line 10
    sget-object p0, Lcom/salesforce/marketingcloud/messages/d;->B:Ljava/lang/String;

    new-array p1, v1, [Ljava/lang/Object;

    const-string v0, "Proximity messaging is already enabled."

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return v1

    .line 11
    :cond_1
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/d;->t:Lcom/salesforce/marketingcloud/messages/proximity/a;

    if-nez p1, :cond_2

    .line 12
    sget-object p0, Lcom/salesforce/marketingcloud/messages/d;->B:Ljava/lang/String;

    new-array p1, v1, [Ljava/lang/Object;

    const-string v0, "Proximity messaging was not enabled while configuring the SDK.  Messaging will not be enabled."

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return v1

    .line 13
    :cond_2
    sget p1, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v0, 0x1f

    if-lt p1, v0, :cond_3

    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/d;->h:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 14
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->proximityNotificationCustomizationOptions()Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;

    move-result-object p1

    if-nez p1, :cond_3

    .line 15
    sget-object p0, Lcom/salesforce/marketingcloud/messages/d;->B:Ljava/lang/String;

    new-array p1, v1, [Ljava/lang/Object;

    const-string v0, "Proximity messaging configuration is not passed while configuring the SDK.  Messaging will not be enabled."

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return v1

    .line 16
    :cond_3
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/d;->t:Lcom/salesforce/marketingcloud/messages/proximity/a;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/proximity/a;->d()Z

    move-result p1

    if-eqz p1, :cond_7

    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/d;->f:Lcom/salesforce/marketingcloud/location/f;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/location/f;->a()Z

    move-result p1

    if-nez p1, :cond_4

    goto :goto_0

    .line 17
    :cond_4
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/d;->j:Landroid/content/Context;

    invoke-static {p1}, Lcom/salesforce/marketingcloud/util/f;->b(Landroid/content/Context;)Z

    move-result p1

    if-nez p1, :cond_5

    .line 18
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/d;->f()V

    return v1

    .line 19
    :cond_5
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/d;->j:Landroid/content/Context;

    invoke-static {p1}, Lcom/salesforce/marketingcloud/util/f;->c(Landroid/content/Context;)Z

    move-result p1

    if-nez p1, :cond_6

    .line 20
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/d;->e()V

    return v1

    :cond_6
    const/4 p0, 0x1

    return p0

    .line 21
    :cond_7
    :goto_0
    sget-object p0, Lcom/salesforce/marketingcloud/messages/d;->B:Ljava/lang/String;

    new-array p1, v1, [Ljava/lang/Object;

    const-string v0, "Proximity messaging was not enabled due to device limitation."

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return v1
.end method

.method private static c(Lcom/salesforce/marketingcloud/messages/Region;)Lcom/salesforce/marketingcloud/location/b;
    .locals 8

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/location/b;

    .line 2
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/Region;->id()Ljava/lang/String;

    move-result-object v1

    .line 3
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/Region;->radius()I

    move-result v2

    int-to-float v2, v2

    const v3, 0x3f4ccccd    # 0.8f

    mul-float/2addr v2, v3

    .line 4
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/Region;->center()Lcom/salesforce/marketingcloud/location/LatLon;

    move-result-object v3

    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/location/LatLon;->latitude()D

    move-result-wide v3

    .line 5
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/Region;->center()Lcom/salesforce/marketingcloud/location/LatLon;

    move-result-object p0

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/location/LatLon;->longitude()D

    move-result-wide v5

    const/4 v7, 0x2

    invoke-direct/range {v0 .. v7}, Lcom/salesforce/marketingcloud/location/b;-><init>(Ljava/lang/String;FDDI)V

    return-object v0
.end method

.method private c()Z
    .locals 5
    .annotation build Landroid/annotation/SuppressLint;
        value = {
            "MissingPermission"
        }
    .end annotation

    .line 18
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->s:Lcom/salesforce/marketingcloud/messages/geofence/a;

    const/4 v1, 0x0

    if-nez v0, :cond_0

    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->t:Lcom/salesforce/marketingcloud/messages/proximity/a;

    if-nez v0, :cond_0

    return v1

    .line 19
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->q:Ljava/util/concurrent/atomic/AtomicBoolean;

    const/4 v2, 0x1

    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/atomic/AtomicBoolean;->compareAndSet(ZZ)Z

    move-result v0

    if-eqz v0, :cond_1

    .line 20
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->f:Lcom/salesforce/marketingcloud/location/f;

    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/location/f;->a(Lcom/salesforce/marketingcloud/location/e;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception v0

    .line 21
    sget-object v2, Lcom/salesforce/marketingcloud/messages/d;->B:Ljava/lang/String;

    new-array v3, v1, [Ljava/lang/Object;

    const-string v4, "Unable to request location update"

    invoke-static {v2, v0, v4, v3}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 22
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/d;->b()V

    return v1

    .line 23
    :cond_1
    :goto_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/d;->e:Lcom/salesforce/marketingcloud/alarms/b;

    sget-object v0, Lcom/salesforce/marketingcloud/alarms/a$a;->e:Lcom/salesforce/marketingcloud/alarms/a$a;

    filled-new-array {v0}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/alarms/b;->b([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    return v2
.end method

.method private declared-synchronized c(Z)Z
    .locals 3

    monitor-enter p0

    .line 6
    :try_start_0
    invoke-static {}, Lcom/salesforce/marketingcloud/util/b;->b()Z

    move-result v0

    const/4 v1, 0x0

    if-nez v0, :cond_0

    .line 7
    sget-object p1, Lcom/salesforce/marketingcloud/messages/d;->B:Ljava/lang/String;

    new-array v0, v1, [Ljava/lang/Object;

    const-string v2, "GooglePlayServices Location dependency missing from build."

    invoke-static {p1, v2, v0}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit p0

    return v1

    :catchall_0
    move-exception p1

    goto :goto_0

    .line 8
    :cond_0
    :try_start_1
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/messages/d;->a(Z)Z

    move-result v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    if-nez v0, :cond_1

    monitor-exit p0

    return v1

    .line 9
    :cond_1
    :try_start_2
    sget-object v0, Lcom/salesforce/marketingcloud/messages/d;->B:Ljava/lang/String;

    new-array v1, v1, [Ljava/lang/Object;

    const-string v2, "Enabling geofence messaging"

    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    if-nez p1, :cond_2

    .line 10
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/d;->d:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    move-result-object p1

    invoke-interface {p1}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object p1

    const-string v0, "et_geo_enabled_key"

    const/4 v1, 0x1

    invoke-interface {p1, v0, v1}, Landroid/content/SharedPreferences$Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;

    move-result-object p1

    invoke-interface {p1}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 11
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/d;->d:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    move-result-object p1

    invoke-interface {p1}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object p1

    const-string v0, "et_region_message_toggled_key"

    invoke-interface {p1, v0, v1}, Landroid/content/SharedPreferences$Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;

    move-result-object p1

    invoke-interface {p1}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 12
    sget-object p1, Lcom/salesforce/marketingcloud/toggles/a;->c:Lcom/salesforce/marketingcloud/toggles/a;

    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/d;->u:Lcom/salesforce/marketingcloud/toggles/a;

    .line 13
    new-instance p1, Landroid/os/Bundle;

    invoke-direct {p1}, Landroid/os/Bundle;-><init>()V

    .line 14
    const-string v0, "com.salesforce.marketingcloud.messaging.ENABLED"

    invoke-virtual {p1, v0, v1}, Landroid/os/BaseBundle;->putBoolean(Ljava/lang/String;Z)V

    .line 15
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->j:Landroid/content/Context;

    sget-object v1, Lcom/salesforce/marketingcloud/behaviors/a;->m:Lcom/salesforce/marketingcloud/behaviors/a;

    invoke-static {v0, v1, p1}, Lcom/salesforce/marketingcloud/behaviors/c;->a(Landroid/content/Context;Lcom/salesforce/marketingcloud/behaviors/a;Landroid/os/Bundle;)V

    .line 16
    :cond_2
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/d;->s:Lcom/salesforce/marketingcloud/messages/geofence/a;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/geofence/a;->a()V

    .line 17
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/d;->c()Z

    move-result p1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    monitor-exit p0

    return p1

    :goto_0
    :try_start_3
    monitor-exit p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    throw p1
.end method

.method private d(Lcom/salesforce/marketingcloud/messages/Region;)V
    .locals 4

    .line 17
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->r:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v0

    new-instance v1, Lcom/salesforce/marketingcloud/messages/d$e;

    const/4 v2, 0x0

    new-array v2, v2, [Ljava/lang/Object;

    const-string v3, "storing_fence"

    invoke-direct {v1, p0, v3, v2, p1}, Lcom/salesforce/marketingcloud/messages/d$e;-><init>(Lcom/salesforce/marketingcloud/messages/d;Ljava/lang/String;[Ljava/lang/Object;Lcom/salesforce/marketingcloud/messages/Region;)V

    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    return-void
.end method

.method private d(Z)Z
    .locals 3

    .line 1
    invoke-static {}, Lcom/salesforce/marketingcloud/util/b;->a()Z

    move-result v0

    const/4 v1, 0x0

    if-nez v0, :cond_0

    .line 2
    sget-object p0, Lcom/salesforce/marketingcloud/messages/d;->B:Ljava/lang/String;

    new-array p1, v1, [Ljava/lang/Object;

    const-string v0, "If you wish to use proximity messenger then you need to add the AltBeacon dependency."

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return v1

    .line 3
    :cond_0
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/messages/d;->b(Z)Z

    move-result v0

    if-nez v0, :cond_1

    return v1

    .line 4
    :cond_1
    sget-object v0, Lcom/salesforce/marketingcloud/messages/d;->B:Ljava/lang/String;

    new-array v1, v1, [Ljava/lang/Object;

    const-string v2, "Enabling proximity messaging."

    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    if-nez p1, :cond_3

    .line 5
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/d;->d:Lcom/salesforce/marketingcloud/storage/h;

    const/4 v0, 0x1

    if-eqz p1, :cond_2

    .line 6
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    move-result-object p1

    invoke-interface {p1}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object p1

    const-string v1, "et_proximity_enabled_key"

    invoke-interface {p1, v1, v0}, Landroid/content/SharedPreferences$Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;

    move-result-object p1

    invoke-interface {p1}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 7
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/d;->d:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    move-result-object p1

    invoke-interface {p1}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object p1

    const-string v1, "et_region_message_toggled_key"

    invoke-interface {p1, v1, v0}, Landroid/content/SharedPreferences$Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;

    move-result-object p1

    invoke-interface {p1}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 8
    :cond_2
    sget-object p1, Lcom/salesforce/marketingcloud/toggles/a;->c:Lcom/salesforce/marketingcloud/toggles/a;

    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/d;->v:Lcom/salesforce/marketingcloud/toggles/a;

    .line 9
    new-instance p1, Landroid/os/Bundle;

    invoke-direct {p1}, Landroid/os/Bundle;-><init>()V

    .line 10
    const-string v1, "com.salesforce.marketingcloud.messaging.ENABLED"

    invoke-virtual {p1, v1, v0}, Landroid/os/BaseBundle;->putBoolean(Ljava/lang/String;Z)V

    .line 11
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->j:Landroid/content/Context;

    sget-object v1, Lcom/salesforce/marketingcloud/behaviors/a;->n:Lcom/salesforce/marketingcloud/behaviors/a;

    invoke-static {v0, v1, p1}, Lcom/salesforce/marketingcloud/behaviors/c;->a(Landroid/content/Context;Lcom/salesforce/marketingcloud/behaviors/a;Landroid/os/Bundle;)V

    goto :goto_0

    .line 12
    :cond_3
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/d;->t:Lcom/salesforce/marketingcloud/messages/proximity/a;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/proximity/a;->c()V

    .line 13
    :goto_0
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/d;->t:Lcom/salesforce/marketingcloud/messages/proximity/a;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/proximity/a;->a()V

    .line 14
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/d;->c()Z

    move-result p0

    return p0
.end method

.method private e()V
    .locals 2

    .line 1
    sget p0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 2
    .line 3
    const/16 v0, 0x1f

    .line 4
    .line 5
    if-lt p0, v0, :cond_0

    .line 6
    .line 7
    sget-object p0, Lcom/salesforce/marketingcloud/messages/d;->B:Ljava/lang/String;

    .line 8
    .line 9
    const-string v0, "android.permission.BLUETOOTH_SCAN"

    .line 10
    .line 11
    const-string v1, "android.permission.BLUETOOTH_CONNECT"

    .line 12
    .line 13
    filled-new-array {v0, v1}, [Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    const-string v1, "Missing %s or %s"

    .line 18
    .line 19
    invoke-static {p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    :cond_0
    return-void
.end method

.method private f()V
    .locals 2

    .line 1
    sget-object p0, Lcom/salesforce/marketingcloud/messages/d;->B:Ljava/lang/String;

    .line 2
    .line 3
    const-string v0, "android.permission.ACCESS_FINE_LOCATION"

    .line 4
    .line 5
    const-string v1, "android.permission.ACCESS_BACKGROUND_LOCATION"

    .line 6
    .line 7
    filled-new-array {v0, v1}, [Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    const-string v1, "Missing %s or %s"

    .line 12
    .line 13
    invoke-static {p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method private g()V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/d;->isGeofenceMessagingEnabled()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x1

    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    invoke-direct {p0, v1}, Lcom/salesforce/marketingcloud/messages/d;->a(Z)Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->s:Lcom/salesforce/marketingcloud/messages/geofence/a;

    .line 15
    .line 16
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/geofence/a;->c()V

    .line 17
    .line 18
    .line 19
    :cond_0
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/d;->isProximityMessagingEnabled()Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_1

    .line 24
    .line 25
    invoke-direct {p0, v1}, Lcom/salesforce/marketingcloud/messages/d;->b(Z)Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-eqz v0, :cond_1

    .line 30
    .line 31
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/d;->t:Lcom/salesforce/marketingcloud/messages/proximity/a;

    .line 32
    .line 33
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/proximity/a;->c()V

    .line 34
    .line 35
    .line 36
    :cond_1
    return-void
.end method

.method private h()V
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->r:Lcom/salesforce/marketingcloud/internal/n;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    new-instance v1, Lcom/salesforce/marketingcloud/messages/d$c;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    new-array v2, v2, [Ljava/lang/Object;

    .line 11
    .line 12
    const-string v3, "reset_flags"

    .line 13
    .line 14
    invoke-direct {v1, p0, v3, v2}, Lcom/salesforce/marketingcloud/messages/d$c;-><init>(Lcom/salesforce/marketingcloud/messages/d;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method private i()V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/d;->isGeofenceMessagingEnabled()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->r:Lcom/salesforce/marketingcloud/internal/n;

    .line 8
    .line 9
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    new-instance v1, Lcom/salesforce/marketingcloud/messages/d$a;

    .line 14
    .line 15
    const/4 v2, 0x0

    .line 16
    new-array v2, v2, [Ljava/lang/Object;

    .line 17
    .line 18
    const-string v3, "update_geofence"

    .line 19
    .line 20
    invoke-direct {v1, p0, v3, v2}, Lcom/salesforce/marketingcloud/messages/d$a;-><init>(Lcom/salesforce/marketingcloud/messages/d;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 24
    .line 25
    .line 26
    :cond_0
    return-void
.end method

.method private j()V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/d;->isProximityMessagingEnabled()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->r:Lcom/salesforce/marketingcloud/internal/n;

    .line 8
    .line 9
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    new-instance v1, Lcom/salesforce/marketingcloud/messages/d$b;

    .line 14
    .line 15
    const/4 v2, 0x0

    .line 16
    new-array v2, v2, [Ljava/lang/Object;

    .line 17
    .line 18
    const-string v3, "update_proximity"

    .line 19
    .line 20
    invoke-direct {v1, p0, v3, v2}, Lcom/salesforce/marketingcloud/messages/d$b;-><init>(Lcom/salesforce/marketingcloud/messages/d;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 24
    .line 25
    .line 26
    :cond_0
    return-void
.end method


# virtual methods
.method public final a(ILjava/lang/String;)V
    .locals 0

    .line 52
    sget-object p0, Lcom/salesforce/marketingcloud/messages/d;->B:Ljava/lang/String;

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    filled-new-array {p1, p2}, [Ljava/lang/Object;

    move-result-object p1

    const-string p2, "Region error %d - %s"

    invoke-static {p0, p2, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public a(Landroid/location/Location;)V
    .locals 6

    .line 33
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->q:Ljava/util/concurrent/atomic/AtomicBoolean;

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    if-nez p1, :cond_0

    return-void

    .line 34
    :cond_0
    :try_start_0
    new-instance v0, Lcom/salesforce/marketingcloud/location/LatLon;

    invoke-virtual {p1}, Landroid/location/Location;->getLatitude()D

    move-result-wide v2

    invoke-virtual {p1}, Landroid/location/Location;->getLongitude()D

    move-result-wide v4

    invoke-direct {v0, v2, v3, v4, v5}, Lcom/salesforce/marketingcloud/location/LatLon;-><init>(DD)V

    .line 35
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/d;->r:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object p1

    new-instance v2, Lcom/salesforce/marketingcloud/messages/d$d;

    const-string v3, "store_latlon"

    new-array v4, v1, [Ljava/lang/Object;

    invoke-direct {v2, p0, v3, v4, v0}, Lcom/salesforce/marketingcloud/messages/d$d;-><init>(Lcom/salesforce/marketingcloud/messages/d;Ljava/lang/String;[Ljava/lang/Object;Lcom/salesforce/marketingcloud/location/LatLon;)V

    invoke-interface {p1, v2}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception p0

    .line 36
    sget-object p1, Lcom/salesforce/marketingcloud/messages/d;->B:Ljava/lang/String;

    new-array v0, v1, [Ljava/lang/Object;

    const-string v1, "Unable to make geofence message request after location update"

    invoke-static {p1, p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public final a(Lcom/salesforce/marketingcloud/alarms/a$a;)V
    .locals 1

    .line 20
    sget-object v0, Lcom/salesforce/marketingcloud/messages/d$g;->a:[I

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    aget p1, v0, p1

    const/4 v0, 0x1

    if-eq p1, v0, :cond_0

    goto :goto_0

    .line 21
    :cond_0
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/d;->i()V

    .line 22
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/d;->j()V

    .line 23
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/d;->isGeofenceMessagingEnabled()Z

    move-result p1

    if-nez p1, :cond_2

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/d;->isProximityMessagingEnabled()Z

    move-result p1

    if-eqz p1, :cond_1

    goto :goto_1

    :cond_1
    :goto_0
    return-void

    .line 24
    :cond_2
    :goto_1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/d;->e:Lcom/salesforce/marketingcloud/alarms/b;

    sget-object p1, Lcom/salesforce/marketingcloud/alarms/a$a;->e:Lcom/salesforce/marketingcloud/alarms/a$a;

    filled-new-array {p1}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    move-result-object p1

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/alarms/b;->b([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/location/LatLon;)V
    .locals 3

    .line 25
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/d;->isGeofenceMessagingEnabled()Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->s:Lcom/salesforce/marketingcloud/messages/geofence/a;

    if-eqz v0, :cond_0

    if-eqz p1, :cond_0

    .line 26
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/d;->i:Ljava/lang/String;

    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/d;->h:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    invoke-virtual {v0, p1, v1, v2, p0}, Lcom/salesforce/marketingcloud/messages/geofence/a;->a(Lcom/salesforce/marketingcloud/location/LatLon;Ljava/lang/String;Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/messages/c$b;)V

    return-void

    .line 27
    :cond_0
    sget-object p0, Lcom/salesforce/marketingcloud/messages/d;->B:Ljava/lang/String;

    const/4 p1, 0x0

    new-array p1, p1, [Ljava/lang/Object;

    const-string v0, "Tried to update geofence messages, but was not enabled."

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/location/LatLon;I)V
    .locals 1

    .line 53
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->j:Landroid/content/Context;

    invoke-static {v0}, Lcom/salesforce/marketingcloud/util/f;->b(Landroid/content/Context;)Z

    move-result v0

    if-eqz v0, :cond_0

    .line 54
    invoke-static {p1, p2}, Lcom/salesforce/marketingcloud/internal/l;->a(Lcom/salesforce/marketingcloud/location/LatLon;I)Lcom/salesforce/marketingcloud/messages/Region;

    move-result-object p1

    .line 55
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/messages/d;->d(Lcom/salesforce/marketingcloud/messages/Region;)V

    .line 56
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/d;->f:Lcom/salesforce/marketingcloud/location/f;

    invoke-static {p1}, Lcom/salesforce/marketingcloud/messages/d;->c(Lcom/salesforce/marketingcloud/messages/Region;)Lcom/salesforce/marketingcloud/location/b;

    move-result-object p1

    filled-new-array {p1}, [Lcom/salesforce/marketingcloud/location/b;

    move-result-object p1

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/location/f;->a([Lcom/salesforce/marketingcloud/location/b;)V

    :cond_0
    return-void
.end method

.method public final a(Lcom/salesforce/marketingcloud/messages/MessageResponse;)V
    .locals 2

    if-nez p1, :cond_0

    return-void

    .line 28
    :cond_0
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/messages/d;->b(Lcom/salesforce/marketingcloud/messages/MessageResponse;)V

    .line 29
    :try_start_0
    invoke-interface {p1}, Lcom/salesforce/marketingcloud/messages/MessageResponse;->getRefreshCenter()Lcom/salesforce/marketingcloud/location/LatLon;

    move-result-object v0

    invoke-interface {p1}, Lcom/salesforce/marketingcloud/messages/MessageResponse;->getRefreshRadius()I

    move-result p1

    invoke-static {v0, p1}, Lcom/salesforce/marketingcloud/internal/l;->a(Lcom/salesforce/marketingcloud/location/LatLon;I)Lcom/salesforce/marketingcloud/messages/Region;

    move-result-object p1

    .line 30
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/messages/d;->d(Lcom/salesforce/marketingcloud/messages/Region;)V

    .line 31
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/d;->f:Lcom/salesforce/marketingcloud/location/f;

    invoke-static {p1}, Lcom/salesforce/marketingcloud/messages/d;->c(Lcom/salesforce/marketingcloud/messages/Region;)Lcom/salesforce/marketingcloud/location/b;

    move-result-object p1

    filled-new-array {p1}, [Lcom/salesforce/marketingcloud/location/b;

    move-result-object p1

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/location/f;->a([Lcom/salesforce/marketingcloud/location/b;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception p0

    .line 32
    sget-object p1, Lcom/salesforce/marketingcloud/messages/d;->B:Ljava/lang/String;

    const/4 v0, 0x0

    new-array v0, v0, [Ljava/lang/Object;

    const-string v1, "Failed to updated radius for magic region."

    invoke-static {p1, p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/messages/Region;)V
    .locals 1

    const/4 v0, 0x2

    .line 63
    invoke-direct {p0, v0, p1}, Lcom/salesforce/marketingcloud/messages/d;->a(ILcom/salesforce/marketingcloud/messages/Region;)V

    return-void
.end method

.method public final a(Lcom/salesforce/marketingcloud/messages/Region;Lcom/salesforce/marketingcloud/messages/Message;)V
    .locals 3

    if-eqz p1, :cond_1

    if-nez p2, :cond_0

    goto :goto_0

    .line 57
    :cond_0
    sget-object v0, Lcom/salesforce/marketingcloud/messages/d;->B:Ljava/lang/String;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/Region;->id()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/messages/Message;->id()Ljava/lang/String;

    move-result-object v2

    filled-new-array {v1, v2}, [Ljava/lang/Object;

    move-result-object v1

    const-string v2, "showMessage(%s, %s)"

    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 58
    invoke-static {p2, p1}, Lcom/salesforce/marketingcloud/internal/j;->a(Lcom/salesforce/marketingcloud/messages/Message;Lcom/salesforce/marketingcloud/messages/Region;)Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    move-result-object p1

    if-eqz p1, :cond_1

    .line 59
    invoke-static {p2}, Lcom/salesforce/marketingcloud/messages/b;->c(Lcom/salesforce/marketingcloud/messages/Message;)Z

    move-result v0

    if-eqz v0, :cond_1

    .line 60
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->d:Lcom/salesforce/marketingcloud/storage/h;

    invoke-static {p2, v0}, Lcom/salesforce/marketingcloud/messages/b;->a(Lcom/salesforce/marketingcloud/messages/Message;Lcom/salesforce/marketingcloud/storage/h;)V

    .line 61
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->k:Lcom/salesforce/marketingcloud/notifications/a;

    new-instance v1, Lcom/salesforce/marketingcloud/messages/d$f;

    invoke-direct {v1, p0, p2}, Lcom/salesforce/marketingcloud/messages/d$f;-><init>(Lcom/salesforce/marketingcloud/messages/d;Lcom/salesforce/marketingcloud/messages/Message;)V

    invoke-virtual {v0, p1, v1}, Lcom/salesforce/marketingcloud/notifications/a;->a(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;Lcom/salesforce/marketingcloud/notifications/a$b;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception p0

    .line 62
    sget-object p1, Lcom/salesforce/marketingcloud/messages/d;->B:Ljava/lang/String;

    const/4 p2, 0x0

    new-array p2, p2, [Ljava/lang/Object;

    const-string v0, "Failed to show message"

    invoke-static {p1, p0, v0, p2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    :cond_1
    :goto_0
    return-void
.end method

.method public final a(Ljava/lang/String;ILandroid/location/Location;)V
    .locals 2
    .annotation build Landroid/annotation/SuppressLint;
        value = {
            "MissingPermission"
        }
    .end annotation

    const/4 v0, 0x2

    if-ne p2, v0, :cond_2

    .line 45
    const-string p2, "~~m@g1c_f3nc3~~"

    invoke-virtual {p2, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_2

    .line 46
    sget-object p1, Lcom/salesforce/marketingcloud/messages/d;->B:Ljava/lang/String;

    const/4 p2, 0x0

    new-array v0, p2, [Ljava/lang/Object;

    const-string v1, "MagicRegion exited"

    invoke-static {p1, v1, v0}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 47
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->j:Landroid/content/Context;

    invoke-static {v0}, Lcom/salesforce/marketingcloud/util/f;->b(Landroid/content/Context;)Z

    move-result v0

    if-eqz v0, :cond_1

    if-eqz p3, :cond_0

    .line 48
    invoke-virtual {p0, p3}, Lcom/salesforce/marketingcloud/messages/d;->a(Landroid/location/Location;)V

    return-void

    .line 49
    :cond_0
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/d;->f:Lcom/salesforce/marketingcloud/location/f;

    invoke-virtual {p1, p0}, Lcom/salesforce/marketingcloud/location/f;->a(Lcom/salesforce/marketingcloud/location/e;)V

    return-void

    .line 50
    :cond_1
    new-array p2, p2, [Ljava/lang/Object;

    const-string p3, "MagicRegion exited, but was missing location permission."

    invoke-static {p1, p3, p2}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 51
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/d;->b()V

    :cond_2
    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/location/LatLon;Lcom/salesforce/marketingcloud/messages/Region;)Z
    .locals 12

    const/4 v0, 0x1

    if-eqz p2, :cond_1

    const/4 v1, 0x4

    const/4 v2, 0x0

    .line 37
    :try_start_0
    new-array v11, v1, [F

    fill-array-data v11, :array_0

    .line 38
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/location/LatLon;->latitude()D

    move-result-wide v3

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/location/LatLon;->longitude()D

    move-result-wide v5

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/messages/Region;->center()Lcom/salesforce/marketingcloud/location/LatLon;

    move-result-object p1

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/location/LatLon;->latitude()D

    move-result-wide v7

    .line 39
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/messages/Region;->center()Lcom/salesforce/marketingcloud/location/LatLon;

    move-result-object p1

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/location/LatLon;->longitude()D

    move-result-wide v9

    .line 40
    invoke-static/range {v3 .. v11}, Landroid/location/Location;->distanceBetween(DDDD[F)V

    .line 41
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/d;->d()Z

    move-result p1

    if-nez p1, :cond_1

    aget p1, v11, v2

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/messages/Region;->radius()I

    move-result p2
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    int-to-float p2, p2

    const v1, 0x3f4ccccd    # 0.8f

    mul-float/2addr p2, v1

    cmpl-float p1, p1, p2

    if-lez p1, :cond_0

    goto :goto_0

    :cond_0
    move v0, v2

    goto :goto_0

    .line 42
    :catch_0
    sget-object p1, Lcom/salesforce/marketingcloud/messages/d;->B:Ljava/lang/String;

    new-array p2, v2, [Ljava/lang/Object;

    const-string v1, "An error occurred while calculating distance between last known location and the current location."

    invoke-static {p1, v1, p2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 43
    :cond_1
    :goto_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/d;->d:Lcom/salesforce/marketingcloud/storage/h;

    if-eqz p0, :cond_2

    .line 44
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    move-result-object p0

    invoke-interface {p0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object p0

    const-string p1, "et_region_message_toggled_key"

    invoke-interface {p0, p1}, Landroid/content/SharedPreferences$Editor;->remove(Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    move-result-object p0

    invoke-interface {p0}, Landroid/content/SharedPreferences$Editor;->apply()V

    :cond_2
    return v0

    :array_0
    .array-data 4
        0x0
        0x0
        0x0
        0x0
    .end array-data
.end method

.method public b(Lcom/salesforce/marketingcloud/location/LatLon;)V
    .locals 3

    .line 24
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/d;->isProximityMessagingEnabled()Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->t:Lcom/salesforce/marketingcloud/messages/proximity/a;

    if-eqz v0, :cond_0

    if-eqz p1, :cond_0

    .line 25
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/d;->i:Ljava/lang/String;

    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/d;->h:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    invoke-virtual {v0, p1, v1, v2, p0}, Lcom/salesforce/marketingcloud/messages/proximity/a;->a(Lcom/salesforce/marketingcloud/location/LatLon;Ljava/lang/String;Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/messages/c$b;)V

    return-void

    .line 26
    :cond_0
    sget-object p0, Lcom/salesforce/marketingcloud/messages/d;->B:Ljava/lang/String;

    const/4 p1, 0x0

    new-array p1, p1, [Ljava/lang/Object;

    const-string v0, "Tried to update proximity messages, but was not enabled."

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public b(Lcom/salesforce/marketingcloud/messages/Region;)V
    .locals 1

    const/4 v0, 0x1

    .line 45
    invoke-direct {p0, v0, p1}, Lcom/salesforce/marketingcloud/messages/d;->a(ILcom/salesforce/marketingcloud/messages/Region;)V

    return-void
.end method

.method public final componentName()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "RegionMessageManager"

    .line 2
    .line 3
    return-object p0
.end method

.method public final componentState()Lorg/json/JSONObject;
    .locals 5

    .line 1
    new-instance v0, Lorg/json/JSONObject;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 4
    .line 5
    .line 6
    :try_start_0
    const-string v1, "geofenceMessagingEnabled"

    .line 7
    .line 8
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/d;->isGeofenceMessagingEnabled()Z

    .line 9
    .line 10
    .line 11
    move-result v2

    .line 12
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Z)Lorg/json/JSONObject;

    .line 13
    .line 14
    .line 15
    const-string v1, "proximityMessagingEnabled"

    .line 16
    .line 17
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/d;->isProximityMessagingEnabled()Z

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Z)Lorg/json/JSONObject;

    .line 22
    .line 23
    .line 24
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/d;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 25
    .line 26
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/storage/h;->o()Lcom/salesforce/marketingcloud/storage/j;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/d;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 31
    .line 32
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 33
    .line 34
    .line 35
    move-result-object v2

    .line 36
    if-eqz v1, :cond_1

    .line 37
    .line 38
    invoke-interface {v1, v2}, Lcom/salesforce/marketingcloud/storage/j;->l(Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/messages/Region;

    .line 39
    .line 40
    .line 41
    move-result-object v3

    .line 42
    if-eqz v3, :cond_0

    .line 43
    .line 44
    const-string v4, "magic_fence"

    .line 45
    .line 46
    invoke-virtual {v0, v4, v3}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 47
    .line 48
    .line 49
    goto :goto_0

    .line 50
    :catch_0
    move-exception p0

    .line 51
    goto :goto_1

    .line 52
    :cond_0
    :goto_0
    const-string v3, "geofence_regions"

    .line 53
    .line 54
    const/4 v4, 0x1

    .line 55
    invoke-interface {v1, v4, v2}, Lcom/salesforce/marketingcloud/storage/j;->a(ILcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;

    .line 56
    .line 57
    .line 58
    move-result-object v4

    .line 59
    invoke-virtual {v0, v3, v4}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 60
    .line 61
    .line 62
    const-string v3, "geofence_region_messages"

    .line 63
    .line 64
    iget-object v4, p0, Lcom/salesforce/marketingcloud/messages/d;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 65
    .line 66
    invoke-virtual {v4}, Lcom/salesforce/marketingcloud/storage/h;->n()Lcom/salesforce/marketingcloud/storage/i;

    .line 67
    .line 68
    .line 69
    move-result-object v4

    .line 70
    invoke-interface {v4, v2}, Lcom/salesforce/marketingcloud/storage/i;->a(Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;

    .line 71
    .line 72
    .line 73
    move-result-object v4

    .line 74
    invoke-virtual {v0, v3, v4}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 75
    .line 76
    .line 77
    const-string v3, "proximity_regions"

    .line 78
    .line 79
    const/4 v4, 0x3

    .line 80
    invoke-interface {v1, v4, v2}, Lcom/salesforce/marketingcloud/storage/j;->a(ILcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;

    .line 81
    .line 82
    .line 83
    move-result-object v1

    .line 84
    invoke-virtual {v0, v3, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 85
    .line 86
    .line 87
    const-string v1, "proximity_region_messages"

    .line 88
    .line 89
    iget-object v3, p0, Lcom/salesforce/marketingcloud/messages/d;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 90
    .line 91
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/storage/h;->n()Lcom/salesforce/marketingcloud/storage/i;

    .line 92
    .line 93
    .line 94
    move-result-object v3

    .line 95
    invoke-interface {v3, v2}, Lcom/salesforce/marketingcloud/storage/i;->b(Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;

    .line 96
    .line 97
    .line 98
    move-result-object v2

    .line 99
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 100
    .line 101
    .line 102
    const-string v1, "boot_complete_permission"

    .line 103
    .line 104
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/d;->j:Landroid/content/Context;

    .line 105
    .line 106
    const-string v2, "android.permission.RECEIVE_BOOT_COMPLETED"

    .line 107
    .line 108
    invoke-static {p0, v2}, Lcom/salesforce/marketingcloud/util/f;->a(Landroid/content/Context;Ljava/lang/String;)Z

    .line 109
    .line 110
    .line 111
    move-result p0

    .line 112
    invoke-virtual {v0, v1, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Z)Lorg/json/JSONObject;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 113
    .line 114
    .line 115
    :cond_1
    return-object v0

    .line 116
    :goto_1
    sget-object v1, Lcom/salesforce/marketingcloud/messages/d;->B:Ljava/lang/String;

    .line 117
    .line 118
    const/4 v2, 0x0

    .line 119
    new-array v2, v2, [Ljava/lang/Object;

    .line 120
    .line 121
    const-string v3, "Error creating RegionMessageManager state."

    .line 122
    .line 123
    invoke-static {v1, p0, v3, v2}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 124
    .line 125
    .line 126
    return-object v0
.end method

.method public final declared-synchronized controlChannelInit(I)V
    .locals 5

    .line 1
    monitor-enter p0

    .line 2
    const/16 v0, 0x20

    .line 3
    .line 4
    :try_start_0
    invoke-static {p1, v0}, Lcom/salesforce/marketingcloud/b;->a(II)Z

    .line 5
    .line 6
    .line 7
    move-result v1

    .line 8
    const/4 v2, 0x0

    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/d;->disableGeofenceMessaging()V

    .line 12
    .line 13
    .line 14
    iput-object v2, p0, Lcom/salesforce/marketingcloud/messages/d;->s:Lcom/salesforce/marketingcloud/messages/geofence/a;

    .line 15
    .line 16
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/d;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 17
    .line 18
    iget-object v3, p0, Lcom/salesforce/marketingcloud/messages/d;->f:Lcom/salesforce/marketingcloud/location/f;

    .line 19
    .line 20
    iget-object v4, p0, Lcom/salesforce/marketingcloud/messages/d;->m:Lcom/salesforce/marketingcloud/http/e;

    .line 21
    .line 22
    invoke-static {p1, v0}, Lcom/salesforce/marketingcloud/b;->c(II)Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    invoke-static {v1, v3, v4, v0}, Lcom/salesforce/marketingcloud/messages/geofence/a;->a(Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/location/f;Lcom/salesforce/marketingcloud/http/e;Z)V

    .line 27
    .line 28
    .line 29
    goto :goto_0

    .line 30
    :catchall_0
    move-exception p1

    .line 31
    goto/16 :goto_3

    .line 32
    .line 33
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->s:Lcom/salesforce/marketingcloud/messages/geofence/a;

    .line 34
    .line 35
    if-nez v0, :cond_1

    .line 36
    .line 37
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->h:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 38
    .line 39
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->geofencingEnabled()Z

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    if-eqz v0, :cond_1

    .line 44
    .line 45
    invoke-direct {p0, v2, p1}, Lcom/salesforce/marketingcloud/messages/d;->a(Lcom/salesforce/marketingcloud/InitializationStatus$a;I)V

    .line 46
    .line 47
    .line 48
    :cond_1
    :goto_0
    const/16 v0, 0x40

    .line 49
    .line 50
    invoke-static {p1, v0}, Lcom/salesforce/marketingcloud/b;->a(II)Z

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    if-eqz v1, :cond_2

    .line 55
    .line 56
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/d;->disableProximityMessaging()V

    .line 57
    .line 58
    .line 59
    iput-object v2, p0, Lcom/salesforce/marketingcloud/messages/d;->t:Lcom/salesforce/marketingcloud/messages/proximity/a;

    .line 60
    .line 61
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/d;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 62
    .line 63
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/d;->g:Lcom/salesforce/marketingcloud/proximity/e;

    .line 64
    .line 65
    iget-object v3, p0, Lcom/salesforce/marketingcloud/messages/d;->m:Lcom/salesforce/marketingcloud/http/e;

    .line 66
    .line 67
    invoke-static {p1, v0}, Lcom/salesforce/marketingcloud/b;->c(II)Z

    .line 68
    .line 69
    .line 70
    move-result v0

    .line 71
    invoke-static {v1, v2, v3, v0}, Lcom/salesforce/marketingcloud/messages/proximity/a;->a(Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/proximity/e;Lcom/salesforce/marketingcloud/http/e;Z)V

    .line 72
    .line 73
    .line 74
    goto :goto_1

    .line 75
    :cond_2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->t:Lcom/salesforce/marketingcloud/messages/proximity/a;

    .line 76
    .line 77
    if-nez v0, :cond_3

    .line 78
    .line 79
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->h:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 80
    .line 81
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->proximityEnabled()Z

    .line 82
    .line 83
    .line 84
    move-result v0

    .line 85
    if-eqz v0, :cond_3

    .line 86
    .line 87
    invoke-direct {p0, v2, p1}, Lcom/salesforce/marketingcloud/messages/d;->b(Lcom/salesforce/marketingcloud/InitializationStatus$a;I)V

    .line 88
    .line 89
    .line 90
    :cond_3
    :goto_1
    const/16 v0, 0x60

    .line 91
    .line 92
    invoke-static {p1, v0}, Lcom/salesforce/marketingcloud/b;->a(II)Z

    .line 93
    .line 94
    .line 95
    move-result p1

    .line 96
    if-eqz p1, :cond_4

    .line 97
    .line 98
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/d;->f:Lcom/salesforce/marketingcloud/location/f;

    .line 99
    .line 100
    invoke-virtual {p1, p0}, Lcom/salesforce/marketingcloud/location/f;->b(Lcom/salesforce/marketingcloud/location/c;)V

    .line 101
    .line 102
    .line 103
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/d;->f:Lcom/salesforce/marketingcloud/location/f;

    .line 104
    .line 105
    invoke-virtual {p1, p0}, Lcom/salesforce/marketingcloud/location/f;->b(Lcom/salesforce/marketingcloud/location/e;)V

    .line 106
    .line 107
    .line 108
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/d;->l:Lcom/salesforce/marketingcloud/behaviors/c;

    .line 109
    .line 110
    invoke-virtual {p1, p0}, Lcom/salesforce/marketingcloud/behaviors/c;->a(Lcom/salesforce/marketingcloud/behaviors/b;)V

    .line 111
    .line 112
    .line 113
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/d;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 114
    .line 115
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/storage/h;->m()Lcom/salesforce/marketingcloud/storage/g;

    .line 116
    .line 117
    .line 118
    move-result-object p1

    .line 119
    invoke-interface {p1}, Lcom/salesforce/marketingcloud/storage/g;->g()I

    .line 120
    .line 121
    .line 122
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/d;->e:Lcom/salesforce/marketingcloud/alarms/b;

    .line 123
    .line 124
    sget-object v0, Lcom/salesforce/marketingcloud/alarms/a$a;->e:Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 125
    .line 126
    filled-new-array {v0}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 127
    .line 128
    .line 129
    move-result-object v1

    .line 130
    invoke-virtual {p1, v1}, Lcom/salesforce/marketingcloud/alarms/b;->e([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 131
    .line 132
    .line 133
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/d;->e:Lcom/salesforce/marketingcloud/alarms/b;

    .line 134
    .line 135
    filled-new-array {v0}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 136
    .line 137
    .line 138
    move-result-object v0

    .line 139
    invoke-virtual {p1, v0}, Lcom/salesforce/marketingcloud/alarms/b;->d([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 140
    .line 141
    .line 142
    goto :goto_2

    .line 143
    :cond_4
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/d;->l:Lcom/salesforce/marketingcloud/behaviors/c;

    .line 144
    .line 145
    sget-object v0, Lcom/salesforce/marketingcloud/behaviors/a;->f:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 146
    .line 147
    sget-object v1, Lcom/salesforce/marketingcloud/behaviors/a;->h:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 148
    .line 149
    sget-object v2, Lcom/salesforce/marketingcloud/behaviors/a;->e:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 150
    .line 151
    sget-object v3, Lcom/salesforce/marketingcloud/behaviors/a;->i:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 152
    .line 153
    invoke-static {v0, v1, v2, v3}, Ljava/util/EnumSet;->of(Ljava/lang/Enum;Ljava/lang/Enum;Ljava/lang/Enum;Ljava/lang/Enum;)Ljava/util/EnumSet;

    .line 154
    .line 155
    .line 156
    move-result-object v0

    .line 157
    invoke-virtual {p1, p0, v0}, Lcom/salesforce/marketingcloud/behaviors/c;->a(Lcom/salesforce/marketingcloud/behaviors/b;Ljava/util/EnumSet;)V

    .line 158
    .line 159
    .line 160
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/d;->f:Lcom/salesforce/marketingcloud/location/f;

    .line 161
    .line 162
    invoke-virtual {p1, p0}, Lcom/salesforce/marketingcloud/location/f;->a(Lcom/salesforce/marketingcloud/location/c;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 163
    .line 164
    .line 165
    :goto_2
    monitor-exit p0

    .line 166
    return-void

    .line 167
    :goto_3
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 168
    throw p1
.end method

.method public d()Z
    .locals 2

    .line 15
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/d;->isProximityMessagingEnabled()Z

    move-result v0

    const/4 v1, 0x0

    if-nez v0, :cond_0

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/d;->isGeofenceMessagingEnabled()Z

    move-result v0

    if-eqz v0, :cond_1

    :cond_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/d;->d:Lcom/salesforce/marketingcloud/storage/h;

    if-eqz p0, :cond_1

    .line 16
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    move-result-object p0

    const-string v0, "et_region_message_toggled_key"

    invoke-interface {p0, v0, v1}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    move-result p0

    if-eqz p0, :cond_1

    const/4 p0, 0x1

    return p0

    :cond_1
    return v1
.end method

.method public final declared-synchronized disableGeofenceMessaging()V
    .locals 4

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    sget-object v0, Lcom/salesforce/marketingcloud/messages/d;->B:Ljava/lang/String;

    .line 3
    .line 4
    const/4 v1, 0x0

    .line 5
    new-array v2, v1, [Ljava/lang/Object;

    .line 6
    .line 7
    const-string v3, "Disabling geofence messaging"

    .line 8
    .line 9
    invoke-static {v0, v3, v2}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/d;->isGeofenceMessagingEnabled()Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-eqz v0, :cond_1

    .line 17
    .line 18
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 19
    .line 20
    if-eqz v0, :cond_0

    .line 21
    .line 22
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    const-string v2, "et_geo_enabled_key"

    .line 31
    .line 32
    invoke-interface {v0, v2, v1}, Landroid/content/SharedPreferences$Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 37
    .line 38
    .line 39
    goto :goto_0

    .line 40
    :catchall_0
    move-exception v0

    .line 41
    goto :goto_1

    .line 42
    :cond_0
    :goto_0
    sget-object v0, Lcom/salesforce/marketingcloud/toggles/a;->d:Lcom/salesforce/marketingcloud/toggles/a;

    .line 43
    .line 44
    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->u:Lcom/salesforce/marketingcloud/toggles/a;

    .line 45
    .line 46
    new-instance v0, Landroid/os/Bundle;

    .line 47
    .line 48
    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 49
    .line 50
    .line 51
    const-string v2, "com.salesforce.marketingcloud.messaging.ENABLED"

    .line 52
    .line 53
    invoke-virtual {v0, v2, v1}, Landroid/os/BaseBundle;->putBoolean(Ljava/lang/String;Z)V

    .line 54
    .line 55
    .line 56
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/d;->j:Landroid/content/Context;

    .line 57
    .line 58
    sget-object v2, Lcom/salesforce/marketingcloud/behaviors/a;->m:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 59
    .line 60
    invoke-static {v1, v2, v0}, Lcom/salesforce/marketingcloud/behaviors/c;->a(Landroid/content/Context;Lcom/salesforce/marketingcloud/behaviors/a;Landroid/os/Bundle;)V

    .line 61
    .line 62
    .line 63
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->s:Lcom/salesforce/marketingcloud/messages/geofence/a;

    .line 64
    .line 65
    if-eqz v0, :cond_1

    .line 66
    .line 67
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/geofence/a;->b()V

    .line 68
    .line 69
    .line 70
    :cond_1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/d;->a()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 71
    .line 72
    .line 73
    monitor-exit p0

    .line 74
    return-void

    .line 75
    :goto_1
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 76
    throw v0
.end method

.method public final declared-synchronized disableProximityMessaging()V
    .locals 4

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    sget-object v0, Lcom/salesforce/marketingcloud/messages/d;->B:Ljava/lang/String;

    .line 3
    .line 4
    const/4 v1, 0x0

    .line 5
    new-array v2, v1, [Ljava/lang/Object;

    .line 6
    .line 7
    const-string v3, "Disabling proximity messaging"

    .line 8
    .line 9
    invoke-static {v0, v3, v2}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/d;->isProximityMessagingEnabled()Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-eqz v0, :cond_1

    .line 17
    .line 18
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 19
    .line 20
    if-eqz v0, :cond_0

    .line 21
    .line 22
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    const-string v2, "et_proximity_enabled_key"

    .line 31
    .line 32
    invoke-interface {v0, v2, v1}, Landroid/content/SharedPreferences$Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 37
    .line 38
    .line 39
    goto :goto_0

    .line 40
    :catchall_0
    move-exception v0

    .line 41
    goto :goto_1

    .line 42
    :cond_0
    :goto_0
    sget-object v0, Lcom/salesforce/marketingcloud/toggles/a;->d:Lcom/salesforce/marketingcloud/toggles/a;

    .line 43
    .line 44
    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->v:Lcom/salesforce/marketingcloud/toggles/a;

    .line 45
    .line 46
    new-instance v0, Landroid/os/Bundle;

    .line 47
    .line 48
    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 49
    .line 50
    .line 51
    const-string v2, "com.salesforce.marketingcloud.messaging.ENABLED"

    .line 52
    .line 53
    invoke-virtual {v0, v2, v1}, Landroid/os/BaseBundle;->putBoolean(Ljava/lang/String;Z)V

    .line 54
    .line 55
    .line 56
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/d;->j:Landroid/content/Context;

    .line 57
    .line 58
    sget-object v2, Lcom/salesforce/marketingcloud/behaviors/a;->n:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 59
    .line 60
    invoke-static {v1, v2, v0}, Lcom/salesforce/marketingcloud/behaviors/c;->a(Landroid/content/Context;Lcom/salesforce/marketingcloud/behaviors/a;Landroid/os/Bundle;)V

    .line 61
    .line 62
    .line 63
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->t:Lcom/salesforce/marketingcloud/messages/proximity/a;

    .line 64
    .line 65
    if-eqz v0, :cond_1

    .line 66
    .line 67
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/proximity/a;->b()V

    .line 68
    .line 69
    .line 70
    :cond_1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/d;->a()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 71
    .line 72
    .line 73
    monitor-exit p0

    .line 74
    return-void

    .line 75
    :goto_1
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 76
    throw v0
.end method

.method public final declared-synchronized enableGeofenceMessaging()Z
    .locals 1
    .annotation build Landroid/annotation/SuppressLint;
        value = {
            "MissingPermission"
        }
    .end annotation

    .line 1
    monitor-enter p0

    .line 2
    const/4 v0, 0x0

    .line 3
    :try_start_0
    invoke-direct {p0, v0}, Lcom/salesforce/marketingcloud/messages/d;->c(Z)Z

    .line 4
    .line 5
    .line 6
    move-result v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 7
    monitor-exit p0

    .line 8
    return v0

    .line 9
    :catchall_0
    move-exception v0

    .line 10
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 11
    throw v0
.end method

.method public final declared-synchronized enableProximityMessaging()Z
    .locals 1
    .annotation build Landroid/annotation/SuppressLint;
        value = {
            "MissingPermission"
        }
    .end annotation

    .line 1
    monitor-enter p0

    .line 2
    const/4 v0, 0x0

    .line 3
    :try_start_0
    invoke-direct {p0, v0}, Lcom/salesforce/marketingcloud/messages/d;->d(Z)Z

    .line 4
    .line 5
    .line 6
    move-result v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 7
    monitor-exit p0

    .line 8
    return v0

    .line 9
    :catchall_0
    move-exception v0

    .line 10
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 11
    throw v0
.end method

.method public final declared-synchronized init(Lcom/salesforce/marketingcloud/InitializationStatus$a;I)V
    .locals 3

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    invoke-direct {p0, p1, p2}, Lcom/salesforce/marketingcloud/messages/d;->a(Lcom/salesforce/marketingcloud/InitializationStatus$a;I)V

    .line 3
    .line 4
    .line 5
    invoke-direct {p0, p1, p2}, Lcom/salesforce/marketingcloud/messages/d;->b(Lcom/salesforce/marketingcloud/InitializationStatus$a;I)V

    .line 6
    .line 7
    .line 8
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/d;->s:Lcom/salesforce/marketingcloud/messages/geofence/a;

    .line 9
    .line 10
    if-nez p1, :cond_0

    .line 11
    .line 12
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/d;->t:Lcom/salesforce/marketingcloud/messages/proximity/a;

    .line 13
    .line 14
    if-eqz p1, :cond_1

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :catchall_0
    move-exception p1

    .line 18
    goto :goto_1

    .line 19
    :cond_0
    :goto_0
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/d;->l:Lcom/salesforce/marketingcloud/behaviors/c;

    .line 20
    .line 21
    sget-object p2, Lcom/salesforce/marketingcloud/behaviors/a;->f:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 22
    .line 23
    sget-object v0, Lcom/salesforce/marketingcloud/behaviors/a;->h:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 24
    .line 25
    sget-object v1, Lcom/salesforce/marketingcloud/behaviors/a;->e:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 26
    .line 27
    sget-object v2, Lcom/salesforce/marketingcloud/behaviors/a;->i:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 28
    .line 29
    invoke-static {p2, v0, v1, v2}, Ljava/util/EnumSet;->of(Ljava/lang/Enum;Ljava/lang/Enum;Ljava/lang/Enum;Ljava/lang/Enum;)Ljava/util/EnumSet;

    .line 30
    .line 31
    .line 32
    move-result-object p2

    .line 33
    invoke-virtual {p1, p0, p2}, Lcom/salesforce/marketingcloud/behaviors/c;->a(Lcom/salesforce/marketingcloud/behaviors/b;Ljava/util/EnumSet;)V

    .line 34
    .line 35
    .line 36
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/d;->f:Lcom/salesforce/marketingcloud/location/f;

    .line 37
    .line 38
    invoke-virtual {p1, p0}, Lcom/salesforce/marketingcloud/location/f;->a(Lcom/salesforce/marketingcloud/location/c;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 39
    .line 40
    .line 41
    :cond_1
    monitor-exit p0

    .line 42
    return-void

    .line 43
    :goto_1
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 44
    throw p1
.end method

.method public final isGeofenceMessagingEnabled()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->j()Lcom/salesforce/marketingcloud/storage/d;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-static {v0}, Lcom/salesforce/marketingcloud/b;->a(Lcom/salesforce/marketingcloud/storage/d;)I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    const/16 v1, 0x20

    .line 12
    .line 13
    invoke-static {v0, v1}, Lcom/salesforce/marketingcloud/b;->a(II)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    const/4 v1, 0x0

    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    return v1

    .line 21
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->u:Lcom/salesforce/marketingcloud/toggles/a;

    .line 22
    .line 23
    if-nez v0, :cond_1

    .line 24
    .line 25
    const-string v0, "et_geo_enabled_key"

    .line 26
    .line 27
    const/4 v2, 0x0

    .line 28
    invoke-direct {p0, v0, v2}, Lcom/salesforce/marketingcloud/messages/d;->a(Ljava/lang/String;Lcom/salesforce/marketingcloud/toggles/a;)Lcom/salesforce/marketingcloud/toggles/a;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->u:Lcom/salesforce/marketingcloud/toggles/a;

    .line 33
    .line 34
    :cond_1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->u:Lcom/salesforce/marketingcloud/toggles/a;

    .line 35
    .line 36
    sget-object v2, Lcom/salesforce/marketingcloud/toggles/a;->c:Lcom/salesforce/marketingcloud/toggles/a;

    .line 37
    .line 38
    if-eq v0, v2, :cond_3

    .line 39
    .line 40
    sget-object v2, Lcom/salesforce/marketingcloud/toggles/a;->b:Lcom/salesforce/marketingcloud/toggles/a;

    .line 41
    .line 42
    if-ne v0, v2, :cond_2

    .line 43
    .line 44
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/d;->h:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 45
    .line 46
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->geofencingEnabled()Z

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    if-eqz p0, :cond_2

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_2
    return v1

    .line 54
    :cond_3
    :goto_0
    const/4 p0, 0x1

    .line 55
    return p0
.end method

.method public final isProximityMessagingEnabled()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->j()Lcom/salesforce/marketingcloud/storage/d;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-static {v0}, Lcom/salesforce/marketingcloud/b;->a(Lcom/salesforce/marketingcloud/storage/d;)I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    const/16 v1, 0x40

    .line 12
    .line 13
    invoke-static {v0, v1}, Lcom/salesforce/marketingcloud/b;->a(II)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    const/4 v1, 0x0

    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    return v1

    .line 21
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->v:Lcom/salesforce/marketingcloud/toggles/a;

    .line 22
    .line 23
    if-nez v0, :cond_1

    .line 24
    .line 25
    const-string v0, "et_proximity_enabled_key"

    .line 26
    .line 27
    const/4 v2, 0x0

    .line 28
    invoke-direct {p0, v0, v2}, Lcom/salesforce/marketingcloud/messages/d;->a(Ljava/lang/String;Lcom/salesforce/marketingcloud/toggles/a;)Lcom/salesforce/marketingcloud/toggles/a;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->v:Lcom/salesforce/marketingcloud/toggles/a;

    .line 33
    .line 34
    :cond_1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->v:Lcom/salesforce/marketingcloud/toggles/a;

    .line 35
    .line 36
    sget-object v2, Lcom/salesforce/marketingcloud/toggles/a;->c:Lcom/salesforce/marketingcloud/toggles/a;

    .line 37
    .line 38
    if-eq v0, v2, :cond_3

    .line 39
    .line 40
    sget-object v2, Lcom/salesforce/marketingcloud/toggles/a;->b:Lcom/salesforce/marketingcloud/toggles/a;

    .line 41
    .line 42
    if-ne v0, v2, :cond_2

    .line 43
    .line 44
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/d;->h:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 45
    .line 46
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->proximityEnabled()Z

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    if-eqz p0, :cond_2

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_2
    return v1

    .line 54
    :cond_3
    :goto_0
    const/4 p0, 0x1

    .line 55
    return p0
.end method

.method public final onBehavior(Lcom/salesforce/marketingcloud/behaviors/a;Landroid/os/Bundle;)V
    .locals 1

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    goto :goto_0

    .line 4
    :cond_0
    sget-object p2, Lcom/salesforce/marketingcloud/messages/d$g;->b:[I

    .line 5
    .line 6
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    aget p1, p2, p1

    .line 11
    .line 12
    const/4 p2, 0x1

    .line 13
    if-eq p1, p2, :cond_5

    .line 14
    .line 15
    const/4 p2, 0x2

    .line 16
    if-eq p1, p2, :cond_6

    .line 17
    .line 18
    const/4 p2, 0x3

    .line 19
    if-eq p1, p2, :cond_4

    .line 20
    .line 21
    const/4 p2, 0x4

    .line 22
    if-eq p1, p2, :cond_1

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/d;->i()V

    .line 26
    .line 27
    .line 28
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/d;->j()V

    .line 29
    .line 30
    .line 31
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/d;->isGeofenceMessagingEnabled()Z

    .line 32
    .line 33
    .line 34
    move-result p1

    .line 35
    if-nez p1, :cond_3

    .line 36
    .line 37
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/d;->isProximityMessagingEnabled()Z

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    if-eqz p1, :cond_2

    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_2
    :goto_0
    return-void

    .line 45
    :cond_3
    :goto_1
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/d;->e:Lcom/salesforce/marketingcloud/alarms/b;

    .line 46
    .line 47
    sget-object p2, Lcom/salesforce/marketingcloud/alarms/a$a;->e:Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 48
    .line 49
    filled-new-array {p2}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    invoke-virtual {p1, v0}, Lcom/salesforce/marketingcloud/alarms/b;->d([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 54
    .line 55
    .line 56
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/d;->e:Lcom/salesforce/marketingcloud/alarms/b;

    .line 57
    .line 58
    filled-new-array {p2}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/alarms/b;->b([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 63
    .line 64
    .line 65
    return-void

    .line 66
    :cond_4
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/d;->h()V

    .line 67
    .line 68
    .line 69
    return-void

    .line 70
    :cond_5
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/d;->h()V

    .line 71
    .line 72
    .line 73
    :cond_6
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/d;->g()V

    .line 74
    .line 75
    .line 76
    return-void
.end method

.method public final registerGeofenceMessageResponseListener(Lcom/salesforce/marketingcloud/messages/RegionMessageManager$GeofenceMessageResponseListener;)V
    .locals 1

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->n:Ljava/util/Set;

    .line 4
    .line 5
    monitor-enter v0

    .line 6
    :try_start_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/d;->n:Ljava/util/Set;

    .line 7
    .line 8
    invoke-interface {p0, p1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    monitor-exit v0

    .line 12
    return-void

    .line 13
    :catchall_0
    move-exception p0

    .line 14
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 15
    throw p0

    .line 16
    :cond_0
    return-void
.end method

.method public final registerProximityMessageResponseListener(Lcom/salesforce/marketingcloud/messages/RegionMessageManager$ProximityMessageResponseListener;)V
    .locals 1

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->o:Ljava/util/Set;

    .line 4
    .line 5
    monitor-enter v0

    .line 6
    :try_start_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/d;->o:Ljava/util/Set;

    .line 7
    .line 8
    invoke-interface {p0, p1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    monitor-exit v0

    .line 12
    return-void

    .line 13
    :catchall_0
    move-exception p0

    .line 14
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 15
    throw p0

    .line 16
    :cond_0
    return-void
.end method

.method public final registerRegionTransitionEventListener(Lcom/salesforce/marketingcloud/messages/RegionMessageManager$RegionTransitionEventListener;)V
    .locals 1

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->p:Ljava/util/Set;

    .line 4
    .line 5
    monitor-enter v0

    .line 6
    :try_start_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/d;->p:Ljava/util/Set;

    .line 7
    .line 8
    invoke-interface {p0, p1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    monitor-exit v0

    .line 12
    return-void

    .line 13
    :catchall_0
    move-exception p0

    .line 14
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 15
    throw p0

    .line 16
    :cond_0
    return-void
.end method

.method public tearDown(Z)V
    .locals 0

    .line 1
    return-void
.end method

.method public final unregisterGeofenceMessageResponseListener(Lcom/salesforce/marketingcloud/messages/RegionMessageManager$GeofenceMessageResponseListener;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->n:Ljava/util/Set;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/d;->n:Ljava/util/Set;

    .line 5
    .line 6
    invoke-interface {p0, p1}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z

    .line 7
    .line 8
    .line 9
    monitor-exit v0

    .line 10
    return-void

    .line 11
    :catchall_0
    move-exception p0

    .line 12
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 13
    throw p0
.end method

.method public final unregisterProximityMessageResponseListener(Lcom/salesforce/marketingcloud/messages/RegionMessageManager$ProximityMessageResponseListener;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->o:Ljava/util/Set;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/d;->o:Ljava/util/Set;

    .line 5
    .line 6
    invoke-interface {p0, p1}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z

    .line 7
    .line 8
    .line 9
    monitor-exit v0

    .line 10
    return-void

    .line 11
    :catchall_0
    move-exception p0

    .line 12
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 13
    throw p0
.end method

.method public final unregisterRegionTransitionEventListener(Lcom/salesforce/marketingcloud/messages/RegionMessageManager$RegionTransitionEventListener;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d;->p:Ljava/util/Set;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/d;->p:Ljava/util/Set;

    .line 5
    .line 6
    invoke-interface {p0, p1}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z

    .line 7
    .line 8
    .line 9
    monitor-exit v0

    .line 10
    return-void

    .line 11
    :catchall_0
    move-exception p0

    .line 12
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 13
    throw p0
.end method
