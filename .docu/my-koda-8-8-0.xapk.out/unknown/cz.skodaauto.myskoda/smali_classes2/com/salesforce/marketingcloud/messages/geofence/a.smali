.class public final Lcom/salesforce/marketingcloud/messages/geofence/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/messages/c;
.implements Lcom/salesforce/marketingcloud/location/c;
.implements Lcom/salesforce/marketingcloud/http/e$c;


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation


# static fields
.field static final k:Ljava/lang/String;


# instance fields
.field final d:Lcom/salesforce/marketingcloud/location/f;

.field final e:Lcom/salesforce/marketingcloud/storage/h;

.field final f:Lcom/salesforce/marketingcloud/messages/c$a;

.field final g:Lcom/salesforce/marketingcloud/http/e;

.field private final h:Lcom/salesforce/marketingcloud/internal/n;

.field i:Ljava/util/concurrent/atomic/AtomicBoolean;

.field private j:Lcom/salesforce/marketingcloud/messages/c$b;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "GeofenceMessageManager"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/messages/geofence/a;->k:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/location/f;Lcom/salesforce/marketingcloud/http/e;Lcom/salesforce/marketingcloud/internal/n;Lcom/salesforce/marketingcloud/messages/c$a;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/geofence/a;->i:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 11
    .line 12
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/geofence/a;->e:Lcom/salesforce/marketingcloud/storage/h;

    .line 13
    .line 14
    iput-object p2, p0, Lcom/salesforce/marketingcloud/messages/geofence/a;->d:Lcom/salesforce/marketingcloud/location/f;

    .line 15
    .line 16
    iput-object p3, p0, Lcom/salesforce/marketingcloud/messages/geofence/a;->g:Lcom/salesforce/marketingcloud/http/e;

    .line 17
    .line 18
    iput-object p5, p0, Lcom/salesforce/marketingcloud/messages/geofence/a;->f:Lcom/salesforce/marketingcloud/messages/c$a;

    .line 19
    .line 20
    iput-object p4, p0, Lcom/salesforce/marketingcloud/messages/geofence/a;->h:Lcom/salesforce/marketingcloud/internal/n;

    .line 21
    .line 22
    sget-object p1, Lcom/salesforce/marketingcloud/http/b;->n:Lcom/salesforce/marketingcloud/http/b;

    .line 23
    .line 24
    invoke-virtual {p3, p1, p0}, Lcom/salesforce/marketingcloud/http/e;->a(Lcom/salesforce/marketingcloud/http/b;Lcom/salesforce/marketingcloud/http/e$c;)V

    .line 25
    .line 26
    .line 27
    return-void
.end method

.method private static a(I)I
    .locals 1

    .line 1
    const/16 v0, 0x64

    if-ge p0, v0, :cond_0

    return v0

    :cond_0
    return p0
.end method

.method public static a(Lcom/salesforce/marketingcloud/messages/Region;)Lcom/salesforce/marketingcloud/location/b;
    .locals 8

    .line 10
    new-instance v0, Lcom/salesforce/marketingcloud/location/b;

    .line 11
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/Region;->id()Ljava/lang/String;

    move-result-object v1

    .line 12
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/Region;->radius()I

    move-result v2

    invoke-static {v2}, Lcom/salesforce/marketingcloud/messages/geofence/a;->a(I)I

    move-result v2

    int-to-float v2, v2

    .line 13
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/Region;->center()Lcom/salesforce/marketingcloud/location/LatLon;

    move-result-object v3

    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/location/LatLon;->latitude()D

    move-result-wide v3

    .line 14
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/Region;->center()Lcom/salesforce/marketingcloud/location/LatLon;

    move-result-object p0

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/location/LatLon;->longitude()D

    move-result-wide v5

    const/4 v7, 0x3

    invoke-direct/range {v0 .. v7}, Lcom/salesforce/marketingcloud/location/b;-><init>(Ljava/lang/String;FDDI)V

    return-object v0
.end method

.method public static a(Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/location/f;Lcom/salesforce/marketingcloud/http/e;Z)V
    .locals 3

    .line 2
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->o()Lcom/salesforce/marketingcloud/storage/j;

    move-result-object v0

    const/4 v1, 0x1

    invoke-interface {v0, v1}, Lcom/salesforce/marketingcloud/storage/j;->d(I)Ljava/util/List;

    move-result-object v0

    .line 3
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v2

    if-nez v2, :cond_0

    .line 4
    invoke-virtual {p1, v0}, Lcom/salesforce/marketingcloud/location/f;->a(Ljava/util/List;)V

    :cond_0
    if-eqz p3, :cond_1

    .line 5
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->o()Lcom/salesforce/marketingcloud/storage/j;

    move-result-object p1

    invoke-interface {p1, v1}, Lcom/salesforce/marketingcloud/storage/j;->f(I)I

    .line 6
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->n()Lcom/salesforce/marketingcloud/storage/i;

    move-result-object p0

    const/4 p1, 0x3

    .line 7
    invoke-interface {p0, p1}, Lcom/salesforce/marketingcloud/storage/i;->e(I)I

    const/4 p1, 0x4

    .line 8
    invoke-interface {p0, p1}, Lcom/salesforce/marketingcloud/storage/i;->e(I)I

    .line 9
    :cond_1
    sget-object p0, Lcom/salesforce/marketingcloud/http/b;->n:Lcom/salesforce/marketingcloud/http/b;

    invoke-virtual {p2, p0}, Lcom/salesforce/marketingcloud/http/e;->a(Lcom/salesforce/marketingcloud/http/b;)V

    return-void
.end method


# virtual methods
.method public a()V
    .locals 2

    .line 22
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/geofence/a;->d:Lcom/salesforce/marketingcloud/location/f;

    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/location/f;->a(Lcom/salesforce/marketingcloud/location/c;)V

    .line 23
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/geofence/a;->g:Lcom/salesforce/marketingcloud/http/e;

    sget-object v1, Lcom/salesforce/marketingcloud/http/b;->n:Lcom/salesforce/marketingcloud/http/b;

    invoke-virtual {v0, v1, p0}, Lcom/salesforce/marketingcloud/http/e;->a(Lcom/salesforce/marketingcloud/http/b;Lcom/salesforce/marketingcloud/http/e$c;)V

    return-void
.end method

.method public a(ILjava/lang/String;)V
    .locals 0

    .line 21
    sget-object p0, Lcom/salesforce/marketingcloud/messages/geofence/a;->k:Ljava/lang/String;

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    filled-new-array {p1, p2}, [Ljava/lang/Object;

    move-result-object p1

    const-string p2, "Region error %d - %s"

    invoke-static {p0, p2, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/http/c;Lcom/salesforce/marketingcloud/http/f;)V
    .locals 1

    .line 24
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->p()Z

    move-result p1

    if-eqz p1, :cond_0

    .line 25
    :try_start_0
    new-instance p1, Lcom/salesforce/marketingcloud/messages/geofence/GeofenceMessageResponse;

    new-instance v0, Lorg/json/JSONObject;

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->j()Ljava/lang/String;

    move-result-object p2

    invoke-direct {v0, p2}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V

    invoke-direct {p1, v0}, Lcom/salesforce/marketingcloud/messages/geofence/GeofenceMessageResponse;-><init>(Lorg/json/JSONObject;)V

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/messages/geofence/a;->a(Lcom/salesforce/marketingcloud/messages/geofence/GeofenceMessageResponse;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception p0

    .line 26
    sget-object p1, Lcom/salesforce/marketingcloud/messages/geofence/a;->k:Ljava/lang/String;

    const/4 p2, 0x0

    new-array p2, p2, [Ljava/lang/Object;

    const-string v0, "Error parsing response."

    invoke-static {p1, p0, v0, p2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void

    .line 27
    :cond_0
    sget-object p0, Lcom/salesforce/marketingcloud/messages/geofence/a;->k:Ljava/lang/String;

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->k()I

    move-result p1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->n()Ljava/lang/String;

    move-result-object p2

    filled-new-array {p1, p2}, [Ljava/lang/Object;

    move-result-object p1

    const-string p2, "Request failed: %d - %s"

    invoke-static {p0, p2, p1}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/location/LatLon;Ljava/lang/String;Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/messages/c$b;)V
    .locals 0

    .line 15
    iput-object p4, p0, Lcom/salesforce/marketingcloud/messages/geofence/a;->j:Lcom/salesforce/marketingcloud/messages/c$b;

    .line 16
    :try_start_0
    new-instance p4, Lcom/salesforce/marketingcloud/messages/geofence/a$a;

    invoke-direct {p4, p0, p3, p2, p1}, Lcom/salesforce/marketingcloud/messages/geofence/a$a;-><init>(Lcom/salesforce/marketingcloud/messages/geofence/a;Lcom/salesforce/marketingcloud/MarketingCloudConfig;Ljava/lang/String;Lcom/salesforce/marketingcloud/location/LatLon;)V

    invoke-static {p4}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->requestSdk(Lcom/salesforce/marketingcloud/MarketingCloudSdk$WhenReadyListener;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception p0

    .line 17
    sget-object p1, Lcom/salesforce/marketingcloud/messages/geofence/a;->k:Ljava/lang/String;

    const/4 p2, 0x0

    new-array p2, p2, [Ljava/lang/Object;

    const-string p3, "Failed to update geofence messages"

    invoke-static {p1, p0, p3, p2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/messages/geofence/GeofenceMessageResponse;)V
    .locals 4

    .line 28
    sget-object v0, Lcom/salesforce/marketingcloud/messages/geofence/a;->k:Ljava/lang/String;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/geofence/GeofenceMessageResponse;->fences()Ljava/util/List;

    move-result-object v1

    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v1

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    const-string v2, "Geofence message request contained %d regions"

    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 29
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/geofence/a;->j:Lcom/salesforce/marketingcloud/messages/c$b;

    if-eqz v0, :cond_0

    .line 30
    invoke-interface {v0, p1}, Lcom/salesforce/marketingcloud/messages/c$b;->a(Lcom/salesforce/marketingcloud/messages/MessageResponse;)V

    .line 31
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/geofence/a;->h:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v0

    new-instance v1, Lcom/salesforce/marketingcloud/messages/geofence/a$d;

    const/4 v2, 0x0

    new-array v2, v2, [Ljava/lang/Object;

    const-string v3, "fence_response"

    invoke-direct {v1, p0, v3, v2, p1}, Lcom/salesforce/marketingcloud/messages/geofence/a$d;-><init>(Lcom/salesforce/marketingcloud/messages/geofence/a;Ljava/lang/String;[Ljava/lang/Object;Lcom/salesforce/marketingcloud/messages/geofence/GeofenceMessageResponse;)V

    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    return-void
.end method

.method public a(Ljava/lang/String;ILandroid/location/Location;)V
    .locals 6

    .line 18
    sget-object p3, Lcom/salesforce/marketingcloud/messages/geofence/a;->k:Ljava/lang/String;

    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    filled-new-array {p1, v0}, [Ljava/lang/Object;

    move-result-object v0

    const-string v1, "Geofence (%s - %s) was tripped."

    invoke-static {p3, v1, v0}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    const/4 v0, 0x4

    if-ne p2, v0, :cond_0

    .line 19
    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p0

    const-string p1, "Dwell transition ignore for %s"

    invoke-static {p3, p1, p0}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void

    .line 20
    :cond_0
    iget-object p3, p0, Lcom/salesforce/marketingcloud/messages/geofence/a;->h:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {p3}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object p3

    new-instance v0, Lcom/salesforce/marketingcloud/messages/geofence/a$b;

    const/4 v1, 0x0

    new-array v3, v1, [Ljava/lang/Object;

    const-string v2, "fence_event"

    move-object v1, p0

    move-object v4, p1

    move v5, p2

    invoke-direct/range {v0 .. v5}, Lcom/salesforce/marketingcloud/messages/geofence/a$b;-><init>(Lcom/salesforce/marketingcloud/messages/geofence/a;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/String;I)V

    invoke-interface {p3, v0}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    return-void
.end method

.method public b()V
    .locals 5

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/geofence/a;->d:Lcom/salesforce/marketingcloud/location/f;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/location/f;->b(Lcom/salesforce/marketingcloud/location/c;)V

    .line 7
    .line 8
    .line 9
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/geofence/a;->e:Lcom/salesforce/marketingcloud/storage/h;

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/geofence/a;->h:Lcom/salesforce/marketingcloud/internal/n;

    .line 14
    .line 15
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    new-instance v2, Lcom/salesforce/marketingcloud/messages/geofence/a$c;

    .line 20
    .line 21
    new-array v3, v1, [Ljava/lang/Object;

    .line 22
    .line 23
    const-string v4, "disable_fence_tracking"

    .line 24
    .line 25
    invoke-direct {v2, p0, v4, v3}, Lcom/salesforce/marketingcloud/messages/geofence/a$c;-><init>(Lcom/salesforce/marketingcloud/messages/geofence/a;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    invoke-interface {v0, v2}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 29
    .line 30
    .line 31
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/geofence/a;->g:Lcom/salesforce/marketingcloud/http/e;

    .line 32
    .line 33
    sget-object v2, Lcom/salesforce/marketingcloud/http/b;->n:Lcom/salesforce/marketingcloud/http/b;

    .line 34
    .line 35
    invoke-virtual {v0, v2}, Lcom/salesforce/marketingcloud/http/e;->a(Lcom/salesforce/marketingcloud/http/b;)V

    .line 36
    .line 37
    .line 38
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/geofence/a;->i:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 39
    .line 40
    invoke-virtual {p0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 41
    .line 42
    .line 43
    return-void
.end method

.method public c()V
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/geofence/a;->h:Lcom/salesforce/marketingcloud/internal/n;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    new-instance v1, Lcom/salesforce/marketingcloud/messages/geofence/a$e;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    new-array v2, v2, [Ljava/lang/Object;

    .line 11
    .line 12
    const-string v3, "monitor_stored_regions"

    .line 13
    .line 14
    invoke-direct {v1, p0, v3, v2}, Lcom/salesforce/marketingcloud/messages/geofence/a$e;-><init>(Lcom/salesforce/marketingcloud/messages/geofence/a;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public d()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/geofence/a;->d:Lcom/salesforce/marketingcloud/location/f;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/location/f;->a()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method
