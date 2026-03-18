.class Lcom/salesforce/marketingcloud/location/h;
.super Lcom/salesforce/marketingcloud/location/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/location/h$a;
    }
.end annotation


# instance fields
.field final q:Lcom/salesforce/marketingcloud/location/d;

.field final r:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Lcom/salesforce/marketingcloud/location/e;",
            ">;"
        }
    .end annotation
.end field

.field private final s:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Lcom/salesforce/marketingcloud/location/c;",
            ">;"
        }
    .end annotation
.end field

.field private t:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

.field private u:I

.field private v:I

.field private w:Ljava/lang/String;

.field private x:I

.field private y:Landroid/content/Context;

.field private z:Landroid/content/BroadcastReceiver;


# direct methods
.method public constructor <init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/MarketingCloudConfig;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/location/f;-><init>()V

    .line 2
    new-instance v0, Landroidx/collection/g;

    const/4 v1, 0x0

    .line 3
    invoke-direct {v0, v1}, Landroidx/collection/g;-><init>(Ljava/lang/Object;)V

    .line 4
    iput-object v0, p0, Lcom/salesforce/marketingcloud/location/h;->r:Ljava/util/Set;

    .line 5
    new-instance v0, Landroidx/collection/g;

    .line 6
    invoke-direct {v0, v1}, Landroidx/collection/g;-><init>(Ljava/lang/Object;)V

    .line 7
    iput-object v0, p0, Lcom/salesforce/marketingcloud/location/h;->s:Ljava/util/Set;

    .line 8
    iput-object p1, p0, Lcom/salesforce/marketingcloud/location/h;->y:Landroid/content/Context;

    .line 9
    new-instance v0, Lcom/salesforce/marketingcloud/location/d;

    invoke-direct {v0, p1}, Lcom/salesforce/marketingcloud/location/d;-><init>(Landroid/content/Context;)V

    iput-object v0, p0, Lcom/salesforce/marketingcloud/location/h;->q:Lcom/salesforce/marketingcloud/location/d;

    .line 10
    iput-object p2, p0, Lcom/salesforce/marketingcloud/location/h;->t:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/location/d;)V
    .locals 2

    .line 11
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/location/f;-><init>()V

    .line 12
    new-instance v0, Landroidx/collection/g;

    const/4 v1, 0x0

    .line 13
    invoke-direct {v0, v1}, Landroidx/collection/g;-><init>(Ljava/lang/Object;)V

    .line 14
    iput-object v0, p0, Lcom/salesforce/marketingcloud/location/h;->r:Ljava/util/Set;

    .line 15
    new-instance v0, Landroidx/collection/g;

    .line 16
    invoke-direct {v0, v1}, Landroidx/collection/g;-><init>(Ljava/lang/Object;)V

    .line 17
    iput-object v0, p0, Lcom/salesforce/marketingcloud/location/h;->s:Ljava/util/Set;

    .line 18
    iput-object p1, p0, Lcom/salesforce/marketingcloud/location/h;->y:Landroid/content/Context;

    .line 19
    iput-object p2, p0, Lcom/salesforce/marketingcloud/location/h;->q:Lcom/salesforce/marketingcloud/location/d;

    return-void
.end method


# virtual methods
.method public a(Lcom/salesforce/marketingcloud/InitializationStatus$a;)V
    .locals 4

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/location/h$a;

    invoke-direct {v0, p0}, Lcom/salesforce/marketingcloud/location/h$a;-><init>(Lcom/salesforce/marketingcloud/location/h;)V

    iput-object v0, p0, Lcom/salesforce/marketingcloud/location/h;->z:Landroid/content/BroadcastReceiver;

    .line 2
    new-instance v0, Landroid/content/IntentFilter;

    invoke-direct {v0}, Landroid/content/IntentFilter;-><init>()V

    .line 3
    const-string v1, "com.salesforce.marketingcloud.location.LOCATION_UPDATE"

    invoke-virtual {v0, v1}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V

    .line 4
    const-string v1, "com.salesforce.marketingcloud.location.GEOFENCE_EVENT"

    invoke-virtual {v0, v1}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V

    .line 5
    const-string v1, "com.salesforce.marketingcloud.location.GEOFENCE_ERROR"

    invoke-virtual {v0, v1}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V

    .line 6
    iget-object v1, p0, Lcom/salesforce/marketingcloud/location/h;->y:Landroid/content/Context;

    iget-object v2, p0, Lcom/salesforce/marketingcloud/location/h;->z:Landroid/content/BroadcastReceiver;

    const/4 v3, 0x4

    invoke-static {v1, v2, v0, v3}, Ln5/a;->d(Landroid/content/Context;Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;I)V

    .line 7
    iget-object v0, p0, Lcom/salesforce/marketingcloud/location/h;->q:Lcom/salesforce/marketingcloud/location/d;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/location/d;->c()I

    move-result v0

    invoke-virtual {p1, v0}, Lcom/salesforce/marketingcloud/InitializationStatus$a;->a(I)V

    .line 8
    iget-object v0, p0, Lcom/salesforce/marketingcloud/location/h;->q:Lcom/salesforce/marketingcloud/location/d;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/location/d;->b()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1, v0}, Lcom/salesforce/marketingcloud/InitializationStatus$a;->a(Ljava/lang/String;)V

    .line 9
    iget-object p0, p0, Lcom/salesforce/marketingcloud/location/h;->q:Lcom/salesforce/marketingcloud/location/d;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/location/d;->d()Z

    move-result p0

    xor-int/lit8 p0, p0, 0x1

    invoke-virtual {p1, p0}, Lcom/salesforce/marketingcloud/InitializationStatus$a;->b(Z)V

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/location/c;)V
    .locals 3

    .line 25
    sget-object v0, Lcom/salesforce/marketingcloud/location/f;->p:Ljava/lang/String;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v1

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    const-string v2, "registerForGeofenceRegionEvents(%s)"

    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 26
    iget-object v0, p0, Lcom/salesforce/marketingcloud/location/h;->s:Ljava/util/Set;

    monitor-enter v0

    .line 27
    :try_start_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/location/h;->s:Ljava/util/Set;

    invoke-interface {p0, p1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 28
    monitor-exit v0

    return-void

    :catchall_0
    move-exception p0

    .line 29
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0
.end method

.method public a(Lcom/salesforce/marketingcloud/location/e;)V
    .locals 3
    .annotation build Landroid/annotation/SuppressLint;
        value = {
            "MissingPermission"
        }
    .end annotation

    if-nez p1, :cond_0

    goto :goto_1

    .line 11
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/location/h;->r:Ljava/util/Set;

    monitor-enter v0

    .line 12
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/location/h;->r:Ljava/util/Set;

    invoke-interface {v1, p1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    move-result v1

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    iget-object v1, p0, Lcom/salesforce/marketingcloud/location/h;->r:Ljava/util/Set;

    invoke-interface {v1}, Ljava/util/Set;->size()I

    move-result v1

    if-ne v1, v2, :cond_1

    move v1, v2

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_2

    :cond_1
    const/4 v1, 0x0

    .line 13
    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-eqz v1, :cond_2

    .line 14
    iget v0, p0, Lcom/salesforce/marketingcloud/location/h;->u:I

    add-int/2addr v0, v2

    iput v0, p0, Lcom/salesforce/marketingcloud/location/h;->u:I

    .line 15
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p1

    iput-object p1, p0, Lcom/salesforce/marketingcloud/location/h;->w:Ljava/lang/String;

    .line 16
    iget-object p0, p0, Lcom/salesforce/marketingcloud/location/h;->q:Lcom/salesforce/marketingcloud/location/d;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/location/d;->e()V

    :cond_2
    :goto_1
    return-void

    .line 17
    :goto_2
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw p0
.end method

.method public a(Ljava/util/List;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    if-eqz p1, :cond_1

    .line 22
    invoke-interface {p1}, Ljava/util/List;->size()I

    move-result v0

    if-nez v0, :cond_0

    goto :goto_0

    .line 23
    :cond_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/location/h;->q:Lcom/salesforce/marketingcloud/location/d;

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/location/d;->a(Ljava/util/List;)V

    return-void

    .line 24
    :cond_1
    :goto_0
    sget-object p0, Lcom/salesforce/marketingcloud/location/f;->p:Ljava/lang/String;

    const/4 p1, 0x0

    new-array p1, p1, [Ljava/lang/Object;

    const-string v0, "unmonitorGeofences - No geofenceRegionIds provided."

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public varargs a([Lcom/salesforce/marketingcloud/location/b;)V
    .locals 3

    if-eqz p1, :cond_1

    .line 18
    array-length v0, p1

    if-nez v0, :cond_0

    goto :goto_0

    .line 19
    :cond_0
    sget-object v0, Lcom/salesforce/marketingcloud/location/f;->p:Ljava/lang/String;

    array-length v1, p1

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    const-string v2, "Monitoring %s fence(s)."

    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 20
    iget-object p0, p0, Lcom/salesforce/marketingcloud/location/h;->q:Lcom/salesforce/marketingcloud/location/d;

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/location/d;->a([Lcom/salesforce/marketingcloud/location/b;)V

    return-void

    .line 21
    :cond_1
    :goto_0
    sget-object p0, Lcom/salesforce/marketingcloud/location/f;->p:Ljava/lang/String;

    const/4 p1, 0x0

    new-array p1, p1, [Ljava/lang/Object;

    const-string v0, "monitorGeofences - No geofenceRegions provided."

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public a()Z
    .locals 0

    .line 10
    iget-object p0, p0, Lcom/salesforce/marketingcloud/location/h;->q:Lcom/salesforce/marketingcloud/location/d;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/location/d;->d()Z

    move-result p0

    return p0
.end method

.method public b()V
    .locals 0

    .line 5
    iget-object p0, p0, Lcom/salesforce/marketingcloud/location/h;->q:Lcom/salesforce/marketingcloud/location/d;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/location/d;->a()V

    return-void
.end method

.method public b(ILjava/lang/String;)V
    .locals 2

    .line 32
    iget-object v0, p0, Lcom/salesforce/marketingcloud/location/h;->s:Ljava/util/Set;

    monitor-enter v0

    .line 33
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/location/h;->s:Ljava/util/Set;

    invoke-interface {v1}, Ljava/util/Set;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_1

    .line 34
    iget-object p0, p0, Lcom/salesforce/marketingcloud/location/h;->s:Ljava/util/Set;

    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lcom/salesforce/marketingcloud/location/c;

    if-eqz v1, :cond_0

    .line 35
    invoke-interface {v1, p1, p2}, Lcom/salesforce/marketingcloud/location/c;->a(ILjava/lang/String;)V

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    .line 36
    :cond_1
    monitor-exit v0

    return-void

    .line 37
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0
.end method

.method public b(ILjava/util/List;Landroid/location/Location;)V
    .locals 8
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(I",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;",
            "Landroid/location/Location;",
            ")V"
        }
    .end annotation

    .line 17
    sget-object v0, Lcom/salesforce/marketingcloud/location/f;->p:Ljava/lang/String;

    const/4 v1, 0x0

    new-array v2, v1, [Ljava/lang/Object;

    const-string v3, "onGeofenceRegionEvent"

    invoke-static {v0, v3, v2}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    if-eqz p2, :cond_4

    .line 18
    invoke-interface {p2}, Ljava/util/List;->isEmpty()Z

    move-result v2

    if-eqz v2, :cond_0

    goto :goto_2

    .line 19
    :cond_0
    iget v2, p0, Lcom/salesforce/marketingcloud/location/h;->x:I

    add-int/lit8 v2, v2, 0x1

    iput v2, p0, Lcom/salesforce/marketingcloud/location/h;->x:I

    .line 20
    iget-object v2, p0, Lcom/salesforce/marketingcloud/location/h;->s:Ljava/util/Set;

    monitor-enter v2

    .line 21
    :try_start_0
    iget-object v3, p0, Lcom/salesforce/marketingcloud/location/h;->s:Ljava/util/Set;

    invoke-interface {v3}, Ljava/util/Set;->isEmpty()Z

    move-result v3

    if-nez v3, :cond_2

    .line 22
    iget-object p0, p0, Lcom/salesforce/marketingcloud/location/h;->s:Ljava/util/Set;

    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :cond_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_3

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lcom/salesforce/marketingcloud/location/c;

    if-eqz v0, :cond_1

    .line 23
    invoke-interface {p2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_1

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/String;

    .line 24
    sget-object v4, Lcom/salesforce/marketingcloud/location/f;->p:Ljava/lang/String;

    const-string v5, "Notifiying %s of geofence [%s] region event [d]"

    .line 25
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v6

    invoke-virtual {v6}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v6

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    filled-new-array {v6, v3, v7}, [Ljava/lang/Object;

    move-result-object v6

    .line 26
    invoke-static {v4, v5, v6}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 27
    invoke-interface {v0, v3, p1, p3}, Lcom/salesforce/marketingcloud/location/c;->a(Ljava/lang/String;ILandroid/location/Location;)V

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    .line 28
    :cond_2
    const-string p0, "Geofence region event occured with no one listening."

    new-array p1, v1, [Ljava/lang/Object;

    invoke-static {v0, p0, p1}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 29
    :cond_3
    monitor-exit v2

    return-void

    .line 30
    :goto_1
    monitor-exit v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0

    .line 31
    :cond_4
    :goto_2
    new-array p0, v1, [Ljava/lang/Object;

    const-string p1, "No fenceIds were provided."

    invoke-static {v0, p1, p0}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public b(Landroid/location/Location;)V
    .locals 3

    if-nez p1, :cond_0

    return-void

    .line 9
    :cond_0
    iget v0, p0, Lcom/salesforce/marketingcloud/location/h;->v:I

    add-int/lit8 v0, v0, 0x1

    iput v0, p0, Lcom/salesforce/marketingcloud/location/h;->v:I

    .line 10
    iget-object v0, p0, Lcom/salesforce/marketingcloud/location/h;->r:Ljava/util/Set;

    monitor-enter v0

    .line 11
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/location/h;->r:Ljava/util/Set;

    invoke-interface {v1}, Ljava/util/Set;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_3

    .line 12
    iget-object v1, p0, Lcom/salesforce/marketingcloud/location/h;->r:Ljava/util/Set;

    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_1
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_2

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Lcom/salesforce/marketingcloud/location/e;

    if-eqz v2, :cond_1

    .line 13
    invoke-interface {v2, p1}, Lcom/salesforce/marketingcloud/location/e;->a(Landroid/location/Location;)V

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    .line 14
    :cond_2
    iget-object p0, p0, Lcom/salesforce/marketingcloud/location/h;->r:Ljava/util/Set;

    invoke-interface {p0}, Ljava/util/Set;->clear()V

    .line 15
    :cond_3
    monitor-exit v0

    return-void

    .line 16
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0
.end method

.method public b(Lcom/salesforce/marketingcloud/location/c;)V
    .locals 1

    if-eqz p1, :cond_0

    .line 6
    iget-object v0, p0, Lcom/salesforce/marketingcloud/location/h;->s:Ljava/util/Set;

    monitor-enter v0

    .line 7
    :try_start_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/location/h;->s:Ljava/util/Set;

    invoke-interface {p0, p1}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z

    .line 8
    monitor-exit v0

    return-void

    :catchall_0
    move-exception p0

    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0

    :cond_0
    return-void
.end method

.method public b(Lcom/salesforce/marketingcloud/location/e;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/location/h;->r:Ljava/util/Set;

    monitor-enter v0

    .line 2
    :try_start_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/location/h;->r:Ljava/util/Set;

    invoke-interface {p0, p1}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z

    .line 3
    monitor-exit v0

    return-void

    :catchall_0
    move-exception p0

    .line 4
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0
.end method

.method public componentState()Lorg/json/JSONObject;
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/location/h;->t:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 2
    .line 3
    iget-object v1, p0, Lcom/salesforce/marketingcloud/location/h;->q:Lcom/salesforce/marketingcloud/location/d;

    .line 4
    .line 5
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/location/d;->c()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    iget-object v2, p0, Lcom/salesforce/marketingcloud/location/h;->q:Lcom/salesforce/marketingcloud/location/d;

    .line 10
    .line 11
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/location/d;->b()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    invoke-static {v0, v1, v2}, Lcom/salesforce/marketingcloud/location/f;->a(Lcom/salesforce/marketingcloud/MarketingCloudConfig;ILjava/lang/String;)Lorg/json/JSONObject;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    :try_start_0
    const-string v1, "locationRequests"

    .line 20
    .line 21
    iget v2, p0, Lcom/salesforce/marketingcloud/location/h;->u:I

    .line 22
    .line 23
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;I)Lorg/json/JSONObject;

    .line 24
    .line 25
    .line 26
    const-string v1, "locationsReceived"

    .line 27
    .line 28
    iget v2, p0, Lcom/salesforce/marketingcloud/location/h;->v:I

    .line 29
    .line 30
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;I)Lorg/json/JSONObject;

    .line 31
    .line 32
    .line 33
    const-string v1, "lastLocationRequester"

    .line 34
    .line 35
    iget-object v2, p0, Lcom/salesforce/marketingcloud/location/h;->w:Ljava/lang/String;

    .line 36
    .line 37
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 38
    .line 39
    .line 40
    const-string v1, "geofenceEvents"

    .line 41
    .line 42
    iget p0, p0, Lcom/salesforce/marketingcloud/location/h;->x:I

    .line 43
    .line 44
    invoke-virtual {v0, v1, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;I)Lorg/json/JSONObject;
    :try_end_0
    .catch Lorg/json/JSONException; {:try_start_0 .. :try_end_0} :catch_0

    .line 45
    .line 46
    .line 47
    return-object v0

    .line 48
    :catch_0
    move-exception p0

    .line 49
    sget-object v1, Lcom/salesforce/marketingcloud/location/f;->p:Ljava/lang/String;

    .line 50
    .line 51
    const/4 v2, 0x0

    .line 52
    new-array v2, v2, [Ljava/lang/Object;

    .line 53
    .line 54
    const-string v3, "Error creating state for RealLocationManager."

    .line 55
    .line 56
    invoke-static {v1, p0, v3, v2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    return-object v0
.end method

.method public tearDown(Z)V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/location/h;->q:Lcom/salesforce/marketingcloud/location/d;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    if-eqz p1, :cond_0

    .line 6
    .line 7
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/location/d;->a()V

    .line 8
    .line 9
    .line 10
    :cond_0
    iget-object p1, p0, Lcom/salesforce/marketingcloud/location/h;->y:Landroid/content/Context;

    .line 11
    .line 12
    if-eqz p1, :cond_1

    .line 13
    .line 14
    iget-object p0, p0, Lcom/salesforce/marketingcloud/location/h;->z:Landroid/content/BroadcastReceiver;

    .line 15
    .line 16
    if-eqz p0, :cond_1

    .line 17
    .line 18
    invoke-virtual {p1, p0}, Landroid/content/Context;->unregisterReceiver(Landroid/content/BroadcastReceiver;)V

    .line 19
    .line 20
    .line 21
    :cond_1
    return-void
.end method
