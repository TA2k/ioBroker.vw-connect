.class Lcom/salesforce/marketingcloud/proximity/b;
.super Lcom/salesforce/marketingcloud/proximity/e;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/proximity/b$a;
    }
.end annotation


# instance fields
.field private final i:Landroid/content/Context;

.field private final j:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Lcom/salesforce/marketingcloud/proximity/e$a;",
            ">;"
        }
    .end annotation
.end field

.field private final k:Lcom/salesforce/marketingcloud/proximity/a;

.field private l:Landroid/content/BroadcastReceiver;

.field private m:I

.field private n:I


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 1

    const/4 v0, 0x0

    .line 1
    invoke-direct {p0, p1, v0}, Lcom/salesforce/marketingcloud/proximity/b;-><init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;)V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;)V
    .locals 3

    .line 2
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/proximity/e;-><init>()V

    .line 3
    new-instance v0, Landroidx/collection/g;

    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Landroidx/collection/g;-><init>(Ljava/lang/Object;)V

    .line 5
    iput-object v0, p0, Lcom/salesforce/marketingcloud/proximity/b;->j:Ljava/util/Set;

    .line 6
    const-string v0, "Context is null"

    invoke-static {p1, v0}, Lcom/salesforce/marketingcloud/util/g;->a(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 7
    iput-object p1, p0, Lcom/salesforce/marketingcloud/proximity/b;->i:Landroid/content/Context;

    .line 8
    invoke-virtual {p1}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    move-result-object v0

    new-instance v1, Landroid/content/Intent;

    const-class v2, Lorg/altbeacon/beacon/service/BeaconService;

    invoke-direct {v1, p1, v2}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    invoke-static {v0, v1}, Lcom/salesforce/marketingcloud/util/f;->b(Landroid/content/pm/PackageManager;Landroid/content/Intent;)Z

    move-result v0

    if-eqz v0, :cond_0

    .line 9
    new-instance v0, Lcom/salesforce/marketingcloud/proximity/a;

    invoke-direct {v0, p1, p2}, Lcom/salesforce/marketingcloud/proximity/a;-><init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;)V

    iput-object v0, p0, Lcom/salesforce/marketingcloud/proximity/b;->k:Lcom/salesforce/marketingcloud/proximity/a;

    return-void

    .line 10
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "AltBeacon service not found"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0
.end method


# virtual methods
.method public a(Lcom/salesforce/marketingcloud/InitializationStatus$a;)V
    .locals 2

    const/4 v0, 0x0

    .line 1
    invoke-virtual {p1, v0}, Lcom/salesforce/marketingcloud/InitializationStatus$a;->d(Z)V

    .line 2
    new-instance p1, Lcom/salesforce/marketingcloud/proximity/b$a;

    invoke-direct {p1, p0}, Lcom/salesforce/marketingcloud/proximity/b$a;-><init>(Lcom/salesforce/marketingcloud/proximity/b;)V

    iput-object p1, p0, Lcom/salesforce/marketingcloud/proximity/b;->l:Landroid/content/BroadcastReceiver;

    .line 3
    new-instance p1, Landroid/content/IntentFilter;

    invoke-direct {p1}, Landroid/content/IntentFilter;-><init>()V

    .line 4
    const-string v0, "com.salesforce.marketingcloud.proximity.BEACON_REGION_ENTERED"

    invoke-virtual {p1, v0}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V

    .line 5
    const-string v0, "com.salesforce.marketingcloud.proximity.BEACON_REGION_EXITED"

    invoke-virtual {p1, v0}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V

    .line 6
    iget-object v0, p0, Lcom/salesforce/marketingcloud/proximity/b;->i:Landroid/content/Context;

    iget-object p0, p0, Lcom/salesforce/marketingcloud/proximity/b;->l:Landroid/content/BroadcastReceiver;

    const/4 v1, 0x4

    invoke-static {v0, p0, p1, v1}, Ln5/a;->d(Landroid/content/Context;Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;I)V

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/proximity/c;)V
    .locals 4

    .line 13
    iget-object v0, p0, Lcom/salesforce/marketingcloud/proximity/b;->j:Ljava/util/Set;

    monitor-enter v0

    .line 14
    :try_start_0
    iget v1, p0, Lcom/salesforce/marketingcloud/proximity/b;->m:I

    add-int/lit8 v1, v1, 0x1

    iput v1, p0, Lcom/salesforce/marketingcloud/proximity/b;->m:I

    if-eqz p1, :cond_1

    .line 15
    iget-object v1, p0, Lcom/salesforce/marketingcloud/proximity/b;->j:Ljava/util/Set;

    invoke-interface {v1}, Ljava/util/Set;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_1

    .line 16
    sget-object v1, Lcom/salesforce/marketingcloud/proximity/e;->h:Ljava/lang/String;

    const-string v2, "Entered %s"

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object v3

    invoke-static {v1, v2, v3}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 17
    iget-object p0, p0, Lcom/salesforce/marketingcloud/proximity/b;->j:Ljava/util/Set;

    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lcom/salesforce/marketingcloud/proximity/e$a;

    if-eqz v1, :cond_0

    .line 18
    invoke-interface {v1, p1}, Lcom/salesforce/marketingcloud/proximity/e$a;->b(Lcom/salesforce/marketingcloud/proximity/c;)V

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    .line 19
    :cond_1
    monitor-exit v0

    return-void

    .line 20
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0
.end method

.method public a(Lcom/salesforce/marketingcloud/proximity/e$a;)V
    .locals 1

    .line 9
    iget-object v0, p0, Lcom/salesforce/marketingcloud/proximity/b;->j:Ljava/util/Set;

    monitor-enter v0

    if-eqz p1, :cond_0

    .line 10
    :try_start_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/proximity/b;->j:Ljava/util/Set;

    invoke-interface {p0, p1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    .line 11
    :cond_0
    :goto_0
    monitor-exit v0

    return-void

    .line 12
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0
.end method

.method public a(Ljava/util/List;)V
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/proximity/c;",
            ">;)V"
        }
    .end annotation

    if-eqz p1, :cond_0

    .line 7
    sget-object v0, Lcom/salesforce/marketingcloud/proximity/e;->h:Ljava/lang/String;

    invoke-interface {p1}, Ljava/util/List;->size()I

    move-result v1

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    const-string v2, "monitorBeaconRegions(%d region)"

    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 8
    iget-object p0, p0, Lcom/salesforce/marketingcloud/proximity/b;->k:Lcom/salesforce/marketingcloud/proximity/a;

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/proximity/a;->a(Ljava/util/List;)V

    :cond_0
    return-void
.end method

.method public b(Lcom/salesforce/marketingcloud/proximity/c;)V
    .locals 4

    .line 8
    iget-object v0, p0, Lcom/salesforce/marketingcloud/proximity/b;->j:Ljava/util/Set;

    monitor-enter v0

    .line 9
    :try_start_0
    iget v1, p0, Lcom/salesforce/marketingcloud/proximity/b;->n:I

    add-int/lit8 v1, v1, 0x1

    iput v1, p0, Lcom/salesforce/marketingcloud/proximity/b;->n:I

    if-eqz p1, :cond_1

    .line 10
    iget-object v1, p0, Lcom/salesforce/marketingcloud/proximity/b;->j:Ljava/util/Set;

    invoke-interface {v1}, Ljava/util/Set;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_1

    .line 11
    sget-object v1, Lcom/salesforce/marketingcloud/proximity/e;->h:Ljava/lang/String;

    const-string v2, "Exited %s"

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object v3

    invoke-static {v1, v2, v3}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 12
    iget-object p0, p0, Lcom/salesforce/marketingcloud/proximity/b;->j:Ljava/util/Set;

    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lcom/salesforce/marketingcloud/proximity/e$a;

    if-eqz v1, :cond_0

    .line 13
    invoke-interface {v1, p1}, Lcom/salesforce/marketingcloud/proximity/e$a;->a(Lcom/salesforce/marketingcloud/proximity/c;)V

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    .line 14
    :cond_1
    monitor-exit v0

    return-void

    .line 15
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0
.end method

.method public b(Lcom/salesforce/marketingcloud/proximity/e$a;)V
    .locals 1

    .line 4
    iget-object v0, p0, Lcom/salesforce/marketingcloud/proximity/b;->j:Ljava/util/Set;

    monitor-enter v0

    .line 5
    :try_start_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/proximity/b;->j:Ljava/util/Set;

    invoke-interface {p0, p1}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z

    .line 6
    monitor-exit v0

    return-void

    :catchall_0
    move-exception p0

    .line 7
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0
.end method

.method public b(Ljava/util/List;)V
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/proximity/c;",
            ">;)V"
        }
    .end annotation

    if-eqz p1, :cond_0

    .line 2
    sget-object v0, Lcom/salesforce/marketingcloud/proximity/e;->h:Ljava/lang/String;

    invoke-interface {p1}, Ljava/util/List;->size()I

    move-result v1

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    const-string v2, "unmonitorBeaconRegions(%d region)"

    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/proximity/b;->k:Lcom/salesforce/marketingcloud/proximity/a;

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/proximity/a;->b(Ljava/util/List;)V

    :cond_0
    return-void
.end method

.method public b()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    return p0
.end method

.method public c()V
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/proximity/b;->k:Lcom/salesforce/marketingcloud/proximity/a;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/proximity/a;->d()V

    .line 6
    .line 7
    .line 8
    :cond_0
    return-void
.end method

.method public componentState()Lorg/json/JSONObject;
    .locals 4

    .line 1
    :try_start_0
    invoke-static {}, Lcom/salesforce/marketingcloud/proximity/e;->a()Lorg/json/JSONObject;

    .line 2
    .line 3
    .line 4
    move-result-object v0
    :try_end_0
    .catch Lorg/json/JSONException; {:try_start_0 .. :try_end_0} :catch_1

    .line 5
    :try_start_1
    const-string v1, "enteredEvents"

    .line 6
    .line 7
    iget v2, p0, Lcom/salesforce/marketingcloud/proximity/b;->m:I

    .line 8
    .line 9
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;I)Lorg/json/JSONObject;

    .line 10
    .line 11
    .line 12
    const-string v1, "exitedEvents"

    .line 13
    .line 14
    iget p0, p0, Lcom/salesforce/marketingcloud/proximity/b;->n:I

    .line 15
    .line 16
    invoke-virtual {v0, v1, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;I)Lorg/json/JSONObject;
    :try_end_1
    .catch Lorg/json/JSONException; {:try_start_1 .. :try_end_1} :catch_0

    .line 17
    .line 18
    .line 19
    return-object v0

    .line 20
    :catch_0
    move-exception p0

    .line 21
    goto :goto_0

    .line 22
    :catch_1
    move-exception p0

    .line 23
    const/4 v0, 0x0

    .line 24
    :goto_0
    sget-object v1, Lcom/salesforce/marketingcloud/proximity/e;->h:Ljava/lang/String;

    .line 25
    .line 26
    const/4 v2, 0x0

    .line 27
    new-array v2, v2, [Ljava/lang/Object;

    .line 28
    .line 29
    const-string v3, "Failed to create component state."

    .line 30
    .line 31
    invoke-static {v1, p0, v3, v2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    return-object v0
.end method

.method public tearDown(Z)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/proximity/b;->c()V

    .line 2
    .line 3
    .line 4
    iget-object p1, p0, Lcom/salesforce/marketingcloud/proximity/b;->i:Landroid/content/Context;

    .line 5
    .line 6
    if-eqz p1, :cond_0

    .line 7
    .line 8
    iget-object p0, p0, Lcom/salesforce/marketingcloud/proximity/b;->l:Landroid/content/BroadcastReceiver;

    .line 9
    .line 10
    if-eqz p0, :cond_0

    .line 11
    .line 12
    invoke-virtual {p1, p0}, Landroid/content/Context;->unregisterReceiver(Landroid/content/BroadcastReceiver;)V

    .line 13
    .line 14
    .line 15
    :cond_0
    return-void
.end method
