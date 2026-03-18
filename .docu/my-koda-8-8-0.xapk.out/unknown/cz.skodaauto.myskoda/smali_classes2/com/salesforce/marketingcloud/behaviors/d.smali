.class public final Lcom/salesforce/marketingcloud/behaviors/d;
.super Lcom/salesforce/marketingcloud/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/lifecycle/w;


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation


# static fields
.field static g:Lcom/salesforce/marketingcloud/behaviors/d;


# instance fields
.field private final d:Landroid/app/Application;

.field private final e:Ljava/util/concurrent/atomic/AtomicBoolean;

.field f:Ljava/util/concurrent/atomic/AtomicBoolean;


# direct methods
.method private constructor <init>(Landroid/app/Application;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/f;-><init>()V

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
    iput-object v0, p0, Lcom/salesforce/marketingcloud/behaviors/d;->e:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 11
    .line 12
    new-instance v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 13
    .line 14
    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    .line 15
    .line 16
    .line 17
    iput-object v0, p0, Lcom/salesforce/marketingcloud/behaviors/d;->f:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 18
    .line 19
    iput-object p1, p0, Lcom/salesforce/marketingcloud/behaviors/d;->d:Landroid/app/Application;

    .line 20
    .line 21
    return-void
.end method

.method public static declared-synchronized a(Landroid/app/Application;)Lcom/salesforce/marketingcloud/behaviors/d;
    .locals 2

    const-class v0, Lcom/salesforce/marketingcloud/behaviors/d;

    monitor-enter v0

    .line 1
    :try_start_0
    sget-object v1, Lcom/salesforce/marketingcloud/behaviors/d;->g:Lcom/salesforce/marketingcloud/behaviors/d;

    if-nez v1, :cond_0

    .line 2
    new-instance v1, Lcom/salesforce/marketingcloud/behaviors/d;

    invoke-direct {v1, p0}, Lcom/salesforce/marketingcloud/behaviors/d;-><init>(Landroid/app/Application;)V

    sput-object v1, Lcom/salesforce/marketingcloud/behaviors/d;->g:Lcom/salesforce/marketingcloud/behaviors/d;

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    .line 3
    :cond_0
    :goto_0
    sget-object p0, Lcom/salesforce/marketingcloud/behaviors/d;->g:Lcom/salesforce/marketingcloud/behaviors/d;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit v0

    return-object p0

    :goto_1
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw p0
.end method


# virtual methods
.method public a(Lcom/salesforce/marketingcloud/InitializationStatus$a;)V
    .locals 1

    .line 4
    iget-object p1, p0, Lcom/salesforce/marketingcloud/behaviors/d;->e:Ljava/util/concurrent/atomic/AtomicBoolean;

    const/4 v0, 0x1

    invoke-virtual {p1, v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 5
    iget-object p1, p0, Lcom/salesforce/marketingcloud/behaviors/d;->f:Ljava/util/concurrent/atomic/AtomicBoolean;

    invoke-virtual {p1}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    move-result p1

    if-eqz p1, :cond_0

    .line 6
    iget-object p0, p0, Lcom/salesforce/marketingcloud/behaviors/d;->d:Landroid/app/Application;

    sget-object p1, Lcom/salesforce/marketingcloud/behaviors/a;->i:Lcom/salesforce/marketingcloud/behaviors/a;

    const/4 v0, 0x0

    invoke-static {p0, p1, v0}, Lcom/salesforce/marketingcloud/behaviors/c;->a(Landroid/content/Context;Lcom/salesforce/marketingcloud/behaviors/a;Landroid/os/Bundle;)V

    :cond_0
    return-void
.end method

.method public componentName()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "LifecycleManager"

    .line 2
    .line 3
    return-object p0
.end method

.method public componentState()Lorg/json/JSONObject;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method

.method public onApplicationBackgrounded()V
    .locals 3
    .annotation runtime Landroidx/lifecycle/k0;
        value = .enum Landroidx/lifecycle/p;->ON_STOP:Landroidx/lifecycle/p;
    .end annotation

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/behaviors/d;->f:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;->getAndSet(Z)Z

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    sget-object v0, Lcom/salesforce/marketingcloud/behaviors/c;->k:Ljava/lang/String;

    .line 11
    .line 12
    new-array v1, v1, [Ljava/lang/Object;

    .line 13
    .line 14
    const-string v2, "Application went into the background."

    .line 15
    .line 16
    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    iget-object p0, p0, Lcom/salesforce/marketingcloud/behaviors/d;->d:Landroid/app/Application;

    .line 20
    .line 21
    sget-object v0, Lcom/salesforce/marketingcloud/behaviors/a;->j:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 22
    .line 23
    new-instance v1, Landroid/os/Bundle;

    .line 24
    .line 25
    invoke-direct {v1}, Landroid/os/Bundle;-><init>()V

    .line 26
    .line 27
    .line 28
    invoke-static {p0, v0, v1}, Lcom/salesforce/marketingcloud/behaviors/c;->a(Landroid/content/Context;Lcom/salesforce/marketingcloud/behaviors/a;Landroid/os/Bundle;)V

    .line 29
    .line 30
    .line 31
    :cond_0
    return-void
.end method

.method public onApplicationForegrounded()V
    .locals 3
    .annotation runtime Landroidx/lifecycle/k0;
        value = .enum Landroidx/lifecycle/p;->ON_START:Landroidx/lifecycle/p;
    .end annotation

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/behaviors/d;->f:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;->getAndSet(Z)Z

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    if-nez v0, :cond_0

    .line 9
    .line 10
    iget-object v0, p0, Lcom/salesforce/marketingcloud/behaviors/d;->e:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 11
    .line 12
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-eqz v0, :cond_0

    .line 17
    .line 18
    sget-object v0, Lcom/salesforce/marketingcloud/behaviors/c;->k:Ljava/lang/String;

    .line 19
    .line 20
    const/4 v1, 0x0

    .line 21
    new-array v1, v1, [Ljava/lang/Object;

    .line 22
    .line 23
    const-string v2, "Application came into the foreground."

    .line 24
    .line 25
    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    iget-object p0, p0, Lcom/salesforce/marketingcloud/behaviors/d;->d:Landroid/app/Application;

    .line 29
    .line 30
    sget-object v0, Lcom/salesforce/marketingcloud/behaviors/a;->i:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 31
    .line 32
    new-instance v1, Landroid/os/Bundle;

    .line 33
    .line 34
    invoke-direct {v1}, Landroid/os/Bundle;-><init>()V

    .line 35
    .line 36
    .line 37
    invoke-static {p0, v0, v1}, Lcom/salesforce/marketingcloud/behaviors/c;->a(Landroid/content/Context;Lcom/salesforce/marketingcloud/behaviors/a;Landroid/os/Bundle;)V

    .line 38
    .line 39
    .line 40
    :cond_0
    return-void
.end method

.method public tearDown(Z)V
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/behaviors/d;->e:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 2
    .line 3
    const/4 p1, 0x0

    .line 4
    invoke-virtual {p0, p1}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 5
    .line 6
    .line 7
    return-void
.end method
