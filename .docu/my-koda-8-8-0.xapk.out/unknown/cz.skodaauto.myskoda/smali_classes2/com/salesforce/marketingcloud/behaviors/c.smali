.class public Lcom/salesforce/marketingcloud/behaviors/c;
.super Lcom/salesforce/marketingcloud/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/behaviors/c$a;,
        Lcom/salesforce/marketingcloud/behaviors/c$b;
    }
.end annotation


# static fields
.field public static final i:Ljava/lang/String; = "timestamp"

.field static final j:I = 0x1

.field static final k:Ljava/lang/String;


# instance fields
.field private final d:Ljava/util/concurrent/ExecutorService;

.field private final e:Landroidx/collection/f;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroidx/collection/f;"
        }
    .end annotation
.end field

.field private final f:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Lcom/salesforce/marketingcloud/behaviors/a;",
            "Landroid/os/Bundle;",
            ">;"
        }
    .end annotation
.end field

.field private final g:Landroid/content/Context;

.field private h:Landroid/content/BroadcastReceiver;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "BehaviorManager"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/behaviors/c;->k:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Ljava/util/concurrent/ExecutorService;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/f;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Landroidx/collection/f;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-direct {v0, v1}, Landroidx/collection/a1;-><init>(I)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lcom/salesforce/marketingcloud/behaviors/c;->e:Landroidx/collection/f;

    .line 11
    .line 12
    new-instance v0, Landroidx/collection/f;

    .line 13
    .line 14
    const/4 v1, 0x1

    .line 15
    invoke-direct {v0, v1}, Landroidx/collection/a1;-><init>(I)V

    .line 16
    .line 17
    .line 18
    iput-object v0, p0, Lcom/salesforce/marketingcloud/behaviors/c;->f:Ljava/util/Map;

    .line 19
    .line 20
    iput-object p1, p0, Lcom/salesforce/marketingcloud/behaviors/c;->g:Landroid/content/Context;

    .line 21
    .line 22
    iput-object p2, p0, Lcom/salesforce/marketingcloud/behaviors/c;->d:Ljava/util/concurrent/ExecutorService;

    .line 23
    .line 24
    return-void
.end method

.method public static a(Landroid/content/Context;Lcom/salesforce/marketingcloud/behaviors/a;Landroid/os/Bundle;)V
    .locals 1

    .line 1
    const-string v0, "Context is null"

    invoke-static {p0, v0}, Lcom/salesforce/marketingcloud/util/g;->a(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 2
    const-string v0, "Behavior is null"

    invoke-static {p1, v0}, Lcom/salesforce/marketingcloud/util/g;->a(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 3
    new-instance v0, Landroid/content/Intent;

    iget-object p1, p1, Lcom/salesforce/marketingcloud/behaviors/a;->b:Ljava/lang/String;

    invoke-direct {v0, p1}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    if-eqz p2, :cond_0

    .line 4
    invoke-virtual {v0, p2}, Landroid/content/Intent;->putExtras(Landroid/os/Bundle;)Landroid/content/Intent;

    .line 5
    :cond_0
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {v0, p1}, Landroid/content/Intent;->setPackage(Ljava/lang/String;)Landroid/content/Intent;

    move-result-object p1

    invoke-virtual {p0, p1}, Landroid/content/Context;->sendBroadcast(Landroid/content/Intent;)V

    return-void
.end method


# virtual methods
.method public a(Lcom/salesforce/marketingcloud/InitializationStatus$a;)V
    .locals 4

    .line 6
    new-instance p1, Lcom/salesforce/marketingcloud/behaviors/c$a;

    invoke-direct {p1, p0}, Lcom/salesforce/marketingcloud/behaviors/c$a;-><init>(Lcom/salesforce/marketingcloud/behaviors/c;)V

    iput-object p1, p0, Lcom/salesforce/marketingcloud/behaviors/c;->h:Landroid/content/BroadcastReceiver;

    .line 7
    new-instance p1, Landroid/content/IntentFilter;

    invoke-direct {p1}, Landroid/content/IntentFilter;-><init>()V

    .line 8
    invoke-static {}, Lcom/salesforce/marketingcloud/behaviors/a;->values()[Lcom/salesforce/marketingcloud/behaviors/a;

    move-result-object v0

    array-length v1, v0

    const/4 v2, 0x0

    :goto_0
    if-ge v2, v1, :cond_0

    aget-object v3, v0, v2

    .line 9
    iget-object v3, v3, Lcom/salesforce/marketingcloud/behaviors/a;->b:Ljava/lang/String;

    invoke-virtual {p1, v3}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    .line 10
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/behaviors/c;->g:Landroid/content/Context;

    iget-object p0, p0, Lcom/salesforce/marketingcloud/behaviors/c;->h:Landroid/content/BroadcastReceiver;

    const/4 v1, 0x4

    invoke-static {v0, p0, p1, v1}, Ln5/a;->d(Landroid/content/Context;Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;I)V

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/behaviors/b;)V
    .locals 2

    .line 32
    iget-object v0, p0, Lcom/salesforce/marketingcloud/behaviors/c;->e:Landroidx/collection/f;

    monitor-enter v0

    .line 33
    :try_start_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/behaviors/c;->e:Landroidx/collection/f;

    invoke-virtual {p0}, Landroidx/collection/f;->entrySet()Ljava/util/Set;

    move-result-object p0

    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/util/Map$Entry;

    .line 34
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/util/Set;

    invoke-interface {v1, p1}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    .line 35
    :cond_0
    monitor-exit v0

    return-void

    .line 36
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0
.end method

.method public a(Lcom/salesforce/marketingcloud/behaviors/b;Ljava/util/EnumSet;)V
    .locals 6
    .annotation build Landroid/annotation/SuppressLint;
        value = {
            "LambdaLast"
        }
    .end annotation

    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/behaviors/b;",
            "Ljava/util/EnumSet<",
            "Lcom/salesforce/marketingcloud/behaviors/a;",
            ">;)V"
        }
    .end annotation

    .line 11
    const-string v0, "BehaviorListener is null"

    invoke-static {p1, v0}, Lcom/salesforce/marketingcloud/util/g;->a(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 12
    const-string v0, "Behavior set is null"

    invoke-static {p2, v0}, Lcom/salesforce/marketingcloud/util/g;->a(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 13
    iget-object v0, p0, Lcom/salesforce/marketingcloud/behaviors/c;->e:Landroidx/collection/f;

    monitor-enter v0

    .line 14
    :try_start_0
    sget-object v1, Lcom/salesforce/marketingcloud/behaviors/c;->k:Ljava/lang/String;

    const-string v2, "Registering %s for behaviors: %s"

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v3

    invoke-virtual {v3}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v3

    .line 15
    invoke-virtual {p2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v4

    filled-new-array {v3, v4}, [Ljava/lang/Object;

    move-result-object v3

    .line 16
    invoke-static {v1, v2, v3}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 17
    invoke-virtual {p2}, Ljava/util/AbstractCollection;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_1

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Lcom/salesforce/marketingcloud/behaviors/a;

    .line 18
    iget-object v3, p0, Lcom/salesforce/marketingcloud/behaviors/c;->e:Landroidx/collection/f;

    invoke-virtual {v3, v2}, Landroidx/collection/f;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/util/Set;

    if-nez v3, :cond_0

    .line 19
    new-instance v3, Ljava/util/HashSet;

    invoke-direct {v3}, Ljava/util/HashSet;-><init>()V

    .line 20
    iget-object v4, p0, Lcom/salesforce/marketingcloud/behaviors/c;->e:Landroidx/collection/f;

    invoke-virtual {v4, v2, v3}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_1

    :catchall_0
    move-exception p0

    goto :goto_4

    .line 21
    :cond_0
    :goto_1
    invoke-interface {v3, p1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    goto :goto_0

    .line 22
    :cond_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 23
    iget-object v1, p0, Lcom/salesforce/marketingcloud/behaviors/c;->f:Ljava/util/Map;

    monitor-enter v1

    .line 24
    :try_start_1
    invoke-virtual {p2}, Ljava/util/AbstractCollection;->iterator()Ljava/util/Iterator;

    move-result-object p2

    :cond_2
    :goto_2
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_3

    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lcom/salesforce/marketingcloud/behaviors/a;

    .line 25
    iget-boolean v2, v0, Lcom/salesforce/marketingcloud/behaviors/a;->c:Z

    if-eqz v2, :cond_2

    iget-object v2, p0, Lcom/salesforce/marketingcloud/behaviors/c;->f:Ljava/util/Map;

    invoke-interface {v2, v0}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_2

    .line 26
    iget-object v2, p0, Lcom/salesforce/marketingcloud/behaviors/c;->d:Ljava/util/concurrent/ExecutorService;

    new-instance v3, Lcom/salesforce/marketingcloud/behaviors/c$b;

    .line 27
    invoke-static {p1}, Ljava/util/Collections;->singleton(Ljava/lang/Object;)Ljava/util/Set;

    move-result-object v4

    iget-object v5, p0, Lcom/salesforce/marketingcloud/behaviors/c;->f:Ljava/util/Map;

    invoke-interface {v5, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Landroid/os/Bundle;

    invoke-direct {v3, v4, v0, v5}, Lcom/salesforce/marketingcloud/behaviors/c$b;-><init>(Ljava/util/Set;Lcom/salesforce/marketingcloud/behaviors/a;Landroid/os/Bundle;)V

    .line 28
    invoke-interface {v2, v3}, Ljava/util/concurrent/ExecutorService;->submit(Ljava/lang/Runnable;)Ljava/util/concurrent/Future;

    goto :goto_2

    :catchall_1
    move-exception p0

    goto :goto_3

    .line 29
    :cond_3
    monitor-exit v1

    return-void

    .line 30
    :goto_3
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    throw p0

    .line 31
    :goto_4
    :try_start_2
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    throw p0
.end method

.method public final componentName()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "BehaviorManager"

    .line 2
    .line 3
    return-object p0
.end method

.method public final componentState()Lorg/json/JSONObject;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method

.method public onBehavior(Lcom/salesforce/marketingcloud/behaviors/a;Landroid/os/Bundle;)V
    .locals 5

    .line 1
    if-nez p2, :cond_0

    .line 2
    .line 3
    new-instance p2, Landroid/os/Bundle;

    .line 4
    .line 5
    invoke-direct {p2}, Landroid/os/Bundle;-><init>()V

    .line 6
    .line 7
    .line 8
    :cond_0
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 9
    .line 10
    .line 11
    move-result-wide v0

    .line 12
    const-string v2, "timestamp"

    .line 13
    .line 14
    invoke-virtual {p2, v2, v0, v1}, Landroid/os/BaseBundle;->putLong(Ljava/lang/String;J)V

    .line 15
    .line 16
    .line 17
    sget-object v0, Lcom/salesforce/marketingcloud/behaviors/c;->k:Ljava/lang/String;

    .line 18
    .line 19
    invoke-virtual {p1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    const-string v2, "Behavior found: %s"

    .line 28
    .line 29
    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    iget-object v0, p0, Lcom/salesforce/marketingcloud/behaviors/c;->e:Landroidx/collection/f;

    .line 33
    .line 34
    monitor-enter v0

    .line 35
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/behaviors/c;->e:Landroidx/collection/f;

    .line 36
    .line 37
    invoke-virtual {v1, p1}, Landroidx/collection/f;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    check-cast v1, Ljava/util/Set;

    .line 42
    .line 43
    if-eqz v1, :cond_1

    .line 44
    .line 45
    invoke-interface {v1}, Ljava/util/Set;->isEmpty()Z

    .line 46
    .line 47
    .line 48
    move-result v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 49
    if-nez v2, :cond_1

    .line 50
    .line 51
    :try_start_1
    iget-object v2, p0, Lcom/salesforce/marketingcloud/behaviors/c;->d:Ljava/util/concurrent/ExecutorService;

    .line 52
    .line 53
    new-instance v3, Lcom/salesforce/marketingcloud/behaviors/c$b;

    .line 54
    .line 55
    invoke-static {v1}, Ljava/util/Collections;->unmodifiableSet(Ljava/util/Set;)Ljava/util/Set;

    .line 56
    .line 57
    .line 58
    move-result-object v1

    .line 59
    invoke-direct {v3, v1, p1, p2}, Lcom/salesforce/marketingcloud/behaviors/c$b;-><init>(Ljava/util/Set;Lcom/salesforce/marketingcloud/behaviors/a;Landroid/os/Bundle;)V

    .line 60
    .line 61
    .line 62
    invoke-interface {v2, v3}, Ljava/util/concurrent/ExecutorService;->submit(Ljava/lang/Runnable;)Ljava/util/concurrent/Future;
    :try_end_1
    .catch Ljava/util/concurrent/RejectedExecutionException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 63
    .line 64
    .line 65
    goto :goto_0

    .line 66
    :catchall_0
    move-exception p0

    .line 67
    goto :goto_3

    .line 68
    :catch_0
    move-exception v1

    .line 69
    :try_start_2
    sget-object v2, Lcom/salesforce/marketingcloud/behaviors/c;->k:Ljava/lang/String;

    .line 70
    .line 71
    const-string v3, "Unable to deliver behavior %s."

    .line 72
    .line 73
    iget-object v4, p1, Lcom/salesforce/marketingcloud/behaviors/a;->b:Ljava/lang/String;

    .line 74
    .line 75
    filled-new-array {v4}, [Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v4

    .line 79
    invoke-static {v2, v1, v3, v4}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    :cond_1
    :goto_0
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 83
    iget-object v1, p0, Lcom/salesforce/marketingcloud/behaviors/c;->f:Ljava/util/Map;

    .line 84
    .line 85
    monitor-enter v1

    .line 86
    :try_start_3
    iget-boolean v0, p1, Lcom/salesforce/marketingcloud/behaviors/a;->c:Z

    .line 87
    .line 88
    if-eqz v0, :cond_2

    .line 89
    .line 90
    iget-object v0, p0, Lcom/salesforce/marketingcloud/behaviors/c;->f:Ljava/util/Map;

    .line 91
    .line 92
    invoke-interface {v0, p1, p2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    goto :goto_1

    .line 96
    :catchall_1
    move-exception p0

    .line 97
    goto :goto_2

    .line 98
    :cond_2
    :goto_1
    iget-object p1, p1, Lcom/salesforce/marketingcloud/behaviors/a;->d:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 99
    .line 100
    if-eqz p1, :cond_3

    .line 101
    .line 102
    iget-object p0, p0, Lcom/salesforce/marketingcloud/behaviors/c;->f:Ljava/util/Map;

    .line 103
    .line 104
    const/4 p2, 0x0

    .line 105
    invoke-interface {p0, p1, p2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    :cond_3
    monitor-exit v1

    .line 109
    return-void

    .line 110
    :goto_2
    monitor-exit v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 111
    throw p0

    .line 112
    :goto_3
    :try_start_4
    monitor-exit v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 113
    throw p0
.end method

.method public final tearDown(Z)V
    .locals 0

    .line 1
    iget-object p1, p0, Lcom/salesforce/marketingcloud/behaviors/c;->g:Landroid/content/Context;

    .line 2
    .line 3
    if-eqz p1, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Lcom/salesforce/marketingcloud/behaviors/c;->h:Landroid/content/BroadcastReceiver;

    .line 6
    .line 7
    invoke-virtual {p1, p0}, Landroid/content/Context;->unregisterReceiver(Landroid/content/BroadcastReceiver;)V

    .line 8
    .line 9
    .line 10
    :cond_0
    return-void
.end method
