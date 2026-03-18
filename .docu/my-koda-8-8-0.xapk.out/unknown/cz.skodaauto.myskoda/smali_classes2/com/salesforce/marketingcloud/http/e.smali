.class public Lcom/salesforce/marketingcloud/http/e;
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
        Lcom/salesforce/marketingcloud/http/e$d;,
        Lcom/salesforce/marketingcloud/http/e$c;
    }
.end annotation


# static fields
.field public static final j:Ljava/lang/String; = "com.salesforce.marketingcloud.http.RESPONSE"

.field public static final k:Ljava/lang/String; = "http_response"

.field public static final l:Ljava/lang/String; = "http_request"

.field static final m:Ljava/lang/String;

.field private static final n:I = 0xa


# instance fields
.field final d:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Lcom/salesforce/marketingcloud/http/b;",
            "Lcom/salesforce/marketingcloud/http/e$c;",
            ">;"
        }
    .end annotation
.end field

.field private final e:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private final f:Landroid/content/Context;

.field private final g:Landroid/content/SharedPreferences;

.field private h:Lcom/salesforce/marketingcloud/internal/n;

.field private i:Landroid/content/BroadcastReceiver;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "RequestManager"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/http/e;->m:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/content/SharedPreferences;Lcom/salesforce/marketingcloud/internal/n;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/f;-><init>()V

    .line 2
    .line 3
    .line 4
    const-string v0, "Context is null"

    .line 5
    .line 6
    invoke-static {p1, v0}, Lcom/salesforce/marketingcloud/util/g;->a(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    check-cast p1, Landroid/content/Context;

    .line 11
    .line 12
    iput-object p1, p0, Lcom/salesforce/marketingcloud/http/e;->f:Landroid/content/Context;

    .line 13
    .line 14
    const-string p1, "SharedPreferences is null"

    .line 15
    .line 16
    invoke-static {p2, p1}, Lcom/salesforce/marketingcloud/util/g;->a(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    check-cast p1, Landroid/content/SharedPreferences;

    .line 21
    .line 22
    iput-object p1, p0, Lcom/salesforce/marketingcloud/http/e;->g:Landroid/content/SharedPreferences;

    .line 23
    .line 24
    iput-object p3, p0, Lcom/salesforce/marketingcloud/http/e;->h:Lcom/salesforce/marketingcloud/internal/n;

    .line 25
    .line 26
    new-instance p1, Lcom/salesforce/marketingcloud/http/e$a;

    .line 27
    .line 28
    invoke-direct {p1, p0}, Lcom/salesforce/marketingcloud/http/e$a;-><init>(Lcom/salesforce/marketingcloud/http/e;)V

    .line 29
    .line 30
    .line 31
    iput-object p1, p0, Lcom/salesforce/marketingcloud/http/e;->e:Ljava/util/Map;

    .line 32
    .line 33
    new-instance p1, Landroidx/collection/f;

    .line 34
    .line 35
    const/4 p2, 0x0

    .line 36
    invoke-direct {p1, p2}, Landroidx/collection/a1;-><init>(I)V

    .line 37
    .line 38
    .line 39
    iput-object p1, p0, Lcom/salesforce/marketingcloud/http/e;->d:Ljava/util/Map;

    .line 40
    .line 41
    return-void
.end method

.method private a()V
    .locals 0

    .line 8
    iget-object p0, p0, Lcom/salesforce/marketingcloud/http/e;->f:Landroid/content/Context;

    invoke-static {p0}, Lwp/a;->a(Landroid/content/Context;)V

    return-void
.end method


# virtual methods
.method public final a(Lcom/salesforce/marketingcloud/InitializationStatus$a;)V
    .locals 3

    .line 1
    :try_start_0
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/http/e;->a()V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception v0

    const/4 v1, 0x1

    .line 2
    invoke-virtual {p1, v1}, Lcom/salesforce/marketingcloud/InitializationStatus$a;->e(Z)V

    .line 3
    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Failed to install providers: "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1, v0}, Lcom/salesforce/marketingcloud/InitializationStatus$a;->a(Ljava/lang/String;)V

    .line 4
    :goto_0
    new-instance p1, Lcom/salesforce/marketingcloud/http/e$d;

    invoke-direct {p1, p0}, Lcom/salesforce/marketingcloud/http/e$d;-><init>(Lcom/salesforce/marketingcloud/http/e;)V

    iput-object p1, p0, Lcom/salesforce/marketingcloud/http/e;->i:Landroid/content/BroadcastReceiver;

    .line 5
    new-instance p1, Landroid/content/IntentFilter;

    invoke-direct {p1}, Landroid/content/IntentFilter;-><init>()V

    .line 6
    const-string v0, "com.salesforce.marketingcloud.http.RESPONSE"

    invoke-virtual {p1, v0}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V

    .line 7
    iget-object v0, p0, Lcom/salesforce/marketingcloud/http/e;->f:Landroid/content/Context;

    iget-object p0, p0, Lcom/salesforce/marketingcloud/http/e;->i:Landroid/content/BroadcastReceiver;

    const/4 v1, 0x4

    invoke-static {v0, p0, p1, v1}, Ln5/a;->d(Landroid/content/Context;Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;I)V

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/http/b;)V
    .locals 1

    .line 16
    iget-object v0, p0, Lcom/salesforce/marketingcloud/http/e;->d:Ljava/util/Map;

    monitor-enter v0

    .line 17
    :try_start_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/http/e;->d:Ljava/util/Map;

    invoke-interface {p0, p1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 18
    monitor-exit v0

    return-void

    :catchall_0
    move-exception p0

    .line 19
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0
.end method

.method public a(Lcom/salesforce/marketingcloud/http/b;Lcom/salesforce/marketingcloud/http/e$c;)V
    .locals 2

    .line 9
    iget-object v0, p0, Lcom/salesforce/marketingcloud/http/e;->d:Ljava/util/Map;

    monitor-enter v0

    .line 10
    :try_start_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/http/e;->d:Ljava/util/Map;

    invoke-interface {p0, p1, p2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    if-eqz p0, :cond_0

    .line 11
    sget-object p0, Lcom/salesforce/marketingcloud/http/e;->m:Ljava/lang/String;

    const-string v1, "%s replaces previous listener for $s requests"

    .line 12
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p2

    invoke-virtual {p2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object p1

    filled-new-array {p2, p1}, [Ljava/lang/Object;

    move-result-object p1

    .line 13
    invoke-static {p0, v1, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    .line 14
    :cond_0
    :goto_0
    monitor-exit v0

    return-void

    .line 15
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0
.end method

.method public declared-synchronized a(Lcom/salesforce/marketingcloud/http/c;)V
    .locals 6

    monitor-enter p0

    .line 20
    :try_start_0
    const-string v0, "request is null"

    invoke-static {p1, v0}, Lcom/salesforce/marketingcloud/util/g;->a(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 21
    :try_start_1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/http/e;->a()V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_2

    .line 22
    :catch_0
    :try_start_2
    sget-object v0, Lcom/salesforce/marketingcloud/http/e;->m:Ljava/lang/String;

    const/4 v1, 0x0

    new-array v1, v1, [Ljava/lang/Object;

    const-string v2, "Failed to verify SSL providers via Google Play Services."

    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 23
    :goto_0
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v0

    .line 24
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/http/c;->q()Lcom/salesforce/marketingcloud/http/b;

    move-result-object v2

    iget-object v3, p0, Lcom/salesforce/marketingcloud/http/e;->g:Landroid/content/SharedPreferences;

    invoke-virtual {v2, v3}, Lcom/salesforce/marketingcloud/http/b;->c(Landroid/content/SharedPreferences;)J

    move-result-wide v2

    .line 25
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/http/c;->q()Lcom/salesforce/marketingcloud/http/b;

    move-result-object v4

    iget-object v5, p0, Lcom/salesforce/marketingcloud/http/e;->g:Landroid/content/SharedPreferences;

    invoke-virtual {v4, v5}, Lcom/salesforce/marketingcloud/http/b;->a(Landroid/content/SharedPreferences;)J

    move-result-wide v4

    cmp-long v2, v0, v2

    if-lez v2, :cond_0

    cmp-long v0, v0, v4

    if-lez v0, :cond_0

    .line 26
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/http/c;->q()Lcom/salesforce/marketingcloud/http/b;

    move-result-object v0

    iget-object v1, p0, Lcom/salesforce/marketingcloud/http/e;->g:Landroid/content/SharedPreferences;

    invoke-virtual {v0, v1}, Lcom/salesforce/marketingcloud/http/b;->b(Landroid/content/SharedPreferences;)V

    .line 27
    iget-object v0, p0, Lcom/salesforce/marketingcloud/http/e;->f:Landroid/content/Context;

    invoke-static {v0, p1}, Lcom/salesforce/marketingcloud/MCService;->a(Landroid/content/Context;Lcom/salesforce/marketingcloud/http/c;)V

    goto :goto_1

    .line 28
    :cond_0
    const-string v0, "Too Many Requests"

    const/16 v1, 0x1ad

    invoke-static {v0, v1}, Lcom/salesforce/marketingcloud/http/f;->a(Ljava/lang/String;I)Lcom/salesforce/marketingcloud/http/f;

    move-result-object v0

    invoke-virtual {p0, p1, v0}, Lcom/salesforce/marketingcloud/http/e;->a(Lcom/salesforce/marketingcloud/http/c;Lcom/salesforce/marketingcloud/http/f;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    :goto_1
    monitor-exit p0

    return-void

    :goto_2
    :try_start_3
    monitor-exit p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    throw p1
.end method

.method public a(Lcom/salesforce/marketingcloud/http/c;Lcom/salesforce/marketingcloud/http/f;)V
    .locals 11

    .line 29
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/http/c;->q()Lcom/salesforce/marketingcloud/http/b;

    move-result-object v1

    .line 30
    sget-object v0, Lcom/salesforce/marketingcloud/http/e;->m:Ljava/lang/String;

    invoke-virtual {v1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->q()J

    move-result-wide v3

    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v3

    .line 31
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->k()I

    move-result v4

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    filled-new-array {v2, v3, v4}, [Ljava/lang/Object;

    move-result-object v2

    .line 32
    const-string v3, "%s request took %dms with code: %d"

    invoke-static {v0, v3, v2}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 33
    iget-object v0, p0, Lcom/salesforce/marketingcloud/http/e;->g:Landroid/content/SharedPreferences;

    invoke-virtual {v1, v0, p2}, Lcom/salesforce/marketingcloud/http/b;->a(Landroid/content/SharedPreferences;Lcom/salesforce/marketingcloud/http/f;)V

    const/4 v2, 0x0

    .line 34
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/http/e;->e:Ljava/util/Map;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/http/c;->s()Ljava/lang/String;

    move-result-object v3

    sget-object v4, Ljava/util/Locale;->ENGLISH:Ljava/util/Locale;

    .line 35
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->n()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->k()I

    move-result v5

    new-instance v6, Ljava/lang/StringBuilder;

    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    const-string v4, " - "

    .line 37
    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v6, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    .line 38
    invoke-interface {v0, v3, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception v0

    .line 39
    sget-object v3, Lcom/salesforce/marketingcloud/http/e;->m:Ljava/lang/String;

    new-array v4, v2, [Ljava/lang/Object;

    const-string v5, "Failed to record response."

    invoke-static {v3, v0, v5, v4}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 40
    :goto_0
    iget-object v3, p0, Lcom/salesforce/marketingcloud/http/e;->d:Ljava/util/Map;

    monitor-enter v3

    .line 41
    :try_start_1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/http/e;->d:Ljava/util/Map;

    invoke-interface {v0, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    move-object v8, v0

    check-cast v8, Lcom/salesforce/marketingcloud/http/e$c;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    if-eqz v8, :cond_0

    .line 42
    :try_start_2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/http/e;->h:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->a()Ljava/util/concurrent/ExecutorService;

    move-result-object v0

    new-instance v4, Lcom/salesforce/marketingcloud/http/e$b;

    const-string v6, "onResponse"

    new-array v7, v2, [Ljava/lang/Object;

    move-object v5, p0

    move-object v9, p1

    move-object v10, p2

    invoke-direct/range {v4 .. v10}, Lcom/salesforce/marketingcloud/http/e$b;-><init>(Lcom/salesforce/marketingcloud/http/e;Ljava/lang/String;[Ljava/lang/Object;Lcom/salesforce/marketingcloud/http/e$c;Lcom/salesforce/marketingcloud/http/c;Lcom/salesforce/marketingcloud/http/f;)V

    invoke-interface {v0, v4}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_1
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    goto :goto_1

    :catchall_0
    move-exception v0

    move-object p0, v0

    goto :goto_2

    :catch_1
    move-exception v0

    move-object p0, v0

    .line 43
    :try_start_3
    sget-object p1, Lcom/salesforce/marketingcloud/http/e;->m:Ljava/lang/String;

    const-string p2, "Failed to deliver response."

    new-array v0, v2, [Ljava/lang/Object;

    invoke-static {p1, p0, p2, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    goto :goto_1

    :cond_0
    move-object v9, p1

    move-object v10, p2

    .line 44
    sget-object p0, Lcom/salesforce/marketingcloud/http/e;->m:Ljava/lang/String;

    const-string p1, "Request %s complete, but no listener was present to handle response %d."

    .line 45
    invoke-virtual {v9}, Lcom/salesforce/marketingcloud/http/c;->s()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {v10}, Lcom/salesforce/marketingcloud/http/f;->k()I

    move-result v0

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    filled-new-array {p2, v0}, [Ljava/lang/Object;

    move-result-object p2

    .line 46
    invoke-static {p0, p1, p2}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 47
    :goto_1
    monitor-exit v3

    return-void

    .line 48
    :goto_2
    monitor-exit v3
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    throw p0
.end method

.method public final componentName()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "RequestManager"

    .line 2
    .line 3
    return-object p0
.end method

.method public final componentState()Lorg/json/JSONObject;
    .locals 1

    .line 1
    new-instance v0, Lorg/json/JSONObject;

    .line 2
    .line 3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/http/e;->e:Ljava/util/Map;

    .line 4
    .line 5
    invoke-direct {v0, p0}, Lorg/json/JSONObject;-><init>(Ljava/util/Map;)V

    .line 6
    .line 7
    .line 8
    return-object v0
.end method

.method public final tearDown(Z)V
    .locals 1

    .line 1
    iget-object p1, p0, Lcom/salesforce/marketingcloud/http/e;->d:Ljava/util/Map;

    .line 2
    .line 3
    monitor-enter p1

    .line 4
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/http/e;->d:Ljava/util/Map;

    .line 5
    .line 6
    invoke-interface {v0}, Ljava/util/Map;->clear()V

    .line 7
    .line 8
    .line 9
    monitor-exit p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 10
    iget-object p1, p0, Lcom/salesforce/marketingcloud/http/e;->f:Landroid/content/Context;

    .line 11
    .line 12
    if-eqz p1, :cond_0

    .line 13
    .line 14
    iget-object p0, p0, Lcom/salesforce/marketingcloud/http/e;->i:Landroid/content/BroadcastReceiver;

    .line 15
    .line 16
    if-eqz p0, :cond_0

    .line 17
    .line 18
    invoke-virtual {p1, p0}, Landroid/content/Context;->unregisterReceiver(Landroid/content/BroadcastReceiver;)V

    .line 19
    .line 20
    .line 21
    :cond_0
    return-void

    .line 22
    :catchall_0
    move-exception p0

    .line 23
    :try_start_1
    monitor-exit p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 24
    throw p0
.end method
