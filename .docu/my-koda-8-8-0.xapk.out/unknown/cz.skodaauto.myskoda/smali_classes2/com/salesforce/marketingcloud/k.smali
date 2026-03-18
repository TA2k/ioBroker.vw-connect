.class public Lcom/salesforce/marketingcloud/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/e;
.implements Lcom/salesforce/marketingcloud/behaviors/b;
.implements Lcom/salesforce/marketingcloud/http/e$c;
.implements Lcom/salesforce/marketingcloud/alarms/b$b;


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/k$e;,
        Lcom/salesforce/marketingcloud/k$f;
    }
.end annotation


# static fields
.field public static final n:Ljava/lang/String; = "_sync"

.field public static final o:Ljava/lang/String; = "_nodes"

.field private static final p:Ljava/lang/String;

.field private static final q:I = 0xca


# instance fields
.field protected final d:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

.field protected final e:Lcom/salesforce/marketingcloud/http/e;

.field protected final f:Lcom/salesforce/marketingcloud/storage/h;

.field protected final g:Ljava/lang/String;

.field private final h:Lcom/salesforce/marketingcloud/internal/n;

.field private final i:Lcom/salesforce/marketingcloud/behaviors/c;

.field private final j:Lcom/salesforce/marketingcloud/alarms/b;

.field private final k:Lcom/salesforce/marketingcloud/analytics/l;

.field protected l:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Lcom/salesforce/marketingcloud/k$e;",
            "Lcom/salesforce/marketingcloud/k$f;",
            ">;"
        }
    .end annotation
.end field

.field private m:Z


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "SyncRouteComponent"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/k;->p:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/http/e;Lcom/salesforce/marketingcloud/behaviors/c;Lcom/salesforce/marketingcloud/alarms/b;Lcom/salesforce/marketingcloud/internal/n;Lcom/salesforce/marketingcloud/analytics/l;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Landroidx/collection/f;

    .line 5
    .line 6
    invoke-static {}, Lcom/salesforce/marketingcloud/k$e;->values()[Lcom/salesforce/marketingcloud/k$e;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    array-length v1, v1

    .line 11
    invoke-direct {v0, v1}, Landroidx/collection/a1;-><init>(I)V

    .line 12
    .line 13
    .line 14
    iput-object v0, p0, Lcom/salesforce/marketingcloud/k;->l:Ljava/util/Map;

    .line 15
    .line 16
    iput-object p1, p0, Lcom/salesforce/marketingcloud/k;->g:Ljava/lang/String;

    .line 17
    .line 18
    iput-object p2, p0, Lcom/salesforce/marketingcloud/k;->d:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 19
    .line 20
    iput-object p3, p0, Lcom/salesforce/marketingcloud/k;->f:Lcom/salesforce/marketingcloud/storage/h;

    .line 21
    .line 22
    iput-object p5, p0, Lcom/salesforce/marketingcloud/k;->i:Lcom/salesforce/marketingcloud/behaviors/c;

    .line 23
    .line 24
    iput-object p4, p0, Lcom/salesforce/marketingcloud/k;->e:Lcom/salesforce/marketingcloud/http/e;

    .line 25
    .line 26
    iput-object p6, p0, Lcom/salesforce/marketingcloud/k;->j:Lcom/salesforce/marketingcloud/alarms/b;

    .line 27
    .line 28
    iput-object p7, p0, Lcom/salesforce/marketingcloud/k;->h:Lcom/salesforce/marketingcloud/internal/n;

    .line 29
    .line 30
    iput-object p8, p0, Lcom/salesforce/marketingcloud/k;->k:Lcom/salesforce/marketingcloud/analytics/l;

    .line 31
    .line 32
    return-void
.end method

.method private a()V
    .locals 4

    .line 11
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/k;->c()Z

    move-result v0

    if-eqz v0, :cond_0

    .line 12
    iget-object v0, p0, Lcom/salesforce/marketingcloud/k;->h:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v0

    new-instance v1, Lcom/salesforce/marketingcloud/k$a;

    const/4 v2, 0x0

    new-array v2, v2, [Ljava/lang/Object;

    const-string v3, "attempt_sync_route_request"

    invoke-direct {v1, p0, v3, v2}, Lcom/salesforce/marketingcloud/k$a;-><init>(Lcom/salesforce/marketingcloud/k;Ljava/lang/String;[Ljava/lang/Object;)V

    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    :cond_0
    return-void
.end method

.method private a(J)V
    .locals 3

    .line 23
    new-instance v0, Lorg/json/JSONObject;

    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 24
    :try_start_0
    sget-object v1, Lcom/salesforce/marketingcloud/analytics/l$a;->c:Lcom/salesforce/marketingcloud/analytics/l$a;

    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/analytics/l$a;->b()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v0, v2, p1, p2}, Lorg/json/JSONObject;->put(Ljava/lang/String;J)Lorg/json/JSONObject;

    .line 25
    invoke-static {}, Lcom/salesforce/marketingcloud/config/a;->g()Lcom/salesforce/marketingcloud/config/a;

    move-result-object p1

    if-eqz p1, :cond_0

    invoke-static {}, Lcom/salesforce/marketingcloud/config/a;->g()Lcom/salesforce/marketingcloud/config/a;

    move-result-object p1

    .line 26
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/config/a;->n()Z

    move-result p1

    if-eqz p1, :cond_0

    .line 27
    iget-object p0, p0, Lcom/salesforce/marketingcloud/k;->k:Lcom/salesforce/marketingcloud/analytics/l;

    invoke-interface {p0, v1, v0}, Lcom/salesforce/marketingcloud/analytics/l;->a(Lcom/salesforce/marketingcloud/analytics/l$a;Lorg/json/JSONObject;)V
    :try_end_0
    .catch Lorg/json/JSONException; {:try_start_0 .. :try_end_0} :catch_0

    :cond_0
    return-void

    :catch_0
    move-exception p0

    .line 28
    sget-object p1, Lcom/salesforce/marketingcloud/k;->p:Ljava/lang/String;

    const/4 p2, 0x0

    new-array p2, p2, [Ljava/lang/Object;

    const-string v0, "Failed to log TelemetryEvent for Sync Route"

    invoke-static {p1, p0, v0, p2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method private a(Ljava/lang/String;)V
    .locals 2

    if-eqz p1, :cond_0

    .line 9
    :try_start_0
    new-instance v0, Lorg/json/JSONArray;

    invoke-direct {v0, p1}, Lorg/json/JSONArray;-><init>(Ljava/lang/String;)V

    invoke-direct {p0, v0}, Lcom/salesforce/marketingcloud/k;->a(Lorg/json/JSONArray;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception p0

    .line 10
    sget-object p1, Lcom/salesforce/marketingcloud/k;->p:Ljava/lang/String;

    const/4 v0, 0x0

    new-array v0, v0, [Ljava/lang/Object;

    const-string v1, "Failed to parse sync push message"

    invoke-static {p1, p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    :cond_0
    return-void
.end method

.method private a(Lorg/json/JSONArray;)V
    .locals 1

    const/16 v0, 0xca

    .line 29
    invoke-direct {p0, p1, v0}, Lcom/salesforce/marketingcloud/k;->a(Lorg/json/JSONArray;I)V

    return-void
.end method

.method private a(Lorg/json/JSONArray;I)V
    .locals 11

    .line 30
    invoke-virtual {p1}, Lorg/json/JSONArray;->length()I

    move-result v0

    const/4 v1, 0x0

    move v2, v1

    :goto_0
    if-ge v2, v0, :cond_1

    .line 31
    invoke-virtual {p1, v2}, Lorg/json/JSONArray;->getJSONObject(I)Lorg/json/JSONObject;

    move-result-object v8

    .line 32
    :try_start_0
    const-string v3, "name"

    invoke-virtual {v8, v3}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v9
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_1

    .line 33
    :try_start_1
    invoke-static {v9}, Lcom/salesforce/marketingcloud/k$e;->valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/k$e;

    move-result-object v7

    const/16 v3, 0xca

    if-ne p2, v3, :cond_0

    .line 34
    sget-object v3, Lcom/salesforce/marketingcloud/k$e;->f:Lcom/salesforce/marketingcloud/k$e;

    if-eq v7, v3, :cond_0

    sget-object v3, Lcom/salesforce/marketingcloud/k$e;->b:Lcom/salesforce/marketingcloud/k$e;

    if-eq v7, v3, :cond_0

    move-object v4, p0

    goto :goto_2

    :catch_0
    move-object v4, p0

    goto :goto_1

    .line 35
    :cond_0
    iget-object v3, p0, Lcom/salesforce/marketingcloud/k;->h:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/internal/n;->a()Ljava/util/concurrent/ExecutorService;

    move-result-object v10

    new-instance v3, Lcom/salesforce/marketingcloud/k$c;

    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v4, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v5, "-sync_node_process"

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v5

    new-array v6, v1, [Ljava/lang/Object;
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    move-object v4, p0

    :try_start_2
    invoke-direct/range {v3 .. v8}, Lcom/salesforce/marketingcloud/k$c;-><init>(Lcom/salesforce/marketingcloud/k;Ljava/lang/String;[Ljava/lang/Object;Lcom/salesforce/marketingcloud/k$e;Lorg/json/JSONObject;)V

    invoke-interface {v10, v3}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_2

    goto :goto_2

    :catch_1
    move-object v4, p0

    const/4 v9, 0x0

    .line 36
    :catch_2
    :goto_1
    sget-object p0, Lcom/salesforce/marketingcloud/k;->p:Ljava/lang/String;

    filled-new-array {v9}, [Ljava/lang/Object;

    move-result-object v3

    const-string v5, "Failed to process node %s sync route"

    invoke-static {p0, v5, v3}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    :goto_2
    add-int/lit8 v2, v2, 0x1

    move-object p0, v4

    goto :goto_0

    :cond_1
    return-void
.end method

.method public static a(Ljava/util/Map;)Z
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;)Z"
        }
    .end annotation

    .line 1
    const-string v0, "_sync"

    invoke-interface {p0, v0}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_1

    const-string v0, "_nodes"

    invoke-interface {p0, v0}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result p0

    if-eqz p0, :cond_0

    goto :goto_0

    :cond_0
    const/4 p0, 0x0

    return p0

    :cond_1
    :goto_0
    const/4 p0, 0x1

    return p0
.end method

.method private c()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/k;->m:Z

    .line 2
    .line 3
    xor-int/lit8 p0, p0, 0x1

    .line 4
    .line 5
    return p0
.end method


# virtual methods
.method public a(Lcom/salesforce/marketingcloud/alarms/a$a;)V
    .locals 1

    .line 7
    sget-object v0, Lcom/salesforce/marketingcloud/alarms/a$a;->h:Lcom/salesforce/marketingcloud/alarms/a$a;

    if-ne p1, v0, :cond_0

    .line 8
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/k;->a()V

    :cond_0
    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/http/c;Lcom/salesforce/marketingcloud/http/f;)V
    .locals 2

    .line 13
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->p()Z

    move-result p1

    if-eqz p1, :cond_1

    .line 14
    iget-object p1, p0, Lcom/salesforce/marketingcloud/k;->j:Lcom/salesforce/marketingcloud/alarms/b;

    sget-object v0, Lcom/salesforce/marketingcloud/alarms/a$a;->h:Lcom/salesforce/marketingcloud/alarms/a$a;

    filled-new-array {v0}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    move-result-object v0

    invoke-virtual {p1, v0}, Lcom/salesforce/marketingcloud/alarms/b;->d([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 15
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->m()Ljava/util/Map;

    move-result-object p1

    iget-object v0, p0, Lcom/salesforce/marketingcloud/k;->f:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->c()Lcom/salesforce/marketingcloud/storage/b;

    move-result-object v0

    invoke-static {p1, v0}, Lcom/salesforce/marketingcloud/http/b;->a(Ljava/util/Map;Lcom/salesforce/marketingcloud/storage/b;)V

    .line 16
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->q()J

    move-result-wide v0

    invoke-direct {p0, v0, v1}, Lcom/salesforce/marketingcloud/k;->a(J)V

    .line 17
    :try_start_0
    new-instance p1, Lorg/json/JSONObject;

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->j()Ljava/lang/String;

    move-result-object v0

    invoke-direct {p1, v0}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V

    .line 18
    const-string v0, "nodes"

    invoke-virtual {p1, v0}, Lorg/json/JSONObject;->getJSONArray(Ljava/lang/String;)Lorg/json/JSONArray;

    move-result-object p1

    if-eqz p1, :cond_0

    .line 19
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->k()I

    move-result p2

    invoke-direct {p0, p1, p2}, Lcom/salesforce/marketingcloud/k;->a(Lorg/json/JSONArray;I)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    :cond_0
    return-void

    :catch_0
    move-exception p0

    .line 20
    sget-object p1, Lcom/salesforce/marketingcloud/k;->p:Ljava/lang/String;

    const/4 p2, 0x0

    new-array p2, p2, [Ljava/lang/Object;

    const-string v0, "Failed to parse /sync route response"

    invoke-static {p1, p0, v0, p2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void

    .line 21
    :cond_1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/k;->j:Lcom/salesforce/marketingcloud/alarms/b;

    sget-object p1, Lcom/salesforce/marketingcloud/alarms/a$a;->h:Lcom/salesforce/marketingcloud/alarms/a$a;

    filled-new-array {p1}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    move-result-object p1

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/alarms/b;->b([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 22
    sget-object p0, Lcom/salesforce/marketingcloud/k;->p:Ljava/lang/String;

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->n()Ljava/lang/String;

    move-result-object p1

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    const-string p2, "Sync route request failed with message: %s"

    invoke-static {p0, p2, p1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/k$e;Lcom/salesforce/marketingcloud/k$f;)V
    .locals 1

    .line 2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/k;->l:Ljava/util/Map;

    invoke-interface {v0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lcom/salesforce/marketingcloud/k$f;

    if-eqz v0, :cond_0

    if-eqz p2, :cond_0

    if-eq v0, p2, :cond_0

    .line 3
    sget-object p0, Lcom/salesforce/marketingcloud/k;->p:Ljava/lang/String;

    filled-new-array {p1, v0, p2}, [Ljava/lang/Object;

    move-result-object p1

    const-string p2, "Node %s already assigned to listener %s.  %s was not added for the Node."

    invoke-static {p0, p2, p1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void

    .line 4
    :cond_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/k;->l:Ljava/util/Map;

    invoke-interface {p0, p1, p2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

.method public a(Ljava/util/EnumSet;Lcom/salesforce/marketingcloud/k$f;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/EnumSet<",
            "Lcom/salesforce/marketingcloud/k$e;",
            ">;",
            "Lcom/salesforce/marketingcloud/k$f;",
            ")V"
        }
    .end annotation

    .line 5
    invoke-virtual {p1}, Ljava/util/AbstractCollection;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lcom/salesforce/marketingcloud/k$e;

    .line 6
    invoke-virtual {p0, v0, p2}, Lcom/salesforce/marketingcloud/k;->a(Lcom/salesforce/marketingcloud/k$e;Lcom/salesforce/marketingcloud/k$f;)V

    goto :goto_0

    :cond_0
    return-void
.end method

.method public b()Lcom/salesforce/marketingcloud/MarketingCloudSdk$WhenReadyListener;
    .locals 1

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/k$b;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lcom/salesforce/marketingcloud/k$b;-><init>(Lcom/salesforce/marketingcloud/k;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public componentName()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "SyncRoute"

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

.method public controlChannelInit(I)V
    .locals 2

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/b$c;->c:Lcom/salesforce/marketingcloud/b$c;

    .line 2
    .line 3
    iget v0, v0, Lcom/salesforce/marketingcloud/b$c;->b:I

    .line 4
    .line 5
    invoke-static {p1, v0}, Lcom/salesforce/marketingcloud/b;->a(II)Z

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    if-eqz p1, :cond_0

    .line 10
    .line 11
    iget-object p1, p0, Lcom/salesforce/marketingcloud/k;->i:Lcom/salesforce/marketingcloud/behaviors/c;

    .line 12
    .line 13
    invoke-virtual {p1, p0}, Lcom/salesforce/marketingcloud/behaviors/c;->a(Lcom/salesforce/marketingcloud/behaviors/b;)V

    .line 14
    .line 15
    .line 16
    iget-object p1, p0, Lcom/salesforce/marketingcloud/k;->e:Lcom/salesforce/marketingcloud/http/e;

    .line 17
    .line 18
    sget-object v0, Lcom/salesforce/marketingcloud/http/b;->q:Lcom/salesforce/marketingcloud/http/b;

    .line 19
    .line 20
    invoke-virtual {p1, v0}, Lcom/salesforce/marketingcloud/http/e;->a(Lcom/salesforce/marketingcloud/http/b;)V

    .line 21
    .line 22
    .line 23
    iget-object p1, p0, Lcom/salesforce/marketingcloud/k;->j:Lcom/salesforce/marketingcloud/alarms/b;

    .line 24
    .line 25
    sget-object v0, Lcom/salesforce/marketingcloud/alarms/a$a;->h:Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 26
    .line 27
    filled-new-array {v0}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    invoke-virtual {p1, v1}, Lcom/salesforce/marketingcloud/alarms/b;->e([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 32
    .line 33
    .line 34
    iget-object p1, p0, Lcom/salesforce/marketingcloud/k;->j:Lcom/salesforce/marketingcloud/alarms/b;

    .line 35
    .line 36
    filled-new-array {v0}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    invoke-virtual {p1, v0}, Lcom/salesforce/marketingcloud/alarms/b;->d([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 41
    .line 42
    .line 43
    const/4 p1, 0x1

    .line 44
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/k;->m:Z

    .line 45
    .line 46
    :cond_0
    return-void
.end method

.method public init(Lcom/salesforce/marketingcloud/InitializationStatus$a;I)V
    .locals 1

    .line 1
    sget-object p1, Lcom/salesforce/marketingcloud/b$c;->c:Lcom/salesforce/marketingcloud/b$c;

    .line 2
    .line 3
    iget p1, p1, Lcom/salesforce/marketingcloud/b$c;->b:I

    .line 4
    .line 5
    invoke-static {p2, p1}, Lcom/salesforce/marketingcloud/b;->a(II)Z

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    if-eqz p1, :cond_0

    .line 10
    .line 11
    const/4 p1, 0x1

    .line 12
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/k;->m:Z

    .line 13
    .line 14
    return-void

    .line 15
    :cond_0
    iget-object p1, p0, Lcom/salesforce/marketingcloud/k;->e:Lcom/salesforce/marketingcloud/http/e;

    .line 16
    .line 17
    sget-object p2, Lcom/salesforce/marketingcloud/http/b;->q:Lcom/salesforce/marketingcloud/http/b;

    .line 18
    .line 19
    invoke-virtual {p1, p2, p0}, Lcom/salesforce/marketingcloud/http/e;->a(Lcom/salesforce/marketingcloud/http/b;Lcom/salesforce/marketingcloud/http/e$c;)V

    .line 20
    .line 21
    .line 22
    iget-object p1, p0, Lcom/salesforce/marketingcloud/k;->i:Lcom/salesforce/marketingcloud/behaviors/c;

    .line 23
    .line 24
    sget-object p2, Lcom/salesforce/marketingcloud/behaviors/a;->i:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 25
    .line 26
    sget-object v0, Lcom/salesforce/marketingcloud/behaviors/a;->l:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 27
    .line 28
    invoke-static {p2, v0}, Ljava/util/EnumSet;->of(Ljava/lang/Enum;Ljava/lang/Enum;)Ljava/util/EnumSet;

    .line 29
    .line 30
    .line 31
    move-result-object p2

    .line 32
    invoke-virtual {p1, p0, p2}, Lcom/salesforce/marketingcloud/behaviors/c;->a(Lcom/salesforce/marketingcloud/behaviors/b;Ljava/util/EnumSet;)V

    .line 33
    .line 34
    .line 35
    iget-object p1, p0, Lcom/salesforce/marketingcloud/k;->j:Lcom/salesforce/marketingcloud/alarms/b;

    .line 36
    .line 37
    sget-object p2, Lcom/salesforce/marketingcloud/alarms/a$a;->h:Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 38
    .line 39
    filled-new-array {p2}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 40
    .line 41
    .line 42
    move-result-object p2

    .line 43
    invoke-virtual {p1, p0, p2}, Lcom/salesforce/marketingcloud/alarms/b;->a(Lcom/salesforce/marketingcloud/alarms/b$b;[Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 44
    .line 45
    .line 46
    return-void
.end method

.method public onBehavior(Lcom/salesforce/marketingcloud/behaviors/a;Landroid/os/Bundle;)V
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/k$d;->a:[I

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    aget p1, v0, p1

    .line 8
    .line 9
    const/4 v0, 0x1

    .line 10
    if-eq p1, v0, :cond_3

    .line 11
    .line 12
    const/4 v0, 0x2

    .line 13
    if-eq p1, v0, :cond_0

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    const-string p1, "_sync"

    .line 17
    .line 18
    invoke-virtual {p2, p1}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 19
    .line 20
    .line 21
    move-result p1

    .line 22
    if-eqz p1, :cond_1

    .line 23
    .line 24
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/k;->a()V

    .line 25
    .line 26
    .line 27
    return-void

    .line 28
    :cond_1
    const-string p1, "_nodes"

    .line 29
    .line 30
    invoke-virtual {p2, p1}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-eqz v0, :cond_2

    .line 35
    .line 36
    invoke-virtual {p2, p1}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/k;->a(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    :cond_2
    :goto_0
    return-void

    .line 44
    :cond_3
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/k;->a()V

    .line 45
    .line 46
    .line 47
    return-void
.end method

.method public tearDown(Z)V
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/k;->i:Lcom/salesforce/marketingcloud/behaviors/c;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/behaviors/c;->a(Lcom/salesforce/marketingcloud/behaviors/b;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcom/salesforce/marketingcloud/k;->e:Lcom/salesforce/marketingcloud/http/e;

    .line 7
    .line 8
    sget-object v1, Lcom/salesforce/marketingcloud/http/b;->q:Lcom/salesforce/marketingcloud/http/b;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Lcom/salesforce/marketingcloud/http/e;->a(Lcom/salesforce/marketingcloud/http/b;)V

    .line 11
    .line 12
    .line 13
    iget-object v0, p0, Lcom/salesforce/marketingcloud/k;->j:Lcom/salesforce/marketingcloud/alarms/b;

    .line 14
    .line 15
    sget-object v1, Lcom/salesforce/marketingcloud/alarms/a$a;->h:Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 16
    .line 17
    filled-new-array {v1}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    invoke-virtual {v0, v2}, Lcom/salesforce/marketingcloud/alarms/b;->e([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 22
    .line 23
    .line 24
    if-eqz p1, :cond_0

    .line 25
    .line 26
    iget-object p0, p0, Lcom/salesforce/marketingcloud/k;->j:Lcom/salesforce/marketingcloud/alarms/b;

    .line 27
    .line 28
    filled-new-array {v1}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/alarms/b;->d([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 33
    .line 34
    .line 35
    :cond_0
    return-void
.end method
