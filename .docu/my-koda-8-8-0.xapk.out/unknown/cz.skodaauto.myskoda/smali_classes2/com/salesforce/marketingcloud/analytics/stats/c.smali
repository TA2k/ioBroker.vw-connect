.class public Lcom/salesforce/marketingcloud/analytics/stats/c;
.super Lcom/salesforce/marketingcloud/analytics/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/http/e$c;
.implements Lcom/salesforce/marketingcloud/alarms/b$b;


# static fields
.field static final k:Ljava/lang/String;

.field private static final l:Ljava/lang/String; = "nodes"

.field private static final m:Ljava/lang/String; = "version"

.field private static final n:Ljava/lang/String; = "event"

.field private static final o:Ljava/lang/String; = "eventType"

.field private static final p:Ljava/lang/String; = "items"

.field private static final q:I = 0x3e7

.field private static final r:I = 0x1


# instance fields
.field public final d:Z

.field protected final e:Lcom/salesforce/marketingcloud/internal/n;

.field final f:Ljava/lang/String;

.field final g:Lcom/salesforce/marketingcloud/storage/h;

.field final h:Lcom/salesforce/marketingcloud/http/e;

.field final i:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

.field final j:Lcom/salesforce/marketingcloud/alarms/b;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "DeviceStats"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Ljava/lang/String;ZLcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/http/e;Lcom/salesforce/marketingcloud/alarms/b;Lcom/salesforce/marketingcloud/internal/n;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/analytics/i;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->i:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 5
    .line 6
    iput-object p2, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->f:Ljava/lang/String;

    .line 7
    .line 8
    iput-boolean p3, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->d:Z

    .line 9
    .line 10
    iput-object p4, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->g:Lcom/salesforce/marketingcloud/storage/h;

    .line 11
    .line 12
    iput-object p5, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->h:Lcom/salesforce/marketingcloud/http/e;

    .line 13
    .line 14
    iput-object p6, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->j:Lcom/salesforce/marketingcloud/alarms/b;

    .line 15
    .line 16
    iput-object p7, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->e:Lcom/salesforce/marketingcloud/internal/n;

    .line 17
    .line 18
    sget-object p1, Lcom/salesforce/marketingcloud/http/b;->r:Lcom/salesforce/marketingcloud/http/b;

    .line 19
    .line 20
    invoke-virtual {p5, p1, p0}, Lcom/salesforce/marketingcloud/http/e;->a(Lcom/salesforce/marketingcloud/http/b;Lcom/salesforce/marketingcloud/http/e$c;)V

    .line 21
    .line 22
    .line 23
    sget-object p1, Lcom/salesforce/marketingcloud/http/b;->s:Lcom/salesforce/marketingcloud/http/b;

    .line 24
    .line 25
    invoke-virtual {p5, p1, p0}, Lcom/salesforce/marketingcloud/http/e;->a(Lcom/salesforce/marketingcloud/http/b;Lcom/salesforce/marketingcloud/http/e$c;)V

    .line 26
    .line 27
    .line 28
    sget-object p1, Lcom/salesforce/marketingcloud/alarms/a$a;->j:Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 29
    .line 30
    sget-object p2, Lcom/salesforce/marketingcloud/alarms/a$a;->k:Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 31
    .line 32
    filled-new-array {p1, p2}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    invoke-virtual {p6, p0, p1}, Lcom/salesforce/marketingcloud/alarms/b;->a(Lcom/salesforce/marketingcloud/alarms/b$b;[Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 37
    .line 38
    .line 39
    return-void
.end method

.method public static a(Lcom/salesforce/marketingcloud/storage/h;Z)V
    .locals 0

    if-eqz p1, :cond_0

    .line 1
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->i()Lcom/salesforce/marketingcloud/storage/c;

    move-result-object p0

    invoke-interface {p0}, Lcom/salesforce/marketingcloud/storage/c;->f()I

    :cond_0
    return-void
.end method


# virtual methods
.method public a(Ljava/util/List;I)Ljava/util/Map;
    .locals 17
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/analytics/stats/b;",
            ">;I)",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Lorg/json/JSONArray;",
            ">;"
        }
    .end annotation

    move/from16 v1, p2

    .line 114
    invoke-interface/range {p1 .. p1}, Ljava/util/List;->size()I

    move-result v2

    int-to-double v3, v2

    int-to-double v5, v1

    div-double/2addr v3, v5

    .line 115
    invoke-static {v3, v4}, Ljava/lang/Math;->ceil(D)D

    move-result-wide v3

    double-to-int v3, v3

    .line 116
    new-instance v4, Landroidx/collection/f;

    .line 117
    invoke-direct {v4, v3}, Landroidx/collection/a1;-><init>(I)V

    const/4 v6, 0x0

    :goto_0
    if-ge v6, v3, :cond_3

    .line 118
    new-instance v7, Ljava/lang/StringBuilder;

    invoke-direct {v7}, Ljava/lang/StringBuilder;-><init>()V

    .line 119
    new-instance v8, Lorg/json/JSONArray;

    invoke-direct {v8}, Lorg/json/JSONArray;-><init>()V

    mul-int v9, v6, v1

    const/4 v0, 0x1

    move v10, v9

    :goto_1
    if-ge v10, v2, :cond_2

    add-int v11, v9, v1

    if-ge v10, v11, :cond_2

    move-object/from16 v11, p1

    .line 120
    invoke-interface {v11, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v12

    check-cast v12, Lcom/salesforce/marketingcloud/analytics/stats/b;

    if-eqz v0, :cond_0

    const/4 v13, 0x0

    goto :goto_2

    :cond_0
    const/16 v13, 0x2c

    .line 121
    invoke-virtual {v7, v13}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    move v13, v0

    .line 122
    :goto_2
    invoke-virtual {v12}, Lcom/salesforce/marketingcloud/analytics/stats/b;->b()Ljava/lang/Integer;

    move-result-object v0

    invoke-virtual {v7, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 123
    new-instance v0, Lorg/json/JSONObject;

    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 124
    :try_start_0
    const-string v14, "eventType"

    invoke-virtual {v12}, Lcom/salesforce/marketingcloud/analytics/stats/b;->d()I

    move-result v15

    invoke-virtual {v0, v14, v15}, Lorg/json/JSONObject;->put(Ljava/lang/String;I)Lorg/json/JSONObject;

    .line 125
    invoke-virtual {v12}, Lcom/salesforce/marketingcloud/analytics/stats/b;->d()I

    move-result v14

    const/16 v15, 0x70

    if-ne v14, v15, :cond_1

    .line 126
    invoke-virtual {v12}, Lcom/salesforce/marketingcloud/analytics/stats/b;->c()Lcom/salesforce/marketingcloud/analytics/stats/d;

    move-result-object v14

    iget-object v14, v14, Lcom/salesforce/marketingcloud/analytics/stats/d;->a:Lorg/json/JSONObject;

    const-string v15, "receiptDateUtc"

    new-instance v16, Ljava/util/Date;

    invoke-direct/range {v16 .. v16}, Ljava/util/Date;-><init>()V

    .line 127
    invoke-static/range {v16 .. v16}, Lcom/salesforce/marketingcloud/util/j;->a(Ljava/util/Date;)Ljava/lang/String;

    move-result-object v5

    .line 128
    invoke-virtual {v14, v15, v5}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    goto :goto_3

    :catch_0
    move-exception v0

    goto :goto_4

    .line 129
    :cond_1
    :goto_3
    const-string v5, "event"

    invoke-virtual {v12}, Lcom/salesforce/marketingcloud/analytics/stats/b;->c()Lcom/salesforce/marketingcloud/analytics/stats/d;

    move-result-object v12

    iget-object v12, v12, Lcom/salesforce/marketingcloud/analytics/stats/d;->a:Lorg/json/JSONObject;

    invoke-virtual {v0, v5, v12}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 130
    invoke-virtual {v8, v0}, Lorg/json/JSONArray;->put(Ljava/lang/Object;)Lorg/json/JSONArray;
    :try_end_0
    .catch Lorg/json/JSONException; {:try_start_0 .. :try_end_0} :catch_0

    const/4 v12, 0x0

    goto :goto_5

    .line 131
    :goto_4
    sget-object v5, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    const/4 v12, 0x0

    new-array v14, v12, [Ljava/lang/Object;

    const-string v15, "Unable to add device stats to payload."

    invoke-static {v5, v0, v15, v14}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    :goto_5
    add-int/lit8 v10, v10, 0x1

    move v0, v13

    goto :goto_1

    :cond_2
    move-object/from16 v11, p1

    const/4 v12, 0x0

    .line 132
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-interface {v4, v0, v8}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    add-int/lit8 v6, v6, 0x1

    goto/16 :goto_0

    :cond_3
    return-object v4
.end method

.method public a()V
    .locals 1

    .line 111
    sget-object v0, Lcom/salesforce/marketingcloud/http/b;->r:Lcom/salesforce/marketingcloud/http/b;

    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/analytics/stats/c;->a(Lcom/salesforce/marketingcloud/http/b;)V

    .line 112
    sget-object v0, Lcom/salesforce/marketingcloud/http/b;->s:Lcom/salesforce/marketingcloud/http/b;

    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/analytics/stats/c;->a(Lcom/salesforce/marketingcloud/http/b;)V

    return-void
.end method

.method public a(J)V
    .locals 2

    .line 26
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->e:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object p1

    new-instance p2, Lcom/salesforce/marketingcloud/analytics/stats/c$a;

    const/4 v0, 0x0

    new-array v0, v0, [Ljava/lang/Object;

    const-string v1, "stats_app_close"

    invoke-direct {p2, p0, v1, v0}, Lcom/salesforce/marketingcloud/analytics/stats/c$a;-><init>(Lcom/salesforce/marketingcloud/analytics/stats/c;Ljava/lang/String;[Ljava/lang/Object;)V

    invoke-interface {p1, p2}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/alarms/a$a;)V
    .locals 2

    .line 23
    sget-object v0, Lcom/salesforce/marketingcloud/alarms/a$a;->j:Lcom/salesforce/marketingcloud/alarms/a$a;

    if-eq p1, v0, :cond_1

    sget-object v0, Lcom/salesforce/marketingcloud/alarms/a$a;->k:Lcom/salesforce/marketingcloud/alarms/a$a;

    if-ne p1, v0, :cond_0

    goto :goto_0

    :cond_0
    return-void

    .line 24
    :cond_1
    :goto_0
    sget-object v0, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    invoke-virtual {p1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object p1

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    const-string v1, "Handling alarm to send stats type [%s]"

    invoke-static {v0, v1, p1}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 25
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/analytics/stats/c;->a()V

    return-void
.end method

.method public varargs a(Lcom/salesforce/marketingcloud/analytics/e;[Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;)V
    .locals 9

    const/4 v1, 0x0

    .line 108
    :try_start_0
    new-instance v7, Ljava/util/Date;

    invoke-direct {v7}, Ljava/util/Date;-><init>()V

    .line 109
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->e:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v0

    new-instance v2, Lcom/salesforce/marketingcloud/analytics/stats/c$f;

    const-string v4, "track_events"

    new-array v5, v1, [Ljava/lang/Object;

    move-object v3, p0

    move-object v8, p1

    move-object v6, p2

    invoke-direct/range {v2 .. v8}, Lcom/salesforce/marketingcloud/analytics/stats/c$f;-><init>(Lcom/salesforce/marketingcloud/analytics/stats/c;Ljava/lang/String;[Ljava/lang/Object;[Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;Ljava/util/Date;Lcom/salesforce/marketingcloud/analytics/e;)V

    invoke-interface {v0, v2}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception v0

    move-object p0, v0

    .line 110
    sget-object p1, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    new-array p2, v1, [Ljava/lang/Object;

    const-string v0, "Failed to record iam displayed event stat."

    invoke-static {p1, p0, v0, p2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/analytics/l$a;Lorg/json/JSONObject;)V
    .locals 7

    .line 106
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->e:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v0

    new-instance v1, Lcom/salesforce/marketingcloud/analytics/stats/c$e;

    const-string v3, "onTelemetryEvent"

    const/4 v2, 0x0

    new-array v4, v2, [Ljava/lang/Object;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_1

    move-object v2, p0

    move-object v6, p1

    move-object v5, p2

    :try_start_1
    invoke-direct/range {v1 .. v6}, Lcom/salesforce/marketingcloud/analytics/stats/c$e;-><init>(Lcom/salesforce/marketingcloud/analytics/stats/c;Ljava/lang/String;[Ljava/lang/Object;Lorg/json/JSONObject;Lcom/salesforce/marketingcloud/analytics/l$a;)V

    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    return-void

    :catch_0
    move-exception v0

    :goto_0
    move-object p0, v0

    goto :goto_1

    :catch_1
    move-exception v0

    move-object v6, p1

    goto :goto_0

    .line 107
    :goto_1
    sget-object p1, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    invoke-virtual {v6}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object p2

    filled-new-array {p2}, [Ljava/lang/Object;

    move-result-object p2

    const-string v0, "Failed to track onTelemetryEvent stat. %s"

    invoke-static {p1, p0, v0, p2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/http/b;)V
    .locals 4

    .line 113
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->e:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v0

    new-instance v1, Lcom/salesforce/marketingcloud/analytics/stats/c$h;

    const/4 v2, 0x0

    new-array v2, v2, [Ljava/lang/Object;

    const-string v3, "send_stats"

    invoke-direct {v1, p0, v3, v2, p1}, Lcom/salesforce/marketingcloud/analytics/stats/c$h;-><init>(Lcom/salesforce/marketingcloud/analytics/stats/c;Ljava/lang/String;[Ljava/lang/Object;Lcom/salesforce/marketingcloud/http/b;)V

    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/http/c;Lcom/salesforce/marketingcloud/http/f;)V
    .locals 2

    .line 6
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->p()Z

    move-result v0

    if-eqz v0, :cond_2

    .line 7
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/http/c;->q()Lcom/salesforce/marketingcloud/http/b;

    move-result-object p2

    sget-object v0, Lcom/salesforce/marketingcloud/http/b;->r:Lcom/salesforce/marketingcloud/http/b;

    if-ne p2, v0, :cond_0

    .line 8
    iget-object p2, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->j:Lcom/salesforce/marketingcloud/alarms/b;

    sget-object v0, Lcom/salesforce/marketingcloud/alarms/a$a;->j:Lcom/salesforce/marketingcloud/alarms/a$a;

    filled-new-array {v0}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    move-result-object v0

    invoke-virtual {p2, v0}, Lcom/salesforce/marketingcloud/alarms/b;->c([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    goto :goto_0

    .line 9
    :cond_0
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/http/c;->q()Lcom/salesforce/marketingcloud/http/b;

    move-result-object p2

    sget-object v0, Lcom/salesforce/marketingcloud/http/b;->s:Lcom/salesforce/marketingcloud/http/b;

    if-ne p2, v0, :cond_1

    .line 10
    iget-object p2, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->j:Lcom/salesforce/marketingcloud/alarms/b;

    sget-object v0, Lcom/salesforce/marketingcloud/alarms/a$a;->k:Lcom/salesforce/marketingcloud/alarms/a$a;

    filled-new-array {v0}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    move-result-object v0

    invoke-virtual {p2, v0}, Lcom/salesforce/marketingcloud/alarms/b;->c([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 11
    :cond_1
    :goto_0
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/http/c;->r()Ljava/lang/String;

    move-result-object p2

    if-eqz p2, :cond_5

    .line 12
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/http/c;->r()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Lcom/salesforce/marketingcloud/analytics/c;->a(Ljava/lang/String;)[Ljava/lang/String;

    move-result-object p1

    .line 13
    sget-object p2, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    invoke-static {p1}, Ljava/util/Arrays;->toString([Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    filled-new-array {v0}, [Ljava/lang/Object;

    move-result-object v0

    const-string v1, "Removing events %s from DB"

    invoke-static {p2, v1, v0}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 14
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->g:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->i()Lcom/salesforce/marketingcloud/storage/c;

    move-result-object p0

    invoke-interface {p0, p1}, Lcom/salesforce/marketingcloud/storage/c;->c([Ljava/lang/String;)V

    return-void

    .line 15
    :cond_2
    sget-object v0, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->k()I

    move-result v1

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->n()Ljava/lang/String;

    move-result-object p2

    filled-new-array {v1, p2}, [Ljava/lang/Object;

    move-result-object p2

    const-string v1, "Request failed: %d - %s"

    invoke-static {v0, v1, p2}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 16
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/http/c;->q()Lcom/salesforce/marketingcloud/http/b;

    move-result-object p2

    sget-object v0, Lcom/salesforce/marketingcloud/http/b;->r:Lcom/salesforce/marketingcloud/http/b;

    if-ne p2, v0, :cond_3

    .line 17
    iget-object p2, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->j:Lcom/salesforce/marketingcloud/alarms/b;

    sget-object v0, Lcom/salesforce/marketingcloud/alarms/a$a;->j:Lcom/salesforce/marketingcloud/alarms/a$a;

    filled-new-array {v0}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    move-result-object v0

    invoke-virtual {p2, v0}, Lcom/salesforce/marketingcloud/alarms/b;->b([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    goto :goto_1

    .line 18
    :cond_3
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/http/c;->q()Lcom/salesforce/marketingcloud/http/b;

    move-result-object p2

    sget-object v0, Lcom/salesforce/marketingcloud/http/b;->s:Lcom/salesforce/marketingcloud/http/b;

    if-ne p2, v0, :cond_4

    .line 19
    iget-object p2, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->j:Lcom/salesforce/marketingcloud/alarms/b;

    sget-object v0, Lcom/salesforce/marketingcloud/alarms/a$a;->k:Lcom/salesforce/marketingcloud/alarms/a$a;

    filled-new-array {v0}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    move-result-object v0

    invoke-virtual {p2, v0}, Lcom/salesforce/marketingcloud/alarms/b;->b([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 20
    :cond_4
    :goto_1
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/http/c;->r()Ljava/lang/String;

    move-result-object p2

    if-eqz p2, :cond_5

    .line 21
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/http/c;->r()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Lcom/salesforce/marketingcloud/analytics/c;->a(Ljava/lang/String;)[Ljava/lang/String;

    move-result-object p1

    .line 22
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->g:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->i()Lcom/salesforce/marketingcloud/storage/c;

    move-result-object p0

    invoke-interface {p0, p1}, Lcom/salesforce/marketingcloud/storage/c;->d([Ljava/lang/String;)V

    :cond_5
    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)V
    .locals 6

    .line 91
    :try_start_0
    sget-object v0, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    const-string v1, "InAppMessage displayed event stat for message id %s"

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->id()Ljava/lang/String;

    move-result-object v2

    filled-new-array {v2}, [Ljava/lang/Object;

    move-result-object v2

    invoke-static {v0, v1, v2}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 92
    new-instance v0, Ljava/util/Date;

    invoke-direct {v0}, Ljava/util/Date;-><init>()V

    .line 93
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->i:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 94
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->applicationId()Ljava/lang/String;

    move-result-object v1

    iget-object v2, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->f:Ljava/lang/String;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->id()Ljava/lang/String;

    move-result-object v3

    .line 95
    invoke-static {p1}, Lcom/salesforce/marketingcloud/internal/c;->a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)Ljava/lang/String;

    move-result-object p1

    .line 96
    invoke-static {v1, v2, v0, v3, p1}, Lcom/salesforce/marketingcloud/analytics/stats/d;->a(Ljava/lang/String;Ljava/lang/String;Ljava/util/Date;Ljava/lang/String;Ljava/lang/String;)Lcom/salesforce/marketingcloud/analytics/stats/d;

    move-result-object p1

    .line 97
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->e:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v1

    new-instance v2, Lcom/salesforce/marketingcloud/analytics/stats/a;

    iget-object v3, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->g:Lcom/salesforce/marketingcloud/storage/h;

    .line 98
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/storage/h;->i()Lcom/salesforce/marketingcloud/storage/c;

    move-result-object v3

    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->g:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    move-result-object p0

    const/16 v4, 0x68

    const/4 v5, 0x1

    .line 99
    invoke-static {v4, v0, p1, v5}, Lcom/salesforce/marketingcloud/analytics/stats/b;->a(ILjava/util/Date;Lcom/salesforce/marketingcloud/analytics/stats/d;Z)Lcom/salesforce/marketingcloud/analytics/stats/b;

    move-result-object p1

    invoke-direct {v2, v3, p0, p1}, Lcom/salesforce/marketingcloud/analytics/stats/a;-><init>(Lcom/salesforce/marketingcloud/storage/c;Lcom/salesforce/marketingcloud/util/Crypto;Lcom/salesforce/marketingcloud/analytics/stats/b;)V

    .line 100
    invoke-interface {v1, v2}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception p0

    .line 101
    sget-object p1, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    const/4 v0, 0x0

    new-array v0, v0, [Ljava/lang/Object;

    const-string v1, "Failed to record iam displayed event stat."

    invoke-static {p1, p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;Lcom/salesforce/marketingcloud/messages/iam/j;)V
    .locals 16

    move-object/from16 v0, p0

    .line 27
    iget-boolean v1, v0, Lcom/salesforce/marketingcloud/analytics/stats/c;->d:Z

    const/4 v2, 0x0

    if-nez v1, :cond_0

    .line 28
    sget-object v0, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    new-array v1, v2, [Ljava/lang/Object;

    const-string v2, "Track user is false. Ignoring onInAppMessageCompleted event."

    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void

    .line 29
    :cond_0
    :try_start_0
    sget-object v1, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    const-string v3, "Creating display event stat for message id %s"

    invoke-virtual/range {p1 .. p1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->id()Ljava/lang/String;

    move-result-object v4

    filled-new-array {v4}, [Ljava/lang/Object;

    move-result-object v4

    invoke-static {v1, v3, v4}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 30
    invoke-virtual/range {p2 .. p2}, Lcom/salesforce/marketingcloud/messages/iam/j;->h()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;

    move-result-object v1

    .line 31
    invoke-virtual/range {p2 .. p2}, Lcom/salesforce/marketingcloud/messages/iam/j;->l()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    move-result v4

    const v5, -0x37bd8446

    const/4 v6, 0x1

    if-eq v4, v5, :cond_2

    const v5, 0x7e31e495

    if-eq v4, v5, :cond_1

    goto :goto_0

    :cond_1
    const-string v4, "buttonClicked"

    invoke-virtual {v3, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_3

    move v3, v6

    goto :goto_1

    :catch_0
    move-exception v0

    goto/16 :goto_4

    .line 32
    :cond_2
    const-string v4, "autoDismissed"

    invoke-virtual {v3, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_3

    move v3, v2

    goto :goto_1

    :cond_3
    :goto_0
    const/4 v3, -0x1

    :goto_1
    const/4 v4, 0x0

    if-eqz v3, :cond_4

    if-eq v3, v6, :cond_5

    const/4 v6, 0x3

    :cond_4
    :goto_2
    move-object v15, v4

    move v14, v6

    goto :goto_3

    :cond_5
    if-eqz v1, :cond_6

    .line 33
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->id()Ljava/lang/String;

    move-result-object v4

    :cond_6
    const/4 v6, 0x2

    goto :goto_2

    .line 34
    :goto_3
    new-instance v9, Ljava/util/Date;

    invoke-virtual/range {p2 .. p2}, Lcom/salesforce/marketingcloud/messages/iam/j;->k()Ljava/util/Date;

    move-result-object v1

    invoke-virtual {v1}, Ljava/util/Date;->getTime()J

    move-result-wide v3

    invoke-virtual/range {p2 .. p2}, Lcom/salesforce/marketingcloud/messages/iam/j;->j()J

    move-result-wide v5

    add-long/2addr v3, v5

    invoke-direct {v9, v3, v4}, Ljava/util/Date;-><init>(J)V

    .line 35
    iget-object v1, v0, Lcom/salesforce/marketingcloud/analytics/stats/c;->i:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 36
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->applicationId()Ljava/lang/String;

    move-result-object v7

    iget-object v8, v0, Lcom/salesforce/marketingcloud/analytics/stats/c;->f:Ljava/lang/String;

    invoke-virtual/range {p1 .. p1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->id()Ljava/lang/String;

    move-result-object v10

    .line 37
    invoke-static/range {p1 .. p1}, Lcom/salesforce/marketingcloud/internal/c;->a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)Ljava/lang/String;

    move-result-object v11

    .line 38
    invoke-virtual/range {p2 .. p2}, Lcom/salesforce/marketingcloud/messages/iam/j;->j()J

    move-result-wide v3

    long-to-double v3, v3

    const-wide v5, 0x408f400000000000L    # 1000.0

    div-double/2addr v3, v5

    invoke-static {v3, v4}, Ljava/lang/Math;->ceil(D)D

    move-result-wide v3

    double-to-long v12, v3

    .line 39
    invoke-static/range {v7 .. v15}, Lcom/salesforce/marketingcloud/analytics/stats/d;->a(Ljava/lang/String;Ljava/lang/String;Ljava/util/Date;Ljava/lang/String;Ljava/lang/String;JILjava/lang/String;)Lcom/salesforce/marketingcloud/analytics/stats/d;

    move-result-object v1

    .line 40
    iget-object v3, v0, Lcom/salesforce/marketingcloud/analytics/stats/c;->e:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v3

    new-instance v4, Lcom/salesforce/marketingcloud/analytics/stats/a;

    iget-object v5, v0, Lcom/salesforce/marketingcloud/analytics/stats/c;->g:Lcom/salesforce/marketingcloud/storage/h;

    .line 41
    invoke-virtual {v5}, Lcom/salesforce/marketingcloud/storage/h;->i()Lcom/salesforce/marketingcloud/storage/c;

    move-result-object v5

    iget-object v0, v0, Lcom/salesforce/marketingcloud/analytics/stats/c;->g:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    move-result-object v0

    const/16 v6, 0x64

    .line 42
    invoke-static {v6, v9, v1, v2}, Lcom/salesforce/marketingcloud/analytics/stats/b;->a(ILjava/util/Date;Lcom/salesforce/marketingcloud/analytics/stats/d;Z)Lcom/salesforce/marketingcloud/analytics/stats/b;

    move-result-object v1

    invoke-direct {v4, v5, v0, v1}, Lcom/salesforce/marketingcloud/analytics/stats/a;-><init>(Lcom/salesforce/marketingcloud/storage/c;Lcom/salesforce/marketingcloud/util/Crypto;Lcom/salesforce/marketingcloud/analytics/stats/b;)V

    .line 43
    invoke-interface {v3, v4}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    .line 44
    :goto_4
    sget-object v1, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    new-array v2, v2, [Ljava/lang/Object;

    const-string v3, "Failed to record analytic event for In App Message Displayed"

    invoke-static {v1, v0, v3, v2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;Lorg/json/JSONObject;)V
    .locals 8

    const/4 v1, 0x0

    .line 102
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->e:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v0

    new-instance v2, Lcom/salesforce/marketingcloud/analytics/stats/c$b;

    const-string v4, "onInAppMessageThrottled"

    new-array v5, v1, [Ljava/lang/Object;

    move-object v3, p0

    move-object v6, p1

    move-object v7, p2

    invoke-direct/range {v2 .. v7}, Lcom/salesforce/marketingcloud/analytics/stats/c$b;-><init>(Lcom/salesforce/marketingcloud/analytics/stats/c;Ljava/lang/String;[Ljava/lang/Object;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;Lorg/json/JSONObject;)V

    invoke-interface {v0, v2}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception v0

    move-object p0, v0

    .line 103
    sget-object p1, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    new-array p2, v1, [Ljava/lang/Object;

    const-string v0, "Failed to track iam throttled event stat."

    invoke-static {p1, p0, v0, p2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;ILjava/lang/String;Ljava/lang/String;)V
    .locals 10

    .line 58
    iget-boolean v0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->d:Z

    const/4 v1, 0x0

    if-nez v0, :cond_0

    .line 59
    sget-object p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    new-array p1, v1, [Ljava/lang/Object;

    const-string p2, "Track user is false.  Ignoring recordNotificationMessageClicked event or message is null."

    invoke-static {p0, p2, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void

    :cond_0
    if-nez p1, :cond_1

    .line 60
    sget-object p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    new-array p1, v1, [Ljava/lang/Object;

    const-string p2, "NotificationMessage is null. Ignoring recordNotificationMessageClicked event."

    invoke-static {p0, p2, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void

    .line 61
    :cond_1
    :try_start_0
    new-instance v4, Ljava/util/Date;

    invoke-direct {v4}, Ljava/util/Date;-><init>()V

    .line 62
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->i:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 63
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->applicationId()Ljava/lang/String;

    move-result-object v2

    iget-object v3, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->f:Ljava/lang/String;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->id()Ljava/lang/String;

    move-result-object v5

    iget-object v7, p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->requestId:Ljava/lang/String;

    .line 64
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->propertyBag()Ljava/lang/String;

    move-result-object v8

    move-object v6, p3

    move-object v9, p4

    .line 65
    invoke-static/range {v2 .. v9}, Lcom/salesforce/marketingcloud/analytics/stats/d;->a(Ljava/lang/String;Ljava/lang/String;Ljava/util/Date;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lcom/salesforce/marketingcloud/analytics/stats/d;

    move-result-object p1

    .line 66
    iget-object p3, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->e:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {p3}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object p3

    new-instance p4, Lcom/salesforce/marketingcloud/analytics/stats/a;

    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->g:Lcom/salesforce/marketingcloud/storage/h;

    .line 67
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->i()Lcom/salesforce/marketingcloud/storage/c;

    move-result-object v0

    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->g:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    move-result-object p0

    const/4 v2, 0x1

    .line 68
    invoke-static {p2, v4, p1, v2}, Lcom/salesforce/marketingcloud/analytics/stats/b;->a(ILjava/util/Date;Lcom/salesforce/marketingcloud/analytics/stats/d;Z)Lcom/salesforce/marketingcloud/analytics/stats/b;

    move-result-object p1

    invoke-direct {p4, v0, p0, p1}, Lcom/salesforce/marketingcloud/analytics/stats/a;-><init>(Lcom/salesforce/marketingcloud/storage/c;Lcom/salesforce/marketingcloud/util/Crypto;Lcom/salesforce/marketingcloud/analytics/stats/b;)V

    .line 69
    invoke-interface {p3, p4}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception v0

    move-object p0, v0

    .line 70
    sget-object p1, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    new-array p2, v1, [Ljava/lang/Object;

    const-string p3, "Failed to record analytic event for recordNotificationMessageClicked"

    invoke-static {p1, p0, p3, p2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/push/f;Ljava/lang/String;)V
    .locals 9

    .line 45
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/push/f;->getMessage()Ljava/lang/String;

    move-result-object v0

    .line 46
    iget-boolean v1, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->d:Z

    const/4 v2, 0x0

    if-eqz v1, :cond_1

    if-nez v0, :cond_0

    goto :goto_0

    .line 47
    :cond_0
    :try_start_0
    new-instance v5, Ljava/util/Date;

    invoke-direct {v5}, Ljava/util/Date;-><init>()V

    .line 48
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->i:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 49
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->applicationId()Ljava/lang/String;

    move-result-object v3

    iget-object v4, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->f:Ljava/lang/String;

    .line 50
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/push/f;->b()Lorg/json/JSONObject;

    move-result-object v8

    const/4 v7, 0x0

    move-object v6, p2

    .line 51
    invoke-static/range {v3 .. v8}, Lcom/salesforce/marketingcloud/analytics/stats/d;->a(Ljava/lang/String;Ljava/lang/String;Ljava/util/Date;Ljava/lang/String;Ljava/lang/String;Lorg/json/JSONObject;)Lcom/salesforce/marketingcloud/analytics/stats/d;

    move-result-object p1

    .line 52
    iget-object p2, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->e:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object p2

    new-instance v0, Lcom/salesforce/marketingcloud/analytics/stats/a;

    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->g:Lcom/salesforce/marketingcloud/storage/h;

    .line 53
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/storage/h;->i()Lcom/salesforce/marketingcloud/storage/c;

    move-result-object v1

    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->g:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    move-result-object p0

    const/16 v3, 0x6a

    const/4 v4, 0x1

    .line 54
    invoke-static {v3, v5, p1, v4}, Lcom/salesforce/marketingcloud/analytics/stats/b;->a(ILjava/util/Date;Lcom/salesforce/marketingcloud/analytics/stats/d;Z)Lcom/salesforce/marketingcloud/analytics/stats/b;

    move-result-object p1

    invoke-direct {v0, v1, p0, p1}, Lcom/salesforce/marketingcloud/analytics/stats/a;-><init>(Lcom/salesforce/marketingcloud/storage/c;Lcom/salesforce/marketingcloud/util/Crypto;Lcom/salesforce/marketingcloud/analytics/stats/b;)V

    .line 55
    invoke-interface {p2, v0}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception v0

    move-object p0, v0

    .line 56
    sget-object p1, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    new-array p2, v2, [Ljava/lang/Object;

    const-string v0, "Failed to record analytic event for Push Notification Error"

    invoke-static {p1, p0, v0, p2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void

    .line 57
    :cond_1
    :goto_0
    sget-object p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    new-array p1, v2, [Ljava/lang/Object;

    const-string p2, "Track user is false.  Ignoring PushNotificationError event."

    invoke-static {p0, p2, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public a(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 11

    .line 71
    iget-boolean v0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->d:Z

    const/4 v1, 0x0

    if-nez v0, :cond_0

    .line 72
    sget-object p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    new-array p1, v1, [Ljava/lang/Object;

    const-string p2, "Track user is false.  Ignoring onTriggerSuccessEvent event."

    invoke-static {p0, p2, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void

    .line 73
    :cond_0
    sget-object v0, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object v2

    const-string v3, "Creating trigger event stat for message id %s"

    invoke-static {v0, v3, v2}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 74
    :try_start_0
    new-instance v6, Ljava/util/Date;

    invoke-direct {v6}, Ljava/util/Date;-><init>()V

    .line 75
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->i:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 76
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->applicationId()Ljava/lang/String;

    move-result-object v4

    iget-object v5, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->f:Ljava/lang/String;

    move-object v9, p1

    move-object v7, p2

    move-object v10, p3

    move-object v8, p4

    invoke-static/range {v4 .. v10}, Lcom/salesforce/marketingcloud/analytics/stats/d;->a(Ljava/lang/String;Ljava/lang/String;Ljava/util/Date;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lcom/salesforce/marketingcloud/analytics/stats/d;

    move-result-object p1

    .line 77
    iget-object p2, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->e:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object p2

    new-instance p3, Lcom/salesforce/marketingcloud/analytics/stats/a;

    iget-object p4, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->g:Lcom/salesforce/marketingcloud/storage/h;

    .line 78
    invoke-virtual {p4}, Lcom/salesforce/marketingcloud/storage/h;->i()Lcom/salesforce/marketingcloud/storage/c;

    move-result-object p4

    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->g:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    move-result-object p0

    const/16 v0, 0x66

    const/4 v2, 0x1

    .line 79
    invoke-static {v0, v6, p1, v2}, Lcom/salesforce/marketingcloud/analytics/stats/b;->a(ILjava/util/Date;Lcom/salesforce/marketingcloud/analytics/stats/d;Z)Lcom/salesforce/marketingcloud/analytics/stats/b;

    move-result-object p1

    invoke-direct {p3, p4, p0, p1}, Lcom/salesforce/marketingcloud/analytics/stats/a;-><init>(Lcom/salesforce/marketingcloud/storage/c;Lcom/salesforce/marketingcloud/util/Crypto;Lcom/salesforce/marketingcloud/analytics/stats/b;)V

    .line 80
    invoke-interface {p2, p3}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception v0

    move-object p0, v0

    .line 81
    sget-object p1, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    new-array p2, v1, [Ljava/lang/Object;

    const-string p3, "Failed to record device stat for successful trigger event"

    invoke-static {p1, p0, p3, p2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public a(Ljava/lang/String;Ljava/lang/String;Ljava/util/List;)V
    .locals 9
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    .line 82
    sget-object v0, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object v1

    const-string v2, "Creating message validation error event stat for message id %s"

    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 83
    :try_start_0
    new-instance v5, Ljava/util/Date;

    invoke-direct {v5}, Ljava/util/Date;-><init>()V

    .line 84
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->i:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 85
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->applicationId()Ljava/lang/String;

    move-result-object v3

    iget-object v4, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->f:Ljava/lang/String;

    move-object v6, p1

    move-object v7, p2

    move-object v8, p3

    invoke-static/range {v3 .. v8}, Lcom/salesforce/marketingcloud/analytics/stats/d;->a(Ljava/lang/String;Ljava/lang/String;Ljava/util/Date;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;)Lcom/salesforce/marketingcloud/analytics/stats/d;

    move-result-object p1

    .line 86
    iget-object p2, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->e:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object p2

    new-instance p3, Lcom/salesforce/marketingcloud/analytics/stats/a;

    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->g:Lcom/salesforce/marketingcloud/storage/h;

    .line 87
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->i()Lcom/salesforce/marketingcloud/storage/c;

    move-result-object v0

    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->g:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    move-result-object p0

    const/16 v1, 0x67

    const/4 v2, 0x1

    .line 88
    invoke-static {v1, v5, p1, v2}, Lcom/salesforce/marketingcloud/analytics/stats/b;->a(ILjava/util/Date;Lcom/salesforce/marketingcloud/analytics/stats/d;Z)Lcom/salesforce/marketingcloud/analytics/stats/b;

    move-result-object p1

    invoke-direct {p3, v0, p0, p1}, Lcom/salesforce/marketingcloud/analytics/stats/a;-><init>(Lcom/salesforce/marketingcloud/storage/c;Lcom/salesforce/marketingcloud/util/Crypto;Lcom/salesforce/marketingcloud/analytics/stats/b;)V

    .line 89
    invoke-interface {p2, p3}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception v0

    move-object p0, v0

    .line 90
    sget-object p1, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    const/4 p2, 0x0

    new-array p2, p2, [Ljava/lang/Object;

    const-string p3, "Failed to record validation event stat."

    invoke-static {p1, p0, p3, p2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public a(Lorg/json/JSONObject;)V
    .locals 5

    const/4 v0, 0x0

    .line 104
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->e:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v1

    new-instance v2, Lcom/salesforce/marketingcloud/analytics/stats/c$d;

    const-string v3, "onInvalidConfigEvent"

    new-array v4, v0, [Ljava/lang/Object;

    invoke-direct {v2, p0, v3, v4, p1}, Lcom/salesforce/marketingcloud/analytics/stats/c$d;-><init>(Lcom/salesforce/marketingcloud/analytics/stats/c;Ljava/lang/String;[Ljava/lang/Object;Lorg/json/JSONObject;)V

    invoke-interface {v1, v2}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception p0

    .line 105
    sget-object p1, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    new-array v0, v0, [Ljava/lang/Object;

    const-string v1, "Failed to track onInvalidConfig Event stat."

    invoke-static {p1, p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public a(Z)V
    .locals 4

    .line 2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->h:Lcom/salesforce/marketingcloud/http/e;

    sget-object v1, Lcom/salesforce/marketingcloud/http/b;->r:Lcom/salesforce/marketingcloud/http/b;

    invoke-virtual {v0, v1}, Lcom/salesforce/marketingcloud/http/e;->a(Lcom/salesforce/marketingcloud/http/b;)V

    .line 3
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->h:Lcom/salesforce/marketingcloud/http/e;

    sget-object v1, Lcom/salesforce/marketingcloud/http/b;->s:Lcom/salesforce/marketingcloud/http/b;

    invoke-virtual {v0, v1}, Lcom/salesforce/marketingcloud/http/e;->a(Lcom/salesforce/marketingcloud/http/b;)V

    .line 4
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->j:Lcom/salesforce/marketingcloud/alarms/b;

    sget-object v1, Lcom/salesforce/marketingcloud/alarms/a$a;->j:Lcom/salesforce/marketingcloud/alarms/a$a;

    sget-object v2, Lcom/salesforce/marketingcloud/alarms/a$a;->k:Lcom/salesforce/marketingcloud/alarms/a$a;

    filled-new-array {v1, v2}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    move-result-object v3

    invoke-virtual {v0, v3}, Lcom/salesforce/marketingcloud/alarms/b;->e([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    if-eqz p1, :cond_0

    .line 5
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->j:Lcom/salesforce/marketingcloud/alarms/b;

    sget-object p1, Lcom/salesforce/marketingcloud/alarms/a$a;->l:Lcom/salesforce/marketingcloud/alarms/a$a;

    filled-new-array {v1, v2, p1}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    move-result-object p1

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/alarms/b;->d([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    :cond_0
    return-void
.end method

.method public b(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)V
    .locals 7

    .line 1
    iget-boolean v0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->d:Z

    const/4 v1, 0x0

    if-nez v0, :cond_0

    .line 2
    sget-object p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    new-array p1, v1, [Ljava/lang/Object;

    const-string v0, "Track user is false.  Ignoring onInAppMessageDownloaded event."

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void

    .line 3
    :cond_0
    :try_start_0
    sget-object v0, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    const-string v2, "Creating download event stat for message id %s"

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->id()Ljava/lang/String;

    move-result-object v3

    filled-new-array {v3}, [Ljava/lang/Object;

    move-result-object v3

    invoke-static {v0, v2, v3}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 4
    new-instance v0, Ljava/util/Date;

    invoke-direct {v0}, Ljava/util/Date;-><init>()V

    .line 5
    iget-object v2, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->i:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 6
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->applicationId()Ljava/lang/String;

    move-result-object v2

    iget-object v3, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->f:Ljava/lang/String;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->id()Ljava/lang/String;

    move-result-object v4

    .line 7
    invoke-static {p1}, Lcom/salesforce/marketingcloud/internal/c;->a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)Ljava/lang/String;

    move-result-object p1

    .line 8
    invoke-static {v2, v3, v0, v4, p1}, Lcom/salesforce/marketingcloud/analytics/stats/d;->b(Ljava/lang/String;Ljava/lang/String;Ljava/util/Date;Ljava/lang/String;Ljava/lang/String;)Lcom/salesforce/marketingcloud/analytics/stats/d;

    move-result-object p1

    .line 9
    iget-object v2, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->e:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v2

    new-instance v3, Lcom/salesforce/marketingcloud/analytics/stats/a;

    iget-object v4, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->g:Lcom/salesforce/marketingcloud/storage/h;

    .line 10
    invoke-virtual {v4}, Lcom/salesforce/marketingcloud/storage/h;->i()Lcom/salesforce/marketingcloud/storage/c;

    move-result-object v4

    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->g:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    move-result-object p0

    const/16 v5, 0x65

    const/4 v6, 0x1

    .line 11
    invoke-static {v5, v0, p1, v6}, Lcom/salesforce/marketingcloud/analytics/stats/b;->a(ILjava/util/Date;Lcom/salesforce/marketingcloud/analytics/stats/d;Z)Lcom/salesforce/marketingcloud/analytics/stats/b;

    move-result-object p1

    invoke-direct {v3, v4, p0, p1}, Lcom/salesforce/marketingcloud/analytics/stats/a;-><init>(Lcom/salesforce/marketingcloud/storage/c;Lcom/salesforce/marketingcloud/util/Crypto;Lcom/salesforce/marketingcloud/analytics/stats/b;)V

    .line 12
    invoke-interface {v2, v3}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception p0

    .line 13
    sget-object p1, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    new-array v0, v1, [Ljava/lang/Object;

    const-string v1, "Failed to record analytic event for In App Message Downloaded"

    invoke-static {p1, p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public b(Ljava/util/Map;)V
    .locals 5
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    const/4 v0, 0x0

    .line 16
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->e:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v1

    new-instance v2, Lcom/salesforce/marketingcloud/analytics/stats/c$g;

    const-string v3, "onPushReceived"

    new-array v4, v0, [Ljava/lang/Object;

    invoke-direct {v2, p0, v3, v4, p1}, Lcom/salesforce/marketingcloud/analytics/stats/c$g;-><init>(Lcom/salesforce/marketingcloud/analytics/stats/c;Ljava/lang/String;[Ljava/lang/Object;Ljava/util/Map;)V

    invoke-interface {v1, v2}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception p0

    .line 17
    sget-object p1, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    new-array v0, v0, [Ljava/lang/Object;

    const-string v1, "Failed to track Delivery Receipt event stat"

    invoke-static {p1, p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public b(Lorg/json/JSONObject;)V
    .locals 5

    const/4 v0, 0x0

    .line 14
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->e:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v1

    new-instance v2, Lcom/salesforce/marketingcloud/analytics/stats/c$c;

    const-string v3, "onSyncGateTimedOutEvent"

    new-array v4, v0, [Ljava/lang/Object;

    invoke-direct {v2, p0, v3, v4, p1}, Lcom/salesforce/marketingcloud/analytics/stats/c$c;-><init>(Lcom/salesforce/marketingcloud/analytics/stats/c;Ljava/lang/String;[Ljava/lang/Object;Lorg/json/JSONObject;)V

    invoke-interface {v1, v2}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception p0

    .line 15
    sget-object p1, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    new-array v0, v0, [Ljava/lang/Object;

    const-string v1, "Failed to track syncGateTimeOut Event stat."

    invoke-static {p1, p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method
