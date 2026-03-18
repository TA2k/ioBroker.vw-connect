.class public Lcom/salesforce/marketingcloud/analytics/etanalytics/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/http/e$c;
.implements Lcom/salesforce/marketingcloud/alarms/b$b;


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation


# static fields
.field private static final j:I = 0x3e800

.field private static final k:I = 0x3e7

.field private static final l:I = 0x32


# instance fields
.field final d:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

.field final e:Ljava/lang/String;

.field final f:Lcom/salesforce/marketingcloud/storage/h;

.field final g:Lcom/salesforce/marketingcloud/http/e;

.field final h:Lcom/salesforce/marketingcloud/alarms/b;

.field private final i:Lcom/salesforce/marketingcloud/internal/n;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Ljava/lang/String;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/http/e;Lcom/salesforce/marketingcloud/alarms/b;Lcom/salesforce/marketingcloud/internal/n;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const-string v0, "Config is null"

    .line 5
    .line 6
    invoke-static {p1, v0}, Lcom/salesforce/marketingcloud/util/g;->a(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    check-cast p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 11
    .line 12
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/c;->d:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 13
    .line 14
    const-string p1, "DeviceId is null"

    .line 15
    .line 16
    invoke-static {p2, p1}, Lcom/salesforce/marketingcloud/util/g;->a(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    check-cast p1, Ljava/lang/String;

    .line 21
    .line 22
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/c;->e:Ljava/lang/String;

    .line 23
    .line 24
    const-string p1, "MCStorage is null"

    .line 25
    .line 26
    invoke-static {p3, p1}, Lcom/salesforce/marketingcloud/util/g;->a(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    check-cast p1, Lcom/salesforce/marketingcloud/storage/h;

    .line 31
    .line 32
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/c;->f:Lcom/salesforce/marketingcloud/storage/h;

    .line 33
    .line 34
    const-string p1, "RequestManager is null"

    .line 35
    .line 36
    invoke-static {p4, p1}, Lcom/salesforce/marketingcloud/util/g;->a(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    check-cast p1, Lcom/salesforce/marketingcloud/http/e;

    .line 41
    .line 42
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/c;->g:Lcom/salesforce/marketingcloud/http/e;

    .line 43
    .line 44
    const-string p1, "AlarmScheduler is null"

    .line 45
    .line 46
    invoke-static {p5, p1}, Lcom/salesforce/marketingcloud/util/g;->a(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object p1

    .line 50
    check-cast p1, Lcom/salesforce/marketingcloud/alarms/b;

    .line 51
    .line 52
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/c;->h:Lcom/salesforce/marketingcloud/alarms/b;

    .line 53
    .line 54
    iput-object p6, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/c;->i:Lcom/salesforce/marketingcloud/internal/n;

    .line 55
    .line 56
    sget-object p1, Lcom/salesforce/marketingcloud/http/b;->i:Lcom/salesforce/marketingcloud/http/b;

    .line 57
    .line 58
    invoke-virtual {p4, p1, p0}, Lcom/salesforce/marketingcloud/http/e;->a(Lcom/salesforce/marketingcloud/http/b;Lcom/salesforce/marketingcloud/http/e$c;)V

    .line 59
    .line 60
    .line 61
    sget-object p1, Lcom/salesforce/marketingcloud/alarms/a$a;->d:Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 62
    .line 63
    filled-new-array {p1}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 64
    .line 65
    .line 66
    move-result-object p1

    .line 67
    invoke-virtual {p5, p0, p1}, Lcom/salesforce/marketingcloud/alarms/b;->a(Lcom/salesforce/marketingcloud/alarms/b$b;[Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 68
    .line 69
    .line 70
    return-void
.end method


# virtual methods
.method public a(Ljava/lang/String;Ljava/lang/String;Ljava/util/List;)Lorg/json/JSONArray;
    .locals 8
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/analytics/b;",
            ">;)",
            "Lorg/json/JSONArray;"
        }
    .end annotation

    .line 12
    const-string p0, "requestId"

    const-string v0, "uuid"

    const-string v1, "propertyBag"

    new-instance v2, Lorg/json/JSONArray;

    invoke-direct {v2}, Lorg/json/JSONArray;-><init>()V

    .line 13
    invoke-interface {p3}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p3

    :goto_0
    invoke-interface {p3}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_4

    invoke-interface {p3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Lcom/salesforce/marketingcloud/analytics/b;

    .line 14
    :try_start_0
    new-instance v4, Lorg/json/JSONObject;

    invoke-direct {v4}, Lorg/json/JSONObject;-><init>()V

    .line 15
    const-string v5, "etAppId"

    invoke-virtual {v4, v5, p1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 16
    const-string v5, "deviceId"

    invoke-virtual {v4, v5, p2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 17
    const-string v5, "eventDate"

    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/analytics/b;->b()Ljava/util/Date;

    move-result-object v6

    invoke-static {v6}, Lcom/salesforce/marketingcloud/util/j;->a(Ljava/util/Date;)Ljava/lang/String;

    move-result-object v6

    invoke-virtual {v4, v5, v6}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 18
    const-string v5, "value"

    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/analytics/b;->g()I

    move-result v6

    invoke-virtual {v4, v5, v6}, Lorg/json/JSONObject;->put(Ljava/lang/String;I)Lorg/json/JSONObject;

    .line 19
    const-string v5, "analyticTypes"

    new-instance v6, Lorg/json/JSONArray;

    .line 20
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/analytics/b;->a()I

    move-result v7

    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    invoke-static {v7}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v7

    invoke-direct {v6, v7}, Lorg/json/JSONArray;-><init>(Ljava/util/Collection;)V

    .line 21
    invoke-virtual {v4, v5, v6}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 22
    const-string v5, "objectIds"

    new-instance v6, Lorg/json/JSONArray;

    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/analytics/b;->i()Ljava/util/List;

    move-result-object v7

    invoke-direct {v6, v7}, Lorg/json/JSONArray;-><init>(Ljava/util/Collection;)V

    invoke-virtual {v4, v5, v6}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 23
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/analytics/b;->c()Ljava/lang/String;

    move-result-object v3

    .line 24
    invoke-static {v3}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v5

    if-nez v5, :cond_3

    .line 25
    new-instance v5, Lorg/json/JSONObject;

    invoke-direct {v5, v3}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V

    .line 26
    invoke-virtual {v5, v0}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v3

    .line 27
    invoke-static {v3}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v6

    if-nez v6, :cond_0

    .line 28
    invoke-virtual {v4, v0, v3}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    goto :goto_1

    :catch_0
    move-exception v3

    goto :goto_3

    .line 29
    :cond_0
    :goto_1
    invoke-virtual {v5, p0}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v3

    .line 30
    invoke-static {v3}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v6

    if-nez v6, :cond_1

    .line 31
    invoke-virtual {v4, p0, v3}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 32
    :cond_1
    invoke-virtual {v5, v1}, Lorg/json/JSONObject;->optJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    move-result-object v3

    if-eqz v3, :cond_2

    invoke-virtual {v5, v1}, Lorg/json/JSONObject;->getJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    move-result-object v3

    goto :goto_2

    .line 33
    :cond_2
    new-instance v3, Lorg/json/JSONObject;

    invoke-direct {v3}, Lorg/json/JSONObject;-><init>()V

    .line 34
    :goto_2
    const-string v5, "platform"

    const-string v6, "Android"

    invoke-virtual {v3, v5, v6}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 35
    invoke-virtual {v4, v1, v3}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 36
    :cond_3
    invoke-virtual {v2, v4}, Lorg/json/JSONArray;->put(Ljava/lang/Object;)Lorg/json/JSONArray;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto/16 :goto_0

    .line 37
    :goto_3
    sget-object v4, Lcom/salesforce/marketingcloud/analytics/AnalyticsManager;->TAG:Ljava/lang/String;

    const/4 v5, 0x0

    new-array v5, v5, [Ljava/lang/Object;

    const-string v6, "Failed to update EtAnalyticItem or convert it to JSON for transmission."

    invoke-static {v4, v3, v6, v5}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    goto/16 :goto_0

    :cond_4
    return-object v2
.end method

.method public a()V
    .locals 1

    const/16 v0, 0x3e7

    .line 10
    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/analytics/etanalytics/c;->a(I)V

    return-void
.end method

.method public a(I)V
    .locals 4

    .line 11
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/c;->i:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v0

    new-instance v1, Lcom/salesforce/marketingcloud/analytics/etanalytics/c$a;

    const/4 v2, 0x0

    new-array v2, v2, [Ljava/lang/Object;

    const-string v3, "send_analytics"

    invoke-direct {v1, p0, v3, v2, p1}, Lcom/salesforce/marketingcloud/analytics/etanalytics/c$a;-><init>(Lcom/salesforce/marketingcloud/analytics/etanalytics/c;Ljava/lang/String;[Ljava/lang/Object;I)V

    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/alarms/a$a;)V
    .locals 1

    .line 8
    sget-object v0, Lcom/salesforce/marketingcloud/alarms/a$a;->d:Lcom/salesforce/marketingcloud/alarms/a$a;

    if-ne p1, v0, :cond_0

    .line 9
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/analytics/etanalytics/c;->a()V

    :cond_0
    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/http/c;Lcom/salesforce/marketingcloud/http/f;)V
    .locals 1

    .line 1
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->p()Z

    move-result v0

    if-eqz v0, :cond_1

    .line 2
    iget-object p2, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/c;->h:Lcom/salesforce/marketingcloud/alarms/b;

    sget-object v0, Lcom/salesforce/marketingcloud/alarms/a$a;->d:Lcom/salesforce/marketingcloud/alarms/a$a;

    filled-new-array {v0}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    move-result-object v0

    invoke-virtual {p2, v0}, Lcom/salesforce/marketingcloud/alarms/b;->c([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 3
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/http/c;->r()Ljava/lang/String;

    move-result-object p2

    if-eqz p2, :cond_0

    .line 4
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/http/c;->r()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Lcom/salesforce/marketingcloud/analytics/c;->a(Ljava/lang/String;)[Ljava/lang/String;

    move-result-object p1

    .line 5
    iget-object p2, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/c;->i:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object p2

    new-instance v0, Lcom/salesforce/marketingcloud/analytics/d;

    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/c;->f:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->h()Lcom/salesforce/marketingcloud/storage/a;

    move-result-object p0

    invoke-direct {v0, p0, p1}, Lcom/salesforce/marketingcloud/analytics/d;-><init>(Lcom/salesforce/marketingcloud/storage/a;[Ljava/lang/String;)V

    invoke-interface {p2, v0}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    :cond_0
    return-void

    .line 6
    :cond_1
    sget-object p1, Lcom/salesforce/marketingcloud/analytics/AnalyticsManager;->TAG:Ljava/lang/String;

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->k()I

    move-result v0

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->n()Ljava/lang/String;

    move-result-object p2

    filled-new-array {v0, p2}, [Ljava/lang/Object;

    move-result-object p2

    const-string v0, "Request failed: %d - %s"

    invoke-static {p1, v0, p2}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 7
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/c;->h:Lcom/salesforce/marketingcloud/alarms/b;

    sget-object p1, Lcom/salesforce/marketingcloud/alarms/a$a;->d:Lcom/salesforce/marketingcloud/alarms/a$a;

    filled-new-array {p1}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    move-result-object p1

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/alarms/b;->b([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    return-void
.end method

.method public b()V
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/c;->g:Lcom/salesforce/marketingcloud/http/e;

    .line 2
    .line 3
    sget-object v1, Lcom/salesforce/marketingcloud/http/b;->i:Lcom/salesforce/marketingcloud/http/b;

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Lcom/salesforce/marketingcloud/http/e;->a(Lcom/salesforce/marketingcloud/http/b;)V

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/c;->h:Lcom/salesforce/marketingcloud/alarms/b;

    .line 9
    .line 10
    sget-object v1, Lcom/salesforce/marketingcloud/alarms/a$a;->d:Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 11
    .line 12
    filled-new-array {v1}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    invoke-virtual {v0, v2}, Lcom/salesforce/marketingcloud/alarms/b;->d([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 17
    .line 18
    .line 19
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/c;->h:Lcom/salesforce/marketingcloud/alarms/b;

    .line 20
    .line 21
    filled-new-array {v1}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/alarms/b;->e([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 26
    .line 27
    .line 28
    return-void
.end method
