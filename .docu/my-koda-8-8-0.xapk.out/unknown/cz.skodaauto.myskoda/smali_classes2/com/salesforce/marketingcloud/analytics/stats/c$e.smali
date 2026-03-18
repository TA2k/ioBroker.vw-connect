.class Lcom/salesforce/marketingcloud/analytics/stats/c$e;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/analytics/stats/c;->a(Lcom/salesforce/marketingcloud/analytics/l$a;Lorg/json/JSONObject;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:Lorg/json/JSONObject;

.field final synthetic d:Lcom/salesforce/marketingcloud/analytics/l$a;

.field final synthetic e:Lcom/salesforce/marketingcloud/analytics/stats/c;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/analytics/stats/c;Ljava/lang/String;[Ljava/lang/Object;Lorg/json/JSONObject;Lcom/salesforce/marketingcloud/analytics/l$a;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$e;->e:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 2
    .line 3
    iput-object p4, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$e;->c:Lorg/json/JSONObject;

    .line 4
    .line 5
    iput-object p5, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$e;->d:Lcom/salesforce/marketingcloud/analytics/l$a;

    .line 6
    .line 7
    invoke-direct {p0, p2, p3}, Lcom/salesforce/marketingcloud/internal/i;-><init>(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public a()V
    .locals 8

    .line 1
    :try_start_0
    invoke-static {}, Lcom/salesforce/marketingcloud/config/a;->g()Lcom/salesforce/marketingcloud/config/a;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-static {}, Lcom/salesforce/marketingcloud/config/a;->g()Lcom/salesforce/marketingcloud/config/a;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/config/a;->n()Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    return-void

    .line 18
    :catch_0
    move-exception v0

    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ljava/util/Date;

    .line 21
    .line 22
    invoke-direct {v0}, Ljava/util/Date;-><init>()V

    .line 23
    .line 24
    .line 25
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$e;->e:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 26
    .line 27
    iget-object v1, v1, Lcom/salesforce/marketingcloud/analytics/stats/c;->i:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 28
    .line 29
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->applicationId()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    iget-object v2, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$e;->e:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 34
    .line 35
    iget-object v2, v2, Lcom/salesforce/marketingcloud/analytics/stats/c;->f:Ljava/lang/String;

    .line 36
    .line 37
    iget-object v3, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$e;->c:Lorg/json/JSONObject;

    .line 38
    .line 39
    invoke-static {v1, v2, v0, v3}, Lcom/salesforce/marketingcloud/analytics/stats/d;->a(Ljava/lang/String;Ljava/lang/String;Ljava/util/Date;Lorg/json/JSONObject;)Lcom/salesforce/marketingcloud/analytics/stats/d;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    iget-object v2, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$e;->e:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 44
    .line 45
    iget-object v2, v2, Lcom/salesforce/marketingcloud/analytics/stats/c;->e:Lcom/salesforce/marketingcloud/internal/n;

    .line 46
    .line 47
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    .line 48
    .line 49
    .line 50
    move-result-object v2

    .line 51
    new-instance v3, Lcom/salesforce/marketingcloud/analytics/stats/a;

    .line 52
    .line 53
    iget-object v4, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$e;->e:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 54
    .line 55
    iget-object v4, v4, Lcom/salesforce/marketingcloud/analytics/stats/c;->g:Lcom/salesforce/marketingcloud/storage/h;

    .line 56
    .line 57
    invoke-virtual {v4}, Lcom/salesforce/marketingcloud/storage/h;->i()Lcom/salesforce/marketingcloud/storage/c;

    .line 58
    .line 59
    .line 60
    move-result-object v4

    .line 61
    iget-object v5, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$e;->e:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 62
    .line 63
    iget-object v5, v5, Lcom/salesforce/marketingcloud/analytics/stats/c;->g:Lcom/salesforce/marketingcloud/storage/h;

    .line 64
    .line 65
    invoke-virtual {v5}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 66
    .line 67
    .line 68
    move-result-object v5

    .line 69
    const/16 v6, 0x6b

    .line 70
    .line 71
    const/4 v7, 0x1

    .line 72
    invoke-static {v6, v0, v1, v7}, Lcom/salesforce/marketingcloud/analytics/stats/b;->a(ILjava/util/Date;Lcom/salesforce/marketingcloud/analytics/stats/d;Z)Lcom/salesforce/marketingcloud/analytics/stats/b;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    invoke-direct {v3, v4, v5, v0}, Lcom/salesforce/marketingcloud/analytics/stats/a;-><init>(Lcom/salesforce/marketingcloud/storage/c;Lcom/salesforce/marketingcloud/util/Crypto;Lcom/salesforce/marketingcloud/analytics/stats/b;)V

    .line 77
    .line 78
    .line 79
    invoke-interface {v2, v3}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 80
    .line 81
    .line 82
    return-void

    .line 83
    :goto_0
    sget-object v1, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    .line 84
    .line 85
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$e;->d:Lcom/salesforce/marketingcloud/analytics/l$a;

    .line 86
    .line 87
    invoke-virtual {p0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    const-string v2, "Failed to record onTelemetryEvent stat. %s"

    .line 96
    .line 97
    invoke-static {v1, v0, v2, p0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 98
    .line 99
    .line 100
    return-void
.end method
