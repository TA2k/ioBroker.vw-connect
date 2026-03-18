.class Lcom/salesforce/marketingcloud/analytics/stats/c$b;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/analytics/stats/c;->a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;Lorg/json/JSONObject;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

.field final synthetic d:Lorg/json/JSONObject;

.field final synthetic e:Lcom/salesforce/marketingcloud/analytics/stats/c;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/analytics/stats/c;Ljava/lang/String;[Ljava/lang/Object;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;Lorg/json/JSONObject;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$b;->e:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 2
    .line 3
    iput-object p4, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$b;->c:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    .line 4
    .line 5
    iput-object p5, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$b;->d:Lorg/json/JSONObject;

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
    .locals 10

    .line 1
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
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/config/a;->j()Z

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
    :cond_0
    sget-object v0, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    .line 19
    .line 20
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$b;->c:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    .line 21
    .line 22
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->id()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    const-string v2, "InAppMessage throttled event stat for message id %s"

    .line 31
    .line 32
    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    new-instance v5, Ljava/util/Date;

    .line 36
    .line 37
    invoke-direct {v5}, Ljava/util/Date;-><init>()V

    .line 38
    .line 39
    .line 40
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$b;->e:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 41
    .line 42
    iget-object v0, v0, Lcom/salesforce/marketingcloud/analytics/stats/c;->e:Lcom/salesforce/marketingcloud/internal/n;

    .line 43
    .line 44
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    new-instance v1, Lcom/salesforce/marketingcloud/analytics/stats/a;

    .line 49
    .line 50
    iget-object v2, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$b;->e:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 51
    .line 52
    iget-object v2, v2, Lcom/salesforce/marketingcloud/analytics/stats/c;->g:Lcom/salesforce/marketingcloud/storage/h;

    .line 53
    .line 54
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/storage/h;->i()Lcom/salesforce/marketingcloud/storage/c;

    .line 55
    .line 56
    .line 57
    move-result-object v2

    .line 58
    iget-object v3, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$b;->e:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 59
    .line 60
    iget-object v3, v3, Lcom/salesforce/marketingcloud/analytics/stats/c;->g:Lcom/salesforce/marketingcloud/storage/h;

    .line 61
    .line 62
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 63
    .line 64
    .line 65
    move-result-object v9

    .line 66
    iget-object v3, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$b;->e:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 67
    .line 68
    iget-object v3, v3, Lcom/salesforce/marketingcloud/analytics/stats/c;->i:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 69
    .line 70
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->applicationId()Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object v3

    .line 74
    iget-object v4, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$b;->e:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 75
    .line 76
    iget-object v4, v4, Lcom/salesforce/marketingcloud/analytics/stats/c;->f:Ljava/lang/String;

    .line 77
    .line 78
    iget-object v6, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$b;->c:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    .line 79
    .line 80
    invoke-virtual {v6}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->id()Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object v6

    .line 84
    iget-object v7, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$b;->c:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    .line 85
    .line 86
    invoke-static {v7}, Lcom/salesforce/marketingcloud/internal/c;->a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object v7

    .line 90
    iget-object v8, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$b;->d:Lorg/json/JSONObject;

    .line 91
    .line 92
    invoke-static/range {v3 .. v8}, Lcom/salesforce/marketingcloud/analytics/stats/d;->a(Ljava/lang/String;Ljava/lang/String;Ljava/util/Date;Ljava/lang/String;Ljava/lang/String;Lorg/json/JSONObject;)Lcom/salesforce/marketingcloud/analytics/stats/d;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    const/4 v3, 0x1

    .line 97
    const/16 v4, 0x6a

    .line 98
    .line 99
    invoke-static {v4, v5, p0, v3}, Lcom/salesforce/marketingcloud/analytics/stats/b;->a(ILjava/util/Date;Lcom/salesforce/marketingcloud/analytics/stats/d;Z)Lcom/salesforce/marketingcloud/analytics/stats/b;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    invoke-direct {v1, v2, v9, p0}, Lcom/salesforce/marketingcloud/analytics/stats/a;-><init>(Lcom/salesforce/marketingcloud/storage/c;Lcom/salesforce/marketingcloud/util/Crypto;Lcom/salesforce/marketingcloud/analytics/stats/b;)V

    .line 104
    .line 105
    .line 106
    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_0
    .catch Lorg/json/JSONException; {:try_start_0 .. :try_end_0} :catch_0

    .line 107
    .line 108
    .line 109
    return-void

    .line 110
    :catch_0
    move-exception v0

    .line 111
    move-object p0, v0

    .line 112
    sget-object v0, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    .line 113
    .line 114
    const/4 v1, 0x0

    .line 115
    new-array v1, v1, [Ljava/lang/Object;

    .line 116
    .line 117
    const-string v2, "Failed to record iam throttled event stat."

    .line 118
    .line 119
    invoke-static {v0, p0, v2, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    return-void
.end method
