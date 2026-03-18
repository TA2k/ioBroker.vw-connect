.class Lcom/salesforce/marketingcloud/analytics/etanalytics/b$e;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->b(Lcom/salesforce/marketingcloud/messages/Region;Ljava/util/Date;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:Lcom/salesforce/marketingcloud/messages/Region;

.field final synthetic d:Ljava/util/Date;

.field final synthetic e:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/analytics/etanalytics/b;Ljava/lang/String;[Ljava/lang/Object;Lcom/salesforce/marketingcloud/messages/Region;Ljava/util/Date;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b$e;->e:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    .line 2
    .line 3
    iput-object p4, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b$e;->c:Lcom/salesforce/marketingcloud/messages/Region;

    .line 4
    .line 5
    iput-object p5, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b$e;->d:Ljava/util/Date;

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
    .locals 7

    .line 1
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b$e;->e:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    .line 2
    .line 3
    iget-object v0, v0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 4
    .line 5
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->h()Lcom/salesforce/marketingcloud/storage/a;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b$e;->c:Lcom/salesforce/marketingcloud/messages/Region;

    .line 10
    .line 11
    iget-object v2, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b$e;->e:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    .line 12
    .line 13
    iget-object v2, v2, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 14
    .line 15
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    invoke-interface {v0, v1, v2}, Lcom/salesforce/marketingcloud/storage/a;->b(Lcom/salesforce/marketingcloud/messages/Region;Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    if-nez v1, :cond_1

    .line 28
    .line 29
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    if-eqz v1, :cond_1

    .line 38
    .line 39
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    check-cast v1, Lcom/salesforce/marketingcloud/analytics/b;

    .line 44
    .line 45
    sget-object v2, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 46
    .line 47
    iget-object v3, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b$e;->d:Ljava/util/Date;

    .line 48
    .line 49
    invoke-virtual {v3}, Ljava/util/Date;->getTime()J

    .line 50
    .line 51
    .line 52
    move-result-wide v3

    .line 53
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/analytics/b;->b()Ljava/util/Date;

    .line 54
    .line 55
    .line 56
    move-result-object v5

    .line 57
    invoke-virtual {v5}, Ljava/util/Date;->getTime()J

    .line 58
    .line 59
    .line 60
    move-result-wide v5

    .line 61
    sub-long/2addr v3, v5

    .line 62
    invoke-virtual {v2, v3, v4}, Ljava/util/concurrent/TimeUnit;->toSeconds(J)J

    .line 63
    .line 64
    .line 65
    move-result-wide v2

    .line 66
    long-to-int v2, v2

    .line 67
    if-lez v2, :cond_0

    .line 68
    .line 69
    invoke-virtual {v1, v2}, Lcom/salesforce/marketingcloud/analytics/b;->b(I)V

    .line 70
    .line 71
    .line 72
    const/4 v2, 0x1

    .line 73
    invoke-virtual {v1, v2}, Lcom/salesforce/marketingcloud/analytics/b;->a(Z)V

    .line 74
    .line 75
    .line 76
    iget-object v2, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b$e;->e:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    .line 77
    .line 78
    iget-object v2, v2, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 79
    .line 80
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/storage/h;->h()Lcom/salesforce/marketingcloud/storage/a;

    .line 81
    .line 82
    .line 83
    move-result-object v2

    .line 84
    iget-object v3, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b$e;->e:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    .line 85
    .line 86
    iget-object v3, v3, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 87
    .line 88
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 89
    .line 90
    .line 91
    move-result-object v3

    .line 92
    invoke-interface {v2, v1, v3}, Lcom/salesforce/marketingcloud/storage/a;->b(Lcom/salesforce/marketingcloud/analytics/b;Lcom/salesforce/marketingcloud/util/Crypto;)I
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 93
    .line 94
    .line 95
    goto :goto_0

    .line 96
    :cond_1
    return-void

    .line 97
    :catch_0
    move-exception p0

    .line 98
    sget-object v0, Lcom/salesforce/marketingcloud/analytics/AnalyticsManager;->TAG:Ljava/lang/String;

    .line 99
    .line 100
    const/4 v1, 0x0

    .line 101
    new-array v1, v1, [Ljava/lang/Object;

    .line 102
    .line 103
    const-string v2, "Failed to record EtAnalyticItem for stopTimeInRegion."

    .line 104
    .line 105
    invoke-static {v0, p0, v2, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 106
    .line 107
    .line 108
    return-void
.end method
