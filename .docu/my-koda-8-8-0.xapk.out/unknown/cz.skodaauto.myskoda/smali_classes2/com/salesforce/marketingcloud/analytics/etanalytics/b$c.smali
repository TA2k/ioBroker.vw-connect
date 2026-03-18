.class Lcom/salesforce/marketingcloud/analytics/etanalytics/b$c;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->a(J)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:J

.field final synthetic d:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/analytics/etanalytics/b;Ljava/lang/String;[Ljava/lang/Object;J)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b$c;->d:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    .line 2
    .line 3
    iput-wide p4, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b$c;->c:J

    .line 4
    .line 5
    invoke-direct {p0, p2, p3}, Lcom/salesforce/marketingcloud/internal/i;-><init>(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public a()V
    .locals 7

    .line 1
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b$c;->d:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

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
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b$c;->d:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    .line 10
    .line 11
    iget-object v1, v1, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 12
    .line 13
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    invoke-interface {v0, v1}, Lcom/salesforce/marketingcloud/storage/a;->f(Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    if-nez v1, :cond_1

    .line 26
    .line 27
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    if-eqz v1, :cond_1

    .line 36
    .line 37
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    check-cast v1, Lcom/salesforce/marketingcloud/analytics/b;

    .line 42
    .line 43
    sget-object v2, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 44
    .line 45
    iget-wide v3, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b$c;->c:J

    .line 46
    .line 47
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/analytics/b;->b()Ljava/util/Date;

    .line 48
    .line 49
    .line 50
    move-result-object v5

    .line 51
    invoke-virtual {v5}, Ljava/util/Date;->getTime()J

    .line 52
    .line 53
    .line 54
    move-result-wide v5

    .line 55
    sub-long/2addr v3, v5

    .line 56
    invoke-virtual {v2, v3, v4}, Ljava/util/concurrent/TimeUnit;->toSeconds(J)J

    .line 57
    .line 58
    .line 59
    move-result-wide v2

    .line 60
    long-to-int v2, v2

    .line 61
    if-lez v2, :cond_0

    .line 62
    .line 63
    invoke-virtual {v1, v2}, Lcom/salesforce/marketingcloud/analytics/b;->b(I)V

    .line 64
    .line 65
    .line 66
    const/4 v2, 0x1

    .line 67
    invoke-virtual {v1, v2}, Lcom/salesforce/marketingcloud/analytics/b;->a(Z)V

    .line 68
    .line 69
    .line 70
    iget-object v2, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b$c;->d:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    .line 71
    .line 72
    iget-object v2, v2, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 73
    .line 74
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/storage/h;->h()Lcom/salesforce/marketingcloud/storage/a;

    .line 75
    .line 76
    .line 77
    move-result-object v2

    .line 78
    iget-object v3, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b$c;->d:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    .line 79
    .line 80
    iget-object v3, v3, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 81
    .line 82
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 83
    .line 84
    .line 85
    move-result-object v3

    .line 86
    invoke-interface {v2, v1, v3}, Lcom/salesforce/marketingcloud/storage/a;->b(Lcom/salesforce/marketingcloud/analytics/b;Lcom/salesforce/marketingcloud/util/Crypto;)I
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 87
    .line 88
    .line 89
    goto :goto_0

    .line 90
    :cond_1
    return-void

    .line 91
    :catch_0
    move-exception p0

    .line 92
    sget-object v0, Lcom/salesforce/marketingcloud/analytics/AnalyticsManager;->TAG:Ljava/lang/String;

    .line 93
    .line 94
    const/4 v1, 0x0

    .line 95
    new-array v1, v1, [Ljava/lang/Object;

    .line 96
    .line 97
    const-string v2, "Failed to update our EtAnalytic TimeInApp."

    .line 98
    .line 99
    invoke-static {v0, p0, v2, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    return-void
.end method
