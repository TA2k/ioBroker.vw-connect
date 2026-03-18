.class Lcom/salesforce/marketingcloud/analytics/etanalytics/b$b;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->b(J)V
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
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b$b;->d:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    .line 2
    .line 3
    iput-wide p4, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b$b;->c:J

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
    .locals 5

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b$b;->d:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

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
    const/4 v1, 0x0

    .line 10
    invoke-interface {v0, v1}, Lcom/salesforce/marketingcloud/storage/a;->c(I)Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-nez v0, :cond_0

    .line 15
    .line 16
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b$b;->d:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    .line 17
    .line 18
    iget-object v0, v0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 19
    .line 20
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->h()Lcom/salesforce/marketingcloud/storage/a;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    new-instance v2, Ljava/util/Date;

    .line 25
    .line 26
    iget-wide v3, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b$b;->c:J

    .line 27
    .line 28
    invoke-direct {v2, v3, v4}, Ljava/util/Date;-><init>(J)V

    .line 29
    .line 30
    .line 31
    const/4 v3, 0x4

    .line 32
    invoke-static {v2, v1, v3}, Lcom/salesforce/marketingcloud/analytics/b;->a(Ljava/util/Date;II)Lcom/salesforce/marketingcloud/analytics/b;

    .line 33
    .line 34
    .line 35
    move-result-object v2

    .line 36
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b$b;->d:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    .line 37
    .line 38
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 39
    .line 40
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    invoke-interface {v0, v2, p0}, Lcom/salesforce/marketingcloud/storage/a;->a(Lcom/salesforce/marketingcloud/analytics/b;Lcom/salesforce/marketingcloud/util/Crypto;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 45
    .line 46
    .line 47
    return-void

    .line 48
    :catch_0
    move-exception p0

    .line 49
    sget-object v0, Lcom/salesforce/marketingcloud/analytics/AnalyticsManager;->TAG:Ljava/lang/String;

    .line 50
    .line 51
    new-array v1, v1, [Ljava/lang/Object;

    .line 52
    .line 53
    const-string v2, "Failed to create our EtAnalyticItem for TimeInApp."

    .line 54
    .line 55
    invoke-static {v0, p0, v2, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    :cond_0
    return-void
.end method
