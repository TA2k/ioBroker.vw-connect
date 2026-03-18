.class Lcom/salesforce/marketingcloud/analytics/stats/c$a;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/analytics/stats/c;->a(J)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:Lcom/salesforce/marketingcloud/analytics/stats/c;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/analytics/stats/c;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$a;->c:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 2
    .line 3
    invoke-direct {p0, p2, p3}, Lcom/salesforce/marketingcloud/internal/i;-><init>(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public a()V
    .locals 7

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$a;->c:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 2
    .line 3
    iget-object v0, v0, Lcom/salesforce/marketingcloud/analytics/stats/c;->g:Lcom/salesforce/marketingcloud/storage/h;

    .line 4
    .line 5
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->i()Lcom/salesforce/marketingcloud/storage/c;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$a;->c:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 10
    .line 11
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->g:Lcom/salesforce/marketingcloud/storage/h;

    .line 12
    .line 13
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    invoke-interface {v0, p0}, Lcom/salesforce/marketingcloud/storage/c;->i(Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    invoke-interface {v1}, Ljava/util/List;->isEmpty()Z

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    if-nez v2, :cond_0

    .line 26
    .line 27
    new-instance v2, Ljava/util/Date;

    .line 28
    .line 29
    invoke-direct {v2}, Ljava/util/Date;-><init>()V

    .line 30
    .line 31
    .line 32
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 37
    .line 38
    .line 39
    move-result v3

    .line 40
    if-eqz v3, :cond_0

    .line 41
    .line 42
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v3

    .line 46
    check-cast v3, Lcom/salesforce/marketingcloud/analytics/stats/b;

    .line 47
    .line 48
    :try_start_0
    invoke-virtual {v3, v2}, Lcom/salesforce/marketingcloud/analytics/stats/b;->a(Ljava/util/Date;)V

    .line 49
    .line 50
    .line 51
    invoke-interface {v0, v3, p0}, Lcom/salesforce/marketingcloud/storage/c;->a(Lcom/salesforce/marketingcloud/analytics/stats/b;Lcom/salesforce/marketingcloud/util/Crypto;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 52
    .line 53
    .line 54
    goto :goto_0

    .line 55
    :catch_0
    move-exception v4

    .line 56
    sget-object v5, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    .line 57
    .line 58
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/analytics/stats/b;->d()I

    .line 59
    .line 60
    .line 61
    move-result v3

    .line 62
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 63
    .line 64
    .line 65
    move-result-object v3

    .line 66
    filled-new-array {v3}, [Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v3

    .line 70
    const-string v6, "Unable to update sync event analytic [%s]"

    .line 71
    .line 72
    invoke-static {v5, v4, v6, v3}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    goto :goto_0

    .line 76
    :cond_0
    sget-object p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    .line 77
    .line 78
    const/4 v0, 0x0

    .line 79
    new-array v0, v0, [Ljava/lang/Object;

    .line 80
    .line 81
    const-string v1, "Handling app close and sending stats."

    .line 82
    .line 83
    invoke-static {p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    return-void
.end method
