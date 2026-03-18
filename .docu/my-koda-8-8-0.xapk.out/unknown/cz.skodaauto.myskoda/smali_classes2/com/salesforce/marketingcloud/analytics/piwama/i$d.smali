.class Lcom/salesforce/marketingcloud/analytics/piwama/i$d;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/analytics/piwama/i;->c()V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:Lcom/salesforce/marketingcloud/analytics/piwama/i;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/analytics/piwama/i;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i$d;->c:Lcom/salesforce/marketingcloud/analytics/piwama/i;

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
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i$d;->c:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    .line 2
    .line 3
    iget-object v1, v0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->e:Lcom/salesforce/marketingcloud/http/e;

    .line 4
    .line 5
    iget-object v0, v0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 6
    .line 7
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->h()Lcom/salesforce/marketingcloud/storage/a;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i$d;->c:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    .line 12
    .line 13
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 14
    .line 15
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    const/16 v2, 0x3e7

    .line 20
    .line 21
    invoke-interface {v0, p0, v2}, Lcom/salesforce/marketingcloud/storage/a;->a(Lcom/salesforce/marketingcloud/util/Crypto;I)Ljava/util/List;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-static {v1, p0}, Lcom/salesforce/marketingcloud/analytics/piwama/i;->a(Lcom/salesforce/marketingcloud/http/e;Ljava/util/List;)V

    .line 26
    .line 27
    .line 28
    return-void
.end method
