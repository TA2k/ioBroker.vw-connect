.class Lcom/salesforce/marketingcloud/analytics/etanalytics/b$a;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->a(Lcom/salesforce/marketingcloud/internal/n;Lcom/salesforce/marketingcloud/storage/h;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:Lcom/salesforce/marketingcloud/storage/h;


# direct methods
.method public varargs constructor <init>(Ljava/lang/String;[Ljava/lang/Object;Lcom/salesforce/marketingcloud/storage/h;)V
    .locals 0

    .line 1
    iput-object p3, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b$a;->c:Lcom/salesforce/marketingcloud/storage/h;

    .line 2
    .line 3
    invoke-direct {p0, p1, p2}, Lcom/salesforce/marketingcloud/internal/i;-><init>(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public a()V
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b$a;->c:Lcom/salesforce/marketingcloud/storage/h;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->h()Lcom/salesforce/marketingcloud/storage/a;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const/4 v0, 0x0

    .line 8
    invoke-interface {p0, v0}, Lcom/salesforce/marketingcloud/storage/a;->a(I)I

    .line 9
    .line 10
    .line 11
    return-void
.end method
