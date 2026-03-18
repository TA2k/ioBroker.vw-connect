.class Lcom/salesforce/marketingcloud/k$a;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/k;->a()V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:Lcom/salesforce/marketingcloud/k;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/k;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/k$a;->c:Lcom/salesforce/marketingcloud/k;

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
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/k$a;->c:Lcom/salesforce/marketingcloud/k;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/k;->b()Lcom/salesforce/marketingcloud/MarketingCloudSdk$WhenReadyListener;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-static {p0}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->requestSdk(Lcom/salesforce/marketingcloud/MarketingCloudSdk$WhenReadyListener;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method
