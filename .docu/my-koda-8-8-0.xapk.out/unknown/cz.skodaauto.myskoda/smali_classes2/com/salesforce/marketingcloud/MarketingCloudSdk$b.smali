.class Lcom/salesforce/marketingcloud/MarketingCloudSdk$b;
.super Lcom/salesforce/marketingcloud/MarketingCloudSdk$c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/MarketingCloudSdk;->requestSdk(Landroid/os/Looper;Lcom/salesforce/marketingcloud/MarketingCloudSdk$WhenReadyListener;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# direct methods
.method public constructor <init>(Landroid/os/Looper;Lcom/salesforce/marketingcloud/MarketingCloudSdk$WhenReadyListener;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lcom/salesforce/marketingcloud/MarketingCloudSdk$c;-><init>(Landroid/os/Looper;Lcom/salesforce/marketingcloud/MarketingCloudSdk$WhenReadyListener;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public a(Lcom/salesforce/marketingcloud/MarketingCloudSdk$WhenReadyListener;)V
    .locals 2

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    :try_start_0
    sget-object p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->y:Lcom/salesforce/marketingcloud/MarketingCloudSdk;

    .line 4
    .line 5
    invoke-interface {p1, p0}, Lcom/salesforce/marketingcloud/MarketingCloudSdk$WhenReadyListener;->ready(Lcom/salesforce/marketingcloud/MarketingCloudSdk;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 6
    .line 7
    .line 8
    return-void

    .line 9
    :catch_0
    move-exception p0

    .line 10
    sget-object v0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->v:Ljava/lang/String;

    .line 11
    .line 12
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    invoke-virtual {p1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    const-string v1, "Error occurred in %s"

    .line 25
    .line 26
    invoke-static {v0, p0, v1, p1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    :cond_0
    return-void
.end method
