.class public final synthetic Lcom/salesforce/marketingcloud/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/MarketingCloudSdk$InitializationListener;
.implements Lcom/salesforce/marketingcloud/MarketingCloudSdk$WhenReadyListener;


# instance fields
.field public final synthetic d:Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;


# direct methods
.method public synthetic constructor <init>(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/l;->d:Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public complete(Lcom/salesforce/marketingcloud/InitializationStatus;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/l;->d:Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;

    .line 2
    .line 3
    invoke-static {p0, p1}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->a(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;Lcom/salesforce/marketingcloud/InitializationStatus;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public ready(Lcom/salesforce/marketingcloud/MarketingCloudSdk;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/l;->d:Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;

    .line 2
    .line 3
    invoke-static {p0, p1}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->b(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;Lcom/salesforce/marketingcloud/MarketingCloudSdk;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
