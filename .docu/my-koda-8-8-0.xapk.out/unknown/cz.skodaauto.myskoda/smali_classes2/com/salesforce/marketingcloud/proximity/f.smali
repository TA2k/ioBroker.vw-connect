.class public final synthetic Lcom/salesforce/marketingcloud/proximity/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/MarketingCloudSdk$WhenReadyListener;


# instance fields
.field public final synthetic d:Lcom/salesforce/marketingcloud/proximity/a;

.field public final synthetic e:Landroid/content/Intent;


# direct methods
.method public synthetic constructor <init>(Lcom/salesforce/marketingcloud/proximity/a;Landroid/content/Intent;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/salesforce/marketingcloud/proximity/f;->d:Lcom/salesforce/marketingcloud/proximity/a;

    .line 5
    .line 6
    iput-object p2, p0, Lcom/salesforce/marketingcloud/proximity/f;->e:Landroid/content/Intent;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final ready(Lcom/salesforce/marketingcloud/MarketingCloudSdk;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/proximity/f;->d:Lcom/salesforce/marketingcloud/proximity/a;

    .line 2
    .line 3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/proximity/f;->e:Landroid/content/Intent;

    .line 4
    .line 5
    invoke-static {v0, p0, p1}, Lcom/salesforce/marketingcloud/proximity/a;->a(Lcom/salesforce/marketingcloud/proximity/a;Landroid/content/Intent;Lcom/salesforce/marketingcloud/MarketingCloudSdk;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method
