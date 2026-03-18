.class Lcom/salesforce/marketingcloud/MarketingCloudSdk$c$a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/MarketingCloudSdk$c;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic b:Lcom/salesforce/marketingcloud/MarketingCloudSdk$c;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/MarketingCloudSdk$c;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk$c$a;->b:Lcom/salesforce/marketingcloud/MarketingCloudSdk$c;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public run()V
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk$c$a;->b:Lcom/salesforce/marketingcloud/MarketingCloudSdk$c;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk$c$a;->b:Lcom/salesforce/marketingcloud/MarketingCloudSdk$c;

    .line 5
    .line 6
    iget-boolean v1, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk$c;->c:Z

    .line 7
    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    monitor-exit v0

    .line 11
    return-void

    .line 12
    :catchall_0
    move-exception p0

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk$c$a;->b:Lcom/salesforce/marketingcloud/MarketingCloudSdk$c;

    .line 15
    .line 16
    iget-object v2, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk$c;->b:Lcom/salesforce/marketingcloud/MarketingCloudSdk$WhenReadyListener;

    .line 17
    .line 18
    invoke-virtual {v1, v2}, Lcom/salesforce/marketingcloud/MarketingCloudSdk$c;->a(Lcom/salesforce/marketingcloud/MarketingCloudSdk$WhenReadyListener;)V

    .line 19
    .line 20
    .line 21
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk$c$a;->b:Lcom/salesforce/marketingcloud/MarketingCloudSdk$c;

    .line 22
    .line 23
    const/4 v1, 0x1

    .line 24
    iput-boolean v1, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk$c;->c:Z

    .line 25
    .line 26
    monitor-exit v0

    .line 27
    return-void

    .line 28
    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 29
    throw p0
.end method
