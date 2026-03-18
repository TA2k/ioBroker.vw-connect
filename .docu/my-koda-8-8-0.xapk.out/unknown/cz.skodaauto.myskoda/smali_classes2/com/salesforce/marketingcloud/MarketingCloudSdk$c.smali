.class abstract Lcom/salesforce/marketingcloud/MarketingCloudSdk$c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/MarketingCloudSdk;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x409
    name = "c"
.end annotation


# instance fields
.field private final a:Landroid/os/Handler;

.field b:Lcom/salesforce/marketingcloud/MarketingCloudSdk$WhenReadyListener;

.field volatile c:Z

.field private final d:Ljava/lang/Runnable;

.field private volatile e:Z


# direct methods
.method public constructor <init>(Landroid/os/Looper;Lcom/salesforce/marketingcloud/MarketingCloudSdk$WhenReadyListener;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lcom/salesforce/marketingcloud/MarketingCloudSdk$c$a;

    .line 5
    .line 6
    invoke-direct {v0, p0}, Lcom/salesforce/marketingcloud/MarketingCloudSdk$c$a;-><init>(Lcom/salesforce/marketingcloud/MarketingCloudSdk$c;)V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk$c;->d:Ljava/lang/Runnable;

    .line 10
    .line 11
    if-nez p1, :cond_1

    .line 12
    .line 13
    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    if-eqz p1, :cond_0

    .line 18
    .line 19
    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    :cond_1
    :goto_0
    iput-object p2, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk$c;->b:Lcom/salesforce/marketingcloud/MarketingCloudSdk$WhenReadyListener;

    .line 29
    .line 30
    new-instance p2, Landroid/os/Handler;

    .line 31
    .line 32
    invoke-direct {p2, p1}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 33
    .line 34
    .line 35
    iput-object p2, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk$c;->a:Landroid/os/Handler;

    .line 36
    .line 37
    return-void
.end method


# virtual methods
.method public a()V
    .locals 2

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-boolean v0, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk$c;->c:Z

    if-nez v0, :cond_1

    iget-boolean v0, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk$c;->e:Z

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    const/4 v0, 0x1

    .line 3
    iput-boolean v0, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk$c;->e:Z

    .line 4
    iget-object v0, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk$c;->a:Landroid/os/Handler;

    iget-object v1, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk$c;->d:Ljava/lang/Runnable;

    invoke-virtual {v0, v1}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 5
    monitor-exit p0

    return-void

    :catchall_0
    move-exception v0

    goto :goto_1

    .line 6
    :cond_1
    :goto_0
    monitor-exit p0

    return-void

    .line 7
    :goto_1
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw v0
.end method

.method public abstract a(Lcom/salesforce/marketingcloud/MarketingCloudSdk$WhenReadyListener;)V
.end method
