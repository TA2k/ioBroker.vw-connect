.class Lcom/salesforce/marketingcloud/MarketingCloudSdk$a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/MarketingCloudSdk;->b(Landroid/content/Context;Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;Lcom/salesforce/marketingcloud/MarketingCloudSdk$InitializationListener;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic b:Landroid/content/Context;

.field final synthetic c:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

.field final synthetic d:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;

.field final synthetic e:Lcom/salesforce/marketingcloud/MarketingCloudSdk$InitializationListener;


# direct methods
.method public constructor <init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;Lcom/salesforce/marketingcloud/MarketingCloudSdk$InitializationListener;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk$a;->b:Landroid/content/Context;

    .line 2
    .line 3
    iput-object p2, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk$a;->c:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 4
    .line 5
    iput-object p3, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk$a;->d:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;

    .line 6
    .line 7
    iput-object p4, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk$a;->e:Lcom/salesforce/marketingcloud/MarketingCloudSdk$InitializationListener;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public run()V
    .locals 6

    .line 1
    const-string v0, "~~ MarketingCloudSdk v%s init complete ~~"

    .line 2
    .line 3
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-virtual {v1}, Ljava/lang/Thread;->getName()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    const-string v3, "SFMC_init"

    .line 16
    .line 17
    invoke-virtual {v2, v3}, Ljava/lang/Thread;->setName(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    :try_start_0
    sget-object v2, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->v:Ljava/lang/String;

    .line 21
    .line 22
    const-string v3, "Starting init thread"

    .line 23
    .line 24
    const/4 v4, 0x0

    .line 25
    new-array v4, v4, [Ljava/lang/Object;

    .line 26
    .line 27
    invoke-static {v2, v3, v4}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    iget-object v3, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk$a;->b:Landroid/content/Context;

    .line 31
    .line 32
    iget-object v4, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk$a;->c:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 33
    .line 34
    iget-object v5, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk$a;->d:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;

    .line 35
    .line 36
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk$a;->e:Lcom/salesforce/marketingcloud/MarketingCloudSdk$InitializationListener;

    .line 37
    .line 38
    invoke-static {v3, v4, v5, p0}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->a(Landroid/content/Context;Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;Lcom/salesforce/marketingcloud/MarketingCloudSdk$InitializationListener;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 39
    .line 40
    .line 41
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    invoke-virtual {p0, v1}, Ljava/lang/Thread;->setName(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    invoke-static {}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->getSdkVersionName()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    invoke-static {v2, v0, p0}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    return-void

    .line 60
    :catchall_0
    move-exception p0

    .line 61
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 62
    .line 63
    .line 64
    move-result-object v2

    .line 65
    invoke-virtual {v2, v1}, Ljava/lang/Thread;->setName(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    sget-object v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->v:Ljava/lang/String;

    .line 69
    .line 70
    invoke-static {}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->getSdkVersionName()Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object v2

    .line 74
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v2

    .line 78
    invoke-static {v1, v0, v2}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    throw p0
.end method
