.class Lcom/salesforce/marketingcloud/registration/e$a$a;
.super Lcom/salesforce/marketingcloud/registration/e$e;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/registration/e$a;->ready(Lcom/salesforce/marketingcloud/MarketingCloudSdk;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic a:Lcom/salesforce/marketingcloud/registration/e$a;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/registration/e$a;I)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/registration/e$a$a;->a:Lcom/salesforce/marketingcloud/registration/e$a;

    .line 2
    .line 3
    invoke-direct {p0, p2}, Lcom/salesforce/marketingcloud/registration/e$e;-><init>(I)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public onFinish()V
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/registration/e$a$a;->a:Lcom/salesforce/marketingcloud/registration/e$a;

    .line 2
    .line 3
    iget-object v0, v0, Lcom/salesforce/marketingcloud/registration/e$a;->b:Lcom/salesforce/marketingcloud/registration/e;

    .line 4
    .line 5
    iget-object v0, v0, Lcom/salesforce/marketingcloud/registration/e;->i:Lcom/salesforce/marketingcloud/internal/n;

    .line 6
    .line 7
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    new-instance v1, Lcom/salesforce/marketingcloud/registration/e$a$a$a;

    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    new-array v2, v2, [Ljava/lang/Object;

    .line 15
    .line 16
    const-string v3, "registration_request"

    .line 17
    .line 18
    invoke-direct {v1, p0, v3, v2}, Lcom/salesforce/marketingcloud/registration/e$a$a$a;-><init>(Lcom/salesforce/marketingcloud/registration/e$a$a;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 22
    .line 23
    .line 24
    return-void
.end method
