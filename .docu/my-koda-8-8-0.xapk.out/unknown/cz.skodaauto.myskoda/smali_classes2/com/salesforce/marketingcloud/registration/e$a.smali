.class Lcom/salesforce/marketingcloud/registration/e$a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/MarketingCloudSdk$WhenReadyListener;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/registration/e;->a(Z)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic a:Z

.field final synthetic b:Lcom/salesforce/marketingcloud/registration/e;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/registration/e;Z)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/registration/e$a;->b:Lcom/salesforce/marketingcloud/registration/e;

    .line 2
    .line 3
    iput-boolean p2, p0, Lcom/salesforce/marketingcloud/registration/e$a;->a:Z

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public ready(Lcom/salesforce/marketingcloud/MarketingCloudSdk;)V
    .locals 1

    .line 1
    new-instance p1, Lcom/salesforce/marketingcloud/registration/e$a$a;

    .line 2
    .line 3
    iget-boolean v0, p0, Lcom/salesforce/marketingcloud/registration/e$a;->a:Z

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    const/16 v0, 0x3e8

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const/4 v0, 0x0

    .line 11
    :goto_0
    invoke-direct {p1, p0, v0}, Lcom/salesforce/marketingcloud/registration/e$a$a;-><init>(Lcom/salesforce/marketingcloud/registration/e$a;I)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p1}, Landroid/os/CountDownTimer;->start()Landroid/os/CountDownTimer;

    .line 15
    .line 16
    .line 17
    return-void
.end method
