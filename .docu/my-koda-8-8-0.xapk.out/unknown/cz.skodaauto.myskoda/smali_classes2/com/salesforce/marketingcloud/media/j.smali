.class public Lcom/salesforce/marketingcloud/media/j;
.super Lcom/salesforce/marketingcloud/media/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lcom/salesforce/marketingcloud/media/a<",
        "Ljava/lang/Object;",
        ">;"
    }
.end annotation


# instance fields
.field private f:Lcom/salesforce/marketingcloud/media/f;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/media/o;Lcom/salesforce/marketingcloud/media/t;Lcom/salesforce/marketingcloud/media/f;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, p1, v0, p2}, Lcom/salesforce/marketingcloud/media/a;-><init>(Lcom/salesforce/marketingcloud/media/o;Lcom/salesforce/marketingcloud/media/w;Lcom/salesforce/marketingcloud/media/t;)V

    .line 3
    .line 4
    .line 5
    iput-object p3, p0, Lcom/salesforce/marketingcloud/media/j;->f:Lcom/salesforce/marketingcloud/media/f;

    .line 6
    .line 7
    return-void
.end method


# virtual methods
.method public a()V
    .locals 1

    .line 5
    invoke-super {p0}, Lcom/salesforce/marketingcloud/media/a;->a()V

    const/4 v0, 0x0

    .line 6
    iput-object v0, p0, Lcom/salesforce/marketingcloud/media/j;->f:Lcom/salesforce/marketingcloud/media/f;

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/media/v$b;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/j;->f:Lcom/salesforce/marketingcloud/media/f;

    if-eqz p0, :cond_0

    .line 2
    invoke-interface {p0}, Lcom/salesforce/marketingcloud/media/f;->a()V

    :cond_0
    return-void
.end method

.method public a(Ljava/lang/Exception;)V
    .locals 0

    .line 3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/j;->f:Lcom/salesforce/marketingcloud/media/f;

    if-eqz p0, :cond_0

    .line 4
    invoke-interface {p0, p1}, Lcom/salesforce/marketingcloud/media/f;->a(Ljava/lang/Exception;)V

    :cond_0
    return-void
.end method
