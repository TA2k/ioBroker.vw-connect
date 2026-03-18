.class public Lcom/salesforce/marketingcloud/media/p;
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
        "Landroid/widget/ImageView;",
        ">;"
    }
.end annotation


# instance fields
.field f:Lcom/salesforce/marketingcloud/media/f;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/media/o;Lcom/salesforce/marketingcloud/media/w;Lcom/salesforce/marketingcloud/media/t;Lcom/salesforce/marketingcloud/media/f;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/media/o;",
            "Lcom/salesforce/marketingcloud/media/w<",
            "Landroid/widget/ImageView;",
            ">;",
            "Lcom/salesforce/marketingcloud/media/t;",
            "Lcom/salesforce/marketingcloud/media/f;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1, p2, p3}, Lcom/salesforce/marketingcloud/media/a;-><init>(Lcom/salesforce/marketingcloud/media/o;Lcom/salesforce/marketingcloud/media/w;Lcom/salesforce/marketingcloud/media/t;)V

    .line 2
    .line 3
    .line 4
    iput-object p4, p0, Lcom/salesforce/marketingcloud/media/p;->f:Lcom/salesforce/marketingcloud/media/f;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public a()V
    .locals 1

    .line 8
    invoke-super {p0}, Lcom/salesforce/marketingcloud/media/a;->a()V

    const/4 v0, 0x0

    .line 9
    iput-object v0, p0, Lcom/salesforce/marketingcloud/media/p;->f:Lcom/salesforce/marketingcloud/media/f;

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/media/v$b;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/media/a;->b:Ljava/lang/ref/WeakReference;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/widget/ImageView;

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    if-nez v0, :cond_1

    goto :goto_1

    .line 2
    :cond_1
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/media/a;->b()Lcom/salesforce/marketingcloud/media/o;

    move-result-object v1

    iget-object v1, v1, Lcom/salesforce/marketingcloud/media/o;->a:Landroid/content/Context;

    .line 3
    invoke-static {v0, v1, p1}, Lcom/salesforce/marketingcloud/media/l;->a(Landroid/widget/ImageView;Landroid/content/Context;Lcom/salesforce/marketingcloud/media/v$b;)V

    .line 4
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/p;->f:Lcom/salesforce/marketingcloud/media/f;

    if-eqz p0, :cond_2

    .line 5
    invoke-interface {p0}, Lcom/salesforce/marketingcloud/media/f;->a()V

    :cond_2
    :goto_1
    return-void
.end method

.method public a(Ljava/lang/Exception;)V
    .locals 0

    .line 6
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/p;->f:Lcom/salesforce/marketingcloud/media/f;

    if-eqz p0, :cond_0

    .line 7
    invoke-interface {p0, p1}, Lcom/salesforce/marketingcloud/media/f;->a(Ljava/lang/Exception;)V

    :cond_0
    return-void
.end method
