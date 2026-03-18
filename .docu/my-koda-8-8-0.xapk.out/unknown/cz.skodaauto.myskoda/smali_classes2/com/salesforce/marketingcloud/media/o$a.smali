.class Lcom/salesforce/marketingcloud/media/o$a;
.super Landroid/os/Handler;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/media/o;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# direct methods
.method public constructor <init>(Landroid/os/Looper;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public handleMessage(Landroid/os/Message;)V
    .locals 1

    .line 1
    iget p0, p1, Landroid/os/Message;->what:I

    .line 2
    .line 3
    const/4 v0, 0x2

    .line 4
    if-eq p0, v0, :cond_1

    .line 5
    .line 6
    const/4 v0, 0x5

    .line 7
    if-eq p0, v0, :cond_0

    .line 8
    .line 9
    return-void

    .line 10
    :cond_0
    iget-object p0, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Lcom/salesforce/marketingcloud/media/e;

    .line 13
    .line 14
    iget-object p1, p0, Lcom/salesforce/marketingcloud/media/e;->b:Lcom/salesforce/marketingcloud/media/o;

    .line 15
    .line 16
    invoke-virtual {p1, p0}, Lcom/salesforce/marketingcloud/media/o;->a(Lcom/salesforce/marketingcloud/media/e;)V

    .line 17
    .line 18
    .line 19
    return-void

    .line 20
    :cond_1
    iget-object p0, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast p0, Lcom/salesforce/marketingcloud/media/n;

    .line 23
    .line 24
    iget-object p1, p0, Lcom/salesforce/marketingcloud/media/n;->b:Lcom/salesforce/marketingcloud/media/o;

    .line 25
    .line 26
    invoke-virtual {p1, p0}, Lcom/salesforce/marketingcloud/media/o;->a(Lcom/salesforce/marketingcloud/media/n;)V

    .line 27
    .line 28
    .line 29
    return-void
.end method
