.class Lcom/salesforce/marketingcloud/media/h$a;
.super Landroid/os/Handler;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/media/h;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "a"
.end annotation


# instance fields
.field private final a:Lcom/salesforce/marketingcloud/media/h;


# direct methods
.method public constructor <init>(Landroid/os/Looper;Lcom/salesforce/marketingcloud/media/h;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lcom/salesforce/marketingcloud/media/h$a;->a:Lcom/salesforce/marketingcloud/media/h;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public handleMessage(Landroid/os/Message;)V
    .locals 1

    .line 1
    iget v0, p1, Landroid/os/Message;->what:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    return-void

    .line 7
    :pswitch_0
    iget-object p1, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p1, Lcom/salesforce/marketingcloud/media/a;

    .line 10
    .line 11
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/h$a;->a:Lcom/salesforce/marketingcloud/media/h;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/media/h;->c(Lcom/salesforce/marketingcloud/media/a;)V

    .line 14
    .line 15
    .line 16
    return-void

    .line 17
    :pswitch_1
    iget-object p1, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast p1, Lcom/salesforce/marketingcloud/media/e;

    .line 20
    .line 21
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/h$a;->a:Lcom/salesforce/marketingcloud/media/h;

    .line 22
    .line 23
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/media/h;->b(Lcom/salesforce/marketingcloud/media/e;)V

    .line 24
    .line 25
    .line 26
    return-void

    .line 27
    :pswitch_2
    iget-object p1, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast p1, Lcom/salesforce/marketingcloud/media/d;

    .line 30
    .line 31
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/h$a;->a:Lcom/salesforce/marketingcloud/media/h;

    .line 32
    .line 33
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/media/h;->b(Lcom/salesforce/marketingcloud/media/d;)V

    .line 34
    .line 35
    .line 36
    return-void

    .line 37
    :pswitch_3
    iget-object p1, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast p1, Lcom/salesforce/marketingcloud/media/n;

    .line 40
    .line 41
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/h$a;->a:Lcom/salesforce/marketingcloud/media/h;

    .line 42
    .line 43
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/media/h;->e(Lcom/salesforce/marketingcloud/media/n;)V

    .line 44
    .line 45
    .line 46
    return-void

    .line 47
    :pswitch_4
    iget-object p1, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast p1, Lcom/salesforce/marketingcloud/media/n;

    .line 50
    .line 51
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/h$a;->a:Lcom/salesforce/marketingcloud/media/h;

    .line 52
    .line 53
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/media/h;->d(Lcom/salesforce/marketingcloud/media/n;)V

    .line 54
    .line 55
    .line 56
    return-void

    .line 57
    :pswitch_5
    iget-object p1, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast p1, Lcom/salesforce/marketingcloud/media/a;

    .line 60
    .line 61
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/h$a;->a:Lcom/salesforce/marketingcloud/media/h;

    .line 62
    .line 63
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/media/h;->d(Lcom/salesforce/marketingcloud/media/a;)V

    .line 64
    .line 65
    .line 66
    return-void

    .line 67
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
