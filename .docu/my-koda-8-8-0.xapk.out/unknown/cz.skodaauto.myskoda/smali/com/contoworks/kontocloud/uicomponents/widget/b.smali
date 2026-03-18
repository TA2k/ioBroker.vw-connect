.class public final synthetic Lcom/contoworks/kontocloud/uicomponents/widget/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/b;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Lcom/contoworks/kontocloud/uicomponents/widget/b;->e:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p3, p0, Lcom/contoworks/kontocloud/uicomponents/widget/b;->f:Ljava/lang/Object;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 1

    .line 1
    iget v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/b;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;

    .line 9
    .line 10
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/b;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Ljava/lang/String;

    .line 13
    .line 14
    invoke-static {v0, p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->a(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :pswitch_0
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/b;->e:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;

    .line 21
    .line 22
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/b;->f:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast p0, Ljava/lang/String;

    .line 25
    .line 26
    invoke-static {v0, p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->d(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    return-void

    .line 30
    :pswitch_1
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/b;->e:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;

    .line 33
    .line 34
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/b;->f:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast p0, Landroid/webkit/WebResourceError;

    .line 37
    .line 38
    invoke-static {v0, p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;->a(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;Landroid/webkit/WebResourceError;)V

    .line 39
    .line 40
    .line 41
    return-void

    .line 42
    nop

    .line 43
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
