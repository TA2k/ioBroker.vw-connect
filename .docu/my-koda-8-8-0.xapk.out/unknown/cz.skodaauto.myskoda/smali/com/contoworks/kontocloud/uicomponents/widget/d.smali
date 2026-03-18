.class public final synthetic Lcom/contoworks/kontocloud/uicomponents/widget/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lcom/contoworks/kontocloud/uicomponents/widget/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/d;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 1

    .line 1
    iget v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/d;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/d;->e:Ljava/lang/Object;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;

    .line 9
    .line 10
    invoke-static {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->b(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;)V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :pswitch_0
    check-cast p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;

    .line 15
    .line 16
    invoke-static {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->b(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;)V

    .line 17
    .line 18
    .line 19
    return-void

    .line 20
    nop

    .line 21
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
