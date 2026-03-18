.class public final synthetic Lcom/contoworks/kontocloud/uicomponents/widget/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;


# direct methods
.method public synthetic constructor <init>(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;I)V
    .locals 0

    .line 1
    iput p2, p0, Lcom/contoworks/kontocloud/uicomponents/widget/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/a;->e:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

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
    iget v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/a;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/a;->e:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-static {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->b(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)V

    .line 9
    .line 10
    .line 11
    return-void

    .line 12
    :pswitch_0
    invoke-static {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->c(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)V

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :pswitch_1
    invoke-static {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->a(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)V

    .line 17
    .line 18
    .line 19
    return-void

    .line 20
    nop

    .line 21
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
