.class public final synthetic Lcom/contoworks/kontocloud/uicomponents/widget/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/String;

.field public final synthetic g:Ljava/io/Serializable;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/String;Ljava/io/Serializable;I)V
    .locals 0

    .line 1
    iput p4, p0, Lcom/contoworks/kontocloud/uicomponents/widget/e;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/e;->e:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p2, p0, Lcom/contoworks/kontocloud/uicomponents/widget/e;->f:Ljava/lang/String;

    .line 6
    .line 7
    iput-object p3, p0, Lcom/contoworks/kontocloud/uicomponents/widget/e;->g:Ljava/io/Serializable;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 2

    .line 1
    iget v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/e;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/e;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;

    .line 9
    .line 10
    iget-object v1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/e;->g:Ljava/io/Serializable;

    .line 11
    .line 12
    check-cast v1, Ljava/util/HashMap;

    .line 13
    .line 14
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/e;->f:Ljava/lang/String;

    .line 15
    .line 16
    invoke-static {v0, p0, v1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->c(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;Ljava/lang/String;Ljava/util/HashMap;)V

    .line 17
    .line 18
    .line 19
    return-void

    .line 20
    :pswitch_0
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/e;->e:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;

    .line 23
    .line 24
    iget-object v1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/e;->g:Ljava/io/Serializable;

    .line 25
    .line 26
    check-cast v1, Ljava/lang/String;

    .line 27
    .line 28
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/e;->f:Ljava/lang/String;

    .line 29
    .line 30
    invoke-static {v0, p0, v1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->a(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;Ljava/lang/String;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    return-void

    .line 34
    :pswitch_1
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/e;->e:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;

    .line 37
    .line 38
    iget-object v1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/e;->g:Ljava/io/Serializable;

    .line 39
    .line 40
    check-cast v1, Ljava/lang/String;

    .line 41
    .line 42
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/e;->f:Ljava/lang/String;

    .line 43
    .line 44
    invoke-static {v0, p0, v1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->c(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;Ljava/lang/String;Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    return-void

    .line 48
    nop

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
