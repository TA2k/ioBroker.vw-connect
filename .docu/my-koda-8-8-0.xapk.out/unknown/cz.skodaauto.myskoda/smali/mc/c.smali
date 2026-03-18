.class public final Lmc/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback;


# instance fields
.field public final synthetic a:Lay0/k;


# direct methods
.method public constructor <init>(Lay0/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lmc/c;->a:Lay0/k;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final onBeforeSubmit(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback$OnBeforeSubmitArgs;)V
    .locals 1

    .line 1
    new-instance v0, Lmc/h;

    .line 2
    .line 3
    invoke-direct {v0, p1}, Lmc/h;-><init>(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback$OnBeforeSubmitArgs;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lmc/c;->a:Lay0/k;

    .line 7
    .line 8
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final onCancel()V
    .locals 1

    .line 1
    iget-object p0, p0, Lmc/c;->a:Lay0/k;

    .line 2
    .line 3
    sget-object v0, Lmc/g;->b:Lmc/g;

    .line 4
    .line 5
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final onError(Ljava/lang/String;)V
    .locals 1

    .line 1
    new-instance v0, Lmc/i;

    .line 2
    .line 3
    invoke-direct {v0, p1}, Lmc/i;-><init>(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lmc/c;->a:Lay0/k;

    .line 7
    .line 8
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final onSuccess(Ljava/lang/String;Ljava/lang/String;)V
    .locals 2

    .line 1
    new-instance v0, Lmc/k;

    const/4 v1, 0x0

    invoke-direct {v0, p1, p2, v1}, Lmc/k;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    iget-object p0, p0, Lmc/c;->a:Lay0/k;

    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

.method public final onSuccess(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    .line 2
    new-instance v0, Lmc/k;

    invoke-direct {v0, p1, p2, p3}, Lmc/k;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    iget-object p0, p0, Lmc/c;->a:Lay0/k;

    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method
