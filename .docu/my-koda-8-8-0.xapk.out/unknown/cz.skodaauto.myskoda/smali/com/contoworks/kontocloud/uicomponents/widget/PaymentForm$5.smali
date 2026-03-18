.class Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;
.super Landroid/webkit/WebViewClient;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->setWebViewClient(Ljava/lang/String;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

.field final synthetic val$paymentProvider:Ljava/lang/String;


# direct methods
.method public constructor <init>(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 2
    .line 3
    iput-object p2, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->val$paymentProvider:Ljava/lang/String;

    .line 4
    .line 5
    invoke-direct {p0}, Landroid/webkit/WebViewClient;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public static synthetic a(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->lambda$shouldOverrideUrlLoading$2(Ljava/lang/String;Ljava/lang/String;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic b(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->lambda$shouldOverrideUrlLoading$0()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic c(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->lambda$shouldOverrideUrlLoading$1(Ljava/lang/String;Ljava/lang/String;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic d(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->lambda$onPageFinished$3(Ljava/lang/String;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private synthetic lambda$onPageFinished$3(Ljava/lang/String;)V
    .locals 1

    .line 1
    const-string v0, "PaymentOS"

    .line 2
    .line 3
    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    if-eqz p1, :cond_0

    .line 8
    .line 9
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 10
    .line 11
    invoke-static {p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->k(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Z

    .line 12
    .line 13
    .line 14
    move-result p1

    .line 15
    if-nez p1, :cond_1

    .line 16
    .line 17
    :cond_0
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 18
    .line 19
    invoke-static {p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->y(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)V

    .line 20
    .line 21
    .line 22
    :cond_1
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 23
    .line 24
    iget-object v0, p1, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->jsCalls:Ljava/util/List;

    .line 25
    .line 26
    invoke-static {p1, v0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->A(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;Ljava/util/List;)V

    .line 27
    .line 28
    .line 29
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 30
    .line 31
    iget-object p1, p1, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->jsCalls:Ljava/util/List;

    .line 32
    .line 33
    invoke-interface {p1}, Ljava/util/List;->clear()V

    .line 34
    .line 35
    .line 36
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 37
    .line 38
    invoke-static {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->v(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)V

    .line 39
    .line 40
    .line 41
    return-void
.end method

.method private synthetic lambda$shouldOverrideUrlLoading$0()V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 2
    .line 3
    invoke-static {v0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->r(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 7
    .line 8
    invoke-static {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->l(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    invoke-interface {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback;->onCancel()V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method private synthetic lambda$shouldOverrideUrlLoading$1(Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 4
    .line 5
    invoke-static {p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->l(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 10
    .line 11
    invoke-static {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->d(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-interface {p1, p2, p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback;->onSuccess(Ljava/lang/String;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 20
    .line 21
    invoke-static {v0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->l(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 26
    .line 27
    invoke-static {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->d(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    invoke-interface {v0, p2, p0, p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback;->onSuccess(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    return-void
.end method

.method private synthetic lambda$shouldOverrideUrlLoading$2(Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 4
    .line 5
    invoke-static {p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->l(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 10
    .line 11
    invoke-static {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->d(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-interface {p1, p2, p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback;->onSuccess(Ljava/lang/String;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 20
    .line 21
    invoke-static {v0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->l(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 26
    .line 27
    invoke-static {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->d(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    invoke-interface {v0, p2, p0, p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback;->onSuccess(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    return-void
.end method

.method private shouldOverrideUrlLoading(Landroid/net/Uri;)Z
    .locals 7

    .line 3
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    invoke-static {v0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->l(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback;

    move-result-object v0

    const/4 v1, 0x0

    if-eqz v0, :cond_7

    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    invoke-static {v0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->h(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Z

    move-result v0

    if-nez v0, :cond_7

    .line 4
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 5
    const-string v2, "https://www.kontocloud.com/callbacks/payon/"

    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 6
    iget-object v2, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    invoke-static {v2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->n(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    move-result-object v2

    invoke-virtual {v2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->getRedirectUrl()Ljava/lang/String;

    move-result-object v2

    if-eqz v2, :cond_0

    .line 7
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 8
    :cond_0
    iget-object v2, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    invoke-static {v2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->n(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    move-result-object v2

    invoke-virtual {v2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->getPaymentProvider()Ljava/lang/String;

    move-result-object v2

    const-string v3, "PayPal"

    invoke-virtual {v2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    const-string v4, "https://www.kontocloud.com/callbacks/paypal/cancel/"

    if-eqz v2, :cond_1

    .line 9
    const-string v2, "https://www.kontocloud.com/callbacks/paypal/success/"

    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 10
    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 11
    :cond_1
    invoke-virtual {p1}, Landroid/net/Uri;->toString()Ljava/lang/String;

    move-result-object v2

    .line 12
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_7

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/lang/String;

    .line 13
    iget-object v6, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    invoke-static {v6, v5}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->x(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v6

    .line 14
    invoke-virtual {v2, v6}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v6

    if-eqz v6, :cond_2

    .line 15
    invoke-virtual {v5, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    const/4 v2, 0x1

    if-eqz v0, :cond_3

    .line 16
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    new-instance v0, Lcom/contoworks/kontocloud/uicomponents/widget/d;

    const/4 v1, 0x0

    invoke-direct {v0, p0, v1}, Lcom/contoworks/kontocloud/uicomponents/widget/d;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {p1, v0}, Landroid/view/View;->post(Ljava/lang/Runnable;)Z

    return v2

    .line 17
    :cond_3
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    iget-object v4, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->processingPayments:Ljava/util/Map;

    invoke-static {v0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->d(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Ljava/lang/String;

    move-result-object v0

    invoke-interface {v4, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/String;

    if-eqz v0, :cond_6

    .line 18
    iget-object v4, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    invoke-static {v4}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->n(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    move-result-object v4

    invoke-virtual {v4}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->getPaymentProvider()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v4, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_4

    .line 19
    const-string v3, "PayerID"

    invoke-virtual {p1, v3}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    goto :goto_0

    :cond_4
    const/4 p1, 0x0

    .line 20
    :goto_0
    iget-object v3, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    invoke-static {v3}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->n(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    move-result-object v3

    invoke-virtual {v3}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->getPaymentProvider()Ljava/lang/String;

    move-result-object v3

    const-string v4, "PaymentOS"

    invoke-virtual {v3, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_5

    .line 21
    iget-object v2, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    invoke-static {v2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->B(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)V

    .line 22
    iget-object v2, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    invoke-static {v2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->u(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)V

    .line 23
    iget-object v2, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    invoke-static {v2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->r(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)V

    .line 24
    iget-object v2, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    invoke-virtual {v2}, Lcom/contoworks/kontocloud/uicomponents/widget/CompoundView;->getUiHandler()Landroid/os/Handler;

    move-result-object v2

    new-instance v3, Lcom/contoworks/kontocloud/uicomponents/widget/e;

    const/4 v4, 0x0

    invoke-direct {v3, p0, p1, v0, v4}, Lcom/contoworks/kontocloud/uicomponents/widget/e;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/io/Serializable;I)V

    const-wide/16 p0, 0xbb8

    invoke-virtual {v2, v3, p0, p1}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    return v1

    .line 25
    :cond_5
    iget-object v1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    invoke-static {v1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->r(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)V

    .line 26
    iget-object v1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    new-instance v3, Lcom/contoworks/kontocloud/uicomponents/widget/e;

    const/4 v4, 0x1

    invoke-direct {v3, p0, p1, v0, v4}, Lcom/contoworks/kontocloud/uicomponents/widget/e;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/io/Serializable;I)V

    invoke-virtual {v1, v3}, Landroid/view/View;->post(Ljava/lang/Runnable;)Z

    return v2

    .line 27
    :cond_6
    new-instance p1, Ljava/lang/IllegalStateException;

    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    invoke-static {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->d(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Ljava/lang/String;

    move-result-object p0

    const-string v0, "Payment option code not found for \'"

    const-string v1, "\'"

    .line 28
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    .line 29
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_7
    return v1
.end method


# virtual methods
.method public onPageFinished(Landroid/webkit/WebView;Ljava/lang/String;)V
    .locals 3

    .line 1
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 2
    .line 3
    invoke-virtual {p1}, Lcom/contoworks/kontocloud/uicomponents/widget/CompoundView;->getUiHandler()Landroid/os/Handler;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    iget-object p2, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->val$paymentProvider:Ljava/lang/String;

    .line 8
    .line 9
    new-instance v0, Lcom/contoworks/kontocloud/uicomponents/widget/b;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-direct {v0, v1, p0, p2}, Lcom/contoworks/kontocloud/uicomponents/widget/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    const-wide/16 v1, 0x190

    .line 16
    .line 17
    invoke-virtual {p1, v0, v1, v2}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public shouldOverrideUrlLoading(Landroid/webkit/WebView;Landroid/webkit/WebResourceRequest;)Z
    .locals 0
    .annotation build Landroid/annotation/TargetApi;
        value = 0x18
    .end annotation

    .line 2
    invoke-interface {p2}, Landroid/webkit/WebResourceRequest;->getUrl()Landroid/net/Uri;

    move-result-object p1

    invoke-direct {p0, p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->shouldOverrideUrlLoading(Landroid/net/Uri;)Z

    move-result p0

    return p0
.end method

.method public shouldOverrideUrlLoading(Landroid/webkit/WebView;Ljava/lang/String;)Z
    .locals 0

    .line 1
    invoke-static {p2}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    move-result-object p1

    invoke-direct {p0, p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;->shouldOverrideUrlLoading(Landroid/net/Uri;)Z

    move-result p0

    return p0
.end method
