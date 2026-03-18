.class Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;
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
    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 2
    .line 3
    iput-object p2, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;->val$paymentProvider:Ljava/lang/String;

    .line 4
    .line 5
    invoke-direct {p0}, Landroid/webkit/WebViewClient;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public static synthetic a(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;Landroid/webkit/WebResourceError;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;->lambda$onReceivedError$0(Landroid/webkit/WebResourceError;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic b(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;->lambda$shouldInterceptRequest$1()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic c(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;->lambda$shouldInterceptRequest$2()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private synthetic lambda$onReceivedError$0(Landroid/webkit/WebResourceError;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 2
    .line 3
    invoke-static {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->l(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    invoke-interface {p0, p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback;->onError(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method private synthetic lambda$shouldInterceptRequest$1()V
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 2
    .line 3
    invoke-static {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->B(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method private synthetic lambda$shouldInterceptRequest$2()V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-static {v0, v1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->p(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;Z)V

    .line 5
    .line 6
    .line 7
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 8
    .line 9
    iget-object v0, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->webView:Landroid/webkit/WebView;

    .line 10
    .line 11
    invoke-virtual {v0}, Landroid/webkit/WebView;->stopLoading()V

    .line 12
    .line 13
    .line 14
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 15
    .line 16
    invoke-static {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->w(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)V

    .line 17
    .line 18
    .line 19
    return-void
.end method


# virtual methods
.method public onLoadResource(Landroid/webkit/WebView;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-super {p0, p1, p2}, Landroid/webkit/WebViewClient;->onLoadResource(Landroid/webkit/WebView;Ljava/lang/String;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public onPageCommitVisible(Landroid/webkit/WebView;Ljava/lang/String;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;->val$paymentProvider:Ljava/lang/String;

    .line 2
    .line 3
    const-string v1, "Sepa"

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 12
    .line 13
    invoke-static {v0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->w(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)V

    .line 14
    .line 15
    .line 16
    :cond_0
    invoke-super {p0, p1, p2}, Landroid/webkit/WebViewClient;->onPageCommitVisible(Landroid/webkit/WebView;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public onPageFinished(Landroid/webkit/WebView;Ljava/lang/String;)V
    .locals 1

    .line 1
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 2
    .line 3
    invoke-static {p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->n(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->getApiUrl()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    invoke-virtual {p2, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result p1

    .line 15
    if-eqz p1, :cond_0

    .line 16
    .line 17
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 18
    .line 19
    invoke-static {p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->i(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Z

    .line 20
    .line 21
    .line 22
    move-result p1

    .line 23
    if-eqz p1, :cond_2

    .line 24
    .line 25
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 26
    .line 27
    invoke-static {p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->y(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)V

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;->val$paymentProvider:Ljava/lang/String;

    .line 32
    .line 33
    const-string v0, "CyberSource"

    .line 34
    .line 35
    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result p1

    .line 39
    if-nez p1, :cond_1

    .line 40
    .line 41
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;->val$paymentProvider:Ljava/lang/String;

    .line 42
    .line 43
    const-string v0, "CyberSourceWithTokenEx"

    .line 44
    .line 45
    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result p1

    .line 49
    if-nez p1, :cond_1

    .line 50
    .line 51
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;->val$paymentProvider:Ljava/lang/String;

    .line 52
    .line 53
    const-string v0, "PayonWithPCIProxy"

    .line 54
    .line 55
    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result p1

    .line 59
    if-nez p1, :cond_1

    .line 60
    .line 61
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;->val$paymentProvider:Ljava/lang/String;

    .line 62
    .line 63
    const-string v0, "Sepa"

    .line 64
    .line 65
    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    move-result p1

    .line 69
    if-nez p1, :cond_1

    .line 70
    .line 71
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;->val$paymentProvider:Ljava/lang/String;

    .line 72
    .line 73
    const-string v0, "VestaWithTokenEx"

    .line 74
    .line 75
    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result p1

    .line 79
    if-eqz p1, :cond_2

    .line 80
    .line 81
    :cond_1
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 82
    .line 83
    invoke-static {p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->B(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)V

    .line 84
    .line 85
    .line 86
    :cond_2
    :goto_0
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 87
    .line 88
    invoke-static {p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->l(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback;

    .line 89
    .line 90
    .line 91
    move-result-object p1

    .line 92
    if-eqz p1, :cond_3

    .line 93
    .line 94
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 95
    .line 96
    invoke-static {p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->n(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    .line 97
    .line 98
    .line 99
    move-result-object p1

    .line 100
    invoke-virtual {p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->getRedirectUrl()Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object p1

    .line 104
    invoke-virtual {p2, p1}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 105
    .line 106
    .line 107
    move-result p1

    .line 108
    if-nez p1, :cond_3

    .line 109
    .line 110
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 111
    .line 112
    invoke-static {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->w(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)V

    .line 113
    .line 114
    .line 115
    :cond_3
    return-void
.end method

.method public onReceivedError(Landroid/webkit/WebView;Landroid/webkit/WebResourceRequest;Landroid/webkit/WebResourceError;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 2
    .line 3
    invoke-static {v0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->j(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 10
    .line 11
    invoke-static {v0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->t(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)V

    .line 12
    .line 13
    .line 14
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 15
    .line 16
    invoke-static {v0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->y(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)V

    .line 17
    .line 18
    .line 19
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 20
    .line 21
    invoke-static {v0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->l(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    if-eqz v0, :cond_0

    .line 26
    .line 27
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 28
    .line 29
    new-instance v1, Lcom/contoworks/kontocloud/uicomponents/widget/b;

    .line 30
    .line 31
    const/4 v2, 0x0

    .line 32
    invoke-direct {v1, v2, p0, p3}, Lcom/contoworks/kontocloud/uicomponents/widget/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {v0, v1}, Landroid/view/View;->post(Ljava/lang/Runnable;)Z

    .line 36
    .line 37
    .line 38
    :cond_0
    invoke-super {p0, p1, p2, p3}, Landroid/webkit/WebViewClient;->onReceivedError(Landroid/webkit/WebView;Landroid/webkit/WebResourceRequest;Landroid/webkit/WebResourceError;)V

    .line 39
    .line 40
    .line 41
    return-void
.end method

.method public onReceivedHttpError(Landroid/webkit/WebView;Landroid/webkit/WebResourceRequest;Landroid/webkit/WebResourceResponse;)V
    .locals 0

    .line 1
    invoke-virtual {p3}, Landroid/webkit/WebResourceResponse;->getStatusCode()I

    .line 2
    .line 3
    .line 4
    invoke-virtual {p3}, Landroid/webkit/WebResourceResponse;->getReasonPhrase()Ljava/lang/String;

    .line 5
    .line 6
    .line 7
    invoke-super {p0, p1, p2, p3}, Landroid/webkit/WebViewClient;->onReceivedHttpError(Landroid/webkit/WebView;Landroid/webkit/WebResourceRequest;Landroid/webkit/WebResourceResponse;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public shouldInterceptRequest(Landroid/webkit/WebView;Landroid/webkit/WebResourceRequest;)Landroid/webkit/WebResourceResponse;
    .locals 4

    .line 1
    invoke-interface {p2}, Landroid/webkit/WebResourceRequest;->getUrl()Landroid/net/Uri;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Landroid/net/Uri;->toString()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iget-object v1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 10
    .line 11
    invoke-static {v1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->j(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Z

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-eqz v1, :cond_0

    .line 16
    .line 17
    new-instance v1, Landroid/os/Handler;

    .line 18
    .line 19
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    invoke-direct {v1, v2}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 24
    .line 25
    .line 26
    new-instance v2, Lcom/contoworks/kontocloud/uicomponents/widget/c;

    .line 27
    .line 28
    const/4 v3, 0x0

    .line 29
    invoke-direct {v2, p0, v3}, Lcom/contoworks/kontocloud/uicomponents/widget/c;-><init>(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;I)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {v1, v2}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 33
    .line 34
    .line 35
    :cond_0
    iget-object v1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 36
    .line 37
    invoke-static {v1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->n(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    invoke-virtual {v1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->getRedirectUrl()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 46
    .line 47
    .line 48
    move-result v0

    .line 49
    if-eqz v0, :cond_1

    .line 50
    .line 51
    new-instance v0, Landroid/os/Handler;

    .line 52
    .line 53
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    invoke-direct {v0, v1}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 58
    .line 59
    .line 60
    new-instance v1, Lcom/contoworks/kontocloud/uicomponents/widget/c;

    .line 61
    .line 62
    const/4 v2, 0x1

    .line 63
    invoke-direct {v1, p0, v2}, Lcom/contoworks/kontocloud/uicomponents/widget/c;-><init>(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;I)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {v0, v1}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 67
    .line 68
    .line 69
    :cond_1
    invoke-super {p0, p1, p2}, Landroid/webkit/WebViewClient;->shouldInterceptRequest(Landroid/webkit/WebView;Landroid/webkit/WebResourceRequest;)Landroid/webkit/WebResourceResponse;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    return-object p0
.end method

.method public shouldOverrideUrlLoading(Landroid/webkit/WebView;Landroid/webkit/WebResourceRequest;)Z
    .locals 0
    .annotation build Landroid/annotation/TargetApi;
        value = 0x18
    .end annotation

    .line 2
    invoke-super {p0, p1, p2}, Landroid/webkit/WebViewClient;->shouldOverrideUrlLoading(Landroid/webkit/WebView;Landroid/webkit/WebResourceRequest;)Z

    move-result p0

    return p0
.end method

.method public shouldOverrideUrlLoading(Landroid/webkit/WebView;Ljava/lang/String;)Z
    .locals 0

    .line 1
    invoke-super {p0, p1, p2}, Landroid/webkit/WebViewClient;->shouldOverrideUrlLoading(Landroid/webkit/WebView;Ljava/lang/String;)Z

    move-result p0

    return p0
.end method
