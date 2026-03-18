.class Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->continueValidationElement(Ljava/lang/String;Ljava/lang/String;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

.field final synthetic val$isSubmited:Ljava/lang/String;

.field final synthetic val$jsValidationScriptStr:Ljava/lang/String;


# direct methods
.method public constructor <init>(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$2;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 2
    .line 3
    iput-object p2, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$2;->val$jsValidationScriptStr:Ljava/lang/String;

    .line 4
    .line 5
    iput-object p3, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$2;->val$isSubmited:Ljava/lang/String;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public run()V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$2;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 2
    .line 3
    iget-object v0, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->webView:Landroid/webkit/WebView;

    .line 4
    .line 5
    iget-object v1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$2;->val$jsValidationScriptStr:Ljava/lang/String;

    .line 6
    .line 7
    invoke-virtual {v0, v1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$2;->val$isSubmited:Ljava/lang/String;

    .line 11
    .line 12
    const-string v1, "true"

    .line 13
    .line 14
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$2;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 21
    .line 22
    invoke-virtual {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->clearHiddenElementErrors()V

    .line 23
    .line 24
    .line 25
    :cond_0
    return-void
.end method
