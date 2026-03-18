.class Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->validateElement(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$FormElement;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

.field final synthetic val$jsValidationScriptStr:Ljava/lang/String;


# direct methods
.method public constructor <init>(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;Ljava/lang/String;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$1;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 2
    .line 3
    iput-object p2, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$1;->val$jsValidationScriptStr:Ljava/lang/String;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public run()V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$1;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 2
    .line 3
    iget-object v0, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->webView:Landroid/webkit/WebView;

    .line 4
    .line 5
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$1;->val$jsValidationScriptStr:Ljava/lang/String;

    .line 6
    .line 7
    invoke-virtual {v0, p0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method
