.class public Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;
.super Lcom/contoworks/kontocloud/uicomponents/widget/CompoundView;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$FormElement;,
        Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback;,
        Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnValidationCallback;,
        Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$SavedState;
    }
.end annotation


# static fields
.field private static final TAG:Ljava/lang/String; = "PAYMENT_FORM"

.field private static paymentOptionCards:Ljava/util/Collection;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private static payonBrandMap:Ljava/util/HashMap;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/HashMap<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field private final MAX_CARDHOLDER_LENGTH:Ljava/lang/Integer;

.field private final PAYON_CALLBACK_URL:Ljava/lang/String;

.field private final PAYPAL_CALLBACK_CANCEL_URL:Ljava/lang/String;

.field private final PAYPAL_CALLBACK_SUCCESS_URL:Ljava/lang/String;

.field private authorizationToken:Ljava/lang/String;

.field private formPostParams:Ljava/lang/String;

.field private isAlreadyRedirect:Z

.field private isBeforeSubmitAccepted:Z

.field private isFormFinished:Z

.field private isFormLoaded:Z

.field private isFormSubmitted:Z

.field private isPayuFinished:Z

.field private isWebViewLoaded:Z

.field jsCalls:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private onBeforeSubmitParams:Ljava/lang/String;

.field private onSubmitCallback:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback;

.field private onValidationCallback:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnValidationCallback;

.field private options:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

.field private payPalButtonStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;

.field private final paymentFormVersion:Ljava/lang/String;

.field processingPayments:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field progressBarView:Landroid/widget/ProgressBar;

.field visibleElements:Ljava/util/HashSet;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/HashSet<",
            "Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$FormElement;",
            ">;"
        }
    .end annotation
.end field

.field webView:Landroid/webkit/WebView;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->payonBrandMap:Ljava/util/HashMap;

    .line 7
    .line 8
    const-string v1, "BNKACCT"

    .line 9
    .line 10
    const-string v2, "DIRECTDEBIT_SEPA"

    .line 11
    .line 12
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    sget-object v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->payonBrandMap:Ljava/util/HashMap;

    .line 16
    .line 17
    const-string v1, "VISA"

    .line 18
    .line 19
    invoke-virtual {v0, v1, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    sget-object v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->payonBrandMap:Ljava/util/HashMap;

    .line 23
    .line 24
    const-string v2, "MASTER"

    .line 25
    .line 26
    const-string v3, "MSTRCRD"

    .line 27
    .line 28
    invoke-virtual {v0, v3, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    sget-object v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->payonBrandMap:Ljava/util/HashMap;

    .line 32
    .line 33
    const-string v2, "PAYPAL"

    .line 34
    .line 35
    invoke-virtual {v0, v2, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    new-instance v0, Ljava/util/ArrayList;

    .line 39
    .line 40
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 41
    .line 42
    .line 43
    sput-object v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->paymentOptionCards:Ljava/util/Collection;

    .line 44
    .line 45
    invoke-interface {v0, v1}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    sget-object v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->paymentOptionCards:Ljava/util/Collection;

    .line 49
    .line 50
    invoke-interface {v0, v3}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    sget-object v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->paymentOptionCards:Ljava/util/Collection;

    .line 54
    .line 55
    const-string v1, "AMEX"

    .line 56
    .line 57
    invoke-interface {v0, v1}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    sget-object v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->paymentOptionCards:Ljava/util/Collection;

    .line 61
    .line 62
    const-string v1, "MSTRO"

    .line 63
    .line 64
    invoke-interface {v0, v1}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    sget-object v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->paymentOptionCards:Ljava/util/Collection;

    .line 68
    .line 69
    const-string v1, "DISCOVER"

    .line 70
    .line 71
    invoke-interface {v0, v1}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lcom/contoworks/kontocloud/uicomponents/widget/CompoundView;-><init>(Landroid/content/Context;)V

    .line 2
    const-string p1, "https://www.kontocloud.com/callbacks/payon/"

    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->PAYON_CALLBACK_URL:Ljava/lang/String;

    .line 3
    const-string p1, "https://www.kontocloud.com/callbacks/paypal/success/"

    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->PAYPAL_CALLBACK_SUCCESS_URL:Ljava/lang/String;

    .line 4
    const-string p1, "https://www.kontocloud.com/callbacks/paypal/cancel/"

    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->PAYPAL_CALLBACK_CANCEL_URL:Ljava/lang/String;

    const/16 p1, 0xc9

    .line 5
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->MAX_CARDHOLDER_LENGTH:Ljava/lang/Integer;

    .line 6
    const-string p1, "7.4.0"

    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->paymentFormVersion:Ljava/lang/String;

    .line 7
    new-instance p1, Ljava/util/HashMap;

    invoke-direct {p1}, Ljava/util/HashMap;-><init>()V

    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->processingPayments:Ljava/util/Map;

    .line 8
    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->jsCalls:Ljava/util/List;

    .line 9
    new-instance p1, Ljava/util/HashSet;

    invoke-direct {p1}, Ljava/util/HashSet;-><init>()V

    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->visibleElements:Ljava/util/HashSet;

    .line 10
    new-instance p1, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    invoke-direct {p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;-><init>()V

    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->options:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    const/4 p1, 0x0

    .line 11
    iput-boolean p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isBeforeSubmitAccepted:Z

    .line 12
    iput-boolean p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isWebViewLoaded:Z

    .line 13
    iput-boolean p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isPayuFinished:Z

    .line 14
    iput-boolean p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isFormLoaded:Z

    .line 15
    iput-boolean p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isFormSubmitted:Z

    .line 16
    iput-boolean p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isFormFinished:Z

    .line 17
    iput-boolean p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isAlreadyRedirect:Z

    .line 18
    new-instance p1, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;

    invoke-direct {p1}, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;-><init>()V

    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->payPalButtonStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;)V
    .locals 0

    .line 19
    invoke-direct {p0, p1, p2}, Lcom/contoworks/kontocloud/uicomponents/widget/CompoundView;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    .line 20
    const-string p1, "https://www.kontocloud.com/callbacks/payon/"

    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->PAYON_CALLBACK_URL:Ljava/lang/String;

    .line 21
    const-string p1, "https://www.kontocloud.com/callbacks/paypal/success/"

    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->PAYPAL_CALLBACK_SUCCESS_URL:Ljava/lang/String;

    .line 22
    const-string p1, "https://www.kontocloud.com/callbacks/paypal/cancel/"

    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->PAYPAL_CALLBACK_CANCEL_URL:Ljava/lang/String;

    const/16 p1, 0xc9

    .line 23
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->MAX_CARDHOLDER_LENGTH:Ljava/lang/Integer;

    .line 24
    const-string p1, "7.4.0"

    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->paymentFormVersion:Ljava/lang/String;

    .line 25
    new-instance p1, Ljava/util/HashMap;

    invoke-direct {p1}, Ljava/util/HashMap;-><init>()V

    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->processingPayments:Ljava/util/Map;

    .line 26
    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->jsCalls:Ljava/util/List;

    .line 27
    new-instance p1, Ljava/util/HashSet;

    invoke-direct {p1}, Ljava/util/HashSet;-><init>()V

    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->visibleElements:Ljava/util/HashSet;

    .line 28
    new-instance p1, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    invoke-direct {p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;-><init>()V

    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->options:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    const/4 p1, 0x0

    .line 29
    iput-boolean p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isBeforeSubmitAccepted:Z

    .line 30
    iput-boolean p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isWebViewLoaded:Z

    .line 31
    iput-boolean p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isPayuFinished:Z

    .line 32
    iput-boolean p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isFormLoaded:Z

    .line 33
    iput-boolean p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isFormSubmitted:Z

    .line 34
    iput-boolean p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isFormFinished:Z

    .line 35
    iput-boolean p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isAlreadyRedirect:Z

    .line 36
    new-instance p1, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;

    invoke-direct {p1}, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;-><init>()V

    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->payPalButtonStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;

    .line 37
    invoke-direct {p0, p2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->init(Landroid/util/AttributeSet;)V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V
    .locals 0

    .line 38
    invoke-direct {p0, p1, p2, p3}, Lcom/contoworks/kontocloud/uicomponents/widget/CompoundView;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V

    .line 39
    const-string p1, "https://www.kontocloud.com/callbacks/payon/"

    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->PAYON_CALLBACK_URL:Ljava/lang/String;

    .line 40
    const-string p1, "https://www.kontocloud.com/callbacks/paypal/success/"

    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->PAYPAL_CALLBACK_SUCCESS_URL:Ljava/lang/String;

    .line 41
    const-string p1, "https://www.kontocloud.com/callbacks/paypal/cancel/"

    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->PAYPAL_CALLBACK_CANCEL_URL:Ljava/lang/String;

    const/16 p1, 0xc9

    .line 42
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->MAX_CARDHOLDER_LENGTH:Ljava/lang/Integer;

    .line 43
    const-string p1, "7.4.0"

    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->paymentFormVersion:Ljava/lang/String;

    .line 44
    new-instance p1, Ljava/util/HashMap;

    invoke-direct {p1}, Ljava/util/HashMap;-><init>()V

    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->processingPayments:Ljava/util/Map;

    .line 45
    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->jsCalls:Ljava/util/List;

    .line 46
    new-instance p1, Ljava/util/HashSet;

    invoke-direct {p1}, Ljava/util/HashSet;-><init>()V

    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->visibleElements:Ljava/util/HashSet;

    .line 47
    new-instance p1, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    invoke-direct {p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;-><init>()V

    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->options:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    const/4 p1, 0x0

    .line 48
    iput-boolean p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isBeforeSubmitAccepted:Z

    .line 49
    iput-boolean p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isWebViewLoaded:Z

    .line 50
    iput-boolean p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isPayuFinished:Z

    .line 51
    iput-boolean p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isFormLoaded:Z

    .line 52
    iput-boolean p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isFormSubmitted:Z

    .line 53
    iput-boolean p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isFormFinished:Z

    .line 54
    iput-boolean p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isAlreadyRedirect:Z

    .line 55
    new-instance p1, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;

    invoke-direct {p1}, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;-><init>()V

    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->payPalButtonStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;

    .line 56
    invoke-direct {p0, p2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->init(Landroid/util/AttributeSet;)V

    return-void
.end method

.method public static bridge synthetic A(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;Ljava/util/List;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->performJSCalls(Ljava/util/List;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic B(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->showLoading()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic C(Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->getPaymentOptionCode(Ljava/lang/String;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic a(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->lambda$clearHiddenElementErrors$0()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic b(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->lambda$internalSubmit$2()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic c(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->lambda$internalSubmit$1()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private createCopyAndPayFormStyles()Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;
    .locals 15

    .line 1
    new-instance v0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;

    .line 7
    .line 8
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 9
    .line 10
    .line 11
    move-result-object v2

    .line 12
    sget v3, Lcom/contoworks/kontocloud/uicomponents/R$style;->Widget_PaymentForm_Label:I

    .line 13
    .line 14
    sget v4, Lcom/contoworks/kontocloud/uicomponents/R$attr;->paymentFormLabelStyle:I

    .line 15
    .line 16
    filled-new-array {v4}, [I

    .line 17
    .line 18
    .line 19
    move-result-object v4

    .line 20
    invoke-direct {v1, v2, v3, v4}, Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;-><init>(Landroid/content/Context;I[I)V

    .line 21
    .line 22
    .line 23
    new-instance v2, Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;

    .line 24
    .line 25
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 26
    .line 27
    .line 28
    move-result-object v3

    .line 29
    sget v4, Lcom/contoworks/kontocloud/uicomponents/R$style;->Widget_PaymentForm_EditText:I

    .line 30
    .line 31
    sget v5, Lcom/contoworks/kontocloud/uicomponents/R$attr;->paymentFormCardNumberEditTextStyle:I

    .line 32
    .line 33
    sget v6, Lcom/contoworks/kontocloud/uicomponents/R$attr;->paymentFormEditTextStyle:I

    .line 34
    .line 35
    filled-new-array {v5, v6}, [I

    .line 36
    .line 37
    .line 38
    move-result-object v5

    .line 39
    invoke-direct {v2, v3, v4, v5}, Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;-><init>(Landroid/content/Context;I[I)V

    .line 40
    .line 41
    .line 42
    new-instance v3, Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;

    .line 43
    .line 44
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 45
    .line 46
    .line 47
    move-result-object v4

    .line 48
    sget v5, Lcom/contoworks/kontocloud/uicomponents/R$style;->Widget_PaymentForm_EditText:I

    .line 49
    .line 50
    sget v6, Lcom/contoworks/kontocloud/uicomponents/R$attr;->paymentFormExpiryDateEditTextStyle:I

    .line 51
    .line 52
    sget v7, Lcom/contoworks/kontocloud/uicomponents/R$attr;->paymentFormEditTextStyle:I

    .line 53
    .line 54
    filled-new-array {v6, v7}, [I

    .line 55
    .line 56
    .line 57
    move-result-object v6

    .line 58
    invoke-direct {v3, v4, v5, v6}, Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;-><init>(Landroid/content/Context;I[I)V

    .line 59
    .line 60
    .line 61
    new-instance v4, Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;

    .line 62
    .line 63
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 64
    .line 65
    .line 66
    move-result-object v5

    .line 67
    sget v6, Lcom/contoworks/kontocloud/uicomponents/R$style;->Widget_PaymentForm_EditText:I

    .line 68
    .line 69
    sget v7, Lcom/contoworks/kontocloud/uicomponents/R$attr;->paymentFormCardHolderEditTextStyle:I

    .line 70
    .line 71
    sget v8, Lcom/contoworks/kontocloud/uicomponents/R$attr;->paymentFormEditTextStyle:I

    .line 72
    .line 73
    filled-new-array {v7, v8}, [I

    .line 74
    .line 75
    .line 76
    move-result-object v7

    .line 77
    invoke-direct {v4, v5, v6, v7}, Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;-><init>(Landroid/content/Context;I[I)V

    .line 78
    .line 79
    .line 80
    new-instance v5, Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;

    .line 81
    .line 82
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 83
    .line 84
    .line 85
    move-result-object v6

    .line 86
    sget v7, Lcom/contoworks/kontocloud/uicomponents/R$style;->Widget_PaymentForm_EditText:I

    .line 87
    .line 88
    sget v8, Lcom/contoworks/kontocloud/uicomponents/R$attr;->paymentFormCvvEditTextStyle:I

    .line 89
    .line 90
    sget v9, Lcom/contoworks/kontocloud/uicomponents/R$attr;->paymentFormEditTextStyle:I

    .line 91
    .line 92
    filled-new-array {v8, v9}, [I

    .line 93
    .line 94
    .line 95
    move-result-object v8

    .line 96
    invoke-direct {v5, v6, v7, v8}, Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;-><init>(Landroid/content/Context;I[I)V

    .line 97
    .line 98
    .line 99
    new-instance v6, Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;

    .line 100
    .line 101
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 102
    .line 103
    .line 104
    move-result-object v7

    .line 105
    sget v8, Lcom/contoworks/kontocloud/uicomponents/R$style;->Widget_PaymentForm_EditText:I

    .line 106
    .line 107
    sget v9, Lcom/contoworks/kontocloud/uicomponents/R$attr;->paymentFormAccountHolderEditTextStyle:I

    .line 108
    .line 109
    sget v10, Lcom/contoworks/kontocloud/uicomponents/R$attr;->paymentFormEditTextStyle:I

    .line 110
    .line 111
    filled-new-array {v9, v10}, [I

    .line 112
    .line 113
    .line 114
    move-result-object v9

    .line 115
    invoke-direct {v6, v7, v8, v9}, Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;-><init>(Landroid/content/Context;I[I)V

    .line 116
    .line 117
    .line 118
    new-instance v7, Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;

    .line 119
    .line 120
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 121
    .line 122
    .line 123
    move-result-object v8

    .line 124
    sget v9, Lcom/contoworks/kontocloud/uicomponents/R$style;->Widget_PaymentForm_EditText:I

    .line 125
    .line 126
    sget v10, Lcom/contoworks/kontocloud/uicomponents/R$attr;->paymentFormIbanEditTextStyle:I

    .line 127
    .line 128
    sget v11, Lcom/contoworks/kontocloud/uicomponents/R$attr;->paymentFormEditTextStyle:I

    .line 129
    .line 130
    filled-new-array {v10, v11}, [I

    .line 131
    .line 132
    .line 133
    move-result-object v10

    .line 134
    invoke-direct {v7, v8, v9, v10}, Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;-><init>(Landroid/content/Context;I[I)V

    .line 135
    .line 136
    .line 137
    new-instance v8, Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;

    .line 138
    .line 139
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 140
    .line 141
    .line 142
    move-result-object v9

    .line 143
    sget v10, Lcom/contoworks/kontocloud/uicomponents/R$style;->Widget_PaymentForm_ValidatorHint:I

    .line 144
    .line 145
    sget v11, Lcom/contoworks/kontocloud/uicomponents/R$attr;->paymentFormValidationHintStyle:I

    .line 146
    .line 147
    filled-new-array {v11}, [I

    .line 148
    .line 149
    .line 150
    move-result-object v11

    .line 151
    invoke-direct {v8, v9, v10, v11}, Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;-><init>(Landroid/content/Context;I[I)V

    .line 152
    .line 153
    .line 154
    sget v9, Lcom/contoworks/kontocloud/uicomponents/R$attr;->paymentFormFontName:I

    .line 155
    .line 156
    const-string v10, "sans-serif"

    .line 157
    .line 158
    invoke-direct {p0, v9, v10}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->getAttributeStringValue(ILjava/lang/String;)Ljava/lang/String;

    .line 159
    .line 160
    .line 161
    move-result-object v9

    .line 162
    sget v10, Lcom/contoworks/kontocloud/uicomponents/R$attr;->paymentFormShowCVVHint:I

    .line 163
    .line 164
    const/4 v11, 0x0

    .line 165
    invoke-direct {p0, v10, v11}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->getAttributeBooleanValue(IZ)Z

    .line 166
    .line 167
    .line 168
    move-result v10

    .line 169
    iput-object v9, v0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->fontName:Ljava/lang/String;

    .line 170
    .line 171
    iput-boolean v10, v0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->showCVVHint:Z

    .line 172
    .line 173
    new-instance v9, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;

    .line 174
    .line 175
    const v10, 0x1010095

    .line 176
    .line 177
    .line 178
    invoke-virtual {v1, v10}, Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;->getDimension(I)Ljava/lang/Float;

    .line 179
    .line 180
    .line 181
    move-result-object v11

    .line 182
    const v12, 0x1010098

    .line 183
    .line 184
    .line 185
    invoke-virtual {v1, v12}, Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;->getColor(I)Ljava/lang/Integer;

    .line 186
    .line 187
    .line 188
    move-result-object v13

    .line 189
    const v14, 0x1010097

    .line 190
    .line 191
    .line 192
    invoke-virtual {v1, v14}, Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;->getInteger(I)Ljava/lang/Integer;

    .line 193
    .line 194
    .line 195
    move-result-object v1

    .line 196
    invoke-direct {v9, v11, v13, v1}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;-><init>(Ljava/lang/Float;Ljava/lang/Integer;Ljava/lang/Integer;)V

    .line 197
    .line 198
    .line 199
    iput-object v9, v0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->labelFont:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;

    .line 200
    .line 201
    invoke-direct {p0, v2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->createEditTextStyle(Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;)Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 202
    .line 203
    .line 204
    move-result-object v1

    .line 205
    iput-object v1, v0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->cardNumberEditTextStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 206
    .line 207
    invoke-direct {p0, v3}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->createEditTextStyle(Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;)Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 208
    .line 209
    .line 210
    move-result-object v1

    .line 211
    iput-object v1, v0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->expiryDateEditTextStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 212
    .line 213
    invoke-direct {p0, v4}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->createEditTextStyle(Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;)Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 214
    .line 215
    .line 216
    move-result-object v1

    .line 217
    iput-object v1, v0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->cardHolderEditTextStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 218
    .line 219
    invoke-direct {p0, v5}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->createEditTextStyle(Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;)Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 220
    .line 221
    .line 222
    move-result-object v1

    .line 223
    iput-object v1, v0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->cvvEditTextStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 224
    .line 225
    invoke-direct {p0, v6}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->createEditTextStyle(Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;)Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 226
    .line 227
    .line 228
    move-result-object v1

    .line 229
    iput-object v1, v0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->accountHolderEditTextStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 230
    .line 231
    invoke-direct {p0, v7}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->createEditTextStyle(Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;)Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 232
    .line 233
    .line 234
    move-result-object p0

    .line 235
    iput-object p0, v0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->ibanEditTextStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 236
    .line 237
    new-instance p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;

    .line 238
    .line 239
    invoke-virtual {v8, v10}, Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;->getDimension(I)Ljava/lang/Float;

    .line 240
    .line 241
    .line 242
    move-result-object v1

    .line 243
    invoke-virtual {v8, v12}, Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;->getColor(I)Ljava/lang/Integer;

    .line 244
    .line 245
    .line 246
    move-result-object v2

    .line 247
    invoke-virtual {v8, v14}, Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;->getInteger(I)Ljava/lang/Integer;

    .line 248
    .line 249
    .line 250
    move-result-object v3

    .line 251
    invoke-direct {p0, v1, v2, v3}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;-><init>(Ljava/lang/Float;Ljava/lang/Integer;Ljava/lang/Integer;)V

    .line 252
    .line 253
    .line 254
    iput-object p0, v0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->validationHintFont:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;

    .line 255
    .line 256
    return-object v0
.end method

.method private createEditTextStyle(Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;)Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;
    .locals 13

    .line 1
    new-instance p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 2
    .line 3
    invoke-direct {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;

    .line 7
    .line 8
    const v1, 0x1010095

    .line 9
    .line 10
    .line 11
    invoke-virtual {p1, v1}, Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;->getDimension(I)Ljava/lang/Float;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    const v2, 0x1010098

    .line 16
    .line 17
    .line 18
    invoke-virtual {p1, v2}, Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;->getColor(I)Ljava/lang/Integer;

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    const v3, 0x1010097

    .line 23
    .line 24
    .line 25
    invoke-virtual {p1, v3}, Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;->getInteger(I)Ljava/lang/Integer;

    .line 26
    .line 27
    .line 28
    move-result-object v3

    .line 29
    invoke-direct {v0, v1, v2, v3}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;-><init>(Ljava/lang/Float;Ljava/lang/Integer;Ljava/lang/Integer;)V

    .line 30
    .line 31
    .line 32
    iput-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;->editTextFont:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;

    .line 33
    .line 34
    new-instance v4, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderStyle;

    .line 35
    .line 36
    sget v0, Lcom/contoworks/kontocloud/uicomponents/R$attr;->borderLeftSize:I

    .line 37
    .line 38
    invoke-virtual {p1, v0}, Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;->getDimension(I)Ljava/lang/Float;

    .line 39
    .line 40
    .line 41
    move-result-object v5

    .line 42
    sget v0, Lcom/contoworks/kontocloud/uicomponents/R$attr;->borderLeftColor:I

    .line 43
    .line 44
    invoke-virtual {p1, v0}, Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;->getColor(I)Ljava/lang/Integer;

    .line 45
    .line 46
    .line 47
    move-result-object v6

    .line 48
    sget v0, Lcom/contoworks/kontocloud/uicomponents/R$attr;->borderTopSize:I

    .line 49
    .line 50
    invoke-virtual {p1, v0}, Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;->getDimension(I)Ljava/lang/Float;

    .line 51
    .line 52
    .line 53
    move-result-object v7

    .line 54
    sget v0, Lcom/contoworks/kontocloud/uicomponents/R$attr;->borderTopColor:I

    .line 55
    .line 56
    invoke-virtual {p1, v0}, Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;->getColor(I)Ljava/lang/Integer;

    .line 57
    .line 58
    .line 59
    move-result-object v8

    .line 60
    sget v0, Lcom/contoworks/kontocloud/uicomponents/R$attr;->borderRightSize:I

    .line 61
    .line 62
    invoke-virtual {p1, v0}, Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;->getDimension(I)Ljava/lang/Float;

    .line 63
    .line 64
    .line 65
    move-result-object v9

    .line 66
    sget v0, Lcom/contoworks/kontocloud/uicomponents/R$attr;->borderRightColor:I

    .line 67
    .line 68
    invoke-virtual {p1, v0}, Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;->getColor(I)Ljava/lang/Integer;

    .line 69
    .line 70
    .line 71
    move-result-object v10

    .line 72
    sget v0, Lcom/contoworks/kontocloud/uicomponents/R$attr;->borderBottomSize:I

    .line 73
    .line 74
    invoke-virtual {p1, v0}, Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;->getDimension(I)Ljava/lang/Float;

    .line 75
    .line 76
    .line 77
    move-result-object v11

    .line 78
    sget v0, Lcom/contoworks/kontocloud/uicomponents/R$attr;->borderBottomColor:I

    .line 79
    .line 80
    invoke-virtual {p1, v0}, Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;->getColor(I)Ljava/lang/Integer;

    .line 81
    .line 82
    .line 83
    move-result-object v12

    .line 84
    invoke-direct/range {v4 .. v12}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderStyle;-><init>(Ljava/lang/Float;Ljava/lang/Integer;Ljava/lang/Float;Ljava/lang/Integer;Ljava/lang/Float;Ljava/lang/Integer;Ljava/lang/Float;Ljava/lang/Integer;)V

    .line 85
    .line 86
    .line 87
    iput-object v4, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;->editTextBorder:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderStyle;

    .line 88
    .line 89
    sget v0, Lcom/contoworks/kontocloud/uicomponents/R$attr;->isPlaceholderVisible:I

    .line 90
    .line 91
    invoke-virtual {p1, v0}, Lcom/contoworks/kontocloud/uicomponents/widget/StyleAdapter;->getBoolean(I)Ljava/lang/Boolean;

    .line 92
    .line 93
    .line 94
    move-result-object p1

    .line 95
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 96
    .line 97
    .line 98
    move-result p1

    .line 99
    iput-boolean p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;->isPlaceholderVisible:Z

    .line 100
    .line 101
    return-object p0
.end method

.method public static bridge synthetic d(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->authorizationToken:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public static bridge synthetic e(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->formPostParams:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public static bridge synthetic f(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isAlreadyRedirect:Z

    .line 2
    .line 3
    return p0
.end method

.method public static bridge synthetic g(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isBeforeSubmitAccepted:Z

    .line 2
    .line 3
    return p0
.end method

.method private getAttributeBooleanValue(IZ)Z
    .locals 2

    .line 1
    new-instance v0, Landroid/util/TypedValue;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/util/TypedValue;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {p0}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    const/4 v1, 0x1

    .line 15
    invoke-virtual {p0, p1, v0, v1}, Landroid/content/res/Resources$Theme;->resolveAttribute(ILandroid/util/TypedValue;Z)Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    if-eqz p0, :cond_2

    .line 20
    .line 21
    iget p0, v0, Landroid/util/TypedValue;->type:I

    .line 22
    .line 23
    const/16 p2, 0x12

    .line 24
    .line 25
    if-ne p0, p2, :cond_1

    .line 26
    .line 27
    iget p0, v0, Landroid/util/TypedValue;->data:I

    .line 28
    .line 29
    if-eqz p0, :cond_0

    .line 30
    .line 31
    return v1

    .line 32
    :cond_0
    const/4 p0, 0x0

    .line 33
    return p0

    .line 34
    :cond_1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 35
    .line 36
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    const-string p2, "Failed to resolve attribute %d. Expected value of type boolean."

    .line 45
    .line 46
    invoke-static {p2, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object p1

    .line 50
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :cond_2
    return p2
.end method

.method private getAttributeStringValue(ILjava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Landroid/util/TypedValue;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/util/TypedValue;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {p0}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    const/4 v1, 0x1

    .line 15
    invoke-virtual {p0, p1, v0, v1}, Landroid/content/res/Resources$Theme;->resolveAttribute(ILandroid/util/TypedValue;Z)Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    if-eqz p0, :cond_1

    .line 20
    .line 21
    iget p0, v0, Landroid/util/TypedValue;->type:I

    .line 22
    .line 23
    const/4 p2, 0x3

    .line 24
    if-ne p0, p2, :cond_0

    .line 25
    .line 26
    iget-object p0, v0, Landroid/util/TypedValue;->string:Ljava/lang/CharSequence;

    .line 27
    .line 28
    invoke-interface {p0}, Ljava/lang/CharSequence;->toString()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0

    .line 33
    :cond_0
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 34
    .line 35
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    const-string p2, "Failed to resolve attribute %d. Expected value of type string."

    .line 44
    .line 45
    invoke-static {p2, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw p0

    .line 53
    :cond_1
    return-object p2
.end method

.method private getHttpBody()V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isFormLoaded:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->webView:Landroid/webkit/WebView;

    .line 7
    .line 8
    const-string v0, "javascript:var inputs, index, result = \'\'; inputs = document.getElementsByTagName(\'input\');if (inputs != undefined) {for (index = 0; index < inputs.length; ++index) { var curInput = inputs[index]; if (curInput.name == undefined || curInput.name.length == 0) { continue; }if (curInput.name == \'data\') {result = encodeURIComponent(curInput.name) + \'=\' + encodeURIComponent(curInput.value); break; }else { result = result + encodeURIComponent(curInput.name) + \'=\' + encodeURIComponent(curInput.value) + \'&\'; }}} android.postParams(result);"

    .line 9
    .line 10
    invoke-virtual {p0, v0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method private static getPaymentOptionCode(Ljava/lang/String;)Ljava/lang/String;
    .locals 3

    .line 1
    sget-object v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->payonBrandMap:Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/HashMap;->keySet()Ljava/util/Set;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-eqz v1, :cond_1

    .line 16
    .line 17
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    check-cast v1, Ljava/lang/String;

    .line 22
    .line 23
    sget-object v2, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->payonBrandMap:Ljava/util/HashMap;

    .line 24
    .line 25
    invoke-virtual {v2, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    check-cast v2, Ljava/lang/String;

    .line 30
    .line 31
    invoke-virtual {v2, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v2

    .line 35
    if-eqz v2, :cond_0

    .line 36
    .line 37
    return-object v1

    .line 38
    :cond_1
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 39
    .line 40
    const-string v1, " is not supported."

    .line 41
    .line 42
    invoke-static {p0, v1}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw v0
.end method

.method private static getPayonBrand(Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    sget-object v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->payonBrandMap:Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    sget-object v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->payonBrandMap:Ljava/util/HashMap;

    .line 10
    .line 11
    invoke-virtual {v0, p0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    check-cast p0, Ljava/lang/String;

    .line 16
    .line 17
    return-object p0

    .line 18
    :cond_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 19
    .line 20
    const-string v1, " is not supported."

    .line 21
    .line 22
    invoke-static {p0, v1}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    throw v0
.end method

.method private static getPayonBrands(Ljava/lang/Iterable;)Ljava/util/Collection;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/Iterable<",
            "Ljava/lang/String;",
            ">;)",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-eqz v1, :cond_0

    .line 15
    .line 16
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    check-cast v1, Ljava/lang/String;

    .line 21
    .line 22
    invoke-static {v1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->getPayonBrand(Ljava/lang/String;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    return-object v0
.end method

.method private getUrlWithoutParameters(Ljava/lang/String;)Ljava/lang/String;
    .locals 6

    .line 1
    :try_start_0
    new-instance p0, Ljava/net/URI;

    .line 2
    .line 3
    invoke-direct {p0, p1}, Ljava/net/URI;-><init>(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Ljava/net/URI;

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/net/URI;->getScheme()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    invoke-virtual {p0}, Ljava/net/URI;->getAuthority()Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    invoke-virtual {p0}, Ljava/net/URI;->getPath()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v3

    .line 20
    invoke-virtual {p0}, Ljava/net/URI;->getFragment()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v5

    .line 24
    const/4 v4, 0x0

    .line 25
    invoke-direct/range {v0 .. v5}, Ljava/net/URI;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/net/URI;->toString()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0
    :try_end_0
    .catch Ljava/net/URISyntaxException; {:try_start_0 .. :try_end_0} :catch_0

    .line 32
    return-object p0

    .line 33
    :catch_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 34
    .line 35
    invoke-direct {p0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 36
    .line 37
    .line 38
    throw p0
.end method

.method public static bridge synthetic h(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isFormFinished:Z

    .line 2
    .line 3
    return p0
.end method

.method private hideKeyboard(Landroid/app/Activity;)V
    .locals 1

    .line 1
    const p0, 0x1020002

    .line 2
    .line 3
    .line 4
    invoke-virtual {p1, p0}, Landroid/app/Activity;->findViewById(I)Landroid/view/View;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    if-eqz p0, :cond_0

    .line 9
    .line 10
    const-string v0, "input_method"

    .line 11
    .line 12
    invoke-virtual {p1, v0}, Landroid/app/Activity;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    check-cast p1, Landroid/view/inputmethod/InputMethodManager;

    .line 17
    .line 18
    invoke-virtual {p0}, Landroid/view/View;->getWindowToken()Landroid/os/IBinder;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    const/4 v0, 0x0

    .line 23
    invoke-virtual {p1, p0, v0}, Landroid/view/inputmethod/InputMethodManager;->hideSoftInputFromWindow(Landroid/os/IBinder;I)Z

    .line 24
    .line 25
    .line 26
    :cond_0
    return-void
.end method

.method private hideLoading()V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->webView:Landroid/webkit/WebView;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-virtual {v0, v1}, Landroid/view/View;->setVisibility(I)V

    .line 5
    .line 6
    .line 7
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->progressBarView:Landroid/widget/ProgressBar;

    .line 8
    .line 9
    const/16 v0, 0x8

    .line 10
    .line 11
    invoke-virtual {p0, v0}, Landroid/view/View;->setVisibility(I)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public static bridge synthetic i(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isFormLoaded:Z

    .line 2
    .line 3
    return p0
.end method

.method private init(Landroid/util/AttributeSet;)V
    .locals 4

    .line 1
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    sget-object v1, Lcom/contoworks/kontocloud/uicomponents/R$styleable;->PaymentForm:[I

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    invoke-virtual {v0, p1, v1, v2, v2}, Landroid/content/res/Resources$Theme;->obtainStyledAttributes(Landroid/util/AttributeSet;[III)Landroid/content/res/TypedArray;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    :try_start_0
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->options:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    .line 17
    .line 18
    sget v1, Lcom/contoworks/kontocloud/uicomponents/R$styleable;->PaymentForm_paymentProviderMode:I

    .line 19
    .line 20
    const/4 v3, -0x1

    .line 21
    invoke-virtual {p1, v1, v3}, Landroid/content/res/TypedArray;->getInteger(II)I

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    invoke-virtual {v0, v1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->setMode(Ljava/lang/Integer;)V

    .line 30
    .line 31
    .line 32
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->options:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    .line 33
    .line 34
    sget v1, Lcom/contoworks/kontocloud/uicomponents/R$styleable;->PaymentForm_paymentProviderMode:I

    .line 35
    .line 36
    invoke-virtual {p1, v1, v3}, Landroid/content/res/TypedArray;->getInteger(II)I

    .line 37
    .line 38
    .line 39
    move-result v1

    .line 40
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    invoke-virtual {v0, v1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->setPaymentProviderMode(Ljava/lang/Integer;)V

    .line 45
    .line 46
    .line 47
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->options:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    .line 48
    .line 49
    sget v1, Lcom/contoworks/kontocloud/uicomponents/R$styleable;->PaymentForm_showStorePaymentMethod:I

    .line 50
    .line 51
    invoke-virtual {p1, v1, v2}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    .line 52
    .line 53
    .line 54
    move-result v1

    .line 55
    invoke-virtual {v0, v1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->setShowStorePaymentMethod(Z)V

    .line 56
    .line 57
    .line 58
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->options:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    .line 59
    .line 60
    sget v1, Lcom/contoworks/kontocloud/uicomponents/R$styleable;->PaymentForm_paymentProvider:I

    .line 61
    .line 62
    invoke-virtual {p1, v1}, Landroid/content/res/TypedArray;->getString(I)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v1

    .line 66
    invoke-virtual {v0, v1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->setPaymentProvider(Ljava/lang/String;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 67
    .line 68
    .line 69
    invoke-virtual {p1}, Landroid/content/res/TypedArray;->recycle()V

    .line 70
    .line 71
    .line 72
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->options:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    .line 73
    .line 74
    invoke-virtual {p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->getMode()Ljava/lang/Integer;

    .line 75
    .line 76
    .line 77
    move-result-object p1

    .line 78
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 79
    .line 80
    .line 81
    move-result p1

    .line 82
    const/4 v0, 0x0

    .line 83
    if-ne p1, v3, :cond_0

    .line 84
    .line 85
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->options:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    .line 86
    .line 87
    invoke-virtual {p1, v0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->setMode(Ljava/lang/Integer;)V

    .line 88
    .line 89
    .line 90
    :cond_0
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->options:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    .line 91
    .line 92
    invoke-virtual {p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->getPaymentProviderMode()Ljava/lang/Integer;

    .line 93
    .line 94
    .line 95
    move-result-object p1

    .line 96
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 97
    .line 98
    .line 99
    move-result p1

    .line 100
    if-ne p1, v3, :cond_1

    .line 101
    .line 102
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->options:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    .line 103
    .line 104
    invoke-virtual {p0, v0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->setPaymentProviderMode(Ljava/lang/Integer;)V

    .line 105
    .line 106
    .line 107
    :cond_1
    return-void

    .line 108
    :catchall_0
    move-exception p0

    .line 109
    invoke-virtual {p1}, Landroid/content/res/TypedArray;->recycle()V

    .line 110
    .line 111
    .line 112
    throw p0
.end method

.method private internalSubmit()V
    .locals 4

    .line 1
    iget-boolean v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isFormSubmitted:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->options:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    .line 7
    .line 8
    invoke-virtual {v0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->getPaymentProvider()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    const-string v1, "Payon"

    .line 13
    .line 14
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    if-nez v2, :cond_1

    .line 19
    .line 20
    const/4 v2, 0x1

    .line 21
    iput-boolean v2, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isFormSubmitted:Z

    .line 22
    .line 23
    :cond_1
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    check-cast v2, Landroid/app/Activity;

    .line 28
    .line 29
    invoke-direct {p0, v2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->hideKeyboard(Landroid/app/Activity;)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    const-wide/16 v1, 0x64

    .line 37
    .line 38
    if-eqz v0, :cond_2

    .line 39
    .line 40
    new-instance v0, Lcom/contoworks/kontocloud/uicomponents/widget/a;

    .line 41
    .line 42
    const/4 v3, 0x1

    .line 43
    invoke-direct {v0, p0, v3}, Lcom/contoworks/kontocloud/uicomponents/widget/a;-><init>(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;I)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {p0, v0, v1, v2}, Landroid/view/View;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 47
    .line 48
    .line 49
    return-void

    .line 50
    :cond_2
    new-instance v0, Lcom/contoworks/kontocloud/uicomponents/widget/a;

    .line 51
    .line 52
    const/4 v3, 0x2

    .line 53
    invoke-direct {v0, p0, v3}, Lcom/contoworks/kontocloud/uicomponents/widget/a;-><init>(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;I)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {p0, v0, v1, v2}, Landroid/view/View;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 57
    .line 58
    .line 59
    return-void
.end method

.method private isPaymentOptionValid(Ljava/lang/String;)Z
    .locals 7

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->options:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->getPaymentProvider()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const-string v0, "Payon"

    .line 8
    .line 9
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    const/4 v1, 0x1

    .line 14
    const-string v2, "MSTRCRD"

    .line 15
    .line 16
    const-string v3, "VISA"

    .line 17
    .line 18
    const-string v4, "PAYPAL"

    .line 19
    .line 20
    const-string v5, "BNKACCT"

    .line 21
    .line 22
    const/4 v6, 0x0

    .line 23
    if-nez v0, :cond_8

    .line 24
    .line 25
    const-string v0, "PayonWithPCIProxy"

    .line 26
    .line 27
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-eqz v0, :cond_0

    .line 32
    .line 33
    goto :goto_2

    .line 34
    :cond_0
    const-string v0, "Sepa"

    .line 35
    .line 36
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    if-eqz v0, :cond_1

    .line 41
    .line 42
    invoke-virtual {p1, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    return p0

    .line 47
    :cond_1
    const-string v0, "PaymentOS"

    .line 48
    .line 49
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v0

    .line 53
    if-eqz v0, :cond_2

    .line 54
    .line 55
    const-string p0, "PAYU"

    .line 56
    .line 57
    invoke-virtual {p1, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result p0

    .line 61
    return p0

    .line 62
    :cond_2
    const-string v0, "PayPal"

    .line 63
    .line 64
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v0

    .line 68
    if-eqz v0, :cond_3

    .line 69
    .line 70
    invoke-virtual {p1, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    move-result p0

    .line 74
    return p0

    .line 75
    :cond_3
    const-string v0, "CyberSource"

    .line 76
    .line 77
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    move-result v0

    .line 81
    if-nez v0, :cond_5

    .line 82
    .line 83
    const-string v0, "CyberSourceWithTokenEx"

    .line 84
    .line 85
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    move-result v0

    .line 89
    if-nez v0, :cond_5

    .line 90
    .line 91
    const-string v0, "VestaWithTokenEx"

    .line 92
    .line 93
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 94
    .line 95
    .line 96
    move-result p0

    .line 97
    if-eqz p0, :cond_4

    .line 98
    .line 99
    goto :goto_0

    .line 100
    :cond_4
    return v6

    .line 101
    :cond_5
    :goto_0
    invoke-virtual {p1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    move-result p0

    .line 105
    if-nez p0, :cond_7

    .line 106
    .line 107
    invoke-virtual {p1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 108
    .line 109
    .line 110
    move-result p0

    .line 111
    if-nez p0, :cond_7

    .line 112
    .line 113
    const-string p0, "MSTRO"

    .line 114
    .line 115
    invoke-virtual {p1, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    move-result p0

    .line 119
    if-nez p0, :cond_7

    .line 120
    .line 121
    const-string p0, "AMEX"

    .line 122
    .line 123
    invoke-virtual {p1, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 124
    .line 125
    .line 126
    move-result p0

    .line 127
    if-nez p0, :cond_7

    .line 128
    .line 129
    const-string p0, "DISCOVER"

    .line 130
    .line 131
    invoke-virtual {p1, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 132
    .line 133
    .line 134
    move-result p0

    .line 135
    if-eqz p0, :cond_6

    .line 136
    .line 137
    goto :goto_1

    .line 138
    :cond_6
    return v6

    .line 139
    :cond_7
    :goto_1
    return v1

    .line 140
    :cond_8
    :goto_2
    invoke-virtual {p1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 141
    .line 142
    .line 143
    move-result p0

    .line 144
    if-nez p0, :cond_a

    .line 145
    .line 146
    invoke-virtual {p1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 147
    .line 148
    .line 149
    move-result p0

    .line 150
    if-nez p0, :cond_a

    .line 151
    .line 152
    invoke-virtual {p1, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 153
    .line 154
    .line 155
    move-result p0

    .line 156
    if-nez p0, :cond_a

    .line 157
    .line 158
    invoke-virtual {p1, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 159
    .line 160
    .line 161
    move-result p0

    .line 162
    if-eqz p0, :cond_9

    .line 163
    .line 164
    goto :goto_3

    .line 165
    :cond_9
    return v6

    .line 166
    :cond_a
    :goto_3
    return v1
.end method

.method public static bridge synthetic j(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isFormSubmitted:Z

    .line 2
    .line 3
    return p0
.end method

.method public static bridge synthetic k(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isPayuFinished:Z

    .line 2
    .line 3
    return p0
.end method

.method public static bridge synthetic l(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->onSubmitCallback:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback;

    .line 2
    .line 3
    return-object p0
.end method

.method private synthetic lambda$clearHiddenElementErrors$0()V
    .locals 7

    .line 1
    invoke-static {}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$FormElement;->values()[Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$FormElement;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    array-length v1, v0

    .line 6
    const/4 v2, 0x0

    .line 7
    :goto_0
    if-ge v2, v1, :cond_1

    .line 8
    .line 9
    aget-object v3, v0, v2

    .line 10
    .line 11
    sget-object v4, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$FormElement;->all:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$FormElement;

    .line 12
    .line 13
    if-eq v3, v4, :cond_0

    .line 14
    .line 15
    iget-object v4, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->visibleElements:Ljava/util/HashSet;

    .line 16
    .line 17
    invoke-virtual {v4, v3}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v4

    .line 21
    if-nez v4, :cond_0

    .line 22
    .line 23
    iget-object v4, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->webView:Landroid/webkit/WebView;

    .line 24
    .line 25
    new-instance v5, Ljava/lang/StringBuilder;

    .line 26
    .line 27
    const-string v6, "javascript:clearElementErrorWithName(\'"

    .line 28
    .line 29
    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {v5, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string v3, "\');"

    .line 36
    .line 37
    invoke-virtual {v5, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object v3

    .line 44
    invoke-virtual {v4, v3}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_1
    return-void
.end method

.method private synthetic lambda$internalSubmit$1()V
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->webView:Landroid/webkit/WebView;

    .line 2
    .line 3
    const-string v0, "javascript:kc.submit();"

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method private synthetic lambda$internalSubmit$2()V
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->webView:Landroid/webkit/WebView;

    .line 2
    .line 3
    const-string v0, "javascript:submit();"

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public static bridge synthetic m(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnValidationCallback;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->onValidationCallback:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnValidationCallback;

    .line 2
    .line 3
    return-object p0
.end method

.method private mapLocaleForPayon(Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string p0, "zh"

    .line 2
    .line 3
    invoke-virtual {p1, p0}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    const-string v0, "cn"

    .line 10
    .line 11
    invoke-virtual {p1, p0, v0}, Ljava/lang/String;->replaceFirst(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0

    .line 16
    :cond_0
    const-string p0, "cs"

    .line 17
    .line 18
    invoke-virtual {p1, p0}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_1

    .line 23
    .line 24
    const-string v0, "cz"

    .line 25
    .line 26
    invoke-virtual {p1, p0, v0}, Ljava/lang/String;->replaceFirst(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0

    .line 31
    :cond_1
    const-string p0, "el"

    .line 32
    .line 33
    invoke-virtual {p1, p0}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    if-eqz v0, :cond_2

    .line 38
    .line 39
    const-string v0, "gr"

    .line 40
    .line 41
    invoke-virtual {p1, p0, v0}, Ljava/lang/String;->replaceFirst(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    return-object p0

    .line 46
    :cond_2
    return-object p1
.end method

.method public static bridge synthetic n(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->options:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    .line 2
    .line 3
    return-object p0
.end method

.method public static bridge synthetic o(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->formPostParams:Ljava/lang/String;

    .line 2
    .line 3
    return-void
.end method

.method public static bridge synthetic p(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isAlreadyRedirect:Z

    .line 2
    .line 3
    return-void
.end method

.method private performJSCalls(Ljava/util/List;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    .line 1
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    check-cast v0, Ljava/lang/String;

    .line 16
    .line 17
    iget-object v1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->webView:Landroid/webkit/WebView;

    .line 18
    .line 19
    invoke-virtual {v1, v0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    return-void
.end method

.method public static bridge synthetic q(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isBeforeSubmitAccepted:Z

    .line 2
    .line 3
    return-void
.end method

.method public static bridge synthetic r(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isFormFinished:Z

    .line 3
    .line 4
    return-void
.end method

.method private render(Ljava/util/List;Ljava/lang/String;)V
    .locals 20
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;",
            "Ljava/lang/String;",
            ")V"
        }
    .end annotation

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    move-object/from16 v3, p2

    const/4 v2, 0x0

    .line 18
    iput-boolean v2, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isFormSubmitted:Z

    .line 19
    iput-boolean v2, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isFormFinished:Z

    if-eqz v3, :cond_1c

    .line 20
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v4

    :goto_0
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_1

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/lang/String;

    .line 21
    invoke-direct {v0, v5}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isPaymentOptionValid(Ljava/lang/String;)Z

    move-result v6

    if-eqz v6, :cond_0

    goto :goto_0

    .line 22
    :cond_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "Invalid payment option "

    const-string v2, " for current payment provider."

    .line 23
    invoke-static {v1, v5, v2}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    .line 24
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 25
    :cond_1
    iget-object v4, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->options:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    invoke-virtual {v4, v1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->validateState(Ljava/util/List;)V

    .line 26
    invoke-interface {v1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    .line 27
    iget-object v5, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->options:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    invoke-virtual {v5}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->getPaymentProvider()Ljava/lang/String;

    move-result-object v5

    .line 28
    iget-object v6, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->options:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    invoke-virtual {v6}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->getApiUrl()Ljava/lang/String;

    move-result-object v6

    if-eqz v6, :cond_1b

    iget-object v6, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->options:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    invoke-virtual {v6}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->getApiUrl()Ljava/lang/String;

    move-result-object v6

    invoke-virtual {v6}, Ljava/lang/String;->length()I

    move-result v6

    if-eqz v6, :cond_1b

    .line 29
    const-string v6, "PaymentOS"

    invoke-virtual {v5, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v7

    const-string v8, "CyberSourceWithTokenEx"

    const-string v9, "PAYU"

    const-string v10, "VestaWithTokenEx"

    const-string v11, "PayonWithPCIProxy"

    const-string v12, "CyberSource"

    const-string v13, "Sepa"

    if-eqz v7, :cond_2

    invoke-virtual {v4, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v7

    if-nez v7, :cond_3

    .line 30
    :cond_2
    invoke-virtual {v5, v12}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v7

    if-nez v7, :cond_3

    .line 31
    invoke-virtual {v5, v13}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v7

    if-nez v7, :cond_3

    .line 32
    invoke-virtual {v5, v11}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v7

    if-nez v7, :cond_3

    .line 33
    invoke-virtual {v5, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v7

    if-nez v7, :cond_3

    .line 34
    invoke-virtual {v5, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_4

    .line 35
    :cond_3
    iget-object v7, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->options:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    invoke-virtual {v7}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->getRedirectUrl()Ljava/lang/String;

    move-result-object v7

    if-eqz v7, :cond_1a

    iget-object v7, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->options:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    invoke-virtual {v7}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->getRedirectUrl()Ljava/lang/String;

    move-result-object v7

    invoke-virtual {v7}, Ljava/lang/String;->length()I

    move-result v7

    if-eqz v7, :cond_1a

    .line 36
    :cond_4
    invoke-direct {v0, v5}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->setWebViewClient(Ljava/lang/String;)V

    .line 37
    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v7

    const/4 v14, 0x1

    if-ne v7, v14, :cond_5

    .line 38
    iget-object v7, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->processingPayments:Ljava/util/Map;

    invoke-interface {v7, v3, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 39
    :cond_5
    new-instance v7, Ljava/lang/StringBuilder;

    invoke-direct {v7}, Ljava/lang/StringBuilder;-><init>()V

    move v15, v2

    .line 40
    :goto_1
    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v14

    const-string v2, "\""

    if-ge v15, v14, :cond_7

    if-eqz v15, :cond_6

    .line 41
    const-string v14, ","

    invoke-virtual {v7, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 42
    :cond_6
    invoke-virtual {v7, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-interface {v1, v15}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v14

    check-cast v14, Ljava/lang/String;

    invoke-virtual {v7, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v7, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    add-int/lit8 v15, v15, 0x1

    const/4 v2, 0x0

    goto :goto_1

    .line 43
    :cond_7
    iput-object v3, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->authorizationToken:Ljava/lang/String;

    .line 44
    invoke-direct {v0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->showLoading()V

    const/4 v14, 0x0

    .line 45
    iput-boolean v14, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isBeforeSubmitAccepted:Z

    .line 46
    iget-object v15, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->options:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    invoke-virtual {v15}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->getPaymentProviderMode()Ljava/lang/Integer;

    move-result-object v15

    invoke-virtual {v15}, Ljava/lang/Integer;->intValue()I

    move-result v15

    const/4 v14, 0x1

    if-ne v15, v14, :cond_8

    goto :goto_2

    :cond_8
    const/4 v14, 0x0

    :goto_2
    if-eqz v14, :cond_9

    .line 47
    const-string v15, "live"

    goto :goto_3

    :cond_9
    const-string v15, "test"

    .line 48
    :goto_3
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    move-result-object v16

    invoke-virtual/range {v16 .. v16}, Ljava/util/Locale;->getLanguage()Ljava/lang/String;

    move-result-object v1

    move-object/from16 v16, v7

    .line 49
    const-string v7, "PayPal"

    invoke-virtual {v5, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v7

    move/from16 v17, v7

    const-string v7, "locale"

    move/from16 v18, v14

    const-string v14, "paymentProviderMode"

    move-object/from16 v19, v2

    const-string v2, "authorizationToken"

    if-eqz v17, :cond_b

    .line 50
    iget-object v4, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->webView:Landroid/webkit/WebView;

    invoke-virtual {v4}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v4

    const/4 v5, -0x1

    .line 51
    iput v5, v4, Landroid/view/ViewGroup$LayoutParams;->height:I

    .line 52
    iget-object v5, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->webView:Landroid/webkit/WebView;

    invoke-virtual {v5, v4}, Landroid/webkit/WebView;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    .line 53
    new-instance v4, Ljava/util/HashMap;

    invoke-direct {v4}, Ljava/util/HashMap;-><init>()V

    .line 54
    invoke-virtual {v4, v2, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 55
    invoke-virtual {v4, v14, v15}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 56
    const-string v2, "successURL"

    const-string v3, "https://www.kontocloud.com/callbacks/paypal/success/"

    invoke-virtual {v4, v2, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 57
    const-string v2, "cancelURL"

    const-string v3, "https://www.kontocloud.com/callbacks/paypal/cancel/"

    invoke-virtual {v4, v2, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    const-string v2, "formHeight"

    const-string v3, "300px"

    invoke-virtual {v4, v2, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 59
    iget-object v2, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->payPalButtonStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;

    if-nez v2, :cond_a

    .line 60
    new-instance v2, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;

    invoke-direct {v2}, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;-><init>()V

    iput-object v2, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->payPalButtonStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;

    .line 61
    :cond_a
    iget-object v2, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->payPalButtonStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;

    invoke-virtual {v2}, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;->getButtonSize()Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;

    move-result-object v2

    invoke-virtual {v2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;->toString()Ljava/lang/String;

    move-result-object v2

    const-string v3, "paypalButtonSize"

    invoke-virtual {v4, v3, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 62
    iget-object v2, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->payPalButtonStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;

    invoke-virtual {v2}, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;->getButtonColor()Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonColor;

    move-result-object v2

    invoke-virtual {v2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonColor;->toString()Ljava/lang/String;

    move-result-object v2

    const-string v3, "paypalButtonColor"

    invoke-virtual {v4, v3, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 63
    iget-object v2, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->payPalButtonStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;

    invoke-virtual {v2}, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;->getButtonShape()Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonShape;

    move-result-object v2

    invoke-virtual {v2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonShape;->toString()Ljava/lang/String;

    move-result-object v2

    const-string v3, "paypalButtonShape"

    invoke-virtual {v4, v3, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 64
    iget-object v2, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->payPalButtonStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;

    invoke-virtual {v2}, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;->getButtonLabel()Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;

    move-result-object v2

    invoke-virtual {v2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;->toString()Ljava/lang/String;

    move-result-object v2

    const-string v3, "paypalButtonLabel"

    invoke-virtual {v4, v3, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 65
    iget-object v2, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->payPalButtonStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;

    invoke-virtual {v2}, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;->getButtonTagline()Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonTagline;

    move-result-object v2

    invoke-virtual {v2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonTagline;->toString()Ljava/lang/String;

    move-result-object v2

    const-string v3, "paypalButtonTagline"

    invoke-virtual {v4, v3, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 66
    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, "_"

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    move-result-object v1

    invoke-virtual {v1}, Ljava/util/Locale;->getCountry()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    .line 67
    invoke-virtual {v4, v7, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 68
    invoke-virtual {v0}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v1

    sget v2, Lcom/contoworks/kontocloud/uicomponents/R$raw;->template_paypal:I

    invoke-static {v1, v4, v2}, Lcom/contoworks/kontocloud/uicomponents/widget/PayonTemplateHelper;->renderTemplate(Landroid/content/Context;Ljava/lang/Object;I)Ljava/lang/String;

    move-result-object v7

    .line 69
    iget-object v5, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->webView:Landroid/webkit/WebView;

    iget-object v0, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->options:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    invoke-virtual {v0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->getApiUrl()Ljava/lang/String;

    move-result-object v6

    const-string v9, "utf-8"

    const/4 v10, 0x0

    const-string v8, "text/html"

    invoke-virtual/range {v5 .. v10}, Landroid/webkit/WebView;->loadDataWithBaseURL(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    return-void

    .line 70
    :cond_b
    invoke-virtual {v5, v12}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v17

    if-nez v17, :cond_12

    .line 71
    invoke-virtual {v5, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v8

    if-nez v8, :cond_12

    .line 72
    invoke-virtual {v5, v13}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v8

    if-nez v8, :cond_12

    .line 73
    invoke-virtual {v5, v11}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v8

    if-nez v8, :cond_12

    .line 74
    invoke-virtual {v5, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_c

    goto/16 :goto_5

    .line 75
    :cond_c
    invoke-virtual {v5, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_11

    .line 76
    invoke-virtual {v4, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_10

    .line 77
    const-string v2, "lang="

    invoke-static {v2, v1}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    .line 78
    invoke-virtual {v3, v2}, Ljava/lang/String;->indexOf(Ljava/lang/String;)I

    move-result v2

    .line 79
    const-string v4, "&"

    if-ltz v2, :cond_e

    .line 80
    invoke-virtual {v3, v4, v2}, Ljava/lang/String;->indexOf(Ljava/lang/String;I)I

    move-result v4

    .line 81
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    move-result v5

    sub-int/2addr v5, v2

    if-ltz v4, :cond_d

    sub-int v5, v4, v2

    :cond_d
    add-int/2addr v5, v2

    .line 82
    invoke-virtual {v3, v2, v5}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    move-result-object v2

    .line 83
    invoke-virtual {v3, v2, v1}, Ljava/lang/String;->replace(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;

    move-result-object v1

    goto :goto_4

    .line 84
    :cond_e
    const-string v2, "?"

    invoke-virtual {v3, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v5

    if-eqz v5, :cond_f

    .line 85
    invoke-static {v3, v4, v1}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    goto :goto_4

    .line 86
    :cond_f
    invoke-static {v3, v2, v1}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    .line 87
    :goto_4
    iget-object v0, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->webView:Landroid/webkit/WebView;

    invoke-virtual {v0, v1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V

    :cond_10
    return-void

    .line 88
    :cond_11
    invoke-static/range {p1 .. p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->getPayonBrands(Ljava/lang/Iterable;)Ljava/util/Collection;

    move-result-object v5

    .line 89
    new-instance v8, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData$Strings;

    invoke-direct {v8}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData$Strings;-><init>()V

    .line 90
    invoke-virtual {v0}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v2

    invoke-virtual {v2}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v2

    .line 91
    invoke-direct {v0, v1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->mapLocaleForPayon(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v7

    .line 92
    sget v1, Lcom/contoworks/kontocloud/uicomponents/R$string;->payment_form_validation_invalid_iban_country:I

    invoke-virtual {v2, v1}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v8, v1}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData$Strings;->setValidationErrorInvalidIbanCountry(Ljava/lang/String;)V

    .line 93
    sget v1, Lcom/contoworks/kontocloud/uicomponents/R$string;->payment_form_validation_invalid_acc_holder:I

    invoke-virtual {v2, v1}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v8, v1}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData$Strings;->setValidationErrorAccountHolder(Ljava/lang/String;)V

    .line 94
    sget v1, Lcom/contoworks/kontocloud/uicomponents/R$string;->payment_form_validation_invalid_card_holder:I

    invoke-virtual {v2, v1}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v8, v1}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData$Strings;->setValidationErrorCardHolder(Ljava/lang/String;)V

    .line 95
    sget v1, Lcom/contoworks/kontocloud/uicomponents/R$string;->payment_form_store_payment_method:I

    invoke-virtual {v2, v1}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v8, v1}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData$Strings;->setStorePaymentMethod(Ljava/lang/String;)V

    .line 96
    new-instance v1, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData;

    invoke-static/range {v18 .. v18}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v2

    const-string v6, "https://www.kontocloud.com/callbacks/payon/"

    invoke-direct {v0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->createCopyAndPayFormStyles()Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;

    move-result-object v9

    const-string v4, "7.4.0"

    invoke-direct/range {v1 .. v9}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData;-><init>(Ljava/lang/Boolean;Ljava/lang/String;Ljava/lang/String;Ljava/util/Collection;Ljava/lang/String;Ljava/lang/String;Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData$Strings;Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;)V

    .line 97
    iget-object v2, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->options:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    invoke-virtual {v2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->isShowStorePaymentMethod()Z

    move-result v2

    invoke-virtual {v1, v2}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData;->setShowStorePaymentMethod(Z)V

    .line 98
    invoke-virtual {v0}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v2

    sget v3, Lcom/contoworks/kontocloud/uicomponents/R$raw;->template_payon_form:I

    invoke-static {v2, v1, v3}, Lcom/contoworks/kontocloud/uicomponents/widget/PayonTemplateHelper;->renderTemplate(Landroid/content/Context;Ljava/lang/Object;I)Ljava/lang/String;

    move-result-object v6

    .line 99
    iget-object v4, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->webView:Landroid/webkit/WebView;

    invoke-virtual {v1}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData;->getWidgetUrl()Ljava/lang/String;

    move-result-object v5

    const-string v8, "utf-8"

    const/4 v9, 0x0

    const-string v7, "text/html"

    invoke-virtual/range {v4 .. v9}, Landroid/webkit/WebView;->loadDataWithBaseURL(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    return-void

    .line 100
    :cond_12
    :goto_5
    invoke-virtual {v0}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v4

    invoke-virtual {v4}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v4

    .line 101
    new-instance v6, Ljava/util/HashMap;

    invoke-direct {v6}, Ljava/util/HashMap;-><init>()V

    .line 102
    invoke-virtual {v6, v2, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 103
    invoke-virtual {v6, v14, v15}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 104
    const-string v2, "paymentFormVersion"

    const-string v3, "7.4.0"

    invoke-virtual {v6, v2, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 105
    const-string v2, "brands"

    const-string v8, ""

    invoke-virtual {v6, v2, v8}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 106
    iget-object v2, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->options:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    invoke-virtual {v2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->getApiUrl()Ljava/lang/String;

    move-result-object v2

    .line 107
    invoke-virtual {v5, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_13

    .line 108
    const-string v9, "vesta"

    goto :goto_6

    .line 109
    :cond_13
    invoke-virtual {v5, v11}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_14

    .line 110
    const-string v9, "payonpci"

    goto :goto_6

    .line 111
    :cond_14
    invoke-virtual {v5, v13}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_15

    .line 112
    const-string v9, "SEPA"

    invoke-virtual {v9}, Ljava/lang/String;->toLowerCase()Ljava/lang/String;

    move-result-object v9

    goto :goto_6

    .line 113
    :cond_15
    const-string v9, "cyber"

    .line 114
    :goto_6
    iget-object v10, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->options:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    invoke-virtual {v10}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->getMode()Ljava/lang/Integer;

    move-result-object v10

    invoke-virtual {v10}, Ljava/lang/Integer;->intValue()I

    move-result v10

    const-string v11, "submitButtonTitle"

    if-nez v10, :cond_16

    .line 115
    sget v10, Lcom/contoworks/kontocloud/uicomponents/R$string;->payment_form_submit_butt_text:I

    invoke-virtual {v4, v10}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    move-result-object v10

    invoke-virtual {v6, v11, v10}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_7

    .line 116
    :cond_16
    sget v10, Lcom/contoworks/kontocloud/uicomponents/R$string;->payment_form_pay_butt_text:I

    invoke-virtual {v4, v10}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    move-result-object v10

    invoke-virtual {v6, v11, v10}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 117
    :goto_7
    const-string v10, "payment_form_version"

    invoke-virtual {v6, v10, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 118
    const-string v3, "paymentFormUrl"

    invoke-virtual {v6, v3, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 119
    invoke-virtual {v6, v7, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 120
    const-string v1, "paymentProvider"

    invoke-virtual {v6, v1, v9}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 121
    const-string v1, "callBackURL"

    invoke-virtual {v6, v1, v8}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 122
    sget v1, Lcom/contoworks/kontocloud/uicomponents/R$string;->payment_form_store_payment_method:I

    invoke-virtual {v4, v1}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    move-result-object v1

    const-string v2, "storePaymentMethodText"

    invoke-virtual {v6, v2, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 123
    invoke-virtual {v0}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v1

    sget v2, Lcom/contoworks/kontocloud/uicomponents/R$raw;->template_cybersource:I

    invoke-static {v1, v6, v2}, Lcom/contoworks/kontocloud/uicomponents/widget/PayonTemplateHelper;->renderTemplate(Landroid/content/Context;Ljava/lang/Object;I)Ljava/lang/String;

    move-result-object v1

    .line 124
    invoke-direct {v0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->createCopyAndPayFormStyles()Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;

    move-result-object v2

    .line 125
    iput-object v5, v2, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->provider:Ljava/lang/String;

    .line 126
    invoke-virtual {v2}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->toCss()Ljava/lang/String;

    move-result-object v2

    .line 127
    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, " .cw-group-brand { display: flex; justify-content: flex-end; align-items: center; } .cw-label-brand {display: none;} "

    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    .line 128
    const-string v3, "\n"

    invoke-virtual {v2, v3, v8}, Ljava/lang/String;->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    .line 129
    const-string v3, "\\\""

    move-object/from16 v4, v19

    invoke-virtual {v2, v4, v3}, Ljava/lang/String;->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    .line 130
    invoke-virtual {v5, v13}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v3

    const-string v4, "__iframeCss__"

    if-eqz v3, :cond_17

    .line 131
    const-string v2, "(null) .cw-group-brand {display: flex; justify-content: flex-end; align-items: center; } .cw-label-brand {display: none;}"

    invoke-virtual {v1, v4, v2}, Ljava/lang/String;->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    goto :goto_8

    .line 132
    :cond_17
    invoke-virtual {v1, v4, v2}, Ljava/lang/String;->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    .line 133
    :goto_8
    const-string v2, "__paymentOptionCodes__"

    invoke-virtual/range {v16 .. v16}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v1, v2, v3}, Ljava/lang/String;->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    .line 134
    iget-object v2, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->options:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    invoke-virtual {v2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->isShowStorePaymentMethod()Z

    move-result v2

    const-string v3, "false"

    const-string v4, "true"

    if-eqz v2, :cond_18

    move-object v2, v4

    goto :goto_9

    :cond_18
    move-object v2, v3

    :goto_9
    const-string v6, "__isStorable__"

    invoke-virtual {v1, v6, v2}, Ljava/lang/String;->replaceFirst(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    .line 135
    invoke-virtual {v5, v12}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_19

    goto :goto_a

    :cond_19
    move-object v3, v4

    :goto_a
    const-string v2, "__useTokenEx__"

    invoke-virtual {v1, v2, v3}, Ljava/lang/String;->replaceFirst(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v6

    .line 136
    iget-object v4, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->webView:Landroid/webkit/WebView;

    iget-object v0, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->options:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    invoke-virtual {v0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->getApiUrl()Ljava/lang/String;

    move-result-object v5

    const-string v8, "utf-8"

    const/4 v9, 0x0

    const-string v7, "text/html"

    invoke-virtual/range {v4 .. v9}, Landroid/webkit/WebView;->loadDataWithBaseURL(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    return-void

    .line 137
    :cond_1a
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "The \'redirectUrl\' property must be set."

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 138
    :cond_1b
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "The \'apiUrl\' must be set."

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 139
    :cond_1c
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "The \'authorizationToken\' property must be set."

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public static bridge synthetic s(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isFormLoaded:Z

    .line 3
    .line 4
    return-void
.end method

.method private setWebViewClient(Ljava/lang/String;)V
    .locals 2

    .line 1
    const-string v0, "CyberSource"

    .line 2
    .line 3
    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    const-string v0, "CyberSourceWithTokenEx"

    .line 10
    .line 11
    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-nez v0, :cond_1

    .line 16
    .line 17
    const-string v0, "PayonWithPCIProxy"

    .line 18
    .line 19
    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-nez v0, :cond_1

    .line 24
    .line 25
    const-string v0, "Sepa"

    .line 26
    .line 27
    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-nez v0, :cond_1

    .line 32
    .line 33
    const-string v0, "VestaWithTokenEx"

    .line 34
    .line 35
    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    if-eqz v0, :cond_0

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_0
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->webView:Landroid/webkit/WebView;

    .line 43
    .line 44
    new-instance v1, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;

    .line 45
    .line 46
    invoke-direct {v1, p0, p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$5;-><init>(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    invoke-virtual {v0, v1}, Landroid/webkit/WebView;->setWebViewClient(Landroid/webkit/WebViewClient;)V

    .line 50
    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_1
    :goto_0
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->webView:Landroid/webkit/WebView;

    .line 54
    .line 55
    new-instance v1, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;

    .line 56
    .line 57
    invoke-direct {v1, p0, p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$4;-><init>(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {v0, v1}, Landroid/webkit/WebView;->setWebViewClient(Landroid/webkit/WebViewClient;)V

    .line 61
    .line 62
    .line 63
    :goto_1
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->webView:Landroid/webkit/WebView;

    .line 64
    .line 65
    new-instance v1, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;

    .line 66
    .line 67
    invoke-direct {v1, p0, p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;-><init>(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    const-string p0, "android"

    .line 71
    .line 72
    invoke-virtual {v0, v1, p0}, Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    return-void
.end method

.method private showLoading()V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->webView:Landroid/webkit/WebView;

    .line 2
    .line 3
    const/16 v1, 0x8

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Landroid/view/View;->setVisibility(I)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->progressBarView:Landroid/widget/ProgressBar;

    .line 9
    .line 10
    const/4 v0, 0x0

    .line 11
    invoke-virtual {p0, v0}, Landroid/view/View;->setVisibility(I)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public static bridge synthetic t(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-boolean v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isFormSubmitted:Z

    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic u(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isPayuFinished:Z

    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic v(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isWebViewLoaded:Z

    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic w(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->getHttpBody()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic x(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->getUrlWithoutParameters(Ljava/lang/String;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static bridge synthetic y(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->hideLoading()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic z(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->internalSubmit()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public clearHiddenElementErrors()V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/CompoundView;->getUiHandler()Landroid/os/Handler;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v1, Lcom/contoworks/kontocloud/uicomponents/widget/a;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    invoke-direct {v1, p0, v2}, Lcom/contoworks/kontocloud/uicomponents/widget/a;-><init>(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;I)V

    .line 9
    .line 10
    .line 11
    const-wide/16 v2, 0x12c

    .line 12
    .line 13
    invoke-virtual {v0, v1, v2, v3}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public continueValidationElement(Ljava/lang/String;Ljava/lang/String;)V
    .locals 2

    .line 1
    const-string v0, "javascript:validateElement(\'"

    .line 2
    .line 3
    const-string v1, "\');"

    .line 4
    .line 5
    invoke-static {v0, p1, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    invoke-virtual {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/CompoundView;->getUiHandler()Landroid/os/Handler;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    new-instance v1, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$2;

    .line 14
    .line 15
    invoke-direct {v1, p0, p1, p2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$2;-><init>(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;Ljava/lang/String;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    const-wide/16 p0, 0x190

    .line 19
    .line 20
    invoke-virtual {v0, v1, p0, p1}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 21
    .line 22
    .line 23
    return-void
.end method

.method public getLayoutId()I
    .locals 0

    .line 1
    sget p0, Lcom/contoworks/kontocloud/uicomponents/R$layout;->widget_payment_option_data:I

    .line 2
    .line 3
    return p0
.end method

.method public getOptions()Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->options:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    .line 2
    .line 3
    return-object p0
.end method

.method public onRestoreInstanceState(Landroid/os/Parcelable;)V
    .locals 1

    .line 1
    check-cast p1, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$SavedState;

    .line 2
    .line 3
    invoke-virtual {p1}, Landroid/view/AbsSavedState;->getSuperState()Landroid/os/Parcelable;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-super {p0, v0}, Landroid/view/View;->onRestoreInstanceState(Landroid/os/Parcelable;)V

    .line 8
    .line 9
    .line 10
    iget-object v0, p1, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$SavedState;->processingPayments:Ljava/util/Map;

    .line 11
    .line 12
    iput-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->processingPayments:Ljava/util/Map;

    .line 13
    .line 14
    invoke-static {p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$SavedState;->a(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$SavedState;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    iput-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->authorizationToken:Ljava/lang/String;

    .line 19
    .line 20
    iget-object v0, p1, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$SavedState;->paymentFormOptions:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    .line 21
    .line 22
    iput-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->options:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    .line 23
    .line 24
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->webView:Landroid/webkit/WebView;

    .line 25
    .line 26
    iget-object p1, p1, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$SavedState;->webViewBundle:Landroid/os/Bundle;

    .line 27
    .line 28
    invoke-virtual {p0, p1}, Landroid/webkit/WebView;->restoreState(Landroid/os/Bundle;)Landroid/webkit/WebBackForwardList;

    .line 29
    .line 30
    .line 31
    return-void
.end method

.method public onSaveInstanceState()Landroid/os/Parcelable;
    .locals 2

    .line 1
    invoke-super {p0}, Landroid/view/View;->onSaveInstanceState()Landroid/os/Parcelable;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v1, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$SavedState;

    .line 6
    .line 7
    invoke-direct {v1, v0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$SavedState;-><init>(Landroid/os/Parcelable;)V

    .line 8
    .line 9
    .line 10
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->processingPayments:Ljava/util/Map;

    .line 11
    .line 12
    iput-object v0, v1, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$SavedState;->processingPayments:Ljava/util/Map;

    .line 13
    .line 14
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->authorizationToken:Ljava/lang/String;

    .line 15
    .line 16
    invoke-static {v1, v0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$SavedState;->b(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$SavedState;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->options:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    .line 20
    .line 21
    iput-object v0, v1, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$SavedState;->paymentFormOptions:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    .line 22
    .line 23
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->webView:Landroid/webkit/WebView;

    .line 24
    .line 25
    new-instance v0, Landroid/os/Bundle;

    .line 26
    .line 27
    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 28
    .line 29
    .line 30
    iput-object v0, v1, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$SavedState;->webViewBundle:Landroid/os/Bundle;

    .line 31
    .line 32
    invoke-virtual {p0, v0}, Landroid/webkit/WebView;->saveState(Landroid/os/Bundle;)Landroid/webkit/WebBackForwardList;

    .line 33
    .line 34
    .line 35
    return-object v1
.end method

.method public onViewCreated(Landroid/view/View;)V
    .locals 3
    .annotation build Landroid/annotation/SuppressLint;
        value = {
            "SetJavaScriptEnabled"
        }
    .end annotation

    .line 1
    invoke-static {}, Landroid/webkit/CookieManager;->getInstance()Landroid/webkit/CookieManager;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    const/4 v0, 0x1

    .line 6
    invoke-virtual {p1, v0}, Landroid/webkit/CookieManager;->setAcceptCookie(Z)V

    .line 7
    .line 8
    .line 9
    sget p1, Lcom/contoworks/kontocloud/uicomponents/R$id;->payment_provider_web_view:I

    .line 10
    .line 11
    invoke-virtual {p0, p1}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    check-cast p1, Landroid/webkit/WebView;

    .line 16
    .line 17
    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->webView:Landroid/webkit/WebView;

    .line 18
    .line 19
    sget p1, Lcom/contoworks/kontocloud/uicomponents/R$id;->progress:I

    .line 20
    .line 21
    invoke-virtual {p0, p1}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    check-cast p1, Landroid/widget/ProgressBar;

    .line 26
    .line 27
    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->progressBarView:Landroid/widget/ProgressBar;

    .line 28
    .line 29
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->webView:Landroid/webkit/WebView;

    .line 30
    .line 31
    invoke-virtual {p1, v0}, Landroid/webkit/WebView;->clearCache(Z)V

    .line 32
    .line 33
    .line 34
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->webView:Landroid/webkit/WebView;

    .line 35
    .line 36
    const/4 v1, 0x0

    .line 37
    invoke-static {v1, v1, v1, v1}, Landroid/graphics/Color;->argb(IIII)I

    .line 38
    .line 39
    .line 40
    move-result v2

    .line 41
    invoke-virtual {p1, v2}, Landroid/webkit/WebView;->setBackgroundColor(I)V

    .line 42
    .line 43
    .line 44
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->webView:Landroid/webkit/WebView;

    .line 45
    .line 46
    invoke-virtual {p1}, Landroid/webkit/WebView;->getSettings()Landroid/webkit/WebSettings;

    .line 47
    .line 48
    .line 49
    move-result-object p1

    .line 50
    invoke-virtual {p1, v0}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V

    .line 51
    .line 52
    .line 53
    const-string v2, "utf-8"

    .line 54
    .line 55
    invoke-virtual {p1, v2}, Landroid/webkit/WebSettings;->setDefaultTextEncodingName(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    invoke-virtual {p1, v0}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {p1, v0}, Landroid/webkit/WebSettings;->setSupportMultipleWindows(Z)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {p1, v1}, Landroid/webkit/WebSettings;->setAllowFileAccess(Z)V

    .line 65
    .line 66
    .line 67
    invoke-virtual {p1, v1}, Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs(Z)V

    .line 68
    .line 69
    .line 70
    invoke-virtual {p1, v1}, Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V

    .line 71
    .line 72
    .line 73
    invoke-virtual {p1, v1}, Landroid/webkit/WebSettings;->setAllowContentAccess(Z)V

    .line 74
    .line 75
    .line 76
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->webView:Landroid/webkit/WebView;

    .line 77
    .line 78
    new-instance v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$3;

    .line 79
    .line 80
    invoke-direct {v0, p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$3;-><init>(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)V

    .line 81
    .line 82
    .line 83
    invoke-virtual {p1, v0}, Landroid/webkit/WebView;->setWebChromeClient(Landroid/webkit/WebChromeClient;)V

    .line 84
    .line 85
    .line 86
    return-void
.end method

.method public render(Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    if-eqz p1, :cond_0

    .line 1
    invoke-static {p1}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    move-result-object p1

    invoke-direct {p0, p1, p2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->render(Ljava/util/List;Ljava/lang/String;)V

    return-void

    .line 2
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "The \'paymentOptionCode\' property must be set."

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public render([Ljava/lang/String;Ljava/lang/String;)V
    .locals 4

    if-eqz p1, :cond_3

    .line 3
    array-length v0, p1

    if-lez v0, :cond_2

    .line 4
    array-length v0, p1

    const/4 v1, 0x1

    if-le v0, v1, :cond_1

    .line 5
    array-length v0, p1

    const/4 v1, 0x0

    :goto_0
    if-ge v1, v0, :cond_1

    aget-object v2, p1, v1

    .line 6
    sget-object v3, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->paymentOptionCards:Ljava/util/Collection;

    invoke-interface {v3, v2}, Ljava/util/Collection;->contains(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_0

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    .line 7
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "The \'paymentOptionCodes\' array contains non-cards payment option "

    const-string p2, "."

    .line 8
    invoke-static {p1, v2, p2}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    .line 9
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 10
    :cond_1
    invoke-static {p1}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    move-result-object p1

    invoke-direct {p0, p1, p2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->render(Ljava/util/List;Ljava/lang/String;)V

    return-void

    .line 11
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "The \'paymentOptionCodes\' array must be not empty."

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 12
    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "The \'paymentOptionCodes\' property must be set."

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public setElementVisible(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$FormElement;Z)V
    .locals 9

    .line 1
    if-eqz p2, :cond_0

    .line 2
    .line 3
    const-string v0, "true"

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    const-string v0, "false"

    .line 7
    .line 8
    :goto_0
    sget-object v1, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$FormElement;->all:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$FormElement;

    .line 9
    .line 10
    const-string v2, ");"

    .line 11
    .line 12
    const-string v3, "\',"

    .line 13
    .line 14
    const-string v4, "javascript:setVisibility(\'"

    .line 15
    .line 16
    if-ne p1, v1, :cond_3

    .line 17
    .line 18
    if-nez p2, :cond_1

    .line 19
    .line 20
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->visibleElements:Ljava/util/HashSet;

    .line 21
    .line 22
    invoke-virtual {p1}, Ljava/util/HashSet;->clear()V

    .line 23
    .line 24
    .line 25
    :cond_1
    invoke-static {}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$FormElement;->values()[Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$FormElement;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    array-length v1, p1

    .line 30
    const/4 v5, 0x0

    .line 31
    :goto_1
    if-ge v5, v1, :cond_5

    .line 32
    .line 33
    aget-object v6, p1, v5

    .line 34
    .line 35
    sget-object v7, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$FormElement;->all:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$FormElement;

    .line 36
    .line 37
    if-eq v6, v7, :cond_2

    .line 38
    .line 39
    iget-object v7, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->jsCalls:Ljava/util/List;

    .line 40
    .line 41
    new-instance v8, Ljava/lang/StringBuilder;

    .line 42
    .line 43
    invoke-direct {v8, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {v8, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    invoke-virtual {v8, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    invoke-virtual {v8, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    invoke-virtual {v8, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object v8

    .line 62
    invoke-interface {v7, v8}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    if-eqz p2, :cond_2

    .line 66
    .line 67
    iget-object v7, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->visibleElements:Ljava/util/HashSet;

    .line 68
    .line 69
    invoke-virtual {v7, v6}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    :cond_2
    add-int/lit8 v5, v5, 0x1

    .line 73
    .line 74
    goto :goto_1

    .line 75
    :cond_3
    if-eqz p2, :cond_4

    .line 76
    .line 77
    iget-object p2, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->visibleElements:Ljava/util/HashSet;

    .line 78
    .line 79
    invoke-virtual {p2, p1}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    goto :goto_2

    .line 83
    :cond_4
    iget-object p2, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->visibleElements:Ljava/util/HashSet;

    .line 84
    .line 85
    invoke-virtual {p2, p1}, Ljava/util/HashSet;->remove(Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    :goto_2
    iget-object p2, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->jsCalls:Ljava/util/List;

    .line 89
    .line 90
    new-instance v1, Ljava/lang/StringBuilder;

    .line 91
    .line 92
    invoke-direct {v1, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 99
    .line 100
    .line 101
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 102
    .line 103
    .line 104
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 105
    .line 106
    .line 107
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object p1

    .line 111
    invoke-interface {p2, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 112
    .line 113
    .line 114
    :cond_5
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->webView:Landroid/webkit/WebView;

    .line 115
    .line 116
    if-eqz p1, :cond_6

    .line 117
    .line 118
    iget-boolean p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isWebViewLoaded:Z

    .line 119
    .line 120
    if-eqz p1, :cond_6

    .line 121
    .line 122
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->jsCalls:Ljava/util/List;

    .line 123
    .line 124
    invoke-direct {p0, p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->performJSCalls(Ljava/util/List;)V

    .line 125
    .line 126
    .line 127
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->jsCalls:Ljava/util/List;

    .line 128
    .line 129
    invoke-interface {p0}, Ljava/util/List;->clear()V

    .line 130
    .line 131
    .line 132
    :cond_6
    return-void
.end method

.method public setMode(I)V
    .locals 0
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->options:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    .line 2
    .line 3
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p0, p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->setMode(Ljava/lang/Integer;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public setOnSubmitCallback(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->onSubmitCallback:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback;

    .line 2
    .line 3
    return-void
.end method

.method public setOnValidationCallback(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnValidationCallback;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->onValidationCallback:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnValidationCallback;

    .line 2
    .line 3
    return-void
.end method

.method public setOptions(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;)V
    .locals 0

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->options:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 7
    .line 8
    const-string p1, "The \'options\' property must be set."

    .line 9
    .line 10
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    throw p0
.end method

.method public setPayPalButtonStyle(Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->payPalButtonStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;

    .line 2
    .line 3
    return-void
.end method

.method public setPaymentProviderMode(I)V
    .locals 0
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->options:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    .line 2
    .line 3
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p0, p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->setPaymentProviderMode(Ljava/lang/Integer;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public submit()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-boolean v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->isFormSubmitted:Z

    .line 3
    .line 4
    invoke-direct {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->internalSubmit()V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public validateElement(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$FormElement;)V
    .locals 8

    .line 1
    sget-object v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$FormElement;->all:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$FormElement;

    .line 2
    .line 3
    if-eq p1, v0, :cond_2

    .line 4
    .line 5
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    check-cast v0, Landroid/app/Activity;

    .line 10
    .line 11
    invoke-direct {p0, v0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->hideKeyboard(Landroid/app/Activity;)V

    .line 12
    .line 13
    .line 14
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->visibleElements:Ljava/util/HashSet;

    .line 15
    .line 16
    invoke-virtual {v0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    const-string v1, ""

    .line 21
    .line 22
    move-object v2, v1

    .line 23
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    const-string v4, "\');"

    .line 28
    .line 29
    if-eqz v3, :cond_0

    .line 30
    .line 31
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v3

    .line 35
    check-cast v3, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$FormElement;

    .line 36
    .line 37
    iget-object v5, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->webView:Landroid/webkit/WebView;

    .line 38
    .line 39
    new-instance v6, Ljava/lang/StringBuilder;

    .line 40
    .line 41
    const-string v7, "javascript:blurElement(\'\\"

    .line 42
    .line 43
    invoke-direct {v6, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {v6, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v4

    .line 56
    invoke-virtual {v5, v4}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    new-instance v4, Ljava/lang/StringBuilder;

    .line 60
    .line 61
    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    .line 62
    .line 63
    .line 64
    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    const-string v2, ","

    .line 74
    .line 75
    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object v2

    .line 82
    goto :goto_0

    .line 83
    :cond_0
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 84
    .line 85
    .line 86
    move-result v0

    .line 87
    if-lez v0, :cond_1

    .line 88
    .line 89
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 90
    .line 91
    .line 92
    move-result v0

    .line 93
    add-int/lit8 v0, v0, -0x1

    .line 94
    .line 95
    const/4 v1, 0x0

    .line 96
    invoke-virtual {v2, v1, v0}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 97
    .line 98
    .line 99
    move-result-object v2

    .line 100
    :cond_1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 101
    .line 102
    const-string v1, "javascript:firstValidationStep(\'"

    .line 103
    .line 104
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 105
    .line 106
    .line 107
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 108
    .line 109
    .line 110
    const-string v1, "\', \'"

    .line 111
    .line 112
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 113
    .line 114
    .line 115
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 116
    .line 117
    .line 118
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 119
    .line 120
    .line 121
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 122
    .line 123
    .line 124
    move-result-object p1

    .line 125
    invoke-virtual {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/CompoundView;->getUiHandler()Landroid/os/Handler;

    .line 126
    .line 127
    .line 128
    move-result-object v0

    .line 129
    new-instance v1, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$1;

    .line 130
    .line 131
    invoke-direct {v1, p0, p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$1;-><init>(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    const-wide/16 p0, 0x190

    .line 135
    .line 136
    invoke-virtual {v0, v1, p0, p1}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 137
    .line 138
    .line 139
    return-void

    .line 140
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 141
    .line 142
    const-string p1, "The payment form element should be specified."

    .line 143
    .line 144
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 145
    .line 146
    .line 147
    throw p0
.end method
