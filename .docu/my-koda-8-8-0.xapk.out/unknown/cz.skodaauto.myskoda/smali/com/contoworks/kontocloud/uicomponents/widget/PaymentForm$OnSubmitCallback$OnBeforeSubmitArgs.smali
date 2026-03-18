.class public Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback$OnBeforeSubmitArgs;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "OnBeforeSubmitArgs"
.end annotation


# instance fields
.field private data:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private isSubmitPrevented:Z

.field private paymentOptionCode:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/util/Map;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback$OnBeforeSubmitArgs;->paymentOptionCode:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback$OnBeforeSubmitArgs;->data:Ljava/util/Map;

    .line 7
    .line 8
    return-void
.end method

.method public static bridge synthetic a(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback$OnBeforeSubmitArgs;)Z
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback$OnBeforeSubmitArgs;->isSubmitPrevented()Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method private isSubmitPrevented()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback$OnBeforeSubmitArgs;->isSubmitPrevented:Z

    .line 2
    .line 3
    return p0
.end method


# virtual methods
.method public getData()Ljava/util/Map;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback$OnBeforeSubmitArgs;->data:Ljava/util/Map;

    .line 2
    .line 3
    return-object p0
.end method

.method public getPaymentOptionCode()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback$OnBeforeSubmitArgs;->paymentOptionCode:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public preventSubmit()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback$OnBeforeSubmitArgs;->isSubmitPrevented:Z

    .line 3
    .line 4
    return-void
.end method
