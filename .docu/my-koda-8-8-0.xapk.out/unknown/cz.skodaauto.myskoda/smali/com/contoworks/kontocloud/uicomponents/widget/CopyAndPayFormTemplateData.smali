.class Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData$Strings;
    }
.end annotation


# static fields
.field private static final productionWidgetUrl:Ljava/lang/String; = "https://eu-prod.oppwa.com/"

.field private static final testWidgetUrl:Ljava/lang/String; = "https://eu-test.oppwa.com/"


# instance fields
.field private brands:Ljava/util/Collection;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private callbackUrl:Ljava/lang/String;

.field private locale:Ljava/lang/String;

.field private paymentFormVersion:Ljava/lang/String;

.field private showStorePaymentMethod:Z

.field private strings:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData$Strings;

.field private styles:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;

.field private token:Ljava/lang/String;

.field private widgetUrl:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/Boolean;Ljava/lang/String;Ljava/lang/String;Ljava/util/Collection;Ljava/lang/String;Ljava/lang/String;Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData$Strings;Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/Boolean;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData$Strings;",
            "Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 5
    .line 6
    .line 7
    move-result p1

    .line 8
    if-eqz p1, :cond_0

    .line 9
    .line 10
    const-string p1, "https://eu-prod.oppwa.com/"

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const-string p1, "https://eu-test.oppwa.com/"

    .line 14
    .line 15
    :goto_0
    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData;->widgetUrl:Ljava/lang/String;

    .line 16
    .line 17
    iput-object p2, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData;->token:Ljava/lang/String;

    .line 18
    .line 19
    iput-object p4, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData;->brands:Ljava/util/Collection;

    .line 20
    .line 21
    iput-object p5, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData;->callbackUrl:Ljava/lang/String;

    .line 22
    .line 23
    iput-object p6, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData;->locale:Ljava/lang/String;

    .line 24
    .line 25
    iput-object p7, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData;->strings:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData$Strings;

    .line 26
    .line 27
    iput-object p8, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData;->styles:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;

    .line 28
    .line 29
    iput-object p3, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData;->paymentFormVersion:Ljava/lang/String;

    .line 30
    .line 31
    return-void
.end method


# virtual methods
.method public getBrands()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData;->brands:Ljava/util/Collection;

    .line 7
    .line 8
    invoke-interface {p0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    const-string v1, ""

    .line 13
    .line 14
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    if-eqz v2, :cond_0

    .line 19
    .line 20
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v2

    .line 24
    check-cast v2, Ljava/lang/String;

    .line 25
    .line 26
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    const-string v1, " "

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_0
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0
.end method

.method public getCallbackUrl()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData;->callbackUrl:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getCardNumberPlaceholderJson()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData;->styles:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->toCardNumberPlaceholderJson()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getCssStyles()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData;->styles:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->toCss()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getCvvPlaceholderJson()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData;->styles:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->toCvvPlaceholderJson()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getLocale()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData;->locale:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getStrings()Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData$Strings;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData;->strings:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData$Strings;

    .line 2
    .line 3
    return-object p0
.end method

.method public getToken()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData;->token:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getWidgetUrl()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData;->widgetUrl:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public isShowCVVHint()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData;->styles:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;

    .line 2
    .line 3
    iget-boolean p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->showCVVHint:Z

    .line 4
    .line 5
    return p0
.end method

.method public isShowStorePaymentMethod()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData;->showStorePaymentMethod:Z

    .line 2
    .line 3
    return p0
.end method

.method public isUseBrandDetection()Z
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData;->brands:Ljava/util/Collection;

    .line 2
    .line 3
    invoke-interface {p0}, Ljava/util/Collection;->size()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    const/4 v0, 0x1

    .line 8
    if-le p0, v0, :cond_0

    .line 9
    .line 10
    return v0

    .line 11
    :cond_0
    const/4 p0, 0x0

    .line 12
    return p0
.end method

.method public setShowStorePaymentMethod(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormTemplateData;->showStorePaymentMethod:Z

    .line 2
    .line 3
    return-void
.end method
