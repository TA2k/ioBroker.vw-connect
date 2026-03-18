.class public Lcom/salesforce/marketingcloud/messages/iam/IamModalActivity;
.super Lcom/salesforce/marketingcloud/messages/iam/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/View$OnClickListener;


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)I
    .locals 2

    .line 1
    sget p0, Lcom/salesforce/marketingcloud/R$layout;->mcsdk_iam_modal_inset_itb:I

    .line 2
    .line 3
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->media()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sget-object v1, Lcom/salesforce/marketingcloud/messages/iam/IamModalActivity$a;->a:[I

    .line 8
    .line 9
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->layoutOrder()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    aget p1, v1, p1

    .line 18
    .line 19
    const/4 v1, 0x1

    .line 20
    if-eq p1, v1, :cond_2

    .line 21
    .line 22
    const/4 v1, 0x2

    .line 23
    if-eq p1, v1, :cond_0

    .line 24
    .line 25
    return p0

    .line 26
    :cond_0
    if-eqz v0, :cond_1

    .line 27
    .line 28
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;->size()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media$ImageSize;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    sget-object p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media$ImageSize;->e2e:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media$ImageSize;

    .line 33
    .line 34
    if-ne p0, p1, :cond_1

    .line 35
    .line 36
    sget p0, Lcom/salesforce/marketingcloud/R$layout;->mcsdk_iam_modal_e2e_tib:I

    .line 37
    .line 38
    return p0

    .line 39
    :cond_1
    sget p0, Lcom/salesforce/marketingcloud/R$layout;->mcsdk_iam_modal_inset_tib:I

    .line 40
    .line 41
    return p0

    .line 42
    :cond_2
    if-eqz v0, :cond_3

    .line 43
    .line 44
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;->size()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media$ImageSize;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    sget-object p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media$ImageSize;->e2e:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media$ImageSize;

    .line 49
    .line 50
    if-ne p0, p1, :cond_3

    .line 51
    .line 52
    sget p0, Lcom/salesforce/marketingcloud/R$layout;->mcsdk_iam_modal_e2e_itb:I

    .line 53
    .line 54
    return p0

    .line 55
    :cond_3
    sget p0, Lcom/salesforce/marketingcloud/R$layout;->mcsdk_iam_modal_inset_itb:I

    .line 56
    .line 57
    return p0
.end method

.method public bridge synthetic b(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;)V
    .locals 0

    .line 1
    invoke-super {p0, p1}, Lcom/salesforce/marketingcloud/messages/iam/f;->b(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public bridge synthetic finish()V
    .locals 0

    .line 1
    invoke-super {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->finish()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public bridge synthetic onClick(Landroid/view/View;)V
    .locals 0

    .line 1
    invoke-super {p0, p1}, Lcom/salesforce/marketingcloud/messages/iam/f;->onClick(Landroid/view/View;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public onCreate(Landroid/os/Bundle;)V
    .locals 1

    .line 1
    invoke-super {p0, p1}, Lcom/salesforce/marketingcloud/messages/iam/f;->onCreate(Landroid/os/Bundle;)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Landroid/app/Activity;->isFinishing()Z

    .line 5
    .line 6
    .line 7
    move-result p1

    .line 8
    if-eqz p1, :cond_0

    .line 9
    .line 10
    return-void

    .line 11
    :cond_0
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->c()Lcom/salesforce/marketingcloud/messages/iam/k;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/iam/k;->l()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/messages/iam/IamModalActivity;->a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)I

    .line 20
    .line 21
    .line 22
    move-result p1

    .line 23
    invoke-virtual {p0, p1}, Lb/r;->setContentView(I)V

    .line 24
    .line 25
    .line 26
    new-instance p1, Lcom/salesforce/marketingcloud/messages/iam/l;

    .line 27
    .line 28
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->c()Lcom/salesforce/marketingcloud/messages/iam/k;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/iam/k;->s()Landroid/graphics/Typeface;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    invoke-direct {p1, p0, v0}, Lcom/salesforce/marketingcloud/messages/iam/l;-><init>(Landroid/view/View$OnClickListener;Landroid/graphics/Typeface;)V

    .line 37
    .line 38
    .line 39
    const v0, 0x1020002

    .line 40
    .line 41
    .line 42
    invoke-virtual {p0, v0}, Landroid/app/Activity;->findViewById(I)Landroid/view/View;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->c()Lcom/salesforce/marketingcloud/messages/iam/k;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    invoke-virtual {p1, v0, p0}, Lcom/salesforce/marketingcloud/messages/iam/d;->a(Landroid/view/View;Lcom/salesforce/marketingcloud/messages/iam/k;)V

    .line 51
    .line 52
    .line 53
    return-void
.end method

.method public bridge synthetic onDismissed()V
    .locals 0

    .line 1
    invoke-super {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->onDismissed()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public bridge synthetic onRequestPermissionsResult(I[Ljava/lang/String;[I)V
    .locals 0

    .line 1
    invoke-super {p0, p1, p2, p3}, Lcom/salesforce/marketingcloud/messages/iam/f;->onRequestPermissionsResult(I[Ljava/lang/String;[I)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public bridge synthetic onSwipeStarted()V
    .locals 0

    .line 1
    invoke-super {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->onSwipeStarted()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public bridge synthetic onViewSettled()V
    .locals 0

    .line 1
    invoke-super {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->onViewSettled()V

    .line 2
    .line 3
    .line 4
    return-void
.end method
