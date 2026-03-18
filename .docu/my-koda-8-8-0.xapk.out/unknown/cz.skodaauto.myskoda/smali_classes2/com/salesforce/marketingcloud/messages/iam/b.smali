.class Lcom/salesforce/marketingcloud/messages/iam/b;
.super Lcom/salesforce/marketingcloud/messages/iam/d;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public constructor <init>(Landroid/view/View$OnClickListener;Landroid/graphics/Typeface;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lcom/salesforce/marketingcloud/messages/iam/d;-><init>(Landroid/view/View$OnClickListener;Landroid/graphics/Typeface;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public a(Landroid/content/res/Resources;)F
    .locals 0

    .line 7
    sget p0, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_iam_banner_closebtn_hitbox_increase:I

    invoke-virtual {p1, p0}, Landroid/content/res/Resources;->getDimension(I)F

    move-result p0

    return p0
.end method

.method public a(Landroid/content/res/Resources;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;)F
    .locals 0

    if-nez p2, :cond_0

    .line 2
    sget-object p2, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;->s:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 3
    :cond_0
    sget-object p0, Lcom/salesforce/marketingcloud/messages/iam/b$a;->a:[I

    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    move-result p2

    aget p0, p0, p2

    const/4 p2, 0x1

    if-eq p0, p2, :cond_2

    const/4 p2, 0x2

    if-eq p0, p2, :cond_1

    .line 4
    sget p0, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_iam_banner_body_font_small:I

    invoke-virtual {p1, p0}, Landroid/content/res/Resources;->getDimension(I)F

    move-result p0

    return p0

    .line 5
    :cond_1
    sget p0, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_iam_banner_body_font_medium:I

    invoke-virtual {p1, p0}, Landroid/content/res/Resources;->getDimension(I)F

    move-result p0

    return p0

    .line 6
    :cond_2
    sget p0, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_iam_banner_body_font_large:I

    invoke-virtual {p1, p0}, Landroid/content/res/Resources;->getDimension(I)F

    move-result p0

    return p0
.end method

.method public a()I
    .locals 0

    .line 8
    sget p0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_iam_body:I

    return p0
.end method

.method public a(Landroid/view/View;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;Ljava/util/List;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Landroid/view/View;",
            "Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;",
            ">;)V"
        }
    .end annotation

    .line 9
    sget-object p2, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;->twoUp:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;

    invoke-super {p0, p1, p2, p3}, Lcom/salesforce/marketingcloud/messages/iam/d;->a(Landroid/view/View;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;Ljava/util/List;)V

    return-void
.end method

.method public a(Landroid/view/View;Ljava/lang/String;)V
    .locals 0

    .line 1
    return-void
.end method

.method public b(Landroid/content/res/Resources;)F
    .locals 0

    .line 22
    sget p0, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_button_group_horizontal_divider:I

    invoke-virtual {p1, p0}, Landroid/content/res/Resources;->getDimension(I)F

    move-result p0

    return p0
.end method

.method public b(Landroid/content/res/Resources;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;)F
    .locals 0

    if-nez p2, :cond_0

    .line 17
    sget-object p2, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;->s:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 18
    :cond_0
    sget-object p0, Lcom/salesforce/marketingcloud/messages/iam/b$a;->a:[I

    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    move-result p2

    aget p0, p0, p2

    const/4 p2, 0x1

    if-eq p0, p2, :cond_2

    const/4 p2, 0x2

    if-eq p0, p2, :cond_1

    .line 19
    sget p0, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_iam_banner_btn_font_small:I

    invoke-virtual {p1, p0}, Landroid/content/res/Resources;->getDimension(I)F

    move-result p0

    return p0

    .line 20
    :cond_1
    sget p0, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_iam_banner_btn_font_medium:I

    invoke-virtual {p1, p0}, Landroid/content/res/Resources;->getDimension(I)F

    move-result p0

    return p0

    .line 21
    :cond_2
    sget p0, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_iam_banner_btn_font_large:I

    invoke-virtual {p1, p0}, Landroid/content/res/Resources;->getDimension(I)F

    move-result p0

    return p0
.end method

.method public b()I
    .locals 0

    .line 23
    sget p0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_iam_buttons:I

    return p0
.end method

.method public b(Landroid/view/View;Lcom/salesforce/marketingcloud/messages/iam/k;)V
    .locals 4

    .line 1
    invoke-super {p0, p1, p2}, Lcom/salesforce/marketingcloud/messages/iam/d;->b(Landroid/view/View;Lcom/salesforce/marketingcloud/messages/iam/k;)V

    .line 2
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/messages/iam/k;->l()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    move-result-object p2

    .line 3
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->closeButton()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;

    move-result-object v0

    if-eqz v0, :cond_2

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->title()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;

    move-result-object p2

    invoke-static {p2}, Lcom/salesforce/marketingcloud/messages/iam/d;->a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;)Z

    move-result p2

    if-nez p2, :cond_2

    .line 4
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/b;->f()I

    move-result p2

    invoke-virtual {p1, p2}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    move-result-object p1

    check-cast p1, Landroidx/constraintlayout/widget/ConstraintLayout;

    if-eqz p1, :cond_2

    .line 5
    new-instance p2, Landroidx/constraintlayout/widget/o;

    invoke-direct {p2}, Landroidx/constraintlayout/widget/o;-><init>()V

    .line 6
    invoke-virtual {p2, p1}, Landroidx/constraintlayout/widget/o;->b(Landroidx/constraintlayout/widget/ConstraintLayout;)V

    .line 7
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/b;->a()I

    move-result v0

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/b;->c()I

    move-result p0

    .line 8
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    iget-object v2, p2, Landroidx/constraintlayout/widget/o;->c:Ljava/util/HashMap;

    invoke-virtual {v2, v1}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_0

    .line 9
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    new-instance v3, Landroidx/constraintlayout/widget/j;

    invoke-direct {v3}, Landroidx/constraintlayout/widget/j;-><init>()V

    invoke-virtual {v2, v1, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 10
    :cond_0
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    invoke-virtual {v2, v0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroidx/constraintlayout/widget/j;

    if-nez v0, :cond_1

    goto :goto_0

    .line 11
    :cond_1
    iget-object v0, v0, Landroidx/constraintlayout/widget/j;->d:Landroidx/constraintlayout/widget/k;

    .line 12
    iput p0, v0, Landroidx/constraintlayout/widget/k;->u:I

    const/4 p0, -0x1

    .line 13
    iput p0, v0, Landroidx/constraintlayout/widget/k;->v:I

    .line 14
    :goto_0
    invoke-virtual {p2, p1}, Landroidx/constraintlayout/widget/o;->a(Landroidx/constraintlayout/widget/ConstraintLayout;)V

    const/4 p0, 0x0

    .line 15
    invoke-virtual {p1, p0}, Landroidx/constraintlayout/widget/ConstraintLayout;->setConstraintSet(Landroidx/constraintlayout/widget/o;)V

    .line 16
    invoke-virtual {p1}, Landroidx/constraintlayout/widget/ConstraintLayout;->requestLayout()V

    :cond_2
    return-void
.end method

.method public c(Landroid/content/res/Resources;)F
    .locals 0

    .line 5
    sget p0, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_button_group_vertical_divider:I

    invoke-virtual {p1, p0}, Landroid/content/res/Resources;->getDimension(I)F

    move-result p0

    return p0
.end method

.method public c(Landroid/content/res/Resources;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;)F
    .locals 0

    if-nez p2, :cond_0

    .line 1
    sget-object p2, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;->s:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 2
    :cond_0
    sget-object p0, Lcom/salesforce/marketingcloud/messages/iam/b$a;->a:[I

    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    move-result p2

    aget p0, p0, p2

    const/4 p2, 0x1

    if-eq p0, p2, :cond_1

    const/4 p2, 0x2

    if-eq p0, p2, :cond_1

    .line 3
    sget p0, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_iam_banner_title_font_small:I

    invoke-virtual {p1, p0}, Landroid/content/res/Resources;->getDimension(I)F

    move-result p0

    return p0

    .line 4
    :cond_1
    sget p0, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_iam_banner_title_font_large:I

    invoke-virtual {p1, p0}, Landroid/content/res/Resources;->getDimension(I)F

    move-result p0

    return p0
.end method

.method public c()I
    .locals 0

    .line 6
    sget p0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_iam_close:I

    return p0
.end method

.method public d()I
    .locals 0

    .line 1
    sget p0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_iam_media:I

    .line 2
    .line 3
    return p0
.end method

.method public e()I
    .locals 0

    .line 1
    sget p0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_iam_media:I

    .line 2
    .line 3
    return p0
.end method

.method public f()I
    .locals 0

    .line 1
    sget p0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_iam_container:I

    .line 2
    .line 3
    return p0
.end method

.method public g()I
    .locals 0

    .line 1
    sget p0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_iam_parent:I

    .line 2
    .line 3
    return p0
.end method

.method public h()I
    .locals 0

    .line 1
    sget p0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_iam_title:I

    .line 2
    .line 3
    return p0
.end method
