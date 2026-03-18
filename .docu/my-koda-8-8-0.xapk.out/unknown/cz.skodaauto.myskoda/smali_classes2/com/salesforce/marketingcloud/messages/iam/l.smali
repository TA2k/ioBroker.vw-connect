.class Lcom/salesforce/marketingcloud/messages/iam/l;
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

    .line 6
    sget p0, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_iam_modal_closebtn_hitbox_increase:I

    invoke-virtual {p1, p0}, Landroid/content/res/Resources;->getDimension(I)F

    move-result p0

    return p0
.end method

.method public a(Landroid/content/res/Resources;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;)F
    .locals 0

    if-nez p2, :cond_0

    .line 1
    sget-object p2, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;->s:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 2
    :cond_0
    sget-object p0, Lcom/salesforce/marketingcloud/messages/iam/l$a;->a:[I

    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    move-result p2

    aget p0, p0, p2

    const/4 p2, 0x1

    if-eq p0, p2, :cond_2

    const/4 p2, 0x2

    if-eq p0, p2, :cond_1

    .line 3
    sget p0, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_iam_modal_body_font_small:I

    invoke-virtual {p1, p0}, Landroid/content/res/Resources;->getDimension(I)F

    move-result p0

    return p0

    .line 4
    :cond_1
    sget p0, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_iam_modal_body_font_medium:I

    invoke-virtual {p1, p0}, Landroid/content/res/Resources;->getDimension(I)F

    move-result p0

    return p0

    .line 5
    :cond_2
    sget p0, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_iam_modal_body_font_large:I

    invoke-virtual {p1, p0}, Landroid/content/res/Resources;->getDimension(I)F

    move-result p0

    return p0
.end method

.method public a()I
    .locals 0

    .line 7
    sget p0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_iam_body:I

    return p0
.end method

.method public b(Landroid/content/res/Resources;)F
    .locals 0

    .line 6
    sget p0, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_button_group_horizontal_divider:I

    invoke-virtual {p1, p0}, Landroid/content/res/Resources;->getDimension(I)F

    move-result p0

    return p0
.end method

.method public b(Landroid/content/res/Resources;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;)F
    .locals 0

    if-nez p2, :cond_0

    .line 1
    sget-object p2, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;->s:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 2
    :cond_0
    sget-object p0, Lcom/salesforce/marketingcloud/messages/iam/l$a;->a:[I

    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    move-result p2

    aget p0, p0, p2

    const/4 p2, 0x1

    if-eq p0, p2, :cond_2

    const/4 p2, 0x2

    if-eq p0, p2, :cond_1

    .line 3
    sget p0, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_iam_modal_btn_font_small:I

    invoke-virtual {p1, p0}, Landroid/content/res/Resources;->getDimension(I)F

    move-result p0

    return p0

    .line 4
    :cond_1
    sget p0, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_iam_modal_btn_font_medium:I

    invoke-virtual {p1, p0}, Landroid/content/res/Resources;->getDimension(I)F

    move-result p0

    return p0

    .line 5
    :cond_2
    sget p0, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_iam_modal_btn_font_large:I

    invoke-virtual {p1, p0}, Landroid/content/res/Resources;->getDimension(I)F

    move-result p0

    return p0
.end method

.method public b()I
    .locals 0

    .line 7
    sget p0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_iam_buttons:I

    return p0
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
    sget-object p0, Lcom/salesforce/marketingcloud/messages/iam/l$a;->a:[I

    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    move-result p2

    aget p0, p0, p2

    const/4 p2, 0x1

    if-eq p0, p2, :cond_1

    const/4 p2, 0x2

    if-eq p0, p2, :cond_1

    .line 3
    sget p0, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_iam_modal_title_font_small:I

    invoke-virtual {p1, p0}, Landroid/content/res/Resources;->getDimension(I)F

    move-result p0

    return p0

    .line 4
    :cond_1
    sget p0, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_iam_modal_title_font_large:I

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
    sget p0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_iam_media_group:I

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
