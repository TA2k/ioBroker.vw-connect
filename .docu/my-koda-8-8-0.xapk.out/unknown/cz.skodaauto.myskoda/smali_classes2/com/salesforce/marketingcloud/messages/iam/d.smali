.class abstract Lcom/salesforce/marketingcloud/messages/iam/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final a:Landroid/view/View$OnClickListener;

.field private final b:Landroid/graphics/Typeface;


# direct methods
.method public constructor <init>(Landroid/view/View$OnClickListener;Landroid/graphics/Typeface;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/d;->a:Landroid/view/View$OnClickListener;

    .line 5
    .line 6
    iput-object p2, p0, Lcom/salesforce/marketingcloud/messages/iam/d;->b:Landroid/graphics/Typeface;

    .line 7
    .line 8
    return-void
.end method

.method private a(Landroid/content/Context;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;)F
    .locals 0

    if-nez p2, :cond_0

    .line 22
    sget-object p2, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;->s:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 23
    :cond_0
    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object p0

    .line 24
    sget-object p1, Lcom/salesforce/marketingcloud/messages/iam/d$c;->a:[I

    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    move-result p2

    aget p1, p1, p2

    const/4 p2, 0x1

    if-eq p1, p2, :cond_2

    const/4 p2, 0x2

    if-eq p1, p2, :cond_1

    .line 25
    sget p1, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_border_width_small:I

    invoke-virtual {p0, p1}, Landroid/content/res/Resources;->getDimension(I)F

    move-result p0

    return p0

    .line 26
    :cond_1
    sget p1, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_border_width_medium:I

    invoke-virtual {p0, p1}, Landroid/content/res/Resources;->getDimension(I)F

    move-result p0

    return p0

    .line 27
    :cond_2
    sget p1, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_border_width_large:I

    invoke-virtual {p0, p1}, Landroid/content/res/Resources;->getDimension(I)F

    move-result p0

    return p0
.end method

.method private a(Landroid/view/View;)V
    .locals 3

    if-nez p1, :cond_0

    return-void

    .line 61
    :cond_0
    invoke-virtual {p1}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    move-result-object v0

    check-cast v0, Landroid/view/View;

    .line 62
    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v1

    invoke-virtual {v1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v1

    invoke-virtual {p0, v1}, Lcom/salesforce/marketingcloud/messages/iam/d;->a(Landroid/content/res/Resources;)F

    move-result v1

    invoke-static {v1}, Ljava/lang/Math;->round(F)I

    move-result v1

    .line 63
    new-instance v2, Lcom/salesforce/marketingcloud/messages/iam/d$b;

    invoke-direct {v2, p0, p1, v1, v0}, Lcom/salesforce/marketingcloud/messages/iam/d$b;-><init>(Lcom/salesforce/marketingcloud/messages/iam/d;Landroid/view/View;ILandroid/view/View;)V

    invoke-virtual {v0, v2}, Landroid/view/View;->post(Ljava/lang/Runnable;)Z

    return-void
.end method

.method private a(Landroid/view/View;Lcom/salesforce/marketingcloud/media/o;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;)V
    .locals 2

    .line 99
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/d;->e()I

    move-result v0

    invoke-virtual {p1, v0}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    move-result-object v0

    check-cast v0, Landroid/widget/ImageView;

    if-nez v0, :cond_0

    goto :goto_1

    .line 100
    :cond_0
    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v1

    if-eqz p3, :cond_3

    if-eqz p2, :cond_2

    const/4 p1, 0x0

    .line 101
    invoke-virtual {v0, p1}, Landroid/widget/ImageView;->setVisibility(I)V

    .line 102
    invoke-virtual {p3}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;->url()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p2, p1}, Lcom/salesforce/marketingcloud/media/o;->b(Ljava/lang/String;)Lcom/salesforce/marketingcloud/media/u;

    move-result-object p1

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/media/u;->d()Lcom/salesforce/marketingcloud/media/u;

    move-result-object p1

    .line 103
    sget-object p2, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;->fullImageFill:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;

    if-ne p4, p2, :cond_1

    .line 104
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/media/u;->b()Lcom/salesforce/marketingcloud/media/u;

    goto :goto_0

    .line 105
    :cond_1
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/media/u;->a()Lcom/salesforce/marketingcloud/media/u;

    .line 106
    :goto_0
    invoke-virtual {p3}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;->cornerRadius()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    move-result-object p2

    invoke-direct {p0, v1, p2}, Lcom/salesforce/marketingcloud/messages/iam/d;->b(Landroid/content/Context;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;)F

    move-result p2

    .line 107
    invoke-virtual {p3}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;->borderWidth()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    move-result-object p4

    invoke-direct {p0, v1, p4}, Lcom/salesforce/marketingcloud/messages/iam/d;->a(Landroid/content/Context;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;)F

    move-result p0

    .line 108
    invoke-virtual {p3}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;->borderColor()Ljava/lang/String;

    move-result-object p3

    sget p4, Lcom/salesforce/marketingcloud/R$color;->mcsdk_iam_default_border:I

    invoke-static {v1, p3, p4}, Lcom/salesforce/marketingcloud/messages/iam/g;->a(Landroid/content/Context;Ljava/lang/String;I)I

    move-result p3

    .line 109
    invoke-virtual {p1, p2, p0, p3}, Lcom/salesforce/marketingcloud/media/u;->a(FFI)Lcom/salesforce/marketingcloud/media/u;

    move-result-object p0

    .line 110
    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/media/u;->a(Landroid/widget/ImageView;)V

    :cond_2
    :goto_1
    return-void

    .line 111
    :cond_3
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/d;->d()I

    move-result p0

    invoke-virtual {p1, p0}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    move-result-object p0

    const/16 p1, 0x8

    if-eqz p0, :cond_4

    .line 112
    invoke-virtual {p0, p1}, Landroid/view/View;->setVisibility(I)V

    return-void

    .line 113
    :cond_4
    invoke-virtual {v0, p1}, Landroid/widget/ImageView;->setVisibility(I)V

    return-void
.end method

.method private a(Landroid/view/View;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;)V
    .locals 1

    .line 53
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/d;->c()I

    move-result v0

    invoke-virtual {p1, v0}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    move-result-object p1

    check-cast p1, Landroid/widget/ImageButton;

    if-nez p1, :cond_0

    return-void

    :cond_0
    if-eqz p2, :cond_1

    .line 54
    sget-object v0, Ld6/r0;->a:Ljava/util/WeakHashMap;

    const/high16 v0, 0x3f800000    # 1.0f

    .line 55
    invoke-static {p1, v0}, Ld6/k0;->l(Landroid/view/View;F)V

    const/4 v0, 0x0

    .line 56
    invoke-virtual {p1, v0}, Landroid/view/View;->setVisibility(I)V

    .line 57
    invoke-virtual {p1, p2}, Landroid/view/View;->setTag(Ljava/lang/Object;)V

    .line 58
    iget-object p2, p0, Lcom/salesforce/marketingcloud/messages/iam/d;->a:Landroid/view/View$OnClickListener;

    invoke-virtual {p1, p2}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 59
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/messages/iam/d;->a(Landroid/view/View;)V

    return-void

    :cond_1
    const/16 p0, 0x8

    .line 60
    invoke-virtual {p1, p0}, Landroid/view/View;->setVisibility(I)V

    return-void
.end method

.method private a(Landroid/view/View;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;)V
    .locals 5

    .line 42
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/d;->a()I

    move-result v0

    invoke-virtual {p1, v0}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    move-result-object v0

    check-cast v0, Landroid/widget/TextView;

    if-nez v0, :cond_0

    return-void

    .line 43
    :cond_0
    invoke-static {p2}, Lcom/salesforce/marketingcloud/messages/iam/d;->a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;)Z

    move-result v1

    if-eqz v1, :cond_2

    const/4 v1, 0x0

    .line 44
    invoke-virtual {v0, v1}, Landroid/view/View;->setVisibility(I)V

    .line 45
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/iam/d;->b:Landroid/graphics/Typeface;

    if-eqz v2, :cond_1

    .line 46
    invoke-virtual {v0, v2, v1}, Landroid/widget/TextView;->setTypeface(Landroid/graphics/Typeface;I)V

    .line 47
    :cond_1
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;->text()Ljava/lang/String;

    move-result-object v1

    .line 48
    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v2

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;->fontColor()Ljava/lang/String;

    move-result-object v3

    sget v4, Lcom/salesforce/marketingcloud/R$color;->mcsdk_iam_default_font_color:I

    invoke-static {v2, v3, v4}, Lcom/salesforce/marketingcloud/messages/iam/g;->a(Landroid/content/Context;Ljava/lang/String;I)I

    move-result v2

    .line 49
    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object p1

    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object p1

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;->fontSize()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    move-result-object v3

    invoke-virtual {p0, p1, v3}, Lcom/salesforce/marketingcloud/messages/iam/d;->a(Landroid/content/res/Resources;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;)F

    move-result p0

    .line 50
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;->alignment()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;

    move-result-object p1

    invoke-static {p1}, Lcom/salesforce/marketingcloud/messages/iam/g;->a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;)I

    move-result p1

    .line 51
    invoke-static {v0, v1, v2, p0, p1}, Lcom/salesforce/marketingcloud/messages/iam/g;->a(Landroid/widget/TextView;Ljava/lang/String;IFI)V

    return-void

    :cond_2
    const/16 p0, 0x8

    .line 52
    invoke-virtual {v0, p0}, Landroid/view/View;->setVisibility(I)V

    return-void
.end method

.method private a(Landroid/view/ViewGroup;)V
    .locals 3

    .line 94
    new-instance v0, Landroid/widget/Space;

    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v1

    invoke-direct {v0, v1}, Landroid/widget/Space;-><init>(Landroid/content/Context;)V

    .line 95
    new-instance v1, Landroid/widget/LinearLayout$LayoutParams;

    .line 96
    invoke-virtual {p1}, Landroid/view/View;->getResources()Landroid/content/res/Resources;

    move-result-object v2

    invoke-virtual {p0, v2}, Lcom/salesforce/marketingcloud/messages/iam/d;->b(Landroid/content/res/Resources;)F

    move-result p0

    invoke-static {p0}, Ljava/lang/Math;->round(F)I

    move-result p0

    const/4 v2, -0x1

    invoke-direct {v1, p0, v2}, Landroid/widget/LinearLayout$LayoutParams;-><init>(II)V

    .line 97
    invoke-virtual {v0, v1}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    .line 98
    invoke-virtual {p1, v0}, Landroid/view/ViewGroup;->addView(Landroid/view/View;)V

    return-void
.end method

.method public static a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;)Z
    .locals 0

    if-eqz p0, :cond_0

    .line 1
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;->text()Ljava/lang/String;

    move-result-object p0

    invoke-static {p0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result p0

    if-nez p0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0
.end method

.method public static a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)Z
    .locals 2

    .line 2
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->type()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;

    move-result-object v0

    sget-object v1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;->full:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;

    if-eq v0, v1, :cond_0

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->type()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;

    move-result-object v0

    sget-object v1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;->modal:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;

    if-ne v0, v1, :cond_2

    .line 3
    :cond_0
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->closeButton()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;

    move-result-object v0

    if-nez v0, :cond_2

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->buttons()Ljava/util/List;

    move-result-object v0

    if-eqz v0, :cond_1

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->buttons()Ljava/util/List;

    move-result-object p0

    invoke-interface {p0}, Ljava/util/List;->isEmpty()Z

    move-result p0

    if-nez p0, :cond_1

    goto :goto_0

    :cond_1
    const/4 p0, 0x0

    return p0

    :cond_2
    :goto_0
    const/4 p0, 0x1

    return p0
.end method

.method private b(Landroid/content/Context;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;)F
    .locals 0

    if-nez p2, :cond_0

    .line 2
    sget-object p2, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;->s:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 3
    :cond_0
    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object p0

    .line 4
    sget-object p1, Lcom/salesforce/marketingcloud/messages/iam/d$c;->a:[I

    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    move-result p2

    aget p1, p1, p2

    const/4 p2, 0x1

    if-eq p1, p2, :cond_2

    const/4 p2, 0x2

    if-eq p1, p2, :cond_1

    .line 5
    sget p1, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_corner_radius_small:I

    invoke-virtual {p0, p1}, Landroid/content/res/Resources;->getDimension(I)F

    move-result p0

    return p0

    .line 6
    :cond_1
    sget p1, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_corner_radius_medium:I

    invoke-virtual {p0, p1}, Landroid/content/res/Resources;->getDimension(I)F

    move-result p0

    return p0

    .line 7
    :cond_2
    sget p1, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_corner_radius_large:I

    invoke-virtual {p0, p1}, Landroid/content/res/Resources;->getDimension(I)F

    move-result p0

    return p0
.end method

.method private b(Landroid/view/View;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;)V
    .locals 5

    .line 8
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/d;->h()I

    move-result v0

    invoke-virtual {p1, v0}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    move-result-object v0

    check-cast v0, Landroid/widget/TextView;

    if-nez v0, :cond_0

    return-void

    .line 9
    :cond_0
    invoke-static {p2}, Lcom/salesforce/marketingcloud/messages/iam/d;->a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;)Z

    move-result v1

    if-eqz v1, :cond_2

    const/4 v1, 0x0

    .line 10
    invoke-virtual {v0, v1}, Landroid/view/View;->setVisibility(I)V

    .line 11
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/d;->b:Landroid/graphics/Typeface;

    if-eqz v1, :cond_1

    const/4 v2, 0x1

    .line 12
    invoke-virtual {v0, v1, v2}, Landroid/widget/TextView;->setTypeface(Landroid/graphics/Typeface;I)V

    .line 13
    :cond_1
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;->text()Ljava/lang/String;

    move-result-object v1

    .line 14
    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v2

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;->fontColor()Ljava/lang/String;

    move-result-object v3

    sget v4, Lcom/salesforce/marketingcloud/R$color;->mcsdk_iam_default_font_color:I

    invoke-static {v2, v3, v4}, Lcom/salesforce/marketingcloud/messages/iam/g;->a(Landroid/content/Context;Ljava/lang/String;I)I

    move-result v2

    .line 15
    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object p1

    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object p1

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;->fontSize()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    move-result-object v3

    invoke-virtual {p0, p1, v3}, Lcom/salesforce/marketingcloud/messages/iam/d;->c(Landroid/content/res/Resources;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;)F

    move-result p0

    .line 16
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;->alignment()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;

    move-result-object p1

    invoke-static {p1}, Lcom/salesforce/marketingcloud/messages/iam/g;->a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;)I

    move-result p1

    .line 17
    invoke-static {v0, v1, v2, p0, p1}, Lcom/salesforce/marketingcloud/messages/iam/g;->a(Landroid/widget/TextView;Ljava/lang/String;IFI)V

    return-void

    :cond_2
    const/16 p0, 0x8

    .line 18
    invoke-virtual {v0, p0}, Landroid/view/View;->setVisibility(I)V

    return-void
.end method

.method private b(Landroid/view/ViewGroup;)V
    .locals 3

    .line 19
    new-instance v0, Landroid/widget/Space;

    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v1

    invoke-direct {v0, v1}, Landroid/widget/Space;-><init>(Landroid/content/Context;)V

    .line 20
    new-instance v1, Landroid/widget/LinearLayout$LayoutParams;

    .line 21
    invoke-virtual {p1}, Landroid/view/View;->getResources()Landroid/content/res/Resources;

    move-result-object v2

    invoke-virtual {p0, v2}, Lcom/salesforce/marketingcloud/messages/iam/d;->c(Landroid/content/res/Resources;)F

    move-result p0

    invoke-static {p0}, Ljava/lang/Math;->round(F)I

    move-result p0

    const/4 v2, -0x1

    invoke-direct {v1, v2, p0}, Landroid/widget/LinearLayout$LayoutParams;-><init>(II)V

    .line 22
    invoke-virtual {v0, v1}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    .line 23
    invoke-virtual {p1, v0}, Landroid/view/ViewGroup;->addView(Landroid/view/View;)V

    return-void
.end method


# virtual methods
.method public abstract a(Landroid/content/res/Resources;)F
.end method

.method public abstract a(Landroid/content/res/Resources;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;)F
.end method

.method public abstract a()I
.end method

.method public a(Landroid/view/View;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;Ljava/util/List;)V
    .locals 16
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

    move-object/from16 v0, p0

    move-object/from16 v1, p2

    .line 64
    invoke-virtual/range {p1 .. p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v2

    .line 65
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/iam/d;->b()I

    move-result v3

    move-object/from16 v4, p1

    invoke-virtual {v4, v3}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    move-result-object v3

    check-cast v3, Landroid/widget/LinearLayout;

    .line 66
    sget-object v4, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;->stacked:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;

    const/4 v5, 0x1

    const/4 v6, 0x0

    if-ne v1, v4, :cond_0

    .line 67
    invoke-virtual {v3, v5}, Landroid/widget/LinearLayout;->setOrientation(I)V

    .line 68
    sget v4, Lcom/salesforce/marketingcloud/R$layout;->mcsdk_iam_stacked_button:I

    goto :goto_0

    .line 69
    :cond_0
    invoke-virtual {v3, v6}, Landroid/widget/LinearLayout;->setOrientation(I)V

    .line 70
    sget v4, Lcom/salesforce/marketingcloud/R$layout;->mcsdk_iam_sbs_button:I

    .line 71
    :goto_0
    invoke-static {v2}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    move-result-object v7

    .line 72
    invoke-interface/range {p3 .. p3}, Ljava/util/List;->size()I

    move-result v8

    move v9, v6

    :goto_1
    const/4 v10, 0x2

    if-ge v9, v10, :cond_4

    if-ge v9, v8, :cond_4

    move-object/from16 v10, p3

    .line 73
    invoke-interface {v10, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v11

    check-cast v11, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;

    .line 74
    invoke-virtual {v7, v4, v3, v6}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;Z)Landroid/view/View;

    move-result-object v12

    check-cast v12, Landroid/widget/Button;

    .line 75
    iget-object v13, v0, Lcom/salesforce/marketingcloud/messages/iam/d;->b:Landroid/graphics/Typeface;

    if-eqz v13, :cond_1

    .line 76
    invoke-virtual {v12, v13, v6}, Landroid/widget/TextView;->setTypeface(Landroid/graphics/Typeface;I)V

    .line 77
    :cond_1
    invoke-virtual {v11}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->text()Ljava/lang/String;

    move-result-object v13

    .line 78
    invoke-virtual {v11}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->fontColor()Ljava/lang/String;

    move-result-object v14

    sget v15, Lcom/salesforce/marketingcloud/R$color;->mcsdk_iam_default_font_color:I

    invoke-static {v2, v14, v15}, Lcom/salesforce/marketingcloud/messages/iam/g;->a(Landroid/content/Context;Ljava/lang/String;I)I

    move-result v14

    .line 79
    invoke-virtual {v2}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v15

    invoke-virtual {v11}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->fontSize()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    move-result-object v6

    invoke-virtual {v0, v15, v6}, Lcom/salesforce/marketingcloud/messages/iam/d;->b(Landroid/content/res/Resources;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;)F

    move-result v6

    sget-object v15, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;->center:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;

    .line 80
    invoke-static {v15}, Lcom/salesforce/marketingcloud/messages/iam/g;->a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;)I

    move-result v15

    .line 81
    invoke-static {v12, v13, v14, v6, v15}, Lcom/salesforce/marketingcloud/messages/iam/g;->a(Landroid/widget/TextView;Ljava/lang/String;IFI)V

    .line 82
    invoke-virtual {v11}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->backgroundColor()Ljava/lang/String;

    move-result-object v6

    sget v13, Lcom/salesforce/marketingcloud/R$color;->mcsdk_iam_default_btn_background:I

    invoke-static {v2, v6, v13}, Lcom/salesforce/marketingcloud/messages/iam/g;->a(Landroid/content/Context;Ljava/lang/String;I)I

    move-result v6

    .line 83
    invoke-virtual {v11}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->cornerRadius()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    move-result-object v13

    invoke-direct {v0, v2, v13}, Lcom/salesforce/marketingcloud/messages/iam/d;->b(Landroid/content/Context;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;)F

    move-result v13

    .line 84
    invoke-virtual {v11}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->borderColor()Ljava/lang/String;

    move-result-object v14

    sget v15, Lcom/salesforce/marketingcloud/R$color;->mcsdk_iam_default_border:I

    invoke-static {v2, v14, v15}, Lcom/salesforce/marketingcloud/messages/iam/g;->a(Landroid/content/Context;Ljava/lang/String;I)I

    move-result v14

    .line 85
    invoke-virtual {v11}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->borderWidth()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    move-result-object v15

    invoke-direct {v0, v2, v15}, Lcom/salesforce/marketingcloud/messages/iam/d;->a(Landroid/content/Context;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;)F

    move-result v15

    .line 86
    invoke-static {v6, v13, v14, v15}, Lcom/salesforce/marketingcloud/messages/iam/g;->a(IFIF)Landroid/graphics/drawable/Drawable;

    move-result-object v6

    sget-object v13, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 87
    invoke-virtual {v12, v6}, Landroid/view/View;->setBackground(Landroid/graphics/drawable/Drawable;)V

    .line 88
    invoke-virtual {v12, v11}, Landroid/view/View;->setTag(Ljava/lang/Object;)V

    .line 89
    iget-object v6, v0, Lcom/salesforce/marketingcloud/messages/iam/d;->a:Landroid/view/View$OnClickListener;

    invoke-virtual {v12, v6}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 90
    invoke-virtual {v3, v12}, Landroid/view/ViewGroup;->addView(Landroid/view/View;)V

    if-nez v9, :cond_3

    if-le v8, v5, :cond_3

    .line 91
    sget-object v6, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;->stacked:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;

    if-ne v1, v6, :cond_2

    .line 92
    invoke-direct {v0, v3}, Lcom/salesforce/marketingcloud/messages/iam/d;->b(Landroid/view/ViewGroup;)V

    goto :goto_2

    .line 93
    :cond_2
    invoke-direct {v0, v3}, Lcom/salesforce/marketingcloud/messages/iam/d;->a(Landroid/view/ViewGroup;)V

    :cond_3
    :goto_2
    add-int/lit8 v9, v9, 0x1

    const/4 v6, 0x0

    goto/16 :goto_1

    :cond_4
    return-void
.end method

.method public a(Landroid/view/View;Lcom/salesforce/marketingcloud/messages/iam/k;)V
    .locals 8

    if-eqz p2, :cond_4

    if-nez p1, :cond_0

    goto/16 :goto_2

    .line 4
    :cond_0
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/messages/iam/k;->l()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    move-result-object v0

    .line 5
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->windowColor()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p0, p1, v1}, Lcom/salesforce/marketingcloud/messages/iam/d;->a(Landroid/view/View;Ljava/lang/String;)V

    .line 6
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->backgroundColor()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->borderColor()Ljava/lang/String;

    move-result-object v5

    .line 7
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->borderWidth()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    move-result-object v6

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->cornerRadius()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    move-result-object v7

    move-object v2, p0

    move-object v3, p1

    .line 8
    invoke-virtual/range {v2 .. v7}, Lcom/salesforce/marketingcloud/messages/iam/d;->a(Landroid/view/View;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;)V

    .line 9
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->title()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;

    move-result-object p0

    invoke-direct {v2, v3, p0}, Lcom/salesforce/marketingcloud/messages/iam/d;->b(Landroid/view/View;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;)V

    .line 10
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->body()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;

    move-result-object p0

    invoke-direct {v2, v3, p0}, Lcom/salesforce/marketingcloud/messages/iam/d;->a(Landroid/view/View;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;)V

    .line 11
    invoke-static {v0}, Lcom/salesforce/marketingcloud/messages/iam/d;->a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)Z

    move-result p0

    if-eqz p0, :cond_1

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->closeButton()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;

    move-result-object p0

    goto :goto_0

    :cond_1
    invoke-static {}, Lcom/salesforce/marketingcloud/internal/c;->a()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;

    move-result-object p0

    .line 12
    :goto_0
    invoke-direct {v2, v3, p0}, Lcom/salesforce/marketingcloud/messages/iam/d;->a(Landroid/view/View;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;)V

    .line 13
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->buttons()Ljava/util/List;

    move-result-object p0

    if-eqz p0, :cond_2

    .line 14
    invoke-interface {p0}, Ljava/util/List;->isEmpty()Z

    move-result p1

    if-nez p1, :cond_2

    .line 15
    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1, p0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 16
    new-instance p0, Lcom/salesforce/marketingcloud/messages/iam/d$a;

    invoke-direct {p0, v2}, Lcom/salesforce/marketingcloud/messages/iam/d$a;-><init>(Lcom/salesforce/marketingcloud/messages/iam/d;)V

    invoke-static {p1, p0}, Ljava/util/Collections;->sort(Ljava/util/List;Ljava/util/Comparator;)V

    .line 17
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->buttonConfiguration()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;

    move-result-object p0

    invoke-virtual {v2, v3, p0, p1}, Lcom/salesforce/marketingcloud/messages/iam/d;->a(Landroid/view/View;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;Ljava/util/List;)V

    goto :goto_1

    .line 18
    :cond_2
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/messages/iam/d;->b()I

    move-result p0

    invoke-virtual {v3, p0}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    move-result-object p0

    if-eqz p0, :cond_3

    const/16 p1, 0x8

    .line 19
    invoke-virtual {p0, p1}, Landroid/view/View;->setVisibility(I)V

    .line 20
    :cond_3
    :goto_1
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/messages/iam/k;->m()Lcom/salesforce/marketingcloud/media/o;

    move-result-object p0

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->media()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;

    move-result-object p1

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->type()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;

    move-result-object v0

    invoke-direct {v2, v3, p0, p1, v0}, Lcom/salesforce/marketingcloud/messages/iam/d;->a(Landroid/view/View;Lcom/salesforce/marketingcloud/media/o;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;)V

    .line 21
    invoke-virtual {v2, v3, p2}, Lcom/salesforce/marketingcloud/messages/iam/d;->b(Landroid/view/View;Lcom/salesforce/marketingcloud/messages/iam/k;)V

    :cond_4
    :goto_2
    return-void
.end method

.method public a(Landroid/view/View;Ljava/lang/String;)V
    .locals 1

    .line 28
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/d;->g()I

    move-result p0

    invoke-virtual {p1, p0}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    move-result-object p0

    if-nez p0, :cond_0

    return-void

    .line 29
    :cond_0
    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object p1

    sget v0, Lcom/salesforce/marketingcloud/R$color;->mcsdk_iam_default_window_background:I

    invoke-static {p1, p2, v0}, Lcom/salesforce/marketingcloud/messages/iam/g;->a(Landroid/content/Context;Ljava/lang/String;I)I

    move-result p1

    .line 30
    invoke-virtual {p0, p1}, Landroid/view/View;->setBackgroundColor(I)V

    return-void
.end method

.method public a(Landroid/view/View;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;)V
    .locals 1

    .line 31
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/d;->f()I

    move-result v0

    invoke-virtual {p1, v0}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    move-result-object v0

    if-nez v0, :cond_0

    goto :goto_0

    .line 32
    :cond_0
    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object p1

    .line 33
    invoke-direct {p0, p1, p5}, Lcom/salesforce/marketingcloud/messages/iam/d;->b(Landroid/content/Context;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;)F

    move-result p5

    .line 34
    invoke-direct {p0, p1, p4}, Lcom/salesforce/marketingcloud/messages/iam/d;->a(Landroid/content/Context;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;)F

    move-result p0

    .line 35
    sget p4, Lcom/salesforce/marketingcloud/R$color;->mcsdk_iam_default_message_background:I

    .line 36
    invoke-static {p1, p2, p4}, Lcom/salesforce/marketingcloud/messages/iam/g;->a(Landroid/content/Context;Ljava/lang/String;I)I

    move-result p2

    sget p4, Lcom/salesforce/marketingcloud/R$color;->mcsdk_iam_default_border:I

    .line 37
    invoke-static {p1, p3, p4}, Lcom/salesforce/marketingcloud/messages/iam/g;->a(Landroid/content/Context;Ljava/lang/String;I)I

    move-result p1

    .line 38
    invoke-static {p2, p5, p1, p0}, Lcom/salesforce/marketingcloud/messages/iam/g;->a(IFIF)Landroid/graphics/drawable/Drawable;

    move-result-object p1

    sget-object p2, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 39
    invoke-virtual {v0, p1}, Landroid/view/View;->setBackground(Landroid/graphics/drawable/Drawable;)V

    .line 40
    instance-of p1, v0, Lcom/salesforce/marketingcloud/messages/iam/ClippingConstraintLayout;

    if-eqz p1, :cond_1

    .line 41
    check-cast v0, Lcom/salesforce/marketingcloud/messages/iam/ClippingConstraintLayout;

    invoke-virtual {v0, p0, p5}, Lcom/salesforce/marketingcloud/messages/iam/ClippingConstraintLayout;->setClippingDetails(FF)V

    :cond_1
    :goto_0
    return-void
.end method

.method public abstract b(Landroid/content/res/Resources;)F
.end method

.method public abstract b(Landroid/content/res/Resources;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;)F
.end method

.method public abstract b()I
.end method

.method public b(Landroid/view/View;Lcom/salesforce/marketingcloud/messages/iam/k;)V
    .locals 0

    .line 1
    return-void
.end method

.method public abstract c(Landroid/content/res/Resources;)F
.end method

.method public abstract c(Landroid/content/res/Resources;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;)F
.end method

.method public abstract c()I
.end method

.method public abstract d()I
.end method

.method public abstract e()I
.end method

.method public abstract f()I
.end method

.method public abstract g()I
.end method

.method public abstract h()I
.end method
