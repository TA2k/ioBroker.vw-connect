.class public Lcom/salesforce/marketingcloud/messages/iam/c;
.super Landroidx/fragment/app/j0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation


# instance fields
.field private a:Lcom/salesforce/marketingcloud/messages/iam/k;


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Landroidx/fragment/app/j0;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)I
    .locals 0

    .line 5
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->type()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;

    move-result-object p0

    sget-object p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;->bannerTop:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;

    if-ne p0, p1, :cond_0

    .line 6
    sget p0, Lcom/salesforce/marketingcloud/R$layout;->mcsdk_iam_banner_top:I

    return p0

    .line 7
    :cond_0
    sget p0, Lcom/salesforce/marketingcloud/R$layout;->mcsdk_iam_banner_bottom:I

    return p0
.end method

.method public static a(Lcom/salesforce/marketingcloud/messages/iam/k;)Lcom/salesforce/marketingcloud/messages/iam/c;
    .locals 2

    .line 1
    new-instance v0, Landroid/os/Bundle;

    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 2
    const-string v1, "messageHandler"

    invoke-virtual {v0, v1, p0}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 3
    new-instance p0, Lcom/salesforce/marketingcloud/messages/iam/c;

    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/iam/c;-><init>()V

    .line 4
    invoke-virtual {p0, v0}, Landroidx/fragment/app/j0;->setArguments(Landroid/os/Bundle;)V

    return-object p0
.end method


# virtual methods
.method public onCreate(Landroid/os/Bundle;)V
    .locals 1

    .line 1
    invoke-super {p0, p1}, Landroidx/fragment/app/j0;->onCreate(Landroid/os/Bundle;)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->getArguments()Landroid/os/Bundle;

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    if-eqz p1, :cond_0

    .line 9
    .line 10
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->getArguments()Landroid/os/Bundle;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    const-string v0, "messageHandler"

    .line 15
    .line 16
    invoke-virtual {p1, v0}, Landroid/os/Bundle;->getParcelable(Ljava/lang/String;)Landroid/os/Parcelable;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    check-cast p1, Lcom/salesforce/marketingcloud/messages/iam/k;

    .line 21
    .line 22
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/c;->a:Lcom/salesforce/marketingcloud/messages/iam/k;

    .line 23
    .line 24
    :cond_0
    return-void
.end method

.method public onCreateAnimation(IZI)Landroid/view/animation/Animation;
    .locals 2

    .line 1
    invoke-super {p0, p1, p2, p3}, Landroidx/fragment/app/j0;->onCreateAnimation(IZI)Landroid/view/animation/Animation;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    if-nez p1, :cond_0

    .line 6
    .line 7
    if-eqz p3, :cond_0

    .line 8
    .line 9
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->getActivity()Landroidx/fragment/app/o0;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    invoke-static {p1, p3}, Landroid/view/animation/AnimationUtils;->loadAnimation(Landroid/content/Context;I)Landroid/view/animation/Animation;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    :cond_0
    if-eqz p1, :cond_1

    .line 18
    .line 19
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->getView()Landroid/view/View;

    .line 20
    .line 21
    .line 22
    move-result-object p3

    .line 23
    if-eqz p3, :cond_1

    .line 24
    .line 25
    const/4 v0, 0x2

    .line 26
    const/4 v1, 0x0

    .line 27
    invoke-virtual {p3, v0, v1}, Landroid/view/View;->setLayerType(ILandroid/graphics/Paint;)V

    .line 28
    .line 29
    .line 30
    new-instance p3, Lcom/salesforce/marketingcloud/messages/iam/c$a;

    .line 31
    .line 32
    invoke-direct {p3, p0, p2}, Lcom/salesforce/marketingcloud/messages/iam/c$a;-><init>(Lcom/salesforce/marketingcloud/messages/iam/c;Z)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {p1, p3}, Landroid/view/animation/Animation;->setAnimationListener(Landroid/view/animation/Animation$AnimationListener;)V

    .line 36
    .line 37
    .line 38
    :cond_1
    return-object p1
.end method

.method public onCreateView(Landroid/view/LayoutInflater;Landroid/view/ViewGroup;Landroid/os/Bundle;)Landroid/view/View;
    .locals 2

    .line 1
    iget-object p3, p0, Lcom/salesforce/marketingcloud/messages/iam/c;->a:Lcom/salesforce/marketingcloud/messages/iam/k;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    if-nez p3, :cond_0

    .line 5
    .line 6
    return-object v0

    .line 7
    :cond_0
    invoke-virtual {p3}, Lcom/salesforce/marketingcloud/messages/iam/k;->l()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    .line 8
    .line 9
    .line 10
    move-result-object p3

    .line 11
    invoke-direct {p0, p3}, Lcom/salesforce/marketingcloud/messages/iam/c;->a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)I

    .line 12
    .line 13
    .line 14
    move-result p3

    .line 15
    const/4 v1, 0x0

    .line 16
    invoke-virtual {p1, p3, p2, v1}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;Z)Landroid/view/View;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->getActivity()Landroidx/fragment/app/o0;

    .line 21
    .line 22
    .line 23
    move-result-object p2

    .line 24
    instance-of p2, p2, Landroid/view/View$OnClickListener;

    .line 25
    .line 26
    if-eqz p2, :cond_1

    .line 27
    .line 28
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->getActivity()Landroidx/fragment/app/o0;

    .line 29
    .line 30
    .line 31
    move-result-object p2

    .line 32
    move-object v0, p2

    .line 33
    check-cast v0, Landroid/view/View$OnClickListener;

    .line 34
    .line 35
    :cond_1
    new-instance p2, Lcom/salesforce/marketingcloud/messages/iam/b;

    .line 36
    .line 37
    iget-object p3, p0, Lcom/salesforce/marketingcloud/messages/iam/c;->a:Lcom/salesforce/marketingcloud/messages/iam/k;

    .line 38
    .line 39
    invoke-virtual {p3}, Lcom/salesforce/marketingcloud/messages/iam/k;->s()Landroid/graphics/Typeface;

    .line 40
    .line 41
    .line 42
    move-result-object p3

    .line 43
    invoke-direct {p2, v0, p3}, Lcom/salesforce/marketingcloud/messages/iam/b;-><init>(Landroid/view/View$OnClickListener;Landroid/graphics/Typeface;)V

    .line 44
    .line 45
    .line 46
    iget-object p3, p0, Lcom/salesforce/marketingcloud/messages/iam/c;->a:Lcom/salesforce/marketingcloud/messages/iam/k;

    .line 47
    .line 48
    invoke-virtual {p2, p1, p3}, Lcom/salesforce/marketingcloud/messages/iam/d;->a(Landroid/view/View;Lcom/salesforce/marketingcloud/messages/iam/k;)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/messages/iam/b;->g()I

    .line 52
    .line 53
    .line 54
    move-result p2

    .line 55
    invoke-virtual {p1, p2}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 56
    .line 57
    .line 58
    move-result-object p2

    .line 59
    check-cast p2, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;

    .line 60
    .line 61
    if-eqz p2, :cond_2

    .line 62
    .line 63
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->getActivity()Landroidx/fragment/app/o0;

    .line 64
    .line 65
    .line 66
    move-result-object p3

    .line 67
    instance-of p3, p3, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$SwipeDismissListener;

    .line 68
    .line 69
    if-eqz p3, :cond_2

    .line 70
    .line 71
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->getActivity()Landroidx/fragment/app/o0;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    check-cast p0, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$SwipeDismissListener;

    .line 76
    .line 77
    invoke-virtual {p2, p0}, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;->setListener(Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$SwipeDismissListener;)V

    .line 78
    .line 79
    .line 80
    :cond_2
    return-object p1
.end method
