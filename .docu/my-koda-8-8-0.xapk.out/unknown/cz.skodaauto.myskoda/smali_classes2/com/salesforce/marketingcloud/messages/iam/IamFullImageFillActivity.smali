.class public final Lcom/salesforce/marketingcloud/messages/iam/IamFullImageFillActivity;
.super Lcom/salesforce/marketingcloud/messages/iam/IamFullscreenActivity;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ld6/s;


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/iam/IamFullscreenActivity;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private final h()V
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-virtual {p0, v0}, Landroid/app/Activity;->requestWindowFeature(I)Z

    .line 3
    .line 4
    .line 5
    invoke-virtual {p0}, Landroid/app/Activity;->getWindow()Landroid/view/Window;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    const/16 v2, 0x600

    .line 10
    .line 11
    invoke-virtual {v1, v2, v2}, Landroid/view/Window;->setFlags(II)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0}, Landroid/app/Activity;->getWindow()Landroid/view/Window;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    invoke-virtual {v1}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    const/16 v2, 0x1002

    .line 23
    .line 24
    invoke-virtual {v1, v2}, Landroid/view/View;->setSystemUiVisibility(I)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0}, Landroid/app/Activity;->getWindow()Landroid/view/Window;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    invoke-virtual {p0}, Landroid/view/Window;->getAttributes()Landroid/view/WindowManager$LayoutParams;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    iput v0, p0, Landroid/view/WindowManager$LayoutParams;->layoutInDisplayCutoutMode:I

    .line 36
    .line 37
    return-void
.end method


# virtual methods
.method public onApplyWindowInsets(Landroid/view/View;Ld6/w1;)Ld6/w1;
    .locals 4

    .line 1
    const-string v0, "v"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "insets"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p2, Ld6/w1;->a:Ld6/s1;

    .line 12
    .line 13
    invoke-virtual {p0}, Landroid/app/Activity;->isFinishing()Z

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    if-nez v1, :cond_2

    .line 18
    .line 19
    invoke-virtual {p2}, Ld6/w1;->e()Z

    .line 20
    .line 21
    .line 22
    move-result p2

    .line 23
    if-eqz p2, :cond_2

    .line 24
    .line 25
    invoke-virtual {v0}, Ld6/s1;->f()Ld6/i;

    .line 26
    .line 27
    .line 28
    move-result-object p2

    .line 29
    if-eqz p2, :cond_2

    .line 30
    .line 31
    iget-object p2, p2, Ld6/i;->a:Landroid/view/DisplayCutout;

    .line 32
    .line 33
    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    sget v2, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_iam_fif_content_padding_top:I

    .line 38
    .line 39
    invoke-virtual {v1, v2}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    invoke-virtual {p2}, Landroid/view/DisplayCutout;->getSafeInsetTop()I

    .line 44
    .line 45
    .line 46
    move-result v2

    .line 47
    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    sget v3, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_iam_fif_content_padding_bottom:I

    .line 52
    .line 53
    invoke-virtual {p0, v3}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    .line 54
    .line 55
    .line 56
    move-result p0

    .line 57
    invoke-virtual {p2}, Landroid/view/DisplayCutout;->getSafeInsetBottom()I

    .line 58
    .line 59
    .line 60
    move-result p2

    .line 61
    sget v3, Lcom/salesforce/marketingcloud/R$id;->mcsdk_iam_container:I

    .line 62
    .line 63
    invoke-virtual {p1, v3}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 64
    .line 65
    .line 66
    move-result-object p1

    .line 67
    if-lt v2, v1, :cond_0

    .line 68
    .line 69
    move v1, v2

    .line 70
    :cond_0
    if-lt p2, p0, :cond_1

    .line 71
    .line 72
    move p0, p2

    .line 73
    :cond_1
    const/4 p2, 0x0

    .line 74
    invoke-virtual {p1, p2, v1, p2, p0}, Landroid/view/View;->setPadding(IIII)V

    .line 75
    .line 76
    .line 77
    :cond_2
    invoke-virtual {v0}, Ld6/s1;->c()Ld6/w1;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    const-string p1, "consumeSystemWindowInsets(...)"

    .line 82
    .line 83
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    return-object p0
.end method

.method public onCreate(Landroid/os/Bundle;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/iam/IamFullImageFillActivity;->h()V

    .line 2
    .line 3
    .line 4
    invoke-super {p0, p1}, Lcom/salesforce/marketingcloud/messages/iam/IamFullscreenActivity;->onCreate(Landroid/os/Bundle;)V

    .line 5
    .line 6
    .line 7
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/IamFullscreenActivity;->g:Landroid/view/View;

    .line 8
    .line 9
    if-eqz p1, :cond_0

    .line 10
    .line 11
    sget-object v0, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 12
    .line 13
    invoke-static {p1, p0}, Ld6/k0;->j(Landroid/view/View;Ld6/s;)V

    .line 14
    .line 15
    .line 16
    :cond_0
    return-void
.end method
