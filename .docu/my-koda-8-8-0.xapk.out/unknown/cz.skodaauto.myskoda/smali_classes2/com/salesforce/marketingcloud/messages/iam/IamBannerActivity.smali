.class public Lcom/salesforce/marketingcloud/messages/iam/IamBannerActivity;
.super Lcom/salesforce/marketingcloud/messages/iam/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final j:Ljava/lang/String;


# instance fields
.field private g:Lcom/salesforce/marketingcloud/messages/iam/a;

.field private h:Z

.field private i:J


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "IamBaseActivity"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/messages/iam/IamBannerActivity;->j:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)I
    .locals 0

    .line 4
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->type()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;

    move-result-object p0

    sget-object p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;->bannerTop:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;

    if-ne p0, p1, :cond_0

    .line 5
    sget p0, Lcom/salesforce/marketingcloud/R$anim;->mcsdk_iam_slide_in_from_top:I

    return p0

    .line 6
    :cond_0
    sget p0, Lcom/salesforce/marketingcloud/R$anim;->mcsdk_iam_slide_in_from_bottom:I

    return p0
.end method

.method private a(JJ)V
    .locals 9

    const-wide/16 v0, 0x0

    cmp-long v0, p1, v0

    if-lez v0, :cond_0

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/messages/iam/IamBannerActivity;->j:Ljava/lang/String;

    sub-long v1, p1, p3

    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v1

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    const-string v2, "Banner dismiss timer set.  Will auto dismiss in %dms"

    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 2
    new-instance v3, Lcom/salesforce/marketingcloud/messages/iam/IamBannerActivity$a;

    move-object v4, p0

    move-wide v5, p1

    move-wide v7, p3

    invoke-direct/range {v3 .. v8}, Lcom/salesforce/marketingcloud/messages/iam/IamBannerActivity$a;-><init>(Lcom/salesforce/marketingcloud/messages/iam/IamBannerActivity;JJ)V

    iput-object v3, v4, Lcom/salesforce/marketingcloud/messages/iam/IamBannerActivity;->g:Lcom/salesforce/marketingcloud/messages/iam/a;

    .line 3
    invoke-virtual {v3}, Landroid/os/CountDownTimer;->start()Landroid/os/CountDownTimer;

    :cond_0
    return-void
.end method

.method private b(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)I
    .locals 0

    .line 2
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->type()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;

    move-result-object p0

    sget-object p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;->bannerTop:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;

    if-ne p0, p1, :cond_0

    .line 3
    sget p0, Lcom/salesforce/marketingcloud/R$anim;->mcsdk_iam_slide_out_from_top:I

    return p0

    .line 4
    :cond_0
    sget p0, Lcom/salesforce/marketingcloud/R$anim;->mcsdk_iam_slide_out_from_bottom:I

    return p0
.end method


# virtual methods
.method public bridge synthetic b(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;)V
    .locals 0

    .line 1
    invoke-super {p0, p1}, Lcom/salesforce/marketingcloud/messages/iam/f;->b(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;)V

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

.method public h()V
    .locals 4

    .line 1
    invoke-virtual {p0}, Landroidx/fragment/app/o0;->getSupportFragmentManager()Landroidx/fragment/app/j1;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const v1, 0x1020002

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, v1}, Landroidx/fragment/app/j1;->C(I)Landroidx/fragment/app/j0;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    if-eqz v1, :cond_0

    .line 13
    .line 14
    new-instance v2, Landroidx/fragment/app/a;

    .line 15
    .line 16
    invoke-direct {v2, v0}, Landroidx/fragment/app/a;-><init>(Landroidx/fragment/app/j1;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->c()Lcom/salesforce/marketingcloud/messages/iam/k;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/iam/k;->l()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    invoke-direct {p0, v0}, Lcom/salesforce/marketingcloud/messages/iam/IamBannerActivity;->b(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)I

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    const/4 v3, 0x0

    .line 32
    iput v3, v2, Landroidx/fragment/app/a;->b:I

    .line 33
    .line 34
    iput v0, v2, Landroidx/fragment/app/a;->c:I

    .line 35
    .line 36
    iput v3, v2, Landroidx/fragment/app/a;->d:I

    .line 37
    .line 38
    iput v3, v2, Landroidx/fragment/app/a;->e:I

    .line 39
    .line 40
    invoke-virtual {v2, v1}, Landroidx/fragment/app/a;->h(Landroidx/fragment/app/j0;)V

    .line 41
    .line 42
    .line 43
    const/4 v0, 0x1

    .line 44
    invoke-virtual {v2, v0, v0}, Landroidx/fragment/app/a;->e(ZZ)I

    .line 45
    .line 46
    .line 47
    :cond_0
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->c()Lcom/salesforce/marketingcloud/messages/iam/k;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/iam/k;->k()Ljava/util/Date;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->a()J

    .line 56
    .line 57
    .line 58
    move-result-wide v1

    .line 59
    invoke-static {v0, v1, v2}, Lcom/salesforce/marketingcloud/messages/iam/j;->a(Ljava/util/Date;J)Lcom/salesforce/marketingcloud/messages/iam/j;

    .line 60
    .line 61
    .line 62
    move-result-object v0

    .line 63
    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/messages/iam/f;->a(Lcom/salesforce/marketingcloud/messages/iam/j;)V

    .line 64
    .line 65
    .line 66
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
    .locals 6

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
    goto :goto_0

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
    move-result-object v0

    .line 19
    const v1, 0x1020002

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0, v1}, Landroid/app/Activity;->findViewById(I)Landroid/view/View;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    new-instance v3, Landroid/graphics/drawable/ColorDrawable;

    .line 27
    .line 28
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->windowColor()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v4

    .line 32
    sget v5, Lcom/salesforce/marketingcloud/R$color;->mcsdk_iam_default_window_background:I

    .line 33
    .line 34
    invoke-static {p0, v4, v5}, Lcom/salesforce/marketingcloud/messages/iam/g;->a(Landroid/content/Context;Ljava/lang/String;I)I

    .line 35
    .line 36
    .line 37
    move-result v4

    .line 38
    invoke-direct {v3, v4}, Landroid/graphics/drawable/ColorDrawable;-><init>(I)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {v2, v3}, Landroid/view/View;->setBackgroundDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {p0}, Landroidx/fragment/app/o0;->getSupportFragmentManager()Landroidx/fragment/app/j1;

    .line 45
    .line 46
    .line 47
    move-result-object v2

    .line 48
    invoke-virtual {v2, v1}, Landroidx/fragment/app/j1;->C(I)Landroidx/fragment/app/j0;

    .line 49
    .line 50
    .line 51
    move-result-object v3

    .line 52
    if-nez v3, :cond_1

    .line 53
    .line 54
    const/4 v3, 0x1

    .line 55
    iput-boolean v3, p0, Lcom/salesforce/marketingcloud/messages/iam/IamBannerActivity;->h:Z

    .line 56
    .line 57
    new-instance v4, Landroidx/fragment/app/a;

    .line 58
    .line 59
    invoke-direct {v4, v2}, Landroidx/fragment/app/a;-><init>(Landroidx/fragment/app/j1;)V

    .line 60
    .line 61
    .line 62
    invoke-direct {p0, v0}, Lcom/salesforce/marketingcloud/messages/iam/IamBannerActivity;->a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)I

    .line 63
    .line 64
    .line 65
    move-result p0

    .line 66
    iput p0, v4, Landroidx/fragment/app/a;->b:I

    .line 67
    .line 68
    const/4 p0, 0x0

    .line 69
    iput p0, v4, Landroidx/fragment/app/a;->c:I

    .line 70
    .line 71
    iput p0, v4, Landroidx/fragment/app/a;->d:I

    .line 72
    .line 73
    iput p0, v4, Landroidx/fragment/app/a;->e:I

    .line 74
    .line 75
    invoke-static {p1}, Lcom/salesforce/marketingcloud/messages/iam/c;->a(Lcom/salesforce/marketingcloud/messages/iam/k;)Lcom/salesforce/marketingcloud/messages/iam/c;

    .line 76
    .line 77
    .line 78
    move-result-object p1

    .line 79
    const/4 v0, 0x0

    .line 80
    invoke-virtual {v4, v1, p1, v0, v3}, Landroidx/fragment/app/a;->f(ILandroidx/fragment/app/j0;Ljava/lang/String;I)V

    .line 81
    .line 82
    .line 83
    invoke-virtual {v4, p0, v3}, Landroidx/fragment/app/a;->e(ZZ)I

    .line 84
    .line 85
    .line 86
    :cond_1
    :goto_0
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

.method public onPause()V
    .locals 1

    .line 1
    invoke-super {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->onPause()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/IamBannerActivity;->g:Lcom/salesforce/marketingcloud/messages/iam/a;

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    invoke-virtual {v0}, Landroid/os/CountDownTimer;->cancel()V

    .line 9
    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/IamBannerActivity;->g:Lcom/salesforce/marketingcloud/messages/iam/a;

    .line 13
    .line 14
    :cond_0
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

.method public onResume()V
    .locals 6

    .line 1
    invoke-super {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->onResume()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->b()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->displayDuration()J

    .line 9
    .line 10
    .line 11
    move-result-wide v0

    .line 12
    iget-boolean v2, p0, Lcom/salesforce/marketingcloud/messages/iam/IamBannerActivity;->h:Z

    .line 13
    .line 14
    if-eqz v2, :cond_0

    .line 15
    .line 16
    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    sget v3, Lcom/salesforce/marketingcloud/R$integer;->mcsdk_iam_banner_animation_duration:I

    .line 21
    .line 22
    invoke-virtual {v2, v3}, Landroid/content/res/Resources;->getInteger(I)I

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    int-to-double v2, v2

    .line 27
    const-wide/high16 v4, -0x4010000000000000L    # -1.0

    .line 28
    .line 29
    mul-double/2addr v2, v4

    .line 30
    double-to-long v2, v2

    .line 31
    goto :goto_0

    .line 32
    :cond_0
    const-wide/16 v2, 0x0

    .line 33
    .line 34
    :goto_0
    const/4 v4, 0x0

    .line 35
    iput-boolean v4, p0, Lcom/salesforce/marketingcloud/messages/iam/IamBannerActivity;->h:Z

    .line 36
    .line 37
    invoke-direct {p0, v0, v1, v2, v3}, Lcom/salesforce/marketingcloud/messages/iam/IamBannerActivity;->a(JJ)V

    .line 38
    .line 39
    .line 40
    return-void
.end method

.method public onSwipeStarted()V
    .locals 2

    .line 1
    invoke-super {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->onSwipeStarted()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/IamBannerActivity;->g:Lcom/salesforce/marketingcloud/messages/iam/a;

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    invoke-virtual {v0}, Landroid/os/CountDownTimer;->cancel()V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/IamBannerActivity;->g:Lcom/salesforce/marketingcloud/messages/iam/a;

    .line 12
    .line 13
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/iam/a;->a()J

    .line 14
    .line 15
    .line 16
    move-result-wide v0

    .line 17
    iput-wide v0, p0, Lcom/salesforce/marketingcloud/messages/iam/IamBannerActivity;->i:J

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/IamBannerActivity;->g:Lcom/salesforce/marketingcloud/messages/iam/a;

    .line 21
    .line 22
    :cond_0
    return-void
.end method

.method public onViewSettled()V
    .locals 4

    .line 1
    invoke-super {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->onViewSettled()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->b()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->displayDuration()J

    .line 9
    .line 10
    .line 11
    move-result-wide v0

    .line 12
    iget-wide v2, p0, Lcom/salesforce/marketingcloud/messages/iam/IamBannerActivity;->i:J

    .line 13
    .line 14
    invoke-direct {p0, v0, v1, v2, v3}, Lcom/salesforce/marketingcloud/messages/iam/IamBannerActivity;->a(JJ)V

    .line 15
    .line 16
    .line 17
    return-void
.end method
