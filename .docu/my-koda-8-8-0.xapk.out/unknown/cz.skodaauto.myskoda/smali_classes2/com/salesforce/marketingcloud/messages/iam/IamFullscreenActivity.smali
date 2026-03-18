.class public Lcom/salesforce/marketingcloud/messages/iam/IamFullscreenActivity;
.super Lcom/salesforce/marketingcloud/messages/iam/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field protected g:Landroid/view/View;

.field private h:Lcom/salesforce/marketingcloud/messages/iam/k;

.field private i:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;


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

.method private a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)I
    .locals 4

    .line 1
    sget p0, Lcom/salesforce/marketingcloud/R$layout;->mcsdk_iam_full_inset_itb:I

    .line 2
    .line 3
    sget-object v0, Lcom/salesforce/marketingcloud/messages/iam/IamFullscreenActivity$a;->b:[I

    .line 4
    .line 5
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->type()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    aget v0, v0, v1

    .line 14
    .line 15
    const/4 v1, 0x2

    .line 16
    const/4 v2, 0x1

    .line 17
    if-eq v0, v2, :cond_2

    .line 18
    .line 19
    if-eq v0, v1, :cond_0

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->media()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    if-eqz p0, :cond_1

    .line 27
    .line 28
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->media()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;->size()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media$ImageSize;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    sget-object p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media$ImageSize;->e2e:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media$ImageSize;

    .line 37
    .line 38
    if-ne p0, p1, :cond_1

    .line 39
    .line 40
    sget p0, Lcom/salesforce/marketingcloud/R$layout;->mcsdk_iam_fif_e2e_itb:I

    .line 41
    .line 42
    return p0

    .line 43
    :cond_1
    sget p0, Lcom/salesforce/marketingcloud/R$layout;->mcsdk_iam_fif_inset_itb:I

    .line 44
    .line 45
    return p0

    .line 46
    :cond_2
    sget-object v0, Lcom/salesforce/marketingcloud/messages/iam/IamFullscreenActivity$a;->a:[I

    .line 47
    .line 48
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->layoutOrder()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;

    .line 49
    .line 50
    .line 51
    move-result-object v3

    .line 52
    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    .line 53
    .line 54
    .line 55
    move-result v3

    .line 56
    aget v0, v0, v3

    .line 57
    .line 58
    if-eq v0, v2, :cond_5

    .line 59
    .line 60
    if-eq v0, v1, :cond_3

    .line 61
    .line 62
    :goto_0
    return p0

    .line 63
    :cond_3
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->media()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    if-eqz p0, :cond_4

    .line 68
    .line 69
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->media()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;->size()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media$ImageSize;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    sget-object p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media$ImageSize;->e2e:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media$ImageSize;

    .line 78
    .line 79
    if-ne p0, p1, :cond_4

    .line 80
    .line 81
    sget p0, Lcom/salesforce/marketingcloud/R$layout;->mcsdk_iam_full_e2e_tib:I

    .line 82
    .line 83
    return p0

    .line 84
    :cond_4
    sget p0, Lcom/salesforce/marketingcloud/R$layout;->mcsdk_iam_full_inset_tib:I

    .line 85
    .line 86
    return p0

    .line 87
    :cond_5
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->media()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    if-eqz p0, :cond_6

    .line 92
    .line 93
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->media()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;->size()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media$ImageSize;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    sget-object p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media$ImageSize;->e2e:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media$ImageSize;

    .line 102
    .line 103
    if-ne p0, p1, :cond_6

    .line 104
    .line 105
    sget p0, Lcom/salesforce/marketingcloud/R$layout;->mcsdk_iam_full_e2e_itb:I

    .line 106
    .line 107
    return p0

    .line 108
    :cond_6
    sget p0, Lcom/salesforce/marketingcloud/R$layout;->mcsdk_iam_full_inset_itb:I

    .line 109
    .line 110
    return p0
.end method


# virtual methods
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

.method public onConfigurationChanged(Landroid/content/res/Configuration;)V
    .locals 3

    .line 1
    invoke-super {p0, p1}, Lb/r;->onConfigurationChanged(Landroid/content/res/Configuration;)V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/IamFullscreenActivity;->i:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->type()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    sget-object v1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;->fullImageFill:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;

    .line 13
    .line 14
    if-ne v0, v1, :cond_0

    .line 15
    .line 16
    iget p1, p1, Landroid/content/res/Configuration;->orientation:I

    .line 17
    .line 18
    const/4 v0, 0x2

    .line 19
    if-ne p1, v0, :cond_0

    .line 20
    .line 21
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/IamFullscreenActivity;->h:Lcom/salesforce/marketingcloud/messages/iam/k;

    .line 22
    .line 23
    if-eqz p1, :cond_0

    .line 24
    .line 25
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/iam/k;->k()Ljava/util/Date;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/IamFullscreenActivity;->h:Lcom/salesforce/marketingcloud/messages/iam/k;

    .line 30
    .line 31
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/messages/iam/k;->j()J

    .line 32
    .line 33
    .line 34
    move-result-wide v1

    .line 35
    invoke-static {v0, v1, v2}, Lcom/salesforce/marketingcloud/messages/iam/j;->a(Ljava/util/Date;J)Lcom/salesforce/marketingcloud/messages/iam/j;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    invoke-virtual {p1, v0}, Lcom/salesforce/marketingcloud/messages/iam/k;->a(Lcom/salesforce/marketingcloud/messages/iam/j;)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/IamFullscreenActivity;->finish()V

    .line 43
    .line 44
    .line 45
    :cond_0
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
    const p1, 0x1020002

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0, p1}, Landroid/app/Activity;->findViewById(I)Landroid/view/View;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/IamFullscreenActivity;->g:Landroid/view/View;

    .line 19
    .line 20
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->c()Lcom/salesforce/marketingcloud/messages/iam/k;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/IamFullscreenActivity;->h:Lcom/salesforce/marketingcloud/messages/iam/k;

    .line 25
    .line 26
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/iam/k;->l()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/IamFullscreenActivity;->i:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    .line 31
    .line 32
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/messages/iam/IamFullscreenActivity;->a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)I

    .line 33
    .line 34
    .line 35
    move-result p1

    .line 36
    invoke-virtual {p0, p1}, Lb/r;->setContentView(I)V

    .line 37
    .line 38
    .line 39
    new-instance p1, Lcom/salesforce/marketingcloud/messages/iam/e;

    .line 40
    .line 41
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/IamFullscreenActivity;->h:Lcom/salesforce/marketingcloud/messages/iam/k;

    .line 42
    .line 43
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/iam/k;->s()Landroid/graphics/Typeface;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    invoke-direct {p1, p0, v0}, Lcom/salesforce/marketingcloud/messages/iam/e;-><init>(Landroid/view/View$OnClickListener;Landroid/graphics/Typeface;)V

    .line 48
    .line 49
    .line 50
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/IamFullscreenActivity;->g:Landroid/view/View;

    .line 51
    .line 52
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/IamFullscreenActivity;->h:Lcom/salesforce/marketingcloud/messages/iam/k;

    .line 53
    .line 54
    invoke-virtual {p1, v0, p0}, Lcom/salesforce/marketingcloud/messages/iam/d;->a(Landroid/view/View;Lcom/salesforce/marketingcloud/messages/iam/k;)V

    .line 55
    .line 56
    .line 57
    return-void
.end method

.method public onDestroy()V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/IamFullscreenActivity;->g:Landroid/view/View;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    sget-object v1, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    invoke-static {v0, v1}, Ld6/k0;->j(Landroid/view/View;Ld6/s;)V

    .line 9
    .line 10
    .line 11
    :cond_0
    invoke-super {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->onDestroy()V

    .line 12
    .line 13
    .line 14
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
