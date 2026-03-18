.class public final Ly9/u;
.super Landroid/animation/AnimatorListenerAdapter;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ly9/w;


# direct methods
.method public synthetic constructor <init>(Ly9/w;I)V
    .locals 0

    .line 1
    iput p2, p0, Ly9/u;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Ly9/u;->b:Ly9/w;

    .line 4
    .line 5
    invoke-direct {p0}, Landroid/animation/AnimatorListenerAdapter;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public onAnimationEnd(Landroid/animation/Animator;)V
    .locals 1

    .line 1
    iget v0, p0, Ly9/u;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    :pswitch_0
    invoke-super {p0, p1}, Landroid/animation/AnimatorListenerAdapter;->onAnimationEnd(Landroid/animation/Animator;)V

    .line 7
    .line 8
    .line 9
    return-void

    .line 10
    :pswitch_1
    iget-object p0, p0, Ly9/u;->b:Ly9/w;

    .line 11
    .line 12
    iget-object p0, p0, Ly9/w;->h:Landroid/view/ViewGroup;

    .line 13
    .line 14
    if-eqz p0, :cond_0

    .line 15
    .line 16
    const/4 p1, 0x4

    .line 17
    invoke-virtual {p0, p1}, Landroid/view/View;->setVisibility(I)V

    .line 18
    .line 19
    .line 20
    :cond_0
    return-void

    .line 21
    :pswitch_2
    iget-object p0, p0, Ly9/u;->b:Ly9/w;

    .line 22
    .line 23
    iget-object p0, p0, Ly9/w;->f:Landroid/view/ViewGroup;

    .line 24
    .line 25
    if-eqz p0, :cond_1

    .line 26
    .line 27
    const/4 p1, 0x4

    .line 28
    invoke-virtual {p0, p1}, Landroid/view/View;->setVisibility(I)V

    .line 29
    .line 30
    .line 31
    :cond_1
    return-void

    .line 32
    :pswitch_3
    iget-object p0, p0, Ly9/u;->b:Ly9/w;

    .line 33
    .line 34
    const/4 p1, 0x0

    .line 35
    invoke-virtual {p0, p1}, Ly9/w;->i(I)V

    .line 36
    .line 37
    .line 38
    return-void

    .line 39
    :pswitch_4
    iget-object p0, p0, Ly9/u;->b:Ly9/w;

    .line 40
    .line 41
    const/4 p1, 0x0

    .line 42
    invoke-virtual {p0, p1}, Ly9/w;->i(I)V

    .line 43
    .line 44
    .line 45
    return-void

    .line 46
    :pswitch_5
    iget-object p0, p0, Ly9/u;->b:Ly9/w;

    .line 47
    .line 48
    iget-object p1, p0, Ly9/w;->b:Landroid/view/View;

    .line 49
    .line 50
    const/4 v0, 0x4

    .line 51
    if-eqz p1, :cond_2

    .line 52
    .line 53
    invoke-virtual {p1, v0}, Landroid/view/View;->setVisibility(I)V

    .line 54
    .line 55
    .line 56
    :cond_2
    iget-object p1, p0, Ly9/w;->c:Landroid/view/ViewGroup;

    .line 57
    .line 58
    if-eqz p1, :cond_3

    .line 59
    .line 60
    invoke-virtual {p1, v0}, Landroid/view/View;->setVisibility(I)V

    .line 61
    .line 62
    .line 63
    :cond_3
    iget-object p0, p0, Ly9/w;->e:Landroid/view/ViewGroup;

    .line 64
    .line 65
    if-eqz p0, :cond_4

    .line 66
    .line 67
    invoke-virtual {p0, v0}, Landroid/view/View;->setVisibility(I)V

    .line 68
    .line 69
    .line 70
    :cond_4
    return-void

    .line 71
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
    .end packed-switch
.end method

.method public final onAnimationStart(Landroid/animation/Animator;)V
    .locals 7

    .line 1
    iget p1, p0, Ly9/u;->a:I

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    const/4 v1, 0x2

    .line 5
    const-wide/16 v2, 0xfa

    .line 6
    .line 7
    const/4 v4, 0x4

    .line 8
    const/4 v5, 0x0

    .line 9
    iget-object p0, p0, Ly9/u;->b:Ly9/w;

    .line 10
    .line 11
    packed-switch p1, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    iget-object p0, p0, Ly9/w;->f:Landroid/view/ViewGroup;

    .line 15
    .line 16
    if-eqz p0, :cond_0

    .line 17
    .line 18
    invoke-virtual {p0, v5}, Landroid/view/View;->setVisibility(I)V

    .line 19
    .line 20
    .line 21
    :cond_0
    return-void

    .line 22
    :pswitch_0
    iget-object p1, p0, Ly9/w;->h:Landroid/view/ViewGroup;

    .line 23
    .line 24
    if-eqz p1, :cond_1

    .line 25
    .line 26
    invoke-virtual {p1, v5}, Landroid/view/View;->setVisibility(I)V

    .line 27
    .line 28
    .line 29
    iget-object p1, p0, Ly9/w;->h:Landroid/view/ViewGroup;

    .line 30
    .line 31
    invoke-virtual {p1}, Landroid/view/View;->getWidth()I

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    int-to-float v0, v0

    .line 36
    invoke-virtual {p1, v0}, Landroid/view/View;->setTranslationX(F)V

    .line 37
    .line 38
    .line 39
    iget-object p0, p0, Ly9/w;->h:Landroid/view/ViewGroup;

    .line 40
    .line 41
    invoke-virtual {p0}, Landroid/view/View;->getWidth()I

    .line 42
    .line 43
    .line 44
    move-result p1

    .line 45
    invoke-virtual {p0, p1, v5}, Landroid/view/View;->scrollTo(II)V

    .line 46
    .line 47
    .line 48
    :cond_1
    return-void

    .line 49
    :pswitch_1
    invoke-virtual {p0, v4}, Ly9/w;->i(I)V

    .line 50
    .line 51
    .line 52
    return-void

    .line 53
    :pswitch_2
    invoke-virtual {p0, v4}, Ly9/w;->i(I)V

    .line 54
    .line 55
    .line 56
    return-void

    .line 57
    :pswitch_3
    iget-object p1, p0, Ly9/w;->b:Landroid/view/View;

    .line 58
    .line 59
    if-eqz p1, :cond_2

    .line 60
    .line 61
    invoke-virtual {p1, v5}, Landroid/view/View;->setVisibility(I)V

    .line 62
    .line 63
    .line 64
    :cond_2
    iget-object p1, p0, Ly9/w;->c:Landroid/view/ViewGroup;

    .line 65
    .line 66
    if-eqz p1, :cond_3

    .line 67
    .line 68
    invoke-virtual {p1, v5}, Landroid/view/View;->setVisibility(I)V

    .line 69
    .line 70
    .line 71
    :cond_3
    iget-object p1, p0, Ly9/w;->e:Landroid/view/ViewGroup;

    .line 72
    .line 73
    if-eqz p1, :cond_5

    .line 74
    .line 75
    iget-boolean v6, p0, Ly9/w;->A:Z

    .line 76
    .line 77
    if-eqz v6, :cond_4

    .line 78
    .line 79
    move v4, v5

    .line 80
    :cond_4
    invoke-virtual {p1, v4}, Landroid/view/View;->setVisibility(I)V

    .line 81
    .line 82
    .line 83
    :cond_5
    iget-object p1, p0, Ly9/w;->j:Landroid/view/View;

    .line 84
    .line 85
    instance-of v4, p1, Ly9/d;

    .line 86
    .line 87
    if-eqz v4, :cond_7

    .line 88
    .line 89
    iget-boolean p0, p0, Ly9/w;->A:Z

    .line 90
    .line 91
    if-nez p0, :cond_7

    .line 92
    .line 93
    check-cast p1, Ly9/d;

    .line 94
    .line 95
    iget-object p0, p1, Ly9/d;->H:Landroid/animation/ValueAnimator;

    .line 96
    .line 97
    invoke-virtual {p0}, Landroid/animation/ValueAnimator;->isStarted()Z

    .line 98
    .line 99
    .line 100
    move-result v4

    .line 101
    if-eqz v4, :cond_6

    .line 102
    .line 103
    invoke-virtual {p0}, Landroid/animation/ValueAnimator;->cancel()V

    .line 104
    .line 105
    .line 106
    :cond_6
    iput-boolean v5, p1, Ly9/d;->J:Z

    .line 107
    .line 108
    iget p1, p1, Ly9/d;->I:F

    .line 109
    .line 110
    new-array v1, v1, [F

    .line 111
    .line 112
    aput p1, v1, v5

    .line 113
    .line 114
    const/high16 p1, 0x3f800000    # 1.0f

    .line 115
    .line 116
    aput p1, v1, v0

    .line 117
    .line 118
    invoke-virtual {p0, v1}, Landroid/animation/ValueAnimator;->setFloatValues([F)V

    .line 119
    .line 120
    .line 121
    invoke-virtual {p0, v2, v3}, Landroid/animation/ValueAnimator;->setDuration(J)Landroid/animation/ValueAnimator;

    .line 122
    .line 123
    .line 124
    invoke-virtual {p0}, Landroid/animation/ValueAnimator;->start()V

    .line 125
    .line 126
    .line 127
    :cond_7
    return-void

    .line 128
    :pswitch_4
    iget-object p1, p0, Ly9/w;->j:Landroid/view/View;

    .line 129
    .line 130
    instance-of v4, p1, Ly9/d;

    .line 131
    .line 132
    if-eqz v4, :cond_9

    .line 133
    .line 134
    iget-boolean p0, p0, Ly9/w;->A:Z

    .line 135
    .line 136
    if-nez p0, :cond_9

    .line 137
    .line 138
    check-cast p1, Ly9/d;

    .line 139
    .line 140
    iget-object p0, p1, Ly9/d;->H:Landroid/animation/ValueAnimator;

    .line 141
    .line 142
    invoke-virtual {p0}, Landroid/animation/ValueAnimator;->isStarted()Z

    .line 143
    .line 144
    .line 145
    move-result v4

    .line 146
    if-eqz v4, :cond_8

    .line 147
    .line 148
    invoke-virtual {p0}, Landroid/animation/ValueAnimator;->cancel()V

    .line 149
    .line 150
    .line 151
    :cond_8
    iget p1, p1, Ly9/d;->I:F

    .line 152
    .line 153
    new-array v1, v1, [F

    .line 154
    .line 155
    aput p1, v1, v5

    .line 156
    .line 157
    const/4 p1, 0x0

    .line 158
    aput p1, v1, v0

    .line 159
    .line 160
    invoke-virtual {p0, v1}, Landroid/animation/ValueAnimator;->setFloatValues([F)V

    .line 161
    .line 162
    .line 163
    invoke-virtual {p0, v2, v3}, Landroid/animation/ValueAnimator;->setDuration(J)Landroid/animation/ValueAnimator;

    .line 164
    .line 165
    .line 166
    invoke-virtual {p0}, Landroid/animation/ValueAnimator;->start()V

    .line 167
    .line 168
    .line 169
    :cond_9
    return-void

    .line 170
    nop

    .line 171
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
