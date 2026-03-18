.class public Lq/z;
.super Landroidx/fragment/app/x;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final t:Landroid/os/Handler;

.field public final u:Laq/p;

.field public v:Lq/s;

.field public w:I

.field public x:I

.field public y:Landroid/widget/ImageView;

.field public z:Landroid/widget/TextView;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Landroidx/fragment/app/x;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Landroid/os/Handler;

    .line 5
    .line 6
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    invoke-direct {v0, v1}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 11
    .line 12
    .line 13
    iput-object v0, p0, Lq/z;->t:Landroid/os/Handler;

    .line 14
    .line 15
    new-instance v0, Laq/p;

    .line 16
    .line 17
    const/16 v1, 0x16

    .line 18
    .line 19
    invoke-direct {v0, p0, v1}, Laq/p;-><init>(Ljava/lang/Object;I)V

    .line 20
    .line 21
    .line 22
    iput-object v0, p0, Lq/z;->u:Laq/p;

    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public final j()Landroid/app/Dialog;
    .locals 8

    .line 1
    new-instance v0, Lh/e;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->requireContext()Landroid/content/Context;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-direct {v0, v1}, Lh/e;-><init>(Landroid/content/Context;)V

    .line 8
    .line 9
    .line 10
    iget-object v1, p0, Lq/z;->v:Lq/s;

    .line 11
    .line 12
    iget-object v1, v1, Lq/s;->f:Lil/g;

    .line 13
    .line 14
    const/4 v2, 0x0

    .line 15
    if-eqz v1, :cond_0

    .line 16
    .line 17
    iget-object v1, v1, Lil/g;->e:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v1, Ljava/lang/CharSequence;

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    move-object v1, v2

    .line 23
    :goto_0
    invoke-virtual {v0, v1}, Lh/e;->setTitle(Ljava/lang/CharSequence;)Lh/e;

    .line 24
    .line 25
    .line 26
    invoke-virtual {v0}, Lh/e;->getContext()Landroid/content/Context;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    invoke-static {v1}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    const v3, 0x7f0d015e

    .line 35
    .line 36
    .line 37
    invoke-virtual {v1, v3, v2}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;)Landroid/view/View;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    const v3, 0x7f0a016c

    .line 42
    .line 43
    .line 44
    invoke-virtual {v1, v3}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 45
    .line 46
    .line 47
    move-result-object v3

    .line 48
    check-cast v3, Landroid/widget/TextView;

    .line 49
    .line 50
    const/16 v4, 0x8

    .line 51
    .line 52
    const/4 v5, 0x0

    .line 53
    if-eqz v3, :cond_2

    .line 54
    .line 55
    iget-object v6, p0, Lq/z;->v:Lq/s;

    .line 56
    .line 57
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 58
    .line 59
    .line 60
    invoke-static {v2}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 61
    .line 62
    .line 63
    move-result v6

    .line 64
    if-eqz v6, :cond_1

    .line 65
    .line 66
    invoke-virtual {v3, v4}, Landroid/view/View;->setVisibility(I)V

    .line 67
    .line 68
    .line 69
    goto :goto_1

    .line 70
    :cond_1
    invoke-virtual {v3, v5}, Landroid/view/View;->setVisibility(I)V

    .line 71
    .line 72
    .line 73
    invoke-virtual {v3, v2}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 74
    .line 75
    .line 76
    :cond_2
    :goto_1
    const v3, 0x7f0a0169

    .line 77
    .line 78
    .line 79
    invoke-virtual {v1, v3}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 80
    .line 81
    .line 82
    move-result-object v3

    .line 83
    check-cast v3, Landroid/widget/TextView;

    .line 84
    .line 85
    if-eqz v3, :cond_5

    .line 86
    .line 87
    iget-object v6, p0, Lq/z;->v:Lq/s;

    .line 88
    .line 89
    iget-object v6, v6, Lq/s;->f:Lil/g;

    .line 90
    .line 91
    if-eqz v6, :cond_3

    .line 92
    .line 93
    iget-object v6, v6, Lil/g;->f:Ljava/lang/Object;

    .line 94
    .line 95
    check-cast v6, Ljava/lang/CharSequence;

    .line 96
    .line 97
    goto :goto_2

    .line 98
    :cond_3
    move-object v6, v2

    .line 99
    :goto_2
    invoke-static {v6}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 100
    .line 101
    .line 102
    move-result v7

    .line 103
    if-eqz v7, :cond_4

    .line 104
    .line 105
    invoke-virtual {v3, v4}, Landroid/view/View;->setVisibility(I)V

    .line 106
    .line 107
    .line 108
    goto :goto_3

    .line 109
    :cond_4
    invoke-virtual {v3, v5}, Landroid/view/View;->setVisibility(I)V

    .line 110
    .line 111
    .line 112
    invoke-virtual {v3, v6}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 113
    .line 114
    .line 115
    :cond_5
    :goto_3
    const v3, 0x7f0a016b

    .line 116
    .line 117
    .line 118
    invoke-virtual {v1, v3}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 119
    .line 120
    .line 121
    move-result-object v3

    .line 122
    check-cast v3, Landroid/widget/ImageView;

    .line 123
    .line 124
    iput-object v3, p0, Lq/z;->y:Landroid/widget/ImageView;

    .line 125
    .line 126
    const v3, 0x7f0a016a

    .line 127
    .line 128
    .line 129
    invoke-virtual {v1, v3}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 130
    .line 131
    .line 132
    move-result-object v3

    .line 133
    check-cast v3, Landroid/widget/TextView;

    .line 134
    .line 135
    iput-object v3, p0, Lq/z;->z:Landroid/widget/TextView;

    .line 136
    .line 137
    iget-object v3, p0, Lq/z;->v:Lq/s;

    .line 138
    .line 139
    iget-object v4, v3, Lq/s;->f:Lil/g;

    .line 140
    .line 141
    if-eqz v4, :cond_7

    .line 142
    .line 143
    iget-object v3, v3, Lq/s;->g:Lcom/google/firebase/messaging/w;

    .line 144
    .line 145
    if-eqz v3, :cond_6

    .line 146
    .line 147
    const/16 v3, 0xf

    .line 148
    .line 149
    goto :goto_4

    .line 150
    :cond_6
    const/16 v3, 0xff

    .line 151
    .line 152
    goto :goto_4

    .line 153
    :cond_7
    move v3, v5

    .line 154
    :goto_4
    invoke-static {v3}, Ljp/ge;->a(I)Z

    .line 155
    .line 156
    .line 157
    move-result v3

    .line 158
    if-eqz v3, :cond_8

    .line 159
    .line 160
    const v2, 0x7f120168

    .line 161
    .line 162
    .line 163
    invoke-virtual {p0, v2}, Landroidx/fragment/app/j0;->getString(I)Ljava/lang/String;

    .line 164
    .line 165
    .line 166
    move-result-object v2

    .line 167
    goto :goto_5

    .line 168
    :cond_8
    iget-object v3, p0, Lq/z;->v:Lq/s;

    .line 169
    .line 170
    iget-object v3, v3, Lq/s;->f:Lil/g;

    .line 171
    .line 172
    if-eqz v3, :cond_a

    .line 173
    .line 174
    iget-object v2, v3, Lil/g;->g:Ljava/lang/Object;

    .line 175
    .line 176
    check-cast v2, Ljava/lang/CharSequence;

    .line 177
    .line 178
    if-eqz v2, :cond_9

    .line 179
    .line 180
    goto :goto_5

    .line 181
    :cond_9
    const-string v2, ""

    .line 182
    .line 183
    :cond_a
    :goto_5
    new-instance v3, Lq/r;

    .line 184
    .line 185
    invoke-direct {v3, p0}, Lq/r;-><init>(Lq/z;)V

    .line 186
    .line 187
    .line 188
    iget-object p0, v0, Lh/e;->a:Lh/b;

    .line 189
    .line 190
    iput-object v2, p0, Lh/b;->h:Ljava/lang/CharSequence;

    .line 191
    .line 192
    iput-object v3, p0, Lh/b;->i:Landroid/content/DialogInterface$OnClickListener;

    .line 193
    .line 194
    invoke-virtual {v0, v1}, Lh/e;->setView(Landroid/view/View;)Lh/e;

    .line 195
    .line 196
    .line 197
    invoke-virtual {v0}, Lh/e;->create()Lh/f;

    .line 198
    .line 199
    .line 200
    move-result-object p0

    .line 201
    invoke-virtual {p0, v5}, Landroid/app/Dialog;->setCanceledOnTouchOutside(Z)V

    .line 202
    .line 203
    .line 204
    return-object p0
.end method

.method public final l(I)I
    .locals 4

    .line 1
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->getContext()Landroid/content/Context;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->getActivity()Landroidx/fragment/app/o0;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    const/4 v1, 0x0

    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    if-nez p0, :cond_0

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    new-instance v2, Landroid/util/TypedValue;

    .line 16
    .line 17
    invoke-direct {v2}, Landroid/util/TypedValue;-><init>()V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    const/4 v3, 0x1

    .line 25
    invoke-virtual {v0, p1, v2, v3}, Landroid/content/res/Resources$Theme;->resolveAttribute(ILandroid/util/TypedValue;Z)Z

    .line 26
    .line 27
    .line 28
    iget v0, v2, Landroid/util/TypedValue;->data:I

    .line 29
    .line 30
    filled-new-array {p1}, [I

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    invoke-virtual {p0, v0, p1}, Landroid/content/Context;->obtainStyledAttributes(I[I)Landroid/content/res/TypedArray;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    invoke-virtual {p0, v1, v1}, Landroid/content/res/TypedArray;->getColor(II)I

    .line 39
    .line 40
    .line 41
    move-result p1

    .line 42
    invoke-virtual {p0}, Landroid/content/res/TypedArray;->recycle()V

    .line 43
    .line 44
    .line 45
    return p1

    .line 46
    :cond_1
    :goto_0
    const-string p0, "FingerprintFragment"

    .line 47
    .line 48
    const-string p1, "Unable to get themed color. Context or activity is null."

    .line 49
    .line 50
    invoke-static {p0, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 51
    .line 52
    .line 53
    return v1
.end method

.method public final onCancel(Landroid/content/DialogInterface;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lq/z;->v:Lq/s;

    .line 2
    .line 3
    iget-object p1, p0, Lq/s;->u:Landroidx/lifecycle/i0;

    .line 4
    .line 5
    if-nez p1, :cond_0

    .line 6
    .line 7
    new-instance p1, Landroidx/lifecycle/i0;

    .line 8
    .line 9
    invoke-direct {p1}, Landroidx/lifecycle/g0;-><init>()V

    .line 10
    .line 11
    .line 12
    iput-object p1, p0, Lq/s;->u:Landroidx/lifecycle/i0;

    .line 13
    .line 14
    :cond_0
    iget-object p0, p0, Lq/s;->u:Landroidx/lifecycle/i0;

    .line 15
    .line 16
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 17
    .line 18
    invoke-static {p0, p1}, Lq/s;->g(Landroidx/lifecycle/i0;Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method public final onCreate(Landroid/os/Bundle;)V
    .locals 3

    .line 1
    invoke-super {p0, p1}, Landroidx/fragment/app/x;->onCreate(Landroid/os/Bundle;)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->getActivity()Landroidx/fragment/app/o0;

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    if-nez p1, :cond_0

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    invoke-interface {p1}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    invoke-interface {p1}, Landroidx/lifecycle/k;->getDefaultViewModelProviderFactory()Landroidx/lifecycle/e1;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    invoke-interface {p1}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    const-string v2, "store"

    .line 24
    .line 25
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    const-string v2, "factory"

    .line 29
    .line 30
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    const-string v2, "defaultCreationExtras"

    .line 34
    .line 35
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    new-instance v2, Lcom/google/firebase/messaging/w;

    .line 39
    .line 40
    invoke-direct {v2, v0, v1, p1}, Lcom/google/firebase/messaging/w;-><init>(Landroidx/lifecycle/h1;Landroidx/lifecycle/e1;Lp7/c;)V

    .line 41
    .line 42
    .line 43
    const-class p1, Lq/s;

    .line 44
    .line 45
    invoke-static {p1}, Ljp/p1;->f(Ljava/lang/Class;)Lhy0/d;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    const-string v0, "modelClass"

    .line 50
    .line 51
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    invoke-interface {p1}, Lhy0/d;->getQualifiedName()Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    if-eqz v0, :cond_3

    .line 59
    .line 60
    const-string v1, "androidx.lifecycle.ViewModelProvider.DefaultKey:"

    .line 61
    .line 62
    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    invoke-virtual {v2, p1, v0}, Lcom/google/firebase/messaging/w;->l(Lhy0/d;Ljava/lang/String;)Landroidx/lifecycle/b1;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    check-cast p1, Lq/s;

    .line 71
    .line 72
    iput-object p1, p0, Lq/z;->v:Lq/s;

    .line 73
    .line 74
    iget-object v0, p1, Lq/s;->w:Landroidx/lifecycle/i0;

    .line 75
    .line 76
    if-nez v0, :cond_1

    .line 77
    .line 78
    new-instance v0, Landroidx/lifecycle/i0;

    .line 79
    .line 80
    invoke-direct {v0}, Landroidx/lifecycle/g0;-><init>()V

    .line 81
    .line 82
    .line 83
    iput-object v0, p1, Lq/s;->w:Landroidx/lifecycle/i0;

    .line 84
    .line 85
    :cond_1
    iget-object p1, p1, Lq/s;->w:Landroidx/lifecycle/i0;

    .line 86
    .line 87
    new-instance v0, Lq/w;

    .line 88
    .line 89
    const/4 v1, 0x0

    .line 90
    invoke-direct {v0, p0, v1}, Lq/w;-><init>(Lq/z;I)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {p1, p0, v0}, Landroidx/lifecycle/g0;->e(Landroidx/fragment/app/j0;Landroidx/lifecycle/j0;)V

    .line 94
    .line 95
    .line 96
    iget-object p1, p0, Lq/z;->v:Lq/s;

    .line 97
    .line 98
    iget-object v0, p1, Lq/s;->x:Landroidx/lifecycle/i0;

    .line 99
    .line 100
    if-nez v0, :cond_2

    .line 101
    .line 102
    new-instance v0, Landroidx/lifecycle/i0;

    .line 103
    .line 104
    invoke-direct {v0}, Landroidx/lifecycle/g0;-><init>()V

    .line 105
    .line 106
    .line 107
    iput-object v0, p1, Lq/s;->x:Landroidx/lifecycle/i0;

    .line 108
    .line 109
    :cond_2
    iget-object p1, p1, Lq/s;->x:Landroidx/lifecycle/i0;

    .line 110
    .line 111
    new-instance v0, Lq/w;

    .line 112
    .line 113
    const/4 v1, 0x1

    .line 114
    invoke-direct {v0, p0, v1}, Lq/w;-><init>(Lq/z;I)V

    .line 115
    .line 116
    .line 117
    invoke-virtual {p1, p0, v0}, Landroidx/lifecycle/g0;->e(Landroidx/fragment/app/j0;Landroidx/lifecycle/j0;)V

    .line 118
    .line 119
    .line 120
    :goto_0
    invoke-static {}, Lq/y;->a()I

    .line 121
    .line 122
    .line 123
    move-result p1

    .line 124
    invoke-virtual {p0, p1}, Lq/z;->l(I)I

    .line 125
    .line 126
    .line 127
    move-result p1

    .line 128
    iput p1, p0, Lq/z;->w:I

    .line 129
    .line 130
    const p1, 0x1010038

    .line 131
    .line 132
    .line 133
    invoke-virtual {p0, p1}, Lq/z;->l(I)I

    .line 134
    .line 135
    .line 136
    move-result p1

    .line 137
    iput p1, p0, Lq/z;->x:I

    .line 138
    .line 139
    return-void

    .line 140
    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 141
    .line 142
    const-string p1, "Local and anonymous classes can not be ViewModels"

    .line 143
    .line 144
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 145
    .line 146
    .line 147
    throw p0
.end method

.method public final onPause()V
    .locals 1

    .line 1
    invoke-super {p0}, Landroidx/fragment/app/j0;->onPause()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lq/z;->t:Landroid/os/Handler;

    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    invoke-virtual {p0, v0}, Landroid/os/Handler;->removeCallbacksAndMessages(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public final onResume()V
    .locals 2

    .line 1
    invoke-super {p0}, Landroidx/fragment/app/j0;->onResume()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lq/z;->v:Lq/s;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    iput v1, v0, Lq/s;->v:I

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    invoke-virtual {v0, v1}, Lq/s;->d(I)V

    .line 11
    .line 12
    .line 13
    iget-object v0, p0, Lq/z;->v:Lq/s;

    .line 14
    .line 15
    const v1, 0x7f120335

    .line 16
    .line 17
    .line 18
    invoke-virtual {p0, v1}, Landroidx/fragment/app/j0;->getString(I)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    invoke-virtual {v0, p0}, Lq/s;->b(Ljava/lang/CharSequence;)V

    .line 23
    .line 24
    .line 25
    return-void
.end method
