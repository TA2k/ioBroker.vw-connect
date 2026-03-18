.class public final Lkn/k0;
.super Lb/t;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public g:Lay0/a;

.field public h:Lkn/j0;

.field public final i:Landroid/view/View;

.field public final j:Lkn/n0;


# direct methods
.method public constructor <init>(Lay0/a;Lkn/j0;Landroid/view/View;Lt4/m;Ljava/util/UUID;)V
    .locals 3

    .line 1
    const-string v0, "onDismissRequest"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "behaviors"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "composeView"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "layoutDirection"

    .line 17
    .line 18
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {p3}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    const-string v1, "getContext(...)"

    .line 26
    .line 27
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    const v2, 0x7f13012f

    .line 31
    .line 32
    .line 33
    invoke-direct {p0, v0, v2}, Lb/t;-><init>(Landroid/content/Context;I)V

    .line 34
    .line 35
    .line 36
    iput-object p1, p0, Lkn/k0;->g:Lay0/a;

    .line 37
    .line 38
    iput-object p2, p0, Lkn/k0;->h:Lkn/j0;

    .line 39
    .line 40
    iput-object p3, p0, Lkn/k0;->i:Landroid/view/View;

    .line 41
    .line 42
    invoke-virtual {p0}, Landroid/app/Dialog;->getWindow()Landroid/view/Window;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    if-eqz p1, :cond_2

    .line 47
    .line 48
    const/4 p2, 0x1

    .line 49
    invoke-virtual {p1, p2}, Landroid/view/Window;->requestFeature(I)Z

    .line 50
    .line 51
    .line 52
    const p2, 0x106000d

    .line 53
    .line 54
    .line 55
    invoke-virtual {p1, p2}, Landroid/view/Window;->setBackgroundDrawableResource(I)V

    .line 56
    .line 57
    .line 58
    const/4 p2, 0x0

    .line 59
    invoke-virtual {p1, p2}, Landroid/view/Window;->setDimAmount(F)V

    .line 60
    .line 61
    .line 62
    const/high16 p2, -0x80000000

    .line 63
    .line 64
    invoke-virtual {p1, p2}, Landroid/view/Window;->addFlags(I)V

    .line 65
    .line 66
    .line 67
    const/4 p2, -0x1

    .line 68
    invoke-virtual {p1, p2, p2}, Landroid/view/Window;->setLayout(II)V

    .line 69
    .line 70
    .line 71
    const/16 p2, 0x300

    .line 72
    .line 73
    invoke-virtual {p1}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    invoke-virtual {v0, p2}, Landroid/view/View;->setSystemUiVisibility(I)V

    .line 78
    .line 79
    .line 80
    new-instance p2, Lkn/n0;

    .line 81
    .line 82
    invoke-virtual {p0}, Landroid/app/Dialog;->getContext()Landroid/content/Context;

    .line 83
    .line 84
    .line 85
    move-result-object v0

    .line 86
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    invoke-direct {p2, v0, p1}, Lkn/n0;-><init>(Landroid/content/Context;Landroid/view/Window;)V

    .line 90
    .line 91
    .line 92
    new-instance v0, Ljava/lang/StringBuilder;

    .line 93
    .line 94
    const-string v1, "SheetDialog:"

    .line 95
    .line 96
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    invoke-virtual {v0, p5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object p5

    .line 106
    const v0, 0x7f0a00e9

    .line 107
    .line 108
    .line 109
    invoke-virtual {p2, v0, p5}, Landroid/view/View;->setTag(ILjava/lang/Object;)V

    .line 110
    .line 111
    .line 112
    const/4 p5, 0x0

    .line 113
    invoke-virtual {p2, p5}, Landroid/view/ViewGroup;->setClipChildren(Z)V

    .line 114
    .line 115
    .line 116
    iput-object p2, p0, Lkn/k0;->j:Lkn/n0;

    .line 117
    .line 118
    invoke-virtual {p1}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    .line 119
    .line 120
    .line 121
    move-result-object p1

    .line 122
    instance-of p5, p1, Landroid/view/ViewGroup;

    .line 123
    .line 124
    if-eqz p5, :cond_0

    .line 125
    .line 126
    check-cast p1, Landroid/view/ViewGroup;

    .line 127
    .line 128
    goto :goto_0

    .line 129
    :cond_0
    const/4 p1, 0x0

    .line 130
    :goto_0
    if-eqz p1, :cond_1

    .line 131
    .line 132
    invoke-static {p1}, Lkn/k0;->c(Landroid/view/ViewGroup;)V

    .line 133
    .line 134
    .line 135
    :cond_1
    invoke-virtual {p0, p2}, Lb/t;->setContentView(Landroid/view/View;)V

    .line 136
    .line 137
    .line 138
    invoke-static {p3}, Landroidx/lifecycle/v0;->d(Landroid/view/View;)Landroidx/lifecycle/x;

    .line 139
    .line 140
    .line 141
    move-result-object p1

    .line 142
    invoke-static {p2, p1}, Landroidx/lifecycle/v0;->l(Landroid/view/View;Landroidx/lifecycle/x;)V

    .line 143
    .line 144
    .line 145
    invoke-static {p3}, Landroidx/lifecycle/v0;->e(Landroid/view/View;)Landroidx/lifecycle/i1;

    .line 146
    .line 147
    .line 148
    move-result-object p1

    .line 149
    invoke-static {p2, p1}, Landroidx/lifecycle/v0;->m(Landroid/view/View;Landroidx/lifecycle/i1;)V

    .line 150
    .line 151
    .line 152
    invoke-static {p3}, Lkp/w;->b(Landroid/view/View;)Lra/f;

    .line 153
    .line 154
    .line 155
    move-result-object p1

    .line 156
    invoke-static {p2, p1}, Lkp/w;->d(Landroid/view/View;Lra/f;)V

    .line 157
    .line 158
    .line 159
    iget-object p1, p0, Lkn/k0;->g:Lay0/a;

    .line 160
    .line 161
    iget-object p2, p0, Lkn/k0;->h:Lkn/j0;

    .line 162
    .line 163
    invoke-virtual {p0, p1, p2, p4}, Lkn/k0;->d(Lay0/a;Lkn/j0;Lt4/m;)V

    .line 164
    .line 165
    .line 166
    iget-object p1, p0, Lb/t;->f:Lb/h0;

    .line 167
    .line 168
    new-instance p2, La3/f;

    .line 169
    .line 170
    const/16 p3, 0x16

    .line 171
    .line 172
    invoke-direct {p2, p0, p3}, La3/f;-><init>(Ljava/lang/Object;I)V

    .line 173
    .line 174
    .line 175
    invoke-static {p1, p0, p2}, Ljp/t1;->e(Lb/h0;Lb/t;Lay0/k;)V

    .line 176
    .line 177
    .line 178
    return-void

    .line 179
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 180
    .line 181
    const-string p1, "Dialog has no window"

    .line 182
    .line 183
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 184
    .line 185
    .line 186
    throw p0
.end method

.method public static final c(Landroid/view/ViewGroup;)V
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, v0}, Landroid/view/ViewGroup;->setClipChildren(Z)V

    .line 3
    .line 4
    .line 5
    instance-of v1, p0, Lkn/n0;

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    goto :goto_2

    .line 10
    :cond_0
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    :goto_0
    if-ge v0, v1, :cond_3

    .line 15
    .line 16
    invoke-virtual {p0, v0}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    instance-of v3, v2, Landroid/view/ViewGroup;

    .line 21
    .line 22
    if-eqz v3, :cond_1

    .line 23
    .line 24
    check-cast v2, Landroid/view/ViewGroup;

    .line 25
    .line 26
    goto :goto_1

    .line 27
    :cond_1
    const/4 v2, 0x0

    .line 28
    :goto_1
    if-eqz v2, :cond_2

    .line 29
    .line 30
    invoke-static {v2}, Lkn/k0;->c(Landroid/view/ViewGroup;)V

    .line 31
    .line 32
    .line 33
    :cond_2
    add-int/lit8 v0, v0, 0x1

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_3
    :goto_2
    return-void
.end method


# virtual methods
.method public final cancel()V
    .locals 0

    .line 1
    return-void
.end method

.method public final d(Lay0/a;Lkn/j0;Lt4/m;)V
    .locals 4

    .line 1
    const-string v0, "onDismissRequest"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "behaviors"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "layoutDirection"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Lkn/k0;->g:Lay0/a;

    .line 17
    .line 18
    iput-object p2, p0, Lkn/k0;->h:Lkn/j0;

    .line 19
    .line 20
    iget-object p1, p2, Lkn/j0;->b:Lx4/x;

    .line 21
    .line 22
    iget-object v0, p0, Lkn/k0;->i:Landroid/view/View;

    .line 23
    .line 24
    invoke-virtual {v0}, Landroid/view/View;->getRootView()Landroid/view/View;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    invoke-virtual {v0}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    instance-of v1, v0, Landroid/view/WindowManager$LayoutParams;

    .line 33
    .line 34
    if-eqz v1, :cond_0

    .line 35
    .line 36
    check-cast v0, Landroid/view/WindowManager$LayoutParams;

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_0
    const/4 v0, 0x0

    .line 40
    :goto_0
    const/4 v1, 0x1

    .line 41
    const/16 v2, 0x2000

    .line 42
    .line 43
    const/4 v3, 0x0

    .line 44
    if-eqz v0, :cond_1

    .line 45
    .line 46
    iget v0, v0, Landroid/view/WindowManager$LayoutParams;->flags:I

    .line 47
    .line 48
    and-int/2addr v0, v2

    .line 49
    if-eqz v0, :cond_1

    .line 50
    .line 51
    move v0, v1

    .line 52
    goto :goto_1

    .line 53
    :cond_1
    move v0, v3

    .line 54
    :goto_1
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 55
    .line 56
    .line 57
    move-result p1

    .line 58
    if-eqz p1, :cond_4

    .line 59
    .line 60
    if-eq p1, v1, :cond_3

    .line 61
    .line 62
    const/4 v0, 0x2

    .line 63
    if-ne p1, v0, :cond_2

    .line 64
    .line 65
    move v0, v3

    .line 66
    goto :goto_2

    .line 67
    :cond_2
    new-instance p0, La8/r0;

    .line 68
    .line 69
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 70
    .line 71
    .line 72
    throw p0

    .line 73
    :cond_3
    move v0, v1

    .line 74
    :cond_4
    :goto_2
    invoke-virtual {p0}, Landroid/app/Dialog;->getWindow()Landroid/view/Window;

    .line 75
    .line 76
    .line 77
    move-result-object p1

    .line 78
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    if-eqz v0, :cond_5

    .line 82
    .line 83
    move v0, v2

    .line 84
    goto :goto_3

    .line 85
    :cond_5
    const/16 v0, -0x2001

    .line 86
    .line 87
    :goto_3
    invoke-virtual {p1, v0, v2}, Landroid/view/Window;->setFlags(II)V

    .line 88
    .line 89
    .line 90
    invoke-virtual {p3}, Ljava/lang/Enum;->ordinal()I

    .line 91
    .line 92
    .line 93
    move-result p1

    .line 94
    if-eqz p1, :cond_7

    .line 95
    .line 96
    if-ne p1, v1, :cond_6

    .line 97
    .line 98
    goto :goto_4

    .line 99
    :cond_6
    new-instance p0, La8/r0;

    .line 100
    .line 101
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 102
    .line 103
    .line 104
    throw p0

    .line 105
    :cond_7
    move v1, v3

    .line 106
    :goto_4
    iget-object p1, p0, Lkn/k0;->j:Lkn/n0;

    .line 107
    .line 108
    invoke-virtual {p1, v1}, Landroid/view/View;->setLayoutDirection(I)V

    .line 109
    .line 110
    .line 111
    invoke-virtual {p0}, Landroid/app/Dialog;->getWindow()Landroid/view/Window;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    if-eqz p0, :cond_a

    .line 116
    .line 117
    iget p1, p2, Lkn/j0;->c:I

    .line 118
    .line 119
    invoke-virtual {p0, p1}, Landroid/view/Window;->setSoftInputMode(I)V

    .line 120
    .line 121
    .line 122
    iget-wide v0, p2, Lkn/j0;->e:J

    .line 123
    .line 124
    invoke-static {v0, v1}, Le3/j0;->z(J)I

    .line 125
    .line 126
    .line 127
    move-result p1

    .line 128
    invoke-virtual {p0, p1}, Landroid/view/Window;->setStatusBarColor(I)V

    .line 129
    .line 130
    .line 131
    iget-wide v0, p2, Lkn/j0;->f:J

    .line 132
    .line 133
    invoke-static {v0, v1}, Le3/j0;->z(J)I

    .line 134
    .line 135
    .line 136
    move-result p1

    .line 137
    invoke-virtual {p0, p1}, Landroid/view/Window;->setNavigationBarColor(I)V

    .line 138
    .line 139
    .line 140
    invoke-virtual {p0}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    .line 141
    .line 142
    .line 143
    move-result-object p1

    .line 144
    new-instance p3, Laq/a;

    .line 145
    .line 146
    invoke-direct {p3, p1}, Laq/a;-><init>(Landroid/view/View;)V

    .line 147
    .line 148
    .line 149
    sget p1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 150
    .line 151
    const/16 v0, 0x23

    .line 152
    .line 153
    if-lt p1, v0, :cond_8

    .line 154
    .line 155
    new-instance p1, Ld6/z1;

    .line 156
    .line 157
    invoke-direct {p1, p0, p3}, Ld6/y1;-><init>(Landroid/view/Window;Laq/a;)V

    .line 158
    .line 159
    .line 160
    goto :goto_5

    .line 161
    :cond_8
    const/16 v0, 0x1e

    .line 162
    .line 163
    if-lt p1, v0, :cond_9

    .line 164
    .line 165
    new-instance p1, Ld6/y1;

    .line 166
    .line 167
    invoke-direct {p1, p0, p3}, Ld6/y1;-><init>(Landroid/view/Window;Laq/a;)V

    .line 168
    .line 169
    .line 170
    goto :goto_5

    .line 171
    :cond_9
    new-instance p1, Ld6/x1;

    .line 172
    .line 173
    invoke-direct {p1, p0, p3}, Ld6/x1;-><init>(Landroid/view/Window;Laq/a;)V

    .line 174
    .line 175
    .line 176
    :goto_5
    invoke-virtual {p1, v3}, Ljp/rf;->c(Z)V

    .line 177
    .line 178
    .line 179
    iget-boolean p0, p2, Lkn/j0;->d:Z

    .line 180
    .line 181
    invoke-virtual {p1, p0}, Ljp/rf;->b(Z)V

    .line 182
    .line 183
    .line 184
    :cond_a
    return-void
.end method

.method public final onTouchEvent(Landroid/view/MotionEvent;)Z
    .locals 1

    .line 1
    const-string v0, "event"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1}, Landroid/app/Dialog;->onTouchEvent(Landroid/view/MotionEvent;)Z

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    if-eqz p1, :cond_0

    .line 11
    .line 12
    iget-object v0, p0, Lkn/k0;->h:Lkn/j0;

    .line 13
    .line 14
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    iget-object p0, p0, Lkn/k0;->g:Lay0/a;

    .line 18
    .line 19
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    :cond_0
    return p1
.end method
