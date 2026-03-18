.class public final Ly9/f;
.super Lka/y;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:Ljava/util/List;

.field public final synthetic e:Ly9/r;

.field public final synthetic f:I

.field public final synthetic g:Ly9/r;


# direct methods
.method public constructor <init>(Ly9/r;I)V
    .locals 0

    .line 1
    iput p2, p0, Ly9/f;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Ly9/f;->g:Ly9/r;

    .line 4
    .line 5
    iput-object p1, p0, Ly9/f;->e:Ly9/r;

    .line 6
    .line 7
    invoke-direct {p0}, Lka/y;-><init>()V

    .line 8
    .line 9
    .line 10
    new-instance p1, Ljava/util/ArrayList;

    .line 11
    .line 12
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 13
    .line 14
    .line 15
    iput-object p1, p0, Ly9/f;->d:Ljava/util/List;

    .line 16
    .line 17
    return-void
.end method

.method private final i(Ljava/lang/String;)V
    .locals 0

    .line 1
    return-void
.end method


# virtual methods
.method public final a()I
    .locals 1

    .line 1
    iget-object v0, p0, Ly9/f;->d:Ljava/util/List;

    .line 2
    .line 3
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    return p0

    .line 11
    :cond_0
    iget-object p0, p0, Ly9/f;->d:Ljava/util/List;

    .line 12
    .line 13
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    add-int/lit8 p0, p0, 0x1

    .line 18
    .line 19
    return p0
.end method

.method public bridge synthetic c(Lka/v0;I)V
    .locals 1

    .line 1
    iget v0, p0, Ly9/f;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ly9/n;

    .line 7
    .line 8
    invoke-virtual {p0, p1, p2}, Ly9/f;->g(Ly9/n;I)V

    .line 9
    .line 10
    .line 11
    return-void

    .line 12
    :pswitch_0
    check-cast p1, Ly9/n;

    .line 13
    .line 14
    invoke-virtual {p0, p1, p2}, Ly9/f;->g(Ly9/n;I)V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    nop

    .line 19
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public final d(Landroid/view/ViewGroup;)Lka/v0;
    .locals 2

    .line 1
    iget-object p0, p0, Ly9/f;->e:Ly9/r;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-static {p0}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    const v0, 0x7f0d015c

    .line 12
    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    invoke-virtual {p0, v0, p1, v1}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;Z)Landroid/view/View;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    new-instance p1, Ly9/n;

    .line 20
    .line 21
    invoke-direct {p1, p0}, Ly9/n;-><init>(Landroid/view/View;)V

    .line 22
    .line 23
    .line 24
    return-object p1
.end method

.method public e(Lt7/u0;)Z
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    move v1, v0

    .line 3
    :goto_0
    iget-object v2, p0, Ly9/f;->d:Ljava/util/List;

    .line 4
    .line 5
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 6
    .line 7
    .line 8
    move-result v2

    .line 9
    if-ge v1, v2, :cond_1

    .line 10
    .line 11
    iget-object v2, p0, Ly9/f;->d:Ljava/util/List;

    .line 12
    .line 13
    invoke-interface {v2, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    check-cast v2, Ly9/o;

    .line 18
    .line 19
    iget-object v2, v2, Ly9/o;->a:Lt7/v0;

    .line 20
    .line 21
    iget-object v2, v2, Lt7/v0;->b:Lt7/q0;

    .line 22
    .line 23
    iget-object v3, p1, Lt7/u0;->s:Lhr/c1;

    .line 24
    .line 25
    invoke-virtual {v3, v2}, Lhr/c1;->containsKey(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    if-eqz v2, :cond_0

    .line 30
    .line 31
    const/4 p0, 0x1

    .line 32
    return p0

    .line 33
    :cond_0
    add-int/lit8 v1, v1, 0x1

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_1
    return v0
.end method

.method public f(Ljava/util/List;)V
    .locals 6

    .line 1
    iget-object v0, p0, Ly9/f;->g:Ly9/r;

    .line 2
    .line 3
    iget-object v1, v0, Ly9/r;->F:Landroid/widget/ImageView;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    move v3, v2

    .line 7
    :goto_0
    move-object v4, p1

    .line 8
    check-cast v4, Lhr/x0;

    .line 9
    .line 10
    iget v4, v4, Lhr/x0;->g:I

    .line 11
    .line 12
    if-ge v3, v4, :cond_1

    .line 13
    .line 14
    move-object v4, p1

    .line 15
    check-cast v4, Lhr/x0;

    .line 16
    .line 17
    invoke-virtual {v4, v3}, Lhr/x0;->get(I)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v4

    .line 21
    check-cast v4, Ly9/o;

    .line 22
    .line 23
    iget-object v5, v4, Ly9/o;->a:Lt7/v0;

    .line 24
    .line 25
    iget v4, v4, Ly9/o;->b:I

    .line 26
    .line 27
    iget-object v5, v5, Lt7/v0;->e:[Z

    .line 28
    .line 29
    aget-boolean v4, v5, v4

    .line 30
    .line 31
    if-eqz v4, :cond_0

    .line 32
    .line 33
    const/4 v2, 0x1

    .line 34
    goto :goto_1

    .line 35
    :cond_0
    add-int/lit8 v3, v3, 0x1

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_1
    :goto_1
    if-eqz v1, :cond_4

    .line 39
    .line 40
    if-eqz v2, :cond_2

    .line 41
    .line 42
    iget-object v3, v0, Ly9/r;->t1:Landroid/graphics/drawable/Drawable;

    .line 43
    .line 44
    goto :goto_2

    .line 45
    :cond_2
    iget-object v3, v0, Ly9/r;->u1:Landroid/graphics/drawable/Drawable;

    .line 46
    .line 47
    :goto_2
    invoke-virtual {v1, v3}, Landroid/widget/ImageView;->setImageDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 48
    .line 49
    .line 50
    if-eqz v2, :cond_3

    .line 51
    .line 52
    iget-object v0, v0, Ly9/r;->v1:Ljava/lang/String;

    .line 53
    .line 54
    goto :goto_3

    .line 55
    :cond_3
    iget-object v0, v0, Ly9/r;->w1:Ljava/lang/String;

    .line 56
    .line 57
    :goto_3
    invoke-virtual {v1, v0}, Landroid/view/View;->setContentDescription(Ljava/lang/CharSequence;)V

    .line 58
    .line 59
    .line 60
    :cond_4
    iput-object p1, p0, Ly9/f;->d:Ljava/util/List;

    .line 61
    .line 62
    return-void
.end method

.method public g(Ly9/n;I)V
    .locals 1

    .line 1
    iget v0, p0, Ly9/f;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, p1, p2}, Ly9/f;->h(Ly9/n;I)V

    .line 7
    .line 8
    .line 9
    return-void

    .line 10
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Ly9/f;->h(Ly9/n;I)V

    .line 11
    .line 12
    .line 13
    if-lez p2, :cond_1

    .line 14
    .line 15
    iget-object p0, p0, Ly9/f;->d:Ljava/util/List;

    .line 16
    .line 17
    add-int/lit8 p2, p2, -0x1

    .line 18
    .line 19
    invoke-interface {p0, p2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    check-cast p0, Ly9/o;

    .line 24
    .line 25
    iget-object p1, p1, Ly9/n;->v:Landroid/view/View;

    .line 26
    .line 27
    iget-object p2, p0, Ly9/o;->a:Lt7/v0;

    .line 28
    .line 29
    iget p0, p0, Ly9/o;->b:I

    .line 30
    .line 31
    iget-object p2, p2, Lt7/v0;->e:[Z

    .line 32
    .line 33
    aget-boolean p0, p2, p0

    .line 34
    .line 35
    if-eqz p0, :cond_0

    .line 36
    .line 37
    const/4 p0, 0x0

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    const/4 p0, 0x4

    .line 40
    :goto_0
    invoke-virtual {p1, p0}, Landroid/view/View;->setVisibility(I)V

    .line 41
    .line 42
    .line 43
    :cond_1
    return-void

    .line 44
    nop

    .line 45
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public final h(Ly9/n;I)V
    .locals 6

    .line 1
    iget-object v0, p0, Ly9/f;->e:Ly9/r;

    .line 2
    .line 3
    iget-object v0, v0, Ly9/r;->B1:Lt7/l0;

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    if-nez p2, :cond_5

    .line 9
    .line 10
    iget p2, p0, Ly9/f;->f:I

    .line 11
    .line 12
    packed-switch p2, :pswitch_data_0

    .line 13
    .line 14
    .line 15
    iget-object p2, p1, Ly9/n;->u:Landroid/widget/TextView;

    .line 16
    .line 17
    const v0, 0x7f1202f7

    .line 18
    .line 19
    .line 20
    invoke-virtual {p2, v0}, Landroid/widget/TextView;->setText(I)V

    .line 21
    .line 22
    .line 23
    const/4 p2, 0x0

    .line 24
    move v0, p2

    .line 25
    :goto_0
    iget-object v1, p0, Ly9/f;->d:Ljava/util/List;

    .line 26
    .line 27
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    if-ge v0, v1, :cond_2

    .line 32
    .line 33
    iget-object v1, p0, Ly9/f;->d:Ljava/util/List;

    .line 34
    .line 35
    invoke-interface {v1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v1

    .line 39
    check-cast v1, Ly9/o;

    .line 40
    .line 41
    iget-object v2, v1, Ly9/o;->a:Lt7/v0;

    .line 42
    .line 43
    iget v1, v1, Ly9/o;->b:I

    .line 44
    .line 45
    iget-object v2, v2, Lt7/v0;->e:[Z

    .line 46
    .line 47
    aget-boolean v1, v2, v1

    .line 48
    .line 49
    if-eqz v1, :cond_1

    .line 50
    .line 51
    move v0, p2

    .line 52
    goto :goto_1

    .line 53
    :cond_1
    add-int/lit8 v0, v0, 0x1

    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_2
    const/4 v0, 0x1

    .line 57
    :goto_1
    iget-object v1, p1, Ly9/n;->v:Landroid/view/View;

    .line 58
    .line 59
    if-eqz v0, :cond_3

    .line 60
    .line 61
    goto :goto_2

    .line 62
    :cond_3
    const/4 p2, 0x4

    .line 63
    :goto_2
    invoke-virtual {v1, p2}, Landroid/view/View;->setVisibility(I)V

    .line 64
    .line 65
    .line 66
    iget-object p1, p1, Lka/v0;->a:Landroid/view/View;

    .line 67
    .line 68
    new-instance p2, Ly9/e;

    .line 69
    .line 70
    const/4 v0, 0x3

    .line 71
    invoke-direct {p2, p0, v0}, Ly9/e;-><init>(Ljava/lang/Object;I)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {p1, p2}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 75
    .line 76
    .line 77
    goto :goto_4

    .line 78
    :pswitch_0
    iget-object p2, p1, Ly9/n;->u:Landroid/widget/TextView;

    .line 79
    .line 80
    const v0, 0x7f1202f6

    .line 81
    .line 82
    .line 83
    invoke-virtual {p2, v0}, Landroid/widget/TextView;->setText(I)V

    .line 84
    .line 85
    .line 86
    iget-object p2, p0, Ly9/f;->g:Ly9/r;

    .line 87
    .line 88
    iget-object p2, p2, Ly9/r;->B1:Lt7/l0;

    .line 89
    .line 90
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 91
    .line 92
    .line 93
    check-cast p2, La8/i0;

    .line 94
    .line 95
    invoke-virtual {p2}, La8/i0;->q0()Lt7/u0;

    .line 96
    .line 97
    .line 98
    move-result-object p2

    .line 99
    invoke-virtual {p0, p2}, Ly9/f;->e(Lt7/u0;)Z

    .line 100
    .line 101
    .line 102
    move-result p2

    .line 103
    iget-object v0, p1, Ly9/n;->v:Landroid/view/View;

    .line 104
    .line 105
    if-eqz p2, :cond_4

    .line 106
    .line 107
    const/4 p2, 0x4

    .line 108
    goto :goto_3

    .line 109
    :cond_4
    const/4 p2, 0x0

    .line 110
    :goto_3
    invoke-virtual {v0, p2}, Landroid/view/View;->setVisibility(I)V

    .line 111
    .line 112
    .line 113
    iget-object p1, p1, Lka/v0;->a:Landroid/view/View;

    .line 114
    .line 115
    new-instance p2, Ly9/e;

    .line 116
    .line 117
    const/4 v0, 0x1

    .line 118
    invoke-direct {p2, p0, v0}, Ly9/e;-><init>(Ljava/lang/Object;I)V

    .line 119
    .line 120
    .line 121
    invoke-virtual {p1, p2}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 122
    .line 123
    .line 124
    :goto_4
    return-void

    .line 125
    :cond_5
    iget-object v1, p0, Ly9/f;->d:Ljava/util/List;

    .line 126
    .line 127
    const/4 v2, 0x1

    .line 128
    sub-int/2addr p2, v2

    .line 129
    invoke-interface {v1, p2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object p2

    .line 133
    check-cast p2, Ly9/o;

    .line 134
    .line 135
    iget-object v1, p2, Ly9/o;->a:Lt7/v0;

    .line 136
    .line 137
    iget-object v1, v1, Lt7/v0;->b:Lt7/q0;

    .line 138
    .line 139
    move-object v3, v0

    .line 140
    check-cast v3, La8/i0;

    .line 141
    .line 142
    invoke-virtual {v3}, La8/i0;->q0()Lt7/u0;

    .line 143
    .line 144
    .line 145
    move-result-object v3

    .line 146
    iget-object v3, v3, Lt7/u0;->s:Lhr/c1;

    .line 147
    .line 148
    invoke-virtual {v3, v1}, Lhr/c1;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object v3

    .line 152
    const/4 v4, 0x0

    .line 153
    if-eqz v3, :cond_6

    .line 154
    .line 155
    iget-object v3, p2, Ly9/o;->a:Lt7/v0;

    .line 156
    .line 157
    iget v5, p2, Ly9/o;->b:I

    .line 158
    .line 159
    iget-object v3, v3, Lt7/v0;->e:[Z

    .line 160
    .line 161
    aget-boolean v3, v3, v5

    .line 162
    .line 163
    if-eqz v3, :cond_6

    .line 164
    .line 165
    goto :goto_5

    .line 166
    :cond_6
    move v2, v4

    .line 167
    :goto_5
    iget-object v3, p1, Ly9/n;->u:Landroid/widget/TextView;

    .line 168
    .line 169
    iget-object v5, p2, Ly9/o;->c:Ljava/lang/String;

    .line 170
    .line 171
    invoke-virtual {v3, v5}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 172
    .line 173
    .line 174
    iget-object v3, p1, Ly9/n;->v:Landroid/view/View;

    .line 175
    .line 176
    if-eqz v2, :cond_7

    .line 177
    .line 178
    goto :goto_6

    .line 179
    :cond_7
    const/4 v4, 0x4

    .line 180
    :goto_6
    invoke-virtual {v3, v4}, Landroid/view/View;->setVisibility(I)V

    .line 181
    .line 182
    .line 183
    iget-object p1, p1, Lka/v0;->a:Landroid/view/View;

    .line 184
    .line 185
    new-instance v2, Ly9/p;

    .line 186
    .line 187
    invoke-direct {v2, p0, v0, v1, p2}, Ly9/p;-><init>(Ly9/f;Lt7/l0;Lt7/q0;Ly9/o;)V

    .line 188
    .line 189
    .line 190
    invoke-virtual {p1, v2}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 191
    .line 192
    .line 193
    return-void

    .line 194
    nop

    .line 195
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
