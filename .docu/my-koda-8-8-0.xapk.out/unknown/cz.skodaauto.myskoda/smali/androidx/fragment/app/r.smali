.class public final Landroidx/fragment/app/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Landroid/view/ViewGroup;

.field public final b:Ljava/util/ArrayList;

.field public final c:Ljava/util/ArrayList;

.field public d:Z

.field public e:Z

.field public f:Z


# direct methods
.method public constructor <init>(Landroid/view/ViewGroup;)V
    .locals 1

    .line 1
    const-string v0, "container"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Landroidx/fragment/app/r;->a:Landroid/view/ViewGroup;

    .line 10
    .line 11
    new-instance p1, Ljava/util/ArrayList;

    .line 12
    .line 13
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Landroidx/fragment/app/r;->b:Ljava/util/ArrayList;

    .line 17
    .line 18
    new-instance p1, Ljava/util/ArrayList;

    .line 19
    .line 20
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object p1, p0, Landroidx/fragment/app/r;->c:Ljava/util/ArrayList;

    .line 24
    .line 25
    return-void
.end method

.method public static f(Landroidx/collection/f;Landroid/view/View;)V
    .locals 4

    .line 1
    sget-object v0, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 2
    .line 3
    invoke-static {p1}, Ld6/k0;->e(Landroid/view/View;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    invoke-interface {p0, v0, p1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    :cond_0
    instance-of v0, p1, Landroid/view/ViewGroup;

    .line 13
    .line 14
    if-eqz v0, :cond_2

    .line 15
    .line 16
    check-cast p1, Landroid/view/ViewGroup;

    .line 17
    .line 18
    invoke-virtual {p1}, Landroid/view/ViewGroup;->getChildCount()I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    const/4 v1, 0x0

    .line 23
    :goto_0
    if-ge v1, v0, :cond_2

    .line 24
    .line 25
    invoke-virtual {p1, v1}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    invoke-virtual {v2}, Landroid/view/View;->getVisibility()I

    .line 30
    .line 31
    .line 32
    move-result v3

    .line 33
    if-nez v3, :cond_1

    .line 34
    .line 35
    invoke-static {p0, v2}, Landroidx/fragment/app/r;->f(Landroidx/collection/f;Landroid/view/View;)V

    .line 36
    .line 37
    .line 38
    :cond_1
    add-int/lit8 v1, v1, 0x1

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_2
    return-void
.end method

.method public static final j(Landroid/view/ViewGroup;Landroidx/fragment/app/j1;)Landroidx/fragment/app/r;
    .locals 2

    .line 1
    const-string v0, "container"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "fragmentManager"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p1}, Landroidx/fragment/app/j1;->J()Lip/v;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    const-string v0, "fragmentManager.specialEffectsControllerFactory"

    .line 16
    .line 17
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    const p1, 0x7f0a02a4

    .line 21
    .line 22
    .line 23
    invoke-virtual {p0, p1}, Landroid/view/View;->getTag(I)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    instance-of v1, v0, Landroidx/fragment/app/r;

    .line 28
    .line 29
    if-eqz v1, :cond_0

    .line 30
    .line 31
    check-cast v0, Landroidx/fragment/app/r;

    .line 32
    .line 33
    return-object v0

    .line 34
    :cond_0
    new-instance v0, Landroidx/fragment/app/r;

    .line 35
    .line 36
    invoke-direct {v0, p0}, Landroidx/fragment/app/r;-><init>(Landroid/view/ViewGroup;)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {p0, p1, v0}, Landroid/view/View;->setTag(ILjava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    return-object v0
.end method

.method public static k(Ljava/util/ArrayList;)Z
    .locals 5

    .line 1
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const/4 v1, 0x1

    .line 6
    :cond_0
    :goto_0
    move v2, v1

    .line 7
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 8
    .line 9
    .line 10
    move-result v3

    .line 11
    const/4 v4, 0x0

    .line 12
    if-eqz v3, :cond_4

    .line 13
    .line 14
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    check-cast v2, Landroidx/fragment/app/g2;

    .line 19
    .line 20
    iget-object v3, v2, Landroidx/fragment/app/g2;->k:Ljava/util/ArrayList;

    .line 21
    .line 22
    invoke-virtual {v3}, Ljava/util/ArrayList;->isEmpty()Z

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    if-nez v3, :cond_3

    .line 27
    .line 28
    iget-object v2, v2, Landroidx/fragment/app/g2;->k:Ljava/util/ArrayList;

    .line 29
    .line 30
    if-eqz v2, :cond_1

    .line 31
    .line 32
    invoke-virtual {v2}, Ljava/util/ArrayList;->isEmpty()Z

    .line 33
    .line 34
    .line 35
    move-result v3

    .line 36
    if-eqz v3, :cond_1

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_1
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 40
    .line 41
    .line 42
    move-result-object v2

    .line 43
    :cond_2
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 44
    .line 45
    .line 46
    move-result v3

    .line 47
    if-eqz v3, :cond_0

    .line 48
    .line 49
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v3

    .line 53
    check-cast v3, Landroidx/fragment/app/f2;

    .line 54
    .line 55
    invoke-virtual {v3}, Landroidx/fragment/app/f2;->a()Z

    .line 56
    .line 57
    .line 58
    move-result v3

    .line 59
    if-nez v3, :cond_2

    .line 60
    .line 61
    :cond_3
    move v2, v4

    .line 62
    goto :goto_1

    .line 63
    :cond_4
    if-eqz v2, :cond_6

    .line 64
    .line 65
    new-instance v0, Ljava/util/ArrayList;

    .line 66
    .line 67
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 68
    .line 69
    .line 70
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    :goto_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 75
    .line 76
    .line 77
    move-result v2

    .line 78
    if-eqz v2, :cond_5

    .line 79
    .line 80
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v2

    .line 84
    check-cast v2, Landroidx/fragment/app/g2;

    .line 85
    .line 86
    iget-object v2, v2, Landroidx/fragment/app/g2;->k:Ljava/util/ArrayList;

    .line 87
    .line 88
    invoke-static {v2, v0}, Lmx0/q;->w(Ljava/lang/Iterable;Ljava/util/Collection;)V

    .line 89
    .line 90
    .line 91
    goto :goto_2

    .line 92
    :cond_5
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 93
    .line 94
    .line 95
    move-result p0

    .line 96
    if-nez p0, :cond_6

    .line 97
    .line 98
    return v1

    .line 99
    :cond_6
    return v4
.end method


# virtual methods
.method public final a(Landroidx/fragment/app/g2;)V
    .locals 3

    .line 1
    const-string v0, "operation"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-boolean v0, p1, Landroidx/fragment/app/g2;->i:Z

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    iget v0, p1, Landroidx/fragment/app/g2;->a:I

    .line 11
    .line 12
    iget-object v1, p1, Landroidx/fragment/app/g2;->c:Landroidx/fragment/app/j0;

    .line 13
    .line 14
    invoke-virtual {v1}, Landroidx/fragment/app/j0;->requireView()Landroid/view/View;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    const-string v2, "operation.fragment.requireView()"

    .line 19
    .line 20
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    iget-object p0, p0, Landroidx/fragment/app/r;->a:Landroid/view/ViewGroup;

    .line 24
    .line 25
    invoke-static {v0, v1, p0}, La7/g0;->a(ILandroid/view/View;Landroid/view/ViewGroup;)V

    .line 26
    .line 27
    .line 28
    const/4 p0, 0x0

    .line 29
    iput-boolean p0, p1, Landroidx/fragment/app/g2;->i:Z

    .line 30
    .line 31
    :cond_0
    return-void
.end method

.method public final b(Ljava/util/ArrayList;Z)V
    .locals 26

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v14, p2

    .line 4
    .line 5
    const/4 v15, 0x2

    .line 6
    invoke-static {v15}, Landroidx/fragment/app/j1;->L(I)Z

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    const-string v2, "FragmentManager"

    .line 11
    .line 12
    if-eqz v1, :cond_0

    .line 13
    .line 14
    const-string v1, "Collecting Effects"

    .line 15
    .line 16
    invoke-static {v2, v1}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 17
    .line 18
    .line 19
    :cond_0
    invoke-interface/range {p1 .. p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    :cond_1
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    const-string v4, "Unknown visibility "

    .line 28
    .line 29
    const/16 v5, 0x8

    .line 30
    .line 31
    const/4 v6, 0x4

    .line 32
    const/4 v7, 0x0

    .line 33
    const-string v8, "operation.fragment.mView"

    .line 34
    .line 35
    if-eqz v3, :cond_5

    .line 36
    .line 37
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v3

    .line 41
    move-object v10, v3

    .line 42
    check-cast v10, Landroidx/fragment/app/g2;

    .line 43
    .line 44
    iget-object v11, v10, Landroidx/fragment/app/g2;->c:Landroidx/fragment/app/j0;

    .line 45
    .line 46
    iget-object v11, v11, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 47
    .line 48
    invoke-static {v11, v8}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {v11}, Landroid/view/View;->getAlpha()F

    .line 52
    .line 53
    .line 54
    move-result v12

    .line 55
    cmpg-float v12, v12, v7

    .line 56
    .line 57
    if-nez v12, :cond_2

    .line 58
    .line 59
    invoke-virtual {v11}, Landroid/view/View;->getVisibility()I

    .line 60
    .line 61
    .line 62
    move-result v12

    .line 63
    if-nez v12, :cond_2

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_2
    invoke-virtual {v11}, Landroid/view/View;->getVisibility()I

    .line 67
    .line 68
    .line 69
    move-result v11

    .line 70
    if-eqz v11, :cond_4

    .line 71
    .line 72
    if-eq v11, v6, :cond_1

    .line 73
    .line 74
    if-ne v11, v5, :cond_3

    .line 75
    .line 76
    goto :goto_0

    .line 77
    :cond_3
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 78
    .line 79
    invoke-static {v11, v4}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object v1

    .line 83
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    throw v0

    .line 87
    :cond_4
    iget v10, v10, Landroidx/fragment/app/g2;->a:I

    .line 88
    .line 89
    if-eq v10, v15, :cond_1

    .line 90
    .line 91
    goto :goto_1

    .line 92
    :cond_5
    const/4 v3, 0x0

    .line 93
    :goto_1
    check-cast v3, Landroidx/fragment/app/g2;

    .line 94
    .line 95
    invoke-virtual/range {p1 .. p1}, Ljava/util/ArrayList;->size()I

    .line 96
    .line 97
    .line 98
    move-result v1

    .line 99
    move-object/from16 v10, p1

    .line 100
    .line 101
    invoke-virtual {v10, v1}, Ljava/util/ArrayList;->listIterator(I)Ljava/util/ListIterator;

    .line 102
    .line 103
    .line 104
    move-result-object v1

    .line 105
    :cond_6
    invoke-interface {v1}, Ljava/util/ListIterator;->hasPrevious()Z

    .line 106
    .line 107
    .line 108
    move-result v11

    .line 109
    if-eqz v11, :cond_a

    .line 110
    .line 111
    invoke-interface {v1}, Ljava/util/ListIterator;->previous()Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v11

    .line 115
    move-object v12, v11

    .line 116
    check-cast v12, Landroidx/fragment/app/g2;

    .line 117
    .line 118
    iget-object v13, v12, Landroidx/fragment/app/g2;->c:Landroidx/fragment/app/j0;

    .line 119
    .line 120
    iget-object v13, v13, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 121
    .line 122
    invoke-static {v13, v8}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    invoke-virtual {v13}, Landroid/view/View;->getAlpha()F

    .line 126
    .line 127
    .line 128
    move-result v16

    .line 129
    cmpg-float v16, v16, v7

    .line 130
    .line 131
    if-nez v16, :cond_7

    .line 132
    .line 133
    invoke-virtual {v13}, Landroid/view/View;->getVisibility()I

    .line 134
    .line 135
    .line 136
    move-result v16

    .line 137
    if-nez v16, :cond_7

    .line 138
    .line 139
    goto :goto_2

    .line 140
    :cond_7
    invoke-virtual {v13}, Landroid/view/View;->getVisibility()I

    .line 141
    .line 142
    .line 143
    move-result v13

    .line 144
    if-eqz v13, :cond_6

    .line 145
    .line 146
    if-eq v13, v6, :cond_9

    .line 147
    .line 148
    if-ne v13, v5, :cond_8

    .line 149
    .line 150
    goto :goto_2

    .line 151
    :cond_8
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 152
    .line 153
    invoke-static {v13, v4}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 154
    .line 155
    .line 156
    move-result-object v1

    .line 157
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 158
    .line 159
    .line 160
    throw v0

    .line 161
    :cond_9
    :goto_2
    iget v12, v12, Landroidx/fragment/app/g2;->a:I

    .line 162
    .line 163
    if-ne v12, v15, :cond_6

    .line 164
    .line 165
    goto :goto_3

    .line 166
    :cond_a
    const/4 v11, 0x0

    .line 167
    :goto_3
    move-object v4, v11

    .line 168
    check-cast v4, Landroidx/fragment/app/g2;

    .line 169
    .line 170
    invoke-static {v15}, Landroidx/fragment/app/j1;->L(I)Z

    .line 171
    .line 172
    .line 173
    move-result v1

    .line 174
    if-eqz v1, :cond_b

    .line 175
    .line 176
    new-instance v1, Ljava/lang/StringBuilder;

    .line 177
    .line 178
    const-string v5, "Executing operations from "

    .line 179
    .line 180
    invoke-direct {v1, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 181
    .line 182
    .line 183
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 184
    .line 185
    .line 186
    const-string v5, " to "

    .line 187
    .line 188
    invoke-virtual {v1, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 189
    .line 190
    .line 191
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 192
    .line 193
    .line 194
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 195
    .line 196
    .line 197
    move-result-object v1

    .line 198
    invoke-static {v2, v1}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 199
    .line 200
    .line 201
    :cond_b
    new-instance v1, Ljava/util/ArrayList;

    .line 202
    .line 203
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 204
    .line 205
    .line 206
    new-instance v5, Ljava/util/ArrayList;

    .line 207
    .line 208
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 209
    .line 210
    .line 211
    invoke-static {v10}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object v6

    .line 215
    check-cast v6, Landroidx/fragment/app/g2;

    .line 216
    .line 217
    iget-object v6, v6, Landroidx/fragment/app/g2;->c:Landroidx/fragment/app/j0;

    .line 218
    .line 219
    invoke-virtual {v10}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 220
    .line 221
    .line 222
    move-result-object v7

    .line 223
    :goto_4
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 224
    .line 225
    .line 226
    move-result v8

    .line 227
    if-eqz v8, :cond_c

    .line 228
    .line 229
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 230
    .line 231
    .line 232
    move-result-object v8

    .line 233
    check-cast v8, Landroidx/fragment/app/g2;

    .line 234
    .line 235
    iget-object v8, v8, Landroidx/fragment/app/g2;->c:Landroidx/fragment/app/j0;

    .line 236
    .line 237
    iget-object v8, v8, Landroidx/fragment/app/j0;->mAnimationInfo:Landroidx/fragment/app/g0;

    .line 238
    .line 239
    iget-object v11, v6, Landroidx/fragment/app/j0;->mAnimationInfo:Landroidx/fragment/app/g0;

    .line 240
    .line 241
    iget v12, v11, Landroidx/fragment/app/g0;->b:I

    .line 242
    .line 243
    iput v12, v8, Landroidx/fragment/app/g0;->b:I

    .line 244
    .line 245
    iget v12, v11, Landroidx/fragment/app/g0;->c:I

    .line 246
    .line 247
    iput v12, v8, Landroidx/fragment/app/g0;->c:I

    .line 248
    .line 249
    iget v12, v11, Landroidx/fragment/app/g0;->d:I

    .line 250
    .line 251
    iput v12, v8, Landroidx/fragment/app/g0;->d:I

    .line 252
    .line 253
    iget v11, v11, Landroidx/fragment/app/g0;->e:I

    .line 254
    .line 255
    iput v11, v8, Landroidx/fragment/app/g0;->e:I

    .line 256
    .line 257
    goto :goto_4

    .line 258
    :cond_c
    invoke-virtual {v10}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 259
    .line 260
    .line 261
    move-result-object v6

    .line 262
    :goto_5
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 263
    .line 264
    .line 265
    move-result v7

    .line 266
    const/4 v8, 0x0

    .line 267
    const/4 v10, 0x1

    .line 268
    if-eqz v7, :cond_f

    .line 269
    .line 270
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 271
    .line 272
    .line 273
    move-result-object v7

    .line 274
    check-cast v7, Landroidx/fragment/app/g2;

    .line 275
    .line 276
    new-instance v11, Landroidx/fragment/app/f;

    .line 277
    .line 278
    invoke-direct {v11, v7, v14}, Landroidx/fragment/app/f;-><init>(Landroidx/fragment/app/g2;Z)V

    .line 279
    .line 280
    .line 281
    invoke-virtual {v1, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 282
    .line 283
    .line 284
    new-instance v11, Landroidx/fragment/app/q;

    .line 285
    .line 286
    if-eqz v14, :cond_d

    .line 287
    .line 288
    if-ne v7, v3, :cond_e

    .line 289
    .line 290
    :goto_6
    move v8, v10

    .line 291
    goto :goto_7

    .line 292
    :cond_d
    if-ne v7, v4, :cond_e

    .line 293
    .line 294
    goto :goto_6

    .line 295
    :cond_e
    :goto_7
    invoke-direct {v11, v7, v14, v8}, Landroidx/fragment/app/q;-><init>(Landroidx/fragment/app/g2;ZZ)V

    .line 296
    .line 297
    .line 298
    invoke-virtual {v5, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 299
    .line 300
    .line 301
    new-instance v8, Landroidx/fragment/app/e2;

    .line 302
    .line 303
    invoke-direct {v8, v0, v7, v10}, Landroidx/fragment/app/e2;-><init>(Landroidx/fragment/app/r;Landroidx/fragment/app/g2;I)V

    .line 304
    .line 305
    .line 306
    iget-object v7, v7, Landroidx/fragment/app/g2;->d:Ljava/util/ArrayList;

    .line 307
    .line 308
    invoke-virtual {v7, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 309
    .line 310
    .line 311
    goto :goto_5

    .line 312
    :cond_f
    new-instance v6, Ljava/util/ArrayList;

    .line 313
    .line 314
    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    .line 315
    .line 316
    .line 317
    invoke-virtual {v5}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 318
    .line 319
    .line 320
    move-result-object v5

    .line 321
    :cond_10
    :goto_8
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 322
    .line 323
    .line 324
    move-result v7

    .line 325
    if-eqz v7, :cond_11

    .line 326
    .line 327
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 328
    .line 329
    .line 330
    move-result-object v7

    .line 331
    move-object v11, v7

    .line 332
    check-cast v11, Landroidx/fragment/app/q;

    .line 333
    .line 334
    invoke-virtual {v11}, Landroidx/fragment/app/k;->a()Z

    .line 335
    .line 336
    .line 337
    move-result v11

    .line 338
    if-nez v11, :cond_10

    .line 339
    .line 340
    invoke-virtual {v6, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 341
    .line 342
    .line 343
    goto :goto_8

    .line 344
    :cond_11
    new-instance v5, Ljava/util/ArrayList;

    .line 345
    .line 346
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 347
    .line 348
    .line 349
    invoke-virtual {v6}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 350
    .line 351
    .line 352
    move-result-object v6

    .line 353
    :cond_12
    :goto_9
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 354
    .line 355
    .line 356
    move-result v7

    .line 357
    if-eqz v7, :cond_13

    .line 358
    .line 359
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 360
    .line 361
    .line 362
    move-result-object v7

    .line 363
    move-object v11, v7

    .line 364
    check-cast v11, Landroidx/fragment/app/q;

    .line 365
    .line 366
    invoke-virtual {v11}, Landroidx/fragment/app/q;->b()Landroidx/fragment/app/b2;

    .line 367
    .line 368
    .line 369
    move-result-object v11

    .line 370
    if-eqz v11, :cond_12

    .line 371
    .line 372
    invoke-virtual {v5, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 373
    .line 374
    .line 375
    goto :goto_9

    .line 376
    :cond_13
    invoke-virtual {v5}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 377
    .line 378
    .line 379
    move-result-object v6

    .line 380
    move-object v7, v5

    .line 381
    const/4 v5, 0x0

    .line 382
    :goto_a
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 383
    .line 384
    .line 385
    move-result v11

    .line 386
    if-eqz v11, :cond_16

    .line 387
    .line 388
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 389
    .line 390
    .line 391
    move-result-object v11

    .line 392
    check-cast v11, Landroidx/fragment/app/q;

    .line 393
    .line 394
    invoke-virtual {v11}, Landroidx/fragment/app/q;->b()Landroidx/fragment/app/b2;

    .line 395
    .line 396
    .line 397
    move-result-object v12

    .line 398
    if-eqz v5, :cond_15

    .line 399
    .line 400
    if-ne v12, v5, :cond_14

    .line 401
    .line 402
    goto :goto_b

    .line 403
    :cond_14
    new-instance v0, Ljava/lang/StringBuilder;

    .line 404
    .line 405
    const-string v1, "Mixing framework transitions and AndroidX transitions is not allowed. Fragment "

    .line 406
    .line 407
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 408
    .line 409
    .line 410
    iget-object v1, v11, Landroidx/fragment/app/k;->a:Landroidx/fragment/app/g2;

    .line 411
    .line 412
    iget-object v1, v1, Landroidx/fragment/app/g2;->c:Landroidx/fragment/app/j0;

    .line 413
    .line 414
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 415
    .line 416
    .line 417
    const-string v1, " returned Transition "

    .line 418
    .line 419
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 420
    .line 421
    .line 422
    iget-object v1, v11, Landroidx/fragment/app/q;->b:Ljava/lang/Object;

    .line 423
    .line 424
    const-string v2, " which uses a different Transition type than other Fragments."

    .line 425
    .line 426
    invoke-static {v0, v1, v2}, Lf2/m0;->k(Ljava/lang/StringBuilder;Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;

    .line 427
    .line 428
    .line 429
    move-result-object v0

    .line 430
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 431
    .line 432
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 433
    .line 434
    .line 435
    move-result-object v0

    .line 436
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 437
    .line 438
    .line 439
    throw v1

    .line 440
    :cond_15
    :goto_b
    move-object v5, v12

    .line 441
    goto :goto_a

    .line 442
    :cond_16
    if-nez v5, :cond_17

    .line 443
    .line 444
    move-object/from16 v22, v1

    .line 445
    .line 446
    move/from16 v16, v10

    .line 447
    .line 448
    move/from16 v21, v15

    .line 449
    .line 450
    goto/16 :goto_16

    .line 451
    .line 452
    :cond_17
    move-object v6, v7

    .line 453
    new-instance v7, Ljava/util/ArrayList;

    .line 454
    .line 455
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 456
    .line 457
    .line 458
    new-instance v11, Ljava/util/ArrayList;

    .line 459
    .line 460
    invoke-direct {v11}, Ljava/util/ArrayList;-><init>()V

    .line 461
    .line 462
    .line 463
    new-instance v12, Landroidx/collection/f;

    .line 464
    .line 465
    invoke-direct {v12, v8}, Landroidx/collection/a1;-><init>(I)V

    .line 466
    .line 467
    .line 468
    new-instance v13, Ljava/util/ArrayList;

    .line 469
    .line 470
    invoke-direct {v13}, Ljava/util/ArrayList;-><init>()V

    .line 471
    .line 472
    .line 473
    new-instance v16, Ljava/util/ArrayList;

    .line 474
    .line 475
    invoke-direct/range {v16 .. v16}, Ljava/util/ArrayList;-><init>()V

    .line 476
    .line 477
    .line 478
    move/from16 p1, v10

    .line 479
    .line 480
    new-instance v10, Landroidx/collection/f;

    .line 481
    .line 482
    invoke-direct {v10, v8}, Landroidx/collection/a1;-><init>(I)V

    .line 483
    .line 484
    .line 485
    move-object/from16 v17, v13

    .line 486
    .line 487
    new-instance v13, Landroidx/collection/f;

    .line 488
    .line 489
    invoke-direct {v13, v8}, Landroidx/collection/a1;-><init>(I)V

    .line 490
    .line 491
    .line 492
    invoke-virtual {v6}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 493
    .line 494
    .line 495
    move-result-object v18

    .line 496
    move-object/from16 v19, v6

    .line 497
    .line 498
    :goto_c
    const/4 v6, 0x0

    .line 499
    :goto_d
    invoke-interface/range {v18 .. v18}, Ljava/util/Iterator;->hasNext()Z

    .line 500
    .line 501
    .line 502
    move-result v20

    .line 503
    if-eqz v20, :cond_25

    .line 504
    .line 505
    invoke-interface/range {v18 .. v18}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 506
    .line 507
    .line 508
    move-result-object v20

    .line 509
    move/from16 v21, v15

    .line 510
    .line 511
    move-object/from16 v15, v20

    .line 512
    .line 513
    check-cast v15, Landroidx/fragment/app/q;

    .line 514
    .line 515
    iget-object v15, v15, Landroidx/fragment/app/q;->d:Ljava/lang/Object;

    .line 516
    .line 517
    if-eqz v15, :cond_24

    .line 518
    .line 519
    if-eqz v3, :cond_24

    .line 520
    .line 521
    iget-object v8, v3, Landroidx/fragment/app/g2;->c:Landroidx/fragment/app/j0;

    .line 522
    .line 523
    if-eqz v4, :cond_23

    .line 524
    .line 525
    iget-object v6, v4, Landroidx/fragment/app/g2;->c:Landroidx/fragment/app/j0;

    .line 526
    .line 527
    invoke-virtual {v5, v15}, Landroidx/fragment/app/b2;->h(Ljava/lang/Object;)Ljava/lang/Object;

    .line 528
    .line 529
    .line 530
    move-result-object v15

    .line 531
    invoke-virtual {v5, v15}, Landroidx/fragment/app/b2;->y(Ljava/lang/Object;)Ljava/lang/Object;

    .line 532
    .line 533
    .line 534
    move-result-object v15

    .line 535
    invoke-virtual {v6}, Landroidx/fragment/app/j0;->getSharedElementSourceNames()Ljava/util/ArrayList;

    .line 536
    .line 537
    .line 538
    move-result-object v9

    .line 539
    move-object/from16 v22, v1

    .line 540
    .line 541
    const-string v1, "lastIn.fragment.sharedElementSourceNames"

    .line 542
    .line 543
    invoke-static {v9, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 544
    .line 545
    .line 546
    invoke-virtual {v8}, Landroidx/fragment/app/j0;->getSharedElementSourceNames()Ljava/util/ArrayList;

    .line 547
    .line 548
    .line 549
    move-result-object v1

    .line 550
    move-object/from16 v23, v5

    .line 551
    .line 552
    const-string v5, "firstOut.fragment.sharedElementSourceNames"

    .line 553
    .line 554
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 555
    .line 556
    .line 557
    invoke-virtual {v8}, Landroidx/fragment/app/j0;->getSharedElementTargetNames()Ljava/util/ArrayList;

    .line 558
    .line 559
    .line 560
    move-result-object v5

    .line 561
    move-object/from16 v24, v7

    .line 562
    .line 563
    const-string v7, "firstOut.fragment.sharedElementTargetNames"

    .line 564
    .line 565
    invoke-static {v5, v7}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 566
    .line 567
    .line 568
    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    .line 569
    .line 570
    .line 571
    move-result v7

    .line 572
    move-object/from16 v25, v11

    .line 573
    .line 574
    const/4 v11, 0x0

    .line 575
    :goto_e
    const/4 v14, -0x1

    .line 576
    if-ge v11, v7, :cond_19

    .line 577
    .line 578
    move/from16 v16, v7

    .line 579
    .line 580
    invoke-virtual {v5, v11}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 581
    .line 582
    .line 583
    move-result-object v7

    .line 584
    invoke-virtual {v9, v7}, Ljava/util/ArrayList;->indexOf(Ljava/lang/Object;)I

    .line 585
    .line 586
    .line 587
    move-result v7

    .line 588
    if-eq v7, v14, :cond_18

    .line 589
    .line 590
    invoke-virtual {v1, v11}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 591
    .line 592
    .line 593
    move-result-object v14

    .line 594
    invoke-virtual {v9, v7, v14}, Ljava/util/ArrayList;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 595
    .line 596
    .line 597
    :cond_18
    add-int/lit8 v11, v11, 0x1

    .line 598
    .line 599
    move/from16 v7, v16

    .line 600
    .line 601
    goto :goto_e

    .line 602
    :cond_19
    invoke-virtual {v6}, Landroidx/fragment/app/j0;->getSharedElementTargetNames()Ljava/util/ArrayList;

    .line 603
    .line 604
    .line 605
    move-result-object v1

    .line 606
    const-string v5, "lastIn.fragment.sharedElementTargetNames"

    .line 607
    .line 608
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 609
    .line 610
    .line 611
    if-nez p2, :cond_1a

    .line 612
    .line 613
    invoke-virtual {v8}, Landroidx/fragment/app/j0;->getExitTransitionCallback()Landroidx/core/app/l0;

    .line 614
    .line 615
    .line 616
    invoke-virtual {v6}, Landroidx/fragment/app/j0;->getEnterTransitionCallback()Landroidx/core/app/l0;

    .line 617
    .line 618
    .line 619
    new-instance v5, Llx0/l;

    .line 620
    .line 621
    const/4 v7, 0x0

    .line 622
    invoke-direct {v5, v7, v7}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 623
    .line 624
    .line 625
    goto :goto_f

    .line 626
    :cond_1a
    const/4 v7, 0x0

    .line 627
    invoke-virtual {v8}, Landroidx/fragment/app/j0;->getEnterTransitionCallback()Landroidx/core/app/l0;

    .line 628
    .line 629
    .line 630
    invoke-virtual {v6}, Landroidx/fragment/app/j0;->getExitTransitionCallback()Landroidx/core/app/l0;

    .line 631
    .line 632
    .line 633
    new-instance v5, Llx0/l;

    .line 634
    .line 635
    invoke-direct {v5, v7, v7}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 636
    .line 637
    .line 638
    :goto_f
    iget-object v11, v5, Llx0/l;->d:Ljava/lang/Object;

    .line 639
    .line 640
    if-nez v11, :cond_22

    .line 641
    .line 642
    iget-object v5, v5, Llx0/l;->e:Ljava/lang/Object;

    .line 643
    .line 644
    if-nez v5, :cond_21

    .line 645
    .line 646
    invoke-virtual {v9}, Ljava/util/ArrayList;->size()I

    .line 647
    .line 648
    .line 649
    move-result v5

    .line 650
    const/4 v11, 0x0

    .line 651
    :goto_10
    if-ge v11, v5, :cond_1b

    .line 652
    .line 653
    invoke-virtual {v9, v11}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 654
    .line 655
    .line 656
    move-result-object v7

    .line 657
    const-string v14, "exitingNames[i]"

    .line 658
    .line 659
    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 660
    .line 661
    .line 662
    check-cast v7, Ljava/lang/String;

    .line 663
    .line 664
    invoke-virtual {v1, v11}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 665
    .line 666
    .line 667
    move-result-object v14

    .line 668
    move/from16 v17, v5

    .line 669
    .line 670
    const-string v5, "enteringNames[i]"

    .line 671
    .line 672
    invoke-static {v14, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 673
    .line 674
    .line 675
    check-cast v14, Ljava/lang/String;

    .line 676
    .line 677
    invoke-interface {v12, v7, v14}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 678
    .line 679
    .line 680
    add-int/lit8 v11, v11, 0x1

    .line 681
    .line 682
    move/from16 v5, v17

    .line 683
    .line 684
    const/4 v7, 0x0

    .line 685
    const/4 v14, -0x1

    .line 686
    goto :goto_10

    .line 687
    :cond_1b
    invoke-static/range {v21 .. v21}, Landroidx/fragment/app/j1;->L(I)Z

    .line 688
    .line 689
    .line 690
    move-result v5

    .line 691
    if-eqz v5, :cond_1d

    .line 692
    .line 693
    const-string v5, ">>> entering view names <<<"

    .line 694
    .line 695
    invoke-static {v2, v5}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 696
    .line 697
    .line 698
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 699
    .line 700
    .line 701
    move-result-object v5

    .line 702
    :goto_11
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 703
    .line 704
    .line 705
    move-result v7

    .line 706
    const-string v11, "Name: "

    .line 707
    .line 708
    if-eqz v7, :cond_1c

    .line 709
    .line 710
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 711
    .line 712
    .line 713
    move-result-object v7

    .line 714
    check-cast v7, Ljava/lang/String;

    .line 715
    .line 716
    new-instance v14, Ljava/lang/StringBuilder;

    .line 717
    .line 718
    invoke-direct {v14, v11}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 719
    .line 720
    .line 721
    invoke-virtual {v14, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 722
    .line 723
    .line 724
    invoke-virtual {v14}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 725
    .line 726
    .line 727
    move-result-object v7

    .line 728
    invoke-static {v2, v7}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 729
    .line 730
    .line 731
    goto :goto_11

    .line 732
    :cond_1c
    const-string v5, ">>> exiting view names <<<"

    .line 733
    .line 734
    invoke-static {v2, v5}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 735
    .line 736
    .line 737
    invoke-virtual {v9}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 738
    .line 739
    .line 740
    move-result-object v5

    .line 741
    :goto_12
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 742
    .line 743
    .line 744
    move-result v7

    .line 745
    if-eqz v7, :cond_1d

    .line 746
    .line 747
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 748
    .line 749
    .line 750
    move-result-object v7

    .line 751
    check-cast v7, Ljava/lang/String;

    .line 752
    .line 753
    new-instance v14, Ljava/lang/StringBuilder;

    .line 754
    .line 755
    invoke-direct {v14, v11}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 756
    .line 757
    .line 758
    invoke-virtual {v14, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 759
    .line 760
    .line 761
    invoke-virtual {v14}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 762
    .line 763
    .line 764
    move-result-object v7

    .line 765
    invoke-static {v2, v7}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 766
    .line 767
    .line 768
    goto :goto_12

    .line 769
    :cond_1d
    iget-object v5, v8, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 770
    .line 771
    const-string v7, "firstOut.fragment.mView"

    .line 772
    .line 773
    invoke-static {v5, v7}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 774
    .line 775
    .line 776
    invoke-static {v10, v5}, Landroidx/fragment/app/r;->f(Landroidx/collection/f;Landroid/view/View;)V

    .line 777
    .line 778
    .line 779
    invoke-virtual {v10, v9}, Landroidx/collection/f;->retainAll(Ljava/util/Collection;)Z

    .line 780
    .line 781
    .line 782
    invoke-virtual {v10}, Landroidx/collection/f;->keySet()Ljava/util/Set;

    .line 783
    .line 784
    .line 785
    move-result-object v5

    .line 786
    check-cast v5, Ljava/util/Collection;

    .line 787
    .line 788
    invoke-virtual {v12, v5}, Landroidx/collection/f;->retainAll(Ljava/util/Collection;)Z

    .line 789
    .line 790
    .line 791
    iget-object v5, v6, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 792
    .line 793
    const-string v6, "lastIn.fragment.mView"

    .line 794
    .line 795
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 796
    .line 797
    .line 798
    invoke-static {v13, v5}, Landroidx/fragment/app/r;->f(Landroidx/collection/f;Landroid/view/View;)V

    .line 799
    .line 800
    .line 801
    invoke-virtual {v13, v1}, Landroidx/collection/f;->retainAll(Ljava/util/Collection;)Z

    .line 802
    .line 803
    .line 804
    invoke-virtual {v12}, Landroidx/collection/f;->values()Ljava/util/Collection;

    .line 805
    .line 806
    .line 807
    move-result-object v5

    .line 808
    invoke-virtual {v13, v5}, Landroidx/collection/f;->retainAll(Ljava/util/Collection;)Z

    .line 809
    .line 810
    .line 811
    sget-object v5, Landroidx/fragment/app/u1;->a:Landroidx/fragment/app/z1;

    .line 812
    .line 813
    invoke-virtual {v12}, Landroidx/collection/a1;->size()I

    .line 814
    .line 815
    .line 816
    move-result v5

    .line 817
    add-int/lit8 v5, v5, -0x1

    .line 818
    .line 819
    const/4 v6, -0x1

    .line 820
    :goto_13
    if-ge v6, v5, :cond_1f

    .line 821
    .line 822
    invoke-virtual {v12, v5}, Landroidx/collection/a1;->valueAt(I)Ljava/lang/Object;

    .line 823
    .line 824
    .line 825
    move-result-object v7

    .line 826
    check-cast v7, Ljava/lang/String;

    .line 827
    .line 828
    invoke-virtual {v13, v7}, Landroidx/collection/f;->containsKey(Ljava/lang/Object;)Z

    .line 829
    .line 830
    .line 831
    move-result v7

    .line 832
    if-nez v7, :cond_1e

    .line 833
    .line 834
    invoke-virtual {v12, v5}, Landroidx/collection/a1;->removeAt(I)Ljava/lang/Object;

    .line 835
    .line 836
    .line 837
    :cond_1e
    add-int/lit8 v5, v5, -0x1

    .line 838
    .line 839
    goto :goto_13

    .line 840
    :cond_1f
    invoke-virtual {v12}, Landroidx/collection/f;->keySet()Ljava/util/Set;

    .line 841
    .line 842
    .line 843
    move-result-object v5

    .line 844
    const-string v6, "sharedElementNameMapping.keys"

    .line 845
    .line 846
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 847
    .line 848
    .line 849
    check-cast v5, Ljava/util/Collection;

    .line 850
    .line 851
    invoke-virtual {v10}, Landroidx/collection/f;->entrySet()Ljava/util/Set;

    .line 852
    .line 853
    .line 854
    move-result-object v6

    .line 855
    const-string v7, "entries"

    .line 856
    .line 857
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 858
    .line 859
    .line 860
    check-cast v6, Ljava/lang/Iterable;

    .line 861
    .line 862
    new-instance v8, La3/f;

    .line 863
    .line 864
    const/4 v11, 0x5

    .line 865
    invoke-direct {v8, v5, v11}, La3/f;-><init>(Ljava/lang/Object;I)V

    .line 866
    .line 867
    .line 868
    const/4 v5, 0x0

    .line 869
    invoke-static {v6, v8, v5}, Lmx0/q;->G(Ljava/lang/Iterable;Lay0/k;Z)Z

    .line 870
    .line 871
    .line 872
    invoke-virtual {v12}, Landroidx/collection/f;->values()Ljava/util/Collection;

    .line 873
    .line 874
    .line 875
    move-result-object v6

    .line 876
    const-string v8, "sharedElementNameMapping.values"

    .line 877
    .line 878
    invoke-static {v6, v8}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 879
    .line 880
    .line 881
    invoke-virtual {v13}, Landroidx/collection/f;->entrySet()Ljava/util/Set;

    .line 882
    .line 883
    .line 884
    move-result-object v8

    .line 885
    invoke-static {v8, v7}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 886
    .line 887
    .line 888
    check-cast v8, Ljava/lang/Iterable;

    .line 889
    .line 890
    new-instance v7, La3/f;

    .line 891
    .line 892
    invoke-direct {v7, v6, v11}, La3/f;-><init>(Ljava/lang/Object;I)V

    .line 893
    .line 894
    .line 895
    invoke-static {v8, v7, v5}, Lmx0/q;->G(Ljava/lang/Iterable;Lay0/k;Z)Z

    .line 896
    .line 897
    .line 898
    invoke-virtual {v12}, Landroidx/collection/a1;->isEmpty()Z

    .line 899
    .line 900
    .line 901
    move-result v6

    .line 902
    if-eqz v6, :cond_20

    .line 903
    .line 904
    new-instance v6, Ljava/lang/StringBuilder;

    .line 905
    .line 906
    const-string v7, "Ignoring shared elements transition "

    .line 907
    .line 908
    invoke-direct {v6, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 909
    .line 910
    .line 911
    invoke-virtual {v6, v15}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 912
    .line 913
    .line 914
    const-string v7, " between "

    .line 915
    .line 916
    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 917
    .line 918
    .line 919
    invoke-virtual {v6, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 920
    .line 921
    .line 922
    const-string v7, " and "

    .line 923
    .line 924
    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 925
    .line 926
    .line 927
    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 928
    .line 929
    .line 930
    const-string v7, " as there are no matching elements in both the entering and exiting fragment. In order to run a SharedElementTransition, both fragments involved must have the element."

    .line 931
    .line 932
    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 933
    .line 934
    .line 935
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 936
    .line 937
    .line 938
    move-result-object v6

    .line 939
    invoke-static {v2, v6}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    .line 940
    .line 941
    .line 942
    invoke-virtual/range {v24 .. v24}, Ljava/util/ArrayList;->clear()V

    .line 943
    .line 944
    .line 945
    invoke-virtual/range {v25 .. v25}, Ljava/util/ArrayList;->clear()V

    .line 946
    .line 947
    .line 948
    move/from16 v14, p2

    .line 949
    .line 950
    move-object/from16 v17, v1

    .line 951
    .line 952
    move v8, v5

    .line 953
    move-object/from16 v16, v9

    .line 954
    .line 955
    move/from16 v15, v21

    .line 956
    .line 957
    move-object/from16 v1, v22

    .line 958
    .line 959
    move-object/from16 v5, v23

    .line 960
    .line 961
    move-object/from16 v7, v24

    .line 962
    .line 963
    move-object/from16 v11, v25

    .line 964
    .line 965
    goto/16 :goto_c

    .line 966
    .line 967
    :cond_20
    move/from16 v14, p2

    .line 968
    .line 969
    move-object/from16 v17, v1

    .line 970
    .line 971
    move v8, v5

    .line 972
    move-object/from16 v16, v9

    .line 973
    .line 974
    move-object v6, v15

    .line 975
    :goto_14
    move/from16 v15, v21

    .line 976
    .line 977
    move-object/from16 v1, v22

    .line 978
    .line 979
    move-object/from16 v5, v23

    .line 980
    .line 981
    move-object/from16 v7, v24

    .line 982
    .line 983
    move-object/from16 v11, v25

    .line 984
    .line 985
    goto/16 :goto_d

    .line 986
    .line 987
    :cond_21
    new-instance v0, Ljava/lang/ClassCastException;

    .line 988
    .line 989
    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    .line 990
    .line 991
    .line 992
    throw v0

    .line 993
    :cond_22
    new-instance v0, Ljava/lang/ClassCastException;

    .line 994
    .line 995
    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    .line 996
    .line 997
    .line 998
    throw v0

    .line 999
    :cond_23
    move-object/from16 v22, v1

    .line 1000
    .line 1001
    move-object/from16 v23, v5

    .line 1002
    .line 1003
    move-object/from16 v24, v7

    .line 1004
    .line 1005
    move-object/from16 v25, v11

    .line 1006
    .line 1007
    const/4 v5, 0x0

    .line 1008
    goto :goto_15

    .line 1009
    :cond_24
    move-object/from16 v22, v1

    .line 1010
    .line 1011
    move-object/from16 v23, v5

    .line 1012
    .line 1013
    move-object/from16 v24, v7

    .line 1014
    .line 1015
    move v5, v8

    .line 1016
    move-object/from16 v25, v11

    .line 1017
    .line 1018
    :goto_15
    move/from16 v14, p2

    .line 1019
    .line 1020
    move v8, v5

    .line 1021
    goto :goto_14

    .line 1022
    :cond_25
    move-object/from16 v22, v1

    .line 1023
    .line 1024
    move-object/from16 v23, v5

    .line 1025
    .line 1026
    move-object/from16 v24, v7

    .line 1027
    .line 1028
    move v5, v8

    .line 1029
    move-object/from16 v25, v11

    .line 1030
    .line 1031
    move/from16 v21, v15

    .line 1032
    .line 1033
    if-nez v6, :cond_28

    .line 1034
    .line 1035
    invoke-virtual/range {v19 .. v19}, Ljava/util/ArrayList;->isEmpty()Z

    .line 1036
    .line 1037
    .line 1038
    move-result v1

    .line 1039
    if-eqz v1, :cond_27

    .line 1040
    .line 1041
    :cond_26
    move/from16 v16, p1

    .line 1042
    .line 1043
    :goto_16
    move-object v15, v2

    .line 1044
    goto :goto_19

    .line 1045
    :cond_27
    invoke-virtual/range {v19 .. v19}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 1046
    .line 1047
    .line 1048
    move-result-object v1

    .line 1049
    :goto_17
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 1050
    .line 1051
    .line 1052
    move-result v7

    .line 1053
    if-eqz v7, :cond_26

    .line 1054
    .line 1055
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1056
    .line 1057
    .line 1058
    move-result-object v7

    .line 1059
    check-cast v7, Landroidx/fragment/app/q;

    .line 1060
    .line 1061
    iget-object v7, v7, Landroidx/fragment/app/q;->b:Ljava/lang/Object;

    .line 1062
    .line 1063
    if-nez v7, :cond_28

    .line 1064
    .line 1065
    goto :goto_17

    .line 1066
    :cond_28
    new-instance v1, Landroidx/fragment/app/p;

    .line 1067
    .line 1068
    move/from16 v14, p2

    .line 1069
    .line 1070
    move-object v15, v2

    .line 1071
    move-object v9, v12

    .line 1072
    move-object/from16 v11, v16

    .line 1073
    .line 1074
    move-object/from16 v2, v19

    .line 1075
    .line 1076
    move-object/from16 v5, v23

    .line 1077
    .line 1078
    move-object/from16 v7, v24

    .line 1079
    .line 1080
    move-object/from16 v8, v25

    .line 1081
    .line 1082
    move/from16 v16, p1

    .line 1083
    .line 1084
    move-object v12, v10

    .line 1085
    move-object/from16 v10, v17

    .line 1086
    .line 1087
    invoke-direct/range {v1 .. v14}, Landroidx/fragment/app/p;-><init>(Ljava/util/ArrayList;Landroidx/fragment/app/g2;Landroidx/fragment/app/g2;Landroidx/fragment/app/b2;Ljava/lang/Object;Ljava/util/ArrayList;Ljava/util/ArrayList;Landroidx/collection/f;Ljava/util/ArrayList;Ljava/util/ArrayList;Landroidx/collection/f;Landroidx/collection/f;Z)V

    .line 1088
    .line 1089
    .line 1090
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 1091
    .line 1092
    .line 1093
    move-result-object v2

    .line 1094
    :goto_18
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 1095
    .line 1096
    .line 1097
    move-result v3

    .line 1098
    if-eqz v3, :cond_29

    .line 1099
    .line 1100
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1101
    .line 1102
    .line 1103
    move-result-object v3

    .line 1104
    check-cast v3, Landroidx/fragment/app/q;

    .line 1105
    .line 1106
    iget-object v3, v3, Landroidx/fragment/app/k;->a:Landroidx/fragment/app/g2;

    .line 1107
    .line 1108
    iget-object v3, v3, Landroidx/fragment/app/g2;->j:Ljava/util/ArrayList;

    .line 1109
    .line 1110
    invoke-virtual {v3, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1111
    .line 1112
    .line 1113
    goto :goto_18

    .line 1114
    :cond_29
    :goto_19
    new-instance v1, Ljava/util/ArrayList;

    .line 1115
    .line 1116
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 1117
    .line 1118
    .line 1119
    new-instance v2, Ljava/util/ArrayList;

    .line 1120
    .line 1121
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 1122
    .line 1123
    .line 1124
    invoke-virtual/range {v22 .. v22}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 1125
    .line 1126
    .line 1127
    move-result-object v3

    .line 1128
    :goto_1a
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 1129
    .line 1130
    .line 1131
    move-result v4

    .line 1132
    if-eqz v4, :cond_2a

    .line 1133
    .line 1134
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1135
    .line 1136
    .line 1137
    move-result-object v4

    .line 1138
    check-cast v4, Landroidx/fragment/app/f;

    .line 1139
    .line 1140
    iget-object v4, v4, Landroidx/fragment/app/k;->a:Landroidx/fragment/app/g2;

    .line 1141
    .line 1142
    iget-object v4, v4, Landroidx/fragment/app/g2;->k:Ljava/util/ArrayList;

    .line 1143
    .line 1144
    invoke-static {v4, v2}, Lmx0/q;->w(Ljava/lang/Iterable;Ljava/util/Collection;)V

    .line 1145
    .line 1146
    .line 1147
    goto :goto_1a

    .line 1148
    :cond_2a
    invoke-virtual {v2}, Ljava/util/ArrayList;->isEmpty()Z

    .line 1149
    .line 1150
    .line 1151
    move-result v2

    .line 1152
    invoke-virtual/range {v22 .. v22}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 1153
    .line 1154
    .line 1155
    move-result-object v3

    .line 1156
    const/4 v8, 0x0

    .line 1157
    :cond_2b
    :goto_1b
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 1158
    .line 1159
    .line 1160
    move-result v4

    .line 1161
    if-eqz v4, :cond_30

    .line 1162
    .line 1163
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1164
    .line 1165
    .line 1166
    move-result-object v4

    .line 1167
    check-cast v4, Landroidx/fragment/app/f;

    .line 1168
    .line 1169
    iget-object v5, v0, Landroidx/fragment/app/r;->a:Landroid/view/ViewGroup;

    .line 1170
    .line 1171
    invoke-virtual {v5}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 1172
    .line 1173
    .line 1174
    move-result-object v5

    .line 1175
    iget-object v6, v4, Landroidx/fragment/app/k;->a:Landroidx/fragment/app/g2;

    .line 1176
    .line 1177
    const-string v7, "context"

    .line 1178
    .line 1179
    invoke-static {v5, v7}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1180
    .line 1181
    .line 1182
    invoke-virtual {v4, v5}, Landroidx/fragment/app/f;->b(Landroid/content/Context;)Landroidx/fragment/app/p0;

    .line 1183
    .line 1184
    .line 1185
    move-result-object v5

    .line 1186
    if-nez v5, :cond_2c

    .line 1187
    .line 1188
    goto :goto_1b

    .line 1189
    :cond_2c
    iget-object v5, v5, Landroidx/fragment/app/p0;->b:Ljava/lang/Cloneable;

    .line 1190
    .line 1191
    check-cast v5, Landroid/animation/AnimatorSet;

    .line 1192
    .line 1193
    if-nez v5, :cond_2d

    .line 1194
    .line 1195
    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1196
    .line 1197
    .line 1198
    goto :goto_1b

    .line 1199
    :cond_2d
    iget-object v5, v6, Landroidx/fragment/app/g2;->c:Landroidx/fragment/app/j0;

    .line 1200
    .line 1201
    iget-object v7, v6, Landroidx/fragment/app/g2;->k:Ljava/util/ArrayList;

    .line 1202
    .line 1203
    invoke-virtual {v7}, Ljava/util/ArrayList;->isEmpty()Z

    .line 1204
    .line 1205
    .line 1206
    move-result v7

    .line 1207
    if-nez v7, :cond_2e

    .line 1208
    .line 1209
    invoke-static/range {v21 .. v21}, Landroidx/fragment/app/j1;->L(I)Z

    .line 1210
    .line 1211
    .line 1212
    move-result v4

    .line 1213
    if-eqz v4, :cond_2b

    .line 1214
    .line 1215
    new-instance v4, Ljava/lang/StringBuilder;

    .line 1216
    .line 1217
    const-string v6, "Ignoring Animator set on "

    .line 1218
    .line 1219
    invoke-direct {v4, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1220
    .line 1221
    .line 1222
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1223
    .line 1224
    .line 1225
    const-string v5, " as this Fragment was involved in a Transition."

    .line 1226
    .line 1227
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1228
    .line 1229
    .line 1230
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1231
    .line 1232
    .line 1233
    move-result-object v4

    .line 1234
    invoke-static {v15, v4}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 1235
    .line 1236
    .line 1237
    goto :goto_1b

    .line 1238
    :cond_2e
    iget v5, v6, Landroidx/fragment/app/g2;->a:I

    .line 1239
    .line 1240
    const/4 v7, 0x3

    .line 1241
    if-ne v5, v7, :cond_2f

    .line 1242
    .line 1243
    const/4 v5, 0x0

    .line 1244
    iput-boolean v5, v6, Landroidx/fragment/app/g2;->i:Z

    .line 1245
    .line 1246
    goto :goto_1c

    .line 1247
    :cond_2f
    const/4 v5, 0x0

    .line 1248
    :goto_1c
    new-instance v7, Landroidx/fragment/app/h;

    .line 1249
    .line 1250
    invoke-direct {v7, v4}, Landroidx/fragment/app/h;-><init>(Landroidx/fragment/app/f;)V

    .line 1251
    .line 1252
    .line 1253
    iget-object v4, v6, Landroidx/fragment/app/g2;->j:Ljava/util/ArrayList;

    .line 1254
    .line 1255
    invoke-virtual {v4, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1256
    .line 1257
    .line 1258
    move/from16 v8, v16

    .line 1259
    .line 1260
    goto :goto_1b

    .line 1261
    :cond_30
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 1262
    .line 1263
    .line 1264
    move-result-object v0

    .line 1265
    :cond_31
    :goto_1d
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 1266
    .line 1267
    .line 1268
    move-result v1

    .line 1269
    if-eqz v1, :cond_34

    .line 1270
    .line 1271
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1272
    .line 1273
    .line 1274
    move-result-object v1

    .line 1275
    check-cast v1, Landroidx/fragment/app/f;

    .line 1276
    .line 1277
    iget-object v3, v1, Landroidx/fragment/app/k;->a:Landroidx/fragment/app/g2;

    .line 1278
    .line 1279
    iget-object v4, v3, Landroidx/fragment/app/g2;->c:Landroidx/fragment/app/j0;

    .line 1280
    .line 1281
    const-string v5, "Ignoring Animation set on "

    .line 1282
    .line 1283
    if-nez v2, :cond_32

    .line 1284
    .line 1285
    invoke-static/range {v21 .. v21}, Landroidx/fragment/app/j1;->L(I)Z

    .line 1286
    .line 1287
    .line 1288
    move-result v1

    .line 1289
    if-eqz v1, :cond_31

    .line 1290
    .line 1291
    new-instance v1, Ljava/lang/StringBuilder;

    .line 1292
    .line 1293
    invoke-direct {v1, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1294
    .line 1295
    .line 1296
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1297
    .line 1298
    .line 1299
    const-string v3, " as Animations cannot run alongside Transitions."

    .line 1300
    .line 1301
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1302
    .line 1303
    .line 1304
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1305
    .line 1306
    .line 1307
    move-result-object v1

    .line 1308
    invoke-static {v15, v1}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 1309
    .line 1310
    .line 1311
    goto :goto_1d

    .line 1312
    :cond_32
    if-eqz v8, :cond_33

    .line 1313
    .line 1314
    invoke-static/range {v21 .. v21}, Landroidx/fragment/app/j1;->L(I)Z

    .line 1315
    .line 1316
    .line 1317
    move-result v1

    .line 1318
    if-eqz v1, :cond_31

    .line 1319
    .line 1320
    new-instance v1, Ljava/lang/StringBuilder;

    .line 1321
    .line 1322
    invoke-direct {v1, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1323
    .line 1324
    .line 1325
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1326
    .line 1327
    .line 1328
    const-string v3, " as Animations cannot run alongside Animators."

    .line 1329
    .line 1330
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1331
    .line 1332
    .line 1333
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1334
    .line 1335
    .line 1336
    move-result-object v1

    .line 1337
    invoke-static {v15, v1}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 1338
    .line 1339
    .line 1340
    goto :goto_1d

    .line 1341
    :cond_33
    new-instance v4, Landroidx/fragment/app/e;

    .line 1342
    .line 1343
    invoke-direct {v4, v1}, Landroidx/fragment/app/e;-><init>(Landroidx/fragment/app/f;)V

    .line 1344
    .line 1345
    .line 1346
    iget-object v1, v3, Landroidx/fragment/app/g2;->j:Ljava/util/ArrayList;

    .line 1347
    .line 1348
    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1349
    .line 1350
    .line 1351
    goto :goto_1d

    .line 1352
    :cond_34
    return-void
.end method

.method public final c(Ljava/util/List;)V
    .locals 7

    .line 1
    const-string v0, "operations"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    move-object v0, p1

    .line 7
    check-cast v0, Ljava/lang/Iterable;

    .line 8
    .line 9
    new-instance v1, Ljava/util/ArrayList;

    .line 10
    .line 11
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 12
    .line 13
    .line 14
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    if-eqz v3, :cond_0

    .line 23
    .line 24
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v3

    .line 28
    check-cast v3, Landroidx/fragment/app/g2;

    .line 29
    .line 30
    iget-object v3, v3, Landroidx/fragment/app/g2;->k:Ljava/util/ArrayList;

    .line 31
    .line 32
    invoke-static {v3, v1}, Lmx0/q;->w(Ljava/lang/Iterable;Ljava/util/Collection;)V

    .line 33
    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    invoke-static {v1}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    check-cast v1, Ljava/lang/Iterable;

    .line 41
    .line 42
    invoke-static {v1}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 43
    .line 44
    .line 45
    move-result-object v1

    .line 46
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 47
    .line 48
    .line 49
    move-result v2

    .line 50
    const/4 v3, 0x0

    .line 51
    move v4, v3

    .line 52
    :goto_1
    if-ge v4, v2, :cond_1

    .line 53
    .line 54
    invoke-interface {v1, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object v5

    .line 58
    check-cast v5, Landroidx/fragment/app/f2;

    .line 59
    .line 60
    iget-object v6, p0, Landroidx/fragment/app/r;->a:Landroid/view/ViewGroup;

    .line 61
    .line 62
    invoke-virtual {v5, v6}, Landroidx/fragment/app/f2;->c(Landroid/view/ViewGroup;)V

    .line 63
    .line 64
    .line 65
    add-int/lit8 v4, v4, 0x1

    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_1
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 69
    .line 70
    .line 71
    move-result v1

    .line 72
    move v2, v3

    .line 73
    :goto_2
    if-ge v2, v1, :cond_2

    .line 74
    .line 75
    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v4

    .line 79
    check-cast v4, Landroidx/fragment/app/g2;

    .line 80
    .line 81
    invoke-virtual {p0, v4}, Landroidx/fragment/app/r;->a(Landroidx/fragment/app/g2;)V

    .line 82
    .line 83
    .line 84
    add-int/lit8 v2, v2, 0x1

    .line 85
    .line 86
    goto :goto_2

    .line 87
    :cond_2
    invoke-static {v0}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 92
    .line 93
    .line 94
    move-result p1

    .line 95
    :goto_3
    if-ge v3, p1, :cond_4

    .line 96
    .line 97
    invoke-interface {p0, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v0

    .line 101
    check-cast v0, Landroidx/fragment/app/g2;

    .line 102
    .line 103
    iget-object v1, v0, Landroidx/fragment/app/g2;->k:Ljava/util/ArrayList;

    .line 104
    .line 105
    invoke-virtual {v1}, Ljava/util/ArrayList;->isEmpty()Z

    .line 106
    .line 107
    .line 108
    move-result v1

    .line 109
    if-eqz v1, :cond_3

    .line 110
    .line 111
    invoke-virtual {v0}, Landroidx/fragment/app/g2;->b()V

    .line 112
    .line 113
    .line 114
    :cond_3
    add-int/lit8 v3, v3, 0x1

    .line 115
    .line 116
    goto :goto_3

    .line 117
    :cond_4
    return-void
.end method

.method public final d(IILandroidx/fragment/app/r1;)V
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/fragment/app/r;->b:Ljava/util/ArrayList;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p3, Landroidx/fragment/app/r1;->c:Landroidx/fragment/app/j0;

    .line 5
    .line 6
    const-string v2, "fragmentStateManager.fragment"

    .line 7
    .line 8
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0, v1}, Landroidx/fragment/app/r;->g(Landroidx/fragment/app/j0;)Landroidx/fragment/app/g2;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    if-nez v1, :cond_2

    .line 16
    .line 17
    iget-object v1, p3, Landroidx/fragment/app/r1;->c:Landroidx/fragment/app/j0;

    .line 18
    .line 19
    iget-boolean v2, v1, Landroidx/fragment/app/j0;->mTransitioning:Z

    .line 20
    .line 21
    if-nez v2, :cond_1

    .line 22
    .line 23
    iget-boolean v2, v1, Landroidx/fragment/app/j0;->mRemoving:Z

    .line 24
    .line 25
    if-eqz v2, :cond_0

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 v1, 0x0

    .line 29
    goto :goto_1

    .line 30
    :catchall_0
    move-exception p0

    .line 31
    goto :goto_2

    .line 32
    :cond_1
    :goto_0
    invoke-virtual {p0, v1}, Landroidx/fragment/app/r;->h(Landroidx/fragment/app/j0;)Landroidx/fragment/app/g2;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    :cond_2
    :goto_1
    if-eqz v1, :cond_3

    .line 37
    .line 38
    invoke-virtual {v1, p1, p2}, Landroidx/fragment/app/g2;->d(II)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 39
    .line 40
    .line 41
    monitor-exit v0

    .line 42
    return-void

    .line 43
    :cond_3
    :try_start_1
    new-instance v1, Landroidx/fragment/app/g2;

    .line 44
    .line 45
    invoke-direct {v1, p1, p2, p3}, Landroidx/fragment/app/g2;-><init>(IILandroidx/fragment/app/r1;)V

    .line 46
    .line 47
    .line 48
    iget-object p1, p0, Landroidx/fragment/app/r;->b:Ljava/util/ArrayList;

    .line 49
    .line 50
    invoke-virtual {p1, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    new-instance p1, Landroidx/fragment/app/e2;

    .line 54
    .line 55
    const/4 p2, 0x0

    .line 56
    invoke-direct {p1, p0, v1, p2}, Landroidx/fragment/app/e2;-><init>(Landroidx/fragment/app/r;Landroidx/fragment/app/g2;I)V

    .line 57
    .line 58
    .line 59
    iget-object p2, v1, Landroidx/fragment/app/g2;->d:Ljava/util/ArrayList;

    .line 60
    .line 61
    invoke-virtual {p2, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    new-instance p1, Landroidx/fragment/app/e2;

    .line 65
    .line 66
    const/4 p2, 0x2

    .line 67
    invoke-direct {p1, p0, v1, p2}, Landroidx/fragment/app/e2;-><init>(Landroidx/fragment/app/r;Landroidx/fragment/app/g2;I)V

    .line 68
    .line 69
    .line 70
    iget-object p0, v1, Landroidx/fragment/app/g2;->d:Ljava/util/ArrayList;

    .line 71
    .line 72
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 73
    .line 74
    .line 75
    monitor-exit v0

    .line 76
    return-void

    .line 77
    :goto_2
    monitor-exit v0

    .line 78
    throw p0
.end method

.method public final e()V
    .locals 9

    .line 1
    iget-boolean v0, p0, Landroidx/fragment/app/r;->f:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    iget-object v0, p0, Landroidx/fragment/app/r;->a:Landroid/view/ViewGroup;

    .line 7
    .line 8
    invoke-virtual {v0}, Landroid/view/View;->isAttachedToWindow()Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    const/4 v1, 0x0

    .line 13
    if-nez v0, :cond_1

    .line 14
    .line 15
    invoke-virtual {p0}, Landroidx/fragment/app/r;->i()V

    .line 16
    .line 17
    .line 18
    iput-boolean v1, p0, Landroidx/fragment/app/r;->e:Z

    .line 19
    .line 20
    return-void

    .line 21
    :cond_1
    iget-object v0, p0, Landroidx/fragment/app/r;->b:Ljava/util/ArrayList;

    .line 22
    .line 23
    monitor-enter v0

    .line 24
    :try_start_0
    iget-object v2, p0, Landroidx/fragment/app/r;->c:Ljava/util/ArrayList;

    .line 25
    .line 26
    invoke-static {v2}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 27
    .line 28
    .line 29
    move-result-object v2

    .line 30
    iget-object v3, p0, Landroidx/fragment/app/r;->c:Ljava/util/ArrayList;

    .line 31
    .line 32
    invoke-virtual {v3}, Ljava/util/ArrayList;->clear()V

    .line 33
    .line 34
    .line 35
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 36
    .line 37
    .line 38
    move-result-object v3

    .line 39
    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 40
    .line 41
    .line 42
    move-result v4

    .line 43
    const/4 v5, 0x1

    .line 44
    if-eqz v4, :cond_3

    .line 45
    .line 46
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v4

    .line 50
    check-cast v4, Landroidx/fragment/app/g2;

    .line 51
    .line 52
    iget-object v6, p0, Landroidx/fragment/app/r;->b:Ljava/util/ArrayList;

    .line 53
    .line 54
    invoke-virtual {v6}, Ljava/util/ArrayList;->isEmpty()Z

    .line 55
    .line 56
    .line 57
    move-result v6

    .line 58
    if-nez v6, :cond_2

    .line 59
    .line 60
    iget-object v6, v4, Landroidx/fragment/app/g2;->c:Landroidx/fragment/app/j0;

    .line 61
    .line 62
    iget-boolean v6, v6, Landroidx/fragment/app/j0;->mTransitioning:Z

    .line 63
    .line 64
    if-eqz v6, :cond_2

    .line 65
    .line 66
    goto :goto_1

    .line 67
    :catchall_0
    move-exception p0

    .line 68
    goto/16 :goto_8

    .line 69
    .line 70
    :cond_2
    move v5, v1

    .line 71
    :goto_1
    iput-boolean v5, v4, Landroidx/fragment/app/g2;->g:Z

    .line 72
    .line 73
    goto :goto_0

    .line 74
    :cond_3
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 75
    .line 76
    .line 77
    move-result-object v2

    .line 78
    :cond_4
    :goto_2
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 79
    .line 80
    .line 81
    move-result v3

    .line 82
    const/4 v4, 0x2

    .line 83
    if-eqz v3, :cond_8

    .line 84
    .line 85
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v3

    .line 89
    check-cast v3, Landroidx/fragment/app/g2;

    .line 90
    .line 91
    iget-boolean v6, p0, Landroidx/fragment/app/r;->d:Z

    .line 92
    .line 93
    if-eqz v6, :cond_6

    .line 94
    .line 95
    invoke-static {v4}, Landroidx/fragment/app/j1;->L(I)Z

    .line 96
    .line 97
    .line 98
    move-result v4

    .line 99
    if-eqz v4, :cond_5

    .line 100
    .line 101
    const-string v4, "FragmentManager"

    .line 102
    .line 103
    new-instance v6, Ljava/lang/StringBuilder;

    .line 104
    .line 105
    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    .line 106
    .line 107
    .line 108
    const-string v7, "SpecialEffectsController: Completing non-seekable operation "

    .line 109
    .line 110
    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 111
    .line 112
    .line 113
    invoke-virtual {v6, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 114
    .line 115
    .line 116
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object v6

    .line 120
    invoke-static {v4, v6}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 121
    .line 122
    .line 123
    :cond_5
    invoke-virtual {v3}, Landroidx/fragment/app/g2;->b()V

    .line 124
    .line 125
    .line 126
    goto :goto_3

    .line 127
    :cond_6
    invoke-static {v4}, Landroidx/fragment/app/j1;->L(I)Z

    .line 128
    .line 129
    .line 130
    move-result v4

    .line 131
    if-eqz v4, :cond_7

    .line 132
    .line 133
    const-string v4, "FragmentManager"

    .line 134
    .line 135
    new-instance v6, Ljava/lang/StringBuilder;

    .line 136
    .line 137
    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    .line 138
    .line 139
    .line 140
    const-string v7, "SpecialEffectsController: Cancelling operation "

    .line 141
    .line 142
    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 143
    .line 144
    .line 145
    invoke-virtual {v6, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 146
    .line 147
    .line 148
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 149
    .line 150
    .line 151
    move-result-object v6

    .line 152
    invoke-static {v4, v6}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 153
    .line 154
    .line 155
    :cond_7
    iget-object v4, p0, Landroidx/fragment/app/r;->a:Landroid/view/ViewGroup;

    .line 156
    .line 157
    invoke-virtual {v3, v4}, Landroidx/fragment/app/g2;->a(Landroid/view/ViewGroup;)V

    .line 158
    .line 159
    .line 160
    :goto_3
    iput-boolean v1, p0, Landroidx/fragment/app/r;->d:Z

    .line 161
    .line 162
    iget-boolean v4, v3, Landroidx/fragment/app/g2;->f:Z

    .line 163
    .line 164
    if-nez v4, :cond_4

    .line 165
    .line 166
    iget-object v4, p0, Landroidx/fragment/app/r;->c:Ljava/util/ArrayList;

    .line 167
    .line 168
    invoke-virtual {v4, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 169
    .line 170
    .line 171
    goto :goto_2

    .line 172
    :cond_8
    iget-object v2, p0, Landroidx/fragment/app/r;->b:Ljava/util/ArrayList;

    .line 173
    .line 174
    invoke-virtual {v2}, Ljava/util/ArrayList;->isEmpty()Z

    .line 175
    .line 176
    .line 177
    move-result v2

    .line 178
    if-nez v2, :cond_11

    .line 179
    .line 180
    invoke-virtual {p0}, Landroidx/fragment/app/r;->n()V

    .line 181
    .line 182
    .line 183
    iget-object v2, p0, Landroidx/fragment/app/r;->b:Ljava/util/ArrayList;

    .line 184
    .line 185
    invoke-static {v2}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 186
    .line 187
    .line 188
    move-result-object v2

    .line 189
    invoke-virtual {v2}, Ljava/util/ArrayList;->isEmpty()Z

    .line 190
    .line 191
    .line 192
    move-result v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 193
    if-eqz v3, :cond_9

    .line 194
    .line 195
    monitor-exit v0

    .line 196
    return-void

    .line 197
    :cond_9
    :try_start_1
    iget-object v3, p0, Landroidx/fragment/app/r;->b:Ljava/util/ArrayList;

    .line 198
    .line 199
    invoke-virtual {v3}, Ljava/util/ArrayList;->clear()V

    .line 200
    .line 201
    .line 202
    iget-object v3, p0, Landroidx/fragment/app/r;->c:Ljava/util/ArrayList;

    .line 203
    .line 204
    invoke-virtual {v3, v2}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 205
    .line 206
    .line 207
    invoke-static {v4}, Landroidx/fragment/app/j1;->L(I)Z

    .line 208
    .line 209
    .line 210
    move-result v3

    .line 211
    if-eqz v3, :cond_a

    .line 212
    .line 213
    const-string v3, "FragmentManager"

    .line 214
    .line 215
    const-string v6, "SpecialEffectsController: Executing pending operations"

    .line 216
    .line 217
    invoke-static {v3, v6}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 218
    .line 219
    .line 220
    :cond_a
    iget-boolean v3, p0, Landroidx/fragment/app/r;->e:Z

    .line 221
    .line 222
    invoke-virtual {p0, v2, v3}, Landroidx/fragment/app/r;->b(Ljava/util/ArrayList;Z)V

    .line 223
    .line 224
    .line 225
    invoke-static {v2}, Landroidx/fragment/app/r;->k(Ljava/util/ArrayList;)Z

    .line 226
    .line 227
    .line 228
    move-result v3

    .line 229
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 230
    .line 231
    .line 232
    move-result-object v6

    .line 233
    move v7, v5

    .line 234
    :cond_b
    :goto_4
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 235
    .line 236
    .line 237
    move-result v8

    .line 238
    if-eqz v8, :cond_c

    .line 239
    .line 240
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 241
    .line 242
    .line 243
    move-result-object v8

    .line 244
    check-cast v8, Landroidx/fragment/app/g2;

    .line 245
    .line 246
    iget-object v8, v8, Landroidx/fragment/app/g2;->c:Landroidx/fragment/app/j0;

    .line 247
    .line 248
    iget-boolean v8, v8, Landroidx/fragment/app/j0;->mTransitioning:Z

    .line 249
    .line 250
    if-nez v8, :cond_b

    .line 251
    .line 252
    move v7, v1

    .line 253
    goto :goto_4

    .line 254
    :cond_c
    if-eqz v7, :cond_d

    .line 255
    .line 256
    if-nez v3, :cond_d

    .line 257
    .line 258
    goto :goto_5

    .line 259
    :cond_d
    move v5, v1

    .line 260
    :goto_5
    iput-boolean v5, p0, Landroidx/fragment/app/r;->d:Z

    .line 261
    .line 262
    invoke-static {v4}, Landroidx/fragment/app/j1;->L(I)Z

    .line 263
    .line 264
    .line 265
    move-result v5

    .line 266
    if-eqz v5, :cond_e

    .line 267
    .line 268
    const-string v5, "FragmentManager"

    .line 269
    .line 270
    new-instance v6, Ljava/lang/StringBuilder;

    .line 271
    .line 272
    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    .line 273
    .line 274
    .line 275
    const-string v8, "SpecialEffectsController: Operation seekable = "

    .line 276
    .line 277
    invoke-virtual {v6, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 278
    .line 279
    .line 280
    invoke-virtual {v6, v3}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 281
    .line 282
    .line 283
    const-string v8, " \ntransition = "

    .line 284
    .line 285
    invoke-virtual {v6, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 286
    .line 287
    .line 288
    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 289
    .line 290
    .line 291
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 292
    .line 293
    .line 294
    move-result-object v6

    .line 295
    invoke-static {v5, v6}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 296
    .line 297
    .line 298
    :cond_e
    if-nez v7, :cond_f

    .line 299
    .line 300
    invoke-virtual {p0, v2}, Landroidx/fragment/app/r;->m(Ljava/util/List;)V

    .line 301
    .line 302
    .line 303
    invoke-virtual {p0, v2}, Landroidx/fragment/app/r;->c(Ljava/util/List;)V

    .line 304
    .line 305
    .line 306
    goto :goto_7

    .line 307
    :cond_f
    if-eqz v3, :cond_10

    .line 308
    .line 309
    invoke-virtual {p0, v2}, Landroidx/fragment/app/r;->m(Ljava/util/List;)V

    .line 310
    .line 311
    .line 312
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 313
    .line 314
    .line 315
    move-result v3

    .line 316
    move v5, v1

    .line 317
    :goto_6
    if-ge v5, v3, :cond_10

    .line 318
    .line 319
    invoke-virtual {v2, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 320
    .line 321
    .line 322
    move-result-object v6

    .line 323
    check-cast v6, Landroidx/fragment/app/g2;

    .line 324
    .line 325
    invoke-virtual {p0, v6}, Landroidx/fragment/app/r;->a(Landroidx/fragment/app/g2;)V

    .line 326
    .line 327
    .line 328
    add-int/lit8 v5, v5, 0x1

    .line 329
    .line 330
    goto :goto_6

    .line 331
    :cond_10
    :goto_7
    iput-boolean v1, p0, Landroidx/fragment/app/r;->e:Z

    .line 332
    .line 333
    invoke-static {v4}, Landroidx/fragment/app/j1;->L(I)Z

    .line 334
    .line 335
    .line 336
    move-result p0

    .line 337
    if-eqz p0, :cond_11

    .line 338
    .line 339
    const-string p0, "FragmentManager"

    .line 340
    .line 341
    const-string v1, "SpecialEffectsController: Finished executing pending operations"

    .line 342
    .line 343
    invoke-static {p0, v1}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 344
    .line 345
    .line 346
    :cond_11
    monitor-exit v0

    .line 347
    return-void

    .line 348
    :goto_8
    monitor-exit v0

    .line 349
    throw p0
.end method

.method public final g(Landroidx/fragment/app/j0;)Landroidx/fragment/app/g2;
    .locals 3

    .line 1
    iget-object p0, p0, Landroidx/fragment/app/r;->b:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    :cond_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_1

    .line 12
    .line 13
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    move-object v1, v0

    .line 18
    check-cast v1, Landroidx/fragment/app/g2;

    .line 19
    .line 20
    iget-object v2, v1, Landroidx/fragment/app/g2;->c:Landroidx/fragment/app/j0;

    .line 21
    .line 22
    invoke-static {v2, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    if-eqz v2, :cond_0

    .line 27
    .line 28
    iget-boolean v1, v1, Landroidx/fragment/app/g2;->e:Z

    .line 29
    .line 30
    if-nez v1, :cond_0

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_1
    const/4 v0, 0x0

    .line 34
    :goto_0
    check-cast v0, Landroidx/fragment/app/g2;

    .line 35
    .line 36
    return-object v0
.end method

.method public final h(Landroidx/fragment/app/j0;)Landroidx/fragment/app/g2;
    .locals 3

    .line 1
    iget-object p0, p0, Landroidx/fragment/app/r;->c:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    :cond_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_1

    .line 12
    .line 13
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    move-object v1, v0

    .line 18
    check-cast v1, Landroidx/fragment/app/g2;

    .line 19
    .line 20
    iget-object v2, v1, Landroidx/fragment/app/g2;->c:Landroidx/fragment/app/j0;

    .line 21
    .line 22
    invoke-static {v2, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    if-eqz v2, :cond_0

    .line 27
    .line 28
    iget-boolean v1, v1, Landroidx/fragment/app/g2;->e:Z

    .line 29
    .line 30
    if-nez v1, :cond_0

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_1
    const/4 v0, 0x0

    .line 34
    :goto_0
    check-cast v0, Landroidx/fragment/app/g2;

    .line 35
    .line 36
    return-object v0
.end method

.method public final i()V
    .locals 10

    .line 1
    const/4 v0, 0x2

    .line 2
    invoke-static {v0}, Landroidx/fragment/app/j1;->L(I)Z

    .line 3
    .line 4
    .line 5
    move-result v1

    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    const-string v1, "FragmentManager"

    .line 9
    .line 10
    const-string v2, "SpecialEffectsController: Forcing all operations to complete"

    .line 11
    .line 12
    invoke-static {v1, v2}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 13
    .line 14
    .line 15
    :cond_0
    iget-object v1, p0, Landroidx/fragment/app/r;->a:Landroid/view/ViewGroup;

    .line 16
    .line 17
    invoke-virtual {v1}, Landroid/view/View;->isAttachedToWindow()Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    iget-object v2, p0, Landroidx/fragment/app/r;->b:Ljava/util/ArrayList;

    .line 22
    .line 23
    monitor-enter v2

    .line 24
    :try_start_0
    invoke-virtual {p0}, Landroidx/fragment/app/r;->n()V

    .line 25
    .line 26
    .line 27
    iget-object v3, p0, Landroidx/fragment/app/r;->b:Ljava/util/ArrayList;

    .line 28
    .line 29
    invoke-virtual {p0, v3}, Landroidx/fragment/app/r;->m(Ljava/util/List;)V

    .line 30
    .line 31
    .line 32
    iget-object v3, p0, Landroidx/fragment/app/r;->c:Ljava/util/ArrayList;

    .line 33
    .line 34
    invoke-static {v3}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 35
    .line 36
    .line 37
    move-result-object v3

    .line 38
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 39
    .line 40
    .line 41
    move-result-object v4

    .line 42
    :goto_0
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 43
    .line 44
    .line 45
    move-result v5

    .line 46
    const/4 v6, 0x0

    .line 47
    if-eqz v5, :cond_1

    .line 48
    .line 49
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v5

    .line 53
    check-cast v5, Landroidx/fragment/app/g2;

    .line 54
    .line 55
    iput-boolean v6, v5, Landroidx/fragment/app/g2;->g:Z

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :catchall_0
    move-exception p0

    .line 59
    goto/16 :goto_6

    .line 60
    .line 61
    :cond_1
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 62
    .line 63
    .line 64
    move-result-object v3

    .line 65
    :goto_1
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 66
    .line 67
    .line 68
    move-result v4

    .line 69
    if-eqz v4, :cond_4

    .line 70
    .line 71
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v4

    .line 75
    check-cast v4, Landroidx/fragment/app/g2;

    .line 76
    .line 77
    invoke-static {v0}, Landroidx/fragment/app/j1;->L(I)Z

    .line 78
    .line 79
    .line 80
    move-result v5

    .line 81
    if-eqz v5, :cond_3

    .line 82
    .line 83
    if-eqz v1, :cond_2

    .line 84
    .line 85
    const-string v5, ""

    .line 86
    .line 87
    goto :goto_2

    .line 88
    :cond_2
    new-instance v5, Ljava/lang/StringBuilder;

    .line 89
    .line 90
    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    .line 91
    .line 92
    .line 93
    const-string v7, "Container "

    .line 94
    .line 95
    invoke-virtual {v5, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    iget-object v7, p0, Landroidx/fragment/app/r;->a:Landroid/view/ViewGroup;

    .line 99
    .line 100
    invoke-virtual {v5, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    const-string v7, " is not attached to window. "

    .line 104
    .line 105
    invoke-virtual {v5, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 109
    .line 110
    .line 111
    move-result-object v5

    .line 112
    :goto_2
    const-string v7, "FragmentManager"

    .line 113
    .line 114
    new-instance v8, Ljava/lang/StringBuilder;

    .line 115
    .line 116
    invoke-direct {v8}, Ljava/lang/StringBuilder;-><init>()V

    .line 117
    .line 118
    .line 119
    const-string v9, "SpecialEffectsController: "

    .line 120
    .line 121
    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 122
    .line 123
    .line 124
    invoke-virtual {v8, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 125
    .line 126
    .line 127
    const-string v5, "Cancelling running operation "

    .line 128
    .line 129
    invoke-virtual {v8, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 130
    .line 131
    .line 132
    invoke-virtual {v8, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 133
    .line 134
    .line 135
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 136
    .line 137
    .line 138
    move-result-object v5

    .line 139
    invoke-static {v7, v5}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 140
    .line 141
    .line 142
    :cond_3
    iget-object v5, p0, Landroidx/fragment/app/r;->a:Landroid/view/ViewGroup;

    .line 143
    .line 144
    invoke-virtual {v4, v5}, Landroidx/fragment/app/g2;->a(Landroid/view/ViewGroup;)V

    .line 145
    .line 146
    .line 147
    goto :goto_1

    .line 148
    :cond_4
    iget-object v3, p0, Landroidx/fragment/app/r;->b:Ljava/util/ArrayList;

    .line 149
    .line 150
    invoke-static {v3}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 151
    .line 152
    .line 153
    move-result-object v3

    .line 154
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 155
    .line 156
    .line 157
    move-result-object v4

    .line 158
    :goto_3
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 159
    .line 160
    .line 161
    move-result v5

    .line 162
    if-eqz v5, :cond_5

    .line 163
    .line 164
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object v5

    .line 168
    check-cast v5, Landroidx/fragment/app/g2;

    .line 169
    .line 170
    iput-boolean v6, v5, Landroidx/fragment/app/g2;->g:Z

    .line 171
    .line 172
    goto :goto_3

    .line 173
    :cond_5
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 174
    .line 175
    .line 176
    move-result-object v3

    .line 177
    :goto_4
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 178
    .line 179
    .line 180
    move-result v4

    .line 181
    if-eqz v4, :cond_8

    .line 182
    .line 183
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 184
    .line 185
    .line 186
    move-result-object v4

    .line 187
    check-cast v4, Landroidx/fragment/app/g2;

    .line 188
    .line 189
    invoke-static {v0}, Landroidx/fragment/app/j1;->L(I)Z

    .line 190
    .line 191
    .line 192
    move-result v5

    .line 193
    if-eqz v5, :cond_7

    .line 194
    .line 195
    if-eqz v1, :cond_6

    .line 196
    .line 197
    const-string v5, ""

    .line 198
    .line 199
    goto :goto_5

    .line 200
    :cond_6
    new-instance v5, Ljava/lang/StringBuilder;

    .line 201
    .line 202
    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    .line 203
    .line 204
    .line 205
    const-string v6, "Container "

    .line 206
    .line 207
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 208
    .line 209
    .line 210
    iget-object v6, p0, Landroidx/fragment/app/r;->a:Landroid/view/ViewGroup;

    .line 211
    .line 212
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 213
    .line 214
    .line 215
    const-string v6, " is not attached to window. "

    .line 216
    .line 217
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 218
    .line 219
    .line 220
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 221
    .line 222
    .line 223
    move-result-object v5

    .line 224
    :goto_5
    const-string v6, "FragmentManager"

    .line 225
    .line 226
    new-instance v7, Ljava/lang/StringBuilder;

    .line 227
    .line 228
    invoke-direct {v7}, Ljava/lang/StringBuilder;-><init>()V

    .line 229
    .line 230
    .line 231
    const-string v8, "SpecialEffectsController: "

    .line 232
    .line 233
    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 234
    .line 235
    .line 236
    invoke-virtual {v7, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 237
    .line 238
    .line 239
    const-string v5, "Cancelling pending operation "

    .line 240
    .line 241
    invoke-virtual {v7, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 242
    .line 243
    .line 244
    invoke-virtual {v7, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 245
    .line 246
    .line 247
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 248
    .line 249
    .line 250
    move-result-object v5

    .line 251
    invoke-static {v6, v5}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 252
    .line 253
    .line 254
    :cond_7
    iget-object v5, p0, Landroidx/fragment/app/r;->a:Landroid/view/ViewGroup;

    .line 255
    .line 256
    invoke-virtual {v4, v5}, Landroidx/fragment/app/g2;->a(Landroid/view/ViewGroup;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 257
    .line 258
    .line 259
    goto :goto_4

    .line 260
    :cond_8
    monitor-exit v2

    .line 261
    return-void

    .line 262
    :goto_6
    monitor-exit v2

    .line 263
    throw p0
.end method

.method public final l()V
    .locals 9

    .line 1
    iget-object v0, p0, Landroidx/fragment/app/r;->b:Ljava/util/ArrayList;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    invoke-virtual {p0}, Landroidx/fragment/app/r;->n()V

    .line 5
    .line 6
    .line 7
    iget-object v1, p0, Landroidx/fragment/app/r;->b:Ljava/util/ArrayList;

    .line 8
    .line 9
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->listIterator(I)Ljava/util/ListIterator;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    :cond_0
    invoke-interface {v1}, Ljava/util/ListIterator;->hasPrevious()Z

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    const/4 v3, 0x0

    .line 22
    if-eqz v2, :cond_5

    .line 23
    .line 24
    invoke-interface {v1}, Ljava/util/ListIterator;->previous()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v2

    .line 28
    move-object v4, v2

    .line 29
    check-cast v4, Landroidx/fragment/app/g2;

    .line 30
    .line 31
    iget-object v5, v4, Landroidx/fragment/app/g2;->c:Landroidx/fragment/app/j0;

    .line 32
    .line 33
    iget-object v5, v5, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 34
    .line 35
    const-string v6, "operation.fragment.mView"

    .line 36
    .line 37
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {v5}, Landroid/view/View;->getAlpha()F

    .line 41
    .line 42
    .line 43
    move-result v6

    .line 44
    const/4 v7, 0x0

    .line 45
    cmpg-float v6, v6, v7

    .line 46
    .line 47
    const/4 v7, 0x2

    .line 48
    const/4 v8, 0x4

    .line 49
    if-nez v6, :cond_1

    .line 50
    .line 51
    invoke-virtual {v5}, Landroid/view/View;->getVisibility()I

    .line 52
    .line 53
    .line 54
    move-result v6

    .line 55
    if-nez v6, :cond_1

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_1
    invoke-virtual {v5}, Landroid/view/View;->getVisibility()I

    .line 59
    .line 60
    .line 61
    move-result v5

    .line 62
    if-eqz v5, :cond_3

    .line 63
    .line 64
    if-eq v5, v8, :cond_4

    .line 65
    .line 66
    const/16 v6, 0x8

    .line 67
    .line 68
    if-ne v5, v6, :cond_2

    .line 69
    .line 70
    const/4 v8, 0x3

    .line 71
    goto :goto_0

    .line 72
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 73
    .line 74
    new-instance v1, Ljava/lang/StringBuilder;

    .line 75
    .line 76
    const-string v2, "Unknown visibility "

    .line 77
    .line 78
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {v1, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object v1

    .line 88
    invoke-direct {p0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    throw p0

    .line 92
    :cond_3
    move v8, v7

    .line 93
    :cond_4
    :goto_0
    iget v4, v4, Landroidx/fragment/app/g2;->a:I

    .line 94
    .line 95
    if-ne v4, v7, :cond_0

    .line 96
    .line 97
    if-eq v8, v7, :cond_0

    .line 98
    .line 99
    goto :goto_1

    .line 100
    :catchall_0
    move-exception p0

    .line 101
    goto :goto_3

    .line 102
    :cond_5
    move-object v2, v3

    .line 103
    :goto_1
    check-cast v2, Landroidx/fragment/app/g2;

    .line 104
    .line 105
    if-eqz v2, :cond_6

    .line 106
    .line 107
    iget-object v3, v2, Landroidx/fragment/app/g2;->c:Landroidx/fragment/app/j0;

    .line 108
    .line 109
    :cond_6
    if-eqz v3, :cond_7

    .line 110
    .line 111
    invoke-virtual {v3}, Landroidx/fragment/app/j0;->isPostponed()Z

    .line 112
    .line 113
    .line 114
    move-result v1

    .line 115
    goto :goto_2

    .line 116
    :cond_7
    const/4 v1, 0x0

    .line 117
    :goto_2
    iput-boolean v1, p0, Landroidx/fragment/app/r;->f:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 118
    .line 119
    monitor-exit v0

    .line 120
    return-void

    .line 121
    :goto_3
    monitor-exit v0

    .line 122
    throw p0
.end method

.method public final m(Ljava/util/List;)V
    .locals 12

    .line 1
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    move v2, v1

    .line 7
    :goto_0
    const/4 v3, 0x1

    .line 8
    if-ge v2, v0, :cond_9

    .line 9
    .line 10
    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v4

    .line 14
    check-cast v4, Landroidx/fragment/app/g2;

    .line 15
    .line 16
    iget-object v5, v4, Landroidx/fragment/app/g2;->l:Landroidx/fragment/app/r1;

    .line 17
    .line 18
    iget-boolean v6, v4, Landroidx/fragment/app/g2;->h:Z

    .line 19
    .line 20
    if-eqz v6, :cond_0

    .line 21
    .line 22
    goto/16 :goto_1

    .line 23
    .line 24
    :cond_0
    iput-boolean v3, v4, Landroidx/fragment/app/g2;->h:Z

    .line 25
    .line 26
    iget v3, v4, Landroidx/fragment/app/g2;->b:I

    .line 27
    .line 28
    const/4 v6, 0x2

    .line 29
    const-string v7, " for Fragment "

    .line 30
    .line 31
    const-string v8, "fragmentStateManager.fragment"

    .line 32
    .line 33
    const-string v9, "FragmentManager"

    .line 34
    .line 35
    if-ne v3, v6, :cond_6

    .line 36
    .line 37
    iget-object v3, v5, Landroidx/fragment/app/r1;->c:Landroidx/fragment/app/j0;

    .line 38
    .line 39
    invoke-static {v3, v8}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    iget-object v8, v3, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 43
    .line 44
    invoke-virtual {v8}, Landroid/view/View;->findFocus()Landroid/view/View;

    .line 45
    .line 46
    .line 47
    move-result-object v8

    .line 48
    if-eqz v8, :cond_1

    .line 49
    .line 50
    invoke-virtual {v3, v8}, Landroidx/fragment/app/j0;->setFocusedView(Landroid/view/View;)V

    .line 51
    .line 52
    .line 53
    invoke-static {v6}, Landroidx/fragment/app/j1;->L(I)Z

    .line 54
    .line 55
    .line 56
    move-result v10

    .line 57
    if-eqz v10, :cond_1

    .line 58
    .line 59
    new-instance v10, Ljava/lang/StringBuilder;

    .line 60
    .line 61
    const-string v11, "requestFocus: Saved focused view "

    .line 62
    .line 63
    invoke-direct {v10, v11}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {v10, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    invoke-virtual {v10, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    invoke-virtual {v10, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    invoke-virtual {v10}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object v7

    .line 79
    invoke-static {v9, v7}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 80
    .line 81
    .line 82
    :cond_1
    iget-object v4, v4, Landroidx/fragment/app/g2;->c:Landroidx/fragment/app/j0;

    .line 83
    .line 84
    invoke-virtual {v4}, Landroidx/fragment/app/j0;->requireView()Landroid/view/View;

    .line 85
    .line 86
    .line 87
    move-result-object v4

    .line 88
    const-string v7, "this.fragment.requireView()"

    .line 89
    .line 90
    invoke-static {v4, v7}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {v4}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 94
    .line 95
    .line 96
    move-result-object v7

    .line 97
    const/4 v8, 0x0

    .line 98
    if-nez v7, :cond_3

    .line 99
    .line 100
    invoke-static {v6}, Landroidx/fragment/app/j1;->L(I)Z

    .line 101
    .line 102
    .line 103
    move-result v7

    .line 104
    if-eqz v7, :cond_2

    .line 105
    .line 106
    new-instance v7, Ljava/lang/StringBuilder;

    .line 107
    .line 108
    const-string v10, "Adding fragment "

    .line 109
    .line 110
    invoke-direct {v7, v10}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 111
    .line 112
    .line 113
    invoke-virtual {v7, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 114
    .line 115
    .line 116
    const-string v10, " view "

    .line 117
    .line 118
    invoke-virtual {v7, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 119
    .line 120
    .line 121
    invoke-virtual {v7, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 122
    .line 123
    .line 124
    const-string v10, " to container in onStart"

    .line 125
    .line 126
    invoke-virtual {v7, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 127
    .line 128
    .line 129
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 130
    .line 131
    .line 132
    move-result-object v7

    .line 133
    invoke-static {v9, v7}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 134
    .line 135
    .line 136
    :cond_2
    invoke-virtual {v5}, Landroidx/fragment/app/r1;->b()V

    .line 137
    .line 138
    .line 139
    invoke-virtual {v4, v8}, Landroid/view/View;->setAlpha(F)V

    .line 140
    .line 141
    .line 142
    :cond_3
    invoke-virtual {v4}, Landroid/view/View;->getAlpha()F

    .line 143
    .line 144
    .line 145
    move-result v5

    .line 146
    cmpg-float v5, v5, v8

    .line 147
    .line 148
    if-nez v5, :cond_5

    .line 149
    .line 150
    invoke-virtual {v4}, Landroid/view/View;->getVisibility()I

    .line 151
    .line 152
    .line 153
    move-result v5

    .line 154
    if-nez v5, :cond_5

    .line 155
    .line 156
    invoke-static {v6}, Landroidx/fragment/app/j1;->L(I)Z

    .line 157
    .line 158
    .line 159
    move-result v5

    .line 160
    if-eqz v5, :cond_4

    .line 161
    .line 162
    new-instance v5, Ljava/lang/StringBuilder;

    .line 163
    .line 164
    const-string v7, "Making view "

    .line 165
    .line 166
    invoke-direct {v5, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 167
    .line 168
    .line 169
    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 170
    .line 171
    .line 172
    const-string v7, " INVISIBLE in onStart"

    .line 173
    .line 174
    invoke-virtual {v5, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 175
    .line 176
    .line 177
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 178
    .line 179
    .line 180
    move-result-object v5

    .line 181
    invoke-static {v9, v5}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 182
    .line 183
    .line 184
    :cond_4
    const/4 v5, 0x4

    .line 185
    invoke-virtual {v4, v5}, Landroid/view/View;->setVisibility(I)V

    .line 186
    .line 187
    .line 188
    :cond_5
    invoke-virtual {v3}, Landroidx/fragment/app/j0;->getPostOnViewCreatedAlpha()F

    .line 189
    .line 190
    .line 191
    move-result v5

    .line 192
    invoke-virtual {v4, v5}, Landroid/view/View;->setAlpha(F)V

    .line 193
    .line 194
    .line 195
    invoke-static {v6}, Landroidx/fragment/app/j1;->L(I)Z

    .line 196
    .line 197
    .line 198
    move-result v4

    .line 199
    if-eqz v4, :cond_8

    .line 200
    .line 201
    new-instance v4, Ljava/lang/StringBuilder;

    .line 202
    .line 203
    const-string v5, "Setting view alpha to "

    .line 204
    .line 205
    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 206
    .line 207
    .line 208
    invoke-virtual {v3}, Landroidx/fragment/app/j0;->getPostOnViewCreatedAlpha()F

    .line 209
    .line 210
    .line 211
    move-result v3

    .line 212
    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 213
    .line 214
    .line 215
    const-string v3, " in onStart"

    .line 216
    .line 217
    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 218
    .line 219
    .line 220
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 221
    .line 222
    .line 223
    move-result-object v3

    .line 224
    invoke-static {v9, v3}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 225
    .line 226
    .line 227
    goto :goto_1

    .line 228
    :cond_6
    const/4 v4, 0x3

    .line 229
    if-ne v3, v4, :cond_8

    .line 230
    .line 231
    iget-object v3, v5, Landroidx/fragment/app/r1;->c:Landroidx/fragment/app/j0;

    .line 232
    .line 233
    invoke-static {v3, v8}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 234
    .line 235
    .line 236
    invoke-virtual {v3}, Landroidx/fragment/app/j0;->requireView()Landroid/view/View;

    .line 237
    .line 238
    .line 239
    move-result-object v4

    .line 240
    const-string v5, "fragment.requireView()"

    .line 241
    .line 242
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 243
    .line 244
    .line 245
    invoke-static {v6}, Landroidx/fragment/app/j1;->L(I)Z

    .line 246
    .line 247
    .line 248
    move-result v5

    .line 249
    if-eqz v5, :cond_7

    .line 250
    .line 251
    new-instance v5, Ljava/lang/StringBuilder;

    .line 252
    .line 253
    const-string v6, "Clearing focus "

    .line 254
    .line 255
    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 256
    .line 257
    .line 258
    invoke-virtual {v4}, Landroid/view/View;->findFocus()Landroid/view/View;

    .line 259
    .line 260
    .line 261
    move-result-object v6

    .line 262
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 263
    .line 264
    .line 265
    const-string v6, " on view "

    .line 266
    .line 267
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 268
    .line 269
    .line 270
    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 271
    .line 272
    .line 273
    invoke-virtual {v5, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 274
    .line 275
    .line 276
    invoke-virtual {v5, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 277
    .line 278
    .line 279
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 280
    .line 281
    .line 282
    move-result-object v3

    .line 283
    invoke-static {v9, v3}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 284
    .line 285
    .line 286
    :cond_7
    invoke-virtual {v4}, Landroid/view/View;->clearFocus()V

    .line 287
    .line 288
    .line 289
    :cond_8
    :goto_1
    add-int/lit8 v2, v2, 0x1

    .line 290
    .line 291
    goto/16 :goto_0

    .line 292
    .line 293
    :cond_9
    check-cast p1, Ljava/lang/Iterable;

    .line 294
    .line 295
    new-instance v0, Ljava/util/ArrayList;

    .line 296
    .line 297
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 298
    .line 299
    .line 300
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 301
    .line 302
    .line 303
    move-result-object p1

    .line 304
    :goto_2
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 305
    .line 306
    .line 307
    move-result v2

    .line 308
    if-eqz v2, :cond_a

    .line 309
    .line 310
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 311
    .line 312
    .line 313
    move-result-object v2

    .line 314
    check-cast v2, Landroidx/fragment/app/g2;

    .line 315
    .line 316
    iget-object v2, v2, Landroidx/fragment/app/g2;->k:Ljava/util/ArrayList;

    .line 317
    .line 318
    invoke-static {v2, v0}, Lmx0/q;->w(Ljava/lang/Iterable;Ljava/util/Collection;)V

    .line 319
    .line 320
    .line 321
    goto :goto_2

    .line 322
    :cond_a
    invoke-static {v0}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 323
    .line 324
    .line 325
    move-result-object p1

    .line 326
    check-cast p1, Ljava/lang/Iterable;

    .line 327
    .line 328
    invoke-static {p1}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 329
    .line 330
    .line 331
    move-result-object p1

    .line 332
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 333
    .line 334
    .line 335
    move-result v0

    .line 336
    :goto_3
    if-ge v1, v0, :cond_c

    .line 337
    .line 338
    invoke-interface {p1, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 339
    .line 340
    .line 341
    move-result-object v2

    .line 342
    check-cast v2, Landroidx/fragment/app/f2;

    .line 343
    .line 344
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 345
    .line 346
    .line 347
    const-string v4, "container"

    .line 348
    .line 349
    iget-object v5, p0, Landroidx/fragment/app/r;->a:Landroid/view/ViewGroup;

    .line 350
    .line 351
    invoke-static {v5, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 352
    .line 353
    .line 354
    iget-boolean v4, v2, Landroidx/fragment/app/f2;->a:Z

    .line 355
    .line 356
    if-nez v4, :cond_b

    .line 357
    .line 358
    invoke-virtual {v2, v5}, Landroidx/fragment/app/f2;->e(Landroid/view/ViewGroup;)V

    .line 359
    .line 360
    .line 361
    :cond_b
    iput-boolean v3, v2, Landroidx/fragment/app/f2;->a:Z

    .line 362
    .line 363
    add-int/lit8 v1, v1, 0x1

    .line 364
    .line 365
    goto :goto_3

    .line 366
    :cond_c
    return-void
.end method

.method public final n()V
    .locals 4

    .line 1
    iget-object p0, p0, Landroidx/fragment/app/r;->b:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_3

    .line 12
    .line 13
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    check-cast v0, Landroidx/fragment/app/g2;

    .line 18
    .line 19
    iget v1, v0, Landroidx/fragment/app/g2;->b:I

    .line 20
    .line 21
    const/4 v2, 0x2

    .line 22
    if-ne v1, v2, :cond_0

    .line 23
    .line 24
    iget-object v1, v0, Landroidx/fragment/app/g2;->c:Landroidx/fragment/app/j0;

    .line 25
    .line 26
    invoke-virtual {v1}, Landroidx/fragment/app/j0;->requireView()Landroid/view/View;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    const-string v3, "fragment.requireView()"

    .line 31
    .line 32
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {v1}, Landroid/view/View;->getVisibility()I

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    if-eqz v1, :cond_2

    .line 40
    .line 41
    const/4 v2, 0x4

    .line 42
    if-eq v1, v2, :cond_2

    .line 43
    .line 44
    const/16 v2, 0x8

    .line 45
    .line 46
    if-ne v1, v2, :cond_1

    .line 47
    .line 48
    const/4 v2, 0x3

    .line 49
    goto :goto_1

    .line 50
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 51
    .line 52
    const-string v0, "Unknown visibility "

    .line 53
    .line 54
    invoke-static {v1, v0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    throw p0

    .line 62
    :cond_2
    :goto_1
    const/4 v1, 0x1

    .line 63
    invoke-virtual {v0, v2, v1}, Landroidx/fragment/app/g2;->d(II)V

    .line 64
    .line 65
    .line 66
    goto :goto_0

    .line 67
    :cond_3
    return-void
.end method
