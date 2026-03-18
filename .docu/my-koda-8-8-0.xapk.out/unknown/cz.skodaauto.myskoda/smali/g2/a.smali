.class public final Lg2/a;
.super Lx2/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/l;
.implements Lv3/p;
.implements Lv3/x;


# instance fields
.field public final A:Landroidx/collection/l0;

.field public B:Lg2/d;

.field public C:Lg2/e;

.field public final r:Li1/l;

.field public final s:Z

.field public final t:F

.field public final u:Le3/t;

.field public final v:Lay0/a;

.field public w:Lvv0/d;

.field public x:F

.field public y:J

.field public z:Z


# direct methods
.method public constructor <init>(Li1/l;ZFLe3/t;Lay0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lx2/r;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lg2/a;->r:Li1/l;

    .line 5
    .line 6
    iput-boolean p2, p0, Lg2/a;->s:Z

    .line 7
    .line 8
    iput p3, p0, Lg2/a;->t:F

    .line 9
    .line 10
    iput-object p4, p0, Lg2/a;->u:Le3/t;

    .line 11
    .line 12
    iput-object p5, p0, Lg2/a;->v:Lay0/a;

    .line 13
    .line 14
    const-wide/16 p1, 0x0

    .line 15
    .line 16
    iput-wide p1, p0, Lg2/a;->y:J

    .line 17
    .line 18
    new-instance p1, Landroidx/collection/l0;

    .line 19
    .line 20
    invoke-direct {p1}, Landroidx/collection/l0;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object p1, p0, Lg2/a;->A:Landroidx/collection/l0;

    .line 24
    .line 25
    return-void
.end method


# virtual methods
.method public final C0(Lv3/j0;)V
    .locals 14

    .line 1
    iget-object v0, p1, Lv3/j0;->d:Lg3/b;

    .line 2
    .line 3
    invoke-virtual {p1}, Lv3/j0;->b()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lg2/a;->w:Lvv0/d;

    .line 7
    .line 8
    if-eqz v1, :cond_1

    .line 9
    .line 10
    iget v5, p0, Lg2/a;->x:F

    .line 11
    .line 12
    iget-object v2, p0, Lg2/a;->u:Le3/t;

    .line 13
    .line 14
    invoke-interface {v2}, Le3/t;->a()J

    .line 15
    .line 16
    .line 17
    move-result-wide v2

    .line 18
    iget-object v4, v1, Lvv0/d;->c:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v4, Lc1/c;

    .line 21
    .line 22
    invoke-virtual {v4}, Lc1/c;->d()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v4

    .line 26
    check-cast v4, Ljava/lang/Number;

    .line 27
    .line 28
    invoke-virtual {v4}, Ljava/lang/Number;->floatValue()F

    .line 29
    .line 30
    .line 31
    move-result v4

    .line 32
    const/4 v6, 0x0

    .line 33
    cmpl-float v6, v4, v6

    .line 34
    .line 35
    if-lez v6, :cond_1

    .line 36
    .line 37
    invoke-static {v2, v3, v4}, Le3/s;->b(JF)J

    .line 38
    .line 39
    .line 40
    move-result-wide v3

    .line 41
    iget-boolean v1, v1, Lvv0/d;->a:Z

    .line 42
    .line 43
    if-eqz v1, :cond_0

    .line 44
    .line 45
    invoke-interface {v0}, Lg3/d;->e()J

    .line 46
    .line 47
    .line 48
    move-result-wide v1

    .line 49
    invoke-static {v1, v2}, Ld3/e;->d(J)F

    .line 50
    .line 51
    .line 52
    move-result v9

    .line 53
    invoke-interface {v0}, Lg3/d;->e()J

    .line 54
    .line 55
    .line 56
    move-result-wide v1

    .line 57
    invoke-static {v1, v2}, Ld3/e;->b(J)F

    .line 58
    .line 59
    .line 60
    move-result v10

    .line 61
    iget-object v1, v0, Lg3/b;->e:Lgw0/c;

    .line 62
    .line 63
    invoke-virtual {v1}, Lgw0/c;->o()J

    .line 64
    .line 65
    .line 66
    move-result-wide v12

    .line 67
    invoke-virtual {v1}, Lgw0/c;->h()Le3/r;

    .line 68
    .line 69
    .line 70
    move-result-object v2

    .line 71
    invoke-interface {v2}, Le3/r;->o()V

    .line 72
    .line 73
    .line 74
    :try_start_0
    iget-object v2, v1, Lgw0/c;->e:Ljava/lang/Object;

    .line 75
    .line 76
    check-cast v2, Lbu/c;

    .line 77
    .line 78
    iget-object v2, v2, Lbu/c;->e:Ljava/lang/Object;

    .line 79
    .line 80
    check-cast v2, Lgw0/c;

    .line 81
    .line 82
    invoke-virtual {v2}, Lgw0/c;->h()Le3/r;

    .line 83
    .line 84
    .line 85
    move-result-object v6

    .line 86
    const/4 v7, 0x0

    .line 87
    const/4 v8, 0x0

    .line 88
    const/4 v11, 0x1

    .line 89
    invoke-interface/range {v6 .. v11}, Le3/r;->g(FFFFI)V

    .line 90
    .line 91
    .line 92
    const/4 v8, 0x0

    .line 93
    const/16 v9, 0x7c

    .line 94
    .line 95
    const-wide/16 v6, 0x0

    .line 96
    .line 97
    move-object v2, p1

    .line 98
    invoke-static/range {v2 .. v9}, Lg3/d;->u0(Lg3/d;JFJLg3/e;I)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 99
    .line 100
    .line 101
    invoke-static {v1, v12, v13}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->y(Lgw0/c;J)V

    .line 102
    .line 103
    .line 104
    goto :goto_0

    .line 105
    :catchall_0
    move-exception v0

    .line 106
    move-object p0, v0

    .line 107
    invoke-static {v1, v12, v13}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->y(Lgw0/c;J)V

    .line 108
    .line 109
    .line 110
    throw p0

    .line 111
    :cond_0
    move-object v2, p1

    .line 112
    const/4 v8, 0x0

    .line 113
    const/16 v9, 0x7c

    .line 114
    .line 115
    const-wide/16 v6, 0x0

    .line 116
    .line 117
    invoke-static/range {v2 .. v9}, Lg3/d;->u0(Lg3/d;JFJLg3/e;I)V

    .line 118
    .line 119
    .line 120
    :cond_1
    :goto_0
    iget-object p1, v0, Lg3/b;->e:Lgw0/c;

    .line 121
    .line 122
    invoke-virtual {p1}, Lgw0/c;->h()Le3/r;

    .line 123
    .line 124
    .line 125
    move-result-object p1

    .line 126
    iget-object v0, p0, Lg2/a;->C:Lg2/e;

    .line 127
    .line 128
    if-eqz v0, :cond_2

    .line 129
    .line 130
    iget-wide v1, p0, Lg2/a;->y:J

    .line 131
    .line 132
    iget v3, p0, Lg2/a;->x:F

    .line 133
    .line 134
    invoke-static {v3}, Lcy0/a;->i(F)I

    .line 135
    .line 136
    .line 137
    move-result v3

    .line 138
    iget-object v4, p0, Lg2/a;->u:Le3/t;

    .line 139
    .line 140
    invoke-interface {v4}, Le3/t;->a()J

    .line 141
    .line 142
    .line 143
    move-result-wide v4

    .line 144
    iget-object p0, p0, Lg2/a;->v:Lay0/a;

    .line 145
    .line 146
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object p0

    .line 150
    check-cast p0, Lg2/b;

    .line 151
    .line 152
    iget v6, p0, Lg2/b;->d:F

    .line 153
    .line 154
    invoke-virtual/range {v0 .. v6}, Lg2/e;->e(JIJF)V

    .line 155
    .line 156
    .line 157
    invoke-static {p1}, Le3/b;->a(Le3/r;)Landroid/graphics/Canvas;

    .line 158
    .line 159
    .line 160
    move-result-object p0

    .line 161
    invoke-virtual {v0, p0}, Lg2/e;->draw(Landroid/graphics/Canvas;)V

    .line 162
    .line 163
    .line 164
    :cond_2
    return-void
.end method

.method public final M0()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final P0()V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lx2/r;->L0()Lvy0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v1, Le60/m;

    .line 6
    .line 7
    const/16 v2, 0x14

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    invoke-direct {v1, p0, v3, v2}, Le60/m;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 11
    .line 12
    .line 13
    const/4 p0, 0x3

    .line 14
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public final Q0()V
    .locals 5

    .line 1
    iget-object v0, p0, Lg2/a;->B:Lg2/d;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    iput-object v1, p0, Lg2/a;->C:Lg2/e;

    .line 7
    .line 8
    invoke-static {p0}, Lv3/f;->m(Lv3/p;)V

    .line 9
    .line 10
    .line 11
    iget-object v1, v0, Lg2/d;->g:Lb81/b;

    .line 12
    .line 13
    iget-object v2, v1, Lb81/b;->e:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v2, Ljava/util/LinkedHashMap;

    .line 16
    .line 17
    invoke-virtual {v2, p0}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    check-cast v2, Lg2/e;

    .line 22
    .line 23
    if-eqz v2, :cond_1

    .line 24
    .line 25
    invoke-virtual {v2}, Lg2/e;->c()V

    .line 26
    .line 27
    .line 28
    iget-object v3, v1, Lb81/b;->e:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast v3, Ljava/util/LinkedHashMap;

    .line 31
    .line 32
    invoke-virtual {v3, p0}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v4

    .line 36
    check-cast v4, Lg2/e;

    .line 37
    .line 38
    if-eqz v4, :cond_0

    .line 39
    .line 40
    iget-object v1, v1, Lb81/b;->f:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast v1, Ljava/util/LinkedHashMap;

    .line 43
    .line 44
    invoke-interface {v1, v4}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    check-cast v1, Lg2/a;

    .line 49
    .line 50
    :cond_0
    invoke-interface {v3, p0}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    iget-object p0, v0, Lg2/d;->f:Ljava/util/ArrayList;

    .line 54
    .line 55
    invoke-virtual {p0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    :cond_1
    return-void
.end method

.method public final X0(Li1/p;)V
    .locals 11

    .line 1
    instance-of v0, p1, Li1/n;

    .line 2
    .line 3
    if-eqz v0, :cond_c

    .line 4
    .line 5
    move-object v2, p1

    .line 6
    check-cast v2, Li1/n;

    .line 7
    .line 8
    iget-wide v4, p0, Lg2/a;->y:J

    .line 9
    .line 10
    iget p1, p0, Lg2/a;->x:F

    .line 11
    .line 12
    iget-object v0, p0, Lg2/a;->B:Lg2/d;

    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    goto :goto_3

    .line 18
    :cond_0
    sget-object v0, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->f:Ll2/u2;

    .line 19
    .line 20
    invoke-static {p0, v0}, Lv3/f;->i(Lv3/l;Ll2/s1;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    check-cast v0, Landroid/view/View;

    .line 25
    .line 26
    :goto_0
    instance-of v3, v0, Landroid/view/ViewGroup;

    .line 27
    .line 28
    if-nez v3, :cond_2

    .line 29
    .line 30
    move-object v3, v0

    .line 31
    check-cast v3, Landroid/view/View;

    .line 32
    .line 33
    invoke-virtual {v3}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 34
    .line 35
    .line 36
    move-result-object v3

    .line 37
    instance-of v6, v3, Landroid/view/View;

    .line 38
    .line 39
    if-eqz v6, :cond_1

    .line 40
    .line 41
    move-object v0, v3

    .line 42
    goto :goto_0

    .line 43
    :cond_1
    const-string p0, "Couldn\'t find a valid parent for "

    .line 44
    .line 45
    const-string p1, ". Are you overriding LocalView and providing a View that is not attached to the view hierarchy?"

    .line 46
    .line 47
    invoke-static {v0, p0, p1}, Lf2/m0;->g(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 52
    .line 53
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw p1

    .line 61
    :cond_2
    check-cast v0, Landroid/view/ViewGroup;

    .line 62
    .line 63
    invoke-virtual {v0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 64
    .line 65
    .line 66
    move-result v3

    .line 67
    move v6, v1

    .line 68
    :goto_1
    if-ge v6, v3, :cond_4

    .line 69
    .line 70
    invoke-virtual {v0, v6}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 71
    .line 72
    .line 73
    move-result-object v7

    .line 74
    instance-of v8, v7, Lg2/d;

    .line 75
    .line 76
    if-eqz v8, :cond_3

    .line 77
    .line 78
    check-cast v7, Lg2/d;

    .line 79
    .line 80
    move-object v0, v7

    .line 81
    goto :goto_2

    .line 82
    :cond_3
    add-int/lit8 v6, v6, 0x1

    .line 83
    .line 84
    goto :goto_1

    .line 85
    :cond_4
    new-instance v3, Lg2/d;

    .line 86
    .line 87
    invoke-virtual {v0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 88
    .line 89
    .line 90
    move-result-object v6

    .line 91
    invoke-direct {v3, v6}, Lg2/d;-><init>(Landroid/content/Context;)V

    .line 92
    .line 93
    .line 94
    invoke-virtual {v0, v3}, Landroid/view/ViewGroup;->addView(Landroid/view/View;)V

    .line 95
    .line 96
    .line 97
    move-object v0, v3

    .line 98
    :goto_2
    iput-object v0, p0, Lg2/a;->B:Lg2/d;

    .line 99
    .line 100
    :goto_3
    iget-object v3, v0, Lg2/d;->e:Ljava/util/ArrayList;

    .line 101
    .line 102
    iget-object v6, v0, Lg2/d;->g:Lb81/b;

    .line 103
    .line 104
    iget-object v7, v6, Lb81/b;->e:Ljava/lang/Object;

    .line 105
    .line 106
    check-cast v7, Ljava/util/LinkedHashMap;

    .line 107
    .line 108
    iget-object v8, v6, Lb81/b;->e:Ljava/lang/Object;

    .line 109
    .line 110
    check-cast v8, Ljava/util/LinkedHashMap;

    .line 111
    .line 112
    iget-object v6, v6, Lb81/b;->f:Ljava/lang/Object;

    .line 113
    .line 114
    check-cast v6, Ljava/util/LinkedHashMap;

    .line 115
    .line 116
    invoke-virtual {v7, p0}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v7

    .line 120
    check-cast v7, Lg2/e;

    .line 121
    .line 122
    if-eqz v7, :cond_5

    .line 123
    .line 124
    :goto_4
    move-object v1, v7

    .line 125
    goto/16 :goto_8

    .line 126
    .line 127
    :cond_5
    iget-object v7, v0, Lg2/d;->f:Ljava/util/ArrayList;

    .line 128
    .line 129
    const-string v9, "<this>"

    .line 130
    .line 131
    invoke-static {v7, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    invoke-virtual {v7}, Ljava/util/ArrayList;->isEmpty()Z

    .line 135
    .line 136
    .line 137
    move-result v9

    .line 138
    const/4 v10, 0x0

    .line 139
    if-eqz v9, :cond_6

    .line 140
    .line 141
    move-object v7, v10

    .line 142
    goto :goto_5

    .line 143
    :cond_6
    invoke-virtual {v7, v1}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object v7

    .line 147
    :goto_5
    check-cast v7, Lg2/e;

    .line 148
    .line 149
    if-nez v7, :cond_b

    .line 150
    .line 151
    iget v7, v0, Lg2/d;->h:I

    .line 152
    .line 153
    invoke-static {v3}, Ljp/k1;->h(Ljava/util/List;)I

    .line 154
    .line 155
    .line 156
    move-result v9

    .line 157
    if-le v7, v9, :cond_7

    .line 158
    .line 159
    new-instance v7, Lg2/e;

    .line 160
    .line 161
    invoke-virtual {v0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 162
    .line 163
    .line 164
    move-result-object v9

    .line 165
    invoke-direct {v7, v9}, Landroid/view/View;-><init>(Landroid/content/Context;)V

    .line 166
    .line 167
    .line 168
    invoke-virtual {v0, v7}, Landroid/view/ViewGroup;->addView(Landroid/view/View;)V

    .line 169
    .line 170
    .line 171
    invoke-virtual {v3, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 172
    .line 173
    .line 174
    goto :goto_6

    .line 175
    :cond_7
    iget v7, v0, Lg2/d;->h:I

    .line 176
    .line 177
    invoke-virtual {v3, v7}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 178
    .line 179
    .line 180
    move-result-object v3

    .line 181
    move-object v7, v3

    .line 182
    check-cast v7, Lg2/e;

    .line 183
    .line 184
    invoke-virtual {v6, v7}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 185
    .line 186
    .line 187
    move-result-object v3

    .line 188
    check-cast v3, Lg2/a;

    .line 189
    .line 190
    if-eqz v3, :cond_9

    .line 191
    .line 192
    iput-object v10, v3, Lg2/a;->C:Lg2/e;

    .line 193
    .line 194
    invoke-static {v3}, Lv3/f;->m(Lv3/p;)V

    .line 195
    .line 196
    .line 197
    invoke-virtual {v8, v3}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 198
    .line 199
    .line 200
    move-result-object v9

    .line 201
    check-cast v9, Lg2/e;

    .line 202
    .line 203
    if-eqz v9, :cond_8

    .line 204
    .line 205
    invoke-interface {v6, v9}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    move-result-object v9

    .line 209
    check-cast v9, Lg2/a;

    .line 210
    .line 211
    :cond_8
    invoke-interface {v8, v3}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    invoke-virtual {v7}, Lg2/e;->c()V

    .line 215
    .line 216
    .line 217
    :cond_9
    :goto_6
    iget v3, v0, Lg2/d;->h:I

    .line 218
    .line 219
    iget v9, v0, Lg2/d;->d:I

    .line 220
    .line 221
    add-int/lit8 v9, v9, -0x1

    .line 222
    .line 223
    if-ge v3, v9, :cond_a

    .line 224
    .line 225
    add-int/lit8 v3, v3, 0x1

    .line 226
    .line 227
    iput v3, v0, Lg2/d;->h:I

    .line 228
    .line 229
    goto :goto_7

    .line 230
    :cond_a
    iput v1, v0, Lg2/d;->h:I

    .line 231
    .line 232
    :cond_b
    :goto_7
    invoke-interface {v8, p0, v7}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 233
    .line 234
    .line 235
    invoke-interface {v6, v7, p0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 236
    .line 237
    .line 238
    goto :goto_4

    .line 239
    :goto_8
    invoke-static {p1}, Lcy0/a;->i(F)I

    .line 240
    .line 241
    .line 242
    move-result v6

    .line 243
    iget-object p1, p0, Lg2/a;->u:Le3/t;

    .line 244
    .line 245
    invoke-interface {p1}, Le3/t;->a()J

    .line 246
    .line 247
    .line 248
    move-result-wide v7

    .line 249
    iget-object p1, p0, Lg2/a;->v:Lay0/a;

    .line 250
    .line 251
    invoke-interface {p1}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 252
    .line 253
    .line 254
    move-result-object p1

    .line 255
    check-cast p1, Lg2/b;

    .line 256
    .line 257
    iget v9, p1, Lg2/b;->d:F

    .line 258
    .line 259
    new-instance v10, Ld2/g;

    .line 260
    .line 261
    const/16 p1, 0x12

    .line 262
    .line 263
    invoke-direct {v10, p0, p1}, Ld2/g;-><init>(Ljava/lang/Object;I)V

    .line 264
    .line 265
    .line 266
    iget-boolean v3, p0, Lg2/a;->s:Z

    .line 267
    .line 268
    invoke-virtual/range {v1 .. v10}, Lg2/e;->b(Li1/n;ZJIJFLd2/g;)V

    .line 269
    .line 270
    .line 271
    iput-object v1, p0, Lg2/a;->C:Lg2/e;

    .line 272
    .line 273
    invoke-static {p0}, Lv3/f;->m(Lv3/p;)V

    .line 274
    .line 275
    .line 276
    return-void

    .line 277
    :cond_c
    instance-of v0, p1, Li1/o;

    .line 278
    .line 279
    if-eqz v0, :cond_d

    .line 280
    .line 281
    iget-object p0, p0, Lg2/a;->C:Lg2/e;

    .line 282
    .line 283
    if-eqz p0, :cond_e

    .line 284
    .line 285
    invoke-virtual {p0}, Lg2/e;->d()V

    .line 286
    .line 287
    .line 288
    return-void

    .line 289
    :cond_d
    instance-of p1, p1, Li1/m;

    .line 290
    .line 291
    if-eqz p1, :cond_e

    .line 292
    .line 293
    iget-object p0, p0, Lg2/a;->C:Lg2/e;

    .line 294
    .line 295
    if-eqz p0, :cond_e

    .line 296
    .line 297
    invoke-virtual {p0}, Lg2/e;->d()V

    .line 298
    .line 299
    .line 300
    :cond_e
    return-void
.end method

.method public final h(J)V
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lg2/a;->z:Z

    .line 3
    .line 4
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    iget-object v0, v0, Lv3/h0;->A:Lt4/c;

    .line 9
    .line 10
    invoke-static {p1, p2}, Lkp/f9;->c(J)J

    .line 11
    .line 12
    .line 13
    move-result-wide p1

    .line 14
    iput-wide p1, p0, Lg2/a;->y:J

    .line 15
    .line 16
    iget p1, p0, Lg2/a;->t:F

    .line 17
    .line 18
    invoke-static {p1}, Ljava/lang/Float;->isNaN(F)Z

    .line 19
    .line 20
    .line 21
    move-result p2

    .line 22
    if-eqz p2, :cond_0

    .line 23
    .line 24
    iget-wide p1, p0, Lg2/a;->y:J

    .line 25
    .line 26
    sget v1, Lg2/c;->a:F

    .line 27
    .line 28
    invoke-static {p1, p2}, Ld3/e;->d(J)F

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    invoke-static {p1, p2}, Ld3/e;->b(J)F

    .line 33
    .line 34
    .line 35
    move-result p1

    .line 36
    invoke-static {v1, p1}, Ljp/bf;->a(FF)J

    .line 37
    .line 38
    .line 39
    move-result-wide p1

    .line 40
    invoke-static {p1, p2}, Ld3/b;->d(J)F

    .line 41
    .line 42
    .line 43
    move-result p1

    .line 44
    const/high16 p2, 0x40000000    # 2.0f

    .line 45
    .line 46
    div-float/2addr p1, p2

    .line 47
    iget-boolean p2, p0, Lg2/a;->s:Z

    .line 48
    .line 49
    if-eqz p2, :cond_1

    .line 50
    .line 51
    sget p2, Lg2/c;->a:F

    .line 52
    .line 53
    invoke-interface {v0, p2}, Lt4/c;->w0(F)F

    .line 54
    .line 55
    .line 56
    move-result p2

    .line 57
    add-float/2addr p1, p2

    .line 58
    goto :goto_0

    .line 59
    :cond_0
    invoke-interface {v0, p1}, Lt4/c;->w0(F)F

    .line 60
    .line 61
    .line 62
    move-result p1

    .line 63
    :cond_1
    :goto_0
    iput p1, p0, Lg2/a;->x:F

    .line 64
    .line 65
    iget-object p1, p0, Lg2/a;->A:Landroidx/collection/l0;

    .line 66
    .line 67
    iget-object p2, p1, Landroidx/collection/l0;->a:[Ljava/lang/Object;

    .line 68
    .line 69
    iget v0, p1, Landroidx/collection/l0;->b:I

    .line 70
    .line 71
    const/4 v1, 0x0

    .line 72
    :goto_1
    if-ge v1, v0, :cond_2

    .line 73
    .line 74
    aget-object v2, p2, v1

    .line 75
    .line 76
    check-cast v2, Li1/p;

    .line 77
    .line 78
    invoke-virtual {p0, v2}, Lg2/a;->X0(Li1/p;)V

    .line 79
    .line 80
    .line 81
    add-int/lit8 v1, v1, 0x1

    .line 82
    .line 83
    goto :goto_1

    .line 84
    :cond_2
    invoke-virtual {p1}, Landroidx/collection/l0;->c()V

    .line 85
    .line 86
    .line 87
    return-void
.end method
