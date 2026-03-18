.class public Landroidx/recyclerview/widget/StaggeredGridLayoutManager;
.super Lka/f0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lka/q0;


# instance fields
.field public A:I

.field public final B:Lb81/b;

.field public final C:I

.field public D:Z

.field public E:Z

.field public F:Lka/c1;

.field public final G:Landroid/graphics/Rect;

.field public final H:Lka/z0;

.field public final I:Z

.field public J:[I

.field public final K:Laq/p;

.field public final p:I

.field public final q:[Lka/d1;

.field public final r:Lka/u;

.field public final s:Lka/u;

.field public final t:I

.field public u:I

.field public final v:Lka/o;

.field public w:Z

.field public x:Z

.field public final y:Ljava/util/BitSet;

.field public z:I


# direct methods
.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;II)V
    .locals 5

    .line 1
    invoke-direct {p0}, Lka/f0;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, -0x1

    .line 5
    iput v0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    iput-boolean v1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->w:Z

    .line 9
    .line 10
    iput-boolean v1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->x:Z

    .line 11
    .line 12
    iput v0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->z:I

    .line 13
    .line 14
    const/high16 v0, -0x80000000

    .line 15
    .line 16
    iput v0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->A:I

    .line 17
    .line 18
    new-instance v0, Lb81/b;

    .line 19
    .line 20
    const/16 v2, 0xd

    .line 21
    .line 22
    const/4 v3, 0x0

    .line 23
    invoke-direct {v0, v2, v3}, Lb81/b;-><init>(IZ)V

    .line 24
    .line 25
    .line 26
    iput-object v0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->B:Lb81/b;

    .line 27
    .line 28
    const/4 v2, 0x2

    .line 29
    iput v2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->C:I

    .line 30
    .line 31
    new-instance v2, Landroid/graphics/Rect;

    .line 32
    .line 33
    invoke-direct {v2}, Landroid/graphics/Rect;-><init>()V

    .line 34
    .line 35
    .line 36
    iput-object v2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->G:Landroid/graphics/Rect;

    .line 37
    .line 38
    new-instance v2, Lka/z0;

    .line 39
    .line 40
    invoke-direct {v2, p0}, Lka/z0;-><init>(Landroidx/recyclerview/widget/StaggeredGridLayoutManager;)V

    .line 41
    .line 42
    .line 43
    iput-object v2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->H:Lka/z0;

    .line 44
    .line 45
    const/4 v2, 0x1

    .line 46
    iput-boolean v2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->I:Z

    .line 47
    .line 48
    new-instance v3, Laq/p;

    .line 49
    .line 50
    const/16 v4, 0xe

    .line 51
    .line 52
    invoke-direct {v3, p0, v4}, Laq/p;-><init>(Ljava/lang/Object;I)V

    .line 53
    .line 54
    .line 55
    iput-object v3, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->K:Laq/p;

    .line 56
    .line 57
    invoke-static {p1, p2, p3, p4}, Lka/f0;->I(Landroid/content/Context;Landroid/util/AttributeSet;II)Lka/e0;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    iget p2, p1, Lka/e0;->a:I

    .line 62
    .line 63
    if-eqz p2, :cond_1

    .line 64
    .line 65
    if-ne p2, v2, :cond_0

    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 69
    .line 70
    const-string p1, "invalid orientation."

    .line 71
    .line 72
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    throw p0

    .line 76
    :cond_1
    :goto_0
    const/4 p3, 0x0

    .line 77
    invoke-virtual {p0, p3}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->c(Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    iget p4, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->t:I

    .line 81
    .line 82
    if-ne p2, p4, :cond_2

    .line 83
    .line 84
    goto :goto_1

    .line 85
    :cond_2
    iput p2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->t:I

    .line 86
    .line 87
    iget-object p2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 88
    .line 89
    iget-object p4, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->s:Lka/u;

    .line 90
    .line 91
    iput-object p4, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 92
    .line 93
    iput-object p2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->s:Lka/u;

    .line 94
    .line 95
    invoke-virtual {p0}, Lka/f0;->n0()V

    .line 96
    .line 97
    .line 98
    :goto_1
    iget p2, p1, Lka/e0;->b:I

    .line 99
    .line 100
    invoke-virtual {p0, p3}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->c(Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    iget p4, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 104
    .line 105
    if-eq p2, p4, :cond_4

    .line 106
    .line 107
    invoke-virtual {v0}, Lb81/b;->k()V

    .line 108
    .line 109
    .line 110
    invoke-virtual {p0}, Lka/f0;->n0()V

    .line 111
    .line 112
    .line 113
    iput p2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 114
    .line 115
    new-instance p2, Ljava/util/BitSet;

    .line 116
    .line 117
    iget p4, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 118
    .line 119
    invoke-direct {p2, p4}, Ljava/util/BitSet;-><init>(I)V

    .line 120
    .line 121
    .line 122
    iput-object p2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->y:Ljava/util/BitSet;

    .line 123
    .line 124
    iget p2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 125
    .line 126
    new-array p2, p2, [Lka/d1;

    .line 127
    .line 128
    iput-object p2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->q:[Lka/d1;

    .line 129
    .line 130
    move p2, v1

    .line 131
    :goto_2
    iget p4, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 132
    .line 133
    if-ge p2, p4, :cond_3

    .line 134
    .line 135
    iget-object p4, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->q:[Lka/d1;

    .line 136
    .line 137
    new-instance v0, Lka/d1;

    .line 138
    .line 139
    invoke-direct {v0, p0, p2}, Lka/d1;-><init>(Landroidx/recyclerview/widget/StaggeredGridLayoutManager;I)V

    .line 140
    .line 141
    .line 142
    aput-object v0, p4, p2

    .line 143
    .line 144
    add-int/lit8 p2, p2, 0x1

    .line 145
    .line 146
    goto :goto_2

    .line 147
    :cond_3
    invoke-virtual {p0}, Lka/f0;->n0()V

    .line 148
    .line 149
    .line 150
    :cond_4
    iget-boolean p1, p1, Lka/e0;->c:Z

    .line 151
    .line 152
    invoke-virtual {p0, p3}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->c(Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    iget-object p2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->F:Lka/c1;

    .line 156
    .line 157
    if-eqz p2, :cond_5

    .line 158
    .line 159
    iget-boolean p3, p2, Lka/c1;->k:Z

    .line 160
    .line 161
    if-eq p3, p1, :cond_5

    .line 162
    .line 163
    iput-boolean p1, p2, Lka/c1;->k:Z

    .line 164
    .line 165
    :cond_5
    iput-boolean p1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->w:Z

    .line 166
    .line 167
    invoke-virtual {p0}, Lka/f0;->n0()V

    .line 168
    .line 169
    .line 170
    new-instance p1, Lka/o;

    .line 171
    .line 172
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 173
    .line 174
    .line 175
    iput-boolean v2, p1, Lka/o;->a:Z

    .line 176
    .line 177
    iput v1, p1, Lka/o;->f:I

    .line 178
    .line 179
    iput v1, p1, Lka/o;->g:I

    .line 180
    .line 181
    iput-object p1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->v:Lka/o;

    .line 182
    .line 183
    iget p1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->t:I

    .line 184
    .line 185
    invoke-static {p0, p1}, Lka/u;->b(Lka/f0;I)Lka/u;

    .line 186
    .line 187
    .line 188
    move-result-object p1

    .line 189
    iput-object p1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 190
    .line 191
    iget p1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->t:I

    .line 192
    .line 193
    sub-int/2addr v2, p1

    .line 194
    invoke-static {p0, v2}, Lka/u;->b(Lka/f0;I)Lka/u;

    .line 195
    .line 196
    .line 197
    move-result-object p1

    .line 198
    iput-object p1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->s:Lka/u;

    .line 199
    .line 200
    return-void
.end method

.method public static c1(III)I
    .locals 2

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    if-nez p2, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    invoke-static {p0}, Landroid/view/View$MeasureSpec;->getMode(I)I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    const/high16 v1, -0x80000000

    .line 11
    .line 12
    if-eq v0, v1, :cond_2

    .line 13
    .line 14
    const/high16 v1, 0x40000000    # 2.0f

    .line 15
    .line 16
    if-ne v0, v1, :cond_1

    .line 17
    .line 18
    goto :goto_1

    .line 19
    :cond_1
    :goto_0
    return p0

    .line 20
    :cond_2
    :goto_1
    invoke-static {p0}, Landroid/view/View$MeasureSpec;->getSize(I)I

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    sub-int/2addr p0, p1

    .line 25
    sub-int/2addr p0, p2

    .line 26
    const/4 p1, 0x0

    .line 27
    invoke-static {p1, p0}, Ljava/lang/Math;->max(II)I

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    invoke-static {p0, v0}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    return p0
.end method


# virtual methods
.method public final B0()Z
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->F:Lka/c1;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method

.method public final C0()Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lka/f0;->v()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-eqz v0, :cond_2

    .line 7
    .line 8
    iget v0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->C:I

    .line 9
    .line 10
    if-eqz v0, :cond_2

    .line 11
    .line 12
    iget-boolean v0, p0, Lka/f0;->g:Z

    .line 13
    .line 14
    if-nez v0, :cond_0

    .line 15
    .line 16
    goto :goto_1

    .line 17
    :cond_0
    iget-boolean v0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->x:Z

    .line 18
    .line 19
    if-eqz v0, :cond_1

    .line 20
    .line 21
    invoke-virtual {p0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->K0()I

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    invoke-virtual {p0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->J0()I

    .line 26
    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_1
    invoke-virtual {p0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->J0()I

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    invoke-virtual {p0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->K0()I

    .line 34
    .line 35
    .line 36
    :goto_0
    if-nez v0, :cond_2

    .line 37
    .line 38
    invoke-virtual {p0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->O0()Landroid/view/View;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    if-eqz v0, :cond_2

    .line 43
    .line 44
    iget-object v0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->B:Lb81/b;

    .line 45
    .line 46
    invoke-virtual {v0}, Lb81/b;->k()V

    .line 47
    .line 48
    .line 49
    const/4 v0, 0x1

    .line 50
    iput-boolean v0, p0, Lka/f0;->f:Z

    .line 51
    .line 52
    invoke-virtual {p0}, Lka/f0;->n0()V

    .line 53
    .line 54
    .line 55
    return v0

    .line 56
    :cond_2
    :goto_1
    return v1
.end method

.method public final D0(Lka/r0;)I
    .locals 8

    .line 1
    invoke-virtual {p0}, Lka/f0;->v()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return p0

    .line 9
    :cond_0
    iget-boolean v0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->I:Z

    .line 10
    .line 11
    xor-int/lit8 v0, v0, 0x1

    .line 12
    .line 13
    invoke-virtual {p0, v0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->G0(Z)Landroid/view/View;

    .line 14
    .line 15
    .line 16
    move-result-object v3

    .line 17
    invoke-virtual {p0, v0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->F0(Z)Landroid/view/View;

    .line 18
    .line 19
    .line 20
    move-result-object v4

    .line 21
    iget-boolean v6, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->I:Z

    .line 22
    .line 23
    iget-boolean v7, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->x:Z

    .line 24
    .line 25
    iget-object v2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 26
    .line 27
    move-object v5, p0

    .line 28
    move-object v1, p1

    .line 29
    invoke-static/range {v1 .. v7}, Llp/hd;->d(Lka/r0;Lka/u;Landroid/view/View;Landroid/view/View;Lka/f0;ZZ)I

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    return p0
.end method

.method public final E0(Lka/l0;Lka/o;Lka/r0;)I
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    iget-object v3, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->y:Ljava/util/BitSet;

    .line 8
    .line 9
    const/4 v4, 0x0

    .line 10
    iget v5, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 11
    .line 12
    const/4 v6, 0x1

    .line 13
    invoke-virtual {v3, v4, v5, v6}, Ljava/util/BitSet;->set(IIZ)V

    .line 14
    .line 15
    .line 16
    iget-object v3, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->v:Lka/o;

    .line 17
    .line 18
    iget-boolean v5, v3, Lka/o;->i:Z

    .line 19
    .line 20
    if-eqz v5, :cond_1

    .line 21
    .line 22
    iget v5, v2, Lka/o;->e:I

    .line 23
    .line 24
    if-ne v5, v6, :cond_0

    .line 25
    .line 26
    const v5, 0x7fffffff

    .line 27
    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    const/high16 v5, -0x80000000

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_1
    iget v5, v2, Lka/o;->e:I

    .line 34
    .line 35
    if-ne v5, v6, :cond_2

    .line 36
    .line 37
    iget v5, v2, Lka/o;->g:I

    .line 38
    .line 39
    iget v9, v2, Lka/o;->b:I

    .line 40
    .line 41
    add-int/2addr v5, v9

    .line 42
    goto :goto_0

    .line 43
    :cond_2
    iget v5, v2, Lka/o;->f:I

    .line 44
    .line 45
    iget v9, v2, Lka/o;->b:I

    .line 46
    .line 47
    sub-int/2addr v5, v9

    .line 48
    :goto_0
    iget v9, v2, Lka/o;->e:I

    .line 49
    .line 50
    move v10, v4

    .line 51
    :goto_1
    iget v11, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 52
    .line 53
    if-ge v10, v11, :cond_4

    .line 54
    .line 55
    iget-object v11, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->q:[Lka/d1;

    .line 56
    .line 57
    aget-object v11, v11, v10

    .line 58
    .line 59
    iget-object v11, v11, Lka/d1;->a:Ljava/util/ArrayList;

    .line 60
    .line 61
    invoke-virtual {v11}, Ljava/util/ArrayList;->isEmpty()Z

    .line 62
    .line 63
    .line 64
    move-result v11

    .line 65
    if-eqz v11, :cond_3

    .line 66
    .line 67
    goto :goto_2

    .line 68
    :cond_3
    iget-object v11, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->q:[Lka/d1;

    .line 69
    .line 70
    aget-object v11, v11, v10

    .line 71
    .line 72
    invoke-virtual {v0, v11, v9, v5}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->b1(Lka/d1;II)V

    .line 73
    .line 74
    .line 75
    :goto_2
    add-int/lit8 v10, v10, 0x1

    .line 76
    .line 77
    goto :goto_1

    .line 78
    :cond_4
    iget-boolean v9, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->x:Z

    .line 79
    .line 80
    if-eqz v9, :cond_5

    .line 81
    .line 82
    iget-object v9, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 83
    .line 84
    invoke-virtual {v9}, Lka/u;->i()I

    .line 85
    .line 86
    .line 87
    move-result v9

    .line 88
    goto :goto_3

    .line 89
    :cond_5
    iget-object v9, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 90
    .line 91
    invoke-virtual {v9}, Lka/u;->m()I

    .line 92
    .line 93
    .line 94
    move-result v9

    .line 95
    :goto_3
    move v10, v4

    .line 96
    :goto_4
    iget v11, v2, Lka/o;->c:I

    .line 97
    .line 98
    const/4 v12, -0x1

    .line 99
    if-ltz v11, :cond_1c

    .line 100
    .line 101
    invoke-virtual/range {p3 .. p3}, Lka/r0;->b()I

    .line 102
    .line 103
    .line 104
    move-result v13

    .line 105
    if-ge v11, v13, :cond_1c

    .line 106
    .line 107
    iget-boolean v11, v3, Lka/o;->i:Z

    .line 108
    .line 109
    if-nez v11, :cond_6

    .line 110
    .line 111
    iget-object v11, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->y:Ljava/util/BitSet;

    .line 112
    .line 113
    invoke-virtual {v11}, Ljava/util/BitSet;->isEmpty()Z

    .line 114
    .line 115
    .line 116
    move-result v11

    .line 117
    if-nez v11, :cond_1c

    .line 118
    .line 119
    :cond_6
    iget v10, v2, Lka/o;->c:I

    .line 120
    .line 121
    invoke-virtual {v1, v10}, Lka/l0;->d(I)Landroid/view/View;

    .line 122
    .line 123
    .line 124
    move-result-object v10

    .line 125
    iget v11, v2, Lka/o;->c:I

    .line 126
    .line 127
    iget v13, v2, Lka/o;->d:I

    .line 128
    .line 129
    add-int/2addr v11, v13

    .line 130
    iput v11, v2, Lka/o;->c:I

    .line 131
    .line 132
    invoke-virtual {v10}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 133
    .line 134
    .line 135
    move-result-object v11

    .line 136
    check-cast v11, Lka/a1;

    .line 137
    .line 138
    iget-object v13, v11, Lka/g0;->a:Lka/v0;

    .line 139
    .line 140
    invoke-virtual {v13}, Lka/v0;->b()I

    .line 141
    .line 142
    .line 143
    move-result v13

    .line 144
    iget-object v14, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->B:Lb81/b;

    .line 145
    .line 146
    iget-object v15, v14, Lb81/b;->e:Ljava/lang/Object;

    .line 147
    .line 148
    check-cast v15, [I

    .line 149
    .line 150
    if-eqz v15, :cond_8

    .line 151
    .line 152
    array-length v8, v15

    .line 153
    if-lt v13, v8, :cond_7

    .line 154
    .line 155
    goto :goto_5

    .line 156
    :cond_7
    aget v8, v15, v13

    .line 157
    .line 158
    goto :goto_6

    .line 159
    :cond_8
    :goto_5
    move v8, v12

    .line 160
    :goto_6
    if-ne v8, v12, :cond_e

    .line 161
    .line 162
    iget v8, v2, Lka/o;->e:I

    .line 163
    .line 164
    invoke-virtual {v0, v8}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->S0(I)Z

    .line 165
    .line 166
    .line 167
    move-result v8

    .line 168
    if-eqz v8, :cond_9

    .line 169
    .line 170
    iget v8, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 171
    .line 172
    sub-int/2addr v8, v6

    .line 173
    move v15, v12

    .line 174
    move/from16 v16, v15

    .line 175
    .line 176
    goto :goto_7

    .line 177
    :cond_9
    iget v8, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 178
    .line 179
    move/from16 v16, v6

    .line 180
    .line 181
    move v15, v8

    .line 182
    move v8, v4

    .line 183
    :goto_7
    iget v7, v2, Lka/o;->e:I

    .line 184
    .line 185
    const/16 v17, 0x0

    .line 186
    .line 187
    if-ne v7, v6, :cond_c

    .line 188
    .line 189
    iget-object v7, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 190
    .line 191
    invoke-virtual {v7}, Lka/u;->m()I

    .line 192
    .line 193
    .line 194
    move-result v7

    .line 195
    const v4, 0x7fffffff

    .line 196
    .line 197
    .line 198
    :goto_8
    if-eq v8, v15, :cond_b

    .line 199
    .line 200
    iget-object v12, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->q:[Lka/d1;

    .line 201
    .line 202
    aget-object v12, v12, v8

    .line 203
    .line 204
    invoke-virtual {v12, v7}, Lka/d1;->f(I)I

    .line 205
    .line 206
    .line 207
    move-result v6

    .line 208
    if-ge v6, v4, :cond_a

    .line 209
    .line 210
    move v4, v6

    .line 211
    move-object/from16 v17, v12

    .line 212
    .line 213
    :cond_a
    add-int v8, v8, v16

    .line 214
    .line 215
    const/4 v6, 0x1

    .line 216
    const/4 v12, -0x1

    .line 217
    goto :goto_8

    .line 218
    :cond_b
    move-object/from16 v4, v17

    .line 219
    .line 220
    goto :goto_a

    .line 221
    :cond_c
    iget-object v4, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 222
    .line 223
    invoke-virtual {v4}, Lka/u;->i()I

    .line 224
    .line 225
    .line 226
    move-result v4

    .line 227
    const/high16 v6, -0x80000000

    .line 228
    .line 229
    :goto_9
    if-eq v8, v15, :cond_b

    .line 230
    .line 231
    iget-object v7, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->q:[Lka/d1;

    .line 232
    .line 233
    aget-object v7, v7, v8

    .line 234
    .line 235
    invoke-virtual {v7, v4}, Lka/d1;->h(I)I

    .line 236
    .line 237
    .line 238
    move-result v12

    .line 239
    if-le v12, v6, :cond_d

    .line 240
    .line 241
    move-object/from16 v17, v7

    .line 242
    .line 243
    move v6, v12

    .line 244
    :cond_d
    add-int v8, v8, v16

    .line 245
    .line 246
    goto :goto_9

    .line 247
    :goto_a
    invoke-virtual {v14, v13}, Lb81/b;->m(I)V

    .line 248
    .line 249
    .line 250
    iget-object v6, v14, Lb81/b;->e:Ljava/lang/Object;

    .line 251
    .line 252
    check-cast v6, [I

    .line 253
    .line 254
    iget v7, v4, Lka/d1;->e:I

    .line 255
    .line 256
    aput v7, v6, v13

    .line 257
    .line 258
    goto :goto_b

    .line 259
    :cond_e
    iget-object v4, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->q:[Lka/d1;

    .line 260
    .line 261
    aget-object v4, v4, v8

    .line 262
    .line 263
    :goto_b
    iput-object v4, v11, Lka/a1;->e:Lka/d1;

    .line 264
    .line 265
    iget v6, v2, Lka/o;->e:I

    .line 266
    .line 267
    const/4 v7, 0x1

    .line 268
    if-ne v6, v7, :cond_f

    .line 269
    .line 270
    const/4 v6, -0x1

    .line 271
    const/4 v8, 0x0

    .line 272
    invoke-virtual {v0, v10, v6, v8}, Lka/f0;->b(Landroid/view/View;IZ)V

    .line 273
    .line 274
    .line 275
    goto :goto_c

    .line 276
    :cond_f
    const/4 v8, 0x0

    .line 277
    invoke-virtual {v0, v10, v8, v8}, Lka/f0;->b(Landroid/view/View;IZ)V

    .line 278
    .line 279
    .line 280
    :goto_c
    iget v6, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->t:I

    .line 281
    .line 282
    if-ne v6, v7, :cond_10

    .line 283
    .line 284
    iget v6, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->u:I

    .line 285
    .line 286
    iget v12, v0, Lka/f0;->l:I

    .line 287
    .line 288
    iget v13, v11, Landroid/view/ViewGroup$MarginLayoutParams;->width:I

    .line 289
    .line 290
    invoke-static {v6, v12, v8, v13, v8}, Lka/f0;->w(IIIIZ)I

    .line 291
    .line 292
    .line 293
    move-result v6

    .line 294
    iget v8, v0, Lka/f0;->o:I

    .line 295
    .line 296
    iget v12, v0, Lka/f0;->m:I

    .line 297
    .line 298
    invoke-virtual {v0}, Lka/f0;->G()I

    .line 299
    .line 300
    .line 301
    move-result v13

    .line 302
    invoke-virtual {v0}, Lka/f0;->D()I

    .line 303
    .line 304
    .line 305
    move-result v14

    .line 306
    add-int/2addr v14, v13

    .line 307
    iget v13, v11, Landroid/view/ViewGroup$MarginLayoutParams;->height:I

    .line 308
    .line 309
    invoke-static {v8, v12, v14, v13, v7}, Lka/f0;->w(IIIIZ)I

    .line 310
    .line 311
    .line 312
    move-result v8

    .line 313
    invoke-virtual {v0, v10, v6, v8}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->Q0(Landroid/view/View;II)V

    .line 314
    .line 315
    .line 316
    goto :goto_d

    .line 317
    :cond_10
    iget v6, v0, Lka/f0;->n:I

    .line 318
    .line 319
    iget v8, v0, Lka/f0;->l:I

    .line 320
    .line 321
    invoke-virtual {v0}, Lka/f0;->E()I

    .line 322
    .line 323
    .line 324
    move-result v12

    .line 325
    invoke-virtual {v0}, Lka/f0;->F()I

    .line 326
    .line 327
    .line 328
    move-result v13

    .line 329
    add-int/2addr v13, v12

    .line 330
    iget v12, v11, Landroid/view/ViewGroup$MarginLayoutParams;->width:I

    .line 331
    .line 332
    invoke-static {v6, v8, v13, v12, v7}, Lka/f0;->w(IIIIZ)I

    .line 333
    .line 334
    .line 335
    move-result v6

    .line 336
    iget v8, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->u:I

    .line 337
    .line 338
    iget v12, v0, Lka/f0;->m:I

    .line 339
    .line 340
    iget v13, v11, Landroid/view/ViewGroup$MarginLayoutParams;->height:I

    .line 341
    .line 342
    const/4 v14, 0x0

    .line 343
    invoke-static {v8, v12, v14, v13, v14}, Lka/f0;->w(IIIIZ)I

    .line 344
    .line 345
    .line 346
    move-result v8

    .line 347
    invoke-virtual {v0, v10, v6, v8}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->Q0(Landroid/view/View;II)V

    .line 348
    .line 349
    .line 350
    :goto_d
    iget v6, v2, Lka/o;->e:I

    .line 351
    .line 352
    if-ne v6, v7, :cond_11

    .line 353
    .line 354
    invoke-virtual {v4, v9}, Lka/d1;->f(I)I

    .line 355
    .line 356
    .line 357
    move-result v6

    .line 358
    iget-object v7, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 359
    .line 360
    invoke-virtual {v7, v10}, Lka/u;->e(Landroid/view/View;)I

    .line 361
    .line 362
    .line 363
    move-result v7

    .line 364
    add-int/2addr v7, v6

    .line 365
    goto :goto_e

    .line 366
    :cond_11
    invoke-virtual {v4, v9}, Lka/d1;->h(I)I

    .line 367
    .line 368
    .line 369
    move-result v7

    .line 370
    iget-object v6, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 371
    .line 372
    invoke-virtual {v6, v10}, Lka/u;->e(Landroid/view/View;)I

    .line 373
    .line 374
    .line 375
    move-result v6

    .line 376
    sub-int v6, v7, v6

    .line 377
    .line 378
    :goto_e
    iget v8, v2, Lka/o;->e:I

    .line 379
    .line 380
    const/4 v12, 0x1

    .line 381
    if-ne v8, v12, :cond_15

    .line 382
    .line 383
    iget-object v8, v11, Lka/a1;->e:Lka/d1;

    .line 384
    .line 385
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 386
    .line 387
    .line 388
    invoke-virtual {v10}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 389
    .line 390
    .line 391
    move-result-object v11

    .line 392
    check-cast v11, Lka/a1;

    .line 393
    .line 394
    iput-object v8, v11, Lka/a1;->e:Lka/d1;

    .line 395
    .line 396
    iget-object v13, v8, Lka/d1;->a:Ljava/util/ArrayList;

    .line 397
    .line 398
    invoke-virtual {v13, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 399
    .line 400
    .line 401
    const/high16 v14, -0x80000000

    .line 402
    .line 403
    iput v14, v8, Lka/d1;->c:I

    .line 404
    .line 405
    invoke-virtual {v13}, Ljava/util/ArrayList;->size()I

    .line 406
    .line 407
    .line 408
    move-result v13

    .line 409
    if-ne v13, v12, :cond_12

    .line 410
    .line 411
    iput v14, v8, Lka/d1;->b:I

    .line 412
    .line 413
    :cond_12
    iget-object v12, v11, Lka/g0;->a:Lka/v0;

    .line 414
    .line 415
    invoke-virtual {v12}, Lka/v0;->h()Z

    .line 416
    .line 417
    .line 418
    move-result v12

    .line 419
    if-nez v12, :cond_13

    .line 420
    .line 421
    iget-object v11, v11, Lka/g0;->a:Lka/v0;

    .line 422
    .line 423
    invoke-virtual {v11}, Lka/v0;->k()Z

    .line 424
    .line 425
    .line 426
    move-result v11

    .line 427
    if-eqz v11, :cond_14

    .line 428
    .line 429
    :cond_13
    iget v11, v8, Lka/d1;->d:I

    .line 430
    .line 431
    iget-object v12, v8, Lka/d1;->f:Landroidx/recyclerview/widget/StaggeredGridLayoutManager;

    .line 432
    .line 433
    iget-object v12, v12, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 434
    .line 435
    invoke-virtual {v12, v10}, Lka/u;->e(Landroid/view/View;)I

    .line 436
    .line 437
    .line 438
    move-result v12

    .line 439
    add-int/2addr v12, v11

    .line 440
    iput v12, v8, Lka/d1;->d:I

    .line 441
    .line 442
    :cond_14
    const/high16 v14, -0x80000000

    .line 443
    .line 444
    goto :goto_f

    .line 445
    :cond_15
    iget-object v8, v11, Lka/a1;->e:Lka/d1;

    .line 446
    .line 447
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 448
    .line 449
    .line 450
    invoke-virtual {v10}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 451
    .line 452
    .line 453
    move-result-object v11

    .line 454
    check-cast v11, Lka/a1;

    .line 455
    .line 456
    iput-object v8, v11, Lka/a1;->e:Lka/d1;

    .line 457
    .line 458
    iget-object v12, v8, Lka/d1;->a:Ljava/util/ArrayList;

    .line 459
    .line 460
    const/4 v14, 0x0

    .line 461
    invoke-virtual {v12, v14, v10}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    .line 462
    .line 463
    .line 464
    const/high16 v14, -0x80000000

    .line 465
    .line 466
    iput v14, v8, Lka/d1;->b:I

    .line 467
    .line 468
    invoke-virtual {v12}, Ljava/util/ArrayList;->size()I

    .line 469
    .line 470
    .line 471
    move-result v12

    .line 472
    const/4 v13, 0x1

    .line 473
    if-ne v12, v13, :cond_16

    .line 474
    .line 475
    iput v14, v8, Lka/d1;->c:I

    .line 476
    .line 477
    :cond_16
    iget-object v12, v11, Lka/g0;->a:Lka/v0;

    .line 478
    .line 479
    invoke-virtual {v12}, Lka/v0;->h()Z

    .line 480
    .line 481
    .line 482
    move-result v12

    .line 483
    if-nez v12, :cond_17

    .line 484
    .line 485
    iget-object v11, v11, Lka/g0;->a:Lka/v0;

    .line 486
    .line 487
    invoke-virtual {v11}, Lka/v0;->k()Z

    .line 488
    .line 489
    .line 490
    move-result v11

    .line 491
    if-eqz v11, :cond_18

    .line 492
    .line 493
    :cond_17
    iget v11, v8, Lka/d1;->d:I

    .line 494
    .line 495
    iget-object v12, v8, Lka/d1;->f:Landroidx/recyclerview/widget/StaggeredGridLayoutManager;

    .line 496
    .line 497
    iget-object v12, v12, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 498
    .line 499
    invoke-virtual {v12, v10}, Lka/u;->e(Landroid/view/View;)I

    .line 500
    .line 501
    .line 502
    move-result v12

    .line 503
    add-int/2addr v12, v11

    .line 504
    iput v12, v8, Lka/d1;->d:I

    .line 505
    .line 506
    :cond_18
    :goto_f
    invoke-virtual {v0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->P0()Z

    .line 507
    .line 508
    .line 509
    move-result v8

    .line 510
    if-eqz v8, :cond_19

    .line 511
    .line 512
    iget v8, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->t:I

    .line 513
    .line 514
    const/4 v12, 0x1

    .line 515
    if-ne v8, v12, :cond_19

    .line 516
    .line 517
    iget-object v8, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->s:Lka/u;

    .line 518
    .line 519
    invoke-virtual {v8}, Lka/u;->i()I

    .line 520
    .line 521
    .line 522
    move-result v8

    .line 523
    iget v11, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 524
    .line 525
    sub-int/2addr v11, v12

    .line 526
    iget v12, v4, Lka/d1;->e:I

    .line 527
    .line 528
    sub-int/2addr v11, v12

    .line 529
    iget v12, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->u:I

    .line 530
    .line 531
    mul-int/2addr v11, v12

    .line 532
    sub-int/2addr v8, v11

    .line 533
    iget-object v11, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->s:Lka/u;

    .line 534
    .line 535
    invoke-virtual {v11, v10}, Lka/u;->e(Landroid/view/View;)I

    .line 536
    .line 537
    .line 538
    move-result v11

    .line 539
    sub-int v11, v8, v11

    .line 540
    .line 541
    goto :goto_10

    .line 542
    :cond_19
    iget v8, v4, Lka/d1;->e:I

    .line 543
    .line 544
    iget v11, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->u:I

    .line 545
    .line 546
    mul-int/2addr v8, v11

    .line 547
    iget-object v11, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->s:Lka/u;

    .line 548
    .line 549
    invoke-virtual {v11}, Lka/u;->m()I

    .line 550
    .line 551
    .line 552
    move-result v11

    .line 553
    add-int/2addr v11, v8

    .line 554
    iget-object v8, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->s:Lka/u;

    .line 555
    .line 556
    invoke-virtual {v8, v10}, Lka/u;->e(Landroid/view/View;)I

    .line 557
    .line 558
    .line 559
    move-result v8

    .line 560
    add-int/2addr v8, v11

    .line 561
    :goto_10
    iget v12, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->t:I

    .line 562
    .line 563
    const/4 v13, 0x1

    .line 564
    if-ne v12, v13, :cond_1a

    .line 565
    .line 566
    invoke-static {v10, v11, v6, v8, v7}, Lka/f0;->N(Landroid/view/View;IIII)V

    .line 567
    .line 568
    .line 569
    goto :goto_11

    .line 570
    :cond_1a
    invoke-static {v10, v6, v11, v7, v8}, Lka/f0;->N(Landroid/view/View;IIII)V

    .line 571
    .line 572
    .line 573
    :goto_11
    iget v6, v3, Lka/o;->e:I

    .line 574
    .line 575
    invoke-virtual {v0, v4, v6, v5}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->b1(Lka/d1;II)V

    .line 576
    .line 577
    .line 578
    invoke-virtual {v0, v1, v3}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->U0(Lka/l0;Lka/o;)V

    .line 579
    .line 580
    .line 581
    iget-boolean v6, v3, Lka/o;->h:Z

    .line 582
    .line 583
    if-eqz v6, :cond_1b

    .line 584
    .line 585
    invoke-virtual {v10}, Landroid/view/View;->hasFocusable()Z

    .line 586
    .line 587
    .line 588
    move-result v6

    .line 589
    if-eqz v6, :cond_1b

    .line 590
    .line 591
    iget-object v6, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->y:Ljava/util/BitSet;

    .line 592
    .line 593
    iget v4, v4, Lka/d1;->e:I

    .line 594
    .line 595
    const/4 v8, 0x0

    .line 596
    invoke-virtual {v6, v4, v8}, Ljava/util/BitSet;->set(IZ)V

    .line 597
    .line 598
    .line 599
    :cond_1b
    move v6, v13

    .line 600
    move v10, v6

    .line 601
    const/4 v4, 0x0

    .line 602
    goto/16 :goto_4

    .line 603
    .line 604
    :cond_1c
    if-nez v10, :cond_1d

    .line 605
    .line 606
    invoke-virtual {v0, v1, v3}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->U0(Lka/l0;Lka/o;)V

    .line 607
    .line 608
    .line 609
    :cond_1d
    iget v1, v3, Lka/o;->e:I

    .line 610
    .line 611
    const/4 v6, -0x1

    .line 612
    if-ne v1, v6, :cond_1e

    .line 613
    .line 614
    iget-object v1, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 615
    .line 616
    invoke-virtual {v1}, Lka/u;->m()I

    .line 617
    .line 618
    .line 619
    move-result v1

    .line 620
    invoke-virtual {v0, v1}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->M0(I)I

    .line 621
    .line 622
    .line 623
    move-result v1

    .line 624
    iget-object v0, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 625
    .line 626
    invoke-virtual {v0}, Lka/u;->m()I

    .line 627
    .line 628
    .line 629
    move-result v0

    .line 630
    sub-int/2addr v0, v1

    .line 631
    goto :goto_12

    .line 632
    :cond_1e
    iget-object v1, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 633
    .line 634
    invoke-virtual {v1}, Lka/u;->i()I

    .line 635
    .line 636
    .line 637
    move-result v1

    .line 638
    invoke-virtual {v0, v1}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->L0(I)I

    .line 639
    .line 640
    .line 641
    move-result v1

    .line 642
    iget-object v0, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 643
    .line 644
    invoke-virtual {v0}, Lka/u;->i()I

    .line 645
    .line 646
    .line 647
    move-result v0

    .line 648
    sub-int v0, v1, v0

    .line 649
    .line 650
    :goto_12
    if-lez v0, :cond_1f

    .line 651
    .line 652
    iget v1, v2, Lka/o;->b:I

    .line 653
    .line 654
    invoke-static {v1, v0}, Ljava/lang/Math;->min(II)I

    .line 655
    .line 656
    .line 657
    move-result v0

    .line 658
    return v0

    .line 659
    :cond_1f
    const/16 v18, 0x0

    .line 660
    .line 661
    return v18
.end method

.method public final F0(Z)Landroid/view/View;
    .locals 7

    .line 1
    iget-object v0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 2
    .line 3
    invoke-virtual {v0}, Lka/u;->m()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget-object v1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 8
    .line 9
    invoke-virtual {v1}, Lka/u;->i()I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    invoke-virtual {p0}, Lka/f0;->v()I

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    add-int/lit8 v2, v2, -0x1

    .line 18
    .line 19
    const/4 v3, 0x0

    .line 20
    :goto_0
    if-ltz v2, :cond_4

    .line 21
    .line 22
    invoke-virtual {p0, v2}, Lka/f0;->u(I)Landroid/view/View;

    .line 23
    .line 24
    .line 25
    move-result-object v4

    .line 26
    iget-object v5, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 27
    .line 28
    invoke-virtual {v5, v4}, Lka/u;->g(Landroid/view/View;)I

    .line 29
    .line 30
    .line 31
    move-result v5

    .line 32
    iget-object v6, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 33
    .line 34
    invoke-virtual {v6, v4}, Lka/u;->d(Landroid/view/View;)I

    .line 35
    .line 36
    .line 37
    move-result v6

    .line 38
    if-le v6, v0, :cond_3

    .line 39
    .line 40
    if-lt v5, v1, :cond_0

    .line 41
    .line 42
    goto :goto_2

    .line 43
    :cond_0
    if-le v6, v1, :cond_2

    .line 44
    .line 45
    if-nez p1, :cond_1

    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_1
    if-nez v3, :cond_3

    .line 49
    .line 50
    move-object v3, v4

    .line 51
    goto :goto_2

    .line 52
    :cond_2
    :goto_1
    return-object v4

    .line 53
    :cond_3
    :goto_2
    add-int/lit8 v2, v2, -0x1

    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_4
    return-object v3
.end method

.method public final G0(Z)Landroid/view/View;
    .locals 8

    .line 1
    iget-object v0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 2
    .line 3
    invoke-virtual {v0}, Lka/u;->m()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget-object v1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 8
    .line 9
    invoke-virtual {v1}, Lka/u;->i()I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    invoke-virtual {p0}, Lka/f0;->v()I

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    const/4 v3, 0x0

    .line 18
    const/4 v4, 0x0

    .line 19
    :goto_0
    if-ge v4, v2, :cond_4

    .line 20
    .line 21
    invoke-virtual {p0, v4}, Lka/f0;->u(I)Landroid/view/View;

    .line 22
    .line 23
    .line 24
    move-result-object v5

    .line 25
    iget-object v6, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 26
    .line 27
    invoke-virtual {v6, v5}, Lka/u;->g(Landroid/view/View;)I

    .line 28
    .line 29
    .line 30
    move-result v6

    .line 31
    iget-object v7, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 32
    .line 33
    invoke-virtual {v7, v5}, Lka/u;->d(Landroid/view/View;)I

    .line 34
    .line 35
    .line 36
    move-result v7

    .line 37
    if-le v7, v0, :cond_3

    .line 38
    .line 39
    if-lt v6, v1, :cond_0

    .line 40
    .line 41
    goto :goto_2

    .line 42
    :cond_0
    if-ge v6, v0, :cond_2

    .line 43
    .line 44
    if-nez p1, :cond_1

    .line 45
    .line 46
    goto :goto_1

    .line 47
    :cond_1
    if-nez v3, :cond_3

    .line 48
    .line 49
    move-object v3, v5

    .line 50
    goto :goto_2

    .line 51
    :cond_2
    :goto_1
    return-object v5

    .line 52
    :cond_3
    :goto_2
    add-int/lit8 v4, v4, 0x1

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_4
    return-object v3
.end method

.method public final H0(Lka/l0;Lka/r0;Z)V
    .locals 2

    .line 1
    const/high16 v0, -0x80000000

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->L0(I)I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-ne v1, v0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    iget-object v0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 11
    .line 12
    invoke-virtual {v0}, Lka/u;->i()I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    sub-int/2addr v0, v1

    .line 17
    if-lez v0, :cond_1

    .line 18
    .line 19
    neg-int v1, v0

    .line 20
    invoke-virtual {p0, v1, p1, p2}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->Y0(ILka/l0;Lka/r0;)I

    .line 21
    .line 22
    .line 23
    move-result p1

    .line 24
    neg-int p1, p1

    .line 25
    sub-int/2addr v0, p1

    .line 26
    if-eqz p3, :cond_1

    .line 27
    .line 28
    if-lez v0, :cond_1

    .line 29
    .line 30
    iget-object p0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 31
    .line 32
    invoke-virtual {p0, v0}, Lka/u;->q(I)V

    .line 33
    .line 34
    .line 35
    :cond_1
    :goto_0
    return-void
.end method

.method public final I0(Lka/l0;Lka/r0;Z)V
    .locals 2

    .line 1
    const v0, 0x7fffffff

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0, v0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->M0(I)I

    .line 5
    .line 6
    .line 7
    move-result v1

    .line 8
    if-ne v1, v0, :cond_0

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    iget-object v0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 12
    .line 13
    invoke-virtual {v0}, Lka/u;->m()I

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    sub-int/2addr v1, v0

    .line 18
    if-lez v1, :cond_1

    .line 19
    .line 20
    invoke-virtual {p0, v1, p1, p2}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->Y0(ILka/l0;Lka/r0;)I

    .line 21
    .line 22
    .line 23
    move-result p1

    .line 24
    sub-int/2addr v1, p1

    .line 25
    if-eqz p3, :cond_1

    .line 26
    .line 27
    if-lez v1, :cond_1

    .line 28
    .line 29
    iget-object p0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 30
    .line 31
    neg-int p1, v1

    .line 32
    invoke-virtual {p0, p1}, Lka/u;->q(I)V

    .line 33
    .line 34
    .line 35
    :cond_1
    :goto_0
    return-void
.end method

.method public final J0()I
    .locals 2

    .line 1
    invoke-virtual {p0}, Lka/f0;->v()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-nez v0, :cond_0

    .line 7
    .line 8
    return v1

    .line 9
    :cond_0
    invoke-virtual {p0, v1}, Lka/f0;->u(I)Landroid/view/View;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-static {p0}, Lka/f0;->H(Landroid/view/View;)I

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    return p0
.end method

.method public final K0()I
    .locals 1

    .line 1
    invoke-virtual {p0}, Lka/f0;->v()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return p0

    .line 9
    :cond_0
    add-int/lit8 v0, v0, -0x1

    .line 10
    .line 11
    invoke-virtual {p0, v0}, Lka/f0;->u(I)Landroid/view/View;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-static {p0}, Lka/f0;->H(Landroid/view/View;)I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public final L()Z
    .locals 0

    .line 1
    iget p0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->C:I

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method

.method public final L0(I)I
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->q:[Lka/d1;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    aget-object v0, v0, v1

    .line 5
    .line 6
    invoke-virtual {v0, p1}, Lka/d1;->f(I)I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    const/4 v1, 0x1

    .line 11
    :goto_0
    iget v2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 12
    .line 13
    if-ge v1, v2, :cond_1

    .line 14
    .line 15
    iget-object v2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->q:[Lka/d1;

    .line 16
    .line 17
    aget-object v2, v2, v1

    .line 18
    .line 19
    invoke-virtual {v2, p1}, Lka/d1;->f(I)I

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    if-le v2, v0, :cond_0

    .line 24
    .line 25
    move v0, v2

    .line 26
    :cond_0
    add-int/lit8 v1, v1, 0x1

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_1
    return v0
.end method

.method public final M0(I)I
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->q:[Lka/d1;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    aget-object v0, v0, v1

    .line 5
    .line 6
    invoke-virtual {v0, p1}, Lka/d1;->h(I)I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    const/4 v1, 0x1

    .line 11
    :goto_0
    iget v2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 12
    .line 13
    if-ge v1, v2, :cond_1

    .line 14
    .line 15
    iget-object v2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->q:[Lka/d1;

    .line 16
    .line 17
    aget-object v2, v2, v1

    .line 18
    .line 19
    invoke-virtual {v2, p1}, Lka/d1;->h(I)I

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    if-ge v2, v0, :cond_0

    .line 24
    .line 25
    move v0, v2

    .line 26
    :cond_0
    add-int/lit8 v1, v1, 0x1

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_1
    return v0
.end method

.method public final N0(III)V
    .locals 9

    .line 1
    iget-boolean v0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->x:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->K0()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    goto :goto_0

    .line 10
    :cond_0
    invoke-virtual {p0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->J0()I

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    :goto_0
    const/16 v1, 0x8

    .line 15
    .line 16
    if-ne p3, v1, :cond_2

    .line 17
    .line 18
    if-ge p1, p2, :cond_1

    .line 19
    .line 20
    add-int/lit8 v2, p2, 0x1

    .line 21
    .line 22
    :goto_1
    move v3, p1

    .line 23
    goto :goto_2

    .line 24
    :cond_1
    add-int/lit8 v2, p1, 0x1

    .line 25
    .line 26
    move v3, p2

    .line 27
    goto :goto_2

    .line 28
    :cond_2
    add-int v2, p1, p2

    .line 29
    .line 30
    goto :goto_1

    .line 31
    :goto_2
    iget-object v4, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->B:Lb81/b;

    .line 32
    .line 33
    iget-object v5, v4, Lb81/b;->e:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast v5, [I

    .line 36
    .line 37
    if-nez v5, :cond_3

    .line 38
    .line 39
    goto/16 :goto_9

    .line 40
    .line 41
    :cond_3
    array-length v5, v5

    .line 42
    if-lt v3, v5, :cond_4

    .line 43
    .line 44
    goto/16 :goto_9

    .line 45
    .line 46
    :cond_4
    iget-object v5, v4, Lb81/b;->f:Ljava/lang/Object;

    .line 47
    .line 48
    check-cast v5, Ljava/util/ArrayList;

    .line 49
    .line 50
    const/4 v6, -0x1

    .line 51
    if-nez v5, :cond_6

    .line 52
    .line 53
    :cond_5
    move v5, v6

    .line 54
    goto :goto_8

    .line 55
    :cond_6
    if-nez v5, :cond_7

    .line 56
    .line 57
    goto :goto_4

    .line 58
    :cond_7
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 59
    .line 60
    .line 61
    move-result v5

    .line 62
    add-int/lit8 v5, v5, -0x1

    .line 63
    .line 64
    :goto_3
    if-ltz v5, :cond_9

    .line 65
    .line 66
    iget-object v7, v4, Lb81/b;->f:Ljava/lang/Object;

    .line 67
    .line 68
    check-cast v7, Ljava/util/ArrayList;

    .line 69
    .line 70
    invoke-interface {v7, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v7

    .line 74
    check-cast v7, Lka/b1;

    .line 75
    .line 76
    iget v8, v7, Lka/b1;->d:I

    .line 77
    .line 78
    if-ne v8, v3, :cond_8

    .line 79
    .line 80
    goto :goto_5

    .line 81
    :cond_8
    add-int/lit8 v5, v5, -0x1

    .line 82
    .line 83
    goto :goto_3

    .line 84
    :cond_9
    :goto_4
    const/4 v7, 0x0

    .line 85
    :goto_5
    if-eqz v7, :cond_a

    .line 86
    .line 87
    iget-object v5, v4, Lb81/b;->f:Ljava/lang/Object;

    .line 88
    .line 89
    check-cast v5, Ljava/util/ArrayList;

    .line 90
    .line 91
    invoke-interface {v5, v7}, Ljava/util/List;->remove(Ljava/lang/Object;)Z

    .line 92
    .line 93
    .line 94
    :cond_a
    iget-object v5, v4, Lb81/b;->f:Ljava/lang/Object;

    .line 95
    .line 96
    check-cast v5, Ljava/util/ArrayList;

    .line 97
    .line 98
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 99
    .line 100
    .line 101
    move-result v5

    .line 102
    const/4 v7, 0x0

    .line 103
    :goto_6
    if-ge v7, v5, :cond_c

    .line 104
    .line 105
    iget-object v8, v4, Lb81/b;->f:Ljava/lang/Object;

    .line 106
    .line 107
    check-cast v8, Ljava/util/ArrayList;

    .line 108
    .line 109
    invoke-interface {v8, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v8

    .line 113
    check-cast v8, Lka/b1;

    .line 114
    .line 115
    iget v8, v8, Lka/b1;->d:I

    .line 116
    .line 117
    if-lt v8, v3, :cond_b

    .line 118
    .line 119
    goto :goto_7

    .line 120
    :cond_b
    add-int/lit8 v7, v7, 0x1

    .line 121
    .line 122
    goto :goto_6

    .line 123
    :cond_c
    move v7, v6

    .line 124
    :goto_7
    if-eq v7, v6, :cond_5

    .line 125
    .line 126
    iget-object v5, v4, Lb81/b;->f:Ljava/lang/Object;

    .line 127
    .line 128
    check-cast v5, Ljava/util/ArrayList;

    .line 129
    .line 130
    invoke-interface {v5, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v5

    .line 134
    check-cast v5, Lka/b1;

    .line 135
    .line 136
    iget-object v8, v4, Lb81/b;->f:Ljava/lang/Object;

    .line 137
    .line 138
    check-cast v8, Ljava/util/ArrayList;

    .line 139
    .line 140
    invoke-interface {v8, v7}, Ljava/util/List;->remove(I)Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    iget v5, v5, Lka/b1;->d:I

    .line 144
    .line 145
    :goto_8
    if-ne v5, v6, :cond_d

    .line 146
    .line 147
    iget-object v5, v4, Lb81/b;->e:Ljava/lang/Object;

    .line 148
    .line 149
    check-cast v5, [I

    .line 150
    .line 151
    array-length v7, v5

    .line 152
    invoke-static {v5, v3, v7, v6}, Ljava/util/Arrays;->fill([IIII)V

    .line 153
    .line 154
    .line 155
    iget-object v5, v4, Lb81/b;->e:Ljava/lang/Object;

    .line 156
    .line 157
    check-cast v5, [I

    .line 158
    .line 159
    array-length v5, v5

    .line 160
    goto :goto_9

    .line 161
    :cond_d
    add-int/lit8 v5, v5, 0x1

    .line 162
    .line 163
    iget-object v7, v4, Lb81/b;->e:Ljava/lang/Object;

    .line 164
    .line 165
    check-cast v7, [I

    .line 166
    .line 167
    array-length v7, v7

    .line 168
    invoke-static {v5, v7}, Ljava/lang/Math;->min(II)I

    .line 169
    .line 170
    .line 171
    move-result v5

    .line 172
    iget-object v7, v4, Lb81/b;->e:Ljava/lang/Object;

    .line 173
    .line 174
    check-cast v7, [I

    .line 175
    .line 176
    invoke-static {v7, v3, v5, v6}, Ljava/util/Arrays;->fill([IIII)V

    .line 177
    .line 178
    .line 179
    :goto_9
    const/4 v5, 0x1

    .line 180
    if-eq p3, v5, :cond_10

    .line 181
    .line 182
    const/4 v6, 0x2

    .line 183
    if-eq p3, v6, :cond_f

    .line 184
    .line 185
    if-eq p3, v1, :cond_e

    .line 186
    .line 187
    goto :goto_a

    .line 188
    :cond_e
    invoke-virtual {v4, p1, v5}, Lb81/b;->r(II)V

    .line 189
    .line 190
    .line 191
    invoke-virtual {v4, p2, v5}, Lb81/b;->q(II)V

    .line 192
    .line 193
    .line 194
    goto :goto_a

    .line 195
    :cond_f
    invoke-virtual {v4, p1, p2}, Lb81/b;->r(II)V

    .line 196
    .line 197
    .line 198
    goto :goto_a

    .line 199
    :cond_10
    invoke-virtual {v4, p1, p2}, Lb81/b;->q(II)V

    .line 200
    .line 201
    .line 202
    :goto_a
    if-gt v2, v0, :cond_11

    .line 203
    .line 204
    goto :goto_c

    .line 205
    :cond_11
    iget-boolean p1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->x:Z

    .line 206
    .line 207
    if-eqz p1, :cond_12

    .line 208
    .line 209
    invoke-virtual {p0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->J0()I

    .line 210
    .line 211
    .line 212
    move-result p1

    .line 213
    goto :goto_b

    .line 214
    :cond_12
    invoke-virtual {p0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->K0()I

    .line 215
    .line 216
    .line 217
    move-result p1

    .line 218
    :goto_b
    if-gt v3, p1, :cond_13

    .line 219
    .line 220
    invoke-virtual {p0}, Lka/f0;->n0()V

    .line 221
    .line 222
    .line 223
    :cond_13
    :goto_c
    return-void
.end method

.method public final O(I)V
    .locals 4

    .line 1
    invoke-super {p0, p1}, Lka/f0;->O(I)V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    :goto_0
    iget v1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 6
    .line 7
    if-ge v0, v1, :cond_2

    .line 8
    .line 9
    iget-object v1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->q:[Lka/d1;

    .line 10
    .line 11
    aget-object v1, v1, v0

    .line 12
    .line 13
    iget v2, v1, Lka/d1;->b:I

    .line 14
    .line 15
    const/high16 v3, -0x80000000

    .line 16
    .line 17
    if-eq v2, v3, :cond_0

    .line 18
    .line 19
    add-int/2addr v2, p1

    .line 20
    iput v2, v1, Lka/d1;->b:I

    .line 21
    .line 22
    :cond_0
    iget v2, v1, Lka/d1;->c:I

    .line 23
    .line 24
    if-eq v2, v3, :cond_1

    .line 25
    .line 26
    add-int/2addr v2, p1

    .line 27
    iput v2, v1, Lka/d1;->c:I

    .line 28
    .line 29
    :cond_1
    add-int/lit8 v0, v0, 0x1

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_2
    return-void
.end method

.method public final O0()Landroid/view/View;
    .locals 14

    .line 1
    invoke-virtual {p0}, Lka/f0;->v()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    add-int/lit8 v1, v0, -0x1

    .line 6
    .line 7
    new-instance v2, Ljava/util/BitSet;

    .line 8
    .line 9
    iget v3, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 10
    .line 11
    invoke-direct {v2, v3}, Ljava/util/BitSet;-><init>(I)V

    .line 12
    .line 13
    .line 14
    iget v3, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 15
    .line 16
    const/4 v4, 0x0

    .line 17
    const/4 v5, 0x1

    .line 18
    invoke-virtual {v2, v4, v3, v5}, Ljava/util/BitSet;->set(IIZ)V

    .line 19
    .line 20
    .line 21
    iget v3, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->t:I

    .line 22
    .line 23
    const/4 v6, -0x1

    .line 24
    if-ne v3, v5, :cond_0

    .line 25
    .line 26
    invoke-virtual {p0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->P0()Z

    .line 27
    .line 28
    .line 29
    move-result v3

    .line 30
    if-eqz v3, :cond_0

    .line 31
    .line 32
    move v3, v5

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    move v3, v6

    .line 35
    :goto_0
    iget-boolean v7, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->x:Z

    .line 36
    .line 37
    if-eqz v7, :cond_1

    .line 38
    .line 39
    move v0, v6

    .line 40
    goto :goto_1

    .line 41
    :cond_1
    move v1, v4

    .line 42
    :goto_1
    if-ge v1, v0, :cond_2

    .line 43
    .line 44
    move v6, v5

    .line 45
    :cond_2
    if-eq v1, v0, :cond_d

    .line 46
    .line 47
    invoke-virtual {p0, v1}, Lka/f0;->u(I)Landroid/view/View;

    .line 48
    .line 49
    .line 50
    move-result-object v7

    .line 51
    invoke-virtual {v7}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 52
    .line 53
    .line 54
    move-result-object v8

    .line 55
    check-cast v8, Lka/a1;

    .line 56
    .line 57
    iget-object v9, v8, Lka/a1;->e:Lka/d1;

    .line 58
    .line 59
    iget v9, v9, Lka/d1;->e:I

    .line 60
    .line 61
    invoke-virtual {v2, v9}, Ljava/util/BitSet;->get(I)Z

    .line 62
    .line 63
    .line 64
    move-result v9

    .line 65
    if-eqz v9, :cond_7

    .line 66
    .line 67
    iget-object v9, v8, Lka/a1;->e:Lka/d1;

    .line 68
    .line 69
    iget-boolean v10, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->x:Z

    .line 70
    .line 71
    const/high16 v11, -0x80000000

    .line 72
    .line 73
    if-eqz v10, :cond_4

    .line 74
    .line 75
    iget v10, v9, Lka/d1;->c:I

    .line 76
    .line 77
    if-eq v10, v11, :cond_3

    .line 78
    .line 79
    goto :goto_2

    .line 80
    :cond_3
    invoke-virtual {v9}, Lka/d1;->a()V

    .line 81
    .line 82
    .line 83
    iget v10, v9, Lka/d1;->c:I

    .line 84
    .line 85
    :goto_2
    iget-object v11, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 86
    .line 87
    invoke-virtual {v11}, Lka/u;->i()I

    .line 88
    .line 89
    .line 90
    move-result v11

    .line 91
    if-ge v10, v11, :cond_6

    .line 92
    .line 93
    iget-object p0, v9, Lka/d1;->a:Ljava/util/ArrayList;

    .line 94
    .line 95
    invoke-static {p0, v5}, Lkx/a;->f(Ljava/util/ArrayList;I)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    check-cast p0, Landroid/view/View;

    .line 100
    .line 101
    invoke-virtual {p0}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    check-cast p0, Lka/a1;

    .line 106
    .line 107
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 108
    .line 109
    .line 110
    return-object v7

    .line 111
    :cond_4
    iget v10, v9, Lka/d1;->b:I

    .line 112
    .line 113
    iget-object v12, v9, Lka/d1;->a:Ljava/util/ArrayList;

    .line 114
    .line 115
    if-eq v10, v11, :cond_5

    .line 116
    .line 117
    goto :goto_3

    .line 118
    :cond_5
    invoke-virtual {v12, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v10

    .line 122
    check-cast v10, Landroid/view/View;

    .line 123
    .line 124
    invoke-virtual {v10}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 125
    .line 126
    .line 127
    move-result-object v11

    .line 128
    check-cast v11, Lka/a1;

    .line 129
    .line 130
    iget-object v13, v9, Lka/d1;->f:Landroidx/recyclerview/widget/StaggeredGridLayoutManager;

    .line 131
    .line 132
    iget-object v13, v13, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 133
    .line 134
    invoke-virtual {v13, v10}, Lka/u;->g(Landroid/view/View;)I

    .line 135
    .line 136
    .line 137
    move-result v10

    .line 138
    iput v10, v9, Lka/d1;->b:I

    .line 139
    .line 140
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 141
    .line 142
    .line 143
    iget v10, v9, Lka/d1;->b:I

    .line 144
    .line 145
    :goto_3
    iget-object v9, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 146
    .line 147
    invoke-virtual {v9}, Lka/u;->m()I

    .line 148
    .line 149
    .line 150
    move-result v9

    .line 151
    if-le v10, v9, :cond_6

    .line 152
    .line 153
    invoke-virtual {v12, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 154
    .line 155
    .line 156
    move-result-object p0

    .line 157
    check-cast p0, Landroid/view/View;

    .line 158
    .line 159
    invoke-virtual {p0}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 160
    .line 161
    .line 162
    move-result-object p0

    .line 163
    check-cast p0, Lka/a1;

    .line 164
    .line 165
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 166
    .line 167
    .line 168
    return-object v7

    .line 169
    :cond_6
    iget-object v9, v8, Lka/a1;->e:Lka/d1;

    .line 170
    .line 171
    iget v9, v9, Lka/d1;->e:I

    .line 172
    .line 173
    invoke-virtual {v2, v9}, Ljava/util/BitSet;->clear(I)V

    .line 174
    .line 175
    .line 176
    :cond_7
    add-int/2addr v1, v6

    .line 177
    if-eq v1, v0, :cond_2

    .line 178
    .line 179
    invoke-virtual {p0, v1}, Lka/f0;->u(I)Landroid/view/View;

    .line 180
    .line 181
    .line 182
    move-result-object v9

    .line 183
    iget-boolean v10, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->x:Z

    .line 184
    .line 185
    if-eqz v10, :cond_9

    .line 186
    .line 187
    iget-object v10, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 188
    .line 189
    invoke-virtual {v10, v7}, Lka/u;->d(Landroid/view/View;)I

    .line 190
    .line 191
    .line 192
    move-result v10

    .line 193
    iget-object v11, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 194
    .line 195
    invoke-virtual {v11, v9}, Lka/u;->d(Landroid/view/View;)I

    .line 196
    .line 197
    .line 198
    move-result v11

    .line 199
    if-ge v10, v11, :cond_8

    .line 200
    .line 201
    goto :goto_7

    .line 202
    :cond_8
    if-ne v10, v11, :cond_2

    .line 203
    .line 204
    goto :goto_4

    .line 205
    :cond_9
    iget-object v10, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 206
    .line 207
    invoke-virtual {v10, v7}, Lka/u;->g(Landroid/view/View;)I

    .line 208
    .line 209
    .line 210
    move-result v10

    .line 211
    iget-object v11, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 212
    .line 213
    invoke-virtual {v11, v9}, Lka/u;->g(Landroid/view/View;)I

    .line 214
    .line 215
    .line 216
    move-result v11

    .line 217
    if-le v10, v11, :cond_a

    .line 218
    .line 219
    goto :goto_7

    .line 220
    :cond_a
    if-ne v10, v11, :cond_2

    .line 221
    .line 222
    :goto_4
    invoke-virtual {v9}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 223
    .line 224
    .line 225
    move-result-object v9

    .line 226
    check-cast v9, Lka/a1;

    .line 227
    .line 228
    iget-object v8, v8, Lka/a1;->e:Lka/d1;

    .line 229
    .line 230
    iget v8, v8, Lka/d1;->e:I

    .line 231
    .line 232
    iget-object v9, v9, Lka/a1;->e:Lka/d1;

    .line 233
    .line 234
    iget v9, v9, Lka/d1;->e:I

    .line 235
    .line 236
    sub-int/2addr v8, v9

    .line 237
    if-gez v8, :cond_b

    .line 238
    .line 239
    move v8, v5

    .line 240
    goto :goto_5

    .line 241
    :cond_b
    move v8, v4

    .line 242
    :goto_5
    if-gez v3, :cond_c

    .line 243
    .line 244
    move v9, v5

    .line 245
    goto :goto_6

    .line 246
    :cond_c
    move v9, v4

    .line 247
    :goto_6
    if-eq v8, v9, :cond_2

    .line 248
    .line 249
    :goto_7
    return-object v7

    .line 250
    :cond_d
    const/4 p0, 0x0

    .line 251
    return-object p0
.end method

.method public final P(I)V
    .locals 4

    .line 1
    invoke-super {p0, p1}, Lka/f0;->P(I)V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    :goto_0
    iget v1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 6
    .line 7
    if-ge v0, v1, :cond_2

    .line 8
    .line 9
    iget-object v1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->q:[Lka/d1;

    .line 10
    .line 11
    aget-object v1, v1, v0

    .line 12
    .line 13
    iget v2, v1, Lka/d1;->b:I

    .line 14
    .line 15
    const/high16 v3, -0x80000000

    .line 16
    .line 17
    if-eq v2, v3, :cond_0

    .line 18
    .line 19
    add-int/2addr v2, p1

    .line 20
    iput v2, v1, Lka/d1;->b:I

    .line 21
    .line 22
    :cond_0
    iget v2, v1, Lka/d1;->c:I

    .line 23
    .line 24
    if-eq v2, v3, :cond_1

    .line 25
    .line 26
    add-int/2addr v2, p1

    .line 27
    iput v2, v1, Lka/d1;->c:I

    .line 28
    .line 29
    :cond_1
    add-int/lit8 v0, v0, 0x1

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_2
    return-void
.end method

.method public final P0()Z
    .locals 1

    .line 1
    invoke-virtual {p0}, Lka/f0;->C()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    const/4 v0, 0x1

    .line 6
    if-ne p0, v0, :cond_0

    .line 7
    .line 8
    return v0

    .line 9
    :cond_0
    const/4 p0, 0x0

    .line 10
    return p0
.end method

.method public final Q()V
    .locals 2

    .line 1
    iget-object v0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->B:Lb81/b;

    .line 2
    .line 3
    invoke-virtual {v0}, Lb81/b;->k()V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    :goto_0
    iget v1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 8
    .line 9
    if-ge v0, v1, :cond_0

    .line 10
    .line 11
    iget-object v1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->q:[Lka/d1;

    .line 12
    .line 13
    aget-object v1, v1, v0

    .line 14
    .line 15
    invoke-virtual {v1}, Lka/d1;->b()V

    .line 16
    .line 17
    .line 18
    add-int/lit8 v0, v0, 0x1

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    return-void
.end method

.method public final Q0(Landroid/view/View;II)V
    .locals 5

    .line 1
    iget-object v0, p0, Lka/f0;->b:Landroidx/recyclerview/widget/RecyclerView;

    .line 2
    .line 3
    iget-object v1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->G:Landroid/graphics/Rect;

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    invoke-virtual {v1, v0, v0, v0, v0}, Landroid/graphics/Rect;->set(IIII)V

    .line 9
    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    invoke-virtual {v0, p1}, Landroidx/recyclerview/widget/RecyclerView;->K(Landroid/view/View;)Landroid/graphics/Rect;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    invoke-virtual {v1, v0}, Landroid/graphics/Rect;->set(Landroid/graphics/Rect;)V

    .line 17
    .line 18
    .line 19
    :goto_0
    invoke-virtual {p1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    check-cast v0, Lka/a1;

    .line 24
    .line 25
    iget v2, v0, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    .line 26
    .line 27
    iget v3, v1, Landroid/graphics/Rect;->left:I

    .line 28
    .line 29
    add-int/2addr v2, v3

    .line 30
    iget v3, v0, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    .line 31
    .line 32
    iget v4, v1, Landroid/graphics/Rect;->right:I

    .line 33
    .line 34
    add-int/2addr v3, v4

    .line 35
    invoke-static {p2, v2, v3}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->c1(III)I

    .line 36
    .line 37
    .line 38
    move-result p2

    .line 39
    iget v2, v0, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    .line 40
    .line 41
    iget v3, v1, Landroid/graphics/Rect;->top:I

    .line 42
    .line 43
    add-int/2addr v2, v3

    .line 44
    iget v3, v0, Landroid/view/ViewGroup$MarginLayoutParams;->bottomMargin:I

    .line 45
    .line 46
    iget v1, v1, Landroid/graphics/Rect;->bottom:I

    .line 47
    .line 48
    add-int/2addr v3, v1

    .line 49
    invoke-static {p3, v2, v3}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->c1(III)I

    .line 50
    .line 51
    .line 52
    move-result p3

    .line 53
    invoke-virtual {p0, p1, p2, p3, v0}, Lka/f0;->w0(Landroid/view/View;IILka/g0;)Z

    .line 54
    .line 55
    .line 56
    move-result p0

    .line 57
    if-eqz p0, :cond_1

    .line 58
    .line 59
    invoke-virtual {p1, p2, p3}, Landroid/view/View;->measure(II)V

    .line 60
    .line 61
    .line 62
    :cond_1
    return-void
.end method

.method public final R0(Lka/l0;Lka/r0;Z)V
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    iget-object v3, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->F:Lka/c1;

    .line 8
    .line 9
    const/4 v4, -0x1

    .line 10
    iget-object v5, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->H:Lka/z0;

    .line 11
    .line 12
    if-nez v3, :cond_0

    .line 13
    .line 14
    iget v3, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->z:I

    .line 15
    .line 16
    if-eq v3, v4, :cond_1

    .line 17
    .line 18
    :cond_0
    invoke-virtual {v2}, Lka/r0;->b()I

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    if-nez v3, :cond_1

    .line 23
    .line 24
    invoke-virtual/range {p0 .. p1}, Lka/f0;->i0(Lka/l0;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {v5}, Lka/z0;->a()V

    .line 28
    .line 29
    .line 30
    return-void

    .line 31
    :cond_1
    iget-boolean v3, v5, Lka/z0;->e:Z

    .line 32
    .line 33
    iget-object v6, v5, Lka/z0;->g:Landroidx/recyclerview/widget/StaggeredGridLayoutManager;

    .line 34
    .line 35
    const/4 v7, 0x0

    .line 36
    const/4 v8, 0x1

    .line 37
    if-eqz v3, :cond_3

    .line 38
    .line 39
    iget v3, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->z:I

    .line 40
    .line 41
    if-ne v3, v4, :cond_3

    .line 42
    .line 43
    iget-object v3, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->F:Lka/c1;

    .line 44
    .line 45
    if-eqz v3, :cond_2

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_2
    move v3, v7

    .line 49
    goto :goto_1

    .line 50
    :cond_3
    :goto_0
    move v3, v8

    .line 51
    :goto_1
    iget-object v9, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->B:Lb81/b;

    .line 52
    .line 53
    const/high16 v10, -0x80000000

    .line 54
    .line 55
    if-eqz v3, :cond_25

    .line 56
    .line 57
    invoke-virtual {v5}, Lka/z0;->a()V

    .line 58
    .line 59
    .line 60
    iget-object v11, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->F:Lka/c1;

    .line 61
    .line 62
    if-eqz v11, :cond_a

    .line 63
    .line 64
    iget v12, v11, Lka/c1;->f:I

    .line 65
    .line 66
    const/4 v13, 0x0

    .line 67
    if-lez v12, :cond_7

    .line 68
    .line 69
    iget v14, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 70
    .line 71
    if-ne v12, v14, :cond_6

    .line 72
    .line 73
    move v11, v7

    .line 74
    :goto_2
    iget v12, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 75
    .line 76
    if-ge v11, v12, :cond_7

    .line 77
    .line 78
    iget-object v12, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->q:[Lka/d1;

    .line 79
    .line 80
    aget-object v12, v12, v11

    .line 81
    .line 82
    invoke-virtual {v12}, Lka/d1;->b()V

    .line 83
    .line 84
    .line 85
    iget-object v12, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->F:Lka/c1;

    .line 86
    .line 87
    iget-object v14, v12, Lka/c1;->g:[I

    .line 88
    .line 89
    aget v14, v14, v11

    .line 90
    .line 91
    if-eq v14, v10, :cond_5

    .line 92
    .line 93
    iget-boolean v12, v12, Lka/c1;->l:Z

    .line 94
    .line 95
    if-eqz v12, :cond_4

    .line 96
    .line 97
    iget-object v12, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 98
    .line 99
    invoke-virtual {v12}, Lka/u;->i()I

    .line 100
    .line 101
    .line 102
    move-result v12

    .line 103
    :goto_3
    add-int/2addr v14, v12

    .line 104
    goto :goto_4

    .line 105
    :cond_4
    iget-object v12, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 106
    .line 107
    invoke-virtual {v12}, Lka/u;->m()I

    .line 108
    .line 109
    .line 110
    move-result v12

    .line 111
    goto :goto_3

    .line 112
    :cond_5
    :goto_4
    iget-object v12, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->q:[Lka/d1;

    .line 113
    .line 114
    aget-object v12, v12, v11

    .line 115
    .line 116
    iput v14, v12, Lka/d1;->b:I

    .line 117
    .line 118
    iput v14, v12, Lka/d1;->c:I

    .line 119
    .line 120
    add-int/lit8 v11, v11, 0x1

    .line 121
    .line 122
    goto :goto_2

    .line 123
    :cond_6
    iput-object v13, v11, Lka/c1;->g:[I

    .line 124
    .line 125
    iput v7, v11, Lka/c1;->f:I

    .line 126
    .line 127
    iput v7, v11, Lka/c1;->h:I

    .line 128
    .line 129
    iput-object v13, v11, Lka/c1;->i:[I

    .line 130
    .line 131
    iput-object v13, v11, Lka/c1;->j:Ljava/util/ArrayList;

    .line 132
    .line 133
    iget v12, v11, Lka/c1;->e:I

    .line 134
    .line 135
    iput v12, v11, Lka/c1;->d:I

    .line 136
    .line 137
    :cond_7
    iget-object v11, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->F:Lka/c1;

    .line 138
    .line 139
    iget-boolean v12, v11, Lka/c1;->m:Z

    .line 140
    .line 141
    iput-boolean v12, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->E:Z

    .line 142
    .line 143
    iget-boolean v11, v11, Lka/c1;->k:Z

    .line 144
    .line 145
    invoke-virtual {v0, v13}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->c(Ljava/lang/String;)V

    .line 146
    .line 147
    .line 148
    iget-object v12, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->F:Lka/c1;

    .line 149
    .line 150
    if-eqz v12, :cond_8

    .line 151
    .line 152
    iget-boolean v13, v12, Lka/c1;->k:Z

    .line 153
    .line 154
    if-eq v13, v11, :cond_8

    .line 155
    .line 156
    iput-boolean v11, v12, Lka/c1;->k:Z

    .line 157
    .line 158
    :cond_8
    iput-boolean v11, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->w:Z

    .line 159
    .line 160
    invoke-virtual {v0}, Lka/f0;->n0()V

    .line 161
    .line 162
    .line 163
    invoke-virtual {v0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->X0()V

    .line 164
    .line 165
    .line 166
    iget-object v11, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->F:Lka/c1;

    .line 167
    .line 168
    iget v12, v11, Lka/c1;->d:I

    .line 169
    .line 170
    if-eq v12, v4, :cond_9

    .line 171
    .line 172
    iput v12, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->z:I

    .line 173
    .line 174
    iget-boolean v12, v11, Lka/c1;->l:Z

    .line 175
    .line 176
    iput-boolean v12, v5, Lka/z0;->c:Z

    .line 177
    .line 178
    goto :goto_5

    .line 179
    :cond_9
    iget-boolean v12, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->x:Z

    .line 180
    .line 181
    iput-boolean v12, v5, Lka/z0;->c:Z

    .line 182
    .line 183
    :goto_5
    iget v12, v11, Lka/c1;->h:I

    .line 184
    .line 185
    if-le v12, v8, :cond_b

    .line 186
    .line 187
    iget-object v12, v11, Lka/c1;->i:[I

    .line 188
    .line 189
    iput-object v12, v9, Lb81/b;->e:Ljava/lang/Object;

    .line 190
    .line 191
    iget-object v11, v11, Lka/c1;->j:Ljava/util/ArrayList;

    .line 192
    .line 193
    iput-object v11, v9, Lb81/b;->f:Ljava/lang/Object;

    .line 194
    .line 195
    goto :goto_6

    .line 196
    :cond_a
    invoke-virtual {v0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->X0()V

    .line 197
    .line 198
    .line 199
    iget-boolean v11, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->x:Z

    .line 200
    .line 201
    iput-boolean v11, v5, Lka/z0;->c:Z

    .line 202
    .line 203
    :cond_b
    :goto_6
    iget-boolean v11, v2, Lka/r0;->g:Z

    .line 204
    .line 205
    if-nez v11, :cond_20

    .line 206
    .line 207
    iget v11, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->z:I

    .line 208
    .line 209
    if-ne v11, v4, :cond_c

    .line 210
    .line 211
    goto/16 :goto_10

    .line 212
    .line 213
    :cond_c
    if-ltz v11, :cond_1f

    .line 214
    .line 215
    invoke-virtual {v2}, Lka/r0;->b()I

    .line 216
    .line 217
    .line 218
    move-result v12

    .line 219
    if-lt v11, v12, :cond_d

    .line 220
    .line 221
    goto/16 :goto_f

    .line 222
    .line 223
    :cond_d
    iget-object v11, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->F:Lka/c1;

    .line 224
    .line 225
    if-eqz v11, :cond_f

    .line 226
    .line 227
    iget v12, v11, Lka/c1;->d:I

    .line 228
    .line 229
    if-eq v12, v4, :cond_f

    .line 230
    .line 231
    iget v11, v11, Lka/c1;->f:I

    .line 232
    .line 233
    if-ge v11, v8, :cond_e

    .line 234
    .line 235
    goto :goto_7

    .line 236
    :cond_e
    iput v10, v5, Lka/z0;->b:I

    .line 237
    .line 238
    iget v11, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->z:I

    .line 239
    .line 240
    iput v11, v5, Lka/z0;->a:I

    .line 241
    .line 242
    goto/16 :goto_14

    .line 243
    .line 244
    :cond_f
    :goto_7
    iget v11, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->z:I

    .line 245
    .line 246
    invoke-virtual {v0, v11}, Lka/f0;->q(I)Landroid/view/View;

    .line 247
    .line 248
    .line 249
    move-result-object v11

    .line 250
    if-eqz v11, :cond_17

    .line 251
    .line 252
    iget-boolean v12, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->x:Z

    .line 253
    .line 254
    if-eqz v12, :cond_10

    .line 255
    .line 256
    invoke-virtual {v0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->K0()I

    .line 257
    .line 258
    .line 259
    move-result v12

    .line 260
    goto :goto_8

    .line 261
    :cond_10
    invoke-virtual {v0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->J0()I

    .line 262
    .line 263
    .line 264
    move-result v12

    .line 265
    :goto_8
    iput v12, v5, Lka/z0;->a:I

    .line 266
    .line 267
    iget v12, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->A:I

    .line 268
    .line 269
    if-eq v12, v10, :cond_12

    .line 270
    .line 271
    iget-boolean v12, v5, Lka/z0;->c:Z

    .line 272
    .line 273
    if-eqz v12, :cond_11

    .line 274
    .line 275
    iget-object v12, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 276
    .line 277
    invoke-virtual {v12}, Lka/u;->i()I

    .line 278
    .line 279
    .line 280
    move-result v12

    .line 281
    iget v13, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->A:I

    .line 282
    .line 283
    sub-int/2addr v12, v13

    .line 284
    iget-object v13, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 285
    .line 286
    invoke-virtual {v13, v11}, Lka/u;->d(Landroid/view/View;)I

    .line 287
    .line 288
    .line 289
    move-result v11

    .line 290
    sub-int/2addr v12, v11

    .line 291
    iput v12, v5, Lka/z0;->b:I

    .line 292
    .line 293
    goto/16 :goto_14

    .line 294
    .line 295
    :cond_11
    iget-object v12, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 296
    .line 297
    invoke-virtual {v12}, Lka/u;->m()I

    .line 298
    .line 299
    .line 300
    move-result v12

    .line 301
    iget v13, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->A:I

    .line 302
    .line 303
    add-int/2addr v12, v13

    .line 304
    iget-object v13, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 305
    .line 306
    invoke-virtual {v13, v11}, Lka/u;->g(Landroid/view/View;)I

    .line 307
    .line 308
    .line 309
    move-result v11

    .line 310
    sub-int/2addr v12, v11

    .line 311
    iput v12, v5, Lka/z0;->b:I

    .line 312
    .line 313
    goto/16 :goto_14

    .line 314
    .line 315
    :cond_12
    iget-object v12, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 316
    .line 317
    invoke-virtual {v12, v11}, Lka/u;->e(Landroid/view/View;)I

    .line 318
    .line 319
    .line 320
    move-result v12

    .line 321
    iget-object v13, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 322
    .line 323
    invoke-virtual {v13}, Lka/u;->n()I

    .line 324
    .line 325
    .line 326
    move-result v13

    .line 327
    if-le v12, v13, :cond_14

    .line 328
    .line 329
    iget-boolean v11, v5, Lka/z0;->c:Z

    .line 330
    .line 331
    if-eqz v11, :cond_13

    .line 332
    .line 333
    iget-object v11, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 334
    .line 335
    invoke-virtual {v11}, Lka/u;->i()I

    .line 336
    .line 337
    .line 338
    move-result v11

    .line 339
    goto :goto_9

    .line 340
    :cond_13
    iget-object v11, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 341
    .line 342
    invoke-virtual {v11}, Lka/u;->m()I

    .line 343
    .line 344
    .line 345
    move-result v11

    .line 346
    :goto_9
    iput v11, v5, Lka/z0;->b:I

    .line 347
    .line 348
    goto/16 :goto_14

    .line 349
    .line 350
    :cond_14
    iget-object v12, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 351
    .line 352
    invoke-virtual {v12, v11}, Lka/u;->g(Landroid/view/View;)I

    .line 353
    .line 354
    .line 355
    move-result v12

    .line 356
    iget-object v13, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 357
    .line 358
    invoke-virtual {v13}, Lka/u;->m()I

    .line 359
    .line 360
    .line 361
    move-result v13

    .line 362
    sub-int/2addr v12, v13

    .line 363
    if-gez v12, :cond_15

    .line 364
    .line 365
    neg-int v11, v12

    .line 366
    iput v11, v5, Lka/z0;->b:I

    .line 367
    .line 368
    goto/16 :goto_14

    .line 369
    .line 370
    :cond_15
    iget-object v12, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 371
    .line 372
    invoke-virtual {v12}, Lka/u;->i()I

    .line 373
    .line 374
    .line 375
    move-result v12

    .line 376
    iget-object v13, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 377
    .line 378
    invoke-virtual {v13, v11}, Lka/u;->d(Landroid/view/View;)I

    .line 379
    .line 380
    .line 381
    move-result v11

    .line 382
    sub-int/2addr v12, v11

    .line 383
    if-gez v12, :cond_16

    .line 384
    .line 385
    iput v12, v5, Lka/z0;->b:I

    .line 386
    .line 387
    goto/16 :goto_14

    .line 388
    .line 389
    :cond_16
    iput v10, v5, Lka/z0;->b:I

    .line 390
    .line 391
    goto/16 :goto_14

    .line 392
    .line 393
    :cond_17
    iget v11, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->z:I

    .line 394
    .line 395
    iput v11, v5, Lka/z0;->a:I

    .line 396
    .line 397
    iget v12, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->A:I

    .line 398
    .line 399
    if-ne v12, v10, :cond_1d

    .line 400
    .line 401
    invoke-virtual {v0}, Lka/f0;->v()I

    .line 402
    .line 403
    .line 404
    move-result v12

    .line 405
    if-nez v12, :cond_18

    .line 406
    .line 407
    iget-boolean v11, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->x:Z

    .line 408
    .line 409
    if-eqz v11, :cond_1a

    .line 410
    .line 411
    goto :goto_b

    .line 412
    :cond_18
    invoke-virtual {v0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->J0()I

    .line 413
    .line 414
    .line 415
    move-result v12

    .line 416
    if-ge v11, v12, :cond_19

    .line 417
    .line 418
    move v11, v8

    .line 419
    goto :goto_a

    .line 420
    :cond_19
    move v11, v7

    .line 421
    :goto_a
    iget-boolean v12, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->x:Z

    .line 422
    .line 423
    if-eq v11, v12, :cond_1b

    .line 424
    .line 425
    :cond_1a
    move v11, v7

    .line 426
    goto :goto_c

    .line 427
    :cond_1b
    :goto_b
    move v11, v8

    .line 428
    :goto_c
    iput-boolean v11, v5, Lka/z0;->c:Z

    .line 429
    .line 430
    if-eqz v11, :cond_1c

    .line 431
    .line 432
    iget-object v11, v6, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 433
    .line 434
    invoke-virtual {v11}, Lka/u;->i()I

    .line 435
    .line 436
    .line 437
    move-result v11

    .line 438
    goto :goto_d

    .line 439
    :cond_1c
    iget-object v11, v6, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 440
    .line 441
    invoke-virtual {v11}, Lka/u;->m()I

    .line 442
    .line 443
    .line 444
    move-result v11

    .line 445
    :goto_d
    iput v11, v5, Lka/z0;->b:I

    .line 446
    .line 447
    goto :goto_e

    .line 448
    :cond_1d
    iget-boolean v11, v5, Lka/z0;->c:Z

    .line 449
    .line 450
    if-eqz v11, :cond_1e

    .line 451
    .line 452
    iget-object v11, v6, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 453
    .line 454
    invoke-virtual {v11}, Lka/u;->i()I

    .line 455
    .line 456
    .line 457
    move-result v11

    .line 458
    sub-int/2addr v11, v12

    .line 459
    iput v11, v5, Lka/z0;->b:I

    .line 460
    .line 461
    goto :goto_e

    .line 462
    :cond_1e
    iget-object v11, v6, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 463
    .line 464
    invoke-virtual {v11}, Lka/u;->m()I

    .line 465
    .line 466
    .line 467
    move-result v11

    .line 468
    add-int/2addr v11, v12

    .line 469
    iput v11, v5, Lka/z0;->b:I

    .line 470
    .line 471
    :goto_e
    iput-boolean v8, v5, Lka/z0;->d:Z

    .line 472
    .line 473
    goto :goto_14

    .line 474
    :cond_1f
    :goto_f
    iput v4, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->z:I

    .line 475
    .line 476
    iput v10, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->A:I

    .line 477
    .line 478
    :cond_20
    :goto_10
    iget-boolean v11, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->D:Z

    .line 479
    .line 480
    if-eqz v11, :cond_23

    .line 481
    .line 482
    invoke-virtual {v2}, Lka/r0;->b()I

    .line 483
    .line 484
    .line 485
    move-result v11

    .line 486
    invoke-virtual {v0}, Lka/f0;->v()I

    .line 487
    .line 488
    .line 489
    move-result v12

    .line 490
    sub-int/2addr v12, v8

    .line 491
    :goto_11
    if-ltz v12, :cond_22

    .line 492
    .line 493
    invoke-virtual {v0, v12}, Lka/f0;->u(I)Landroid/view/View;

    .line 494
    .line 495
    .line 496
    move-result-object v13

    .line 497
    invoke-static {v13}, Lka/f0;->H(Landroid/view/View;)I

    .line 498
    .line 499
    .line 500
    move-result v13

    .line 501
    if-ltz v13, :cond_21

    .line 502
    .line 503
    if-ge v13, v11, :cond_21

    .line 504
    .line 505
    goto :goto_13

    .line 506
    :cond_21
    add-int/lit8 v12, v12, -0x1

    .line 507
    .line 508
    goto :goto_11

    .line 509
    :cond_22
    move v13, v7

    .line 510
    goto :goto_13

    .line 511
    :cond_23
    invoke-virtual {v2}, Lka/r0;->b()I

    .line 512
    .line 513
    .line 514
    move-result v11

    .line 515
    invoke-virtual {v0}, Lka/f0;->v()I

    .line 516
    .line 517
    .line 518
    move-result v12

    .line 519
    move v13, v7

    .line 520
    :goto_12
    if-ge v13, v12, :cond_22

    .line 521
    .line 522
    invoke-virtual {v0, v13}, Lka/f0;->u(I)Landroid/view/View;

    .line 523
    .line 524
    .line 525
    move-result-object v14

    .line 526
    invoke-static {v14}, Lka/f0;->H(Landroid/view/View;)I

    .line 527
    .line 528
    .line 529
    move-result v14

    .line 530
    if-ltz v14, :cond_24

    .line 531
    .line 532
    if-ge v14, v11, :cond_24

    .line 533
    .line 534
    move v13, v14

    .line 535
    goto :goto_13

    .line 536
    :cond_24
    add-int/lit8 v13, v13, 0x1

    .line 537
    .line 538
    goto :goto_12

    .line 539
    :goto_13
    iput v13, v5, Lka/z0;->a:I

    .line 540
    .line 541
    iput v10, v5, Lka/z0;->b:I

    .line 542
    .line 543
    :goto_14
    iput-boolean v8, v5, Lka/z0;->e:Z

    .line 544
    .line 545
    :cond_25
    iget-object v11, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->F:Lka/c1;

    .line 546
    .line 547
    if-nez v11, :cond_27

    .line 548
    .line 549
    iget v11, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->z:I

    .line 550
    .line 551
    if-ne v11, v4, :cond_27

    .line 552
    .line 553
    iget-boolean v11, v5, Lka/z0;->c:Z

    .line 554
    .line 555
    iget-boolean v12, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->D:Z

    .line 556
    .line 557
    if-ne v11, v12, :cond_26

    .line 558
    .line 559
    invoke-virtual {v0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->P0()Z

    .line 560
    .line 561
    .line 562
    move-result v11

    .line 563
    iget-boolean v12, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->E:Z

    .line 564
    .line 565
    if-eq v11, v12, :cond_27

    .line 566
    .line 567
    :cond_26
    invoke-virtual {v9}, Lb81/b;->k()V

    .line 568
    .line 569
    .line 570
    iput-boolean v8, v5, Lka/z0;->d:Z

    .line 571
    .line 572
    :cond_27
    invoke-virtual {v0}, Lka/f0;->v()I

    .line 573
    .line 574
    .line 575
    move-result v9

    .line 576
    if-lez v9, :cond_36

    .line 577
    .line 578
    iget-object v9, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->F:Lka/c1;

    .line 579
    .line 580
    if-eqz v9, :cond_28

    .line 581
    .line 582
    iget v9, v9, Lka/c1;->f:I

    .line 583
    .line 584
    if-ge v9, v8, :cond_36

    .line 585
    .line 586
    :cond_28
    iget-boolean v9, v5, Lka/z0;->d:Z

    .line 587
    .line 588
    if-eqz v9, :cond_2a

    .line 589
    .line 590
    move v3, v7

    .line 591
    :goto_15
    iget v6, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 592
    .line 593
    if-ge v3, v6, :cond_36

    .line 594
    .line 595
    iget-object v6, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->q:[Lka/d1;

    .line 596
    .line 597
    aget-object v6, v6, v3

    .line 598
    .line 599
    invoke-virtual {v6}, Lka/d1;->b()V

    .line 600
    .line 601
    .line 602
    iget v6, v5, Lka/z0;->b:I

    .line 603
    .line 604
    if-eq v6, v10, :cond_29

    .line 605
    .line 606
    iget-object v9, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->q:[Lka/d1;

    .line 607
    .line 608
    aget-object v9, v9, v3

    .line 609
    .line 610
    iput v6, v9, Lka/d1;->b:I

    .line 611
    .line 612
    iput v6, v9, Lka/d1;->c:I

    .line 613
    .line 614
    :cond_29
    add-int/lit8 v3, v3, 0x1

    .line 615
    .line 616
    goto :goto_15

    .line 617
    :cond_2a
    if-nez v3, :cond_2c

    .line 618
    .line 619
    iget-object v3, v5, Lka/z0;->f:[I

    .line 620
    .line 621
    if-nez v3, :cond_2b

    .line 622
    .line 623
    goto :goto_17

    .line 624
    :cond_2b
    move v3, v7

    .line 625
    :goto_16
    iget v6, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 626
    .line 627
    if-ge v3, v6, :cond_36

    .line 628
    .line 629
    iget-object v6, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->q:[Lka/d1;

    .line 630
    .line 631
    aget-object v6, v6, v3

    .line 632
    .line 633
    invoke-virtual {v6}, Lka/d1;->b()V

    .line 634
    .line 635
    .line 636
    iget-object v9, v5, Lka/z0;->f:[I

    .line 637
    .line 638
    aget v9, v9, v3

    .line 639
    .line 640
    iput v9, v6, Lka/d1;->b:I

    .line 641
    .line 642
    iput v9, v6, Lka/d1;->c:I

    .line 643
    .line 644
    add-int/lit8 v3, v3, 0x1

    .line 645
    .line 646
    goto :goto_16

    .line 647
    :cond_2c
    :goto_17
    move v3, v7

    .line 648
    :goto_18
    iget v9, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 649
    .line 650
    if-ge v3, v9, :cond_33

    .line 651
    .line 652
    iget-object v9, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->q:[Lka/d1;

    .line 653
    .line 654
    aget-object v9, v9, v3

    .line 655
    .line 656
    iget-boolean v11, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->x:Z

    .line 657
    .line 658
    iget v12, v5, Lka/z0;->b:I

    .line 659
    .line 660
    iget-object v13, v9, Lka/d1;->f:Landroidx/recyclerview/widget/StaggeredGridLayoutManager;

    .line 661
    .line 662
    if-eqz v11, :cond_2d

    .line 663
    .line 664
    invoke-virtual {v9, v10}, Lka/d1;->f(I)I

    .line 665
    .line 666
    .line 667
    move-result v14

    .line 668
    goto :goto_19

    .line 669
    :cond_2d
    invoke-virtual {v9, v10}, Lka/d1;->h(I)I

    .line 670
    .line 671
    .line 672
    move-result v14

    .line 673
    :goto_19
    invoke-virtual {v9}, Lka/d1;->b()V

    .line 674
    .line 675
    .line 676
    if-ne v14, v10, :cond_2e

    .line 677
    .line 678
    goto :goto_1a

    .line 679
    :cond_2e
    if-eqz v11, :cond_2f

    .line 680
    .line 681
    iget-object v15, v13, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 682
    .line 683
    invoke-virtual {v15}, Lka/u;->i()I

    .line 684
    .line 685
    .line 686
    move-result v15

    .line 687
    if-lt v14, v15, :cond_32

    .line 688
    .line 689
    :cond_2f
    if-nez v11, :cond_30

    .line 690
    .line 691
    iget-object v11, v13, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 692
    .line 693
    invoke-virtual {v11}, Lka/u;->m()I

    .line 694
    .line 695
    .line 696
    move-result v11

    .line 697
    if-le v14, v11, :cond_30

    .line 698
    .line 699
    goto :goto_1a

    .line 700
    :cond_30
    if-eq v12, v10, :cond_31

    .line 701
    .line 702
    add-int/2addr v14, v12

    .line 703
    :cond_31
    iput v14, v9, Lka/d1;->c:I

    .line 704
    .line 705
    iput v14, v9, Lka/d1;->b:I

    .line 706
    .line 707
    :cond_32
    :goto_1a
    add-int/lit8 v3, v3, 0x1

    .line 708
    .line 709
    goto :goto_18

    .line 710
    :cond_33
    iget-object v3, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->q:[Lka/d1;

    .line 711
    .line 712
    array-length v9, v3

    .line 713
    iget-object v11, v5, Lka/z0;->f:[I

    .line 714
    .line 715
    if-eqz v11, :cond_34

    .line 716
    .line 717
    array-length v11, v11

    .line 718
    if-ge v11, v9, :cond_35

    .line 719
    .line 720
    :cond_34
    iget-object v6, v6, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->q:[Lka/d1;

    .line 721
    .line 722
    array-length v6, v6

    .line 723
    new-array v6, v6, [I

    .line 724
    .line 725
    iput-object v6, v5, Lka/z0;->f:[I

    .line 726
    .line 727
    :cond_35
    move v6, v7

    .line 728
    :goto_1b
    if-ge v6, v9, :cond_36

    .line 729
    .line 730
    iget-object v11, v5, Lka/z0;->f:[I

    .line 731
    .line 732
    aget-object v12, v3, v6

    .line 733
    .line 734
    invoke-virtual {v12, v10}, Lka/d1;->h(I)I

    .line 735
    .line 736
    .line 737
    move-result v12

    .line 738
    aput v12, v11, v6

    .line 739
    .line 740
    add-int/lit8 v6, v6, 0x1

    .line 741
    .line 742
    goto :goto_1b

    .line 743
    :cond_36
    invoke-virtual/range {p0 .. p1}, Lka/f0;->p(Lka/l0;)V

    .line 744
    .line 745
    .line 746
    iget-object v3, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->v:Lka/o;

    .line 747
    .line 748
    iput-boolean v7, v3, Lka/o;->a:Z

    .line 749
    .line 750
    iget-object v6, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->s:Lka/u;

    .line 751
    .line 752
    invoke-virtual {v6}, Lka/u;->n()I

    .line 753
    .line 754
    .line 755
    move-result v6

    .line 756
    iget v9, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 757
    .line 758
    div-int v9, v6, v9

    .line 759
    .line 760
    iput v9, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->u:I

    .line 761
    .line 762
    iget-object v9, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->s:Lka/u;

    .line 763
    .line 764
    invoke-virtual {v9}, Lka/u;->k()I

    .line 765
    .line 766
    .line 767
    move-result v9

    .line 768
    invoke-static {v6, v9}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 769
    .line 770
    .line 771
    iget v6, v5, Lka/z0;->a:I

    .line 772
    .line 773
    invoke-virtual {v0, v6, v2}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->a1(ILka/r0;)V

    .line 774
    .line 775
    .line 776
    iget-boolean v6, v5, Lka/z0;->c:Z

    .line 777
    .line 778
    if-eqz v6, :cond_37

    .line 779
    .line 780
    invoke-virtual {v0, v4}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->Z0(I)V

    .line 781
    .line 782
    .line 783
    invoke-virtual {v0, v1, v3, v2}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->E0(Lka/l0;Lka/o;Lka/r0;)I

    .line 784
    .line 785
    .line 786
    invoke-virtual {v0, v8}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->Z0(I)V

    .line 787
    .line 788
    .line 789
    iget v4, v5, Lka/z0;->a:I

    .line 790
    .line 791
    iget v6, v3, Lka/o;->d:I

    .line 792
    .line 793
    add-int/2addr v4, v6

    .line 794
    iput v4, v3, Lka/o;->c:I

    .line 795
    .line 796
    invoke-virtual {v0, v1, v3, v2}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->E0(Lka/l0;Lka/o;Lka/r0;)I

    .line 797
    .line 798
    .line 799
    goto :goto_1c

    .line 800
    :cond_37
    invoke-virtual {v0, v8}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->Z0(I)V

    .line 801
    .line 802
    .line 803
    invoke-virtual {v0, v1, v3, v2}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->E0(Lka/l0;Lka/o;Lka/r0;)I

    .line 804
    .line 805
    .line 806
    invoke-virtual {v0, v4}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->Z0(I)V

    .line 807
    .line 808
    .line 809
    iget v4, v5, Lka/z0;->a:I

    .line 810
    .line 811
    iget v6, v3, Lka/o;->d:I

    .line 812
    .line 813
    add-int/2addr v4, v6

    .line 814
    iput v4, v3, Lka/o;->c:I

    .line 815
    .line 816
    invoke-virtual {v0, v1, v3, v2}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->E0(Lka/l0;Lka/o;Lka/r0;)I

    .line 817
    .line 818
    .line 819
    :goto_1c
    iget-object v3, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->s:Lka/u;

    .line 820
    .line 821
    invoke-virtual {v3}, Lka/u;->k()I

    .line 822
    .line 823
    .line 824
    move-result v3

    .line 825
    const/high16 v4, 0x40000000    # 2.0f

    .line 826
    .line 827
    if-ne v3, v4, :cond_38

    .line 828
    .line 829
    goto/16 :goto_21

    .line 830
    .line 831
    :cond_38
    invoke-virtual {v0}, Lka/f0;->v()I

    .line 832
    .line 833
    .line 834
    move-result v3

    .line 835
    const/4 v4, 0x0

    .line 836
    move v6, v7

    .line 837
    :goto_1d
    if-ge v6, v3, :cond_3a

    .line 838
    .line 839
    invoke-virtual {v0, v6}, Lka/f0;->u(I)Landroid/view/View;

    .line 840
    .line 841
    .line 842
    move-result-object v9

    .line 843
    iget-object v11, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->s:Lka/u;

    .line 844
    .line 845
    invoke-virtual {v11, v9}, Lka/u;->e(Landroid/view/View;)I

    .line 846
    .line 847
    .line 848
    move-result v11

    .line 849
    int-to-float v11, v11

    .line 850
    cmpg-float v12, v11, v4

    .line 851
    .line 852
    if-gez v12, :cond_39

    .line 853
    .line 854
    goto :goto_1e

    .line 855
    :cond_39
    invoke-virtual {v9}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 856
    .line 857
    .line 858
    move-result-object v9

    .line 859
    check-cast v9, Lka/a1;

    .line 860
    .line 861
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 862
    .line 863
    .line 864
    invoke-static {v4, v11}, Ljava/lang/Math;->max(FF)F

    .line 865
    .line 866
    .line 867
    move-result v4

    .line 868
    :goto_1e
    add-int/lit8 v6, v6, 0x1

    .line 869
    .line 870
    goto :goto_1d

    .line 871
    :cond_3a
    iget v6, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->u:I

    .line 872
    .line 873
    iget v9, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 874
    .line 875
    int-to-float v9, v9

    .line 876
    mul-float/2addr v4, v9

    .line 877
    invoke-static {v4}, Ljava/lang/Math;->round(F)I

    .line 878
    .line 879
    .line 880
    move-result v4

    .line 881
    iget-object v9, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->s:Lka/u;

    .line 882
    .line 883
    invoke-virtual {v9}, Lka/u;->k()I

    .line 884
    .line 885
    .line 886
    move-result v9

    .line 887
    if-ne v9, v10, :cond_3b

    .line 888
    .line 889
    iget-object v9, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->s:Lka/u;

    .line 890
    .line 891
    invoke-virtual {v9}, Lka/u;->n()I

    .line 892
    .line 893
    .line 894
    move-result v9

    .line 895
    invoke-static {v4, v9}, Ljava/lang/Math;->min(II)I

    .line 896
    .line 897
    .line 898
    move-result v4

    .line 899
    :cond_3b
    iget v9, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 900
    .line 901
    div-int v9, v4, v9

    .line 902
    .line 903
    iput v9, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->u:I

    .line 904
    .line 905
    iget-object v9, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->s:Lka/u;

    .line 906
    .line 907
    invoke-virtual {v9}, Lka/u;->k()I

    .line 908
    .line 909
    .line 910
    move-result v9

    .line 911
    invoke-static {v4, v9}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 912
    .line 913
    .line 914
    iget v4, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->u:I

    .line 915
    .line 916
    if-ne v4, v6, :cond_3c

    .line 917
    .line 918
    goto :goto_21

    .line 919
    :cond_3c
    move v4, v7

    .line 920
    :goto_1f
    if-ge v4, v3, :cond_3f

    .line 921
    .line 922
    invoke-virtual {v0, v4}, Lka/f0;->u(I)Landroid/view/View;

    .line 923
    .line 924
    .line 925
    move-result-object v9

    .line 926
    invoke-virtual {v9}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 927
    .line 928
    .line 929
    move-result-object v10

    .line 930
    check-cast v10, Lka/a1;

    .line 931
    .line 932
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 933
    .line 934
    .line 935
    invoke-virtual {v0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->P0()Z

    .line 936
    .line 937
    .line 938
    move-result v11

    .line 939
    if-eqz v11, :cond_3d

    .line 940
    .line 941
    iget v11, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->t:I

    .line 942
    .line 943
    if-ne v11, v8, :cond_3d

    .line 944
    .line 945
    iget v11, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 946
    .line 947
    sub-int/2addr v11, v8

    .line 948
    iget-object v10, v10, Lka/a1;->e:Lka/d1;

    .line 949
    .line 950
    iget v10, v10, Lka/d1;->e:I

    .line 951
    .line 952
    sub-int/2addr v11, v10

    .line 953
    neg-int v10, v11

    .line 954
    iget v11, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->u:I

    .line 955
    .line 956
    mul-int/2addr v11, v10

    .line 957
    mul-int/2addr v10, v6

    .line 958
    sub-int/2addr v11, v10

    .line 959
    invoke-virtual {v9, v11}, Landroid/view/View;->offsetLeftAndRight(I)V

    .line 960
    .line 961
    .line 962
    goto :goto_20

    .line 963
    :cond_3d
    iget-object v10, v10, Lka/a1;->e:Lka/d1;

    .line 964
    .line 965
    iget v10, v10, Lka/d1;->e:I

    .line 966
    .line 967
    iget v11, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->u:I

    .line 968
    .line 969
    mul-int/2addr v11, v10

    .line 970
    mul-int/2addr v10, v6

    .line 971
    iget v12, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->t:I

    .line 972
    .line 973
    if-ne v12, v8, :cond_3e

    .line 974
    .line 975
    sub-int/2addr v11, v10

    .line 976
    invoke-virtual {v9, v11}, Landroid/view/View;->offsetLeftAndRight(I)V

    .line 977
    .line 978
    .line 979
    goto :goto_20

    .line 980
    :cond_3e
    sub-int/2addr v11, v10

    .line 981
    invoke-virtual {v9, v11}, Landroid/view/View;->offsetTopAndBottom(I)V

    .line 982
    .line 983
    .line 984
    :goto_20
    add-int/lit8 v4, v4, 0x1

    .line 985
    .line 986
    goto :goto_1f

    .line 987
    :cond_3f
    :goto_21
    invoke-virtual {v0}, Lka/f0;->v()I

    .line 988
    .line 989
    .line 990
    move-result v3

    .line 991
    if-lez v3, :cond_41

    .line 992
    .line 993
    iget-boolean v3, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->x:Z

    .line 994
    .line 995
    if-eqz v3, :cond_40

    .line 996
    .line 997
    invoke-virtual {v0, v1, v2, v8}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->H0(Lka/l0;Lka/r0;Z)V

    .line 998
    .line 999
    .line 1000
    invoke-virtual {v0, v1, v2, v7}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->I0(Lka/l0;Lka/r0;Z)V

    .line 1001
    .line 1002
    .line 1003
    goto :goto_22

    .line 1004
    :cond_40
    invoke-virtual {v0, v1, v2, v8}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->I0(Lka/l0;Lka/r0;Z)V

    .line 1005
    .line 1006
    .line 1007
    invoke-virtual {v0, v1, v2, v7}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->H0(Lka/l0;Lka/r0;Z)V

    .line 1008
    .line 1009
    .line 1010
    :cond_41
    :goto_22
    if-eqz p3, :cond_43

    .line 1011
    .line 1012
    iget-boolean v3, v2, Lka/r0;->g:Z

    .line 1013
    .line 1014
    if-nez v3, :cond_43

    .line 1015
    .line 1016
    iget v3, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->C:I

    .line 1017
    .line 1018
    if-eqz v3, :cond_43

    .line 1019
    .line 1020
    invoke-virtual {v0}, Lka/f0;->v()I

    .line 1021
    .line 1022
    .line 1023
    move-result v3

    .line 1024
    if-lez v3, :cond_43

    .line 1025
    .line 1026
    invoke-virtual {v0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->O0()Landroid/view/View;

    .line 1027
    .line 1028
    .line 1029
    move-result-object v3

    .line 1030
    if-eqz v3, :cond_43

    .line 1031
    .line 1032
    iget-object v3, v0, Lka/f0;->b:Landroidx/recyclerview/widget/RecyclerView;

    .line 1033
    .line 1034
    if-eqz v3, :cond_42

    .line 1035
    .line 1036
    iget-object v4, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->K:Laq/p;

    .line 1037
    .line 1038
    invoke-virtual {v3, v4}, Landroid/view/View;->removeCallbacks(Ljava/lang/Runnable;)Z

    .line 1039
    .line 1040
    .line 1041
    :cond_42
    invoke-virtual {v0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->C0()Z

    .line 1042
    .line 1043
    .line 1044
    move-result v3

    .line 1045
    if-eqz v3, :cond_43

    .line 1046
    .line 1047
    goto :goto_23

    .line 1048
    :cond_43
    move v8, v7

    .line 1049
    :goto_23
    iget-boolean v3, v2, Lka/r0;->g:Z

    .line 1050
    .line 1051
    if-eqz v3, :cond_44

    .line 1052
    .line 1053
    invoke-virtual {v5}, Lka/z0;->a()V

    .line 1054
    .line 1055
    .line 1056
    :cond_44
    iget-boolean v3, v5, Lka/z0;->c:Z

    .line 1057
    .line 1058
    iput-boolean v3, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->D:Z

    .line 1059
    .line 1060
    invoke-virtual {v0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->P0()Z

    .line 1061
    .line 1062
    .line 1063
    move-result v3

    .line 1064
    iput-boolean v3, v0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->E:Z

    .line 1065
    .line 1066
    if-eqz v8, :cond_45

    .line 1067
    .line 1068
    invoke-virtual {v5}, Lka/z0;->a()V

    .line 1069
    .line 1070
    .line 1071
    invoke-virtual {v0, v1, v2, v7}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->R0(Lka/l0;Lka/r0;Z)V

    .line 1072
    .line 1073
    .line 1074
    :cond_45
    return-void
.end method

.method public final S(Landroidx/recyclerview/widget/RecyclerView;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lka/f0;->b:Landroidx/recyclerview/widget/RecyclerView;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->K:Laq/p;

    .line 6
    .line 7
    invoke-virtual {v0, v1}, Landroid/view/View;->removeCallbacks(Ljava/lang/Runnable;)Z

    .line 8
    .line 9
    .line 10
    :cond_0
    const/4 v0, 0x0

    .line 11
    :goto_0
    iget v1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 12
    .line 13
    if-ge v0, v1, :cond_1

    .line 14
    .line 15
    iget-object v1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->q:[Lka/d1;

    .line 16
    .line 17
    aget-object v1, v1, v0

    .line 18
    .line 19
    invoke-virtual {v1}, Lka/d1;->b()V

    .line 20
    .line 21
    .line 22
    add-int/lit8 v0, v0, 0x1

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_1
    invoke-virtual {p1}, Landroidx/recyclerview/widget/RecyclerView;->requestLayout()V

    .line 26
    .line 27
    .line 28
    return-void
.end method

.method public final S0(I)Z
    .locals 4

    .line 1
    iget v0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->t:I

    .line 2
    .line 3
    const/4 v1, -0x1

    .line 4
    const/4 v2, 0x0

    .line 5
    const/4 v3, 0x1

    .line 6
    if-nez v0, :cond_2

    .line 7
    .line 8
    if-ne p1, v1, :cond_0

    .line 9
    .line 10
    move p1, v3

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    move p1, v2

    .line 13
    :goto_0
    iget-boolean p0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->x:Z

    .line 14
    .line 15
    if-eq p1, p0, :cond_1

    .line 16
    .line 17
    return v3

    .line 18
    :cond_1
    return v2

    .line 19
    :cond_2
    if-ne p1, v1, :cond_3

    .line 20
    .line 21
    move p1, v3

    .line 22
    goto :goto_1

    .line 23
    :cond_3
    move p1, v2

    .line 24
    :goto_1
    iget-boolean v0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->x:Z

    .line 25
    .line 26
    if-ne p1, v0, :cond_4

    .line 27
    .line 28
    move p1, v3

    .line 29
    goto :goto_2

    .line 30
    :cond_4
    move p1, v2

    .line 31
    :goto_2
    invoke-virtual {p0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->P0()Z

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    if-ne p1, p0, :cond_5

    .line 36
    .line 37
    return v3

    .line 38
    :cond_5
    return v2
.end method

.method public final T(Landroid/view/View;ILka/l0;Lka/r0;)Landroid/view/View;
    .locals 8

    .line 1
    invoke-virtual {p0}, Lka/f0;->v()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-nez v0, :cond_0

    .line 7
    .line 8
    goto/16 :goto_10

    .line 9
    .line 10
    :cond_0
    iget-object v0, p0, Lka/f0;->b:Landroidx/recyclerview/widget/RecyclerView;

    .line 11
    .line 12
    if-nez v0, :cond_1

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_1
    invoke-virtual {v0, p1}, Landroidx/recyclerview/widget/RecyclerView;->B(Landroid/view/View;)Landroid/view/View;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    if-nez p1, :cond_2

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_2
    iget-object v0, p0, Lka/f0;->a:Lil/g;

    .line 23
    .line 24
    iget-object v0, v0, Lil/g;->g:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast v0, Ljava/util/ArrayList;

    .line 27
    .line 28
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    if-eqz v0, :cond_3

    .line 33
    .line 34
    :goto_0
    move-object p1, v1

    .line 35
    :cond_3
    if-nez p1, :cond_4

    .line 36
    .line 37
    goto/16 :goto_10

    .line 38
    .line 39
    :cond_4
    invoke-virtual {p0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->X0()V

    .line 40
    .line 41
    .line 42
    const/high16 v0, -0x80000000

    .line 43
    .line 44
    const/4 v2, -0x1

    .line 45
    const/4 v3, 0x1

    .line 46
    if-eq p2, v3, :cond_e

    .line 47
    .line 48
    const/4 v4, 0x2

    .line 49
    if-eq p2, v4, :cond_c

    .line 50
    .line 51
    const/16 v4, 0x11

    .line 52
    .line 53
    if-eq p2, v4, :cond_b

    .line 54
    .line 55
    const/16 v4, 0x21

    .line 56
    .line 57
    if-eq p2, v4, :cond_9

    .line 58
    .line 59
    const/16 v4, 0x42

    .line 60
    .line 61
    if-eq p2, v4, :cond_8

    .line 62
    .line 63
    const/16 v4, 0x82

    .line 64
    .line 65
    if-eq p2, v4, :cond_6

    .line 66
    .line 67
    :cond_5
    move p2, v0

    .line 68
    goto :goto_4

    .line 69
    :cond_6
    iget p2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->t:I

    .line 70
    .line 71
    if-ne p2, v3, :cond_5

    .line 72
    .line 73
    :cond_7
    :goto_1
    move p2, v3

    .line 74
    goto :goto_4

    .line 75
    :cond_8
    iget p2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->t:I

    .line 76
    .line 77
    if-nez p2, :cond_5

    .line 78
    .line 79
    goto :goto_1

    .line 80
    :cond_9
    iget p2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->t:I

    .line 81
    .line 82
    if-ne p2, v3, :cond_5

    .line 83
    .line 84
    :cond_a
    :goto_2
    move p2, v2

    .line 85
    goto :goto_4

    .line 86
    :cond_b
    iget p2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->t:I

    .line 87
    .line 88
    if-nez p2, :cond_5

    .line 89
    .line 90
    :goto_3
    goto :goto_2

    .line 91
    :cond_c
    iget p2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->t:I

    .line 92
    .line 93
    if-ne p2, v3, :cond_d

    .line 94
    .line 95
    goto :goto_1

    .line 96
    :cond_d
    invoke-virtual {p0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->P0()Z

    .line 97
    .line 98
    .line 99
    move-result p2

    .line 100
    if-eqz p2, :cond_7

    .line 101
    .line 102
    goto :goto_2

    .line 103
    :cond_e
    iget p2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->t:I

    .line 104
    .line 105
    if-ne p2, v3, :cond_f

    .line 106
    .line 107
    goto :goto_3

    .line 108
    :cond_f
    invoke-virtual {p0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->P0()Z

    .line 109
    .line 110
    .line 111
    move-result p2

    .line 112
    if-eqz p2, :cond_a

    .line 113
    .line 114
    goto :goto_1

    .line 115
    :goto_4
    if-ne p2, v0, :cond_10

    .line 116
    .line 117
    goto/16 :goto_10

    .line 118
    .line 119
    :cond_10
    invoke-virtual {p1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 120
    .line 121
    .line 122
    move-result-object v0

    .line 123
    check-cast v0, Lka/a1;

    .line 124
    .line 125
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 126
    .line 127
    .line 128
    iget-object v0, v0, Lka/a1;->e:Lka/d1;

    .line 129
    .line 130
    if-ne p2, v3, :cond_11

    .line 131
    .line 132
    invoke-virtual {p0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->K0()I

    .line 133
    .line 134
    .line 135
    move-result v4

    .line 136
    goto :goto_5

    .line 137
    :cond_11
    invoke-virtual {p0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->J0()I

    .line 138
    .line 139
    .line 140
    move-result v4

    .line 141
    :goto_5
    invoke-virtual {p0, v4, p4}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->a1(ILka/r0;)V

    .line 142
    .line 143
    .line 144
    invoke-virtual {p0, p2}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->Z0(I)V

    .line 145
    .line 146
    .line 147
    iget-object v5, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->v:Lka/o;

    .line 148
    .line 149
    iget v6, v5, Lka/o;->d:I

    .line 150
    .line 151
    add-int/2addr v6, v4

    .line 152
    iput v6, v5, Lka/o;->c:I

    .line 153
    .line 154
    iget-object v6, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 155
    .line 156
    invoke-virtual {v6}, Lka/u;->n()I

    .line 157
    .line 158
    .line 159
    move-result v6

    .line 160
    int-to-float v6, v6

    .line 161
    const v7, 0x3eaaaaab

    .line 162
    .line 163
    .line 164
    mul-float/2addr v6, v7

    .line 165
    float-to-int v6, v6

    .line 166
    iput v6, v5, Lka/o;->b:I

    .line 167
    .line 168
    iput-boolean v3, v5, Lka/o;->h:Z

    .line 169
    .line 170
    const/4 v6, 0x0

    .line 171
    iput-boolean v6, v5, Lka/o;->a:Z

    .line 172
    .line 173
    invoke-virtual {p0, p3, v5, p4}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->E0(Lka/l0;Lka/o;Lka/r0;)I

    .line 174
    .line 175
    .line 176
    iget-boolean p3, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->x:Z

    .line 177
    .line 178
    iput-boolean p3, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->D:Z

    .line 179
    .line 180
    invoke-virtual {v0, v4, p2}, Lka/d1;->g(II)Landroid/view/View;

    .line 181
    .line 182
    .line 183
    move-result-object p3

    .line 184
    if-eqz p3, :cond_12

    .line 185
    .line 186
    if-eq p3, p1, :cond_12

    .line 187
    .line 188
    return-object p3

    .line 189
    :cond_12
    invoke-virtual {p0, p2}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->S0(I)Z

    .line 190
    .line 191
    .line 192
    move-result p3

    .line 193
    if-eqz p3, :cond_14

    .line 194
    .line 195
    iget p3, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 196
    .line 197
    sub-int/2addr p3, v3

    .line 198
    :goto_6
    if-ltz p3, :cond_16

    .line 199
    .line 200
    iget-object p4, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->q:[Lka/d1;

    .line 201
    .line 202
    aget-object p4, p4, p3

    .line 203
    .line 204
    invoke-virtual {p4, v4, p2}, Lka/d1;->g(II)Landroid/view/View;

    .line 205
    .line 206
    .line 207
    move-result-object p4

    .line 208
    if-eqz p4, :cond_13

    .line 209
    .line 210
    if-eq p4, p1, :cond_13

    .line 211
    .line 212
    return-object p4

    .line 213
    :cond_13
    add-int/lit8 p3, p3, -0x1

    .line 214
    .line 215
    goto :goto_6

    .line 216
    :cond_14
    move p3, v6

    .line 217
    :goto_7
    iget p4, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 218
    .line 219
    if-ge p3, p4, :cond_16

    .line 220
    .line 221
    iget-object p4, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->q:[Lka/d1;

    .line 222
    .line 223
    aget-object p4, p4, p3

    .line 224
    .line 225
    invoke-virtual {p4, v4, p2}, Lka/d1;->g(II)Landroid/view/View;

    .line 226
    .line 227
    .line 228
    move-result-object p4

    .line 229
    if-eqz p4, :cond_15

    .line 230
    .line 231
    if-eq p4, p1, :cond_15

    .line 232
    .line 233
    return-object p4

    .line 234
    :cond_15
    add-int/lit8 p3, p3, 0x1

    .line 235
    .line 236
    goto :goto_7

    .line 237
    :cond_16
    iget-boolean p3, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->w:Z

    .line 238
    .line 239
    xor-int/2addr p3, v3

    .line 240
    if-ne p2, v2, :cond_17

    .line 241
    .line 242
    move p4, v3

    .line 243
    goto :goto_8

    .line 244
    :cond_17
    move p4, v6

    .line 245
    :goto_8
    if-ne p3, p4, :cond_18

    .line 246
    .line 247
    move p3, v3

    .line 248
    goto :goto_9

    .line 249
    :cond_18
    move p3, v6

    .line 250
    :goto_9
    if-eqz p3, :cond_19

    .line 251
    .line 252
    invoke-virtual {v0}, Lka/d1;->c()I

    .line 253
    .line 254
    .line 255
    move-result p4

    .line 256
    goto :goto_a

    .line 257
    :cond_19
    invoke-virtual {v0}, Lka/d1;->d()I

    .line 258
    .line 259
    .line 260
    move-result p4

    .line 261
    :goto_a
    invoke-virtual {p0, p4}, Lka/f0;->q(I)Landroid/view/View;

    .line 262
    .line 263
    .line 264
    move-result-object p4

    .line 265
    if-eqz p4, :cond_1a

    .line 266
    .line 267
    if-eq p4, p1, :cond_1a

    .line 268
    .line 269
    return-object p4

    .line 270
    :cond_1a
    invoke-virtual {p0, p2}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->S0(I)Z

    .line 271
    .line 272
    .line 273
    move-result p2

    .line 274
    if-eqz p2, :cond_1e

    .line 275
    .line 276
    iget p2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 277
    .line 278
    sub-int/2addr p2, v3

    .line 279
    :goto_b
    if-ltz p2, :cond_21

    .line 280
    .line 281
    iget p4, v0, Lka/d1;->e:I

    .line 282
    .line 283
    if-ne p2, p4, :cond_1b

    .line 284
    .line 285
    goto :goto_d

    .line 286
    :cond_1b
    if-eqz p3, :cond_1c

    .line 287
    .line 288
    iget-object p4, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->q:[Lka/d1;

    .line 289
    .line 290
    aget-object p4, p4, p2

    .line 291
    .line 292
    invoke-virtual {p4}, Lka/d1;->c()I

    .line 293
    .line 294
    .line 295
    move-result p4

    .line 296
    goto :goto_c

    .line 297
    :cond_1c
    iget-object p4, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->q:[Lka/d1;

    .line 298
    .line 299
    aget-object p4, p4, p2

    .line 300
    .line 301
    invoke-virtual {p4}, Lka/d1;->d()I

    .line 302
    .line 303
    .line 304
    move-result p4

    .line 305
    :goto_c
    invoke-virtual {p0, p4}, Lka/f0;->q(I)Landroid/view/View;

    .line 306
    .line 307
    .line 308
    move-result-object p4

    .line 309
    if-eqz p4, :cond_1d

    .line 310
    .line 311
    if-eq p4, p1, :cond_1d

    .line 312
    .line 313
    return-object p4

    .line 314
    :cond_1d
    :goto_d
    add-int/lit8 p2, p2, -0x1

    .line 315
    .line 316
    goto :goto_b

    .line 317
    :cond_1e
    :goto_e
    iget p2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 318
    .line 319
    if-ge v6, p2, :cond_21

    .line 320
    .line 321
    if-eqz p3, :cond_1f

    .line 322
    .line 323
    iget-object p2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->q:[Lka/d1;

    .line 324
    .line 325
    aget-object p2, p2, v6

    .line 326
    .line 327
    invoke-virtual {p2}, Lka/d1;->c()I

    .line 328
    .line 329
    .line 330
    move-result p2

    .line 331
    goto :goto_f

    .line 332
    :cond_1f
    iget-object p2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->q:[Lka/d1;

    .line 333
    .line 334
    aget-object p2, p2, v6

    .line 335
    .line 336
    invoke-virtual {p2}, Lka/d1;->d()I

    .line 337
    .line 338
    .line 339
    move-result p2

    .line 340
    :goto_f
    invoke-virtual {p0, p2}, Lka/f0;->q(I)Landroid/view/View;

    .line 341
    .line 342
    .line 343
    move-result-object p2

    .line 344
    if-eqz p2, :cond_20

    .line 345
    .line 346
    if-eq p2, p1, :cond_20

    .line 347
    .line 348
    return-object p2

    .line 349
    :cond_20
    add-int/lit8 v6, v6, 0x1

    .line 350
    .line 351
    goto :goto_e

    .line 352
    :cond_21
    :goto_10
    return-object v1
.end method

.method public final T0(ILka/r0;)V
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-lez p1, :cond_0

    .line 3
    .line 4
    invoke-virtual {p0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->K0()I

    .line 5
    .line 6
    .line 7
    move-result v1

    .line 8
    move v2, v0

    .line 9
    goto :goto_0

    .line 10
    :cond_0
    invoke-virtual {p0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->J0()I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    const/4 v2, -0x1

    .line 15
    :goto_0
    iget-object v3, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->v:Lka/o;

    .line 16
    .line 17
    iput-boolean v0, v3, Lka/o;->a:Z

    .line 18
    .line 19
    invoke-virtual {p0, v1, p2}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->a1(ILka/r0;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0, v2}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->Z0(I)V

    .line 23
    .line 24
    .line 25
    iget p0, v3, Lka/o;->d:I

    .line 26
    .line 27
    add-int/2addr v1, p0

    .line 28
    iput v1, v3, Lka/o;->c:I

    .line 29
    .line 30
    invoke-static {p1}, Ljava/lang/Math;->abs(I)I

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    iput p0, v3, Lka/o;->b:I

    .line 35
    .line 36
    return-void
.end method

.method public final U(Landroid/view/accessibility/AccessibilityEvent;)V
    .locals 2

    .line 1
    invoke-super {p0, p1}, Lka/f0;->U(Landroid/view/accessibility/AccessibilityEvent;)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lka/f0;->v()I

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    if-lez v0, :cond_2

    .line 9
    .line 10
    const/4 v0, 0x0

    .line 11
    invoke-virtual {p0, v0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->G0(Z)Landroid/view/View;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    invoke-virtual {p0, v0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->F0(Z)Landroid/view/View;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    if-eqz v1, :cond_2

    .line 20
    .line 21
    if-nez p0, :cond_0

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    invoke-static {v1}, Lka/f0;->H(Landroid/view/View;)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    invoke-static {p0}, Lka/f0;->H(Landroid/view/View;)I

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    if-ge v0, p0, :cond_1

    .line 33
    .line 34
    invoke-virtual {p1, v0}, Landroid/view/accessibility/AccessibilityRecord;->setFromIndex(I)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {p1, p0}, Landroid/view/accessibility/AccessibilityRecord;->setToIndex(I)V

    .line 38
    .line 39
    .line 40
    return-void

    .line 41
    :cond_1
    invoke-virtual {p1, p0}, Landroid/view/accessibility/AccessibilityRecord;->setFromIndex(I)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {p1, v0}, Landroid/view/accessibility/AccessibilityRecord;->setToIndex(I)V

    .line 45
    .line 46
    .line 47
    :cond_2
    :goto_0
    return-void
.end method

.method public final U0(Lka/l0;Lka/o;)V
    .locals 4

    .line 1
    iget-boolean v0, p2, Lka/o;->a:Z

    .line 2
    .line 3
    if-eqz v0, :cond_a

    .line 4
    .line 5
    iget-boolean v0, p2, Lka/o;->i:Z

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    goto/16 :goto_4

    .line 10
    .line 11
    :cond_0
    iget v0, p2, Lka/o;->b:I

    .line 12
    .line 13
    const/4 v1, -0x1

    .line 14
    if-nez v0, :cond_2

    .line 15
    .line 16
    iget v0, p2, Lka/o;->e:I

    .line 17
    .line 18
    if-ne v0, v1, :cond_1

    .line 19
    .line 20
    iget p2, p2, Lka/o;->g:I

    .line 21
    .line 22
    invoke-virtual {p0, p1, p2}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->V0(Lka/l0;I)V

    .line 23
    .line 24
    .line 25
    return-void

    .line 26
    :cond_1
    iget p2, p2, Lka/o;->f:I

    .line 27
    .line 28
    invoke-virtual {p0, p1, p2}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->W0(Lka/l0;I)V

    .line 29
    .line 30
    .line 31
    return-void

    .line 32
    :cond_2
    iget v0, p2, Lka/o;->e:I

    .line 33
    .line 34
    const/4 v2, 0x1

    .line 35
    const/4 v3, 0x0

    .line 36
    if-ne v0, v1, :cond_6

    .line 37
    .line 38
    iget v0, p2, Lka/o;->f:I

    .line 39
    .line 40
    iget-object v1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->q:[Lka/d1;

    .line 41
    .line 42
    aget-object v1, v1, v3

    .line 43
    .line 44
    invoke-virtual {v1, v0}, Lka/d1;->h(I)I

    .line 45
    .line 46
    .line 47
    move-result v1

    .line 48
    :goto_0
    iget v3, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 49
    .line 50
    if-ge v2, v3, :cond_4

    .line 51
    .line 52
    iget-object v3, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->q:[Lka/d1;

    .line 53
    .line 54
    aget-object v3, v3, v2

    .line 55
    .line 56
    invoke-virtual {v3, v0}, Lka/d1;->h(I)I

    .line 57
    .line 58
    .line 59
    move-result v3

    .line 60
    if-le v3, v1, :cond_3

    .line 61
    .line 62
    move v1, v3

    .line 63
    :cond_3
    add-int/lit8 v2, v2, 0x1

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_4
    sub-int/2addr v0, v1

    .line 67
    if-gez v0, :cond_5

    .line 68
    .line 69
    iget p2, p2, Lka/o;->g:I

    .line 70
    .line 71
    goto :goto_1

    .line 72
    :cond_5
    iget v1, p2, Lka/o;->g:I

    .line 73
    .line 74
    iget p2, p2, Lka/o;->b:I

    .line 75
    .line 76
    invoke-static {v0, p2}, Ljava/lang/Math;->min(II)I

    .line 77
    .line 78
    .line 79
    move-result p2

    .line 80
    sub-int p2, v1, p2

    .line 81
    .line 82
    :goto_1
    invoke-virtual {p0, p1, p2}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->V0(Lka/l0;I)V

    .line 83
    .line 84
    .line 85
    return-void

    .line 86
    :cond_6
    iget v0, p2, Lka/o;->g:I

    .line 87
    .line 88
    iget-object v1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->q:[Lka/d1;

    .line 89
    .line 90
    aget-object v1, v1, v3

    .line 91
    .line 92
    invoke-virtual {v1, v0}, Lka/d1;->f(I)I

    .line 93
    .line 94
    .line 95
    move-result v1

    .line 96
    :goto_2
    iget v3, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 97
    .line 98
    if-ge v2, v3, :cond_8

    .line 99
    .line 100
    iget-object v3, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->q:[Lka/d1;

    .line 101
    .line 102
    aget-object v3, v3, v2

    .line 103
    .line 104
    invoke-virtual {v3, v0}, Lka/d1;->f(I)I

    .line 105
    .line 106
    .line 107
    move-result v3

    .line 108
    if-ge v3, v1, :cond_7

    .line 109
    .line 110
    move v1, v3

    .line 111
    :cond_7
    add-int/lit8 v2, v2, 0x1

    .line 112
    .line 113
    goto :goto_2

    .line 114
    :cond_8
    iget v0, p2, Lka/o;->g:I

    .line 115
    .line 116
    sub-int/2addr v1, v0

    .line 117
    if-gez v1, :cond_9

    .line 118
    .line 119
    iget p2, p2, Lka/o;->f:I

    .line 120
    .line 121
    goto :goto_3

    .line 122
    :cond_9
    iget v0, p2, Lka/o;->f:I

    .line 123
    .line 124
    iget p2, p2, Lka/o;->b:I

    .line 125
    .line 126
    invoke-static {v1, p2}, Ljava/lang/Math;->min(II)I

    .line 127
    .line 128
    .line 129
    move-result p2

    .line 130
    add-int/2addr p2, v0

    .line 131
    :goto_3
    invoke-virtual {p0, p1, p2}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->W0(Lka/l0;I)V

    .line 132
    .line 133
    .line 134
    :cond_a
    :goto_4
    return-void
.end method

.method public final V0(Lka/l0;I)V
    .locals 8

    .line 1
    invoke-virtual {p0}, Lka/f0;->v()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x1

    .line 6
    sub-int/2addr v0, v1

    .line 7
    :goto_0
    if-ltz v0, :cond_4

    .line 8
    .line 9
    invoke-virtual {p0, v0}, Lka/f0;->u(I)Landroid/view/View;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    iget-object v3, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 14
    .line 15
    invoke-virtual {v3, v2}, Lka/u;->g(Landroid/view/View;)I

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    if-lt v3, p2, :cond_4

    .line 20
    .line 21
    iget-object v3, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 22
    .line 23
    invoke-virtual {v3, v2}, Lka/u;->p(Landroid/view/View;)I

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    if-lt v3, p2, :cond_4

    .line 28
    .line 29
    invoke-virtual {v2}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 30
    .line 31
    .line 32
    move-result-object v3

    .line 33
    check-cast v3, Lka/a1;

    .line 34
    .line 35
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 36
    .line 37
    .line 38
    iget-object v4, v3, Lka/a1;->e:Lka/d1;

    .line 39
    .line 40
    iget-object v4, v4, Lka/d1;->a:Ljava/util/ArrayList;

    .line 41
    .line 42
    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    .line 43
    .line 44
    .line 45
    move-result v4

    .line 46
    if-ne v4, v1, :cond_0

    .line 47
    .line 48
    goto :goto_1

    .line 49
    :cond_0
    iget-object v3, v3, Lka/a1;->e:Lka/d1;

    .line 50
    .line 51
    iget-object v4, v3, Lka/d1;->a:Ljava/util/ArrayList;

    .line 52
    .line 53
    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    .line 54
    .line 55
    .line 56
    move-result v5

    .line 57
    add-int/lit8 v6, v5, -0x1

    .line 58
    .line 59
    invoke-virtual {v4, v6}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v4

    .line 63
    check-cast v4, Landroid/view/View;

    .line 64
    .line 65
    invoke-virtual {v4}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 66
    .line 67
    .line 68
    move-result-object v6

    .line 69
    check-cast v6, Lka/a1;

    .line 70
    .line 71
    const/4 v7, 0x0

    .line 72
    iput-object v7, v6, Lka/a1;->e:Lka/d1;

    .line 73
    .line 74
    iget-object v7, v6, Lka/g0;->a:Lka/v0;

    .line 75
    .line 76
    invoke-virtual {v7}, Lka/v0;->h()Z

    .line 77
    .line 78
    .line 79
    move-result v7

    .line 80
    if-nez v7, :cond_1

    .line 81
    .line 82
    iget-object v6, v6, Lka/g0;->a:Lka/v0;

    .line 83
    .line 84
    invoke-virtual {v6}, Lka/v0;->k()Z

    .line 85
    .line 86
    .line 87
    move-result v6

    .line 88
    if-eqz v6, :cond_2

    .line 89
    .line 90
    :cond_1
    iget v6, v3, Lka/d1;->d:I

    .line 91
    .line 92
    iget-object v7, v3, Lka/d1;->f:Landroidx/recyclerview/widget/StaggeredGridLayoutManager;

    .line 93
    .line 94
    iget-object v7, v7, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 95
    .line 96
    invoke-virtual {v7, v4}, Lka/u;->e(Landroid/view/View;)I

    .line 97
    .line 98
    .line 99
    move-result v4

    .line 100
    sub-int/2addr v6, v4

    .line 101
    iput v6, v3, Lka/d1;->d:I

    .line 102
    .line 103
    :cond_2
    const/high16 v4, -0x80000000

    .line 104
    .line 105
    if-ne v5, v1, :cond_3

    .line 106
    .line 107
    iput v4, v3, Lka/d1;->b:I

    .line 108
    .line 109
    :cond_3
    iput v4, v3, Lka/d1;->c:I

    .line 110
    .line 111
    invoke-virtual {p0, v2, p1}, Lka/f0;->k0(Landroid/view/View;Lka/l0;)V

    .line 112
    .line 113
    .line 114
    add-int/lit8 v0, v0, -0x1

    .line 115
    .line 116
    goto :goto_0

    .line 117
    :cond_4
    :goto_1
    return-void
.end method

.method public final W0(Lka/l0;I)V
    .locals 6

    .line 1
    :goto_0
    invoke-virtual {p0}, Lka/f0;->v()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-lez v0, :cond_4

    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    invoke-virtual {p0, v0}, Lka/f0;->u(I)Landroid/view/View;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    iget-object v2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 13
    .line 14
    invoke-virtual {v2, v1}, Lka/u;->d(Landroid/view/View;)I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    if-gt v2, p2, :cond_4

    .line 19
    .line 20
    iget-object v2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 21
    .line 22
    invoke-virtual {v2, v1}, Lka/u;->o(Landroid/view/View;)I

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    if-gt v2, p2, :cond_4

    .line 27
    .line 28
    invoke-virtual {v1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    check-cast v2, Lka/a1;

    .line 33
    .line 34
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 35
    .line 36
    .line 37
    iget-object v3, v2, Lka/a1;->e:Lka/d1;

    .line 38
    .line 39
    iget-object v3, v3, Lka/d1;->a:Ljava/util/ArrayList;

    .line 40
    .line 41
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    .line 42
    .line 43
    .line 44
    move-result v3

    .line 45
    const/4 v4, 0x1

    .line 46
    if-ne v3, v4, :cond_0

    .line 47
    .line 48
    goto :goto_1

    .line 49
    :cond_0
    iget-object v2, v2, Lka/a1;->e:Lka/d1;

    .line 50
    .line 51
    iget-object v3, v2, Lka/d1;->a:Ljava/util/ArrayList;

    .line 52
    .line 53
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v0

    .line 57
    check-cast v0, Landroid/view/View;

    .line 58
    .line 59
    invoke-virtual {v0}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 60
    .line 61
    .line 62
    move-result-object v4

    .line 63
    check-cast v4, Lka/a1;

    .line 64
    .line 65
    const/4 v5, 0x0

    .line 66
    iput-object v5, v4, Lka/a1;->e:Lka/d1;

    .line 67
    .line 68
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    .line 69
    .line 70
    .line 71
    move-result v3

    .line 72
    const/high16 v5, -0x80000000

    .line 73
    .line 74
    if-nez v3, :cond_1

    .line 75
    .line 76
    iput v5, v2, Lka/d1;->c:I

    .line 77
    .line 78
    :cond_1
    iget-object v3, v4, Lka/g0;->a:Lka/v0;

    .line 79
    .line 80
    invoke-virtual {v3}, Lka/v0;->h()Z

    .line 81
    .line 82
    .line 83
    move-result v3

    .line 84
    if-nez v3, :cond_2

    .line 85
    .line 86
    iget-object v3, v4, Lka/g0;->a:Lka/v0;

    .line 87
    .line 88
    invoke-virtual {v3}, Lka/v0;->k()Z

    .line 89
    .line 90
    .line 91
    move-result v3

    .line 92
    if-eqz v3, :cond_3

    .line 93
    .line 94
    :cond_2
    iget v3, v2, Lka/d1;->d:I

    .line 95
    .line 96
    iget-object v4, v2, Lka/d1;->f:Landroidx/recyclerview/widget/StaggeredGridLayoutManager;

    .line 97
    .line 98
    iget-object v4, v4, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 99
    .line 100
    invoke-virtual {v4, v0}, Lka/u;->e(Landroid/view/View;)I

    .line 101
    .line 102
    .line 103
    move-result v0

    .line 104
    sub-int/2addr v3, v0

    .line 105
    iput v3, v2, Lka/d1;->d:I

    .line 106
    .line 107
    :cond_3
    iput v5, v2, Lka/d1;->b:I

    .line 108
    .line 109
    invoke-virtual {p0, v1, p1}, Lka/f0;->k0(Landroid/view/View;Lka/l0;)V

    .line 110
    .line 111
    .line 112
    goto :goto_0

    .line 113
    :cond_4
    :goto_1
    return-void
.end method

.method public final X0()V
    .locals 2

    .line 1
    iget v0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->t:I

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-eq v0, v1, :cond_1

    .line 5
    .line 6
    invoke-virtual {p0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->P0()Z

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    iget-boolean v0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->w:Z

    .line 14
    .line 15
    xor-int/2addr v0, v1

    .line 16
    iput-boolean v0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->x:Z

    .line 17
    .line 18
    return-void

    .line 19
    :cond_1
    :goto_0
    iget-boolean v0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->w:Z

    .line 20
    .line 21
    iput-boolean v0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->x:Z

    .line 22
    .line 23
    return-void
.end method

.method public final Y(II)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-virtual {p0, p1, p2, v0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->N0(III)V

    .line 3
    .line 4
    .line 5
    return-void
.end method

.method public final Y0(ILka/l0;Lka/r0;)I
    .locals 3

    .line 1
    invoke-virtual {p0}, Lka/f0;->v()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-eqz v0, :cond_3

    .line 7
    .line 8
    if-nez p1, :cond_0

    .line 9
    .line 10
    goto :goto_1

    .line 11
    :cond_0
    invoke-virtual {p0, p1, p3}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->T0(ILka/r0;)V

    .line 12
    .line 13
    .line 14
    iget-object v0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->v:Lka/o;

    .line 15
    .line 16
    invoke-virtual {p0, p2, v0, p3}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->E0(Lka/l0;Lka/o;Lka/r0;)I

    .line 17
    .line 18
    .line 19
    move-result p3

    .line 20
    iget v2, v0, Lka/o;->b:I

    .line 21
    .line 22
    if-ge v2, p3, :cond_1

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_1
    if-gez p1, :cond_2

    .line 26
    .line 27
    neg-int p1, p3

    .line 28
    goto :goto_0

    .line 29
    :cond_2
    move p1, p3

    .line 30
    :goto_0
    iget-object p3, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 31
    .line 32
    neg-int v2, p1

    .line 33
    invoke-virtual {p3, v2}, Lka/u;->q(I)V

    .line 34
    .line 35
    .line 36
    iget-boolean p3, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->x:Z

    .line 37
    .line 38
    iput-boolean p3, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->D:Z

    .line 39
    .line 40
    iput v1, v0, Lka/o;->b:I

    .line 41
    .line 42
    invoke-virtual {p0, p2, v0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->U0(Lka/l0;Lka/o;)V

    .line 43
    .line 44
    .line 45
    return p1

    .line 46
    :cond_3
    :goto_1
    return v1
.end method

.method public final Z()V
    .locals 1

    .line 1
    iget-object v0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->B:Lb81/b;

    .line 2
    .line 3
    invoke-virtual {v0}, Lb81/b;->k()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lka/f0;->n0()V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public final Z0(I)V
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->v:Lka/o;

    .line 2
    .line 3
    iput p1, v0, Lka/o;->e:I

    .line 4
    .line 5
    iget-boolean p0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->x:Z

    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    const/4 v2, -0x1

    .line 9
    if-ne p1, v2, :cond_0

    .line 10
    .line 11
    move p1, v1

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const/4 p1, 0x0

    .line 14
    :goto_0
    if-ne p0, p1, :cond_1

    .line 15
    .line 16
    goto :goto_1

    .line 17
    :cond_1
    move v1, v2

    .line 18
    :goto_1
    iput v1, v0, Lka/o;->d:I

    .line 19
    .line 20
    return-void
.end method

.method public final a(I)Landroid/graphics/PointF;
    .locals 3

    .line 1
    invoke-virtual {p0}, Lka/f0;->v()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, -0x1

    .line 6
    const/4 v2, 0x1

    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    iget-boolean p1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->x:Z

    .line 10
    .line 11
    if-eqz p1, :cond_3

    .line 12
    .line 13
    :cond_0
    move v1, v2

    .line 14
    goto :goto_1

    .line 15
    :cond_1
    invoke-virtual {p0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->J0()I

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-ge p1, v0, :cond_2

    .line 20
    .line 21
    move p1, v2

    .line 22
    goto :goto_0

    .line 23
    :cond_2
    const/4 p1, 0x0

    .line 24
    :goto_0
    iget-boolean v0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->x:Z

    .line 25
    .line 26
    if-eq p1, v0, :cond_0

    .line 27
    .line 28
    :cond_3
    :goto_1
    new-instance p1, Landroid/graphics/PointF;

    .line 29
    .line 30
    invoke-direct {p1}, Landroid/graphics/PointF;-><init>()V

    .line 31
    .line 32
    .line 33
    if-nez v1, :cond_4

    .line 34
    .line 35
    const/4 p0, 0x0

    .line 36
    return-object p0

    .line 37
    :cond_4
    iget p0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->t:I

    .line 38
    .line 39
    const/4 v0, 0x0

    .line 40
    if-nez p0, :cond_5

    .line 41
    .line 42
    int-to-float p0, v1

    .line 43
    iput p0, p1, Landroid/graphics/PointF;->x:F

    .line 44
    .line 45
    iput v0, p1, Landroid/graphics/PointF;->y:F

    .line 46
    .line 47
    return-object p1

    .line 48
    :cond_5
    iput v0, p1, Landroid/graphics/PointF;->x:F

    .line 49
    .line 50
    int-to-float p0, v1

    .line 51
    iput p0, p1, Landroid/graphics/PointF;->y:F

    .line 52
    .line 53
    return-object p1
.end method

.method public final a0(II)V
    .locals 1

    .line 1
    const/16 v0, 0x8

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2, v0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->N0(III)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final a1(ILka/r0;)V
    .locals 4

    .line 1
    iget-object v0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->v:Lka/o;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    iput v1, v0, Lka/o;->b:I

    .line 5
    .line 6
    iput p1, v0, Lka/o;->c:I

    .line 7
    .line 8
    iget-object v2, p0, Lka/f0;->e:Lka/s;

    .line 9
    .line 10
    const/4 v3, 0x1

    .line 11
    if-eqz v2, :cond_2

    .line 12
    .line 13
    iget-boolean v2, v2, Lka/s;->e:Z

    .line 14
    .line 15
    if-eqz v2, :cond_2

    .line 16
    .line 17
    iget p2, p2, Lka/r0;->a:I

    .line 18
    .line 19
    const/4 v2, -0x1

    .line 20
    if-eq p2, v2, :cond_2

    .line 21
    .line 22
    iget-boolean v2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->x:Z

    .line 23
    .line 24
    if-ge p2, p1, :cond_0

    .line 25
    .line 26
    move p1, v3

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    move p1, v1

    .line 29
    :goto_0
    if-ne v2, p1, :cond_1

    .line 30
    .line 31
    iget-object p1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 32
    .line 33
    invoke-virtual {p1}, Lka/u;->n()I

    .line 34
    .line 35
    .line 36
    move-result p1

    .line 37
    move p2, v1

    .line 38
    goto :goto_1

    .line 39
    :cond_1
    iget-object p1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 40
    .line 41
    invoke-virtual {p1}, Lka/u;->n()I

    .line 42
    .line 43
    .line 44
    move-result p1

    .line 45
    move p2, p1

    .line 46
    move p1, v1

    .line 47
    goto :goto_1

    .line 48
    :cond_2
    move p1, v1

    .line 49
    move p2, p1

    .line 50
    :goto_1
    iget-object v2, p0, Lka/f0;->b:Landroidx/recyclerview/widget/RecyclerView;

    .line 51
    .line 52
    if-eqz v2, :cond_3

    .line 53
    .line 54
    iget-boolean v2, v2, Landroidx/recyclerview/widget/RecyclerView;->k:Z

    .line 55
    .line 56
    if-eqz v2, :cond_3

    .line 57
    .line 58
    iget-object v2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 59
    .line 60
    invoke-virtual {v2}, Lka/u;->m()I

    .line 61
    .line 62
    .line 63
    move-result v2

    .line 64
    sub-int/2addr v2, p2

    .line 65
    iput v2, v0, Lka/o;->f:I

    .line 66
    .line 67
    iget-object p2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 68
    .line 69
    invoke-virtual {p2}, Lka/u;->i()I

    .line 70
    .line 71
    .line 72
    move-result p2

    .line 73
    add-int/2addr p2, p1

    .line 74
    iput p2, v0, Lka/o;->g:I

    .line 75
    .line 76
    goto :goto_2

    .line 77
    :cond_3
    iget-object v2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 78
    .line 79
    invoke-virtual {v2}, Lka/u;->h()I

    .line 80
    .line 81
    .line 82
    move-result v2

    .line 83
    add-int/2addr v2, p1

    .line 84
    iput v2, v0, Lka/o;->g:I

    .line 85
    .line 86
    neg-int p1, p2

    .line 87
    iput p1, v0, Lka/o;->f:I

    .line 88
    .line 89
    :goto_2
    iput-boolean v1, v0, Lka/o;->h:Z

    .line 90
    .line 91
    iput-boolean v3, v0, Lka/o;->a:Z

    .line 92
    .line 93
    iget-object p1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 94
    .line 95
    invoke-virtual {p1}, Lka/u;->k()I

    .line 96
    .line 97
    .line 98
    move-result p1

    .line 99
    if-nez p1, :cond_4

    .line 100
    .line 101
    iget-object p0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 102
    .line 103
    invoke-virtual {p0}, Lka/u;->h()I

    .line 104
    .line 105
    .line 106
    move-result p0

    .line 107
    if-nez p0, :cond_4

    .line 108
    .line 109
    move v1, v3

    .line 110
    :cond_4
    iput-boolean v1, v0, Lka/o;->i:Z

    .line 111
    .line 112
    return-void
.end method

.method public final b0(II)V
    .locals 1

    .line 1
    const/4 v0, 0x2

    .line 2
    invoke-virtual {p0, p1, p2, v0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->N0(III)V

    .line 3
    .line 4
    .line 5
    return-void
.end method

.method public final b1(Lka/d1;II)V
    .locals 5

    .line 1
    iget v0, p1, Lka/d1;->d:I

    .line 2
    .line 3
    iget v1, p1, Lka/d1;->e:I

    .line 4
    .line 5
    const/4 v2, -0x1

    .line 6
    const/high16 v3, -0x80000000

    .line 7
    .line 8
    const/4 v4, 0x0

    .line 9
    if-ne p2, v2, :cond_1

    .line 10
    .line 11
    iget p2, p1, Lka/d1;->b:I

    .line 12
    .line 13
    if-eq p2, v3, :cond_0

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    iget-object p2, p1, Lka/d1;->a:Ljava/util/ArrayList;

    .line 17
    .line 18
    invoke-virtual {p2, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p2

    .line 22
    check-cast p2, Landroid/view/View;

    .line 23
    .line 24
    invoke-virtual {p2}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 25
    .line 26
    .line 27
    move-result-object v2

    .line 28
    check-cast v2, Lka/a1;

    .line 29
    .line 30
    iget-object v3, p1, Lka/d1;->f:Landroidx/recyclerview/widget/StaggeredGridLayoutManager;

    .line 31
    .line 32
    iget-object v3, v3, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 33
    .line 34
    invoke-virtual {v3, p2}, Lka/u;->g(Landroid/view/View;)I

    .line 35
    .line 36
    .line 37
    move-result p2

    .line 38
    iput p2, p1, Lka/d1;->b:I

    .line 39
    .line 40
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 41
    .line 42
    .line 43
    iget p2, p1, Lka/d1;->b:I

    .line 44
    .line 45
    :goto_0
    add-int/2addr p2, v0

    .line 46
    if-gt p2, p3, :cond_3

    .line 47
    .line 48
    iget-object p0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->y:Ljava/util/BitSet;

    .line 49
    .line 50
    invoke-virtual {p0, v1, v4}, Ljava/util/BitSet;->set(IZ)V

    .line 51
    .line 52
    .line 53
    return-void

    .line 54
    :cond_1
    iget p2, p1, Lka/d1;->c:I

    .line 55
    .line 56
    if-eq p2, v3, :cond_2

    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_2
    invoke-virtual {p1}, Lka/d1;->a()V

    .line 60
    .line 61
    .line 62
    iget p2, p1, Lka/d1;->c:I

    .line 63
    .line 64
    :goto_1
    sub-int/2addr p2, v0

    .line 65
    if-lt p2, p3, :cond_3

    .line 66
    .line 67
    iget-object p0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->y:Ljava/util/BitSet;

    .line 68
    .line 69
    invoke-virtual {p0, v1, v4}, Ljava/util/BitSet;->set(IZ)V

    .line 70
    .line 71
    .line 72
    :cond_3
    return-void
.end method

.method public final c(Ljava/lang/String;)V
    .locals 1

    .line 1
    iget-object v0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->F:Lka/c1;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-super {p0, p1}, Lka/f0;->c(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    :cond_0
    return-void
.end method

.method public final c0(II)V
    .locals 1

    .line 1
    const/4 v0, 0x4

    .line 2
    invoke-virtual {p0, p1, p2, v0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->N0(III)V

    .line 3
    .line 4
    .line 5
    return-void
.end method

.method public final d()Z
    .locals 0

    .line 1
    iget p0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->t:I

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method

.method public final d0(Lka/l0;Lka/r0;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-virtual {p0, p1, p2, v0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->R0(Lka/l0;Lka/r0;Z)V

    .line 3
    .line 4
    .line 5
    return-void
.end method

.method public final e()Z
    .locals 1

    .line 1
    iget p0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->t:I

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    if-ne p0, v0, :cond_0

    .line 5
    .line 6
    return v0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method

.method public final e0(Lka/r0;)V
    .locals 0

    .line 1
    const/4 p1, -0x1

    .line 2
    iput p1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->z:I

    .line 3
    .line 4
    const/high16 p1, -0x80000000

    .line 5
    .line 6
    iput p1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->A:I

    .line 7
    .line 8
    const/4 p1, 0x0

    .line 9
    iput-object p1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->F:Lka/c1;

    .line 10
    .line 11
    iget-object p0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->H:Lka/z0;

    .line 12
    .line 13
    invoke-virtual {p0}, Lka/z0;->a()V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public final f(Lka/g0;)Z
    .locals 0

    .line 1
    instance-of p0, p1, Lka/a1;

    .line 2
    .line 3
    return p0
.end method

.method public final f0(Landroid/os/Parcelable;)V
    .locals 2

    .line 1
    instance-of v0, p1, Lka/c1;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    check-cast p1, Lka/c1;

    .line 6
    .line 7
    iput-object p1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->F:Lka/c1;

    .line 8
    .line 9
    iget v0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->z:I

    .line 10
    .line 11
    const/4 v1, -0x1

    .line 12
    if-eq v0, v1, :cond_0

    .line 13
    .line 14
    iput v1, p1, Lka/c1;->d:I

    .line 15
    .line 16
    iput v1, p1, Lka/c1;->e:I

    .line 17
    .line 18
    const/4 v0, 0x0

    .line 19
    iput-object v0, p1, Lka/c1;->g:[I

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    iput v1, p1, Lka/c1;->f:I

    .line 23
    .line 24
    iput v1, p1, Lka/c1;->h:I

    .line 25
    .line 26
    iput-object v0, p1, Lka/c1;->i:[I

    .line 27
    .line 28
    iput-object v0, p1, Lka/c1;->j:Ljava/util/ArrayList;

    .line 29
    .line 30
    :cond_0
    invoke-virtual {p0}, Lka/f0;->n0()V

    .line 31
    .line 32
    .line 33
    :cond_1
    return-void
.end method

.method public final g0()Landroid/os/Parcelable;
    .locals 5

    .line 1
    iget-object v0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->F:Lka/c1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    new-instance p0, Lka/c1;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    iget v1, v0, Lka/c1;->f:I

    .line 11
    .line 12
    iput v1, p0, Lka/c1;->f:I

    .line 13
    .line 14
    iget v1, v0, Lka/c1;->d:I

    .line 15
    .line 16
    iput v1, p0, Lka/c1;->d:I

    .line 17
    .line 18
    iget v1, v0, Lka/c1;->e:I

    .line 19
    .line 20
    iput v1, p0, Lka/c1;->e:I

    .line 21
    .line 22
    iget-object v1, v0, Lka/c1;->g:[I

    .line 23
    .line 24
    iput-object v1, p0, Lka/c1;->g:[I

    .line 25
    .line 26
    iget v1, v0, Lka/c1;->h:I

    .line 27
    .line 28
    iput v1, p0, Lka/c1;->h:I

    .line 29
    .line 30
    iget-object v1, v0, Lka/c1;->i:[I

    .line 31
    .line 32
    iput-object v1, p0, Lka/c1;->i:[I

    .line 33
    .line 34
    iget-boolean v1, v0, Lka/c1;->k:Z

    .line 35
    .line 36
    iput-boolean v1, p0, Lka/c1;->k:Z

    .line 37
    .line 38
    iget-boolean v1, v0, Lka/c1;->l:Z

    .line 39
    .line 40
    iput-boolean v1, p0, Lka/c1;->l:Z

    .line 41
    .line 42
    iget-boolean v1, v0, Lka/c1;->m:Z

    .line 43
    .line 44
    iput-boolean v1, p0, Lka/c1;->m:Z

    .line 45
    .line 46
    iget-object v0, v0, Lka/c1;->j:Ljava/util/ArrayList;

    .line 47
    .line 48
    iput-object v0, p0, Lka/c1;->j:Ljava/util/ArrayList;

    .line 49
    .line 50
    return-object p0

    .line 51
    :cond_0
    new-instance v0, Lka/c1;

    .line 52
    .line 53
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 54
    .line 55
    .line 56
    iget-boolean v1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->w:Z

    .line 57
    .line 58
    iput-boolean v1, v0, Lka/c1;->k:Z

    .line 59
    .line 60
    iget-boolean v1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->D:Z

    .line 61
    .line 62
    iput-boolean v1, v0, Lka/c1;->l:Z

    .line 63
    .line 64
    iget-boolean v1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->E:Z

    .line 65
    .line 66
    iput-boolean v1, v0, Lka/c1;->m:Z

    .line 67
    .line 68
    const/4 v1, 0x0

    .line 69
    iget-object v2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->B:Lb81/b;

    .line 70
    .line 71
    if-eqz v2, :cond_1

    .line 72
    .line 73
    iget-object v3, v2, Lb81/b;->e:Ljava/lang/Object;

    .line 74
    .line 75
    check-cast v3, [I

    .line 76
    .line 77
    if-eqz v3, :cond_1

    .line 78
    .line 79
    iput-object v3, v0, Lka/c1;->i:[I

    .line 80
    .line 81
    array-length v3, v3

    .line 82
    iput v3, v0, Lka/c1;->h:I

    .line 83
    .line 84
    iget-object v2, v2, Lb81/b;->f:Ljava/lang/Object;

    .line 85
    .line 86
    check-cast v2, Ljava/util/ArrayList;

    .line 87
    .line 88
    iput-object v2, v0, Lka/c1;->j:Ljava/util/ArrayList;

    .line 89
    .line 90
    goto :goto_0

    .line 91
    :cond_1
    iput v1, v0, Lka/c1;->h:I

    .line 92
    .line 93
    :goto_0
    invoke-virtual {p0}, Lka/f0;->v()I

    .line 94
    .line 95
    .line 96
    move-result v2

    .line 97
    const/4 v3, -0x1

    .line 98
    if-lez v2, :cond_8

    .line 99
    .line 100
    iget-boolean v2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->D:Z

    .line 101
    .line 102
    if-eqz v2, :cond_2

    .line 103
    .line 104
    invoke-virtual {p0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->K0()I

    .line 105
    .line 106
    .line 107
    move-result v2

    .line 108
    goto :goto_1

    .line 109
    :cond_2
    invoke-virtual {p0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->J0()I

    .line 110
    .line 111
    .line 112
    move-result v2

    .line 113
    :goto_1
    iput v2, v0, Lka/c1;->d:I

    .line 114
    .line 115
    iget-boolean v2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->x:Z

    .line 116
    .line 117
    const/4 v4, 0x1

    .line 118
    if-eqz v2, :cond_3

    .line 119
    .line 120
    invoke-virtual {p0, v4}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->F0(Z)Landroid/view/View;

    .line 121
    .line 122
    .line 123
    move-result-object v2

    .line 124
    goto :goto_2

    .line 125
    :cond_3
    invoke-virtual {p0, v4}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->G0(Z)Landroid/view/View;

    .line 126
    .line 127
    .line 128
    move-result-object v2

    .line 129
    :goto_2
    if-nez v2, :cond_4

    .line 130
    .line 131
    goto :goto_3

    .line 132
    :cond_4
    invoke-static {v2}, Lka/f0;->H(Landroid/view/View;)I

    .line 133
    .line 134
    .line 135
    move-result v3

    .line 136
    :goto_3
    iput v3, v0, Lka/c1;->e:I

    .line 137
    .line 138
    iget v2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 139
    .line 140
    iput v2, v0, Lka/c1;->f:I

    .line 141
    .line 142
    new-array v2, v2, [I

    .line 143
    .line 144
    iput-object v2, v0, Lka/c1;->g:[I

    .line 145
    .line 146
    :goto_4
    iget v2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 147
    .line 148
    if-ge v1, v2, :cond_7

    .line 149
    .line 150
    iget-boolean v2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->D:Z

    .line 151
    .line 152
    const/high16 v3, -0x80000000

    .line 153
    .line 154
    if-eqz v2, :cond_5

    .line 155
    .line 156
    iget-object v2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->q:[Lka/d1;

    .line 157
    .line 158
    aget-object v2, v2, v1

    .line 159
    .line 160
    invoke-virtual {v2, v3}, Lka/d1;->f(I)I

    .line 161
    .line 162
    .line 163
    move-result v2

    .line 164
    if-eq v2, v3, :cond_6

    .line 165
    .line 166
    iget-object v3, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 167
    .line 168
    invoke-virtual {v3}, Lka/u;->i()I

    .line 169
    .line 170
    .line 171
    move-result v3

    .line 172
    :goto_5
    sub-int/2addr v2, v3

    .line 173
    goto :goto_6

    .line 174
    :cond_5
    iget-object v2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->q:[Lka/d1;

    .line 175
    .line 176
    aget-object v2, v2, v1

    .line 177
    .line 178
    invoke-virtual {v2, v3}, Lka/d1;->h(I)I

    .line 179
    .line 180
    .line 181
    move-result v2

    .line 182
    if-eq v2, v3, :cond_6

    .line 183
    .line 184
    iget-object v3, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 185
    .line 186
    invoke-virtual {v3}, Lka/u;->m()I

    .line 187
    .line 188
    .line 189
    move-result v3

    .line 190
    goto :goto_5

    .line 191
    :cond_6
    :goto_6
    iget-object v3, v0, Lka/c1;->g:[I

    .line 192
    .line 193
    aput v2, v3, v1

    .line 194
    .line 195
    add-int/lit8 v1, v1, 0x1

    .line 196
    .line 197
    goto :goto_4

    .line 198
    :cond_7
    return-object v0

    .line 199
    :cond_8
    iput v3, v0, Lka/c1;->d:I

    .line 200
    .line 201
    iput v3, v0, Lka/c1;->e:I

    .line 202
    .line 203
    iput v1, v0, Lka/c1;->f:I

    .line 204
    .line 205
    return-object v0
.end method

.method public final h(IILka/r0;Landroidx/collection/i;)V
    .locals 4

    .line 1
    iget v0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->t:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    move p1, p2

    .line 7
    :goto_0
    invoke-virtual {p0}, Lka/f0;->v()I

    .line 8
    .line 9
    .line 10
    move-result p2

    .line 11
    if-eqz p2, :cond_7

    .line 12
    .line 13
    if-nez p1, :cond_1

    .line 14
    .line 15
    goto :goto_5

    .line 16
    :cond_1
    invoke-virtual {p0, p1, p3}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->T0(ILka/r0;)V

    .line 17
    .line 18
    .line 19
    iget-object p1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->J:[I

    .line 20
    .line 21
    if-eqz p1, :cond_2

    .line 22
    .line 23
    array-length p1, p1

    .line 24
    iget p2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 25
    .line 26
    if-ge p1, p2, :cond_3

    .line 27
    .line 28
    :cond_2
    iget p1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 29
    .line 30
    new-array p1, p1, [I

    .line 31
    .line 32
    iput-object p1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->J:[I

    .line 33
    .line 34
    :cond_3
    const/4 p1, 0x0

    .line 35
    move p2, p1

    .line 36
    move v0, p2

    .line 37
    :goto_1
    iget v1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 38
    .line 39
    iget-object v2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->v:Lka/o;

    .line 40
    .line 41
    if-ge p2, v1, :cond_6

    .line 42
    .line 43
    iget v1, v2, Lka/o;->d:I

    .line 44
    .line 45
    const/4 v3, -0x1

    .line 46
    if-ne v1, v3, :cond_4

    .line 47
    .line 48
    iget v1, v2, Lka/o;->f:I

    .line 49
    .line 50
    iget-object v2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->q:[Lka/d1;

    .line 51
    .line 52
    aget-object v2, v2, p2

    .line 53
    .line 54
    invoke-virtual {v2, v1}, Lka/d1;->h(I)I

    .line 55
    .line 56
    .line 57
    move-result v2

    .line 58
    :goto_2
    sub-int/2addr v1, v2

    .line 59
    goto :goto_3

    .line 60
    :cond_4
    iget-object v1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->q:[Lka/d1;

    .line 61
    .line 62
    aget-object v1, v1, p2

    .line 63
    .line 64
    iget v3, v2, Lka/o;->g:I

    .line 65
    .line 66
    invoke-virtual {v1, v3}, Lka/d1;->f(I)I

    .line 67
    .line 68
    .line 69
    move-result v1

    .line 70
    iget v2, v2, Lka/o;->g:I

    .line 71
    .line 72
    goto :goto_2

    .line 73
    :goto_3
    if-ltz v1, :cond_5

    .line 74
    .line 75
    iget-object v2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->J:[I

    .line 76
    .line 77
    aput v1, v2, v0

    .line 78
    .line 79
    add-int/lit8 v0, v0, 0x1

    .line 80
    .line 81
    :cond_5
    add-int/lit8 p2, p2, 0x1

    .line 82
    .line 83
    goto :goto_1

    .line 84
    :cond_6
    iget-object p2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->J:[I

    .line 85
    .line 86
    invoke-static {p2, p1, v0}, Ljava/util/Arrays;->sort([III)V

    .line 87
    .line 88
    .line 89
    :goto_4
    if-ge p1, v0, :cond_7

    .line 90
    .line 91
    iget p2, v2, Lka/o;->c:I

    .line 92
    .line 93
    if-ltz p2, :cond_7

    .line 94
    .line 95
    invoke-virtual {p3}, Lka/r0;->b()I

    .line 96
    .line 97
    .line 98
    move-result v1

    .line 99
    if-ge p2, v1, :cond_7

    .line 100
    .line 101
    iget p2, v2, Lka/o;->c:I

    .line 102
    .line 103
    iget-object v1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->J:[I

    .line 104
    .line 105
    aget v1, v1, p1

    .line 106
    .line 107
    invoke-virtual {p4, p2, v1}, Landroidx/collection/i;->b(II)V

    .line 108
    .line 109
    .line 110
    iget p2, v2, Lka/o;->c:I

    .line 111
    .line 112
    iget v1, v2, Lka/o;->d:I

    .line 113
    .line 114
    add-int/2addr p2, v1

    .line 115
    iput p2, v2, Lka/o;->c:I

    .line 116
    .line 117
    add-int/lit8 p1, p1, 0x1

    .line 118
    .line 119
    goto :goto_4

    .line 120
    :cond_7
    :goto_5
    return-void
.end method

.method public final h0(I)V
    .locals 0

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    invoke-virtual {p0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->C0()Z

    .line 4
    .line 5
    .line 6
    :cond_0
    return-void
.end method

.method public final j(Lka/r0;)I
    .locals 7

    .line 1
    invoke-virtual {p0}, Lka/f0;->v()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return p0

    .line 9
    :cond_0
    iget-boolean v0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->I:Z

    .line 10
    .line 11
    xor-int/lit8 v0, v0, 0x1

    .line 12
    .line 13
    invoke-virtual {p0, v0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->G0(Z)Landroid/view/View;

    .line 14
    .line 15
    .line 16
    move-result-object v3

    .line 17
    invoke-virtual {p0, v0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->F0(Z)Landroid/view/View;

    .line 18
    .line 19
    .line 20
    move-result-object v4

    .line 21
    iget-boolean v6, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->I:Z

    .line 22
    .line 23
    iget-object v2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 24
    .line 25
    move-object v5, p0

    .line 26
    move-object v1, p1

    .line 27
    invoke-static/range {v1 .. v6}, Llp/hd;->c(Lka/r0;Lka/u;Landroid/view/View;Landroid/view/View;Lka/f0;Z)I

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    return p0
.end method

.method public final k(Lka/r0;)I
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->D0(Lka/r0;)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public final l(Lka/r0;)I
    .locals 7

    .line 1
    invoke-virtual {p0}, Lka/f0;->v()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return p0

    .line 9
    :cond_0
    iget-boolean v0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->I:Z

    .line 10
    .line 11
    xor-int/lit8 v0, v0, 0x1

    .line 12
    .line 13
    invoke-virtual {p0, v0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->G0(Z)Landroid/view/View;

    .line 14
    .line 15
    .line 16
    move-result-object v3

    .line 17
    invoke-virtual {p0, v0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->F0(Z)Landroid/view/View;

    .line 18
    .line 19
    .line 20
    move-result-object v4

    .line 21
    iget-boolean v6, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->I:Z

    .line 22
    .line 23
    iget-object v2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 24
    .line 25
    move-object v5, p0

    .line 26
    move-object v1, p1

    .line 27
    invoke-static/range {v1 .. v6}, Llp/hd;->e(Lka/r0;Lka/u;Landroid/view/View;Landroid/view/View;Lka/f0;Z)I

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    return p0
.end method

.method public final m(Lka/r0;)I
    .locals 7

    .line 1
    invoke-virtual {p0}, Lka/f0;->v()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return p0

    .line 9
    :cond_0
    iget-boolean v0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->I:Z

    .line 10
    .line 11
    xor-int/lit8 v0, v0, 0x1

    .line 12
    .line 13
    invoke-virtual {p0, v0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->G0(Z)Landroid/view/View;

    .line 14
    .line 15
    .line 16
    move-result-object v3

    .line 17
    invoke-virtual {p0, v0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->F0(Z)Landroid/view/View;

    .line 18
    .line 19
    .line 20
    move-result-object v4

    .line 21
    iget-boolean v6, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->I:Z

    .line 22
    .line 23
    iget-object v2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 24
    .line 25
    move-object v5, p0

    .line 26
    move-object v1, p1

    .line 27
    invoke-static/range {v1 .. v6}, Llp/hd;->c(Lka/r0;Lka/u;Landroid/view/View;Landroid/view/View;Lka/f0;Z)I

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    return p0
.end method

.method public final n(Lka/r0;)I
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->D0(Lka/r0;)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public final o(Lka/r0;)I
    .locals 7

    .line 1
    invoke-virtual {p0}, Lka/f0;->v()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return p0

    .line 9
    :cond_0
    iget-boolean v0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->I:Z

    .line 10
    .line 11
    xor-int/lit8 v0, v0, 0x1

    .line 12
    .line 13
    invoke-virtual {p0, v0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->G0(Z)Landroid/view/View;

    .line 14
    .line 15
    .line 16
    move-result-object v3

    .line 17
    invoke-virtual {p0, v0}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->F0(Z)Landroid/view/View;

    .line 18
    .line 19
    .line 20
    move-result-object v4

    .line 21
    iget-boolean v6, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->I:Z

    .line 22
    .line 23
    iget-object v2, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->r:Lka/u;

    .line 24
    .line 25
    move-object v5, p0

    .line 26
    move-object v1, p1

    .line 27
    invoke-static/range {v1 .. v6}, Llp/hd;->e(Lka/r0;Lka/u;Landroid/view/View;Landroid/view/View;Lka/f0;Z)I

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    return p0
.end method

.method public final o0(ILka/l0;Lka/r0;)I
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p2, p3}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->Y0(ILka/l0;Lka/r0;)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public final p0(I)V
    .locals 2

    .line 1
    iget-object v0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->F:Lka/c1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget v1, v0, Lka/c1;->d:I

    .line 6
    .line 7
    if-eq v1, p1, :cond_0

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    iput-object v1, v0, Lka/c1;->g:[I

    .line 11
    .line 12
    const/4 v1, 0x0

    .line 13
    iput v1, v0, Lka/c1;->f:I

    .line 14
    .line 15
    const/4 v1, -0x1

    .line 16
    iput v1, v0, Lka/c1;->d:I

    .line 17
    .line 18
    iput v1, v0, Lka/c1;->e:I

    .line 19
    .line 20
    :cond_0
    iput p1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->z:I

    .line 21
    .line 22
    const/high16 p1, -0x80000000

    .line 23
    .line 24
    iput p1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->A:I

    .line 25
    .line 26
    invoke-virtual {p0}, Lka/f0;->n0()V

    .line 27
    .line 28
    .line 29
    return-void
.end method

.method public final q0(ILka/l0;Lka/r0;)I
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p2, p3}, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->Y0(ILka/l0;Lka/r0;)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public final r()Lka/g0;
    .locals 2

    .line 1
    iget p0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->t:I

    .line 2
    .line 3
    const/4 v0, -0x1

    .line 4
    const/4 v1, -0x2

    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    new-instance p0, Lka/a1;

    .line 8
    .line 9
    invoke-direct {p0, v1, v0}, Lka/g0;-><init>(II)V

    .line 10
    .line 11
    .line 12
    return-object p0

    .line 13
    :cond_0
    new-instance p0, Lka/a1;

    .line 14
    .line 15
    invoke-direct {p0, v0, v1}, Lka/g0;-><init>(II)V

    .line 16
    .line 17
    .line 18
    return-object p0
.end method

.method public final s(Landroid/content/Context;Landroid/util/AttributeSet;)Lka/g0;
    .locals 0

    .line 1
    new-instance p0, Lka/a1;

    .line 2
    .line 3
    invoke-direct {p0, p1, p2}, Lka/g0;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public final t(Landroid/view/ViewGroup$LayoutParams;)Lka/g0;
    .locals 0

    .line 1
    instance-of p0, p1, Landroid/view/ViewGroup$MarginLayoutParams;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    new-instance p0, Lka/a1;

    .line 6
    .line 7
    check-cast p1, Landroid/view/ViewGroup$MarginLayoutParams;

    .line 8
    .line 9
    invoke-direct {p0, p1}, Lka/g0;-><init>(Landroid/view/ViewGroup$MarginLayoutParams;)V

    .line 10
    .line 11
    .line 12
    return-object p0

    .line 13
    :cond_0
    new-instance p0, Lka/a1;

    .line 14
    .line 15
    invoke-direct {p0, p1}, Lka/g0;-><init>(Landroid/view/ViewGroup$LayoutParams;)V

    .line 16
    .line 17
    .line 18
    return-object p0
.end method

.method public final t0(Landroid/graphics/Rect;II)V
    .locals 5

    .line 1
    invoke-virtual {p0}, Lka/f0;->E()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p0}, Lka/f0;->F()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    add-int/2addr v1, v0

    .line 10
    invoke-virtual {p0}, Lka/f0;->G()I

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    invoke-virtual {p0}, Lka/f0;->D()I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    add-int/2addr v2, v0

    .line 19
    iget v0, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->t:I

    .line 20
    .line 21
    const/4 v3, 0x1

    .line 22
    iget v4, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->p:I

    .line 23
    .line 24
    if-ne v0, v3, :cond_0

    .line 25
    .line 26
    invoke-virtual {p1}, Landroid/graphics/Rect;->height()I

    .line 27
    .line 28
    .line 29
    move-result p1

    .line 30
    add-int/2addr p1, v2

    .line 31
    iget-object v0, p0, Lka/f0;->b:Landroidx/recyclerview/widget/RecyclerView;

    .line 32
    .line 33
    sget-object v2, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 34
    .line 35
    invoke-virtual {v0}, Landroid/view/View;->getMinimumHeight()I

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    invoke-static {p3, p1, v0}, Lka/f0;->g(III)I

    .line 40
    .line 41
    .line 42
    move-result p1

    .line 43
    iget p3, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->u:I

    .line 44
    .line 45
    mul-int/2addr p3, v4

    .line 46
    add-int/2addr p3, v1

    .line 47
    iget-object v0, p0, Lka/f0;->b:Landroidx/recyclerview/widget/RecyclerView;

    .line 48
    .line 49
    invoke-virtual {v0}, Landroid/view/View;->getMinimumWidth()I

    .line 50
    .line 51
    .line 52
    move-result v0

    .line 53
    invoke-static {p2, p3, v0}, Lka/f0;->g(III)I

    .line 54
    .line 55
    .line 56
    move-result p2

    .line 57
    goto :goto_0

    .line 58
    :cond_0
    invoke-virtual {p1}, Landroid/graphics/Rect;->width()I

    .line 59
    .line 60
    .line 61
    move-result p1

    .line 62
    add-int/2addr p1, v1

    .line 63
    iget-object v0, p0, Lka/f0;->b:Landroidx/recyclerview/widget/RecyclerView;

    .line 64
    .line 65
    sget-object v1, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 66
    .line 67
    invoke-virtual {v0}, Landroid/view/View;->getMinimumWidth()I

    .line 68
    .line 69
    .line 70
    move-result v0

    .line 71
    invoke-static {p2, p1, v0}, Lka/f0;->g(III)I

    .line 72
    .line 73
    .line 74
    move-result p2

    .line 75
    iget p1, p0, Landroidx/recyclerview/widget/StaggeredGridLayoutManager;->u:I

    .line 76
    .line 77
    mul-int/2addr p1, v4

    .line 78
    add-int/2addr p1, v2

    .line 79
    iget-object v0, p0, Lka/f0;->b:Landroidx/recyclerview/widget/RecyclerView;

    .line 80
    .line 81
    invoke-virtual {v0}, Landroid/view/View;->getMinimumHeight()I

    .line 82
    .line 83
    .line 84
    move-result v0

    .line 85
    invoke-static {p3, p1, v0}, Lka/f0;->g(III)I

    .line 86
    .line 87
    .line 88
    move-result p1

    .line 89
    :goto_0
    iget-object p0, p0, Lka/f0;->b:Landroidx/recyclerview/widget/RecyclerView;

    .line 90
    .line 91
    invoke-static {p0, p2, p1}, Landroidx/recyclerview/widget/RecyclerView;->e(Landroidx/recyclerview/widget/RecyclerView;II)V

    .line 92
    .line 93
    .line 94
    return-void
.end method

.method public final z0(Landroidx/recyclerview/widget/RecyclerView;I)V
    .locals 1

    .line 1
    new-instance v0, Lka/s;

    .line 2
    .line 3
    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-direct {v0, p1}, Lka/s;-><init>(Landroid/content/Context;)V

    .line 8
    .line 9
    .line 10
    iput p2, v0, Lka/s;->a:I

    .line 11
    .line 12
    invoke-virtual {p0, v0}, Lka/f0;->A0(Lka/s;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method
