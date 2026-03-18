.class public abstract Lw4/g;
.super Landroid/view/ViewGroup;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ld6/r;
.implements Ll2/j;
.implements Lv3/p1;
.implements Ld6/s;


# instance fields
.field public A:Z

.field public final B:Lv3/h0;

.field public final d:Lo3/d;

.field public final e:Landroid/view/View;

.field public final f:Lv3/o1;

.field public g:Lay0/a;

.field public h:Z

.field public i:Lay0/a;

.field public j:Lay0/a;

.field public k:Lx2/s;

.field public l:Lay0/k;

.field public m:Lt4/c;

.field public n:Lay0/k;

.field public o:Landroidx/lifecycle/x;

.field public p:Lra/f;

.field public final q:[I

.field public r:J

.field public s:Ld6/w1;

.field public final t:Lw4/f;

.field public final u:Lw4/f;

.field public v:Lay0/k;

.field public final w:[I

.field public x:I

.field public y:I

.field public final z:Lb8/i;


# direct methods
.method public constructor <init>(Landroid/content/Context;Ll2/r;ILo3/d;Landroid/view/View;Lv3/o1;)V
    .locals 4

    .line 1
    invoke-direct {p0, p1}, Landroid/view/ViewGroup;-><init>(Landroid/content/Context;)V

    .line 2
    .line 3
    .line 4
    iput-object p4, p0, Lw4/g;->d:Lo3/d;

    .line 5
    .line 6
    iput-object p5, p0, Lw4/g;->e:Landroid/view/View;

    .line 7
    .line 8
    iput-object p6, p0, Lw4/g;->f:Lv3/o1;

    .line 9
    .line 10
    sget-object p1, Lw3/p2;->a:Ljava/util/LinkedHashMap;

    .line 11
    .line 12
    const p1, 0x7f0a0050

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0, p1, p2}, Landroid/view/View;->setTag(ILjava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    const/4 p1, 0x0

    .line 19
    invoke-virtual {p0, p1}, Landroid/view/View;->setSaveFromParentEnabled(Z)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0, p5}, Landroid/view/ViewGroup;->addView(Landroid/view/View;)V

    .line 23
    .line 24
    .line 25
    new-instance p2, Lw4/a;

    .line 26
    .line 27
    move-object p3, p0

    .line 28
    check-cast p3, Lw4/o;

    .line 29
    .line 30
    invoke-direct {p2, p3, p1}, Lw4/a;-><init>(Landroid/view/ViewGroup;I)V

    .line 31
    .line 32
    .line 33
    invoke-static {p0, p2}, Ld6/r0;->k(Landroid/view/View;Landroidx/datastore/preferences/protobuf/k;)V

    .line 34
    .line 35
    .line 36
    invoke-static {p0, p0}, Ld6/k0;->j(Landroid/view/View;Ld6/s;)V

    .line 37
    .line 38
    .line 39
    sget-object p2, Lw4/e;->i:Lw4/e;

    .line 40
    .line 41
    iput-object p2, p0, Lw4/g;->g:Lay0/a;

    .line 42
    .line 43
    sget-object p2, Lw4/e;->h:Lw4/e;

    .line 44
    .line 45
    iput-object p2, p0, Lw4/g;->i:Lay0/a;

    .line 46
    .line 47
    sget-object p2, Lw4/e;->g:Lw4/e;

    .line 48
    .line 49
    iput-object p2, p0, Lw4/g;->j:Lay0/a;

    .line 50
    .line 51
    sget-object p2, Lx2/p;->b:Lx2/p;

    .line 52
    .line 53
    iput-object p2, p0, Lw4/g;->k:Lx2/s;

    .line 54
    .line 55
    invoke-static {}, Lkp/b9;->a()Lt4/d;

    .line 56
    .line 57
    .line 58
    move-result-object p5

    .line 59
    iput-object p5, p0, Lw4/g;->m:Lt4/c;

    .line 60
    .line 61
    const/4 p5, 0x2

    .line 62
    new-array p6, p5, [I

    .line 63
    .line 64
    iput-object p6, p0, Lw4/g;->q:[I

    .line 65
    .line 66
    const-wide/16 v0, 0x0

    .line 67
    .line 68
    iput-wide v0, p0, Lw4/g;->r:J

    .line 69
    .line 70
    new-instance p6, Lw4/f;

    .line 71
    .line 72
    const/4 v0, 0x1

    .line 73
    invoke-direct {p6, p3, v0}, Lw4/f;-><init>(Lw4/o;I)V

    .line 74
    .line 75
    .line 76
    iput-object p6, p0, Lw4/g;->t:Lw4/f;

    .line 77
    .line 78
    new-instance p6, Lw4/f;

    .line 79
    .line 80
    invoke-direct {p6, p3, p1}, Lw4/f;-><init>(Lw4/o;I)V

    .line 81
    .line 82
    .line 83
    iput-object p6, p0, Lw4/g;->u:Lw4/f;

    .line 84
    .line 85
    new-array p6, p5, [I

    .line 86
    .line 87
    iput-object p6, p0, Lw4/g;->w:[I

    .line 88
    .line 89
    const/high16 p6, -0x80000000

    .line 90
    .line 91
    iput p6, p0, Lw4/g;->x:I

    .line 92
    .line 93
    iput p6, p0, Lw4/g;->y:I

    .line 94
    .line 95
    new-instance p6, Lb8/i;

    .line 96
    .line 97
    invoke-direct {p6, v0}, Lb8/i;-><init>(I)V

    .line 98
    .line 99
    .line 100
    iput-object p6, p0, Lw4/g;->z:Lb8/i;

    .line 101
    .line 102
    new-instance p6, Lv3/h0;

    .line 103
    .line 104
    const/4 v1, 0x3

    .line 105
    invoke-direct {p6, v1}, Lv3/h0;-><init>(I)V

    .line 106
    .line 107
    .line 108
    iput-object p3, p6, Lv3/h0;->q:Lw4/o;

    .line 109
    .line 110
    sget-object v1, Lw4/i;->a:Lw4/h;

    .line 111
    .line 112
    invoke-static {p2, v1, p4}, Landroidx/compose/ui/input/nestedscroll/a;->a(Lx2/s;Lo3/a;Lo3/d;)Lx2/s;

    .line 113
    .line 114
    .line 115
    move-result-object p2

    .line 116
    sget-object p4, Lw4/b;->i:Lw4/b;

    .line 117
    .line 118
    invoke-static {p2, v0, p4}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 119
    .line 120
    .line 121
    move-result-object p2

    .line 122
    new-instance p4, Lp3/a0;

    .line 123
    .line 124
    invoke-direct {p4}, Lp3/a0;-><init>()V

    .line 125
    .line 126
    .line 127
    new-instance v1, Lp3/b0;

    .line 128
    .line 129
    invoke-direct {v1, p3, p1}, Lp3/b0;-><init>(Lw4/o;I)V

    .line 130
    .line 131
    .line 132
    iput-object v1, p4, Lp3/a0;->b:Lay0/k;

    .line 133
    .line 134
    new-instance v1, Lag/t;

    .line 135
    .line 136
    invoke-direct {v1}, Lag/t;-><init>()V

    .line 137
    .line 138
    .line 139
    iget-object v2, p4, Lp3/a0;->c:Lag/t;

    .line 140
    .line 141
    if-eqz v2, :cond_0

    .line 142
    .line 143
    const/4 v3, 0x0

    .line 144
    iput-object v3, v2, Lag/t;->e:Ljava/lang/Object;

    .line 145
    .line 146
    :cond_0
    iput-object v1, p4, Lp3/a0;->c:Lag/t;

    .line 147
    .line 148
    iput-object p4, v1, Lag/t;->e:Ljava/lang/Object;

    .line 149
    .line 150
    invoke-virtual {p0, v1}, Lw4/g;->setOnRequestDisallowInterceptTouchEvent$ui_release(Lay0/k;)V

    .line 151
    .line 152
    .line 153
    invoke-interface {p2, p4}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 154
    .line 155
    .line 156
    move-result-object p2

    .line 157
    new-instance p4, La3/g;

    .line 158
    .line 159
    const/16 v1, 0x8

    .line 160
    .line 161
    invoke-direct {p4, p3, p6, p3, v1}, La3/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 162
    .line 163
    .line 164
    invoke-static {p2, p4}, Landroidx/compose/ui/draw/a;->a(Lx2/s;Lay0/k;)Lx2/s;

    .line 165
    .line 166
    .line 167
    move-result-object p2

    .line 168
    new-instance p4, Lw4/c;

    .line 169
    .line 170
    invoke-direct {p4, p3, p6, p5}, Lw4/c;-><init>(Lw4/o;Lv3/h0;I)V

    .line 171
    .line 172
    .line 173
    invoke-static {p2, p4}, Landroidx/compose/ui/layout/a;->d(Lx2/s;Lay0/k;)Lx2/s;

    .line 174
    .line 175
    .line 176
    move-result-object p2

    .line 177
    iget-object p4, p0, Lw4/g;->k:Lx2/s;

    .line 178
    .line 179
    invoke-interface {p4, p2}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 180
    .line 181
    .line 182
    move-result-object p4

    .line 183
    invoke-virtual {p6, p4}, Lv3/h0;->i0(Lx2/s;)V

    .line 184
    .line 185
    .line 186
    new-instance p4, Lb1/e;

    .line 187
    .line 188
    const/16 p5, 0x14

    .line 189
    .line 190
    invoke-direct {p4, p5, p6, p2}, Lb1/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 191
    .line 192
    .line 193
    iput-object p4, p0, Lw4/g;->l:Lay0/k;

    .line 194
    .line 195
    iget-object p2, p0, Lw4/g;->m:Lt4/c;

    .line 196
    .line 197
    invoke-virtual {p6, p2}, Lv3/h0;->d0(Lt4/c;)V

    .line 198
    .line 199
    .line 200
    new-instance p2, Lw3/a0;

    .line 201
    .line 202
    const/4 p4, 0x6

    .line 203
    invoke-direct {p2, p6, p4}, Lw3/a0;-><init>(Ljava/lang/Object;I)V

    .line 204
    .line 205
    .line 206
    iput-object p2, p0, Lw4/g;->n:Lay0/k;

    .line 207
    .line 208
    new-instance p2, Lw4/c;

    .line 209
    .line 210
    invoke-direct {p2, p3, p6, p1}, Lw4/c;-><init>(Lw4/o;Lv3/h0;I)V

    .line 211
    .line 212
    .line 213
    iput-object p2, p6, Lv3/h0;->O:Lw4/c;

    .line 214
    .line 215
    new-instance p1, Lp3/b0;

    .line 216
    .line 217
    invoke-direct {p1, p3, v0}, Lp3/b0;-><init>(Lw4/o;I)V

    .line 218
    .line 219
    .line 220
    iput-object p1, p6, Lv3/h0;->P:Lp3/b0;

    .line 221
    .line 222
    new-instance p1, Lw4/d;

    .line 223
    .line 224
    invoke-direct {p1, p3, p6}, Lw4/d;-><init>(Lw4/o;Lv3/h0;)V

    .line 225
    .line 226
    .line 227
    invoke-virtual {p6, p1}, Lv3/h0;->h0(Lt3/q0;)V

    .line 228
    .line 229
    .line 230
    iput-object p6, p0, Lw4/g;->B:Lv3/h0;

    .line 231
    .line 232
    return-void
.end method

.method private final getSnapshotObserver()Lv3/q1;
    .locals 1

    .line 1
    invoke-virtual {p0}, Landroid/view/View;->isAttachedToWindow()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const-string v0, "Expected AndroidViewHolder to be attached when observing reads."

    .line 8
    .line 9
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    :cond_0
    iget-object p0, p0, Lw4/g;->f:Lv3/o1;

    .line 13
    .line 14
    check-cast p0, Lw3/t;

    .line 15
    .line 16
    invoke-virtual {p0}, Lw3/t;->getSnapshotObserver()Lv3/q1;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method

.method public static final synthetic j(Lw4/o;)Lv3/q1;
    .locals 0

    .line 1
    invoke-direct {p0}, Lw4/g;->getSnapshotObserver()Lv3/q1;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static final k(Lw4/o;III)I
    .locals 1

    .line 1
    const/high16 p0, 0x40000000    # 2.0f

    .line 2
    .line 3
    if-gez p3, :cond_3

    .line 4
    .line 5
    if-ne p1, p2, :cond_0

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    const/4 p1, -0x2

    .line 9
    const v0, 0x7fffffff

    .line 10
    .line 11
    .line 12
    if-ne p3, p1, :cond_1

    .line 13
    .line 14
    if-eq p2, v0, :cond_1

    .line 15
    .line 16
    const/high16 p0, -0x80000000

    .line 17
    .line 18
    invoke-static {p2, p0}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    return p0

    .line 23
    :cond_1
    const/4 p1, -0x1

    .line 24
    if-ne p3, p1, :cond_2

    .line 25
    .line 26
    if-eq p2, v0, :cond_2

    .line 27
    .line 28
    invoke-static {p2, p0}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    return p0

    .line 33
    :cond_2
    const/4 p0, 0x0

    .line 34
    invoke-static {p0, p0}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    return p0

    .line 39
    :cond_3
    :goto_0
    invoke-static {p3, p1, p2}, Lkp/r9;->e(III)I

    .line 40
    .line 41
    .line 42
    move-result p1

    .line 43
    invoke-static {p1, p0}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 44
    .line 45
    .line 46
    move-result p0

    .line 47
    return p0
.end method

.method public static l(Ls5/b;IIII)Ls5/b;
    .locals 2

    .line 1
    iget v0, p0, Ls5/b;->a:I

    .line 2
    .line 3
    sub-int/2addr v0, p1

    .line 4
    const/4 p1, 0x0

    .line 5
    if-gez v0, :cond_0

    .line 6
    .line 7
    move v0, p1

    .line 8
    :cond_0
    iget v1, p0, Ls5/b;->b:I

    .line 9
    .line 10
    sub-int/2addr v1, p2

    .line 11
    if-gez v1, :cond_1

    .line 12
    .line 13
    move v1, p1

    .line 14
    :cond_1
    iget p2, p0, Ls5/b;->c:I

    .line 15
    .line 16
    sub-int/2addr p2, p3

    .line 17
    if-gez p2, :cond_2

    .line 18
    .line 19
    move p2, p1

    .line 20
    :cond_2
    iget p0, p0, Ls5/b;->d:I

    .line 21
    .line 22
    sub-int/2addr p0, p4

    .line 23
    if-gez p0, :cond_3

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_3
    move p1, p0

    .line 27
    :goto_0
    invoke-static {v0, v1, p2, p1}, Ls5/b;->b(IIII)Ls5/b;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0
.end method


# virtual methods
.method public final a()V
    .locals 1

    .line 1
    iget-object v0, p0, Lw4/g;->i:Lay0/a;

    .line 2
    .line 3
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Landroid/view/ViewGroup;->removeAllViewsInLayout()V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public final b(Landroid/view/View;Landroid/view/View;II)V
    .locals 0

    .line 1
    const/4 p1, 0x1

    .line 2
    iget-object p0, p0, Lw4/g;->z:Lb8/i;

    .line 3
    .line 4
    if-ne p4, p1, :cond_0

    .line 5
    .line 6
    iput p3, p0, Lb8/i;->c:I

    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    iput p3, p0, Lb8/i;->b:I

    .line 10
    .line 11
    return-void
.end method

.method public final c(Landroid/view/View;I)V
    .locals 1

    .line 1
    const/4 p1, 0x1

    .line 2
    iget-object p0, p0, Lw4/g;->z:Lb8/i;

    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    if-ne p2, p1, :cond_0

    .line 6
    .line 7
    iput v0, p0, Lb8/i;->c:I

    .line 8
    .line 9
    return-void

    .line 10
    :cond_0
    iput v0, p0, Lb8/i;->b:I

    .line 11
    .line 12
    return-void
.end method

.method public final d(Landroid/view/View;II[II)V
    .locals 5

    .line 1
    iget-object p1, p0, Lw4/g;->e:Landroid/view/View;

    .line 2
    .line 3
    invoke-virtual {p1}, Landroid/view/View;->isNestedScrollingEnabled()Z

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    if-nez p1, :cond_0

    .line 8
    .line 9
    return-void

    .line 10
    :cond_0
    int-to-float p1, p2

    .line 11
    const/4 p2, -0x1

    .line 12
    int-to-float p2, p2

    .line 13
    mul-float/2addr p1, p2

    .line 14
    int-to-float p3, p3

    .line 15
    mul-float/2addr p3, p2

    .line 16
    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 17
    .line 18
    .line 19
    move-result p1

    .line 20
    int-to-long p1, p1

    .line 21
    invoke-static {p3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 22
    .line 23
    .line 24
    move-result p3

    .line 25
    int-to-long v0, p3

    .line 26
    const/16 p3, 0x20

    .line 27
    .line 28
    shl-long/2addr p1, p3

    .line 29
    const-wide v2, 0xffffffffL

    .line 30
    .line 31
    .line 32
    .line 33
    .line 34
    and-long/2addr v0, v2

    .line 35
    or-long/2addr p1, v0

    .line 36
    const/4 v0, 0x1

    .line 37
    if-nez p5, :cond_1

    .line 38
    .line 39
    move p5, v0

    .line 40
    goto :goto_0

    .line 41
    :cond_1
    const/4 p5, 0x2

    .line 42
    :goto_0
    iget-object p0, p0, Lw4/g;->d:Lo3/d;

    .line 43
    .line 44
    iget-object p0, p0, Lo3/d;->a:Lo3/g;

    .line 45
    .line 46
    const/4 v1, 0x0

    .line 47
    if-eqz p0, :cond_2

    .line 48
    .line 49
    iget-boolean v4, p0, Lx2/r;->q:Z

    .line 50
    .line 51
    if-eqz v4, :cond_2

    .line 52
    .line 53
    invoke-static {p0}, Lv3/f;->j(Lv3/c2;)Lv3/c2;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    move-object v1, p0

    .line 58
    check-cast v1, Lo3/g;

    .line 59
    .line 60
    :cond_2
    if-eqz v1, :cond_3

    .line 61
    .line 62
    invoke-virtual {v1, p5, p1, p2}, Lo3/g;->z(IJ)J

    .line 63
    .line 64
    .line 65
    move-result-wide p0

    .line 66
    goto :goto_1

    .line 67
    :cond_3
    const-wide/16 p0, 0x0

    .line 68
    .line 69
    :goto_1
    shr-long p2, p0, p3

    .line 70
    .line 71
    long-to-int p2, p2

    .line 72
    invoke-static {p2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 73
    .line 74
    .line 75
    move-result p2

    .line 76
    invoke-static {p2}, Lw3/h0;->n(F)I

    .line 77
    .line 78
    .line 79
    move-result p2

    .line 80
    const/4 p3, 0x0

    .line 81
    aput p2, p4, p3

    .line 82
    .line 83
    and-long/2addr p0, v2

    .line 84
    long-to-int p0, p0

    .line 85
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 86
    .line 87
    .line 88
    move-result p0

    .line 89
    invoke-static {p0}, Lw3/h0;->n(F)I

    .line 90
    .line 91
    .line 92
    move-result p0

    .line 93
    aput p0, p4, v0

    .line 94
    .line 95
    return-void
.end method

.method public final e()V
    .locals 2

    .line 1
    iget-object v0, p0, Lw4/g;->e:Landroid/view/View;

    .line 2
    .line 3
    invoke-virtual {v0}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    if-eq v1, p0, :cond_0

    .line 8
    .line 9
    invoke-virtual {p0, v0}, Landroid/view/ViewGroup;->addView(Landroid/view/View;)V

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    iget-object p0, p0, Lw4/g;->i:Lay0/a;

    .line 14
    .line 15
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public final e0()Z
    .locals 0

    .line 1
    invoke-virtual {p0}, Landroid/view/View;->isAttachedToWindow()Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public final f()V
    .locals 0

    .line 1
    iget-object p0, p0, Lw4/g;->j:Lay0/a;

    .line 2
    .line 3
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final g(Landroid/view/View;IIIII[I)V
    .locals 12

    .line 1
    iget-object p1, p0, Lw4/g;->e:Landroid/view/View;

    .line 2
    .line 3
    invoke-virtual {p1}, Landroid/view/View;->isNestedScrollingEnabled()Z

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    if-nez p1, :cond_0

    .line 8
    .line 9
    return-void

    .line 10
    :cond_0
    int-to-float p1, p2

    .line 11
    const/4 p2, -0x1

    .line 12
    int-to-float p2, p2

    .line 13
    mul-float/2addr p1, p2

    .line 14
    int-to-float p3, p3

    .line 15
    mul-float/2addr p3, p2

    .line 16
    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 17
    .line 18
    .line 19
    move-result p1

    .line 20
    int-to-long v0, p1

    .line 21
    invoke-static {p3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 22
    .line 23
    .line 24
    move-result p1

    .line 25
    int-to-long v2, p1

    .line 26
    const/16 p1, 0x20

    .line 27
    .line 28
    shl-long/2addr v0, p1

    .line 29
    const-wide v4, 0xffffffffL

    .line 30
    .line 31
    .line 32
    .line 33
    .line 34
    and-long/2addr v2, v4

    .line 35
    or-long v8, v0, v2

    .line 36
    .line 37
    move/from16 p3, p4

    .line 38
    .line 39
    int-to-float p3, p3

    .line 40
    mul-float/2addr p3, p2

    .line 41
    move/from16 v0, p5

    .line 42
    .line 43
    int-to-float v0, v0

    .line 44
    mul-float/2addr v0, p2

    .line 45
    invoke-static {p3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 46
    .line 47
    .line 48
    move-result p2

    .line 49
    int-to-long p2, p2

    .line 50
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    int-to-long v0, v0

    .line 55
    shl-long/2addr p2, p1

    .line 56
    and-long/2addr v0, v4

    .line 57
    or-long v10, p2, v0

    .line 58
    .line 59
    const/4 p2, 0x1

    .line 60
    if-nez p6, :cond_1

    .line 61
    .line 62
    move v7, p2

    .line 63
    goto :goto_0

    .line 64
    :cond_1
    const/4 p3, 0x2

    .line 65
    move v7, p3

    .line 66
    :goto_0
    iget-object p0, p0, Lw4/g;->d:Lo3/d;

    .line 67
    .line 68
    iget-object p0, p0, Lo3/d;->a:Lo3/g;

    .line 69
    .line 70
    const/4 p3, 0x0

    .line 71
    if-eqz p0, :cond_2

    .line 72
    .line 73
    iget-boolean v0, p0, Lx2/r;->q:Z

    .line 74
    .line 75
    if-eqz v0, :cond_2

    .line 76
    .line 77
    invoke-static {p0}, Lv3/f;->j(Lv3/c2;)Lv3/c2;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    move-object p3, p0

    .line 82
    check-cast p3, Lo3/g;

    .line 83
    .line 84
    :cond_2
    move-object v6, p3

    .line 85
    if-eqz v6, :cond_3

    .line 86
    .line 87
    invoke-virtual/range {v6 .. v11}, Lo3/g;->P(IJJ)J

    .line 88
    .line 89
    .line 90
    move-result-wide v0

    .line 91
    goto :goto_1

    .line 92
    :cond_3
    const-wide/16 v0, 0x0

    .line 93
    .line 94
    :goto_1
    shr-long p0, v0, p1

    .line 95
    .line 96
    long-to-int p0, p0

    .line 97
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 98
    .line 99
    .line 100
    move-result p0

    .line 101
    invoke-static {p0}, Lw3/h0;->n(F)I

    .line 102
    .line 103
    .line 104
    move-result p0

    .line 105
    const/4 p1, 0x0

    .line 106
    aput p0, p7, p1

    .line 107
    .line 108
    and-long p0, v0, v4

    .line 109
    .line 110
    long-to-int p0, p0

    .line 111
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 112
    .line 113
    .line 114
    move-result p0

    .line 115
    invoke-static {p0}, Lw3/h0;->n(F)I

    .line 116
    .line 117
    .line 118
    move-result p0

    .line 119
    aput p0, p7, p2

    .line 120
    .line 121
    return-void
.end method

.method public final gatherTransparentRegion(Landroid/graphics/Region;)Z
    .locals 9

    .line 1
    const/4 v0, 0x1

    .line 2
    if-nez p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    iget-object v1, p0, Lw4/g;->w:[I

    .line 6
    .line 7
    invoke-virtual {p0, v1}, Landroid/view/View;->getLocationInWindow([I)V

    .line 8
    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    aget v4, v1, v2

    .line 12
    .line 13
    aget v5, v1, v0

    .line 14
    .line 15
    invoke-virtual {p0}, Landroid/view/View;->getWidth()I

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    add-int v6, v2, v4

    .line 20
    .line 21
    aget v1, v1, v0

    .line 22
    .line 23
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    add-int v7, p0, v1

    .line 28
    .line 29
    sget-object v8, Landroid/graphics/Region$Op;->DIFFERENCE:Landroid/graphics/Region$Op;

    .line 30
    .line 31
    move-object v3, p1

    .line 32
    invoke-virtual/range {v3 .. v8}, Landroid/graphics/Region;->op(IIIILandroid/graphics/Region$Op;)Z

    .line 33
    .line 34
    .line 35
    return v0
.end method

.method public getAccessibilityClassName()Ljava/lang/CharSequence;
    .locals 0

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public final getDensity()Lt4/c;
    .locals 0

    .line 1
    iget-object p0, p0, Lw4/g;->m:Lt4/c;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getInteropView()Landroid/view/View;
    .locals 0

    .line 1
    iget-object p0, p0, Lw4/g;->e:Landroid/view/View;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getLayoutNode()Lv3/h0;
    .locals 0

    .line 1
    iget-object p0, p0, Lw4/g;->B:Lv3/h0;

    .line 2
    .line 3
    return-object p0
.end method

.method public getLayoutParams()Landroid/view/ViewGroup$LayoutParams;
    .locals 1

    .line 1
    iget-object p0, p0, Lw4/g;->e:Landroid/view/View;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    if-nez p0, :cond_0

    .line 8
    .line 9
    new-instance p0, Landroid/view/ViewGroup$LayoutParams;

    .line 10
    .line 11
    const/4 v0, -0x1

    .line 12
    invoke-direct {p0, v0, v0}, Landroid/view/ViewGroup$LayoutParams;-><init>(II)V

    .line 13
    .line 14
    .line 15
    :cond_0
    return-object p0
.end method

.method public final getLifecycleOwner()Landroidx/lifecycle/x;
    .locals 0

    .line 1
    iget-object p0, p0, Lw4/g;->o:Landroidx/lifecycle/x;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getModifier()Lx2/s;
    .locals 0

    .line 1
    iget-object p0, p0, Lw4/g;->k:Lx2/s;

    .line 2
    .line 3
    return-object p0
.end method

.method public getNestedScrollAxes()I
    .locals 1

    .line 1
    iget-object p0, p0, Lw4/g;->z:Lb8/i;

    .line 2
    .line 3
    iget v0, p0, Lb8/i;->b:I

    .line 4
    .line 5
    iget p0, p0, Lb8/i;->c:I

    .line 6
    .line 7
    or-int/2addr p0, v0

    .line 8
    return p0
.end method

.method public final getOnDensityChanged$ui_release()Lay0/k;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lay0/k;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lw4/g;->n:Lay0/k;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getOnModifierChanged$ui_release()Lay0/k;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lay0/k;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lw4/g;->l:Lay0/k;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getOnRequestDisallowInterceptTouchEvent$ui_release()Lay0/k;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lay0/k;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lw4/g;->v:Lay0/k;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getRelease()Lay0/a;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lay0/a;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lw4/g;->j:Lay0/a;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getReset()Lay0/a;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lay0/a;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lw4/g;->i:Lay0/a;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getSavedStateRegistryOwner()Lra/f;
    .locals 0

    .line 1
    iget-object p0, p0, Lw4/g;->p:Lra/f;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getUpdate()Lay0/a;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lay0/a;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lw4/g;->g:Lay0/a;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getView()Landroid/view/View;
    .locals 0

    .line 1
    iget-object p0, p0, Lw4/g;->e:Landroid/view/View;

    .line 2
    .line 3
    return-object p0
.end method

.method public final h(Landroid/view/View;IIIII)V
    .locals 12

    .line 1
    iget-object p1, p0, Lw4/g;->e:Landroid/view/View;

    .line 2
    .line 3
    invoke-virtual {p1}, Landroid/view/View;->isNestedScrollingEnabled()Z

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    if-nez p1, :cond_0

    .line 8
    .line 9
    return-void

    .line 10
    :cond_0
    int-to-float p1, p2

    .line 11
    const/4 p2, -0x1

    .line 12
    int-to-float p2, p2

    .line 13
    mul-float/2addr p1, p2

    .line 14
    int-to-float p3, p3

    .line 15
    mul-float/2addr p3, p2

    .line 16
    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 17
    .line 18
    .line 19
    move-result p1

    .line 20
    int-to-long v0, p1

    .line 21
    invoke-static {p3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 22
    .line 23
    .line 24
    move-result p1

    .line 25
    int-to-long v2, p1

    .line 26
    const/16 p1, 0x20

    .line 27
    .line 28
    shl-long/2addr v0, p1

    .line 29
    const-wide v4, 0xffffffffL

    .line 30
    .line 31
    .line 32
    .line 33
    .line 34
    and-long/2addr v2, v4

    .line 35
    or-long v8, v0, v2

    .line 36
    .line 37
    move/from16 p3, p4

    .line 38
    .line 39
    int-to-float p3, p3

    .line 40
    mul-float/2addr p3, p2

    .line 41
    move/from16 v0, p5

    .line 42
    .line 43
    int-to-float v0, v0

    .line 44
    mul-float/2addr v0, p2

    .line 45
    invoke-static {p3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 46
    .line 47
    .line 48
    move-result p2

    .line 49
    int-to-long p2, p2

    .line 50
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    int-to-long v0, v0

    .line 55
    shl-long p1, p2, p1

    .line 56
    .line 57
    and-long/2addr v0, v4

    .line 58
    or-long v10, p1, v0

    .line 59
    .line 60
    if-nez p6, :cond_1

    .line 61
    .line 62
    const/4 p1, 0x1

    .line 63
    :goto_0
    move v7, p1

    .line 64
    goto :goto_1

    .line 65
    :cond_1
    const/4 p1, 0x2

    .line 66
    goto :goto_0

    .line 67
    :goto_1
    iget-object p0, p0, Lw4/g;->d:Lo3/d;

    .line 68
    .line 69
    iget-object p0, p0, Lo3/d;->a:Lo3/g;

    .line 70
    .line 71
    const/4 p1, 0x0

    .line 72
    if-eqz p0, :cond_2

    .line 73
    .line 74
    iget-boolean p2, p0, Lx2/r;->q:Z

    .line 75
    .line 76
    if-eqz p2, :cond_2

    .line 77
    .line 78
    invoke-static {p0}, Lv3/f;->j(Lv3/c2;)Lv3/c2;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    move-object p1, p0

    .line 83
    check-cast p1, Lo3/g;

    .line 84
    .line 85
    :cond_2
    move-object v6, p1

    .line 86
    if-eqz v6, :cond_3

    .line 87
    .line 88
    invoke-virtual/range {v6 .. v11}, Lo3/g;->P(IJJ)J

    .line 89
    .line 90
    .line 91
    :cond_3
    return-void
.end method

.method public final i(Landroid/view/View;Landroid/view/View;II)Z
    .locals 0

    .line 1
    and-int/lit8 p0, p3, 0x2

    .line 2
    .line 3
    const/4 p1, 0x1

    .line 4
    if-nez p0, :cond_1

    .line 5
    .line 6
    and-int/lit8 p0, p3, 0x1

    .line 7
    .line 8
    if-eqz p0, :cond_0

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    const/4 p0, 0x0

    .line 12
    return p0

    .line 13
    :cond_1
    :goto_0
    return p1
.end method

.method public final invalidateChildInParent([ILandroid/graphics/Rect;)Landroid/view/ViewParent;
    .locals 1

    .line 1
    invoke-super {p0, p1, p2}, Landroid/view/ViewGroup;->invalidateChildInParent([ILandroid/graphics/Rect;)Landroid/view/ViewParent;

    .line 2
    .line 3
    .line 4
    iget-boolean p1, p0, Lw4/g;->A:Z

    .line 5
    .line 6
    if-eqz p1, :cond_0

    .line 7
    .line 8
    new-instance p1, Lh91/c;

    .line 9
    .line 10
    const/4 p2, 0x6

    .line 11
    iget-object v0, p0, Lw4/g;->u:Lw4/f;

    .line 12
    .line 13
    invoke-direct {p1, v0, p2}, Lh91/c;-><init>(Lay0/a;I)V

    .line 14
    .line 15
    .line 16
    iget-object p0, p0, Lw4/g;->e:Landroid/view/View;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Landroid/view/View;->postOnAnimation(Ljava/lang/Runnable;)V

    .line 19
    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    iget-object p0, p0, Lw4/g;->B:Lv3/h0;

    .line 23
    .line 24
    invoke-virtual {p0}, Lv3/h0;->C()V

    .line 25
    .line 26
    .line 27
    :goto_0
    const/4 p0, 0x0

    .line 28
    return-object p0
.end method

.method public final isNestedScrollingEnabled()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lw4/g;->e:Landroid/view/View;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/view/View;->isNestedScrollingEnabled()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final m(Ld6/w1;)Ld6/w1;
    .locals 13

    .line 1
    invoke-virtual {p1}, Ld6/w1;->e()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    goto/16 :goto_1

    .line 8
    .line 9
    :cond_0
    iget-object p0, p0, Lw4/g;->B:Lv3/h0;

    .line 10
    .line 11
    iget-object p0, p0, Lv3/h0;->H:Lg1/q;

    .line 12
    .line 13
    iget-object p0, p0, Lg1/q;->d:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p0, Lv3/u;

    .line 16
    .line 17
    iget-object v0, p0, Lv3/u;->S:Lv3/z1;

    .line 18
    .line 19
    iget-boolean v0, v0, Lx2/r;->q:Z

    .line 20
    .line 21
    if-nez v0, :cond_1

    .line 22
    .line 23
    goto :goto_1

    .line 24
    :cond_1
    const-wide/16 v0, 0x0

    .line 25
    .line 26
    invoke-virtual {p0, v0, v1}, Lv3/f1;->R(J)J

    .line 27
    .line 28
    .line 29
    move-result-wide v0

    .line 30
    invoke-static {v0, v1}, Lkp/d9;->b(J)J

    .line 31
    .line 32
    .line 33
    move-result-wide v0

    .line 34
    const/16 v2, 0x20

    .line 35
    .line 36
    shr-long v3, v0, v2

    .line 37
    .line 38
    long-to-int v3, v3

    .line 39
    const/4 v4, 0x0

    .line 40
    if-gez v3, :cond_2

    .line 41
    .line 42
    move v3, v4

    .line 43
    :cond_2
    const-wide v5, 0xffffffffL

    .line 44
    .line 45
    .line 46
    .line 47
    .line 48
    and-long/2addr v0, v5

    .line 49
    long-to-int v0, v0

    .line 50
    if-gez v0, :cond_3

    .line 51
    .line 52
    move v0, v4

    .line 53
    :cond_3
    invoke-static {p0}, Lt3/k1;->i(Lt3/y;)Lt3/y;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    invoke-interface {v1}, Lt3/y;->h()J

    .line 58
    .line 59
    .line 60
    move-result-wide v7

    .line 61
    shr-long v9, v7, v2

    .line 62
    .line 63
    long-to-int v1, v9

    .line 64
    and-long/2addr v7, v5

    .line 65
    long-to-int v7, v7

    .line 66
    iget-wide v8, p0, Lt3/e1;->f:J

    .line 67
    .line 68
    shr-long v10, v8, v2

    .line 69
    .line 70
    long-to-int v10, v10

    .line 71
    and-long/2addr v8, v5

    .line 72
    long-to-int v8, v8

    .line 73
    int-to-float v9, v10

    .line 74
    int-to-float v8, v8

    .line 75
    invoke-static {v9}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 76
    .line 77
    .line 78
    move-result v9

    .line 79
    int-to-long v9, v9

    .line 80
    invoke-static {v8}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 81
    .line 82
    .line 83
    move-result v8

    .line 84
    int-to-long v11, v8

    .line 85
    shl-long v8, v9, v2

    .line 86
    .line 87
    and-long v10, v11, v5

    .line 88
    .line 89
    or-long/2addr v8, v10

    .line 90
    invoke-virtual {p0, v8, v9}, Lv3/f1;->R(J)J

    .line 91
    .line 92
    .line 93
    move-result-wide v8

    .line 94
    invoke-static {v8, v9}, Lkp/d9;->b(J)J

    .line 95
    .line 96
    .line 97
    move-result-wide v8

    .line 98
    shr-long v10, v8, v2

    .line 99
    .line 100
    long-to-int p0, v10

    .line 101
    sub-int/2addr v1, p0

    .line 102
    if-gez v1, :cond_4

    .line 103
    .line 104
    move v1, v4

    .line 105
    :cond_4
    and-long/2addr v5, v8

    .line 106
    long-to-int p0, v5

    .line 107
    sub-int/2addr v7, p0

    .line 108
    if-gez v7, :cond_5

    .line 109
    .line 110
    goto :goto_0

    .line 111
    :cond_5
    move v4, v7

    .line 112
    :goto_0
    if-nez v3, :cond_6

    .line 113
    .line 114
    if-nez v0, :cond_6

    .line 115
    .line 116
    if-nez v1, :cond_6

    .line 117
    .line 118
    if-nez v4, :cond_6

    .line 119
    .line 120
    :goto_1
    return-object p1

    .line 121
    :cond_6
    iget-object p0, p1, Ld6/w1;->a:Ld6/s1;

    .line 122
    .line 123
    invoke-virtual {p0, v3, v0, v1, v4}, Ld6/s1;->n(IIII)Ld6/w1;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    return-object p0
.end method

.method public final onApplyWindowInsets(Landroid/view/View;Ld6/w1;)Ld6/w1;
    .locals 0

    .line 1
    new-instance p1, Ld6/w1;

    .line 2
    .line 3
    invoke-direct {p1, p2}, Ld6/w1;-><init>(Ld6/w1;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lw4/g;->s:Ld6/w1;

    .line 7
    .line 8
    invoke-virtual {p0, p2}, Lw4/g;->m(Ld6/w1;)Ld6/w1;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0
.end method

.method public final onAttachedToWindow()V
    .locals 0

    .line 1
    invoke-super {p0}, Landroid/view/ViewGroup;->onAttachedToWindow()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lw4/g;->t:Lw4/f;

    .line 5
    .line 6
    invoke-virtual {p0}, Lw4/f;->invoke()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public final onDescendantInvalidated(Landroid/view/View;Landroid/view/View;)V
    .locals 1

    .line 1
    invoke-super {p0, p1, p2}, Landroid/view/ViewGroup;->onDescendantInvalidated(Landroid/view/View;Landroid/view/View;)V

    .line 2
    .line 3
    .line 4
    iget-boolean p1, p0, Lw4/g;->A:Z

    .line 5
    .line 6
    if-eqz p1, :cond_0

    .line 7
    .line 8
    new-instance p1, Lh91/c;

    .line 9
    .line 10
    const/4 p2, 0x6

    .line 11
    iget-object v0, p0, Lw4/g;->u:Lw4/f;

    .line 12
    .line 13
    invoke-direct {p1, v0, p2}, Lh91/c;-><init>(Lay0/a;I)V

    .line 14
    .line 15
    .line 16
    iget-object p0, p0, Lw4/g;->e:Landroid/view/View;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Landroid/view/View;->postOnAnimation(Ljava/lang/Runnable;)V

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    :cond_0
    iget-object p0, p0, Lw4/g;->B:Lv3/h0;

    .line 23
    .line 24
    invoke-virtual {p0}, Lv3/h0;->C()V

    .line 25
    .line 26
    .line 27
    return-void
.end method

.method public final onDetachedFromWindow()V
    .locals 1

    .line 1
    invoke-super {p0}, Landroid/view/ViewGroup;->onDetachedFromWindow()V

    .line 2
    .line 3
    .line 4
    invoke-direct {p0}, Lw4/g;->getSnapshotObserver()Lv3/q1;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    iget-object v0, v0, Lv3/q1;->a:Lv2/r;

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Lv2/r;->b(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public final onLayout(ZIIII)V
    .locals 0

    .line 1
    sub-int/2addr p4, p2

    .line 2
    sub-int/2addr p5, p3

    .line 3
    iget-object p0, p0, Lw4/g;->e:Landroid/view/View;

    .line 4
    .line 5
    const/4 p1, 0x0

    .line 6
    invoke-virtual {p0, p1, p1, p4, p5}, Landroid/view/View;->layout(IIII)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public final onMeasure(II)V
    .locals 3

    .line 1
    iget-object v0, p0, Lw4/g;->e:Landroid/view/View;

    .line 2
    .line 3
    invoke-virtual {v0}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    if-eq v1, p0, :cond_0

    .line 8
    .line 9
    invoke-static {p1}, Landroid/view/View$MeasureSpec;->getSize(I)I

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    invoke-static {p2}, Landroid/view/View$MeasureSpec;->getSize(I)I

    .line 14
    .line 15
    .line 16
    move-result p2

    .line 17
    invoke-virtual {p0, p1, p2}, Landroid/view/View;->setMeasuredDimension(II)V

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :cond_0
    invoke-virtual {v0}, Landroid/view/View;->getVisibility()I

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    const/16 v2, 0x8

    .line 26
    .line 27
    if-ne v1, v2, :cond_1

    .line 28
    .line 29
    const/4 p1, 0x0

    .line 30
    invoke-virtual {p0, p1, p1}, Landroid/view/View;->setMeasuredDimension(II)V

    .line 31
    .line 32
    .line 33
    return-void

    .line 34
    :cond_1
    invoke-virtual {v0, p1, p2}, Landroid/view/View;->measure(II)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {v0}, Landroid/view/View;->getMeasuredWidth()I

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    invoke-virtual {v0}, Landroid/view/View;->getMeasuredHeight()I

    .line 42
    .line 43
    .line 44
    move-result v0

    .line 45
    invoke-virtual {p0, v1, v0}, Landroid/view/View;->setMeasuredDimension(II)V

    .line 46
    .line 47
    .line 48
    iput p1, p0, Lw4/g;->x:I

    .line 49
    .line 50
    iput p2, p0, Lw4/g;->y:I

    .line 51
    .line 52
    return-void
.end method

.method public final onNestedFling(Landroid/view/View;FFZ)Z
    .locals 7

    .line 1
    iget-object p1, p0, Lw4/g;->e:Landroid/view/View;

    .line 2
    .line 3
    invoke-virtual {p1}, Landroid/view/View;->isNestedScrollingEnabled()Z

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    const/4 v0, 0x0

    .line 8
    if-nez p1, :cond_0

    .line 9
    .line 10
    return v0

    .line 11
    :cond_0
    const/high16 p1, -0x40800000    # -1.0f

    .line 12
    .line 13
    mul-float/2addr p2, p1

    .line 14
    mul-float/2addr p3, p1

    .line 15
    invoke-static {p2, p3}, Lkp/g9;->a(FF)J

    .line 16
    .line 17
    .line 18
    move-result-wide v4

    .line 19
    iget-object p1, p0, Lw4/g;->d:Lo3/d;

    .line 20
    .line 21
    invoke-virtual {p1}, Lo3/d;->c()Lvy0/b0;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    new-instance v1, Lc00/r1;

    .line 26
    .line 27
    const/4 v6, 0x0

    .line 28
    move-object v3, p0

    .line 29
    move v2, p4

    .line 30
    invoke-direct/range {v1 .. v6}, Lc00/r1;-><init>(ZLw4/g;JLkotlin/coroutines/Continuation;)V

    .line 31
    .line 32
    .line 33
    const/4 p0, 0x3

    .line 34
    const/4 p2, 0x0

    .line 35
    invoke-static {p1, p2, p2, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 36
    .line 37
    .line 38
    return v0
.end method

.method public final onNestedPreFling(Landroid/view/View;FF)Z
    .locals 7

    .line 1
    iget-object p1, p0, Lw4/g;->e:Landroid/view/View;

    .line 2
    .line 3
    invoke-virtual {p1}, Landroid/view/View;->isNestedScrollingEnabled()Z

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    const/4 v0, 0x0

    .line 8
    if-nez p1, :cond_0

    .line 9
    .line 10
    return v0

    .line 11
    :cond_0
    const/high16 p1, -0x40800000    # -1.0f

    .line 12
    .line 13
    mul-float/2addr p2, p1

    .line 14
    mul-float/2addr p3, p1

    .line 15
    invoke-static {p2, p3}, Lkp/g9;->a(FF)J

    .line 16
    .line 17
    .line 18
    move-result-wide v3

    .line 19
    iget-object p1, p0, Lw4/g;->d:Lo3/d;

    .line 20
    .line 21
    invoke-virtual {p1}, Lo3/d;->c()Lvy0/b0;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    new-instance v1, Le2/f0;

    .line 26
    .line 27
    const/4 v6, 0x6

    .line 28
    const/4 v5, 0x0

    .line 29
    move-object v2, p0

    .line 30
    invoke-direct/range {v1 .. v6}, Le2/f0;-><init>(Ljava/lang/Object;JLkotlin/coroutines/Continuation;I)V

    .line 31
    .line 32
    .line 33
    const/4 p0, 0x3

    .line 34
    invoke-static {p1, v5, v5, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 35
    .line 36
    .line 37
    return v0
.end method

.method public final onWindowVisibilityChanged(I)V
    .locals 0

    .line 1
    invoke-super {p0, p1}, Landroid/view/View;->onWindowVisibilityChanged(I)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final requestDisallowInterceptTouchEvent(Z)V
    .locals 2

    .line 1
    iget-object v0, p0, Lw4/g;->v:Lay0/k;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    :cond_0
    invoke-super {p0, p1}, Landroid/view/ViewGroup;->requestDisallowInterceptTouchEvent(Z)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public final setDensity(Lt4/c;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lw4/g;->m:Lt4/c;

    .line 2
    .line 3
    if-eq p1, v0, :cond_0

    .line 4
    .line 5
    iput-object p1, p0, Lw4/g;->m:Lt4/c;

    .line 6
    .line 7
    iget-object p0, p0, Lw4/g;->n:Lay0/k;

    .line 8
    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    :cond_0
    return-void
.end method

.method public final setLifecycleOwner(Landroidx/lifecycle/x;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lw4/g;->o:Landroidx/lifecycle/x;

    .line 2
    .line 3
    if-eq p1, v0, :cond_0

    .line 4
    .line 5
    iput-object p1, p0, Lw4/g;->o:Landroidx/lifecycle/x;

    .line 6
    .line 7
    invoke-static {p0, p1}, Landroidx/lifecycle/v0;->l(Landroid/view/View;Landroidx/lifecycle/x;)V

    .line 8
    .line 9
    .line 10
    :cond_0
    return-void
.end method

.method public final setModifier(Lx2/s;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lw4/g;->k:Lx2/s;

    .line 2
    .line 3
    if-eq p1, v0, :cond_0

    .line 4
    .line 5
    iput-object p1, p0, Lw4/g;->k:Lx2/s;

    .line 6
    .line 7
    iget-object p0, p0, Lw4/g;->l:Lay0/k;

    .line 8
    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    :cond_0
    return-void
.end method

.method public final setOnDensityChanged$ui_release(Lay0/k;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lay0/k;",
            ")V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lw4/g;->n:Lay0/k;

    .line 2
    .line 3
    return-void
.end method

.method public final setOnModifierChanged$ui_release(Lay0/k;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lay0/k;",
            ")V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lw4/g;->l:Lay0/k;

    .line 2
    .line 3
    return-void
.end method

.method public final setOnRequestDisallowInterceptTouchEvent$ui_release(Lay0/k;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lay0/k;",
            ")V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lw4/g;->v:Lay0/k;

    .line 2
    .line 3
    return-void
.end method

.method public final setRelease(Lay0/a;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lay0/a;",
            ")V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lw4/g;->j:Lay0/a;

    .line 2
    .line 3
    return-void
.end method

.method public final setReset(Lay0/a;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lay0/a;",
            ")V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lw4/g;->i:Lay0/a;

    .line 2
    .line 3
    return-void
.end method

.method public final setSavedStateRegistryOwner(Lra/f;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lw4/g;->p:Lra/f;

    .line 2
    .line 3
    if-eq p1, v0, :cond_0

    .line 4
    .line 5
    iput-object p1, p0, Lw4/g;->p:Lra/f;

    .line 6
    .line 7
    invoke-static {p0, p1}, Lkp/w;->d(Landroid/view/View;Lra/f;)V

    .line 8
    .line 9
    .line 10
    :cond_0
    return-void
.end method

.method public final setUpdate(Lay0/a;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lay0/a;",
            ")V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lw4/g;->g:Lay0/a;

    .line 2
    .line 3
    const/4 p1, 0x1

    .line 4
    iput-boolean p1, p0, Lw4/g;->h:Z

    .line 5
    .line 6
    iget-object p0, p0, Lw4/g;->t:Lw4/f;

    .line 7
    .line 8
    invoke-virtual {p0}, Lw4/f;->invoke()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final shouldDelayChildPressedState()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method
