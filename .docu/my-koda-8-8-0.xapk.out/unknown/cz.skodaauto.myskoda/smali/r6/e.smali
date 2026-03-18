.class public final Lr6/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final p:Lr6/c;

.field public static final q:Lr6/c;

.field public static final r:Lr6/c;

.field public static final s:Lr6/c;

.field public static final t:Lr6/c;

.field public static final u:Lr6/c;


# instance fields
.field public a:F

.field public b:F

.field public c:Z

.field public final d:Lwq/v;

.field public final e:Lkp/l;

.field public f:Z

.field public g:F

.field public h:F

.field public i:J

.field public j:F

.field public final k:Ljava/util/ArrayList;

.field public final l:Ljava/util/ArrayList;

.field public m:Lr6/f;

.field public n:F

.field public o:Z


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lr6/c;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, v1}, Lr6/c;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lr6/e;->p:Lr6/c;

    .line 8
    .line 9
    new-instance v0, Lr6/c;

    .line 10
    .line 11
    const/4 v1, 0x2

    .line 12
    invoke-direct {v0, v1}, Lr6/c;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lr6/e;->q:Lr6/c;

    .line 16
    .line 17
    new-instance v0, Lr6/c;

    .line 18
    .line 19
    const/4 v1, 0x3

    .line 20
    invoke-direct {v0, v1}, Lr6/c;-><init>(I)V

    .line 21
    .line 22
    .line 23
    sput-object v0, Lr6/e;->r:Lr6/c;

    .line 24
    .line 25
    new-instance v0, Lr6/c;

    .line 26
    .line 27
    const/4 v1, 0x4

    .line 28
    invoke-direct {v0, v1}, Lr6/c;-><init>(I)V

    .line 29
    .line 30
    .line 31
    sput-object v0, Lr6/e;->s:Lr6/c;

    .line 32
    .line 33
    new-instance v0, Lr6/c;

    .line 34
    .line 35
    const/4 v1, 0x5

    .line 36
    invoke-direct {v0, v1}, Lr6/c;-><init>(I)V

    .line 37
    .line 38
    .line 39
    sput-object v0, Lr6/e;->t:Lr6/c;

    .line 40
    .line 41
    new-instance v0, Lr6/c;

    .line 42
    .line 43
    const/4 v1, 0x0

    .line 44
    invoke-direct {v0, v1}, Lr6/c;-><init>(I)V

    .line 45
    .line 46
    .line 47
    sput-object v0, Lr6/e;->u:Lr6/c;

    .line 48
    .line 49
    return-void
.end method

.method public constructor <init>(Lk1/f;)V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 2
    iput v0, p0, Lr6/e;->a:F

    const v0, 0x7f7fffff    # Float.MAX_VALUE

    .line 3
    iput v0, p0, Lr6/e;->b:F

    const/4 v1, 0x0

    .line 4
    iput-boolean v1, p0, Lr6/e;->c:Z

    .line 5
    iput-boolean v1, p0, Lr6/e;->f:Z

    .line 6
    iput v0, p0, Lr6/e;->g:F

    const v2, -0x800001

    .line 7
    iput v2, p0, Lr6/e;->h:F

    const-wide/16 v2, 0x0

    .line 8
    iput-wide v2, p0, Lr6/e;->i:J

    .line 9
    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    iput-object v2, p0, Lr6/e;->k:Ljava/util/ArrayList;

    .line 10
    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    iput-object v2, p0, Lr6/e;->l:Ljava/util/ArrayList;

    const/4 v2, 0x0

    .line 11
    iput-object v2, p0, Lr6/e;->d:Lwq/v;

    .line 12
    new-instance v3, Lr6/d;

    invoke-direct {v3, p1}, Lr6/d;-><init>(Lk1/f;)V

    iput-object v3, p0, Lr6/e;->e:Lkp/l;

    const/high16 p1, 0x3f800000    # 1.0f

    .line 13
    iput p1, p0, Lr6/e;->j:F

    .line 14
    iput-object v2, p0, Lr6/e;->m:Lr6/f;

    .line 15
    iput v0, p0, Lr6/e;->n:F

    .line 16
    iput-boolean v1, p0, Lr6/e;->o:Z

    return-void
.end method

.method public constructor <init>(Lwq/v;Lkp/l;)V
    .locals 4

    .line 17
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 18
    iput v0, p0, Lr6/e;->a:F

    const v0, 0x7f7fffff    # Float.MAX_VALUE

    .line 19
    iput v0, p0, Lr6/e;->b:F

    const/4 v1, 0x0

    .line 20
    iput-boolean v1, p0, Lr6/e;->c:Z

    .line 21
    iput-boolean v1, p0, Lr6/e;->f:Z

    .line 22
    iput v0, p0, Lr6/e;->g:F

    const v2, -0x800001

    .line 23
    iput v2, p0, Lr6/e;->h:F

    const-wide/16 v2, 0x0

    .line 24
    iput-wide v2, p0, Lr6/e;->i:J

    .line 25
    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    iput-object v2, p0, Lr6/e;->k:Ljava/util/ArrayList;

    .line 26
    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    iput-object v2, p0, Lr6/e;->l:Ljava/util/ArrayList;

    .line 27
    iput-object p1, p0, Lr6/e;->d:Lwq/v;

    .line 28
    iput-object p2, p0, Lr6/e;->e:Lkp/l;

    .line 29
    sget-object p1, Lr6/e;->r:Lr6/c;

    if-eq p2, p1, :cond_4

    sget-object p1, Lr6/e;->s:Lr6/c;

    if-eq p2, p1, :cond_4

    sget-object p1, Lr6/e;->t:Lr6/c;

    if-ne p2, p1, :cond_0

    goto :goto_1

    .line 30
    :cond_0
    sget-object p1, Lr6/e;->u:Lr6/c;

    if-ne p2, p1, :cond_1

    const/high16 p1, 0x3b800000    # 0.00390625f

    .line 31
    iput p1, p0, Lr6/e;->j:F

    goto :goto_2

    .line 32
    :cond_1
    sget-object p1, Lr6/e;->p:Lr6/c;

    if-eq p2, p1, :cond_3

    sget-object p1, Lr6/e;->q:Lr6/c;

    if-ne p2, p1, :cond_2

    goto :goto_0

    :cond_2
    const/high16 p1, 0x3f800000    # 1.0f

    .line 33
    iput p1, p0, Lr6/e;->j:F

    goto :goto_2

    :cond_3
    :goto_0
    const p1, 0x3b03126f    # 0.002f

    .line 34
    iput p1, p0, Lr6/e;->j:F

    goto :goto_2

    :cond_4
    :goto_1
    const p1, 0x3dcccccd    # 0.1f

    .line 35
    iput p1, p0, Lr6/e;->j:F

    :goto_2
    const/4 p1, 0x0

    .line 36
    iput-object p1, p0, Lr6/e;->m:Lr6/f;

    .line 37
    iput v0, p0, Lr6/e;->n:F

    .line 38
    iput-boolean v1, p0, Lr6/e;->o:Z

    return-void
.end method

.method public static b()Lr6/b;
    .locals 4

    .line 1
    sget-object v0, Lr6/b;->i:Ljava/lang/ThreadLocal;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    if-nez v1, :cond_0

    .line 8
    .line 9
    new-instance v1, Lr6/b;

    .line 10
    .line 11
    new-instance v2, Lb81/b;

    .line 12
    .line 13
    const/16 v3, 0x16

    .line 14
    .line 15
    invoke-direct {v2, v3}, Lb81/b;-><init>(I)V

    .line 16
    .line 17
    .line 18
    invoke-direct {v1, v2}, Lr6/b;-><init>(Lb81/b;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v0, v1}, Ljava/lang/ThreadLocal;->set(Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    :cond_0
    invoke-virtual {v0}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    check-cast v0, Lr6/b;

    .line 29
    .line 30
    return-object v0
.end method


# virtual methods
.method public final a(F)V
    .locals 5

    .line 1
    iget-boolean v0, p0, Lr6/e;->f:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iput p1, p0, Lr6/e;->n:F

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    iget-object v0, p0, Lr6/e;->m:Lr6/f;

    .line 9
    .line 10
    if-nez v0, :cond_1

    .line 11
    .line 12
    new-instance v0, Lr6/f;

    .line 13
    .line 14
    invoke-direct {v0, p1}, Lr6/f;-><init>(F)V

    .line 15
    .line 16
    .line 17
    iput-object v0, p0, Lr6/e;->m:Lr6/f;

    .line 18
    .line 19
    :cond_1
    iget-object v0, p0, Lr6/e;->m:Lr6/f;

    .line 20
    .line 21
    float-to-double v1, p1

    .line 22
    iput-wide v1, v0, Lr6/f;->i:D

    .line 23
    .line 24
    double-to-float p1, v1

    .line 25
    float-to-double v1, p1

    .line 26
    iget p1, p0, Lr6/e;->g:F

    .line 27
    .line 28
    float-to-double v3, p1

    .line 29
    cmpl-double p1, v1, v3

    .line 30
    .line 31
    if-gtz p1, :cond_9

    .line 32
    .line 33
    iget p1, p0, Lr6/e;->h:F

    .line 34
    .line 35
    float-to-double v3, p1

    .line 36
    cmpg-double p1, v1, v3

    .line 37
    .line 38
    if-ltz p1, :cond_8

    .line 39
    .line 40
    iget p1, p0, Lr6/e;->j:F

    .line 41
    .line 42
    const/high16 v1, 0x3f400000    # 0.75f

    .line 43
    .line 44
    mul-float/2addr p1, v1

    .line 45
    float-to-double v1, p1

    .line 46
    invoke-static {v1, v2}, Ljava/lang/Math;->abs(D)D

    .line 47
    .line 48
    .line 49
    move-result-wide v1

    .line 50
    iput-wide v1, v0, Lr6/f;->d:D

    .line 51
    .line 52
    const-wide v3, 0x404f400000000000L    # 62.5

    .line 53
    .line 54
    .line 55
    .line 56
    .line 57
    mul-double/2addr v1, v3

    .line 58
    iput-wide v1, v0, Lr6/f;->e:D

    .line 59
    .line 60
    invoke-static {}, Lr6/e;->b()Lr6/b;

    .line 61
    .line 62
    .line 63
    move-result-object p1

    .line 64
    iget-object p1, p1, Lr6/b;->e:Lb81/b;

    .line 65
    .line 66
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 67
    .line 68
    .line 69
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 70
    .line 71
    .line 72
    move-result-object v0

    .line 73
    iget-object p1, p1, Lb81/b;->f:Ljava/lang/Object;

    .line 74
    .line 75
    check-cast p1, Landroid/os/Looper;

    .line 76
    .line 77
    invoke-virtual {p1}, Landroid/os/Looper;->getThread()Ljava/lang/Thread;

    .line 78
    .line 79
    .line 80
    move-result-object p1

    .line 81
    if-ne v0, p1, :cond_7

    .line 82
    .line 83
    iget-boolean p1, p0, Lr6/e;->f:Z

    .line 84
    .line 85
    if-nez p1, :cond_6

    .line 86
    .line 87
    if-nez p1, :cond_6

    .line 88
    .line 89
    const/4 p1, 0x1

    .line 90
    iput-boolean p1, p0, Lr6/e;->f:Z

    .line 91
    .line 92
    iget-boolean p1, p0, Lr6/e;->c:Z

    .line 93
    .line 94
    if-nez p1, :cond_2

    .line 95
    .line 96
    iget-object p1, p0, Lr6/e;->e:Lkp/l;

    .line 97
    .line 98
    iget-object v0, p0, Lr6/e;->d:Lwq/v;

    .line 99
    .line 100
    invoke-virtual {p1, v0}, Lkp/l;->b(Lwq/v;)F

    .line 101
    .line 102
    .line 103
    move-result p1

    .line 104
    iput p1, p0, Lr6/e;->b:F

    .line 105
    .line 106
    :cond_2
    iget p1, p0, Lr6/e;->b:F

    .line 107
    .line 108
    iget v0, p0, Lr6/e;->g:F

    .line 109
    .line 110
    cmpl-float v0, p1, v0

    .line 111
    .line 112
    if-gtz v0, :cond_5

    .line 113
    .line 114
    iget v0, p0, Lr6/e;->h:F

    .line 115
    .line 116
    cmpg-float p1, p1, v0

    .line 117
    .line 118
    if-ltz p1, :cond_5

    .line 119
    .line 120
    invoke-static {}, Lr6/e;->b()Lr6/b;

    .line 121
    .line 122
    .line 123
    move-result-object p1

    .line 124
    iget-object v0, p1, Lr6/b;->b:Ljava/util/ArrayList;

    .line 125
    .line 126
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 127
    .line 128
    .line 129
    move-result v1

    .line 130
    if-nez v1, :cond_4

    .line 131
    .line 132
    iget-object v1, p1, Lr6/b;->e:Lb81/b;

    .line 133
    .line 134
    iget-object v2, p1, Lr6/b;->d:Lm8/o;

    .line 135
    .line 136
    iget-object v1, v1, Lb81/b;->e:Ljava/lang/Object;

    .line 137
    .line 138
    check-cast v1, Landroid/view/Choreographer;

    .line 139
    .line 140
    new-instance v3, Ll4/z;

    .line 141
    .line 142
    const/4 v4, 0x1

    .line 143
    invoke-direct {v3, v2, v4}, Ll4/z;-><init>(Ljava/lang/Runnable;I)V

    .line 144
    .line 145
    .line 146
    invoke-virtual {v1, v3}, Landroid/view/Choreographer;->postFrameCallback(Landroid/view/Choreographer$FrameCallback;)V

    .line 147
    .line 148
    .line 149
    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 150
    .line 151
    const/16 v2, 0x21

    .line 152
    .line 153
    if-lt v1, v2, :cond_4

    .line 154
    .line 155
    invoke-static {}, Li2/p0;->a()F

    .line 156
    .line 157
    .line 158
    move-result v1

    .line 159
    iput v1, p1, Lr6/b;->g:F

    .line 160
    .line 161
    iget-object v1, p1, Lr6/b;->h:Lb81/a;

    .line 162
    .line 163
    if-nez v1, :cond_3

    .line 164
    .line 165
    new-instance v1, Lb81/a;

    .line 166
    .line 167
    const/16 v2, 0x16

    .line 168
    .line 169
    invoke-direct {v1, p1, v2}, Lb81/a;-><init>(Ljava/lang/Object;I)V

    .line 170
    .line 171
    .line 172
    iput-object v1, p1, Lr6/b;->h:Lb81/a;

    .line 173
    .line 174
    :cond_3
    iget-object p1, p1, Lr6/b;->h:Lb81/a;

    .line 175
    .line 176
    iget-object v1, p1, Lb81/a;->e:Ljava/lang/Object;

    .line 177
    .line 178
    check-cast v1, Lr6/a;

    .line 179
    .line 180
    if-nez v1, :cond_4

    .line 181
    .line 182
    new-instance v1, Lr6/a;

    .line 183
    .line 184
    invoke-direct {v1, p1}, Lr6/a;-><init>(Lb81/a;)V

    .line 185
    .line 186
    .line 187
    iput-object v1, p1, Lb81/a;->e:Ljava/lang/Object;

    .line 188
    .line 189
    invoke-static {v1}, Li2/p0;->o(Lr6/a;)Z

    .line 190
    .line 191
    .line 192
    :cond_4
    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 193
    .line 194
    .line 195
    move-result p1

    .line 196
    if-nez p1, :cond_6

    .line 197
    .line 198
    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 199
    .line 200
    .line 201
    return-void

    .line 202
    :cond_5
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 203
    .line 204
    const-string p1, "Starting value need to be in between min value and max value"

    .line 205
    .line 206
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 207
    .line 208
    .line 209
    throw p0

    .line 210
    :cond_6
    return-void

    .line 211
    :cond_7
    new-instance p0, Landroid/util/AndroidRuntimeException;

    .line 212
    .line 213
    const-string p1, "Animations may only be started on the same thread as the animation handler"

    .line 214
    .line 215
    invoke-direct {p0, p1}, Landroid/util/AndroidRuntimeException;-><init>(Ljava/lang/String;)V

    .line 216
    .line 217
    .line 218
    throw p0

    .line 219
    :cond_8
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 220
    .line 221
    const-string p1, "Final position of the spring cannot be less than the min value."

    .line 222
    .line 223
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 224
    .line 225
    .line 226
    throw p0

    .line 227
    :cond_9
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 228
    .line 229
    const-string p1, "Final position of the spring cannot be greater than the max value."

    .line 230
    .line 231
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 232
    .line 233
    .line 234
    throw p0
.end method

.method public final c(F)V
    .locals 7

    .line 1
    iget-object v0, p0, Lr6/e;->e:Lkp/l;

    .line 2
    .line 3
    iget-object v1, p0, Lr6/e;->d:Lwq/v;

    .line 4
    .line 5
    invoke-virtual {v0, v1, p1}, Lkp/l;->c(Lwq/v;F)V

    .line 6
    .line 7
    .line 8
    const/4 p1, 0x0

    .line 9
    :goto_0
    iget-object v0, p0, Lr6/e;->l:Ljava/util/ArrayList;

    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-ge p1, v1, :cond_1

    .line 16
    .line 17
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    if-eqz v1, :cond_0

    .line 22
    .line 23
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    check-cast v0, Lbb/u;

    .line 28
    .line 29
    iget v1, p0, Lr6/e;->b:F

    .line 30
    .line 31
    iget-object v2, v0, Lbb/u;->g:Lbb/d0;

    .line 32
    .line 33
    iget-wide v3, v2, Lbb/x;->A:J

    .line 34
    .line 35
    const-wide/16 v5, 0x1

    .line 36
    .line 37
    add-long/2addr v3, v5

    .line 38
    float-to-double v5, v1

    .line 39
    invoke-static {v5, v6}, Ljava/lang/Math;->round(D)J

    .line 40
    .line 41
    .line 42
    move-result-wide v5

    .line 43
    invoke-static {v3, v4, v5, v6}, Ljava/lang/Math;->min(JJ)J

    .line 44
    .line 45
    .line 46
    move-result-wide v3

    .line 47
    const-wide/16 v5, -0x1

    .line 48
    .line 49
    invoke-static {v5, v6, v3, v4}, Ljava/lang/Math;->max(JJ)J

    .line 50
    .line 51
    .line 52
    move-result-wide v3

    .line 53
    iget-wide v5, v0, Lbb/u;->a:J

    .line 54
    .line 55
    invoke-virtual {v2, v3, v4, v5, v6}, Lbb/d0;->F(JJ)V

    .line 56
    .line 57
    .line 58
    iput-wide v3, v0, Lbb/u;->a:J

    .line 59
    .line 60
    :cond_0
    add-int/lit8 p1, p1, 0x1

    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_1
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 64
    .line 65
    .line 66
    move-result p0

    .line 67
    add-int/lit8 p0, p0, -0x1

    .line 68
    .line 69
    :goto_1
    if-ltz p0, :cond_3

    .line 70
    .line 71
    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object p1

    .line 75
    if-nez p1, :cond_2

    .line 76
    .line 77
    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    :cond_2
    add-int/lit8 p0, p0, -0x1

    .line 81
    .line 82
    goto :goto_1

    .line 83
    :cond_3
    return-void
.end method

.method public final d()V
    .locals 4

    .line 1
    iget-object v0, p0, Lr6/e;->m:Lr6/f;

    .line 2
    .line 3
    iget-wide v0, v0, Lr6/f;->b:D

    .line 4
    .line 5
    const-wide/16 v2, 0x0

    .line 6
    .line 7
    cmpl-double v0, v0, v2

    .line 8
    .line 9
    if-lez v0, :cond_2

    .line 10
    .line 11
    invoke-static {}, Lr6/e;->b()Lr6/b;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iget-object v0, v0, Lr6/b;->e:Lb81/b;

    .line 16
    .line 17
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 18
    .line 19
    .line 20
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    iget-object v0, v0, Lb81/b;->f:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast v0, Landroid/os/Looper;

    .line 27
    .line 28
    invoke-virtual {v0}, Landroid/os/Looper;->getThread()Ljava/lang/Thread;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    if-ne v1, v0, :cond_1

    .line 33
    .line 34
    iget-boolean v0, p0, Lr6/e;->f:Z

    .line 35
    .line 36
    if-eqz v0, :cond_0

    .line 37
    .line 38
    const/4 v0, 0x1

    .line 39
    iput-boolean v0, p0, Lr6/e;->o:Z

    .line 40
    .line 41
    :cond_0
    return-void

    .line 42
    :cond_1
    new-instance p0, Landroid/util/AndroidRuntimeException;

    .line 43
    .line 44
    const-string v0, "Animations may only be started on the same thread as the animation handler"

    .line 45
    .line 46
    invoke-direct {p0, v0}, Landroid/util/AndroidRuntimeException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p0

    .line 50
    :cond_2
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 51
    .line 52
    const-string v0, "Spring animations can only come to an end when there is damping"

    .line 53
    .line 54
    invoke-direct {p0, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw p0
.end method
