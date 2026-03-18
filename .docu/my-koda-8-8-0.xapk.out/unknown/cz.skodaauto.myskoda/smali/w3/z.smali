.class public final Lw3/z;
.super Ld6/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final Q:Landroidx/collection/a0;


# instance fields
.field public A:Z

.field public B:Lw3/w;

.field public C:Landroidx/collection/b0;

.field public final D:Landroidx/collection/c0;

.field public final E:Landroidx/collection/z;

.field public final F:Landroidx/collection/z;

.field public final G:Ljava/lang/String;

.field public final H:Ljava/lang/String;

.field public final I:Lil/g;

.field public final J:Landroidx/collection/b0;

.field public K:Lw3/a2;

.field public L:Z

.field public final M:Landroidx/collection/z;

.field public final N:Lm8/o;

.field public final O:Ljava/util/ArrayList;

.field public final P:Lw3/y;

.field public final d:Lw3/t;

.field public e:I

.field public final f:Lw3/y;

.field public final g:Landroid/view/accessibility/AccessibilityManager;

.field public h:J

.field public final i:Lw3/u;

.field public final j:Lw3/v;

.field public k:Ljava/util/List;

.field public final l:Landroid/os/Handler;

.field public final m:Lk6/a;

.field public n:I

.field public o:I

.field public p:Le6/d;

.field public q:Le6/d;

.field public r:Z

.field public final s:Landroidx/collection/b0;

.field public final t:Landroidx/collection/b0;

.field public final u:Landroidx/collection/b1;

.field public final v:Landroidx/collection/b1;

.field public w:I

.field public x:Ljava/lang/Integer;

.field public final y:Landroidx/collection/g;

.field public final z:Lxy0/j;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    .line 1
    const/16 v0, 0x20

    .line 2
    .line 3
    new-array v1, v0, [I

    .line 4
    .line 5
    fill-array-data v1, :array_0

    .line 6
    .line 7
    .line 8
    sget-object v2, Landroidx/collection/o;->a:Landroidx/collection/a0;

    .line 9
    .line 10
    new-instance v2, Landroidx/collection/a0;

    .line 11
    .line 12
    invoke-direct {v2, v0}, Landroidx/collection/a0;-><init>(I)V

    .line 13
    .line 14
    .line 15
    iget v3, v2, Landroidx/collection/a0;->b:I

    .line 16
    .line 17
    if-ltz v3, :cond_1

    .line 18
    .line 19
    add-int/lit8 v4, v3, 0x20

    .line 20
    .line 21
    invoke-virtual {v2, v4}, Landroidx/collection/a0;->b(I)V

    .line 22
    .line 23
    .line 24
    iget-object v5, v2, Landroidx/collection/a0;->a:[I

    .line 25
    .line 26
    iget v6, v2, Landroidx/collection/a0;->b:I

    .line 27
    .line 28
    if-eq v3, v6, :cond_0

    .line 29
    .line 30
    invoke-static {v4, v3, v6, v5, v5}, Lmx0/n;->h(III[I[I)V

    .line 31
    .line 32
    .line 33
    :cond_0
    const/4 v4, 0x0

    .line 34
    const/16 v6, 0xc

    .line 35
    .line 36
    invoke-static {v3, v4, v6, v1, v5}, Lmx0/n;->l(III[I[I)V

    .line 37
    .line 38
    .line 39
    iget v1, v2, Landroidx/collection/a0;->b:I

    .line 40
    .line 41
    add-int/2addr v1, v0

    .line 42
    iput v1, v2, Landroidx/collection/a0;->b:I

    .line 43
    .line 44
    sput-object v2, Lw3/z;->Q:Landroidx/collection/a0;

    .line 45
    .line 46
    return-void

    .line 47
    :cond_1
    const-string v0, ""

    .line 48
    .line 49
    invoke-static {v0}, La1/a;->d(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    const/4 v0, 0x0

    .line 53
    throw v0

    .line 54
    nop

    .line 55
    :array_0
    .array-data 4
        0x7f0a0010
        0x7f0a0011
        0x7f0a001c
        0x7f0a0027
        0x7f0a002a
        0x7f0a002b
        0x7f0a002c
        0x7f0a002d
        0x7f0a002e
        0x7f0a002f
        0x7f0a0012
        0x7f0a0013
        0x7f0a0014
        0x7f0a0015
        0x7f0a0016
        0x7f0a0017
        0x7f0a0018
        0x7f0a0019
        0x7f0a001a
        0x7f0a001b
        0x7f0a001d
        0x7f0a001e
        0x7f0a001f
        0x7f0a0020
        0x7f0a0021
        0x7f0a0022
        0x7f0a0023
        0x7f0a0024
        0x7f0a0025
        0x7f0a0026
        0x7f0a0028
        0x7f0a0029
    .end array-data
.end method

.method public constructor <init>(Lw3/t;)V
    .locals 5

    .line 1
    invoke-direct {p0}, Ld6/b;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lw3/z;->d:Lw3/t;

    .line 5
    .line 6
    const/high16 v0, -0x80000000

    .line 7
    .line 8
    iput v0, p0, Lw3/z;->e:I

    .line 9
    .line 10
    new-instance v1, Lw3/y;

    .line 11
    .line 12
    const/4 v2, 0x0

    .line 13
    invoke-direct {v1, p0, v2}, Lw3/y;-><init>(Lw3/z;I)V

    .line 14
    .line 15
    .line 16
    iput-object v1, p0, Lw3/z;->f:Lw3/y;

    .line 17
    .line 18
    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    const-string v3, "accessibility"

    .line 23
    .line 24
    invoke-virtual {v1, v3}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    const-string v3, "null cannot be cast to non-null type android.view.accessibility.AccessibilityManager"

    .line 29
    .line 30
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    check-cast v1, Landroid/view/accessibility/AccessibilityManager;

    .line 34
    .line 35
    iput-object v1, p0, Lw3/z;->g:Landroid/view/accessibility/AccessibilityManager;

    .line 36
    .line 37
    const-wide/16 v3, 0x64

    .line 38
    .line 39
    iput-wide v3, p0, Lw3/z;->h:J

    .line 40
    .line 41
    new-instance v3, Lw3/u;

    .line 42
    .line 43
    invoke-direct {v3, p0}, Lw3/u;-><init>(Lw3/z;)V

    .line 44
    .line 45
    .line 46
    iput-object v3, p0, Lw3/z;->i:Lw3/u;

    .line 47
    .line 48
    new-instance v3, Lw3/v;

    .line 49
    .line 50
    invoke-direct {v3, p0, v2}, Lw3/v;-><init>(Ljava/lang/Object;I)V

    .line 51
    .line 52
    .line 53
    iput-object v3, p0, Lw3/z;->j:Lw3/v;

    .line 54
    .line 55
    const/4 v3, -0x1

    .line 56
    invoke-virtual {v1, v3}, Landroid/view/accessibility/AccessibilityManager;->getEnabledAccessibilityServiceList(I)Ljava/util/List;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    iput-object v1, p0, Lw3/z;->k:Ljava/util/List;

    .line 61
    .line 62
    new-instance v1, Landroid/os/Handler;

    .line 63
    .line 64
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 65
    .line 66
    .line 67
    move-result-object v4

    .line 68
    invoke-direct {v1, v4}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 69
    .line 70
    .line 71
    iput-object v1, p0, Lw3/z;->l:Landroid/os/Handler;

    .line 72
    .line 73
    new-instance v1, Lk6/a;

    .line 74
    .line 75
    const/4 v4, 0x1

    .line 76
    invoke-direct {v1, p0, v4}, Lk6/a;-><init>(Ld6/b;I)V

    .line 77
    .line 78
    .line 79
    iput-object v1, p0, Lw3/z;->m:Lk6/a;

    .line 80
    .line 81
    iput v0, p0, Lw3/z;->n:I

    .line 82
    .line 83
    iput v0, p0, Lw3/z;->o:I

    .line 84
    .line 85
    new-instance v0, Landroidx/collection/b0;

    .line 86
    .line 87
    invoke-direct {v0}, Landroidx/collection/b0;-><init>()V

    .line 88
    .line 89
    .line 90
    iput-object v0, p0, Lw3/z;->s:Landroidx/collection/b0;

    .line 91
    .line 92
    new-instance v0, Landroidx/collection/b0;

    .line 93
    .line 94
    invoke-direct {v0}, Landroidx/collection/b0;-><init>()V

    .line 95
    .line 96
    .line 97
    iput-object v0, p0, Lw3/z;->t:Landroidx/collection/b0;

    .line 98
    .line 99
    new-instance v0, Landroidx/collection/b1;

    .line 100
    .line 101
    invoke-direct {v0, v2}, Landroidx/collection/b1;-><init>(I)V

    .line 102
    .line 103
    .line 104
    iput-object v0, p0, Lw3/z;->u:Landroidx/collection/b1;

    .line 105
    .line 106
    new-instance v0, Landroidx/collection/b1;

    .line 107
    .line 108
    invoke-direct {v0, v2}, Landroidx/collection/b1;-><init>(I)V

    .line 109
    .line 110
    .line 111
    iput-object v0, p0, Lw3/z;->v:Landroidx/collection/b1;

    .line 112
    .line 113
    iput v3, p0, Lw3/z;->w:I

    .line 114
    .line 115
    new-instance v0, Landroidx/collection/g;

    .line 116
    .line 117
    const/4 v1, 0x0

    .line 118
    invoke-direct {v0, v1}, Landroidx/collection/g;-><init>(Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    iput-object v0, p0, Lw3/z;->y:Landroidx/collection/g;

    .line 122
    .line 123
    const/4 v0, 0x6

    .line 124
    invoke-static {v4, v0, v1}, Llp/jf;->a(IILxy0/a;)Lxy0/j;

    .line 125
    .line 126
    .line 127
    move-result-object v0

    .line 128
    iput-object v0, p0, Lw3/z;->z:Lxy0/j;

    .line 129
    .line 130
    iput-boolean v4, p0, Lw3/z;->A:Z

    .line 131
    .line 132
    sget-object v0, Landroidx/collection/q;->a:Landroidx/collection/b0;

    .line 133
    .line 134
    const-string v1, "null cannot be cast to non-null type androidx.collection.IntObjectMap<V of androidx.collection.IntObjectMapKt.intObjectMapOf>"

    .line 135
    .line 136
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    iput-object v0, p0, Lw3/z;->C:Landroidx/collection/b0;

    .line 140
    .line 141
    new-instance v2, Landroidx/collection/c0;

    .line 142
    .line 143
    invoke-direct {v2}, Landroidx/collection/c0;-><init>()V

    .line 144
    .line 145
    .line 146
    iput-object v2, p0, Lw3/z;->D:Landroidx/collection/c0;

    .line 147
    .line 148
    new-instance v2, Landroidx/collection/z;

    .line 149
    .line 150
    invoke-direct {v2}, Landroidx/collection/z;-><init>()V

    .line 151
    .line 152
    .line 153
    iput-object v2, p0, Lw3/z;->E:Landroidx/collection/z;

    .line 154
    .line 155
    new-instance v2, Landroidx/collection/z;

    .line 156
    .line 157
    invoke-direct {v2}, Landroidx/collection/z;-><init>()V

    .line 158
    .line 159
    .line 160
    iput-object v2, p0, Lw3/z;->F:Landroidx/collection/z;

    .line 161
    .line 162
    const-string v2, "android.view.accessibility.extra.EXTRA_DATA_TEST_TRAVERSALBEFORE_VAL"

    .line 163
    .line 164
    iput-object v2, p0, Lw3/z;->G:Ljava/lang/String;

    .line 165
    .line 166
    const-string v2, "android.view.accessibility.extra.EXTRA_DATA_TEST_TRAVERSALAFTER_VAL"

    .line 167
    .line 168
    iput-object v2, p0, Lw3/z;->H:Ljava/lang/String;

    .line 169
    .line 170
    new-instance v2, Lil/g;

    .line 171
    .line 172
    const/16 v3, 0x15

    .line 173
    .line 174
    invoke-direct {v2, v3}, Lil/g;-><init>(I)V

    .line 175
    .line 176
    .line 177
    iput-object v2, p0, Lw3/z;->I:Lil/g;

    .line 178
    .line 179
    new-instance v2, Landroidx/collection/b0;

    .line 180
    .line 181
    invoke-direct {v2}, Landroidx/collection/b0;-><init>()V

    .line 182
    .line 183
    .line 184
    iput-object v2, p0, Lw3/z;->J:Landroidx/collection/b0;

    .line 185
    .line 186
    new-instance v2, Lw3/a2;

    .line 187
    .line 188
    invoke-virtual {p1}, Lw3/t;->getSemanticsOwner()Ld4/s;

    .line 189
    .line 190
    .line 191
    move-result-object v3

    .line 192
    invoke-virtual {v3}, Ld4/s;->a()Ld4/q;

    .line 193
    .line 194
    .line 195
    move-result-object v3

    .line 196
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 197
    .line 198
    .line 199
    invoke-direct {v2, v3, v0}, Lw3/a2;-><init>(Ld4/q;Landroidx/collection/p;)V

    .line 200
    .line 201
    .line 202
    iput-object v2, p0, Lw3/z;->K:Lw3/a2;

    .line 203
    .line 204
    sget v0, Landroidx/collection/m;->a:I

    .line 205
    .line 206
    new-instance v0, Landroidx/collection/z;

    .line 207
    .line 208
    invoke-direct {v0}, Landroidx/collection/z;-><init>()V

    .line 209
    .line 210
    .line 211
    iput-object v0, p0, Lw3/z;->M:Landroidx/collection/z;

    .line 212
    .line 213
    new-instance v0, Le3/d;

    .line 214
    .line 215
    const/4 v1, 0x5

    .line 216
    invoke-direct {v0, p0, v1}, Le3/d;-><init>(Ljava/lang/Object;I)V

    .line 217
    .line 218
    .line 219
    invoke-virtual {p1, v0}, Landroid/view/View;->addOnAttachStateChangeListener(Landroid/view/View$OnAttachStateChangeListener;)V

    .line 220
    .line 221
    .line 222
    new-instance p1, Lm8/o;

    .line 223
    .line 224
    const/16 v0, 0x17

    .line 225
    .line 226
    invoke-direct {p1, p0, v0}, Lm8/o;-><init>(Ljava/lang/Object;I)V

    .line 227
    .line 228
    .line 229
    iput-object p1, p0, Lw3/z;->N:Lm8/o;

    .line 230
    .line 231
    new-instance p1, Ljava/util/ArrayList;

    .line 232
    .line 233
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 234
    .line 235
    .line 236
    iput-object p1, p0, Lw3/z;->O:Ljava/util/ArrayList;

    .line 237
    .line 238
    new-instance p1, Lw3/y;

    .line 239
    .line 240
    invoke-direct {p1, p0, v4}, Lw3/y;-><init>(Lw3/z;I)V

    .line 241
    .line 242
    .line 243
    iput-object p1, p0, Lw3/z;->P:Lw3/y;

    .line 244
    .line 245
    return-void
.end method

.method public static synthetic E(Lw3/z;IILjava/lang/Integer;I)V
    .locals 1

    .line 1
    and-int/lit8 p4, p4, 0x4

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    if-eqz p4, :cond_0

    .line 5
    .line 6
    move-object p3, v0

    .line 7
    :cond_0
    invoke-virtual {p0, p1, p2, p3, v0}, Lw3/z;->D(IILjava/lang/Integer;Ljava/util/List;)Z

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public static M(Le3/g0;)Landroid/graphics/Rect;
    .locals 4

    .line 1
    instance-of v0, p0, Le3/e0;

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    instance-of v0, p0, Le3/f0;

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const/4 p0, 0x0

    .line 11
    return-object p0

    .line 12
    :cond_1
    :goto_0
    invoke-virtual {p0}, Le3/g0;->a()Ld3/c;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    new-instance v0, Landroid/graphics/Rect;

    .line 17
    .line 18
    iget v1, p0, Ld3/c;->a:F

    .line 19
    .line 20
    float-to-int v1, v1

    .line 21
    iget v2, p0, Ld3/c;->b:F

    .line 22
    .line 23
    float-to-int v2, v2

    .line 24
    iget v3, p0, Ld3/c;->c:F

    .line 25
    .line 26
    float-to-int v3, v3

    .line 27
    iget p0, p0, Ld3/c;->d:F

    .line 28
    .line 29
    float-to-int p0, p0

    .line 30
    invoke-direct {v0, v1, v2, v3, p0}, Landroid/graphics/Rect;-><init>(IIII)V

    .line 31
    .line 32
    .line 33
    return-object v0
.end method

.method public static N(Le3/g0;)[F
    .locals 13

    .line 1
    instance-of v0, p0, Le3/f0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p0, Le3/f0;

    .line 6
    .line 7
    iget-object p0, p0, Le3/f0;->a:Ld3/d;

    .line 8
    .line 9
    iget-wide v0, p0, Ld3/d;->h:J

    .line 10
    .line 11
    iget-wide v2, p0, Ld3/d;->g:J

    .line 12
    .line 13
    iget-wide v4, p0, Ld3/d;->f:J

    .line 14
    .line 15
    iget-wide v6, p0, Ld3/d;->e:J

    .line 16
    .line 17
    const/16 p0, 0x20

    .line 18
    .line 19
    shr-long v8, v6, p0

    .line 20
    .line 21
    long-to-int v8, v8

    .line 22
    invoke-static {v8}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 23
    .line 24
    .line 25
    move-result v8

    .line 26
    const-wide v9, 0xffffffffL

    .line 27
    .line 28
    .line 29
    .line 30
    .line 31
    and-long/2addr v6, v9

    .line 32
    long-to-int v6, v6

    .line 33
    invoke-static {v6}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 34
    .line 35
    .line 36
    move-result v6

    .line 37
    shr-long v11, v4, p0

    .line 38
    .line 39
    long-to-int v7, v11

    .line 40
    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 41
    .line 42
    .line 43
    move-result v7

    .line 44
    and-long/2addr v4, v9

    .line 45
    long-to-int v4, v4

    .line 46
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 47
    .line 48
    .line 49
    move-result v4

    .line 50
    shr-long v11, v2, p0

    .line 51
    .line 52
    long-to-int v5, v11

    .line 53
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 54
    .line 55
    .line 56
    move-result v5

    .line 57
    and-long/2addr v2, v9

    .line 58
    long-to-int v2, v2

    .line 59
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 60
    .line 61
    .line 62
    move-result v2

    .line 63
    shr-long v11, v0, p0

    .line 64
    .line 65
    long-to-int p0, v11

    .line 66
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 67
    .line 68
    .line 69
    move-result p0

    .line 70
    and-long/2addr v0, v9

    .line 71
    long-to-int v0, v0

    .line 72
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 73
    .line 74
    .line 75
    move-result v0

    .line 76
    const/16 v1, 0x8

    .line 77
    .line 78
    new-array v1, v1, [F

    .line 79
    .line 80
    const/4 v3, 0x0

    .line 81
    aput v8, v1, v3

    .line 82
    .line 83
    const/4 v3, 0x1

    .line 84
    aput v6, v1, v3

    .line 85
    .line 86
    const/4 v3, 0x2

    .line 87
    aput v7, v1, v3

    .line 88
    .line 89
    const/4 v3, 0x3

    .line 90
    aput v4, v1, v3

    .line 91
    .line 92
    const/4 v3, 0x4

    .line 93
    aput v5, v1, v3

    .line 94
    .line 95
    const/4 v3, 0x5

    .line 96
    aput v2, v1, v3

    .line 97
    .line 98
    const/4 v2, 0x6

    .line 99
    aput p0, v1, v2

    .line 100
    .line 101
    const/4 p0, 0x7

    .line 102
    aput v0, v1, p0

    .line 103
    .line 104
    return-object v1

    .line 105
    :cond_0
    const/4 p0, 0x0

    .line 106
    return-object p0
.end method

.method public static O(Le3/g0;)Landroid/graphics/Region;
    .locals 6

    .line 1
    instance-of v0, p0, Le3/d0;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    new-instance v0, Landroid/graphics/Region;

    .line 6
    .line 7
    check-cast p0, Le3/d0;

    .line 8
    .line 9
    invoke-virtual {p0}, Le3/d0;->a()Ld3/c;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    new-instance v2, Landroid/graphics/Rect;

    .line 14
    .line 15
    iget v3, v1, Ld3/c;->a:F

    .line 16
    .line 17
    float-to-int v3, v3

    .line 18
    iget v4, v1, Ld3/c;->b:F

    .line 19
    .line 20
    float-to-int v4, v4

    .line 21
    iget v5, v1, Ld3/c;->c:F

    .line 22
    .line 23
    float-to-int v5, v5

    .line 24
    iget v1, v1, Ld3/c;->d:F

    .line 25
    .line 26
    float-to-int v1, v1

    .line 27
    invoke-direct {v2, v3, v4, v5, v1}, Landroid/graphics/Rect;-><init>(IIII)V

    .line 28
    .line 29
    .line 30
    invoke-direct {v0, v2}, Landroid/graphics/Region;-><init>(Landroid/graphics/Rect;)V

    .line 31
    .line 32
    .line 33
    new-instance v1, Landroid/graphics/Region;

    .line 34
    .line 35
    invoke-direct {v1}, Landroid/graphics/Region;-><init>()V

    .line 36
    .line 37
    .line 38
    iget-object p0, p0, Le3/d0;->a:Le3/i;

    .line 39
    .line 40
    instance-of v2, p0, Le3/i;

    .line 41
    .line 42
    if-eqz v2, :cond_0

    .line 43
    .line 44
    iget-object p0, p0, Le3/i;->a:Landroid/graphics/Path;

    .line 45
    .line 46
    invoke-virtual {v1, p0, v0}, Landroid/graphics/Region;->setPath(Landroid/graphics/Path;Landroid/graphics/Region;)Z

    .line 47
    .line 48
    .line 49
    return-object v1

    .line 50
    :cond_0
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 51
    .line 52
    const-string v0, "Unable to obtain android.graphics.Path"

    .line 53
    .line 54
    invoke-direct {p0, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw p0

    .line 58
    :cond_1
    const/4 p0, 0x0

    .line 59
    return-object p0
.end method

.method public static P(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;
    .locals 3

    .line 1
    invoke-interface {p0}, Ljava/lang/CharSequence;->length()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    invoke-interface {p0}, Ljava/lang/CharSequence;->length()I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    const v1, 0x186a0

    .line 13
    .line 14
    .line 15
    if-gt v0, v1, :cond_1

    .line 16
    .line 17
    :goto_0
    return-object p0

    .line 18
    :cond_1
    const v0, 0x1869f

    .line 19
    .line 20
    .line 21
    invoke-interface {p0, v0}, Ljava/lang/CharSequence;->charAt(I)C

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    invoke-static {v2}, Ljava/lang/Character;->isHighSurrogate(C)Z

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    if-eqz v2, :cond_2

    .line 30
    .line 31
    invoke-interface {p0, v1}, Ljava/lang/CharSequence;->charAt(I)C

    .line 32
    .line 33
    .line 34
    move-result v2

    .line 35
    invoke-static {v2}, Ljava/lang/Character;->isLowSurrogate(C)Z

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    if-eqz v2, :cond_2

    .line 40
    .line 41
    move v1, v0

    .line 42
    :cond_2
    const/4 v0, 0x0

    .line 43
    invoke-interface {p0, v0, v1}, Ljava/lang/CharSequence;->subSequence(II)Ljava/lang/CharSequence;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    const-string v0, "null cannot be cast to non-null type T of androidx.compose.ui.platform.AndroidComposeViewAccessibilityDelegateCompat.trimToSize"

    .line 48
    .line 49
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    return-object p0
.end method

.method public static u(Ld4/q;)Ljava/lang/String;
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    if-nez p0, :cond_0

    .line 3
    .line 4
    goto :goto_0

    .line 5
    :cond_0
    iget-object p0, p0, Ld4/q;->d:Ld4/l;

    .line 6
    .line 7
    iget-object v1, p0, Ld4/l;->d:Landroidx/collection/q0;

    .line 8
    .line 9
    sget-object v2, Ld4/v;->a:Ld4/z;

    .line 10
    .line 11
    invoke-virtual {v1, v2}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v3

    .line 15
    if-eqz v3, :cond_1

    .line 16
    .line 17
    invoke-virtual {p0, v2}, Ld4/l;->e(Ld4/z;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    check-cast p0, Ljava/util/List;

    .line 22
    .line 23
    const-string v1, ","

    .line 24
    .line 25
    const/16 v2, 0x3e

    .line 26
    .line 27
    invoke-static {p0, v1, v0, v2}, Lv4/a;->a(Ljava/util/List;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0

    .line 32
    :cond_1
    sget-object p0, Ld4/v;->E:Ld4/z;

    .line 33
    .line 34
    invoke-virtual {v1, p0}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v2

    .line 38
    if-eqz v2, :cond_3

    .line 39
    .line 40
    invoke-virtual {v1, p0}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    if-nez p0, :cond_2

    .line 45
    .line 46
    move-object p0, v0

    .line 47
    :cond_2
    check-cast p0, Lg4/g;

    .line 48
    .line 49
    if-eqz p0, :cond_5

    .line 50
    .line 51
    iget-object p0, p0, Lg4/g;->e:Ljava/lang/String;

    .line 52
    .line 53
    return-object p0

    .line 54
    :cond_3
    sget-object p0, Ld4/v;->A:Ld4/z;

    .line 55
    .line 56
    invoke-virtual {v1, p0}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    if-nez p0, :cond_4

    .line 61
    .line 62
    move-object p0, v0

    .line 63
    :cond_4
    check-cast p0, Ljava/util/List;

    .line 64
    .line 65
    if-eqz p0, :cond_5

    .line 66
    .line 67
    invoke-static {p0}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    check-cast p0, Lg4/g;

    .line 72
    .line 73
    if-eqz p0, :cond_5

    .line 74
    .line 75
    iget-object p0, p0, Lg4/g;->e:Ljava/lang/String;

    .line 76
    .line 77
    return-object p0

    .line 78
    :cond_5
    :goto_0
    return-object v0
.end method

.method public static final x(Ld4/j;F)Z
    .locals 3

    .line 1
    iget-object v0, p0, Ld4/j;->a:Lay0/a;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    cmpg-float v2, p1, v1

    .line 5
    .line 6
    if-gez v2, :cond_0

    .line 7
    .line 8
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v2

    .line 12
    check-cast v2, Ljava/lang/Number;

    .line 13
    .line 14
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    cmpl-float v2, v2, v1

    .line 19
    .line 20
    if-gtz v2, :cond_1

    .line 21
    .line 22
    :cond_0
    cmpl-float p1, p1, v1

    .line 23
    .line 24
    if-lez p1, :cond_2

    .line 25
    .line 26
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    check-cast p1, Ljava/lang/Number;

    .line 31
    .line 32
    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    .line 33
    .line 34
    .line 35
    move-result p1

    .line 36
    iget-object p0, p0, Ld4/j;->b:Lay0/a;

    .line 37
    .line 38
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    check-cast p0, Ljava/lang/Number;

    .line 43
    .line 44
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 45
    .line 46
    .line 47
    move-result p0

    .line 48
    cmpg-float p0, p1, p0

    .line 49
    .line 50
    if-gez p0, :cond_2

    .line 51
    .line 52
    :cond_1
    const/4 p0, 0x1

    .line 53
    return p0

    .line 54
    :cond_2
    const/4 p0, 0x0

    .line 55
    return p0
.end method

.method public static final y(Ld4/j;)Z
    .locals 4

    .line 1
    iget-object v0, p0, Ld4/j;->a:Lay0/a;

    .line 2
    .line 3
    iget-boolean v1, p0, Ld4/j;->c:Z

    .line 4
    .line 5
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v2

    .line 9
    check-cast v2, Ljava/lang/Number;

    .line 10
    .line 11
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    const/4 v3, 0x0

    .line 16
    cmpl-float v2, v2, v3

    .line 17
    .line 18
    if-lez v2, :cond_0

    .line 19
    .line 20
    if-eqz v1, :cond_1

    .line 21
    .line 22
    :cond_0
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    check-cast v0, Ljava/lang/Number;

    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    iget-object p0, p0, Ld4/j;->b:Lay0/a;

    .line 33
    .line 34
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    check-cast p0, Ljava/lang/Number;

    .line 39
    .line 40
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    cmpg-float p0, v0, p0

    .line 45
    .line 46
    if-gez p0, :cond_2

    .line 47
    .line 48
    if-eqz v1, :cond_2

    .line 49
    .line 50
    :cond_1
    const/4 p0, 0x1

    .line 51
    return p0

    .line 52
    :cond_2
    const/4 p0, 0x0

    .line 53
    return p0
.end method

.method public static final z(Ld4/j;)Z
    .locals 3

    .line 1
    iget-object v0, p0, Ld4/j;->a:Lay0/a;

    .line 2
    .line 3
    iget-boolean v1, p0, Ld4/j;->c:Z

    .line 4
    .line 5
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v2

    .line 9
    check-cast v2, Ljava/lang/Number;

    .line 10
    .line 11
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    iget-object p0, p0, Ld4/j;->b:Lay0/a;

    .line 16
    .line 17
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    check-cast p0, Ljava/lang/Number;

    .line 22
    .line 23
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    cmpg-float p0, v2, p0

    .line 28
    .line 29
    if-gez p0, :cond_0

    .line 30
    .line 31
    if-eqz v1, :cond_1

    .line 32
    .line 33
    :cond_0
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    check-cast p0, Ljava/lang/Number;

    .line 38
    .line 39
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    const/4 v0, 0x0

    .line 44
    cmpl-float p0, p0, v0

    .line 45
    .line 46
    if-lez p0, :cond_2

    .line 47
    .line 48
    if-eqz v1, :cond_2

    .line 49
    .line 50
    :cond_1
    const/4 p0, 0x1

    .line 51
    return p0

    .line 52
    :cond_2
    const/4 p0, 0x0

    .line 53
    return p0
.end method


# virtual methods
.method public final A(I)I
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/z;->d:Lw3/t;

    .line 2
    .line 3
    invoke-virtual {p0}, Lw3/t;->getSemanticsOwner()Ld4/s;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-virtual {p0}, Ld4/s;->a()Ld4/q;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    iget p0, p0, Ld4/q;->g:I

    .line 12
    .line 13
    if-ne p1, p0, :cond_0

    .line 14
    .line 15
    const/4 p0, -0x1

    .line 16
    return p0

    .line 17
    :cond_0
    return p1
.end method

.method public final B(Ld4/q;Lw3/a2;)V
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
    sget-object v3, Landroidx/collection/r;->a:[I

    .line 8
    .line 9
    new-instance v3, Landroidx/collection/c0;

    .line 10
    .line 11
    invoke-direct {v3}, Landroidx/collection/c0;-><init>()V

    .line 12
    .line 13
    .line 14
    const/4 v4, 0x4

    .line 15
    invoke-static {v4, v1}, Ld4/q;->j(ILd4/q;)Ljava/util/List;

    .line 16
    .line 17
    .line 18
    move-result-object v5

    .line 19
    iget-object v6, v1, Ld4/q;->c:Lv3/h0;

    .line 20
    .line 21
    move-object v7, v5

    .line 22
    check-cast v7, Ljava/util/Collection;

    .line 23
    .line 24
    invoke-interface {v7}, Ljava/util/Collection;->size()I

    .line 25
    .line 26
    .line 27
    move-result v7

    .line 28
    const/4 v8, 0x0

    .line 29
    move v9, v8

    .line 30
    :goto_0
    if-ge v9, v7, :cond_2

    .line 31
    .line 32
    invoke-interface {v5, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v10

    .line 36
    check-cast v10, Ld4/q;

    .line 37
    .line 38
    invoke-virtual {v0}, Lw3/z;->t()Landroidx/collection/p;

    .line 39
    .line 40
    .line 41
    move-result-object v11

    .line 42
    iget v10, v10, Ld4/q;->g:I

    .line 43
    .line 44
    invoke-virtual {v11, v10}, Landroidx/collection/p;->a(I)Z

    .line 45
    .line 46
    .line 47
    move-result v11

    .line 48
    if-eqz v11, :cond_1

    .line 49
    .line 50
    iget-object v11, v2, Lw3/a2;->b:Landroidx/collection/c0;

    .line 51
    .line 52
    invoke-virtual {v11, v10}, Landroidx/collection/c0;->b(I)Z

    .line 53
    .line 54
    .line 55
    move-result v11

    .line 56
    if-nez v11, :cond_0

    .line 57
    .line 58
    invoke-virtual {v0, v6}, Lw3/z;->w(Lv3/h0;)V

    .line 59
    .line 60
    .line 61
    return-void

    .line 62
    :cond_0
    invoke-virtual {v3, v10}, Landroidx/collection/c0;->a(I)Z

    .line 63
    .line 64
    .line 65
    :cond_1
    add-int/lit8 v9, v9, 0x1

    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_2
    iget-object v2, v2, Lw3/a2;->b:Landroidx/collection/c0;

    .line 69
    .line 70
    iget-object v5, v2, Landroidx/collection/c0;->b:[I

    .line 71
    .line 72
    iget-object v2, v2, Landroidx/collection/c0;->a:[J

    .line 73
    .line 74
    array-length v7, v2

    .line 75
    add-int/lit8 v7, v7, -0x2

    .line 76
    .line 77
    if-ltz v7, :cond_6

    .line 78
    .line 79
    move v9, v8

    .line 80
    :goto_1
    aget-wide v10, v2, v9

    .line 81
    .line 82
    not-long v12, v10

    .line 83
    const/4 v14, 0x7

    .line 84
    shl-long/2addr v12, v14

    .line 85
    and-long/2addr v12, v10

    .line 86
    const-wide v14, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 87
    .line 88
    .line 89
    .line 90
    .line 91
    and-long/2addr v12, v14

    .line 92
    cmp-long v12, v12, v14

    .line 93
    .line 94
    if-eqz v12, :cond_5

    .line 95
    .line 96
    sub-int v12, v9, v7

    .line 97
    .line 98
    not-int v12, v12

    .line 99
    ushr-int/lit8 v12, v12, 0x1f

    .line 100
    .line 101
    const/16 v13, 0x8

    .line 102
    .line 103
    rsub-int/lit8 v12, v12, 0x8

    .line 104
    .line 105
    move v14, v8

    .line 106
    :goto_2
    if-ge v14, v12, :cond_4

    .line 107
    .line 108
    const-wide/16 v15, 0xff

    .line 109
    .line 110
    and-long/2addr v15, v10

    .line 111
    const-wide/16 v17, 0x80

    .line 112
    .line 113
    cmp-long v15, v15, v17

    .line 114
    .line 115
    if-gez v15, :cond_3

    .line 116
    .line 117
    shl-int/lit8 v15, v9, 0x3

    .line 118
    .line 119
    add-int/2addr v15, v14

    .line 120
    aget v15, v5, v15

    .line 121
    .line 122
    invoke-virtual {v3, v15}, Landroidx/collection/c0;->b(I)Z

    .line 123
    .line 124
    .line 125
    move-result v15

    .line 126
    if-nez v15, :cond_3

    .line 127
    .line 128
    invoke-virtual {v0, v6}, Lw3/z;->w(Lv3/h0;)V

    .line 129
    .line 130
    .line 131
    return-void

    .line 132
    :cond_3
    shr-long/2addr v10, v13

    .line 133
    add-int/lit8 v14, v14, 0x1

    .line 134
    .line 135
    goto :goto_2

    .line 136
    :cond_4
    if-ne v12, v13, :cond_6

    .line 137
    .line 138
    :cond_5
    if-eq v9, v7, :cond_6

    .line 139
    .line 140
    add-int/lit8 v9, v9, 0x1

    .line 141
    .line 142
    goto :goto_1

    .line 143
    :cond_6
    invoke-static {v4, v1}, Ld4/q;->j(ILd4/q;)Ljava/util/List;

    .line 144
    .line 145
    .line 146
    move-result-object v1

    .line 147
    move-object v2, v1

    .line 148
    check-cast v2, Ljava/util/Collection;

    .line 149
    .line 150
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 151
    .line 152
    .line 153
    move-result v2

    .line 154
    :goto_3
    if-ge v8, v2, :cond_8

    .line 155
    .line 156
    invoke-interface {v1, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object v3

    .line 160
    check-cast v3, Ld4/q;

    .line 161
    .line 162
    iget-object v4, v0, Lw3/z;->J:Landroidx/collection/b0;

    .line 163
    .line 164
    iget v5, v3, Ld4/q;->g:I

    .line 165
    .line 166
    invoke-virtual {v4, v5}, Landroidx/collection/p;->b(I)Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    move-result-object v4

    .line 170
    check-cast v4, Lw3/a2;

    .line 171
    .line 172
    if-eqz v4, :cond_7

    .line 173
    .line 174
    invoke-virtual {v0}, Lw3/z;->t()Landroidx/collection/p;

    .line 175
    .line 176
    .line 177
    move-result-object v5

    .line 178
    iget v6, v3, Ld4/q;->g:I

    .line 179
    .line 180
    invoke-virtual {v5, v6}, Landroidx/collection/p;->a(I)Z

    .line 181
    .line 182
    .line 183
    move-result v5

    .line 184
    if-eqz v5, :cond_7

    .line 185
    .line 186
    invoke-virtual {v0, v3, v4}, Lw3/z;->B(Ld4/q;Lw3/a2;)V

    .line 187
    .line 188
    .line 189
    :cond_7
    add-int/lit8 v8, v8, 0x1

    .line 190
    .line 191
    goto :goto_3

    .line 192
    :cond_8
    return-void
.end method

.method public final C(Landroid/view/accessibility/AccessibilityEvent;)Z
    .locals 3

    .line 1
    invoke-virtual {p0}, Lw3/z;->v()Z

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
    invoke-virtual {p1}, Landroid/view/accessibility/AccessibilityEvent;->getEventType()I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    const/16 v2, 0x800

    .line 14
    .line 15
    if-eq v0, v2, :cond_1

    .line 16
    .line 17
    invoke-virtual {p1}, Landroid/view/accessibility/AccessibilityEvent;->getEventType()I

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    const v2, 0x8000

    .line 22
    .line 23
    .line 24
    if-ne v0, v2, :cond_2

    .line 25
    .line 26
    :cond_1
    const/4 v0, 0x1

    .line 27
    iput-boolean v0, p0, Lw3/z;->r:Z

    .line 28
    .line 29
    :cond_2
    :try_start_0
    iget-object v0, p0, Lw3/z;->f:Lw3/y;

    .line 30
    .line 31
    invoke-virtual {v0, p1}, Lw3/y;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    check-cast p1, Ljava/lang/Boolean;

    .line 36
    .line 37
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 38
    .line 39
    .line 40
    move-result p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 41
    iput-boolean v1, p0, Lw3/z;->r:Z

    .line 42
    .line 43
    return p1

    .line 44
    :catchall_0
    move-exception p1

    .line 45
    iput-boolean v1, p0, Lw3/z;->r:Z

    .line 46
    .line 47
    throw p1
.end method

.method public final D(IILjava/lang/Integer;Ljava/util/List;)Z
    .locals 1

    .line 1
    const/high16 v0, -0x80000000

    .line 2
    .line 3
    if-eq p1, v0, :cond_3

    .line 4
    .line 5
    invoke-virtual {p0}, Lw3/z;->v()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    invoke-virtual {p0, p1, p2}, Lw3/z;->o(II)Landroid/view/accessibility/AccessibilityEvent;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    if-eqz p3, :cond_1

    .line 17
    .line 18
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 19
    .line 20
    .line 21
    move-result p2

    .line 22
    invoke-virtual {p1, p2}, Landroid/view/accessibility/AccessibilityEvent;->setContentChangeTypes(I)V

    .line 23
    .line 24
    .line 25
    :cond_1
    if-eqz p4, :cond_2

    .line 26
    .line 27
    const/4 p2, 0x0

    .line 28
    const/16 p3, 0x3e

    .line 29
    .line 30
    const-string v0, ","

    .line 31
    .line 32
    invoke-static {p4, v0, p2, p3}, Lv4/a;->a(Ljava/util/List;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p2

    .line 36
    invoke-virtual {p1, p2}, Landroid/view/accessibility/AccessibilityRecord;->setContentDescription(Ljava/lang/CharSequence;)V

    .line 37
    .line 38
    .line 39
    :cond_2
    invoke-virtual {p0, p1}, Lw3/z;->C(Landroid/view/accessibility/AccessibilityEvent;)Z

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    return p0

    .line 44
    :cond_3
    :goto_0
    const/4 p0, 0x0

    .line 45
    return p0
.end method

.method public final F(IILjava/lang/String;)V
    .locals 1

    .line 1
    invoke-virtual {p0, p1}, Lw3/z;->A(I)I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    const/16 v0, 0x20

    .line 6
    .line 7
    invoke-virtual {p0, p1, v0}, Lw3/z;->o(II)Landroid/view/accessibility/AccessibilityEvent;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    invoke-virtual {p1, p2}, Landroid/view/accessibility/AccessibilityEvent;->setContentChangeTypes(I)V

    .line 12
    .line 13
    .line 14
    if-eqz p3, :cond_0

    .line 15
    .line 16
    invoke-virtual {p1}, Landroid/view/accessibility/AccessibilityRecord;->getText()Ljava/util/List;

    .line 17
    .line 18
    .line 19
    move-result-object p2

    .line 20
    invoke-interface {p2, p3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    :cond_0
    invoke-virtual {p0, p1}, Lw3/z;->C(Landroid/view/accessibility/AccessibilityEvent;)Z

    .line 24
    .line 25
    .line 26
    return-void
.end method

.method public final G(I)V
    .locals 6

    .line 1
    iget-object v0, p0, Lw3/z;->B:Lw3/w;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    iget-object v1, v0, Lw3/w;->a:Ld4/q;

    .line 6
    .line 7
    iget v2, v1, Ld4/q;->g:I

    .line 8
    .line 9
    if-eq p1, v2, :cond_0

    .line 10
    .line 11
    return-void

    .line 12
    :cond_0
    invoke-static {}, Landroid/os/SystemClock;->uptimeMillis()J

    .line 13
    .line 14
    .line 15
    move-result-wide v2

    .line 16
    iget-wide v4, v0, Lw3/w;->f:J

    .line 17
    .line 18
    sub-long/2addr v2, v4

    .line 19
    const-wide/16 v4, 0x3e8

    .line 20
    .line 21
    cmp-long p1, v2, v4

    .line 22
    .line 23
    if-gtz p1, :cond_1

    .line 24
    .line 25
    iget p1, v1, Ld4/q;->g:I

    .line 26
    .line 27
    invoke-virtual {p0, p1}, Lw3/z;->A(I)I

    .line 28
    .line 29
    .line 30
    move-result p1

    .line 31
    const/high16 v2, 0x20000

    .line 32
    .line 33
    invoke-virtual {p0, p1, v2}, Lw3/z;->o(II)Landroid/view/accessibility/AccessibilityEvent;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    iget v2, v0, Lw3/w;->d:I

    .line 38
    .line 39
    invoke-virtual {p1, v2}, Landroid/view/accessibility/AccessibilityRecord;->setFromIndex(I)V

    .line 40
    .line 41
    .line 42
    iget v2, v0, Lw3/w;->e:I

    .line 43
    .line 44
    invoke-virtual {p1, v2}, Landroid/view/accessibility/AccessibilityRecord;->setToIndex(I)V

    .line 45
    .line 46
    .line 47
    iget v2, v0, Lw3/w;->b:I

    .line 48
    .line 49
    invoke-virtual {p1, v2}, Landroid/view/accessibility/AccessibilityEvent;->setAction(I)V

    .line 50
    .line 51
    .line 52
    iget v0, v0, Lw3/w;->c:I

    .line 53
    .line 54
    invoke-virtual {p1, v0}, Landroid/view/accessibility/AccessibilityEvent;->setMovementGranularity(I)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {p1}, Landroid/view/accessibility/AccessibilityRecord;->getText()Ljava/util/List;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    invoke-static {v1}, Lw3/z;->u(Ld4/q;)Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object v1

    .line 65
    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    invoke-virtual {p0, p1}, Lw3/z;->C(Landroid/view/accessibility/AccessibilityEvent;)Z

    .line 69
    .line 70
    .line 71
    :cond_1
    const/4 p1, 0x0

    .line 72
    iput-object p1, p0, Lw3/z;->B:Lw3/w;

    .line 73
    .line 74
    return-void
.end method

.method public final H(Landroidx/collection/p;)V
    .locals 59

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v6, p1

    .line 4
    .line 5
    const/16 v1, 0x40

    .line 6
    .line 7
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 8
    .line 9
    .line 10
    move-result-object v7

    .line 11
    new-instance v8, Ljava/util/ArrayList;

    .line 12
    .line 13
    iget-object v9, v0, Lw3/z;->O:Ljava/util/ArrayList;

    .line 14
    .line 15
    invoke-direct {v8, v9}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {v9}, Ljava/util/ArrayList;->clear()V

    .line 19
    .line 20
    .line 21
    iget-object v10, v6, Landroidx/collection/p;->b:[I

    .line 22
    .line 23
    iget-object v11, v6, Landroidx/collection/p;->a:[J

    .line 24
    .line 25
    array-length v1, v11

    .line 26
    const/4 v12, 0x2

    .line 27
    add-int/lit8 v13, v1, -0x2

    .line 28
    .line 29
    const/4 v14, 0x0

    .line 30
    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    if-ltz v13, :cond_51

    .line 35
    .line 36
    move v15, v14

    .line 37
    :goto_0
    aget-wide v3, v11, v15

    .line 38
    .line 39
    move/from16 v16, v12

    .line 40
    .line 41
    move/from16 v17, v13

    .line 42
    .line 43
    not-long v12, v3

    .line 44
    const/16 v18, 0x7

    .line 45
    .line 46
    shl-long v12, v12, v18

    .line 47
    .line 48
    and-long/2addr v12, v3

    .line 49
    const-wide v19, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 50
    .line 51
    .line 52
    .line 53
    .line 54
    and-long v12, v12, v19

    .line 55
    .line 56
    cmp-long v1, v12, v19

    .line 57
    .line 58
    if-eqz v1, :cond_50

    .line 59
    .line 60
    sub-int v1, v15, v17

    .line 61
    .line 62
    not-int v1, v1

    .line 63
    ushr-int/lit8 v1, v1, 0x1f

    .line 64
    .line 65
    const/16 v12, 0x8

    .line 66
    .line 67
    rsub-int/lit8 v13, v1, 0x8

    .line 68
    .line 69
    move-wide/from16 v21, v3

    .line 70
    .line 71
    move v1, v14

    .line 72
    :goto_1
    if-ge v1, v13, :cond_4f

    .line 73
    .line 74
    const-wide/16 v23, 0xff

    .line 75
    .line 76
    and-long v3, v21, v23

    .line 77
    .line 78
    const-wide/16 v25, 0x80

    .line 79
    .line 80
    cmp-long v3, v3, v25

    .line 81
    .line 82
    if-gez v3, :cond_4e

    .line 83
    .line 84
    shl-int/lit8 v3, v15, 0x3

    .line 85
    .line 86
    add-int/2addr v3, v1

    .line 87
    aget v3, v10, v3

    .line 88
    .line 89
    iget-object v4, v0, Lw3/z;->J:Landroidx/collection/b0;

    .line 90
    .line 91
    invoke-virtual {v4, v3}, Landroidx/collection/p;->b(I)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v4

    .line 95
    check-cast v4, Lw3/a2;

    .line 96
    .line 97
    if-nez v4, :cond_0

    .line 98
    .line 99
    goto/16 :goto_29

    .line 100
    .line 101
    :cond_0
    iget-object v4, v4, Lw3/a2;->a:Ld4/l;

    .line 102
    .line 103
    iget-object v5, v4, Ld4/l;->d:Landroidx/collection/q0;

    .line 104
    .line 105
    invoke-virtual {v6, v3}, Landroidx/collection/p;->b(I)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v27

    .line 109
    move-object/from16 v14, v27

    .line 110
    .line 111
    check-cast v14, Ld4/r;

    .line 112
    .line 113
    move/from16 v27, v12

    .line 114
    .line 115
    if-eqz v14, :cond_1

    .line 116
    .line 117
    iget-object v14, v14, Ld4/r;->a:Ld4/q;

    .line 118
    .line 119
    goto :goto_2

    .line 120
    :cond_1
    const/4 v14, 0x0

    .line 121
    :goto_2
    if-eqz v14, :cond_4d

    .line 122
    .line 123
    iget-object v12, v14, Ld4/q;->c:Lv3/h0;

    .line 124
    .line 125
    iget-object v6, v14, Ld4/q;->d:Ld4/l;

    .line 126
    .line 127
    move-object/from16 v29, v10

    .line 128
    .line 129
    iget v10, v14, Ld4/q;->g:I

    .line 130
    .line 131
    move-object/from16 v30, v11

    .line 132
    .line 133
    iget-object v11, v6, Ld4/l;->d:Landroidx/collection/q0;

    .line 134
    .line 135
    move/from16 v31, v15

    .line 136
    .line 137
    iget-object v15, v11, Landroidx/collection/q0;->b:[Ljava/lang/Object;

    .line 138
    .line 139
    move-object/from16 v32, v15

    .line 140
    .line 141
    iget-object v15, v11, Landroidx/collection/q0;->c:[Ljava/lang/Object;

    .line 142
    .line 143
    move-object/from16 v33, v15

    .line 144
    .line 145
    iget-object v15, v11, Landroidx/collection/q0;->a:[J

    .line 146
    .line 147
    move/from16 v34, v1

    .line 148
    .line 149
    array-length v1, v15

    .line 150
    add-int/lit8 v1, v1, -0x2

    .line 151
    .line 152
    move-object/from16 v35, v15

    .line 153
    .line 154
    if-ltz v1, :cond_47

    .line 155
    .line 156
    move-object/from16 v40, v12

    .line 157
    .line 158
    move/from16 v39, v13

    .line 159
    .line 160
    const/4 v15, 0x0

    .line 161
    const/16 v38, 0x0

    .line 162
    .line 163
    :goto_3
    aget-wide v12, v35, v15

    .line 164
    .line 165
    move-object/from16 v41, v14

    .line 166
    .line 167
    move/from16 v42, v15

    .line 168
    .line 169
    not-long v14, v12

    .line 170
    shl-long v14, v14, v18

    .line 171
    .line 172
    and-long/2addr v14, v12

    .line 173
    and-long v14, v14, v19

    .line 174
    .line 175
    cmp-long v14, v14, v19

    .line 176
    .line 177
    if-eqz v14, :cond_46

    .line 178
    .line 179
    sub-int v15, v42, v1

    .line 180
    .line 181
    not-int v14, v15

    .line 182
    ushr-int/lit8 v14, v14, 0x1f

    .line 183
    .line 184
    rsub-int/lit8 v14, v14, 0x8

    .line 185
    .line 186
    const/4 v15, 0x0

    .line 187
    :goto_4
    if-ge v15, v14, :cond_45

    .line 188
    .line 189
    and-long v43, v12, v23

    .line 190
    .line 191
    cmp-long v43, v43, v25

    .line 192
    .line 193
    if-gez v43, :cond_44

    .line 194
    .line 195
    shl-int/lit8 v43, v42, 0x3

    .line 196
    .line 197
    add-int v43, v43, v15

    .line 198
    .line 199
    aget-object v44, v32, v43

    .line 200
    .line 201
    move/from16 v45, v1

    .line 202
    .line 203
    aget-object v1, v33, v43

    .line 204
    .line 205
    move-object/from16 v43, v4

    .line 206
    .line 207
    move-object/from16 v4, v44

    .line 208
    .line 209
    check-cast v4, Ld4/z;

    .line 210
    .line 211
    move-wide/from16 v46, v12

    .line 212
    .line 213
    sget-object v12, Ld4/v;->t:Ld4/z;

    .line 214
    .line 215
    invoke-static {v4, v12}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 216
    .line 217
    .line 218
    move-result v13

    .line 219
    if-nez v13, :cond_3

    .line 220
    .line 221
    sget-object v13, Ld4/v;->u:Ld4/z;

    .line 222
    .line 223
    invoke-static {v4, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 224
    .line 225
    .line 226
    move-result v13

    .line 227
    if-eqz v13, :cond_2

    .line 228
    .line 229
    goto :goto_5

    .line 230
    :cond_2
    const/16 v44, 0x0

    .line 231
    .line 232
    goto :goto_7

    .line 233
    :cond_3
    :goto_5
    invoke-static {v8, v3}, Lw3/h0;->p(Ljava/util/ArrayList;I)Lw3/z1;

    .line 234
    .line 235
    .line 236
    move-result-object v13

    .line 237
    if-eqz v13, :cond_4

    .line 238
    .line 239
    const/16 v44, 0x0

    .line 240
    .line 241
    goto :goto_6

    .line 242
    :cond_4
    new-instance v13, Lw3/z1;

    .line 243
    .line 244
    invoke-direct {v13, v9, v3}, Lw3/z1;-><init>(Ljava/util/ArrayList;I)V

    .line 245
    .line 246
    .line 247
    const/16 v44, 0x1

    .line 248
    .line 249
    :goto_6
    invoke-virtual {v9, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 250
    .line 251
    .line 252
    :goto_7
    if-nez v44, :cond_6

    .line 253
    .line 254
    invoke-virtual {v5, v4}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 255
    .line 256
    .line 257
    move-result-object v13

    .line 258
    if-nez v13, :cond_5

    .line 259
    .line 260
    const/4 v13, 0x0

    .line 261
    :cond_5
    invoke-static {v1, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 262
    .line 263
    .line 264
    move-result v13

    .line 265
    if-eqz v13, :cond_6

    .line 266
    .line 267
    move-object v13, v2

    .line 268
    move-object v2, v5

    .line 269
    move-object/from16 v44, v6

    .line 270
    .line 271
    move-object/from16 v48, v8

    .line 272
    .line 273
    move/from16 v28, v15

    .line 274
    .line 275
    move/from16 v12, v27

    .line 276
    .line 277
    goto/16 :goto_9

    .line 278
    .line 279
    :cond_6
    sget-object v13, Ld4/v;->d:Ld4/z;

    .line 280
    .line 281
    invoke-static {v4, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 282
    .line 283
    .line 284
    move-result v44

    .line 285
    if-eqz v44, :cond_8

    .line 286
    .line 287
    const-string v4, "null cannot be cast to non-null type kotlin.String"

    .line 288
    .line 289
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 290
    .line 291
    .line 292
    check-cast v1, Ljava/lang/String;

    .line 293
    .line 294
    invoke-virtual {v5, v13}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 295
    .line 296
    .line 297
    move-result v4

    .line 298
    if-eqz v4, :cond_7

    .line 299
    .line 300
    move/from16 v4, v27

    .line 301
    .line 302
    invoke-virtual {v0, v3, v4, v1}, Lw3/z;->F(IILjava/lang/String;)V

    .line 303
    .line 304
    .line 305
    :cond_7
    move-object v13, v2

    .line 306
    move-object v2, v5

    .line 307
    move-object/from16 v44, v6

    .line 308
    .line 309
    move-object/from16 v48, v8

    .line 310
    .line 311
    move/from16 v28, v15

    .line 312
    .line 313
    move-object/from16 v8, v40

    .line 314
    .line 315
    const/16 v12, 0x8

    .line 316
    .line 317
    :goto_8
    move v15, v3

    .line 318
    move/from16 v3, v45

    .line 319
    .line 320
    goto/16 :goto_25

    .line 321
    .line 322
    :cond_8
    sget-object v13, Ld4/v;->b:Ld4/z;

    .line 323
    .line 324
    invoke-static {v4, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 325
    .line 326
    .line 327
    move-result v13

    .line 328
    if-nez v13, :cond_9

    .line 329
    .line 330
    sget-object v13, Ld4/v;->I:Ld4/z;

    .line 331
    .line 332
    invoke-static {v4, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 333
    .line 334
    .line 335
    move-result v13

    .line 336
    if-eqz v13, :cond_a

    .line 337
    .line 338
    :cond_9
    move-object v13, v2

    .line 339
    move-object v2, v5

    .line 340
    move-object/from16 v44, v6

    .line 341
    .line 342
    move-object/from16 v48, v8

    .line 343
    .line 344
    move/from16 v28, v15

    .line 345
    .line 346
    move-object/from16 v8, v40

    .line 347
    .line 348
    move v15, v3

    .line 349
    move/from16 v3, v45

    .line 350
    .line 351
    goto/16 :goto_24

    .line 352
    .line 353
    :cond_a
    sget-object v13, Ld4/v;->c:Ld4/z;

    .line 354
    .line 355
    invoke-static {v4, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 356
    .line 357
    .line 358
    move-result v13

    .line 359
    if-eqz v13, :cond_b

    .line 360
    .line 361
    invoke-virtual {v0, v3}, Lw3/z;->A(I)I

    .line 362
    .line 363
    .line 364
    move-result v1

    .line 365
    const/16 v4, 0x800

    .line 366
    .line 367
    const/16 v12, 0x8

    .line 368
    .line 369
    invoke-static {v0, v1, v4, v7, v12}, Lw3/z;->E(Lw3/z;IILjava/lang/Integer;I)V

    .line 370
    .line 371
    .line 372
    invoke-virtual {v0, v3}, Lw3/z;->A(I)I

    .line 373
    .line 374
    .line 375
    move-result v1

    .line 376
    invoke-static {v0, v1, v4, v2, v12}, Lw3/z;->E(Lw3/z;IILjava/lang/Integer;I)V

    .line 377
    .line 378
    .line 379
    move-object v13, v2

    .line 380
    move-object v2, v5

    .line 381
    move-object/from16 v44, v6

    .line 382
    .line 383
    move-object/from16 v48, v8

    .line 384
    .line 385
    move/from16 v28, v15

    .line 386
    .line 387
    :goto_9
    move-object/from16 v8, v40

    .line 388
    .line 389
    goto :goto_8

    .line 390
    :cond_b
    sget-object v13, Ld4/v;->H:Ld4/z;

    .line 391
    .line 392
    invoke-static {v4, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 393
    .line 394
    .line 395
    move-result v44

    .line 396
    move-object/from16 v48, v8

    .line 397
    .line 398
    const/4 v8, 0x4

    .line 399
    if-eqz v44, :cond_18

    .line 400
    .line 401
    sget-object v1, Ld4/v;->x:Ld4/z;

    .line 402
    .line 403
    invoke-virtual {v11, v1}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 404
    .line 405
    .line 406
    move-result-object v1

    .line 407
    if-nez v1, :cond_c

    .line 408
    .line 409
    const/4 v1, 0x0

    .line 410
    :cond_c
    check-cast v1, Ld4/i;

    .line 411
    .line 412
    if-nez v1, :cond_e

    .line 413
    .line 414
    :cond_d
    const/4 v1, 0x0

    .line 415
    goto :goto_a

    .line 416
    :cond_e
    iget v1, v1, Ld4/i;->a:I

    .line 417
    .line 418
    if-ne v1, v8, :cond_d

    .line 419
    .line 420
    const/4 v1, 0x1

    .line 421
    :goto_a
    if-eqz v1, :cond_17

    .line 422
    .line 423
    invoke-virtual {v11, v13}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 424
    .line 425
    .line 426
    move-result-object v1

    .line 427
    if-nez v1, :cond_f

    .line 428
    .line 429
    const/4 v1, 0x0

    .line 430
    :cond_f
    sget-object v4, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 431
    .line 432
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 433
    .line 434
    .line 435
    move-result v1

    .line 436
    if-eqz v1, :cond_16

    .line 437
    .line 438
    invoke-virtual {v0, v3}, Lw3/z;->A(I)I

    .line 439
    .line 440
    .line 441
    move-result v1

    .line 442
    invoke-virtual {v0, v1, v8}, Lw3/z;->o(II)Landroid/view/accessibility/AccessibilityEvent;

    .line 443
    .line 444
    .line 445
    move-result-object v1

    .line 446
    new-instance v4, Ld4/q;

    .line 447
    .line 448
    move-object/from16 v13, v41

    .line 449
    .line 450
    iget-object v8, v13, Ld4/q;->a:Lx2/r;

    .line 451
    .line 452
    move-object/from16 v12, v40

    .line 453
    .line 454
    const/4 v13, 0x1

    .line 455
    invoke-direct {v4, v8, v13, v12, v6}, Ld4/q;-><init>(Lx2/r;ZLv3/h0;Ld4/l;)V

    .line 456
    .line 457
    .line 458
    invoke-virtual {v4}, Ld4/q;->k()Ld4/l;

    .line 459
    .line 460
    .line 461
    move-result-object v8

    .line 462
    sget-object v13, Ld4/v;->a:Ld4/z;

    .line 463
    .line 464
    iget-object v8, v8, Ld4/l;->d:Landroidx/collection/q0;

    .line 465
    .line 466
    invoke-virtual {v8, v13}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 467
    .line 468
    .line 469
    move-result-object v8

    .line 470
    if-nez v8, :cond_10

    .line 471
    .line 472
    const/4 v8, 0x0

    .line 473
    :cond_10
    check-cast v8, Ljava/util/List;

    .line 474
    .line 475
    const/16 v13, 0x3e

    .line 476
    .line 477
    move-object/from16 v40, v4

    .line 478
    .line 479
    const-string v4, ","

    .line 480
    .line 481
    move-object/from16 v44, v12

    .line 482
    .line 483
    const/4 v12, 0x0

    .line 484
    if-eqz v8, :cond_11

    .line 485
    .line 486
    invoke-static {v8, v4, v12, v13}, Lv4/a;->a(Ljava/util/List;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 487
    .line 488
    .line 489
    move-result-object v8

    .line 490
    move-object v12, v8

    .line 491
    :cond_11
    invoke-virtual/range {v40 .. v40}, Ld4/q;->k()Ld4/l;

    .line 492
    .line 493
    .line 494
    move-result-object v8

    .line 495
    sget-object v13, Ld4/v;->A:Ld4/z;

    .line 496
    .line 497
    iget-object v8, v8, Ld4/l;->d:Landroidx/collection/q0;

    .line 498
    .line 499
    invoke-virtual {v8, v13}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 500
    .line 501
    .line 502
    move-result-object v8

    .line 503
    if-nez v8, :cond_12

    .line 504
    .line 505
    const/4 v8, 0x0

    .line 506
    :cond_12
    check-cast v8, Ljava/util/List;

    .line 507
    .line 508
    move/from16 v28, v15

    .line 509
    .line 510
    const/4 v13, 0x0

    .line 511
    if-eqz v8, :cond_13

    .line 512
    .line 513
    const/16 v15, 0x3e

    .line 514
    .line 515
    invoke-static {v8, v4, v13, v15}, Lv4/a;->a(Ljava/util/List;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 516
    .line 517
    .line 518
    move-result-object v4

    .line 519
    goto :goto_b

    .line 520
    :cond_13
    move-object v4, v13

    .line 521
    :goto_b
    if-eqz v12, :cond_14

    .line 522
    .line 523
    invoke-virtual {v1, v12}, Landroid/view/accessibility/AccessibilityRecord;->setContentDescription(Ljava/lang/CharSequence;)V

    .line 524
    .line 525
    .line 526
    :cond_14
    if-eqz v4, :cond_15

    .line 527
    .line 528
    invoke-virtual {v1}, Landroid/view/accessibility/AccessibilityRecord;->getText()Ljava/util/List;

    .line 529
    .line 530
    .line 531
    move-result-object v8

    .line 532
    invoke-interface {v8, v4}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 533
    .line 534
    .line 535
    :cond_15
    invoke-virtual {v0, v1}, Lw3/z;->C(Landroid/view/accessibility/AccessibilityEvent;)Z

    .line 536
    .line 537
    .line 538
    const/16 v15, 0x800

    .line 539
    .line 540
    goto :goto_c

    .line 541
    :cond_16
    move/from16 v28, v15

    .line 542
    .line 543
    move-object/from16 v44, v40

    .line 544
    .line 545
    const/4 v13, 0x0

    .line 546
    invoke-virtual {v0, v3}, Lw3/z;->A(I)I

    .line 547
    .line 548
    .line 549
    move-result v1

    .line 550
    const/16 v4, 0x8

    .line 551
    .line 552
    const/16 v15, 0x800

    .line 553
    .line 554
    invoke-static {v0, v1, v15, v2, v4}, Lw3/z;->E(Lw3/z;IILjava/lang/Integer;I)V

    .line 555
    .line 556
    .line 557
    goto :goto_c

    .line 558
    :cond_17
    move/from16 v28, v15

    .line 559
    .line 560
    move-object/from16 v44, v40

    .line 561
    .line 562
    const/16 v4, 0x8

    .line 563
    .line 564
    const/4 v13, 0x0

    .line 565
    const/16 v15, 0x800

    .line 566
    .line 567
    invoke-virtual {v0, v3}, Lw3/z;->A(I)I

    .line 568
    .line 569
    .line 570
    move-result v1

    .line 571
    invoke-static {v0, v1, v15, v7, v4}, Lw3/z;->E(Lw3/z;IILjava/lang/Integer;I)V

    .line 572
    .line 573
    .line 574
    invoke-virtual {v0, v3}, Lw3/z;->A(I)I

    .line 575
    .line 576
    .line 577
    move-result v1

    .line 578
    invoke-static {v0, v1, v15, v2, v4}, Lw3/z;->E(Lw3/z;IILjava/lang/Integer;I)V

    .line 579
    .line 580
    .line 581
    :goto_c
    move-object v13, v2

    .line 582
    move v15, v3

    .line 583
    move-object v2, v5

    .line 584
    move-object/from16 v8, v44

    .line 585
    .line 586
    move/from16 v3, v45

    .line 587
    .line 588
    const/16 v12, 0x8

    .line 589
    .line 590
    :goto_d
    move-object/from16 v44, v6

    .line 591
    .line 592
    goto/16 :goto_25

    .line 593
    .line 594
    :cond_18
    move/from16 v36, v8

    .line 595
    .line 596
    move/from16 v28, v15

    .line 597
    .line 598
    move-object/from16 v8, v40

    .line 599
    .line 600
    const/16 v15, 0x800

    .line 601
    .line 602
    sget-object v13, Ld4/v;->a:Ld4/z;

    .line 603
    .line 604
    invoke-static {v4, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 605
    .line 606
    .line 607
    move-result v13

    .line 608
    if-eqz v13, :cond_1a

    .line 609
    .line 610
    invoke-virtual {v0, v3}, Lw3/z;->A(I)I

    .line 611
    .line 612
    .line 613
    move-result v4

    .line 614
    invoke-static/range {v36 .. v36}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 615
    .line 616
    .line 617
    move-result-object v12

    .line 618
    const-string v13, "null cannot be cast to non-null type kotlin.collections.List<kotlin.String>"

    .line 619
    .line 620
    invoke-static {v1, v13}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 621
    .line 622
    .line 623
    check-cast v1, Ljava/util/List;

    .line 624
    .line 625
    invoke-virtual {v0, v4, v15, v12, v1}, Lw3/z;->D(IILjava/lang/Integer;Ljava/util/List;)Z

    .line 626
    .line 627
    .line 628
    move-object v13, v2

    .line 629
    move v15, v3

    .line 630
    move-object v2, v5

    .line 631
    move-object/from16 v44, v6

    .line 632
    .line 633
    move/from16 v3, v45

    .line 634
    .line 635
    :cond_19
    :goto_e
    const/16 v12, 0x8

    .line 636
    .line 637
    goto/16 :goto_25

    .line 638
    .line 639
    :cond_1a
    sget-object v13, Ld4/v;->E:Ld4/z;

    .line 640
    .line 641
    invoke-static {v4, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 642
    .line 643
    .line 644
    move-result v15

    .line 645
    const-wide v49, 0xffffffffL

    .line 646
    .line 647
    .line 648
    .line 649
    .line 650
    const/16 v44, 0x20

    .line 651
    .line 652
    const-string v51, ""

    .line 653
    .line 654
    if-eqz v15, :cond_2b

    .line 655
    .line 656
    sget-object v1, Ld4/k;->j:Ld4/z;

    .line 657
    .line 658
    invoke-virtual {v11, v1}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 659
    .line 660
    .line 661
    move-result v1

    .line 662
    if-eqz v1, :cond_2a

    .line 663
    .line 664
    invoke-virtual {v5, v13}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 665
    .line 666
    .line 667
    move-result-object v12

    .line 668
    if-nez v12, :cond_1b

    .line 669
    .line 670
    const/4 v12, 0x0

    .line 671
    :cond_1b
    check-cast v12, Lg4/g;

    .line 672
    .line 673
    if-eqz v12, :cond_1c

    .line 674
    .line 675
    goto :goto_f

    .line 676
    :cond_1c
    move-object/from16 v12, v51

    .line 677
    .line 678
    :goto_f
    invoke-virtual {v11, v13}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 679
    .line 680
    .line 681
    move-result-object v1

    .line 682
    if-nez v1, :cond_1d

    .line 683
    .line 684
    const/4 v1, 0x0

    .line 685
    :cond_1d
    check-cast v1, Lg4/g;

    .line 686
    .line 687
    if-eqz v1, :cond_1e

    .line 688
    .line 689
    goto :goto_10

    .line 690
    :cond_1e
    move-object/from16 v1, v51

    .line 691
    .line 692
    :goto_10
    invoke-static {v1}, Lw3/z;->P(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    .line 693
    .line 694
    .line 695
    move-result-object v4

    .line 696
    invoke-interface {v12}, Ljava/lang/CharSequence;->length()I

    .line 697
    .line 698
    .line 699
    move-result v13

    .line 700
    invoke-interface {v1}, Ljava/lang/CharSequence;->length()I

    .line 701
    .line 702
    .line 703
    move-result v15

    .line 704
    move-object/from16 v52, v2

    .line 705
    .line 706
    if-le v13, v15, :cond_1f

    .line 707
    .line 708
    move v2, v15

    .line 709
    goto :goto_11

    .line 710
    :cond_1f
    move v2, v13

    .line 711
    :goto_11
    move/from16 v51, v13

    .line 712
    .line 713
    const/4 v13, 0x0

    .line 714
    :goto_12
    move/from16 v53, v2

    .line 715
    .line 716
    if-ge v13, v2, :cond_21

    .line 717
    .line 718
    invoke-interface {v12, v13}, Ljava/lang/CharSequence;->charAt(I)C

    .line 719
    .line 720
    .line 721
    move-result v2

    .line 722
    move/from16 v54, v15

    .line 723
    .line 724
    invoke-interface {v1, v13}, Ljava/lang/CharSequence;->charAt(I)C

    .line 725
    .line 726
    .line 727
    move-result v15

    .line 728
    if-eq v2, v15, :cond_20

    .line 729
    .line 730
    goto :goto_13

    .line 731
    :cond_20
    add-int/lit8 v13, v13, 0x1

    .line 732
    .line 733
    move/from16 v2, v53

    .line 734
    .line 735
    move/from16 v15, v54

    .line 736
    .line 737
    goto :goto_12

    .line 738
    :cond_21
    move/from16 v54, v15

    .line 739
    .line 740
    :goto_13
    const/4 v2, 0x0

    .line 741
    :goto_14
    sub-int v15, v53, v13

    .line 742
    .line 743
    if-ge v2, v15, :cond_23

    .line 744
    .line 745
    add-int/lit8 v15, v51, -0x1

    .line 746
    .line 747
    sub-int/2addr v15, v2

    .line 748
    invoke-interface {v12, v15}, Ljava/lang/CharSequence;->charAt(I)C

    .line 749
    .line 750
    .line 751
    move-result v15

    .line 752
    add-int/lit8 v55, v54, -0x1

    .line 753
    .line 754
    move/from16 v56, v2

    .line 755
    .line 756
    sub-int v2, v55, v56

    .line 757
    .line 758
    invoke-interface {v1, v2}, Ljava/lang/CharSequence;->charAt(I)C

    .line 759
    .line 760
    .line 761
    move-result v2

    .line 762
    if-eq v15, v2, :cond_22

    .line 763
    .line 764
    goto :goto_15

    .line 765
    :cond_22
    add-int/lit8 v2, v56, 0x1

    .line 766
    .line 767
    goto :goto_14

    .line 768
    :cond_23
    move/from16 v56, v2

    .line 769
    .line 770
    :goto_15
    sub-int v1, v51, v56

    .line 771
    .line 772
    sub-int/2addr v1, v13

    .line 773
    sub-int v15, v54, v56

    .line 774
    .line 775
    sub-int/2addr v15, v13

    .line 776
    sget-object v2, Ld4/v;->J:Ld4/z;

    .line 777
    .line 778
    invoke-virtual {v5, v2}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 779
    .line 780
    .line 781
    move-result v51

    .line 782
    invoke-virtual {v11, v2}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 783
    .line 784
    .line 785
    move-result v2

    .line 786
    move/from16 v53, v2

    .line 787
    .line 788
    sget-object v2, Ld4/v;->E:Ld4/z;

    .line 789
    .line 790
    invoke-virtual {v5, v2}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 791
    .line 792
    .line 793
    move-result v2

    .line 794
    if-eqz v2, :cond_24

    .line 795
    .line 796
    if-nez v51, :cond_24

    .line 797
    .line 798
    if-eqz v53, :cond_24

    .line 799
    .line 800
    const/16 v55, 0x1

    .line 801
    .line 802
    goto :goto_16

    .line 803
    :cond_24
    const/16 v55, 0x0

    .line 804
    .line 805
    :goto_16
    if-eqz v2, :cond_25

    .line 806
    .line 807
    if-eqz v51, :cond_25

    .line 808
    .line 809
    if-nez v53, :cond_25

    .line 810
    .line 811
    const/16 v51, 0x1

    .line 812
    .line 813
    goto :goto_17

    .line 814
    :cond_25
    const/16 v51, 0x0

    .line 815
    .line 816
    :goto_17
    if-nez v55, :cond_26

    .line 817
    .line 818
    if-eqz v51, :cond_27

    .line 819
    .line 820
    :cond_26
    move-object/from16 v53, v5

    .line 821
    .line 822
    goto :goto_18

    .line 823
    :cond_27
    invoke-virtual {v0, v3}, Lw3/z;->A(I)I

    .line 824
    .line 825
    .line 826
    move-result v2

    .line 827
    move-object/from16 v53, v5

    .line 828
    .line 829
    const/16 v5, 0x10

    .line 830
    .line 831
    invoke-virtual {v0, v2, v5}, Lw3/z;->o(II)Landroid/view/accessibility/AccessibilityEvent;

    .line 832
    .line 833
    .line 834
    move-result-object v2

    .line 835
    invoke-virtual {v2, v13}, Landroid/view/accessibility/AccessibilityRecord;->setFromIndex(I)V

    .line 836
    .line 837
    .line 838
    invoke-virtual {v2, v1}, Landroid/view/accessibility/AccessibilityRecord;->setRemovedCount(I)V

    .line 839
    .line 840
    .line 841
    invoke-virtual {v2, v15}, Landroid/view/accessibility/AccessibilityRecord;->setAddedCount(I)V

    .line 842
    .line 843
    .line 844
    invoke-virtual {v2, v12}, Landroid/view/accessibility/AccessibilityRecord;->setBeforeText(Ljava/lang/CharSequence;)V

    .line 845
    .line 846
    .line 847
    invoke-virtual {v2}, Landroid/view/accessibility/AccessibilityRecord;->getText()Ljava/util/List;

    .line 848
    .line 849
    .line 850
    move-result-object v1

    .line 851
    invoke-interface {v1, v4}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 852
    .line 853
    .line 854
    move-object v1, v2

    .line 855
    move v15, v3

    .line 856
    move-object/from16 v2, v52

    .line 857
    .line 858
    goto :goto_19

    .line 859
    :goto_18
    invoke-virtual {v0, v3}, Lw3/z;->A(I)I

    .line 860
    .line 861
    .line 862
    move-result v1

    .line 863
    invoke-static/range {v54 .. v54}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 864
    .line 865
    .line 866
    move-result-object v2

    .line 867
    move v5, v3

    .line 868
    move-object/from16 v3, v52

    .line 869
    .line 870
    move v15, v5

    .line 871
    move-object v5, v4

    .line 872
    move-object v4, v2

    .line 873
    move-object/from16 v2, v52

    .line 874
    .line 875
    invoke-virtual/range {v0 .. v5}, Lw3/z;->q(ILjava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/CharSequence;)Landroid/view/accessibility/AccessibilityEvent;

    .line 876
    .line 877
    .line 878
    move-result-object v1

    .line 879
    :goto_19
    const-string v3, "android.widget.EditText"

    .line 880
    .line 881
    invoke-virtual {v1, v3}, Landroid/view/accessibility/AccessibilityRecord;->setClassName(Ljava/lang/CharSequence;)V

    .line 882
    .line 883
    .line 884
    invoke-virtual {v0, v1}, Lw3/z;->C(Landroid/view/accessibility/AccessibilityEvent;)Z

    .line 885
    .line 886
    .line 887
    if-nez v55, :cond_28

    .line 888
    .line 889
    if-eqz v51, :cond_29

    .line 890
    .line 891
    :cond_28
    sget-object v3, Ld4/v;->F:Ld4/z;

    .line 892
    .line 893
    invoke-virtual {v6, v3}, Ld4/l;->e(Ld4/z;)Ljava/lang/Object;

    .line 894
    .line 895
    .line 896
    move-result-object v3

    .line 897
    check-cast v3, Lg4/o0;

    .line 898
    .line 899
    iget-wide v3, v3, Lg4/o0;->a:J

    .line 900
    .line 901
    shr-long v12, v3, v44

    .line 902
    .line 903
    long-to-int v5, v12

    .line 904
    invoke-virtual {v1, v5}, Landroid/view/accessibility/AccessibilityRecord;->setFromIndex(I)V

    .line 905
    .line 906
    .line 907
    and-long v3, v3, v49

    .line 908
    .line 909
    long-to-int v3, v3

    .line 910
    invoke-virtual {v1, v3}, Landroid/view/accessibility/AccessibilityRecord;->setToIndex(I)V

    .line 911
    .line 912
    .line 913
    invoke-virtual {v0, v1}, Lw3/z;->C(Landroid/view/accessibility/AccessibilityEvent;)Z

    .line 914
    .line 915
    .line 916
    :cond_29
    move-object v13, v2

    .line 917
    :goto_1a
    move-object/from16 v44, v6

    .line 918
    .line 919
    move/from16 v3, v45

    .line 920
    .line 921
    move-object/from16 v2, v53

    .line 922
    .line 923
    goto/16 :goto_e

    .line 924
    .line 925
    :cond_2a
    move v15, v3

    .line 926
    move-object/from16 v53, v5

    .line 927
    .line 928
    invoke-virtual {v0, v15}, Lw3/z;->A(I)I

    .line 929
    .line 930
    .line 931
    move-result v1

    .line 932
    invoke-static/range {v16 .. v16}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 933
    .line 934
    .line 935
    move-result-object v3

    .line 936
    const/16 v4, 0x800

    .line 937
    .line 938
    const/16 v12, 0x8

    .line 939
    .line 940
    invoke-static {v0, v1, v4, v3, v12}, Lw3/z;->E(Lw3/z;IILjava/lang/Integer;I)V

    .line 941
    .line 942
    .line 943
    move-object v13, v2

    .line 944
    move-object/from16 v44, v6

    .line 945
    .line 946
    move/from16 v3, v45

    .line 947
    .line 948
    move-object/from16 v2, v53

    .line 949
    .line 950
    goto/16 :goto_25

    .line 951
    .line 952
    :cond_2b
    move v15, v3

    .line 953
    move-object/from16 v53, v5

    .line 954
    .line 955
    sget-object v3, Ld4/v;->F:Ld4/z;

    .line 956
    .line 957
    invoke-static {v4, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 958
    .line 959
    .line 960
    move-result v5

    .line 961
    if-eqz v5, :cond_2f

    .line 962
    .line 963
    invoke-virtual {v11, v13}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 964
    .line 965
    .line 966
    move-result-object v12

    .line 967
    if-nez v12, :cond_2c

    .line 968
    .line 969
    const/4 v12, 0x0

    .line 970
    :cond_2c
    check-cast v12, Lg4/g;

    .line 971
    .line 972
    if-eqz v12, :cond_2e

    .line 973
    .line 974
    iget-object v1, v12, Lg4/g;->e:Ljava/lang/String;

    .line 975
    .line 976
    if-nez v1, :cond_2d

    .line 977
    .line 978
    goto :goto_1b

    .line 979
    :cond_2d
    move-object/from16 v51, v1

    .line 980
    .line 981
    :cond_2e
    :goto_1b
    invoke-virtual {v6, v3}, Ld4/l;->e(Ld4/z;)Ljava/lang/Object;

    .line 982
    .line 983
    .line 984
    move-result-object v1

    .line 985
    check-cast v1, Lg4/o0;

    .line 986
    .line 987
    iget-wide v3, v1, Lg4/o0;->a:J

    .line 988
    .line 989
    invoke-virtual {v0, v15}, Lw3/z;->A(I)I

    .line 990
    .line 991
    .line 992
    move-result v1

    .line 993
    shr-long v12, v3, v44

    .line 994
    .line 995
    long-to-int v5, v12

    .line 996
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 997
    .line 998
    .line 999
    move-result-object v5

    .line 1000
    and-long v3, v3, v49

    .line 1001
    .line 1002
    long-to-int v3, v3

    .line 1003
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1004
    .line 1005
    .line 1006
    move-result-object v3

    .line 1007
    invoke-virtual/range {v51 .. v51}, Ljava/lang/String;->length()I

    .line 1008
    .line 1009
    .line 1010
    move-result v4

    .line 1011
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1012
    .line 1013
    .line 1014
    move-result-object v4

    .line 1015
    invoke-static/range {v51 .. v51}, Lw3/z;->P(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    .line 1016
    .line 1017
    .line 1018
    move-result-object v12

    .line 1019
    move-object v13, v2

    .line 1020
    move-object v2, v5

    .line 1021
    move-object v5, v12

    .line 1022
    invoke-virtual/range {v0 .. v5}, Lw3/z;->q(ILjava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/CharSequence;)Landroid/view/accessibility/AccessibilityEvent;

    .line 1023
    .line 1024
    .line 1025
    move-result-object v1

    .line 1026
    invoke-virtual {v0, v1}, Lw3/z;->C(Landroid/view/accessibility/AccessibilityEvent;)Z

    .line 1027
    .line 1028
    .line 1029
    invoke-virtual {v0, v10}, Lw3/z;->G(I)V

    .line 1030
    .line 1031
    .line 1032
    goto :goto_1a

    .line 1033
    :cond_2f
    move-object v13, v2

    .line 1034
    move/from16 v3, v45

    .line 1035
    .line 1036
    move-object/from16 v2, v53

    .line 1037
    .line 1038
    invoke-static {v4, v12}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1039
    .line 1040
    .line 1041
    move-result v5

    .line 1042
    if-nez v5, :cond_30

    .line 1043
    .line 1044
    sget-object v5, Ld4/v;->u:Ld4/z;

    .line 1045
    .line 1046
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1047
    .line 1048
    .line 1049
    move-result v5

    .line 1050
    if-eqz v5, :cond_31

    .line 1051
    .line 1052
    :cond_30
    move-object/from16 v44, v6

    .line 1053
    .line 1054
    goto/16 :goto_23

    .line 1055
    .line 1056
    :cond_31
    sget-object v5, Ld4/v;->k:Ld4/z;

    .line 1057
    .line 1058
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1059
    .line 1060
    .line 1061
    move-result v5

    .line 1062
    if-eqz v5, :cond_33

    .line 1063
    .line 1064
    const-string v4, "null cannot be cast to non-null type kotlin.Boolean"

    .line 1065
    .line 1066
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1067
    .line 1068
    .line 1069
    check-cast v1, Ljava/lang/Boolean;

    .line 1070
    .line 1071
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 1072
    .line 1073
    .line 1074
    move-result v1

    .line 1075
    if-eqz v1, :cond_32

    .line 1076
    .line 1077
    invoke-virtual {v0, v10}, Lw3/z;->A(I)I

    .line 1078
    .line 1079
    .line 1080
    move-result v1

    .line 1081
    const/16 v4, 0x8

    .line 1082
    .line 1083
    invoke-virtual {v0, v1, v4}, Lw3/z;->o(II)Landroid/view/accessibility/AccessibilityEvent;

    .line 1084
    .line 1085
    .line 1086
    move-result-object v1

    .line 1087
    invoke-virtual {v0, v1}, Lw3/z;->C(Landroid/view/accessibility/AccessibilityEvent;)Z

    .line 1088
    .line 1089
    .line 1090
    goto :goto_1c

    .line 1091
    :cond_32
    const/16 v4, 0x8

    .line 1092
    .line 1093
    :goto_1c
    invoke-virtual {v0, v10}, Lw3/z;->A(I)I

    .line 1094
    .line 1095
    .line 1096
    move-result v1

    .line 1097
    const/16 v5, 0x800

    .line 1098
    .line 1099
    invoke-static {v0, v1, v5, v13, v4}, Lw3/z;->E(Lw3/z;IILjava/lang/Integer;I)V

    .line 1100
    .line 1101
    .line 1102
    move v12, v4

    .line 1103
    goto/16 :goto_d

    .line 1104
    .line 1105
    :cond_33
    sget-object v5, Ld4/k;->w:Ld4/z;

    .line 1106
    .line 1107
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1108
    .line 1109
    .line 1110
    move-result v12

    .line 1111
    if-eqz v12, :cond_3a

    .line 1112
    .line 1113
    invoke-virtual {v6, v5}, Ld4/l;->e(Ld4/z;)Ljava/lang/Object;

    .line 1114
    .line 1115
    .line 1116
    move-result-object v1

    .line 1117
    check-cast v1, Ljava/util/List;

    .line 1118
    .line 1119
    invoke-virtual {v2, v5}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1120
    .line 1121
    .line 1122
    move-result-object v12

    .line 1123
    if-nez v12, :cond_34

    .line 1124
    .line 1125
    const/4 v12, 0x0

    .line 1126
    :cond_34
    check-cast v12, Ljava/util/List;

    .line 1127
    .line 1128
    if-eqz v12, :cond_38

    .line 1129
    .line 1130
    new-instance v4, Ljava/util/LinkedHashSet;

    .line 1131
    .line 1132
    invoke-direct {v4}, Ljava/util/LinkedHashSet;-><init>()V

    .line 1133
    .line 1134
    .line 1135
    move-object v5, v1

    .line 1136
    check-cast v5, Ljava/util/Collection;

    .line 1137
    .line 1138
    invoke-interface {v5}, Ljava/util/Collection;->size()I

    .line 1139
    .line 1140
    .line 1141
    move-result v5

    .line 1142
    move-object/from16 v44, v6

    .line 1143
    .line 1144
    const/4 v6, 0x0

    .line 1145
    :goto_1d
    if-ge v6, v5, :cond_35

    .line 1146
    .line 1147
    invoke-interface {v1, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1148
    .line 1149
    .line 1150
    move-result-object v38

    .line 1151
    move-object/from16 v45, v1

    .line 1152
    .line 1153
    move-object/from16 v1, v38

    .line 1154
    .line 1155
    check-cast v1, Ld4/d;

    .line 1156
    .line 1157
    iget-object v1, v1, Ld4/d;->a:Ljava/lang/String;

    .line 1158
    .line 1159
    invoke-interface {v4, v1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 1160
    .line 1161
    .line 1162
    add-int/lit8 v6, v6, 0x1

    .line 1163
    .line 1164
    move-object/from16 v1, v45

    .line 1165
    .line 1166
    goto :goto_1d

    .line 1167
    :cond_35
    new-instance v1, Ljava/util/LinkedHashSet;

    .line 1168
    .line 1169
    invoke-direct {v1}, Ljava/util/LinkedHashSet;-><init>()V

    .line 1170
    .line 1171
    .line 1172
    move-object v5, v12

    .line 1173
    check-cast v5, Ljava/util/Collection;

    .line 1174
    .line 1175
    invoke-interface {v5}, Ljava/util/Collection;->size()I

    .line 1176
    .line 1177
    .line 1178
    move-result v5

    .line 1179
    const/4 v6, 0x0

    .line 1180
    :goto_1e
    if-ge v6, v5, :cond_36

    .line 1181
    .line 1182
    invoke-interface {v12, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1183
    .line 1184
    .line 1185
    move-result-object v38

    .line 1186
    move/from16 v45, v5

    .line 1187
    .line 1188
    move-object/from16 v5, v38

    .line 1189
    .line 1190
    check-cast v5, Ld4/d;

    .line 1191
    .line 1192
    iget-object v5, v5, Ld4/d;->a:Ljava/lang/String;

    .line 1193
    .line 1194
    invoke-interface {v1, v5}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 1195
    .line 1196
    .line 1197
    add-int/lit8 v6, v6, 0x1

    .line 1198
    .line 1199
    move/from16 v5, v45

    .line 1200
    .line 1201
    goto :goto_1e

    .line 1202
    :cond_36
    invoke-interface {v4, v1}, Ljava/util/Set;->containsAll(Ljava/util/Collection;)Z

    .line 1203
    .line 1204
    .line 1205
    move-result v5

    .line 1206
    if-eqz v5, :cond_39

    .line 1207
    .line 1208
    invoke-interface {v1, v4}, Ljava/util/Set;->containsAll(Ljava/util/Collection;)Z

    .line 1209
    .line 1210
    .line 1211
    move-result v1

    .line 1212
    if-nez v1, :cond_37

    .line 1213
    .line 1214
    goto :goto_1f

    .line 1215
    :cond_37
    const/16 v38, 0x0

    .line 1216
    .line 1217
    goto/16 :goto_e

    .line 1218
    .line 1219
    :cond_38
    move-object/from16 v45, v1

    .line 1220
    .line 1221
    move-object/from16 v44, v6

    .line 1222
    .line 1223
    move-object/from16 v1, v45

    .line 1224
    .line 1225
    check-cast v1, Ljava/util/Collection;

    .line 1226
    .line 1227
    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    .line 1228
    .line 1229
    .line 1230
    move-result v1

    .line 1231
    if-nez v1, :cond_19

    .line 1232
    .line 1233
    :cond_39
    :goto_1f
    const/16 v38, 0x1

    .line 1234
    .line 1235
    goto/16 :goto_e

    .line 1236
    .line 1237
    :cond_3a
    move-object/from16 v44, v6

    .line 1238
    .line 1239
    instance-of v5, v1, Ld4/a;

    .line 1240
    .line 1241
    if-eqz v5, :cond_39

    .line 1242
    .line 1243
    check-cast v1, Ld4/a;

    .line 1244
    .line 1245
    invoke-virtual {v2, v4}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1246
    .line 1247
    .line 1248
    move-result-object v12

    .line 1249
    if-nez v12, :cond_3b

    .line 1250
    .line 1251
    const/4 v12, 0x0

    .line 1252
    :cond_3b
    if-ne v1, v12, :cond_3c

    .line 1253
    .line 1254
    goto :goto_21

    .line 1255
    :cond_3c
    instance-of v4, v12, Ld4/a;

    .line 1256
    .line 1257
    if-nez v4, :cond_3d

    .line 1258
    .line 1259
    goto :goto_20

    .line 1260
    :cond_3d
    iget-object v4, v1, Ld4/a;->a:Ljava/lang/String;

    .line 1261
    .line 1262
    check-cast v12, Ld4/a;

    .line 1263
    .line 1264
    iget-object v5, v12, Ld4/a;->b:Llx0/e;

    .line 1265
    .line 1266
    iget-object v6, v12, Ld4/a;->a:Ljava/lang/String;

    .line 1267
    .line 1268
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1269
    .line 1270
    .line 1271
    move-result v4

    .line 1272
    if-nez v4, :cond_3e

    .line 1273
    .line 1274
    goto :goto_20

    .line 1275
    :cond_3e
    iget-object v1, v1, Ld4/a;->b:Llx0/e;

    .line 1276
    .line 1277
    if-nez v1, :cond_3f

    .line 1278
    .line 1279
    if-eqz v5, :cond_3f

    .line 1280
    .line 1281
    goto :goto_20

    .line 1282
    :cond_3f
    if-eqz v1, :cond_40

    .line 1283
    .line 1284
    if-nez v5, :cond_40

    .line 1285
    .line 1286
    :goto_20
    const/4 v1, 0x0

    .line 1287
    goto :goto_22

    .line 1288
    :cond_40
    :goto_21
    const/4 v1, 0x1

    .line 1289
    :goto_22
    if-nez v1, :cond_37

    .line 1290
    .line 1291
    goto :goto_1f

    .line 1292
    :goto_23
    invoke-virtual {v0, v8}, Lw3/z;->w(Lv3/h0;)V

    .line 1293
    .line 1294
    .line 1295
    invoke-static {v9, v15}, Lw3/h0;->p(Ljava/util/ArrayList;I)Lw3/z1;

    .line 1296
    .line 1297
    .line 1298
    move-result-object v1

    .line 1299
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 1300
    .line 1301
    .line 1302
    invoke-virtual {v11, v12}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1303
    .line 1304
    .line 1305
    move-result-object v12

    .line 1306
    if-nez v12, :cond_41

    .line 1307
    .line 1308
    const/4 v12, 0x0

    .line 1309
    :cond_41
    check-cast v12, Ld4/j;

    .line 1310
    .line 1311
    iput-object v12, v1, Lw3/z1;->h:Ld4/j;

    .line 1312
    .line 1313
    sget-object v4, Ld4/v;->u:Ld4/z;

    .line 1314
    .line 1315
    invoke-virtual {v11, v4}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1316
    .line 1317
    .line 1318
    move-result-object v12

    .line 1319
    if-nez v12, :cond_42

    .line 1320
    .line 1321
    const/4 v12, 0x0

    .line 1322
    :cond_42
    check-cast v12, Ld4/j;

    .line 1323
    .line 1324
    iput-object v12, v1, Lw3/z1;->i:Ld4/j;

    .line 1325
    .line 1326
    iget-object v4, v1, Lw3/z1;->e:Ljava/util/List;

    .line 1327
    .line 1328
    invoke-interface {v4, v1}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 1329
    .line 1330
    .line 1331
    move-result v4

    .line 1332
    if-nez v4, :cond_43

    .line 1333
    .line 1334
    goto/16 :goto_e

    .line 1335
    .line 1336
    :cond_43
    iget-object v4, v0, Lw3/z;->d:Lw3/t;

    .line 1337
    .line 1338
    invoke-virtual {v4}, Lw3/t;->getSnapshotObserver()Lv3/q1;

    .line 1339
    .line 1340
    .line 1341
    move-result-object v4

    .line 1342
    new-instance v5, La4/b;

    .line 1343
    .line 1344
    const/16 v6, 0xb

    .line 1345
    .line 1346
    invoke-direct {v5, v6, v1, v0}, La4/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 1347
    .line 1348
    .line 1349
    iget-object v6, v0, Lw3/z;->P:Lw3/y;

    .line 1350
    .line 1351
    invoke-virtual {v4, v1, v6, v5}, Lv3/q1;->a(Lv3/p1;Lay0/k;Lay0/a;)V

    .line 1352
    .line 1353
    .line 1354
    goto/16 :goto_e

    .line 1355
    .line 1356
    :goto_24
    invoke-virtual {v0, v15}, Lw3/z;->A(I)I

    .line 1357
    .line 1358
    .line 1359
    move-result v1

    .line 1360
    const/16 v4, 0x800

    .line 1361
    .line 1362
    const/16 v12, 0x8

    .line 1363
    .line 1364
    invoke-static {v0, v1, v4, v7, v12}, Lw3/z;->E(Lw3/z;IILjava/lang/Integer;I)V

    .line 1365
    .line 1366
    .line 1367
    invoke-virtual {v0, v15}, Lw3/z;->A(I)I

    .line 1368
    .line 1369
    .line 1370
    move-result v1

    .line 1371
    invoke-static {v0, v1, v4, v13, v12}, Lw3/z;->E(Lw3/z;IILjava/lang/Integer;I)V

    .line 1372
    .line 1373
    .line 1374
    goto :goto_25

    .line 1375
    :cond_44
    move-object/from16 v43, v4

    .line 1376
    .line 1377
    move-object/from16 v44, v6

    .line 1378
    .line 1379
    move-object/from16 v48, v8

    .line 1380
    .line 1381
    move-wide/from16 v46, v12

    .line 1382
    .line 1383
    move/from16 v28, v15

    .line 1384
    .line 1385
    move/from16 v12, v27

    .line 1386
    .line 1387
    move-object/from16 v8, v40

    .line 1388
    .line 1389
    move-object v13, v2

    .line 1390
    move v15, v3

    .line 1391
    move-object v2, v5

    .line 1392
    move v3, v1

    .line 1393
    :goto_25
    shr-long v4, v46, v12

    .line 1394
    .line 1395
    add-int/lit8 v1, v28, 0x1

    .line 1396
    .line 1397
    move v6, v15

    .line 1398
    move v15, v1

    .line 1399
    move v1, v3

    .line 1400
    move v3, v6

    .line 1401
    move-object/from16 v40, v8

    .line 1402
    .line 1403
    move/from16 v27, v12

    .line 1404
    .line 1405
    move-object/from16 v6, v44

    .line 1406
    .line 1407
    move-object/from16 v8, v48

    .line 1408
    .line 1409
    move-wide/from16 v57, v4

    .line 1410
    .line 1411
    move-object v5, v2

    .line 1412
    move-object v2, v13

    .line 1413
    move-object/from16 v4, v43

    .line 1414
    .line 1415
    move-wide/from16 v12, v57

    .line 1416
    .line 1417
    goto/16 :goto_4

    .line 1418
    .line 1419
    :cond_45
    move-object v13, v2

    .line 1420
    move v15, v3

    .line 1421
    move-object/from16 v43, v4

    .line 1422
    .line 1423
    move-object v2, v5

    .line 1424
    move-object/from16 v44, v6

    .line 1425
    .line 1426
    move-object/from16 v48, v8

    .line 1427
    .line 1428
    move/from16 v12, v27

    .line 1429
    .line 1430
    move-object/from16 v8, v40

    .line 1431
    .line 1432
    move v3, v1

    .line 1433
    if-ne v14, v12, :cond_48

    .line 1434
    .line 1435
    :goto_26
    move/from16 v1, v42

    .line 1436
    .line 1437
    goto :goto_27

    .line 1438
    :cond_46
    move-object v13, v2

    .line 1439
    move v15, v3

    .line 1440
    move-object/from16 v43, v4

    .line 1441
    .line 1442
    move-object v2, v5

    .line 1443
    move-object/from16 v44, v6

    .line 1444
    .line 1445
    move-object/from16 v48, v8

    .line 1446
    .line 1447
    move-object/from16 v8, v40

    .line 1448
    .line 1449
    move v3, v1

    .line 1450
    goto :goto_26

    .line 1451
    :goto_27
    if-eq v1, v3, :cond_48

    .line 1452
    .line 1453
    add-int/lit8 v1, v1, 0x1

    .line 1454
    .line 1455
    move v4, v15

    .line 1456
    move v15, v1

    .line 1457
    move v1, v3

    .line 1458
    move v3, v4

    .line 1459
    move-object v5, v2

    .line 1460
    move-object/from16 v40, v8

    .line 1461
    .line 1462
    move-object v2, v13

    .line 1463
    move-object/from16 v14, v41

    .line 1464
    .line 1465
    move-object/from16 v4, v43

    .line 1466
    .line 1467
    move-object/from16 v6, v44

    .line 1468
    .line 1469
    move-object/from16 v8, v48

    .line 1470
    .line 1471
    const/16 v27, 0x8

    .line 1472
    .line 1473
    goto/16 :goto_3

    .line 1474
    .line 1475
    :cond_47
    move v15, v3

    .line 1476
    move-object/from16 v43, v4

    .line 1477
    .line 1478
    move-object/from16 v48, v8

    .line 1479
    .line 1480
    move/from16 v39, v13

    .line 1481
    .line 1482
    move-object/from16 v41, v14

    .line 1483
    .line 1484
    move-object v13, v2

    .line 1485
    const/16 v38, 0x0

    .line 1486
    .line 1487
    :cond_48
    if-nez v38, :cond_4b

    .line 1488
    .line 1489
    invoke-virtual/range {v43 .. v43}, Ld4/l;->iterator()Ljava/util/Iterator;

    .line 1490
    .line 1491
    .line 1492
    move-result-object v1

    .line 1493
    :cond_49
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 1494
    .line 1495
    .line 1496
    move-result v2

    .line 1497
    if-eqz v2, :cond_4a

    .line 1498
    .line 1499
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1500
    .line 1501
    .line 1502
    move-result-object v2

    .line 1503
    check-cast v2, Ljava/util/Map$Entry;

    .line 1504
    .line 1505
    invoke-virtual/range {v41 .. v41}, Ld4/q;->k()Ld4/l;

    .line 1506
    .line 1507
    .line 1508
    move-result-object v3

    .line 1509
    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 1510
    .line 1511
    .line 1512
    move-result-object v2

    .line 1513
    check-cast v2, Ld4/z;

    .line 1514
    .line 1515
    iget-object v3, v3, Ld4/l;->d:Landroidx/collection/q0;

    .line 1516
    .line 1517
    invoke-virtual {v3, v2}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 1518
    .line 1519
    .line 1520
    move-result v2

    .line 1521
    if-nez v2, :cond_49

    .line 1522
    .line 1523
    const/16 v37, 0x1

    .line 1524
    .line 1525
    goto :goto_28

    .line 1526
    :cond_4a
    const/16 v37, 0x0

    .line 1527
    .line 1528
    :goto_28
    move/from16 v38, v37

    .line 1529
    .line 1530
    :cond_4b
    if-eqz v38, :cond_4c

    .line 1531
    .line 1532
    invoke-virtual {v0, v15}, Lw3/z;->A(I)I

    .line 1533
    .line 1534
    .line 1535
    move-result v1

    .line 1536
    const/16 v4, 0x800

    .line 1537
    .line 1538
    const/16 v12, 0x8

    .line 1539
    .line 1540
    invoke-static {v0, v1, v4, v13, v12}, Lw3/z;->E(Lw3/z;IILjava/lang/Integer;I)V

    .line 1541
    .line 1542
    .line 1543
    goto :goto_2a

    .line 1544
    :cond_4c
    const/16 v12, 0x8

    .line 1545
    .line 1546
    goto :goto_2a

    .line 1547
    :cond_4d
    const-string v0, "no value for specified key"

    .line 1548
    .line 1549
    invoke-static {v0}, Lvj/b;->b(Ljava/lang/String;)La8/r0;

    .line 1550
    .line 1551
    .line 1552
    move-result-object v0

    .line 1553
    throw v0

    .line 1554
    :cond_4e
    :goto_29
    move/from16 v34, v1

    .line 1555
    .line 1556
    move-object/from16 v48, v8

    .line 1557
    .line 1558
    move-object/from16 v29, v10

    .line 1559
    .line 1560
    move-object/from16 v30, v11

    .line 1561
    .line 1562
    move/from16 v39, v13

    .line 1563
    .line 1564
    move/from16 v31, v15

    .line 1565
    .line 1566
    move-object v13, v2

    .line 1567
    :goto_2a
    shr-long v21, v21, v12

    .line 1568
    .line 1569
    add-int/lit8 v1, v34, 0x1

    .line 1570
    .line 1571
    move-object/from16 v6, p1

    .line 1572
    .line 1573
    move-object v2, v13

    .line 1574
    move-object/from16 v10, v29

    .line 1575
    .line 1576
    move-object/from16 v11, v30

    .line 1577
    .line 1578
    move/from16 v15, v31

    .line 1579
    .line 1580
    move/from16 v13, v39

    .line 1581
    .line 1582
    move-object/from16 v8, v48

    .line 1583
    .line 1584
    const/4 v14, 0x0

    .line 1585
    goto/16 :goto_1

    .line 1586
    .line 1587
    :cond_4f
    move-object/from16 v48, v8

    .line 1588
    .line 1589
    move-object/from16 v29, v10

    .line 1590
    .line 1591
    move-object/from16 v30, v11

    .line 1592
    .line 1593
    move v1, v13

    .line 1594
    move/from16 v31, v15

    .line 1595
    .line 1596
    move-object v13, v2

    .line 1597
    if-ne v1, v12, :cond_51

    .line 1598
    .line 1599
    move/from16 v14, v31

    .line 1600
    .line 1601
    :goto_2b
    move/from16 v1, v17

    .line 1602
    .line 1603
    goto :goto_2c

    .line 1604
    :cond_50
    move-object v13, v2

    .line 1605
    move-object/from16 v48, v8

    .line 1606
    .line 1607
    move-object/from16 v29, v10

    .line 1608
    .line 1609
    move-object/from16 v30, v11

    .line 1610
    .line 1611
    move v14, v15

    .line 1612
    goto :goto_2b

    .line 1613
    :goto_2c
    if-eq v14, v1, :cond_51

    .line 1614
    .line 1615
    add-int/lit8 v15, v14, 0x1

    .line 1616
    .line 1617
    move-object/from16 v6, p1

    .line 1618
    .line 1619
    move-object v2, v13

    .line 1620
    move/from16 v12, v16

    .line 1621
    .line 1622
    move-object/from16 v10, v29

    .line 1623
    .line 1624
    move-object/from16 v11, v30

    .line 1625
    .line 1626
    move-object/from16 v8, v48

    .line 1627
    .line 1628
    const/4 v14, 0x0

    .line 1629
    move v13, v1

    .line 1630
    goto/16 :goto_0

    .line 1631
    .line 1632
    :cond_51
    return-void
.end method

.method public final I(Lv3/h0;Landroidx/collection/c0;)V
    .locals 5

    .line 1
    invoke-virtual {p1}, Lv3/h0;->I()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    goto/16 :goto_4

    .line 8
    .line 9
    :cond_0
    iget-object v0, p0, Lw3/z;->d:Lw3/t;

    .line 10
    .line 11
    invoke-virtual {v0}, Lw3/t;->getAndroidViewsHandler$ui_release()Lw3/t0;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    invoke-virtual {v0}, Lw3/t0;->getLayoutNodeToHolder()Ljava/util/HashMap;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    invoke-interface {v0, p1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_1

    .line 24
    .line 25
    goto/16 :goto_4

    .line 26
    .line 27
    :cond_1
    iget-object v0, p1, Lv3/h0;->H:Lg1/q;

    .line 28
    .line 29
    const/16 v1, 0x8

    .line 30
    .line 31
    invoke-virtual {v0, v1}, Lg1/q;->i(I)Z

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    const/4 v2, 0x0

    .line 36
    if-eqz v0, :cond_2

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_2
    invoke-virtual {p1}, Lv3/h0;->v()Lv3/h0;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    :goto_0
    if-eqz p1, :cond_4

    .line 44
    .line 45
    iget-object v0, p1, Lv3/h0;->H:Lg1/q;

    .line 46
    .line 47
    invoke-virtual {v0, v1}, Lg1/q;->i(I)Z

    .line 48
    .line 49
    .line 50
    move-result v0

    .line 51
    if-eqz v0, :cond_3

    .line 52
    .line 53
    goto :goto_1

    .line 54
    :cond_3
    invoke-virtual {p1}, Lv3/h0;->v()Lv3/h0;

    .line 55
    .line 56
    .line 57
    move-result-object p1

    .line 58
    goto :goto_0

    .line 59
    :cond_4
    move-object p1, v2

    .line 60
    :goto_1
    if-eqz p1, :cond_a

    .line 61
    .line 62
    invoke-virtual {p1}, Lv3/h0;->x()Ld4/l;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    if-nez v0, :cond_5

    .line 67
    .line 68
    goto :goto_4

    .line 69
    :cond_5
    iget-boolean v0, v0, Ld4/l;->f:Z

    .line 70
    .line 71
    const/4 v3, 0x1

    .line 72
    if-nez v0, :cond_8

    .line 73
    .line 74
    invoke-virtual {p1}, Lv3/h0;->v()Lv3/h0;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    :goto_2
    if-eqz v0, :cond_7

    .line 79
    .line 80
    invoke-virtual {v0}, Lv3/h0;->x()Ld4/l;

    .line 81
    .line 82
    .line 83
    move-result-object v4

    .line 84
    if-eqz v4, :cond_6

    .line 85
    .line 86
    iget-boolean v4, v4, Ld4/l;->f:Z

    .line 87
    .line 88
    if-ne v4, v3, :cond_6

    .line 89
    .line 90
    move-object v2, v0

    .line 91
    goto :goto_3

    .line 92
    :cond_6
    invoke-virtual {v0}, Lv3/h0;->v()Lv3/h0;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    goto :goto_2

    .line 97
    :cond_7
    :goto_3
    if-eqz v2, :cond_8

    .line 98
    .line 99
    move-object p1, v2

    .line 100
    :cond_8
    iget p1, p1, Lv3/h0;->e:I

    .line 101
    .line 102
    invoke-virtual {p2, p1}, Landroidx/collection/c0;->a(I)Z

    .line 103
    .line 104
    .line 105
    move-result p2

    .line 106
    if-nez p2, :cond_9

    .line 107
    .line 108
    goto :goto_4

    .line 109
    :cond_9
    invoke-virtual {p0, p1}, Lw3/z;->A(I)I

    .line 110
    .line 111
    .line 112
    move-result p1

    .line 113
    const/16 p2, 0x800

    .line 114
    .line 115
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 116
    .line 117
    .line 118
    move-result-object v0

    .line 119
    invoke-static {p0, p1, p2, v0, v1}, Lw3/z;->E(Lw3/z;IILjava/lang/Integer;I)V

    .line 120
    .line 121
    .line 122
    :cond_a
    :goto_4
    return-void
.end method

.method public final J(Lv3/h0;)V
    .locals 3

    .line 1
    invoke-virtual {p1}, Lv3/h0;->I()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    iget-object v0, p0, Lw3/z;->d:Lw3/t;

    .line 9
    .line 10
    invoke-virtual {v0}, Lw3/t;->getAndroidViewsHandler$ui_release()Lw3/t0;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    invoke-virtual {v0}, Lw3/t0;->getLayoutNodeToHolder()Ljava/util/HashMap;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    invoke-interface {v0, p1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_1

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_1
    iget p1, p1, Lv3/h0;->e:I

    .line 26
    .line 27
    iget-object v0, p0, Lw3/z;->s:Landroidx/collection/b0;

    .line 28
    .line 29
    invoke-virtual {v0, p1}, Landroidx/collection/p;->b(I)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    check-cast v0, Ld4/j;

    .line 34
    .line 35
    iget-object v1, p0, Lw3/z;->t:Landroidx/collection/b0;

    .line 36
    .line 37
    invoke-virtual {v1, p1}, Landroidx/collection/p;->b(I)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    check-cast v1, Ld4/j;

    .line 42
    .line 43
    if-nez v0, :cond_2

    .line 44
    .line 45
    if-nez v1, :cond_2

    .line 46
    .line 47
    :goto_0
    return-void

    .line 48
    :cond_2
    const/16 v2, 0x1000

    .line 49
    .line 50
    invoke-virtual {p0, p1, v2}, Lw3/z;->o(II)Landroid/view/accessibility/AccessibilityEvent;

    .line 51
    .line 52
    .line 53
    move-result-object p1

    .line 54
    if-eqz v0, :cond_3

    .line 55
    .line 56
    iget-object v2, v0, Ld4/j;->a:Lay0/a;

    .line 57
    .line 58
    invoke-interface {v2}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v2

    .line 62
    check-cast v2, Ljava/lang/Number;

    .line 63
    .line 64
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 65
    .line 66
    .line 67
    move-result v2

    .line 68
    float-to-int v2, v2

    .line 69
    invoke-virtual {p1, v2}, Landroid/view/accessibility/AccessibilityRecord;->setScrollX(I)V

    .line 70
    .line 71
    .line 72
    iget-object v0, v0, Ld4/j;->b:Lay0/a;

    .line 73
    .line 74
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    check-cast v0, Ljava/lang/Number;

    .line 79
    .line 80
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 81
    .line 82
    .line 83
    move-result v0

    .line 84
    float-to-int v0, v0

    .line 85
    invoke-virtual {p1, v0}, Landroid/view/accessibility/AccessibilityRecord;->setMaxScrollX(I)V

    .line 86
    .line 87
    .line 88
    :cond_3
    if-eqz v1, :cond_4

    .line 89
    .line 90
    iget-object v0, v1, Ld4/j;->a:Lay0/a;

    .line 91
    .line 92
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    check-cast v0, Ljava/lang/Number;

    .line 97
    .line 98
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 99
    .line 100
    .line 101
    move-result v0

    .line 102
    float-to-int v0, v0

    .line 103
    invoke-virtual {p1, v0}, Landroid/view/accessibility/AccessibilityRecord;->setScrollY(I)V

    .line 104
    .line 105
    .line 106
    iget-object v0, v1, Ld4/j;->b:Lay0/a;

    .line 107
    .line 108
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object v0

    .line 112
    check-cast v0, Ljava/lang/Number;

    .line 113
    .line 114
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 115
    .line 116
    .line 117
    move-result v0

    .line 118
    float-to-int v0, v0

    .line 119
    invoke-virtual {p1, v0}, Landroid/view/accessibility/AccessibilityRecord;->setMaxScrollY(I)V

    .line 120
    .line 121
    .line 122
    :cond_4
    invoke-virtual {p0, p1}, Lw3/z;->C(Landroid/view/accessibility/AccessibilityEvent;)Z

    .line 123
    .line 124
    .line 125
    return-void
.end method

.method public final K(Ld4/q;IIZ)Z
    .locals 10

    .line 1
    iget-object v0, p1, Ld4/q;->d:Ld4/l;

    .line 2
    .line 3
    iget v1, p1, Ld4/q;->g:I

    .line 4
    .line 5
    sget-object v2, Ld4/k;->i:Ld4/z;

    .line 6
    .line 7
    iget-object v0, v0, Ld4/l;->d:Landroidx/collection/q0;

    .line 8
    .line 9
    invoke-virtual {v0, v2}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    const/4 v3, 0x0

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    invoke-static {p1}, Lw3/h0;->h(Ld4/q;)Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-eqz v0, :cond_0

    .line 21
    .line 22
    iget-object p0, p1, Ld4/q;->d:Ld4/l;

    .line 23
    .line 24
    invoke-virtual {p0, v2}, Ld4/l;->e(Ld4/z;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    check-cast p0, Ld4/a;

    .line 29
    .line 30
    iget-object p0, p0, Ld4/a;->b:Llx0/e;

    .line 31
    .line 32
    check-cast p0, Lay0/o;

    .line 33
    .line 34
    if-eqz p0, :cond_2

    .line 35
    .line 36
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    invoke-static {p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 41
    .line 42
    .line 43
    move-result-object p2

    .line 44
    invoke-static {p4}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 45
    .line 46
    .line 47
    move-result-object p3

    .line 48
    invoke-interface {p0, p1, p2, p3}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    check-cast p0, Ljava/lang/Boolean;

    .line 53
    .line 54
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 55
    .line 56
    .line 57
    move-result p0

    .line 58
    return p0

    .line 59
    :cond_0
    if-ne p2, p3, :cond_1

    .line 60
    .line 61
    iget p4, p0, Lw3/z;->w:I

    .line 62
    .line 63
    if-ne p3, p4, :cond_1

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_1
    invoke-static {p1}, Lw3/z;->u(Ld4/q;)Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v9

    .line 70
    if-nez v9, :cond_3

    .line 71
    .line 72
    :cond_2
    :goto_0
    return v3

    .line 73
    :cond_3
    if-ltz p2, :cond_4

    .line 74
    .line 75
    if-ne p2, p3, :cond_4

    .line 76
    .line 77
    invoke-virtual {v9}, Ljava/lang/String;->length()I

    .line 78
    .line 79
    .line 80
    move-result p1

    .line 81
    if-gt p3, p1, :cond_4

    .line 82
    .line 83
    goto :goto_1

    .line 84
    :cond_4
    const/4 p2, -0x1

    .line 85
    :goto_1
    iput p2, p0, Lw3/z;->w:I

    .line 86
    .line 87
    invoke-virtual {v9}, Ljava/lang/String;->length()I

    .line 88
    .line 89
    .line 90
    move-result p1

    .line 91
    const/4 p2, 0x1

    .line 92
    if-lez p1, :cond_5

    .line 93
    .line 94
    move v3, p2

    .line 95
    :cond_5
    invoke-virtual {p0, v1}, Lw3/z;->A(I)I

    .line 96
    .line 97
    .line 98
    move-result v5

    .line 99
    const/4 p1, 0x0

    .line 100
    if-eqz v3, :cond_6

    .line 101
    .line 102
    iget p3, p0, Lw3/z;->w:I

    .line 103
    .line 104
    invoke-static {p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 105
    .line 106
    .line 107
    move-result-object p3

    .line 108
    move-object v6, p3

    .line 109
    goto :goto_2

    .line 110
    :cond_6
    move-object v6, p1

    .line 111
    :goto_2
    if-eqz v3, :cond_7

    .line 112
    .line 113
    iget p3, p0, Lw3/z;->w:I

    .line 114
    .line 115
    invoke-static {p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 116
    .line 117
    .line 118
    move-result-object p3

    .line 119
    move-object v7, p3

    .line 120
    goto :goto_3

    .line 121
    :cond_7
    move-object v7, p1

    .line 122
    :goto_3
    if-eqz v3, :cond_8

    .line 123
    .line 124
    invoke-virtual {v9}, Ljava/lang/String;->length()I

    .line 125
    .line 126
    .line 127
    move-result p1

    .line 128
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 129
    .line 130
    .line 131
    move-result-object p1

    .line 132
    :cond_8
    move-object v4, p0

    .line 133
    move-object v8, p1

    .line 134
    invoke-virtual/range {v4 .. v9}, Lw3/z;->q(ILjava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/CharSequence;)Landroid/view/accessibility/AccessibilityEvent;

    .line 135
    .line 136
    .line 137
    move-result-object p0

    .line 138
    invoke-virtual {v4, p0}, Lw3/z;->C(Landroid/view/accessibility/AccessibilityEvent;)Z

    .line 139
    .line 140
    .line 141
    invoke-virtual {v4, v1}, Lw3/z;->G(I)V

    .line 142
    .line 143
    .line 144
    return p2
.end method

.method public final L(Ld4/q;Le6/d;)V
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    invoke-static/range {p1 .. p1}, Lw3/h0;->t(Ld4/q;)Lg4/g;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    if-eqz v1, :cond_20

    .line 8
    .line 9
    iget-object v2, v0, Lw3/z;->d:Lw3/t;

    .line 10
    .line 11
    invoke-virtual {v2}, Lw3/t;->getFontFamilyResolver()Lk4/m;

    .line 12
    .line 13
    .line 14
    move-result-object v3

    .line 15
    invoke-virtual {v2}, Lw3/t;->getDensity()Lt4/c;

    .line 16
    .line 17
    .line 18
    move-result-object v7

    .line 19
    new-instance v4, Landroid/text/SpannableString;

    .line 20
    .line 21
    iget-object v2, v1, Lg4/g;->e:Ljava/lang/String;

    .line 22
    .line 23
    iget-object v10, v1, Lg4/g;->d:Ljava/util/List;

    .line 24
    .line 25
    invoke-direct {v4, v2}, Landroid/text/SpannableString;-><init>(Ljava/lang/CharSequence;)V

    .line 26
    .line 27
    .line 28
    iget-object v11, v1, Lg4/g;->f:Ljava/util/ArrayList;

    .line 29
    .line 30
    if-eqz v11, :cond_10

    .line 31
    .line 32
    invoke-interface {v11}, Ljava/util/Collection;->size()I

    .line 33
    .line 34
    .line 35
    move-result v14

    .line 36
    const/4 v15, 0x0

    .line 37
    :goto_0
    if-ge v15, v14, :cond_10

    .line 38
    .line 39
    invoke-interface {v11, v15}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v5

    .line 43
    check-cast v5, Lg4/e;

    .line 44
    .line 45
    iget-object v6, v5, Lg4/e;->a:Ljava/lang/Object;

    .line 46
    .line 47
    check-cast v6, Lg4/g0;

    .line 48
    .line 49
    iget v8, v5, Lg4/e;->b:I

    .line 50
    .line 51
    iget v9, v5, Lg4/e;->c:I

    .line 52
    .line 53
    const-wide/16 v12, 0x0

    .line 54
    .line 55
    const v5, 0xffdf

    .line 56
    .line 57
    .line 58
    invoke-static {v6, v12, v13, v5}, Lg4/g0;->a(Lg4/g0;JI)Lg4/g0;

    .line 59
    .line 60
    .line 61
    move-result-object v12

    .line 62
    iget-object v5, v12, Lg4/g0;->a:Lr4/o;

    .line 63
    .line 64
    iget-object v13, v12, Lg4/g0;->j:Lr4/p;

    .line 65
    .line 66
    iget-object v6, v12, Lg4/g0;->m:Lr4/l;

    .line 67
    .line 68
    move-object/from16 v16, v2

    .line 69
    .line 70
    iget-object v2, v12, Lg4/g0;->f:Lk4/n;

    .line 71
    .line 72
    move-object/from16 v17, v3

    .line 73
    .line 74
    iget-object v3, v12, Lg4/g0;->d:Lk4/t;

    .line 75
    .line 76
    move-object/from16 v18, v6

    .line 77
    .line 78
    invoke-interface {v5}, Lr4/o;->a()J

    .line 79
    .line 80
    .line 81
    move-result-wide v5

    .line 82
    invoke-static {v4, v5, v6, v8, v9}, Ljp/fd;->g(Landroid/text/Spannable;JII)V

    .line 83
    .line 84
    .line 85
    iget-wide v5, v12, Lg4/g0;->b:J

    .line 86
    .line 87
    move-object/from16 v19, v11

    .line 88
    .line 89
    move-object/from16 v11, v18

    .line 90
    .line 91
    invoke-static/range {v4 .. v9}, Ljp/fd;->h(Landroid/text/Spannable;JLt4/c;II)V

    .line 92
    .line 93
    .line 94
    iget-object v5, v12, Lg4/g0;->c:Lk4/x;

    .line 95
    .line 96
    if-nez v5, :cond_1

    .line 97
    .line 98
    if-eqz v3, :cond_0

    .line 99
    .line 100
    goto :goto_1

    .line 101
    :cond_0
    move-object/from16 v18, v7

    .line 102
    .line 103
    const/16 v3, 0x21

    .line 104
    .line 105
    goto :goto_6

    .line 106
    :cond_1
    :goto_1
    if-nez v5, :cond_2

    .line 107
    .line 108
    sget-object v5, Lk4/x;->l:Lk4/x;

    .line 109
    .line 110
    :cond_2
    if-eqz v3, :cond_3

    .line 111
    .line 112
    iget v3, v3, Lk4/t;->a:I

    .line 113
    .line 114
    goto :goto_2

    .line 115
    :cond_3
    const/4 v3, 0x0

    .line 116
    :goto_2
    new-instance v6, Landroid/text/style/StyleSpan;

    .line 117
    .line 118
    move-object/from16 v18, v7

    .line 119
    .line 120
    sget-object v7, Lk4/x;->h:Lk4/x;

    .line 121
    .line 122
    invoke-virtual {v5, v7}, Lk4/x;->a(Lk4/x;)I

    .line 123
    .line 124
    .line 125
    move-result v5

    .line 126
    const/4 v7, 0x1

    .line 127
    if-ltz v5, :cond_4

    .line 128
    .line 129
    move v5, v7

    .line 130
    goto :goto_3

    .line 131
    :cond_4
    const/4 v5, 0x0

    .line 132
    :goto_3
    if-ne v3, v7, :cond_5

    .line 133
    .line 134
    move v3, v7

    .line 135
    goto :goto_4

    .line 136
    :cond_5
    const/4 v3, 0x0

    .line 137
    :goto_4
    if-eqz v3, :cond_6

    .line 138
    .line 139
    if-eqz v5, :cond_6

    .line 140
    .line 141
    const/4 v3, 0x3

    .line 142
    goto :goto_5

    .line 143
    :cond_6
    if-eqz v5, :cond_7

    .line 144
    .line 145
    move v3, v7

    .line 146
    goto :goto_5

    .line 147
    :cond_7
    if-eqz v3, :cond_8

    .line 148
    .line 149
    const/4 v3, 0x2

    .line 150
    goto :goto_5

    .line 151
    :cond_8
    const/4 v3, 0x0

    .line 152
    :goto_5
    invoke-direct {v6, v3}, Landroid/text/style/StyleSpan;-><init>(I)V

    .line 153
    .line 154
    .line 155
    const/16 v3, 0x21

    .line 156
    .line 157
    invoke-virtual {v4, v6, v8, v9, v3}, Landroid/text/SpannableString;->setSpan(Ljava/lang/Object;III)V

    .line 158
    .line 159
    .line 160
    :goto_6
    if-eqz v2, :cond_9

    .line 161
    .line 162
    instance-of v5, v2, Lk4/z;

    .line 163
    .line 164
    if-eqz v5, :cond_a

    .line 165
    .line 166
    new-instance v5, Landroid/text/style/TypefaceSpan;

    .line 167
    .line 168
    check-cast v2, Lk4/z;

    .line 169
    .line 170
    iget-object v2, v2, Lk4/z;->i:Ljava/lang/String;

    .line 171
    .line 172
    invoke-direct {v5, v2}, Landroid/text/style/TypefaceSpan;-><init>(Ljava/lang/String;)V

    .line 173
    .line 174
    .line 175
    invoke-virtual {v4, v5, v8, v9, v3}, Landroid/text/SpannableString;->setSpan(Ljava/lang/Object;III)V

    .line 176
    .line 177
    .line 178
    :cond_9
    move v2, v3

    .line 179
    goto :goto_8

    .line 180
    :cond_a
    iget-object v3, v12, Lg4/g0;->e:Lk4/u;

    .line 181
    .line 182
    if-eqz v3, :cond_b

    .line 183
    .line 184
    iget v3, v3, Lk4/u;->a:I

    .line 185
    .line 186
    goto :goto_7

    .line 187
    :cond_b
    const v3, 0xffff

    .line 188
    .line 189
    .line 190
    :goto_7
    sget-object v5, Lk4/x;->l:Lk4/x;

    .line 191
    .line 192
    move-object/from16 v6, v17

    .line 193
    .line 194
    check-cast v6, Lk4/o;

    .line 195
    .line 196
    const/4 v7, 0x0

    .line 197
    invoke-virtual {v6, v2, v5, v7, v3}, Lk4/o;->b(Lk4/n;Lk4/x;II)Lk4/i0;

    .line 198
    .line 199
    .line 200
    move-result-object v2

    .line 201
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 202
    .line 203
    .line 204
    move-result-object v2

    .line 205
    const-string v3, "null cannot be cast to non-null type android.graphics.Typeface"

    .line 206
    .line 207
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 208
    .line 209
    .line 210
    check-cast v2, Landroid/graphics/Typeface;

    .line 211
    .line 212
    new-instance v3, Landroid/text/style/TypefaceSpan;

    .line 213
    .line 214
    invoke-direct {v3, v2}, Landroid/text/style/TypefaceSpan;-><init>(Landroid/graphics/Typeface;)V

    .line 215
    .line 216
    .line 217
    const/16 v2, 0x21

    .line 218
    .line 219
    invoke-virtual {v4, v3, v8, v9, v2}, Landroid/text/SpannableString;->setSpan(Ljava/lang/Object;III)V

    .line 220
    .line 221
    .line 222
    :goto_8
    if-eqz v11, :cond_d

    .line 223
    .line 224
    iget v3, v11, Lr4/l;->a:I

    .line 225
    .line 226
    or-int/lit8 v5, v3, 0x1

    .line 227
    .line 228
    if-ne v5, v3, :cond_c

    .line 229
    .line 230
    new-instance v5, Landroid/text/style/UnderlineSpan;

    .line 231
    .line 232
    invoke-direct {v5}, Landroid/text/style/UnderlineSpan;-><init>()V

    .line 233
    .line 234
    .line 235
    invoke-virtual {v4, v5, v8, v9, v2}, Landroid/text/SpannableString;->setSpan(Ljava/lang/Object;III)V

    .line 236
    .line 237
    .line 238
    :cond_c
    or-int/lit8 v5, v3, 0x2

    .line 239
    .line 240
    if-ne v5, v3, :cond_d

    .line 241
    .line 242
    new-instance v3, Landroid/text/style/StrikethroughSpan;

    .line 243
    .line 244
    invoke-direct {v3}, Landroid/text/style/StrikethroughSpan;-><init>()V

    .line 245
    .line 246
    .line 247
    invoke-virtual {v4, v3, v8, v9, v2}, Landroid/text/SpannableString;->setSpan(Ljava/lang/Object;III)V

    .line 248
    .line 249
    .line 250
    :cond_d
    if-eqz v13, :cond_e

    .line 251
    .line 252
    new-instance v3, Landroid/text/style/ScaleXSpan;

    .line 253
    .line 254
    iget v5, v13, Lr4/p;->a:F

    .line 255
    .line 256
    invoke-direct {v3, v5}, Landroid/text/style/ScaleXSpan;-><init>(F)V

    .line 257
    .line 258
    .line 259
    invoke-virtual {v4, v3, v8, v9, v2}, Landroid/text/SpannableString;->setSpan(Ljava/lang/Object;III)V

    .line 260
    .line 261
    .line 262
    :cond_e
    iget-object v2, v12, Lg4/g0;->k:Ln4/b;

    .line 263
    .line 264
    invoke-static {v4, v2, v8, v9}, Ljp/fd;->i(Landroid/text/Spannable;Ln4/b;II)V

    .line 265
    .line 266
    .line 267
    iget-wide v2, v12, Lg4/g0;->l:J

    .line 268
    .line 269
    const-wide/16 v5, 0x10

    .line 270
    .line 271
    cmp-long v5, v2, v5

    .line 272
    .line 273
    if-eqz v5, :cond_f

    .line 274
    .line 275
    new-instance v5, Landroid/text/style/BackgroundColorSpan;

    .line 276
    .line 277
    invoke-static {v2, v3}, Le3/j0;->z(J)I

    .line 278
    .line 279
    .line 280
    move-result v2

    .line 281
    invoke-direct {v5, v2}, Landroid/text/style/BackgroundColorSpan;-><init>(I)V

    .line 282
    .line 283
    .line 284
    const/16 v2, 0x21

    .line 285
    .line 286
    invoke-virtual {v4, v5, v8, v9, v2}, Landroid/text/SpannableString;->setSpan(Ljava/lang/Object;III)V

    .line 287
    .line 288
    .line 289
    :cond_f
    add-int/lit8 v15, v15, 0x1

    .line 290
    .line 291
    move-object/from16 v2, v16

    .line 292
    .line 293
    move-object/from16 v3, v17

    .line 294
    .line 295
    move-object/from16 v7, v18

    .line 296
    .line 297
    move-object/from16 v11, v19

    .line 298
    .line 299
    goto/16 :goto_0

    .line 300
    .line 301
    :cond_10
    move-object/from16 v16, v2

    .line 302
    .line 303
    invoke-virtual/range {v16 .. v16}, Ljava/lang/String;->length()I

    .line 304
    .line 305
    .line 306
    move-result v2

    .line 307
    sget-object v3, Lmx0/s;->d:Lmx0/s;

    .line 308
    .line 309
    if-eqz v10, :cond_12

    .line 310
    .line 311
    new-instance v5, Ljava/util/ArrayList;

    .line 312
    .line 313
    invoke-interface {v10}, Ljava/util/List;->size()I

    .line 314
    .line 315
    .line 316
    move-result v6

    .line 317
    invoke-direct {v5, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 318
    .line 319
    .line 320
    move-object v6, v10

    .line 321
    check-cast v6, Ljava/util/Collection;

    .line 322
    .line 323
    invoke-interface {v6}, Ljava/util/Collection;->size()I

    .line 324
    .line 325
    .line 326
    move-result v6

    .line 327
    const/4 v7, 0x0

    .line 328
    :goto_9
    if-ge v7, v6, :cond_13

    .line 329
    .line 330
    invoke-interface {v10, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 331
    .line 332
    .line 333
    move-result-object v8

    .line 334
    move-object v9, v8

    .line 335
    check-cast v9, Lg4/e;

    .line 336
    .line 337
    iget-object v11, v9, Lg4/e;->a:Ljava/lang/Object;

    .line 338
    .line 339
    instance-of v11, v11, Lg4/r0;

    .line 340
    .line 341
    if-eqz v11, :cond_11

    .line 342
    .line 343
    iget v11, v9, Lg4/e;->b:I

    .line 344
    .line 345
    iget v9, v9, Lg4/e;->c:I

    .line 346
    .line 347
    const/4 v12, 0x0

    .line 348
    invoke-static {v12, v2, v11, v9}, Lg4/h;->b(IIII)Z

    .line 349
    .line 350
    .line 351
    move-result v9

    .line 352
    if-eqz v9, :cond_11

    .line 353
    .line 354
    invoke-virtual {v5, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 355
    .line 356
    .line 357
    :cond_11
    add-int/lit8 v7, v7, 0x1

    .line 358
    .line 359
    goto :goto_9

    .line 360
    :cond_12
    move-object v5, v3

    .line 361
    :cond_13
    move-object v2, v5

    .line 362
    check-cast v2, Ljava/util/Collection;

    .line 363
    .line 364
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 365
    .line 366
    .line 367
    move-result v2

    .line 368
    const/4 v7, 0x0

    .line 369
    :goto_a
    if-ge v7, v2, :cond_15

    .line 370
    .line 371
    invoke-interface {v5, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 372
    .line 373
    .line 374
    move-result-object v6

    .line 375
    check-cast v6, Lg4/e;

    .line 376
    .line 377
    iget-object v8, v6, Lg4/e;->a:Ljava/lang/Object;

    .line 378
    .line 379
    check-cast v8, Lg4/r0;

    .line 380
    .line 381
    iget v9, v6, Lg4/e;->b:I

    .line 382
    .line 383
    iget v6, v6, Lg4/e;->c:I

    .line 384
    .line 385
    instance-of v11, v8, Lg4/r0;

    .line 386
    .line 387
    if-eqz v11, :cond_14

    .line 388
    .line 389
    new-instance v11, Landroid/text/style/TtsSpan$VerbatimBuilder;

    .line 390
    .line 391
    iget-object v8, v8, Lg4/r0;->a:Ljava/lang/String;

    .line 392
    .line 393
    invoke-direct {v11, v8}, Landroid/text/style/TtsSpan$VerbatimBuilder;-><init>(Ljava/lang/String;)V

    .line 394
    .line 395
    .line 396
    invoke-virtual {v11}, Landroid/text/style/TtsSpan$Builder;->build()Landroid/text/style/TtsSpan;

    .line 397
    .line 398
    .line 399
    move-result-object v8

    .line 400
    const/16 v11, 0x21

    .line 401
    .line 402
    invoke-virtual {v4, v8, v9, v6, v11}, Landroid/text/SpannableString;->setSpan(Ljava/lang/Object;III)V

    .line 403
    .line 404
    .line 405
    add-int/lit8 v7, v7, 0x1

    .line 406
    .line 407
    goto :goto_a

    .line 408
    :cond_14
    new-instance v0, La8/r0;

    .line 409
    .line 410
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 411
    .line 412
    .line 413
    throw v0

    .line 414
    :cond_15
    invoke-virtual/range {v16 .. v16}, Ljava/lang/String;->length()I

    .line 415
    .line 416
    .line 417
    move-result v2

    .line 418
    if-eqz v10, :cond_18

    .line 419
    .line 420
    new-instance v3, Ljava/util/ArrayList;

    .line 421
    .line 422
    invoke-interface {v10}, Ljava/util/List;->size()I

    .line 423
    .line 424
    .line 425
    move-result v5

    .line 426
    invoke-direct {v3, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 427
    .line 428
    .line 429
    move-object v5, v10

    .line 430
    check-cast v5, Ljava/util/Collection;

    .line 431
    .line 432
    invoke-interface {v5}, Ljava/util/Collection;->size()I

    .line 433
    .line 434
    .line 435
    move-result v5

    .line 436
    const/4 v7, 0x0

    .line 437
    :goto_b
    if-ge v7, v5, :cond_18

    .line 438
    .line 439
    invoke-interface {v10, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 440
    .line 441
    .line 442
    move-result-object v6

    .line 443
    move-object v8, v6

    .line 444
    check-cast v8, Lg4/e;

    .line 445
    .line 446
    iget-object v9, v8, Lg4/e;->a:Ljava/lang/Object;

    .line 447
    .line 448
    instance-of v9, v9, Lg4/q0;

    .line 449
    .line 450
    if-eqz v9, :cond_16

    .line 451
    .line 452
    iget v9, v8, Lg4/e;->b:I

    .line 453
    .line 454
    iget v8, v8, Lg4/e;->c:I

    .line 455
    .line 456
    const/4 v12, 0x0

    .line 457
    invoke-static {v12, v2, v9, v8}, Lg4/h;->b(IIII)Z

    .line 458
    .line 459
    .line 460
    move-result v8

    .line 461
    if-eqz v8, :cond_17

    .line 462
    .line 463
    invoke-virtual {v3, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 464
    .line 465
    .line 466
    goto :goto_c

    .line 467
    :cond_16
    const/4 v12, 0x0

    .line 468
    :cond_17
    :goto_c
    add-int/lit8 v7, v7, 0x1

    .line 469
    .line 470
    goto :goto_b

    .line 471
    :cond_18
    const/4 v12, 0x0

    .line 472
    move-object v2, v3

    .line 473
    check-cast v2, Ljava/util/Collection;

    .line 474
    .line 475
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 476
    .line 477
    .line 478
    move-result v2

    .line 479
    move v7, v12

    .line 480
    :goto_d
    iget-object v5, v0, Lw3/z;->I:Lil/g;

    .line 481
    .line 482
    if-ge v7, v2, :cond_1a

    .line 483
    .line 484
    invoke-interface {v3, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 485
    .line 486
    .line 487
    move-result-object v6

    .line 488
    check-cast v6, Lg4/e;

    .line 489
    .line 490
    iget-object v8, v6, Lg4/e;->a:Ljava/lang/Object;

    .line 491
    .line 492
    check-cast v8, Lg4/q0;

    .line 493
    .line 494
    iget v9, v6, Lg4/e;->b:I

    .line 495
    .line 496
    iget v6, v6, Lg4/e;->c:I

    .line 497
    .line 498
    iget-object v5, v5, Lil/g;->e:Ljava/lang/Object;

    .line 499
    .line 500
    check-cast v5, Ljava/util/WeakHashMap;

    .line 501
    .line 502
    invoke-virtual {v5, v8}, Ljava/util/WeakHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 503
    .line 504
    .line 505
    move-result-object v10

    .line 506
    if-nez v10, :cond_19

    .line 507
    .line 508
    new-instance v10, Landroid/text/style/URLSpan;

    .line 509
    .line 510
    iget-object v11, v8, Lg4/q0;->a:Ljava/lang/String;

    .line 511
    .line 512
    invoke-direct {v10, v11}, Landroid/text/style/URLSpan;-><init>(Ljava/lang/String;)V

    .line 513
    .line 514
    .line 515
    invoke-virtual {v5, v8, v10}, Ljava/util/WeakHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 516
    .line 517
    .line 518
    :cond_19
    check-cast v10, Landroid/text/style/URLSpan;

    .line 519
    .line 520
    const/16 v11, 0x21

    .line 521
    .line 522
    invoke-virtual {v4, v10, v9, v6, v11}, Landroid/text/SpannableString;->setSpan(Ljava/lang/Object;III)V

    .line 523
    .line 524
    .line 525
    add-int/lit8 v7, v7, 0x1

    .line 526
    .line 527
    goto :goto_d

    .line 528
    :cond_1a
    invoke-virtual/range {v16 .. v16}, Ljava/lang/String;->length()I

    .line 529
    .line 530
    .line 531
    move-result v0

    .line 532
    invoke-virtual {v1, v0}, Lg4/g;->a(I)Ljava/util/List;

    .line 533
    .line 534
    .line 535
    move-result-object v0

    .line 536
    move-object v1, v0

    .line 537
    check-cast v1, Ljava/util/Collection;

    .line 538
    .line 539
    invoke-interface {v1}, Ljava/util/Collection;->size()I

    .line 540
    .line 541
    .line 542
    move-result v1

    .line 543
    :goto_e
    if-ge v12, v1, :cond_1f

    .line 544
    .line 545
    invoke-interface {v0, v12}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 546
    .line 547
    .line 548
    move-result-object v2

    .line 549
    check-cast v2, Lg4/e;

    .line 550
    .line 551
    iget v3, v2, Lg4/e;->b:I

    .line 552
    .line 553
    iget-object v6, v2, Lg4/e;->a:Ljava/lang/Object;

    .line 554
    .line 555
    iget v7, v2, Lg4/e;->c:I

    .line 556
    .line 557
    if-eq v3, v7, :cond_1e

    .line 558
    .line 559
    move-object v8, v6

    .line 560
    check-cast v8, Lg4/n;

    .line 561
    .line 562
    instance-of v9, v8, Lg4/m;

    .line 563
    .line 564
    if-eqz v9, :cond_1c

    .line 565
    .line 566
    move-object v9, v8

    .line 567
    check-cast v9, Lg4/m;

    .line 568
    .line 569
    iget-object v9, v9, Lg4/m;->c:Lxf0/x1;

    .line 570
    .line 571
    if-nez v9, :cond_1c

    .line 572
    .line 573
    new-instance v2, Lg4/e;

    .line 574
    .line 575
    const-string v8, "null cannot be cast to non-null type androidx.compose.ui.text.LinkAnnotation.Url"

    .line 576
    .line 577
    invoke-static {v6, v8}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 578
    .line 579
    .line 580
    check-cast v6, Lg4/m;

    .line 581
    .line 582
    invoke-direct {v2, v6, v3, v7}, Lg4/e;-><init>(Ljava/lang/Object;II)V

    .line 583
    .line 584
    .line 585
    iget-object v8, v5, Lil/g;->f:Ljava/lang/Object;

    .line 586
    .line 587
    check-cast v8, Ljava/util/WeakHashMap;

    .line 588
    .line 589
    invoke-virtual {v8, v2}, Ljava/util/WeakHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 590
    .line 591
    .line 592
    move-result-object v9

    .line 593
    if-nez v9, :cond_1b

    .line 594
    .line 595
    new-instance v9, Landroid/text/style/URLSpan;

    .line 596
    .line 597
    iget-object v6, v6, Lg4/m;->a:Ljava/lang/String;

    .line 598
    .line 599
    invoke-direct {v9, v6}, Landroid/text/style/URLSpan;-><init>(Ljava/lang/String;)V

    .line 600
    .line 601
    .line 602
    invoke-virtual {v8, v2, v9}, Ljava/util/WeakHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 603
    .line 604
    .line 605
    :cond_1b
    check-cast v9, Landroid/text/style/URLSpan;

    .line 606
    .line 607
    const/16 v2, 0x21

    .line 608
    .line 609
    invoke-virtual {v4, v9, v3, v7, v2}, Landroid/text/SpannableString;->setSpan(Ljava/lang/Object;III)V

    .line 610
    .line 611
    .line 612
    goto :goto_f

    .line 613
    :cond_1c
    iget-object v6, v5, Lil/g;->g:Ljava/lang/Object;

    .line 614
    .line 615
    check-cast v6, Ljava/util/WeakHashMap;

    .line 616
    .line 617
    invoke-virtual {v6, v2}, Ljava/util/WeakHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 618
    .line 619
    .line 620
    move-result-object v9

    .line 621
    if-nez v9, :cond_1d

    .line 622
    .line 623
    new-instance v9, Lo4/e;

    .line 624
    .line 625
    invoke-direct {v9, v8}, Lo4/e;-><init>(Lg4/n;)V

    .line 626
    .line 627
    .line 628
    invoke-virtual {v6, v2, v9}, Ljava/util/WeakHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 629
    .line 630
    .line 631
    :cond_1d
    check-cast v9, Landroid/text/style/ClickableSpan;

    .line 632
    .line 633
    const/16 v2, 0x21

    .line 634
    .line 635
    invoke-virtual {v4, v9, v3, v7, v2}, Landroid/text/SpannableString;->setSpan(Ljava/lang/Object;III)V

    .line 636
    .line 637
    .line 638
    goto :goto_f

    .line 639
    :cond_1e
    const/16 v2, 0x21

    .line 640
    .line 641
    :goto_f
    add-int/lit8 v12, v12, 0x1

    .line 642
    .line 643
    goto :goto_e

    .line 644
    :cond_1f
    invoke-static {v4}, Lw3/z;->P(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    .line 645
    .line 646
    .line 647
    move-result-object v0

    .line 648
    check-cast v0, Landroid/text/SpannableString;

    .line 649
    .line 650
    :goto_10
    move-object/from16 v1, p2

    .line 651
    .line 652
    goto :goto_11

    .line 653
    :cond_20
    const/4 v0, 0x0

    .line 654
    goto :goto_10

    .line 655
    :goto_11
    invoke-virtual {v1, v0}, Le6/d;->l(Ljava/lang/CharSequence;)V

    .line 656
    .line 657
    .line 658
    return-void
.end method

.method public final Q()V
    .locals 32

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    new-instance v1, Landroidx/collection/c0;

    .line 4
    .line 5
    invoke-direct {v1}, Landroidx/collection/c0;-><init>()V

    .line 6
    .line 7
    .line 8
    iget-object v2, v0, Lw3/z;->D:Landroidx/collection/c0;

    .line 9
    .line 10
    iget-object v3, v2, Landroidx/collection/c0;->b:[I

    .line 11
    .line 12
    iget-object v4, v2, Landroidx/collection/c0;->a:[J

    .line 13
    .line 14
    array-length v5, v4

    .line 15
    add-int/lit8 v5, v5, -0x2

    .line 16
    .line 17
    iget-object v6, v0, Lw3/z;->J:Landroidx/collection/b0;

    .line 18
    .line 19
    const/16 v14, 0x8

    .line 20
    .line 21
    if-ltz v5, :cond_8

    .line 22
    .line 23
    const/4 v7, 0x0

    .line 24
    const-wide/16 v16, 0x80

    .line 25
    .line 26
    const-wide/16 v18, 0xff

    .line 27
    .line 28
    :goto_0
    aget-wide v9, v4, v7

    .line 29
    .line 30
    const/4 v8, 0x7

    .line 31
    const-wide v20, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 32
    .line 33
    .line 34
    .line 35
    .line 36
    not-long v11, v9

    .line 37
    shl-long/2addr v11, v8

    .line 38
    and-long/2addr v11, v9

    .line 39
    and-long v11, v11, v20

    .line 40
    .line 41
    cmp-long v11, v11, v20

    .line 42
    .line 43
    if-eqz v11, :cond_7

    .line 44
    .line 45
    sub-int v11, v7, v5

    .line 46
    .line 47
    not-int v11, v11

    .line 48
    ushr-int/lit8 v11, v11, 0x1f

    .line 49
    .line 50
    rsub-int/lit8 v11, v11, 0x8

    .line 51
    .line 52
    const/4 v12, 0x0

    .line 53
    :goto_1
    if-ge v12, v11, :cond_6

    .line 54
    .line 55
    and-long v22, v9, v18

    .line 56
    .line 57
    cmp-long v13, v22, v16

    .line 58
    .line 59
    if-gez v13, :cond_4

    .line 60
    .line 61
    shl-int/lit8 v13, v7, 0x3

    .line 62
    .line 63
    add-int/2addr v13, v12

    .line 64
    aget v13, v3, v13

    .line 65
    .line 66
    move/from16 v22, v8

    .line 67
    .line 68
    invoke-virtual {v0}, Lw3/z;->t()Landroidx/collection/p;

    .line 69
    .line 70
    .line 71
    move-result-object v8

    .line 72
    invoke-virtual {v8, v13}, Landroidx/collection/p;->b(I)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object v8

    .line 76
    check-cast v8, Ld4/r;

    .line 77
    .line 78
    const/16 v23, 0x0

    .line 79
    .line 80
    if-eqz v8, :cond_0

    .line 81
    .line 82
    iget-object v8, v8, Ld4/r;->a:Ld4/q;

    .line 83
    .line 84
    goto :goto_2

    .line 85
    :cond_0
    move-object/from16 v8, v23

    .line 86
    .line 87
    :goto_2
    if-eqz v8, :cond_1

    .line 88
    .line 89
    iget-object v8, v8, Ld4/q;->d:Ld4/l;

    .line 90
    .line 91
    sget-object v15, Ld4/v;->d:Ld4/z;

    .line 92
    .line 93
    iget-object v8, v8, Ld4/l;->d:Landroidx/collection/q0;

    .line 94
    .line 95
    invoke-virtual {v8, v15}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 96
    .line 97
    .line 98
    move-result v8

    .line 99
    if-nez v8, :cond_5

    .line 100
    .line 101
    :cond_1
    invoke-virtual {v1, v13}, Landroidx/collection/c0;->a(I)Z

    .line 102
    .line 103
    .line 104
    invoke-virtual {v6, v13}, Landroidx/collection/p;->b(I)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v8

    .line 108
    check-cast v8, Lw3/a2;

    .line 109
    .line 110
    if-eqz v8, :cond_3

    .line 111
    .line 112
    iget-object v8, v8, Lw3/a2;->a:Ld4/l;

    .line 113
    .line 114
    sget-object v15, Ld4/v;->d:Ld4/z;

    .line 115
    .line 116
    iget-object v8, v8, Ld4/l;->d:Landroidx/collection/q0;

    .line 117
    .line 118
    invoke-virtual {v8, v15}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v8

    .line 122
    if-nez v8, :cond_2

    .line 123
    .line 124
    goto :goto_3

    .line 125
    :cond_2
    move-object/from16 v23, v8

    .line 126
    .line 127
    :goto_3
    check-cast v23, Ljava/lang/String;

    .line 128
    .line 129
    :cond_3
    move-object/from16 v8, v23

    .line 130
    .line 131
    const/16 v15, 0x20

    .line 132
    .line 133
    invoke-virtual {v0, v13, v15, v8}, Lw3/z;->F(IILjava/lang/String;)V

    .line 134
    .line 135
    .line 136
    goto :goto_4

    .line 137
    :cond_4
    move/from16 v22, v8

    .line 138
    .line 139
    :cond_5
    :goto_4
    shr-long/2addr v9, v14

    .line 140
    add-int/lit8 v12, v12, 0x1

    .line 141
    .line 142
    move/from16 v8, v22

    .line 143
    .line 144
    goto :goto_1

    .line 145
    :cond_6
    move/from16 v22, v8

    .line 146
    .line 147
    if-ne v11, v14, :cond_9

    .line 148
    .line 149
    goto :goto_5

    .line 150
    :cond_7
    move/from16 v22, v8

    .line 151
    .line 152
    :goto_5
    if-eq v7, v5, :cond_9

    .line 153
    .line 154
    add-int/lit8 v7, v7, 0x1

    .line 155
    .line 156
    goto/16 :goto_0

    .line 157
    .line 158
    :cond_8
    const-wide/16 v16, 0x80

    .line 159
    .line 160
    const-wide/16 v18, 0xff

    .line 161
    .line 162
    const-wide v20, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 163
    .line 164
    .line 165
    .line 166
    .line 167
    const/16 v22, 0x7

    .line 168
    .line 169
    :cond_9
    iget-object v3, v1, Landroidx/collection/c0;->b:[I

    .line 170
    .line 171
    iget-object v1, v1, Landroidx/collection/c0;->a:[J

    .line 172
    .line 173
    array-length v4, v1

    .line 174
    add-int/lit8 v4, v4, -0x2

    .line 175
    .line 176
    if-ltz v4, :cond_11

    .line 177
    .line 178
    const/4 v5, 0x0

    .line 179
    :goto_6
    aget-wide v7, v1, v5

    .line 180
    .line 181
    not-long v9, v7

    .line 182
    shl-long v9, v9, v22

    .line 183
    .line 184
    and-long/2addr v9, v7

    .line 185
    and-long v9, v9, v20

    .line 186
    .line 187
    cmp-long v9, v9, v20

    .line 188
    .line 189
    if-eqz v9, :cond_10

    .line 190
    .line 191
    sub-int v9, v5, v4

    .line 192
    .line 193
    not-int v9, v9

    .line 194
    ushr-int/lit8 v9, v9, 0x1f

    .line 195
    .line 196
    rsub-int/lit8 v9, v9, 0x8

    .line 197
    .line 198
    const/4 v10, 0x0

    .line 199
    :goto_7
    if-ge v10, v9, :cond_f

    .line 200
    .line 201
    and-long v11, v7, v18

    .line 202
    .line 203
    cmp-long v11, v11, v16

    .line 204
    .line 205
    if-gez v11, :cond_d

    .line 206
    .line 207
    shl-int/lit8 v11, v5, 0x3

    .line 208
    .line 209
    add-int/2addr v11, v10

    .line 210
    aget v11, v3, v11

    .line 211
    .line 212
    invoke-static {v11}, Ljava/lang/Integer;->hashCode(I)I

    .line 213
    .line 214
    .line 215
    move-result v12

    .line 216
    const v13, -0x3361d2af    # -8.2930312E7f

    .line 217
    .line 218
    .line 219
    mul-int/2addr v12, v13

    .line 220
    shl-int/lit8 v13, v12, 0x10

    .line 221
    .line 222
    xor-int/2addr v12, v13

    .line 223
    and-int/lit8 v13, v12, 0x7f

    .line 224
    .line 225
    iget v15, v2, Landroidx/collection/c0;->c:I

    .line 226
    .line 227
    ushr-int/lit8 v12, v12, 0x7

    .line 228
    .line 229
    and-int/2addr v12, v15

    .line 230
    move/from16 v24, v14

    .line 231
    .line 232
    const/16 v23, 0x0

    .line 233
    .line 234
    :goto_8
    iget-object v14, v2, Landroidx/collection/c0;->a:[J

    .line 235
    .line 236
    shr-int/lit8 v25, v12, 0x3

    .line 237
    .line 238
    and-int/lit8 v26, v12, 0x7

    .line 239
    .line 240
    move-object/from16 v27, v1

    .line 241
    .line 242
    shl-int/lit8 v1, v26, 0x3

    .line 243
    .line 244
    aget-wide v28, v14, v25

    .line 245
    .line 246
    ushr-long v28, v28, v1

    .line 247
    .line 248
    add-int/lit8 v25, v25, 0x1

    .line 249
    .line 250
    aget-wide v25, v14, v25

    .line 251
    .line 252
    rsub-int/lit8 v14, v1, 0x40

    .line 253
    .line 254
    shl-long v25, v25, v14

    .line 255
    .line 256
    move-wide/from16 v30, v7

    .line 257
    .line 258
    int-to-long v7, v1

    .line 259
    neg-long v7, v7

    .line 260
    const/16 v1, 0x3f

    .line 261
    .line 262
    shr-long/2addr v7, v1

    .line 263
    and-long v7, v25, v7

    .line 264
    .line 265
    or-long v7, v28, v7

    .line 266
    .line 267
    move v1, v15

    .line 268
    int-to-long v14, v13

    .line 269
    const-wide v25, 0x101010101010101L

    .line 270
    .line 271
    .line 272
    .line 273
    .line 274
    mul-long v14, v14, v25

    .line 275
    .line 276
    xor-long/2addr v14, v7

    .line 277
    sub-long v25, v14, v25

    .line 278
    .line 279
    not-long v14, v14

    .line 280
    and-long v14, v25, v14

    .line 281
    .line 282
    and-long v14, v14, v20

    .line 283
    .line 284
    :goto_9
    const-wide/16 v25, 0x0

    .line 285
    .line 286
    cmp-long v28, v14, v25

    .line 287
    .line 288
    if-eqz v28, :cond_b

    .line 289
    .line 290
    invoke-static {v14, v15}, Ljava/lang/Long;->numberOfTrailingZeros(J)I

    .line 291
    .line 292
    .line 293
    move-result v25

    .line 294
    shr-int/lit8 v25, v25, 0x3

    .line 295
    .line 296
    add-int v25, v12, v25

    .line 297
    .line 298
    and-int v25, v25, v1

    .line 299
    .line 300
    move/from16 v28, v1

    .line 301
    .line 302
    iget-object v1, v2, Landroidx/collection/c0;->b:[I

    .line 303
    .line 304
    aget v1, v1, v25

    .line 305
    .line 306
    if-ne v1, v11, :cond_a

    .line 307
    .line 308
    :goto_a
    move/from16 v1, v25

    .line 309
    .line 310
    goto :goto_b

    .line 311
    :cond_a
    const-wide/16 v25, 0x1

    .line 312
    .line 313
    sub-long v25, v14, v25

    .line 314
    .line 315
    and-long v14, v14, v25

    .line 316
    .line 317
    move/from16 v1, v28

    .line 318
    .line 319
    goto :goto_9

    .line 320
    :cond_b
    move/from16 v28, v1

    .line 321
    .line 322
    not-long v14, v7

    .line 323
    const/4 v1, 0x6

    .line 324
    shl-long/2addr v14, v1

    .line 325
    and-long/2addr v7, v14

    .line 326
    and-long v7, v7, v20

    .line 327
    .line 328
    cmp-long v1, v7, v25

    .line 329
    .line 330
    if-eqz v1, :cond_c

    .line 331
    .line 332
    const/16 v25, -0x1

    .line 333
    .line 334
    goto :goto_a

    .line 335
    :goto_b
    if-ltz v1, :cond_e

    .line 336
    .line 337
    invoke-virtual {v2, v1}, Landroidx/collection/c0;->f(I)V

    .line 338
    .line 339
    .line 340
    goto :goto_c

    .line 341
    :cond_c
    add-int/lit8 v23, v23, 0x8

    .line 342
    .line 343
    add-int v12, v12, v23

    .line 344
    .line 345
    and-int v12, v12, v28

    .line 346
    .line 347
    move-object/from16 v1, v27

    .line 348
    .line 349
    move/from16 v15, v28

    .line 350
    .line 351
    move-wide/from16 v7, v30

    .line 352
    .line 353
    goto :goto_8

    .line 354
    :cond_d
    move-object/from16 v27, v1

    .line 355
    .line 356
    move-wide/from16 v30, v7

    .line 357
    .line 358
    move/from16 v24, v14

    .line 359
    .line 360
    :cond_e
    :goto_c
    shr-long v7, v30, v24

    .line 361
    .line 362
    add-int/lit8 v10, v10, 0x1

    .line 363
    .line 364
    move/from16 v14, v24

    .line 365
    .line 366
    move-object/from16 v1, v27

    .line 367
    .line 368
    goto/16 :goto_7

    .line 369
    .line 370
    :cond_f
    move-object/from16 v27, v1

    .line 371
    .line 372
    move v1, v14

    .line 373
    if-ne v9, v1, :cond_11

    .line 374
    .line 375
    goto :goto_d

    .line 376
    :cond_10
    move-object/from16 v27, v1

    .line 377
    .line 378
    :goto_d
    if-eq v5, v4, :cond_11

    .line 379
    .line 380
    add-int/lit8 v5, v5, 0x1

    .line 381
    .line 382
    move-object/from16 v1, v27

    .line 383
    .line 384
    const/16 v14, 0x8

    .line 385
    .line 386
    goto/16 :goto_6

    .line 387
    .line 388
    :cond_11
    invoke-virtual {v6}, Landroidx/collection/b0;->c()V

    .line 389
    .line 390
    .line 391
    invoke-virtual {v0}, Lw3/z;->t()Landroidx/collection/p;

    .line 392
    .line 393
    .line 394
    move-result-object v1

    .line 395
    iget-object v3, v1, Landroidx/collection/p;->b:[I

    .line 396
    .line 397
    iget-object v4, v1, Landroidx/collection/p;->c:[Ljava/lang/Object;

    .line 398
    .line 399
    iget-object v1, v1, Landroidx/collection/p;->a:[J

    .line 400
    .line 401
    array-length v5, v1

    .line 402
    add-int/lit8 v5, v5, -0x2

    .line 403
    .line 404
    if-ltz v5, :cond_16

    .line 405
    .line 406
    const/4 v7, 0x0

    .line 407
    :goto_e
    aget-wide v8, v1, v7

    .line 408
    .line 409
    not-long v10, v8

    .line 410
    shl-long v10, v10, v22

    .line 411
    .line 412
    and-long/2addr v10, v8

    .line 413
    and-long v10, v10, v20

    .line 414
    .line 415
    cmp-long v10, v10, v20

    .line 416
    .line 417
    if-eqz v10, :cond_15

    .line 418
    .line 419
    sub-int v10, v7, v5

    .line 420
    .line 421
    not-int v10, v10

    .line 422
    ushr-int/lit8 v10, v10, 0x1f

    .line 423
    .line 424
    const/16 v24, 0x8

    .line 425
    .line 426
    rsub-int/lit8 v14, v10, 0x8

    .line 427
    .line 428
    const/4 v10, 0x0

    .line 429
    :goto_f
    if-ge v10, v14, :cond_14

    .line 430
    .line 431
    and-long v11, v8, v18

    .line 432
    .line 433
    cmp-long v11, v11, v16

    .line 434
    .line 435
    if-gez v11, :cond_13

    .line 436
    .line 437
    shl-int/lit8 v11, v7, 0x3

    .line 438
    .line 439
    add-int/2addr v11, v10

    .line 440
    aget v12, v3, v11

    .line 441
    .line 442
    aget-object v11, v4, v11

    .line 443
    .line 444
    check-cast v11, Ld4/r;

    .line 445
    .line 446
    iget-object v11, v11, Ld4/r;->a:Ld4/q;

    .line 447
    .line 448
    iget-object v13, v11, Ld4/q;->d:Ld4/l;

    .line 449
    .line 450
    sget-object v15, Ld4/v;->d:Ld4/z;

    .line 451
    .line 452
    iget-object v13, v13, Ld4/l;->d:Landroidx/collection/q0;

    .line 453
    .line 454
    invoke-virtual {v13, v15}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 455
    .line 456
    .line 457
    move-result v13

    .line 458
    if-eqz v13, :cond_12

    .line 459
    .line 460
    invoke-virtual {v2, v12}, Landroidx/collection/c0;->a(I)Z

    .line 461
    .line 462
    .line 463
    move-result v13

    .line 464
    if-eqz v13, :cond_12

    .line 465
    .line 466
    iget-object v13, v11, Ld4/q;->d:Ld4/l;

    .line 467
    .line 468
    invoke-virtual {v13, v15}, Ld4/l;->e(Ld4/z;)Ljava/lang/Object;

    .line 469
    .line 470
    .line 471
    move-result-object v13

    .line 472
    check-cast v13, Ljava/lang/String;

    .line 473
    .line 474
    const/16 v15, 0x10

    .line 475
    .line 476
    invoke-virtual {v0, v12, v15, v13}, Lw3/z;->F(IILjava/lang/String;)V

    .line 477
    .line 478
    .line 479
    :cond_12
    new-instance v13, Lw3/a2;

    .line 480
    .line 481
    invoke-virtual {v0}, Lw3/z;->t()Landroidx/collection/p;

    .line 482
    .line 483
    .line 484
    move-result-object v15

    .line 485
    invoke-direct {v13, v11, v15}, Lw3/a2;-><init>(Ld4/q;Landroidx/collection/p;)V

    .line 486
    .line 487
    .line 488
    invoke-virtual {v6, v12, v13}, Landroidx/collection/b0;->h(ILjava/lang/Object;)V

    .line 489
    .line 490
    .line 491
    :cond_13
    const/16 v11, 0x8

    .line 492
    .line 493
    shr-long/2addr v8, v11

    .line 494
    add-int/lit8 v10, v10, 0x1

    .line 495
    .line 496
    goto :goto_f

    .line 497
    :cond_14
    const/16 v11, 0x8

    .line 498
    .line 499
    if-ne v14, v11, :cond_16

    .line 500
    .line 501
    goto :goto_10

    .line 502
    :cond_15
    const/16 v11, 0x8

    .line 503
    .line 504
    :goto_10
    if-eq v7, v5, :cond_16

    .line 505
    .line 506
    add-int/lit8 v7, v7, 0x1

    .line 507
    .line 508
    goto :goto_e

    .line 509
    :cond_16
    new-instance v1, Lw3/a2;

    .line 510
    .line 511
    iget-object v2, v0, Lw3/z;->d:Lw3/t;

    .line 512
    .line 513
    invoke-virtual {v2}, Lw3/t;->getSemanticsOwner()Ld4/s;

    .line 514
    .line 515
    .line 516
    move-result-object v2

    .line 517
    invoke-virtual {v2}, Ld4/s;->a()Ld4/q;

    .line 518
    .line 519
    .line 520
    move-result-object v2

    .line 521
    invoke-virtual {v0}, Lw3/z;->t()Landroidx/collection/p;

    .line 522
    .line 523
    .line 524
    move-result-object v3

    .line 525
    invoke-direct {v1, v2, v3}, Lw3/a2;-><init>(Ld4/q;Landroidx/collection/p;)V

    .line 526
    .line 527
    .line 528
    iput-object v1, v0, Lw3/z;->K:Lw3/a2;

    .line 529
    .line 530
    return-void
.end method

.method public final b(Landroid/view/View;)Lbu/c;
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/z;->m:Lk6/a;

    .line 2
    .line 3
    return-object p0
.end method

.method public final j(ILe6/d;Ljava/lang/String;Landroid/os/Bundle;)V
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p3

    .line 6
    .line 7
    move-object/from16 v3, p2

    .line 8
    .line 9
    move-object/from16 v4, p4

    .line 10
    .line 11
    iget-object v3, v3, Le6/d;->a:Landroid/view/accessibility/AccessibilityNodeInfo;

    .line 12
    .line 13
    invoke-virtual {v0}, Lw3/z;->t()Landroidx/collection/p;

    .line 14
    .line 15
    .line 16
    move-result-object v5

    .line 17
    invoke-virtual {v5, v1}, Landroidx/collection/p;->b(I)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v5

    .line 21
    check-cast v5, Ld4/r;

    .line 22
    .line 23
    if-eqz v5, :cond_1b

    .line 24
    .line 25
    iget-object v5, v5, Ld4/r;->a:Ld4/q;

    .line 26
    .line 27
    if-nez v5, :cond_0

    .line 28
    .line 29
    goto/16 :goto_c

    .line 30
    .line 31
    :cond_0
    iget-object v6, v5, Ld4/q;->d:Ld4/l;

    .line 32
    .line 33
    iget-object v7, v6, Ld4/l;->d:Landroidx/collection/q0;

    .line 34
    .line 35
    invoke-static {v5}, Lw3/z;->u(Ld4/q;)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object v8

    .line 39
    iget-object v9, v0, Lw3/z;->G:Ljava/lang/String;

    .line 40
    .line 41
    invoke-static {v2, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result v9

    .line 45
    const/4 v10, -0x1

    .line 46
    if-eqz v9, :cond_1

    .line 47
    .line 48
    iget-object v0, v0, Lw3/z;->E:Landroidx/collection/z;

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Landroidx/collection/z;->d(I)I

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    if-eq v0, v10, :cond_1b

    .line 55
    .line 56
    invoke-virtual {v3}, Landroid/view/accessibility/AccessibilityNodeInfo;->getExtras()Landroid/os/Bundle;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    invoke-virtual {v1, v2, v0}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 61
    .line 62
    .line 63
    return-void

    .line 64
    :cond_1
    iget-object v9, v0, Lw3/z;->H:Ljava/lang/String;

    .line 65
    .line 66
    invoke-static {v2, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    move-result v9

    .line 70
    if-eqz v9, :cond_2

    .line 71
    .line 72
    iget-object v0, v0, Lw3/z;->F:Landroidx/collection/z;

    .line 73
    .line 74
    invoke-virtual {v0, v1}, Landroidx/collection/z;->d(I)I

    .line 75
    .line 76
    .line 77
    move-result v0

    .line 78
    if-eq v0, v10, :cond_1b

    .line 79
    .line 80
    invoke-virtual {v3}, Landroid/view/accessibility/AccessibilityNodeInfo;->getExtras()Landroid/os/Bundle;

    .line 81
    .line 82
    .line 83
    move-result-object v1

    .line 84
    invoke-virtual {v1, v2, v0}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 85
    .line 86
    .line 87
    return-void

    .line 88
    :cond_2
    sget-object v1, Ld4/k;->a:Ld4/z;

    .line 89
    .line 90
    invoke-virtual {v7, v1}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    move-result v1

    .line 94
    const/4 v9, 0x0

    .line 95
    if-eqz v1, :cond_d

    .line 96
    .line 97
    if-eqz v4, :cond_d

    .line 98
    .line 99
    const-string v1, "android.view.accessibility.extra.DATA_TEXT_CHARACTER_LOCATION_KEY"

    .line 100
    .line 101
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    move-result v1

    .line 105
    if-eqz v1, :cond_d

    .line 106
    .line 107
    const-string v1, "android.view.accessibility.extra.DATA_TEXT_CHARACTER_LOCATION_ARG_START_INDEX"

    .line 108
    .line 109
    invoke-virtual {v4, v1, v10}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;I)I

    .line 110
    .line 111
    .line 112
    move-result v1

    .line 113
    const-string v7, "android.view.accessibility.extra.DATA_TEXT_CHARACTER_LOCATION_ARG_LENGTH"

    .line 114
    .line 115
    invoke-virtual {v4, v7, v10}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;I)I

    .line 116
    .line 117
    .line 118
    move-result v4

    .line 119
    if-lez v4, :cond_c

    .line 120
    .line 121
    if-ltz v1, :cond_c

    .line 122
    .line 123
    if-eqz v8, :cond_3

    .line 124
    .line 125
    invoke-virtual {v8}, Ljava/lang/String;->length()I

    .line 126
    .line 127
    .line 128
    move-result v7

    .line 129
    goto :goto_0

    .line 130
    :cond_3
    const v7, 0x7fffffff

    .line 131
    .line 132
    .line 133
    :goto_0
    if-lt v1, v7, :cond_4

    .line 134
    .line 135
    goto/16 :goto_6

    .line 136
    .line 137
    :cond_4
    invoke-static {v6}, Lw3/h0;->v(Ld4/l;)Lg4/l0;

    .line 138
    .line 139
    .line 140
    move-result-object v6

    .line 141
    if-nez v6, :cond_5

    .line 142
    .line 143
    goto/16 :goto_c

    .line 144
    .line 145
    :cond_5
    new-instance v7, Ljava/util/ArrayList;

    .line 146
    .line 147
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 148
    .line 149
    .line 150
    const/4 v8, 0x0

    .line 151
    :goto_1
    if-ge v8, v4, :cond_b

    .line 152
    .line 153
    add-int v10, v1, v8

    .line 154
    .line 155
    iget-object v12, v6, Lg4/l0;->a:Lg4/k0;

    .line 156
    .line 157
    iget-object v12, v12, Lg4/k0;->a:Lg4/g;

    .line 158
    .line 159
    iget-object v12, v12, Lg4/g;->e:Ljava/lang/String;

    .line 160
    .line 161
    invoke-virtual {v12}, Ljava/lang/String;->length()I

    .line 162
    .line 163
    .line 164
    move-result v12

    .line 165
    if-lt v10, v12, :cond_6

    .line 166
    .line 167
    invoke-virtual {v7, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 168
    .line 169
    .line 170
    move-object v15, v3

    .line 171
    move/from16 p4, v4

    .line 172
    .line 173
    goto/16 :goto_5

    .line 174
    .line 175
    :cond_6
    invoke-virtual {v6, v10}, Lg4/l0;->b(I)Ld3/c;

    .line 176
    .line 177
    .line 178
    move-result-object v10

    .line 179
    invoke-virtual {v5}, Ld4/q;->d()Lv3/f1;

    .line 180
    .line 181
    .line 182
    move-result-object v12

    .line 183
    const-wide/16 v13, 0x0

    .line 184
    .line 185
    if-eqz v12, :cond_8

    .line 186
    .line 187
    invoke-virtual {v12}, Lv3/f1;->f1()Lx2/r;

    .line 188
    .line 189
    .line 190
    move-result-object v15

    .line 191
    iget-boolean v15, v15, Lx2/r;->q:Z

    .line 192
    .line 193
    if-eqz v15, :cond_7

    .line 194
    .line 195
    goto :goto_2

    .line 196
    :cond_7
    move-object v12, v9

    .line 197
    :goto_2
    if-eqz v12, :cond_8

    .line 198
    .line 199
    invoke-virtual {v12, v13, v14}, Lv3/f1;->R(J)J

    .line 200
    .line 201
    .line 202
    move-result-wide v13

    .line 203
    :cond_8
    invoke-virtual {v10, v13, v14}, Ld3/c;->i(J)Ld3/c;

    .line 204
    .line 205
    .line 206
    move-result-object v10

    .line 207
    invoke-virtual {v5}, Ld4/q;->g()Ld3/c;

    .line 208
    .line 209
    .line 210
    move-result-object v12

    .line 211
    invoke-virtual {v10, v12}, Ld3/c;->g(Ld3/c;)Z

    .line 212
    .line 213
    .line 214
    move-result v13

    .line 215
    if-eqz v13, :cond_9

    .line 216
    .line 217
    invoke-virtual {v10, v12}, Ld3/c;->e(Ld3/c;)Ld3/c;

    .line 218
    .line 219
    .line 220
    move-result-object v10

    .line 221
    goto :goto_3

    .line 222
    :cond_9
    move-object v10, v9

    .line 223
    :goto_3
    if-eqz v10, :cond_a

    .line 224
    .line 225
    iget v12, v10, Ld3/c;->a:F

    .line 226
    .line 227
    iget v13, v10, Ld3/c;->b:F

    .line 228
    .line 229
    invoke-static {v12}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 230
    .line 231
    .line 232
    move-result v12

    .line 233
    int-to-long v14, v12

    .line 234
    invoke-static {v13}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 235
    .line 236
    .line 237
    move-result v12

    .line 238
    int-to-long v12, v12

    .line 239
    const/16 v16, 0x20

    .line 240
    .line 241
    shl-long v14, v14, v16

    .line 242
    .line 243
    const-wide v17, 0xffffffffL

    .line 244
    .line 245
    .line 246
    .line 247
    .line 248
    and-long v12, v12, v17

    .line 249
    .line 250
    or-long/2addr v12, v14

    .line 251
    iget-object v14, v0, Lw3/z;->d:Lw3/t;

    .line 252
    .line 253
    invoke-virtual {v14, v12, v13}, Lw3/t;->q(J)J

    .line 254
    .line 255
    .line 256
    move-result-wide v12

    .line 257
    iget v15, v10, Ld3/c;->c:F

    .line 258
    .line 259
    iget v10, v10, Ld3/c;->d:F

    .line 260
    .line 261
    invoke-static {v15}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 262
    .line 263
    .line 264
    move-result v15

    .line 265
    move/from16 p2, v10

    .line 266
    .line 267
    int-to-long v9, v15

    .line 268
    invoke-static/range {p2 .. p2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 269
    .line 270
    .line 271
    move-result v15

    .line 272
    move-wide/from16 v19, v12

    .line 273
    .line 274
    int-to-long v11, v15

    .line 275
    shl-long v9, v9, v16

    .line 276
    .line 277
    and-long v11, v11, v17

    .line 278
    .line 279
    or-long/2addr v9, v11

    .line 280
    invoke-virtual {v14, v9, v10}, Lw3/t;->q(J)J

    .line 281
    .line 282
    .line 283
    move-result-wide v9

    .line 284
    new-instance v11, Landroid/graphics/RectF;

    .line 285
    .line 286
    shr-long v12, v19, v16

    .line 287
    .line 288
    long-to-int v12, v12

    .line 289
    invoke-static {v12}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 290
    .line 291
    .line 292
    move-result v13

    .line 293
    shr-long v14, v9, v16

    .line 294
    .line 295
    long-to-int v14, v14

    .line 296
    invoke-static {v14}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 297
    .line 298
    .line 299
    move-result v15

    .line 300
    invoke-static {v13, v15}, Ljava/lang/Math;->min(FF)F

    .line 301
    .line 302
    .line 303
    move-result v13

    .line 304
    move-object v15, v3

    .line 305
    move/from16 p4, v4

    .line 306
    .line 307
    and-long v3, v19, v17

    .line 308
    .line 309
    long-to-int v3, v3

    .line 310
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 311
    .line 312
    .line 313
    move-result v4

    .line 314
    and-long v9, v9, v17

    .line 315
    .line 316
    long-to-int v9, v9

    .line 317
    invoke-static {v9}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 318
    .line 319
    .line 320
    move-result v10

    .line 321
    invoke-static {v4, v10}, Ljava/lang/Math;->min(FF)F

    .line 322
    .line 323
    .line 324
    move-result v4

    .line 325
    invoke-static {v12}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 326
    .line 327
    .line 328
    move-result v10

    .line 329
    invoke-static {v14}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 330
    .line 331
    .line 332
    move-result v12

    .line 333
    invoke-static {v10, v12}, Ljava/lang/Math;->max(FF)F

    .line 334
    .line 335
    .line 336
    move-result v10

    .line 337
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 338
    .line 339
    .line 340
    move-result v3

    .line 341
    invoke-static {v9}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 342
    .line 343
    .line 344
    move-result v9

    .line 345
    invoke-static {v3, v9}, Ljava/lang/Math;->max(FF)F

    .line 346
    .line 347
    .line 348
    move-result v3

    .line 349
    invoke-direct {v11, v13, v4, v10, v3}, Landroid/graphics/RectF;-><init>(FFFF)V

    .line 350
    .line 351
    .line 352
    goto :goto_4

    .line 353
    :cond_a
    move-object v15, v3

    .line 354
    move/from16 p4, v4

    .line 355
    .line 356
    const/4 v11, 0x0

    .line 357
    :goto_4
    invoke-virtual {v7, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 358
    .line 359
    .line 360
    :goto_5
    add-int/lit8 v8, v8, 0x1

    .line 361
    .line 362
    move/from16 v4, p4

    .line 363
    .line 364
    move-object v3, v15

    .line 365
    const/4 v9, 0x0

    .line 366
    goto/16 :goto_1

    .line 367
    .line 368
    :cond_b
    move-object v15, v3

    .line 369
    invoke-virtual {v15}, Landroid/view/accessibility/AccessibilityNodeInfo;->getExtras()Landroid/os/Bundle;

    .line 370
    .line 371
    .line 372
    move-result-object v0

    .line 373
    const/4 v1, 0x0

    .line 374
    new-array v1, v1, [Landroid/graphics/RectF;

    .line 375
    .line 376
    invoke-virtual {v7, v1}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 377
    .line 378
    .line 379
    move-result-object v1

    .line 380
    check-cast v1, [Landroid/os/Parcelable;

    .line 381
    .line 382
    invoke-virtual {v0, v2, v1}, Landroid/os/Bundle;->putParcelableArray(Ljava/lang/String;[Landroid/os/Parcelable;)V

    .line 383
    .line 384
    .line 385
    return-void

    .line 386
    :cond_c
    :goto_6
    const-string v0, "AccessibilityDelegate"

    .line 387
    .line 388
    const-string v1, "Invalid arguments for accessibility character locations"

    .line 389
    .line 390
    invoke-static {v0, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 391
    .line 392
    .line 393
    return-void

    .line 394
    :cond_d
    move-object v15, v3

    .line 395
    sget-object v1, Ld4/v;->y:Ld4/z;

    .line 396
    .line 397
    invoke-virtual {v7, v1}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 398
    .line 399
    .line 400
    move-result v3

    .line 401
    if-eqz v3, :cond_f

    .line 402
    .line 403
    if-eqz v4, :cond_f

    .line 404
    .line 405
    const-string v3, "androidx.compose.ui.semantics.testTag"

    .line 406
    .line 407
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 408
    .line 409
    .line 410
    move-result v3

    .line 411
    if-eqz v3, :cond_f

    .line 412
    .line 413
    invoke-virtual {v7, v1}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 414
    .line 415
    .line 416
    move-result-object v0

    .line 417
    if-nez v0, :cond_e

    .line 418
    .line 419
    const/4 v9, 0x0

    .line 420
    goto :goto_7

    .line 421
    :cond_e
    move-object v9, v0

    .line 422
    :goto_7
    check-cast v9, Ljava/lang/String;

    .line 423
    .line 424
    if-eqz v9, :cond_1b

    .line 425
    .line 426
    invoke-virtual {v15}, Landroid/view/accessibility/AccessibilityNodeInfo;->getExtras()Landroid/os/Bundle;

    .line 427
    .line 428
    .line 429
    move-result-object v0

    .line 430
    invoke-virtual {v0, v2, v9}, Landroid/os/Bundle;->putCharSequence(Ljava/lang/String;Ljava/lang/CharSequence;)V

    .line 431
    .line 432
    .line 433
    return-void

    .line 434
    :cond_f
    const-string v1, "androidx.compose.ui.semantics.id"

    .line 435
    .line 436
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 437
    .line 438
    .line 439
    move-result v1

    .line 440
    if-eqz v1, :cond_10

    .line 441
    .line 442
    invoke-virtual {v15}, Landroid/view/accessibility/AccessibilityNodeInfo;->getExtras()Landroid/os/Bundle;

    .line 443
    .line 444
    .line 445
    move-result-object v0

    .line 446
    iget v1, v5, Ld4/q;->g:I

    .line 447
    .line 448
    invoke-virtual {v0, v2, v1}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 449
    .line 450
    .line 451
    return-void

    .line 452
    :cond_10
    const-string v1, "androidx.compose.ui.semantics.shapeType"

    .line 453
    .line 454
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 455
    .line 456
    .line 457
    move-result v3

    .line 458
    const-string v4, "androidx.compose.ui.semantics.shapeRegion"

    .line 459
    .line 460
    const-string v6, "androidx.compose.ui.semantics.shapeCorners"

    .line 461
    .line 462
    const-string v8, "androidx.compose.ui.semantics.shapeRect"

    .line 463
    .line 464
    if-eqz v3, :cond_15

    .line 465
    .line 466
    sget-object v2, Ld4/v;->O:Ld4/z;

    .line 467
    .line 468
    invoke-virtual {v7, v2}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 469
    .line 470
    .line 471
    move-result-object v2

    .line 472
    if-nez v2, :cond_11

    .line 473
    .line 474
    const/4 v9, 0x0

    .line 475
    goto :goto_8

    .line 476
    :cond_11
    move-object v9, v2

    .line 477
    :goto_8
    check-cast v9, Le3/n0;

    .line 478
    .line 479
    if-eqz v9, :cond_1b

    .line 480
    .line 481
    invoke-virtual {v0, v9, v5}, Lw3/z;->p(Le3/n0;Ld4/q;)Le3/g0;

    .line 482
    .line 483
    .line 484
    move-result-object v0

    .line 485
    instance-of v2, v0, Le3/e0;

    .line 486
    .line 487
    if-eqz v2, :cond_12

    .line 488
    .line 489
    invoke-virtual {v15}, Landroid/view/accessibility/AccessibilityNodeInfo;->getExtras()Landroid/os/Bundle;

    .line 490
    .line 491
    .line 492
    move-result-object v2

    .line 493
    const/4 v3, 0x0

    .line 494
    invoke-virtual {v2, v1, v3}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 495
    .line 496
    .line 497
    invoke-virtual {v15}, Landroid/view/accessibility/AccessibilityNodeInfo;->getExtras()Landroid/os/Bundle;

    .line 498
    .line 499
    .line 500
    move-result-object v1

    .line 501
    invoke-static {v0}, Lw3/z;->M(Le3/g0;)Landroid/graphics/Rect;

    .line 502
    .line 503
    .line 504
    move-result-object v0

    .line 505
    invoke-virtual {v1, v8, v0}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 506
    .line 507
    .line 508
    return-void

    .line 509
    :cond_12
    instance-of v2, v0, Le3/f0;

    .line 510
    .line 511
    if-eqz v2, :cond_13

    .line 512
    .line 513
    invoke-virtual {v15}, Landroid/view/accessibility/AccessibilityNodeInfo;->getExtras()Landroid/os/Bundle;

    .line 514
    .line 515
    .line 516
    move-result-object v2

    .line 517
    const/4 v3, 0x1

    .line 518
    invoke-virtual {v2, v1, v3}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 519
    .line 520
    .line 521
    invoke-virtual {v15}, Landroid/view/accessibility/AccessibilityNodeInfo;->getExtras()Landroid/os/Bundle;

    .line 522
    .line 523
    .line 524
    move-result-object v1

    .line 525
    invoke-static {v0}, Lw3/z;->M(Le3/g0;)Landroid/graphics/Rect;

    .line 526
    .line 527
    .line 528
    move-result-object v2

    .line 529
    invoke-virtual {v1, v8, v2}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 530
    .line 531
    .line 532
    invoke-virtual {v15}, Landroid/view/accessibility/AccessibilityNodeInfo;->getExtras()Landroid/os/Bundle;

    .line 533
    .line 534
    .line 535
    move-result-object v1

    .line 536
    invoke-static {v0}, Lw3/z;->N(Le3/g0;)[F

    .line 537
    .line 538
    .line 539
    move-result-object v0

    .line 540
    invoke-virtual {v1, v6, v0}, Landroid/os/Bundle;->putFloatArray(Ljava/lang/String;[F)V

    .line 541
    .line 542
    .line 543
    return-void

    .line 544
    :cond_13
    instance-of v2, v0, Le3/d0;

    .line 545
    .line 546
    if-eqz v2, :cond_14

    .line 547
    .line 548
    invoke-virtual {v15}, Landroid/view/accessibility/AccessibilityNodeInfo;->getExtras()Landroid/os/Bundle;

    .line 549
    .line 550
    .line 551
    move-result-object v2

    .line 552
    const/4 v3, 0x2

    .line 553
    invoke-virtual {v2, v1, v3}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 554
    .line 555
    .line 556
    invoke-virtual {v15}, Landroid/view/accessibility/AccessibilityNodeInfo;->getExtras()Landroid/os/Bundle;

    .line 557
    .line 558
    .line 559
    move-result-object v1

    .line 560
    invoke-static {v0}, Lw3/z;->O(Le3/g0;)Landroid/graphics/Region;

    .line 561
    .line 562
    .line 563
    move-result-object v0

    .line 564
    invoke-virtual {v1, v4, v0}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 565
    .line 566
    .line 567
    return-void

    .line 568
    :cond_14
    new-instance v0, La8/r0;

    .line 569
    .line 570
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 571
    .line 572
    .line 573
    throw v0

    .line 574
    :cond_15
    invoke-static {v2, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 575
    .line 576
    .line 577
    move-result v1

    .line 578
    if-eqz v1, :cond_17

    .line 579
    .line 580
    sget-object v1, Ld4/v;->O:Ld4/z;

    .line 581
    .line 582
    invoke-virtual {v7, v1}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 583
    .line 584
    .line 585
    move-result-object v1

    .line 586
    if-nez v1, :cond_16

    .line 587
    .line 588
    const/4 v9, 0x0

    .line 589
    goto :goto_9

    .line 590
    :cond_16
    move-object v9, v1

    .line 591
    :goto_9
    check-cast v9, Le3/n0;

    .line 592
    .line 593
    if-eqz v9, :cond_1b

    .line 594
    .line 595
    invoke-virtual {v0, v9, v5}, Lw3/z;->p(Le3/n0;Ld4/q;)Le3/g0;

    .line 596
    .line 597
    .line 598
    move-result-object v0

    .line 599
    invoke-static {v0}, Lw3/z;->M(Le3/g0;)Landroid/graphics/Rect;

    .line 600
    .line 601
    .line 602
    move-result-object v0

    .line 603
    if-eqz v0, :cond_1b

    .line 604
    .line 605
    invoke-virtual {v15}, Landroid/view/accessibility/AccessibilityNodeInfo;->getExtras()Landroid/os/Bundle;

    .line 606
    .line 607
    .line 608
    move-result-object v1

    .line 609
    invoke-virtual {v1, v8, v0}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 610
    .line 611
    .line 612
    return-void

    .line 613
    :cond_17
    invoke-static {v2, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 614
    .line 615
    .line 616
    move-result v1

    .line 617
    if-eqz v1, :cond_19

    .line 618
    .line 619
    sget-object v1, Ld4/v;->O:Ld4/z;

    .line 620
    .line 621
    invoke-virtual {v7, v1}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 622
    .line 623
    .line 624
    move-result-object v1

    .line 625
    if-nez v1, :cond_18

    .line 626
    .line 627
    const/4 v9, 0x0

    .line 628
    goto :goto_a

    .line 629
    :cond_18
    move-object v9, v1

    .line 630
    :goto_a
    check-cast v9, Le3/n0;

    .line 631
    .line 632
    if-eqz v9, :cond_1b

    .line 633
    .line 634
    invoke-virtual {v0, v9, v5}, Lw3/z;->p(Le3/n0;Ld4/q;)Le3/g0;

    .line 635
    .line 636
    .line 637
    move-result-object v0

    .line 638
    invoke-static {v0}, Lw3/z;->N(Le3/g0;)[F

    .line 639
    .line 640
    .line 641
    move-result-object v0

    .line 642
    if-eqz v0, :cond_1b

    .line 643
    .line 644
    invoke-virtual {v15}, Landroid/view/accessibility/AccessibilityNodeInfo;->getExtras()Landroid/os/Bundle;

    .line 645
    .line 646
    .line 647
    move-result-object v1

    .line 648
    invoke-virtual {v1, v6, v0}, Landroid/os/Bundle;->putFloatArray(Ljava/lang/String;[F)V

    .line 649
    .line 650
    .line 651
    return-void

    .line 652
    :cond_19
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 653
    .line 654
    .line 655
    move-result v1

    .line 656
    if-eqz v1, :cond_1b

    .line 657
    .line 658
    sget-object v1, Ld4/v;->O:Ld4/z;

    .line 659
    .line 660
    invoke-virtual {v7, v1}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 661
    .line 662
    .line 663
    move-result-object v1

    .line 664
    if-nez v1, :cond_1a

    .line 665
    .line 666
    const/4 v9, 0x0

    .line 667
    goto :goto_b

    .line 668
    :cond_1a
    move-object v9, v1

    .line 669
    :goto_b
    check-cast v9, Le3/n0;

    .line 670
    .line 671
    if-eqz v9, :cond_1b

    .line 672
    .line 673
    invoke-virtual {v0, v9, v5}, Lw3/z;->p(Le3/n0;Ld4/q;)Le3/g0;

    .line 674
    .line 675
    .line 676
    move-result-object v0

    .line 677
    invoke-static {v0}, Lw3/z;->O(Le3/g0;)Landroid/graphics/Region;

    .line 678
    .line 679
    .line 680
    move-result-object v0

    .line 681
    if-eqz v0, :cond_1b

    .line 682
    .line 683
    invoke-virtual {v15}, Landroid/view/accessibility/AccessibilityNodeInfo;->getExtras()Landroid/os/Bundle;

    .line 684
    .line 685
    .line 686
    move-result-object v1

    .line 687
    invoke-virtual {v1, v4, v0}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 688
    .line 689
    .line 690
    :cond_1b
    :goto_c
    return-void
.end method

.method public final k(Ld4/r;)Landroid/graphics/Rect;
    .locals 10

    .line 1
    iget-object p1, p1, Ld4/r;->b:Lt4/k;

    .line 2
    .line 3
    iget v0, p1, Lt4/k;->a:I

    .line 4
    .line 5
    int-to-float v0, v0

    .line 6
    iget v1, p1, Lt4/k;->b:I

    .line 7
    .line 8
    int-to-float v1, v1

    .line 9
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    int-to-long v2, v0

    .line 14
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    int-to-long v0, v0

    .line 19
    const/16 v4, 0x20

    .line 20
    .line 21
    shl-long/2addr v2, v4

    .line 22
    const-wide v5, 0xffffffffL

    .line 23
    .line 24
    .line 25
    .line 26
    .line 27
    and-long/2addr v0, v5

    .line 28
    or-long/2addr v0, v2

    .line 29
    iget-object p0, p0, Lw3/z;->d:Lw3/t;

    .line 30
    .line 31
    invoke-virtual {p0, v0, v1}, Lw3/t;->q(J)J

    .line 32
    .line 33
    .line 34
    move-result-wide v0

    .line 35
    iget v2, p1, Lt4/k;->c:I

    .line 36
    .line 37
    int-to-float v2, v2

    .line 38
    iget p1, p1, Lt4/k;->d:I

    .line 39
    .line 40
    int-to-float p1, p1

    .line 41
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 42
    .line 43
    .line 44
    move-result v2

    .line 45
    int-to-long v2, v2

    .line 46
    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 47
    .line 48
    .line 49
    move-result p1

    .line 50
    int-to-long v7, p1

    .line 51
    shl-long/2addr v2, v4

    .line 52
    and-long/2addr v7, v5

    .line 53
    or-long/2addr v2, v7

    .line 54
    invoke-virtual {p0, v2, v3}, Lw3/t;->q(J)J

    .line 55
    .line 56
    .line 57
    move-result-wide p0

    .line 58
    new-instance v2, Landroid/graphics/Rect;

    .line 59
    .line 60
    shr-long v7, v0, v4

    .line 61
    .line 62
    long-to-int v3, v7

    .line 63
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 64
    .line 65
    .line 66
    move-result v7

    .line 67
    shr-long v8, p0, v4

    .line 68
    .line 69
    long-to-int v4, v8

    .line 70
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 71
    .line 72
    .line 73
    move-result v8

    .line 74
    invoke-static {v7, v8}, Ljava/lang/Math;->min(FF)F

    .line 75
    .line 76
    .line 77
    move-result v7

    .line 78
    float-to-double v7, v7

    .line 79
    invoke-static {v7, v8}, Ljava/lang/Math;->floor(D)D

    .line 80
    .line 81
    .line 82
    move-result-wide v7

    .line 83
    double-to-float v7, v7

    .line 84
    float-to-int v7, v7

    .line 85
    and-long/2addr v0, v5

    .line 86
    long-to-int v0, v0

    .line 87
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 88
    .line 89
    .line 90
    move-result v1

    .line 91
    and-long/2addr p0, v5

    .line 92
    long-to-int p0, p0

    .line 93
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 94
    .line 95
    .line 96
    move-result p1

    .line 97
    invoke-static {v1, p1}, Ljava/lang/Math;->min(FF)F

    .line 98
    .line 99
    .line 100
    move-result p1

    .line 101
    float-to-double v5, p1

    .line 102
    invoke-static {v5, v6}, Ljava/lang/Math;->floor(D)D

    .line 103
    .line 104
    .line 105
    move-result-wide v5

    .line 106
    double-to-float p1, v5

    .line 107
    float-to-int p1, p1

    .line 108
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 109
    .line 110
    .line 111
    move-result v1

    .line 112
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 113
    .line 114
    .line 115
    move-result v3

    .line 116
    invoke-static {v1, v3}, Ljava/lang/Math;->max(FF)F

    .line 117
    .line 118
    .line 119
    move-result v1

    .line 120
    float-to-double v3, v1

    .line 121
    invoke-static {v3, v4}, Ljava/lang/Math;->ceil(D)D

    .line 122
    .line 123
    .line 124
    move-result-wide v3

    .line 125
    double-to-float v1, v3

    .line 126
    float-to-int v1, v1

    .line 127
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 128
    .line 129
    .line 130
    move-result v0

    .line 131
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 132
    .line 133
    .line 134
    move-result p0

    .line 135
    invoke-static {v0, p0}, Ljava/lang/Math;->max(FF)F

    .line 136
    .line 137
    .line 138
    move-result p0

    .line 139
    float-to-double v3, p0

    .line 140
    invoke-static {v3, v4}, Ljava/lang/Math;->ceil(D)D

    .line 141
    .line 142
    .line 143
    move-result-wide v3

    .line 144
    double-to-float p0, v3

    .line 145
    float-to-int p0, p0

    .line 146
    invoke-direct {v2, v7, p1, v1, p0}, Landroid/graphics/Rect;-><init>(IIII)V

    .line 147
    .line 148
    .line 149
    return-object v2
.end method

.method public final l(Lrx0/c;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    instance-of v2, v1, Lw3/x;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    check-cast v2, Lw3/x;

    .line 11
    .line 12
    iget v3, v2, Lw3/x;->h:I

    .line 13
    .line 14
    const/high16 v4, -0x80000000

    .line 15
    .line 16
    and-int v5, v3, v4

    .line 17
    .line 18
    if-eqz v5, :cond_0

    .line 19
    .line 20
    sub-int/2addr v3, v4

    .line 21
    iput v3, v2, Lw3/x;->h:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Lw3/x;

    .line 25
    .line 26
    invoke-direct {v2, v0, v1}, Lw3/x;-><init>(Lw3/z;Lrx0/c;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v1, v2, Lw3/x;->f:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Lw3/x;->h:I

    .line 34
    .line 35
    const/4 v5, 0x2

    .line 36
    iget-object v6, v0, Lw3/z;->y:Landroidx/collection/g;

    .line 37
    .line 38
    const/4 v7, 0x1

    .line 39
    if-eqz v4, :cond_3

    .line 40
    .line 41
    if-eq v4, v7, :cond_2

    .line 42
    .line 43
    if-ne v4, v5, :cond_1

    .line 44
    .line 45
    iget-object v4, v2, Lw3/x;->e:Lxy0/c;

    .line 46
    .line 47
    iget-object v8, v2, Lw3/x;->d:Landroidx/collection/c0;

    .line 48
    .line 49
    :try_start_0
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 50
    .line 51
    .line 52
    move v1, v5

    .line 53
    move-object v9, v6

    .line 54
    goto/16 :goto_7

    .line 55
    .line 56
    :catchall_0
    move-exception v0

    .line 57
    move-object v9, v6

    .line 58
    goto/16 :goto_8

    .line 59
    .line 60
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 61
    .line 62
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 63
    .line 64
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    throw v0

    .line 68
    :cond_2
    iget-object v4, v2, Lw3/x;->e:Lxy0/c;

    .line 69
    .line 70
    iget-object v8, v2, Lw3/x;->d:Landroidx/collection/c0;

    .line 71
    .line 72
    :try_start_1
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 73
    .line 74
    .line 75
    goto :goto_2

    .line 76
    :cond_3
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    :try_start_2
    new-instance v1, Landroidx/collection/c0;

    .line 80
    .line 81
    invoke-direct {v1}, Landroidx/collection/c0;-><init>()V

    .line 82
    .line 83
    .line 84
    iget-object v4, v0, Lw3/z;->z:Lxy0/j;

    .line 85
    .line 86
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 87
    .line 88
    .line 89
    new-instance v8, Lxy0/c;

    .line 90
    .line 91
    invoke-direct {v8, v4}, Lxy0/c;-><init>(Lxy0/j;)V

    .line 92
    .line 93
    .line 94
    :goto_1
    iput-object v1, v2, Lw3/x;->d:Landroidx/collection/c0;

    .line 95
    .line 96
    iput-object v8, v2, Lw3/x;->e:Lxy0/c;

    .line 97
    .line 98
    iput v7, v2, Lw3/x;->h:I

    .line 99
    .line 100
    invoke-virtual {v8, v2}, Lxy0/c;->a(Lrx0/c;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v4

    .line 104
    if-ne v4, v3, :cond_4

    .line 105
    .line 106
    goto/16 :goto_6

    .line 107
    .line 108
    :cond_4
    move-object v15, v8

    .line 109
    move-object v8, v1

    .line 110
    move-object v1, v4

    .line 111
    move-object v4, v15

    .line 112
    :goto_2
    check-cast v1, Ljava/lang/Boolean;

    .line 113
    .line 114
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 115
    .line 116
    .line 117
    move-result v1

    .line 118
    if-eqz v1, :cond_a

    .line 119
    .line 120
    invoke-virtual {v4}, Lxy0/c;->c()Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    invoke-virtual {v0}, Lw3/z;->v()Z

    .line 124
    .line 125
    .line 126
    move-result v1

    .line 127
    if-eqz v1, :cond_7

    .line 128
    .line 129
    iget v1, v6, Landroidx/collection/g;->f:I

    .line 130
    .line 131
    const/4 v9, 0x0

    .line 132
    move v10, v9

    .line 133
    :goto_3
    if-ge v10, v1, :cond_5

    .line 134
    .line 135
    iget-object v11, v6, Landroidx/collection/g;->e:[Ljava/lang/Object;

    .line 136
    .line 137
    aget-object v11, v11, v10

    .line 138
    .line 139
    check-cast v11, Lv3/h0;

    .line 140
    .line 141
    invoke-virtual {v0, v11, v8}, Lw3/z;->I(Lv3/h0;Landroidx/collection/c0;)V

    .line 142
    .line 143
    .line 144
    invoke-virtual {v0, v11}, Lw3/z;->J(Lv3/h0;)V

    .line 145
    .line 146
    .line 147
    add-int/lit8 v10, v10, 0x1

    .line 148
    .line 149
    goto :goto_3

    .line 150
    :cond_5
    iput v9, v8, Landroidx/collection/c0;->d:I

    .line 151
    .line 152
    iget-object v1, v8, Landroidx/collection/c0;->a:[J

    .line 153
    .line 154
    sget-object v9, Landroidx/collection/y0;->a:[J

    .line 155
    .line 156
    if-eq v1, v9, :cond_6

    .line 157
    .line 158
    const-wide v9, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 159
    .line 160
    .line 161
    .line 162
    .line 163
    invoke-static {v9, v10, v1}, Lmx0/n;->r(J[J)V

    .line 164
    .line 165
    .line 166
    iget-object v1, v8, Landroidx/collection/c0;->a:[J

    .line 167
    .line 168
    iget v9, v8, Landroidx/collection/c0;->c:I

    .line 169
    .line 170
    shr-int/lit8 v10, v9, 0x3

    .line 171
    .line 172
    and-int/lit8 v9, v9, 0x7

    .line 173
    .line 174
    shl-int/lit8 v9, v9, 0x3

    .line 175
    .line 176
    aget-wide v11, v1, v10
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 177
    .line 178
    const-wide/16 v13, 0xff

    .line 179
    .line 180
    shl-long/2addr v13, v9

    .line 181
    move-object v9, v6

    .line 182
    not-long v5, v13

    .line 183
    and-long/2addr v5, v11

    .line 184
    or-long/2addr v5, v13

    .line 185
    :try_start_3
    aput-wide v5, v1, v10

    .line 186
    .line 187
    goto :goto_4

    .line 188
    :cond_6
    move-object v9, v6

    .line 189
    :goto_4
    iget v1, v8, Landroidx/collection/c0;->c:I

    .line 190
    .line 191
    invoke-static {v1}, Landroidx/collection/y0;->a(I)I

    .line 192
    .line 193
    .line 194
    move-result v1

    .line 195
    iget v5, v8, Landroidx/collection/c0;->d:I

    .line 196
    .line 197
    sub-int/2addr v1, v5

    .line 198
    iput v1, v8, Landroidx/collection/c0;->e:I

    .line 199
    .line 200
    iget-boolean v1, v0, Lw3/z;->L:Z

    .line 201
    .line 202
    if-nez v1, :cond_8

    .line 203
    .line 204
    iput-boolean v7, v0, Lw3/z;->L:Z

    .line 205
    .line 206
    iget-object v1, v0, Lw3/z;->l:Landroid/os/Handler;

    .line 207
    .line 208
    iget-object v5, v0, Lw3/z;->N:Lm8/o;

    .line 209
    .line 210
    invoke-virtual {v1, v5}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 211
    .line 212
    .line 213
    goto :goto_5

    .line 214
    :catchall_1
    move-exception v0

    .line 215
    goto :goto_8

    .line 216
    :cond_7
    move-object v9, v6

    .line 217
    :cond_8
    :goto_5
    invoke-virtual {v9}, Landroidx/collection/g;->clear()V

    .line 218
    .line 219
    .line 220
    iget-object v1, v0, Lw3/z;->s:Landroidx/collection/b0;

    .line 221
    .line 222
    invoke-virtual {v1}, Landroidx/collection/b0;->c()V

    .line 223
    .line 224
    .line 225
    iget-object v1, v0, Lw3/z;->t:Landroidx/collection/b0;

    .line 226
    .line 227
    invoke-virtual {v1}, Landroidx/collection/b0;->c()V

    .line 228
    .line 229
    .line 230
    iget-wide v5, v0, Lw3/z;->h:J

    .line 231
    .line 232
    iput-object v8, v2, Lw3/x;->d:Landroidx/collection/c0;

    .line 233
    .line 234
    iput-object v4, v2, Lw3/x;->e:Lxy0/c;

    .line 235
    .line 236
    const/4 v1, 0x2

    .line 237
    iput v1, v2, Lw3/x;->h:I

    .line 238
    .line 239
    invoke-static {v5, v6, v2}, Lvy0/e0;->p(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 240
    .line 241
    .line 242
    move-result-object v5
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 243
    if-ne v5, v3, :cond_9

    .line 244
    .line 245
    :goto_6
    return-object v3

    .line 246
    :cond_9
    :goto_7
    move v5, v1

    .line 247
    move-object v1, v8

    .line 248
    move-object v6, v9

    .line 249
    move-object v8, v4

    .line 250
    goto/16 :goto_1

    .line 251
    .line 252
    :cond_a
    move-object v9, v6

    .line 253
    invoke-virtual {v9}, Landroidx/collection/g;->clear()V

    .line 254
    .line 255
    .line 256
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 257
    .line 258
    return-object v0

    .line 259
    :goto_8
    invoke-virtual {v9}, Landroidx/collection/g;->clear()V

    .line 260
    .line 261
    .line 262
    throw v0
.end method

.method public final m(JIZ)Z
    .locals 22

    .line 1
    move-wide/from16 v0, p1

    .line 2
    .line 3
    move/from16 v2, p3

    .line 4
    .line 5
    move/from16 v3, p4

    .line 6
    .line 7
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 8
    .line 9
    .line 10
    move-result-object v4

    .line 11
    invoke-virtual {v4}, Landroid/os/Looper;->getThread()Ljava/lang/Thread;

    .line 12
    .line 13
    .line 14
    move-result-object v4

    .line 15
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 16
    .line 17
    .line 18
    move-result-object v5

    .line 19
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v4

    .line 23
    if-nez v4, :cond_1

    .line 24
    .line 25
    :cond_0
    const/16 v17, 0x0

    .line 26
    .line 27
    goto/16 :goto_b

    .line 28
    .line 29
    :cond_1
    invoke-virtual/range {p0 .. p0}, Lw3/z;->t()Landroidx/collection/p;

    .line 30
    .line 31
    .line 32
    move-result-object v4

    .line 33
    const-wide v6, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 34
    .line 35
    .line 36
    .line 37
    .line 38
    invoke-static {v0, v1, v6, v7}, Ld3/b;->c(JJ)Z

    .line 39
    .line 40
    .line 41
    move-result v6

    .line 42
    if-nez v6, :cond_0

    .line 43
    .line 44
    const-wide v6, 0x7fffffff7fffffffL

    .line 45
    .line 46
    .line 47
    .line 48
    .line 49
    and-long/2addr v6, v0

    .line 50
    const-wide v8, 0x7fffff007fffffL

    .line 51
    .line 52
    .line 53
    .line 54
    .line 55
    add-long/2addr v6, v8

    .line 56
    const-wide v8, -0x7fffffff80000000L    # -1.0609978955E-314

    .line 57
    .line 58
    .line 59
    .line 60
    .line 61
    and-long/2addr v6, v8

    .line 62
    const-wide/16 v8, 0x0

    .line 63
    .line 64
    cmp-long v6, v6, v8

    .line 65
    .line 66
    if-nez v6, :cond_0

    .line 67
    .line 68
    const/4 v6, 0x1

    .line 69
    if-ne v3, v6, :cond_2

    .line 70
    .line 71
    sget-object v3, Ld4/v;->u:Ld4/z;

    .line 72
    .line 73
    goto :goto_0

    .line 74
    :cond_2
    if-nez v3, :cond_13

    .line 75
    .line 76
    sget-object v3, Ld4/v;->t:Ld4/z;

    .line 77
    .line 78
    :goto_0
    iget-object v7, v4, Landroidx/collection/p;->c:[Ljava/lang/Object;

    .line 79
    .line 80
    iget-object v4, v4, Landroidx/collection/p;->a:[J

    .line 81
    .line 82
    array-length v8, v4

    .line 83
    add-int/lit8 v8, v8, -0x2

    .line 84
    .line 85
    if-ltz v8, :cond_0

    .line 86
    .line 87
    const/4 v9, 0x0

    .line 88
    const/4 v10, 0x0

    .line 89
    :goto_1
    aget-wide v11, v4, v9

    .line 90
    .line 91
    not-long v13, v11

    .line 92
    const/4 v15, 0x7

    .line 93
    shl-long/2addr v13, v15

    .line 94
    and-long/2addr v13, v11

    .line 95
    const-wide v15, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 96
    .line 97
    .line 98
    .line 99
    .line 100
    and-long/2addr v13, v15

    .line 101
    cmp-long v13, v13, v15

    .line 102
    .line 103
    if-eqz v13, :cond_11

    .line 104
    .line 105
    sub-int v13, v9, v8

    .line 106
    .line 107
    not-int v13, v13

    .line 108
    ushr-int/lit8 v13, v13, 0x1f

    .line 109
    .line 110
    const/16 v14, 0x8

    .line 111
    .line 112
    rsub-int/lit8 v13, v13, 0x8

    .line 113
    .line 114
    const/4 v15, 0x0

    .line 115
    :goto_2
    if-ge v15, v13, :cond_f

    .line 116
    .line 117
    const-wide/16 v16, 0xff

    .line 118
    .line 119
    and-long v16, v11, v16

    .line 120
    .line 121
    const-wide/16 v18, 0x80

    .line 122
    .line 123
    cmp-long v16, v16, v18

    .line 124
    .line 125
    if-gez v16, :cond_d

    .line 126
    .line 127
    shl-int/lit8 v16, v9, 0x3

    .line 128
    .line 129
    add-int v16, v16, v15

    .line 130
    .line 131
    aget-object v16, v7, v16

    .line 132
    .line 133
    const/16 v17, 0x0

    .line 134
    .line 135
    move-object/from16 v5, v16

    .line 136
    .line 137
    check-cast v5, Ld4/r;

    .line 138
    .line 139
    iget-object v6, v5, Ld4/r;->b:Lt4/k;

    .line 140
    .line 141
    move/from16 p4, v14

    .line 142
    .line 143
    iget v14, v6, Lt4/k;->a:I

    .line 144
    .line 145
    int-to-float v14, v14

    .line 146
    iget v0, v6, Lt4/k;->b:I

    .line 147
    .line 148
    int-to-float v0, v0

    .line 149
    iget v1, v6, Lt4/k;->c:I

    .line 150
    .line 151
    int-to-float v1, v1

    .line 152
    iget v6, v6, Lt4/k;->d:I

    .line 153
    .line 154
    int-to-float v6, v6

    .line 155
    const/16 v16, 0x20

    .line 156
    .line 157
    move/from16 v18, v0

    .line 158
    .line 159
    move/from16 v19, v1

    .line 160
    .line 161
    shr-long v0, p1, v16

    .line 162
    .line 163
    long-to-int v0, v0

    .line 164
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 165
    .line 166
    .line 167
    move-result v0

    .line 168
    const-wide v20, 0xffffffffL

    .line 169
    .line 170
    .line 171
    .line 172
    .line 173
    move/from16 v16, v0

    .line 174
    .line 175
    and-long v0, p1, v20

    .line 176
    .line 177
    long-to-int v0, v0

    .line 178
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 179
    .line 180
    .line 181
    move-result v0

    .line 182
    cmpl-float v1, v16, v14

    .line 183
    .line 184
    if-ltz v1, :cond_3

    .line 185
    .line 186
    const/4 v1, 0x1

    .line 187
    goto :goto_3

    .line 188
    :cond_3
    move/from16 v1, v17

    .line 189
    .line 190
    :goto_3
    cmpg-float v14, v16, v19

    .line 191
    .line 192
    if-gez v14, :cond_4

    .line 193
    .line 194
    const/4 v14, 0x1

    .line 195
    goto :goto_4

    .line 196
    :cond_4
    move/from16 v14, v17

    .line 197
    .line 198
    :goto_4
    and-int/2addr v1, v14

    .line 199
    cmpl-float v14, v0, v18

    .line 200
    .line 201
    if-ltz v14, :cond_5

    .line 202
    .line 203
    const/4 v14, 0x1

    .line 204
    goto :goto_5

    .line 205
    :cond_5
    move/from16 v14, v17

    .line 206
    .line 207
    :goto_5
    and-int/2addr v1, v14

    .line 208
    cmpg-float v0, v0, v6

    .line 209
    .line 210
    if-gez v0, :cond_6

    .line 211
    .line 212
    const/4 v0, 0x1

    .line 213
    goto :goto_6

    .line 214
    :cond_6
    move/from16 v0, v17

    .line 215
    .line 216
    :goto_6
    and-int/2addr v0, v1

    .line 217
    if-nez v0, :cond_7

    .line 218
    .line 219
    goto :goto_9

    .line 220
    :cond_7
    iget-object v0, v5, Ld4/r;->a:Ld4/q;

    .line 221
    .line 222
    iget-object v0, v0, Ld4/q;->d:Ld4/l;

    .line 223
    .line 224
    iget-object v0, v0, Ld4/l;->d:Landroidx/collection/q0;

    .line 225
    .line 226
    invoke-virtual {v0, v3}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 227
    .line 228
    .line 229
    move-result-object v0

    .line 230
    if-nez v0, :cond_8

    .line 231
    .line 232
    const/4 v0, 0x0

    .line 233
    :cond_8
    check-cast v0, Ld4/j;

    .line 234
    .line 235
    if-nez v0, :cond_9

    .line 236
    .line 237
    goto :goto_9

    .line 238
    :cond_9
    iget-object v1, v0, Ld4/j;->a:Lay0/a;

    .line 239
    .line 240
    iget-boolean v5, v0, Ld4/j;->c:Z

    .line 241
    .line 242
    if-eqz v5, :cond_a

    .line 243
    .line 244
    neg-int v6, v2

    .line 245
    goto :goto_7

    .line 246
    :cond_a
    move v6, v2

    .line 247
    :goto_7
    if-nez v2, :cond_b

    .line 248
    .line 249
    if-eqz v5, :cond_b

    .line 250
    .line 251
    const/4 v6, -0x1

    .line 252
    :cond_b
    if-gez v6, :cond_c

    .line 253
    .line 254
    invoke-interface {v1}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 255
    .line 256
    .line 257
    move-result-object v0

    .line 258
    check-cast v0, Ljava/lang/Number;

    .line 259
    .line 260
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 261
    .line 262
    .line 263
    move-result v0

    .line 264
    const/4 v1, 0x0

    .line 265
    cmpl-float v0, v0, v1

    .line 266
    .line 267
    if-lez v0, :cond_e

    .line 268
    .line 269
    :goto_8
    const/4 v10, 0x1

    .line 270
    goto :goto_9

    .line 271
    :cond_c
    invoke-interface {v1}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 272
    .line 273
    .line 274
    move-result-object v1

    .line 275
    check-cast v1, Ljava/lang/Number;

    .line 276
    .line 277
    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    .line 278
    .line 279
    .line 280
    move-result v1

    .line 281
    iget-object v0, v0, Ld4/j;->b:Lay0/a;

    .line 282
    .line 283
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 284
    .line 285
    .line 286
    move-result-object v0

    .line 287
    check-cast v0, Ljava/lang/Number;

    .line 288
    .line 289
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 290
    .line 291
    .line 292
    move-result v0

    .line 293
    cmpg-float v0, v1, v0

    .line 294
    .line 295
    if-gez v0, :cond_e

    .line 296
    .line 297
    goto :goto_8

    .line 298
    :cond_d
    move/from16 p4, v14

    .line 299
    .line 300
    const/16 v17, 0x0

    .line 301
    .line 302
    :cond_e
    :goto_9
    shr-long v11, v11, p4

    .line 303
    .line 304
    add-int/lit8 v15, v15, 0x1

    .line 305
    .line 306
    move-wide/from16 v0, p1

    .line 307
    .line 308
    move/from16 v14, p4

    .line 309
    .line 310
    const/4 v6, 0x1

    .line 311
    goto/16 :goto_2

    .line 312
    .line 313
    :cond_f
    move v0, v14

    .line 314
    const/16 v17, 0x0

    .line 315
    .line 316
    if-ne v13, v0, :cond_10

    .line 317
    .line 318
    goto :goto_a

    .line 319
    :cond_10
    return v10

    .line 320
    :cond_11
    const/16 v17, 0x0

    .line 321
    .line 322
    :goto_a
    if-eq v9, v8, :cond_12

    .line 323
    .line 324
    add-int/lit8 v9, v9, 0x1

    .line 325
    .line 326
    move-wide/from16 v0, p1

    .line 327
    .line 328
    const/4 v6, 0x1

    .line 329
    goto/16 :goto_1

    .line 330
    .line 331
    :cond_12
    return v10

    .line 332
    :cond_13
    new-instance v0, La8/r0;

    .line 333
    .line 334
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 335
    .line 336
    .line 337
    throw v0

    .line 338
    :goto_b
    return v17
.end method

.method public final n()V
    .locals 2

    .line 1
    const-string v0, "sendAccessibilitySemanticsStructureChangeEvents"

    .line 2
    .line 3
    invoke-static {v0}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    :try_start_0
    invoke-virtual {p0}, Lw3/z;->v()Z

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    iget-object v0, p0, Lw3/z;->d:Lw3/t;

    .line 13
    .line 14
    invoke-virtual {v0}, Lw3/t;->getSemanticsOwner()Ld4/s;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    invoke-virtual {v0}, Ld4/s;->a()Ld4/q;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    iget-object v1, p0, Lw3/z;->K:Lw3/a2;

    .line 23
    .line 24
    invoke-virtual {p0, v0, v1}, Lw3/z;->B(Ld4/q;Lw3/a2;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_2

    .line 25
    .line 26
    .line 27
    :cond_0
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 28
    .line 29
    .line 30
    const-string v0, "sendSemanticsPropertyChangeEvents"

    .line 31
    .line 32
    invoke-static {v0}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    :try_start_1
    invoke-virtual {p0}, Lw3/z;->t()Landroidx/collection/p;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    invoke-virtual {p0, v0}, Lw3/z;->H(Landroidx/collection/p;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 40
    .line 41
    .line 42
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 43
    .line 44
    .line 45
    const-string v0, "updateSemanticsNodesCopyAndPanes"

    .line 46
    .line 47
    invoke-static {v0}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    :try_start_2
    invoke-virtual {p0}, Lw3/z;->Q()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 51
    .line 52
    .line 53
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 54
    .line 55
    .line 56
    return-void

    .line 57
    :catchall_0
    move-exception p0

    .line 58
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 59
    .line 60
    .line 61
    throw p0

    .line 62
    :catchall_1
    move-exception p0

    .line 63
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 64
    .line 65
    .line 66
    throw p0

    .line 67
    :catchall_2
    move-exception p0

    .line 68
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 69
    .line 70
    .line 71
    throw p0
.end method

.method public final o(II)Landroid/view/accessibility/AccessibilityEvent;
    .locals 2

    .line 1
    invoke-static {p2}, Landroid/view/accessibility/AccessibilityEvent;->obtain(I)Landroid/view/accessibility/AccessibilityEvent;

    .line 2
    .line 3
    .line 4
    move-result-object p2

    .line 5
    const/4 v0, 0x1

    .line 6
    invoke-virtual {p2, v0}, Landroid/view/accessibility/AccessibilityRecord;->setEnabled(Z)V

    .line 7
    .line 8
    .line 9
    const-string v0, "android.view.View"

    .line 10
    .line 11
    invoke-virtual {p2, v0}, Landroid/view/accessibility/AccessibilityRecord;->setClassName(Ljava/lang/CharSequence;)V

    .line 12
    .line 13
    .line 14
    iget-object v0, p0, Lw3/z;->d:Lw3/t;

    .line 15
    .line 16
    invoke-virtual {v0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    invoke-virtual {v1}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    invoke-virtual {p2, v1}, Landroid/view/accessibility/AccessibilityEvent;->setPackageName(Ljava/lang/CharSequence;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p2, v0, p1}, Landroid/view/accessibility/AccessibilityRecord;->setSource(Landroid/view/View;I)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {p0}, Lw3/z;->v()Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-eqz v0, :cond_1

    .line 35
    .line 36
    invoke-virtual {p0}, Lw3/z;->t()Landroidx/collection/p;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    invoke-virtual {p0, p1}, Landroidx/collection/p;->b(I)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    check-cast p0, Ld4/r;

    .line 45
    .line 46
    if-eqz p0, :cond_1

    .line 47
    .line 48
    iget-object p0, p0, Ld4/r;->a:Ld4/q;

    .line 49
    .line 50
    iget-object p1, p0, Ld4/q;->d:Ld4/l;

    .line 51
    .line 52
    sget-object v0, Ld4/v;->J:Ld4/z;

    .line 53
    .line 54
    iget-object p1, p1, Ld4/l;->d:Landroidx/collection/q0;

    .line 55
    .line 56
    invoke-virtual {p1, v0}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result p1

    .line 60
    invoke-virtual {p2, p1}, Landroid/view/accessibility/AccessibilityRecord;->setPassword(Z)V

    .line 61
    .line 62
    .line 63
    iget-object p0, p0, Ld4/q;->d:Ld4/l;

    .line 64
    .line 65
    sget-object p1, Ld4/v;->n:Ld4/z;

    .line 66
    .line 67
    iget-object p0, p0, Ld4/l;->d:Landroidx/collection/q0;

    .line 68
    .line 69
    invoke-virtual {p0, p1}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    if-nez p0, :cond_0

    .line 74
    .line 75
    const/4 p0, 0x0

    .line 76
    :cond_0
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 77
    .line 78
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result p0

    .line 82
    sget p1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 83
    .line 84
    const/16 v0, 0x22

    .line 85
    .line 86
    if-lt p1, v0, :cond_1

    .line 87
    .line 88
    invoke-static {p2, p0}, Lb/a;->m(Landroid/view/accessibility/AccessibilityEvent;Z)V

    .line 89
    .line 90
    .line 91
    :cond_1
    return-object p2
.end method

.method public final p(Le3/n0;Ld4/q;)Le3/g0;
    .locals 2

    .line 1
    invoke-virtual {p2}, Ld4/q;->d()Lv3/f1;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget-wide v0, v0, Lt3/e1;->f:J

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const-wide/16 v0, 0x0

    .line 11
    .line 12
    :goto_0
    invoke-static {v0, v1}, Lkp/f9;->c(J)J

    .line 13
    .line 14
    .line 15
    move-result-wide v0

    .line 16
    iget-object p2, p2, Ld4/q;->c:Lv3/h0;

    .line 17
    .line 18
    iget-object p2, p2, Lv3/h0;->B:Lt4/m;

    .line 19
    .line 20
    iget-object p0, p0, Lw3/z;->d:Lw3/t;

    .line 21
    .line 22
    invoke-virtual {p0}, Lw3/t;->getDensity()Lt4/c;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    invoke-interface {p1, v0, v1, p2, p0}, Le3/n0;->a(JLt4/m;Lt4/c;)Le3/g0;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0
.end method

.method public final q(ILjava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/CharSequence;)Landroid/view/accessibility/AccessibilityEvent;
    .locals 1

    .line 1
    const/16 v0, 0x2000

    .line 2
    .line 3
    invoke-virtual {p0, p1, v0}, Lw3/z;->o(II)Landroid/view/accessibility/AccessibilityEvent;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    if-eqz p2, :cond_0

    .line 8
    .line 9
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    invoke-virtual {p0, p1}, Landroid/view/accessibility/AccessibilityRecord;->setFromIndex(I)V

    .line 14
    .line 15
    .line 16
    :cond_0
    if-eqz p3, :cond_1

    .line 17
    .line 18
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 19
    .line 20
    .line 21
    move-result p1

    .line 22
    invoke-virtual {p0, p1}, Landroid/view/accessibility/AccessibilityRecord;->setToIndex(I)V

    .line 23
    .line 24
    .line 25
    :cond_1
    if-eqz p4, :cond_2

    .line 26
    .line 27
    invoke-virtual {p4}, Ljava/lang/Number;->intValue()I

    .line 28
    .line 29
    .line 30
    move-result p1

    .line 31
    invoke-virtual {p0, p1}, Landroid/view/accessibility/AccessibilityRecord;->setItemCount(I)V

    .line 32
    .line 33
    .line 34
    :cond_2
    if-eqz p5, :cond_3

    .line 35
    .line 36
    invoke-virtual {p0}, Landroid/view/accessibility/AccessibilityRecord;->getText()Ljava/util/List;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    invoke-interface {p1, p5}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    :cond_3
    return-object p0
.end method

.method public final r(Ld4/q;)I
    .locals 2

    .line 1
    iget-object v0, p1, Ld4/q;->d:Ld4/l;

    .line 2
    .line 3
    iget-object p1, p1, Ld4/q;->d:Ld4/l;

    .line 4
    .line 5
    sget-object v1, Ld4/v;->a:Ld4/z;

    .line 6
    .line 7
    sget-object v1, Ld4/v;->a:Ld4/z;

    .line 8
    .line 9
    iget-object v0, v0, Ld4/l;->d:Landroidx/collection/q0;

    .line 10
    .line 11
    invoke-virtual {v0, v1}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    sget-object v0, Ld4/v;->F:Ld4/z;

    .line 18
    .line 19
    iget-object v1, p1, Ld4/l;->d:Landroidx/collection/q0;

    .line 20
    .line 21
    invoke-virtual {v1, v0}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    if-eqz v1, :cond_0

    .line 26
    .line 27
    invoke-virtual {p1, v0}, Ld4/l;->e(Ld4/z;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Lg4/o0;

    .line 32
    .line 33
    iget-wide p0, p0, Lg4/o0;->a:J

    .line 34
    .line 35
    const-wide v0, 0xffffffffL

    .line 36
    .line 37
    .line 38
    .line 39
    .line 40
    and-long/2addr p0, v0

    .line 41
    long-to-int p0, p0

    .line 42
    return p0

    .line 43
    :cond_0
    iget p0, p0, Lw3/z;->w:I

    .line 44
    .line 45
    return p0
.end method

.method public final s(Ld4/q;)I
    .locals 2

    .line 1
    iget-object v0, p1, Ld4/q;->d:Ld4/l;

    .line 2
    .line 3
    iget-object p1, p1, Ld4/q;->d:Ld4/l;

    .line 4
    .line 5
    sget-object v1, Ld4/v;->a:Ld4/z;

    .line 6
    .line 7
    sget-object v1, Ld4/v;->a:Ld4/z;

    .line 8
    .line 9
    iget-object v0, v0, Ld4/l;->d:Landroidx/collection/q0;

    .line 10
    .line 11
    invoke-virtual {v0, v1}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    sget-object v0, Ld4/v;->F:Ld4/z;

    .line 18
    .line 19
    iget-object v1, p1, Ld4/l;->d:Landroidx/collection/q0;

    .line 20
    .line 21
    invoke-virtual {v1, v0}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    if-eqz v1, :cond_0

    .line 26
    .line 27
    invoke-virtual {p1, v0}, Ld4/l;->e(Ld4/z;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Lg4/o0;

    .line 32
    .line 33
    iget-wide p0, p0, Lg4/o0;->a:J

    .line 34
    .line 35
    const/16 v0, 0x20

    .line 36
    .line 37
    shr-long/2addr p0, v0

    .line 38
    long-to-int p0, p0

    .line 39
    return p0

    .line 40
    :cond_0
    iget p0, p0, Lw3/z;->w:I

    .line 41
    .line 42
    return p0
.end method

.method public final t()Landroidx/collection/p;
    .locals 7

    .line 1
    iget-boolean v0, p0, Lw3/z;->A:Z

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    iput-boolean v0, p0, Lw3/z;->A:Z

    .line 7
    .line 8
    iget-object v0, p0, Lw3/z;->d:Lw3/t;

    .line 9
    .line 10
    invoke-virtual {v0}, Lw3/t;->getSemanticsOwner()Ld4/s;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-static {v1}, Ld4/t;->b(Ld4/s;)Landroidx/collection/b0;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    iput-object v1, p0, Lw3/z;->C:Landroidx/collection/b0;

    .line 19
    .line 20
    invoke-virtual {p0}, Lw3/z;->v()Z

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    if-eqz v1, :cond_1

    .line 25
    .line 26
    iget-object v1, p0, Lw3/z;->C:Landroidx/collection/b0;

    .line 27
    .line 28
    invoke-virtual {v0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    invoke-virtual {v0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    iget-object v2, p0, Lw3/z;->E:Landroidx/collection/z;

    .line 37
    .line 38
    invoke-virtual {v2}, Landroidx/collection/z;->a()V

    .line 39
    .line 40
    .line 41
    iget-object v3, p0, Lw3/z;->F:Landroidx/collection/z;

    .line 42
    .line 43
    invoke-virtual {v3}, Landroidx/collection/z;->a()V

    .line 44
    .line 45
    .line 46
    const/4 v4, -0x1

    .line 47
    invoke-virtual {v1, v4}, Landroidx/collection/p;->b(I)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v4

    .line 51
    check-cast v4, Ld4/r;

    .line 52
    .line 53
    if-eqz v4, :cond_0

    .line 54
    .line 55
    iget-object v4, v4, Ld4/r;->a:Ld4/q;

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_0
    const/4 v4, 0x0

    .line 59
    :goto_0
    invoke-static {v4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    new-instance v5, Lw3/a0;

    .line 63
    .line 64
    const/4 v6, 0x0

    .line 65
    invoke-direct {v5, v1, v6}, Lw3/a0;-><init>(Ljava/lang/Object;I)V

    .line 66
    .line 67
    .line 68
    new-instance v1, Lw3/a0;

    .line 69
    .line 70
    const/4 v6, 0x1

    .line 71
    invoke-direct {v1, v0, v6}, Lw3/a0;-><init>(Ljava/lang/Object;I)V

    .line 72
    .line 73
    .line 74
    invoke-static {v4}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    invoke-static {v4, v5, v1, v0}, Ld4/c0;->b(Ld4/q;Lw3/a0;Lw3/a0;Ljava/util/List;)Ljava/util/ArrayList;

    .line 79
    .line 80
    .line 81
    move-result-object v0

    .line 82
    invoke-static {v0}, Ljp/k1;->h(Ljava/util/List;)I

    .line 83
    .line 84
    .line 85
    move-result v1

    .line 86
    const/4 v4, 0x1

    .line 87
    if-gt v4, v1, :cond_1

    .line 88
    .line 89
    :goto_1
    add-int/lit8 v5, v4, -0x1

    .line 90
    .line 91
    invoke-virtual {v0, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v5

    .line 95
    check-cast v5, Ld4/q;

    .line 96
    .line 97
    iget v5, v5, Ld4/q;->g:I

    .line 98
    .line 99
    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object v6

    .line 103
    check-cast v6, Ld4/q;

    .line 104
    .line 105
    iget v6, v6, Ld4/q;->g:I

    .line 106
    .line 107
    invoke-virtual {v2, v5, v6}, Landroidx/collection/z;->f(II)V

    .line 108
    .line 109
    .line 110
    invoke-virtual {v3, v6, v5}, Landroidx/collection/z;->f(II)V

    .line 111
    .line 112
    .line 113
    if-eq v4, v1, :cond_1

    .line 114
    .line 115
    add-int/lit8 v4, v4, 0x1

    .line 116
    .line 117
    goto :goto_1

    .line 118
    :cond_1
    iget-object p0, p0, Lw3/z;->C:Landroidx/collection/b0;

    .line 119
    .line 120
    return-object p0
.end method

.method public final v()Z
    .locals 1

    .line 1
    iget-object v0, p0, Lw3/z;->g:Landroid/view/accessibility/AccessibilityManager;

    .line 2
    .line 3
    invoke-virtual {v0}, Landroid/view/accessibility/AccessibilityManager;->isEnabled()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    iget-object p0, p0, Lw3/z;->k:Ljava/util/List;

    .line 10
    .line 11
    check-cast p0, Ljava/util/Collection;

    .line 12
    .line 13
    invoke-interface {p0}, Ljava/util/Collection;->isEmpty()Z

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    if-nez p0, :cond_0

    .line 18
    .line 19
    const/4 p0, 0x1

    .line 20
    return p0

    .line 21
    :cond_0
    const/4 p0, 0x0

    .line 22
    return p0
.end method

.method public final w(Lv3/h0;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lw3/z;->y:Landroidx/collection/g;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Landroidx/collection/g;->add(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    if-eqz p1, :cond_0

    .line 8
    .line 9
    iget-object p0, p0, Lw3/z;->z:Lxy0/j;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-interface {p0, p1}, Lxy0/a0;->e(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    :cond_0
    return-void
.end method
