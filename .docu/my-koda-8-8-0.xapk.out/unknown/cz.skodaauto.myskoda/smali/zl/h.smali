.class public final Lzl/h;
.super Li3/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll2/z1;


# static fields
.field public static final y:Lz70/e0;


# instance fields
.field public final i:Ll2/j1;

.field public j:F

.field public k:Le3/m;

.field public l:Z

.field public m:Lvy0/i1;

.field public n:J

.field public o:Lvy0/b0;

.field public p:Lay0/k;

.field public q:Lay0/k;

.field public r:Lt3/k;

.field public s:I

.field public t:Lzl/l;

.field public u:Lzl/b;

.field public final v:Lyy0/c2;

.field public final w:Lyy0/c2;

.field public final x:Lyy0/l1;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lz70/e0;

    .line 2
    .line 3
    const/16 v1, 0x17

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lz70/e0;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lzl/h;->y:Lz70/e0;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>(Lzl/b;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Li3/c;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iput-object v0, p0, Lzl/h;->i:Ll2/j1;

    .line 10
    .line 11
    const/high16 v0, 0x3f800000    # 1.0f

    .line 12
    .line 13
    iput v0, p0, Lzl/h;->j:F

    .line 14
    .line 15
    const-wide v0, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 16
    .line 17
    .line 18
    .line 19
    .line 20
    iput-wide v0, p0, Lzl/h;->n:J

    .line 21
    .line 22
    sget-object v0, Lzl/h;->y:Lz70/e0;

    .line 23
    .line 24
    iput-object v0, p0, Lzl/h;->p:Lay0/k;

    .line 25
    .line 26
    sget-object v0, Lt3/j;->b:Lt3/x0;

    .line 27
    .line 28
    iput-object v0, p0, Lzl/h;->r:Lt3/k;

    .line 29
    .line 30
    const/4 v0, 0x1

    .line 31
    iput v0, p0, Lzl/h;->s:I

    .line 32
    .line 33
    iput-object p1, p0, Lzl/h;->u:Lzl/b;

    .line 34
    .line 35
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    iput-object p1, p0, Lzl/h;->v:Lyy0/c2;

    .line 40
    .line 41
    sget-object p1, Lzl/c;->a:Lzl/c;

    .line 42
    .line 43
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    iput-object p1, p0, Lzl/h;->w:Lyy0/c2;

    .line 48
    .line 49
    new-instance v0, Lyy0/l1;

    .line 50
    .line 51
    invoke-direct {v0, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 52
    .line 53
    .line 54
    iput-object v0, p0, Lzl/h;->x:Lyy0/l1;

    .line 55
    .line 56
    return-void
.end method

.method public static final j(Lzl/h;Lmm/g;Z)Lmm/g;
    .locals 2

    .line 1
    invoke-static {p1}, Lmm/g;->a(Lmm/g;)Lmm/d;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v1, Ly41/a;

    .line 6
    .line 7
    invoke-direct {v1, p1, p0}, Ly41/a;-><init>(Lmm/g;Lzl/h;)V

    .line 8
    .line 9
    .line 10
    iput-object v1, v0, Lmm/d;->d:Lqm/a;

    .line 11
    .line 12
    iget-object p1, p1, Lmm/g;->s:Lmm/f;

    .line 13
    .line 14
    iget-object v1, p1, Lmm/f;->i:Lnm/i;

    .line 15
    .line 16
    if-nez v1, :cond_0

    .line 17
    .line 18
    sget-object v1, Lnm/i;->a:Lnm/e;

    .line 19
    .line 20
    iput-object v1, v0, Lmm/d;->o:Lnm/i;

    .line 21
    .line 22
    :cond_0
    iget-object v1, p1, Lmm/f;->j:Lnm/g;

    .line 23
    .line 24
    if-nez v1, :cond_3

    .line 25
    .line 26
    iget-object p0, p0, Lzl/h;->r:Lt3/k;

    .line 27
    .line 28
    sget v1, Lam/i;->b:I

    .line 29
    .line 30
    sget-object v1, Lt3/j;->b:Lt3/x0;

    .line 31
    .line 32
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    if-nez v1, :cond_2

    .line 37
    .line 38
    sget-object v1, Lt3/j;->e:Lt3/x0;

    .line 39
    .line 40
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    if-eqz p0, :cond_1

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_1
    sget-object p0, Lnm/g;->d:Lnm/g;

    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_2
    :goto_0
    sget-object p0, Lnm/g;->e:Lnm/g;

    .line 51
    .line 52
    :goto_1
    iput-object p0, v0, Lmm/d;->p:Lnm/g;

    .line 53
    .line 54
    :cond_3
    iget-object p0, p1, Lmm/f;->k:Lnm/d;

    .line 55
    .line 56
    if-nez p0, :cond_4

    .line 57
    .line 58
    sget-object p0, Lnm/d;->e:Lnm/d;

    .line 59
    .line 60
    iput-object p0, v0, Lmm/d;->q:Lnm/d;

    .line 61
    .line 62
    :cond_4
    if-eqz p2, :cond_5

    .line 63
    .line 64
    sget-object p0, Lpx0/h;->d:Lpx0/h;

    .line 65
    .line 66
    iput-object p0, v0, Lmm/d;->g:Lpx0/g;

    .line 67
    .line 68
    iput-object p0, v0, Lmm/d;->h:Lpx0/g;

    .line 69
    .line 70
    iput-object p0, v0, Lmm/d;->i:Lpx0/g;

    .line 71
    .line 72
    :cond_5
    invoke-virtual {v0}, Lmm/d;->a()Lmm/g;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    return-object p0
.end method

.method public static final k(Lzl/h;Lzl/g;)V
    .locals 10

    .line 1
    iget-object v0, p0, Lzl/h;->w:Lyy0/c2;

    .line 2
    .line 3
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    check-cast v1, Lzl/g;

    .line 8
    .line 9
    iget-object v2, p0, Lzl/h;->p:Lay0/k;

    .line 10
    .line 11
    invoke-interface {v2, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    check-cast p1, Lzl/g;

    .line 16
    .line 17
    invoke-virtual {v0, p1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    iget-object v5, p0, Lzl/h;->r:Lt3/k;

    .line 21
    .line 22
    instance-of v0, p1, Lzl/f;

    .line 23
    .line 24
    const/4 v9, 0x0

    .line 25
    if-eqz v0, :cond_0

    .line 26
    .line 27
    move-object v0, p1

    .line 28
    check-cast v0, Lzl/f;

    .line 29
    .line 30
    iget-object v0, v0, Lzl/f;->b:Lmm/p;

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    instance-of v0, p1, Lzl/d;

    .line 34
    .line 35
    if-eqz v0, :cond_4

    .line 36
    .line 37
    move-object v0, p1

    .line 38
    check-cast v0, Lzl/d;

    .line 39
    .line 40
    iget-object v0, v0, Lzl/d;->b:Lmm/c;

    .line 41
    .line 42
    :goto_0
    invoke-interface {v0}, Lmm/j;->a()Lmm/g;

    .line 43
    .line 44
    .line 45
    move-result-object v2

    .line 46
    sget-object v3, Lmm/i;->a:Ld8/c;

    .line 47
    .line 48
    invoke-static {v2, v3}, Lyl/m;->d(Lmm/g;Ld8/c;)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    check-cast v2, Lrm/e;

    .line 53
    .line 54
    sget-object v3, Lzl/j;->a:Lzl/i;

    .line 55
    .line 56
    invoke-interface {v2, v3, v0}, Lrm/e;->a(Lzl/i;Lmm/j;)Lrm/f;

    .line 57
    .line 58
    .line 59
    move-result-object v2

    .line 60
    instance-of v3, v2, Lrm/b;

    .line 61
    .line 62
    if-eqz v3, :cond_4

    .line 63
    .line 64
    invoke-interface {v1}, Lzl/g;->a()Li3/c;

    .line 65
    .line 66
    .line 67
    move-result-object v3

    .line 68
    instance-of v4, v1, Lzl/e;

    .line 69
    .line 70
    if-eqz v4, :cond_1

    .line 71
    .line 72
    goto :goto_1

    .line 73
    :cond_1
    move-object v3, v9

    .line 74
    :goto_1
    invoke-interface {p1}, Lzl/g;->a()Li3/c;

    .line 75
    .line 76
    .line 77
    move-result-object v4

    .line 78
    sget v6, Lmy0/c;->g:I

    .line 79
    .line 80
    check-cast v2, Lrm/b;

    .line 81
    .line 82
    iget v2, v2, Lrm/b;->c:I

    .line 83
    .line 84
    sget-object v6, Lmy0/e;->g:Lmy0/e;

    .line 85
    .line 86
    invoke-static {v2, v6}, Lmy0/h;->s(ILmy0/e;)J

    .line 87
    .line 88
    .line 89
    move-result-wide v6

    .line 90
    instance-of v2, v0, Lmm/p;

    .line 91
    .line 92
    if-eqz v2, :cond_3

    .line 93
    .line 94
    check-cast v0, Lmm/p;

    .line 95
    .line 96
    iget-boolean v0, v0, Lmm/p;->g:Z

    .line 97
    .line 98
    if-nez v0, :cond_2

    .line 99
    .line 100
    goto :goto_3

    .line 101
    :cond_2
    const/4 v0, 0x0

    .line 102
    :goto_2
    move v8, v0

    .line 103
    goto :goto_4

    .line 104
    :cond_3
    :goto_3
    const/4 v0, 0x1

    .line 105
    goto :goto_2

    .line 106
    :goto_4
    new-instance v2, Lzl/o;

    .line 107
    .line 108
    invoke-direct/range {v2 .. v8}, Lzl/o;-><init>(Li3/c;Li3/c;Lt3/k;JZ)V

    .line 109
    .line 110
    .line 111
    goto :goto_5

    .line 112
    :cond_4
    move-object v2, v9

    .line 113
    :goto_5
    if-eqz v2, :cond_5

    .line 114
    .line 115
    goto :goto_6

    .line 116
    :cond_5
    invoke-interface {p1}, Lzl/g;->a()Li3/c;

    .line 117
    .line 118
    .line 119
    move-result-object v2

    .line 120
    :goto_6
    iget-object v0, p0, Lzl/h;->i:Ll2/j1;

    .line 121
    .line 122
    invoke-virtual {v0, v2}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 123
    .line 124
    .line 125
    invoke-interface {v1}, Lzl/g;->a()Li3/c;

    .line 126
    .line 127
    .line 128
    move-result-object v0

    .line 129
    invoke-interface {p1}, Lzl/g;->a()Li3/c;

    .line 130
    .line 131
    .line 132
    move-result-object v2

    .line 133
    if-eq v0, v2, :cond_9

    .line 134
    .line 135
    invoke-interface {v1}, Lzl/g;->a()Li3/c;

    .line 136
    .line 137
    .line 138
    move-result-object v0

    .line 139
    instance-of v1, v0, Ll2/z1;

    .line 140
    .line 141
    if-eqz v1, :cond_6

    .line 142
    .line 143
    check-cast v0, Ll2/z1;

    .line 144
    .line 145
    goto :goto_7

    .line 146
    :cond_6
    move-object v0, v9

    .line 147
    :goto_7
    if-eqz v0, :cond_7

    .line 148
    .line 149
    invoke-interface {v0}, Ll2/z1;->h()V

    .line 150
    .line 151
    .line 152
    :cond_7
    invoke-interface {p1}, Lzl/g;->a()Li3/c;

    .line 153
    .line 154
    .line 155
    move-result-object v0

    .line 156
    instance-of v1, v0, Ll2/z1;

    .line 157
    .line 158
    if-eqz v1, :cond_8

    .line 159
    .line 160
    move-object v9, v0

    .line 161
    check-cast v9, Ll2/z1;

    .line 162
    .line 163
    :cond_8
    if-eqz v9, :cond_9

    .line 164
    .line 165
    invoke-interface {v9}, Ll2/z1;->c()V

    .line 166
    .line 167
    .line 168
    :cond_9
    iget-object p0, p0, Lzl/h;->q:Lay0/k;

    .line 169
    .line 170
    if-eqz p0, :cond_a

    .line 171
    .line 172
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    :cond_a
    return-void
.end method


# virtual methods
.method public final a(F)Z
    .locals 0

    .line 1
    iput p1, p0, Lzl/h;->j:F

    .line 2
    .line 3
    const/4 p0, 0x1

    .line 4
    return p0
.end method

.method public final b(Le3/m;)Z
    .locals 0

    .line 1
    iput-object p1, p0, Lzl/h;->k:Le3/m;

    .line 2
    .line 3
    const/4 p0, 0x1

    .line 4
    return p0
.end method

.method public final c()V
    .locals 2

    .line 1
    const-string v0, "AsyncImagePainter.onRemembered"

    .line 2
    .line 3
    invoke-static {v0}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    :try_start_0
    iget-object v0, p0, Lzl/h;->i:Ll2/j1;

    .line 7
    .line 8
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    check-cast v0, Li3/c;

    .line 13
    .line 14
    instance-of v1, v0, Ll2/z1;

    .line 15
    .line 16
    if-eqz v1, :cond_0

    .line 17
    .line 18
    check-cast v0, Ll2/z1;

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v0, 0x0

    .line 22
    :goto_0
    if-eqz v0, :cond_1

    .line 23
    .line 24
    invoke-interface {v0}, Ll2/z1;->c()V

    .line 25
    .line 26
    .line 27
    :cond_1
    invoke-virtual {p0}, Lzl/h;->l()V

    .line 28
    .line 29
    .line 30
    const/4 v0, 0x1

    .line 31
    iput-boolean v0, p0, Lzl/h;->l:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 32
    .line 33
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 34
    .line 35
    .line 36
    return-void

    .line 37
    :catchall_0
    move-exception p0

    .line 38
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 39
    .line 40
    .line 41
    throw p0
.end method

.method public final e()V
    .locals 3

    .line 1
    iget-object v0, p0, Lzl/h;->m:Lvy0/i1;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    invoke-interface {v0, v1}, Lvy0/i1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 7
    .line 8
    .line 9
    :cond_0
    iput-object v1, p0, Lzl/h;->m:Lvy0/i1;

    .line 10
    .line 11
    iget-object v0, p0, Lzl/h;->i:Ll2/j1;

    .line 12
    .line 13
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    check-cast v0, Li3/c;

    .line 18
    .line 19
    instance-of v2, v0, Ll2/z1;

    .line 20
    .line 21
    if-eqz v2, :cond_1

    .line 22
    .line 23
    move-object v1, v0

    .line 24
    check-cast v1, Ll2/z1;

    .line 25
    .line 26
    :cond_1
    if-eqz v1, :cond_2

    .line 27
    .line 28
    invoke-interface {v1}, Ll2/z1;->e()V

    .line 29
    .line 30
    .line 31
    :cond_2
    const/4 v0, 0x0

    .line 32
    iput-boolean v0, p0, Lzl/h;->l:Z

    .line 33
    .line 34
    return-void
.end method

.method public final g()J
    .locals 2

    .line 1
    iget-object p0, p0, Lzl/h;->i:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Li3/c;

    .line 8
    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    invoke-virtual {p0}, Li3/c;->g()J

    .line 12
    .line 13
    .line 14
    move-result-wide v0

    .line 15
    return-wide v0

    .line 16
    :cond_0
    const-wide v0, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 17
    .line 18
    .line 19
    .line 20
    .line 21
    return-wide v0
.end method

.method public final h()V
    .locals 3

    .line 1
    iget-object v0, p0, Lzl/h;->m:Lvy0/i1;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    invoke-interface {v0, v1}, Lvy0/i1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 7
    .line 8
    .line 9
    :cond_0
    iput-object v1, p0, Lzl/h;->m:Lvy0/i1;

    .line 10
    .line 11
    iget-object v0, p0, Lzl/h;->i:Ll2/j1;

    .line 12
    .line 13
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    check-cast v0, Li3/c;

    .line 18
    .line 19
    instance-of v2, v0, Ll2/z1;

    .line 20
    .line 21
    if-eqz v2, :cond_1

    .line 22
    .line 23
    move-object v1, v0

    .line 24
    check-cast v1, Ll2/z1;

    .line 25
    .line 26
    :cond_1
    if-eqz v1, :cond_2

    .line 27
    .line 28
    invoke-interface {v1}, Ll2/z1;->h()V

    .line 29
    .line 30
    .line 31
    :cond_2
    const/4 v0, 0x0

    .line 32
    iput-boolean v0, p0, Lzl/h;->l:Z

    .line 33
    .line 34
    return-void
.end method

.method public final i(Lg3/d;)V
    .locals 7

    .line 1
    invoke-interface {p1}, Lg3/d;->e()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    iget-wide v2, p0, Lzl/h;->n:J

    .line 6
    .line 7
    invoke-static {v2, v3, v0, v1}, Ld3/e;->a(JJ)Z

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    if-nez v2, :cond_0

    .line 12
    .line 13
    iput-wide v0, p0, Lzl/h;->n:J

    .line 14
    .line 15
    :cond_0
    iget-object v0, p0, Lzl/h;->i:Ll2/j1;

    .line 16
    .line 17
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    move-object v1, v0

    .line 22
    check-cast v1, Li3/c;

    .line 23
    .line 24
    if-eqz v1, :cond_1

    .line 25
    .line 26
    invoke-interface {p1}, Lg3/d;->e()J

    .line 27
    .line 28
    .line 29
    move-result-wide v3

    .line 30
    iget v5, p0, Lzl/h;->j:F

    .line 31
    .line 32
    iget-object v6, p0, Lzl/h;->k:Le3/m;

    .line 33
    .line 34
    move-object v2, p1

    .line 35
    invoke-virtual/range {v1 .. v6}, Li3/c;->f(Lg3/d;JFLe3/m;)V

    .line 36
    .line 37
    .line 38
    :cond_1
    return-void
.end method

.method public final l()V
    .locals 5

    .line 1
    iget-object v0, p0, Lzl/h;->u:Lzl/b;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    iget-object v1, p0, Lzl/h;->o:Lvy0/b0;

    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    if-eqz v1, :cond_4

    .line 10
    .line 11
    new-instance v3, Lws/b;

    .line 12
    .line 13
    const/16 v4, 0x15

    .line 14
    .line 15
    invoke-direct {v3, v4, p0, v0, v2}, Lws/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 16
    .line 17
    .line 18
    invoke-interface {v1}, Lvy0/b0;->getCoroutineContext()Lpx0/g;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    sget v4, Lam/i;->b:I

    .line 23
    .line 24
    sget-object v4, Lvy0/x;->d:Lvy0/w;

    .line 25
    .line 26
    invoke-interface {v0, v4}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    check-cast v0, Lvy0/x;

    .line 31
    .line 32
    if-eqz v0, :cond_2

    .line 33
    .line 34
    sget-object v4, Lvy0/p0;->b:Lvy0/h2;

    .line 35
    .line 36
    invoke-virtual {v0, v4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    move-result v4

    .line 40
    if-eqz v4, :cond_1

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_1
    new-instance v4, Lam/e;

    .line 44
    .line 45
    invoke-interface {v1}, Lvy0/b0;->getCoroutineContext()Lpx0/g;

    .line 46
    .line 47
    .line 48
    move-result-object v1

    .line 49
    invoke-direct {v4, v1}, Lam/e;-><init>(Lpx0/g;)V

    .line 50
    .line 51
    .line 52
    invoke-static {v4}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    new-instance v4, Lam/f;

    .line 57
    .line 58
    invoke-direct {v4, v0}, Lam/f;-><init>(Lvy0/x;)V

    .line 59
    .line 60
    .line 61
    sget-object v0, Lvy0/c0;->g:Lvy0/c0;

    .line 62
    .line 63
    invoke-static {v1, v4, v0, v3}, Lvy0/e0;->D(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;)Lvy0/x1;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    goto :goto_1

    .line 68
    :cond_2
    :goto_0
    sget-object v0, Lvy0/p0;->b:Lvy0/h2;

    .line 69
    .line 70
    sget-object v4, Lvy0/c0;->g:Lvy0/c0;

    .line 71
    .line 72
    invoke-static {v1, v0, v4, v3}, Lvy0/e0;->D(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;)Lvy0/x1;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    :goto_1
    iget-object v1, p0, Lzl/h;->m:Lvy0/i1;

    .line 77
    .line 78
    if-eqz v1, :cond_3

    .line 79
    .line 80
    invoke-interface {v1, v2}, Lvy0/i1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 81
    .line 82
    .line 83
    :cond_3
    iput-object v0, p0, Lzl/h;->m:Lvy0/i1;

    .line 84
    .line 85
    return-void

    .line 86
    :cond_4
    const-string p0, "scope"

    .line 87
    .line 88
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    throw v2
.end method

.method public final m(Lzl/b;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lzl/h;->u:Lzl/b;

    .line 2
    .line 3
    invoke-static {v0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_3

    .line 8
    .line 9
    iput-object p1, p0, Lzl/h;->u:Lzl/b;

    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    if-nez p1, :cond_1

    .line 13
    .line 14
    iget-object v1, p0, Lzl/h;->m:Lvy0/i1;

    .line 15
    .line 16
    if-eqz v1, :cond_0

    .line 17
    .line 18
    invoke-interface {v1, v0}, Lvy0/i1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 19
    .line 20
    .line 21
    :cond_0
    iput-object v0, p0, Lzl/h;->m:Lvy0/i1;

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_1
    iget-boolean v1, p0, Lzl/h;->l:Z

    .line 25
    .line 26
    if-eqz v1, :cond_2

    .line 27
    .line 28
    invoke-virtual {p0}, Lzl/h;->l()V

    .line 29
    .line 30
    .line 31
    :cond_2
    :goto_0
    if-eqz p1, :cond_3

    .line 32
    .line 33
    iget-object p0, p0, Lzl/h;->v:Lyy0/c2;

    .line 34
    .line 35
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 36
    .line 37
    .line 38
    invoke-virtual {p0, v0, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    :cond_3
    return-void
.end method
