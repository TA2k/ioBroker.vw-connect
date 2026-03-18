.class public final Ln1/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lg1/q2;


# static fields
.field public static final w:Lu2/l;


# instance fields
.field public final a:Lm1/a;

.field public b:Z

.field public c:Ln1/n;

.field public final d:Lm1/o;

.field public final e:Ll2/j1;

.field public final f:Li1/l;

.field public g:F

.field public final h:Lg1/f0;

.field public final i:Z

.field public j:Lv3/h0;

.field public final k:Lm1/r;

.field public final l:Lo1/d;

.field public final m:Landroidx/compose/foundation/lazy/layout/b;

.field public final n:Lg1/r;

.field public final o:Lo1/l0;

.field public final p:Lj1/a;

.field public final q:Lo1/i0;

.field public final r:Ll2/b1;

.field public final s:Ll2/b1;

.field public final t:Ll2/j1;

.field public final u:Ll2/j1;

.field public final v:Lb81/a;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lmo0/a;

    .line 2
    .line 3
    const/4 v1, 0x7

    .line 4
    invoke-direct {v0, v1}, Lmo0/a;-><init>(I)V

    .line 5
    .line 6
    .line 7
    new-instance v1, Lmj/g;

    .line 8
    .line 9
    const/16 v2, 0xd

    .line 10
    .line 11
    invoke-direct {v1, v2}, Lmj/g;-><init>(I)V

    .line 12
    .line 13
    .line 14
    invoke-static {v0, v1}, Lu2/m;->b(Lay0/n;Lay0/k;)Lu2/l;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    sput-object v0, Ln1/v;->w:Lu2/l;

    .line 19
    .line 20
    return-void
.end method

.method public constructor <init>(II)V
    .locals 4

    .line 1
    new-instance v0, Lm1/a;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 v1, -0x1

    .line 7
    iput v1, v0, Lm1/a;->a:I

    .line 8
    .line 9
    new-instance v2, Ln2/b;

    .line 10
    .line 11
    const/16 v3, 0x10

    .line 12
    .line 13
    new-array v3, v3, [Lo1/k0;

    .line 14
    .line 15
    invoke-direct {v2, v3}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    iput-object v2, v0, Lm1/a;->e:Ljava/lang/Object;

    .line 19
    .line 20
    iput v1, v0, Lm1/a;->c:I

    .line 21
    .line 22
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 23
    .line 24
    .line 25
    iput-object v0, p0, Ln1/v;->a:Lm1/a;

    .line 26
    .line 27
    new-instance v0, Lm1/o;

    .line 28
    .line 29
    const/4 v1, 0x1

    .line 30
    invoke-direct {v0, p1, p2, v1}, Lm1/o;-><init>(III)V

    .line 31
    .line 32
    .line 33
    iput-object v0, p0, Ln1/v;->d:Lm1/o;

    .line 34
    .line 35
    sget-object p2, Ln1/x;->a:Ln1/n;

    .line 36
    .line 37
    sget-object v0, Ll2/x0;->f:Ll2/x0;

    .line 38
    .line 39
    new-instance v1, Ll2/j1;

    .line 40
    .line 41
    invoke-direct {v1, p2, v0}, Ll2/j1;-><init>(Ljava/lang/Object;Ll2/n2;)V

    .line 42
    .line 43
    .line 44
    iput-object v1, p0, Ln1/v;->e:Ll2/j1;

    .line 45
    .line 46
    new-instance p2, Li1/l;

    .line 47
    .line 48
    invoke-direct {p2}, Li1/l;-><init>()V

    .line 49
    .line 50
    .line 51
    iput-object p2, p0, Ln1/v;->f:Li1/l;

    .line 52
    .line 53
    new-instance p2, Lla/p;

    .line 54
    .line 55
    const/16 v0, 0x13

    .line 56
    .line 57
    invoke-direct {p2, p0, v0}, Lla/p;-><init>(Ljava/lang/Object;I)V

    .line 58
    .line 59
    .line 60
    new-instance v0, Lg1/f0;

    .line 61
    .line 62
    invoke-direct {v0, p2}, Lg1/f0;-><init>(Lay0/k;)V

    .line 63
    .line 64
    .line 65
    iput-object v0, p0, Ln1/v;->h:Lg1/f0;

    .line 66
    .line 67
    const/4 p2, 0x1

    .line 68
    iput-boolean p2, p0, Ln1/v;->i:Z

    .line 69
    .line 70
    new-instance p2, Lm1/r;

    .line 71
    .line 72
    const/4 v0, 0x1

    .line 73
    invoke-direct {p2, p0, v0}, Lm1/r;-><init>(Lg1/q2;I)V

    .line 74
    .line 75
    .line 76
    iput-object p2, p0, Ln1/v;->k:Lm1/r;

    .line 77
    .line 78
    new-instance p2, Lo1/d;

    .line 79
    .line 80
    invoke-direct {p2}, Lo1/d;-><init>()V

    .line 81
    .line 82
    .line 83
    iput-object p2, p0, Ln1/v;->l:Lo1/d;

    .line 84
    .line 85
    new-instance p2, Landroidx/compose/foundation/lazy/layout/b;

    .line 86
    .line 87
    invoke-direct {p2}, Landroidx/compose/foundation/lazy/layout/b;-><init>()V

    .line 88
    .line 89
    .line 90
    iput-object p2, p0, Ln1/v;->m:Landroidx/compose/foundation/lazy/layout/b;

    .line 91
    .line 92
    new-instance p2, Lg1/r;

    .line 93
    .line 94
    invoke-direct {p2, v0}, Lg1/r;-><init>(I)V

    .line 95
    .line 96
    .line 97
    iput-object p2, p0, Ln1/v;->n:Lg1/r;

    .line 98
    .line 99
    new-instance p2, Lo1/l0;

    .line 100
    .line 101
    new-instance v0, Lcz/m;

    .line 102
    .line 103
    const/4 v1, 0x1

    .line 104
    invoke-direct {v0, p0, p1, v1}, Lcz/m;-><init>(Ljava/lang/Object;II)V

    .line 105
    .line 106
    .line 107
    invoke-direct {p2, v0}, Lo1/l0;-><init>(Lay0/k;)V

    .line 108
    .line 109
    .line 110
    iput-object p2, p0, Ln1/v;->o:Lo1/l0;

    .line 111
    .line 112
    new-instance p1, Lj1/a;

    .line 113
    .line 114
    const/16 p2, 0x13

    .line 115
    .line 116
    invoke-direct {p1, p0, p2}, Lj1/a;-><init>(Ljava/lang/Object;I)V

    .line 117
    .line 118
    .line 119
    iput-object p1, p0, Ln1/v;->p:Lj1/a;

    .line 120
    .line 121
    new-instance p1, Lo1/i0;

    .line 122
    .line 123
    invoke-direct {p1}, Lo1/i0;-><init>()V

    .line 124
    .line 125
    .line 126
    iput-object p1, p0, Ln1/v;->q:Lo1/i0;

    .line 127
    .line 128
    invoke-static {}, Lo1/y;->h()Ll2/b1;

    .line 129
    .line 130
    .line 131
    move-result-object p1

    .line 132
    iput-object p1, p0, Ln1/v;->r:Ll2/b1;

    .line 133
    .line 134
    invoke-static {}, Lo1/y;->h()Ll2/b1;

    .line 135
    .line 136
    .line 137
    move-result-object p1

    .line 138
    iput-object p1, p0, Ln1/v;->s:Ll2/b1;

    .line 139
    .line 140
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 141
    .line 142
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 143
    .line 144
    .line 145
    move-result-object p2

    .line 146
    iput-object p2, p0, Ln1/v;->t:Ll2/j1;

    .line 147
    .line 148
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 149
    .line 150
    .line 151
    move-result-object p1

    .line 152
    iput-object p1, p0, Ln1/v;->u:Ll2/j1;

    .line 153
    .line 154
    new-instance p1, Lb81/a;

    .line 155
    .line 156
    const/16 p2, 0x14

    .line 157
    .line 158
    invoke-direct {p1, p2}, Lb81/a;-><init>(I)V

    .line 159
    .line 160
    .line 161
    iput-object p1, p0, Ln1/v;->v:Lb81/a;

    .line 162
    .line 163
    return-void
.end method


# virtual methods
.method public final a()Z
    .locals 0

    .line 1
    iget-object p0, p0, Ln1/v;->h:Lg1/f0;

    .line 2
    .line 3
    invoke-virtual {p0}, Lg1/f0;->a()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final b()Z
    .locals 0

    .line 1
    iget-object p0, p0, Ln1/v;->u:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Boolean;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final c(Le1/w0;Lay0/n;Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p3, Ln1/u;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Ln1/u;

    .line 7
    .line 8
    iget v1, v0, Ln1/u;->h:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Ln1/u;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ln1/u;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Ln1/u;-><init>(Ln1/v;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Ln1/u;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ln1/u;->h:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_3

    .line 34
    .line 35
    if-eq v2, v4, :cond_2

    .line 36
    .line 37
    if-ne v2, v3, :cond_1

    .line 38
    .line 39
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    goto :goto_3

    .line 43
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 44
    .line 45
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 46
    .line 47
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw p0

    .line 51
    :cond_2
    iget-object p1, v0, Ln1/u;->e:Lrx0/i;

    .line 52
    .line 53
    move-object p2, p1

    .line 54
    check-cast p2, Lay0/n;

    .line 55
    .line 56
    iget-object p1, v0, Ln1/u;->d:Le1/w0;

    .line 57
    .line 58
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_3
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    iput-object p1, v0, Ln1/u;->d:Le1/w0;

    .line 66
    .line 67
    move-object p3, p2

    .line 68
    check-cast p3, Lrx0/i;

    .line 69
    .line 70
    iput-object p3, v0, Ln1/u;->e:Lrx0/i;

    .line 71
    .line 72
    iput v4, v0, Ln1/u;->h:I

    .line 73
    .line 74
    iget-object p3, p0, Ln1/v;->l:Lo1/d;

    .line 75
    .line 76
    invoke-virtual {p3, v0}, Lo1/d;->h(Lrx0/c;)Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object p3

    .line 80
    if-ne p3, v1, :cond_4

    .line 81
    .line 82
    goto :goto_2

    .line 83
    :cond_4
    :goto_1
    const/4 p3, 0x0

    .line 84
    iput-object p3, v0, Ln1/u;->d:Le1/w0;

    .line 85
    .line 86
    iput-object p3, v0, Ln1/u;->e:Lrx0/i;

    .line 87
    .line 88
    iput v3, v0, Ln1/u;->h:I

    .line 89
    .line 90
    iget-object p0, p0, Ln1/v;->h:Lg1/f0;

    .line 91
    .line 92
    invoke-virtual {p0, p1, p2, v0}, Lg1/f0;->c(Le1/w0;Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    if-ne p0, v1, :cond_5

    .line 97
    .line 98
    :goto_2
    return-object v1

    .line 99
    :cond_5
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 100
    .line 101
    return-object p0
.end method

.method public final d()Z
    .locals 0

    .line 1
    iget-object p0, p0, Ln1/v;->t:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Boolean;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final e(F)F
    .locals 0

    .line 1
    iget-object p0, p0, Ln1/v;->h:Lg1/f0;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lg1/f0;->e(F)F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final f(Ln1/n;ZZ)V
    .locals 11

    .line 1
    iget-object v0, p1, Ln1/n;->m:Ljava/lang/Object;

    .line 2
    .line 3
    iget v1, p1, Ln1/n;->p:I

    .line 4
    .line 5
    iget v2, p1, Ln1/n;->b:I

    .line 6
    .line 7
    iget-object v3, p1, Ln1/n;->a:Ln1/p;

    .line 8
    .line 9
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 10
    .line 11
    .line 12
    move-result v4

    .line 13
    iget-object v5, p0, Ln1/v;->o:Lo1/l0;

    .line 14
    .line 15
    iput v4, v5, Lo1/l0;->e:I

    .line 16
    .line 17
    if-nez p2, :cond_0

    .line 18
    .line 19
    iget-boolean v4, p0, Ln1/v;->b:Z

    .line 20
    .line 21
    if-eqz v4, :cond_0

    .line 22
    .line 23
    iput-object p1, p0, Ln1/v;->c:Ln1/n;

    .line 24
    .line 25
    return-void

    .line 26
    :cond_0
    const/4 v4, 0x1

    .line 27
    if-eqz p2, :cond_1

    .line 28
    .line 29
    iput-boolean v4, p0, Ln1/v;->b:Z

    .line 30
    .line 31
    :cond_1
    iget v5, p0, Ln1/v;->g:F

    .line 32
    .line 33
    iget v6, p1, Ln1/n;->d:F

    .line 34
    .line 35
    sub-float/2addr v5, v6

    .line 36
    iput v5, p0, Ln1/v;->g:F

    .line 37
    .line 38
    iget-object v5, p0, Ln1/v;->e:Ll2/j1;

    .line 39
    .line 40
    invoke-virtual {v5, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    const/4 v5, 0x0

    .line 44
    if-eqz v3, :cond_2

    .line 45
    .line 46
    iget v6, v3, Ln1/p;->a:I

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_2
    move v6, v5

    .line 50
    :goto_0
    if-nez v6, :cond_4

    .line 51
    .line 52
    if-eqz v2, :cond_3

    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_3
    move v6, v5

    .line 56
    goto :goto_2

    .line 57
    :cond_4
    :goto_1
    move v6, v4

    .line 58
    :goto_2
    iget-object v7, p0, Ln1/v;->u:Ll2/j1;

    .line 59
    .line 60
    invoke-static {v6}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 61
    .line 62
    .line 63
    move-result-object v6

    .line 64
    invoke-virtual {v7, v6}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    iget-boolean v6, p1, Ln1/n;->c:Z

    .line 68
    .line 69
    iget-object v7, p0, Ln1/v;->t:Ll2/j1;

    .line 70
    .line 71
    invoke-static {v6}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 72
    .line 73
    .line 74
    move-result-object v6

    .line 75
    invoke-virtual {v7, v6}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    iget-object v6, p0, Ln1/v;->d:Lm1/o;

    .line 79
    .line 80
    const/4 v7, 0x0

    .line 81
    if-eqz p3, :cond_7

    .line 82
    .line 83
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 84
    .line 85
    .line 86
    int-to-float p3, v2

    .line 87
    cmpl-float p3, p3, v7

    .line 88
    .line 89
    if-ltz p3, :cond_5

    .line 90
    .line 91
    goto :goto_3

    .line 92
    :cond_5
    move v4, v5

    .line 93
    :goto_3
    if-nez v4, :cond_6

    .line 94
    .line 95
    const-string p3, "scrollOffset should be non-negative"

    .line 96
    .line 97
    invoke-static {p3}, Lj1/b;->c(Ljava/lang/String;)V

    .line 98
    .line 99
    .line 100
    :cond_6
    iget-object p3, v6, Lm1/o;->c:Ll2/g1;

    .line 101
    .line 102
    invoke-virtual {p3, v2}, Ll2/g1;->p(I)V

    .line 103
    .line 104
    .line 105
    goto/16 :goto_b

    .line 106
    .line 107
    :cond_7
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 108
    .line 109
    .line 110
    if-eqz v3, :cond_8

    .line 111
    .line 112
    iget-object p3, v3, Ln1/p;->b:[Ln1/o;

    .line 113
    .line 114
    invoke-static {p3}, Lmx0/n;->w([Ljava/lang/Object;)Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object p3

    .line 118
    check-cast p3, Ln1/o;

    .line 119
    .line 120
    if-eqz p3, :cond_8

    .line 121
    .line 122
    iget-object p3, p3, Ln1/o;->b:Ljava/lang/Object;

    .line 123
    .line 124
    goto :goto_4

    .line 125
    :cond_8
    const/4 p3, 0x0

    .line 126
    :goto_4
    iput-object p3, v6, Lm1/o;->e:Ljava/lang/Object;

    .line 127
    .line 128
    iget-boolean p3, v6, Lm1/o;->d:Z

    .line 129
    .line 130
    if-nez p3, :cond_9

    .line 131
    .line 132
    if-lez v1, :cond_d

    .line 133
    .line 134
    :cond_9
    iput-boolean v4, v6, Lm1/o;->d:Z

    .line 135
    .line 136
    int-to-float p3, v2

    .line 137
    cmpl-float p3, p3, v7

    .line 138
    .line 139
    if-ltz p3, :cond_a

    .line 140
    .line 141
    move p3, v4

    .line 142
    goto :goto_5

    .line 143
    :cond_a
    move p3, v5

    .line 144
    :goto_5
    if-nez p3, :cond_b

    .line 145
    .line 146
    new-instance p3, Ljava/lang/StringBuilder;

    .line 147
    .line 148
    const-string v8, "scrollOffset should be non-negative ("

    .line 149
    .line 150
    invoke-direct {p3, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 151
    .line 152
    .line 153
    invoke-virtual {p3, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 154
    .line 155
    .line 156
    const/16 v8, 0x29

    .line 157
    .line 158
    invoke-virtual {p3, v8}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 159
    .line 160
    .line 161
    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 162
    .line 163
    .line 164
    move-result-object p3

    .line 165
    invoke-static {p3}, Lj1/b;->c(Ljava/lang/String;)V

    .line 166
    .line 167
    .line 168
    :cond_b
    if-eqz v3, :cond_c

    .line 169
    .line 170
    iget-object p3, v3, Ln1/p;->b:[Ln1/o;

    .line 171
    .line 172
    invoke-static {p3}, Lmx0/n;->w([Ljava/lang/Object;)Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object p3

    .line 176
    check-cast p3, Ln1/o;

    .line 177
    .line 178
    if-eqz p3, :cond_c

    .line 179
    .line 180
    iget p3, p3, Ln1/o;->a:I

    .line 181
    .line 182
    goto :goto_6

    .line 183
    :cond_c
    move p3, v5

    .line 184
    :goto_6
    invoke-virtual {v6, p3, v2}, Lm1/o;->a(II)V

    .line 185
    .line 186
    .line 187
    :cond_d
    iget-boolean p3, p0, Ln1/v;->i:Z

    .line 188
    .line 189
    if-eqz p3, :cond_14

    .line 190
    .line 191
    iget-object p3, p0, Ln1/v;->a:Lm1/a;

    .line 192
    .line 193
    iget-object v2, p3, Lm1/a;->e:Ljava/lang/Object;

    .line 194
    .line 195
    check-cast v2, Ln2/b;

    .line 196
    .line 197
    iget v3, p3, Lm1/a;->a:I

    .line 198
    .line 199
    iget-boolean v6, p3, Lm1/a;->b:Z

    .line 200
    .line 201
    const/4 v8, -0x1

    .line 202
    if-eq v3, v8, :cond_f

    .line 203
    .line 204
    move-object v9, v0

    .line 205
    check-cast v9, Ljava/util/Collection;

    .line 206
    .line 207
    invoke-interface {v9}, Ljava/util/Collection;->isEmpty()Z

    .line 208
    .line 209
    .line 210
    move-result v9

    .line 211
    if-nez v9, :cond_f

    .line 212
    .line 213
    invoke-static {p1, v6}, Lm1/a;->c(Ln1/n;Z)I

    .line 214
    .line 215
    .line 216
    move-result v6

    .line 217
    if-eq v3, v6, :cond_f

    .line 218
    .line 219
    iput v8, p3, Lm1/a;->a:I

    .line 220
    .line 221
    iget-object v3, v2, Ln2/b;->d:[Ljava/lang/Object;

    .line 222
    .line 223
    iget v6, v2, Ln2/b;->f:I

    .line 224
    .line 225
    move v9, v5

    .line 226
    :goto_7
    if-ge v9, v6, :cond_e

    .line 227
    .line 228
    aget-object v10, v3, v9

    .line 229
    .line 230
    check-cast v10, Lo1/k0;

    .line 231
    .line 232
    invoke-interface {v10}, Lo1/k0;->cancel()V

    .line 233
    .line 234
    .line 235
    add-int/lit8 v9, v9, 0x1

    .line 236
    .line 237
    goto :goto_7

    .line 238
    :cond_e
    invoke-virtual {v2}, Ln2/b;->i()V

    .line 239
    .line 240
    .line 241
    :cond_f
    iget v3, p3, Lm1/a;->c:I

    .line 242
    .line 243
    if-eq v3, v8, :cond_13

    .line 244
    .line 245
    iget v6, p3, Lm1/a;->d:F

    .line 246
    .line 247
    cmpg-float v6, v6, v7

    .line 248
    .line 249
    if-nez v6, :cond_10

    .line 250
    .line 251
    goto :goto_a

    .line 252
    :cond_10
    if-eq v3, v1, :cond_13

    .line 253
    .line 254
    check-cast v0, Ljava/util/Collection;

    .line 255
    .line 256
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 257
    .line 258
    .line 259
    move-result v0

    .line 260
    if-nez v0, :cond_13

    .line 261
    .line 262
    iget v0, p3, Lm1/a;->d:F

    .line 263
    .line 264
    cmpg-float v0, v0, v7

    .line 265
    .line 266
    if-gez v0, :cond_11

    .line 267
    .line 268
    move v0, v4

    .line 269
    goto :goto_8

    .line 270
    :cond_11
    move v0, v5

    .line 271
    :goto_8
    invoke-static {p1, v0}, Lm1/a;->c(Ln1/n;Z)I

    .line 272
    .line 273
    .line 274
    move-result v0

    .line 275
    iget v3, p3, Lm1/a;->d:F

    .line 276
    .line 277
    cmpg-float v3, v3, v7

    .line 278
    .line 279
    if-gez v3, :cond_12

    .line 280
    .line 281
    goto :goto_9

    .line 282
    :cond_12
    move v4, v5

    .line 283
    :goto_9
    invoke-static {p1, v4}, Lm1/a;->a(Ln1/n;Z)I

    .line 284
    .line 285
    .line 286
    move-result v3

    .line 287
    if-ltz v3, :cond_13

    .line 288
    .line 289
    if-ge v3, v1, :cond_13

    .line 290
    .line 291
    iget v3, p3, Lm1/a;->a:I

    .line 292
    .line 293
    if-eq v0, v3, :cond_13

    .line 294
    .line 295
    if-ltz v0, :cond_13

    .line 296
    .line 297
    iput v0, p3, Lm1/a;->a:I

    .line 298
    .line 299
    invoke-virtual {v2}, Ln2/b;->i()V

    .line 300
    .line 301
    .line 302
    iget-object v3, p0, Ln1/v;->p:Lj1/a;

    .line 303
    .line 304
    invoke-virtual {v3, v0}, Lj1/a;->y(I)Ljava/util/ArrayList;

    .line 305
    .line 306
    .line 307
    move-result-object v0

    .line 308
    iget v3, v2, Ln2/b;->f:I

    .line 309
    .line 310
    invoke-virtual {v2, v3, v0}, Ln2/b;->e(ILjava/util/List;)V

    .line 311
    .line 312
    .line 313
    :cond_13
    :goto_a
    iput v1, p3, Lm1/a;->c:I

    .line 314
    .line 315
    :cond_14
    :goto_b
    if-eqz p2, :cond_15

    .line 316
    .line 317
    iget p2, p1, Ln1/n;->f:F

    .line 318
    .line 319
    iget-object p3, p1, Ln1/n;->i:Lt4/c;

    .line 320
    .line 321
    iget-object p1, p1, Ln1/n;->h:Lvy0/b0;

    .line 322
    .line 323
    iget-object p0, p0, Ln1/v;->v:Lb81/a;

    .line 324
    .line 325
    invoke-virtual {p0, p2, p3, p1}, Lb81/a;->u(FLt4/c;Lvy0/b0;)V

    .line 326
    .line 327
    .line 328
    :cond_15
    return-void
.end method

.method public final g()Ln1/n;
    .locals 0

    .line 1
    iget-object p0, p0, Ln1/v;->e:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ln1/n;

    .line 8
    .line 9
    return-object p0
.end method

.method public final h(FLn1/n;)V
    .locals 11

    .line 1
    iget-boolean v0, p0, Ln1/v;->i:Z

    .line 2
    .line 3
    if-eqz v0, :cond_6

    .line 4
    .line 5
    iget-object v0, p0, Ln1/v;->a:Lm1/a;

    .line 6
    .line 7
    iget-object v1, v0, Lm1/a;->e:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v1, Ln2/b;

    .line 10
    .line 11
    iget-object v2, p2, Ln1/n;->m:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v2, Ljava/util/Collection;

    .line 14
    .line 15
    invoke-interface {v2}, Ljava/util/Collection;->isEmpty()Z

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    if-nez v2, :cond_5

    .line 20
    .line 21
    const/4 v2, 0x0

    .line 22
    cmpg-float v2, p1, v2

    .line 23
    .line 24
    const/4 v3, 0x0

    .line 25
    if-gez v2, :cond_0

    .line 26
    .line 27
    const/4 v2, 0x1

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    move v2, v3

    .line 30
    :goto_0
    invoke-static {p2, v2}, Lm1/a;->c(Ln1/n;Z)I

    .line 31
    .line 32
    .line 33
    move-result v4

    .line 34
    invoke-static {p2, v2}, Lm1/a;->a(Ln1/n;Z)I

    .line 35
    .line 36
    .line 37
    move-result v5

    .line 38
    if-ltz v5, :cond_5

    .line 39
    .line 40
    iget-object v6, p2, Ln1/n;->q:Lg1/w1;

    .line 41
    .line 42
    iget-object v7, p2, Ln1/n;->m:Ljava/lang/Object;

    .line 43
    .line 44
    iget v8, p2, Ln1/n;->p:I

    .line 45
    .line 46
    if-ge v5, v8, :cond_5

    .line 47
    .line 48
    iget v5, v0, Lm1/a;->a:I

    .line 49
    .line 50
    if-eq v4, v5, :cond_2

    .line 51
    .line 52
    if-ltz v4, :cond_2

    .line 53
    .line 54
    iget-boolean v5, v0, Lm1/a;->b:Z

    .line 55
    .line 56
    if-eq v5, v2, :cond_1

    .line 57
    .line 58
    iget-object v5, v1, Ln2/b;->d:[Ljava/lang/Object;

    .line 59
    .line 60
    iget v8, v1, Ln2/b;->f:I

    .line 61
    .line 62
    move v9, v3

    .line 63
    :goto_1
    if-ge v9, v8, :cond_1

    .line 64
    .line 65
    aget-object v10, v5, v9

    .line 66
    .line 67
    check-cast v10, Lo1/k0;

    .line 68
    .line 69
    invoke-interface {v10}, Lo1/k0;->cancel()V

    .line 70
    .line 71
    .line 72
    add-int/lit8 v9, v9, 0x1

    .line 73
    .line 74
    goto :goto_1

    .line 75
    :cond_1
    iput-boolean v2, v0, Lm1/a;->b:Z

    .line 76
    .line 77
    iput v4, v0, Lm1/a;->a:I

    .line 78
    .line 79
    invoke-virtual {v1}, Ln2/b;->i()V

    .line 80
    .line 81
    .line 82
    iget-object p0, p0, Ln1/v;->p:Lj1/a;

    .line 83
    .line 84
    invoke-virtual {p0, v4}, Lj1/a;->y(I)Ljava/util/ArrayList;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    iget v4, v1, Ln2/b;->f:I

    .line 89
    .line 90
    invoke-virtual {v1, v4, p0}, Ln2/b;->e(ILjava/util/List;)V

    .line 91
    .line 92
    .line 93
    :cond_2
    if-eqz v2, :cond_4

    .line 94
    .line 95
    invoke-static {v7}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    check-cast p0, Ln1/o;

    .line 100
    .line 101
    sget-object v2, Lg1/w1;->d:Lg1/w1;

    .line 102
    .line 103
    if-ne v6, v2, :cond_3

    .line 104
    .line 105
    iget-wide v4, p0, Ln1/o;->s:J

    .line 106
    .line 107
    const-wide v7, 0xffffffffL

    .line 108
    .line 109
    .line 110
    .line 111
    .line 112
    and-long/2addr v4, v7

    .line 113
    :goto_2
    long-to-int v2, v4

    .line 114
    goto :goto_3

    .line 115
    :cond_3
    iget-wide v4, p0, Ln1/o;->s:J

    .line 116
    .line 117
    const/16 v2, 0x20

    .line 118
    .line 119
    shr-long/2addr v4, v2

    .line 120
    goto :goto_2

    .line 121
    :goto_3
    iget v4, p2, Ln1/n;->s:I

    .line 122
    .line 123
    invoke-static {p0, v6}, Lkp/ca;->b(Ln1/o;Lg1/w1;)I

    .line 124
    .line 125
    .line 126
    move-result p0

    .line 127
    add-int/2addr p0, v2

    .line 128
    add-int/2addr p0, v4

    .line 129
    iget p2, p2, Ln1/n;->o:I

    .line 130
    .line 131
    sub-int/2addr p0, p2

    .line 132
    int-to-float p0, p0

    .line 133
    neg-float p2, p1

    .line 134
    cmpg-float p0, p0, p2

    .line 135
    .line 136
    if-gez p0, :cond_5

    .line 137
    .line 138
    iget-object p0, v1, Ln2/b;->d:[Ljava/lang/Object;

    .line 139
    .line 140
    iget p2, v1, Ln2/b;->f:I

    .line 141
    .line 142
    :goto_4
    if-ge v3, p2, :cond_5

    .line 143
    .line 144
    aget-object v1, p0, v3

    .line 145
    .line 146
    check-cast v1, Lo1/k0;

    .line 147
    .line 148
    invoke-interface {v1}, Lo1/k0;->a()V

    .line 149
    .line 150
    .line 151
    add-int/lit8 v3, v3, 0x1

    .line 152
    .line 153
    goto :goto_4

    .line 154
    :cond_4
    invoke-static {v7}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 155
    .line 156
    .line 157
    move-result-object p0

    .line 158
    check-cast p0, Ln1/o;

    .line 159
    .line 160
    iget p2, p2, Ln1/n;->n:I

    .line 161
    .line 162
    invoke-static {p0, v6}, Lkp/ca;->b(Ln1/o;Lg1/w1;)I

    .line 163
    .line 164
    .line 165
    move-result p0

    .line 166
    sub-int/2addr p2, p0

    .line 167
    int-to-float p0, p2

    .line 168
    cmpg-float p0, p0, p1

    .line 169
    .line 170
    if-gez p0, :cond_5

    .line 171
    .line 172
    iget-object p0, v1, Ln2/b;->d:[Ljava/lang/Object;

    .line 173
    .line 174
    iget p2, v1, Ln2/b;->f:I

    .line 175
    .line 176
    :goto_5
    if-ge v3, p2, :cond_5

    .line 177
    .line 178
    aget-object v1, p0, v3

    .line 179
    .line 180
    check-cast v1, Lo1/k0;

    .line 181
    .line 182
    invoke-interface {v1}, Lo1/k0;->a()V

    .line 183
    .line 184
    .line 185
    add-int/lit8 v3, v3, 0x1

    .line 186
    .line 187
    goto :goto_5

    .line 188
    :cond_5
    iput p1, v0, Lm1/a;->d:F

    .line 189
    .line 190
    :cond_6
    return-void
.end method
