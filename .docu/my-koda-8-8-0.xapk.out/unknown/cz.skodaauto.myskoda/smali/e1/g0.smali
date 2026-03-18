.class public final Le1/g0;
.super Lv3/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/x1;
.implements Lv3/q;
.implements Lv3/l;
.implements Lv3/j1;
.implements Lv3/c2;


# static fields
.field public static final z:Le1/f1;


# instance fields
.field public t:Li1/l;

.field public final u:Lay0/k;

.field public v:Li1/e;

.field public w:Lo1/h0;

.field public x:Lv3/f1;

.field public final y:Lc3/v;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Le1/f1;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Le1/g0;->z:Le1/f1;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>(Li1/l;ILcz/j;)V
    .locals 8

    .line 1
    invoke-direct {p0}, Lv3/n;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Le1/g0;->t:Li1/l;

    .line 5
    .line 6
    iput-object p3, p0, Le1/g0;->u:Lay0/k;

    .line 7
    .line 8
    new-instance v0, Lag/c;

    .line 9
    .line 10
    const/4 v6, 0x0

    .line 11
    const/16 v7, 0xd

    .line 12
    .line 13
    const/4 v1, 0x2

    .line 14
    const-class v3, Le1/g0;

    .line 15
    .line 16
    const-string v4, "onFocusStateChange"

    .line 17
    .line 18
    const-string v5, "onFocusStateChange(Landroidx/compose/ui/focus/FocusState;Landroidx/compose/ui/focus/FocusState;)V"

    .line 19
    .line 20
    move-object v2, p0

    .line 21
    invoke-direct/range {v0 .. v7}, Lag/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 22
    .line 23
    .line 24
    new-instance p0, Lc3/v;

    .line 25
    .line 26
    const/4 p1, 0x4

    .line 27
    invoke-direct {p0, p2, v0, p1}, Lc3/v;-><init>(ILay0/n;I)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {v2, p0}, Lv3/n;->X0(Lv3/m;)Lv3/m;

    .line 31
    .line 32
    .line 33
    iput-object p0, v2, Le1/g0;->y:Lc3/v;

    .line 34
    .line 35
    return-void
.end method


# virtual methods
.method public final K(Lv3/f1;)V
    .locals 1

    .line 1
    iput-object p1, p0, Le1/g0;->x:Lv3/f1;

    .line 2
    .line 3
    iget-object v0, p0, Le1/g0;->y:Lc3/v;

    .line 4
    .line 5
    invoke-virtual {v0}, Lc3/v;->Z0()Lc3/u;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-virtual {v0}, Lc3/u;->b()Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-nez v0, :cond_0

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    invoke-virtual {p1}, Lv3/f1;->f1()Lx2/r;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    iget-boolean p1, p1, Lx2/r;->q:Z

    .line 21
    .line 22
    if-eqz p1, :cond_1

    .line 23
    .line 24
    iget-object p1, p0, Le1/g0;->x:Lv3/f1;

    .line 25
    .line 26
    if-eqz p1, :cond_2

    .line 27
    .line 28
    invoke-virtual {p1}, Lv3/f1;->f1()Lx2/r;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    iget-boolean p1, p1, Lx2/r;->q:Z

    .line 33
    .line 34
    if-eqz p1, :cond_2

    .line 35
    .line 36
    invoke-virtual {p0}, Le1/g0;->b1()Le1/h0;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    if-eqz p1, :cond_2

    .line 41
    .line 42
    iget-object p0, p0, Le1/g0;->x:Lv3/f1;

    .line 43
    .line 44
    invoke-virtual {p1, p0}, Le1/h0;->X0(Lt3/y;)V

    .line 45
    .line 46
    .line 47
    return-void

    .line 48
    :cond_1
    invoke-virtual {p0}, Le1/g0;->b1()Le1/h0;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    if-eqz p0, :cond_2

    .line 53
    .line 54
    const/4 p1, 0x0

    .line 55
    invoke-virtual {p0, p1}, Le1/h0;->X0(Lt3/y;)V

    .line 56
    .line 57
    .line 58
    :cond_2
    :goto_0
    return-void
.end method

.method public final M0()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final O()V
    .locals 3

    .line 1
    new-instance v0, Lkotlin/jvm/internal/f0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Ld90/w;

    .line 7
    .line 8
    const/4 v2, 0x7

    .line 9
    invoke-direct {v1, v2, v0, p0}, Ld90/w;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    invoke-static {p0, v1}, Lv3/f;->t(Lx2/r;Lay0/a;)V

    .line 13
    .line 14
    .line 15
    iget-object v0, v0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v0, Lo1/h0;

    .line 18
    .line 19
    iget-object v1, p0, Le1/g0;->y:Lc3/v;

    .line 20
    .line 21
    invoke-virtual {v1}, Lc3/v;->Z0()Lc3/u;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    invoke-virtual {v1}, Lc3/u;->b()Z

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    if-eqz v1, :cond_2

    .line 30
    .line 31
    iget-object v1, p0, Le1/g0;->w:Lo1/h0;

    .line 32
    .line 33
    if-eqz v1, :cond_0

    .line 34
    .line 35
    invoke-virtual {v1}, Lo1/h0;->b()V

    .line 36
    .line 37
    .line 38
    :cond_0
    if-eqz v0, :cond_1

    .line 39
    .line 40
    invoke-virtual {v0}, Lo1/h0;->a()Lo1/h0;

    .line 41
    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_1
    const/4 v0, 0x0

    .line 45
    :goto_0
    iput-object v0, p0, Le1/g0;->w:Lo1/h0;

    .line 46
    .line 47
    :cond_2
    return-void
.end method

.method public final R0()V
    .locals 1

    .line 1
    iget-object v0, p0, Le1/g0;->w:Lo1/h0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0}, Lo1/h0;->b()V

    .line 6
    .line 7
    .line 8
    :cond_0
    const/4 v0, 0x0

    .line 9
    iput-object v0, p0, Le1/g0;->w:Lo1/h0;

    .line 10
    .line 11
    return-void
.end method

.method public final a0(Ld4/l;)V
    .locals 10

    .line 1
    iget-object v0, p0, Le1/g0;->y:Lc3/v;

    .line 2
    .line 3
    invoke-virtual {v0}, Lc3/v;->Z0()Lc3/u;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {v0}, Lc3/u;->b()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    sget-object v1, Ld4/x;->a:[Lhy0/z;

    .line 12
    .line 13
    sget-object v1, Ld4/v;->k:Ld4/z;

    .line 14
    .line 15
    sget-object v2, Ld4/x;->a:[Lhy0/z;

    .line 16
    .line 17
    const/4 v3, 0x4

    .line 18
    aget-object v2, v2, v3

    .line 19
    .line 20
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    invoke-virtual {v1, p1, v0}, Ld4/z;->a(Ld4/l;Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    new-instance v2, Ld90/n;

    .line 28
    .line 29
    const/4 v8, 0x0

    .line 30
    const/16 v9, 0x1b

    .line 31
    .line 32
    const/4 v3, 0x0

    .line 33
    const-class v5, Le1/g0;

    .line 34
    .line 35
    const-string v6, "requestFocus"

    .line 36
    .line 37
    const-string v7, "requestFocus()Z"

    .line 38
    .line 39
    move-object v4, p0

    .line 40
    invoke-direct/range {v2 .. v9}, Ld90/n;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 41
    .line 42
    .line 43
    sget-object p0, Ld4/k;->v:Ld4/z;

    .line 44
    .line 45
    new-instance v0, Ld4/a;

    .line 46
    .line 47
    const/4 v1, 0x0

    .line 48
    invoke-direct {v0, v1, v2}, Ld4/a;-><init>(Ljava/lang/String;Llx0/e;)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {p1, p0, v0}, Ld4/l;->i(Ld4/z;Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    return-void
.end method

.method public final a1(Li1/l;Li1/k;)V
    .locals 7

    .line 1
    iget-boolean v0, p0, Lx2/r;->q:Z

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    invoke-virtual {p0}, Lx2/r;->L0()Lvy0/b0;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    check-cast v0, Lpw0/a;

    .line 10
    .line 11
    iget-object v0, v0, Lpw0/a;->e:Lpx0/g;

    .line 12
    .line 13
    sget-object v1, Lvy0/h1;->d:Lvy0/h1;

    .line 14
    .line 15
    invoke-interface {v0, v1}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    check-cast v0, Lvy0/i1;

    .line 20
    .line 21
    const/4 v6, 0x0

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    new-instance v1, Laa/z;

    .line 25
    .line 26
    const/16 v2, 0x18

    .line 27
    .line 28
    invoke-direct {v1, v2, p1, p2}, Laa/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    invoke-interface {v0, v1}, Lvy0/i1;->E(Lay0/k;)Lvy0/r0;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    move-object v5, v0

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    move-object v5, v6

    .line 38
    :goto_0
    invoke-virtual {p0}, Lx2/r;->L0()Lvy0/b0;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    new-instance v1, Le1/e;

    .line 43
    .line 44
    const/4 v2, 0x1

    .line 45
    move-object v3, p1

    .line 46
    move-object v4, p2

    .line 47
    invoke-direct/range {v1 .. v6}, Le1/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 48
    .line 49
    .line 50
    const/4 p1, 0x3

    .line 51
    invoke-static {p0, v6, v6, v1, p1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 52
    .line 53
    .line 54
    return-void

    .line 55
    :cond_1
    move-object v3, p1

    .line 56
    move-object v4, p2

    .line 57
    invoke-virtual {v3, v4}, Li1/l;->b(Li1/k;)V

    .line 58
    .line 59
    .line 60
    return-void
.end method

.method public final b1()Le1/h0;
    .locals 9

    .line 1
    iget-boolean v0, p0, Lx2/r;->q:Z

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_c

    .line 5
    .line 6
    iget-object v0, p0, Lx2/r;->d:Lx2/r;

    .line 7
    .line 8
    iget-boolean v0, v0, Lx2/r;->q:Z

    .line 9
    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    const-string v0, "visitAncestors called on an unattached node"

    .line 13
    .line 14
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    :cond_0
    iget-object v0, p0, Lx2/r;->d:Lx2/r;

    .line 18
    .line 19
    iget-object v0, v0, Lx2/r;->h:Lx2/r;

    .line 20
    .line 21
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    :goto_0
    if-eqz p0, :cond_b

    .line 26
    .line 27
    iget-object v2, p0, Lv3/h0;->H:Lg1/q;

    .line 28
    .line 29
    iget-object v2, v2, Lg1/q;->g:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast v2, Lx2/r;

    .line 32
    .line 33
    iget v2, v2, Lx2/r;->g:I

    .line 34
    .line 35
    const/high16 v3, 0x40000

    .line 36
    .line 37
    and-int/2addr v2, v3

    .line 38
    if-eqz v2, :cond_9

    .line 39
    .line 40
    :goto_1
    if-eqz v0, :cond_9

    .line 41
    .line 42
    iget v2, v0, Lx2/r;->f:I

    .line 43
    .line 44
    and-int/2addr v2, v3

    .line 45
    if-eqz v2, :cond_8

    .line 46
    .line 47
    move-object v2, v0

    .line 48
    move-object v4, v1

    .line 49
    :goto_2
    if-eqz v2, :cond_8

    .line 50
    .line 51
    instance-of v5, v2, Lv3/c2;

    .line 52
    .line 53
    if-eqz v5, :cond_1

    .line 54
    .line 55
    check-cast v2, Lv3/c2;

    .line 56
    .line 57
    invoke-interface {v2}, Lv3/c2;->g()Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v5

    .line 61
    sget-object v6, Le1/h0;->s:Le1/f1;

    .line 62
    .line 63
    invoke-virtual {v6, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    move-result v5

    .line 67
    if-eqz v5, :cond_7

    .line 68
    .line 69
    goto :goto_5

    .line 70
    :cond_1
    iget v5, v2, Lx2/r;->f:I

    .line 71
    .line 72
    and-int/2addr v5, v3

    .line 73
    if-eqz v5, :cond_7

    .line 74
    .line 75
    instance-of v5, v2, Lv3/n;

    .line 76
    .line 77
    if-eqz v5, :cond_7

    .line 78
    .line 79
    move-object v5, v2

    .line 80
    check-cast v5, Lv3/n;

    .line 81
    .line 82
    iget-object v5, v5, Lv3/n;->s:Lx2/r;

    .line 83
    .line 84
    const/4 v6, 0x0

    .line 85
    :goto_3
    const/4 v7, 0x1

    .line 86
    if-eqz v5, :cond_6

    .line 87
    .line 88
    iget v8, v5, Lx2/r;->f:I

    .line 89
    .line 90
    and-int/2addr v8, v3

    .line 91
    if-eqz v8, :cond_5

    .line 92
    .line 93
    add-int/lit8 v6, v6, 0x1

    .line 94
    .line 95
    if-ne v6, v7, :cond_2

    .line 96
    .line 97
    move-object v2, v5

    .line 98
    goto :goto_4

    .line 99
    :cond_2
    if-nez v4, :cond_3

    .line 100
    .line 101
    new-instance v4, Ln2/b;

    .line 102
    .line 103
    const/16 v7, 0x10

    .line 104
    .line 105
    new-array v7, v7, [Lx2/r;

    .line 106
    .line 107
    invoke-direct {v4, v7}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 108
    .line 109
    .line 110
    :cond_3
    if-eqz v2, :cond_4

    .line 111
    .line 112
    invoke-virtual {v4, v2}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 113
    .line 114
    .line 115
    move-object v2, v1

    .line 116
    :cond_4
    invoke-virtual {v4, v5}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 117
    .line 118
    .line 119
    :cond_5
    :goto_4
    iget-object v5, v5, Lx2/r;->i:Lx2/r;

    .line 120
    .line 121
    goto :goto_3

    .line 122
    :cond_6
    if-ne v6, v7, :cond_7

    .line 123
    .line 124
    goto :goto_2

    .line 125
    :cond_7
    invoke-static {v4}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 126
    .line 127
    .line 128
    move-result-object v2

    .line 129
    goto :goto_2

    .line 130
    :cond_8
    iget-object v0, v0, Lx2/r;->h:Lx2/r;

    .line 131
    .line 132
    goto :goto_1

    .line 133
    :cond_9
    invoke-virtual {p0}, Lv3/h0;->v()Lv3/h0;

    .line 134
    .line 135
    .line 136
    move-result-object p0

    .line 137
    if-eqz p0, :cond_a

    .line 138
    .line 139
    iget-object v0, p0, Lv3/h0;->H:Lg1/q;

    .line 140
    .line 141
    if-eqz v0, :cond_a

    .line 142
    .line 143
    iget-object v0, v0, Lg1/q;->f:Ljava/lang/Object;

    .line 144
    .line 145
    check-cast v0, Lv3/z1;

    .line 146
    .line 147
    goto :goto_0

    .line 148
    :cond_a
    move-object v0, v1

    .line 149
    goto :goto_0

    .line 150
    :cond_b
    move-object v2, v1

    .line 151
    :goto_5
    instance-of p0, v2, Le1/h0;

    .line 152
    .line 153
    if-eqz p0, :cond_c

    .line 154
    .line 155
    check-cast v2, Le1/h0;

    .line 156
    .line 157
    return-object v2

    .line 158
    :cond_c
    return-object v1
.end method

.method public final c1(Li1/l;)V
    .locals 3

    .line 1
    iget-object v0, p0, Le1/g0;->t:Li1/l;

    .line 2
    .line 3
    invoke-static {v0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    iget-object v0, p0, Le1/g0;->t:Li1/l;

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    iget-object v1, p0, Le1/g0;->v:Li1/e;

    .line 14
    .line 15
    if-eqz v1, :cond_0

    .line 16
    .line 17
    new-instance v2, Li1/f;

    .line 18
    .line 19
    invoke-direct {v2, v1}, Li1/f;-><init>(Li1/e;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {v0, v2}, Li1/l;->b(Li1/k;)V

    .line 23
    .line 24
    .line 25
    :cond_0
    const/4 v0, 0x0

    .line 26
    iput-object v0, p0, Le1/g0;->v:Li1/e;

    .line 27
    .line 28
    iput-object p1, p0, Le1/g0;->t:Li1/l;

    .line 29
    .line 30
    :cond_1
    return-void
.end method

.method public final g()Ljava/lang/Object;
    .locals 0

    .line 1
    sget-object p0, Le1/g0;->z:Le1/f1;

    .line 2
    .line 3
    return-object p0
.end method
