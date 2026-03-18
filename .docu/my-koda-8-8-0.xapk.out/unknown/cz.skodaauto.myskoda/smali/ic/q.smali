.class public final Lic/q;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Ly1/i;

.field public final e:Lay0/a;

.field public final f:Lxh/e;

.field public final g:Lag/c;

.field public final h:Lag/c;

.field public final i:Lc4/i;

.field public final j:Lic/s;

.field public final k:Lyy0/c2;

.field public final l:Lyy0/c2;

.field public final m:Lyy0/c2;

.field public final n:Lyy0/c2;

.field public final o:Lyy0/l1;


# direct methods
.method public constructor <init>(Ly1/i;Lay0/a;Lxh/e;Lag/c;Lag/c;Lc4/i;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lic/q;->d:Ly1/i;

    .line 5
    .line 6
    iput-object p2, p0, Lic/q;->e:Lay0/a;

    .line 7
    .line 8
    iput-object p3, p0, Lic/q;->f:Lxh/e;

    .line 9
    .line 10
    iput-object p4, p0, Lic/q;->g:Lag/c;

    .line 11
    .line 12
    iput-object p5, p0, Lic/q;->h:Lag/c;

    .line 13
    .line 14
    iput-object p6, p0, Lic/q;->i:Lc4/i;

    .line 15
    .line 16
    sget-object p1, Lic/s;->a:Lic/s;

    .line 17
    .line 18
    iput-object p1, p0, Lic/q;->j:Lic/s;

    .line 19
    .line 20
    new-instance p1, Llc/q;

    .line 21
    .line 22
    sget-object p2, Llc/a;->c:Llc/c;

    .line 23
    .line 24
    invoke-direct {p1, p2}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    iput-object p1, p0, Lic/q;->k:Lyy0/c2;

    .line 32
    .line 33
    sget-object p3, Lic/r;->a:Ldc/t;

    .line 34
    .line 35
    invoke-static {p3}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 36
    .line 37
    .line 38
    move-result-object p3

    .line 39
    iput-object p3, p0, Lic/q;->l:Lyy0/c2;

    .line 40
    .line 41
    const/4 p4, 0x0

    .line 42
    invoke-static {p4}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 43
    .line 44
    .line 45
    move-result-object p5

    .line 46
    iput-object p5, p0, Lic/q;->m:Lyy0/c2;

    .line 47
    .line 48
    sget-object p6, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 49
    .line 50
    invoke-static {p6}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 51
    .line 52
    .line 53
    move-result-object p6

    .line 54
    iput-object p6, p0, Lic/q;->n:Lyy0/c2;

    .line 55
    .line 56
    new-instance v0, Lic/p;

    .line 57
    .line 58
    invoke-direct {v0, p0, p4}, Lic/p;-><init>(Lic/q;Lkotlin/coroutines/Continuation;)V

    .line 59
    .line 60
    .line 61
    invoke-static {p1, p3, p5, p6, v0}, Lyy0/u;->l(Lyy0/i;Lyy0/i;Lyy0/i;Lyy0/i;Lay0/q;)Llb0/y;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 66
    .line 67
    .line 68
    move-result-object p3

    .line 69
    new-instance p5, Llc/q;

    .line 70
    .line 71
    invoke-direct {p5, p2}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    sget-object p2, Lyy0/u1;->b:Lyy0/w1;

    .line 75
    .line 76
    invoke-static {p1, p3, p2, p5}, Lyy0/u;->F(Lyy0/i;Lvy0/b0;Lyy0/v1;Ljava/lang/Object;)Lyy0/l1;

    .line 77
    .line 78
    .line 79
    move-result-object p1

    .line 80
    iput-object p1, p0, Lic/q;->o:Lyy0/l1;

    .line 81
    .line 82
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 83
    .line 84
    .line 85
    move-result-object p1

    .line 86
    new-instance p2, Lic/o;

    .line 87
    .line 88
    const/4 p3, 0x0

    .line 89
    invoke-direct {p2, p0, p4, p3}, Lic/o;-><init>(Lic/q;Lkotlin/coroutines/Continuation;I)V

    .line 90
    .line 91
    .line 92
    const/4 p0, 0x3

    .line 93
    invoke-static {p1, p4, p4, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 94
    .line 95
    .line 96
    return-void
.end method

.method public static final a(Lic/q;Ljava/lang/Throwable;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lic/q;->k:Lyy0/c2;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    invoke-static {p1}, Llc/c;->b(Ljava/lang/Throwable;)Llc/l;

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    invoke-static {p1, p0, v0}, Lia/b;->v(Llc/l;Lyy0/c2;Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public static final b(Lic/q;Ldc/t;)V
    .locals 8

    .line 1
    iget-object v0, p0, Lic/q;->k:Lyy0/c2;

    .line 2
    .line 3
    iget-object v1, p1, Ldc/t;->a:Ljava/util/List;

    .line 4
    .line 5
    iget-object v2, p1, Ldc/t;->b:Ljava/util/List;

    .line 6
    .line 7
    invoke-interface {v1}, Ljava/util/List;->isEmpty()Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    const/4 v3, 0x0

    .line 12
    if-eqz v1, :cond_1

    .line 13
    .line 14
    invoke-interface {v2}, Ljava/util/List;->isEmpty()Z

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    if-eqz v1, :cond_1

    .line 19
    .line 20
    new-instance p1, Li70/q;

    .line 21
    .line 22
    const/16 v1, 0xe

    .line 23
    .line 24
    invoke-direct {p1, v1}, Li70/q;-><init>(I)V

    .line 25
    .line 26
    .line 27
    sget-object v1, Lgi/b;->e:Lgi/b;

    .line 28
    .line 29
    sget-object v2, Lgi/a;->e:Lgi/a;

    .line 30
    .line 31
    const-class v4, Lic/q;

    .line 32
    .line 33
    invoke-virtual {v4}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v4

    .line 37
    const/16 v5, 0x24

    .line 38
    .line 39
    invoke-static {v4, v5}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object v5

    .line 43
    const/16 v6, 0x2e

    .line 44
    .line 45
    invoke-static {v6, v5, v5}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object v5

    .line 49
    invoke-virtual {v5}, Ljava/lang/String;->length()I

    .line 50
    .line 51
    .line 52
    move-result v6

    .line 53
    if-nez v6, :cond_0

    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_0
    const-string v4, "Kt"

    .line 57
    .line 58
    invoke-static {v5, v4}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object v4

    .line 62
    :goto_0
    invoke-static {v4, v2, v1, v3, p1}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 63
    .line 64
    .line 65
    new-instance p1, Llc/q;

    .line 66
    .line 67
    sget-object v1, Llc/a;->c:Llc/c;

    .line 68
    .line 69
    invoke-direct {p1, v1}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 73
    .line 74
    .line 75
    invoke-virtual {v0, v3, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    iget-object p0, p0, Lic/q;->e:Lay0/a;

    .line 79
    .line 80
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    return-void

    .line 84
    :cond_1
    iget-object v1, p1, Ldc/t;->c:Ljava/lang/String;

    .line 85
    .line 86
    if-eqz v1, :cond_5

    .line 87
    .line 88
    iget-object v4, p0, Lic/q;->m:Lyy0/c2;

    .line 89
    .line 90
    move-object v5, v2

    .line 91
    check-cast v5, Ljava/lang/Iterable;

    .line 92
    .line 93
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 94
    .line 95
    .line 96
    move-result-object v5

    .line 97
    :cond_2
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 98
    .line 99
    .line 100
    move-result v6

    .line 101
    if-eqz v6, :cond_3

    .line 102
    .line 103
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v6

    .line 107
    move-object v7, v6

    .line 108
    check-cast v7, Lac/a0;

    .line 109
    .line 110
    iget-object v7, v7, Lac/a0;->e:Ljava/lang/String;

    .line 111
    .line 112
    invoke-static {v7, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 113
    .line 114
    .line 115
    move-result v7

    .line 116
    if-eqz v7, :cond_2

    .line 117
    .line 118
    goto :goto_1

    .line 119
    :cond_3
    move-object v6, v3

    .line 120
    :goto_1
    check-cast v6, Lac/a0;

    .line 121
    .line 122
    if-nez v6, :cond_4

    .line 123
    .line 124
    invoke-static {v2}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v1

    .line 128
    move-object v6, v1

    .line 129
    check-cast v6, Lac/a0;

    .line 130
    .line 131
    :cond_4
    invoke-virtual {v4, v6}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 132
    .line 133
    .line 134
    :cond_5
    iget-object p0, p0, Lic/q;->l:Lyy0/c2;

    .line 135
    .line 136
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 137
    .line 138
    .line 139
    invoke-virtual {p0, v3, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 140
    .line 141
    .line 142
    new-instance p0, Llc/q;

    .line 143
    .line 144
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 145
    .line 146
    invoke-direct {p0, p1}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 147
    .line 148
    .line 149
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 150
    .line 151
    .line 152
    invoke-virtual {v0, v3, p0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 153
    .line 154
    .line 155
    return-void
.end method


# virtual methods
.method public final d(Ldc/e;)V
    .locals 4

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    iget-object p0, p0, Lic/q;->d:Ly1/i;

    .line 4
    .line 5
    invoke-virtual {p0}, Ly1/i;->invoke()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    new-instance v0, Llc/q;

    .line 10
    .line 11
    sget-object v1, Llc/a;->c:Llc/c;

    .line 12
    .line 13
    invoke-direct {v0, v1}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    iget-object v1, p0, Lic/q;->k:Lyy0/c2;

    .line 17
    .line 18
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 19
    .line 20
    .line 21
    const/4 v2, 0x0

    .line 22
    invoke-virtual {v1, v2, v0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    new-instance v1, Laa/i0;

    .line 30
    .line 31
    const/16 v3, 0x9

    .line 32
    .line 33
    invoke-direct {v1, v3, p1, p0, v2}, Laa/i0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 34
    .line 35
    .line 36
    const/4 p0, 0x3

    .line 37
    invoke-static {v0, v2, v2, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 38
    .line 39
    .line 40
    return-void
.end method
