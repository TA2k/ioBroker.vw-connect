.class public final Ls10/s;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lq10/l;

.field public final i:Lkf0/v;

.field public final j:Lq10/c;

.field public final k:Lq10/h;

.field public final l:Lrq0/d;

.field public final m:Ltr0/b;

.field public final n:Lij0/a;


# direct methods
.method public constructor <init>(Lq10/l;Lkf0/v;Lq10/c;Lq10/h;Lrq0/d;Ltr0/b;Lij0/a;)V
    .locals 8

    .line 1
    new-instance v0, Ls10/q;

    .line 2
    .line 3
    sget-object v1, Ler0/g;->f:Ler0/g;

    .line 4
    .line 5
    const/16 v2, 0x3f

    .line 6
    .line 7
    const/4 v3, 0x1

    .line 8
    and-int/2addr v2, v3

    .line 9
    if-eqz v2, :cond_0

    .line 10
    .line 11
    sget-object v1, Ler0/g;->d:Ler0/g;

    .line 12
    .line 13
    :cond_0
    const/16 v2, 0x3f

    .line 14
    .line 15
    and-int/lit8 v4, v2, 0x2

    .line 16
    .line 17
    const/4 v7, 0x0

    .line 18
    if-eqz v4, :cond_1

    .line 19
    .line 20
    sget-object v4, Llf0/i;->j:Llf0/i;

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_1
    move-object v4, v7

    .line 24
    :goto_0
    and-int/lit8 v2, v2, 0x8

    .line 25
    .line 26
    if-eqz v2, :cond_2

    .line 27
    .line 28
    goto :goto_1

    .line 29
    :cond_2
    const/4 v3, 0x0

    .line 30
    :goto_1
    sget-object v5, Ls10/o;->d:Ls10/o;

    .line 31
    .line 32
    const/4 v6, 0x0

    .line 33
    move-object v2, v4

    .line 34
    move v4, v3

    .line 35
    const/4 v3, 0x0

    .line 36
    invoke-direct/range {v0 .. v6}, Ls10/q;-><init>(Ler0/g;Llf0/i;ZZLs10/o;Ls10/p;)V

    .line 37
    .line 38
    .line 39
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 40
    .line 41
    .line 42
    iput-object p1, p0, Ls10/s;->h:Lq10/l;

    .line 43
    .line 44
    iput-object p2, p0, Ls10/s;->i:Lkf0/v;

    .line 45
    .line 46
    iput-object p3, p0, Ls10/s;->j:Lq10/c;

    .line 47
    .line 48
    iput-object p4, p0, Ls10/s;->k:Lq10/h;

    .line 49
    .line 50
    iput-object p5, p0, Ls10/s;->l:Lrq0/d;

    .line 51
    .line 52
    iput-object p6, p0, Ls10/s;->m:Ltr0/b;

    .line 53
    .line 54
    iput-object p7, p0, Ls10/s;->n:Lij0/a;

    .line 55
    .line 56
    new-instance p1, Ls10/n;

    .line 57
    .line 58
    const/4 p2, 0x0

    .line 59
    invoke-direct {p1, p2, v7, p0}, Ls10/n;-><init>(ILkotlin/coroutines/Continuation;Ls10/s;)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 63
    .line 64
    .line 65
    return-void
.end method


# virtual methods
.method public final h(Lne0/s;)V
    .locals 9

    .line 1
    sget-object v0, Lne0/d;->a:Lne0/d;

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_1

    .line 8
    .line 9
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    move-object v0, p1

    .line 14
    check-cast v0, Ls10/q;

    .line 15
    .line 16
    iget-boolean p1, v0, Ls10/q;->c:Z

    .line 17
    .line 18
    if-eqz p1, :cond_0

    .line 19
    .line 20
    goto/16 :goto_1

    .line 21
    .line 22
    :cond_0
    const/4 v6, 0x0

    .line 23
    const/16 v7, 0x37

    .line 24
    .line 25
    const/4 v1, 0x0

    .line 26
    const/4 v2, 0x0

    .line 27
    const/4 v3, 0x0

    .line 28
    const/4 v4, 0x1

    .line 29
    const/4 v5, 0x0

    .line 30
    invoke-static/range {v0 .. v7}, Ls10/q;->a(Ls10/q;Ler0/g;Llf0/i;ZZLs10/o;Ls10/p;I)Ls10/q;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    goto :goto_1

    .line 35
    :cond_1
    instance-of v0, p1, Lne0/c;

    .line 36
    .line 37
    if-eqz v0, :cond_4

    .line 38
    .line 39
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    move-object v1, v0

    .line 44
    check-cast v1, Ls10/q;

    .line 45
    .line 46
    check-cast p1, Lne0/c;

    .line 47
    .line 48
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    check-cast v0, Ls10/q;

    .line 53
    .line 54
    iget-boolean v0, v0, Ls10/q;->d:Z

    .line 55
    .line 56
    const/4 v2, 0x1

    .line 57
    if-ne v0, v2, :cond_2

    .line 58
    .line 59
    new-instance v7, Ls10/p;

    .line 60
    .line 61
    const/4 v0, 0x0

    .line 62
    new-array v2, v0, [Ljava/lang/Object;

    .line 63
    .line 64
    iget-object v3, p0, Ls10/s;->n:Lij0/a;

    .line 65
    .line 66
    check-cast v3, Ljj0/f;

    .line 67
    .line 68
    const v4, 0x7f120f47

    .line 69
    .line 70
    .line 71
    invoke-virtual {v3, v4, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object v2

    .line 75
    const v4, 0x7f120f46

    .line 76
    .line 77
    .line 78
    new-array v0, v0, [Ljava/lang/Object;

    .line 79
    .line 80
    invoke-virtual {v3, v4, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object v0

    .line 84
    invoke-direct {v7, v2, v0}, Ls10/p;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    const/4 v6, 0x0

    .line 88
    const/16 v8, 0x17

    .line 89
    .line 90
    const/4 v2, 0x0

    .line 91
    const/4 v3, 0x0

    .line 92
    const/4 v4, 0x0

    .line 93
    const/4 v5, 0x0

    .line 94
    invoke-static/range {v1 .. v8}, Ls10/q;->a(Ls10/q;Ler0/g;Llf0/i;ZZLs10/o;Ls10/p;I)Ls10/q;

    .line 95
    .line 96
    .line 97
    move-result-object v0

    .line 98
    goto :goto_0

    .line 99
    :cond_2
    if-nez v0, :cond_3

    .line 100
    .line 101
    move-object v0, v1

    .line 102
    :goto_0
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 103
    .line 104
    .line 105
    move-result-object v1

    .line 106
    new-instance v2, Lr60/t;

    .line 107
    .line 108
    const/16 v3, 0x8

    .line 109
    .line 110
    const/4 v4, 0x0

    .line 111
    invoke-direct {v2, v3, p0, p1, v4}, Lr60/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 112
    .line 113
    .line 114
    const/4 p1, 0x3

    .line 115
    invoke-static {v1, v4, v4, v2, p1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 116
    .line 117
    .line 118
    goto :goto_1

    .line 119
    :cond_3
    new-instance p0, La8/r0;

    .line 120
    .line 121
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 122
    .line 123
    .line 124
    throw p0

    .line 125
    :cond_4
    instance-of p1, p1, Lne0/e;

    .line 126
    .line 127
    if-eqz p1, :cond_5

    .line 128
    .line 129
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 130
    .line 131
    .line 132
    move-result-object p1

    .line 133
    move-object v0, p1

    .line 134
    check-cast v0, Ls10/q;

    .line 135
    .line 136
    const/4 v6, 0x0

    .line 137
    const/16 v7, 0x37

    .line 138
    .line 139
    const/4 v1, 0x0

    .line 140
    const/4 v2, 0x0

    .line 141
    const/4 v3, 0x0

    .line 142
    const/4 v4, 0x0

    .line 143
    const/4 v5, 0x0

    .line 144
    invoke-static/range {v0 .. v7}, Ls10/q;->a(Ls10/q;Ler0/g;Llf0/i;ZZLs10/o;Ls10/p;I)Ls10/q;

    .line 145
    .line 146
    .line 147
    move-result-object v0

    .line 148
    :goto_1
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 149
    .line 150
    .line 151
    return-void

    .line 152
    :cond_5
    new-instance p0, La8/r0;

    .line 153
    .line 154
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 155
    .line 156
    .line 157
    throw p0
.end method
