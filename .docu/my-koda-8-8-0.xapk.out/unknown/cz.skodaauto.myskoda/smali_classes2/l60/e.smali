.class public final Ll60/e;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lk60/a;

.field public final i:Lzo0/d;

.field public final j:Lzo0/g;

.field public final k:Lzo0/q;

.field public final l:Lwp0/f;

.field public final m:Lbh0/k;

.field public final n:Ltr0/b;

.field public final o:Ltn0/a;

.field public final p:Ltn0/d;

.field public final q:Lij0/a;

.field public r:Lap0/p;


# direct methods
.method public constructor <init>(Lk60/a;Lzo0/d;Lzo0/g;Lzo0/q;Lwp0/f;Lbh0/k;Ltr0/b;Ltn0/a;Ltn0/d;Lij0/a;)V
    .locals 9

    .line 1
    new-instance v0, Ll60/c;

    .line 2
    .line 3
    const/16 v1, 0x7f

    .line 4
    .line 5
    and-int/lit8 v1, v1, 0x10

    .line 6
    .line 7
    const/4 v8, 0x0

    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 11
    .line 12
    move-object v5, v1

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    move-object v5, v8

    .line 15
    :goto_0
    const/4 v6, 0x0

    .line 16
    const/4 v7, 0x0

    .line 17
    const/4 v1, 0x0

    .line 18
    const/4 v2, 0x0

    .line 19
    const/4 v3, 0x0

    .line 20
    const/4 v4, 0x0

    .line 21
    invoke-direct/range {v0 .. v7}, Ll60/c;-><init>(ZLql0/g;Lql0/g;ZLjava/util/List;ZZ)V

    .line 22
    .line 23
    .line 24
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 25
    .line 26
    .line 27
    iput-object p1, p0, Ll60/e;->h:Lk60/a;

    .line 28
    .line 29
    iput-object p2, p0, Ll60/e;->i:Lzo0/d;

    .line 30
    .line 31
    iput-object p3, p0, Ll60/e;->j:Lzo0/g;

    .line 32
    .line 33
    iput-object p4, p0, Ll60/e;->k:Lzo0/q;

    .line 34
    .line 35
    iput-object p5, p0, Ll60/e;->l:Lwp0/f;

    .line 36
    .line 37
    iput-object p6, p0, Ll60/e;->m:Lbh0/k;

    .line 38
    .line 39
    move-object/from16 p1, p7

    .line 40
    .line 41
    iput-object p1, p0, Ll60/e;->n:Ltr0/b;

    .line 42
    .line 43
    move-object/from16 p1, p8

    .line 44
    .line 45
    iput-object p1, p0, Ll60/e;->o:Ltn0/a;

    .line 46
    .line 47
    move-object/from16 p1, p9

    .line 48
    .line 49
    iput-object p1, p0, Ll60/e;->p:Ltn0/d;

    .line 50
    .line 51
    move-object/from16 p1, p10

    .line 52
    .line 53
    iput-object p1, p0, Ll60/e;->q:Lij0/a;

    .line 54
    .line 55
    new-instance p1, Ll60/a;

    .line 56
    .line 57
    const/4 p2, 0x0

    .line 58
    invoke-direct {p1, p0, v8, p2}, Ll60/a;-><init>(Ll60/e;Lkotlin/coroutines/Continuation;I)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 62
    .line 63
    .line 64
    return-void
.end method

.method public static final h(Ll60/e;Lap0/j;Lrx0/c;)Ljava/lang/Object;
    .locals 13

    .line 1
    instance-of v0, p2, Ll60/d;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Ll60/d;

    .line 7
    .line 8
    iget v1, v0, Ll60/d;->g:I

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
    iput v1, v0, Ll60/d;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ll60/d;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Ll60/d;-><init>(Ll60/e;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Ll60/d;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ll60/d;->g:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object p1, v0, Ll60/d;->d:Lap0/j;

    .line 37
    .line 38
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 43
    .line 44
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 45
    .line 46
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p0

    .line 50
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 54
    .line 55
    .line 56
    move-result-object p2

    .line 57
    move-object v4, p2

    .line 58
    check-cast v4, Ll60/c;

    .line 59
    .line 60
    const/4 v11, 0x0

    .line 61
    const/16 v12, 0x3f

    .line 62
    .line 63
    const/4 v5, 0x0

    .line 64
    const/4 v6, 0x0

    .line 65
    const/4 v7, 0x0

    .line 66
    const/4 v8, 0x0

    .line 67
    const/4 v9, 0x0

    .line 68
    const/4 v10, 0x0

    .line 69
    invoke-static/range {v4 .. v12}, Ll60/c;->a(Ll60/c;ZLql0/g;Lql0/g;ZLjava/util/ArrayList;ZZI)Ll60/c;

    .line 70
    .line 71
    .line 72
    move-result-object p2

    .line 73
    invoke-virtual {p0, p2}, Lql0/j;->g(Lql0/h;)V

    .line 74
    .line 75
    .line 76
    const/4 p2, 0x0

    .line 77
    iput-object p2, p0, Ll60/e;->r:Lap0/p;

    .line 78
    .line 79
    iget-object p2, p0, Ll60/e;->k:Lzo0/q;

    .line 80
    .line 81
    iget-boolean v2, p1, Lap0/j;->c:Z

    .line 82
    .line 83
    xor-int/2addr v2, v3

    .line 84
    iget-object v4, p1, Lap0/j;->a:Lap0/p;

    .line 85
    .line 86
    iget-object v5, p1, Lap0/j;->b:Ljava/lang/Boolean;

    .line 87
    .line 88
    new-instance v6, Lap0/j;

    .line 89
    .line 90
    invoke-direct {v6, v4, v5, v2}, Lap0/j;-><init>(Lap0/p;Ljava/lang/Boolean;Z)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {p2, v6}, Lzo0/q;->a(Lap0/j;)Lam0/i;

    .line 94
    .line 95
    .line 96
    move-result-object p2

    .line 97
    new-instance v2, Lgt0/c;

    .line 98
    .line 99
    const/16 v4, 0x1a

    .line 100
    .line 101
    invoke-direct {v2, p0, v4}, Lgt0/c;-><init>(Ljava/lang/Object;I)V

    .line 102
    .line 103
    .line 104
    iput-object p1, v0, Ll60/d;->d:Lap0/j;

    .line 105
    .line 106
    iput v3, v0, Ll60/d;->g:I

    .line 107
    .line 108
    invoke-virtual {p2, v2, v0}, Lam0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object p2

    .line 112
    if-ne p2, v1, :cond_3

    .line 113
    .line 114
    return-object v1

    .line 115
    :cond_3
    :goto_1
    iget-object p2, p1, Lap0/j;->a:Lap0/p;

    .line 116
    .line 117
    sget-object v0, Lap0/p;->e:Lap0/p;

    .line 118
    .line 119
    if-ne p2, v0, :cond_6

    .line 120
    .line 121
    new-instance p2, Lap0/e;

    .line 122
    .line 123
    iget-boolean p1, p1, Lap0/j;->c:Z

    .line 124
    .line 125
    xor-int/lit8 v0, p1, 0x1

    .line 126
    .line 127
    if-ne v0, v3, :cond_4

    .line 128
    .line 129
    sget-object p1, Lap0/d;->d:Lap0/d;

    .line 130
    .line 131
    goto :goto_2

    .line 132
    :cond_4
    if-eqz p1, :cond_5

    .line 133
    .line 134
    sget-object p1, Lap0/d;->e:Lap0/d;

    .line 135
    .line 136
    :goto_2
    sget-object v0, Lap0/d;->d:Lap0/d;

    .line 137
    .line 138
    invoke-direct {p2, p1, v0}, Lap0/e;-><init>(Lap0/d;Lap0/d;)V

    .line 139
    .line 140
    .line 141
    iget-object p0, p0, Ll60/e;->l:Lwp0/f;

    .line 142
    .line 143
    iget-object p0, p0, Lwp0/f;->a:Lzo0/n;

    .line 144
    .line 145
    check-cast p0, Lup0/a;

    .line 146
    .line 147
    new-instance p1, Lup0/c;

    .line 148
    .line 149
    invoke-direct {p1, p2}, Lup0/c;-><init>(Lap0/e;)V

    .line 150
    .line 151
    .line 152
    iget-object p0, p0, Lup0/a;->a:Lyy0/q1;

    .line 153
    .line 154
    invoke-virtual {p0, p1}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 155
    .line 156
    .line 157
    goto :goto_3

    .line 158
    :cond_5
    new-instance p0, La8/r0;

    .line 159
    .line 160
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 161
    .line 162
    .line 163
    throw p0

    .line 164
    :cond_6
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 165
    .line 166
    return-object p0
.end method
