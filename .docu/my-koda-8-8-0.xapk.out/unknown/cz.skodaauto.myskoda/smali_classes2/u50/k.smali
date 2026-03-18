.class public final Lu50/k;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Ls50/s;

.field public final j:Ls50/w;

.field public final k:Ls50/a0;

.field public final l:Ls50/b0;

.field public final m:Ls50/e;

.field public final n:Lrs0/b;

.field public final o:Ls50/h0;

.field public final p:Lij0/a;


# direct methods
.method public constructor <init>(Lkf0/v;Ltr0/b;Ls50/s;Ls50/w;Ls50/a0;Ls50/b0;Ls50/e;Lrs0/b;Ls50/h0;Lij0/a;)V
    .locals 2

    .line 1
    new-instance v0, Lu50/h;

    .line 2
    .line 3
    const/16 v1, 0x7f

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lu50/h;-><init>(I)V

    .line 6
    .line 7
    .line 8
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 9
    .line 10
    .line 11
    iput-object p2, p0, Lu50/k;->h:Ltr0/b;

    .line 12
    .line 13
    iput-object p3, p0, Lu50/k;->i:Ls50/s;

    .line 14
    .line 15
    iput-object p4, p0, Lu50/k;->j:Ls50/w;

    .line 16
    .line 17
    iput-object p5, p0, Lu50/k;->k:Ls50/a0;

    .line 18
    .line 19
    iput-object p6, p0, Lu50/k;->l:Ls50/b0;

    .line 20
    .line 21
    iput-object p7, p0, Lu50/k;->m:Ls50/e;

    .line 22
    .line 23
    iput-object p8, p0, Lu50/k;->n:Lrs0/b;

    .line 24
    .line 25
    iput-object p9, p0, Lu50/k;->o:Ls50/h0;

    .line 26
    .line 27
    iput-object p10, p0, Lu50/k;->p:Lij0/a;

    .line 28
    .line 29
    new-instance p2, Ltr0/e;

    .line 30
    .line 31
    const/4 p3, 0x0

    .line 32
    const/16 p4, 0xa

    .line 33
    .line 34
    invoke-direct {p2, p4, p1, p0, p3}, Ltr0/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {p0, p2}, Lql0/j;->b(Lay0/n;)V

    .line 38
    .line 39
    .line 40
    return-void
.end method

.method public static final h(Lu50/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 13

    .line 1
    instance-of v0, p1, Lu50/i;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lu50/i;

    .line 7
    .line 8
    iget v1, v0, Lu50/i;->f:I

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
    iput v1, v0, Lu50/i;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lu50/i;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lu50/i;-><init>(Lu50/k;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lu50/i;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lu50/i;->f:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    const/4 v4, 0x2

    .line 34
    const/4 v5, 0x1

    .line 35
    if-eqz v2, :cond_3

    .line 36
    .line 37
    if-eq v2, v5, :cond_2

    .line 38
    .line 39
    if-ne v2, v4, :cond_1

    .line 40
    .line 41
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    return-object v3

    .line 45
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 46
    .line 47
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 48
    .line 49
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw p0

    .line 53
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    iget-object p1, p0, Lu50/k;->n:Lrs0/b;

    .line 61
    .line 62
    iput v5, v0, Lu50/i;->f:I

    .line 63
    .line 64
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 65
    .line 66
    .line 67
    invoke-virtual {p1, v0}, Lrs0/b;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object p1

    .line 71
    if-ne p1, v1, :cond_4

    .line 72
    .line 73
    goto :goto_2

    .line 74
    :cond_4
    :goto_1
    check-cast p1, Lne0/t;

    .line 75
    .line 76
    instance-of v2, p1, Lne0/c;

    .line 77
    .line 78
    const/4 v5, 0x0

    .line 79
    if-eqz v2, :cond_5

    .line 80
    .line 81
    new-instance v2, Lu41/u;

    .line 82
    .line 83
    const/4 v6, 0x1

    .line 84
    invoke-direct {v2, v6}, Lu41/u;-><init>(I)V

    .line 85
    .line 86
    .line 87
    invoke-static {v5, p0, v2}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 88
    .line 89
    .line 90
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 91
    .line 92
    .line 93
    move-result-object v2

    .line 94
    move-object v6, v2

    .line 95
    check-cast v6, Lu50/h;

    .line 96
    .line 97
    sget-object v10, Lu50/g;->d:Lu50/g;

    .line 98
    .line 99
    const/4 v11, 0x0

    .line 100
    const/16 v12, 0x6e

    .line 101
    .line 102
    const/4 v7, 0x0

    .line 103
    const/4 v8, 0x0

    .line 104
    const/4 v9, 0x0

    .line 105
    invoke-static/range {v6 .. v12}, Lu50/h;->a(Lu50/h;ZZZLu50/g;Lql0/g;I)Lu50/h;

    .line 106
    .line 107
    .line 108
    move-result-object v2

    .line 109
    invoke-virtual {p0, v2}, Lql0/j;->g(Lql0/h;)V

    .line 110
    .line 111
    .line 112
    :cond_5
    instance-of v2, p1, Lne0/e;

    .line 113
    .line 114
    if-eqz v2, :cond_8

    .line 115
    .line 116
    check-cast p1, Lne0/e;

    .line 117
    .line 118
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 119
    .line 120
    check-cast p1, Lss0/d0;

    .line 121
    .line 122
    instance-of v2, p1, Lss0/g;

    .line 123
    .line 124
    if-eqz v2, :cond_6

    .line 125
    .line 126
    new-instance v0, Lky/s;

    .line 127
    .line 128
    const/4 v1, 0x1

    .line 129
    invoke-direct {v0, p1, v1}, Lky/s;-><init>(Lss0/d0;I)V

    .line 130
    .line 131
    .line 132
    invoke-static {v5, p0, v0}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 133
    .line 134
    .line 135
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 136
    .line 137
    .line 138
    move-result-object p1

    .line 139
    move-object v4, p1

    .line 140
    check-cast v4, Lu50/h;

    .line 141
    .line 142
    sget-object v8, Lu50/g;->e:Lu50/g;

    .line 143
    .line 144
    const/4 v9, 0x0

    .line 145
    const/16 v10, 0x6e

    .line 146
    .line 147
    const/4 v5, 0x0

    .line 148
    const/4 v6, 0x0

    .line 149
    const/4 v7, 0x0

    .line 150
    invoke-static/range {v4 .. v10}, Lu50/h;->a(Lu50/h;ZZZLu50/g;Lql0/g;I)Lu50/h;

    .line 151
    .line 152
    .line 153
    move-result-object p1

    .line 154
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 155
    .line 156
    .line 157
    return-object v3

    .line 158
    :cond_6
    instance-of v2, p1, Lss0/j0;

    .line 159
    .line 160
    if-eqz v2, :cond_7

    .line 161
    .line 162
    check-cast p1, Lss0/j0;

    .line 163
    .line 164
    iget-object p1, p1, Lss0/j0;->d:Ljava/lang/String;

    .line 165
    .line 166
    iput v4, v0, Lu50/i;->f:I

    .line 167
    .line 168
    invoke-virtual {p0, p1, v0}, Lu50/k;->j(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 169
    .line 170
    .line 171
    move-result-object p0

    .line 172
    if-ne p0, v1, :cond_8

    .line 173
    .line 174
    :goto_2
    return-object v1

    .line 175
    :cond_7
    new-instance p0, La8/r0;

    .line 176
    .line 177
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 178
    .line 179
    .line 180
    throw p0

    .line 181
    :cond_8
    return-object v3
.end method


# virtual methods
.method public final j(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p2, Lu50/j;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lu50/j;

    .line 7
    .line 8
    iget v1, v0, Lu50/j;->g:I

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
    iput v1, v0, Lu50/j;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lu50/j;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lu50/j;-><init>(Lu50/k;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lu50/j;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lu50/j;->g:I

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    const/4 v4, 0x2

    .line 33
    const/4 v5, 0x1

    .line 34
    if-eqz v2, :cond_3

    .line 35
    .line 36
    if-eq v2, v5, :cond_2

    .line 37
    .line 38
    if-ne v2, v4, :cond_1

    .line 39
    .line 40
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    goto :goto_3

    .line 44
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_2
    iget-object p1, v0, Lu50/j;->d:Ljava/lang/String;

    .line 53
    .line 54
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    iput-object p1, v0, Lu50/j;->d:Ljava/lang/String;

    .line 62
    .line 63
    iput v5, v0, Lu50/j;->g:I

    .line 64
    .line 65
    iget-object p2, p0, Lu50/k;->m:Ls50/e;

    .line 66
    .line 67
    iget-object p2, p2, Ls50/e;->a:Lp50/d;

    .line 68
    .line 69
    new-instance v2, Lh7/z;

    .line 70
    .line 71
    const/16 v5, 0x11

    .line 72
    .line 73
    invoke-direct {v2, v5, p2, p1, v3}, Lh7/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 74
    .line 75
    .line 76
    new-instance p2, Lyy0/m1;

    .line 77
    .line 78
    invoke-direct {p2, v2}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 79
    .line 80
    .line 81
    if-ne p2, v1, :cond_4

    .line 82
    .line 83
    goto :goto_2

    .line 84
    :cond_4
    :goto_1
    check-cast p2, Lyy0/i;

    .line 85
    .line 86
    new-instance v2, Lqg/l;

    .line 87
    .line 88
    const/16 v5, 0x10

    .line 89
    .line 90
    invoke-direct {v2, v5, p0, p1}, Lqg/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    iput-object v3, v0, Lu50/j;->d:Ljava/lang/String;

    .line 94
    .line 95
    iput v4, v0, Lu50/j;->g:I

    .line 96
    .line 97
    invoke-interface {p2, v2, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    if-ne p0, v1, :cond_5

    .line 102
    .line 103
    :goto_2
    return-object v1

    .line 104
    :cond_5
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 105
    .line 106
    return-object p0
.end method
