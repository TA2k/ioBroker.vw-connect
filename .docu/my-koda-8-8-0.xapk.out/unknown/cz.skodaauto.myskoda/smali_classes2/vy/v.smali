.class public final Lvy/v;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lij0/a;

.field public final i:Ltr0/b;

.field public final j:Lgb0/y;

.field public final k:Ljn0/c;

.field public final l:Lrq0/f;

.field public final m:Lrq0/d;

.field public final n:Lty/c;

.field public final o:Lty/h;

.field public final p:Lyn0/h;

.field public final q:Lty/m;

.field public final r:Lty/k;

.field public final s:Lyt0/b;

.field public final t:Lty/f;

.field public final u:Llb0/g;

.field public final v:Lty/o;

.field public w:Lvy/o;

.field public x:Z


# direct methods
.method public constructor <init>(Lij0/a;Ltr0/b;Lgb0/y;Ljn0/c;Lrq0/f;Lrq0/d;Lty/c;Lty/h;Lyn0/h;Lty/m;Lty/k;Lyt0/b;Lty/f;Llb0/g;Lty/o;)V
    .locals 7

    .line 1
    new-instance v0, Lvy/p;

    .line 2
    .line 3
    const/4 v5, 0x0

    .line 4
    const/16 v6, 0x1ff

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    const/4 v2, 0x0

    .line 8
    const/4 v3, 0x0

    .line 9
    const/4 v4, 0x0

    .line 10
    invoke-direct/range {v0 .. v6}, Lvy/p;-><init>(Ler0/g;Llf0/i;Lvy/o;Lbo0/l;Lvy/n;I)V

    .line 11
    .line 12
    .line 13
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Lvy/v;->h:Lij0/a;

    .line 17
    .line 18
    iput-object p2, p0, Lvy/v;->i:Ltr0/b;

    .line 19
    .line 20
    iput-object p3, p0, Lvy/v;->j:Lgb0/y;

    .line 21
    .line 22
    iput-object p4, p0, Lvy/v;->k:Ljn0/c;

    .line 23
    .line 24
    iput-object p5, p0, Lvy/v;->l:Lrq0/f;

    .line 25
    .line 26
    iput-object p6, p0, Lvy/v;->m:Lrq0/d;

    .line 27
    .line 28
    iput-object p7, p0, Lvy/v;->n:Lty/c;

    .line 29
    .line 30
    iput-object p8, p0, Lvy/v;->o:Lty/h;

    .line 31
    .line 32
    move-object/from16 p1, p9

    .line 33
    .line 34
    iput-object p1, p0, Lvy/v;->p:Lyn0/h;

    .line 35
    .line 36
    move-object/from16 p1, p10

    .line 37
    .line 38
    iput-object p1, p0, Lvy/v;->q:Lty/m;

    .line 39
    .line 40
    move-object/from16 p1, p11

    .line 41
    .line 42
    iput-object p1, p0, Lvy/v;->r:Lty/k;

    .line 43
    .line 44
    move-object/from16 p1, p12

    .line 45
    .line 46
    iput-object p1, p0, Lvy/v;->s:Lyt0/b;

    .line 47
    .line 48
    move-object/from16 p1, p13

    .line 49
    .line 50
    iput-object p1, p0, Lvy/v;->t:Lty/f;

    .line 51
    .line 52
    move-object/from16 p1, p14

    .line 53
    .line 54
    iput-object p1, p0, Lvy/v;->u:Llb0/g;

    .line 55
    .line 56
    move-object/from16 p1, p15

    .line 57
    .line 58
    iput-object p1, p0, Lvy/v;->v:Lty/o;

    .line 59
    .line 60
    sget-object p1, Lvy/o;->d:Lvy/o;

    .line 61
    .line 62
    iput-object p1, p0, Lvy/v;->w:Lvy/o;

    .line 63
    .line 64
    const/4 p1, 0x1

    .line 65
    iput-boolean p1, p0, Lvy/v;->x:Z

    .line 66
    .line 67
    new-instance p1, Lvy/m;

    .line 68
    .line 69
    const/4 p2, 0x0

    .line 70
    const/4 p3, 0x0

    .line 71
    invoke-direct {p1, p3, p2, p0}, Lvy/m;-><init>(ILkotlin/coroutines/Continuation;Lvy/v;)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 75
    .line 76
    .line 77
    return-void
.end method

.method public static final h(Lvy/v;Lvy0/b0;Lne0/s;Lcn0/c;)V
    .locals 8

    .line 1
    instance-of v0, p2, Lne0/c;

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    const/4 v2, 0x0

    .line 5
    const/4 v3, 0x0

    .line 6
    if-eqz v0, :cond_1

    .line 7
    .line 8
    iget-boolean p3, p0, Lvy/v;->x:Z

    .line 9
    .line 10
    if-eqz p3, :cond_0

    .line 11
    .line 12
    iput-boolean v2, p0, Lvy/v;->x:Z

    .line 13
    .line 14
    iget-object p2, p0, Lvy/v;->n:Lty/c;

    .line 15
    .line 16
    new-instance p3, Lty/b;

    .line 17
    .line 18
    invoke-direct {p3, v2}, Lty/b;-><init>(Z)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {p2, p3}, Lty/c;->a(Lty/b;)Lzy0/j;

    .line 22
    .line 23
    .line 24
    move-result-object p2

    .line 25
    new-instance p3, Lvy/l;

    .line 26
    .line 27
    const/4 v0, 0x1

    .line 28
    invoke-direct {p3, p0, p1, v3, v0}, Lvy/l;-><init>(Lvy/v;Lvy0/b0;Lkotlin/coroutines/Continuation;I)V

    .line 29
    .line 30
    .line 31
    invoke-static {p3, p2}, Lbb/j0;->e(Lay0/n;Lyy0/i;)Lne0/n;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    invoke-static {p1, p0}, Lyy0/u;->B(Lyy0/i;Lvy0/b0;)Lvy0/x1;

    .line 40
    .line 41
    .line 42
    return-void

    .line 43
    :cond_0
    check-cast p2, Lne0/c;

    .line 44
    .line 45
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    new-instance p3, Lvu/j;

    .line 50
    .line 51
    const/4 v0, 0x4

    .line 52
    invoke-direct {p3, v0, p0, p2, v3}, Lvu/j;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 53
    .line 54
    .line 55
    invoke-static {p1, v3, v3, p3, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 56
    .line 57
    .line 58
    return-void

    .line 59
    :cond_1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 60
    .line 61
    .line 62
    sget-object v0, Lne0/d;->a:Lne0/d;

    .line 63
    .line 64
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v0

    .line 68
    if-eqz v0, :cond_3

    .line 69
    .line 70
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 71
    .line 72
    .line 73
    move-result-object p1

    .line 74
    check-cast p1, Lvy/p;

    .line 75
    .line 76
    iget-boolean p1, p1, Lvy/p;->d:Z

    .line 77
    .line 78
    if-nez p1, :cond_2

    .line 79
    .line 80
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 81
    .line 82
    .line 83
    move-result-object p1

    .line 84
    move-object v0, p1

    .line 85
    check-cast v0, Lvy/p;

    .line 86
    .line 87
    const/4 v6, 0x0

    .line 88
    const/16 v7, 0x1fb

    .line 89
    .line 90
    const/4 v1, 0x1

    .line 91
    const/4 v2, 0x0

    .line 92
    const/4 v3, 0x0

    .line 93
    const/4 v4, 0x0

    .line 94
    const/4 v5, 0x0

    .line 95
    invoke-static/range {v0 .. v7}, Lvy/p;->a(Lvy/p;ZZLvy/o;Lbo0/l;Lvy/n;ZI)Lvy/p;

    .line 96
    .line 97
    .line 98
    move-result-object p1

    .line 99
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 100
    .line 101
    .line 102
    :cond_2
    return-void

    .line 103
    :cond_3
    instance-of v0, p2, Lne0/e;

    .line 104
    .line 105
    if-eqz v0, :cond_5

    .line 106
    .line 107
    iput-boolean v2, p0, Lvy/v;->x:Z

    .line 108
    .line 109
    move-object v0, p2

    .line 110
    check-cast v0, Lne0/e;

    .line 111
    .line 112
    iget-object v0, v0, Lne0/e;->a:Ljava/lang/Object;

    .line 113
    .line 114
    check-cast v0, Luy/b;

    .line 115
    .line 116
    iget-object v2, v0, Luy/b;->b:Luy/a;

    .line 117
    .line 118
    invoke-static {v2}, Llp/pa;->b(Luy/a;)Z

    .line 119
    .line 120
    .line 121
    move-result v2

    .line 122
    if-eqz v2, :cond_4

    .line 123
    .line 124
    invoke-static {p3}, Ljp/sd;->c(Lcn0/c;)Z

    .line 125
    .line 126
    .line 127
    move-result v2

    .line 128
    if-nez v2, :cond_4

    .line 129
    .line 130
    new-instance v2, Lvu/j;

    .line 131
    .line 132
    const/4 v4, 0x3

    .line 133
    invoke-direct {v2, v4, p0, p2, v3}, Lvu/j;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 134
    .line 135
    .line 136
    invoke-static {p1, v3, v3, v2, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 137
    .line 138
    .line 139
    :cond_4
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 140
    .line 141
    .line 142
    move-result-object p1

    .line 143
    check-cast p1, Lvy/p;

    .line 144
    .line 145
    iget-object p2, p0, Lvy/v;->h:Lij0/a;

    .line 146
    .line 147
    invoke-static {p1, v0, p2, p3}, Llp/pc;->i(Lvy/p;Luy/b;Lij0/a;Lcn0/c;)Lvy/p;

    .line 148
    .line 149
    .line 150
    move-result-object p1

    .line 151
    iget-object p2, p1, Lvy/p;->f:Lvy/o;

    .line 152
    .line 153
    iput-object p2, p0, Lvy/v;->w:Lvy/o;

    .line 154
    .line 155
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 156
    .line 157
    .line 158
    return-void

    .line 159
    :cond_5
    new-instance p0, La8/r0;

    .line 160
    .line 161
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 162
    .line 163
    .line 164
    throw p0
.end method


# virtual methods
.method public final j(Luy/b;Lrx0/c;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p2, Lvy/u;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lvy/u;

    .line 7
    .line 8
    iget v1, v0, Lvy/u;->g:I

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
    iput v1, v0, Lvy/u;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lvy/u;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lvy/u;-><init>(Lvy/v;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lvy/u;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lvy/u;->g:I

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

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
    iget-object p1, v0, Lvy/u;->d:Luy/b;

    .line 52
    .line 53
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    sget p2, Lmy0/c;->g:I

    .line 61
    .line 62
    sget-object p2, Lmy0/e;->i:Lmy0/e;

    .line 63
    .line 64
    invoke-static {v4, p2}, Lmy0/h;->s(ILmy0/e;)J

    .line 65
    .line 66
    .line 67
    move-result-wide v5

    .line 68
    iput-object p1, v0, Lvy/u;->d:Luy/b;

    .line 69
    .line 70
    iput v4, v0, Lvy/u;->g:I

    .line 71
    .line 72
    invoke-static {v5, v6, v0}, Lvy0/e0;->q(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object p2

    .line 76
    if-ne p2, v1, :cond_4

    .line 77
    .line 78
    goto :goto_2

    .line 79
    :cond_4
    :goto_1
    iget-object p2, p1, Luy/b;->a:Ljava/time/OffsetDateTime;

    .line 80
    .line 81
    if-eqz p2, :cond_5

    .line 82
    .line 83
    invoke-static {p2}, Lvo/a;->a(Ljava/time/OffsetDateTime;)J

    .line 84
    .line 85
    .line 86
    move-result-wide v4

    .line 87
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 88
    .line 89
    .line 90
    move-result-object p2

    .line 91
    check-cast p2, Lvy/p;

    .line 92
    .line 93
    iget-object v2, p0, Lvy/v;->h:Lij0/a;

    .line 94
    .line 95
    const/4 v6, 0x0

    .line 96
    invoke-static {p2, p1, v2, v6}, Llp/pc;->i(Lvy/p;Luy/b;Lij0/a;Lcn0/c;)Lvy/p;

    .line 97
    .line 98
    .line 99
    move-result-object p2

    .line 100
    invoke-virtual {p0, p2}, Lql0/j;->g(Lql0/h;)V

    .line 101
    .line 102
    .line 103
    invoke-static {v4, v5}, Lmy0/c;->i(J)Z

    .line 104
    .line 105
    .line 106
    move-result p2

    .line 107
    if-eqz p2, :cond_5

    .line 108
    .line 109
    iput-object v6, v0, Lvy/u;->d:Luy/b;

    .line 110
    .line 111
    iput v3, v0, Lvy/u;->g:I

    .line 112
    .line 113
    invoke-virtual {p0, p1, v0}, Lvy/v;->j(Luy/b;Lrx0/c;)Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object p0

    .line 117
    if-ne p0, v1, :cond_5

    .line 118
    .line 119
    :goto_2
    return-object v1

    .line 120
    :cond_5
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 121
    .line 122
    return-object p0
.end method
