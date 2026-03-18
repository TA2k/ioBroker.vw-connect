.class public final Lr31/i;
.super Lq41/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final f:Lz9/y;

.field public final g:Lk31/f0;

.field public final h:Lk31/l0;

.field public final i:Lk31/e0;

.field public final j:Lk31/n;

.field public final k:Landroidx/lifecycle/s0;

.field public l:Lvy0/x1;


# direct methods
.method public constructor <init>(Lz9/y;Lk31/f0;Lk31/l0;Lk31/e0;Lk31/n;Landroidx/lifecycle/s0;)V
    .locals 4

    .line 1
    new-instance v0, Lr31/j;

    .line 2
    .line 3
    const-string v1, ""

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x1

    .line 7
    invoke-direct {v0, v1, v2, v3, v2}, Lr31/j;-><init>(Ljava/lang/String;ZZZ)V

    .line 8
    .line 9
    .line 10
    invoke-direct {p0, v0}, Lq41/b;-><init>(Lq41/a;)V

    .line 11
    .line 12
    .line 13
    iput-object p1, p0, Lr31/i;->f:Lz9/y;

    .line 14
    .line 15
    iput-object p2, p0, Lr31/i;->g:Lk31/f0;

    .line 16
    .line 17
    iput-object p3, p0, Lr31/i;->h:Lk31/l0;

    .line 18
    .line 19
    iput-object p4, p0, Lr31/i;->i:Lk31/e0;

    .line 20
    .line 21
    iput-object p5, p0, Lr31/i;->j:Lk31/n;

    .line 22
    .line 23
    iput-object p6, p0, Lr31/i;->k:Landroidx/lifecycle/s0;

    .line 24
    .line 25
    const-class p1, Ll31/f;

    .line 26
    .line 27
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 28
    .line 29
    invoke-virtual {p2, p1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    invoke-static {p6, p1}, Ljp/t0;->c(Landroidx/lifecycle/s0;Lhy0/d;)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    check-cast p1, Ll31/f;

    .line 38
    .line 39
    iget-boolean p1, p1, Ll31/f;->a:Z

    .line 40
    .line 41
    if-eqz p1, :cond_1

    .line 42
    .line 43
    iget-object p0, p0, Lq41/b;->d:Lyy0/c2;

    .line 44
    .line 45
    :cond_0
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    move-object p2, p1

    .line 50
    check-cast p2, Lr31/j;

    .line 51
    .line 52
    const/4 p3, 0x0

    .line 53
    const/4 p4, 0x7

    .line 54
    invoke-static {p2, p3, v2, v3, p4}, Lr31/j;->a(Lr31/j;Ljava/lang/String;ZZI)Lr31/j;

    .line 55
    .line 56
    .line 57
    move-result-object p2

    .line 58
    invoke-virtual {p0, p1, p2}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    move-result p1

    .line 62
    if-eqz p1, :cond_0

    .line 63
    .line 64
    :cond_1
    return-void
.end method


# virtual methods
.method public final b(Z)V
    .locals 2

    .line 1
    new-instance v0, Lh2/d9;

    .line 2
    .line 3
    const/4 v1, 0x5

    .line 4
    invoke-direct {v0, p0, p1, v1}, Lh2/d9;-><init>(Ljava/lang/Object;ZI)V

    .line 5
    .line 6
    .line 7
    iget-object p1, p0, Lr31/i;->h:Lk31/l0;

    .line 8
    .line 9
    invoke-virtual {p1, v0}, Lk31/l0;->a(Lay0/k;)V

    .line 10
    .line 11
    .line 12
    const-class p1, Ll31/f;

    .line 13
    .line 14
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 15
    .line 16
    invoke-virtual {v0, p1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    iget-object v0, p0, Lr31/i;->k:Landroidx/lifecycle/s0;

    .line 21
    .line 22
    invoke-static {v0, p1}, Ljp/t0;->c(Landroidx/lifecycle/s0;Lhy0/d;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    check-cast p1, Ll31/f;

    .line 27
    .line 28
    iget-boolean p1, p1, Ll31/f;->a:Z

    .line 29
    .line 30
    iget-object v0, p0, Lr31/i;->f:Lz9/y;

    .line 31
    .line 32
    if-eqz p1, :cond_0

    .line 33
    .line 34
    invoke-virtual {v0}, Lz9/y;->h()Z

    .line 35
    .line 36
    .line 37
    return-void

    .line 38
    :cond_0
    iget-object p0, p0, Lr31/i;->j:Lk31/n;

    .line 39
    .line 40
    invoke-static {p0}, Lkp/j;->b(Lr41/a;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    check-cast p0, Li31/j;

    .line 45
    .line 46
    if-eqz p0, :cond_1

    .line 47
    .line 48
    iget-object p0, p0, Li31/j;->a:Lz21/c;

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_1
    const/4 p0, 0x0

    .line 52
    :goto_0
    sget-object p1, Lz21/c;->i:Lz21/c;

    .line 53
    .line 54
    if-ne p0, p1, :cond_2

    .line 55
    .line 56
    sget-object p0, Ll31/u;->INSTANCE:Ll31/u;

    .line 57
    .line 58
    invoke-static {v0, p0}, Lz9/y;->e(Lz9/y;Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    return-void

    .line 62
    :cond_2
    sget-object p0, Ll31/g;->INSTANCE:Ll31/g;

    .line 63
    .line 64
    invoke-static {v0, p0}, Lz9/y;->e(Lz9/y;Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    return-void
.end method

.method public final d(Lr31/g;)V
    .locals 6

    .line 1
    const-string v0, "event"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Lr31/a;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    invoke-virtual {p0, v1}, Lr31/i;->b(Z)V

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :cond_0
    instance-of v0, p1, Lr31/e;

    .line 16
    .line 17
    const/4 v2, 0x1

    .line 18
    if-eqz v0, :cond_1

    .line 19
    .line 20
    invoke-virtual {p0, v2}, Lr31/i;->b(Z)V

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    :cond_1
    instance-of v0, p1, Lr31/b;

    .line 25
    .line 26
    iget-object v3, p0, Lq41/b;->d:Lyy0/c2;

    .line 27
    .line 28
    if-eqz v0, :cond_3

    .line 29
    .line 30
    check-cast p1, Lr31/b;

    .line 31
    .line 32
    iget-object p1, p1, Lr31/b;->a:Ljava/lang/String;

    .line 33
    .line 34
    iget-object p0, p0, Lr31/i;->i:Lk31/e0;

    .line 35
    .line 36
    invoke-virtual {p0, p1}, Lk31/e0;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    :cond_2
    invoke-virtual {v3}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    move-object p1, p0

    .line 45
    check-cast p1, Lr31/j;

    .line 46
    .line 47
    invoke-static {v0}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 48
    .line 49
    .line 50
    move-result v4

    .line 51
    xor-int/2addr v4, v2

    .line 52
    const/16 v5, 0x1a

    .line 53
    .line 54
    invoke-static {p1, v0, v4, v1, v5}, Lr31/j;->a(Lr31/j;Ljava/lang/String;ZZI)Lr31/j;

    .line 55
    .line 56
    .line 57
    move-result-object p1

    .line 58
    invoke-virtual {v3, p0, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    move-result p0

    .line 62
    if-eqz p0, :cond_2

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_3
    instance-of v0, p1, Lr31/f;

    .line 66
    .line 67
    const/4 v4, 0x0

    .line 68
    if-eqz v0, :cond_5

    .line 69
    .line 70
    :cond_4
    invoke-virtual {v3}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    move-object p1, p0

    .line 75
    check-cast p1, Lr31/j;

    .line 76
    .line 77
    const/16 v0, 0xf

    .line 78
    .line 79
    invoke-static {p1, v4, v1, v1, v0}, Lr31/j;->a(Lr31/j;Ljava/lang/String;ZZI)Lr31/j;

    .line 80
    .line 81
    .line 82
    move-result-object p1

    .line 83
    invoke-virtual {v3, p0, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 84
    .line 85
    .line 86
    move-result p0

    .line 87
    if-eqz p0, :cond_4

    .line 88
    .line 89
    goto :goto_0

    .line 90
    :cond_5
    instance-of v0, p1, Lr31/c;

    .line 91
    .line 92
    if-eqz v0, :cond_7

    .line 93
    .line 94
    iget-object p1, p0, Lr31/i;->l:Lvy0/x1;

    .line 95
    .line 96
    if-eqz p1, :cond_6

    .line 97
    .line 98
    invoke-virtual {p1}, Lvy0/p1;->a()Z

    .line 99
    .line 100
    .line 101
    move-result p1

    .line 102
    if-ne p1, v2, :cond_6

    .line 103
    .line 104
    :goto_0
    return-void

    .line 105
    :cond_6
    iget-object p1, p0, Lr31/i;->g:Lk31/f0;

    .line 106
    .line 107
    invoke-virtual {p1}, Lk31/f0;->a()Lyy0/i;

    .line 108
    .line 109
    .line 110
    move-result-object p1

    .line 111
    new-instance v0, Lhg/q;

    .line 112
    .line 113
    const/16 v1, 0x1b

    .line 114
    .line 115
    invoke-direct {v0, p1, v1}, Lhg/q;-><init>(Lyy0/i;I)V

    .line 116
    .line 117
    .line 118
    invoke-static {v0}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 119
    .line 120
    .line 121
    move-result-object p1

    .line 122
    new-instance v0, Lnz/g;

    .line 123
    .line 124
    const/16 v1, 0x14

    .line 125
    .line 126
    invoke-direct {v0, p0, v4, v1}, Lnz/g;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 127
    .line 128
    .line 129
    new-instance v1, Lne0/n;

    .line 130
    .line 131
    const/4 v2, 0x5

    .line 132
    invoke-direct {v1, p1, v0, v2}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 133
    .line 134
    .line 135
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 136
    .line 137
    .line 138
    move-result-object p1

    .line 139
    invoke-static {v1, p1}, Lyy0/u;->B(Lyy0/i;Lvy0/b0;)Lvy0/x1;

    .line 140
    .line 141
    .line 142
    move-result-object p1

    .line 143
    iput-object p1, p0, Lr31/i;->l:Lvy0/x1;

    .line 144
    .line 145
    return-void

    .line 146
    :cond_7
    instance-of p1, p1, Lr31/d;

    .line 147
    .line 148
    if-eqz p1, :cond_9

    .line 149
    .line 150
    iget-object p1, p0, Lr31/i;->l:Lvy0/x1;

    .line 151
    .line 152
    if-eqz p1, :cond_8

    .line 153
    .line 154
    invoke-virtual {p1, v4}, Lvy0/p1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 155
    .line 156
    .line 157
    :cond_8
    iput-object v4, p0, Lr31/i;->l:Lvy0/x1;

    .line 158
    .line 159
    return-void

    .line 160
    :cond_9
    new-instance p0, La8/r0;

    .line 161
    .line 162
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 163
    .line 164
    .line 165
    throw p0
.end method
