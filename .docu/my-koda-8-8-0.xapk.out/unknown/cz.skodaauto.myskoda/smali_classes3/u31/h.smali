.class public final Lu31/h;
.super Lq41/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final f:Lz9/y;

.field public final g:Lk31/f0;

.field public final h:Lk31/l0;

.field public final i:Landroidx/lifecycle/s0;

.field public j:Lvy0/x1;


# direct methods
.method public constructor <init>(Lz9/y;Lk31/f0;Lk31/l0;Landroidx/lifecycle/s0;)V
    .locals 2

    .line 1
    new-instance v0, Lu31/i;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lu31/i;-><init>(Z)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0, v0}, Lq41/b;-><init>(Lq41/a;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Lu31/h;->f:Lz9/y;

    .line 11
    .line 12
    iput-object p2, p0, Lu31/h;->g:Lk31/f0;

    .line 13
    .line 14
    iput-object p3, p0, Lu31/h;->h:Lk31/l0;

    .line 15
    .line 16
    iput-object p4, p0, Lu31/h;->i:Landroidx/lifecycle/s0;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final b(Lu31/e;)V
    .locals 3

    .line 1
    const-string v0, "event"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Lu31/a;

    .line 7
    .line 8
    if-eqz v0, :cond_1

    .line 9
    .line 10
    new-instance p1, Lu31/f;

    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    invoke-direct {p1, p0, v0}, Lu31/f;-><init>(Lu31/h;I)V

    .line 14
    .line 15
    .line 16
    iget-object v0, p0, Lu31/h;->h:Lk31/l0;

    .line 17
    .line 18
    invoke-virtual {v0, p1}, Lk31/l0;->a(Lay0/k;)V

    .line 19
    .line 20
    .line 21
    const-class p1, Ll31/t;

    .line 22
    .line 23
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 24
    .line 25
    invoke-virtual {v0, p1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    iget-object v0, p0, Lu31/h;->i:Landroidx/lifecycle/s0;

    .line 30
    .line 31
    invoke-static {v0, p1}, Ljp/t0;->c(Landroidx/lifecycle/s0;Lhy0/d;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    check-cast p1, Ll31/t;

    .line 36
    .line 37
    iget-boolean p1, p1, Ll31/t;->a:Z

    .line 38
    .line 39
    iget-object p0, p0, Lu31/h;->f:Lz9/y;

    .line 40
    .line 41
    if-eqz p1, :cond_0

    .line 42
    .line 43
    invoke-virtual {p0}, Lz9/y;->h()Z

    .line 44
    .line 45
    .line 46
    return-void

    .line 47
    :cond_0
    new-instance p1, Ll31/f;

    .line 48
    .line 49
    const/4 v0, 0x0

    .line 50
    invoke-direct {p1, v0}, Ll31/f;-><init>(Z)V

    .line 51
    .line 52
    .line 53
    invoke-static {p0, p1}, Lz9/y;->e(Lz9/y;Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    return-void

    .line 57
    :cond_1
    instance-of v0, p1, Lu31/b;

    .line 58
    .line 59
    if-eqz v0, :cond_3

    .line 60
    .line 61
    check-cast p1, Lu31/b;

    .line 62
    .line 63
    iget-boolean v0, p1, Lu31/b;->a:Z

    .line 64
    .line 65
    :cond_2
    iget-object p1, p0, Lq41/b;->d:Lyy0/c2;

    .line 66
    .line 67
    invoke-virtual {p1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object v1

    .line 71
    move-object v2, v1

    .line 72
    check-cast v2, Lu31/i;

    .line 73
    .line 74
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 75
    .line 76
    .line 77
    new-instance v2, Lu31/i;

    .line 78
    .line 79
    invoke-direct {v2, v0}, Lu31/i;-><init>(Z)V

    .line 80
    .line 81
    .line 82
    invoke-virtual {p1, v1, v2}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 83
    .line 84
    .line 85
    move-result p1

    .line 86
    if-eqz p1, :cond_2

    .line 87
    .line 88
    goto :goto_0

    .line 89
    :cond_3
    instance-of v0, p1, Lu31/c;

    .line 90
    .line 91
    const/4 v1, 0x0

    .line 92
    if-eqz v0, :cond_5

    .line 93
    .line 94
    iget-object p1, p0, Lu31/h;->j:Lvy0/x1;

    .line 95
    .line 96
    if-eqz p1, :cond_4

    .line 97
    .line 98
    invoke-virtual {p1}, Lvy0/p1;->a()Z

    .line 99
    .line 100
    .line 101
    move-result p1

    .line 102
    const/4 v0, 0x1

    .line 103
    if-ne p1, v0, :cond_4

    .line 104
    .line 105
    :goto_0
    return-void

    .line 106
    :cond_4
    iget-object p1, p0, Lu31/h;->g:Lk31/f0;

    .line 107
    .line 108
    invoke-virtual {p1}, Lk31/f0;->a()Lyy0/i;

    .line 109
    .line 110
    .line 111
    move-result-object p1

    .line 112
    new-instance v0, Lrz/k;

    .line 113
    .line 114
    const/4 v2, 0x6

    .line 115
    invoke-direct {v0, p1, v2}, Lrz/k;-><init>(Lyy0/i;I)V

    .line 116
    .line 117
    .line 118
    invoke-static {v0}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 119
    .line 120
    .line 121
    move-result-object p1

    .line 122
    new-instance v0, Lc/m;

    .line 123
    .line 124
    const/16 v2, 0x9

    .line 125
    .line 126
    invoke-direct {v0, p0, v1, v2}, Lc/m;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

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
    iput-object p1, p0, Lu31/h;->j:Lvy0/x1;

    .line 144
    .line 145
    return-void

    .line 146
    :cond_5
    instance-of p1, p1, Lu31/d;

    .line 147
    .line 148
    if-eqz p1, :cond_7

    .line 149
    .line 150
    iget-object p1, p0, Lu31/h;->j:Lvy0/x1;

    .line 151
    .line 152
    if-eqz p1, :cond_6

    .line 153
    .line 154
    invoke-virtual {p1, v1}, Lvy0/p1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 155
    .line 156
    .line 157
    :cond_6
    iput-object v1, p0, Lu31/h;->j:Lvy0/x1;

    .line 158
    .line 159
    return-void

    .line 160
    :cond_7
    new-instance p0, La8/r0;

    .line 161
    .line 162
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 163
    .line 164
    .line 165
    throw p0
.end method
