.class public final Lyd/u;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lus0/a;

.field public final e:Lwp0/c;

.field public final f:Lyj/b;

.field public final g:Lyj/b;

.field public final h:Ly1/i;

.field public final i:Lyy0/c2;

.field public final j:Lyy0/c2;

.field public final k:Lyy0/c2;

.field public final l:Lyy0/c2;

.field public final m:Lyy0/l1;


# direct methods
.method public constructor <init>(Lus0/a;Lwp0/c;Lyj/b;Lyj/b;Ly1/i;)V
    .locals 7

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lyd/u;->d:Lus0/a;

    .line 5
    .line 6
    iput-object p2, p0, Lyd/u;->e:Lwp0/c;

    .line 7
    .line 8
    iput-object p3, p0, Lyd/u;->f:Lyj/b;

    .line 9
    .line 10
    iput-object p4, p0, Lyd/u;->g:Lyj/b;

    .line 11
    .line 12
    iput-object p5, p0, Lyd/u;->h:Ly1/i;

    .line 13
    .line 14
    const/4 p1, 0x0

    .line 15
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 16
    .line 17
    .line 18
    move-result-object p2

    .line 19
    iput-object p2, p0, Lyd/u;->i:Lyy0/c2;

    .line 20
    .line 21
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 22
    .line 23
    .line 24
    move-result-object p3

    .line 25
    iput-object p3, p0, Lyd/u;->j:Lyy0/c2;

    .line 26
    .line 27
    const-string p4, ""

    .line 28
    .line 29
    invoke-static {p4}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 30
    .line 31
    .line 32
    move-result-object p4

    .line 33
    iput-object p4, p0, Lyd/u;->k:Lyy0/c2;

    .line 34
    .line 35
    sget-object p5, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 36
    .line 37
    invoke-static {p5}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 38
    .line 39
    .line 40
    move-result-object p5

    .line 41
    iput-object p5, p0, Lyd/u;->l:Lyy0/c2;

    .line 42
    .line 43
    new-instance v0, Lyd/t;

    .line 44
    .line 45
    const-string v6, "map(Lkotlin/Result;Lcariad/charging/multicharge/kitten/coupons/models/CouponsResponse;Ljava/lang/String;Z)Lcariad/charging/multicharge/common/presentation/loadingcontenterror/UiState;"

    .line 46
    .line 47
    const/4 v2, 0x4

    .line 48
    const/4 v1, 0x5

    .line 49
    const-class v3, Lyd/l;

    .line 50
    .line 51
    sget-object v4, Lyd/l;->a:Lyd/l;

    .line 52
    .line 53
    const-string v5, "map"

    .line 54
    .line 55
    invoke-direct/range {v0 .. v6}, Lkotlin/jvm/internal/a;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    invoke-static {p2, p3, p4, p5, v0}, Lyy0/u;->l(Lyy0/i;Lyy0/i;Lyy0/i;Lyy0/i;Lay0/q;)Llb0/y;

    .line 59
    .line 60
    .line 61
    move-result-object p2

    .line 62
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 63
    .line 64
    .line 65
    move-result-object p3

    .line 66
    const/4 p4, 0x3

    .line 67
    const-wide/16 v0, 0x0

    .line 68
    .line 69
    invoke-static {p4, v0, v1}, Lyy0/u1;->a(IJ)Lyy0/z1;

    .line 70
    .line 71
    .line 72
    move-result-object p5

    .line 73
    new-instance v0, Llc/q;

    .line 74
    .line 75
    sget-object v1, Llc/a;->c:Llc/c;

    .line 76
    .line 77
    invoke-direct {v0, v1}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    invoke-static {p2, p3, p5, v0}, Lyy0/u;->F(Lyy0/i;Lvy0/b0;Lyy0/v1;Ljava/lang/Object;)Lyy0/l1;

    .line 81
    .line 82
    .line 83
    move-result-object p2

    .line 84
    iput-object p2, p0, Lyd/u;->m:Lyy0/l1;

    .line 85
    .line 86
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 87
    .line 88
    .line 89
    move-result-object p2

    .line 90
    new-instance p3, Lxm0/g;

    .line 91
    .line 92
    const/4 p5, 0x7

    .line 93
    invoke-direct {p3, p0, p1, p5}, Lxm0/g;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 94
    .line 95
    .line 96
    invoke-static {p2, p1, p1, p3, p4}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 97
    .line 98
    .line 99
    return-void
.end method


# virtual methods
.method public final a(Lyd/k;)V
    .locals 7

    .line 1
    const-string v0, "event"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Lyd/g;

    .line 7
    .line 8
    const/4 v1, 0x3

    .line 9
    iget-object v2, p0, Lyd/u;->i:Lyy0/c2;

    .line 10
    .line 11
    const/4 v3, 0x0

    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    invoke-virtual {v2, v3}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    new-instance v0, Lyd/s;

    .line 22
    .line 23
    const/4 v2, 0x1

    .line 24
    invoke-direct {v0, p0, v3, v2}, Lyd/s;-><init>(Lyd/u;Lkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    invoke-static {p1, v3, v3, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 28
    .line 29
    .line 30
    return-void

    .line 31
    :cond_0
    instance-of v0, p1, Lyd/f;

    .line 32
    .line 33
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    if-eqz v0, :cond_1

    .line 36
    .line 37
    check-cast p1, Lyd/f;

    .line 38
    .line 39
    iget-object p1, p1, Lyd/f;->a:Ljava/lang/String;

    .line 40
    .line 41
    sget-object v0, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 42
    .line 43
    invoke-virtual {p1, v0}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    const-string v0, "toUpperCase(...)"

    .line 48
    .line 49
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    iget-object p0, p0, Lyd/u;->k:Lyy0/c2;

    .line 53
    .line 54
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 55
    .line 56
    .line 57
    invoke-virtual {p0, v3, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    new-instance p0, Llx0/o;

    .line 61
    .line 62
    invoke-direct {p0, v4}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 66
    .line 67
    .line 68
    invoke-virtual {v2, v3, p0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    return-void

    .line 72
    :cond_1
    instance-of v0, p1, Lyd/i;

    .line 73
    .line 74
    if-eqz v0, :cond_2

    .line 75
    .line 76
    iget-object p0, p0, Lyd/u;->f:Lyj/b;

    .line 77
    .line 78
    invoke-virtual {p0}, Lyj/b;->invoke()Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    return-void

    .line 82
    :cond_2
    instance-of v0, p1, Lyd/j;

    .line 83
    .line 84
    if-eqz v0, :cond_3

    .line 85
    .line 86
    iget-object p0, p0, Lyd/u;->g:Lyj/b;

    .line 87
    .line 88
    invoke-virtual {p0}, Lyj/b;->invoke()Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    return-void

    .line 92
    :cond_3
    instance-of v0, p1, Lyd/d;

    .line 93
    .line 94
    iget-object v5, p0, Lyd/u;->h:Ly1/i;

    .line 95
    .line 96
    if-eqz v0, :cond_5

    .line 97
    .line 98
    iget-object p0, p0, Lyd/u;->l:Lyy0/c2;

    .line 99
    .line 100
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object p1

    .line 104
    check-cast p1, Ljava/lang/Boolean;

    .line 105
    .line 106
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 107
    .line 108
    .line 109
    move-result p1

    .line 110
    if-eqz p1, :cond_4

    .line 111
    .line 112
    invoke-virtual {v5}, Ly1/i;->invoke()Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    return-void

    .line 116
    :cond_4
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 117
    .line 118
    invoke-virtual {p0, v3, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 119
    .line 120
    .line 121
    return-void

    .line 122
    :cond_5
    instance-of v0, p1, Lyd/h;

    .line 123
    .line 124
    iget-object v6, p0, Lyd/u;->j:Lyy0/c2;

    .line 125
    .line 126
    if-eqz v0, :cond_7

    .line 127
    .line 128
    invoke-virtual {v6}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object p1

    .line 132
    if-nez p1, :cond_6

    .line 133
    .line 134
    invoke-virtual {v2, v3}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 135
    .line 136
    .line 137
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 138
    .line 139
    .line 140
    move-result-object p1

    .line 141
    new-instance v0, Lyd/s;

    .line 142
    .line 143
    const/4 v2, 0x0

    .line 144
    invoke-direct {v0, p0, v3, v2}, Lyd/s;-><init>(Lyd/u;Lkotlin/coroutines/Continuation;I)V

    .line 145
    .line 146
    .line 147
    invoke-static {p1, v3, v3, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 148
    .line 149
    .line 150
    return-void

    .line 151
    :cond_6
    invoke-virtual {v2, v3}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 152
    .line 153
    .line 154
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 155
    .line 156
    .line 157
    move-result-object p1

    .line 158
    new-instance v0, Lyd/s;

    .line 159
    .line 160
    const/4 v2, 0x1

    .line 161
    invoke-direct {v0, p0, v3, v2}, Lyd/s;-><init>(Lyd/u;Lkotlin/coroutines/Continuation;I)V

    .line 162
    .line 163
    .line 164
    invoke-static {p1, v3, v3, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 165
    .line 166
    .line 167
    return-void

    .line 168
    :cond_7
    sget-object p0, Lyd/e;->a:Lyd/e;

    .line 169
    .line 170
    invoke-virtual {p1, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 171
    .line 172
    .line 173
    move-result p0

    .line 174
    if-eqz p0, :cond_9

    .line 175
    .line 176
    invoke-virtual {v6}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    move-result-object p0

    .line 180
    if-nez p0, :cond_8

    .line 181
    .line 182
    invoke-virtual {v5}, Ly1/i;->invoke()Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    return-void

    .line 186
    :cond_8
    new-instance p0, Llx0/o;

    .line 187
    .line 188
    invoke-direct {p0, v4}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 189
    .line 190
    .line 191
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 192
    .line 193
    .line 194
    invoke-virtual {v2, v3, p0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 195
    .line 196
    .line 197
    return-void

    .line 198
    :cond_9
    new-instance p0, La8/r0;

    .line 199
    .line 200
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 201
    .line 202
    .line 203
    throw p0
.end method
