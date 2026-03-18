.class public final Lhv0/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lhv0/t;

.field public final b:Lz40/f;

.field public final c:Le60/h;

.field public final d:Lal0/l0;

.field public final e:Lwj0/a0;

.field public final f:Lwj0/j0;

.field public final g:Lwj0/f0;

.field public final h:Lbn0/f;


# direct methods
.method public constructor <init>(Lwj0/k;Lal0/o0;Lhv0/t;Lz40/f;Le60/h;Lal0/l0;Lwj0/a0;Lwj0/j0;Lwj0/f0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Lhv0/k;->a:Lhv0/t;

    .line 5
    .line 6
    iput-object p4, p0, Lhv0/k;->b:Lz40/f;

    .line 7
    .line 8
    iput-object p5, p0, Lhv0/k;->c:Le60/h;

    .line 9
    .line 10
    iput-object p6, p0, Lhv0/k;->d:Lal0/l0;

    .line 11
    .line 12
    iput-object p7, p0, Lhv0/k;->e:Lwj0/a0;

    .line 13
    .line 14
    iput-object p8, p0, Lhv0/k;->f:Lwj0/j0;

    .line 15
    .line 16
    iput-object p9, p0, Lhv0/k;->g:Lwj0/f0;

    .line 17
    .line 18
    invoke-virtual {p1}, Lwj0/k;->invoke()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    check-cast p1, Lyy0/i;

    .line 23
    .line 24
    invoke-virtual {p2}, Lal0/o0;->invoke()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p2

    .line 28
    check-cast p2, Lyy0/i;

    .line 29
    .line 30
    new-instance p3, Lal0/m0;

    .line 31
    .line 32
    const/4 p4, 0x2

    .line 33
    const/16 p5, 0xc

    .line 34
    .line 35
    const/4 p6, 0x0

    .line 36
    invoke-direct {p3, p4, p6, p5}, Lal0/m0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 37
    .line 38
    .line 39
    new-instance p4, Lne0/n;

    .line 40
    .line 41
    invoke-direct {p4, p3, p2}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 42
    .line 43
    .line 44
    new-instance p2, Lal0/y0;

    .line 45
    .line 46
    const/4 p3, 0x3

    .line 47
    const/4 p5, 0x6

    .line 48
    invoke-direct {p2, p3, p6, p5}, Lal0/y0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 49
    .line 50
    .line 51
    new-instance p3, Lbn0/f;

    .line 52
    .line 53
    const/4 p5, 0x5

    .line 54
    invoke-direct {p3, p1, p4, p2, p5}, Lbn0/f;-><init>(Lyy0/i;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 55
    .line 56
    .line 57
    iput-object p3, p0, Lhv0/k;->h:Lbn0/f;

    .line 58
    .line 59
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lhv0/k;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 14

    .line 1
    instance-of v0, p1, Lhv0/f;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lhv0/f;

    .line 7
    .line 8
    iget v1, v0, Lhv0/f;->f:I

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
    iput v1, v0, Lhv0/f;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lhv0/f;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lhv0/f;-><init>(Lhv0/k;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lhv0/f;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lhv0/f;->f:I

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    goto/16 :goto_2

    .line 40
    .line 41
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 42
    .line 43
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 44
    .line 45
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    throw p0

    .line 49
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    iget-object p1, p0, Lhv0/k;->a:Lhv0/t;

    .line 53
    .line 54
    invoke-virtual {p1}, Lhv0/t;->invoke()Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object p1

    .line 58
    check-cast p1, Lyy0/i;

    .line 59
    .line 60
    new-instance v2, Lgb0/z;

    .line 61
    .line 62
    const/4 v4, 0x6

    .line 63
    const/4 v5, 0x0

    .line 64
    invoke-direct {v2, v5, p0, v4}, Lgb0/z;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 65
    .line 66
    .line 67
    invoke-static {p1, v2}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 68
    .line 69
    .line 70
    move-result-object p1

    .line 71
    new-instance v2, Lh40/w3;

    .line 72
    .line 73
    const/16 v4, 0x15

    .line 74
    .line 75
    invoke-direct {v2, p0, v5, v4}, Lh40/w3;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 76
    .line 77
    .line 78
    new-instance v4, Lne0/n;

    .line 79
    .line 80
    const/4 v6, 0x5

    .line 81
    invoke-direct {v4, p1, v2, v6}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 82
    .line 83
    .line 84
    new-instance p1, Lal0/y0;

    .line 85
    .line 86
    const/4 v2, 0x4

    .line 87
    const/4 v6, 0x3

    .line 88
    invoke-direct {p1, v6, v5, v2}, Lal0/y0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 89
    .line 90
    .line 91
    new-instance v2, Lbn0/f;

    .line 92
    .line 93
    const/4 v7, 0x5

    .line 94
    iget-object v8, p0, Lhv0/k;->h:Lbn0/f;

    .line 95
    .line 96
    invoke-direct {v2, v4, v8, p1, v7}, Lbn0/f;-><init>(Lyy0/i;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 97
    .line 98
    .line 99
    iget-object p1, p0, Lhv0/k;->c:Le60/h;

    .line 100
    .line 101
    invoke-virtual {p1}, Le60/h;->invoke()Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object p1

    .line 105
    check-cast p1, Lyy0/i;

    .line 106
    .line 107
    new-instance v4, Lal0/m0;

    .line 108
    .line 109
    const/4 v7, 0x2

    .line 110
    const/16 v8, 0xb

    .line 111
    .line 112
    invoke-direct {v4, v7, v5, v8}, Lal0/m0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 113
    .line 114
    .line 115
    new-instance v7, Lne0/n;

    .line 116
    .line 117
    invoke-direct {v7, v4, p1}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 118
    .line 119
    .line 120
    new-instance p1, Lal0/y0;

    .line 121
    .line 122
    const/4 v4, 0x5

    .line 123
    invoke-direct {p1, v6, v5, v4}, Lal0/y0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 124
    .line 125
    .line 126
    new-instance v4, Lbn0/f;

    .line 127
    .line 128
    const/4 v6, 0x5

    .line 129
    invoke-direct {v4, v2, v7, p1, v6}, Lbn0/f;-><init>(Lyy0/i;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 130
    .line 131
    .line 132
    new-instance v9, Lrz/k;

    .line 133
    .line 134
    const/16 p1, 0x15

    .line 135
    .line 136
    invoke-direct {v9, v4, p1}, Lrz/k;-><init>(Lyy0/i;I)V

    .line 137
    .line 138
    .line 139
    sget-object v10, Lge0/b;->a:Lcz0/e;

    .line 140
    .line 141
    sget-object p1, Lvy0/h1;->d:Lvy0/h1;

    .line 142
    .line 143
    invoke-virtual {v10, p1}, Lvy0/x;->get(Lpx0/f;)Lpx0/e;

    .line 144
    .line 145
    .line 146
    move-result-object p1

    .line 147
    if-nez p1, :cond_6

    .line 148
    .line 149
    sget-object p1, Lpx0/h;->d:Lpx0/h;

    .line 150
    .line 151
    invoke-virtual {v10, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 152
    .line 153
    .line 154
    move-result p1

    .line 155
    if-eqz p1, :cond_3

    .line 156
    .line 157
    goto :goto_1

    .line 158
    :cond_3
    instance-of p1, v9, Lzy0/o;

    .line 159
    .line 160
    if-eqz p1, :cond_4

    .line 161
    .line 162
    check-cast v9, Lzy0/o;

    .line 163
    .line 164
    const/4 p1, 0x0

    .line 165
    const/4 v2, 0x6

    .line 166
    invoke-static {v9, v10, p1, v5, v2}, Lzy0/c;->b(Lzy0/o;Lpx0/g;ILxy0/a;I)Lyy0/i;

    .line 167
    .line 168
    .line 169
    move-result-object v9

    .line 170
    goto :goto_1

    .line 171
    :cond_4
    new-instance v8, Lzy0/g;

    .line 172
    .line 173
    const/4 v12, 0x0

    .line 174
    const/16 v13, 0xc

    .line 175
    .line 176
    const/4 v11, 0x0

    .line 177
    invoke-direct/range {v8 .. v13}, Lzy0/g;-><init>(Lyy0/i;Lpx0/g;ILxy0/a;I)V

    .line 178
    .line 179
    .line 180
    move-object v9, v8

    .line 181
    :goto_1
    new-instance p1, Lgt0/c;

    .line 182
    .line 183
    const/16 v2, 0xe

    .line 184
    .line 185
    invoke-direct {p1, p0, v2}, Lgt0/c;-><init>(Ljava/lang/Object;I)V

    .line 186
    .line 187
    .line 188
    iput v3, v0, Lhv0/f;->f:I

    .line 189
    .line 190
    invoke-interface {v9, p1, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 191
    .line 192
    .line 193
    move-result-object p0

    .line 194
    if-ne p0, v1, :cond_5

    .line 195
    .line 196
    return-object v1

    .line 197
    :cond_5
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 198
    .line 199
    return-object p0

    .line 200
    :cond_6
    new-instance p0, Ljava/lang/StringBuilder;

    .line 201
    .line 202
    const-string p1, "Flow context cannot contain job in it. Had "

    .line 203
    .line 204
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 205
    .line 206
    .line 207
    invoke-virtual {p0, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 208
    .line 209
    .line 210
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 211
    .line 212
    .line 213
    move-result-object p0

    .line 214
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 215
    .line 216
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 217
    .line 218
    .line 219
    move-result-object p0

    .line 220
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 221
    .line 222
    .line 223
    throw p1
.end method
