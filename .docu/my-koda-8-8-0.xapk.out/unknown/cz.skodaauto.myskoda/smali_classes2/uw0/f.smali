.class public final Luw0/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public d:I

.field public final synthetic e:Lio/ktor/utils/io/d0;

.field public final synthetic f:Luw0/a;

.field public final synthetic g:Luw0/h;

.field public final synthetic h:Lqz0/a;

.field public final synthetic i:Ljava/nio/charset/Charset;


# direct methods
.method public constructor <init>(Lio/ktor/utils/io/d0;Luw0/a;Luw0/h;Lqz0/a;Ljava/nio/charset/Charset;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Luw0/f;->e:Lio/ktor/utils/io/d0;

    .line 5
    .line 6
    iput-object p2, p0, Luw0/f;->f:Luw0/a;

    .line 7
    .line 8
    iput-object p3, p0, Luw0/f;->g:Luw0/h;

    .line 9
    .line 10
    iput-object p4, p0, Luw0/f;->h:Lqz0/a;

    .line 11
    .line 12
    iput-object p5, p0, Luw0/f;->i:Ljava/nio/charset/Charset;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 9

    .line 1
    instance-of v0, p2, Luw0/e;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Luw0/e;

    .line 7
    .line 8
    iget v1, v0, Luw0/e;->e:I

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
    iput v1, v0, Luw0/e;->e:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Luw0/e;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Luw0/e;-><init>(Luw0/f;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Luw0/e;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Luw0/e;->e:I

    .line 30
    .line 31
    iget-object v3, p0, Luw0/f;->e:Lio/ktor/utils/io/d0;

    .line 32
    .line 33
    const/4 v4, 0x3

    .line 34
    const/4 v5, 0x2

    .line 35
    const/4 v6, 0x1

    .line 36
    const/4 v7, 0x0

    .line 37
    if-eqz v2, :cond_4

    .line 38
    .line 39
    if-eq v2, v6, :cond_3

    .line 40
    .line 41
    if-eq v2, v5, :cond_2

    .line 42
    .line 43
    if-ne v2, v4, :cond_1

    .line 44
    .line 45
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    goto/16 :goto_4

    .line 49
    .line 50
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 51
    .line 52
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 53
    .line 54
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw p0

    .line 58
    :cond_2
    iget p0, v0, Luw0/e;->i:I

    .line 59
    .line 60
    iget p1, v0, Luw0/e;->h:I

    .line 61
    .line 62
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    goto :goto_2

    .line 66
    :cond_3
    iget p1, v0, Luw0/e;->i:I

    .line 67
    .line 68
    iget v2, v0, Luw0/e;->h:I

    .line 69
    .line 70
    iget-object v6, v0, Luw0/e;->g:Ljava/lang/Object;

    .line 71
    .line 72
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    move p2, p1

    .line 76
    move-object p1, v6

    .line 77
    goto :goto_1

    .line 78
    :cond_4
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    iget v2, p0, Luw0/f;->d:I

    .line 82
    .line 83
    add-int/lit8 p2, v2, 0x1

    .line 84
    .line 85
    iput p2, p0, Luw0/f;->d:I

    .line 86
    .line 87
    if-ltz v2, :cond_8

    .line 88
    .line 89
    const/4 p2, 0x0

    .line 90
    if-lez v2, :cond_5

    .line 91
    .line 92
    iget-object v8, p0, Luw0/f;->f:Luw0/a;

    .line 93
    .line 94
    iget-object v8, v8, Luw0/a;->c:[B

    .line 95
    .line 96
    iput-object p1, v0, Luw0/e;->g:Ljava/lang/Object;

    .line 97
    .line 98
    iput v2, v0, Luw0/e;->h:I

    .line 99
    .line 100
    iput p2, v0, Luw0/e;->i:I

    .line 101
    .line 102
    iput v6, v0, Luw0/e;->e:I

    .line 103
    .line 104
    invoke-static {v3, v8, v0}, Lio/ktor/utils/io/h0;->o(Lio/ktor/utils/io/d0;[BLrx0/c;)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v6

    .line 108
    if-ne v6, v1, :cond_5

    .line 109
    .line 110
    goto :goto_3

    .line 111
    :cond_5
    :goto_1
    iget-object v6, p0, Luw0/f;->g:Luw0/h;

    .line 112
    .line 113
    iget-object v6, v6, Luw0/h;->a:Lvz0/d;

    .line 114
    .line 115
    iget-object v8, p0, Luw0/f;->h:Lqz0/a;

    .line 116
    .line 117
    check-cast v8, Lqz0/a;

    .line 118
    .line 119
    invoke-virtual {v6, v8, p1}, Lvz0/d;->d(Lqz0/a;Ljava/lang/Object;)Ljava/lang/String;

    .line 120
    .line 121
    .line 122
    move-result-object p1

    .line 123
    iget-object p0, p0, Luw0/f;->i:Ljava/nio/charset/Charset;

    .line 124
    .line 125
    invoke-static {p1, p0}, Ljp/ib;->c(Ljava/lang/String;Ljava/nio/charset/Charset;)[B

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    iput-object v7, v0, Luw0/e;->g:Ljava/lang/Object;

    .line 130
    .line 131
    iput v2, v0, Luw0/e;->h:I

    .line 132
    .line 133
    iput p2, v0, Luw0/e;->i:I

    .line 134
    .line 135
    iput v5, v0, Luw0/e;->e:I

    .line 136
    .line 137
    invoke-static {v3, p0, v0}, Lio/ktor/utils/io/h0;->o(Lio/ktor/utils/io/d0;[BLrx0/c;)Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object p0

    .line 141
    if-ne p0, v1, :cond_6

    .line 142
    .line 143
    goto :goto_3

    .line 144
    :cond_6
    move p0, p2

    .line 145
    move p1, v2

    .line 146
    :goto_2
    iput-object v7, v0, Luw0/e;->g:Ljava/lang/Object;

    .line 147
    .line 148
    iput p1, v0, Luw0/e;->h:I

    .line 149
    .line 150
    iput p0, v0, Luw0/e;->i:I

    .line 151
    .line 152
    iput v4, v0, Luw0/e;->e:I

    .line 153
    .line 154
    check-cast v3, Lio/ktor/utils/io/m;

    .line 155
    .line 156
    invoke-virtual {v3, v0}, Lio/ktor/utils/io/m;->b(Lrx0/c;)Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object p0

    .line 160
    if-ne p0, v1, :cond_7

    .line 161
    .line 162
    :goto_3
    return-object v1

    .line 163
    :cond_7
    :goto_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 164
    .line 165
    return-object p0

    .line 166
    :cond_8
    new-instance p0, Ljava/lang/ArithmeticException;

    .line 167
    .line 168
    const-string p1, "Index overflow has happened"

    .line 169
    .line 170
    invoke-direct {p0, p1}, Ljava/lang/ArithmeticException;-><init>(Ljava/lang/String;)V

    .line 171
    .line 172
    .line 173
    throw p0
.end method
