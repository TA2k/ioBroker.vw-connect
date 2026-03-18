.class public final Lj01/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Li01/d;


# static fields
.field public static final g:Ld01/y;


# instance fields
.field public final a:Ld01/h0;

.field public final b:Li01/c;

.field public final c:Lgw0/c;

.field public d:I

.field public final e:Lg1/i3;

.field public f:Ld01/y;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    sget-object v0, Ld01/y;->e:Ld01/y;

    .line 2
    .line 3
    const-string v0, "OkHttp-Response-Body"

    .line 4
    .line 5
    const-string v1, "Truncated"

    .line 6
    .line 7
    filled-new-array {v0, v1}, [Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    invoke-static {v0}, Ljp/te;->b([Ljava/lang/String;)Ld01/y;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lj01/f;->g:Ld01/y;

    .line 16
    .line 17
    return-void
.end method

.method public constructor <init>(Ld01/h0;Li01/c;Lgw0/c;)V
    .locals 1

    .line 1
    const-string v0, "socket"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lj01/f;->a:Ld01/h0;

    .line 10
    .line 11
    iput-object p2, p0, Lj01/f;->b:Li01/c;

    .line 12
    .line 13
    iput-object p3, p0, Lj01/f;->c:Lgw0/c;

    .line 14
    .line 15
    new-instance p1, Lg1/i3;

    .line 16
    .line 17
    iget-object p2, p3, Lgw0/c;->f:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast p2, Lu01/b0;

    .line 20
    .line 21
    invoke-direct {p1, p2}, Lg1/i3;-><init>(Lu01/b0;)V

    .line 22
    .line 23
    .line 24
    iput-object p1, p0, Lj01/f;->e:Lg1/i3;

    .line 25
    .line 26
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 0

    .line 1
    iget-object p0, p0, Lj01/f;->c:Lgw0/c;

    .line 2
    .line 3
    iget-object p0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Lu01/a0;

    .line 6
    .line 7
    invoke-virtual {p0}, Lu01/a0;->flush()V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public final b(Ld01/t0;)J
    .locals 1

    .line 1
    invoke-static {p1}, Li01/e;->a(Ld01/t0;)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    const-wide/16 p0, 0x0

    .line 8
    .line 9
    return-wide p0

    .line 10
    :cond_0
    const-string p0, "Transfer-Encoding"

    .line 11
    .line 12
    invoke-static {p1, p0}, Ld01/t0;->b(Ld01/t0;Ljava/lang/String;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    const-string v0, "chunked"

    .line 17
    .line 18
    invoke-virtual {v0, p0}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    if-eqz p0, :cond_1

    .line 23
    .line 24
    const-wide/16 p0, -0x1

    .line 25
    .line 26
    return-wide p0

    .line 27
    :cond_1
    invoke-static {p1}, Le01/g;->e(Ld01/t0;)J

    .line 28
    .line 29
    .line 30
    move-result-wide p0

    .line 31
    return-wide p0
.end method

.method public final c(Ld01/t0;)Lu01/h0;
    .locals 9

    .line 1
    iget-object v0, p1, Ld01/t0;->d:Ld01/k0;

    .line 2
    .line 3
    invoke-static {p1}, Li01/e;->a(Ld01/t0;)Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-nez v1, :cond_0

    .line 8
    .line 9
    iget-object p1, v0, Ld01/k0;->a:Ld01/a0;

    .line 10
    .line 11
    const-wide/16 v0, 0x0

    .line 12
    .line 13
    invoke-virtual {p0, p1, v0, v1}, Lj01/f;->l(Ld01/a0;J)Lj01/d;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0

    .line 18
    :cond_0
    const-string v1, "Transfer-Encoding"

    .line 19
    .line 20
    invoke-static {p1, v1}, Ld01/t0;->b(Ld01/t0;Ljava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    const-string v2, "chunked"

    .line 25
    .line 26
    invoke-virtual {v2, v1}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    const-string v2, "state: "

    .line 31
    .line 32
    const/4 v3, 0x5

    .line 33
    const/4 v4, 0x4

    .line 34
    if-eqz v1, :cond_2

    .line 35
    .line 36
    iget-object p1, v0, Ld01/k0;->a:Ld01/a0;

    .line 37
    .line 38
    iget v0, p0, Lj01/f;->d:I

    .line 39
    .line 40
    if-ne v0, v4, :cond_1

    .line 41
    .line 42
    iput v3, p0, Lj01/f;->d:I

    .line 43
    .line 44
    new-instance v0, Lj01/c;

    .line 45
    .line 46
    invoke-direct {v0, p0, p1}, Lj01/c;-><init>(Lj01/f;Ld01/a0;)V

    .line 47
    .line 48
    .line 49
    return-object v0

    .line 50
    :cond_1
    new-instance p1, Ljava/lang/StringBuilder;

    .line 51
    .line 52
    invoke-direct {p1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    iget p0, p0, Lj01/f;->d:I

    .line 56
    .line 57
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 65
    .line 66
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    throw p1

    .line 74
    :cond_2
    invoke-static {p1}, Le01/g;->e(Ld01/t0;)J

    .line 75
    .line 76
    .line 77
    move-result-wide v5

    .line 78
    const-wide/16 v7, -0x1

    .line 79
    .line 80
    cmp-long p1, v5, v7

    .line 81
    .line 82
    if-eqz p1, :cond_3

    .line 83
    .line 84
    iget-object p1, v0, Ld01/k0;->a:Ld01/a0;

    .line 85
    .line 86
    invoke-virtual {p0, p1, v5, v6}, Lj01/f;->l(Ld01/a0;J)Lj01/d;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    return-object p0

    .line 91
    :cond_3
    iget-object p1, v0, Ld01/k0;->a:Ld01/a0;

    .line 92
    .line 93
    iget v0, p0, Lj01/f;->d:I

    .line 94
    .line 95
    if-ne v0, v4, :cond_4

    .line 96
    .line 97
    iput v3, p0, Lj01/f;->d:I

    .line 98
    .line 99
    iget-object v0, p0, Lj01/f;->b:Li01/c;

    .line 100
    .line 101
    invoke-interface {v0}, Li01/c;->c()V

    .line 102
    .line 103
    .line 104
    new-instance v0, Lj01/e;

    .line 105
    .line 106
    const-string v1, "url"

    .line 107
    .line 108
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 109
    .line 110
    .line 111
    invoke-direct {v0, p0, p1}, Lj01/a;-><init>(Lj01/f;Ld01/a0;)V

    .line 112
    .line 113
    .line 114
    return-object v0

    .line 115
    :cond_4
    new-instance p1, Ljava/lang/StringBuilder;

    .line 116
    .line 117
    invoke-direct {p1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 118
    .line 119
    .line 120
    iget p0, p0, Lj01/f;->d:I

    .line 121
    .line 122
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 123
    .line 124
    .line 125
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 130
    .line 131
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 132
    .line 133
    .line 134
    move-result-object p0

    .line 135
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 136
    .line 137
    .line 138
    throw p1
.end method

.method public final cancel()V
    .locals 0

    .line 1
    iget-object p0, p0, Lj01/f;->b:Li01/c;

    .line 2
    .line 3
    invoke-interface {p0}, Li01/c;->cancel()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final d()Z
    .locals 1

    .line 1
    iget p0, p0, Lj01/f;->d:I

    .line 2
    .line 3
    const/4 v0, 0x6

    .line 4
    if-ne p0, v0, :cond_0

    .line 5
    .line 6
    const/4 p0, 0x1

    .line 7
    return p0

    .line 8
    :cond_0
    const/4 p0, 0x0

    .line 9
    return p0
.end method

.method public final e(Z)Ld01/s0;
    .locals 10

    .line 1
    iget-object v0, p0, Lj01/f;->e:Lg1/i3;

    .line 2
    .line 3
    iget v1, p0, Lj01/f;->d:I

    .line 4
    .line 5
    const/4 v2, 0x3

    .line 6
    if-eqz v1, :cond_1

    .line 7
    .line 8
    const/4 v3, 0x1

    .line 9
    if-eq v1, v3, :cond_1

    .line 10
    .line 11
    const/4 v3, 0x2

    .line 12
    if-eq v1, v3, :cond_1

    .line 13
    .line 14
    if-ne v1, v2, :cond_0

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    new-instance p1, Ljava/lang/StringBuilder;

    .line 18
    .line 19
    const-string v0, "state: "

    .line 20
    .line 21
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    iget p0, p0, Lj01/f;->d:I

    .line 25
    .line 26
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 34
    .line 35
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    throw p1

    .line 43
    :cond_1
    :goto_0
    :try_start_0
    iget-object v1, v0, Lg1/i3;->f:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast v1, Lu01/h;

    .line 46
    .line 47
    iget-wide v3, v0, Lg1/i3;->e:J

    .line 48
    .line 49
    invoke-interface {v1, v3, v4}, Lu01/h;->x(J)Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object v1

    .line 53
    iget-wide v3, v0, Lg1/i3;->e:J

    .line 54
    .line 55
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 56
    .line 57
    .line 58
    move-result v5

    .line 59
    int-to-long v5, v5

    .line 60
    sub-long/2addr v3, v5

    .line 61
    iput-wide v3, v0, Lg1/i3;->e:J

    .line 62
    .line 63
    invoke-static {v1}, Llp/m1;->b(Ljava/lang/String;)Lbb/g0;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    iget v3, v1, Lbb/g0;->e:I

    .line 68
    .line 69
    new-instance v4, Ld01/s0;

    .line 70
    .line 71
    invoke-direct {v4}, Ld01/s0;-><init>()V

    .line 72
    .line 73
    .line 74
    iget-object v5, v1, Lbb/g0;->f:Ljava/lang/Object;

    .line 75
    .line 76
    check-cast v5, Ld01/i0;

    .line 77
    .line 78
    iput-object v5, v4, Ld01/s0;->b:Ld01/i0;

    .line 79
    .line 80
    iput v3, v4, Ld01/s0;->c:I

    .line 81
    .line 82
    iget-object v1, v1, Lbb/g0;->g:Ljava/lang/Object;

    .line 83
    .line 84
    check-cast v1, Ljava/lang/String;

    .line 85
    .line 86
    iput-object v1, v4, Ld01/s0;->d:Ljava/lang/String;

    .line 87
    .line 88
    new-instance v1, Ld01/x;

    .line 89
    .line 90
    const/4 v5, 0x0

    .line 91
    const/4 v6, 0x0

    .line 92
    invoke-direct {v1, v6, v5}, Ld01/x;-><init>(BI)V

    .line 93
    .line 94
    .line 95
    :goto_1
    iget-object v5, v0, Lg1/i3;->f:Ljava/lang/Object;

    .line 96
    .line 97
    check-cast v5, Lu01/h;

    .line 98
    .line 99
    iget-wide v6, v0, Lg1/i3;->e:J

    .line 100
    .line 101
    invoke-interface {v5, v6, v7}, Lu01/h;->x(J)Ljava/lang/String;

    .line 102
    .line 103
    .line 104
    move-result-object v5

    .line 105
    iget-wide v6, v0, Lg1/i3;->e:J

    .line 106
    .line 107
    invoke-virtual {v5}, Ljava/lang/String;->length()I

    .line 108
    .line 109
    .line 110
    move-result v8

    .line 111
    int-to-long v8, v8

    .line 112
    sub-long/2addr v6, v8

    .line 113
    iput-wide v6, v0, Lg1/i3;->e:J

    .line 114
    .line 115
    invoke-virtual {v5}, Ljava/lang/String;->length()I

    .line 116
    .line 117
    .line 118
    move-result v6

    .line 119
    if-nez v6, :cond_5

    .line 120
    .line 121
    invoke-virtual {v1}, Ld01/x;->j()Ld01/y;

    .line 122
    .line 123
    .line 124
    move-result-object v0

    .line 125
    invoke-virtual {v4, v0}, Ld01/s0;->c(Ld01/y;)V

    .line 126
    .line 127
    .line 128
    const/16 v0, 0x64

    .line 129
    .line 130
    if-eqz p1, :cond_2

    .line 131
    .line 132
    if-ne v3, v0, :cond_2

    .line 133
    .line 134
    const/4 p0, 0x0

    .line 135
    return-object p0

    .line 136
    :cond_2
    if-ne v3, v0, :cond_3

    .line 137
    .line 138
    iput v2, p0, Lj01/f;->d:I

    .line 139
    .line 140
    return-object v4

    .line 141
    :catch_0
    move-exception p1

    .line 142
    goto :goto_2

    .line 143
    :cond_3
    const/16 p1, 0x66

    .line 144
    .line 145
    if-gt p1, v3, :cond_4

    .line 146
    .line 147
    const/16 p1, 0xc8

    .line 148
    .line 149
    if-ge v3, p1, :cond_4

    .line 150
    .line 151
    iput v2, p0, Lj01/f;->d:I

    .line 152
    .line 153
    return-object v4

    .line 154
    :cond_4
    const/4 p1, 0x4

    .line 155
    iput p1, p0, Lj01/f;->d:I

    .line 156
    .line 157
    return-object v4

    .line 158
    :cond_5
    invoke-virtual {v1, v5}, Ld01/x;->e(Ljava/lang/String;)V
    :try_end_0
    .catch Ljava/io/EOFException; {:try_start_0 .. :try_end_0} :catch_0

    .line 159
    .line 160
    .line 161
    goto :goto_1

    .line 162
    :goto_2
    iget-object p0, p0, Lj01/f;->b:Li01/c;

    .line 163
    .line 164
    invoke-interface {p0}, Li01/c;->e()Ld01/w0;

    .line 165
    .line 166
    .line 167
    move-result-object p0

    .line 168
    iget-object p0, p0, Ld01/w0;->a:Ld01/a;

    .line 169
    .line 170
    iget-object p0, p0, Ld01/a;->h:Ld01/a0;

    .line 171
    .line 172
    invoke-virtual {p0}, Ld01/a0;->i()Ljava/lang/String;

    .line 173
    .line 174
    .line 175
    move-result-object p0

    .line 176
    new-instance v0, Ljava/io/IOException;

    .line 177
    .line 178
    const-string v1, "unexpected end of stream on "

    .line 179
    .line 180
    invoke-static {v1, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 181
    .line 182
    .line 183
    move-result-object p0

    .line 184
    invoke-direct {v0, p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 185
    .line 186
    .line 187
    throw v0
.end method

.method public final f()Ld01/y;
    .locals 3

    .line 1
    iget-object v0, p0, Lj01/f;->f:Ld01/y;

    .line 2
    .line 3
    sget-object v1, Lj01/f;->g:Ld01/y;

    .line 4
    .line 5
    if-eq v0, v1, :cond_2

    .line 6
    .line 7
    iget v1, p0, Lj01/f;->d:I

    .line 8
    .line 9
    const/4 v2, 0x5

    .line 10
    if-eq v1, v2, :cond_1

    .line 11
    .line 12
    const/4 v2, 0x6

    .line 13
    if-ne v1, v2, :cond_0

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 17
    .line 18
    const-string v1, "Trailers cannot be read because the state is "

    .line 19
    .line 20
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    iget p0, p0, Lj01/f;->d:I

    .line 24
    .line 25
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 33
    .line 34
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    throw v0

    .line 42
    :cond_1
    :goto_0
    return-object v0

    .line 43
    :cond_2
    new-instance p0, Ljava/io/IOException;

    .line 44
    .line 45
    const-string v0, "Trailers cannot be read because the response body was truncated"

    .line 46
    .line 47
    invoke-direct {p0, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw p0
.end method

.method public final g()V
    .locals 0

    .line 1
    iget-object p0, p0, Lj01/f;->c:Lgw0/c;

    .line 2
    .line 3
    iget-object p0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Lu01/a0;

    .line 6
    .line 7
    invoke-virtual {p0}, Lu01/a0;->flush()V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public final h()Lu01/g0;
    .locals 0

    .line 1
    iget-object p0, p0, Lj01/f;->c:Lgw0/c;

    .line 2
    .line 3
    return-object p0
.end method

.method public final i()Li01/c;
    .locals 0

    .line 1
    iget-object p0, p0, Lj01/f;->b:Li01/c;

    .line 2
    .line 3
    return-object p0
.end method

.method public final j(Ld01/k0;J)Lu01/f0;
    .locals 5

    .line 1
    const-string v0, "request"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p1, Ld01/k0;->d:Ld01/r0;

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    if-eqz v0, :cond_1

    .line 10
    .line 11
    invoke-virtual {v0}, Ld01/r0;->isDuplex()Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eq v0, v1, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    new-instance p0, Ljava/net/ProtocolException;

    .line 19
    .line 20
    const-string p1, "Duplex connections are not supported for HTTP/1"

    .line 21
    .line 22
    invoke-direct {p0, p1}, Ljava/net/ProtocolException;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    throw p0

    .line 26
    :cond_1
    :goto_0
    const-string v0, "Transfer-Encoding"

    .line 27
    .line 28
    iget-object p1, p1, Ld01/k0;->c:Ld01/y;

    .line 29
    .line 30
    invoke-virtual {p1, v0}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    const-string v0, "chunked"

    .line 35
    .line 36
    invoke-virtual {v0, p1}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 37
    .line 38
    .line 39
    move-result p1

    .line 40
    const-string v0, "state: "

    .line 41
    .line 42
    const/4 v2, 0x2

    .line 43
    if-eqz p1, :cond_3

    .line 44
    .line 45
    iget p1, p0, Lj01/f;->d:I

    .line 46
    .line 47
    if-ne p1, v1, :cond_2

    .line 48
    .line 49
    iput v2, p0, Lj01/f;->d:I

    .line 50
    .line 51
    new-instance p1, Lj01/b;

    .line 52
    .line 53
    invoke-direct {p1, p0}, Lj01/b;-><init>(Lj01/f;)V

    .line 54
    .line 55
    .line 56
    return-object p1

    .line 57
    :cond_2
    new-instance p1, Ljava/lang/StringBuilder;

    .line 58
    .line 59
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    iget p0, p0, Lj01/f;->d:I

    .line 63
    .line 64
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 72
    .line 73
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    throw p1

    .line 81
    :cond_3
    const-wide/16 v3, -0x1

    .line 82
    .line 83
    cmp-long p1, p2, v3

    .line 84
    .line 85
    if-eqz p1, :cond_5

    .line 86
    .line 87
    iget p1, p0, Lj01/f;->d:I

    .line 88
    .line 89
    if-ne p1, v1, :cond_4

    .line 90
    .line 91
    iput v2, p0, Lj01/f;->d:I

    .line 92
    .line 93
    new-instance p1, Lcm/e;

    .line 94
    .line 95
    invoke-direct {p1, p0}, Lcm/e;-><init>(Lj01/f;)V

    .line 96
    .line 97
    .line 98
    return-object p1

    .line 99
    :cond_4
    new-instance p1, Ljava/lang/StringBuilder;

    .line 100
    .line 101
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    iget p0, p0, Lj01/f;->d:I

    .line 105
    .line 106
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 107
    .line 108
    .line 109
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 114
    .line 115
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    throw p1

    .line 123
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 124
    .line 125
    const-string p1, "Cannot stream a request body without chunked encoding or a known content length!"

    .line 126
    .line 127
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 128
    .line 129
    .line 130
    throw p0
.end method

.method public final k(Ld01/k0;)V
    .locals 4

    .line 1
    const-string v0, "request"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lj01/f;->b:Li01/c;

    .line 7
    .line 8
    invoke-interface {v0}, Li01/c;->e()Ld01/w0;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iget-object v0, v0, Ld01/w0;->b:Ljava/net/Proxy;

    .line 13
    .line 14
    invoke-virtual {v0}, Ljava/net/Proxy;->type()Ljava/net/Proxy$Type;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    const-string v1, "type(...)"

    .line 19
    .line 20
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    new-instance v1, Ljava/lang/StringBuilder;

    .line 24
    .line 25
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 26
    .line 27
    .line 28
    iget-object v2, p1, Ld01/k0;->b:Ljava/lang/String;

    .line 29
    .line 30
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const/16 v2, 0x20

    .line 34
    .line 35
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object v2, p1, Ld01/k0;->a:Ld01/a0;

    .line 39
    .line 40
    invoke-virtual {v2}, Ld01/a0;->f()Z

    .line 41
    .line 42
    .line 43
    move-result v3

    .line 44
    if-nez v3, :cond_0

    .line 45
    .line 46
    sget-object v3, Ljava/net/Proxy$Type;->HTTP:Ljava/net/Proxy$Type;

    .line 47
    .line 48
    if-ne v0, v3, :cond_0

    .line 49
    .line 50
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_0
    invoke-virtual {v2}, Ld01/a0;->b()Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    invoke-virtual {v2}, Ld01/a0;->d()Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object v2

    .line 62
    if-eqz v2, :cond_1

    .line 63
    .line 64
    new-instance v3, Ljava/lang/StringBuilder;

    .line 65
    .line 66
    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    .line 67
    .line 68
    .line 69
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    const/16 v0, 0x3f

    .line 73
    .line 74
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 78
    .line 79
    .line 80
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object v0

    .line 84
    :cond_1
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    :goto_0
    const-string v0, " HTTP/1.1"

    .line 88
    .line 89
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    iget-object p1, p1, Ld01/k0;->c:Ld01/y;

    .line 97
    .line 98
    invoke-virtual {p0, p1, v0}, Lj01/f;->m(Ld01/y;Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    return-void
.end method

.method public final l(Ld01/a0;J)Lj01/d;
    .locals 2

    .line 1
    iget v0, p0, Lj01/f;->d:I

    .line 2
    .line 3
    const/4 v1, 0x4

    .line 4
    if-ne v0, v1, :cond_0

    .line 5
    .line 6
    const/4 v0, 0x5

    .line 7
    iput v0, p0, Lj01/f;->d:I

    .line 8
    .line 9
    new-instance v0, Lj01/d;

    .line 10
    .line 11
    invoke-direct {v0, p0, p1, p2, p3}, Lj01/d;-><init>(Lj01/f;Ld01/a0;J)V

    .line 12
    .line 13
    .line 14
    return-object v0

    .line 15
    :cond_0
    new-instance p1, Ljava/lang/StringBuilder;

    .line 16
    .line 17
    const-string p2, "state: "

    .line 18
    .line 19
    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    iget p0, p0, Lj01/f;->d:I

    .line 23
    .line 24
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 32
    .line 33
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    throw p1
.end method

.method public final m(Ld01/y;Ljava/lang/String;)V
    .locals 4

    .line 1
    const-string v0, "headers"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "requestLine"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget v0, p0, Lj01/f;->d:I

    .line 12
    .line 13
    if-nez v0, :cond_1

    .line 14
    .line 15
    iget-object v0, p0, Lj01/f;->c:Lgw0/c;

    .line 16
    .line 17
    iget-object v1, v0, Lgw0/c;->g:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v1, Lu01/a0;

    .line 20
    .line 21
    iget-object v0, v0, Lgw0/c;->g:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v0, Lu01/a0;

    .line 24
    .line 25
    invoke-virtual {v1, p2}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 26
    .line 27
    .line 28
    const-string p2, "\r\n"

    .line 29
    .line 30
    invoke-virtual {v1, p2}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 31
    .line 32
    .line 33
    invoke-virtual {p1}, Ld01/y;->size()I

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    const/4 v2, 0x0

    .line 38
    :goto_0
    if-ge v2, v1, :cond_0

    .line 39
    .line 40
    invoke-virtual {p1, v2}, Ld01/y;->e(I)Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object v3

    .line 44
    invoke-virtual {v0, v3}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 45
    .line 46
    .line 47
    const-string v3, ": "

    .line 48
    .line 49
    invoke-virtual {v0, v3}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 50
    .line 51
    .line 52
    invoke-virtual {p1, v2}, Ld01/y;->k(I)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v3

    .line 56
    invoke-interface {v0, v3}, Lu01/g;->z(Ljava/lang/String;)Lu01/g;

    .line 57
    .line 58
    .line 59
    invoke-interface {v0, p2}, Lu01/g;->z(Ljava/lang/String;)Lu01/g;

    .line 60
    .line 61
    .line 62
    add-int/lit8 v2, v2, 0x1

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_0
    invoke-virtual {v0, p2}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 66
    .line 67
    .line 68
    const/4 p1, 0x1

    .line 69
    iput p1, p0, Lj01/f;->d:I

    .line 70
    .line 71
    return-void

    .line 72
    :cond_1
    new-instance p1, Ljava/lang/StringBuilder;

    .line 73
    .line 74
    const-string p2, "state: "

    .line 75
    .line 76
    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    iget p0, p0, Lj01/f;->d:I

    .line 80
    .line 81
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 89
    .line 90
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    throw p1
.end method
