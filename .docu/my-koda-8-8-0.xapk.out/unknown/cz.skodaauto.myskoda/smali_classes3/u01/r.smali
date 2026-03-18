.class public final Lu01/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lu01/h0;


# instance fields
.field public final d:Lu01/b0;

.field public final e:Ljava/util/zip/Inflater;

.field public f:I

.field public g:Z


# direct methods
.method public constructor <init>(Lu01/b0;Ljava/util/zip/Inflater;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lu01/r;->d:Lu01/b0;

    .line 5
    .line 6
    iput-object p2, p0, Lu01/r;->e:Ljava/util/zip/Inflater;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final A(Lu01/f;J)J
    .locals 9

    .line 1
    const-string v0, "sink"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    :goto_0
    iget-object v0, p0, Lu01/r;->e:Ljava/util/zip/Inflater;

    .line 7
    .line 8
    const-string v1, "sink"

    .line 9
    .line 10
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    const-wide/16 v1, 0x0

    .line 14
    .line 15
    cmp-long v3, p2, v1

    .line 16
    .line 17
    if-ltz v3, :cond_b

    .line 18
    .line 19
    iget-boolean v4, p0, Lu01/r;->g:Z

    .line 20
    .line 21
    if-nez v4, :cond_a

    .line 22
    .line 23
    if-nez v3, :cond_0

    .line 24
    .line 25
    goto :goto_3

    .line 26
    :cond_0
    const/4 v3, 0x1

    .line 27
    :try_start_0
    invoke-virtual {p1, v3}, Lu01/f;->W(I)Lu01/c0;

    .line 28
    .line 29
    .line 30
    move-result-object v3

    .line 31
    iget v4, v3, Lu01/c0;->c:I

    .line 32
    .line 33
    rsub-int v4, v4, 0x2000

    .line 34
    .line 35
    int-to-long v4, v4

    .line 36
    invoke-static {p2, p3, v4, v5}, Ljava/lang/Math;->min(JJ)J

    .line 37
    .line 38
    .line 39
    move-result-wide v4

    .line 40
    long-to-int v4, v4

    .line 41
    invoke-virtual {v0}, Ljava/util/zip/Inflater;->needsInput()Z

    .line 42
    .line 43
    .line 44
    move-result v5
    :try_end_0
    .catch Ljava/util/zip/DataFormatException; {:try_start_0 .. :try_end_0} :catch_0

    .line 45
    iget-object v6, p0, Lu01/r;->d:Lu01/b0;

    .line 46
    .line 47
    if-nez v5, :cond_1

    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_1
    :try_start_1
    invoke-virtual {v6}, Lu01/b0;->Z()Z

    .line 51
    .line 52
    .line 53
    move-result v5

    .line 54
    if-eqz v5, :cond_2

    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_2
    iget-object v5, v6, Lu01/b0;->e:Lu01/f;

    .line 58
    .line 59
    iget-object v5, v5, Lu01/f;->d:Lu01/c0;

    .line 60
    .line 61
    invoke-static {v5}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    iget v7, v5, Lu01/c0;->c:I

    .line 65
    .line 66
    iget v8, v5, Lu01/c0;->b:I

    .line 67
    .line 68
    sub-int/2addr v7, v8

    .line 69
    iput v7, p0, Lu01/r;->f:I

    .line 70
    .line 71
    iget-object v5, v5, Lu01/c0;->a:[B

    .line 72
    .line 73
    invoke-virtual {v0, v5, v8, v7}, Ljava/util/zip/Inflater;->setInput([BII)V

    .line 74
    .line 75
    .line 76
    :goto_1
    iget-object v5, v3, Lu01/c0;->a:[B

    .line 77
    .line 78
    iget v7, v3, Lu01/c0;->c:I

    .line 79
    .line 80
    invoke-virtual {v0, v5, v7, v4}, Ljava/util/zip/Inflater;->inflate([BII)I

    .line 81
    .line 82
    .line 83
    move-result v4

    .line 84
    iget v5, p0, Lu01/r;->f:I

    .line 85
    .line 86
    if-nez v5, :cond_3

    .line 87
    .line 88
    goto :goto_2

    .line 89
    :cond_3
    invoke-virtual {v0}, Ljava/util/zip/Inflater;->getRemaining()I

    .line 90
    .line 91
    .line 92
    move-result v0

    .line 93
    sub-int/2addr v5, v0

    .line 94
    iget v0, p0, Lu01/r;->f:I

    .line 95
    .line 96
    sub-int/2addr v0, v5

    .line 97
    iput v0, p0, Lu01/r;->f:I

    .line 98
    .line 99
    int-to-long v7, v5

    .line 100
    invoke-virtual {v6, v7, v8}, Lu01/b0;->skip(J)V

    .line 101
    .line 102
    .line 103
    :goto_2
    if-lez v4, :cond_4

    .line 104
    .line 105
    iget v0, v3, Lu01/c0;->c:I

    .line 106
    .line 107
    add-int/2addr v0, v4

    .line 108
    iput v0, v3, Lu01/c0;->c:I

    .line 109
    .line 110
    iget-wide v0, p1, Lu01/f;->e:J

    .line 111
    .line 112
    int-to-long v2, v4

    .line 113
    add-long/2addr v0, v2

    .line 114
    iput-wide v0, p1, Lu01/f;->e:J

    .line 115
    .line 116
    move-wide v1, v2

    .line 117
    goto :goto_3

    .line 118
    :cond_4
    iget v0, v3, Lu01/c0;->b:I

    .line 119
    .line 120
    iget v4, v3, Lu01/c0;->c:I

    .line 121
    .line 122
    if-ne v0, v4, :cond_5

    .line 123
    .line 124
    invoke-virtual {v3}, Lu01/c0;->a()Lu01/c0;

    .line 125
    .line 126
    .line 127
    move-result-object v0

    .line 128
    iput-object v0, p1, Lu01/f;->d:Lu01/c0;

    .line 129
    .line 130
    invoke-static {v3}, Lu01/d0;->a(Lu01/c0;)V
    :try_end_1
    .catch Ljava/util/zip/DataFormatException; {:try_start_1 .. :try_end_1} :catch_0

    .line 131
    .line 132
    .line 133
    :cond_5
    :goto_3
    const-wide/16 v3, 0x0

    .line 134
    .line 135
    cmp-long v0, v1, v3

    .line 136
    .line 137
    if-lez v0, :cond_6

    .line 138
    .line 139
    return-wide v1

    .line 140
    :cond_6
    iget-object v0, p0, Lu01/r;->e:Ljava/util/zip/Inflater;

    .line 141
    .line 142
    invoke-virtual {v0}, Ljava/util/zip/Inflater;->finished()Z

    .line 143
    .line 144
    .line 145
    move-result v1

    .line 146
    if-nez v1, :cond_9

    .line 147
    .line 148
    invoke-virtual {v0}, Ljava/util/zip/Inflater;->needsDictionary()Z

    .line 149
    .line 150
    .line 151
    move-result v0

    .line 152
    if-eqz v0, :cond_7

    .line 153
    .line 154
    goto :goto_4

    .line 155
    :cond_7
    iget-object v0, p0, Lu01/r;->d:Lu01/b0;

    .line 156
    .line 157
    invoke-virtual {v0}, Lu01/b0;->Z()Z

    .line 158
    .line 159
    .line 160
    move-result v0

    .line 161
    if-nez v0, :cond_8

    .line 162
    .line 163
    goto/16 :goto_0

    .line 164
    .line 165
    :cond_8
    new-instance p0, Ljava/io/EOFException;

    .line 166
    .line 167
    const-string p1, "source exhausted prematurely"

    .line 168
    .line 169
    invoke-direct {p0, p1}, Ljava/io/EOFException;-><init>(Ljava/lang/String;)V

    .line 170
    .line 171
    .line 172
    throw p0

    .line 173
    :cond_9
    :goto_4
    const-wide/16 p0, -0x1

    .line 174
    .line 175
    return-wide p0

    .line 176
    :catch_0
    move-exception p0

    .line 177
    new-instance p1, Ljava/io/IOException;

    .line 178
    .line 179
    invoke-direct {p1, p0}, Ljava/io/IOException;-><init>(Ljava/lang/Throwable;)V

    .line 180
    .line 181
    .line 182
    throw p1

    .line 183
    :cond_a
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 184
    .line 185
    const-string p1, "closed"

    .line 186
    .line 187
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 188
    .line 189
    .line 190
    throw p0

    .line 191
    :cond_b
    const-string p0, "byteCount < 0: "

    .line 192
    .line 193
    invoke-static {p2, p3, p0}, Lp3/m;->f(JLjava/lang/String;)Ljava/lang/String;

    .line 194
    .line 195
    .line 196
    move-result-object p0

    .line 197
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 198
    .line 199
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 200
    .line 201
    .line 202
    move-result-object p0

    .line 203
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 204
    .line 205
    .line 206
    throw p1
.end method

.method public final close()V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lu01/r;->g:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    iget-object v0, p0, Lu01/r;->e:Ljava/util/zip/Inflater;

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/util/zip/Inflater;->end()V

    .line 9
    .line 10
    .line 11
    const/4 v0, 0x1

    .line 12
    iput-boolean v0, p0, Lu01/r;->g:Z

    .line 13
    .line 14
    iget-object p0, p0, Lu01/r;->d:Lu01/b0;

    .line 15
    .line 16
    invoke-virtual {p0}, Lu01/b0;->close()V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public final timeout()Lu01/j0;
    .locals 0

    .line 1
    iget-object p0, p0, Lu01/r;->d:Lu01/b0;

    .line 2
    .line 3
    iget-object p0, p0, Lu01/b0;->d:Lu01/h0;

    .line 4
    .line 5
    invoke-interface {p0}, Lu01/h0;->timeout()Lu01/j0;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
