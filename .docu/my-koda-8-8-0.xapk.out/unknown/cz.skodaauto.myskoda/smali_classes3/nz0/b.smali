.class public final Lnz0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lnz0/d;


# instance fields
.field public final d:Ljava/io/InputStream;


# direct methods
.method public constructor <init>(Ljava/io/InputStream;)V
    .locals 1

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lnz0/b;->d:Ljava/io/InputStream;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final I(Lnz0/a;J)J
    .locals 8

    .line 1
    const-string v0, "Invalid number of bytes written: "

    .line 2
    .line 3
    const-wide/16 v1, 0x0

    .line 4
    .line 5
    cmp-long v3, p2, v1

    .line 6
    .line 7
    if-nez v3, :cond_0

    .line 8
    .line 9
    return-wide v1

    .line 10
    :cond_0
    if-ltz v3, :cond_9

    .line 11
    .line 12
    const/4 v1, 0x0

    .line 13
    const/4 v2, 0x1

    .line 14
    :try_start_0
    invoke-virtual {p1, v2}, Lnz0/a;->j(I)Lnz0/g;

    .line 15
    .line 16
    .line 17
    move-result-object v3

    .line 18
    iget-object v4, v3, Lnz0/g;->a:[B

    .line 19
    .line 20
    iget v5, v3, Lnz0/g;->c:I

    .line 21
    .line 22
    array-length v6, v4

    .line 23
    sub-int/2addr v6, v5

    .line 24
    int-to-long v6, v6

    .line 25
    invoke-static {p2, p3, v6, v7}, Ljava/lang/Math;->min(JJ)J

    .line 26
    .line 27
    .line 28
    move-result-wide p2

    .line 29
    long-to-int p2, p2

    .line 30
    iget-object p0, p0, Lnz0/b;->d:Ljava/io/InputStream;

    .line 31
    .line 32
    invoke-virtual {p0, v4, v5, p2}, Ljava/io/InputStream;->read([BII)I

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    int-to-long p2, p0

    .line 37
    const-wide/16 v4, -0x1

    .line 38
    .line 39
    cmp-long p0, p2, v4

    .line 40
    .line 41
    if-nez p0, :cond_1

    .line 42
    .line 43
    move p0, v1

    .line 44
    goto :goto_0

    .line 45
    :cond_1
    long-to-int p0, p2

    .line 46
    :goto_0
    if-ne p0, v2, :cond_2

    .line 47
    .line 48
    iget v0, v3, Lnz0/g;->c:I

    .line 49
    .line 50
    add-int/2addr v0, p0

    .line 51
    iput v0, v3, Lnz0/g;->c:I

    .line 52
    .line 53
    iget-wide v3, p1, Lnz0/a;->f:J

    .line 54
    .line 55
    int-to-long v5, p0

    .line 56
    add-long/2addr v3, v5

    .line 57
    iput-wide v3, p1, Lnz0/a;->f:J

    .line 58
    .line 59
    return-wide p2

    .line 60
    :catch_0
    move-exception p0

    .line 61
    goto :goto_1

    .line 62
    :cond_2
    if-ltz p0, :cond_5

    .line 63
    .line 64
    invoke-virtual {v3}, Lnz0/g;->a()I

    .line 65
    .line 66
    .line 67
    move-result v4

    .line 68
    if-gt p0, v4, :cond_5

    .line 69
    .line 70
    if-eqz p0, :cond_3

    .line 71
    .line 72
    iget v0, v3, Lnz0/g;->c:I

    .line 73
    .line 74
    add-int/2addr v0, p0

    .line 75
    iput v0, v3, Lnz0/g;->c:I

    .line 76
    .line 77
    iget-wide v3, p1, Lnz0/a;->f:J

    .line 78
    .line 79
    int-to-long v5, p0

    .line 80
    add-long/2addr v3, v5

    .line 81
    iput-wide v3, p1, Lnz0/a;->f:J

    .line 82
    .line 83
    return-wide p2

    .line 84
    :cond_3
    invoke-static {v3}, Lnz0/j;->d(Lnz0/g;)Z

    .line 85
    .line 86
    .line 87
    move-result p0

    .line 88
    if-eqz p0, :cond_4

    .line 89
    .line 90
    invoke-virtual {p1}, Lnz0/a;->f()V

    .line 91
    .line 92
    .line 93
    :cond_4
    return-wide p2

    .line 94
    :cond_5
    new-instance p1, Ljava/lang/StringBuilder;

    .line 95
    .line 96
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    const-string p0, ". Should be in 0.."

    .line 103
    .line 104
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 105
    .line 106
    .line 107
    invoke-virtual {v3}, Lnz0/g;->a()I

    .line 108
    .line 109
    .line 110
    move-result p0

    .line 111
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 112
    .line 113
    .line 114
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 119
    .line 120
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 121
    .line 122
    .line 123
    move-result-object p0

    .line 124
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 125
    .line 126
    .line 127
    throw p1
    :try_end_0
    .catch Ljava/lang/AssertionError; {:try_start_0 .. :try_end_0} :catch_0

    .line 128
    :goto_1
    invoke-virtual {p0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 129
    .line 130
    .line 131
    move-result-object p1

    .line 132
    if-eqz p1, :cond_7

    .line 133
    .line 134
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 135
    .line 136
    .line 137
    move-result-object p1

    .line 138
    if-eqz p1, :cond_6

    .line 139
    .line 140
    const-string p2, "getsockname failed"

    .line 141
    .line 142
    invoke-static {p1, p2, v1}, Lly0/p;->A(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Z)Z

    .line 143
    .line 144
    .line 145
    move-result p1

    .line 146
    goto :goto_2

    .line 147
    :cond_6
    move p1, v1

    .line 148
    :goto_2
    if-eqz p1, :cond_7

    .line 149
    .line 150
    move v1, v2

    .line 151
    :cond_7
    if-eqz v1, :cond_8

    .line 152
    .line 153
    new-instance p1, Ljava/io/IOException;

    .line 154
    .line 155
    invoke-direct {p1, p0}, Ljava/io/IOException;-><init>(Ljava/lang/Throwable;)V

    .line 156
    .line 157
    .line 158
    throw p1

    .line 159
    :cond_8
    throw p0

    .line 160
    :cond_9
    const-string p0, "byteCount ("

    .line 161
    .line 162
    const-string p1, ") < 0"

    .line 163
    .line 164
    invoke-static {p2, p3, p0, p1}, Lp3/m;->g(JLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 165
    .line 166
    .line 167
    move-result-object p0

    .line 168
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 169
    .line 170
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 171
    .line 172
    .line 173
    move-result-object p0

    .line 174
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 175
    .line 176
    .line 177
    throw p1
.end method

.method public final close()V
    .locals 0

    .line 1
    iget-object p0, p0, Lnz0/b;->d:Ljava/io/InputStream;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/io/InputStream;->close()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "RawSource("

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lnz0/b;->d:Ljava/io/InputStream;

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const/16 p0, 0x29

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method
