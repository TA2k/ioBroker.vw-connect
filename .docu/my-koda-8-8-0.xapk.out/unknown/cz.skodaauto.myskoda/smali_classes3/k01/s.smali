.class public final Lk01/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lu01/h0;


# instance fields
.field public final d:Lu01/h;

.field public e:I

.field public f:I

.field public g:I

.field public h:I

.field public i:I


# direct methods
.method public constructor <init>(Lu01/h;)V
    .locals 1

    .line 1
    const-string v0, "source"

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
    iput-object p1, p0, Lk01/s;->d:Lu01/h;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final A(Lu01/f;J)J
    .locals 8

    .line 1
    const-string v0, "sink"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    :goto_0
    iget v0, p0, Lk01/s;->h:I

    .line 7
    .line 8
    const-wide/16 v1, -0x1

    .line 9
    .line 10
    iget-object v3, p0, Lk01/s;->d:Lu01/h;

    .line 11
    .line 12
    if-nez v0, :cond_4

    .line 13
    .line 14
    iget v0, p0, Lk01/s;->i:I

    .line 15
    .line 16
    int-to-long v4, v0

    .line 17
    invoke-interface {v3, v4, v5}, Lu01/h;->skip(J)V

    .line 18
    .line 19
    .line 20
    const/4 v0, 0x0

    .line 21
    iput v0, p0, Lk01/s;->i:I

    .line 22
    .line 23
    iget v0, p0, Lk01/s;->f:I

    .line 24
    .line 25
    and-int/lit8 v0, v0, 0x4

    .line 26
    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    goto :goto_1

    .line 30
    :cond_0
    iget v0, p0, Lk01/s;->g:I

    .line 31
    .line 32
    invoke-static {v3}, Le01/e;->o(Lu01/h;)I

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    iput v1, p0, Lk01/s;->h:I

    .line 37
    .line 38
    iput v1, p0, Lk01/s;->e:I

    .line 39
    .line 40
    invoke-interface {v3}, Lu01/h;->readByte()B

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    and-int/lit16 v1, v1, 0xff

    .line 45
    .line 46
    invoke-interface {v3}, Lu01/h;->readByte()B

    .line 47
    .line 48
    .line 49
    move-result v2

    .line 50
    and-int/lit16 v2, v2, 0xff

    .line 51
    .line 52
    iput v2, p0, Lk01/s;->f:I

    .line 53
    .line 54
    sget-object v2, Lk01/t;->g:Ljava/util/logging/Logger;

    .line 55
    .line 56
    sget-object v4, Ljava/util/logging/Level;->FINE:Ljava/util/logging/Level;

    .line 57
    .line 58
    invoke-virtual {v2, v4}, Ljava/util/logging/Logger;->isLoggable(Ljava/util/logging/Level;)Z

    .line 59
    .line 60
    .line 61
    move-result v4

    .line 62
    if-eqz v4, :cond_1

    .line 63
    .line 64
    sget-object v4, Lk01/h;->a:Lu01/i;

    .line 65
    .line 66
    iget v4, p0, Lk01/s;->g:I

    .line 67
    .line 68
    iget v5, p0, Lk01/s;->e:I

    .line 69
    .line 70
    iget v6, p0, Lk01/s;->f:I

    .line 71
    .line 72
    const/4 v7, 0x1

    .line 73
    invoke-static {v4, v5, v1, v6, v7}, Lk01/h;->b(IIIIZ)Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object v4

    .line 77
    invoke-virtual {v2, v4}, Ljava/util/logging/Logger;->fine(Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    :cond_1
    invoke-interface {v3}, Lu01/h;->readInt()I

    .line 81
    .line 82
    .line 83
    move-result v2

    .line 84
    const v3, 0x7fffffff

    .line 85
    .line 86
    .line 87
    and-int/2addr v2, v3

    .line 88
    iput v2, p0, Lk01/s;->g:I

    .line 89
    .line 90
    const/16 v3, 0x9

    .line 91
    .line 92
    if-ne v1, v3, :cond_3

    .line 93
    .line 94
    if-ne v2, v0, :cond_2

    .line 95
    .line 96
    goto :goto_0

    .line 97
    :cond_2
    new-instance p0, Ljava/io/IOException;

    .line 98
    .line 99
    const-string p1, "TYPE_CONTINUATION streamId changed"

    .line 100
    .line 101
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    throw p0

    .line 105
    :cond_3
    new-instance p0, Ljava/io/IOException;

    .line 106
    .line 107
    const-string p1, " != TYPE_CONTINUATION"

    .line 108
    .line 109
    invoke-static {v1, p1}, Lp3/m;->e(ILjava/lang/String;)Ljava/lang/String;

    .line 110
    .line 111
    .line 112
    move-result-object p1

    .line 113
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 114
    .line 115
    .line 116
    throw p0

    .line 117
    :cond_4
    int-to-long v4, v0

    .line 118
    invoke-static {p2, p3, v4, v5}, Ljava/lang/Math;->min(JJ)J

    .line 119
    .line 120
    .line 121
    move-result-wide p2

    .line 122
    invoke-interface {v3, p1, p2, p3}, Lu01/h0;->A(Lu01/f;J)J

    .line 123
    .line 124
    .line 125
    move-result-wide p1

    .line 126
    cmp-long p3, p1, v1

    .line 127
    .line 128
    if-nez p3, :cond_5

    .line 129
    .line 130
    :goto_1
    return-wide v1

    .line 131
    :cond_5
    iget p3, p0, Lk01/s;->h:I

    .line 132
    .line 133
    long-to-int v0, p1

    .line 134
    sub-int/2addr p3, v0

    .line 135
    iput p3, p0, Lk01/s;->h:I

    .line 136
    .line 137
    return-wide p1
.end method

.method public final close()V
    .locals 0

    .line 1
    return-void
.end method

.method public final timeout()Lu01/j0;
    .locals 0

    .line 1
    iget-object p0, p0, Lk01/s;->d:Lu01/h;

    .line 2
    .line 3
    invoke-interface {p0}, Lu01/h0;->timeout()Lu01/j0;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
