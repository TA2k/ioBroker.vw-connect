.class public abstract Lqw0/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic a:I


# direct methods
.method static constructor <clinit>()V
    .locals 11

    .line 1
    sget-object v0, Low0/s;->f:Ljava/util/List;

    .line 2
    .line 3
    new-instance v1, Lqe/b;

    .line 4
    .line 5
    const/16 v2, 0x16

    .line 6
    .line 7
    invoke-direct {v1, v2}, Lqe/b;-><init>(I)V

    .line 8
    .line 9
    .line 10
    new-instance v2, Lpd0/a;

    .line 11
    .line 12
    const/16 v3, 0x1a

    .line 13
    .line 14
    invoke-direct {v2, v3}, Lpd0/a;-><init>(I)V

    .line 15
    .line 16
    .line 17
    invoke-static {v0, v1, v2}, Ljp/gg;->a(Ljava/util/List;Lay0/k;Lay0/n;)Lnm0/b;

    .line 18
    .line 19
    .line 20
    new-instance v0, Lgy0/j;

    .line 21
    .line 22
    const/4 v1, 0x0

    .line 23
    const/16 v2, 0xff

    .line 24
    .line 25
    const/4 v3, 0x1

    .line 26
    invoke-direct {v0, v1, v2, v3}, Lgy0/h;-><init>(III)V

    .line 27
    .line 28
    .line 29
    new-instance v2, Ljava/util/ArrayList;

    .line 30
    .line 31
    const/16 v4, 0xa

    .line 32
    .line 33
    invoke-static {v0, v4}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 34
    .line 35
    .line 36
    move-result v5

    .line 37
    invoke-direct {v2, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {v0}, Lgy0/h;->iterator()Ljava/util/Iterator;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    :goto_0
    move-object v5, v0

    .line 45
    check-cast v5, Lgy0/i;

    .line 46
    .line 47
    iget-boolean v5, v5, Lgy0/i;->f:Z

    .line 48
    .line 49
    if-eqz v5, :cond_3

    .line 50
    .line 51
    move-object v5, v0

    .line 52
    check-cast v5, Lmx0/w;

    .line 53
    .line 54
    invoke-virtual {v5}, Lmx0/w;->nextInt()I

    .line 55
    .line 56
    .line 57
    move-result v5

    .line 58
    const/16 v6, 0x30

    .line 59
    .line 60
    if-gt v6, v5, :cond_0

    .line 61
    .line 62
    const/16 v6, 0x3a

    .line 63
    .line 64
    if-ge v5, v6, :cond_0

    .line 65
    .line 66
    int-to-long v5, v5

    .line 67
    const-wide/16 v7, 0x30

    .line 68
    .line 69
    sub-long/2addr v5, v7

    .line 70
    goto :goto_2

    .line 71
    :cond_0
    int-to-long v5, v5

    .line 72
    const-wide/16 v7, 0x61

    .line 73
    .line 74
    cmp-long v9, v5, v7

    .line 75
    .line 76
    if-ltz v9, :cond_1

    .line 77
    .line 78
    const-wide/16 v9, 0x66

    .line 79
    .line 80
    cmp-long v9, v5, v9

    .line 81
    .line 82
    if-gtz v9, :cond_1

    .line 83
    .line 84
    :goto_1
    sub-long/2addr v5, v7

    .line 85
    int-to-long v7, v4

    .line 86
    add-long/2addr v5, v7

    .line 87
    goto :goto_2

    .line 88
    :cond_1
    const-wide/16 v7, 0x41

    .line 89
    .line 90
    cmp-long v9, v5, v7

    .line 91
    .line 92
    if-ltz v9, :cond_2

    .line 93
    .line 94
    const-wide/16 v9, 0x46

    .line 95
    .line 96
    cmp-long v9, v5, v9

    .line 97
    .line 98
    if-gtz v9, :cond_2

    .line 99
    .line 100
    goto :goto_1

    .line 101
    :cond_2
    const-wide/16 v5, -0x1

    .line 102
    .line 103
    :goto_2
    invoke-static {v5, v6}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 104
    .line 105
    .line 106
    move-result-object v5

    .line 107
    invoke-virtual {v2, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 108
    .line 109
    .line 110
    goto :goto_0

    .line 111
    :cond_3
    invoke-static {v2}, Lmx0/q;->y0(Ljava/util/Collection;)[J

    .line 112
    .line 113
    .line 114
    new-instance v0, Lgy0/j;

    .line 115
    .line 116
    const/16 v2, 0xf

    .line 117
    .line 118
    invoke-direct {v0, v1, v2, v3}, Lgy0/h;-><init>(III)V

    .line 119
    .line 120
    .line 121
    new-instance v1, Ljava/util/ArrayList;

    .line 122
    .line 123
    invoke-static {v0, v4}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 124
    .line 125
    .line 126
    move-result v2

    .line 127
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 128
    .line 129
    .line 130
    invoke-virtual {v0}, Lgy0/h;->iterator()Ljava/util/Iterator;

    .line 131
    .line 132
    .line 133
    move-result-object v0

    .line 134
    :goto_3
    move-object v2, v0

    .line 135
    check-cast v2, Lgy0/i;

    .line 136
    .line 137
    iget-boolean v2, v2, Lgy0/i;->f:Z

    .line 138
    .line 139
    if-eqz v2, :cond_5

    .line 140
    .line 141
    move-object v2, v0

    .line 142
    check-cast v2, Lmx0/w;

    .line 143
    .line 144
    invoke-virtual {v2}, Lmx0/w;->nextInt()I

    .line 145
    .line 146
    .line 147
    move-result v2

    .line 148
    if-ge v2, v4, :cond_4

    .line 149
    .line 150
    add-int/lit8 v2, v2, 0x30

    .line 151
    .line 152
    :goto_4
    int-to-byte v2, v2

    .line 153
    goto :goto_5

    .line 154
    :cond_4
    add-int/lit8 v2, v2, 0x61

    .line 155
    .line 156
    int-to-char v2, v2

    .line 157
    sub-int/2addr v2, v4

    .line 158
    int-to-char v2, v2

    .line 159
    goto :goto_4

    .line 160
    :goto_5
    invoke-static {v2}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 161
    .line 162
    .line 163
    move-result-object v2

    .line 164
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 165
    .line 166
    .line 167
    goto :goto_3

    .line 168
    :cond_5
    invoke-static {v1}, Lmx0/q;->t0(Ljava/util/Collection;)[B

    .line 169
    .line 170
    .line 171
    return-void
.end method

.method public static final a(Ljava/lang/CharSequence;II)I
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    :goto_0
    if-ge p1, p2, :cond_1

    .line 8
    .line 9
    invoke-interface {p0, p1}, Ljava/lang/CharSequence;->charAt(I)C

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    const/16 v2, 0x41

    .line 14
    .line 15
    if-gt v2, v1, :cond_0

    .line 16
    .line 17
    const/16 v2, 0x5b

    .line 18
    .line 19
    if-ge v1, v2, :cond_0

    .line 20
    .line 21
    add-int/lit8 v1, v1, 0x20

    .line 22
    .line 23
    :cond_0
    mul-int/lit8 v0, v0, 0x1f

    .line 24
    .line 25
    add-int/2addr v0, v1

    .line 26
    add-int/lit8 p1, p1, 0x1

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_1
    return v0
.end method

.method public static final b(Lqw0/b;I)V
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/NumberFormatException;

    .line 2
    .line 3
    new-instance v1, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v2, "Invalid number: "

    .line 6
    .line 7
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v2, ", wrong digit: "

    .line 14
    .line 15
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lqw0/b;->charAt(I)C

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const-string p0, " at position "

    .line 26
    .line 27
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    invoke-direct {v0, p0}, Ljava/lang/NumberFormatException;-><init>(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    throw v0
.end method
