.class public final Lcom/google/gson/r;
.super Lcom/google/gson/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Ljava/io/Serializable;


# direct methods
.method public constructor <init>(Ljava/lang/Boolean;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    iput-object p1, p0, Lcom/google/gson/r;->d:Ljava/io/Serializable;

    return-void
.end method

.method public constructor <init>(Ljava/lang/Number;)V
    .locals 0

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    iput-object p1, p0, Lcom/google/gson/r;->d:Ljava/io/Serializable;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;)V
    .locals 0

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    iput-object p1, p0, Lcom/google/gson/r;->d:Ljava/io/Serializable;

    return-void
.end method

.method public static k(Lcom/google/gson/r;)Z
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/google/gson/r;->d:Ljava/io/Serializable;

    .line 2
    .line 3
    instance-of v0, p0, Ljava/lang/Number;

    .line 4
    .line 5
    if-eqz v0, :cond_1

    .line 6
    .line 7
    check-cast p0, Ljava/lang/Number;

    .line 8
    .line 9
    instance-of v0, p0, Ljava/math/BigInteger;

    .line 10
    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    instance-of v0, p0, Ljava/lang/Long;

    .line 14
    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    instance-of v0, p0, Ljava/lang/Integer;

    .line 18
    .line 19
    if-nez v0, :cond_0

    .line 20
    .line 21
    instance-of v0, p0, Ljava/lang/Short;

    .line 22
    .line 23
    if-nez v0, :cond_0

    .line 24
    .line 25
    instance-of p0, p0, Ljava/lang/Byte;

    .line 26
    .line 27
    if-eqz p0, :cond_1

    .line 28
    .line 29
    :cond_0
    const/4 p0, 0x1

    .line 30
    return p0

    .line 31
    :cond_1
    const/4 p0, 0x0

    .line 32
    return p0
.end method


# virtual methods
.method public final c()J
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/google/gson/r;->d:Ljava/io/Serializable;

    .line 2
    .line 3
    instance-of v0, v0, Ljava/lang/Number;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Lcom/google/gson/r;->i()Ljava/lang/Number;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-virtual {p0}, Ljava/lang/Number;->longValue()J

    .line 12
    .line 13
    .line 14
    move-result-wide v0

    .line 15
    return-wide v0

    .line 16
    :cond_0
    invoke-virtual {p0}, Lcom/google/gson/r;->e()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    invoke-static {p0}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    .line 21
    .line 22
    .line 23
    move-result-wide v0

    .line 24
    return-wide v0
.end method

.method public final e()Ljava/lang/String;
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/google/gson/r;->d:Ljava/io/Serializable;

    .line 2
    .line 3
    instance-of v1, v0, Ljava/lang/String;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    check-cast v0, Ljava/lang/String;

    .line 8
    .line 9
    return-object v0

    .line 10
    :cond_0
    instance-of v1, v0, Ljava/lang/Number;

    .line 11
    .line 12
    if-eqz v1, :cond_1

    .line 13
    .line 14
    invoke-virtual {p0}, Lcom/google/gson/r;->i()Ljava/lang/Number;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :cond_1
    instance-of p0, v0, Ljava/lang/Boolean;

    .line 24
    .line 25
    if-eqz p0, :cond_2

    .line 26
    .line 27
    check-cast v0, Ljava/lang/Boolean;

    .line 28
    .line 29
    invoke-virtual {v0}, Ljava/lang/Boolean;->toString()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0

    .line 34
    :cond_2
    new-instance p0, Ljava/lang/AssertionError;

    .line 35
    .line 36
    new-instance v1, Ljava/lang/StringBuilder;

    .line 37
    .line 38
    const-string v2, "Unexpected value type: "

    .line 39
    .line 40
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    invoke-direct {p0, v0}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    throw p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto/16 :goto_5

    .line 4
    .line 5
    :cond_0
    if-eqz p1, :cond_d

    .line 6
    .line 7
    const-class v0, Lcom/google/gson/r;

    .line 8
    .line 9
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    if-eq v0, v1, :cond_1

    .line 14
    .line 15
    goto/16 :goto_6

    .line 16
    .line 17
    :cond_1
    check-cast p1, Lcom/google/gson/r;

    .line 18
    .line 19
    iget-object v0, p1, Lcom/google/gson/r;->d:Ljava/io/Serializable;

    .line 20
    .line 21
    iget-object v1, p0, Lcom/google/gson/r;->d:Ljava/io/Serializable;

    .line 22
    .line 23
    if-nez v1, :cond_2

    .line 24
    .line 25
    if-nez v0, :cond_d

    .line 26
    .line 27
    goto/16 :goto_5

    .line 28
    .line 29
    :cond_2
    invoke-static {p0}, Lcom/google/gson/r;->k(Lcom/google/gson/r;)Z

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    if-eqz v2, :cond_5

    .line 34
    .line 35
    invoke-static {p1}, Lcom/google/gson/r;->k(Lcom/google/gson/r;)Z

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    if-eqz v2, :cond_5

    .line 40
    .line 41
    instance-of v1, v1, Ljava/math/BigInteger;

    .line 42
    .line 43
    if-nez v1, :cond_4

    .line 44
    .line 45
    instance-of v0, v0, Ljava/math/BigInteger;

    .line 46
    .line 47
    if-eqz v0, :cond_3

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_3
    invoke-virtual {p0}, Lcom/google/gson/r;->i()Ljava/lang/Number;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    invoke-virtual {p0}, Ljava/lang/Number;->longValue()J

    .line 55
    .line 56
    .line 57
    move-result-wide v0

    .line 58
    invoke-virtual {p1}, Lcom/google/gson/r;->i()Ljava/lang/Number;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    invoke-virtual {p0}, Ljava/lang/Number;->longValue()J

    .line 63
    .line 64
    .line 65
    move-result-wide p0

    .line 66
    cmp-long p0, v0, p0

    .line 67
    .line 68
    if-nez p0, :cond_d

    .line 69
    .line 70
    goto/16 :goto_5

    .line 71
    .line 72
    :cond_4
    :goto_0
    invoke-virtual {p0}, Lcom/google/gson/r;->g()Ljava/math/BigInteger;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    invoke-virtual {p1}, Lcom/google/gson/r;->g()Ljava/math/BigInteger;

    .line 77
    .line 78
    .line 79
    move-result-object p1

    .line 80
    invoke-virtual {p0, p1}, Ljava/math/BigInteger;->equals(Ljava/lang/Object;)Z

    .line 81
    .line 82
    .line 83
    move-result p0

    .line 84
    return p0

    .line 85
    :cond_5
    instance-of v2, v1, Ljava/lang/Number;

    .line 86
    .line 87
    if-eqz v2, :cond_c

    .line 88
    .line 89
    instance-of v2, v0, Ljava/lang/Number;

    .line 90
    .line 91
    if-eqz v2, :cond_c

    .line 92
    .line 93
    instance-of v2, v1, Ljava/math/BigDecimal;

    .line 94
    .line 95
    if-eqz v2, :cond_8

    .line 96
    .line 97
    instance-of v2, v0, Ljava/math/BigDecimal;

    .line 98
    .line 99
    if-eqz v2, :cond_8

    .line 100
    .line 101
    instance-of v2, v1, Ljava/math/BigDecimal;

    .line 102
    .line 103
    if-eqz v2, :cond_6

    .line 104
    .line 105
    check-cast v1, Ljava/math/BigDecimal;

    .line 106
    .line 107
    goto :goto_1

    .line 108
    :cond_6
    invoke-virtual {p0}, Lcom/google/gson/r;->e()Ljava/lang/String;

    .line 109
    .line 110
    .line 111
    move-result-object p0

    .line 112
    invoke-static {p0}, Lcom/google/gson/internal/f;->i(Ljava/lang/String;)Ljava/math/BigDecimal;

    .line 113
    .line 114
    .line 115
    move-result-object v1

    .line 116
    :goto_1
    instance-of p0, v0, Ljava/math/BigDecimal;

    .line 117
    .line 118
    if-eqz p0, :cond_7

    .line 119
    .line 120
    check-cast v0, Ljava/math/BigDecimal;

    .line 121
    .line 122
    goto :goto_2

    .line 123
    :cond_7
    invoke-virtual {p1}, Lcom/google/gson/r;->e()Ljava/lang/String;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    invoke-static {p0}, Lcom/google/gson/internal/f;->i(Ljava/lang/String;)Ljava/math/BigDecimal;

    .line 128
    .line 129
    .line 130
    move-result-object v0

    .line 131
    :goto_2
    invoke-virtual {v1, v0}, Ljava/math/BigDecimal;->compareTo(Ljava/math/BigDecimal;)I

    .line 132
    .line 133
    .line 134
    move-result p0

    .line 135
    if-nez p0, :cond_d

    .line 136
    .line 137
    goto :goto_5

    .line 138
    :cond_8
    instance-of v1, v1, Ljava/lang/Number;

    .line 139
    .line 140
    if-eqz v1, :cond_9

    .line 141
    .line 142
    invoke-virtual {p0}, Lcom/google/gson/r;->i()Ljava/lang/Number;

    .line 143
    .line 144
    .line 145
    move-result-object p0

    .line 146
    invoke-virtual {p0}, Ljava/lang/Number;->doubleValue()D

    .line 147
    .line 148
    .line 149
    move-result-wide v1

    .line 150
    goto :goto_3

    .line 151
    :cond_9
    invoke-virtual {p0}, Lcom/google/gson/r;->e()Ljava/lang/String;

    .line 152
    .line 153
    .line 154
    move-result-object p0

    .line 155
    invoke-static {p0}, Ljava/lang/Double;->parseDouble(Ljava/lang/String;)D

    .line 156
    .line 157
    .line 158
    move-result-wide v1

    .line 159
    :goto_3
    instance-of p0, v0, Ljava/lang/Number;

    .line 160
    .line 161
    if-eqz p0, :cond_a

    .line 162
    .line 163
    invoke-virtual {p1}, Lcom/google/gson/r;->i()Ljava/lang/Number;

    .line 164
    .line 165
    .line 166
    move-result-object p0

    .line 167
    invoke-virtual {p0}, Ljava/lang/Number;->doubleValue()D

    .line 168
    .line 169
    .line 170
    move-result-wide p0

    .line 171
    goto :goto_4

    .line 172
    :cond_a
    invoke-virtual {p1}, Lcom/google/gson/r;->e()Ljava/lang/String;

    .line 173
    .line 174
    .line 175
    move-result-object p0

    .line 176
    invoke-static {p0}, Ljava/lang/Double;->parseDouble(Ljava/lang/String;)D

    .line 177
    .line 178
    .line 179
    move-result-wide p0

    .line 180
    :goto_4
    cmpl-double v0, v1, p0

    .line 181
    .line 182
    if-eqz v0, :cond_b

    .line 183
    .line 184
    invoke-static {v1, v2}, Ljava/lang/Double;->isNaN(D)Z

    .line 185
    .line 186
    .line 187
    move-result v0

    .line 188
    if-eqz v0, :cond_d

    .line 189
    .line 190
    invoke-static {p0, p1}, Ljava/lang/Double;->isNaN(D)Z

    .line 191
    .line 192
    .line 193
    move-result p0

    .line 194
    if-eqz p0, :cond_d

    .line 195
    .line 196
    :cond_b
    :goto_5
    const/4 p0, 0x1

    .line 197
    return p0

    .line 198
    :cond_c
    invoke-virtual {v1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 199
    .line 200
    .line 201
    move-result p0

    .line 202
    return p0

    .line 203
    :cond_d
    :goto_6
    const/4 p0, 0x0

    .line 204
    return p0
.end method

.method public final g()Ljava/math/BigInteger;
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/google/gson/r;->d:Ljava/io/Serializable;

    .line 2
    .line 3
    instance-of v1, v0, Ljava/math/BigInteger;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    check-cast v0, Ljava/math/BigInteger;

    .line 8
    .line 9
    return-object v0

    .line 10
    :cond_0
    invoke-static {p0}, Lcom/google/gson/r;->k(Lcom/google/gson/r;)Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-eqz v0, :cond_1

    .line 15
    .line 16
    invoke-virtual {p0}, Lcom/google/gson/r;->i()Ljava/lang/Number;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    invoke-virtual {p0}, Ljava/lang/Number;->longValue()J

    .line 21
    .line 22
    .line 23
    move-result-wide v0

    .line 24
    invoke-static {v0, v1}, Ljava/math/BigInteger;->valueOf(J)Ljava/math/BigInteger;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0

    .line 29
    :cond_1
    invoke-virtual {p0}, Lcom/google/gson/r;->e()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    invoke-static {p0}, Lcom/google/gson/internal/f;->d(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    new-instance v0, Ljava/math/BigInteger;

    .line 37
    .line 38
    invoke-direct {v0, p0}, Ljava/math/BigInteger;-><init>(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    return-object v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/google/gson/r;->d:Ljava/io/Serializable;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/16 p0, 0x1f

    .line 6
    .line 7
    return p0

    .line 8
    :cond_0
    invoke-static {p0}, Lcom/google/gson/r;->k(Lcom/google/gson/r;)Z

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    const/16 v2, 0x20

    .line 13
    .line 14
    if-eqz v1, :cond_1

    .line 15
    .line 16
    invoke-virtual {p0}, Lcom/google/gson/r;->i()Ljava/lang/Number;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    invoke-virtual {p0}, Ljava/lang/Number;->longValue()J

    .line 21
    .line 22
    .line 23
    move-result-wide v0

    .line 24
    :goto_0
    ushr-long v2, v0, v2

    .line 25
    .line 26
    xor-long/2addr v0, v2

    .line 27
    long-to-int p0, v0

    .line 28
    return p0

    .line 29
    :cond_1
    instance-of v1, v0, Ljava/lang/Number;

    .line 30
    .line 31
    if-eqz v1, :cond_2

    .line 32
    .line 33
    invoke-virtual {p0}, Lcom/google/gson/r;->i()Ljava/lang/Number;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    invoke-virtual {p0}, Ljava/lang/Number;->doubleValue()D

    .line 38
    .line 39
    .line 40
    move-result-wide v0

    .line 41
    invoke-static {v0, v1}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 42
    .line 43
    .line 44
    move-result-wide v0

    .line 45
    goto :goto_0

    .line 46
    :cond_2
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    return p0
.end method

.method public final i()Ljava/lang/Number;
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/google/gson/r;->d:Ljava/io/Serializable;

    .line 2
    .line 3
    instance-of v0, p0, Ljava/lang/Number;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    check-cast p0, Ljava/lang/Number;

    .line 8
    .line 9
    return-object p0

    .line 10
    :cond_0
    instance-of v0, p0, Ljava/lang/String;

    .line 11
    .line 12
    if-eqz v0, :cond_1

    .line 13
    .line 14
    new-instance v0, Lcom/google/gson/internal/h;

    .line 15
    .line 16
    check-cast p0, Ljava/lang/String;

    .line 17
    .line 18
    invoke-direct {v0, p0}, Lcom/google/gson/internal/h;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    return-object v0

    .line 22
    :cond_1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 23
    .line 24
    const-string v0, "Primitive is neither a number nor a string"

    .line 25
    .line 26
    invoke-direct {p0, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    throw p0
.end method
