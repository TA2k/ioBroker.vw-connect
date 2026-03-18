.class final Lcom/squareup/moshi/JsonUtf8Reader;
.super Lcom/squareup/moshi/JsonReader;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final p:Lu01/i;

.field public static final q:Lu01/i;

.field public static final r:Lu01/i;

.field public static final s:Lu01/i;

.field public static final t:Lu01/i;


# instance fields
.field public final j:Lu01/h;

.field public final k:Lu01/f;

.field public l:I

.field public m:J

.field public n:I

.field public o:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Lu01/i;->g:Lu01/i;

    .line 2
    .line 3
    const-string v0, "\'\\"

    .line 4
    .line 5
    invoke-static {v0}, Lpy/a;->m(Ljava/lang/String;)Lu01/i;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    sput-object v0, Lcom/squareup/moshi/JsonUtf8Reader;->p:Lu01/i;

    .line 10
    .line 11
    const-string v0, "\"\\"

    .line 12
    .line 13
    invoke-static {v0}, Lpy/a;->m(Ljava/lang/String;)Lu01/i;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    sput-object v0, Lcom/squareup/moshi/JsonUtf8Reader;->q:Lu01/i;

    .line 18
    .line 19
    const-string v0, "{}[]:, \n\t\r\u000c/\\;#="

    .line 20
    .line 21
    invoke-static {v0}, Lpy/a;->m(Ljava/lang/String;)Lu01/i;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    sput-object v0, Lcom/squareup/moshi/JsonUtf8Reader;->r:Lu01/i;

    .line 26
    .line 27
    const-string v0, "\n\r"

    .line 28
    .line 29
    invoke-static {v0}, Lpy/a;->m(Ljava/lang/String;)Lu01/i;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    sput-object v0, Lcom/squareup/moshi/JsonUtf8Reader;->s:Lu01/i;

    .line 34
    .line 35
    const-string v0, "*/"

    .line 36
    .line 37
    invoke-static {v0}, Lpy/a;->m(Ljava/lang/String;)Lu01/i;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    sput-object v0, Lcom/squareup/moshi/JsonUtf8Reader;->t:Lu01/i;

    .line 42
    .line 43
    return-void
.end method

.method public constructor <init>(Lu01/h;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Lcom/squareup/moshi/JsonReader;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 6
    .line 7
    iput-object p1, p0, Lcom/squareup/moshi/JsonUtf8Reader;->j:Lu01/h;

    .line 8
    .line 9
    invoke-interface {p1}, Lu01/h;->n()Lu01/f;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    iput-object p1, p0, Lcom/squareup/moshi/JsonUtf8Reader;->k:Lu01/f;

    .line 14
    .line 15
    const/4 p1, 0x6

    .line 16
    invoke-virtual {p0, p1}, Lcom/squareup/moshi/JsonReader;->V(I)V

    .line 17
    .line 18
    .line 19
    return-void
.end method


# virtual methods
.method public final A0(I)Z
    .locals 1

    .line 1
    const/16 v0, 0x9

    .line 2
    .line 3
    if-eq p1, v0, :cond_1

    .line 4
    .line 5
    const/16 v0, 0xa

    .line 6
    .line 7
    if-eq p1, v0, :cond_1

    .line 8
    .line 9
    const/16 v0, 0xc

    .line 10
    .line 11
    if-eq p1, v0, :cond_1

    .line 12
    .line 13
    const/16 v0, 0xd

    .line 14
    .line 15
    if-eq p1, v0, :cond_1

    .line 16
    .line 17
    const/16 v0, 0x20

    .line 18
    .line 19
    if-eq p1, v0, :cond_1

    .line 20
    .line 21
    const/16 v0, 0x23

    .line 22
    .line 23
    if-eq p1, v0, :cond_0

    .line 24
    .line 25
    const/16 v0, 0x2c

    .line 26
    .line 27
    if-eq p1, v0, :cond_1

    .line 28
    .line 29
    const/16 v0, 0x2f

    .line 30
    .line 31
    if-eq p1, v0, :cond_0

    .line 32
    .line 33
    const/16 v0, 0x3d

    .line 34
    .line 35
    if-eq p1, v0, :cond_0

    .line 36
    .line 37
    const/16 v0, 0x7b

    .line 38
    .line 39
    if-eq p1, v0, :cond_1

    .line 40
    .line 41
    const/16 v0, 0x7d

    .line 42
    .line 43
    if-eq p1, v0, :cond_1

    .line 44
    .line 45
    const/16 v0, 0x3a

    .line 46
    .line 47
    if-eq p1, v0, :cond_1

    .line 48
    .line 49
    const/16 v0, 0x3b

    .line 50
    .line 51
    if-eq p1, v0, :cond_0

    .line 52
    .line 53
    packed-switch p1, :pswitch_data_0

    .line 54
    .line 55
    .line 56
    const/4 p0, 0x1

    .line 57
    return p0

    .line 58
    :cond_0
    :pswitch_0
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->r0()V

    .line 59
    .line 60
    .line 61
    :cond_1
    :pswitch_1
    const/4 p0, 0x0

    .line 62
    return p0

    .line 63
    :pswitch_data_0
    .packed-switch 0x5b
        :pswitch_1
        :pswitch_0
        :pswitch_1
    .end packed-switch
.end method

.method public final B()Ljava/lang/String;
    .locals 3

    .line 1
    iget v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->x0()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    :cond_0
    const/16 v1, 0xe

    .line 10
    .line 11
    if-ne v0, v1, :cond_1

    .line 12
    .line 13
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->D0()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    goto :goto_0

    .line 18
    :cond_1
    const/16 v1, 0xd

    .line 19
    .line 20
    if-ne v0, v1, :cond_2

    .line 21
    .line 22
    sget-object v0, Lcom/squareup/moshi/JsonUtf8Reader;->q:Lu01/i;

    .line 23
    .line 24
    invoke-virtual {p0, v0}, Lcom/squareup/moshi/JsonUtf8Reader;->C0(Lu01/i;)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    goto :goto_0

    .line 29
    :cond_2
    const/16 v1, 0xc

    .line 30
    .line 31
    if-ne v0, v1, :cond_3

    .line 32
    .line 33
    sget-object v0, Lcom/squareup/moshi/JsonUtf8Reader;->p:Lu01/i;

    .line 34
    .line 35
    invoke-virtual {p0, v0}, Lcom/squareup/moshi/JsonUtf8Reader;->C0(Lu01/i;)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    goto :goto_0

    .line 40
    :cond_3
    const/16 v1, 0xf

    .line 41
    .line 42
    if-ne v0, v1, :cond_4

    .line 43
    .line 44
    iget-object v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->o:Ljava/lang/String;

    .line 45
    .line 46
    const/4 v1, 0x0

    .line 47
    iput-object v1, p0, Lcom/squareup/moshi/JsonUtf8Reader;->o:Ljava/lang/String;

    .line 48
    .line 49
    :goto_0
    const/4 v1, 0x0

    .line 50
    iput v1, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 51
    .line 52
    iget-object v1, p0, Lcom/squareup/moshi/JsonReader;->f:[Ljava/lang/String;

    .line 53
    .line 54
    iget p0, p0, Lcom/squareup/moshi/JsonReader;->d:I

    .line 55
    .line 56
    add-int/lit8 p0, p0, -0x1

    .line 57
    .line 58
    aput-object v0, v1, p0

    .line 59
    .line 60
    return-object v0

    .line 61
    :cond_4
    new-instance v0, Lcom/squareup/moshi/JsonDataException;

    .line 62
    .line 63
    new-instance v1, Ljava/lang/StringBuilder;

    .line 64
    .line 65
    const-string v2, "Expected a name but was "

    .line 66
    .line 67
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->T()Lcom/squareup/moshi/JsonReader$Token;

    .line 71
    .line 72
    .line 73
    move-result-object v2

    .line 74
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    const-string v2, " at path "

    .line 78
    .line 79
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonReader;->g()Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    throw v0
.end method

.method public final B0(Z)I
    .locals 12

    .line 1
    const/4 v0, 0x0

    .line 2
    :goto_0
    move v1, v0

    .line 3
    :goto_1
    add-int/lit8 v2, v1, 0x1

    .line 4
    .line 5
    int-to-long v3, v2

    .line 6
    iget-object v5, p0, Lcom/squareup/moshi/JsonUtf8Reader;->j:Lu01/h;

    .line 7
    .line 8
    invoke-interface {v5, v3, v4}, Lu01/h;->c(J)Z

    .line 9
    .line 10
    .line 11
    move-result v3

    .line 12
    if-eqz v3, :cond_c

    .line 13
    .line 14
    int-to-long v3, v1

    .line 15
    iget-object v1, p0, Lcom/squareup/moshi/JsonUtf8Reader;->k:Lu01/f;

    .line 16
    .line 17
    invoke-virtual {v1, v3, v4}, Lu01/f;->h(J)B

    .line 18
    .line 19
    .line 20
    move-result v6

    .line 21
    const/16 v7, 0xa

    .line 22
    .line 23
    if-eq v6, v7, :cond_b

    .line 24
    .line 25
    const/16 v7, 0x20

    .line 26
    .line 27
    if-eq v6, v7, :cond_b

    .line 28
    .line 29
    const/16 v7, 0xd

    .line 30
    .line 31
    if-eq v6, v7, :cond_b

    .line 32
    .line 33
    const/16 v7, 0x9

    .line 34
    .line 35
    if-ne v6, v7, :cond_0

    .line 36
    .line 37
    goto/16 :goto_7

    .line 38
    .line 39
    :cond_0
    invoke-virtual {v1, v3, v4}, Lu01/f;->skip(J)V

    .line 40
    .line 41
    .line 42
    sget-object v2, Lcom/squareup/moshi/JsonUtf8Reader;->s:Lu01/i;

    .line 43
    .line 44
    const-wide/16 v3, -0x1

    .line 45
    .line 46
    const-wide/16 v7, 0x1

    .line 47
    .line 48
    const/16 v9, 0x2f

    .line 49
    .line 50
    if-ne v6, v9, :cond_8

    .line 51
    .line 52
    const-wide/16 v10, 0x2

    .line 53
    .line 54
    invoke-interface {v5, v10, v11}, Lu01/h;->c(J)Z

    .line 55
    .line 56
    .line 57
    move-result v10

    .line 58
    if-nez v10, :cond_1

    .line 59
    .line 60
    goto/16 :goto_6

    .line 61
    .line 62
    :cond_1
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->r0()V

    .line 63
    .line 64
    .line 65
    invoke-virtual {v1, v7, v8}, Lu01/f;->h(J)B

    .line 66
    .line 67
    .line 68
    move-result v10

    .line 69
    const/16 v11, 0x2a

    .line 70
    .line 71
    if-eq v10, v11, :cond_4

    .line 72
    .line 73
    if-eq v10, v9, :cond_2

    .line 74
    .line 75
    goto :goto_6

    .line 76
    :cond_2
    invoke-virtual {v1}, Lu01/f;->readByte()B

    .line 77
    .line 78
    .line 79
    invoke-virtual {v1}, Lu01/f;->readByte()B

    .line 80
    .line 81
    .line 82
    invoke-interface {v5, v2}, Lu01/h;->y(Lu01/i;)J

    .line 83
    .line 84
    .line 85
    move-result-wide v5

    .line 86
    cmp-long v2, v5, v3

    .line 87
    .line 88
    if-eqz v2, :cond_3

    .line 89
    .line 90
    add-long/2addr v5, v7

    .line 91
    goto :goto_2

    .line 92
    :cond_3
    iget-wide v5, v1, Lu01/f;->e:J

    .line 93
    .line 94
    :goto_2
    invoke-virtual {v1, v5, v6}, Lu01/f;->skip(J)V

    .line 95
    .line 96
    .line 97
    goto :goto_0

    .line 98
    :cond_4
    invoke-virtual {v1}, Lu01/f;->readByte()B

    .line 99
    .line 100
    .line 101
    invoke-virtual {v1}, Lu01/f;->readByte()B

    .line 102
    .line 103
    .line 104
    sget-object v2, Lcom/squareup/moshi/JsonUtf8Reader;->t:Lu01/i;

    .line 105
    .line 106
    invoke-interface {v5, v2}, Lu01/h;->i(Lu01/i;)J

    .line 107
    .line 108
    .line 109
    move-result-wide v5

    .line 110
    cmp-long v3, v5, v3

    .line 111
    .line 112
    if-eqz v3, :cond_5

    .line 113
    .line 114
    const/4 v3, 0x1

    .line 115
    goto :goto_3

    .line 116
    :cond_5
    move v3, v0

    .line 117
    :goto_3
    if-eqz v3, :cond_6

    .line 118
    .line 119
    iget-object v2, v2, Lu01/i;->d:[B

    .line 120
    .line 121
    array-length v2, v2

    .line 122
    int-to-long v7, v2

    .line 123
    add-long/2addr v5, v7

    .line 124
    goto :goto_4

    .line 125
    :cond_6
    iget-wide v5, v1, Lu01/f;->e:J

    .line 126
    .line 127
    :goto_4
    invoke-virtual {v1, v5, v6}, Lu01/f;->skip(J)V

    .line 128
    .line 129
    .line 130
    if-eqz v3, :cond_7

    .line 131
    .line 132
    goto/16 :goto_0

    .line 133
    .line 134
    :cond_7
    const-string p1, "Unterminated comment"

    .line 135
    .line 136
    invoke-virtual {p0, p1}, Lcom/squareup/moshi/JsonReader;->n0(Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    const/4 p0, 0x0

    .line 140
    throw p0

    .line 141
    :cond_8
    const/16 v9, 0x23

    .line 142
    .line 143
    if-ne v6, v9, :cond_a

    .line 144
    .line 145
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->r0()V

    .line 146
    .line 147
    .line 148
    invoke-interface {v5, v2}, Lu01/h;->y(Lu01/i;)J

    .line 149
    .line 150
    .line 151
    move-result-wide v5

    .line 152
    cmp-long v2, v5, v3

    .line 153
    .line 154
    if-eqz v2, :cond_9

    .line 155
    .line 156
    add-long/2addr v5, v7

    .line 157
    goto :goto_5

    .line 158
    :cond_9
    iget-wide v5, v1, Lu01/f;->e:J

    .line 159
    .line 160
    :goto_5
    invoke-virtual {v1, v5, v6}, Lu01/f;->skip(J)V

    .line 161
    .line 162
    .line 163
    goto/16 :goto_0

    .line 164
    .line 165
    :cond_a
    :goto_6
    return v6

    .line 166
    :cond_b
    :goto_7
    move v1, v2

    .line 167
    goto/16 :goto_1

    .line 168
    .line 169
    :cond_c
    if-nez p1, :cond_d

    .line 170
    .line 171
    const/4 p0, -0x1

    .line 172
    return p0

    .line 173
    :cond_d
    new-instance p0, Ljava/io/EOFException;

    .line 174
    .line 175
    const-string p1, "End of input"

    .line 176
    .line 177
    invoke-direct {p0, p1}, Ljava/io/EOFException;-><init>(Ljava/lang/String;)V

    .line 178
    .line 179
    .line 180
    throw p0
.end method

.method public final C0(Lu01/i;)Ljava/lang/String;
    .locals 7

    .line 1
    const/4 v0, 0x0

    .line 2
    move-object v1, v0

    .line 3
    :goto_0
    iget-object v2, p0, Lcom/squareup/moshi/JsonUtf8Reader;->j:Lu01/h;

    .line 4
    .line 5
    invoke-interface {v2, p1}, Lu01/h;->y(Lu01/i;)J

    .line 6
    .line 7
    .line 8
    move-result-wide v2

    .line 9
    const-wide/16 v4, -0x1

    .line 10
    .line 11
    cmp-long v4, v2, v4

    .line 12
    .line 13
    if-eqz v4, :cond_3

    .line 14
    .line 15
    iget-object v4, p0, Lcom/squareup/moshi/JsonUtf8Reader;->k:Lu01/f;

    .line 16
    .line 17
    invoke-virtual {v4, v2, v3}, Lu01/f;->h(J)B

    .line 18
    .line 19
    .line 20
    move-result v5

    .line 21
    const/16 v6, 0x5c

    .line 22
    .line 23
    if-ne v5, v6, :cond_1

    .line 24
    .line 25
    if-nez v1, :cond_0

    .line 26
    .line 27
    new-instance v1, Ljava/lang/StringBuilder;

    .line 28
    .line 29
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 30
    .line 31
    .line 32
    :cond_0
    sget-object v5, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 33
    .line 34
    invoke-virtual {v4, v2, v3, v5}, Lu01/f;->M(JLjava/nio/charset/Charset;)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    invoke-virtual {v4}, Lu01/f;->readByte()B

    .line 42
    .line 43
    .line 44
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->E0()C

    .line 45
    .line 46
    .line 47
    move-result v2

    .line 48
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_1
    if-nez v1, :cond_2

    .line 53
    .line 54
    sget-object p0, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 55
    .line 56
    invoke-virtual {v4, v2, v3, p0}, Lu01/f;->M(JLjava/nio/charset/Charset;)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    invoke-virtual {v4}, Lu01/f;->readByte()B

    .line 61
    .line 62
    .line 63
    return-object p0

    .line 64
    :cond_2
    sget-object p0, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 65
    .line 66
    invoke-virtual {v4, v2, v3, p0}, Lu01/f;->M(JLjava/nio/charset/Charset;)Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    invoke-virtual {v4}, Lu01/f;->readByte()B

    .line 74
    .line 75
    .line 76
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    return-object p0

    .line 81
    :cond_3
    const-string p1, "Unterminated string"

    .line 82
    .line 83
    invoke-virtual {p0, p1}, Lcom/squareup/moshi/JsonReader;->n0(Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    throw v0
.end method

.method public final D0()Ljava/lang/String;
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->j:Lu01/h;

    .line 2
    .line 3
    sget-object v1, Lcom/squareup/moshi/JsonUtf8Reader;->r:Lu01/i;

    .line 4
    .line 5
    invoke-interface {v0, v1}, Lu01/h;->y(Lu01/i;)J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    const-wide/16 v2, -0x1

    .line 10
    .line 11
    cmp-long v2, v0, v2

    .line 12
    .line 13
    iget-object p0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->k:Lu01/f;

    .line 14
    .line 15
    if-eqz v2, :cond_0

    .line 16
    .line 17
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 18
    .line 19
    .line 20
    sget-object v2, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 21
    .line 22
    invoke-virtual {p0, v0, v1, v2}, Lu01/f;->M(JLjava/nio/charset/Charset;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0

    .line 27
    :cond_0
    invoke-virtual {p0}, Lu01/f;->T()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0
.end method

.method public final E()V
    .locals 3

    .line 1
    iget v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->x0()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    :cond_0
    const/4 v1, 0x7

    .line 10
    if-ne v0, v1, :cond_1

    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    iput v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 14
    .line 15
    iget-object v0, p0, Lcom/squareup/moshi/JsonReader;->g:[I

    .line 16
    .line 17
    iget p0, p0, Lcom/squareup/moshi/JsonReader;->d:I

    .line 18
    .line 19
    add-int/lit8 p0, p0, -0x1

    .line 20
    .line 21
    aget v1, v0, p0

    .line 22
    .line 23
    add-int/lit8 v1, v1, 0x1

    .line 24
    .line 25
    aput v1, v0, p0

    .line 26
    .line 27
    return-void

    .line 28
    :cond_1
    new-instance v0, Lcom/squareup/moshi/JsonDataException;

    .line 29
    .line 30
    new-instance v1, Ljava/lang/StringBuilder;

    .line 31
    .line 32
    const-string v2, "Expected null but was "

    .line 33
    .line 34
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->T()Lcom/squareup/moshi/JsonReader$Token;

    .line 38
    .line 39
    .line 40
    move-result-object v2

    .line 41
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    const-string v2, " at path "

    .line 45
    .line 46
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonReader;->g()Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    throw v0
.end method

.method public final E0()C
    .locals 9

    .line 1
    const-wide/16 v0, 0x1

    .line 2
    .line 3
    iget-object v2, p0, Lcom/squareup/moshi/JsonUtf8Reader;->j:Lu01/h;

    .line 4
    .line 5
    invoke-interface {v2, v0, v1}, Lu01/h;->c(J)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/4 v1, 0x0

    .line 10
    if-eqz v0, :cond_d

    .line 11
    .line 12
    iget-object v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->k:Lu01/f;

    .line 13
    .line 14
    invoke-virtual {v0}, Lu01/f;->readByte()B

    .line 15
    .line 16
    .line 17
    move-result v3

    .line 18
    const/16 v4, 0xa

    .line 19
    .line 20
    if-eq v3, v4, :cond_c

    .line 21
    .line 22
    const/16 v5, 0x22

    .line 23
    .line 24
    if-eq v3, v5, :cond_c

    .line 25
    .line 26
    const/16 v5, 0x27

    .line 27
    .line 28
    if-eq v3, v5, :cond_c

    .line 29
    .line 30
    const/16 v5, 0x2f

    .line 31
    .line 32
    if-eq v3, v5, :cond_c

    .line 33
    .line 34
    const/16 v5, 0x5c

    .line 35
    .line 36
    if-eq v3, v5, :cond_c

    .line 37
    .line 38
    const/16 v5, 0x62

    .line 39
    .line 40
    if-eq v3, v5, :cond_b

    .line 41
    .line 42
    const/16 v5, 0x66

    .line 43
    .line 44
    if-eq v3, v5, :cond_a

    .line 45
    .line 46
    const/16 v6, 0x6e

    .line 47
    .line 48
    if-eq v3, v6, :cond_9

    .line 49
    .line 50
    const/16 v4, 0x72

    .line 51
    .line 52
    if-eq v3, v4, :cond_8

    .line 53
    .line 54
    const/16 v4, 0x74

    .line 55
    .line 56
    if-eq v3, v4, :cond_7

    .line 57
    .line 58
    const/16 v4, 0x75

    .line 59
    .line 60
    if-eq v3, v4, :cond_1

    .line 61
    .line 62
    iget-boolean v0, p0, Lcom/squareup/moshi/JsonReader;->h:Z

    .line 63
    .line 64
    if-eqz v0, :cond_0

    .line 65
    .line 66
    int-to-char p0, v3

    .line 67
    return p0

    .line 68
    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 69
    .line 70
    const-string v2, "Invalid escape sequence: \\"

    .line 71
    .line 72
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    int-to-char v2, v3

    .line 76
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object v0

    .line 83
    invoke-virtual {p0, v0}, Lcom/squareup/moshi/JsonReader;->n0(Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    throw v1

    .line 87
    :cond_1
    const-wide/16 v3, 0x4

    .line 88
    .line 89
    invoke-interface {v2, v3, v4}, Lu01/h;->c(J)Z

    .line 90
    .line 91
    .line 92
    move-result v2

    .line 93
    if-eqz v2, :cond_6

    .line 94
    .line 95
    const/4 v2, 0x0

    .line 96
    move v6, v2

    .line 97
    :goto_0
    const/4 v7, 0x4

    .line 98
    if-ge v2, v7, :cond_5

    .line 99
    .line 100
    int-to-long v7, v2

    .line 101
    invoke-virtual {v0, v7, v8}, Lu01/f;->h(J)B

    .line 102
    .line 103
    .line 104
    move-result v7

    .line 105
    shl-int/lit8 v6, v6, 0x4

    .line 106
    .line 107
    int-to-char v6, v6

    .line 108
    const/16 v8, 0x30

    .line 109
    .line 110
    if-lt v7, v8, :cond_2

    .line 111
    .line 112
    const/16 v8, 0x39

    .line 113
    .line 114
    if-gt v7, v8, :cond_2

    .line 115
    .line 116
    add-int/lit8 v7, v7, -0x30

    .line 117
    .line 118
    :goto_1
    add-int/2addr v7, v6

    .line 119
    int-to-char v6, v7

    .line 120
    goto :goto_2

    .line 121
    :cond_2
    const/16 v8, 0x61

    .line 122
    .line 123
    if-lt v7, v8, :cond_3

    .line 124
    .line 125
    if-gt v7, v5, :cond_3

    .line 126
    .line 127
    add-int/lit8 v7, v7, -0x57

    .line 128
    .line 129
    goto :goto_1

    .line 130
    :cond_3
    const/16 v8, 0x41

    .line 131
    .line 132
    if-lt v7, v8, :cond_4

    .line 133
    .line 134
    const/16 v8, 0x46

    .line 135
    .line 136
    if-gt v7, v8, :cond_4

    .line 137
    .line 138
    add-int/lit8 v7, v7, -0x37

    .line 139
    .line 140
    goto :goto_1

    .line 141
    :goto_2
    add-int/lit8 v2, v2, 0x1

    .line 142
    .line 143
    goto :goto_0

    .line 144
    :cond_4
    sget-object v2, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 145
    .line 146
    invoke-virtual {v0, v3, v4, v2}, Lu01/f;->M(JLjava/nio/charset/Charset;)Ljava/lang/String;

    .line 147
    .line 148
    .line 149
    move-result-object v0

    .line 150
    const-string v2, "\\u"

    .line 151
    .line 152
    invoke-virtual {v2, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 153
    .line 154
    .line 155
    move-result-object v0

    .line 156
    invoke-virtual {p0, v0}, Lcom/squareup/moshi/JsonReader;->n0(Ljava/lang/String;)V

    .line 157
    .line 158
    .line 159
    throw v1

    .line 160
    :cond_5
    invoke-virtual {v0, v3, v4}, Lu01/f;->skip(J)V

    .line 161
    .line 162
    .line 163
    return v6

    .line 164
    :cond_6
    new-instance v0, Ljava/io/EOFException;

    .line 165
    .line 166
    new-instance v1, Ljava/lang/StringBuilder;

    .line 167
    .line 168
    const-string v2, "Unterminated escape sequence at path "

    .line 169
    .line 170
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 171
    .line 172
    .line 173
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonReader;->g()Ljava/lang/String;

    .line 174
    .line 175
    .line 176
    move-result-object p0

    .line 177
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 178
    .line 179
    .line 180
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 181
    .line 182
    .line 183
    move-result-object p0

    .line 184
    invoke-direct {v0, p0}, Ljava/io/EOFException;-><init>(Ljava/lang/String;)V

    .line 185
    .line 186
    .line 187
    throw v0

    .line 188
    :cond_7
    const/16 p0, 0x9

    .line 189
    .line 190
    return p0

    .line 191
    :cond_8
    const/16 p0, 0xd

    .line 192
    .line 193
    return p0

    .line 194
    :cond_9
    return v4

    .line 195
    :cond_a
    const/16 p0, 0xc

    .line 196
    .line 197
    return p0

    .line 198
    :cond_b
    const/16 p0, 0x8

    .line 199
    .line 200
    return p0

    .line 201
    :cond_c
    int-to-char p0, v3

    .line 202
    return p0

    .line 203
    :cond_d
    const-string v0, "Unterminated escape sequence"

    .line 204
    .line 205
    invoke-virtual {p0, v0}, Lcom/squareup/moshi/JsonReader;->n0(Ljava/lang/String;)V

    .line 206
    .line 207
    .line 208
    throw v1
.end method

.method public final F0(Lu01/i;)V
    .locals 7

    .line 1
    :goto_0
    iget-object v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->j:Lu01/h;

    .line 2
    .line 3
    invoke-interface {v0, p1}, Lu01/h;->y(Lu01/i;)J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    const-wide/16 v2, -0x1

    .line 8
    .line 9
    cmp-long v2, v0, v2

    .line 10
    .line 11
    if-eqz v2, :cond_1

    .line 12
    .line 13
    iget-object v2, p0, Lcom/squareup/moshi/JsonUtf8Reader;->k:Lu01/f;

    .line 14
    .line 15
    invoke-virtual {v2, v0, v1}, Lu01/f;->h(J)B

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    const/16 v4, 0x5c

    .line 20
    .line 21
    const-wide/16 v5, 0x1

    .line 22
    .line 23
    if-ne v3, v4, :cond_0

    .line 24
    .line 25
    add-long/2addr v0, v5

    .line 26
    invoke-virtual {v2, v0, v1}, Lu01/f;->skip(J)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->E0()C

    .line 30
    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    add-long/2addr v0, v5

    .line 34
    invoke-virtual {v2, v0, v1}, Lu01/f;->skip(J)V

    .line 35
    .line 36
    .line 37
    return-void

    .line 38
    :cond_1
    const-string p1, "Unterminated string"

    .line 39
    .line 40
    invoke-virtual {p0, p1}, Lcom/squareup/moshi/JsonReader;->n0(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    const/4 p0, 0x0

    .line 44
    throw p0
.end method

.method public final H()Ljava/lang/String;
    .locals 4

    .line 1
    iget v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->x0()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    :cond_0
    const/16 v1, 0xa

    .line 10
    .line 11
    if-ne v0, v1, :cond_1

    .line 12
    .line 13
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->D0()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    goto :goto_0

    .line 18
    :cond_1
    const/16 v1, 0x9

    .line 19
    .line 20
    if-ne v0, v1, :cond_2

    .line 21
    .line 22
    sget-object v0, Lcom/squareup/moshi/JsonUtf8Reader;->q:Lu01/i;

    .line 23
    .line 24
    invoke-virtual {p0, v0}, Lcom/squareup/moshi/JsonUtf8Reader;->C0(Lu01/i;)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    goto :goto_0

    .line 29
    :cond_2
    const/16 v1, 0x8

    .line 30
    .line 31
    if-ne v0, v1, :cond_3

    .line 32
    .line 33
    sget-object v0, Lcom/squareup/moshi/JsonUtf8Reader;->p:Lu01/i;

    .line 34
    .line 35
    invoke-virtual {p0, v0}, Lcom/squareup/moshi/JsonUtf8Reader;->C0(Lu01/i;)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    goto :goto_0

    .line 40
    :cond_3
    const/16 v1, 0xb

    .line 41
    .line 42
    if-ne v0, v1, :cond_4

    .line 43
    .line 44
    iget-object v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->o:Ljava/lang/String;

    .line 45
    .line 46
    const/4 v1, 0x0

    .line 47
    iput-object v1, p0, Lcom/squareup/moshi/JsonUtf8Reader;->o:Ljava/lang/String;

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_4
    const/16 v1, 0x10

    .line 51
    .line 52
    if-ne v0, v1, :cond_5

    .line 53
    .line 54
    iget-wide v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->m:J

    .line 55
    .line 56
    invoke-static {v0, v1}, Ljava/lang/Long;->toString(J)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    goto :goto_0

    .line 61
    :cond_5
    const/16 v1, 0x11

    .line 62
    .line 63
    if-ne v0, v1, :cond_6

    .line 64
    .line 65
    iget v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->n:I

    .line 66
    .line 67
    int-to-long v0, v0

    .line 68
    iget-object v2, p0, Lcom/squareup/moshi/JsonUtf8Reader;->k:Lu01/f;

    .line 69
    .line 70
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 71
    .line 72
    .line 73
    sget-object v3, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 74
    .line 75
    invoke-virtual {v2, v0, v1, v3}, Lu01/f;->M(JLjava/nio/charset/Charset;)Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object v0

    .line 79
    :goto_0
    const/4 v1, 0x0

    .line 80
    iput v1, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 81
    .line 82
    iget-object v1, p0, Lcom/squareup/moshi/JsonReader;->g:[I

    .line 83
    .line 84
    iget p0, p0, Lcom/squareup/moshi/JsonReader;->d:I

    .line 85
    .line 86
    add-int/lit8 p0, p0, -0x1

    .line 87
    .line 88
    aget v2, v1, p0

    .line 89
    .line 90
    add-int/lit8 v2, v2, 0x1

    .line 91
    .line 92
    aput v2, v1, p0

    .line 93
    .line 94
    return-object v0

    .line 95
    :cond_6
    new-instance v0, Lcom/squareup/moshi/JsonDataException;

    .line 96
    .line 97
    new-instance v1, Ljava/lang/StringBuilder;

    .line 98
    .line 99
    const-string v2, "Expected a string but was "

    .line 100
    .line 101
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->T()Lcom/squareup/moshi/JsonReader$Token;

    .line 105
    .line 106
    .line 107
    move-result-object v2

    .line 108
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 109
    .line 110
    .line 111
    const-string v2, " at path "

    .line 112
    .line 113
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 114
    .line 115
    .line 116
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonReader;->g()Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object p0

    .line 120
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 121
    .line 122
    .line 123
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 128
    .line 129
    .line 130
    throw v0
.end method

.method public final T()Lcom/squareup/moshi/JsonReader$Token;
    .locals 1

    .line 1
    iget v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->x0()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    :cond_0
    packed-switch v0, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    new-instance p0, Ljava/lang/AssertionError;

    .line 13
    .line 14
    invoke-direct {p0}, Ljava/lang/AssertionError;-><init>()V

    .line 15
    .line 16
    .line 17
    throw p0

    .line 18
    :pswitch_0
    sget-object p0, Lcom/squareup/moshi/JsonReader$Token;->m:Lcom/squareup/moshi/JsonReader$Token;

    .line 19
    .line 20
    return-object p0

    .line 21
    :pswitch_1
    sget-object p0, Lcom/squareup/moshi/JsonReader$Token;->j:Lcom/squareup/moshi/JsonReader$Token;

    .line 22
    .line 23
    return-object p0

    .line 24
    :pswitch_2
    sget-object p0, Lcom/squareup/moshi/JsonReader$Token;->h:Lcom/squareup/moshi/JsonReader$Token;

    .line 25
    .line 26
    return-object p0

    .line 27
    :pswitch_3
    sget-object p0, Lcom/squareup/moshi/JsonReader$Token;->i:Lcom/squareup/moshi/JsonReader$Token;

    .line 28
    .line 29
    return-object p0

    .line 30
    :pswitch_4
    sget-object p0, Lcom/squareup/moshi/JsonReader$Token;->l:Lcom/squareup/moshi/JsonReader$Token;

    .line 31
    .line 32
    return-object p0

    .line 33
    :pswitch_5
    sget-object p0, Lcom/squareup/moshi/JsonReader$Token;->k:Lcom/squareup/moshi/JsonReader$Token;

    .line 34
    .line 35
    return-object p0

    .line 36
    :pswitch_6
    sget-object p0, Lcom/squareup/moshi/JsonReader$Token;->e:Lcom/squareup/moshi/JsonReader$Token;

    .line 37
    .line 38
    return-object p0

    .line 39
    :pswitch_7
    sget-object p0, Lcom/squareup/moshi/JsonReader$Token;->d:Lcom/squareup/moshi/JsonReader$Token;

    .line 40
    .line 41
    return-object p0

    .line 42
    :pswitch_8
    sget-object p0, Lcom/squareup/moshi/JsonReader$Token;->g:Lcom/squareup/moshi/JsonReader$Token;

    .line 43
    .line 44
    return-object p0

    .line 45
    :pswitch_9
    sget-object p0, Lcom/squareup/moshi/JsonReader$Token;->f:Lcom/squareup/moshi/JsonReader$Token;

    .line 46
    .line 47
    return-object p0

    .line 48
    nop

    .line 49
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_3
        :pswitch_3
        :pswitch_3
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_1
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final U()V
    .locals 1

    .line 1
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->h()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->B()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iput-object v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->o:Ljava/lang/String;

    .line 12
    .line 13
    const/16 v0, 0xb

    .line 14
    .line 15
    iput v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 16
    .line 17
    :cond_0
    return-void
.end method

.method public final a()V
    .locals 3

    .line 1
    iget v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->x0()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    :cond_0
    const/4 v1, 0x3

    .line 10
    if-ne v0, v1, :cond_1

    .line 11
    .line 12
    const/4 v0, 0x1

    .line 13
    invoke-virtual {p0, v0}, Lcom/squareup/moshi/JsonReader;->V(I)V

    .line 14
    .line 15
    .line 16
    iget-object v1, p0, Lcom/squareup/moshi/JsonReader;->g:[I

    .line 17
    .line 18
    iget v2, p0, Lcom/squareup/moshi/JsonReader;->d:I

    .line 19
    .line 20
    sub-int/2addr v2, v0

    .line 21
    const/4 v0, 0x0

    .line 22
    aput v0, v1, v2

    .line 23
    .line 24
    iput v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 25
    .line 26
    return-void

    .line 27
    :cond_1
    new-instance v0, Lcom/squareup/moshi/JsonDataException;

    .line 28
    .line 29
    new-instance v1, Ljava/lang/StringBuilder;

    .line 30
    .line 31
    const-string v2, "Expected BEGIN_ARRAY but was "

    .line 32
    .line 33
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->T()Lcom/squareup/moshi/JsonReader$Token;

    .line 37
    .line 38
    .line 39
    move-result-object v2

    .line 40
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v2, " at path "

    .line 44
    .line 45
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonReader;->g()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    throw v0
.end method

.method public final b()V
    .locals 3

    .line 1
    iget v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->x0()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    :cond_0
    const/4 v1, 0x1

    .line 10
    if-ne v0, v1, :cond_1

    .line 11
    .line 12
    const/4 v0, 0x3

    .line 13
    invoke-virtual {p0, v0}, Lcom/squareup/moshi/JsonReader;->V(I)V

    .line 14
    .line 15
    .line 16
    const/4 v0, 0x0

    .line 17
    iput v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 18
    .line 19
    return-void

    .line 20
    :cond_1
    new-instance v0, Lcom/squareup/moshi/JsonDataException;

    .line 21
    .line 22
    new-instance v1, Ljava/lang/StringBuilder;

    .line 23
    .line 24
    const-string v2, "Expected BEGIN_OBJECT but was "

    .line 25
    .line 26
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->T()Lcom/squareup/moshi/JsonReader$Token;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    const-string v2, " at path "

    .line 37
    .line 38
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonReader;->g()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw v0
.end method

.method public final close()V
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    iput v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 3
    .line 4
    iget-object v1, p0, Lcom/squareup/moshi/JsonReader;->e:[I

    .line 5
    .line 6
    const/16 v2, 0x8

    .line 7
    .line 8
    aput v2, v1, v0

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    iput v0, p0, Lcom/squareup/moshi/JsonReader;->d:I

    .line 12
    .line 13
    iget-object v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->k:Lu01/f;

    .line 14
    .line 15
    invoke-virtual {v0}, Lu01/f;->a()V

    .line 16
    .line 17
    .line 18
    iget-object p0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->j:Lu01/h;

    .line 19
    .line 20
    invoke-interface {p0}, Ljava/io/Closeable;->close()V

    .line 21
    .line 22
    .line 23
    return-void
.end method

.method public final d()V
    .locals 3

    .line 1
    iget v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->x0()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    :cond_0
    const/4 v1, 0x4

    .line 10
    if-ne v0, v1, :cond_1

    .line 11
    .line 12
    iget v0, p0, Lcom/squareup/moshi/JsonReader;->d:I

    .line 13
    .line 14
    add-int/lit8 v1, v0, -0x1

    .line 15
    .line 16
    iput v1, p0, Lcom/squareup/moshi/JsonReader;->d:I

    .line 17
    .line 18
    iget-object v1, p0, Lcom/squareup/moshi/JsonReader;->g:[I

    .line 19
    .line 20
    add-int/lit8 v0, v0, -0x2

    .line 21
    .line 22
    aget v2, v1, v0

    .line 23
    .line 24
    add-int/lit8 v2, v2, 0x1

    .line 25
    .line 26
    aput v2, v1, v0

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    iput v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 30
    .line 31
    return-void

    .line 32
    :cond_1
    new-instance v0, Lcom/squareup/moshi/JsonDataException;

    .line 33
    .line 34
    new-instance v1, Ljava/lang/StringBuilder;

    .line 35
    .line 36
    const-string v2, "Expected END_ARRAY but was "

    .line 37
    .line 38
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->T()Lcom/squareup/moshi/JsonReader$Token;

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    const-string v2, " at path "

    .line 49
    .line 50
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonReader;->g()Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    throw v0
.end method

.method public final e0(Lcom/squareup/moshi/JsonReader$Options;)I
    .locals 4

    .line 1
    iget v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->x0()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    :cond_0
    const/16 v1, 0xc

    .line 10
    .line 11
    const/4 v2, -0x1

    .line 12
    if-lt v0, v1, :cond_5

    .line 13
    .line 14
    const/16 v1, 0xf

    .line 15
    .line 16
    if-le v0, v1, :cond_1

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_1
    if-ne v0, v1, :cond_2

    .line 20
    .line 21
    iget-object v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->o:Ljava/lang/String;

    .line 22
    .line 23
    invoke-virtual {p0, v0, p1}, Lcom/squareup/moshi/JsonUtf8Reader;->y0(Ljava/lang/String;Lcom/squareup/moshi/JsonReader$Options;)I

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    return p0

    .line 28
    :cond_2
    iget-object v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->j:Lu01/h;

    .line 29
    .line 30
    iget-object v3, p1, Lcom/squareup/moshi/JsonReader$Options;->b:Lu01/w;

    .line 31
    .line 32
    invoke-interface {v0, v3}, Lu01/h;->Q(Lu01/w;)I

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    if-eq v0, v2, :cond_3

    .line 37
    .line 38
    const/4 v1, 0x0

    .line 39
    iput v1, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 40
    .line 41
    iget-object v1, p0, Lcom/squareup/moshi/JsonReader;->f:[Ljava/lang/String;

    .line 42
    .line 43
    iget p0, p0, Lcom/squareup/moshi/JsonReader;->d:I

    .line 44
    .line 45
    add-int/lit8 p0, p0, -0x1

    .line 46
    .line 47
    iget-object p1, p1, Lcom/squareup/moshi/JsonReader$Options;->a:[Ljava/lang/String;

    .line 48
    .line 49
    aget-object p1, p1, v0

    .line 50
    .line 51
    aput-object p1, v1, p0

    .line 52
    .line 53
    return v0

    .line 54
    :cond_3
    iget-object v0, p0, Lcom/squareup/moshi/JsonReader;->f:[Ljava/lang/String;

    .line 55
    .line 56
    iget v3, p0, Lcom/squareup/moshi/JsonReader;->d:I

    .line 57
    .line 58
    add-int/lit8 v3, v3, -0x1

    .line 59
    .line 60
    aget-object v0, v0, v3

    .line 61
    .line 62
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->B()Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v3

    .line 66
    invoke-virtual {p0, v3, p1}, Lcom/squareup/moshi/JsonUtf8Reader;->y0(Ljava/lang/String;Lcom/squareup/moshi/JsonReader$Options;)I

    .line 67
    .line 68
    .line 69
    move-result p1

    .line 70
    if-ne p1, v2, :cond_4

    .line 71
    .line 72
    iput v1, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 73
    .line 74
    iput-object v3, p0, Lcom/squareup/moshi/JsonUtf8Reader;->o:Ljava/lang/String;

    .line 75
    .line 76
    iget-object v1, p0, Lcom/squareup/moshi/JsonReader;->f:[Ljava/lang/String;

    .line 77
    .line 78
    iget p0, p0, Lcom/squareup/moshi/JsonReader;->d:I

    .line 79
    .line 80
    add-int/lit8 p0, p0, -0x1

    .line 81
    .line 82
    aput-object v0, v1, p0

    .line 83
    .line 84
    :cond_4
    return p1

    .line 85
    :cond_5
    :goto_0
    return v2
.end method

.method public final f()V
    .locals 5

    .line 1
    iget v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->x0()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    :cond_0
    const/4 v1, 0x2

    .line 10
    if-ne v0, v1, :cond_1

    .line 11
    .line 12
    iget v0, p0, Lcom/squareup/moshi/JsonReader;->d:I

    .line 13
    .line 14
    add-int/lit8 v2, v0, -0x1

    .line 15
    .line 16
    iput v2, p0, Lcom/squareup/moshi/JsonReader;->d:I

    .line 17
    .line 18
    iget-object v3, p0, Lcom/squareup/moshi/JsonReader;->f:[Ljava/lang/String;

    .line 19
    .line 20
    const/4 v4, 0x0

    .line 21
    aput-object v4, v3, v2

    .line 22
    .line 23
    iget-object v2, p0, Lcom/squareup/moshi/JsonReader;->g:[I

    .line 24
    .line 25
    sub-int/2addr v0, v1

    .line 26
    aget v1, v2, v0

    .line 27
    .line 28
    add-int/lit8 v1, v1, 0x1

    .line 29
    .line 30
    aput v1, v2, v0

    .line 31
    .line 32
    const/4 v0, 0x0

    .line 33
    iput v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 34
    .line 35
    return-void

    .line 36
    :cond_1
    new-instance v0, Lcom/squareup/moshi/JsonDataException;

    .line 37
    .line 38
    new-instance v1, Ljava/lang/StringBuilder;

    .line 39
    .line 40
    const-string v2, "Expected END_OBJECT but was "

    .line 41
    .line 42
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->T()Lcom/squareup/moshi/JsonReader$Token;

    .line 46
    .line 47
    .line 48
    move-result-object v2

    .line 49
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    const-string v2, " at path "

    .line 53
    .line 54
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonReader;->g()Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    throw v0
.end method

.method public final h()Z
    .locals 1

    .line 1
    iget v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->x0()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    :cond_0
    const/4 p0, 0x2

    .line 10
    if-eq v0, p0, :cond_1

    .line 11
    .line 12
    const/4 p0, 0x4

    .line 13
    if-eq v0, p0, :cond_1

    .line 14
    .line 15
    const/16 p0, 0x12

    .line 16
    .line 17
    if-eq v0, p0, :cond_1

    .line 18
    .line 19
    const/4 p0, 0x1

    .line 20
    return p0

    .line 21
    :cond_1
    const/4 p0, 0x0

    .line 22
    return p0
.end method

.method public final h0(Lcom/squareup/moshi/JsonReader$Options;)I
    .locals 4

    .line 1
    iget v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->x0()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    :cond_0
    const/16 v1, 0x8

    .line 10
    .line 11
    const/4 v2, -0x1

    .line 12
    if-lt v0, v1, :cond_5

    .line 13
    .line 14
    const/16 v1, 0xb

    .line 15
    .line 16
    if-le v0, v1, :cond_1

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_1
    if-ne v0, v1, :cond_2

    .line 20
    .line 21
    iget-object v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->o:Ljava/lang/String;

    .line 22
    .line 23
    invoke-virtual {p0, v0, p1}, Lcom/squareup/moshi/JsonUtf8Reader;->z0(Ljava/lang/String;Lcom/squareup/moshi/JsonReader$Options;)I

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    return p0

    .line 28
    :cond_2
    iget-object v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->j:Lu01/h;

    .line 29
    .line 30
    iget-object v3, p1, Lcom/squareup/moshi/JsonReader$Options;->b:Lu01/w;

    .line 31
    .line 32
    invoke-interface {v0, v3}, Lu01/h;->Q(Lu01/w;)I

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    if-eq v0, v2, :cond_3

    .line 37
    .line 38
    const/4 p1, 0x0

    .line 39
    iput p1, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 40
    .line 41
    iget-object p1, p0, Lcom/squareup/moshi/JsonReader;->g:[I

    .line 42
    .line 43
    iget p0, p0, Lcom/squareup/moshi/JsonReader;->d:I

    .line 44
    .line 45
    add-int/lit8 p0, p0, -0x1

    .line 46
    .line 47
    aget v1, p1, p0

    .line 48
    .line 49
    add-int/lit8 v1, v1, 0x1

    .line 50
    .line 51
    aput v1, p1, p0

    .line 52
    .line 53
    return v0

    .line 54
    :cond_3
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->H()Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    invoke-virtual {p0, v0, p1}, Lcom/squareup/moshi/JsonUtf8Reader;->z0(Ljava/lang/String;Lcom/squareup/moshi/JsonReader$Options;)I

    .line 59
    .line 60
    .line 61
    move-result p1

    .line 62
    if-ne p1, v2, :cond_4

    .line 63
    .line 64
    iput v1, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 65
    .line 66
    iput-object v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->o:Ljava/lang/String;

    .line 67
    .line 68
    iget-object v0, p0, Lcom/squareup/moshi/JsonReader;->g:[I

    .line 69
    .line 70
    iget p0, p0, Lcom/squareup/moshi/JsonReader;->d:I

    .line 71
    .line 72
    add-int/lit8 p0, p0, -0x1

    .line 73
    .line 74
    aget v1, v0, p0

    .line 75
    .line 76
    add-int/lit8 v1, v1, -0x1

    .line 77
    .line 78
    aput v1, v0, p0

    .line 79
    .line 80
    :cond_4
    return p1

    .line 81
    :cond_5
    :goto_0
    return v2
.end method

.method public final j()Z
    .locals 4

    .line 1
    iget v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->x0()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    :cond_0
    const/4 v1, 0x5

    .line 10
    const/4 v2, 0x0

    .line 11
    const/4 v3, 0x1

    .line 12
    if-ne v0, v1, :cond_1

    .line 13
    .line 14
    iput v2, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 15
    .line 16
    iget-object v0, p0, Lcom/squareup/moshi/JsonReader;->g:[I

    .line 17
    .line 18
    iget p0, p0, Lcom/squareup/moshi/JsonReader;->d:I

    .line 19
    .line 20
    sub-int/2addr p0, v3

    .line 21
    aget v1, v0, p0

    .line 22
    .line 23
    add-int/2addr v1, v3

    .line 24
    aput v1, v0, p0

    .line 25
    .line 26
    return v3

    .line 27
    :cond_1
    const/4 v1, 0x6

    .line 28
    if-ne v0, v1, :cond_2

    .line 29
    .line 30
    iput v2, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 31
    .line 32
    iget-object v0, p0, Lcom/squareup/moshi/JsonReader;->g:[I

    .line 33
    .line 34
    iget p0, p0, Lcom/squareup/moshi/JsonReader;->d:I

    .line 35
    .line 36
    sub-int/2addr p0, v3

    .line 37
    aget v1, v0, p0

    .line 38
    .line 39
    add-int/2addr v1, v3

    .line 40
    aput v1, v0, p0

    .line 41
    .line 42
    return v2

    .line 43
    :cond_2
    new-instance v0, Lcom/squareup/moshi/JsonDataException;

    .line 44
    .line 45
    new-instance v1, Ljava/lang/StringBuilder;

    .line 46
    .line 47
    const-string v2, "Expected a boolean but was "

    .line 48
    .line 49
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->T()Lcom/squareup/moshi/JsonReader$Token;

    .line 53
    .line 54
    .line 55
    move-result-object v2

    .line 56
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    const-string v2, " at path "

    .line 60
    .line 61
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonReader;->g()Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 69
    .line 70
    .line 71
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    throw v0
.end method

.method public final k()D
    .locals 8

    .line 1
    iget v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->x0()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    :cond_0
    const/16 v1, 0x10

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    if-ne v0, v1, :cond_1

    .line 13
    .line 14
    iput v2, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 15
    .line 16
    iget-object v0, p0, Lcom/squareup/moshi/JsonReader;->g:[I

    .line 17
    .line 18
    iget v1, p0, Lcom/squareup/moshi/JsonReader;->d:I

    .line 19
    .line 20
    add-int/lit8 v1, v1, -0x1

    .line 21
    .line 22
    aget v2, v0, v1

    .line 23
    .line 24
    add-int/lit8 v2, v2, 0x1

    .line 25
    .line 26
    aput v2, v0, v1

    .line 27
    .line 28
    iget-wide v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->m:J

    .line 29
    .line 30
    long-to-double v0, v0

    .line 31
    return-wide v0

    .line 32
    :cond_1
    const/16 v1, 0x11

    .line 33
    .line 34
    const-string v3, "Expected a double but was "

    .line 35
    .line 36
    const/16 v4, 0xb

    .line 37
    .line 38
    const-string v5, " at path "

    .line 39
    .line 40
    if-ne v0, v1, :cond_2

    .line 41
    .line 42
    iget v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->n:I

    .line 43
    .line 44
    int-to-long v0, v0

    .line 45
    iget-object v6, p0, Lcom/squareup/moshi/JsonUtf8Reader;->k:Lu01/f;

    .line 46
    .line 47
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 48
    .line 49
    .line 50
    sget-object v7, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 51
    .line 52
    invoke-virtual {v6, v0, v1, v7}, Lu01/f;->M(JLjava/nio/charset/Charset;)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    iput-object v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->o:Ljava/lang/String;

    .line 57
    .line 58
    goto :goto_0

    .line 59
    :cond_2
    const/16 v1, 0x9

    .line 60
    .line 61
    if-ne v0, v1, :cond_3

    .line 62
    .line 63
    sget-object v0, Lcom/squareup/moshi/JsonUtf8Reader;->q:Lu01/i;

    .line 64
    .line 65
    invoke-virtual {p0, v0}, Lcom/squareup/moshi/JsonUtf8Reader;->C0(Lu01/i;)Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    iput-object v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->o:Ljava/lang/String;

    .line 70
    .line 71
    goto :goto_0

    .line 72
    :cond_3
    const/16 v1, 0x8

    .line 73
    .line 74
    if-ne v0, v1, :cond_4

    .line 75
    .line 76
    sget-object v0, Lcom/squareup/moshi/JsonUtf8Reader;->p:Lu01/i;

    .line 77
    .line 78
    invoke-virtual {p0, v0}, Lcom/squareup/moshi/JsonUtf8Reader;->C0(Lu01/i;)Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object v0

    .line 82
    iput-object v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->o:Ljava/lang/String;

    .line 83
    .line 84
    goto :goto_0

    .line 85
    :cond_4
    const/16 v1, 0xa

    .line 86
    .line 87
    if-ne v0, v1, :cond_5

    .line 88
    .line 89
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->D0()Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object v0

    .line 93
    iput-object v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->o:Ljava/lang/String;

    .line 94
    .line 95
    goto :goto_0

    .line 96
    :cond_5
    if-ne v0, v4, :cond_8

    .line 97
    .line 98
    :goto_0
    iput v4, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 99
    .line 100
    :try_start_0
    iget-object v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->o:Ljava/lang/String;

    .line 101
    .line 102
    invoke-static {v0}, Ljava/lang/Double;->parseDouble(Ljava/lang/String;)D

    .line 103
    .line 104
    .line 105
    move-result-wide v0
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    .line 106
    iget-boolean v3, p0, Lcom/squareup/moshi/JsonReader;->h:Z

    .line 107
    .line 108
    if-nez v3, :cond_7

    .line 109
    .line 110
    invoke-static {v0, v1}, Ljava/lang/Double;->isNaN(D)Z

    .line 111
    .line 112
    .line 113
    move-result v3

    .line 114
    if-nez v3, :cond_6

    .line 115
    .line 116
    invoke-static {v0, v1}, Ljava/lang/Double;->isInfinite(D)Z

    .line 117
    .line 118
    .line 119
    move-result v3

    .line 120
    if-nez v3, :cond_6

    .line 121
    .line 122
    goto :goto_1

    .line 123
    :cond_6
    new-instance v2, Lcom/squareup/moshi/JsonEncodingException;

    .line 124
    .line 125
    const-string v3, "JSON forbids NaN and infinities: "

    .line 126
    .line 127
    invoke-static {v3, v5, v0, v1}, Lp3/m;->r(Ljava/lang/String;Ljava/lang/String;D)Ljava/lang/StringBuilder;

    .line 128
    .line 129
    .line 130
    move-result-object v0

    .line 131
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonReader;->g()Ljava/lang/String;

    .line 132
    .line 133
    .line 134
    move-result-object p0

    .line 135
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 136
    .line 137
    .line 138
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    invoke-direct {v2, p0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 143
    .line 144
    .line 145
    throw v2

    .line 146
    :cond_7
    :goto_1
    const/4 v3, 0x0

    .line 147
    iput-object v3, p0, Lcom/squareup/moshi/JsonUtf8Reader;->o:Ljava/lang/String;

    .line 148
    .line 149
    iput v2, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 150
    .line 151
    iget-object v2, p0, Lcom/squareup/moshi/JsonReader;->g:[I

    .line 152
    .line 153
    iget p0, p0, Lcom/squareup/moshi/JsonReader;->d:I

    .line 154
    .line 155
    add-int/lit8 p0, p0, -0x1

    .line 156
    .line 157
    aget v3, v2, p0

    .line 158
    .line 159
    add-int/lit8 v3, v3, 0x1

    .line 160
    .line 161
    aput v3, v2, p0

    .line 162
    .line 163
    return-wide v0

    .line 164
    :catch_0
    new-instance v0, Lcom/squareup/moshi/JsonDataException;

    .line 165
    .line 166
    new-instance v1, Ljava/lang/StringBuilder;

    .line 167
    .line 168
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 169
    .line 170
    .line 171
    iget-object v2, p0, Lcom/squareup/moshi/JsonUtf8Reader;->o:Ljava/lang/String;

    .line 172
    .line 173
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 174
    .line 175
    .line 176
    invoke-virtual {v1, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 177
    .line 178
    .line 179
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonReader;->g()Ljava/lang/String;

    .line 180
    .line 181
    .line 182
    move-result-object p0

    .line 183
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 184
    .line 185
    .line 186
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 187
    .line 188
    .line 189
    move-result-object p0

    .line 190
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 191
    .line 192
    .line 193
    throw v0

    .line 194
    :cond_8
    new-instance v0, Lcom/squareup/moshi/JsonDataException;

    .line 195
    .line 196
    new-instance v1, Ljava/lang/StringBuilder;

    .line 197
    .line 198
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 199
    .line 200
    .line 201
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->T()Lcom/squareup/moshi/JsonReader$Token;

    .line 202
    .line 203
    .line 204
    move-result-object v2

    .line 205
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 206
    .line 207
    .line 208
    invoke-virtual {v1, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 209
    .line 210
    .line 211
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonReader;->g()Ljava/lang/String;

    .line 212
    .line 213
    .line 214
    move-result-object p0

    .line 215
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 216
    .line 217
    .line 218
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 219
    .line 220
    .line 221
    move-result-object p0

    .line 222
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 223
    .line 224
    .line 225
    throw v0
.end method

.method public final k0()V
    .locals 4

    .line 1
    iget-boolean v0, p0, Lcom/squareup/moshi/JsonReader;->i:Z

    .line 2
    .line 3
    if-nez v0, :cond_6

    .line 4
    .line 5
    iget v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->x0()I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    :cond_0
    const/16 v1, 0xe

    .line 14
    .line 15
    if-ne v0, v1, :cond_2

    .line 16
    .line 17
    iget-object v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->j:Lu01/h;

    .line 18
    .line 19
    sget-object v1, Lcom/squareup/moshi/JsonUtf8Reader;->r:Lu01/i;

    .line 20
    .line 21
    invoke-interface {v0, v1}, Lu01/h;->y(Lu01/i;)J

    .line 22
    .line 23
    .line 24
    move-result-wide v0

    .line 25
    const-wide/16 v2, -0x1

    .line 26
    .line 27
    cmp-long v2, v0, v2

    .line 28
    .line 29
    iget-object v3, p0, Lcom/squareup/moshi/JsonUtf8Reader;->k:Lu01/f;

    .line 30
    .line 31
    if-eqz v2, :cond_1

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_1
    iget-wide v0, v3, Lu01/f;->e:J

    .line 35
    .line 36
    :goto_0
    invoke-virtual {v3, v0, v1}, Lu01/f;->skip(J)V

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_2
    const/16 v1, 0xd

    .line 41
    .line 42
    if-ne v0, v1, :cond_3

    .line 43
    .line 44
    sget-object v0, Lcom/squareup/moshi/JsonUtf8Reader;->q:Lu01/i;

    .line 45
    .line 46
    invoke-virtual {p0, v0}, Lcom/squareup/moshi/JsonUtf8Reader;->F0(Lu01/i;)V

    .line 47
    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_3
    const/16 v1, 0xc

    .line 51
    .line 52
    if-ne v0, v1, :cond_4

    .line 53
    .line 54
    sget-object v0, Lcom/squareup/moshi/JsonUtf8Reader;->p:Lu01/i;

    .line 55
    .line 56
    invoke-virtual {p0, v0}, Lcom/squareup/moshi/JsonUtf8Reader;->F0(Lu01/i;)V

    .line 57
    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_4
    const/16 v1, 0xf

    .line 61
    .line 62
    if-ne v0, v1, :cond_5

    .line 63
    .line 64
    :goto_1
    const/4 v0, 0x0

    .line 65
    iput v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 66
    .line 67
    iget-object v0, p0, Lcom/squareup/moshi/JsonReader;->f:[Ljava/lang/String;

    .line 68
    .line 69
    iget p0, p0, Lcom/squareup/moshi/JsonReader;->d:I

    .line 70
    .line 71
    add-int/lit8 p0, p0, -0x1

    .line 72
    .line 73
    const-string v1, "null"

    .line 74
    .line 75
    aput-object v1, v0, p0

    .line 76
    .line 77
    return-void

    .line 78
    :cond_5
    new-instance v0, Lcom/squareup/moshi/JsonDataException;

    .line 79
    .line 80
    new-instance v1, Ljava/lang/StringBuilder;

    .line 81
    .line 82
    const-string v2, "Expected a name but was "

    .line 83
    .line 84
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->T()Lcom/squareup/moshi/JsonReader$Token;

    .line 88
    .line 89
    .line 90
    move-result-object v2

    .line 91
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    const-string v2, " at path "

    .line 95
    .line 96
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 97
    .line 98
    .line 99
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonReader;->g()Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 104
    .line 105
    .line 106
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 111
    .line 112
    .line 113
    throw v0

    .line 114
    :cond_6
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->T()Lcom/squareup/moshi/JsonReader$Token;

    .line 115
    .line 116
    .line 117
    move-result-object v0

    .line 118
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->B()Ljava/lang/String;

    .line 119
    .line 120
    .line 121
    new-instance v1, Lcom/squareup/moshi/JsonDataException;

    .line 122
    .line 123
    new-instance v2, Ljava/lang/StringBuilder;

    .line 124
    .line 125
    const-string v3, "Cannot skip unexpected "

    .line 126
    .line 127
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 128
    .line 129
    .line 130
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 131
    .line 132
    .line 133
    const-string v0, " at "

    .line 134
    .line 135
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 136
    .line 137
    .line 138
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonReader;->g()Ljava/lang/String;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 143
    .line 144
    .line 145
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 146
    .line 147
    .line 148
    move-result-object p0

    .line 149
    invoke-direct {v1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 150
    .line 151
    .line 152
    throw v1
.end method

.method public final l()I
    .locals 8

    .line 1
    iget v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->x0()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    :cond_0
    const/16 v1, 0x10

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    const-string v3, " at path "

    .line 13
    .line 14
    const-string v4, "Expected an int but was "

    .line 15
    .line 16
    if-ne v0, v1, :cond_2

    .line 17
    .line 18
    iget-wide v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->m:J

    .line 19
    .line 20
    long-to-int v5, v0

    .line 21
    int-to-long v6, v5

    .line 22
    cmp-long v0, v0, v6

    .line 23
    .line 24
    if-nez v0, :cond_1

    .line 25
    .line 26
    iput v2, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 27
    .line 28
    iget-object v0, p0, Lcom/squareup/moshi/JsonReader;->g:[I

    .line 29
    .line 30
    iget p0, p0, Lcom/squareup/moshi/JsonReader;->d:I

    .line 31
    .line 32
    add-int/lit8 p0, p0, -0x1

    .line 33
    .line 34
    aget v1, v0, p0

    .line 35
    .line 36
    add-int/lit8 v1, v1, 0x1

    .line 37
    .line 38
    aput v1, v0, p0

    .line 39
    .line 40
    return v5

    .line 41
    :cond_1
    new-instance v0, Lcom/squareup/moshi/JsonDataException;

    .line 42
    .line 43
    new-instance v1, Ljava/lang/StringBuilder;

    .line 44
    .line 45
    invoke-direct {v1, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    iget-wide v4, p0, Lcom/squareup/moshi/JsonUtf8Reader;->m:J

    .line 49
    .line 50
    invoke-virtual {v1, v4, v5}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonReader;->g()Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    throw v0

    .line 71
    :cond_2
    const/16 v1, 0x11

    .line 72
    .line 73
    const/16 v5, 0xb

    .line 74
    .line 75
    if-ne v0, v1, :cond_3

    .line 76
    .line 77
    iget v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->n:I

    .line 78
    .line 79
    int-to-long v0, v0

    .line 80
    iget-object v6, p0, Lcom/squareup/moshi/JsonUtf8Reader;->k:Lu01/f;

    .line 81
    .line 82
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 83
    .line 84
    .line 85
    sget-object v7, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 86
    .line 87
    invoke-virtual {v6, v0, v1, v7}, Lu01/f;->M(JLjava/nio/charset/Charset;)Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object v0

    .line 91
    iput-object v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->o:Ljava/lang/String;

    .line 92
    .line 93
    goto :goto_2

    .line 94
    :cond_3
    const/16 v1, 0x9

    .line 95
    .line 96
    if-eq v0, v1, :cond_6

    .line 97
    .line 98
    const/16 v6, 0x8

    .line 99
    .line 100
    if-ne v0, v6, :cond_4

    .line 101
    .line 102
    goto :goto_0

    .line 103
    :cond_4
    if-ne v0, v5, :cond_5

    .line 104
    .line 105
    goto :goto_2

    .line 106
    :cond_5
    new-instance v0, Lcom/squareup/moshi/JsonDataException;

    .line 107
    .line 108
    new-instance v1, Ljava/lang/StringBuilder;

    .line 109
    .line 110
    invoke-direct {v1, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 111
    .line 112
    .line 113
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->T()Lcom/squareup/moshi/JsonReader$Token;

    .line 114
    .line 115
    .line 116
    move-result-object v2

    .line 117
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 118
    .line 119
    .line 120
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 121
    .line 122
    .line 123
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonReader;->g()Ljava/lang/String;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 128
    .line 129
    .line 130
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 135
    .line 136
    .line 137
    throw v0

    .line 138
    :cond_6
    :goto_0
    if-ne v0, v1, :cond_7

    .line 139
    .line 140
    sget-object v0, Lcom/squareup/moshi/JsonUtf8Reader;->q:Lu01/i;

    .line 141
    .line 142
    invoke-virtual {p0, v0}, Lcom/squareup/moshi/JsonUtf8Reader;->C0(Lu01/i;)Ljava/lang/String;

    .line 143
    .line 144
    .line 145
    move-result-object v0

    .line 146
    goto :goto_1

    .line 147
    :cond_7
    sget-object v0, Lcom/squareup/moshi/JsonUtf8Reader;->p:Lu01/i;

    .line 148
    .line 149
    invoke-virtual {p0, v0}, Lcom/squareup/moshi/JsonUtf8Reader;->C0(Lu01/i;)Ljava/lang/String;

    .line 150
    .line 151
    .line 152
    move-result-object v0

    .line 153
    :goto_1
    iput-object v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->o:Ljava/lang/String;

    .line 154
    .line 155
    :try_start_0
    invoke-static {v0}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 156
    .line 157
    .line 158
    move-result v0

    .line 159
    iput v2, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 160
    .line 161
    iget-object v1, p0, Lcom/squareup/moshi/JsonReader;->g:[I

    .line 162
    .line 163
    iget v6, p0, Lcom/squareup/moshi/JsonReader;->d:I

    .line 164
    .line 165
    add-int/lit8 v6, v6, -0x1

    .line 166
    .line 167
    aget v7, v1, v6

    .line 168
    .line 169
    add-int/lit8 v7, v7, 0x1

    .line 170
    .line 171
    aput v7, v1, v6
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    .line 172
    .line 173
    return v0

    .line 174
    :catch_0
    :goto_2
    iput v5, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 175
    .line 176
    :try_start_1
    iget-object v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->o:Ljava/lang/String;

    .line 177
    .line 178
    invoke-static {v0}, Ljava/lang/Double;->parseDouble(Ljava/lang/String;)D

    .line 179
    .line 180
    .line 181
    move-result-wide v0
    :try_end_1
    .catch Ljava/lang/NumberFormatException; {:try_start_1 .. :try_end_1} :catch_1

    .line 182
    double-to-int v5, v0

    .line 183
    int-to-double v6, v5

    .line 184
    cmpl-double v0, v6, v0

    .line 185
    .line 186
    if-nez v0, :cond_8

    .line 187
    .line 188
    const/4 v0, 0x0

    .line 189
    iput-object v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->o:Ljava/lang/String;

    .line 190
    .line 191
    iput v2, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 192
    .line 193
    iget-object v0, p0, Lcom/squareup/moshi/JsonReader;->g:[I

    .line 194
    .line 195
    iget p0, p0, Lcom/squareup/moshi/JsonReader;->d:I

    .line 196
    .line 197
    add-int/lit8 p0, p0, -0x1

    .line 198
    .line 199
    aget v1, v0, p0

    .line 200
    .line 201
    add-int/lit8 v1, v1, 0x1

    .line 202
    .line 203
    aput v1, v0, p0

    .line 204
    .line 205
    return v5

    .line 206
    :cond_8
    new-instance v0, Lcom/squareup/moshi/JsonDataException;

    .line 207
    .line 208
    new-instance v1, Ljava/lang/StringBuilder;

    .line 209
    .line 210
    invoke-direct {v1, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 211
    .line 212
    .line 213
    iget-object v2, p0, Lcom/squareup/moshi/JsonUtf8Reader;->o:Ljava/lang/String;

    .line 214
    .line 215
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 216
    .line 217
    .line 218
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 219
    .line 220
    .line 221
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonReader;->g()Ljava/lang/String;

    .line 222
    .line 223
    .line 224
    move-result-object p0

    .line 225
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 226
    .line 227
    .line 228
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 229
    .line 230
    .line 231
    move-result-object p0

    .line 232
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 233
    .line 234
    .line 235
    throw v0

    .line 236
    :catch_1
    new-instance v0, Lcom/squareup/moshi/JsonDataException;

    .line 237
    .line 238
    new-instance v1, Ljava/lang/StringBuilder;

    .line 239
    .line 240
    invoke-direct {v1, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 241
    .line 242
    .line 243
    iget-object v2, p0, Lcom/squareup/moshi/JsonUtf8Reader;->o:Ljava/lang/String;

    .line 244
    .line 245
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 246
    .line 247
    .line 248
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 249
    .line 250
    .line 251
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonReader;->g()Ljava/lang/String;

    .line 252
    .line 253
    .line 254
    move-result-object p0

    .line 255
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 256
    .line 257
    .line 258
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 259
    .line 260
    .line 261
    move-result-object p0

    .line 262
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 263
    .line 264
    .line 265
    throw v0
.end method

.method public final l0()V
    .locals 8

    .line 1
    iget-boolean v0, p0, Lcom/squareup/moshi/JsonReader;->i:Z

    .line 2
    .line 3
    if-nez v0, :cond_11

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    move v1, v0

    .line 7
    :cond_0
    iget v2, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 8
    .line 9
    if-nez v2, :cond_1

    .line 10
    .line 11
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->x0()I

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    :cond_1
    const/4 v3, 0x3

    .line 16
    const/4 v4, 0x1

    .line 17
    if-ne v2, v3, :cond_2

    .line 18
    .line 19
    invoke-virtual {p0, v4}, Lcom/squareup/moshi/JsonReader;->V(I)V

    .line 20
    .line 21
    .line 22
    :goto_0
    add-int/lit8 v1, v1, 0x1

    .line 23
    .line 24
    goto/16 :goto_5

    .line 25
    .line 26
    :cond_2
    if-ne v2, v4, :cond_3

    .line 27
    .line 28
    invoke-virtual {p0, v3}, Lcom/squareup/moshi/JsonReader;->V(I)V

    .line 29
    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_3
    const/4 v3, 0x4

    .line 33
    const-string v5, " at path "

    .line 34
    .line 35
    const-string v6, "Expected a value but was "

    .line 36
    .line 37
    if-ne v2, v3, :cond_5

    .line 38
    .line 39
    add-int/lit8 v1, v1, -0x1

    .line 40
    .line 41
    if-ltz v1, :cond_4

    .line 42
    .line 43
    iget v2, p0, Lcom/squareup/moshi/JsonReader;->d:I

    .line 44
    .line 45
    sub-int/2addr v2, v4

    .line 46
    iput v2, p0, Lcom/squareup/moshi/JsonReader;->d:I

    .line 47
    .line 48
    goto/16 :goto_5

    .line 49
    .line 50
    :cond_4
    new-instance v0, Lcom/squareup/moshi/JsonDataException;

    .line 51
    .line 52
    new-instance v1, Ljava/lang/StringBuilder;

    .line 53
    .line 54
    invoke-direct {v1, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->T()Lcom/squareup/moshi/JsonReader$Token;

    .line 58
    .line 59
    .line 60
    move-result-object v2

    .line 61
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    invoke-virtual {v1, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonReader;->g()Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    throw v0

    .line 82
    :cond_5
    const/4 v3, 0x2

    .line 83
    if-ne v2, v3, :cond_7

    .line 84
    .line 85
    add-int/lit8 v1, v1, -0x1

    .line 86
    .line 87
    if-ltz v1, :cond_6

    .line 88
    .line 89
    iget v2, p0, Lcom/squareup/moshi/JsonReader;->d:I

    .line 90
    .line 91
    sub-int/2addr v2, v4

    .line 92
    iput v2, p0, Lcom/squareup/moshi/JsonReader;->d:I

    .line 93
    .line 94
    goto/16 :goto_5

    .line 95
    .line 96
    :cond_6
    new-instance v0, Lcom/squareup/moshi/JsonDataException;

    .line 97
    .line 98
    new-instance v1, Ljava/lang/StringBuilder;

    .line 99
    .line 100
    invoke-direct {v1, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->T()Lcom/squareup/moshi/JsonReader$Token;

    .line 104
    .line 105
    .line 106
    move-result-object v2

    .line 107
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 108
    .line 109
    .line 110
    invoke-virtual {v1, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 111
    .line 112
    .line 113
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonReader;->g()Ljava/lang/String;

    .line 114
    .line 115
    .line 116
    move-result-object p0

    .line 117
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 118
    .line 119
    .line 120
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 121
    .line 122
    .line 123
    move-result-object p0

    .line 124
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 125
    .line 126
    .line 127
    throw v0

    .line 128
    :cond_7
    const/16 v3, 0xe

    .line 129
    .line 130
    iget-object v7, p0, Lcom/squareup/moshi/JsonUtf8Reader;->k:Lu01/f;

    .line 131
    .line 132
    if-eq v2, v3, :cond_f

    .line 133
    .line 134
    const/16 v3, 0xa

    .line 135
    .line 136
    if-ne v2, v3, :cond_8

    .line 137
    .line 138
    goto :goto_3

    .line 139
    :cond_8
    const/16 v3, 0x9

    .line 140
    .line 141
    if-eq v2, v3, :cond_e

    .line 142
    .line 143
    const/16 v3, 0xd

    .line 144
    .line 145
    if-ne v2, v3, :cond_9

    .line 146
    .line 147
    goto :goto_2

    .line 148
    :cond_9
    const/16 v3, 0x8

    .line 149
    .line 150
    if-eq v2, v3, :cond_d

    .line 151
    .line 152
    const/16 v3, 0xc

    .line 153
    .line 154
    if-ne v2, v3, :cond_a

    .line 155
    .line 156
    goto :goto_1

    .line 157
    :cond_a
    const/16 v3, 0x11

    .line 158
    .line 159
    if-ne v2, v3, :cond_b

    .line 160
    .line 161
    iget v2, p0, Lcom/squareup/moshi/JsonUtf8Reader;->n:I

    .line 162
    .line 163
    int-to-long v2, v2

    .line 164
    invoke-virtual {v7, v2, v3}, Lu01/f;->skip(J)V

    .line 165
    .line 166
    .line 167
    goto :goto_5

    .line 168
    :cond_b
    const/16 v3, 0x12

    .line 169
    .line 170
    if-eq v2, v3, :cond_c

    .line 171
    .line 172
    goto :goto_5

    .line 173
    :cond_c
    new-instance v0, Lcom/squareup/moshi/JsonDataException;

    .line 174
    .line 175
    new-instance v1, Ljava/lang/StringBuilder;

    .line 176
    .line 177
    invoke-direct {v1, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 178
    .line 179
    .line 180
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->T()Lcom/squareup/moshi/JsonReader$Token;

    .line 181
    .line 182
    .line 183
    move-result-object v2

    .line 184
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 185
    .line 186
    .line 187
    invoke-virtual {v1, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 188
    .line 189
    .line 190
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonReader;->g()Ljava/lang/String;

    .line 191
    .line 192
    .line 193
    move-result-object p0

    .line 194
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 195
    .line 196
    .line 197
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 198
    .line 199
    .line 200
    move-result-object p0

    .line 201
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 202
    .line 203
    .line 204
    throw v0

    .line 205
    :cond_d
    :goto_1
    sget-object v2, Lcom/squareup/moshi/JsonUtf8Reader;->p:Lu01/i;

    .line 206
    .line 207
    invoke-virtual {p0, v2}, Lcom/squareup/moshi/JsonUtf8Reader;->F0(Lu01/i;)V

    .line 208
    .line 209
    .line 210
    goto :goto_5

    .line 211
    :cond_e
    :goto_2
    sget-object v2, Lcom/squareup/moshi/JsonUtf8Reader;->q:Lu01/i;

    .line 212
    .line 213
    invoke-virtual {p0, v2}, Lcom/squareup/moshi/JsonUtf8Reader;->F0(Lu01/i;)V

    .line 214
    .line 215
    .line 216
    goto :goto_5

    .line 217
    :cond_f
    :goto_3
    iget-object v2, p0, Lcom/squareup/moshi/JsonUtf8Reader;->j:Lu01/h;

    .line 218
    .line 219
    sget-object v3, Lcom/squareup/moshi/JsonUtf8Reader;->r:Lu01/i;

    .line 220
    .line 221
    invoke-interface {v2, v3}, Lu01/h;->y(Lu01/i;)J

    .line 222
    .line 223
    .line 224
    move-result-wide v2

    .line 225
    const-wide/16 v5, -0x1

    .line 226
    .line 227
    cmp-long v5, v2, v5

    .line 228
    .line 229
    if-eqz v5, :cond_10

    .line 230
    .line 231
    goto :goto_4

    .line 232
    :cond_10
    iget-wide v2, v7, Lu01/f;->e:J

    .line 233
    .line 234
    :goto_4
    invoke-virtual {v7, v2, v3}, Lu01/f;->skip(J)V

    .line 235
    .line 236
    .line 237
    :goto_5
    iput v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 238
    .line 239
    if-nez v1, :cond_0

    .line 240
    .line 241
    iget-object v0, p0, Lcom/squareup/moshi/JsonReader;->g:[I

    .line 242
    .line 243
    iget v1, p0, Lcom/squareup/moshi/JsonReader;->d:I

    .line 244
    .line 245
    sub-int/2addr v1, v4

    .line 246
    aget v2, v0, v1

    .line 247
    .line 248
    add-int/2addr v2, v4

    .line 249
    aput v2, v0, v1

    .line 250
    .line 251
    iget-object p0, p0, Lcom/squareup/moshi/JsonReader;->f:[Ljava/lang/String;

    .line 252
    .line 253
    const-string v0, "null"

    .line 254
    .line 255
    aput-object v0, p0, v1

    .line 256
    .line 257
    return-void

    .line 258
    :cond_11
    new-instance v0, Lcom/squareup/moshi/JsonDataException;

    .line 259
    .line 260
    new-instance v1, Ljava/lang/StringBuilder;

    .line 261
    .line 262
    const-string v2, "Cannot skip unexpected "

    .line 263
    .line 264
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 265
    .line 266
    .line 267
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->T()Lcom/squareup/moshi/JsonReader$Token;

    .line 268
    .line 269
    .line 270
    move-result-object v2

    .line 271
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 272
    .line 273
    .line 274
    const-string v2, " at "

    .line 275
    .line 276
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 277
    .line 278
    .line 279
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonReader;->g()Ljava/lang/String;

    .line 280
    .line 281
    .line 282
    move-result-object p0

    .line 283
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 284
    .line 285
    .line 286
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 287
    .line 288
    .line 289
    move-result-object p0

    .line 290
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 291
    .line 292
    .line 293
    throw v0
.end method

.method public final q()J
    .locals 9

    .line 1
    iget v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->x0()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    :cond_0
    const/16 v1, 0x10

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    if-ne v0, v1, :cond_1

    .line 13
    .line 14
    iput v2, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 15
    .line 16
    iget-object v0, p0, Lcom/squareup/moshi/JsonReader;->g:[I

    .line 17
    .line 18
    iget v1, p0, Lcom/squareup/moshi/JsonReader;->d:I

    .line 19
    .line 20
    add-int/lit8 v1, v1, -0x1

    .line 21
    .line 22
    aget v2, v0, v1

    .line 23
    .line 24
    add-int/lit8 v2, v2, 0x1

    .line 25
    .line 26
    aput v2, v0, v1

    .line 27
    .line 28
    iget-wide v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->m:J

    .line 29
    .line 30
    return-wide v0

    .line 31
    :cond_1
    const/16 v1, 0x11

    .line 32
    .line 33
    const-string v3, " at path "

    .line 34
    .line 35
    const-string v4, "Expected a long but was "

    .line 36
    .line 37
    const/16 v5, 0xb

    .line 38
    .line 39
    if-ne v0, v1, :cond_2

    .line 40
    .line 41
    iget v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->n:I

    .line 42
    .line 43
    int-to-long v0, v0

    .line 44
    iget-object v6, p0, Lcom/squareup/moshi/JsonUtf8Reader;->k:Lu01/f;

    .line 45
    .line 46
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 47
    .line 48
    .line 49
    sget-object v7, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 50
    .line 51
    invoke-virtual {v6, v0, v1, v7}, Lu01/f;->M(JLjava/nio/charset/Charset;)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    iput-object v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->o:Ljava/lang/String;

    .line 56
    .line 57
    goto :goto_2

    .line 58
    :cond_2
    const/16 v1, 0x9

    .line 59
    .line 60
    if-eq v0, v1, :cond_5

    .line 61
    .line 62
    const/16 v6, 0x8

    .line 63
    .line 64
    if-ne v0, v6, :cond_3

    .line 65
    .line 66
    goto :goto_0

    .line 67
    :cond_3
    if-ne v0, v5, :cond_4

    .line 68
    .line 69
    goto :goto_2

    .line 70
    :cond_4
    new-instance v0, Lcom/squareup/moshi/JsonDataException;

    .line 71
    .line 72
    new-instance v1, Ljava/lang/StringBuilder;

    .line 73
    .line 74
    invoke-direct {v1, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Reader;->T()Lcom/squareup/moshi/JsonReader$Token;

    .line 78
    .line 79
    .line 80
    move-result-object v2

    .line 81
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonReader;->g()Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    throw v0

    .line 102
    :cond_5
    :goto_0
    if-ne v0, v1, :cond_6

    .line 103
    .line 104
    sget-object v0, Lcom/squareup/moshi/JsonUtf8Reader;->q:Lu01/i;

    .line 105
    .line 106
    invoke-virtual {p0, v0}, Lcom/squareup/moshi/JsonUtf8Reader;->C0(Lu01/i;)Ljava/lang/String;

    .line 107
    .line 108
    .line 109
    move-result-object v0

    .line 110
    goto :goto_1

    .line 111
    :cond_6
    sget-object v0, Lcom/squareup/moshi/JsonUtf8Reader;->p:Lu01/i;

    .line 112
    .line 113
    invoke-virtual {p0, v0}, Lcom/squareup/moshi/JsonUtf8Reader;->C0(Lu01/i;)Ljava/lang/String;

    .line 114
    .line 115
    .line 116
    move-result-object v0

    .line 117
    :goto_1
    iput-object v0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->o:Ljava/lang/String;

    .line 118
    .line 119
    :try_start_0
    invoke-static {v0}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    .line 120
    .line 121
    .line 122
    move-result-wide v0

    .line 123
    iput v2, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 124
    .line 125
    iget-object v6, p0, Lcom/squareup/moshi/JsonReader;->g:[I

    .line 126
    .line 127
    iget v7, p0, Lcom/squareup/moshi/JsonReader;->d:I

    .line 128
    .line 129
    add-int/lit8 v7, v7, -0x1

    .line 130
    .line 131
    aget v8, v6, v7

    .line 132
    .line 133
    add-int/lit8 v8, v8, 0x1

    .line 134
    .line 135
    aput v8, v6, v7
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    .line 136
    .line 137
    return-wide v0

    .line 138
    :catch_0
    :goto_2
    iput v5, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 139
    .line 140
    :try_start_1
    new-instance v0, Ljava/math/BigDecimal;

    .line 141
    .line 142
    iget-object v1, p0, Lcom/squareup/moshi/JsonUtf8Reader;->o:Ljava/lang/String;

    .line 143
    .line 144
    invoke-direct {v0, v1}, Ljava/math/BigDecimal;-><init>(Ljava/lang/String;)V

    .line 145
    .line 146
    .line 147
    invoke-virtual {v0}, Ljava/math/BigDecimal;->longValueExact()J

    .line 148
    .line 149
    .line 150
    move-result-wide v0
    :try_end_1
    .catch Ljava/lang/NumberFormatException; {:try_start_1 .. :try_end_1} :catch_1
    .catch Ljava/lang/ArithmeticException; {:try_start_1 .. :try_end_1} :catch_1

    .line 151
    const/4 v3, 0x0

    .line 152
    iput-object v3, p0, Lcom/squareup/moshi/JsonUtf8Reader;->o:Ljava/lang/String;

    .line 153
    .line 154
    iput v2, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 155
    .line 156
    iget-object v2, p0, Lcom/squareup/moshi/JsonReader;->g:[I

    .line 157
    .line 158
    iget p0, p0, Lcom/squareup/moshi/JsonReader;->d:I

    .line 159
    .line 160
    add-int/lit8 p0, p0, -0x1

    .line 161
    .line 162
    aget v3, v2, p0

    .line 163
    .line 164
    add-int/lit8 v3, v3, 0x1

    .line 165
    .line 166
    aput v3, v2, p0

    .line 167
    .line 168
    return-wide v0

    .line 169
    :catch_1
    new-instance v0, Lcom/squareup/moshi/JsonDataException;

    .line 170
    .line 171
    new-instance v1, Ljava/lang/StringBuilder;

    .line 172
    .line 173
    invoke-direct {v1, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 174
    .line 175
    .line 176
    iget-object v2, p0, Lcom/squareup/moshi/JsonUtf8Reader;->o:Ljava/lang/String;

    .line 177
    .line 178
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 179
    .line 180
    .line 181
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 182
    .line 183
    .line 184
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonReader;->g()Ljava/lang/String;

    .line 185
    .line 186
    .line 187
    move-result-object p0

    .line 188
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 189
    .line 190
    .line 191
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 192
    .line 193
    .line 194
    move-result-object p0

    .line 195
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 196
    .line 197
    .line 198
    throw v0
.end method

.method public final r0()V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lcom/squareup/moshi/JsonReader;->h:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    const-string v0, "Use JsonReader.setLenient(true) to accept malformed JSON"

    .line 7
    .line 8
    invoke-virtual {p0, v0}, Lcom/squareup/moshi/JsonReader;->n0(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const/4 p0, 0x0

    .line 12
    throw p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "JsonReader("

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lcom/squareup/moshi/JsonUtf8Reader;->j:Lu01/h;

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string p0, ")"

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

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

.method public final x0()I
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lcom/squareup/moshi/JsonReader;->e:[I

    .line 4
    .line 5
    iget v2, v0, Lcom/squareup/moshi/JsonReader;->d:I

    .line 6
    .line 7
    const/4 v3, 0x1

    .line 8
    sub-int/2addr v2, v3

    .line 9
    aget v4, v1, v2

    .line 10
    .line 11
    const/16 v10, 0x5d

    .line 12
    .line 13
    iget-object v13, v0, Lcom/squareup/moshi/JsonUtf8Reader;->j:Lu01/h;

    .line 14
    .line 15
    const/4 v14, 0x3

    .line 16
    const/16 v15, 0x3b

    .line 17
    .line 18
    const/16 v16, 0x0

    .line 19
    .line 20
    const/16 v5, 0x2c

    .line 21
    .line 22
    const-wide/16 v6, 0x0

    .line 23
    .line 24
    const/4 v9, 0x4

    .line 25
    const/4 v11, 0x5

    .line 26
    const/16 v21, 0x7

    .line 27
    .line 28
    const/4 v8, 0x2

    .line 29
    iget-object v12, v0, Lcom/squareup/moshi/JsonUtf8Reader;->k:Lu01/f;

    .line 30
    .line 31
    if-ne v4, v3, :cond_1

    .line 32
    .line 33
    aput v8, v1, v2

    .line 34
    .line 35
    :cond_0
    :goto_0
    const/4 v1, 0x0

    .line 36
    goto/16 :goto_1

    .line 37
    .line 38
    :cond_1
    if-ne v4, v8, :cond_4

    .line 39
    .line 40
    invoke-virtual {v0, v3}, Lcom/squareup/moshi/JsonUtf8Reader;->B0(Z)I

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    invoke-virtual {v12}, Lu01/f;->readByte()B

    .line 45
    .line 46
    .line 47
    if-eq v1, v5, :cond_0

    .line 48
    .line 49
    if-eq v1, v15, :cond_3

    .line 50
    .line 51
    if-ne v1, v10, :cond_2

    .line 52
    .line 53
    iput v9, v0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 54
    .line 55
    return v9

    .line 56
    :cond_2
    const-string v1, "Unterminated array"

    .line 57
    .line 58
    invoke-virtual {v0, v1}, Lcom/squareup/moshi/JsonReader;->n0(Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    throw v16

    .line 62
    :cond_3
    invoke-virtual {v0}, Lcom/squareup/moshi/JsonUtf8Reader;->r0()V

    .line 63
    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_4
    if-eq v4, v14, :cond_5

    .line 67
    .line 68
    if-ne v4, v11, :cond_6

    .line 69
    .line 70
    :cond_5
    move/from16 v22, v9

    .line 71
    .line 72
    goto/16 :goto_15

    .line 73
    .line 74
    :cond_6
    if-ne v4, v9, :cond_8

    .line 75
    .line 76
    aput v11, v1, v2

    .line 77
    .line 78
    invoke-virtual {v0, v3}, Lcom/squareup/moshi/JsonUtf8Reader;->B0(Z)I

    .line 79
    .line 80
    .line 81
    move-result v1

    .line 82
    invoke-virtual {v12}, Lu01/f;->readByte()B

    .line 83
    .line 84
    .line 85
    const/16 v2, 0x3a

    .line 86
    .line 87
    if-eq v1, v2, :cond_0

    .line 88
    .line 89
    const/16 v2, 0x3d

    .line 90
    .line 91
    if-ne v1, v2, :cond_7

    .line 92
    .line 93
    invoke-virtual {v0}, Lcom/squareup/moshi/JsonUtf8Reader;->r0()V

    .line 94
    .line 95
    .line 96
    const-wide/16 v1, 0x1

    .line 97
    .line 98
    invoke-interface {v13, v1, v2}, Lu01/h;->c(J)Z

    .line 99
    .line 100
    .line 101
    move-result v1

    .line 102
    if-eqz v1, :cond_0

    .line 103
    .line 104
    invoke-virtual {v12, v6, v7}, Lu01/f;->h(J)B

    .line 105
    .line 106
    .line 107
    move-result v1

    .line 108
    const/16 v2, 0x3e

    .line 109
    .line 110
    if-ne v1, v2, :cond_0

    .line 111
    .line 112
    invoke-virtual {v12}, Lu01/f;->readByte()B

    .line 113
    .line 114
    .line 115
    goto :goto_0

    .line 116
    :cond_7
    const-string v1, "Expected \':\'"

    .line 117
    .line 118
    invoke-virtual {v0, v1}, Lcom/squareup/moshi/JsonReader;->n0(Ljava/lang/String;)V

    .line 119
    .line 120
    .line 121
    throw v16

    .line 122
    :cond_8
    const/4 v9, 0x6

    .line 123
    if-ne v4, v9, :cond_9

    .line 124
    .line 125
    aput v21, v1, v2

    .line 126
    .line 127
    goto :goto_0

    .line 128
    :cond_9
    move/from16 v1, v21

    .line 129
    .line 130
    if-ne v4, v1, :cond_b

    .line 131
    .line 132
    const/4 v1, 0x0

    .line 133
    invoke-virtual {v0, v1}, Lcom/squareup/moshi/JsonUtf8Reader;->B0(Z)I

    .line 134
    .line 135
    .line 136
    move-result v2

    .line 137
    const/4 v9, -0x1

    .line 138
    if-ne v2, v9, :cond_a

    .line 139
    .line 140
    const/16 v1, 0x12

    .line 141
    .line 142
    iput v1, v0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 143
    .line 144
    return v1

    .line 145
    :cond_a
    invoke-virtual {v0}, Lcom/squareup/moshi/JsonUtf8Reader;->r0()V

    .line 146
    .line 147
    .line 148
    goto :goto_1

    .line 149
    :cond_b
    const/4 v1, 0x0

    .line 150
    const/16 v2, 0x9

    .line 151
    .line 152
    if-eq v4, v2, :cond_3a

    .line 153
    .line 154
    const/16 v2, 0x8

    .line 155
    .line 156
    if-eq v4, v2, :cond_39

    .line 157
    .line 158
    :goto_1
    invoke-virtual {v0, v3}, Lcom/squareup/moshi/JsonUtf8Reader;->B0(Z)I

    .line 159
    .line 160
    .line 161
    move-result v2

    .line 162
    const/16 v9, 0x22

    .line 163
    .line 164
    if-eq v2, v9, :cond_38

    .line 165
    .line 166
    const/16 v9, 0x27

    .line 167
    .line 168
    if-eq v2, v9, :cond_37

    .line 169
    .line 170
    if-eq v2, v5, :cond_34

    .line 171
    .line 172
    if-eq v2, v15, :cond_34

    .line 173
    .line 174
    const/16 v5, 0x5b

    .line 175
    .line 176
    if-eq v2, v5, :cond_33

    .line 177
    .line 178
    if-eq v2, v10, :cond_32

    .line 179
    .line 180
    const/16 v4, 0x7b

    .line 181
    .line 182
    if-eq v2, v4, :cond_31

    .line 183
    .line 184
    invoke-virtual {v12, v6, v7}, Lu01/f;->h(J)B

    .line 185
    .line 186
    .line 187
    move-result v2

    .line 188
    const/16 v4, 0x74

    .line 189
    .line 190
    if-eq v2, v4, :cond_11

    .line 191
    .line 192
    const/16 v4, 0x54

    .line 193
    .line 194
    if-ne v2, v4, :cond_c

    .line 195
    .line 196
    goto :goto_4

    .line 197
    :cond_c
    const/16 v4, 0x66

    .line 198
    .line 199
    if-eq v2, v4, :cond_10

    .line 200
    .line 201
    const/16 v4, 0x46

    .line 202
    .line 203
    if-ne v2, v4, :cond_d

    .line 204
    .line 205
    goto :goto_3

    .line 206
    :cond_d
    const/16 v4, 0x6e

    .line 207
    .line 208
    if-eq v2, v4, :cond_f

    .line 209
    .line 210
    const/16 v4, 0x4e

    .line 211
    .line 212
    if-ne v2, v4, :cond_e

    .line 213
    .line 214
    goto :goto_2

    .line 215
    :cond_e
    move v5, v1

    .line 216
    move-wide/from16 v17, v6

    .line 217
    .line 218
    goto :goto_8

    .line 219
    :cond_f
    :goto_2
    const-string v2, "null"

    .line 220
    .line 221
    const-string v4, "NULL"

    .line 222
    .line 223
    const/4 v5, 0x7

    .line 224
    goto :goto_5

    .line 225
    :cond_10
    :goto_3
    const-string v2, "false"

    .line 226
    .line 227
    const-string v4, "FALSE"

    .line 228
    .line 229
    const/4 v5, 0x6

    .line 230
    goto :goto_5

    .line 231
    :cond_11
    :goto_4
    const-string v2, "true"

    .line 232
    .line 233
    const-string v4, "TRUE"

    .line 234
    .line 235
    move v5, v11

    .line 236
    :goto_5
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 237
    .line 238
    .line 239
    move-result v9

    .line 240
    move v10, v3

    .line 241
    :goto_6
    if-ge v10, v9, :cond_14

    .line 242
    .line 243
    add-int/lit8 v15, v10, 0x1

    .line 244
    .line 245
    move-wide/from16 v17, v6

    .line 246
    .line 247
    int-to-long v6, v15

    .line 248
    invoke-interface {v13, v6, v7}, Lu01/h;->c(J)Z

    .line 249
    .line 250
    .line 251
    move-result v6

    .line 252
    if-nez v6, :cond_12

    .line 253
    .line 254
    :goto_7
    move v5, v1

    .line 255
    goto :goto_8

    .line 256
    :cond_12
    int-to-long v6, v10

    .line 257
    invoke-virtual {v12, v6, v7}, Lu01/f;->h(J)B

    .line 258
    .line 259
    .line 260
    move-result v6

    .line 261
    invoke-virtual {v2, v10}, Ljava/lang/String;->charAt(I)C

    .line 262
    .line 263
    .line 264
    move-result v7

    .line 265
    if-eq v6, v7, :cond_13

    .line 266
    .line 267
    invoke-virtual {v4, v10}, Ljava/lang/String;->charAt(I)C

    .line 268
    .line 269
    .line 270
    move-result v7

    .line 271
    if-eq v6, v7, :cond_13

    .line 272
    .line 273
    goto :goto_7

    .line 274
    :cond_13
    move v10, v15

    .line 275
    move-wide/from16 v6, v17

    .line 276
    .line 277
    goto :goto_6

    .line 278
    :cond_14
    move-wide/from16 v17, v6

    .line 279
    .line 280
    add-int/lit8 v2, v9, 0x1

    .line 281
    .line 282
    int-to-long v6, v2

    .line 283
    invoke-interface {v13, v6, v7}, Lu01/h;->c(J)Z

    .line 284
    .line 285
    .line 286
    move-result v2

    .line 287
    if-eqz v2, :cond_15

    .line 288
    .line 289
    int-to-long v6, v9

    .line 290
    invoke-virtual {v12, v6, v7}, Lu01/f;->h(J)B

    .line 291
    .line 292
    .line 293
    move-result v2

    .line 294
    invoke-virtual {v0, v2}, Lcom/squareup/moshi/JsonUtf8Reader;->A0(I)Z

    .line 295
    .line 296
    .line 297
    move-result v2

    .line 298
    if-eqz v2, :cond_15

    .line 299
    .line 300
    goto :goto_7

    .line 301
    :cond_15
    int-to-long v6, v9

    .line 302
    invoke-virtual {v12, v6, v7}, Lu01/f;->skip(J)V

    .line 303
    .line 304
    .line 305
    iput v5, v0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 306
    .line 307
    :goto_8
    if-eqz v5, :cond_16

    .line 308
    .line 309
    return v5

    .line 310
    :cond_16
    move v2, v1

    .line 311
    move v4, v2

    .line 312
    move v9, v4

    .line 313
    move v5, v3

    .line 314
    move-wide/from16 v6, v17

    .line 315
    .line 316
    :goto_9
    add-int/lit8 v10, v4, 0x1

    .line 317
    .line 318
    int-to-long v14, v10

    .line 319
    invoke-interface {v13, v14, v15}, Lu01/h;->c(J)Z

    .line 320
    .line 321
    .line 322
    move-result v14

    .line 323
    if-nez v14, :cond_17

    .line 324
    .line 325
    goto/16 :goto_f

    .line 326
    .line 327
    :cond_17
    int-to-long v14, v4

    .line 328
    invoke-virtual {v12, v14, v15}, Lu01/f;->h(J)B

    .line 329
    .line 330
    .line 331
    move-result v14

    .line 332
    const/16 v15, 0x2b

    .line 333
    .line 334
    if-eq v14, v15, :cond_2d

    .line 335
    .line 336
    const/16 v15, 0x45

    .line 337
    .line 338
    if-eq v14, v15, :cond_2b

    .line 339
    .line 340
    const/16 v15, 0x65

    .line 341
    .line 342
    if-eq v14, v15, :cond_2b

    .line 343
    .line 344
    const/16 v15, 0x2d

    .line 345
    .line 346
    if-eq v14, v15, :cond_29

    .line 347
    .line 348
    const/16 v15, 0x2e

    .line 349
    .line 350
    if-eq v14, v15, :cond_28

    .line 351
    .line 352
    const/16 v15, 0x30

    .line 353
    .line 354
    if-lt v14, v15, :cond_22

    .line 355
    .line 356
    const/16 v15, 0x39

    .line 357
    .line 358
    if-le v14, v15, :cond_18

    .line 359
    .line 360
    goto :goto_e

    .line 361
    :cond_18
    if-eq v2, v3, :cond_19

    .line 362
    .line 363
    if-nez v2, :cond_1a

    .line 364
    .line 365
    :cond_19
    const/4 v15, 0x6

    .line 366
    goto :goto_d

    .line 367
    :cond_1a
    if-ne v2, v8, :cond_1f

    .line 368
    .line 369
    cmp-long v4, v6, v17

    .line 370
    .line 371
    if-nez v4, :cond_1c

    .line 372
    .line 373
    :cond_1b
    move v11, v1

    .line 374
    goto/16 :goto_13

    .line 375
    .line 376
    :cond_1c
    const-wide/16 v19, 0xa

    .line 377
    .line 378
    mul-long v19, v19, v6

    .line 379
    .line 380
    add-int/lit8 v14, v14, -0x30

    .line 381
    .line 382
    int-to-long v14, v14

    .line 383
    sub-long v19, v19, v14

    .line 384
    .line 385
    const-wide v14, -0xcccccccccccccccL

    .line 386
    .line 387
    .line 388
    .line 389
    .line 390
    cmp-long v4, v6, v14

    .line 391
    .line 392
    if-gtz v4, :cond_1e

    .line 393
    .line 394
    if-nez v4, :cond_1d

    .line 395
    .line 396
    cmp-long v4, v19, v6

    .line 397
    .line 398
    if-gez v4, :cond_1d

    .line 399
    .line 400
    goto :goto_a

    .line 401
    :cond_1d
    move v4, v1

    .line 402
    goto :goto_b

    .line 403
    :cond_1e
    :goto_a
    move v4, v3

    .line 404
    :goto_b
    and-int/2addr v5, v4

    .line 405
    move-wide/from16 v6, v19

    .line 406
    .line 407
    :goto_c
    const/4 v15, 0x6

    .line 408
    goto/16 :goto_12

    .line 409
    .line 410
    :cond_1f
    const/4 v4, 0x3

    .line 411
    if-ne v2, v4, :cond_20

    .line 412
    .line 413
    const/4 v2, 0x4

    .line 414
    goto :goto_c

    .line 415
    :cond_20
    const/4 v15, 0x6

    .line 416
    if-eq v2, v11, :cond_21

    .line 417
    .line 418
    if-ne v2, v15, :cond_2e

    .line 419
    .line 420
    :cond_21
    const/4 v2, 0x7

    .line 421
    goto/16 :goto_12

    .line 422
    .line 423
    :goto_d
    add-int/lit8 v14, v14, -0x30

    .line 424
    .line 425
    neg-int v2, v14

    .line 426
    int-to-long v6, v2

    .line 427
    move v2, v8

    .line 428
    goto :goto_12

    .line 429
    :cond_22
    :goto_e
    invoke-virtual {v0, v14}, Lcom/squareup/moshi/JsonUtf8Reader;->A0(I)Z

    .line 430
    .line 431
    .line 432
    move-result v3

    .line 433
    if-nez v3, :cond_1b

    .line 434
    .line 435
    :goto_f
    if-ne v2, v8, :cond_26

    .line 436
    .line 437
    if-eqz v5, :cond_26

    .line 438
    .line 439
    const-wide/high16 v10, -0x8000000000000000L

    .line 440
    .line 441
    cmp-long v3, v6, v10

    .line 442
    .line 443
    if-nez v3, :cond_23

    .line 444
    .line 445
    if-eqz v9, :cond_26

    .line 446
    .line 447
    :cond_23
    cmp-long v3, v6, v17

    .line 448
    .line 449
    if-nez v3, :cond_24

    .line 450
    .line 451
    if-nez v9, :cond_26

    .line 452
    .line 453
    :cond_24
    if-eqz v9, :cond_25

    .line 454
    .line 455
    goto :goto_10

    .line 456
    :cond_25
    neg-long v6, v6

    .line 457
    :goto_10
    iput-wide v6, v0, Lcom/squareup/moshi/JsonUtf8Reader;->m:J

    .line 458
    .line 459
    int-to-long v1, v4

    .line 460
    invoke-virtual {v12, v1, v2}, Lu01/f;->skip(J)V

    .line 461
    .line 462
    .line 463
    const/16 v11, 0x10

    .line 464
    .line 465
    iput v11, v0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 466
    .line 467
    goto :goto_13

    .line 468
    :cond_26
    if-eq v2, v8, :cond_27

    .line 469
    .line 470
    const/4 v3, 0x4

    .line 471
    if-eq v2, v3, :cond_27

    .line 472
    .line 473
    const/4 v3, 0x7

    .line 474
    if-ne v2, v3, :cond_1b

    .line 475
    .line 476
    :cond_27
    iput v4, v0, Lcom/squareup/moshi/JsonUtf8Reader;->n:I

    .line 477
    .line 478
    const/16 v11, 0x11

    .line 479
    .line 480
    iput v11, v0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 481
    .line 482
    goto :goto_13

    .line 483
    :cond_28
    const/4 v15, 0x6

    .line 484
    if-ne v2, v8, :cond_1b

    .line 485
    .line 486
    const/4 v2, 0x3

    .line 487
    goto :goto_12

    .line 488
    :cond_29
    const/4 v15, 0x6

    .line 489
    if-nez v2, :cond_2a

    .line 490
    .line 491
    move v2, v3

    .line 492
    move v9, v2

    .line 493
    goto :goto_12

    .line 494
    :cond_2a
    if-ne v2, v11, :cond_1b

    .line 495
    .line 496
    :goto_11
    move v2, v15

    .line 497
    goto :goto_12

    .line 498
    :cond_2b
    const/4 v15, 0x6

    .line 499
    if-eq v2, v8, :cond_2c

    .line 500
    .line 501
    const/4 v4, 0x4

    .line 502
    if-ne v2, v4, :cond_1b

    .line 503
    .line 504
    :cond_2c
    move v2, v11

    .line 505
    goto :goto_12

    .line 506
    :cond_2d
    const/4 v15, 0x6

    .line 507
    if-ne v2, v11, :cond_1b

    .line 508
    .line 509
    goto :goto_11

    .line 510
    :cond_2e
    :goto_12
    move v4, v10

    .line 511
    const/4 v14, 0x3

    .line 512
    goto/16 :goto_9

    .line 513
    .line 514
    :goto_13
    if-eqz v11, :cond_2f

    .line 515
    .line 516
    return v11

    .line 517
    :cond_2f
    move-wide/from16 v1, v17

    .line 518
    .line 519
    invoke-virtual {v12, v1, v2}, Lu01/f;->h(J)B

    .line 520
    .line 521
    .line 522
    move-result v1

    .line 523
    invoke-virtual {v0, v1}, Lcom/squareup/moshi/JsonUtf8Reader;->A0(I)Z

    .line 524
    .line 525
    .line 526
    move-result v1

    .line 527
    if-eqz v1, :cond_30

    .line 528
    .line 529
    invoke-virtual {v0}, Lcom/squareup/moshi/JsonUtf8Reader;->r0()V

    .line 530
    .line 531
    .line 532
    const/16 v1, 0xa

    .line 533
    .line 534
    iput v1, v0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 535
    .line 536
    return v1

    .line 537
    :cond_30
    const-string v1, "Expected value"

    .line 538
    .line 539
    invoke-virtual {v0, v1}, Lcom/squareup/moshi/JsonReader;->n0(Ljava/lang/String;)V

    .line 540
    .line 541
    .line 542
    throw v16

    .line 543
    :cond_31
    invoke-virtual {v12}, Lu01/f;->readByte()B

    .line 544
    .line 545
    .line 546
    iput v3, v0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 547
    .line 548
    return v3

    .line 549
    :cond_32
    if-ne v4, v3, :cond_34

    .line 550
    .line 551
    invoke-virtual {v12}, Lu01/f;->readByte()B

    .line 552
    .line 553
    .line 554
    const/4 v3, 0x4

    .line 555
    iput v3, v0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 556
    .line 557
    return v3

    .line 558
    :cond_33
    invoke-virtual {v12}, Lu01/f;->readByte()B

    .line 559
    .line 560
    .line 561
    const/4 v4, 0x3

    .line 562
    iput v4, v0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 563
    .line 564
    return v4

    .line 565
    :cond_34
    if-eq v4, v3, :cond_36

    .line 566
    .line 567
    if-ne v4, v8, :cond_35

    .line 568
    .line 569
    goto :goto_14

    .line 570
    :cond_35
    const-string v1, "Unexpected value"

    .line 571
    .line 572
    invoke-virtual {v0, v1}, Lcom/squareup/moshi/JsonReader;->n0(Ljava/lang/String;)V

    .line 573
    .line 574
    .line 575
    throw v16

    .line 576
    :cond_36
    :goto_14
    invoke-virtual {v0}, Lcom/squareup/moshi/JsonUtf8Reader;->r0()V

    .line 577
    .line 578
    .line 579
    const/4 v1, 0x7

    .line 580
    iput v1, v0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 581
    .line 582
    return v1

    .line 583
    :cond_37
    invoke-virtual {v0}, Lcom/squareup/moshi/JsonUtf8Reader;->r0()V

    .line 584
    .line 585
    .line 586
    invoke-virtual {v12}, Lu01/f;->readByte()B

    .line 587
    .line 588
    .line 589
    const/16 v2, 0x8

    .line 590
    .line 591
    iput v2, v0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 592
    .line 593
    return v2

    .line 594
    :cond_38
    invoke-virtual {v12}, Lu01/f;->readByte()B

    .line 595
    .line 596
    .line 597
    const/16 v2, 0x9

    .line 598
    .line 599
    iput v2, v0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 600
    .line 601
    return v2

    .line 602
    :cond_39
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 603
    .line 604
    const-string v1, "JsonReader is closed"

    .line 605
    .line 606
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 607
    .line 608
    .line 609
    throw v0

    .line 610
    :cond_3a
    throw v16

    .line 611
    :goto_15
    aput v22, v1, v2

    .line 612
    .line 613
    const/16 v1, 0x7d

    .line 614
    .line 615
    if-ne v4, v11, :cond_3d

    .line 616
    .line 617
    invoke-virtual {v0, v3}, Lcom/squareup/moshi/JsonUtf8Reader;->B0(Z)I

    .line 618
    .line 619
    .line 620
    move-result v2

    .line 621
    invoke-virtual {v12}, Lu01/f;->readByte()B

    .line 622
    .line 623
    .line 624
    if-eq v2, v5, :cond_3d

    .line 625
    .line 626
    if-eq v2, v15, :cond_3c

    .line 627
    .line 628
    if-ne v2, v1, :cond_3b

    .line 629
    .line 630
    iput v8, v0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 631
    .line 632
    return v8

    .line 633
    :cond_3b
    const-string v1, "Unterminated object"

    .line 634
    .line 635
    invoke-virtual {v0, v1}, Lcom/squareup/moshi/JsonReader;->n0(Ljava/lang/String;)V

    .line 636
    .line 637
    .line 638
    throw v16

    .line 639
    :cond_3c
    invoke-virtual {v0}, Lcom/squareup/moshi/JsonUtf8Reader;->r0()V

    .line 640
    .line 641
    .line 642
    :cond_3d
    invoke-virtual {v0, v3}, Lcom/squareup/moshi/JsonUtf8Reader;->B0(Z)I

    .line 643
    .line 644
    .line 645
    move-result v2

    .line 646
    const/16 v9, 0x22

    .line 647
    .line 648
    if-eq v2, v9, :cond_42

    .line 649
    .line 650
    const/16 v9, 0x27

    .line 651
    .line 652
    if-eq v2, v9, :cond_41

    .line 653
    .line 654
    const-string v3, "Expected name"

    .line 655
    .line 656
    if-eq v2, v1, :cond_3f

    .line 657
    .line 658
    invoke-virtual {v0}, Lcom/squareup/moshi/JsonUtf8Reader;->r0()V

    .line 659
    .line 660
    .line 661
    int-to-char v1, v2

    .line 662
    invoke-virtual {v0, v1}, Lcom/squareup/moshi/JsonUtf8Reader;->A0(I)Z

    .line 663
    .line 664
    .line 665
    move-result v1

    .line 666
    if-eqz v1, :cond_3e

    .line 667
    .line 668
    const/16 v1, 0xe

    .line 669
    .line 670
    iput v1, v0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 671
    .line 672
    return v1

    .line 673
    :cond_3e
    invoke-virtual {v0, v3}, Lcom/squareup/moshi/JsonReader;->n0(Ljava/lang/String;)V

    .line 674
    .line 675
    .line 676
    throw v16

    .line 677
    :cond_3f
    if-eq v4, v11, :cond_40

    .line 678
    .line 679
    invoke-virtual {v12}, Lu01/f;->readByte()B

    .line 680
    .line 681
    .line 682
    iput v8, v0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 683
    .line 684
    return v8

    .line 685
    :cond_40
    invoke-virtual {v0, v3}, Lcom/squareup/moshi/JsonReader;->n0(Ljava/lang/String;)V

    .line 686
    .line 687
    .line 688
    throw v16

    .line 689
    :cond_41
    invoke-virtual {v12}, Lu01/f;->readByte()B

    .line 690
    .line 691
    .line 692
    invoke-virtual {v0}, Lcom/squareup/moshi/JsonUtf8Reader;->r0()V

    .line 693
    .line 694
    .line 695
    const/16 v1, 0xc

    .line 696
    .line 697
    iput v1, v0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 698
    .line 699
    return v1

    .line 700
    :cond_42
    invoke-virtual {v12}, Lu01/f;->readByte()B

    .line 701
    .line 702
    .line 703
    const/16 v1, 0xd

    .line 704
    .line 705
    iput v1, v0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 706
    .line 707
    return v1
.end method

.method public final y0(Ljava/lang/String;Lcom/squareup/moshi/JsonReader$Options;)I
    .locals 4

    .line 1
    iget-object v0, p2, Lcom/squareup/moshi/JsonReader$Options;->a:[Ljava/lang/String;

    .line 2
    .line 3
    array-length v0, v0

    .line 4
    const/4 v1, 0x0

    .line 5
    move v2, v1

    .line 6
    :goto_0
    if-ge v2, v0, :cond_1

    .line 7
    .line 8
    iget-object v3, p2, Lcom/squareup/moshi/JsonReader$Options;->a:[Ljava/lang/String;

    .line 9
    .line 10
    aget-object v3, v3, v2

    .line 11
    .line 12
    invoke-virtual {p1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    move-result v3

    .line 16
    if-eqz v3, :cond_0

    .line 17
    .line 18
    iput v1, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 19
    .line 20
    iget-object p2, p0, Lcom/squareup/moshi/JsonReader;->f:[Ljava/lang/String;

    .line 21
    .line 22
    iget p0, p0, Lcom/squareup/moshi/JsonReader;->d:I

    .line 23
    .line 24
    add-int/lit8 p0, p0, -0x1

    .line 25
    .line 26
    aput-object p1, p2, p0

    .line 27
    .line 28
    return v2

    .line 29
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_1
    const/4 p0, -0x1

    .line 33
    return p0
.end method

.method public final z0(Ljava/lang/String;Lcom/squareup/moshi/JsonReader$Options;)I
    .locals 4

    .line 1
    iget-object v0, p2, Lcom/squareup/moshi/JsonReader$Options;->a:[Ljava/lang/String;

    .line 2
    .line 3
    array-length v0, v0

    .line 4
    const/4 v1, 0x0

    .line 5
    move v2, v1

    .line 6
    :goto_0
    if-ge v2, v0, :cond_1

    .line 7
    .line 8
    iget-object v3, p2, Lcom/squareup/moshi/JsonReader$Options;->a:[Ljava/lang/String;

    .line 9
    .line 10
    aget-object v3, v3, v2

    .line 11
    .line 12
    invoke-virtual {p1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    move-result v3

    .line 16
    if-eqz v3, :cond_0

    .line 17
    .line 18
    iput v1, p0, Lcom/squareup/moshi/JsonUtf8Reader;->l:I

    .line 19
    .line 20
    iget-object p1, p0, Lcom/squareup/moshi/JsonReader;->g:[I

    .line 21
    .line 22
    iget p0, p0, Lcom/squareup/moshi/JsonReader;->d:I

    .line 23
    .line 24
    add-int/lit8 p0, p0, -0x1

    .line 25
    .line 26
    aget p2, p1, p0

    .line 27
    .line 28
    add-int/lit8 p2, p2, 0x1

    .line 29
    .line 30
    aput p2, p1, p0

    .line 31
    .line 32
    return v2

    .line 33
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_1
    const/4 p0, -0x1

    .line 37
    return p0
.end method
