.class public final Lfn/b;
.super Lfn/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final o:Lu01/i;

.field public static final p:Lu01/i;

.field public static final q:Lu01/i;


# instance fields
.field public final i:Lu01/b0;

.field public final j:Lu01/f;

.field public k:I

.field public l:J

.field public m:I

.field public n:Ljava/lang/String;


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
    sput-object v0, Lfn/b;->o:Lu01/i;

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
    sput-object v0, Lfn/b;->p:Lu01/i;

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
    sput-object v0, Lfn/b;->q:Lu01/i;

    .line 26
    .line 27
    const-string v0, "\n\r"

    .line 28
    .line 29
    invoke-static {v0}, Lpy/a;->m(Ljava/lang/String;)Lu01/i;

    .line 30
    .line 31
    .line 32
    const-string v0, "*/"

    .line 33
    .line 34
    invoke-static {v0}, Lpy/a;->m(Ljava/lang/String;)Lu01/i;

    .line 35
    .line 36
    .line 37
    return-void
.end method

.method public constructor <init>(Lu01/b0;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/16 v0, 0x20

    .line 5
    .line 6
    new-array v1, v0, [I

    .line 7
    .line 8
    iput-object v1, p0, Lfn/a;->e:[I

    .line 9
    .line 10
    new-array v1, v0, [Ljava/lang/String;

    .line 11
    .line 12
    iput-object v1, p0, Lfn/a;->f:[Ljava/lang/String;

    .line 13
    .line 14
    new-array v0, v0, [I

    .line 15
    .line 16
    iput-object v0, p0, Lfn/a;->g:[I

    .line 17
    .line 18
    const/4 v0, 0x0

    .line 19
    iput v0, p0, Lfn/b;->k:I

    .line 20
    .line 21
    iput-object p1, p0, Lfn/b;->i:Lu01/b0;

    .line 22
    .line 23
    iget-object p1, p1, Lu01/b0;->e:Lu01/f;

    .line 24
    .line 25
    iput-object p1, p0, Lfn/b;->j:Lu01/f;

    .line 26
    .line 27
    const/4 p1, 0x6

    .line 28
    invoke-virtual {p0, p1}, Lfn/a;->E(I)V

    .line 29
    .line 30
    .line 31
    return-void
.end method


# virtual methods
.method public final B()I
    .locals 1

    .line 1
    iget v0, p0, Lfn/b;->k:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lfn/b;->W()I

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
    const/16 p0, 0xa

    .line 19
    .line 20
    return p0

    .line 21
    :pswitch_1
    const/4 p0, 0x7

    .line 22
    return p0

    .line 23
    :pswitch_2
    const/4 p0, 0x5

    .line 24
    return p0

    .line 25
    :pswitch_3
    const/4 p0, 0x6

    .line 26
    return p0

    .line 27
    :pswitch_4
    const/16 p0, 0x9

    .line 28
    .line 29
    return p0

    .line 30
    :pswitch_5
    const/16 p0, 0x8

    .line 31
    .line 32
    return p0

    .line 33
    :pswitch_6
    const/4 p0, 0x2

    .line 34
    return p0

    .line 35
    :pswitch_7
    const/4 p0, 0x1

    .line 36
    return p0

    .line 37
    :pswitch_8
    const/4 p0, 0x4

    .line 38
    return p0

    .line 39
    :pswitch_9
    const/4 p0, 0x3

    .line 40
    return p0

    .line 41
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

.method public final H(Lb81/c;)I
    .locals 4

    .line 1
    iget v0, p0, Lfn/b;->k:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lfn/b;->W()I

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
    iget-object v0, p0, Lfn/b;->n:Ljava/lang/String;

    .line 22
    .line 23
    invoke-virtual {p0, v0, p1}, Lfn/b;->e0(Ljava/lang/String;Lb81/c;)I

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    return p0

    .line 28
    :cond_2
    iget-object v0, p1, Lb81/c;->f:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast v0, Lu01/w;

    .line 31
    .line 32
    iget-object v3, p0, Lfn/b;->i:Lu01/b0;

    .line 33
    .line 34
    invoke-virtual {v3, v0}, Lu01/b0;->Q(Lu01/w;)I

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    if-eq v0, v2, :cond_3

    .line 39
    .line 40
    const/4 v1, 0x0

    .line 41
    iput v1, p0, Lfn/b;->k:I

    .line 42
    .line 43
    iget-object v1, p0, Lfn/a;->f:[Ljava/lang/String;

    .line 44
    .line 45
    iget p0, p0, Lfn/a;->d:I

    .line 46
    .line 47
    add-int/lit8 p0, p0, -0x1

    .line 48
    .line 49
    iget-object p1, p1, Lb81/c;->e:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast p1, [Ljava/lang/String;

    .line 52
    .line 53
    aget-object p1, p1, v0

    .line 54
    .line 55
    aput-object p1, v1, p0

    .line 56
    .line 57
    return v0

    .line 58
    :cond_3
    iget-object v0, p0, Lfn/a;->f:[Ljava/lang/String;

    .line 59
    .line 60
    iget v3, p0, Lfn/a;->d:I

    .line 61
    .line 62
    add-int/lit8 v3, v3, -0x1

    .line 63
    .line 64
    aget-object v0, v0, v3

    .line 65
    .line 66
    invoke-virtual {p0}, Lfn/b;->k0()Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v3

    .line 70
    invoke-virtual {p0, v3, p1}, Lfn/b;->e0(Ljava/lang/String;Lb81/c;)I

    .line 71
    .line 72
    .line 73
    move-result p1

    .line 74
    if-ne p1, v2, :cond_4

    .line 75
    .line 76
    iput v1, p0, Lfn/b;->k:I

    .line 77
    .line 78
    iput-object v3, p0, Lfn/b;->n:Ljava/lang/String;

    .line 79
    .line 80
    iget-object v1, p0, Lfn/a;->f:[Ljava/lang/String;

    .line 81
    .line 82
    iget p0, p0, Lfn/a;->d:I

    .line 83
    .line 84
    add-int/lit8 p0, p0, -0x1

    .line 85
    .line 86
    aput-object v0, v1, p0

    .line 87
    .line 88
    :cond_4
    return p1

    .line 89
    :cond_5
    :goto_0
    return v2
.end method

.method public final M()V
    .locals 4

    .line 1
    iget v0, p0, Lfn/b;->k:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lfn/b;->W()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    :cond_0
    const/16 v1, 0xe

    .line 10
    .line 11
    if-ne v0, v1, :cond_2

    .line 12
    .line 13
    iget-object v0, p0, Lfn/b;->i:Lu01/b0;

    .line 14
    .line 15
    sget-object v1, Lfn/b;->q:Lu01/i;

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Lu01/b0;->y(Lu01/i;)J

    .line 18
    .line 19
    .line 20
    move-result-wide v0

    .line 21
    const-wide/16 v2, -0x1

    .line 22
    .line 23
    cmp-long v2, v0, v2

    .line 24
    .line 25
    iget-object v3, p0, Lfn/b;->j:Lu01/f;

    .line 26
    .line 27
    if-eqz v2, :cond_1

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_1
    iget-wide v0, v3, Lu01/f;->e:J

    .line 31
    .line 32
    :goto_0
    invoke-virtual {v3, v0, v1}, Lu01/f;->skip(J)V

    .line 33
    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_2
    const/16 v1, 0xd

    .line 37
    .line 38
    if-ne v0, v1, :cond_3

    .line 39
    .line 40
    sget-object v0, Lfn/b;->p:Lu01/i;

    .line 41
    .line 42
    invoke-virtual {p0, v0}, Lfn/b;->x0(Lu01/i;)V

    .line 43
    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_3
    const/16 v1, 0xc

    .line 47
    .line 48
    if-ne v0, v1, :cond_4

    .line 49
    .line 50
    sget-object v0, Lfn/b;->o:Lu01/i;

    .line 51
    .line 52
    invoke-virtual {p0, v0}, Lfn/b;->x0(Lu01/i;)V

    .line 53
    .line 54
    .line 55
    goto :goto_1

    .line 56
    :cond_4
    const/16 v1, 0xf

    .line 57
    .line 58
    if-ne v0, v1, :cond_5

    .line 59
    .line 60
    :goto_1
    const/4 v0, 0x0

    .line 61
    iput v0, p0, Lfn/b;->k:I

    .line 62
    .line 63
    iget-object v0, p0, Lfn/a;->f:[Ljava/lang/String;

    .line 64
    .line 65
    iget p0, p0, Lfn/a;->d:I

    .line 66
    .line 67
    add-int/lit8 p0, p0, -0x1

    .line 68
    .line 69
    const-string v1, "null"

    .line 70
    .line 71
    aput-object v1, v0, p0

    .line 72
    .line 73
    return-void

    .line 74
    :cond_5
    new-instance v0, La8/r0;

    .line 75
    .line 76
    new-instance v1, Ljava/lang/StringBuilder;

    .line 77
    .line 78
    const-string v2, "Expected a name but was "

    .line 79
    .line 80
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    invoke-virtual {p0}, Lfn/b;->B()I

    .line 84
    .line 85
    .line 86
    move-result v2

    .line 87
    invoke-static {v2}, Lf2/m0;->z(I)Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object v2

    .line 91
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

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
    invoke-virtual {p0}, Lfn/a;->g()Ljava/lang/String;

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
.end method

.method public final T()V
    .locals 8

    .line 1
    const/4 v0, 0x0

    .line 2
    move v1, v0

    .line 3
    :cond_0
    iget v2, p0, Lfn/b;->k:I

    .line 4
    .line 5
    if-nez v2, :cond_1

    .line 6
    .line 7
    invoke-virtual {p0}, Lfn/b;->W()I

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    :cond_1
    const/4 v3, 0x3

    .line 12
    const/4 v4, 0x1

    .line 13
    if-ne v2, v3, :cond_2

    .line 14
    .line 15
    invoke-virtual {p0, v4}, Lfn/a;->E(I)V

    .line 16
    .line 17
    .line 18
    :goto_0
    add-int/lit8 v1, v1, 0x1

    .line 19
    .line 20
    goto/16 :goto_5

    .line 21
    .line 22
    :cond_2
    if-ne v2, v4, :cond_3

    .line 23
    .line 24
    invoke-virtual {p0, v3}, Lfn/a;->E(I)V

    .line 25
    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_3
    const/4 v3, 0x4

    .line 29
    const-string v5, " at path "

    .line 30
    .line 31
    const-string v6, "Expected a value but was "

    .line 32
    .line 33
    if-ne v2, v3, :cond_5

    .line 34
    .line 35
    add-int/lit8 v1, v1, -0x1

    .line 36
    .line 37
    if-ltz v1, :cond_4

    .line 38
    .line 39
    iget v2, p0, Lfn/a;->d:I

    .line 40
    .line 41
    sub-int/2addr v2, v4

    .line 42
    iput v2, p0, Lfn/a;->d:I

    .line 43
    .line 44
    goto/16 :goto_5

    .line 45
    .line 46
    :cond_4
    new-instance v0, La8/r0;

    .line 47
    .line 48
    new-instance v1, Ljava/lang/StringBuilder;

    .line 49
    .line 50
    invoke-direct {v1, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    invoke-virtual {p0}, Lfn/b;->B()I

    .line 54
    .line 55
    .line 56
    move-result v2

    .line 57
    invoke-static {v2}, Lf2/m0;->z(I)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object v2

    .line 61
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    invoke-virtual {v1, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    invoke-virtual {p0}, Lfn/a;->g()Ljava/lang/String;

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
    iget v2, p0, Lfn/a;->d:I

    .line 90
    .line 91
    sub-int/2addr v2, v4

    .line 92
    iput v2, p0, Lfn/a;->d:I

    .line 93
    .line 94
    goto/16 :goto_5

    .line 95
    .line 96
    :cond_6
    new-instance v0, La8/r0;

    .line 97
    .line 98
    new-instance v1, Ljava/lang/StringBuilder;

    .line 99
    .line 100
    invoke-direct {v1, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    invoke-virtual {p0}, Lfn/b;->B()I

    .line 104
    .line 105
    .line 106
    move-result v2

    .line 107
    invoke-static {v2}, Lf2/m0;->z(I)Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object v2

    .line 111
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 112
    .line 113
    .line 114
    invoke-virtual {v1, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 115
    .line 116
    .line 117
    invoke-virtual {p0}, Lfn/a;->g()Ljava/lang/String;

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 122
    .line 123
    .line 124
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 125
    .line 126
    .line 127
    move-result-object p0

    .line 128
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 129
    .line 130
    .line 131
    throw v0

    .line 132
    :cond_7
    const/16 v3, 0xe

    .line 133
    .line 134
    iget-object v7, p0, Lfn/b;->j:Lu01/f;

    .line 135
    .line 136
    if-eq v2, v3, :cond_f

    .line 137
    .line 138
    const/16 v3, 0xa

    .line 139
    .line 140
    if-ne v2, v3, :cond_8

    .line 141
    .line 142
    goto :goto_3

    .line 143
    :cond_8
    const/16 v3, 0x9

    .line 144
    .line 145
    if-eq v2, v3, :cond_e

    .line 146
    .line 147
    const/16 v3, 0xd

    .line 148
    .line 149
    if-ne v2, v3, :cond_9

    .line 150
    .line 151
    goto :goto_2

    .line 152
    :cond_9
    const/16 v3, 0x8

    .line 153
    .line 154
    if-eq v2, v3, :cond_d

    .line 155
    .line 156
    const/16 v3, 0xc

    .line 157
    .line 158
    if-ne v2, v3, :cond_a

    .line 159
    .line 160
    goto :goto_1

    .line 161
    :cond_a
    const/16 v3, 0x11

    .line 162
    .line 163
    if-ne v2, v3, :cond_b

    .line 164
    .line 165
    iget v2, p0, Lfn/b;->m:I

    .line 166
    .line 167
    int-to-long v2, v2

    .line 168
    invoke-virtual {v7, v2, v3}, Lu01/f;->skip(J)V

    .line 169
    .line 170
    .line 171
    goto :goto_5

    .line 172
    :cond_b
    const/16 v3, 0x12

    .line 173
    .line 174
    if-eq v2, v3, :cond_c

    .line 175
    .line 176
    goto :goto_5

    .line 177
    :cond_c
    new-instance v0, La8/r0;

    .line 178
    .line 179
    new-instance v1, Ljava/lang/StringBuilder;

    .line 180
    .line 181
    invoke-direct {v1, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 182
    .line 183
    .line 184
    invoke-virtual {p0}, Lfn/b;->B()I

    .line 185
    .line 186
    .line 187
    move-result v2

    .line 188
    invoke-static {v2}, Lf2/m0;->z(I)Ljava/lang/String;

    .line 189
    .line 190
    .line 191
    move-result-object v2

    .line 192
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 193
    .line 194
    .line 195
    invoke-virtual {v1, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 196
    .line 197
    .line 198
    invoke-virtual {p0}, Lfn/a;->g()Ljava/lang/String;

    .line 199
    .line 200
    .line 201
    move-result-object p0

    .line 202
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 203
    .line 204
    .line 205
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 206
    .line 207
    .line 208
    move-result-object p0

    .line 209
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 210
    .line 211
    .line 212
    throw v0

    .line 213
    :cond_d
    :goto_1
    sget-object v2, Lfn/b;->o:Lu01/i;

    .line 214
    .line 215
    invoke-virtual {p0, v2}, Lfn/b;->x0(Lu01/i;)V

    .line 216
    .line 217
    .line 218
    goto :goto_5

    .line 219
    :cond_e
    :goto_2
    sget-object v2, Lfn/b;->p:Lu01/i;

    .line 220
    .line 221
    invoke-virtual {p0, v2}, Lfn/b;->x0(Lu01/i;)V

    .line 222
    .line 223
    .line 224
    goto :goto_5

    .line 225
    :cond_f
    :goto_3
    iget-object v2, p0, Lfn/b;->i:Lu01/b0;

    .line 226
    .line 227
    sget-object v3, Lfn/b;->q:Lu01/i;

    .line 228
    .line 229
    invoke-virtual {v2, v3}, Lu01/b0;->y(Lu01/i;)J

    .line 230
    .line 231
    .line 232
    move-result-wide v2

    .line 233
    const-wide/16 v5, -0x1

    .line 234
    .line 235
    cmp-long v5, v2, v5

    .line 236
    .line 237
    if-eqz v5, :cond_10

    .line 238
    .line 239
    goto :goto_4

    .line 240
    :cond_10
    iget-wide v2, v7, Lu01/f;->e:J

    .line 241
    .line 242
    :goto_4
    invoke-virtual {v7, v2, v3}, Lu01/f;->skip(J)V

    .line 243
    .line 244
    .line 245
    :goto_5
    iput v0, p0, Lfn/b;->k:I

    .line 246
    .line 247
    if-nez v1, :cond_0

    .line 248
    .line 249
    iget-object v0, p0, Lfn/a;->g:[I

    .line 250
    .line 251
    iget v1, p0, Lfn/a;->d:I

    .line 252
    .line 253
    sub-int/2addr v1, v4

    .line 254
    aget v2, v0, v1

    .line 255
    .line 256
    add-int/2addr v2, v4

    .line 257
    aput v2, v0, v1

    .line 258
    .line 259
    iget-object p0, p0, Lfn/a;->f:[Ljava/lang/String;

    .line 260
    .line 261
    const-string v0, "null"

    .line 262
    .line 263
    aput-object v0, p0, v1

    .line 264
    .line 265
    return-void
.end method

.method public final V()V
    .locals 1

    .line 1
    const-string v0, "Use JsonReader.setLenient(true) to accept malformed JSON"

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Lfn/a;->U(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/4 p0, 0x0

    .line 7
    throw p0
.end method

.method public final W()I
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lfn/a;->e:[I

    .line 4
    .line 5
    iget v2, v0, Lfn/a;->d:I

    .line 6
    .line 7
    const/4 v3, 0x1

    .line 8
    sub-int/2addr v2, v3

    .line 9
    aget v4, v1, v2

    .line 10
    .line 11
    const/16 v8, 0x5d

    .line 12
    .line 13
    const/4 v9, 0x0

    .line 14
    const/4 v10, 0x6

    .line 15
    const/4 v11, 0x3

    .line 16
    const/16 v12, 0x3b

    .line 17
    .line 18
    const/16 v13, 0x2c

    .line 19
    .line 20
    const/4 v14, 0x7

    .line 21
    const/4 v15, 0x4

    .line 22
    const/16 v16, 0x0

    .line 23
    .line 24
    const/4 v5, 0x5

    .line 25
    const/4 v6, 0x2

    .line 26
    iget-object v7, v0, Lfn/b;->j:Lu01/f;

    .line 27
    .line 28
    if-ne v4, v3, :cond_0

    .line 29
    .line 30
    aput v6, v1, v2

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    if-ne v4, v6, :cond_3

    .line 34
    .line 35
    invoke-virtual {v0, v3}, Lfn/b;->l0(Z)I

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    invoke-virtual {v7}, Lu01/f;->readByte()B

    .line 40
    .line 41
    .line 42
    if-eq v1, v13, :cond_b

    .line 43
    .line 44
    if-eq v1, v12, :cond_2

    .line 45
    .line 46
    if-ne v1, v8, :cond_1

    .line 47
    .line 48
    iput v15, v0, Lfn/b;->k:I

    .line 49
    .line 50
    return v15

    .line 51
    :cond_1
    const-string v1, "Unterminated array"

    .line 52
    .line 53
    invoke-virtual {v0, v1}, Lfn/a;->U(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw v16

    .line 57
    :cond_2
    invoke-virtual {v0}, Lfn/b;->V()V

    .line 58
    .line 59
    .line 60
    throw v16

    .line 61
    :cond_3
    if-eq v4, v11, :cond_4

    .line 62
    .line 63
    if-ne v4, v5, :cond_5

    .line 64
    .line 65
    :cond_4
    move/from16 v19, v15

    .line 66
    .line 67
    goto/16 :goto_16

    .line 68
    .line 69
    :cond_5
    if-ne v4, v15, :cond_7

    .line 70
    .line 71
    aput v5, v1, v2

    .line 72
    .line 73
    invoke-virtual {v0, v3}, Lfn/b;->l0(Z)I

    .line 74
    .line 75
    .line 76
    move-result v1

    .line 77
    invoke-virtual {v7}, Lu01/f;->readByte()B

    .line 78
    .line 79
    .line 80
    const/16 v2, 0x3a

    .line 81
    .line 82
    if-eq v1, v2, :cond_b

    .line 83
    .line 84
    const/16 v2, 0x3d

    .line 85
    .line 86
    if-eq v1, v2, :cond_6

    .line 87
    .line 88
    const-string v1, "Expected \':\'"

    .line 89
    .line 90
    invoke-virtual {v0, v1}, Lfn/a;->U(Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    throw v16

    .line 94
    :cond_6
    invoke-virtual {v0}, Lfn/b;->V()V

    .line 95
    .line 96
    .line 97
    throw v16

    .line 98
    :cond_7
    if-ne v4, v10, :cond_8

    .line 99
    .line 100
    aput v14, v1, v2

    .line 101
    .line 102
    goto :goto_0

    .line 103
    :cond_8
    if-ne v4, v14, :cond_a

    .line 104
    .line 105
    invoke-virtual {v0, v9}, Lfn/b;->l0(Z)I

    .line 106
    .line 107
    .line 108
    move-result v1

    .line 109
    const/4 v2, -0x1

    .line 110
    if-ne v1, v2, :cond_9

    .line 111
    .line 112
    const/16 v1, 0x12

    .line 113
    .line 114
    iput v1, v0, Lfn/b;->k:I

    .line 115
    .line 116
    return v1

    .line 117
    :cond_9
    invoke-virtual {v0}, Lfn/b;->V()V

    .line 118
    .line 119
    .line 120
    throw v16

    .line 121
    :cond_a
    const/16 v1, 0x8

    .line 122
    .line 123
    if-eq v4, v1, :cond_39

    .line 124
    .line 125
    :cond_b
    :goto_0
    invoke-virtual {v0, v3}, Lfn/b;->l0(Z)I

    .line 126
    .line 127
    .line 128
    move-result v1

    .line 129
    const/16 v2, 0x22

    .line 130
    .line 131
    if-eq v1, v2, :cond_38

    .line 132
    .line 133
    const/16 v2, 0x27

    .line 134
    .line 135
    if-eq v1, v2, :cond_37

    .line 136
    .line 137
    if-eq v1, v13, :cond_34

    .line 138
    .line 139
    if-eq v1, v12, :cond_34

    .line 140
    .line 141
    const/16 v2, 0x5b

    .line 142
    .line 143
    if-eq v1, v2, :cond_33

    .line 144
    .line 145
    if-eq v1, v8, :cond_32

    .line 146
    .line 147
    const/16 v2, 0x7b

    .line 148
    .line 149
    if-eq v1, v2, :cond_31

    .line 150
    .line 151
    const-wide/16 v1, 0x0

    .line 152
    .line 153
    invoke-virtual {v7, v1, v2}, Lu01/f;->h(J)B

    .line 154
    .line 155
    .line 156
    move-result v4

    .line 157
    const/16 v8, 0x74

    .line 158
    .line 159
    iget-object v12, v0, Lfn/b;->i:Lu01/b0;

    .line 160
    .line 161
    if-eq v4, v8, :cond_11

    .line 162
    .line 163
    const/16 v8, 0x54

    .line 164
    .line 165
    if-ne v4, v8, :cond_c

    .line 166
    .line 167
    goto :goto_3

    .line 168
    :cond_c
    const/16 v8, 0x66

    .line 169
    .line 170
    if-eq v4, v8, :cond_10

    .line 171
    .line 172
    const/16 v8, 0x46

    .line 173
    .line 174
    if-ne v4, v8, :cond_d

    .line 175
    .line 176
    goto :goto_2

    .line 177
    :cond_d
    const/16 v8, 0x6e

    .line 178
    .line 179
    if-eq v4, v8, :cond_f

    .line 180
    .line 181
    const/16 v8, 0x4e

    .line 182
    .line 183
    if-ne v4, v8, :cond_e

    .line 184
    .line 185
    goto :goto_1

    .line 186
    :cond_e
    move-wide/from16 v17, v1

    .line 187
    .line 188
    move v13, v9

    .line 189
    goto :goto_7

    .line 190
    :cond_f
    :goto_1
    const-string v4, "null"

    .line 191
    .line 192
    const-string v8, "NULL"

    .line 193
    .line 194
    move v13, v14

    .line 195
    goto :goto_4

    .line 196
    :cond_10
    :goto_2
    const-string v4, "false"

    .line 197
    .line 198
    const-string v8, "FALSE"

    .line 199
    .line 200
    move v13, v10

    .line 201
    goto :goto_4

    .line 202
    :cond_11
    :goto_3
    const-string v4, "true"

    .line 203
    .line 204
    const-string v8, "TRUE"

    .line 205
    .line 206
    move v13, v5

    .line 207
    :goto_4
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 208
    .line 209
    .line 210
    move-result v9

    .line 211
    move-wide/from16 v17, v1

    .line 212
    .line 213
    move v1, v3

    .line 214
    :goto_5
    if-ge v1, v9, :cond_14

    .line 215
    .line 216
    add-int/lit8 v2, v1, 0x1

    .line 217
    .line 218
    int-to-long v14, v2

    .line 219
    invoke-virtual {v12, v14, v15}, Lu01/b0;->c(J)Z

    .line 220
    .line 221
    .line 222
    move-result v14

    .line 223
    if-nez v14, :cond_12

    .line 224
    .line 225
    :goto_6
    const/4 v13, 0x0

    .line 226
    goto :goto_7

    .line 227
    :cond_12
    int-to-long v14, v1

    .line 228
    invoke-virtual {v7, v14, v15}, Lu01/f;->h(J)B

    .line 229
    .line 230
    .line 231
    move-result v14

    .line 232
    invoke-virtual {v4, v1}, Ljava/lang/String;->charAt(I)C

    .line 233
    .line 234
    .line 235
    move-result v15

    .line 236
    if-eq v14, v15, :cond_13

    .line 237
    .line 238
    invoke-virtual {v8, v1}, Ljava/lang/String;->charAt(I)C

    .line 239
    .line 240
    .line 241
    move-result v1

    .line 242
    if-eq v14, v1, :cond_13

    .line 243
    .line 244
    goto :goto_6

    .line 245
    :cond_13
    move v1, v2

    .line 246
    const/4 v14, 0x7

    .line 247
    const/4 v15, 0x4

    .line 248
    goto :goto_5

    .line 249
    :cond_14
    add-int/lit8 v1, v9, 0x1

    .line 250
    .line 251
    int-to-long v1, v1

    .line 252
    invoke-virtual {v12, v1, v2}, Lu01/b0;->c(J)Z

    .line 253
    .line 254
    .line 255
    move-result v1

    .line 256
    if-eqz v1, :cond_15

    .line 257
    .line 258
    int-to-long v1, v9

    .line 259
    invoke-virtual {v7, v1, v2}, Lu01/f;->h(J)B

    .line 260
    .line 261
    .line 262
    move-result v1

    .line 263
    invoke-virtual {v0, v1}, Lfn/b;->h0(I)Z

    .line 264
    .line 265
    .line 266
    move-result v1

    .line 267
    if-eqz v1, :cond_15

    .line 268
    .line 269
    goto :goto_6

    .line 270
    :cond_15
    int-to-long v1, v9

    .line 271
    invoke-virtual {v7, v1, v2}, Lu01/f;->skip(J)V

    .line 272
    .line 273
    .line 274
    iput v13, v0, Lfn/b;->k:I

    .line 275
    .line 276
    :goto_7
    if-eqz v13, :cond_16

    .line 277
    .line 278
    return v13

    .line 279
    :cond_16
    move v4, v3

    .line 280
    move-wide/from16 v8, v17

    .line 281
    .line 282
    const/4 v1, 0x0

    .line 283
    const/4 v2, 0x0

    .line 284
    const/4 v13, 0x0

    .line 285
    :goto_8
    add-int/lit8 v14, v2, 0x1

    .line 286
    .line 287
    int-to-long v10, v14

    .line 288
    invoke-virtual {v12, v10, v11}, Lu01/b0;->c(J)Z

    .line 289
    .line 290
    .line 291
    move-result v10

    .line 292
    if-nez v10, :cond_17

    .line 293
    .line 294
    goto/16 :goto_10

    .line 295
    .line 296
    :cond_17
    int-to-long v10, v2

    .line 297
    invoke-virtual {v7, v10, v11}, Lu01/f;->h(J)B

    .line 298
    .line 299
    .line 300
    move-result v10

    .line 301
    const/16 v11, 0x2b

    .line 302
    .line 303
    if-eq v10, v11, :cond_2e

    .line 304
    .line 305
    const/16 v11, 0x45

    .line 306
    .line 307
    if-eq v10, v11, :cond_2c

    .line 308
    .line 309
    const/16 v11, 0x65

    .line 310
    .line 311
    if-eq v10, v11, :cond_2c

    .line 312
    .line 313
    const/16 v11, 0x2d

    .line 314
    .line 315
    if-eq v10, v11, :cond_2a

    .line 316
    .line 317
    const/16 v11, 0x2e

    .line 318
    .line 319
    if-eq v10, v11, :cond_29

    .line 320
    .line 321
    const/16 v11, 0x30

    .line 322
    .line 323
    if-lt v10, v11, :cond_23

    .line 324
    .line 325
    const/16 v11, 0x39

    .line 326
    .line 327
    if-le v10, v11, :cond_18

    .line 328
    .line 329
    goto :goto_f

    .line 330
    :cond_18
    if-eq v1, v3, :cond_19

    .line 331
    .line 332
    if-nez v1, :cond_1a

    .line 333
    .line 334
    :cond_19
    const/4 v15, 0x6

    .line 335
    goto :goto_e

    .line 336
    :cond_1a
    if-ne v1, v6, :cond_1f

    .line 337
    .line 338
    cmp-long v2, v8, v17

    .line 339
    .line 340
    if-nez v2, :cond_1c

    .line 341
    .line 342
    :cond_1b
    const/4 v9, 0x0

    .line 343
    goto/16 :goto_14

    .line 344
    .line 345
    :cond_1c
    const-wide/16 v20, 0xa

    .line 346
    .line 347
    mul-long v20, v20, v8

    .line 348
    .line 349
    add-int/lit8 v10, v10, -0x30

    .line 350
    .line 351
    int-to-long v10, v10

    .line 352
    sub-long v20, v20, v10

    .line 353
    .line 354
    const-wide v10, -0xcccccccccccccccL

    .line 355
    .line 356
    .line 357
    .line 358
    .line 359
    cmp-long v2, v8, v10

    .line 360
    .line 361
    if-gtz v2, :cond_1e

    .line 362
    .line 363
    if-nez v2, :cond_1d

    .line 364
    .line 365
    cmp-long v2, v20, v8

    .line 366
    .line 367
    if-gez v2, :cond_1d

    .line 368
    .line 369
    goto :goto_9

    .line 370
    :cond_1d
    const/4 v2, 0x0

    .line 371
    goto :goto_a

    .line 372
    :cond_1e
    :goto_9
    move v2, v3

    .line 373
    :goto_a
    and-int/2addr v4, v2

    .line 374
    move-wide/from16 v8, v20

    .line 375
    .line 376
    :goto_b
    const/4 v10, 0x7

    .line 377
    const/4 v15, 0x6

    .line 378
    goto/16 :goto_13

    .line 379
    .line 380
    :cond_1f
    const/4 v2, 0x3

    .line 381
    if-ne v1, v2, :cond_20

    .line 382
    .line 383
    const/4 v1, 0x4

    .line 384
    goto :goto_b

    .line 385
    :cond_20
    const/4 v15, 0x6

    .line 386
    if-eq v1, v5, :cond_22

    .line 387
    .line 388
    if-ne v1, v15, :cond_21

    .line 389
    .line 390
    goto :goto_d

    .line 391
    :cond_21
    :goto_c
    const/4 v10, 0x7

    .line 392
    goto/16 :goto_13

    .line 393
    .line 394
    :cond_22
    :goto_d
    const/4 v1, 0x7

    .line 395
    goto :goto_c

    .line 396
    :goto_e
    add-int/lit8 v10, v10, -0x30

    .line 397
    .line 398
    neg-int v1, v10

    .line 399
    int-to-long v8, v1

    .line 400
    move v1, v6

    .line 401
    goto :goto_c

    .line 402
    :cond_23
    :goto_f
    invoke-virtual {v0, v10}, Lfn/b;->h0(I)Z

    .line 403
    .line 404
    .line 405
    move-result v3

    .line 406
    if-nez v3, :cond_1b

    .line 407
    .line 408
    :goto_10
    if-ne v1, v6, :cond_27

    .line 409
    .line 410
    if-eqz v4, :cond_27

    .line 411
    .line 412
    const-wide/high16 v3, -0x8000000000000000L

    .line 413
    .line 414
    cmp-long v3, v8, v3

    .line 415
    .line 416
    if-nez v3, :cond_24

    .line 417
    .line 418
    if-eqz v13, :cond_27

    .line 419
    .line 420
    :cond_24
    cmp-long v3, v8, v17

    .line 421
    .line 422
    if-nez v3, :cond_25

    .line 423
    .line 424
    if-nez v13, :cond_27

    .line 425
    .line 426
    :cond_25
    if-eqz v13, :cond_26

    .line 427
    .line 428
    goto :goto_11

    .line 429
    :cond_26
    neg-long v8, v8

    .line 430
    :goto_11
    iput-wide v8, v0, Lfn/b;->l:J

    .line 431
    .line 432
    int-to-long v1, v2

    .line 433
    invoke-virtual {v7, v1, v2}, Lu01/f;->skip(J)V

    .line 434
    .line 435
    .line 436
    const/16 v9, 0x10

    .line 437
    .line 438
    iput v9, v0, Lfn/b;->k:I

    .line 439
    .line 440
    goto :goto_14

    .line 441
    :cond_27
    if-eq v1, v6, :cond_28

    .line 442
    .line 443
    const/4 v3, 0x4

    .line 444
    if-eq v1, v3, :cond_28

    .line 445
    .line 446
    const/4 v10, 0x7

    .line 447
    if-ne v1, v10, :cond_1b

    .line 448
    .line 449
    :cond_28
    iput v2, v0, Lfn/b;->m:I

    .line 450
    .line 451
    const/16 v9, 0x11

    .line 452
    .line 453
    iput v9, v0, Lfn/b;->k:I

    .line 454
    .line 455
    goto :goto_14

    .line 456
    :cond_29
    const/4 v10, 0x7

    .line 457
    const/4 v15, 0x6

    .line 458
    if-ne v1, v6, :cond_1b

    .line 459
    .line 460
    const/4 v1, 0x3

    .line 461
    goto :goto_13

    .line 462
    :cond_2a
    const/4 v10, 0x7

    .line 463
    const/4 v15, 0x6

    .line 464
    if-nez v1, :cond_2b

    .line 465
    .line 466
    move v1, v3

    .line 467
    move v13, v1

    .line 468
    goto :goto_13

    .line 469
    :cond_2b
    if-ne v1, v5, :cond_1b

    .line 470
    .line 471
    :goto_12
    move v1, v15

    .line 472
    goto :goto_13

    .line 473
    :cond_2c
    const/4 v10, 0x7

    .line 474
    const/4 v15, 0x6

    .line 475
    if-eq v1, v6, :cond_2d

    .line 476
    .line 477
    const/4 v2, 0x4

    .line 478
    if-ne v1, v2, :cond_1b

    .line 479
    .line 480
    :cond_2d
    move v1, v5

    .line 481
    goto :goto_13

    .line 482
    :cond_2e
    const/4 v10, 0x7

    .line 483
    const/4 v15, 0x6

    .line 484
    if-ne v1, v5, :cond_1b

    .line 485
    .line 486
    goto :goto_12

    .line 487
    :goto_13
    move v2, v14

    .line 488
    move v10, v15

    .line 489
    const/4 v11, 0x3

    .line 490
    goto/16 :goto_8

    .line 491
    .line 492
    :goto_14
    if-eqz v9, :cond_2f

    .line 493
    .line 494
    return v9

    .line 495
    :cond_2f
    move-wide/from16 v1, v17

    .line 496
    .line 497
    invoke-virtual {v7, v1, v2}, Lu01/f;->h(J)B

    .line 498
    .line 499
    .line 500
    move-result v1

    .line 501
    invoke-virtual {v0, v1}, Lfn/b;->h0(I)Z

    .line 502
    .line 503
    .line 504
    move-result v1

    .line 505
    if-nez v1, :cond_30

    .line 506
    .line 507
    const-string v1, "Expected value"

    .line 508
    .line 509
    invoke-virtual {v0, v1}, Lfn/a;->U(Ljava/lang/String;)V

    .line 510
    .line 511
    .line 512
    throw v16

    .line 513
    :cond_30
    invoke-virtual {v0}, Lfn/b;->V()V

    .line 514
    .line 515
    .line 516
    throw v16

    .line 517
    :cond_31
    invoke-virtual {v7}, Lu01/f;->readByte()B

    .line 518
    .line 519
    .line 520
    iput v3, v0, Lfn/b;->k:I

    .line 521
    .line 522
    return v3

    .line 523
    :cond_32
    if-ne v4, v3, :cond_34

    .line 524
    .line 525
    invoke-virtual {v7}, Lu01/f;->readByte()B

    .line 526
    .line 527
    .line 528
    const/4 v2, 0x4

    .line 529
    iput v2, v0, Lfn/b;->k:I

    .line 530
    .line 531
    return v2

    .line 532
    :cond_33
    invoke-virtual {v7}, Lu01/f;->readByte()B

    .line 533
    .line 534
    .line 535
    const/4 v2, 0x3

    .line 536
    iput v2, v0, Lfn/b;->k:I

    .line 537
    .line 538
    return v2

    .line 539
    :cond_34
    if-eq v4, v3, :cond_36

    .line 540
    .line 541
    if-ne v4, v6, :cond_35

    .line 542
    .line 543
    goto :goto_15

    .line 544
    :cond_35
    const-string v1, "Unexpected value"

    .line 545
    .line 546
    invoke-virtual {v0, v1}, Lfn/a;->U(Ljava/lang/String;)V

    .line 547
    .line 548
    .line 549
    throw v16

    .line 550
    :cond_36
    :goto_15
    invoke-virtual {v0}, Lfn/b;->V()V

    .line 551
    .line 552
    .line 553
    throw v16

    .line 554
    :cond_37
    invoke-virtual {v0}, Lfn/b;->V()V

    .line 555
    .line 556
    .line 557
    throw v16

    .line 558
    :cond_38
    invoke-virtual {v7}, Lu01/f;->readByte()B

    .line 559
    .line 560
    .line 561
    const/16 v1, 0x9

    .line 562
    .line 563
    iput v1, v0, Lfn/b;->k:I

    .line 564
    .line 565
    return v1

    .line 566
    :cond_39
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 567
    .line 568
    const-string v1, "JsonReader is closed"

    .line 569
    .line 570
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 571
    .line 572
    .line 573
    throw v0

    .line 574
    :goto_16
    aput v19, v1, v2

    .line 575
    .line 576
    const/16 v1, 0x7d

    .line 577
    .line 578
    if-ne v4, v5, :cond_3c

    .line 579
    .line 580
    invoke-virtual {v0, v3}, Lfn/b;->l0(Z)I

    .line 581
    .line 582
    .line 583
    move-result v2

    .line 584
    invoke-virtual {v7}, Lu01/f;->readByte()B

    .line 585
    .line 586
    .line 587
    if-eq v2, v13, :cond_3c

    .line 588
    .line 589
    if-eq v2, v12, :cond_3b

    .line 590
    .line 591
    if-ne v2, v1, :cond_3a

    .line 592
    .line 593
    iput v6, v0, Lfn/b;->k:I

    .line 594
    .line 595
    return v6

    .line 596
    :cond_3a
    const-string v1, "Unterminated object"

    .line 597
    .line 598
    invoke-virtual {v0, v1}, Lfn/a;->U(Ljava/lang/String;)V

    .line 599
    .line 600
    .line 601
    throw v16

    .line 602
    :cond_3b
    invoke-virtual {v0}, Lfn/b;->V()V

    .line 603
    .line 604
    .line 605
    throw v16

    .line 606
    :cond_3c
    invoke-virtual {v0, v3}, Lfn/b;->l0(Z)I

    .line 607
    .line 608
    .line 609
    move-result v2

    .line 610
    const/16 v3, 0x22

    .line 611
    .line 612
    if-eq v2, v3, :cond_40

    .line 613
    .line 614
    const/16 v3, 0x27

    .line 615
    .line 616
    if-eq v2, v3, :cond_3f

    .line 617
    .line 618
    if-ne v2, v1, :cond_3e

    .line 619
    .line 620
    if-eq v4, v5, :cond_3d

    .line 621
    .line 622
    invoke-virtual {v7}, Lu01/f;->readByte()B

    .line 623
    .line 624
    .line 625
    iput v6, v0, Lfn/b;->k:I

    .line 626
    .line 627
    return v6

    .line 628
    :cond_3d
    const-string v1, "Expected name"

    .line 629
    .line 630
    invoke-virtual {v0, v1}, Lfn/a;->U(Ljava/lang/String;)V

    .line 631
    .line 632
    .line 633
    throw v16

    .line 634
    :cond_3e
    invoke-virtual {v0}, Lfn/b;->V()V

    .line 635
    .line 636
    .line 637
    throw v16

    .line 638
    :cond_3f
    invoke-virtual {v7}, Lu01/f;->readByte()B

    .line 639
    .line 640
    .line 641
    invoke-virtual {v0}, Lfn/b;->V()V

    .line 642
    .line 643
    .line 644
    throw v16

    .line 645
    :cond_40
    invoke-virtual {v7}, Lu01/f;->readByte()B

    .line 646
    .line 647
    .line 648
    const/16 v1, 0xd

    .line 649
    .line 650
    iput v1, v0, Lfn/b;->k:I

    .line 651
    .line 652
    return v1
.end method

.method public final a()V
    .locals 3

    .line 1
    iget v0, p0, Lfn/b;->k:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lfn/b;->W()I

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
    invoke-virtual {p0, v0}, Lfn/a;->E(I)V

    .line 14
    .line 15
    .line 16
    iget-object v1, p0, Lfn/a;->g:[I

    .line 17
    .line 18
    iget v2, p0, Lfn/a;->d:I

    .line 19
    .line 20
    sub-int/2addr v2, v0

    .line 21
    const/4 v0, 0x0

    .line 22
    aput v0, v1, v2

    .line 23
    .line 24
    iput v0, p0, Lfn/b;->k:I

    .line 25
    .line 26
    return-void

    .line 27
    :cond_1
    new-instance v0, La8/r0;

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
    invoke-virtual {p0}, Lfn/b;->B()I

    .line 37
    .line 38
    .line 39
    move-result v2

    .line 40
    invoke-static {v2}, Lf2/m0;->z(I)Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object v2

    .line 44
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    const-string v2, " at path "

    .line 48
    .line 49
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    invoke-virtual {p0}, Lfn/a;->g()Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    throw v0
.end method

.method public final b()V
    .locals 3

    .line 1
    iget v0, p0, Lfn/b;->k:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lfn/b;->W()I

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
    invoke-virtual {p0, v0}, Lfn/a;->E(I)V

    .line 14
    .line 15
    .line 16
    const/4 v0, 0x0

    .line 17
    iput v0, p0, Lfn/b;->k:I

    .line 18
    .line 19
    return-void

    .line 20
    :cond_1
    new-instance v0, La8/r0;

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
    invoke-virtual {p0}, Lfn/b;->B()I

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    invoke-static {v2}, Lf2/m0;->z(I)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v2

    .line 37
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    const-string v2, " at path "

    .line 41
    .line 42
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    invoke-virtual {p0}, Lfn/a;->g()Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    throw v0
.end method

.method public final close()V
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    iput v0, p0, Lfn/b;->k:I

    .line 3
    .line 4
    iget-object v1, p0, Lfn/a;->e:[I

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
    iput v0, p0, Lfn/a;->d:I

    .line 12
    .line 13
    iget-object v0, p0, Lfn/b;->j:Lu01/f;

    .line 14
    .line 15
    invoke-virtual {v0}, Lu01/f;->a()V

    .line 16
    .line 17
    .line 18
    iget-object p0, p0, Lfn/b;->i:Lu01/b0;

    .line 19
    .line 20
    invoke-virtual {p0}, Lu01/b0;->close()V

    .line 21
    .line 22
    .line 23
    return-void
.end method

.method public final d()V
    .locals 3

    .line 1
    iget v0, p0, Lfn/b;->k:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lfn/b;->W()I

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
    iget v0, p0, Lfn/a;->d:I

    .line 13
    .line 14
    add-int/lit8 v1, v0, -0x1

    .line 15
    .line 16
    iput v1, p0, Lfn/a;->d:I

    .line 17
    .line 18
    iget-object v1, p0, Lfn/a;->g:[I

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
    iput v0, p0, Lfn/b;->k:I

    .line 30
    .line 31
    return-void

    .line 32
    :cond_1
    new-instance v0, La8/r0;

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
    invoke-virtual {p0}, Lfn/b;->B()I

    .line 42
    .line 43
    .line 44
    move-result v2

    .line 45
    invoke-static {v2}, Lf2/m0;->z(I)Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object v2

    .line 49
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

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
    invoke-virtual {p0}, Lfn/a;->g()Ljava/lang/String;

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

.method public final e0(Ljava/lang/String;Lb81/c;)I
    .locals 4

    .line 1
    iget-object v0, p2, Lb81/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, [Ljava/lang/String;

    .line 4
    .line 5
    array-length v0, v0

    .line 6
    const/4 v1, 0x0

    .line 7
    move v2, v1

    .line 8
    :goto_0
    if-ge v2, v0, :cond_1

    .line 9
    .line 10
    iget-object v3, p2, Lb81/c;->e:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v3, [Ljava/lang/String;

    .line 13
    .line 14
    aget-object v3, v3, v2

    .line 15
    .line 16
    invoke-virtual {p1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result v3

    .line 20
    if-eqz v3, :cond_0

    .line 21
    .line 22
    iput v1, p0, Lfn/b;->k:I

    .line 23
    .line 24
    iget-object p2, p0, Lfn/a;->f:[Ljava/lang/String;

    .line 25
    .line 26
    iget p0, p0, Lfn/a;->d:I

    .line 27
    .line 28
    add-int/lit8 p0, p0, -0x1

    .line 29
    .line 30
    aput-object p1, p2, p0

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

.method public final f()V
    .locals 5

    .line 1
    iget v0, p0, Lfn/b;->k:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lfn/b;->W()I

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
    iget v0, p0, Lfn/a;->d:I

    .line 13
    .line 14
    add-int/lit8 v2, v0, -0x1

    .line 15
    .line 16
    iput v2, p0, Lfn/a;->d:I

    .line 17
    .line 18
    iget-object v3, p0, Lfn/a;->f:[Ljava/lang/String;

    .line 19
    .line 20
    const/4 v4, 0x0

    .line 21
    aput-object v4, v3, v2

    .line 22
    .line 23
    iget-object v2, p0, Lfn/a;->g:[I

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
    iput v0, p0, Lfn/b;->k:I

    .line 34
    .line 35
    return-void

    .line 36
    :cond_1
    new-instance v0, La8/r0;

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
    invoke-virtual {p0}, Lfn/b;->B()I

    .line 46
    .line 47
    .line 48
    move-result v2

    .line 49
    invoke-static {v2}, Lf2/m0;->z(I)Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object v2

    .line 53
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    const-string v2, " at path "

    .line 57
    .line 58
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    invoke-virtual {p0}, Lfn/a;->g()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    throw v0
.end method

.method public final h()Z
    .locals 1

    .line 1
    iget v0, p0, Lfn/b;->k:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lfn/b;->W()I

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

.method public final h0(I)Z
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
    invoke-virtual {p0}, Lfn/b;->V()V

    .line 59
    .line 60
    .line 61
    const/4 p0, 0x0

    .line 62
    throw p0

    .line 63
    :cond_1
    :pswitch_1
    const/4 p0, 0x0

    .line 64
    return p0

    .line 65
    :pswitch_data_0
    .packed-switch 0x5b
        :pswitch_1
        :pswitch_0
        :pswitch_1
    .end packed-switch
.end method

.method public final j()Z
    .locals 4

    .line 1
    iget v0, p0, Lfn/b;->k:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lfn/b;->W()I

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
    iput v2, p0, Lfn/b;->k:I

    .line 15
    .line 16
    iget-object v0, p0, Lfn/a;->g:[I

    .line 17
    .line 18
    iget p0, p0, Lfn/a;->d:I

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
    iput v2, p0, Lfn/b;->k:I

    .line 31
    .line 32
    iget-object v0, p0, Lfn/a;->g:[I

    .line 33
    .line 34
    iget p0, p0, Lfn/a;->d:I

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
    new-instance v0, La8/r0;

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
    invoke-virtual {p0}, Lfn/b;->B()I

    .line 53
    .line 54
    .line 55
    move-result v2

    .line 56
    invoke-static {v2}, Lf2/m0;->z(I)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v2

    .line 60
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v2, " at path "

    .line 64
    .line 65
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    invoke-virtual {p0}, Lfn/a;->g()Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    throw v0
.end method

.method public final k()D
    .locals 8

    .line 1
    iget v0, p0, Lfn/b;->k:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lfn/b;->W()I

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
    iput v2, p0, Lfn/b;->k:I

    .line 15
    .line 16
    iget-object v0, p0, Lfn/a;->g:[I

    .line 17
    .line 18
    iget v1, p0, Lfn/a;->d:I

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
    iget-wide v0, p0, Lfn/b;->l:J

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
    iget v0, p0, Lfn/b;->m:I

    .line 43
    .line 44
    int-to-long v0, v0

    .line 45
    iget-object v6, p0, Lfn/b;->j:Lu01/f;

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
    iput-object v0, p0, Lfn/b;->n:Ljava/lang/String;

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
    sget-object v0, Lfn/b;->p:Lu01/i;

    .line 64
    .line 65
    invoke-virtual {p0, v0}, Lfn/b;->n0(Lu01/i;)Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    iput-object v0, p0, Lfn/b;->n:Ljava/lang/String;

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
    sget-object v0, Lfn/b;->o:Lu01/i;

    .line 77
    .line 78
    invoke-virtual {p0, v0}, Lfn/b;->n0(Lu01/i;)Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object v0

    .line 82
    iput-object v0, p0, Lfn/b;->n:Ljava/lang/String;

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
    invoke-virtual {p0}, Lfn/b;->q0()Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object v0

    .line 93
    iput-object v0, p0, Lfn/b;->n:Ljava/lang/String;

    .line 94
    .line 95
    goto :goto_0

    .line 96
    :cond_5
    if-ne v0, v4, :cond_7

    .line 97
    .line 98
    :goto_0
    iput v4, p0, Lfn/b;->k:I

    .line 99
    .line 100
    :try_start_0
    iget-object v0, p0, Lfn/b;->n:Ljava/lang/String;

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
    invoke-static {v0, v1}, Ljava/lang/Double;->isNaN(D)Z

    .line 107
    .line 108
    .line 109
    move-result v3

    .line 110
    if-nez v3, :cond_6

    .line 111
    .line 112
    invoke-static {v0, v1}, Ljava/lang/Double;->isInfinite(D)Z

    .line 113
    .line 114
    .line 115
    move-result v3

    .line 116
    if-nez v3, :cond_6

    .line 117
    .line 118
    const/4 v3, 0x0

    .line 119
    iput-object v3, p0, Lfn/b;->n:Ljava/lang/String;

    .line 120
    .line 121
    iput v2, p0, Lfn/b;->k:I

    .line 122
    .line 123
    iget-object v2, p0, Lfn/a;->g:[I

    .line 124
    .line 125
    iget p0, p0, Lfn/a;->d:I

    .line 126
    .line 127
    add-int/lit8 p0, p0, -0x1

    .line 128
    .line 129
    aget v3, v2, p0

    .line 130
    .line 131
    add-int/lit8 v3, v3, 0x1

    .line 132
    .line 133
    aput v3, v2, p0

    .line 134
    .line 135
    return-wide v0

    .line 136
    :cond_6
    new-instance v2, Lio/ktor/utils/io/k0;

    .line 137
    .line 138
    const-string v3, "JSON forbids NaN and infinities: "

    .line 139
    .line 140
    invoke-static {v3, v5, v0, v1}, Lp3/m;->r(Ljava/lang/String;Ljava/lang/String;D)Ljava/lang/StringBuilder;

    .line 141
    .line 142
    .line 143
    move-result-object v0

    .line 144
    invoke-virtual {p0}, Lfn/a;->g()Ljava/lang/String;

    .line 145
    .line 146
    .line 147
    move-result-object p0

    .line 148
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 149
    .line 150
    .line 151
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 152
    .line 153
    .line 154
    move-result-object p0

    .line 155
    invoke-direct {v2, p0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 156
    .line 157
    .line 158
    throw v2

    .line 159
    :catch_0
    new-instance v0, La8/r0;

    .line 160
    .line 161
    new-instance v1, Ljava/lang/StringBuilder;

    .line 162
    .line 163
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 164
    .line 165
    .line 166
    iget-object v2, p0, Lfn/b;->n:Ljava/lang/String;

    .line 167
    .line 168
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 169
    .line 170
    .line 171
    invoke-virtual {v1, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 172
    .line 173
    .line 174
    invoke-virtual {p0}, Lfn/a;->g()Ljava/lang/String;

    .line 175
    .line 176
    .line 177
    move-result-object p0

    .line 178
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 179
    .line 180
    .line 181
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 182
    .line 183
    .line 184
    move-result-object p0

    .line 185
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 186
    .line 187
    .line 188
    throw v0

    .line 189
    :cond_7
    new-instance v0, La8/r0;

    .line 190
    .line 191
    new-instance v1, Ljava/lang/StringBuilder;

    .line 192
    .line 193
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 194
    .line 195
    .line 196
    invoke-virtual {p0}, Lfn/b;->B()I

    .line 197
    .line 198
    .line 199
    move-result v2

    .line 200
    invoke-static {v2}, Lf2/m0;->z(I)Ljava/lang/String;

    .line 201
    .line 202
    .line 203
    move-result-object v2

    .line 204
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 205
    .line 206
    .line 207
    invoke-virtual {v1, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 208
    .line 209
    .line 210
    invoke-virtual {p0}, Lfn/a;->g()Ljava/lang/String;

    .line 211
    .line 212
    .line 213
    move-result-object p0

    .line 214
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 215
    .line 216
    .line 217
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 218
    .line 219
    .line 220
    move-result-object p0

    .line 221
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 222
    .line 223
    .line 224
    throw v0
.end method

.method public final k0()Ljava/lang/String;
    .locals 3

    .line 1
    iget v0, p0, Lfn/b;->k:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lfn/b;->W()I

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
    invoke-virtual {p0}, Lfn/b;->q0()Ljava/lang/String;

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
    sget-object v0, Lfn/b;->p:Lu01/i;

    .line 23
    .line 24
    invoke-virtual {p0, v0}, Lfn/b;->n0(Lu01/i;)Ljava/lang/String;

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
    sget-object v0, Lfn/b;->o:Lu01/i;

    .line 34
    .line 35
    invoke-virtual {p0, v0}, Lfn/b;->n0(Lu01/i;)Ljava/lang/String;

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
    iget-object v0, p0, Lfn/b;->n:Ljava/lang/String;

    .line 45
    .line 46
    :goto_0
    const/4 v1, 0x0

    .line 47
    iput v1, p0, Lfn/b;->k:I

    .line 48
    .line 49
    iget-object v1, p0, Lfn/a;->f:[Ljava/lang/String;

    .line 50
    .line 51
    iget p0, p0, Lfn/a;->d:I

    .line 52
    .line 53
    add-int/lit8 p0, p0, -0x1

    .line 54
    .line 55
    aput-object v0, v1, p0

    .line 56
    .line 57
    return-object v0

    .line 58
    :cond_4
    new-instance v0, La8/r0;

    .line 59
    .line 60
    new-instance v1, Ljava/lang/StringBuilder;

    .line 61
    .line 62
    const-string v2, "Expected a name but was "

    .line 63
    .line 64
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    invoke-virtual {p0}, Lfn/b;->B()I

    .line 68
    .line 69
    .line 70
    move-result v2

    .line 71
    invoke-static {v2}, Lf2/m0;->z(I)Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object v2

    .line 75
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    const-string v2, " at path "

    .line 79
    .line 80
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    invoke-virtual {p0}, Lfn/a;->g()Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 88
    .line 89
    .line 90
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    throw v0
.end method

.method public final l()I
    .locals 8

    .line 1
    iget v0, p0, Lfn/b;->k:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lfn/b;->W()I

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
    iget-wide v0, p0, Lfn/b;->l:J

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
    iput v2, p0, Lfn/b;->k:I

    .line 27
    .line 28
    iget-object v0, p0, Lfn/a;->g:[I

    .line 29
    .line 30
    iget p0, p0, Lfn/a;->d:I

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
    new-instance v0, La8/r0;

    .line 42
    .line 43
    new-instance v1, Ljava/lang/StringBuilder;

    .line 44
    .line 45
    invoke-direct {v1, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    iget-wide v4, p0, Lfn/b;->l:J

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
    invoke-virtual {p0}, Lfn/a;->g()Ljava/lang/String;

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
    iget v0, p0, Lfn/b;->m:I

    .line 78
    .line 79
    int-to-long v0, v0

    .line 80
    iget-object v6, p0, Lfn/b;->j:Lu01/f;

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
    iput-object v0, p0, Lfn/b;->n:Ljava/lang/String;

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
    new-instance v0, La8/r0;

    .line 107
    .line 108
    new-instance v1, Ljava/lang/StringBuilder;

    .line 109
    .line 110
    invoke-direct {v1, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 111
    .line 112
    .line 113
    invoke-virtual {p0}, Lfn/b;->B()I

    .line 114
    .line 115
    .line 116
    move-result v2

    .line 117
    invoke-static {v2}, Lf2/m0;->z(I)Ljava/lang/String;

    .line 118
    .line 119
    .line 120
    move-result-object v2

    .line 121
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 122
    .line 123
    .line 124
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 125
    .line 126
    .line 127
    invoke-virtual {p0}, Lfn/a;->g()Ljava/lang/String;

    .line 128
    .line 129
    .line 130
    move-result-object p0

    .line 131
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 132
    .line 133
    .line 134
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 135
    .line 136
    .line 137
    move-result-object p0

    .line 138
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 139
    .line 140
    .line 141
    throw v0

    .line 142
    :cond_6
    :goto_0
    if-ne v0, v1, :cond_7

    .line 143
    .line 144
    sget-object v0, Lfn/b;->p:Lu01/i;

    .line 145
    .line 146
    invoke-virtual {p0, v0}, Lfn/b;->n0(Lu01/i;)Ljava/lang/String;

    .line 147
    .line 148
    .line 149
    move-result-object v0

    .line 150
    goto :goto_1

    .line 151
    :cond_7
    sget-object v0, Lfn/b;->o:Lu01/i;

    .line 152
    .line 153
    invoke-virtual {p0, v0}, Lfn/b;->n0(Lu01/i;)Ljava/lang/String;

    .line 154
    .line 155
    .line 156
    move-result-object v0

    .line 157
    :goto_1
    iput-object v0, p0, Lfn/b;->n:Ljava/lang/String;

    .line 158
    .line 159
    :try_start_0
    invoke-static {v0}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 160
    .line 161
    .line 162
    move-result v0

    .line 163
    iput v2, p0, Lfn/b;->k:I

    .line 164
    .line 165
    iget-object v1, p0, Lfn/a;->g:[I

    .line 166
    .line 167
    iget v6, p0, Lfn/a;->d:I

    .line 168
    .line 169
    add-int/lit8 v6, v6, -0x1

    .line 170
    .line 171
    aget v7, v1, v6

    .line 172
    .line 173
    add-int/lit8 v7, v7, 0x1

    .line 174
    .line 175
    aput v7, v1, v6
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    .line 176
    .line 177
    return v0

    .line 178
    :catch_0
    :goto_2
    iput v5, p0, Lfn/b;->k:I

    .line 179
    .line 180
    :try_start_1
    iget-object v0, p0, Lfn/b;->n:Ljava/lang/String;

    .line 181
    .line 182
    invoke-static {v0}, Ljava/lang/Double;->parseDouble(Ljava/lang/String;)D

    .line 183
    .line 184
    .line 185
    move-result-wide v0
    :try_end_1
    .catch Ljava/lang/NumberFormatException; {:try_start_1 .. :try_end_1} :catch_1

    .line 186
    double-to-int v5, v0

    .line 187
    int-to-double v6, v5

    .line 188
    cmpl-double v0, v6, v0

    .line 189
    .line 190
    if-nez v0, :cond_8

    .line 191
    .line 192
    const/4 v0, 0x0

    .line 193
    iput-object v0, p0, Lfn/b;->n:Ljava/lang/String;

    .line 194
    .line 195
    iput v2, p0, Lfn/b;->k:I

    .line 196
    .line 197
    iget-object v0, p0, Lfn/a;->g:[I

    .line 198
    .line 199
    iget p0, p0, Lfn/a;->d:I

    .line 200
    .line 201
    add-int/lit8 p0, p0, -0x1

    .line 202
    .line 203
    aget v1, v0, p0

    .line 204
    .line 205
    add-int/lit8 v1, v1, 0x1

    .line 206
    .line 207
    aput v1, v0, p0

    .line 208
    .line 209
    return v5

    .line 210
    :cond_8
    new-instance v0, La8/r0;

    .line 211
    .line 212
    new-instance v1, Ljava/lang/StringBuilder;

    .line 213
    .line 214
    invoke-direct {v1, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 215
    .line 216
    .line 217
    iget-object v2, p0, Lfn/b;->n:Ljava/lang/String;

    .line 218
    .line 219
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 220
    .line 221
    .line 222
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 223
    .line 224
    .line 225
    invoke-virtual {p0}, Lfn/a;->g()Ljava/lang/String;

    .line 226
    .line 227
    .line 228
    move-result-object p0

    .line 229
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 230
    .line 231
    .line 232
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 233
    .line 234
    .line 235
    move-result-object p0

    .line 236
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 237
    .line 238
    .line 239
    throw v0

    .line 240
    :catch_1
    new-instance v0, La8/r0;

    .line 241
    .line 242
    new-instance v1, Ljava/lang/StringBuilder;

    .line 243
    .line 244
    invoke-direct {v1, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 245
    .line 246
    .line 247
    iget-object v2, p0, Lfn/b;->n:Ljava/lang/String;

    .line 248
    .line 249
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 250
    .line 251
    .line 252
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 253
    .line 254
    .line 255
    invoke-virtual {p0}, Lfn/a;->g()Ljava/lang/String;

    .line 256
    .line 257
    .line 258
    move-result-object p0

    .line 259
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 260
    .line 261
    .line 262
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 263
    .line 264
    .line 265
    move-result-object p0

    .line 266
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 267
    .line 268
    .line 269
    throw v0
.end method

.method public final l0(Z)I
    .locals 7

    .line 1
    const/4 v0, 0x0

    .line 2
    :goto_0
    add-int/lit8 v1, v0, 0x1

    .line 3
    .line 4
    int-to-long v2, v1

    .line 5
    iget-object v4, p0, Lfn/b;->i:Lu01/b0;

    .line 6
    .line 7
    invoke-virtual {v4, v2, v3}, Lu01/b0;->c(J)Z

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    if-eqz v2, :cond_5

    .line 12
    .line 13
    int-to-long v2, v0

    .line 14
    iget-object v0, p0, Lfn/b;->j:Lu01/f;

    .line 15
    .line 16
    invoke-virtual {v0, v2, v3}, Lu01/f;->h(J)B

    .line 17
    .line 18
    .line 19
    move-result v5

    .line 20
    const/16 v6, 0xa

    .line 21
    .line 22
    if-eq v5, v6, :cond_4

    .line 23
    .line 24
    const/16 v6, 0x20

    .line 25
    .line 26
    if-eq v5, v6, :cond_4

    .line 27
    .line 28
    const/16 v6, 0xd

    .line 29
    .line 30
    if-eq v5, v6, :cond_4

    .line 31
    .line 32
    const/16 v6, 0x9

    .line 33
    .line 34
    if-ne v5, v6, :cond_0

    .line 35
    .line 36
    goto :goto_2

    .line 37
    :cond_0
    invoke-virtual {v0, v2, v3}, Lu01/f;->skip(J)V

    .line 38
    .line 39
    .line 40
    const/16 p1, 0x2f

    .line 41
    .line 42
    const/4 v0, 0x0

    .line 43
    if-ne v5, p1, :cond_2

    .line 44
    .line 45
    const-wide/16 v1, 0x2

    .line 46
    .line 47
    invoke-virtual {v4, v1, v2}, Lu01/b0;->c(J)Z

    .line 48
    .line 49
    .line 50
    move-result p1

    .line 51
    if-nez p1, :cond_1

    .line 52
    .line 53
    goto :goto_1

    .line 54
    :cond_1
    invoke-virtual {p0}, Lfn/b;->V()V

    .line 55
    .line 56
    .line 57
    throw v0

    .line 58
    :cond_2
    const/16 p1, 0x23

    .line 59
    .line 60
    if-eq v5, p1, :cond_3

    .line 61
    .line 62
    :goto_1
    return v5

    .line 63
    :cond_3
    invoke-virtual {p0}, Lfn/b;->V()V

    .line 64
    .line 65
    .line 66
    throw v0

    .line 67
    :cond_4
    :goto_2
    move v0, v1

    .line 68
    goto :goto_0

    .line 69
    :cond_5
    if-nez p1, :cond_6

    .line 70
    .line 71
    const/4 p0, -0x1

    .line 72
    return p0

    .line 73
    :cond_6
    new-instance p0, Ljava/io/EOFException;

    .line 74
    .line 75
    const-string p1, "End of input"

    .line 76
    .line 77
    invoke-direct {p0, p1}, Ljava/io/EOFException;-><init>(Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    throw p0
.end method

.method public final n0(Lu01/i;)Ljava/lang/String;
    .locals 7

    .line 1
    const/4 v0, 0x0

    .line 2
    move-object v1, v0

    .line 3
    :goto_0
    iget-object v2, p0, Lfn/b;->i:Lu01/b0;

    .line 4
    .line 5
    invoke-virtual {v2, p1}, Lu01/b0;->y(Lu01/i;)J

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
    iget-object v4, p0, Lfn/b;->j:Lu01/f;

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
    invoke-virtual {p0}, Lfn/b;->r0()C

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
    invoke-virtual {p0, p1}, Lfn/a;->U(Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    throw v0
.end method

.method public final q()Ljava/lang/String;
    .locals 4

    .line 1
    iget v0, p0, Lfn/b;->k:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lfn/b;->W()I

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
    invoke-virtual {p0}, Lfn/b;->q0()Ljava/lang/String;

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
    sget-object v0, Lfn/b;->p:Lu01/i;

    .line 23
    .line 24
    invoke-virtual {p0, v0}, Lfn/b;->n0(Lu01/i;)Ljava/lang/String;

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
    sget-object v0, Lfn/b;->o:Lu01/i;

    .line 34
    .line 35
    invoke-virtual {p0, v0}, Lfn/b;->n0(Lu01/i;)Ljava/lang/String;

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
    iget-object v0, p0, Lfn/b;->n:Ljava/lang/String;

    .line 45
    .line 46
    const/4 v1, 0x0

    .line 47
    iput-object v1, p0, Lfn/b;->n:Ljava/lang/String;

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
    iget-wide v0, p0, Lfn/b;->l:J

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
    iget v0, p0, Lfn/b;->m:I

    .line 66
    .line 67
    int-to-long v0, v0

    .line 68
    iget-object v2, p0, Lfn/b;->j:Lu01/f;

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
    iput v1, p0, Lfn/b;->k:I

    .line 81
    .line 82
    iget-object v1, p0, Lfn/a;->g:[I

    .line 83
    .line 84
    iget p0, p0, Lfn/a;->d:I

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
    new-instance v0, La8/r0;

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
    invoke-virtual {p0}, Lfn/b;->B()I

    .line 105
    .line 106
    .line 107
    move-result v2

    .line 108
    invoke-static {v2}, Lf2/m0;->z(I)Ljava/lang/String;

    .line 109
    .line 110
    .line 111
    move-result-object v2

    .line 112
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 113
    .line 114
    .line 115
    const-string v2, " at path "

    .line 116
    .line 117
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 118
    .line 119
    .line 120
    invoke-virtual {p0}, Lfn/a;->g()Ljava/lang/String;

    .line 121
    .line 122
    .line 123
    move-result-object p0

    .line 124
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 125
    .line 126
    .line 127
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 128
    .line 129
    .line 130
    move-result-object p0

    .line 131
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    throw v0
.end method

.method public final q0()Ljava/lang/String;
    .locals 4

    .line 1
    iget-object v0, p0, Lfn/b;->i:Lu01/b0;

    .line 2
    .line 3
    sget-object v1, Lfn/b;->q:Lu01/i;

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Lu01/b0;->y(Lu01/i;)J

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
    iget-object p0, p0, Lfn/b;->j:Lu01/f;

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

.method public final r0()C
    .locals 9

    .line 1
    const-wide/16 v0, 0x1

    .line 2
    .line 3
    iget-object v2, p0, Lfn/b;->i:Lu01/b0;

    .line 4
    .line 5
    invoke-virtual {v2, v0, v1}, Lu01/b0;->c(J)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/4 v1, 0x0

    .line 10
    if-eqz v0, :cond_c

    .line 11
    .line 12
    iget-object v0, p0, Lfn/b;->j:Lu01/f;

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
    if-eq v3, v4, :cond_b

    .line 21
    .line 22
    const/16 v5, 0x22

    .line 23
    .line 24
    if-eq v3, v5, :cond_b

    .line 25
    .line 26
    const/16 v5, 0x27

    .line 27
    .line 28
    if-eq v3, v5, :cond_b

    .line 29
    .line 30
    const/16 v5, 0x2f

    .line 31
    .line 32
    if-eq v3, v5, :cond_b

    .line 33
    .line 34
    const/16 v5, 0x5c

    .line 35
    .line 36
    if-eq v3, v5, :cond_b

    .line 37
    .line 38
    const/16 v5, 0x62

    .line 39
    .line 40
    if-eq v3, v5, :cond_a

    .line 41
    .line 42
    const/16 v5, 0x66

    .line 43
    .line 44
    if-eq v3, v5, :cond_9

    .line 45
    .line 46
    const/16 v6, 0x6e

    .line 47
    .line 48
    if-eq v3, v6, :cond_8

    .line 49
    .line 50
    const/16 v4, 0x72

    .line 51
    .line 52
    if-eq v3, v4, :cond_7

    .line 53
    .line 54
    const/16 v4, 0x74

    .line 55
    .line 56
    if-eq v3, v4, :cond_6

    .line 57
    .line 58
    const/16 v4, 0x75

    .line 59
    .line 60
    if-ne v3, v4, :cond_5

    .line 61
    .line 62
    const-wide/16 v3, 0x4

    .line 63
    .line 64
    invoke-virtual {v2, v3, v4}, Lu01/b0;->c(J)Z

    .line 65
    .line 66
    .line 67
    move-result v2

    .line 68
    if-eqz v2, :cond_4

    .line 69
    .line 70
    const/4 v2, 0x0

    .line 71
    move v6, v2

    .line 72
    :goto_0
    const/4 v7, 0x4

    .line 73
    if-ge v2, v7, :cond_3

    .line 74
    .line 75
    int-to-long v7, v2

    .line 76
    invoke-virtual {v0, v7, v8}, Lu01/f;->h(J)B

    .line 77
    .line 78
    .line 79
    move-result v7

    .line 80
    shl-int/lit8 v6, v6, 0x4

    .line 81
    .line 82
    int-to-char v6, v6

    .line 83
    const/16 v8, 0x30

    .line 84
    .line 85
    if-lt v7, v8, :cond_0

    .line 86
    .line 87
    const/16 v8, 0x39

    .line 88
    .line 89
    if-gt v7, v8, :cond_0

    .line 90
    .line 91
    add-int/lit8 v7, v7, -0x30

    .line 92
    .line 93
    :goto_1
    add-int/2addr v7, v6

    .line 94
    int-to-char v6, v7

    .line 95
    goto :goto_2

    .line 96
    :cond_0
    const/16 v8, 0x61

    .line 97
    .line 98
    if-lt v7, v8, :cond_1

    .line 99
    .line 100
    if-gt v7, v5, :cond_1

    .line 101
    .line 102
    add-int/lit8 v7, v7, -0x57

    .line 103
    .line 104
    goto :goto_1

    .line 105
    :cond_1
    const/16 v8, 0x41

    .line 106
    .line 107
    if-lt v7, v8, :cond_2

    .line 108
    .line 109
    const/16 v8, 0x46

    .line 110
    .line 111
    if-gt v7, v8, :cond_2

    .line 112
    .line 113
    add-int/lit8 v7, v7, -0x37

    .line 114
    .line 115
    goto :goto_1

    .line 116
    :goto_2
    add-int/lit8 v2, v2, 0x1

    .line 117
    .line 118
    goto :goto_0

    .line 119
    :cond_2
    sget-object v2, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 120
    .line 121
    invoke-virtual {v0, v3, v4, v2}, Lu01/f;->M(JLjava/nio/charset/Charset;)Ljava/lang/String;

    .line 122
    .line 123
    .line 124
    move-result-object v0

    .line 125
    const-string v2, "\\u"

    .line 126
    .line 127
    invoke-virtual {v2, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 128
    .line 129
    .line 130
    move-result-object v0

    .line 131
    invoke-virtual {p0, v0}, Lfn/a;->U(Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    throw v1

    .line 135
    :cond_3
    invoke-virtual {v0, v3, v4}, Lu01/f;->skip(J)V

    .line 136
    .line 137
    .line 138
    return v6

    .line 139
    :cond_4
    new-instance v0, Ljava/io/EOFException;

    .line 140
    .line 141
    new-instance v1, Ljava/lang/StringBuilder;

    .line 142
    .line 143
    const-string v2, "Unterminated escape sequence at path "

    .line 144
    .line 145
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 146
    .line 147
    .line 148
    invoke-virtual {p0}, Lfn/a;->g()Ljava/lang/String;

    .line 149
    .line 150
    .line 151
    move-result-object p0

    .line 152
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 153
    .line 154
    .line 155
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 156
    .line 157
    .line 158
    move-result-object p0

    .line 159
    invoke-direct {v0, p0}, Ljava/io/EOFException;-><init>(Ljava/lang/String;)V

    .line 160
    .line 161
    .line 162
    throw v0

    .line 163
    :cond_5
    new-instance v0, Ljava/lang/StringBuilder;

    .line 164
    .line 165
    const-string v2, "Invalid escape sequence: \\"

    .line 166
    .line 167
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 168
    .line 169
    .line 170
    int-to-char v2, v3

    .line 171
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 172
    .line 173
    .line 174
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 175
    .line 176
    .line 177
    move-result-object v0

    .line 178
    invoke-virtual {p0, v0}, Lfn/a;->U(Ljava/lang/String;)V

    .line 179
    .line 180
    .line 181
    throw v1

    .line 182
    :cond_6
    const/16 p0, 0x9

    .line 183
    .line 184
    return p0

    .line 185
    :cond_7
    const/16 p0, 0xd

    .line 186
    .line 187
    return p0

    .line 188
    :cond_8
    return v4

    .line 189
    :cond_9
    const/16 p0, 0xc

    .line 190
    .line 191
    return p0

    .line 192
    :cond_a
    const/16 p0, 0x8

    .line 193
    .line 194
    return p0

    .line 195
    :cond_b
    int-to-char p0, v3

    .line 196
    return p0

    .line 197
    :cond_c
    const-string v0, "Unterminated escape sequence"

    .line 198
    .line 199
    invoke-virtual {p0, v0}, Lfn/a;->U(Ljava/lang/String;)V

    .line 200
    .line 201
    .line 202
    throw v1
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
    iget-object p0, p0, Lfn/b;->i:Lu01/b0;

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

.method public final x0(Lu01/i;)V
    .locals 7

    .line 1
    :goto_0
    iget-object v0, p0, Lfn/b;->i:Lu01/b0;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lu01/b0;->y(Lu01/i;)J

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
    iget-object v2, p0, Lfn/b;->j:Lu01/f;

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
    invoke-virtual {p0}, Lfn/b;->r0()C

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
    invoke-virtual {p0, p1}, Lfn/a;->U(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    const/4 p0, 0x0

    .line 44
    throw p0
.end method
