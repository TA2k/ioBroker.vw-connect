.class public final Lwe0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lp7/b;
.implements Lgs/e;
.implements Lh8/y0;
.implements Lj9/h;
.implements Ll9/h;
.implements Llp/jg;
.implements Lrr/b;
.implements Lvp/g;
.implements Lvp/u;
.implements Lvs/a;
.implements Lzo/c;


# static fields
.field public static final synthetic e:Lwe0/b;

.field public static final synthetic f:Lwe0/b;

.field public static final synthetic g:Lwe0/b;

.field public static final synthetic h:Lwe0/b;

.field public static final synthetic i:Lwe0/b;

.field public static final synthetic j:Lwe0/b;

.field public static final synthetic k:Lwe0/b;

.field public static final synthetic l:Lwe0/b;

.field public static final synthetic m:Lwe0/b;


# instance fields
.field public final synthetic d:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lwe0/b;

    .line 2
    .line 3
    const/16 v1, 0xf

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lwe0/b;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lwe0/b;->e:Lwe0/b;

    .line 9
    .line 10
    new-instance v0, Lwe0/b;

    .line 11
    .line 12
    const/16 v1, 0x10

    .line 13
    .line 14
    invoke-direct {v0, v1}, Lwe0/b;-><init>(I)V

    .line 15
    .line 16
    .line 17
    sput-object v0, Lwe0/b;->f:Lwe0/b;

    .line 18
    .line 19
    new-instance v0, Lwe0/b;

    .line 20
    .line 21
    const/16 v1, 0x11

    .line 22
    .line 23
    invoke-direct {v0, v1}, Lwe0/b;-><init>(I)V

    .line 24
    .line 25
    .line 26
    sput-object v0, Lwe0/b;->g:Lwe0/b;

    .line 27
    .line 28
    new-instance v0, Lwe0/b;

    .line 29
    .line 30
    const/16 v1, 0x12

    .line 31
    .line 32
    invoke-direct {v0, v1}, Lwe0/b;-><init>(I)V

    .line 33
    .line 34
    .line 35
    sput-object v0, Lwe0/b;->h:Lwe0/b;

    .line 36
    .line 37
    new-instance v0, Lwe0/b;

    .line 38
    .line 39
    const/16 v1, 0x13

    .line 40
    .line 41
    invoke-direct {v0, v1}, Lwe0/b;-><init>(I)V

    .line 42
    .line 43
    .line 44
    sput-object v0, Lwe0/b;->i:Lwe0/b;

    .line 45
    .line 46
    new-instance v0, Lwe0/b;

    .line 47
    .line 48
    const/16 v1, 0x14

    .line 49
    .line 50
    invoke-direct {v0, v1}, Lwe0/b;-><init>(I)V

    .line 51
    .line 52
    .line 53
    sput-object v0, Lwe0/b;->j:Lwe0/b;

    .line 54
    .line 55
    new-instance v0, Lwe0/b;

    .line 56
    .line 57
    const/16 v1, 0x15

    .line 58
    .line 59
    invoke-direct {v0, v1}, Lwe0/b;-><init>(I)V

    .line 60
    .line 61
    .line 62
    sput-object v0, Lwe0/b;->k:Lwe0/b;

    .line 63
    .line 64
    new-instance v0, Lwe0/b;

    .line 65
    .line 66
    const/16 v1, 0x16

    .line 67
    .line 68
    invoke-direct {v0, v1}, Lwe0/b;-><init>(I)V

    .line 69
    .line 70
    .line 71
    sput-object v0, Lwe0/b;->l:Lwe0/b;

    .line 72
    .line 73
    new-instance v0, Lwe0/b;

    .line 74
    .line 75
    const/16 v1, 0x17

    .line 76
    .line 77
    invoke-direct {v0, v1}, Lwe0/b;-><init>(I)V

    .line 78
    .line 79
    .line 80
    sput-object v0, Lwe0/b;->m:Lwe0/b;

    .line 81
    .line 82
    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lwe0/b;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public static r(B[B)V
    .locals 10

    .line 1
    array-length v0, p1

    .line 2
    if-eqz v0, :cond_9

    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    aget-byte v1, p1, v0

    .line 6
    .line 7
    const/4 v2, 0x1

    .line 8
    if-lt v1, v2, :cond_9

    .line 9
    .line 10
    const/4 v2, 0x6

    .line 11
    if-gt v1, v2, :cond_9

    .line 12
    .line 13
    if-ne v1, p0, :cond_8

    .line 14
    .line 15
    const/4 v0, 0x3

    .line 16
    if-eq p0, v0, :cond_6

    .line 17
    .line 18
    const/4 v0, 0x4

    .line 19
    if-eq p0, v0, :cond_4

    .line 20
    .line 21
    const/4 v0, 0x5

    .line 22
    if-eq p0, v0, :cond_2

    .line 23
    .line 24
    if-eq p0, v2, :cond_0

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    array-length p0, p1

    .line 28
    if-lt p0, v0, :cond_1

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_1
    new-instance p0, Lvv0/a;

    .line 32
    .line 33
    const-string p1, "Not enough bytes for Set<String> value"

    .line 34
    .line 35
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    throw p0

    .line 39
    :cond_2
    array-length p0, p1

    .line 40
    if-ne p0, v0, :cond_3

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_3
    new-instance p0, Lvv0/a;

    .line 44
    .line 45
    const-string p1, "Not enough bytes for Float value"

    .line 46
    .line 47
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw p0

    .line 51
    :cond_4
    array-length p0, p1

    .line 52
    const/16 p1, 0x9

    .line 53
    .line 54
    if-ne p0, p1, :cond_5

    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_5
    new-instance p0, Lvv0/a;

    .line 58
    .line 59
    const-string p1, "Not enough bytes for Long value"

    .line 60
    .line 61
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    throw p0

    .line 65
    :cond_6
    array-length p0, p1

    .line 66
    const/4 p1, 0x2

    .line 67
    if-ne p0, p1, :cond_7

    .line 68
    .line 69
    :goto_0
    return-void

    .line 70
    :cond_7
    new-instance p0, Lvv0/a;

    .line 71
    .line 72
    const-string p1, "Not enough bytes for Boolean value"

    .line 73
    .line 74
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    throw p0

    .line 78
    :cond_8
    new-instance v1, Lvv0/a;

    .line 79
    .line 80
    new-instance v2, Ljava/lang/StringBuilder;

    .line 81
    .line 82
    const-string v3, "Requesting \'"

    .line 83
    .line 84
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    const-string v3, "byte[]"

    .line 88
    .line 89
    const-string v4, "String"

    .line 90
    .line 91
    const-string v5, "Boolean"

    .line 92
    .line 93
    const-string v6, "Long"

    .line 94
    .line 95
    const-string v7, "Float"

    .line 96
    .line 97
    const-string v8, "Set<String>"

    .line 98
    .line 99
    const-string v9, "Unknown"

    .line 100
    .line 101
    packed-switch p0, :pswitch_data_0

    .line 102
    .line 103
    .line 104
    move-object p0, v9

    .line 105
    goto :goto_1

    .line 106
    :pswitch_0
    move-object p0, v8

    .line 107
    goto :goto_1

    .line 108
    :pswitch_1
    move-object p0, v7

    .line 109
    goto :goto_1

    .line 110
    :pswitch_2
    move-object p0, v6

    .line 111
    goto :goto_1

    .line 112
    :pswitch_3
    move-object p0, v5

    .line 113
    goto :goto_1

    .line 114
    :pswitch_4
    move-object p0, v4

    .line 115
    goto :goto_1

    .line 116
    :pswitch_5
    move-object p0, v3

    .line 117
    :goto_1
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 118
    .line 119
    .line 120
    const-string p0, "\' but keychain contains \'"

    .line 121
    .line 122
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 123
    .line 124
    .line 125
    aget-byte p0, p1, v0

    .line 126
    .line 127
    packed-switch p0, :pswitch_data_1

    .line 128
    .line 129
    .line 130
    move-object v3, v9

    .line 131
    goto :goto_2

    .line 132
    :pswitch_6
    move-object v3, v8

    .line 133
    goto :goto_2

    .line 134
    :pswitch_7
    move-object v3, v7

    .line 135
    goto :goto_2

    .line 136
    :pswitch_8
    move-object v3, v6

    .line 137
    goto :goto_2

    .line 138
    :pswitch_9
    move-object v3, v5

    .line 139
    goto :goto_2

    .line 140
    :pswitch_a
    move-object v3, v4

    .line 141
    :goto_2
    :pswitch_b
    const-string p0, "\' type"

    .line 142
    .line 143
    invoke-static {v2, v3, p0}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 144
    .line 145
    .line 146
    move-result-object p0

    .line 147
    invoke-direct {v1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 148
    .line 149
    .line 150
    throw v1

    .line 151
    :cond_9
    new-instance p0, Lvv0/a;

    .line 152
    .line 153
    const-string p1, "Invalid encoded keychain content"

    .line 154
    .line 155
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 156
    .line 157
    .line 158
    throw p0

    .line 159
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch

    .line 160
    .line 161
    .line 162
    .line 163
    .line 164
    .line 165
    .line 166
    .line 167
    .line 168
    .line 169
    .line 170
    .line 171
    .line 172
    .line 173
    :pswitch_data_1
    .packed-switch 0x1
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
    .end packed-switch
.end method

.method public static s(Ls71/g;Ls71/j;Ls71/i;)Ls71/k;
    .locals 4

    .line 1
    sget-object v0, Ls71/j;->e:Ls71/j;

    .line 2
    .line 3
    if-ne p1, v0, :cond_0

    .line 4
    .line 5
    sget-object v1, Ls71/g;->e:Ls71/g;

    .line 6
    .line 7
    if-ne p0, v1, :cond_0

    .line 8
    .line 9
    sget-object v1, Ls71/i;->f:Ls71/i;

    .line 10
    .line 11
    if-ne p2, v1, :cond_0

    .line 12
    .line 13
    sget-object p0, Ls71/k;->j:Ls71/k;

    .line 14
    .line 15
    return-object p0

    .line 16
    :cond_0
    sget-object v1, Ls71/j;->f:Ls71/j;

    .line 17
    .line 18
    if-ne p1, v1, :cond_1

    .line 19
    .line 20
    sget-object v2, Ls71/g;->e:Ls71/g;

    .line 21
    .line 22
    if-ne p0, v2, :cond_1

    .line 23
    .line 24
    sget-object v2, Ls71/i;->f:Ls71/i;

    .line 25
    .line 26
    if-ne p2, v2, :cond_1

    .line 27
    .line 28
    sget-object p0, Ls71/k;->k:Ls71/k;

    .line 29
    .line 30
    return-object p0

    .line 31
    :cond_1
    if-ne p1, v0, :cond_2

    .line 32
    .line 33
    sget-object v2, Ls71/g;->e:Ls71/g;

    .line 34
    .line 35
    if-ne p0, v2, :cond_2

    .line 36
    .line 37
    sget-object v2, Ls71/i;->e:Ls71/i;

    .line 38
    .line 39
    if-ne p2, v2, :cond_2

    .line 40
    .line 41
    sget-object p0, Ls71/k;->h:Ls71/k;

    .line 42
    .line 43
    return-object p0

    .line 44
    :cond_2
    if-ne p1, v1, :cond_3

    .line 45
    .line 46
    sget-object v2, Ls71/g;->e:Ls71/g;

    .line 47
    .line 48
    if-ne p0, v2, :cond_3

    .line 49
    .line 50
    sget-object v2, Ls71/i;->e:Ls71/i;

    .line 51
    .line 52
    if-ne p2, v2, :cond_3

    .line 53
    .line 54
    sget-object p0, Ls71/k;->i:Ls71/k;

    .line 55
    .line 56
    return-object p0

    .line 57
    :cond_3
    sget-object v2, Ls71/j;->g:Ls71/j;

    .line 58
    .line 59
    if-ne p1, v2, :cond_4

    .line 60
    .line 61
    sget-object v3, Ls71/g;->e:Ls71/g;

    .line 62
    .line 63
    if-ne p0, v3, :cond_4

    .line 64
    .line 65
    sget-object v3, Ls71/i;->h:Ls71/i;

    .line 66
    .line 67
    if-ne p2, v3, :cond_4

    .line 68
    .line 69
    sget-object p0, Ls71/k;->f:Ls71/k;

    .line 70
    .line 71
    return-object p0

    .line 72
    :cond_4
    if-ne p1, v2, :cond_5

    .line 73
    .line 74
    sget-object v3, Ls71/g;->f:Ls71/g;

    .line 75
    .line 76
    if-ne p0, v3, :cond_5

    .line 77
    .line 78
    sget-object v3, Ls71/i;->h:Ls71/i;

    .line 79
    .line 80
    if-ne p2, v3, :cond_5

    .line 81
    .line 82
    sget-object p0, Ls71/k;->g:Ls71/k;

    .line 83
    .line 84
    return-object p0

    .line 85
    :cond_5
    if-ne p1, v2, :cond_6

    .line 86
    .line 87
    sget-object v3, Ls71/g;->e:Ls71/g;

    .line 88
    .line 89
    if-ne p0, v3, :cond_6

    .line 90
    .line 91
    sget-object v3, Ls71/i;->f:Ls71/i;

    .line 92
    .line 93
    if-ne p2, v3, :cond_6

    .line 94
    .line 95
    sget-object p0, Ls71/k;->f:Ls71/k;

    .line 96
    .line 97
    return-object p0

    .line 98
    :cond_6
    if-ne p1, v2, :cond_7

    .line 99
    .line 100
    sget-object v2, Ls71/g;->f:Ls71/g;

    .line 101
    .line 102
    if-ne p0, v2, :cond_7

    .line 103
    .line 104
    sget-object v2, Ls71/i;->f:Ls71/i;

    .line 105
    .line 106
    if-ne p2, v2, :cond_7

    .line 107
    .line 108
    sget-object p0, Ls71/k;->g:Ls71/k;

    .line 109
    .line 110
    return-object p0

    .line 111
    :cond_7
    if-ne p1, v0, :cond_8

    .line 112
    .line 113
    sget-object v0, Ls71/g;->f:Ls71/g;

    .line 114
    .line 115
    if-ne p0, v0, :cond_8

    .line 116
    .line 117
    sget-object v0, Ls71/i;->f:Ls71/i;

    .line 118
    .line 119
    if-ne p2, v0, :cond_8

    .line 120
    .line 121
    sget-object p0, Ls71/k;->l:Ls71/k;

    .line 122
    .line 123
    return-object p0

    .line 124
    :cond_8
    if-ne p1, v1, :cond_9

    .line 125
    .line 126
    sget-object v0, Ls71/g;->f:Ls71/g;

    .line 127
    .line 128
    if-ne p0, v0, :cond_9

    .line 129
    .line 130
    sget-object v0, Ls71/i;->f:Ls71/i;

    .line 131
    .line 132
    if-ne p2, v0, :cond_9

    .line 133
    .line 134
    sget-object p0, Ls71/k;->m:Ls71/k;

    .line 135
    .line 136
    return-object p0

    .line 137
    :cond_9
    sget-object v0, Ls71/j;->d:Ls71/j;

    .line 138
    .line 139
    if-ne p1, v0, :cond_a

    .line 140
    .line 141
    sget-object v1, Ls71/g;->d:Ls71/g;

    .line 142
    .line 143
    if-ne p0, v1, :cond_a

    .line 144
    .line 145
    sget-object v1, Ls71/i;->j:Ls71/i;

    .line 146
    .line 147
    if-ne p2, v1, :cond_a

    .line 148
    .line 149
    sget-object p0, Ls71/k;->n:Ls71/k;

    .line 150
    .line 151
    return-object p0

    .line 152
    :cond_a
    if-ne p1, v0, :cond_b

    .line 153
    .line 154
    sget-object p1, Ls71/g;->d:Ls71/g;

    .line 155
    .line 156
    if-ne p0, p1, :cond_b

    .line 157
    .line 158
    sget-object p0, Ls71/i;->k:Ls71/i;

    .line 159
    .line 160
    if-ne p2, p0, :cond_b

    .line 161
    .line 162
    sget-object p0, Ls71/k;->n:Ls71/k;

    .line 163
    .line 164
    return-object p0

    .line 165
    :cond_b
    sget-object p0, Ls71/k;->e:Ls71/k;

    .line 166
    .line 167
    return-object p0
.end method

.method public static t([B)Ljava/util/HashSet;
    .locals 6

    .line 1
    const/4 v0, 0x6

    .line 2
    invoke-static {v0, p0}, Lwe0/b;->r(B[B)V

    .line 3
    .line 4
    .line 5
    :try_start_0
    array-length v0, p0

    .line 6
    const/4 v1, 0x1

    .line 7
    sub-int/2addr v0, v1

    .line 8
    invoke-static {p0, v1, v0}, Ljava/nio/ByteBuffer;->wrap([BII)Ljava/nio/ByteBuffer;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    invoke-virtual {p0}, Ljava/nio/ByteBuffer;->getInt()I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    new-instance v1, Ljava/util/HashSet;

    .line 17
    .line 18
    invoke-direct {v1, v0}, Ljava/util/HashSet;-><init>(I)V

    .line 19
    .line 20
    .line 21
    const/4 v2, 0x0

    .line 22
    :goto_0
    if-ge v2, v0, :cond_0

    .line 23
    .line 24
    invoke-virtual {p0}, Ljava/nio/ByteBuffer;->getInt()I

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    new-array v3, v3, [B

    .line 29
    .line 30
    invoke-virtual {p0, v3}, Ljava/nio/ByteBuffer;->get([B)Ljava/nio/ByteBuffer;

    .line 31
    .line 32
    .line 33
    new-instance v4, Ljava/lang/String;

    .line 34
    .line 35
    invoke-static {}, Ljava/nio/charset/Charset;->defaultCharset()Ljava/nio/charset/Charset;

    .line 36
    .line 37
    .line 38
    move-result-object v5

    .line 39
    invoke-direct {v4, v3, v5}, Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {v1, v4}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catch Ljava/nio/BufferUnderflowException; {:try_start_0 .. :try_end_0} :catch_0

    .line 43
    .line 44
    .line 45
    add-int/lit8 v2, v2, 0x1

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_0
    return-object v1

    .line 49
    :catch_0
    move-exception p0

    .line 50
    new-instance v0, Lvv0/a;

    .line 51
    .line 52
    const-string v1, "Not enough bytes for Set<String> value"

    .line 53
    .line 54
    invoke-direct {v0, v1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 55
    .line 56
    .line 57
    throw v0
.end method

.method public static u(Lu6/b;Landroid/text/Editable;IIZ)Z
    .locals 7

    .line 1
    const/4 v0, 0x0

    .line 2
    if-eqz p1, :cond_19

    .line 3
    .line 4
    if-ltz p2, :cond_19

    .line 5
    .line 6
    if-gez p3, :cond_0

    .line 7
    .line 8
    goto/16 :goto_9

    .line 9
    .line 10
    :cond_0
    invoke-static {p1}, Landroid/text/Selection;->getSelectionStart(Ljava/lang/CharSequence;)I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    invoke-static {p1}, Landroid/text/Selection;->getSelectionEnd(Ljava/lang/CharSequence;)I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    const/4 v3, -0x1

    .line 19
    if-eq v1, v3, :cond_19

    .line 20
    .line 21
    if-eq v2, v3, :cond_19

    .line 22
    .line 23
    if-eq v1, v2, :cond_1

    .line 24
    .line 25
    goto/16 :goto_9

    .line 26
    .line 27
    :cond_1
    const/4 v4, 0x1

    .line 28
    if-eqz p4, :cond_16

    .line 29
    .line 30
    invoke-static {p2, v0}, Ljava/lang/Math;->max(II)I

    .line 31
    .line 32
    .line 33
    move-result p2

    .line 34
    invoke-interface {p1}, Ljava/lang/CharSequence;->length()I

    .line 35
    .line 36
    .line 37
    move-result p4

    .line 38
    if-ltz v1, :cond_3

    .line 39
    .line 40
    if-ge p4, v1, :cond_2

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_2
    if-gez p2, :cond_4

    .line 44
    .line 45
    :cond_3
    :goto_0
    move v1, v3

    .line 46
    goto :goto_3

    .line 47
    :cond_4
    :goto_1
    move p4, v0

    .line 48
    :goto_2
    if-nez p2, :cond_5

    .line 49
    .line 50
    goto :goto_3

    .line 51
    :cond_5
    add-int/lit8 v1, v1, -0x1

    .line 52
    .line 53
    if-gez v1, :cond_7

    .line 54
    .line 55
    if-eqz p4, :cond_6

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_6
    move v1, v0

    .line 59
    goto :goto_3

    .line 60
    :cond_7
    invoke-interface {p1, v1}, Ljava/lang/CharSequence;->charAt(I)C

    .line 61
    .line 62
    .line 63
    move-result v5

    .line 64
    if-eqz p4, :cond_9

    .line 65
    .line 66
    invoke-static {v5}, Ljava/lang/Character;->isHighSurrogate(C)Z

    .line 67
    .line 68
    .line 69
    move-result p4

    .line 70
    if-nez p4, :cond_8

    .line 71
    .line 72
    goto :goto_0

    .line 73
    :cond_8
    add-int/lit8 p2, p2, -0x1

    .line 74
    .line 75
    goto :goto_1

    .line 76
    :cond_9
    invoke-static {v5}, Ljava/lang/Character;->isSurrogate(C)Z

    .line 77
    .line 78
    .line 79
    move-result v6

    .line 80
    if-nez v6, :cond_a

    .line 81
    .line 82
    add-int/lit8 p2, p2, -0x1

    .line 83
    .line 84
    goto :goto_2

    .line 85
    :cond_a
    invoke-static {v5}, Ljava/lang/Character;->isHighSurrogate(C)Z

    .line 86
    .line 87
    .line 88
    move-result p4

    .line 89
    if-eqz p4, :cond_b

    .line 90
    .line 91
    goto :goto_0

    .line 92
    :cond_b
    move p4, v4

    .line 93
    goto :goto_2

    .line 94
    :goto_3
    invoke-static {p3, v0}, Ljava/lang/Math;->max(II)I

    .line 95
    .line 96
    .line 97
    move-result p2

    .line 98
    invoke-interface {p1}, Ljava/lang/CharSequence;->length()I

    .line 99
    .line 100
    .line 101
    move-result p3

    .line 102
    if-ltz v2, :cond_d

    .line 103
    .line 104
    if-ge p3, v2, :cond_c

    .line 105
    .line 106
    goto :goto_4

    .line 107
    :cond_c
    if-gez p2, :cond_e

    .line 108
    .line 109
    :cond_d
    :goto_4
    move p3, v3

    .line 110
    goto :goto_7

    .line 111
    :cond_e
    :goto_5
    move p4, v0

    .line 112
    :goto_6
    if-nez p2, :cond_f

    .line 113
    .line 114
    move p3, v2

    .line 115
    goto :goto_7

    .line 116
    :cond_f
    if-lt v2, p3, :cond_10

    .line 117
    .line 118
    if-eqz p4, :cond_15

    .line 119
    .line 120
    goto :goto_4

    .line 121
    :cond_10
    invoke-interface {p1, v2}, Ljava/lang/CharSequence;->charAt(I)C

    .line 122
    .line 123
    .line 124
    move-result v5

    .line 125
    if-eqz p4, :cond_12

    .line 126
    .line 127
    invoke-static {v5}, Ljava/lang/Character;->isLowSurrogate(C)Z

    .line 128
    .line 129
    .line 130
    move-result p4

    .line 131
    if-nez p4, :cond_11

    .line 132
    .line 133
    goto :goto_4

    .line 134
    :cond_11
    add-int/lit8 p2, p2, -0x1

    .line 135
    .line 136
    add-int/lit8 v2, v2, 0x1

    .line 137
    .line 138
    goto :goto_5

    .line 139
    :cond_12
    invoke-static {v5}, Ljava/lang/Character;->isSurrogate(C)Z

    .line 140
    .line 141
    .line 142
    move-result v6

    .line 143
    if-nez v6, :cond_13

    .line 144
    .line 145
    add-int/lit8 p2, p2, -0x1

    .line 146
    .line 147
    add-int/lit8 v2, v2, 0x1

    .line 148
    .line 149
    goto :goto_6

    .line 150
    :cond_13
    invoke-static {v5}, Ljava/lang/Character;->isLowSurrogate(C)Z

    .line 151
    .line 152
    .line 153
    move-result p4

    .line 154
    if-eqz p4, :cond_14

    .line 155
    .line 156
    goto :goto_4

    .line 157
    :cond_14
    add-int/lit8 v2, v2, 0x1

    .line 158
    .line 159
    move p4, v4

    .line 160
    goto :goto_6

    .line 161
    :cond_15
    :goto_7
    if-eq v1, v3, :cond_19

    .line 162
    .line 163
    if-ne p3, v3, :cond_17

    .line 164
    .line 165
    goto :goto_9

    .line 166
    :cond_16
    sub-int/2addr v1, p2

    .line 167
    invoke-static {v1, v0}, Ljava/lang/Math;->max(II)I

    .line 168
    .line 169
    .line 170
    move-result v1

    .line 171
    add-int/2addr v2, p3

    .line 172
    invoke-interface {p1}, Ljava/lang/CharSequence;->length()I

    .line 173
    .line 174
    .line 175
    move-result p2

    .line 176
    invoke-static {v2, p2}, Ljava/lang/Math;->min(II)I

    .line 177
    .line 178
    .line 179
    move-result p3

    .line 180
    :cond_17
    const-class p2, Ls6/u;

    .line 181
    .line 182
    invoke-interface {p1, v1, p3, p2}, Landroid/text/Spanned;->getSpans(IILjava/lang/Class;)[Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object p2

    .line 186
    check-cast p2, [Ls6/u;

    .line 187
    .line 188
    if-eqz p2, :cond_19

    .line 189
    .line 190
    array-length p4, p2

    .line 191
    if-lez p4, :cond_19

    .line 192
    .line 193
    array-length p4, p2

    .line 194
    move v2, v0

    .line 195
    :goto_8
    if-ge v2, p4, :cond_18

    .line 196
    .line 197
    aget-object v3, p2, v2

    .line 198
    .line 199
    invoke-interface {p1, v3}, Landroid/text/Spanned;->getSpanStart(Ljava/lang/Object;)I

    .line 200
    .line 201
    .line 202
    move-result v5

    .line 203
    invoke-interface {p1, v3}, Landroid/text/Spanned;->getSpanEnd(Ljava/lang/Object;)I

    .line 204
    .line 205
    .line 206
    move-result v3

    .line 207
    invoke-static {v5, v1}, Ljava/lang/Math;->min(II)I

    .line 208
    .line 209
    .line 210
    move-result v1

    .line 211
    invoke-static {v3, p3}, Ljava/lang/Math;->max(II)I

    .line 212
    .line 213
    .line 214
    move-result p3

    .line 215
    add-int/lit8 v2, v2, 0x1

    .line 216
    .line 217
    goto :goto_8

    .line 218
    :cond_18
    invoke-static {v1, v0}, Ljava/lang/Math;->max(II)I

    .line 219
    .line 220
    .line 221
    move-result p2

    .line 222
    invoke-interface {p1}, Ljava/lang/CharSequence;->length()I

    .line 223
    .line 224
    .line 225
    move-result p4

    .line 226
    invoke-static {p3, p4}, Ljava/lang/Math;->min(II)I

    .line 227
    .line 228
    .line 229
    move-result p3

    .line 230
    invoke-virtual {p0}, Landroid/view/inputmethod/InputConnectionWrapper;->beginBatchEdit()Z

    .line 231
    .line 232
    .line 233
    invoke-interface {p1, p2, p3}, Landroid/text/Editable;->delete(II)Landroid/text/Editable;

    .line 234
    .line 235
    .line 236
    invoke-virtual {p0}, Landroid/view/inputmethod/InputConnectionWrapper;->endBatchEdit()Z

    .line 237
    .line 238
    .line 239
    return v4

    .line 240
    :cond_19
    :goto_9
    return v0
.end method

.method public static v(Ljava/lang/String;)Ljava/time/LocalDate;
    .locals 0

    .line 1
    if-eqz p0, :cond_0

    .line 2
    .line 3
    invoke-static {p0}, Ljava/time/LocalDate;->parse(Ljava/lang/CharSequence;)Ljava/time/LocalDate;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0

    .line 8
    :cond_0
    const/4 p0, 0x0

    .line 9
    return-object p0
.end method

.method public static w(Ljava/time/LocalDate;)Ljava/lang/String;
    .locals 1

    .line 1
    if-eqz p0, :cond_0

    .line 2
    .line 3
    sget-object v0, Ljava/time/format/DateTimeFormatter;->ISO_LOCAL_DATE:Ljava/time/format/DateTimeFormatter;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Ljava/time/LocalDate;->format(Ljava/time/format/DateTimeFormatter;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0

    .line 10
    :cond_0
    const/4 p0, 0x0

    .line 11
    return-object p0
.end method


# virtual methods
.method public a()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public b(Ljava/lang/String;Ljava/security/Provider;)Ljava/lang/Object;
    .locals 0

    .line 1
    if-nez p2, :cond_0

    .line 2
    .line 3
    invoke-static {p1}, Ljavax/crypto/Mac;->getInstance(Ljava/lang/String;)Ljavax/crypto/Mac;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0

    .line 8
    :cond_0
    invoke-static {p1, p2}, Ljavax/crypto/Mac;->getInstance(Ljava/lang/String;Ljava/security/Provider;)Ljavax/crypto/Mac;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0
.end method

.method public c()V
    .locals 0

    .line 1
    return-void
.end method

.method public d(Lb81/d;Lz7/e;I)I
    .locals 0

    .line 1
    const/4 p0, 0x4

    .line 2
    iput p0, p2, Lkq/d;->e:I

    .line 3
    .line 4
    const/4 p0, -0x4

    .line 5
    return p0
.end method

.method public e(Lin/z1;)Ljava/lang/Object;
    .locals 3

    .line 1
    new-instance p0, Lfv/a;

    .line 2
    .line 3
    invoke-direct {p0}, Lfv/a;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance p1, Lfv/j;

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    invoke-direct {p1, v0}, Lfv/j;-><init>(I)V

    .line 10
    .line 11
    .line 12
    new-instance v0, Lfv/k;

    .line 13
    .line 14
    iget-object v1, p0, Lfv/a;->a:Ljava/lang/ref/ReferenceQueue;

    .line 15
    .line 16
    iget-object v2, p0, Lfv/a;->b:Ljava/util/Set;

    .line 17
    .line 18
    invoke-direct {v0, p0, v1, v2, p1}, Lfv/k;-><init>(Lfv/a;Ljava/lang/ref/ReferenceQueue;Ljava/util/Set;Lfv/j;)V

    .line 19
    .line 20
    .line 21
    invoke-interface {v2, v0}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    new-instance p1, Llr/b;

    .line 25
    .line 26
    const/4 v0, 0x5

    .line 27
    invoke-direct {p1, v0, v1, v2}, Llr/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    new-instance v0, Ljava/lang/Thread;

    .line 31
    .line 32
    const-string v1, "MlKitCleaner"

    .line 33
    .line 34
    invoke-direct {v0, p1, v1}, Ljava/lang/Thread;-><init>(Ljava/lang/Runnable;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    const/4 p1, 0x1

    .line 38
    invoke-virtual {v0, p1}, Ljava/lang/Thread;->setDaemon(Z)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {v0}, Ljava/lang/Thread;->start()V

    .line 42
    .line 43
    .line 44
    return-object p0
.end method

.method public f(Lt7/o;)Ll9/j;
    .locals 3

    .line 1
    iget-object p0, p1, Lt7/o;->n:Ljava/lang/String;

    .line 2
    .line 3
    iget-object p1, p1, Lt7/o;->q:Ljava/util/List;

    .line 4
    .line 5
    if-eqz p0, :cond_9

    .line 6
    .line 7
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    const/4 v1, 0x1

    .line 12
    const/4 v2, -0x1

    .line 13
    sparse-switch v0, :sswitch_data_0

    .line 14
    .line 15
    .line 16
    goto/16 :goto_0

    .line 17
    .line 18
    :sswitch_0
    const-string v0, "application/ttml+xml"

    .line 19
    .line 20
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    if-nez v0, :cond_0

    .line 25
    .line 26
    goto/16 :goto_0

    .line 27
    .line 28
    :cond_0
    const/16 v2, 0x8

    .line 29
    .line 30
    goto/16 :goto_0

    .line 31
    .line 32
    :sswitch_1
    const-string v0, "application/x-subrip"

    .line 33
    .line 34
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    if-nez v0, :cond_1

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_1
    const/4 v2, 0x7

    .line 42
    goto :goto_0

    .line 43
    :sswitch_2
    const-string v0, "application/vobsub"

    .line 44
    .line 45
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v0

    .line 49
    if-nez v0, :cond_2

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_2
    const/4 v2, 0x6

    .line 53
    goto :goto_0

    .line 54
    :sswitch_3
    const-string v0, "text/x-ssa"

    .line 55
    .line 56
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v0

    .line 60
    if-nez v0, :cond_3

    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_3
    const/4 v2, 0x5

    .line 64
    goto :goto_0

    .line 65
    :sswitch_4
    const-string v0, "application/x-quicktime-tx3g"

    .line 66
    .line 67
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v0

    .line 71
    if-nez v0, :cond_4

    .line 72
    .line 73
    goto :goto_0

    .line 74
    :cond_4
    const/4 v2, 0x4

    .line 75
    goto :goto_0

    .line 76
    :sswitch_5
    const-string v0, "text/vtt"

    .line 77
    .line 78
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result v0

    .line 82
    if-nez v0, :cond_5

    .line 83
    .line 84
    goto :goto_0

    .line 85
    :cond_5
    const/4 v2, 0x3

    .line 86
    goto :goto_0

    .line 87
    :sswitch_6
    const-string v0, "application/x-mp4-vtt"

    .line 88
    .line 89
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result v0

    .line 93
    if-nez v0, :cond_6

    .line 94
    .line 95
    goto :goto_0

    .line 96
    :cond_6
    const/4 v2, 0x2

    .line 97
    goto :goto_0

    .line 98
    :sswitch_7
    const-string v0, "application/pgs"

    .line 99
    .line 100
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    move-result v0

    .line 104
    if-nez v0, :cond_7

    .line 105
    .line 106
    goto :goto_0

    .line 107
    :cond_7
    move v2, v1

    .line 108
    goto :goto_0

    .line 109
    :sswitch_8
    const-string v0, "application/dvbsubs"

    .line 110
    .line 111
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 112
    .line 113
    .line 114
    move-result v0

    .line 115
    if-nez v0, :cond_8

    .line 116
    .line 117
    goto :goto_0

    .line 118
    :cond_8
    const/4 v2, 0x0

    .line 119
    :goto_0
    packed-switch v2, :pswitch_data_0

    .line 120
    .line 121
    .line 122
    goto :goto_1

    .line 123
    :pswitch_0
    new-instance p0, Lr9/e;

    .line 124
    .line 125
    invoke-direct {p0}, Lr9/e;-><init>()V

    .line 126
    .line 127
    .line 128
    return-object p0

    .line 129
    :pswitch_1
    new-instance p0, Lq9/a;

    .line 130
    .line 131
    invoke-direct {p0}, Lq9/a;-><init>()V

    .line 132
    .line 133
    .line 134
    return-object p0

    .line 135
    :pswitch_2
    new-instance p0, Lcom/google/firebase/messaging/w;

    .line 136
    .line 137
    invoke-direct {p0, p1}, Lcom/google/firebase/messaging/w;-><init>(Ljava/util/List;)V

    .line 138
    .line 139
    .line 140
    return-object p0

    .line 141
    :pswitch_3
    new-instance p0, Lp9/a;

    .line 142
    .line 143
    invoke-direct {p0, p1}, Lp9/a;-><init>(Ljava/util/List;)V

    .line 144
    .line 145
    .line 146
    return-object p0

    .line 147
    :pswitch_4
    new-instance p0, Ls9/a;

    .line 148
    .line 149
    invoke-direct {p0, p1}, Ls9/a;-><init>(Ljava/util/List;)V

    .line 150
    .line 151
    .line 152
    return-object p0

    .line 153
    :pswitch_5
    new-instance p0, Lb81/a;

    .line 154
    .line 155
    const/16 p1, 0x19

    .line 156
    .line 157
    invoke-direct {p0, p1}, Lb81/a;-><init>(I)V

    .line 158
    .line 159
    .line 160
    return-object p0

    .line 161
    :pswitch_6
    new-instance p0, Lo8/y;

    .line 162
    .line 163
    invoke-direct {p0, v1}, Lo8/y;-><init>(I)V

    .line 164
    .line 165
    .line 166
    return-object p0

    .line 167
    :pswitch_7
    new-instance p0, Lcom/google/firebase/messaging/w;

    .line 168
    .line 169
    const/16 p1, 0x16

    .line 170
    .line 171
    invoke-direct {p0, p1}, Lcom/google/firebase/messaging/w;-><init>(I)V

    .line 172
    .line 173
    .line 174
    return-object p0

    .line 175
    :pswitch_8
    new-instance p0, Ln9/h;

    .line 176
    .line 177
    invoke-direct {p0, p1}, Ln9/h;-><init>(Ljava/util/List;)V

    .line 178
    .line 179
    .line 180
    return-object p0

    .line 181
    :cond_9
    :goto_1
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 182
    .line 183
    const-string v0, "Unsupported MIME type: "

    .line 184
    .line 185
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 186
    .line 187
    .line 188
    move-result-object p0

    .line 189
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 190
    .line 191
    .line 192
    throw p1

    .line 193
    :sswitch_data_0
    .sparse-switch
        -0x5091057c -> :sswitch_8
        -0x4a6813e3 -> :sswitch_7
        -0x3d28a9ba -> :sswitch_6
        -0x3be2f26c -> :sswitch_5
        0x2935f49f -> :sswitch_4
        0x310bebca -> :sswitch_3
        0x45059676 -> :sswitch_2
        0x63771bad -> :sswitch_1
        0x64f8068a -> :sswitch_0
    .end sparse-switch

    .line 194
    .line 195
    .line 196
    .line 197
    .line 198
    .line 199
    .line 200
    .line 201
    .line 202
    .line 203
    .line 204
    .line 205
    .line 206
    .line 207
    .line 208
    .line 209
    .line 210
    .line 211
    .line 212
    .line 213
    .line 214
    .line 215
    .line 216
    .line 217
    .line 218
    .line 219
    .line 220
    .line 221
    .line 222
    .line 223
    .line 224
    .line 225
    .line 226
    .line 227
    .line 228
    .line 229
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public g(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lov/c;

    .line 2
    .line 3
    iget-object p0, p1, Lh/w;->b:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Ljava/lang/String;

    .line 6
    .line 7
    if-nez p0, :cond_0

    .line 8
    .line 9
    const-string p0, ""

    .line 10
    .line 11
    :cond_0
    return-object p0
.end method

.method public h()Ljava/lang/Object;
    .locals 2

    .line 1
    iget p0, p0, Lwe0/b;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 7
    .line 8
    sget-object p0, Lcom/google/android/gms/internal/measurement/u8;->e:Lcom/google/android/gms/internal/measurement/u8;

    .line 9
    .line 10
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/u8;->b()Lcom/google/android/gms/internal/measurement/v8;

    .line 11
    .line 12
    .line 13
    sget-object p0, Lcom/google/android/gms/internal/measurement/w8;->b:Lcom/google/android/gms/internal/measurement/n4;

    .line 14
    .line 15
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    check-cast p0, Ljava/lang/Boolean;

    .line 20
    .line 21
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    return-object p0

    .line 25
    :pswitch_0
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 26
    .line 27
    sget-object p0, Lcom/google/android/gms/internal/measurement/o8;->e:Lcom/google/android/gms/internal/measurement/o8;

    .line 28
    .line 29
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/o8;->d:Lgr/p;

    .line 30
    .line 31
    iget-object p0, p0, Lgr/p;->d:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast p0, Lcom/google/android/gms/internal/measurement/p8;

    .line 34
    .line 35
    sget-object p0, Lcom/google/android/gms/internal/measurement/q8;->a:Lcom/google/android/gms/internal/measurement/n4;

    .line 36
    .line 37
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    check-cast p0, Ljava/lang/Boolean;

    .line 42
    .line 43
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 44
    .line 45
    .line 46
    return-object p0

    .line 47
    :pswitch_1
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 48
    .line 49
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 50
    .line 51
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 52
    .line 53
    .line 54
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->r0:Lcom/google/android/gms/internal/measurement/n4;

    .line 55
    .line 56
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    check-cast p0, Ljava/lang/Long;

    .line 61
    .line 62
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 63
    .line 64
    .line 65
    move-result-wide v0

    .line 66
    long-to-int p0, v0

    .line 67
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    return-object p0

    .line 72
    :pswitch_2
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 73
    .line 74
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 75
    .line 76
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 77
    .line 78
    .line 79
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->d0:Lcom/google/android/gms/internal/measurement/n4;

    .line 80
    .line 81
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    check-cast p0, Ljava/lang/Long;

    .line 86
    .line 87
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 88
    .line 89
    .line 90
    return-object p0

    .line 91
    :pswitch_3
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 92
    .line 93
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 94
    .line 95
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 96
    .line 97
    .line 98
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->G:Lcom/google/android/gms/internal/measurement/n4;

    .line 99
    .line 100
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    check-cast p0, Ljava/lang/Long;

    .line 105
    .line 106
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 107
    .line 108
    .line 109
    return-object p0

    .line 110
    :pswitch_4
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 111
    .line 112
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 113
    .line 114
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 115
    .line 116
    .line 117
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->i:Lcom/google/android/gms/internal/measurement/n4;

    .line 118
    .line 119
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object p0

    .line 123
    check-cast p0, Ljava/lang/Long;

    .line 124
    .line 125
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 126
    .line 127
    .line 128
    return-object p0

    .line 129
    :pswitch_5
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 130
    .line 131
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 132
    .line 133
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 134
    .line 135
    .line 136
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->L:Lcom/google/android/gms/internal/measurement/n4;

    .line 137
    .line 138
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    check-cast p0, Ljava/lang/Long;

    .line 143
    .line 144
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 145
    .line 146
    .line 147
    return-object p0

    .line 148
    :pswitch_6
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 149
    .line 150
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 151
    .line 152
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 153
    .line 154
    .line 155
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->l0:Lcom/google/android/gms/internal/measurement/n4;

    .line 156
    .line 157
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object p0

    .line 161
    check-cast p0, Ljava/lang/Long;

    .line 162
    .line 163
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 164
    .line 165
    .line 166
    move-result-wide v0

    .line 167
    long-to-int p0, v0

    .line 168
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 169
    .line 170
    .line 171
    move-result-object p0

    .line 172
    return-object p0

    .line 173
    :pswitch_data_0
    .packed-switch 0x10
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public i(Lt7/o;)Z
    .locals 0

    .line 1
    iget-object p0, p1, Lt7/o;->n:Ljava/lang/String;

    .line 2
    .line 3
    const-string p1, "text/x-ssa"

    .line 4
    .line 5
    invoke-static {p0, p1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    if-nez p1, :cond_1

    .line 10
    .line 11
    const-string p1, "text/vtt"

    .line 12
    .line 13
    invoke-static {p0, p1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    if-nez p1, :cond_1

    .line 18
    .line 19
    const-string p1, "application/x-mp4-vtt"

    .line 20
    .line 21
    invoke-static {p0, p1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result p1

    .line 25
    if-nez p1, :cond_1

    .line 26
    .line 27
    const-string p1, "application/x-subrip"

    .line 28
    .line 29
    invoke-static {p0, p1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result p1

    .line 33
    if-nez p1, :cond_1

    .line 34
    .line 35
    const-string p1, "application/x-quicktime-tx3g"

    .line 36
    .line 37
    invoke-static {p0, p1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    if-nez p1, :cond_1

    .line 42
    .line 43
    const-string p1, "application/pgs"

    .line 44
    .line 45
    invoke-static {p0, p1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result p1

    .line 49
    if-nez p1, :cond_1

    .line 50
    .line 51
    const-string p1, "application/vobsub"

    .line 52
    .line 53
    invoke-static {p0, p1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result p1

    .line 57
    if-nez p1, :cond_1

    .line 58
    .line 59
    const-string p1, "application/dvbsubs"

    .line 60
    .line 61
    invoke-static {p0, p1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result p1

    .line 65
    if-nez p1, :cond_1

    .line 66
    .line 67
    const-string p1, "application/ttml+xml"

    .line 68
    .line 69
    invoke-static {p0, p1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    move-result p0

    .line 73
    if-eqz p0, :cond_0

    .line 74
    .line 75
    goto :goto_0

    .line 76
    :cond_0
    const/4 p0, 0x0

    .line 77
    return p0

    .line 78
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 79
    return p0
.end method

.method public j(Lt7/o;)I
    .locals 3

    .line 1
    iget-object p0, p1, Lt7/o;->n:Ljava/lang/String;

    .line 2
    .line 3
    if-eqz p0, :cond_9

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    const/4 v0, 0x1

    .line 10
    const/4 v1, 0x2

    .line 11
    const/4 v2, -0x1

    .line 12
    sparse-switch p1, :sswitch_data_0

    .line 13
    .line 14
    .line 15
    goto/16 :goto_0

    .line 16
    .line 17
    :sswitch_0
    const-string p1, "application/ttml+xml"

    .line 18
    .line 19
    invoke-virtual {p0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result p1

    .line 23
    if-nez p1, :cond_0

    .line 24
    .line 25
    goto/16 :goto_0

    .line 26
    .line 27
    :cond_0
    const/16 v2, 0x8

    .line 28
    .line 29
    goto/16 :goto_0

    .line 30
    .line 31
    :sswitch_1
    const-string p1, "application/x-subrip"

    .line 32
    .line 33
    invoke-virtual {p0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result p1

    .line 37
    if-nez p1, :cond_1

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_1
    const/4 v2, 0x7

    .line 41
    goto :goto_0

    .line 42
    :sswitch_2
    const-string p1, "application/vobsub"

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result p1

    .line 48
    if-nez p1, :cond_2

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_2
    const/4 v2, 0x6

    .line 52
    goto :goto_0

    .line 53
    :sswitch_3
    const-string p1, "text/x-ssa"

    .line 54
    .line 55
    invoke-virtual {p0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result p1

    .line 59
    if-nez p1, :cond_3

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_3
    const/4 v2, 0x5

    .line 63
    goto :goto_0

    .line 64
    :sswitch_4
    const-string p1, "application/x-quicktime-tx3g"

    .line 65
    .line 66
    invoke-virtual {p0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    move-result p1

    .line 70
    if-nez p1, :cond_4

    .line 71
    .line 72
    goto :goto_0

    .line 73
    :cond_4
    const/4 v2, 0x4

    .line 74
    goto :goto_0

    .line 75
    :sswitch_5
    const-string p1, "text/vtt"

    .line 76
    .line 77
    invoke-virtual {p0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    move-result p1

    .line 81
    if-nez p1, :cond_5

    .line 82
    .line 83
    goto :goto_0

    .line 84
    :cond_5
    const/4 v2, 0x3

    .line 85
    goto :goto_0

    .line 86
    :sswitch_6
    const-string p1, "application/x-mp4-vtt"

    .line 87
    .line 88
    invoke-virtual {p0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 89
    .line 90
    .line 91
    move-result p1

    .line 92
    if-nez p1, :cond_6

    .line 93
    .line 94
    goto :goto_0

    .line 95
    :cond_6
    move v2, v1

    .line 96
    goto :goto_0

    .line 97
    :sswitch_7
    const-string p1, "application/pgs"

    .line 98
    .line 99
    invoke-virtual {p0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 100
    .line 101
    .line 102
    move-result p1

    .line 103
    if-nez p1, :cond_7

    .line 104
    .line 105
    goto :goto_0

    .line 106
    :cond_7
    move v2, v0

    .line 107
    goto :goto_0

    .line 108
    :sswitch_8
    const-string p1, "application/dvbsubs"

    .line 109
    .line 110
    invoke-virtual {p0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 111
    .line 112
    .line 113
    move-result p1

    .line 114
    if-nez p1, :cond_8

    .line 115
    .line 116
    goto :goto_0

    .line 117
    :cond_8
    const/4 v2, 0x0

    .line 118
    :goto_0
    packed-switch v2, :pswitch_data_0

    .line 119
    .line 120
    .line 121
    goto :goto_1

    .line 122
    :pswitch_0
    return v0

    .line 123
    :pswitch_1
    return v1

    .line 124
    :pswitch_2
    return v0

    .line 125
    :pswitch_3
    return v1

    .line 126
    :pswitch_4
    return v0

    .line 127
    :pswitch_5
    return v1

    .line 128
    :cond_9
    :goto_1
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 129
    .line 130
    const-string v0, "Unsupported MIME type: "

    .line 131
    .line 132
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 133
    .line 134
    .line 135
    move-result-object p0

    .line 136
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    throw p1

    .line 140
    nop

    .line 141
    :sswitch_data_0
    .sparse-switch
        -0x5091057c -> :sswitch_8
        -0x4a6813e3 -> :sswitch_7
        -0x3d28a9ba -> :sswitch_6
        -0x3be2f26c -> :sswitch_5
        0x2935f49f -> :sswitch_4
        0x310bebca -> :sswitch_3
        0x45059676 -> :sswitch_2
        0x63771bad -> :sswitch_1
        0x64f8068a -> :sswitch_0
    .end sparse-switch

    .line 142
    .line 143
    .line 144
    .line 145
    .line 146
    .line 147
    .line 148
    .line 149
    .line 150
    .line 151
    .line 152
    .line 153
    .line 154
    .line 155
    .line 156
    .line 157
    .line 158
    .line 159
    .line 160
    .line 161
    .line 162
    .line 163
    .line 164
    .line 165
    .line 166
    .line 167
    .line 168
    .line 169
    .line 170
    .line 171
    .line 172
    .line 173
    .line 174
    .line 175
    .line 176
    .line 177
    .line 178
    .line 179
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method

.method public k(Lo8/p;)J
    .locals 0

    .line 1
    const-wide/16 p0, -0x1

    .line 2
    .line 3
    return-wide p0
.end method

.method public l(J)I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public m()Lo8/c0;
    .locals 2

    .line 1
    new-instance p0, Lo8/t;

    .line 2
    .line 3
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 4
    .line 5
    .line 6
    .line 7
    .line 8
    invoke-direct {p0, v0, v1}, Lo8/t;-><init>(J)V

    .line 9
    .line 10
    .line 11
    return-object p0
.end method

.method public synthetic n(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method

.method public o([Ljava/lang/StackTraceElement;)[Ljava/lang/StackTraceElement;
    .locals 2

    .line 1
    array-length p0, p1

    .line 2
    const/16 v0, 0x400

    .line 3
    .line 4
    if-gt p0, v0, :cond_0

    .line 5
    .line 6
    return-object p1

    .line 7
    :cond_0
    new-array p0, v0, [Ljava/lang/StackTraceElement;

    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    const/16 v1, 0x200

    .line 11
    .line 12
    invoke-static {p1, v0, p0, v0, v1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 13
    .line 14
    .line 15
    array-length v0, p1

    .line 16
    sub-int/2addr v0, v1

    .line 17
    invoke-static {p1, v0, p0, v1, v1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 18
    .line 19
    .line 20
    return-object p0
.end method

.method public p(Landroid/content/Context;Ljava/lang/String;Lzo/b;)Lm8/j;
    .locals 1

    .line 1
    new-instance p0, Lm8/j;

    .line 2
    .line 3
    invoke-direct {p0}, Lm8/j;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-interface {p3, p1, p2}, Lzo/b;->d(Landroid/content/Context;Ljava/lang/String;)I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    iput v0, p0, Lm8/j;->a:I

    .line 11
    .line 12
    const/4 v0, 0x1

    .line 13
    invoke-interface {p3, p1, p2, v0}, Lzo/b;->b(Landroid/content/Context;Ljava/lang/String;Z)I

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    iput p1, p0, Lm8/j;->b:I

    .line 18
    .line 19
    iget p2, p0, Lm8/j;->a:I

    .line 20
    .line 21
    if-nez p2, :cond_0

    .line 22
    .line 23
    const/4 p2, 0x0

    .line 24
    if-nez p1, :cond_0

    .line 25
    .line 26
    move v0, p2

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    if-lt p2, p1, :cond_1

    .line 29
    .line 30
    const/4 v0, -0x1

    .line 31
    :cond_1
    :goto_0
    iput v0, p0, Lm8/j;->c:I

    .line 32
    .line 33
    return-object p0
.end method

.method public q(J)V
    .locals 0

    .line 1
    return-void
.end method
