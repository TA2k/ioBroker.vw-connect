.class public final Lda/c;
.super Lz9/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic q:I


# direct methods
.method public synthetic constructor <init>(IZ)V
    .locals 0

    .line 1
    iput p1, p0, Lda/c;->q:I

    .line 2
    .line 3
    invoke-direct {p0, p2}, Lz9/g0;-><init>(Z)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public static j(Ljava/lang/String;)[D
    .locals 3

    .line 1
    invoke-static {p0}, Ljava/lang/Double;->parseDouble(Ljava/lang/String;)D

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-virtual {p0}, Ljava/lang/Number;->doubleValue()D

    .line 10
    .line 11
    .line 12
    move-result-wide v0

    .line 13
    const/4 p0, 0x1

    .line 14
    new-array p0, p0, [D

    .line 15
    .line 16
    const/4 v2, 0x0

    .line 17
    aput-wide v0, p0, v2

    .line 18
    .line 19
    return-object p0
.end method


# virtual methods
.method public final a(Ljava/lang/String;Landroid/os/Bundle;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget p0, p0, Lda/c;->q:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string p0, "bundle"

    .line 7
    .line 8
    const-string v0, "key"

    .line 9
    .line 10
    invoke-static {p2, p0, p1, v0, p1}, Lz9/c;->d(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    if-eqz p0, :cond_0

    .line 15
    .line 16
    invoke-static {p1, p2}, Lkp/t;->j(Ljava/lang/String;Landroid/os/Bundle;)Z

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    if-nez p0, :cond_0

    .line 21
    .line 22
    invoke-static {p1, p2}, Lkp/t;->h(Ljava/lang/String;Landroid/os/Bundle;)[Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    invoke-static {p0}, Lmx0/n;->b0([Ljava/lang/Object;)Ljava/util/List;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    check-cast p0, Ljava/lang/Iterable;

    .line 31
    .line 32
    new-instance p1, Ljava/util/ArrayList;

    .line 33
    .line 34
    const/16 p2, 0xa

    .line 35
    .line 36
    invoke-static {p0, p2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 37
    .line 38
    .line 39
    move-result p2

    .line 40
    invoke-direct {p1, p2}, Ljava/util/ArrayList;-><init>(I)V

    .line 41
    .line 42
    .line 43
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 48
    .line 49
    .line 50
    move-result p2

    .line 51
    if-eqz p2, :cond_1

    .line 52
    .line 53
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object p2

    .line 57
    check-cast p2, Ljava/lang/String;

    .line 58
    .line 59
    sget-object v0, Lz9/g0;->n:Lz9/e;

    .line 60
    .line 61
    invoke-virtual {v0, p2}, Lz9/e;->d(Ljava/lang/String;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object p2

    .line 65
    check-cast p2, Ljava/lang/String;

    .line 66
    .line 67
    invoke-virtual {p1, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    goto :goto_0

    .line 71
    :cond_0
    const/4 p1, 0x0

    .line 72
    :cond_1
    return-object p1

    .line 73
    :pswitch_0
    const-string p0, "bundle"

    .line 74
    .line 75
    const-string v0, "key"

    .line 76
    .line 77
    invoke-static {p2, p0, p1, v0, p1}, Lz9/c;->d(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z

    .line 78
    .line 79
    .line 80
    move-result p0

    .line 81
    if-eqz p0, :cond_3

    .line 82
    .line 83
    invoke-static {p1, p2}, Lkp/t;->j(Ljava/lang/String;Landroid/os/Bundle;)Z

    .line 84
    .line 85
    .line 86
    move-result p0

    .line 87
    if-nez p0, :cond_3

    .line 88
    .line 89
    invoke-static {p1, p2}, Lkp/t;->h(Ljava/lang/String;Landroid/os/Bundle;)[Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    new-instance p1, Ljava/util/ArrayList;

    .line 94
    .line 95
    array-length p2, p0

    .line 96
    invoke-direct {p1, p2}, Ljava/util/ArrayList;-><init>(I)V

    .line 97
    .line 98
    .line 99
    array-length p2, p0

    .line 100
    const/4 v0, 0x0

    .line 101
    move v1, v0

    .line 102
    :goto_1
    if-ge v1, p2, :cond_2

    .line 103
    .line 104
    aget-object v2, p0, v1

    .line 105
    .line 106
    sget-object v3, Lz9/g0;->n:Lz9/e;

    .line 107
    .line 108
    invoke-virtual {v3, v2}, Lz9/e;->d(Ljava/lang/String;)Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object v2

    .line 112
    check-cast v2, Ljava/lang/String;

    .line 113
    .line 114
    invoke-virtual {p1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 115
    .line 116
    .line 117
    add-int/lit8 v1, v1, 0x1

    .line 118
    .line 119
    goto :goto_1

    .line 120
    :cond_2
    new-array p0, v0, [Ljava/lang/String;

    .line 121
    .line 122
    invoke-virtual {p1, p0}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object p0

    .line 126
    check-cast p0, [Ljava/lang/String;

    .line 127
    .line 128
    goto :goto_2

    .line 129
    :cond_3
    const/4 p0, 0x0

    .line 130
    :goto_2
    return-object p0

    .line 131
    :pswitch_1
    const-string p0, "bundle"

    .line 132
    .line 133
    const-string v0, "key"

    .line 134
    .line 135
    invoke-static {p2, p0, p1, v0, p1}, Lz9/c;->d(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z

    .line 136
    .line 137
    .line 138
    move-result p0

    .line 139
    const/4 v0, 0x0

    .line 140
    if-eqz p0, :cond_5

    .line 141
    .line 142
    invoke-static {p1, p2}, Lkp/t;->j(Ljava/lang/String;Landroid/os/Bundle;)Z

    .line 143
    .line 144
    .line 145
    move-result p0

    .line 146
    if-nez p0, :cond_5

    .line 147
    .line 148
    invoke-virtual {p2, p1}, Landroid/os/BaseBundle;->getDoubleArray(Ljava/lang/String;)[D

    .line 149
    .line 150
    .line 151
    move-result-object p0

    .line 152
    if-eqz p0, :cond_4

    .line 153
    .line 154
    invoke-static {p0}, Lmx0/n;->X([D)Ljava/util/List;

    .line 155
    .line 156
    .line 157
    move-result-object v0

    .line 158
    goto :goto_3

    .line 159
    :cond_4
    invoke-static {p1}, Lkp/u;->a(Ljava/lang/String;)V

    .line 160
    .line 161
    .line 162
    throw v0

    .line 163
    :cond_5
    :goto_3
    return-object v0

    .line 164
    :pswitch_2
    const-string p0, "bundle"

    .line 165
    .line 166
    const-string v0, "key"

    .line 167
    .line 168
    invoke-static {p2, p0, p1, v0, p1}, Lz9/c;->d(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z

    .line 169
    .line 170
    .line 171
    move-result p0

    .line 172
    const/4 v0, 0x0

    .line 173
    if-eqz p0, :cond_7

    .line 174
    .line 175
    invoke-static {p1, p2}, Lkp/t;->j(Ljava/lang/String;Landroid/os/Bundle;)Z

    .line 176
    .line 177
    .line 178
    move-result p0

    .line 179
    if-nez p0, :cond_7

    .line 180
    .line 181
    invoke-virtual {p2, p1}, Landroid/os/BaseBundle;->getDoubleArray(Ljava/lang/String;)[D

    .line 182
    .line 183
    .line 184
    move-result-object p0

    .line 185
    if-eqz p0, :cond_6

    .line 186
    .line 187
    move-object v0, p0

    .line 188
    goto :goto_4

    .line 189
    :cond_6
    invoke-static {p1}, Lkp/u;->a(Ljava/lang/String;)V

    .line 190
    .line 191
    .line 192
    throw v0

    .line 193
    :cond_7
    :goto_4
    return-object v0

    .line 194
    nop

    .line 195
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final b()Ljava/lang/String;
    .locals 0

    .line 1
    iget p0, p0, Lda/c;->q:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string p0, "List<String?>"

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    const-string p0, "string_nullable[]"

    .line 10
    .line 11
    return-object p0

    .line 12
    :pswitch_1
    const-string p0, "List<Double>"

    .line 13
    .line 14
    return-object p0

    .line 15
    :pswitch_2
    const-string p0, "double[]"

    .line 16
    .line 17
    return-object p0

    .line 18
    nop

    .line 19
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final c(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lda/c;->q:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/util/List;

    .line 7
    .line 8
    sget-object p0, Lz9/g0;->n:Lz9/e;

    .line 9
    .line 10
    if-eqz p1, :cond_0

    .line 11
    .line 12
    check-cast p1, Ljava/util/Collection;

    .line 13
    .line 14
    invoke-virtual {p0, p2}, Lz9/e;->d(Ljava/lang/String;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-static {p0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    check-cast p0, Ljava/lang/Iterable;

    .line 23
    .line 24
    invoke-static {p0, p1}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    invoke-virtual {p0, p2}, Lz9/e;->d(Ljava/lang/String;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    invoke-static {p0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    :goto_0
    return-object p0

    .line 38
    :pswitch_0
    check-cast p1, [Ljava/lang/String;

    .line 39
    .line 40
    invoke-virtual {p0, p2}, Lda/c;->k(Ljava/lang/String;)[Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    if-eqz p1, :cond_1

    .line 45
    .line 46
    invoke-static {p1, p0}, Lmx0/n;->O([Ljava/lang/Object;[Ljava/lang/Object;)[Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    check-cast p0, [Ljava/lang/String;

    .line 51
    .line 52
    :cond_1
    return-object p0

    .line 53
    :pswitch_1
    check-cast p1, Ljava/util/List;

    .line 54
    .line 55
    if-eqz p1, :cond_2

    .line 56
    .line 57
    check-cast p1, Ljava/util/Collection;

    .line 58
    .line 59
    invoke-static {p2}, Ljava/lang/Double;->parseDouble(Ljava/lang/String;)D

    .line 60
    .line 61
    .line 62
    move-result-wide v0

    .line 63
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    invoke-static {p0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    check-cast p0, Ljava/lang/Iterable;

    .line 72
    .line 73
    invoke-static {p0, p1}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    goto :goto_1

    .line 78
    :cond_2
    invoke-static {p2}, Ljava/lang/Double;->parseDouble(Ljava/lang/String;)D

    .line 79
    .line 80
    .line 81
    move-result-wide p0

    .line 82
    invoke-static {p0, p1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    invoke-static {p0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    :goto_1
    return-object p0

    .line 91
    :pswitch_2
    check-cast p1, [D

    .line 92
    .line 93
    if-eqz p1, :cond_3

    .line 94
    .line 95
    invoke-static {p2}, Lda/c;->j(Ljava/lang/String;)[D

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    array-length p2, p1

    .line 100
    add-int/lit8 v0, p2, 0x1

    .line 101
    .line 102
    invoke-static {p1, v0}, Ljava/util/Arrays;->copyOf([DI)[D

    .line 103
    .line 104
    .line 105
    move-result-object p1

    .line 106
    const/4 v0, 0x0

    .line 107
    const/4 v1, 0x1

    .line 108
    invoke-static {p0, v0, p1, p2, v1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 109
    .line 110
    .line 111
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 112
    .line 113
    .line 114
    goto :goto_2

    .line 115
    :cond_3
    invoke-static {p2}, Lda/c;->j(Ljava/lang/String;)[D

    .line 116
    .line 117
    .line 118
    move-result-object p1

    .line 119
    :goto_2
    return-object p1

    .line 120
    nop

    .line 121
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final d(Ljava/lang/String;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lda/c;->q:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object p0, Lz9/g0;->n:Lz9/e;

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Lz9/e;->d(Ljava/lang/String;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    invoke-static {p0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0

    .line 17
    :pswitch_0
    invoke-virtual {p0, p1}, Lda/c;->k(Ljava/lang/String;)[Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0

    .line 22
    :pswitch_1
    invoke-static {p1}, Ljava/lang/Double;->parseDouble(Ljava/lang/String;)D

    .line 23
    .line 24
    .line 25
    move-result-wide p0

    .line 26
    invoke-static {p0, p1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    invoke-static {p0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0

    .line 35
    :pswitch_2
    invoke-static {p1}, Lda/c;->j(Ljava/lang/String;)[D

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0

    .line 40
    nop

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final e(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Object;)V
    .locals 4

    .line 1
    iget p0, p0, Lda/c;->q:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p3, Ljava/util/List;

    .line 7
    .line 8
    const-string p0, "key"

    .line 9
    .line 10
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    if-nez p3, :cond_0

    .line 14
    .line 15
    invoke-static {p2, p1}, Lkp/v;->b(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 16
    .line 17
    .line 18
    goto :goto_1

    .line 19
    :cond_0
    check-cast p3, Ljava/lang/Iterable;

    .line 20
    .line 21
    new-instance p0, Ljava/util/ArrayList;

    .line 22
    .line 23
    const/16 v0, 0xa

    .line 24
    .line 25
    invoke-static {p3, v0}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    invoke-direct {p0, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 30
    .line 31
    .line 32
    invoke-interface {p3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 33
    .line 34
    .line 35
    move-result-object p3

    .line 36
    :goto_0
    invoke-interface {p3}, Ljava/util/Iterator;->hasNext()Z

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    if-eqz v0, :cond_2

    .line 41
    .line 42
    invoke-interface {p3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    check-cast v0, Ljava/lang/String;

    .line 47
    .line 48
    if-nez v0, :cond_1

    .line 49
    .line 50
    const-string v0, "null"

    .line 51
    .line 52
    :cond_1
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_2
    const/4 p3, 0x0

    .line 57
    new-array p3, p3, [Ljava/lang/String;

    .line 58
    .line 59
    invoke-virtual {p0, p3}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    check-cast p0, [Ljava/lang/String;

    .line 64
    .line 65
    invoke-static {p1, p2, p0}, Lkp/v;->f(Landroid/os/Bundle;Ljava/lang/String;[Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    :goto_1
    return-void

    .line 69
    :pswitch_0
    check-cast p3, [Ljava/lang/String;

    .line 70
    .line 71
    const-string p0, "key"

    .line 72
    .line 73
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    if-nez p3, :cond_3

    .line 77
    .line 78
    invoke-static {p2, p1}, Lkp/v;->b(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 79
    .line 80
    .line 81
    goto :goto_3

    .line 82
    :cond_3
    new-instance p0, Ljava/util/ArrayList;

    .line 83
    .line 84
    array-length v0, p3

    .line 85
    invoke-direct {p0, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 86
    .line 87
    .line 88
    array-length v0, p3

    .line 89
    const/4 v1, 0x0

    .line 90
    move v2, v1

    .line 91
    :goto_2
    if-ge v2, v0, :cond_5

    .line 92
    .line 93
    aget-object v3, p3, v2

    .line 94
    .line 95
    if-nez v3, :cond_4

    .line 96
    .line 97
    const-string v3, "null"

    .line 98
    .line 99
    :cond_4
    invoke-virtual {p0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 100
    .line 101
    .line 102
    add-int/lit8 v2, v2, 0x1

    .line 103
    .line 104
    goto :goto_2

    .line 105
    :cond_5
    new-array p3, v1, [Ljava/lang/String;

    .line 106
    .line 107
    invoke-virtual {p0, p3}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    check-cast p0, [Ljava/lang/String;

    .line 112
    .line 113
    invoke-static {p1, p2, p0}, Lkp/v;->f(Landroid/os/Bundle;Ljava/lang/String;[Ljava/lang/String;)V

    .line 114
    .line 115
    .line 116
    :goto_3
    return-void

    .line 117
    :pswitch_1
    check-cast p3, Ljava/util/List;

    .line 118
    .line 119
    const-string p0, "key"

    .line 120
    .line 121
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    if-nez p3, :cond_6

    .line 125
    .line 126
    invoke-static {p2, p1}, Lkp/v;->b(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 127
    .line 128
    .line 129
    goto :goto_5

    .line 130
    :cond_6
    check-cast p3, Ljava/util/Collection;

    .line 131
    .line 132
    invoke-interface {p3}, Ljava/util/Collection;->size()I

    .line 133
    .line 134
    .line 135
    move-result p0

    .line 136
    new-array p0, p0, [D

    .line 137
    .line 138
    invoke-interface {p3}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 139
    .line 140
    .line 141
    move-result-object p3

    .line 142
    const/4 v0, 0x0

    .line 143
    :goto_4
    invoke-interface {p3}, Ljava/util/Iterator;->hasNext()Z

    .line 144
    .line 145
    .line 146
    move-result v1

    .line 147
    if-eqz v1, :cond_7

    .line 148
    .line 149
    invoke-interface {p3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object v1

    .line 153
    check-cast v1, Ljava/lang/Number;

    .line 154
    .line 155
    invoke-virtual {v1}, Ljava/lang/Number;->doubleValue()D

    .line 156
    .line 157
    .line 158
    move-result-wide v1

    .line 159
    add-int/lit8 v3, v0, 0x1

    .line 160
    .line 161
    aput-wide v1, p0, v0

    .line 162
    .line 163
    move v0, v3

    .line 164
    goto :goto_4

    .line 165
    :cond_7
    invoke-virtual {p1, p2, p0}, Landroid/os/BaseBundle;->putDoubleArray(Ljava/lang/String;[D)V

    .line 166
    .line 167
    .line 168
    :goto_5
    return-void

    .line 169
    :pswitch_2
    check-cast p3, [D

    .line 170
    .line 171
    const-string p0, "key"

    .line 172
    .line 173
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 174
    .line 175
    .line 176
    if-nez p3, :cond_8

    .line 177
    .line 178
    invoke-static {p2, p1}, Lkp/v;->b(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 179
    .line 180
    .line 181
    goto :goto_6

    .line 182
    :cond_8
    invoke-virtual {p1, p2, p3}, Landroid/os/BaseBundle;->putDoubleArray(Ljava/lang/String;[D)V

    .line 183
    .line 184
    .line 185
    :goto_6
    return-void

    .line 186
    nop

    .line 187
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final g(Ljava/lang/Object;Ljava/lang/Object;)Z
    .locals 6

    .line 1
    iget p0, p0, Lda/c;->q:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/util/List;

    .line 7
    .line 8
    check-cast p2, Ljava/util/List;

    .line 9
    .line 10
    const/4 p0, 0x0

    .line 11
    const/4 v0, 0x0

    .line 12
    if-eqz p1, :cond_0

    .line 13
    .line 14
    check-cast p1, Ljava/util/Collection;

    .line 15
    .line 16
    new-array v1, v0, [Ljava/lang/String;

    .line 17
    .line 18
    invoke-interface {p1, v1}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    check-cast p1, [Ljava/lang/String;

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    move-object p1, p0

    .line 26
    :goto_0
    if-eqz p2, :cond_1

    .line 27
    .line 28
    check-cast p2, Ljava/util/Collection;

    .line 29
    .line 30
    new-array p0, v0, [Ljava/lang/String;

    .line 31
    .line 32
    invoke-interface {p2, p0}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    check-cast p0, [Ljava/lang/String;

    .line 37
    .line 38
    :cond_1
    invoke-static {p1, p0}, Lmx0/n;->f([Ljava/lang/Object;[Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    return p0

    .line 43
    :pswitch_0
    check-cast p1, [Ljava/lang/String;

    .line 44
    .line 45
    check-cast p2, [Ljava/lang/String;

    .line 46
    .line 47
    invoke-static {p1, p2}, Lmx0/n;->f([Ljava/lang/Object;[Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    move-result p0

    .line 51
    return p0

    .line 52
    :pswitch_1
    check-cast p1, Ljava/util/List;

    .line 53
    .line 54
    check-cast p2, Ljava/util/List;

    .line 55
    .line 56
    const/4 p0, 0x0

    .line 57
    const/4 v0, 0x0

    .line 58
    if-eqz p1, :cond_2

    .line 59
    .line 60
    check-cast p1, Ljava/util/Collection;

    .line 61
    .line 62
    new-array v1, v0, [Ljava/lang/Double;

    .line 63
    .line 64
    invoke-interface {p1, v1}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    check-cast p1, [Ljava/lang/Double;

    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_2
    move-object p1, p0

    .line 72
    :goto_1
    if-eqz p2, :cond_3

    .line 73
    .line 74
    check-cast p2, Ljava/util/Collection;

    .line 75
    .line 76
    new-array p0, v0, [Ljava/lang/Double;

    .line 77
    .line 78
    invoke-interface {p2, p0}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    check-cast p0, [Ljava/lang/Double;

    .line 83
    .line 84
    :cond_3
    invoke-static {p1, p0}, Lmx0/n;->f([Ljava/lang/Object;[Ljava/lang/Object;)Z

    .line 85
    .line 86
    .line 87
    move-result p0

    .line 88
    return p0

    .line 89
    :pswitch_2
    check-cast p1, [D

    .line 90
    .line 91
    check-cast p2, [D

    .line 92
    .line 93
    const/4 p0, 0x0

    .line 94
    const/4 v0, 0x0

    .line 95
    if-eqz p1, :cond_4

    .line 96
    .line 97
    array-length v1, p1

    .line 98
    new-array v1, v1, [Ljava/lang/Double;

    .line 99
    .line 100
    array-length v2, p1

    .line 101
    move v3, p0

    .line 102
    :goto_2
    if-ge v3, v2, :cond_5

    .line 103
    .line 104
    aget-wide v4, p1, v3

    .line 105
    .line 106
    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 107
    .line 108
    .line 109
    move-result-object v4

    .line 110
    aput-object v4, v1, v3

    .line 111
    .line 112
    add-int/lit8 v3, v3, 0x1

    .line 113
    .line 114
    goto :goto_2

    .line 115
    :cond_4
    move-object v1, v0

    .line 116
    :cond_5
    if-eqz p2, :cond_6

    .line 117
    .line 118
    array-length p1, p2

    .line 119
    new-array v0, p1, [Ljava/lang/Double;

    .line 120
    .line 121
    array-length p1, p2

    .line 122
    :goto_3
    if-ge p0, p1, :cond_6

    .line 123
    .line 124
    aget-wide v2, p2, p0

    .line 125
    .line 126
    invoke-static {v2, v3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 127
    .line 128
    .line 129
    move-result-object v2

    .line 130
    aput-object v2, v0, p0

    .line 131
    .line 132
    add-int/lit8 p0, p0, 0x1

    .line 133
    .line 134
    goto :goto_3

    .line 135
    :cond_6
    invoke-static {v1, v0}, Lmx0/n;->f([Ljava/lang/Object;[Ljava/lang/Object;)Z

    .line 136
    .line 137
    .line 138
    move-result p0

    .line 139
    return p0

    .line 140
    nop

    .line 141
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final h()Ljava/lang/Object;
    .locals 0

    .line 1
    iget p0, p0, Lda/c;->q:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    const/4 p0, 0x0

    .line 10
    new-array p0, p0, [Ljava/lang/String;

    .line 11
    .line 12
    return-object p0

    .line 13
    :pswitch_1
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 14
    .line 15
    return-object p0

    .line 16
    :pswitch_2
    const/4 p0, 0x0

    .line 17
    new-array p0, p0, [D

    .line 18
    .line 19
    return-object p0

    .line 20
    nop

    .line 21
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final i(Ljava/lang/Object;)Ljava/util/List;
    .locals 3

    .line 1
    iget p0, p0, Lda/c;->q:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/util/List;

    .line 7
    .line 8
    if-eqz p1, :cond_1

    .line 9
    .line 10
    check-cast p1, Ljava/lang/Iterable;

    .line 11
    .line 12
    new-instance p0, Ljava/util/ArrayList;

    .line 13
    .line 14
    const/16 v0, 0xa

    .line 15
    .line 16
    invoke-static {p1, v0}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    invoke-direct {p0, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 21
    .line 22
    .line 23
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-eqz v0, :cond_2

    .line 32
    .line 33
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    check-cast v0, Ljava/lang/String;

    .line 38
    .line 39
    if-eqz v0, :cond_0

    .line 40
    .line 41
    invoke-static {v0}, Lz9/h0;->b(Ljava/lang/String;)Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    goto :goto_1

    .line 46
    :cond_0
    const-string v0, "null"

    .line 47
    .line 48
    :goto_1
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_1
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 53
    .line 54
    :cond_2
    return-object p0

    .line 55
    :pswitch_0
    check-cast p1, [Ljava/lang/String;

    .line 56
    .line 57
    if-eqz p1, :cond_4

    .line 58
    .line 59
    new-instance p0, Ljava/util/ArrayList;

    .line 60
    .line 61
    array-length v0, p1

    .line 62
    invoke-direct {p0, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 63
    .line 64
    .line 65
    array-length v0, p1

    .line 66
    const/4 v1, 0x0

    .line 67
    :goto_2
    if-ge v1, v0, :cond_5

    .line 68
    .line 69
    aget-object v2, p1, v1

    .line 70
    .line 71
    if-eqz v2, :cond_3

    .line 72
    .line 73
    invoke-static {v2}, Lz9/h0;->b(Ljava/lang/String;)Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object v2

    .line 77
    goto :goto_3

    .line 78
    :cond_3
    const-string v2, "null"

    .line 79
    .line 80
    :goto_3
    invoke-virtual {p0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 81
    .line 82
    .line 83
    add-int/lit8 v1, v1, 0x1

    .line 84
    .line 85
    goto :goto_2

    .line 86
    :cond_4
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 87
    .line 88
    :cond_5
    return-object p0

    .line 89
    :pswitch_1
    check-cast p1, Ljava/util/List;

    .line 90
    .line 91
    if-eqz p1, :cond_6

    .line 92
    .line 93
    check-cast p1, Ljava/lang/Iterable;

    .line 94
    .line 95
    new-instance p0, Ljava/util/ArrayList;

    .line 96
    .line 97
    const/16 v0, 0xa

    .line 98
    .line 99
    invoke-static {p1, v0}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 100
    .line 101
    .line 102
    move-result v0

    .line 103
    invoke-direct {p0, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 104
    .line 105
    .line 106
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 107
    .line 108
    .line 109
    move-result-object p1

    .line 110
    :goto_4
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 111
    .line 112
    .line 113
    move-result v0

    .line 114
    if-eqz v0, :cond_7

    .line 115
    .line 116
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v0

    .line 120
    check-cast v0, Ljava/lang/Number;

    .line 121
    .line 122
    invoke-virtual {v0}, Ljava/lang/Number;->doubleValue()D

    .line 123
    .line 124
    .line 125
    move-result-wide v0

    .line 126
    invoke-static {v0, v1}, Ljava/lang/String;->valueOf(D)Ljava/lang/String;

    .line 127
    .line 128
    .line 129
    move-result-object v0

    .line 130
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 131
    .line 132
    .line 133
    goto :goto_4

    .line 134
    :cond_6
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 135
    .line 136
    :cond_7
    return-object p0

    .line 137
    :pswitch_2
    check-cast p1, [D

    .line 138
    .line 139
    if-eqz p1, :cond_8

    .line 140
    .line 141
    invoke-static {p1}, Lmx0/n;->X([D)Ljava/util/List;

    .line 142
    .line 143
    .line 144
    move-result-object p0

    .line 145
    check-cast p0, Ljava/lang/Iterable;

    .line 146
    .line 147
    new-instance p1, Ljava/util/ArrayList;

    .line 148
    .line 149
    const/16 v0, 0xa

    .line 150
    .line 151
    invoke-static {p0, v0}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 152
    .line 153
    .line 154
    move-result v0

    .line 155
    invoke-direct {p1, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 156
    .line 157
    .line 158
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 159
    .line 160
    .line 161
    move-result-object p0

    .line 162
    :goto_5
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 163
    .line 164
    .line 165
    move-result v0

    .line 166
    if-eqz v0, :cond_9

    .line 167
    .line 168
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 169
    .line 170
    .line 171
    move-result-object v0

    .line 172
    check-cast v0, Ljava/lang/Number;

    .line 173
    .line 174
    invoke-virtual {v0}, Ljava/lang/Number;->doubleValue()D

    .line 175
    .line 176
    .line 177
    move-result-wide v0

    .line 178
    invoke-static {v0, v1}, Ljava/lang/String;->valueOf(D)Ljava/lang/String;

    .line 179
    .line 180
    .line 181
    move-result-object v0

    .line 182
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 183
    .line 184
    .line 185
    goto :goto_5

    .line 186
    :cond_8
    sget-object p1, Lmx0/s;->d:Lmx0/s;

    .line 187
    .line 188
    :cond_9
    return-object p1

    .line 189
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public k(Ljava/lang/String;)[Ljava/lang/String;
    .locals 1

    .line 1
    const/4 p0, 0x1

    .line 2
    new-array p0, p0, [Ljava/lang/String;

    .line 3
    .line 4
    sget-object v0, Lz9/g0;->n:Lz9/e;

    .line 5
    .line 6
    invoke-virtual {v0, p1}, Lz9/e;->d(Ljava/lang/String;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    const/4 v0, 0x0

    .line 11
    aput-object p1, p0, v0

    .line 12
    .line 13
    return-object p0
.end method
