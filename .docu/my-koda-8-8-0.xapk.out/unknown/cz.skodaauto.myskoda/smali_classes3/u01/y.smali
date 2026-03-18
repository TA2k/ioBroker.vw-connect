.class public final Lu01/y;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Comparable;


# static fields
.field public static final e:Ljava/lang/String;


# instance fields
.field public final d:Lu01/i;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    sget-object v0, Ljava/io/File;->separator:Ljava/lang/String;

    .line 2
    .line 3
    const-string v1, "separator"

    .line 4
    .line 5
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lu01/y;->e:Ljava/lang/String;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>(Lu01/i;)V
    .locals 1

    .line 1
    const-string v0, "bytes"

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
    iput-object p1, p0, Lu01/y;->d:Lu01/i;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final a()Ljava/util/ArrayList;
    .locals 7

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-static {p0}, Lv01/c;->a(Lu01/y;)I

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    const/4 v2, -0x1

    .line 11
    const/16 v3, 0x5c

    .line 12
    .line 13
    iget-object p0, p0, Lu01/y;->d:Lu01/i;

    .line 14
    .line 15
    if-ne v1, v2, :cond_0

    .line 16
    .line 17
    const/4 v1, 0x0

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    invoke-virtual {p0}, Lu01/i;->d()I

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    if-ge v1, v2, :cond_1

    .line 24
    .line 25
    invoke-virtual {p0, v1}, Lu01/i;->i(I)B

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    if-ne v2, v3, :cond_1

    .line 30
    .line 31
    add-int/lit8 v1, v1, 0x1

    .line 32
    .line 33
    :cond_1
    :goto_0
    invoke-virtual {p0}, Lu01/i;->d()I

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    move v4, v1

    .line 38
    :goto_1
    if-ge v1, v2, :cond_4

    .line 39
    .line 40
    invoke-virtual {p0, v1}, Lu01/i;->i(I)B

    .line 41
    .line 42
    .line 43
    move-result v5

    .line 44
    const/16 v6, 0x2f

    .line 45
    .line 46
    if-eq v5, v6, :cond_2

    .line 47
    .line 48
    invoke-virtual {p0, v1}, Lu01/i;->i(I)B

    .line 49
    .line 50
    .line 51
    move-result v5

    .line 52
    if-ne v5, v3, :cond_3

    .line 53
    .line 54
    :cond_2
    invoke-virtual {p0, v4, v1}, Lu01/i;->o(II)Lu01/i;

    .line 55
    .line 56
    .line 57
    move-result-object v4

    .line 58
    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    add-int/lit8 v4, v1, 0x1

    .line 62
    .line 63
    :cond_3
    add-int/lit8 v1, v1, 0x1

    .line 64
    .line 65
    goto :goto_1

    .line 66
    :cond_4
    invoke-virtual {p0}, Lu01/i;->d()I

    .line 67
    .line 68
    .line 69
    move-result v1

    .line 70
    if-ge v4, v1, :cond_5

    .line 71
    .line 72
    invoke-virtual {p0}, Lu01/i;->d()I

    .line 73
    .line 74
    .line 75
    move-result v1

    .line 76
    invoke-virtual {p0, v4, v1}, Lu01/i;->o(II)Lu01/i;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 81
    .line 82
    .line 83
    :cond_5
    return-object v0
.end method

.method public final b()Ljava/lang/String;
    .locals 4

    .line 1
    sget-object v0, Lv01/c;->a:Lu01/i;

    .line 2
    .line 3
    iget-object v1, p0, Lu01/y;->d:Lu01/i;

    .line 4
    .line 5
    invoke-static {v1, v0}, Lu01/i;->k(Lu01/i;Lu01/i;)I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/4 v2, -0x1

    .line 10
    if-eq v0, v2, :cond_0

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    sget-object v0, Lv01/c;->b:Lu01/i;

    .line 14
    .line 15
    invoke-static {v1, v0}, Lu01/i;->k(Lu01/i;Lu01/i;)I

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    :goto_0
    const/4 v3, 0x2

    .line 20
    if-eq v0, v2, :cond_1

    .line 21
    .line 22
    add-int/lit8 v0, v0, 0x1

    .line 23
    .line 24
    const/4 p0, 0x0

    .line 25
    invoke-static {v1, v0, p0, v3}, Lu01/i;->p(Lu01/i;III)Lu01/i;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    goto :goto_1

    .line 30
    :cond_1
    invoke-virtual {p0}, Lu01/y;->g()Ljava/lang/Character;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    if-eqz p0, :cond_2

    .line 35
    .line 36
    invoke-virtual {v1}, Lu01/i;->d()I

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    if-ne p0, v3, :cond_2

    .line 41
    .line 42
    sget-object v1, Lu01/i;->g:Lu01/i;

    .line 43
    .line 44
    :cond_2
    :goto_1
    invoke-virtual {v1}, Lu01/i;->r()Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0
.end method

.method public final c()Lu01/y;
    .locals 10

    .line 1
    sget-object v0, Lv01/c;->d:Lu01/i;

    .line 2
    .line 3
    iget-object v1, p0, Lu01/y;->d:Lu01/i;

    .line 4
    .line 5
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v2

    .line 9
    if-nez v2, :cond_b

    .line 10
    .line 11
    sget-object v2, Lv01/c;->a:Lu01/i;

    .line 12
    .line 13
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v3

    .line 17
    if-nez v3, :cond_b

    .line 18
    .line 19
    sget-object v3, Lv01/c;->b:Lu01/i;

    .line 20
    .line 21
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v4

    .line 25
    if-nez v4, :cond_b

    .line 26
    .line 27
    sget-object v4, Lv01/c;->e:Lu01/i;

    .line 28
    .line 29
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 30
    .line 31
    .line 32
    const-string v5, "suffix"

    .line 33
    .line 34
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {v1}, Lu01/i;->d()I

    .line 38
    .line 39
    .line 40
    move-result v5

    .line 41
    iget-object v6, v4, Lu01/i;->d:[B

    .line 42
    .line 43
    array-length v7, v6

    .line 44
    sub-int/2addr v5, v7

    .line 45
    array-length v6, v6

    .line 46
    invoke-virtual {v1, v5, v4, v6}, Lu01/i;->l(ILu01/i;I)Z

    .line 47
    .line 48
    .line 49
    move-result v4

    .line 50
    const/4 v5, 0x3

    .line 51
    const/4 v6, 0x2

    .line 52
    const/4 v7, 0x1

    .line 53
    if-eqz v4, :cond_2

    .line 54
    .line 55
    invoke-virtual {v1}, Lu01/i;->d()I

    .line 56
    .line 57
    .line 58
    move-result v4

    .line 59
    if-ne v4, v6, :cond_0

    .line 60
    .line 61
    goto/16 :goto_1

    .line 62
    .line 63
    :cond_0
    invoke-virtual {v1}, Lu01/i;->d()I

    .line 64
    .line 65
    .line 66
    move-result v4

    .line 67
    sub-int/2addr v4, v5

    .line 68
    invoke-virtual {v1, v4, v2, v7}, Lu01/i;->l(ILu01/i;I)Z

    .line 69
    .line 70
    .line 71
    move-result v4

    .line 72
    if-eqz v4, :cond_1

    .line 73
    .line 74
    goto/16 :goto_1

    .line 75
    .line 76
    :cond_1
    invoke-virtual {v1}, Lu01/i;->d()I

    .line 77
    .line 78
    .line 79
    move-result v4

    .line 80
    sub-int/2addr v4, v5

    .line 81
    invoke-virtual {v1, v4, v3, v7}, Lu01/i;->l(ILu01/i;I)Z

    .line 82
    .line 83
    .line 84
    move-result v4

    .line 85
    if-eqz v4, :cond_2

    .line 86
    .line 87
    goto/16 :goto_1

    .line 88
    .line 89
    :cond_2
    invoke-static {v1, v2}, Lu01/i;->k(Lu01/i;Lu01/i;)I

    .line 90
    .line 91
    .line 92
    move-result v2

    .line 93
    const/4 v4, -0x1

    .line 94
    if-eq v2, v4, :cond_3

    .line 95
    .line 96
    goto :goto_0

    .line 97
    :cond_3
    invoke-static {v1, v3}, Lu01/i;->k(Lu01/i;Lu01/i;)I

    .line 98
    .line 99
    .line 100
    move-result v2

    .line 101
    :goto_0
    const/4 v8, 0x0

    .line 102
    if-ne v2, v6, :cond_5

    .line 103
    .line 104
    invoke-virtual {p0}, Lu01/y;->g()Ljava/lang/Character;

    .line 105
    .line 106
    .line 107
    move-result-object v9

    .line 108
    if-eqz v9, :cond_5

    .line 109
    .line 110
    invoke-virtual {v1}, Lu01/i;->d()I

    .line 111
    .line 112
    .line 113
    move-result p0

    .line 114
    if-ne p0, v5, :cond_4

    .line 115
    .line 116
    goto :goto_1

    .line 117
    :cond_4
    new-instance p0, Lu01/y;

    .line 118
    .line 119
    invoke-static {v1, v8, v5, v7}, Lu01/i;->p(Lu01/i;III)Lu01/i;

    .line 120
    .line 121
    .line 122
    move-result-object v0

    .line 123
    invoke-direct {p0, v0}, Lu01/y;-><init>(Lu01/i;)V

    .line 124
    .line 125
    .line 126
    return-object p0

    .line 127
    :cond_5
    if-ne v2, v7, :cond_6

    .line 128
    .line 129
    const-string v5, "prefix"

    .line 130
    .line 131
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    invoke-virtual {v3}, Lu01/i;->d()I

    .line 135
    .line 136
    .line 137
    move-result v5

    .line 138
    invoke-virtual {v1, v8, v3, v5}, Lu01/i;->l(ILu01/i;I)Z

    .line 139
    .line 140
    .line 141
    move-result v3

    .line 142
    if-eqz v3, :cond_6

    .line 143
    .line 144
    goto :goto_1

    .line 145
    :cond_6
    if-ne v2, v4, :cond_8

    .line 146
    .line 147
    invoke-virtual {p0}, Lu01/y;->g()Ljava/lang/Character;

    .line 148
    .line 149
    .line 150
    move-result-object p0

    .line 151
    if-eqz p0, :cond_8

    .line 152
    .line 153
    invoke-virtual {v1}, Lu01/i;->d()I

    .line 154
    .line 155
    .line 156
    move-result p0

    .line 157
    if-ne p0, v6, :cond_7

    .line 158
    .line 159
    goto :goto_1

    .line 160
    :cond_7
    new-instance p0, Lu01/y;

    .line 161
    .line 162
    invoke-static {v1, v8, v6, v7}, Lu01/i;->p(Lu01/i;III)Lu01/i;

    .line 163
    .line 164
    .line 165
    move-result-object v0

    .line 166
    invoke-direct {p0, v0}, Lu01/y;-><init>(Lu01/i;)V

    .line 167
    .line 168
    .line 169
    return-object p0

    .line 170
    :cond_8
    if-ne v2, v4, :cond_9

    .line 171
    .line 172
    new-instance p0, Lu01/y;

    .line 173
    .line 174
    invoke-direct {p0, v0}, Lu01/y;-><init>(Lu01/i;)V

    .line 175
    .line 176
    .line 177
    return-object p0

    .line 178
    :cond_9
    if-nez v2, :cond_a

    .line 179
    .line 180
    new-instance p0, Lu01/y;

    .line 181
    .line 182
    invoke-static {v1, v8, v7, v7}, Lu01/i;->p(Lu01/i;III)Lu01/i;

    .line 183
    .line 184
    .line 185
    move-result-object v0

    .line 186
    invoke-direct {p0, v0}, Lu01/y;-><init>(Lu01/i;)V

    .line 187
    .line 188
    .line 189
    return-object p0

    .line 190
    :cond_a
    new-instance p0, Lu01/y;

    .line 191
    .line 192
    invoke-static {v1, v8, v2, v7}, Lu01/i;->p(Lu01/i;III)Lu01/i;

    .line 193
    .line 194
    .line 195
    move-result-object v0

    .line 196
    invoke-direct {p0, v0}, Lu01/y;-><init>(Lu01/i;)V

    .line 197
    .line 198
    .line 199
    return-object p0

    .line 200
    :cond_b
    :goto_1
    const/4 p0, 0x0

    .line 201
    return-object p0
.end method

.method public final compareTo(Ljava/lang/Object;)I
    .locals 1

    .line 1
    check-cast p1, Lu01/y;

    .line 2
    .line 3
    const-string v0, "other"

    .line 4
    .line 5
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lu01/y;->d:Lu01/i;

    .line 9
    .line 10
    iget-object p1, p1, Lu01/y;->d:Lu01/i;

    .line 11
    .line 12
    invoke-virtual {p0, p1}, Lu01/i;->b(Lu01/i;)I

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    return p0
.end method

.method public final d(Lu01/y;)Lu01/y;
    .locals 11

    .line 1
    const-string v0, "other"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p1, Lu01/y;->d:Lu01/i;

    .line 7
    .line 8
    invoke-static {p0}, Lv01/c;->a(Lu01/y;)I

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    iget-object v2, p0, Lu01/y;->d:Lu01/i;

    .line 13
    .line 14
    const/4 v3, 0x0

    .line 15
    const/4 v4, 0x0

    .line 16
    const/4 v5, -0x1

    .line 17
    if-ne v1, v5, :cond_0

    .line 18
    .line 19
    move-object v6, v3

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    new-instance v6, Lu01/y;

    .line 22
    .line 23
    invoke-virtual {v2, v4, v1}, Lu01/i;->o(II)Lu01/i;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    invoke-direct {v6, v1}, Lu01/y;-><init>(Lu01/i;)V

    .line 28
    .line 29
    .line 30
    :goto_0
    invoke-static {p1}, Lv01/c;->a(Lu01/y;)I

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    if-ne v1, v5, :cond_1

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_1
    new-instance v3, Lu01/y;

    .line 38
    .line 39
    invoke-virtual {v0, v4, v1}, Lu01/i;->o(II)Lu01/i;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    invoke-direct {v3, v1}, Lu01/y;-><init>(Lu01/i;)V

    .line 44
    .line 45
    .line 46
    :goto_1
    invoke-static {v6, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    const-string v3, " and "

    .line 51
    .line 52
    if-eqz v1, :cond_9

    .line 53
    .line 54
    invoke-virtual {p0}, Lu01/y;->a()Ljava/util/ArrayList;

    .line 55
    .line 56
    .line 57
    move-result-object v1

    .line 58
    invoke-virtual {p1}, Lu01/y;->a()Ljava/util/ArrayList;

    .line 59
    .line 60
    .line 61
    move-result-object v6

    .line 62
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 63
    .line 64
    .line 65
    move-result v7

    .line 66
    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    .line 67
    .line 68
    .line 69
    move-result v8

    .line 70
    invoke-static {v7, v8}, Ljava/lang/Math;->min(II)I

    .line 71
    .line 72
    .line 73
    move-result v7

    .line 74
    move v8, v4

    .line 75
    :goto_2
    if-ge v8, v7, :cond_2

    .line 76
    .line 77
    invoke-virtual {v1, v8}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object v9

    .line 81
    invoke-virtual {v6, v8}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v10

    .line 85
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    move-result v9

    .line 89
    if-eqz v9, :cond_2

    .line 90
    .line 91
    add-int/lit8 v8, v8, 0x1

    .line 92
    .line 93
    goto :goto_2

    .line 94
    :cond_2
    if-ne v8, v7, :cond_3

    .line 95
    .line 96
    invoke-virtual {v2}, Lu01/i;->d()I

    .line 97
    .line 98
    .line 99
    move-result v2

    .line 100
    invoke-virtual {v0}, Lu01/i;->d()I

    .line 101
    .line 102
    .line 103
    move-result v7

    .line 104
    if-ne v2, v7, :cond_3

    .line 105
    .line 106
    const-string p0, "."

    .line 107
    .line 108
    invoke-static {p0}, Lrb0/a;->a(Ljava/lang/String;)Lu01/y;

    .line 109
    .line 110
    .line 111
    move-result-object p0

    .line 112
    return-object p0

    .line 113
    :cond_3
    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    .line 114
    .line 115
    .line 116
    move-result v2

    .line 117
    invoke-virtual {v6, v8, v2}, Ljava/util/ArrayList;->subList(II)Ljava/util/List;

    .line 118
    .line 119
    .line 120
    move-result-object v2

    .line 121
    sget-object v7, Lv01/c;->e:Lu01/i;

    .line 122
    .line 123
    invoke-interface {v2, v7}, Ljava/util/List;->indexOf(Ljava/lang/Object;)I

    .line 124
    .line 125
    .line 126
    move-result v2

    .line 127
    if-ne v2, v5, :cond_8

    .line 128
    .line 129
    sget-object v2, Lv01/c;->d:Lu01/i;

    .line 130
    .line 131
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 132
    .line 133
    .line 134
    move-result v0

    .line 135
    if-eqz v0, :cond_4

    .line 136
    .line 137
    return-object p0

    .line 138
    :cond_4
    new-instance v0, Lu01/f;

    .line 139
    .line 140
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 141
    .line 142
    .line 143
    invoke-static {p1}, Lv01/c;->c(Lu01/y;)Lu01/i;

    .line 144
    .line 145
    .line 146
    move-result-object p1

    .line 147
    if-nez p1, :cond_5

    .line 148
    .line 149
    invoke-static {p0}, Lv01/c;->c(Lu01/y;)Lu01/i;

    .line 150
    .line 151
    .line 152
    move-result-object p1

    .line 153
    if-nez p1, :cond_5

    .line 154
    .line 155
    sget-object p0, Lu01/y;->e:Ljava/lang/String;

    .line 156
    .line 157
    invoke-static {p0}, Lv01/c;->f(Ljava/lang/String;)Lu01/i;

    .line 158
    .line 159
    .line 160
    move-result-object p1

    .line 161
    :cond_5
    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    .line 162
    .line 163
    .line 164
    move-result p0

    .line 165
    move v2, v8

    .line 166
    :goto_3
    if-ge v2, p0, :cond_6

    .line 167
    .line 168
    sget-object v3, Lv01/c;->e:Lu01/i;

    .line 169
    .line 170
    invoke-virtual {v0, v3}, Lu01/f;->e0(Lu01/i;)V

    .line 171
    .line 172
    .line 173
    invoke-virtual {v0, p1}, Lu01/f;->e0(Lu01/i;)V

    .line 174
    .line 175
    .line 176
    add-int/lit8 v2, v2, 0x1

    .line 177
    .line 178
    goto :goto_3

    .line 179
    :cond_6
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 180
    .line 181
    .line 182
    move-result p0

    .line 183
    :goto_4
    if-ge v8, p0, :cond_7

    .line 184
    .line 185
    invoke-virtual {v1, v8}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 186
    .line 187
    .line 188
    move-result-object v2

    .line 189
    check-cast v2, Lu01/i;

    .line 190
    .line 191
    invoke-virtual {v0, v2}, Lu01/f;->e0(Lu01/i;)V

    .line 192
    .line 193
    .line 194
    invoke-virtual {v0, p1}, Lu01/f;->e0(Lu01/i;)V

    .line 195
    .line 196
    .line 197
    add-int/lit8 v8, v8, 0x1

    .line 198
    .line 199
    goto :goto_4

    .line 200
    :cond_7
    invoke-static {v0, v4}, Lv01/c;->d(Lu01/f;Z)Lu01/y;

    .line 201
    .line 202
    .line 203
    move-result-object p0

    .line 204
    return-object p0

    .line 205
    :cond_8
    new-instance v0, Ljava/lang/StringBuilder;

    .line 206
    .line 207
    const-string v1, "Impossible relative path to resolve: "

    .line 208
    .line 209
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 210
    .line 211
    .line 212
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 213
    .line 214
    .line 215
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 216
    .line 217
    .line 218
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 219
    .line 220
    .line 221
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 222
    .line 223
    .line 224
    move-result-object p0

    .line 225
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 226
    .line 227
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 228
    .line 229
    .line 230
    move-result-object p0

    .line 231
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 232
    .line 233
    .line 234
    throw p1

    .line 235
    :cond_9
    new-instance v0, Ljava/lang/StringBuilder;

    .line 236
    .line 237
    const-string v1, "Paths of different roots cannot be relative to each other: "

    .line 238
    .line 239
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 240
    .line 241
    .line 242
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 243
    .line 244
    .line 245
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 246
    .line 247
    .line 248
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 249
    .line 250
    .line 251
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 252
    .line 253
    .line 254
    move-result-object p0

    .line 255
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 256
    .line 257
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 258
    .line 259
    .line 260
    move-result-object p0

    .line 261
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 262
    .line 263
    .line 264
    throw p1
.end method

.method public final e(Ljava/lang/String;)Lu01/y;
    .locals 1

    .line 1
    const-string v0, "child"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lu01/f;

    .line 7
    .line 8
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0, p1}, Lu01/f;->x0(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    const/4 p1, 0x0

    .line 15
    invoke-static {v0, p1}, Lv01/c;->d(Lu01/f;Z)Lu01/y;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    invoke-static {p0, v0, p1}, Lv01/c;->b(Lu01/y;Lu01/y;Z)Lu01/y;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    instance-of v0, p1, Lu01/y;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p1, Lu01/y;

    .line 6
    .line 7
    iget-object p1, p1, Lu01/y;->d:Lu01/i;

    .line 8
    .line 9
    iget-object p0, p0, Lu01/y;->d:Lu01/i;

    .line 10
    .line 11
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    if-eqz p0, :cond_0

    .line 16
    .line 17
    const/4 p0, 0x1

    .line 18
    return p0

    .line 19
    :cond_0
    const/4 p0, 0x0

    .line 20
    return p0
.end method

.method public final f()Ljava/nio/file/Path;
    .locals 1

    .line 1
    iget-object p0, p0, Lu01/y;->d:Lu01/i;

    .line 2
    .line 3
    invoke-virtual {p0}, Lu01/i;->r()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const/4 v0, 0x0

    .line 8
    new-array v0, v0, [Ljava/lang/String;

    .line 9
    .line 10
    invoke-static {p0, v0}, Ljava/nio/file/Paths;->get(Ljava/lang/String;[Ljava/lang/String;)Ljava/nio/file/Path;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    const-string v0, "get(...)"

    .line 15
    .line 16
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    return-object p0
.end method

.method public final g()Ljava/lang/Character;
    .locals 2

    .line 1
    sget-object v0, Lv01/c;->a:Lu01/i;

    .line 2
    .line 3
    iget-object p0, p0, Lu01/y;->d:Lu01/i;

    .line 4
    .line 5
    invoke-static {p0, v0}, Lu01/i;->g(Lu01/i;Lu01/i;)I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/4 v1, -0x1

    .line 10
    if-eq v0, v1, :cond_0

    .line 11
    .line 12
    goto :goto_1

    .line 13
    :cond_0
    invoke-virtual {p0}, Lu01/i;->d()I

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    const/4 v1, 0x2

    .line 18
    if-ge v0, v1, :cond_1

    .line 19
    .line 20
    goto :goto_1

    .line 21
    :cond_1
    const/4 v0, 0x1

    .line 22
    invoke-virtual {p0, v0}, Lu01/i;->i(I)B

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    const/16 v1, 0x3a

    .line 27
    .line 28
    if-eq v0, v1, :cond_2

    .line 29
    .line 30
    goto :goto_1

    .line 31
    :cond_2
    const/4 v0, 0x0

    .line 32
    invoke-virtual {p0, v0}, Lu01/i;->i(I)B

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    int-to-char p0, p0

    .line 37
    const/16 v0, 0x61

    .line 38
    .line 39
    if-gt v0, p0, :cond_3

    .line 40
    .line 41
    const/16 v0, 0x7b

    .line 42
    .line 43
    if-ge p0, v0, :cond_3

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_3
    const/16 v0, 0x41

    .line 47
    .line 48
    if-gt v0, p0, :cond_4

    .line 49
    .line 50
    const/16 v0, 0x5b

    .line 51
    .line 52
    if-ge p0, v0, :cond_4

    .line 53
    .line 54
    :goto_0
    invoke-static {p0}, Ljava/lang/Character;->valueOf(C)Ljava/lang/Character;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    return-object p0

    .line 59
    :cond_4
    :goto_1
    const/4 p0, 0x0

    .line 60
    return-object p0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Lu01/y;->d:Lu01/i;

    .line 2
    .line 3
    invoke-virtual {p0}, Lu01/i;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final toFile()Ljava/io/File;
    .locals 1

    .line 1
    new-instance v0, Ljava/io/File;

    .line 2
    .line 3
    iget-object p0, p0, Lu01/y;->d:Lu01/i;

    .line 4
    .line 5
    invoke-virtual {p0}, Lu01/i;->r()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-direct {v0, p0}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    return-object v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lu01/y;->d:Lu01/i;

    .line 2
    .line 3
    invoke-virtual {p0}, Lu01/i;->r()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
