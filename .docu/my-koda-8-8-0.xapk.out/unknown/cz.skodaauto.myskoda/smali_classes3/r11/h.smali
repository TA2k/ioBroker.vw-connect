.class public abstract Lr11/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lr11/y;
.implements Lr11/w;


# instance fields
.field public final d:Ln11/b;

.field public final e:I

.field public final f:Z


# direct methods
.method public constructor <init>(Ln11/b;IZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lr11/h;->d:Ln11/b;

    .line 5
    .line 6
    iput p2, p0, Lr11/h;->e:I

    .line 7
    .line 8
    iput-boolean p3, p0, Lr11/h;->f:Z

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a()I
    .locals 0

    .line 1
    iget p0, p0, Lr11/h;->e:I

    .line 2
    .line 3
    return p0
.end method

.method public d(Lr11/s;Ljava/lang/CharSequence;I)I
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    move/from16 v2, p3

    .line 6
    .line 7
    invoke-interface {v1}, Ljava/lang/CharSequence;->length()I

    .line 8
    .line 9
    .line 10
    move-result v3

    .line 11
    sub-int/2addr v3, v2

    .line 12
    iget v4, v0, Lr11/h;->e:I

    .line 13
    .line 14
    invoke-static {v4, v3}, Ljava/lang/Math;->min(II)I

    .line 15
    .line 16
    .line 17
    move-result v3

    .line 18
    const/4 v4, 0x0

    .line 19
    move v5, v4

    .line 20
    move v6, v5

    .line 21
    move v7, v6

    .line 22
    :goto_0
    const/16 v8, 0x30

    .line 23
    .line 24
    if-ge v5, v3, :cond_7

    .line 25
    .line 26
    add-int v9, v2, v5

    .line 27
    .line 28
    invoke-interface {v1, v9}, Ljava/lang/CharSequence;->charAt(I)C

    .line 29
    .line 30
    .line 31
    move-result v10

    .line 32
    const/16 v11, 0x39

    .line 33
    .line 34
    if-nez v5, :cond_5

    .line 35
    .line 36
    const/16 v12, 0x2b

    .line 37
    .line 38
    const/16 v13, 0x2d

    .line 39
    .line 40
    if-eq v10, v13, :cond_0

    .line 41
    .line 42
    if-ne v10, v12, :cond_5

    .line 43
    .line 44
    :cond_0
    iget-boolean v14, v0, Lr11/h;->f:Z

    .line 45
    .line 46
    if-eqz v14, :cond_5

    .line 47
    .line 48
    const/4 v6, 0x1

    .line 49
    if-ne v10, v13, :cond_1

    .line 50
    .line 51
    move v7, v6

    .line 52
    goto :goto_1

    .line 53
    :cond_1
    move v7, v4

    .line 54
    :goto_1
    if-ne v10, v12, :cond_2

    .line 55
    .line 56
    goto :goto_2

    .line 57
    :cond_2
    move v6, v4

    .line 58
    :goto_2
    add-int/lit8 v10, v5, 0x1

    .line 59
    .line 60
    if-ge v10, v3, :cond_4

    .line 61
    .line 62
    add-int/lit8 v9, v9, 0x1

    .line 63
    .line 64
    invoke-interface {v1, v9}, Ljava/lang/CharSequence;->charAt(I)C

    .line 65
    .line 66
    .line 67
    move-result v9

    .line 68
    if-lt v9, v8, :cond_4

    .line 69
    .line 70
    if-le v9, v11, :cond_3

    .line 71
    .line 72
    goto :goto_3

    .line 73
    :cond_3
    add-int/lit8 v3, v3, 0x1

    .line 74
    .line 75
    invoke-interface {v1}, Ljava/lang/CharSequence;->length()I

    .line 76
    .line 77
    .line 78
    move-result v5

    .line 79
    sub-int/2addr v5, v2

    .line 80
    invoke-static {v3, v5}, Ljava/lang/Math;->min(II)I

    .line 81
    .line 82
    .line 83
    move-result v3

    .line 84
    move v5, v7

    .line 85
    move v7, v6

    .line 86
    move v6, v5

    .line 87
    move v5, v10

    .line 88
    goto :goto_0

    .line 89
    :cond_4
    :goto_3
    move v15, v7

    .line 90
    move v7, v6

    .line 91
    move v6, v15

    .line 92
    goto :goto_4

    .line 93
    :cond_5
    if-lt v10, v8, :cond_7

    .line 94
    .line 95
    if-le v10, v11, :cond_6

    .line 96
    .line 97
    goto :goto_4

    .line 98
    :cond_6
    add-int/lit8 v5, v5, 0x1

    .line 99
    .line 100
    goto :goto_0

    .line 101
    :cond_7
    :goto_4
    if-nez v5, :cond_8

    .line 102
    .line 103
    not-int v0, v2

    .line 104
    return v0

    .line 105
    :cond_8
    const/16 v3, 0x9

    .line 106
    .line 107
    if-lt v5, v3, :cond_a

    .line 108
    .line 109
    if-eqz v7, :cond_9

    .line 110
    .line 111
    add-int/lit8 v3, v2, 0x1

    .line 112
    .line 113
    add-int/2addr v2, v5

    .line 114
    invoke-interface {v1, v3, v2}, Ljava/lang/CharSequence;->subSequence(II)Ljava/lang/CharSequence;

    .line 115
    .line 116
    .line 117
    move-result-object v1

    .line 118
    invoke-virtual {v1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 119
    .line 120
    .line 121
    move-result-object v1

    .line 122
    invoke-static {v1}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 123
    .line 124
    .line 125
    move-result v1

    .line 126
    goto :goto_8

    .line 127
    :cond_9
    add-int v3, v2, v5

    .line 128
    .line 129
    invoke-interface {v1, v2, v3}, Ljava/lang/CharSequence;->subSequence(II)Ljava/lang/CharSequence;

    .line 130
    .line 131
    .line 132
    move-result-object v1

    .line 133
    invoke-virtual {v1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 134
    .line 135
    .line 136
    move-result-object v1

    .line 137
    invoke-static {v1}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 138
    .line 139
    .line 140
    move-result v1

    .line 141
    move v2, v3

    .line 142
    goto :goto_8

    .line 143
    :cond_a
    if-nez v6, :cond_c

    .line 144
    .line 145
    if-eqz v7, :cond_b

    .line 146
    .line 147
    goto :goto_5

    .line 148
    :cond_b
    move v3, v2

    .line 149
    goto :goto_6

    .line 150
    :cond_c
    :goto_5
    add-int/lit8 v3, v2, 0x1

    .line 151
    .line 152
    :goto_6
    add-int/lit8 v4, v3, 0x1

    .line 153
    .line 154
    :try_start_0
    invoke-interface {v1, v3}, Ljava/lang/CharSequence;->charAt(I)C

    .line 155
    .line 156
    .line 157
    move-result v3
    :try_end_0
    .catch Ljava/lang/StringIndexOutOfBoundsException; {:try_start_0 .. :try_end_0} :catch_0

    .line 158
    sub-int/2addr v3, v8

    .line 159
    add-int/2addr v2, v5

    .line 160
    :goto_7
    if-ge v4, v2, :cond_d

    .line 161
    .line 162
    shl-int/lit8 v5, v3, 0x3

    .line 163
    .line 164
    shl-int/lit8 v3, v3, 0x1

    .line 165
    .line 166
    add-int/2addr v5, v3

    .line 167
    add-int/lit8 v3, v4, 0x1

    .line 168
    .line 169
    invoke-interface {v1, v4}, Ljava/lang/CharSequence;->charAt(I)C

    .line 170
    .line 171
    .line 172
    move-result v4

    .line 173
    add-int/2addr v4, v5

    .line 174
    sub-int/2addr v4, v8

    .line 175
    move v15, v4

    .line 176
    move v4, v3

    .line 177
    move v3, v15

    .line 178
    goto :goto_7

    .line 179
    :cond_d
    if-eqz v6, :cond_e

    .line 180
    .line 181
    neg-int v1, v3

    .line 182
    goto :goto_8

    .line 183
    :cond_e
    move v1, v3

    .line 184
    :goto_8
    invoke-virtual/range {p1 .. p1}, Lr11/s;->c()Lr11/q;

    .line 185
    .line 186
    .line 187
    move-result-object v3

    .line 188
    move-object/from16 v4, p1

    .line 189
    .line 190
    iget-object v4, v4, Lr11/s;->a:Ljp/u1;

    .line 191
    .line 192
    iget-object v0, v0, Lr11/h;->d:Ln11/b;

    .line 193
    .line 194
    invoke-virtual {v0, v4}, Ln11/b;->a(Ljp/u1;)Ln11/a;

    .line 195
    .line 196
    .line 197
    move-result-object v0

    .line 198
    iput-object v0, v3, Lr11/q;->d:Ln11/a;

    .line 199
    .line 200
    iput v1, v3, Lr11/q;->e:I

    .line 201
    .line 202
    const/4 v0, 0x0

    .line 203
    iput-object v0, v3, Lr11/q;->f:Ljava/lang/String;

    .line 204
    .line 205
    iput-object v0, v3, Lr11/q;->g:Ljava/util/Locale;

    .line 206
    .line 207
    return v2

    .line 208
    :catch_0
    not-int v0, v2

    .line 209
    return v0
.end method
