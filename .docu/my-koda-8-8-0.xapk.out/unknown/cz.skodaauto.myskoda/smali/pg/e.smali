.class public final Lpg/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lpg/e;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lpg/e;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lpg/e;->a:Lpg/e;

    .line 7
    .line 8
    return-void
.end method

.method public static a(Lmg/b;Z)Lpg/l;
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    const-string v1, "subscriptionData"

    .line 4
    .line 5
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Lmg/b;->b:Lkg/p0;

    .line 9
    .line 10
    iget-object v2, v0, Lmg/b;->c:Lac/e;

    .line 11
    .line 12
    iget-object v3, v0, Lmg/b;->d:Log/i;

    .line 13
    .line 14
    sget-object v4, Log/i;->e:Log/i;

    .line 15
    .line 16
    if-ne v3, v4, :cond_0

    .line 17
    .line 18
    iget-object v4, v0, Lmg/b;->e:Lac/e;

    .line 19
    .line 20
    if-eqz v4, :cond_0

    .line 21
    .line 22
    new-instance v3, Llx0/l;

    .line 23
    .line 24
    sget-object v5, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 25
    .line 26
    invoke-direct {v3, v5, v4}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    sget-object v4, Log/i;->f:Log/i;

    .line 31
    .line 32
    if-ne v3, v4, :cond_1

    .line 33
    .line 34
    new-instance v3, Llx0/l;

    .line 35
    .line 36
    sget-object v4, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 37
    .line 38
    const/4 v5, 0x0

    .line 39
    invoke-direct {v3, v4, v5}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_1
    new-instance v3, Llx0/l;

    .line 44
    .line 45
    sget-object v4, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 46
    .line 47
    invoke-direct {v3, v4, v2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    :goto_0
    iget-object v4, v3, Llx0/l;->d:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast v4, Ljava/lang/Boolean;

    .line 53
    .line 54
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 55
    .line 56
    .line 57
    move-result v11

    .line 58
    iget-object v3, v3, Llx0/l;->e:Ljava/lang/Object;

    .line 59
    .line 60
    check-cast v3, Lac/e;

    .line 61
    .line 62
    const/4 v5, 0x0

    .line 63
    if-eqz v2, :cond_2

    .line 64
    .line 65
    const/4 v8, 0x1

    .line 66
    goto :goto_1

    .line 67
    :cond_2
    move v8, v5

    .line 68
    :goto_1
    invoke-static {v1, v5}, Llp/p1;->d(Lkg/p0;Z)Lug/b;

    .line 69
    .line 70
    .line 71
    move-result-object v7

    .line 72
    iget-boolean v6, v1, Lkg/p0;->k:Z

    .line 73
    .line 74
    invoke-static {v2}, Lpg/e;->b(Lac/e;)Lpg/a;

    .line 75
    .line 76
    .line 77
    move-result-object v9

    .line 78
    invoke-static {v3}, Lpg/e;->b(Lac/e;)Lpg/a;

    .line 79
    .line 80
    .line 81
    move-result-object v12

    .line 82
    iget-object v2, v0, Lmg/b;->f:Lnc/z;

    .line 83
    .line 84
    const-string v3, "option"

    .line 85
    .line 86
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    sget-object v3, Lmc/z;->e:Lpy/a;

    .line 90
    .line 91
    iget-object v10, v2, Lnc/z;->g:Ljava/lang/String;

    .line 92
    .line 93
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 94
    .line 95
    .line 96
    invoke-static {v10}, Lpy/a;->o(Ljava/lang/String;)Lmc/z;

    .line 97
    .line 98
    .line 99
    move-result-object v3

    .line 100
    if-eqz v3, :cond_3

    .line 101
    .line 102
    new-instance v10, Lmc/v;

    .line 103
    .line 104
    invoke-direct {v10, v3}, Lmc/v;-><init>(Lmc/z;)V

    .line 105
    .line 106
    .line 107
    :goto_2
    move-object v14, v10

    .line 108
    goto :goto_3

    .line 109
    :cond_3
    new-instance v10, Lmc/w;

    .line 110
    .line 111
    iget-object v3, v2, Lnc/z;->e:Ljava/lang/String;

    .line 112
    .line 113
    invoke-direct {v10, v3}, Lmc/w;-><init>(Ljava/lang/String;)V

    .line 114
    .line 115
    .line 116
    goto :goto_2

    .line 117
    :goto_3
    new-instance v13, Lmc/x;

    .line 118
    .line 119
    iget-object v3, v2, Lnc/z;->f:Lnc/c0;

    .line 120
    .line 121
    iget-object v15, v3, Lnc/c0;->d:Ljava/lang/String;

    .line 122
    .line 123
    iget-object v3, v3, Lnc/c0;->e:Ljava/lang/String;

    .line 124
    .line 125
    iget-object v10, v2, Lnc/z;->i:Lnc/c0;

    .line 126
    .line 127
    if-eqz v10, :cond_4

    .line 128
    .line 129
    const/16 v17, 0x1

    .line 130
    .line 131
    goto :goto_4

    .line 132
    :cond_4
    move/from16 v17, v5

    .line 133
    .line 134
    :goto_4
    const-string v21, ""

    .line 135
    .line 136
    if-eqz v10, :cond_6

    .line 137
    .line 138
    iget-object v4, v10, Lnc/c0;->d:Ljava/lang/String;

    .line 139
    .line 140
    if-nez v4, :cond_5

    .line 141
    .line 142
    goto :goto_5

    .line 143
    :cond_5
    move-object/from16 v18, v4

    .line 144
    .line 145
    goto :goto_6

    .line 146
    :cond_6
    :goto_5
    move-object/from16 v18, v21

    .line 147
    .line 148
    :goto_6
    if-eqz v10, :cond_8

    .line 149
    .line 150
    iget-object v4, v10, Lnc/c0;->e:Ljava/lang/String;

    .line 151
    .line 152
    if-nez v4, :cond_7

    .line 153
    .line 154
    goto :goto_7

    .line 155
    :cond_7
    move-object/from16 v19, v4

    .line 156
    .line 157
    goto :goto_8

    .line 158
    :cond_8
    :goto_7
    move-object/from16 v19, v21

    .line 159
    .line 160
    :goto_8
    iget-object v2, v2, Lnc/z;->h:Ljava/lang/String;

    .line 161
    .line 162
    move-object/from16 v20, v2

    .line 163
    .line 164
    move-object/from16 v16, v3

    .line 165
    .line 166
    invoke-direct/range {v13 .. v20}, Lmc/x;-><init>(Lmc/s;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 167
    .line 168
    .line 169
    move v2, v6

    .line 170
    iget-object v6, v0, Lmg/b;->d:Log/i;

    .line 171
    .line 172
    iget-boolean v1, v1, Lkg/p0;->j:Z

    .line 173
    .line 174
    if-eqz v1, :cond_9

    .line 175
    .line 176
    if-nez p1, :cond_9

    .line 177
    .line 178
    if-nez v2, :cond_9

    .line 179
    .line 180
    const/16 v18, 0x1

    .line 181
    .line 182
    goto :goto_9

    .line 183
    :cond_9
    move/from16 v18, v5

    .line 184
    .line 185
    :goto_9
    if-eqz v2, :cond_a

    .line 186
    .line 187
    if-nez p1, :cond_a

    .line 188
    .line 189
    if-nez v1, :cond_a

    .line 190
    .line 191
    const/16 v19, 0x1

    .line 192
    .line 193
    goto :goto_a

    .line 194
    :cond_a
    move/from16 v19, v5

    .line 195
    .line 196
    :goto_a
    if-nez p1, :cond_b

    .line 197
    .line 198
    if-eqz v1, :cond_b

    .line 199
    .line 200
    if-eqz v2, :cond_b

    .line 201
    .line 202
    const/16 v17, 0x1

    .line 203
    .line 204
    goto :goto_b

    .line 205
    :cond_b
    move/from16 v17, v5

    .line 206
    .line 207
    :goto_b
    iget-object v0, v0, Lmg/b;->i:Ljava/lang/String;

    .line 208
    .line 209
    if-nez v0, :cond_c

    .line 210
    .line 211
    goto :goto_c

    .line 212
    :cond_c
    move-object/from16 v21, v0

    .line 213
    .line 214
    :goto_c
    new-instance v5, Lpg/l;

    .line 215
    .line 216
    const/4 v15, 0x0

    .line 217
    const/16 v20, 0x0

    .line 218
    .line 219
    const/4 v14, 0x0

    .line 220
    move v10, v8

    .line 221
    move/from16 v16, p1

    .line 222
    .line 223
    invoke-direct/range {v5 .. v21}, Lpg/l;-><init>(Log/i;Lug/b;ZLpg/a;ZZLpg/a;Lmc/x;ZZZZZZLug/a;Ljava/lang/String;)V

    .line 224
    .line 225
    .line 226
    return-object v5
.end method

.method public static b(Lac/e;)Lpg/a;
    .locals 6

    .line 1
    if-eqz p0, :cond_0

    .line 2
    .line 3
    new-instance v0, Lpg/a;

    .line 4
    .line 5
    iget-object v1, p0, Lac/e;->d:Ljava/lang/String;

    .line 6
    .line 7
    iget-object v2, p0, Lac/e;->e:Ljava/lang/String;

    .line 8
    .line 9
    const-string v3, " "

    .line 10
    .line 11
    invoke-static {v1, v3, v2}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    iget-object v2, p0, Lac/e;->f:Ljava/lang/String;

    .line 16
    .line 17
    iget-object v4, p0, Lac/e;->g:Ljava/lang/String;

    .line 18
    .line 19
    const-string v5, " \n"

    .line 20
    .line 21
    invoke-static {v2, v5, v4}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v2

    .line 25
    iget-object v4, p0, Lac/e;->h:Ljava/lang/String;

    .line 26
    .line 27
    iget-object p0, p0, Lac/e;->i:Ljava/lang/String;

    .line 28
    .line 29
    invoke-static {v4, v3, p0}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    invoke-direct {v0, v1, v2, p0}, Lpg/a;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    return-object v0

    .line 37
    :cond_0
    const/4 p0, 0x0

    .line 38
    return-object p0
.end method
