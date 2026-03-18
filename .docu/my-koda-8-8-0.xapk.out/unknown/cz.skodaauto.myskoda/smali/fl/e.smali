.class public final Lfl/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ld01/c0;


# instance fields
.field public final synthetic a:I

.field public final b:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Landroid/content/SharedPreferences;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lfl/e;->a:I

    const-string v0, "sharedPreferences"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lfl/e;->b:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ltj/h;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lfl/e;->a:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lfl/e;->b:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final intercept(Ld01/b0;)Ld01/t0;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lfl/e;->a:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Li01/f;

    .line 11
    .line 12
    iget-object v2, v1, Li01/f;->e:Ld01/k0;

    .line 13
    .line 14
    invoke-virtual {v1, v2}, Li01/f;->b(Ld01/k0;)Ld01/t0;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    const-string v2, "X-Subscription-Hash"

    .line 19
    .line 20
    invoke-static {v1, v2}, Ld01/t0;->b(Ld01/t0;Ljava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v2

    .line 24
    if-eqz v2, :cond_0

    .line 25
    .line 26
    iget-object v0, v0, Lfl/e;->b:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast v0, Ltj/h;

    .line 29
    .line 30
    invoke-virtual {v0, v2}, Ltj/h;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    :cond_0
    return-object v1

    .line 34
    :pswitch_0
    iget-object v0, v0, Lfl/e;->b:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast v0, Landroid/content/SharedPreferences;

    .line 37
    .line 38
    const-string v1, "consentCookie"

    .line 39
    .line 40
    const/4 v2, 0x0

    .line 41
    invoke-interface {v0, v1, v2}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v3

    .line 45
    move-object/from16 v4, p1

    .line 46
    .line 47
    check-cast v4, Li01/f;

    .line 48
    .line 49
    iget-object v5, v4, Li01/f;->e:Ld01/k0;

    .line 50
    .line 51
    invoke-virtual {v5}, Ld01/k0;->b()Ld01/j0;

    .line 52
    .line 53
    .line 54
    move-result-object v5

    .line 55
    const-string v6, "X-Cookie"

    .line 56
    .line 57
    const-string v7, "Kt"

    .line 58
    .line 59
    const/16 v8, 0x2e

    .line 60
    .line 61
    const/16 v9, 0x24

    .line 62
    .line 63
    const-class v10, Lfl/e;

    .line 64
    .line 65
    if-eqz v3, :cond_2

    .line 66
    .line 67
    sget-object v11, Lgi/a;->d:Lgi/a;

    .line 68
    .line 69
    new-instance v12, Lac0/r;

    .line 70
    .line 71
    const/16 v13, 0x9

    .line 72
    .line 73
    invoke-direct {v12, v3, v13}, Lac0/r;-><init>(Ljava/lang/String;I)V

    .line 74
    .line 75
    .line 76
    sget-object v13, Lgi/b;->e:Lgi/b;

    .line 77
    .line 78
    invoke-virtual {v10}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object v14

    .line 82
    invoke-static {v14, v9}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object v15

    .line 86
    invoke-static {v8, v15, v15}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object v15

    .line 90
    invoke-virtual {v15}, Ljava/lang/String;->length()I

    .line 91
    .line 92
    .line 93
    move-result v16

    .line 94
    if-nez v16, :cond_1

    .line 95
    .line 96
    goto :goto_0

    .line 97
    :cond_1
    invoke-static {v15, v7}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object v14

    .line 101
    :goto_0
    invoke-static {v14, v11, v13, v2, v12}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 102
    .line 103
    .line 104
    invoke-virtual {v5, v6, v3}, Ld01/j0;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 105
    .line 106
    .line 107
    goto :goto_2

    .line 108
    :cond_2
    sget-object v3, Lgi/a;->d:Lgi/a;

    .line 109
    .line 110
    new-instance v11, Lf31/n;

    .line 111
    .line 112
    const/16 v12, 0xc

    .line 113
    .line 114
    invoke-direct {v11, v12}, Lf31/n;-><init>(I)V

    .line 115
    .line 116
    .line 117
    sget-object v12, Lgi/b;->e:Lgi/b;

    .line 118
    .line 119
    invoke-virtual {v10}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 120
    .line 121
    .line 122
    move-result-object v13

    .line 123
    invoke-static {v13, v9}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 124
    .line 125
    .line 126
    move-result-object v14

    .line 127
    invoke-static {v8, v14, v14}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 128
    .line 129
    .line 130
    move-result-object v14

    .line 131
    invoke-virtual {v14}, Ljava/lang/String;->length()I

    .line 132
    .line 133
    .line 134
    move-result v15

    .line 135
    if-nez v15, :cond_3

    .line 136
    .line 137
    goto :goto_1

    .line 138
    :cond_3
    invoke-static {v14, v7}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 139
    .line 140
    .line 141
    move-result-object v13

    .line 142
    :goto_1
    invoke-static {v13, v3, v12, v2, v11}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 143
    .line 144
    .line 145
    :goto_2
    new-instance v3, Ld01/k0;

    .line 146
    .line 147
    invoke-direct {v3, v5}, Ld01/k0;-><init>(Ld01/j0;)V

    .line 148
    .line 149
    .line 150
    invoke-virtual {v4, v3}, Li01/f;->b(Ld01/k0;)Ld01/t0;

    .line 151
    .line 152
    .line 153
    move-result-object v3

    .line 154
    invoke-static {v3, v6}, Ld01/t0;->b(Ld01/t0;Ljava/lang/String;)Ljava/lang/String;

    .line 155
    .line 156
    .line 157
    move-result-object v4

    .line 158
    if-eqz v4, :cond_5

    .line 159
    .line 160
    sget-object v5, Lgi/a;->d:Lgi/a;

    .line 161
    .line 162
    new-instance v6, Lac0/r;

    .line 163
    .line 164
    const/16 v11, 0xa

    .line 165
    .line 166
    invoke-direct {v6, v4, v11}, Lac0/r;-><init>(Ljava/lang/String;I)V

    .line 167
    .line 168
    .line 169
    sget-object v11, Lgi/b;->e:Lgi/b;

    .line 170
    .line 171
    invoke-virtual {v10}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 172
    .line 173
    .line 174
    move-result-object v10

    .line 175
    invoke-static {v10, v9}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 176
    .line 177
    .line 178
    move-result-object v9

    .line 179
    invoke-static {v8, v9, v9}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 180
    .line 181
    .line 182
    move-result-object v8

    .line 183
    invoke-virtual {v8}, Ljava/lang/String;->length()I

    .line 184
    .line 185
    .line 186
    move-result v9

    .line 187
    if-nez v9, :cond_4

    .line 188
    .line 189
    goto :goto_3

    .line 190
    :cond_4
    invoke-static {v8, v7}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 191
    .line 192
    .line 193
    move-result-object v10

    .line 194
    :goto_3
    invoke-static {v10, v5, v11, v2, v6}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 195
    .line 196
    .line 197
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 198
    .line 199
    .line 200
    move-result-object v0

    .line 201
    invoke-interface {v0, v1, v4}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 202
    .line 203
    .line 204
    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 205
    .line 206
    .line 207
    :cond_5
    return-object v3

    .line 208
    nop

    .line 209
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
