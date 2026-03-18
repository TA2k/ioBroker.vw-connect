.class public final Lc3/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final b:Lc3/q;

.field public static final c:Lc3/q;

.field public static final d:Lc3/q;


# instance fields
.field public final a:Ln2/b;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lc3/q;

    .line 2
    .line 3
    invoke-direct {v0}, Lc3/q;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lc3/q;->b:Lc3/q;

    .line 7
    .line 8
    new-instance v0, Lc3/q;

    .line 9
    .line 10
    invoke-direct {v0}, Lc3/q;-><init>()V

    .line 11
    .line 12
    .line 13
    sput-object v0, Lc3/q;->c:Lc3/q;

    .line 14
    .line 15
    new-instance v0, Lc3/q;

    .line 16
    .line 17
    invoke-direct {v0}, Lc3/q;-><init>()V

    .line 18
    .line 19
    .line 20
    sput-object v0, Lc3/q;->d:Lc3/q;

    .line 21
    .line 22
    return-void
.end method

.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ln2/b;

    .line 5
    .line 6
    const/16 v1, 0x10

    .line 7
    .line 8
    new-array v1, v1, [Lc3/r;

    .line 9
    .line 10
    invoke-direct {v0, v1}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    iput-object v0, p0, Lc3/q;->a:Ln2/b;

    .line 14
    .line 15
    return-void
.end method

.method public static b(Lc3/q;)V
    .locals 3

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    new-instance v0, Lc3/n;

    .line 5
    .line 6
    const/4 v1, 0x1

    .line 7
    const/4 v2, 0x3

    .line 8
    invoke-direct {v0, v1, v2}, Lc3/n;-><init>(II)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0, v0}, Lc3/q;->a(Lay0/k;)Z

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final a(Lay0/k;)Z
    .locals 13

    .line 1
    sget-object v0, Lc3/q;->b:Lc3/q;

    .line 2
    .line 3
    const-string v1, "\n    Please check whether the focusRequester is FocusRequester.Cancel or FocusRequester.Default\n    before invoking any functions on the focusRequester.\n"

    .line 4
    .line 5
    if-eq p0, v0, :cond_13

    .line 6
    .line 7
    sget-object v0, Lc3/q;->c:Lc3/q;

    .line 8
    .line 9
    if-eq p0, v0, :cond_12

    .line 10
    .line 11
    iget-object p0, p0, Lc3/q;->a:Ln2/b;

    .line 12
    .line 13
    iget v0, p0, Ln2/b;->f:I

    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    if-nez v0, :cond_0

    .line 17
    .line 18
    const-string p0, "FocusRelatedWarning: \n   FocusRequester is not initialized. Here are some possible fixes:\n\n   1. Remember the FocusRequester: val focusRequester = remember { FocusRequester() }\n   2. Did you forget to add a Modifier.focusRequester() ?\n   3. Are you attempting to request focus during composition? Focus requests should be made in\n   response to some event. Eg Modifier.clickable { focusRequester.requestFocus() }\n"

    .line 19
    .line 20
    sget-object p1, Ljava/lang/System;->out:Ljava/io/PrintStream;

    .line 21
    .line 22
    invoke-virtual {p1, p0}, Ljava/io/PrintStream;->println(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    return v1

    .line 26
    :cond_0
    iget-object p0, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 27
    .line 28
    move v2, v1

    .line 29
    move v3, v2

    .line 30
    :goto_0
    if-ge v2, v0, :cond_11

    .line 31
    .line 32
    aget-object v4, p0, v2

    .line 33
    .line 34
    check-cast v4, Lc3/r;

    .line 35
    .line 36
    check-cast v4, Lx2/r;

    .line 37
    .line 38
    iget-object v5, v4, Lx2/r;->d:Lx2/r;

    .line 39
    .line 40
    iget-boolean v5, v5, Lx2/r;->q:Z

    .line 41
    .line 42
    if-nez v5, :cond_1

    .line 43
    .line 44
    const-string v5, "visitChildren called on an unattached node"

    .line 45
    .line 46
    invoke-static {v5}, Ls3/a;->b(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    :cond_1
    new-instance v5, Ln2/b;

    .line 50
    .line 51
    const/16 v6, 0x10

    .line 52
    .line 53
    new-array v7, v6, [Lx2/r;

    .line 54
    .line 55
    invoke-direct {v5, v7}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    iget-object v4, v4, Lx2/r;->d:Lx2/r;

    .line 59
    .line 60
    iget-object v7, v4, Lx2/r;->i:Lx2/r;

    .line 61
    .line 62
    if-nez v7, :cond_2

    .line 63
    .line 64
    invoke-static {v5, v4}, Lv3/f;->b(Ln2/b;Lx2/r;)V

    .line 65
    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_2
    invoke-virtual {v5, v7}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    :cond_3
    :goto_1
    iget v4, v5, Ln2/b;->f:I

    .line 72
    .line 73
    if-eqz v4, :cond_10

    .line 74
    .line 75
    add-int/lit8 v4, v4, -0x1

    .line 76
    .line 77
    invoke-virtual {v5, v4}, Ln2/b;->m(I)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object v4

    .line 81
    check-cast v4, Lx2/r;

    .line 82
    .line 83
    iget v7, v4, Lx2/r;->g:I

    .line 84
    .line 85
    and-int/lit16 v7, v7, 0x400

    .line 86
    .line 87
    if-nez v7, :cond_4

    .line 88
    .line 89
    invoke-static {v5, v4}, Lv3/f;->b(Ln2/b;Lx2/r;)V

    .line 90
    .line 91
    .line 92
    goto :goto_1

    .line 93
    :cond_4
    :goto_2
    if-eqz v4, :cond_3

    .line 94
    .line 95
    iget v7, v4, Lx2/r;->f:I

    .line 96
    .line 97
    and-int/lit16 v7, v7, 0x400

    .line 98
    .line 99
    if-eqz v7, :cond_f

    .line 100
    .line 101
    const/4 v7, 0x0

    .line 102
    move-object v8, v7

    .line 103
    :goto_3
    if-eqz v4, :cond_3

    .line 104
    .line 105
    instance-of v9, v4, Lc3/v;

    .line 106
    .line 107
    const/4 v10, 0x1

    .line 108
    if-eqz v9, :cond_6

    .line 109
    .line 110
    check-cast v4, Lc3/v;

    .line 111
    .line 112
    invoke-virtual {v4}, Lc3/v;->Y0()Lc3/o;

    .line 113
    .line 114
    .line 115
    move-result-object v9

    .line 116
    iget-boolean v9, v9, Lc3/o;->a:Z

    .line 117
    .line 118
    if-eqz v9, :cond_5

    .line 119
    .line 120
    invoke-interface {p1, v4}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object v4

    .line 124
    check-cast v4, Ljava/lang/Boolean;

    .line 125
    .line 126
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 127
    .line 128
    .line 129
    move-result v4

    .line 130
    goto :goto_4

    .line 131
    :cond_5
    const/4 v9, 0x7

    .line 132
    invoke-static {v4, v9, p1}, Lc3/f;->i(Lc3/v;ILay0/k;)Z

    .line 133
    .line 134
    .line 135
    move-result v4

    .line 136
    :goto_4
    if-eqz v4, :cond_e

    .line 137
    .line 138
    move v3, v10

    .line 139
    goto :goto_9

    .line 140
    :cond_6
    iget v9, v4, Lx2/r;->f:I

    .line 141
    .line 142
    and-int/lit16 v9, v9, 0x400

    .line 143
    .line 144
    if-eqz v9, :cond_7

    .line 145
    .line 146
    move v9, v10

    .line 147
    goto :goto_5

    .line 148
    :cond_7
    move v9, v1

    .line 149
    :goto_5
    if-eqz v9, :cond_e

    .line 150
    .line 151
    instance-of v9, v4, Lv3/n;

    .line 152
    .line 153
    if-eqz v9, :cond_e

    .line 154
    .line 155
    move-object v9, v4

    .line 156
    check-cast v9, Lv3/n;

    .line 157
    .line 158
    iget-object v9, v9, Lv3/n;->s:Lx2/r;

    .line 159
    .line 160
    move v11, v1

    .line 161
    :goto_6
    if-eqz v9, :cond_d

    .line 162
    .line 163
    iget v12, v9, Lx2/r;->f:I

    .line 164
    .line 165
    and-int/lit16 v12, v12, 0x400

    .line 166
    .line 167
    if-eqz v12, :cond_8

    .line 168
    .line 169
    move v12, v10

    .line 170
    goto :goto_7

    .line 171
    :cond_8
    move v12, v1

    .line 172
    :goto_7
    if-eqz v12, :cond_c

    .line 173
    .line 174
    add-int/lit8 v11, v11, 0x1

    .line 175
    .line 176
    if-ne v11, v10, :cond_9

    .line 177
    .line 178
    move-object v4, v9

    .line 179
    goto :goto_8

    .line 180
    :cond_9
    if-nez v8, :cond_a

    .line 181
    .line 182
    new-instance v8, Ln2/b;

    .line 183
    .line 184
    new-array v12, v6, [Lx2/r;

    .line 185
    .line 186
    invoke-direct {v8, v12}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 187
    .line 188
    .line 189
    :cond_a
    if-eqz v4, :cond_b

    .line 190
    .line 191
    invoke-virtual {v8, v4}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 192
    .line 193
    .line 194
    move-object v4, v7

    .line 195
    :cond_b
    invoke-virtual {v8, v9}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 196
    .line 197
    .line 198
    :cond_c
    :goto_8
    iget-object v9, v9, Lx2/r;->i:Lx2/r;

    .line 199
    .line 200
    goto :goto_6

    .line 201
    :cond_d
    if-ne v11, v10, :cond_e

    .line 202
    .line 203
    goto :goto_3

    .line 204
    :cond_e
    invoke-static {v8}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 205
    .line 206
    .line 207
    move-result-object v4

    .line 208
    goto :goto_3

    .line 209
    :cond_f
    iget-object v4, v4, Lx2/r;->i:Lx2/r;

    .line 210
    .line 211
    goto :goto_2

    .line 212
    :cond_10
    :goto_9
    add-int/lit8 v2, v2, 0x1

    .line 213
    .line 214
    goto/16 :goto_0

    .line 215
    .line 216
    :cond_11
    return v3

    .line 217
    :cond_12
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 218
    .line 219
    invoke-direct {p0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 220
    .line 221
    .line 222
    throw p0

    .line 223
    :cond_13
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 224
    .line 225
    invoke-direct {p0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 226
    .line 227
    .line 228
    throw p0
.end method
