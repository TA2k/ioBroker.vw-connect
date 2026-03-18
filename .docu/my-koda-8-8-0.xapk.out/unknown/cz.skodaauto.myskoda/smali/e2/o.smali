.class public final Le2/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lpx0/g;

.field public final b:Landroid/content/Context;

.field public final c:Le2/q;

.field public final d:Ln4/b;

.field public final e:Lez0/c;

.field public f:Landroid/view/textclassifier/TextClassifier;

.field public final g:Ll2/j1;

.field public final h:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lpx0/g;Landroid/content/Context;Le2/q;Ln4/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Le2/o;->a:Lpx0/g;

    .line 5
    .line 6
    iput-object p2, p0, Le2/o;->b:Landroid/content/Context;

    .line 7
    .line 8
    iput-object p3, p0, Le2/o;->c:Le2/q;

    .line 9
    .line 10
    iput-object p4, p0, Le2/o;->d:Ln4/b;

    .line 11
    .line 12
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    iput-object p1, p0, Le2/o;->e:Lez0/c;

    .line 17
    .line 18
    const/4 p1, 0x0

    .line 19
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    iput-object p1, p0, Le2/o;->g:Ll2/j1;

    .line 24
    .line 25
    new-instance p1, Ljava/lang/Object;

    .line 26
    .line 27
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 28
    .line 29
    .line 30
    iput-object p1, p0, Le2/o;->h:Ljava/lang/Object;

    .line 31
    .line 32
    return-void
.end method

.method public static final a(Le2/o;Ljava/lang/CharSequence;JLandroid/view/textclassifier/TextClassifier;Lrx0/c;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p5

    .line 4
    .line 5
    iget-object v2, v0, Le2/o;->e:Lez0/c;

    .line 6
    .line 7
    iget-object v3, v0, Le2/o;->g:Ll2/j1;

    .line 8
    .line 9
    instance-of v4, v1, Le2/m;

    .line 10
    .line 11
    if-eqz v4, :cond_0

    .line 12
    .line 13
    move-object v4, v1

    .line 14
    check-cast v4, Le2/m;

    .line 15
    .line 16
    iget v5, v4, Le2/m;->j:I

    .line 17
    .line 18
    const/high16 v6, -0x80000000

    .line 19
    .line 20
    and-int v7, v5, v6

    .line 21
    .line 22
    if-eqz v7, :cond_0

    .line 23
    .line 24
    sub-int/2addr v5, v6

    .line 25
    iput v5, v4, Le2/m;->j:I

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    new-instance v4, Le2/m;

    .line 29
    .line 30
    invoke-direct {v4, v0, v1}, Le2/m;-><init>(Le2/o;Lrx0/c;)V

    .line 31
    .line 32
    .line 33
    :goto_0
    iget-object v1, v4, Le2/m;->h:Ljava/lang/Object;

    .line 34
    .line 35
    sget-object v5, Lqx0/a;->d:Lqx0/a;

    .line 36
    .line 37
    iget v6, v4, Le2/m;->j:I

    .line 38
    .line 39
    sget-object v7, Llx0/b0;->a:Llx0/b0;

    .line 40
    .line 41
    const/4 v8, 0x2

    .line 42
    const/4 v9, 0x1

    .line 43
    const/4 v10, 0x0

    .line 44
    if-eqz v6, :cond_3

    .line 45
    .line 46
    if-eq v6, v9, :cond_2

    .line 47
    .line 48
    if-ne v6, v8, :cond_1

    .line 49
    .line 50
    iget-wide v5, v4, Le2/m;->g:J

    .line 51
    .line 52
    iget-object v2, v4, Le2/m;->f:Lez0/c;

    .line 53
    .line 54
    iget-object v0, v4, Le2/m;->e:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast v0, Landroid/view/textclassifier/TextClassification;

    .line 57
    .line 58
    iget-object v4, v4, Le2/m;->d:Ljava/lang/CharSequence;

    .line 59
    .line 60
    check-cast v4, Ljava/lang/CharSequence;

    .line 61
    .line 62
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    goto/16 :goto_5

    .line 66
    .line 67
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 68
    .line 69
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 70
    .line 71
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    throw v0

    .line 75
    :cond_2
    iget-wide v11, v4, Le2/m;->g:J

    .line 76
    .line 77
    iget-object v6, v4, Le2/m;->f:Lez0/c;

    .line 78
    .line 79
    iget-object v13, v4, Le2/m;->e:Ljava/lang/Object;

    .line 80
    .line 81
    check-cast v13, Landroid/view/textclassifier/TextClassifier;

    .line 82
    .line 83
    iget-object v14, v4, Le2/m;->d:Ljava/lang/CharSequence;

    .line 84
    .line 85
    check-cast v14, Ljava/lang/CharSequence;

    .line 86
    .line 87
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 88
    .line 89
    .line 90
    goto :goto_1

    .line 91
    :cond_3
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 92
    .line 93
    .line 94
    move-object/from16 v1, p1

    .line 95
    .line 96
    check-cast v1, Ljava/lang/CharSequence;

    .line 97
    .line 98
    iput-object v1, v4, Le2/m;->d:Ljava/lang/CharSequence;

    .line 99
    .line 100
    move-object/from16 v1, p4

    .line 101
    .line 102
    iput-object v1, v4, Le2/m;->e:Ljava/lang/Object;

    .line 103
    .line 104
    iput-object v2, v4, Le2/m;->f:Lez0/c;

    .line 105
    .line 106
    move-wide/from16 v11, p2

    .line 107
    .line 108
    iput-wide v11, v4, Le2/m;->g:J

    .line 109
    .line 110
    iput v9, v4, Le2/m;->j:I

    .line 111
    .line 112
    invoke-virtual {v2, v4}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object v6

    .line 116
    if-ne v6, v5, :cond_4

    .line 117
    .line 118
    goto :goto_4

    .line 119
    :cond_4
    move-object/from16 v14, p1

    .line 120
    .line 121
    move-object v13, v1

    .line 122
    move-object v6, v2

    .line 123
    :goto_1
    :try_start_0
    invoke-virtual {v3}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object v1

    .line 127
    check-cast v1, Le2/l0;

    .line 128
    .line 129
    if-eqz v1, :cond_6

    .line 130
    .line 131
    sget-object v15, Le2/p;->a:Ll2/u2;

    .line 132
    .line 133
    iget-wide v8, v1, Le2/l0;->b:J

    .line 134
    .line 135
    invoke-static {v11, v12, v8, v9}, Lg4/o0;->b(JJ)Z

    .line 136
    .line 137
    .line 138
    move-result v8

    .line 139
    if-eqz v8, :cond_5

    .line 140
    .line 141
    iget-object v1, v1, Le2/l0;->a:Ljava/lang/CharSequence;

    .line 142
    .line 143
    invoke-static {v14, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 144
    .line 145
    .line 146
    move-result v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 147
    if-eqz v1, :cond_5

    .line 148
    .line 149
    const/4 v1, 0x1

    .line 150
    :goto_2
    const/4 v15, 0x1

    .line 151
    goto :goto_3

    .line 152
    :catchall_0
    move-exception v0

    .line 153
    goto :goto_6

    .line 154
    :cond_5
    const/4 v1, 0x0

    .line 155
    goto :goto_2

    .line 156
    :goto_3
    if-ne v1, v15, :cond_6

    .line 157
    .line 158
    invoke-interface {v6, v10}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 159
    .line 160
    .line 161
    return-object v7

    .line 162
    :cond_6
    invoke-interface {v6, v10}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 163
    .line 164
    .line 165
    new-instance v1, Landroid/view/textclassifier/TextClassification$Request$Builder;

    .line 166
    .line 167
    invoke-static {v11, v12}, Lg4/o0;->f(J)I

    .line 168
    .line 169
    .line 170
    move-result v6

    .line 171
    invoke-static {v11, v12}, Lg4/o0;->e(J)I

    .line 172
    .line 173
    .line 174
    move-result v8

    .line 175
    invoke-direct {v1, v14, v6, v8}, Landroid/view/textclassifier/TextClassification$Request$Builder;-><init>(Ljava/lang/CharSequence;II)V

    .line 176
    .line 177
    .line 178
    invoke-virtual {v0}, Le2/o;->b()Landroid/os/LocaleList;

    .line 179
    .line 180
    .line 181
    move-result-object v0

    .line 182
    invoke-virtual {v1, v0}, Landroid/view/textclassifier/TextClassification$Request$Builder;->setDefaultLocales(Landroid/os/LocaleList;)Landroid/view/textclassifier/TextClassification$Request$Builder;

    .line 183
    .line 184
    .line 185
    move-result-object v0

    .line 186
    invoke-virtual {v0}, Landroid/view/textclassifier/TextClassification$Request$Builder;->build()Landroid/view/textclassifier/TextClassification$Request;

    .line 187
    .line 188
    .line 189
    move-result-object v0

    .line 190
    invoke-interface {v13, v0}, Landroid/view/textclassifier/TextClassifier;->classifyText(Landroid/view/textclassifier/TextClassification$Request;)Landroid/view/textclassifier/TextClassification;

    .line 191
    .line 192
    .line 193
    move-result-object v0

    .line 194
    move-object v1, v14

    .line 195
    check-cast v1, Ljava/lang/CharSequence;

    .line 196
    .line 197
    iput-object v1, v4, Le2/m;->d:Ljava/lang/CharSequence;

    .line 198
    .line 199
    iput-object v0, v4, Le2/m;->e:Ljava/lang/Object;

    .line 200
    .line 201
    iput-object v2, v4, Le2/m;->f:Lez0/c;

    .line 202
    .line 203
    iput-wide v11, v4, Le2/m;->g:J

    .line 204
    .line 205
    const/4 v1, 0x2

    .line 206
    iput v1, v4, Le2/m;->j:I

    .line 207
    .line 208
    invoke-virtual {v2, v4}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 209
    .line 210
    .line 211
    move-result-object v1

    .line 212
    if-ne v1, v5, :cond_7

    .line 213
    .line 214
    :goto_4
    return-object v5

    .line 215
    :cond_7
    move-wide v5, v11

    .line 216
    move-object v4, v14

    .line 217
    :goto_5
    :try_start_1
    new-instance v1, Le2/l0;

    .line 218
    .line 219
    invoke-direct {v1, v4, v5, v6, v0}, Le2/l0;-><init>(Ljava/lang/CharSequence;JLandroid/view/textclassifier/TextClassification;)V

    .line 220
    .line 221
    .line 222
    invoke-virtual {v3, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 223
    .line 224
    .line 225
    invoke-interface {v2, v10}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 226
    .line 227
    .line 228
    return-object v7

    .line 229
    :catchall_1
    move-exception v0

    .line 230
    invoke-interface {v2, v10}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 231
    .line 232
    .line 233
    throw v0

    .line 234
    :goto_6
    invoke-interface {v6, v10}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 235
    .line 236
    .line 237
    throw v0
.end method


# virtual methods
.method public final b()Landroid/os/LocaleList;
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object p0, p0, Le2/o;->d:Ln4/b;

    .line 3
    .line 4
    if-eqz p0, :cond_1

    .line 5
    .line 6
    new-instance v1, Ljava/util/ArrayList;

    .line 7
    .line 8
    const/16 v2, 0xa

    .line 9
    .line 10
    invoke-static {p0, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 15
    .line 16
    .line 17
    iget-object p0, p0, Ln4/b;->d:Ljava/util/List;

    .line 18
    .line 19
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    if-eqz v2, :cond_0

    .line 28
    .line 29
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    check-cast v2, Ln4/a;

    .line 34
    .line 35
    iget-object v2, v2, Ln4/a;->a:Ljava/util/Locale;

    .line 36
    .line 37
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_0
    new-array p0, v0, [Ljava/util/Locale;

    .line 42
    .line 43
    invoke-virtual {v1, p0}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    check-cast p0, [Ljava/util/Locale;

    .line 48
    .line 49
    array-length v0, p0

    .line 50
    invoke-static {p0, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    check-cast p0, [Ljava/util/Locale;

    .line 55
    .line 56
    new-instance v0, Landroid/os/LocaleList;

    .line 57
    .line 58
    invoke-direct {v0, p0}, Landroid/os/LocaleList;-><init>([Ljava/util/Locale;)V

    .line 59
    .line 60
    .line 61
    return-object v0

    .line 62
    :cond_1
    new-instance p0, Landroid/os/LocaleList;

    .line 63
    .line 64
    sget-object v1, Ln4/c;->a:Lil/g;

    .line 65
    .line 66
    invoke-virtual {v1}, Lil/g;->z()Ln4/b;

    .line 67
    .line 68
    .line 69
    move-result-object v1

    .line 70
    iget-object v1, v1, Ln4/b;->d:Ljava/util/List;

    .line 71
    .line 72
    invoke-interface {v1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    check-cast v0, Ln4/a;

    .line 77
    .line 78
    iget-object v0, v0, Ln4/a;->a:Ljava/util/Locale;

    .line 79
    .line 80
    filled-new-array {v0}, [Ljava/util/Locale;

    .line 81
    .line 82
    .line 83
    move-result-object v0

    .line 84
    invoke-direct {p0, v0}, Landroid/os/LocaleList;-><init>([Ljava/util/Locale;)V

    .line 85
    .line 86
    .line 87
    return-object p0
.end method
