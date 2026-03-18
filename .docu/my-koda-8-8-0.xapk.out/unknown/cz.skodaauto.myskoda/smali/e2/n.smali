.class public final Le2/n;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:Lez0/c;

.field public e:Le2/o;

.field public f:Ljava/lang/CharSequence;

.field public g:J

.field public h:I

.field public synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/CharSequence;

.field public final synthetic k:J

.field public final synthetic l:Le2/o;


# direct methods
.method public constructor <init>(Ljava/lang/CharSequence;JLe2/o;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Le2/n;->j:Ljava/lang/CharSequence;

    .line 2
    .line 3
    iput-wide p2, p0, Le2/n;->k:J

    .line 4
    .line 5
    iput-object p4, p0, Le2/n;->l:Le2/o;

    .line 6
    .line 7
    const/4 p1, 0x2

    .line 8
    invoke-direct {p0, p1, p5}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 6

    .line 1
    new-instance v0, Le2/n;

    .line 2
    .line 3
    iget-wide v2, p0, Le2/n;->k:J

    .line 4
    .line 5
    iget-object v4, p0, Le2/n;->l:Le2/o;

    .line 6
    .line 7
    iget-object v1, p0, Le2/n;->j:Ljava/lang/CharSequence;

    .line 8
    .line 9
    move-object v5, p2

    .line 10
    invoke-direct/range {v0 .. v5}, Le2/n;-><init>(Ljava/lang/CharSequence;JLe2/o;Lkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    iput-object p1, v0, Le2/n;->i:Ljava/lang/Object;

    .line 14
    .line 15
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Landroid/view/textclassifier/TextClassifier;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Le2/n;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Le2/n;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Le2/n;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Le2/n;->h:I

    .line 4
    .line 5
    const/4 v2, 0x2

    .line 6
    const/4 v3, 0x1

    .line 7
    if-eqz v1, :cond_2

    .line 8
    .line 9
    if-eq v1, v3, :cond_1

    .line 10
    .line 11
    if-ne v1, v2, :cond_0

    .line 12
    .line 13
    iget-wide v0, p0, Le2/n;->g:J

    .line 14
    .line 15
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    goto/16 :goto_2

    .line 19
    .line 20
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 21
    .line 22
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 23
    .line 24
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    throw p0

    .line 28
    :cond_1
    iget-wide v0, p0, Le2/n;->g:J

    .line 29
    .line 30
    iget-object v2, p0, Le2/n;->f:Ljava/lang/CharSequence;

    .line 31
    .line 32
    check-cast v2, Ljava/lang/CharSequence;

    .line 33
    .line 34
    iget-object v3, p0, Le2/n;->e:Le2/o;

    .line 35
    .line 36
    iget-object v4, p0, Le2/n;->d:Lez0/c;

    .line 37
    .line 38
    iget-object p0, p0, Le2/n;->i:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast p0, Landroid/view/textclassifier/TextSelection;

    .line 41
    .line 42
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    iget-object p1, p0, Le2/n;->i:Ljava/lang/Object;

    .line 50
    .line 51
    move-object v8, p1

    .line 52
    check-cast v8, Landroid/view/textclassifier/TextClassifier;

    .line 53
    .line 54
    new-instance p1, Landroid/view/textclassifier/TextSelection$Request$Builder;

    .line 55
    .line 56
    iget-wide v4, p0, Le2/n;->k:J

    .line 57
    .line 58
    invoke-static {v4, v5}, Lg4/o0;->f(J)I

    .line 59
    .line 60
    .line 61
    move-result v1

    .line 62
    invoke-static {v4, v5}, Lg4/o0;->e(J)I

    .line 63
    .line 64
    .line 65
    move-result v4

    .line 66
    iget-object v5, p0, Le2/n;->j:Ljava/lang/CharSequence;

    .line 67
    .line 68
    invoke-direct {p1, v5, v1, v4}, Landroid/view/textclassifier/TextSelection$Request$Builder;-><init>(Ljava/lang/CharSequence;II)V

    .line 69
    .line 70
    .line 71
    iget-object v1, p0, Le2/n;->l:Le2/o;

    .line 72
    .line 73
    invoke-virtual {v1}, Le2/o;->b()Landroid/os/LocaleList;

    .line 74
    .line 75
    .line 76
    move-result-object v4

    .line 77
    invoke-virtual {p1, v4}, Landroid/view/textclassifier/TextSelection$Request$Builder;->setDefaultLocales(Landroid/os/LocaleList;)Landroid/view/textclassifier/TextSelection$Request$Builder;

    .line 78
    .line 79
    .line 80
    move-result-object p1

    .line 81
    sget v4, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 82
    .line 83
    const/16 v6, 0x1f

    .line 84
    .line 85
    if-lt v4, v6, :cond_3

    .line 86
    .line 87
    invoke-static {p1}, Lc4/a;->z(Landroid/view/textclassifier/TextSelection$Request$Builder;)V

    .line 88
    .line 89
    .line 90
    :cond_3
    invoke-virtual {p1}, Landroid/view/textclassifier/TextSelection$Request$Builder;->build()Landroid/view/textclassifier/TextSelection$Request;

    .line 91
    .line 92
    .line 93
    move-result-object p1

    .line 94
    invoke-interface {v8, p1}, Landroid/view/textclassifier/TextClassifier;->suggestSelection(Landroid/view/textclassifier/TextSelection$Request;)Landroid/view/textclassifier/TextSelection;

    .line 95
    .line 96
    .line 97
    move-result-object p1

    .line 98
    invoke-virtual {p1}, Landroid/view/textclassifier/TextSelection;->getSelectionStartIndex()I

    .line 99
    .line 100
    .line 101
    move-result v7

    .line 102
    invoke-virtual {p1}, Landroid/view/textclassifier/TextSelection;->getSelectionEndIndex()I

    .line 103
    .line 104
    .line 105
    move-result v9

    .line 106
    invoke-static {v7, v9}, Lg4/f0;->b(II)J

    .line 107
    .line 108
    .line 109
    move-result-wide v9

    .line 110
    if-lt v4, v6, :cond_5

    .line 111
    .line 112
    invoke-static {p1}, Lc4/a;->q(Landroid/view/textclassifier/TextSelection;)Landroid/view/textclassifier/TextClassification;

    .line 113
    .line 114
    .line 115
    move-result-object v4

    .line 116
    if-eqz v4, :cond_5

    .line 117
    .line 118
    iget-object v4, v1, Le2/o;->e:Lez0/c;

    .line 119
    .line 120
    iput-object p1, p0, Le2/n;->i:Ljava/lang/Object;

    .line 121
    .line 122
    iput-object v4, p0, Le2/n;->d:Lez0/c;

    .line 123
    .line 124
    iput-object v1, p0, Le2/n;->e:Le2/o;

    .line 125
    .line 126
    move-object v2, v5

    .line 127
    check-cast v2, Ljava/lang/CharSequence;

    .line 128
    .line 129
    iput-object v2, p0, Le2/n;->f:Ljava/lang/CharSequence;

    .line 130
    .line 131
    iput-wide v9, p0, Le2/n;->g:J

    .line 132
    .line 133
    iput v3, p0, Le2/n;->h:I

    .line 134
    .line 135
    invoke-virtual {v4, p0}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object p0

    .line 139
    if-ne p0, v0, :cond_4

    .line 140
    .line 141
    goto :goto_1

    .line 142
    :cond_4
    move-object p0, p1

    .line 143
    move-object v3, v1

    .line 144
    move-object v2, v5

    .line 145
    move-wide v0, v9

    .line 146
    :goto_0
    const/4 p1, 0x0

    .line 147
    :try_start_0
    new-instance v5, Le2/l0;

    .line 148
    .line 149
    invoke-static {p0}, Lc4/a;->q(Landroid/view/textclassifier/TextSelection;)Landroid/view/textclassifier/TextClassification;

    .line 150
    .line 151
    .line 152
    move-result-object p0

    .line 153
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 154
    .line 155
    .line 156
    invoke-direct {v5, v2, v0, v1, p0}, Le2/l0;-><init>(Ljava/lang/CharSequence;JLandroid/view/textclassifier/TextClassification;)V

    .line 157
    .line 158
    .line 159
    iget-object p0, v3, Le2/o;->g:Ll2/j1;

    .line 160
    .line 161
    invoke-virtual {p0, v5}, Ll2/j1;->setValue(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 162
    .line 163
    .line 164
    invoke-interface {v4, p1}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 165
    .line 166
    .line 167
    goto :goto_2

    .line 168
    :catchall_0
    move-exception v0

    .line 169
    move-object p0, v0

    .line 170
    invoke-interface {v4, p1}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 171
    .line 172
    .line 173
    throw p0

    .line 174
    :cond_5
    iput-wide v9, p0, Le2/n;->g:J

    .line 175
    .line 176
    iput v2, p0, Le2/n;->h:I

    .line 177
    .line 178
    iget-object v4, p0, Le2/n;->l:Le2/o;

    .line 179
    .line 180
    iget-object v5, p0, Le2/n;->j:Ljava/lang/CharSequence;

    .line 181
    .line 182
    move-wide v6, v9

    .line 183
    move-object v9, p0

    .line 184
    invoke-static/range {v4 .. v9}, Le2/o;->a(Le2/o;Ljava/lang/CharSequence;JLandroid/view/textclassifier/TextClassifier;Lrx0/c;)Ljava/lang/Object;

    .line 185
    .line 186
    .line 187
    move-result-object p0

    .line 188
    if-ne p0, v0, :cond_6

    .line 189
    .line 190
    :goto_1
    return-object v0

    .line 191
    :cond_6
    move-wide v0, v6

    .line 192
    :goto_2
    new-instance p0, Lg4/o0;

    .line 193
    .line 194
    invoke-direct {p0, v0, v1}, Lg4/o0;-><init>(J)V

    .line 195
    .line 196
    .line 197
    return-object p0
.end method
