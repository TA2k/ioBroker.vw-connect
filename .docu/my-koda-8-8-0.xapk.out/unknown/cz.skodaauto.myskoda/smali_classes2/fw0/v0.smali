.class public final Lfw0/v0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public d:I

.field public e:I

.field public synthetic f:Lyw0/e;

.field public synthetic g:Ljava/lang/Object;

.field public final synthetic h:Lfw0/w0;

.field public final synthetic i:Lzv0/c;


# direct methods
.method public constructor <init>(Lfw0/w0;Lzv0/c;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lfw0/v0;->h:Lfw0/w0;

    .line 2
    .line 3
    iput-object p2, p0, Lfw0/v0;->i:Lzv0/c;

    .line 4
    .line 5
    const/4 p1, 0x3

    .line 6
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    check-cast p1, Lyw0/e;

    .line 2
    .line 3
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    new-instance v0, Lfw0/v0;

    .line 6
    .line 7
    iget-object v1, p0, Lfw0/v0;->h:Lfw0/w0;

    .line 8
    .line 9
    iget-object p0, p0, Lfw0/v0;->i:Lzv0/c;

    .line 10
    .line 11
    invoke-direct {v0, v1, p0, p3}, Lfw0/v0;-><init>(Lfw0/w0;Lzv0/c;Lkotlin/coroutines/Continuation;)V

    .line 12
    .line 13
    .line 14
    iput-object p1, v0, Lfw0/v0;->f:Lyw0/e;

    .line 15
    .line 16
    iput-object p2, v0, Lfw0/v0;->g:Ljava/lang/Object;

    .line 17
    .line 18
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 19
    .line 20
    invoke-virtual {v0, p0}, Lfw0/v0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget-object v0, p0, Lfw0/v0;->f:Lyw0/e;

    .line 2
    .line 3
    iget-object v1, p0, Lfw0/v0;->g:Ljava/lang/Object;

    .line 4
    .line 5
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 6
    .line 7
    iget v3, p0, Lfw0/v0;->e:I

    .line 8
    .line 9
    const/4 v4, 0x2

    .line 10
    const/4 v5, 0x1

    .line 11
    const/4 v6, 0x0

    .line 12
    if-eqz v3, :cond_2

    .line 13
    .line 14
    if-eq v3, v5, :cond_1

    .line 15
    .line 16
    if-ne v3, v4, :cond_0

    .line 17
    .line 18
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    goto/16 :goto_4

    .line 22
    .line 23
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 24
    .line 25
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 26
    .line 27
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    throw p0

    .line 31
    :cond_1
    iget v1, p0, Lfw0/v0;->d:I

    .line 32
    .line 33
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    goto :goto_2

    .line 37
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    instance-of p1, v1, Lrw0/d;

    .line 41
    .line 42
    if-eqz p1, :cond_7

    .line 43
    .line 44
    iget-object p1, v0, Lyw0/e;->d:Ljava/lang/Object;

    .line 45
    .line 46
    move-object v3, p1

    .line 47
    check-cast v3, Lkw0/c;

    .line 48
    .line 49
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 50
    .line 51
    .line 52
    iput-object v1, v3, Lkw0/c;->d:Ljava/lang/Object;

    .line 53
    .line 54
    invoke-virtual {v3, v6}, Lkw0/c;->a(Lzw0/a;)V

    .line 55
    .line 56
    .line 57
    check-cast p1, Lkw0/c;

    .line 58
    .line 59
    iget-object v1, p1, Lkw0/c;->f:Lvw0/d;

    .line 60
    .line 61
    sget-object v3, Lfw0/n0;->c:Lvw0/a;

    .line 62
    .line 63
    invoke-virtual {v1, v3}, Lvw0/d;->d(Lvw0/a;)Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    check-cast v1, Ljava/lang/Integer;

    .line 68
    .line 69
    iget-object v3, p0, Lfw0/v0;->h:Lfw0/w0;

    .line 70
    .line 71
    if-eqz v1, :cond_3

    .line 72
    .line 73
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 74
    .line 75
    .line 76
    move-result v1

    .line 77
    add-int/2addr v1, v5

    .line 78
    goto :goto_0

    .line 79
    :cond_3
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 80
    .line 81
    .line 82
    const/16 v1, 0x14

    .line 83
    .line 84
    :goto_0
    new-instance v7, Lfw0/t0;

    .line 85
    .line 86
    iget-object v8, p0, Lfw0/v0;->i:Lzv0/c;

    .line 87
    .line 88
    invoke-direct {v7, v1, v8}, Lfw0/t0;-><init>(ILzv0/c;)V

    .line 89
    .line 90
    .line 91
    iget-object v3, v3, Lfw0/w0;->a:Ljava/util/ArrayList;

    .line 92
    .line 93
    invoke-static {v3}, Lmx0/q;->g0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 94
    .line 95
    .line 96
    move-result-object v3

    .line 97
    invoke-interface {v3}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 98
    .line 99
    .line 100
    move-result-object v3

    .line 101
    :goto_1
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 102
    .line 103
    .line 104
    move-result v8

    .line 105
    if-eqz v8, :cond_4

    .line 106
    .line 107
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object v8

    .line 111
    check-cast v8, Lay0/o;

    .line 112
    .line 113
    new-instance v9, Lfw0/u0;

    .line 114
    .line 115
    invoke-direct {v9, v8, v7}, Lfw0/u0;-><init>(Lay0/o;Lfw0/e1;)V

    .line 116
    .line 117
    .line 118
    move-object v7, v9

    .line 119
    goto :goto_1

    .line 120
    :cond_4
    iput-object v0, p0, Lfw0/v0;->f:Lyw0/e;

    .line 121
    .line 122
    iput-object v6, p0, Lfw0/v0;->g:Ljava/lang/Object;

    .line 123
    .line 124
    iput v1, p0, Lfw0/v0;->d:I

    .line 125
    .line 126
    iput v5, p0, Lfw0/v0;->e:I

    .line 127
    .line 128
    invoke-interface {v7, p1, p0}, Lfw0/e1;->a(Lkw0/c;Lrx0/c;)Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object p1

    .line 132
    if-ne p1, v2, :cond_5

    .line 133
    .line 134
    goto :goto_3

    .line 135
    :cond_5
    :goto_2
    check-cast p1, Law0/c;

    .line 136
    .line 137
    iput-object v6, p0, Lfw0/v0;->f:Lyw0/e;

    .line 138
    .line 139
    iput-object v6, p0, Lfw0/v0;->g:Ljava/lang/Object;

    .line 140
    .line 141
    iput v1, p0, Lfw0/v0;->d:I

    .line 142
    .line 143
    iput v4, p0, Lfw0/v0;->e:I

    .line 144
    .line 145
    invoke-virtual {v0, p1, p0}, Lyw0/e;->d(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object p0

    .line 149
    if-ne p0, v2, :cond_6

    .line 150
    .line 151
    :goto_3
    return-object v2

    .line 152
    :cond_6
    :goto_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 153
    .line 154
    return-object p0

    .line 155
    :cond_7
    new-instance p0, Ljava/lang/StringBuilder;

    .line 156
    .line 157
    const-string p1, "\n|Fail to prepare request body for sending. \n|The body type is: "

    .line 158
    .line 159
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 160
    .line 161
    .line 162
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 163
    .line 164
    .line 165
    move-result-object p1

    .line 166
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 167
    .line 168
    invoke-virtual {v1, p1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 169
    .line 170
    .line 171
    move-result-object p1

    .line 172
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 173
    .line 174
    .line 175
    const-string p1, ", with Content-Type: "

    .line 176
    .line 177
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 178
    .line 179
    .line 180
    iget-object p1, v0, Lyw0/e;->d:Ljava/lang/Object;

    .line 181
    .line 182
    check-cast p1, Lkw0/c;

    .line 183
    .line 184
    invoke-static {p1}, Ljp/pc;->c(Lkw0/c;)Low0/e;

    .line 185
    .line 186
    .line 187
    move-result-object p1

    .line 188
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 189
    .line 190
    .line 191
    const-string p1, ".\n|\n|If you expect serialized body, please check that you have installed the corresponding plugin(like `ContentNegotiation`) and set `Content-Type` header."

    .line 192
    .line 193
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 194
    .line 195
    .line 196
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 197
    .line 198
    .line 199
    move-result-object p0

    .line 200
    invoke-static {p0}, Lly0/q;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 201
    .line 202
    .line 203
    move-result-object p0

    .line 204
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 205
    .line 206
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 207
    .line 208
    .line 209
    move-result-object p0

    .line 210
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 211
    .line 212
    .line 213
    throw p1
.end method
