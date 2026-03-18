.class public final Lhw0/e;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/q;


# instance fields
.field public d:I

.field public synthetic e:Law0/h;

.field public synthetic f:Lio/ktor/utils/io/t;

.field public synthetic g:Lzw0/a;

.field public final synthetic h:Ljava/util/Set;

.field public final synthetic i:Ljava/util/List;

.field public final synthetic j:Lgw0/b;


# direct methods
.method public constructor <init>(Lgw0/b;Ljava/util/List;Ljava/util/Set;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p3, p0, Lhw0/e;->h:Ljava/util/Set;

    .line 2
    .line 3
    iput-object p2, p0, Lhw0/e;->i:Ljava/util/List;

    .line 4
    .line 5
    iput-object p1, p0, Lhw0/e;->j:Lgw0/b;

    .line 6
    .line 7
    const/4 p1, 0x5

    .line 8
    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    check-cast p1, Lgw0/j;

    .line 2
    .line 3
    check-cast p2, Law0/h;

    .line 4
    .line 5
    check-cast p3, Lio/ktor/utils/io/t;

    .line 6
    .line 7
    check-cast p4, Lzw0/a;

    .line 8
    .line 9
    check-cast p5, Lkotlin/coroutines/Continuation;

    .line 10
    .line 11
    new-instance p1, Lhw0/e;

    .line 12
    .line 13
    iget-object v0, p0, Lhw0/e;->i:Ljava/util/List;

    .line 14
    .line 15
    iget-object v1, p0, Lhw0/e;->j:Lgw0/b;

    .line 16
    .line 17
    iget-object p0, p0, Lhw0/e;->h:Ljava/util/Set;

    .line 18
    .line 19
    invoke-direct {p1, v1, v0, p0, p5}, Lhw0/e;-><init>(Lgw0/b;Ljava/util/List;Ljava/util/Set;Lkotlin/coroutines/Continuation;)V

    .line 20
    .line 21
    .line 22
    iput-object p2, p1, Lhw0/e;->e:Law0/h;

    .line 23
    .line 24
    iput-object p3, p1, Lhw0/e;->f:Lio/ktor/utils/io/t;

    .line 25
    .line 26
    iput-object p4, p1, Lhw0/e;->g:Lzw0/a;

    .line 27
    .line 28
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    invoke-virtual {p1, p0}, Lhw0/e;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget-object v0, p0, Lhw0/e;->e:Law0/h;

    .line 2
    .line 3
    iget-object v5, p0, Lhw0/e;->f:Lio/ktor/utils/io/t;

    .line 4
    .line 5
    iget-object v4, p0, Lhw0/e;->g:Lzw0/a;

    .line 6
    .line 7
    sget-object v9, Lqx0/a;->d:Lqx0/a;

    .line 8
    .line 9
    iget v1, p0, Lhw0/e;->d:I

    .line 10
    .line 11
    const/4 v2, 0x1

    .line 12
    if-eqz v1, :cond_1

    .line 13
    .line 14
    if-ne v1, v2, :cond_0

    .line 15
    .line 16
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    return-object p1

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    const-string p1, "<this>"

    .line 32
    .line 33
    invoke-static {v0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    invoke-interface {v0}, Low0/r;->a()Low0/m;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    sget-object v3, Low0/q;->a:Ljava/util/List;

    .line 41
    .line 42
    const-string v3, "Content-Type"

    .line 43
    .line 44
    invoke-interface {v1, v3}, Lvw0/j;->get(Ljava/lang/String;)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    const/4 v3, 0x0

    .line 49
    if-eqz v1, :cond_2

    .line 50
    .line 51
    sget-object v6, Low0/e;->f:Low0/e;

    .line 52
    .line 53
    invoke-static {v1}, Ljp/hc;->b(Ljava/lang/String;)Low0/e;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    move-object v6, v1

    .line 58
    goto :goto_0

    .line 59
    :cond_2
    move-object v6, v3

    .line 60
    :goto_0
    if-nez v6, :cond_3

    .line 61
    .line 62
    return-object v3

    .line 63
    :cond_3
    invoke-static {v0}, Lo5/c;->c(Law0/h;)Lkw0/b;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    invoke-interface {v1}, Low0/r;->a()Low0/m;

    .line 68
    .line 69
    .line 70
    move-result-object v1

    .line 71
    sget-object v7, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 72
    .line 73
    invoke-static {v1, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    const-string p1, "defaultCharset"

    .line 77
    .line 78
    invoke-static {v7, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    const-string p1, "Accept-Charset"

    .line 82
    .line 83
    invoke-interface {v1, p1}, Lvw0/j;->get(Ljava/lang/String;)Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object p1

    .line 87
    invoke-static {p1}, Ljp/jc;->b(Ljava/lang/String;)Ljava/util/List;

    .line 88
    .line 89
    .line 90
    move-result-object p1

    .line 91
    check-cast p1, Ljava/lang/Iterable;

    .line 92
    .line 93
    new-instance v1, Low0/p;

    .line 94
    .line 95
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 96
    .line 97
    .line 98
    invoke-static {p1, v1}, Lmx0/q;->p0(Ljava/lang/Iterable;Ljava/util/Comparator;)Ljava/util/List;

    .line 99
    .line 100
    .line 101
    move-result-object p1

    .line 102
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 103
    .line 104
    .line 105
    move-result-object p1

    .line 106
    :cond_4
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 107
    .line 108
    .line 109
    move-result v1

    .line 110
    if-eqz v1, :cond_6

    .line 111
    .line 112
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object v1

    .line 116
    check-cast v1, Low0/i;

    .line 117
    .line 118
    iget-object v1, v1, Low0/i;->a:Ljava/lang/String;

    .line 119
    .line 120
    const-string v8, "*"

    .line 121
    .line 122
    invoke-static {v1, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 123
    .line 124
    .line 125
    move-result v8

    .line 126
    if-eqz v8, :cond_5

    .line 127
    .line 128
    move-object p1, v7

    .line 129
    goto :goto_1

    .line 130
    :cond_5
    sget-object v8, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 131
    .line 132
    const-string v8, "name"

    .line 133
    .line 134
    invoke-static {v1, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 135
    .line 136
    .line 137
    invoke-static {v1}, Ljava/nio/charset/Charset;->isSupported(Ljava/lang/String;)Z

    .line 138
    .line 139
    .line 140
    move-result v8

    .line 141
    if-eqz v8, :cond_4

    .line 142
    .line 143
    invoke-static {v1}, Ljava/nio/charset/Charset;->forName(Ljava/lang/String;)Ljava/nio/charset/Charset;

    .line 144
    .line 145
    .line 146
    move-result-object p1

    .line 147
    const-string v1, "forName(...)"

    .line 148
    .line 149
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 150
    .line 151
    .line 152
    goto :goto_1

    .line 153
    :cond_6
    move-object p1, v3

    .line 154
    :goto_1
    if-nez p1, :cond_7

    .line 155
    .line 156
    goto :goto_2

    .line 157
    :cond_7
    move-object v7, p1

    .line 158
    :goto_2
    invoke-static {v0}, Lo5/c;->c(Law0/h;)Lkw0/b;

    .line 159
    .line 160
    .line 161
    move-result-object p1

    .line 162
    invoke-interface {p1}, Lkw0/b;->getUrl()Low0/f0;

    .line 163
    .line 164
    .line 165
    move-result-object p1

    .line 166
    iput-object v3, p0, Lhw0/e;->e:Law0/h;

    .line 167
    .line 168
    iput-object v3, p0, Lhw0/e;->f:Lio/ktor/utils/io/t;

    .line 169
    .line 170
    iput-object v3, p0, Lhw0/e;->g:Lzw0/a;

    .line 171
    .line 172
    iput v2, p0, Lhw0/e;->d:I

    .line 173
    .line 174
    iget-object v1, p0, Lhw0/e;->h:Ljava/util/Set;

    .line 175
    .line 176
    iget-object v2, p0, Lhw0/e;->i:Ljava/util/List;

    .line 177
    .line 178
    move-object v8, p0

    .line 179
    move-object v3, p1

    .line 180
    invoke-static/range {v1 .. v8}, Lhw0/h;->b(Ljava/util/Set;Ljava/util/List;Low0/f0;Lzw0/a;Ljava/lang/Object;Low0/e;Ljava/nio/charset/Charset;Lrx0/c;)Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object p0

    .line 184
    if-ne p0, v9, :cond_8

    .line 185
    .line 186
    return-object v9

    .line 187
    :cond_8
    return-object p0
.end method
