.class public final Lfw0/y;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/q;


# instance fields
.field public d:I

.field public synthetic e:Law0/h;

.field public synthetic f:Lio/ktor/utils/io/t;

.field public synthetic g:Lzw0/a;

.field public final synthetic h:Ljava/nio/charset/Charset;


# direct methods
.method public constructor <init>(Ljava/nio/charset/Charset;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lfw0/y;->h:Ljava/nio/charset/Charset;

    .line 2
    .line 3
    const/4 p1, 0x5

    .line 4
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

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
    new-instance p1, Lfw0/y;

    .line 12
    .line 13
    iget-object p0, p0, Lfw0/y;->h:Ljava/nio/charset/Charset;

    .line 14
    .line 15
    invoke-direct {p1, p0, p5}, Lfw0/y;-><init>(Ljava/nio/charset/Charset;Lkotlin/coroutines/Continuation;)V

    .line 16
    .line 17
    .line 18
    iput-object p2, p1, Lfw0/y;->e:Law0/h;

    .line 19
    .line 20
    iput-object p3, p1, Lfw0/y;->f:Lio/ktor/utils/io/t;

    .line 21
    .line 22
    iput-object p4, p1, Lfw0/y;->g:Lzw0/a;

    .line 23
    .line 24
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 25
    .line 26
    invoke-virtual {p1, p0}, Lfw0/y;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget-object v0, p0, Lfw0/y;->e:Law0/h;

    .line 2
    .line 3
    iget-object v1, p0, Lfw0/y;->f:Lio/ktor/utils/io/t;

    .line 4
    .line 5
    iget-object v2, p0, Lfw0/y;->g:Lzw0/a;

    .line 6
    .line 7
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 8
    .line 9
    iget v4, p0, Lfw0/y;->d:I

    .line 10
    .line 11
    const/4 v5, 0x1

    .line 12
    const/4 v6, 0x0

    .line 13
    if-eqz v4, :cond_1

    .line 14
    .line 15
    if-ne v4, v5, :cond_0

    .line 16
    .line 17
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 22
    .line 23
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 24
    .line 25
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw p0

    .line 29
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    iget-object p1, v2, Lzw0/a;->a:Lhy0/d;

    .line 33
    .line 34
    const-class v2, Ljava/lang/String;

    .line 35
    .line 36
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 37
    .line 38
    invoke-virtual {v4, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 39
    .line 40
    .line 41
    move-result-object v2

    .line 42
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result p1

    .line 46
    if-nez p1, :cond_2

    .line 47
    .line 48
    return-object v6

    .line 49
    :cond_2
    iput-object v0, p0, Lfw0/y;->e:Law0/h;

    .line 50
    .line 51
    iput-object v6, p0, Lfw0/y;->f:Lio/ktor/utils/io/t;

    .line 52
    .line 53
    iput-object v6, p0, Lfw0/y;->g:Lzw0/a;

    .line 54
    .line 55
    iput v5, p0, Lfw0/y;->d:I

    .line 56
    .line 57
    invoke-static {v1, p0}, Lio/ktor/utils/io/h0;->i(Lio/ktor/utils/io/t;Lrx0/c;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    if-ne p1, v3, :cond_3

    .line 62
    .line 63
    return-object v3

    .line 64
    :cond_3
    :goto_0
    check-cast p1, Lnz0/i;

    .line 65
    .line 66
    invoke-virtual {v0}, Law0/h;->M()Law0/c;

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    sget-object v1, Lfw0/a0;->a:Lt21/b;

    .line 71
    .line 72
    invoke-virtual {v0}, Law0/c;->d()Law0/h;

    .line 73
    .line 74
    .line 75
    move-result-object v1

    .line 76
    invoke-interface {v1}, Low0/r;->a()Low0/m;

    .line 77
    .line 78
    .line 79
    move-result-object v1

    .line 80
    sget-object v2, Low0/q;->a:Ljava/util/List;

    .line 81
    .line 82
    const-string v2, "Content-Type"

    .line 83
    .line 84
    invoke-interface {v1, v2}, Lvw0/j;->get(Ljava/lang/String;)Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object v1

    .line 88
    if-eqz v1, :cond_4

    .line 89
    .line 90
    sget-object v2, Low0/e;->f:Low0/e;

    .line 91
    .line 92
    invoke-static {v1}, Ljp/hc;->b(Ljava/lang/String;)Low0/e;

    .line 93
    .line 94
    .line 95
    move-result-object v1

    .line 96
    goto :goto_1

    .line 97
    :cond_4
    move-object v1, v6

    .line 98
    :goto_1
    if-eqz v1, :cond_5

    .line 99
    .line 100
    invoke-static {v1}, Ljp/ic;->e(Low0/e;)Ljava/nio/charset/Charset;

    .line 101
    .line 102
    .line 103
    move-result-object v6

    .line 104
    :cond_5
    if-nez v6, :cond_6

    .line 105
    .line 106
    iget-object v6, p0, Lfw0/y;->h:Ljava/nio/charset/Charset;

    .line 107
    .line 108
    :cond_6
    sget-object p0, Lfw0/a0;->a:Lt21/b;

    .line 109
    .line 110
    new-instance v1, Ljava/lang/StringBuilder;

    .line 111
    .line 112
    const-string v2, "Reading response body for "

    .line 113
    .line 114
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    invoke-virtual {v0}, Law0/c;->c()Lkw0/b;

    .line 118
    .line 119
    .line 120
    move-result-object v0

    .line 121
    invoke-interface {v0}, Lkw0/b;->getUrl()Low0/f0;

    .line 122
    .line 123
    .line 124
    move-result-object v0

    .line 125
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 126
    .line 127
    .line 128
    const-string v0, " as String with charset "

    .line 129
    .line 130
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 131
    .line 132
    .line 133
    invoke-virtual {v1, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 134
    .line 135
    .line 136
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 137
    .line 138
    .line 139
    move-result-object v0

    .line 140
    invoke-interface {p0, v0}, Lt21/b;->h(Ljava/lang/String;)V

    .line 141
    .line 142
    .line 143
    const/4 p0, 0x2

    .line 144
    invoke-static {p1, v6, p0}, Ljp/ib;->b(Lnz0/i;Ljava/nio/charset/Charset;I)Ljava/lang/String;

    .line 145
    .line 146
    .line 147
    move-result-object p0

    .line 148
    return-object p0
.end method
