.class public final Lcf0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lhq0/d;

.field public final b:Loj0/f;

.field public final c:Lhq0/a;


# direct methods
.method public constructor <init>(Lhq0/d;Loj0/f;Lhq0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcf0/b;->a:Lhq0/d;

    .line 5
    .line 6
    iput-object p2, p0, Lcf0/b;->b:Loj0/f;

    .line 7
    .line 8
    iput-object p3, p0, Lcf0/b;->c:Lhq0/a;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lcf0/b;->b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 13

    .line 1
    instance-of v0, p2, Lcf0/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lcf0/a;

    .line 7
    .line 8
    iget v1, v0, Lcf0/a;->g:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lcf0/a;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lcf0/a;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lcf0/a;-><init>(Lcf0/b;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lcf0/a;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lcf0/a;->g:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    const/4 v4, 0x3

    .line 34
    const/4 v5, 0x2

    .line 35
    const/4 v6, 0x1

    .line 36
    const/4 v12, 0x0

    .line 37
    if-eqz v2, :cond_4

    .line 38
    .line 39
    if-eq v2, v6, :cond_3

    .line 40
    .line 41
    if-eq v2, v5, :cond_2

    .line 42
    .line 43
    if-ne v2, v4, :cond_1

    .line 44
    .line 45
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    goto :goto_5

    .line 49
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 50
    .line 51
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 52
    .line 53
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw p0

    .line 57
    :cond_2
    iget-object p0, v0, Lcf0/a;->d:Lhq0/d;

    .line 58
    .line 59
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    goto :goto_2

    .line 63
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    goto :goto_1

    .line 67
    :cond_4
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    iput v6, v0, Lcf0/a;->g:I

    .line 71
    .line 72
    iget-object p2, p0, Lcf0/b;->b:Loj0/f;

    .line 73
    .line 74
    invoke-virtual {p2, p1, v0}, Loj0/f;->b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object p2

    .line 78
    if-ne p2, v1, :cond_5

    .line 79
    .line 80
    goto :goto_4

    .line 81
    :cond_5
    :goto_1
    check-cast p2, Lpj0/a;

    .line 82
    .line 83
    invoke-static {}, Ljava/util/Base64;->getDecoder()Ljava/util/Base64$Decoder;

    .line 84
    .line 85
    .line 86
    move-result-object p1

    .line 87
    iget-object v2, p2, Lpj0/a;->b:Ljava/lang/String;

    .line 88
    .line 89
    invoke-virtual {p1, v2}, Ljava/util/Base64$Decoder;->decode(Ljava/lang/String;)[B

    .line 90
    .line 91
    .line 92
    move-result-object v11

    .line 93
    iget-object v10, p2, Lpj0/a;->a:Ljava/lang/String;

    .line 94
    .line 95
    invoke-static {v11}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 96
    .line 97
    .line 98
    iget-object p1, p0, Lcf0/b;->a:Lhq0/d;

    .line 99
    .line 100
    iput-object p1, v0, Lcf0/a;->d:Lhq0/d;

    .line 101
    .line 102
    iput v5, v0, Lcf0/a;->g:I

    .line 103
    .line 104
    sget-object p2, Lge0/b;->c:Lcz0/d;

    .line 105
    .line 106
    new-instance v7, Laa/s;

    .line 107
    .line 108
    const/4 v8, 0x4

    .line 109
    move-object v9, p0

    .line 110
    invoke-direct/range {v7 .. v12}, Laa/s;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 111
    .line 112
    .line 113
    invoke-static {p2, v7, v0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object p2

    .line 117
    if-ne p2, v1, :cond_6

    .line 118
    .line 119
    goto :goto_4

    .line 120
    :cond_6
    move-object p0, p1

    .line 121
    :goto_2
    check-cast p2, Ljava/io/File;

    .line 122
    .line 123
    iput-object v12, v0, Lcf0/a;->d:Lhq0/d;

    .line 124
    .line 125
    iput v4, v0, Lcf0/a;->g:I

    .line 126
    .line 127
    check-cast p0, Lfq0/a;

    .line 128
    .line 129
    iget-object p0, p0, Lfq0/a;->a:Lyy0/q1;

    .line 130
    .line 131
    invoke-virtual {p0, p2, v0}, Lyy0/q1;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object p0

    .line 135
    if-ne p0, v1, :cond_7

    .line 136
    .line 137
    goto :goto_3

    .line 138
    :cond_7
    move-object p0, v3

    .line 139
    :goto_3
    if-ne p0, v1, :cond_8

    .line 140
    .line 141
    :goto_4
    return-object v1

    .line 142
    :cond_8
    :goto_5
    return-object v3
.end method
