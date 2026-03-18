.class public final Lky/i0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lat0/o;

.field public final b:Lat0/a;

.field public final c:Lgb0/d;

.field public final d:Lkf0/i;


# direct methods
.method public constructor <init>(Lat0/o;Lat0/a;Lgb0/d;Lkf0/i;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lky/i0;->a:Lat0/o;

    .line 5
    .line 6
    iput-object p2, p0, Lky/i0;->b:Lat0/a;

    .line 7
    .line 8
    iput-object p3, p0, Lky/i0;->c:Lgb0/d;

    .line 9
    .line 10
    iput-object p4, p0, Lky/i0;->d:Lkf0/i;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lzb0/a;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lky/i0;->b(Lzb0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lzb0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p2, Lky/g0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lky/g0;

    .line 7
    .line 8
    iget v1, v0, Lky/g0;->g:I

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
    iput v1, v0, Lky/g0;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lky/g0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lky/g0;-><init>(Lky/i0;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lky/g0;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lky/g0;->g:I

    .line 30
    .line 31
    const/4 v3, 0x3

    .line 32
    const/4 v4, 0x2

    .line 33
    const/4 v5, 0x1

    .line 34
    sget-object v6, Llx0/b0;->a:Llx0/b0;

    .line 35
    .line 36
    const/4 v7, 0x0

    .line 37
    if-eqz v2, :cond_4

    .line 38
    .line 39
    if-eq v2, v5, :cond_3

    .line 40
    .line 41
    if-eq v2, v4, :cond_2

    .line 42
    .line 43
    if-ne v2, v3, :cond_1

    .line 44
    .line 45
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    return-object v6

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    return-object v6

    .line 61
    :cond_3
    iget-object p1, v0, Lky/g0;->d:Lzb0/a;

    .line 62
    .line 63
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
    iget-object p2, p1, Lzb0/a;->e:Ljava/lang/Object;

    .line 71
    .line 72
    check-cast p2, Lms0/e;

    .line 73
    .line 74
    if-eqz p2, :cond_6

    .line 75
    .line 76
    iget-object p2, p2, Lms0/e;->a:Ljava/lang/String;

    .line 77
    .line 78
    if-eqz p2, :cond_6

    .line 79
    .line 80
    iput-object p1, v0, Lky/g0;->d:Lzb0/a;

    .line 81
    .line 82
    iput v5, v0, Lky/g0;->g:I

    .line 83
    .line 84
    iget-object v2, p0, Lky/i0;->d:Lkf0/i;

    .line 85
    .line 86
    invoke-virtual {v2, p2, v0}, Lkf0/i;->b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object p2

    .line 90
    if-ne p2, v1, :cond_5

    .line 91
    .line 92
    goto :goto_3

    .line 93
    :cond_5
    :goto_1
    check-cast p2, Lss0/k;

    .line 94
    .line 95
    if-eqz p2, :cond_6

    .line 96
    .line 97
    iget-object p2, p2, Lss0/k;->j:Lss0/n;

    .line 98
    .line 99
    goto :goto_2

    .line 100
    :cond_6
    move-object p2, v7

    .line 101
    :goto_2
    sget-object v2, Lss0/n;->f:Lss0/n;

    .line 102
    .line 103
    const-string v5, "owner-verified"

    .line 104
    .line 105
    if-ne p2, v2, :cond_8

    .line 106
    .line 107
    iget-object p1, p1, Lzb0/a;->d:Ljava/lang/String;

    .line 108
    .line 109
    const-string p2, "profile-downloaded"

    .line 110
    .line 111
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 112
    .line 113
    .line 114
    move-result p2

    .line 115
    if-eqz p2, :cond_7

    .line 116
    .line 117
    iput-object v7, v0, Lky/g0;->d:Lzb0/a;

    .line 118
    .line 119
    iput v4, v0, Lky/g0;->g:I

    .line 120
    .line 121
    invoke-virtual {p0, v0}, Lky/i0;->c(Lrx0/c;)Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object p0

    .line 125
    if-ne p0, v1, :cond_9

    .line 126
    .line 127
    goto :goto_3

    .line 128
    :cond_7
    invoke-static {p1, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 129
    .line 130
    .line 131
    move-result p1

    .line 132
    if-eqz p1, :cond_9

    .line 133
    .line 134
    iget-object p0, p0, Lky/i0;->a:Lat0/o;

    .line 135
    .line 136
    sget-object p1, Lbt0/b;->e:Lbt0/b;

    .line 137
    .line 138
    invoke-virtual {p0, p1}, Lat0/o;->a(Lbt0/b;)V

    .line 139
    .line 140
    .line 141
    return-object v6

    .line 142
    :cond_8
    iget-object p1, p1, Lzb0/a;->d:Ljava/lang/String;

    .line 143
    .line 144
    invoke-static {p1, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 145
    .line 146
    .line 147
    move-result p1

    .line 148
    if-eqz p1, :cond_9

    .line 149
    .line 150
    iput-object v7, v0, Lky/g0;->d:Lzb0/a;

    .line 151
    .line 152
    iput v3, v0, Lky/g0;->g:I

    .line 153
    .line 154
    invoke-virtual {p0, v0}, Lky/i0;->c(Lrx0/c;)Ljava/lang/Object;

    .line 155
    .line 156
    .line 157
    move-result-object p0

    .line 158
    if-ne p0, v1, :cond_9

    .line 159
    .line 160
    :goto_3
    return-object v1

    .line 161
    :cond_9
    return-object v6
.end method

.method public final c(Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p1, Lky/h0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lky/h0;

    .line 7
    .line 8
    iget v1, v0, Lky/h0;->f:I

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
    iput v1, v0, Lky/h0;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lky/h0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lky/h0;-><init>(Lky/i0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lky/h0;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lky/h0;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    iput v3, v0, Lky/h0;->f:I

    .line 52
    .line 53
    iget-object p1, p0, Lky/i0;->c:Lgb0/d;

    .line 54
    .line 55
    invoke-virtual {p1, v0}, Lgb0/d;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    if-ne p1, v1, :cond_3

    .line 60
    .line 61
    return-object v1

    .line 62
    :cond_3
    :goto_1
    iget-object p0, p0, Lky/i0;->b:Lat0/a;

    .line 63
    .line 64
    invoke-virtual {p0}, Lat0/a;->invoke()Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 68
    .line 69
    return-object p0
.end method
