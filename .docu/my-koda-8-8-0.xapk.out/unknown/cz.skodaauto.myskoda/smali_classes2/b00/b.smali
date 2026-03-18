.class public final Lb00/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Llq0/b;

.field public final b:Lkf0/o;


# direct methods
.method public constructor <init>(Llq0/b;Lkf0/o;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lb00/b;->a:Llq0/b;

    .line 5
    .line 6
    iput-object p2, p0, Lb00/b;->b:Lkf0/o;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lb00/b;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p1, Lb00/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lb00/a;

    .line 7
    .line 8
    iget v1, v0, Lb00/a;->f:I

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
    iput v1, v0, Lb00/a;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lb00/a;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lb00/a;-><init>(Lb00/b;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lb00/a;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lb00/a;->f:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_3

    .line 34
    .line 35
    if-eq v2, v4, :cond_2

    .line 36
    .line 37
    if-ne v2, v3, :cond_1

    .line 38
    .line 39
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    goto :goto_3

    .line 43
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 44
    .line 45
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 46
    .line 47
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw p0

    .line 51
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    iput v4, v0, Lb00/a;->f:I

    .line 59
    .line 60
    iget-object p1, p0, Lb00/b;->b:Lkf0/o;

    .line 61
    .line 62
    invoke-virtual {p1, v0}, Lkf0/o;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    if-ne p1, v1, :cond_4

    .line 67
    .line 68
    goto :goto_2

    .line 69
    :cond_4
    :goto_1
    check-cast p1, Lne0/t;

    .line 70
    .line 71
    instance-of v2, p1, Lne0/c;

    .line 72
    .line 73
    if-eqz v2, :cond_5

    .line 74
    .line 75
    check-cast p1, Lne0/c;

    .line 76
    .line 77
    return-object p1

    .line 78
    :cond_5
    instance-of v2, p1, Lne0/e;

    .line 79
    .line 80
    if-eqz v2, :cond_7

    .line 81
    .line 82
    check-cast p1, Lne0/e;

    .line 83
    .line 84
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 85
    .line 86
    check-cast p1, Lss0/j0;

    .line 87
    .line 88
    iget-object p1, p1, Lss0/j0;->d:Ljava/lang/String;

    .line 89
    .line 90
    sget-object v2, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->ClimateControl:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 91
    .line 92
    invoke-virtual {v2}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object v2

    .line 96
    const-string v4, "aircondition"

    .line 97
    .line 98
    const-string v5, "start"

    .line 99
    .line 100
    invoke-static {v2, v4, v5}, Lhf0/d;->a(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object v2

    .line 104
    const-string v4, "vin"

    .line 105
    .line 106
    invoke-static {v2, v4, p1}, Lhf0/d;->a(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 107
    .line 108
    .line 109
    move-result-object p1

    .line 110
    new-instance v2, Lmq0/a;

    .line 111
    .line 112
    sget-object v4, Lmq0/b;->e:Lmq0/b;

    .line 113
    .line 114
    invoke-direct {v2, v4, p1}, Lmq0/a;-><init>(Lmq0/b;Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    iput v3, v0, Lb00/a;->f:I

    .line 118
    .line 119
    iget-object p0, p0, Lb00/b;->a:Llq0/b;

    .line 120
    .line 121
    invoke-virtual {p0, v2, v0}, Llq0/b;->b(Lmq0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object p0

    .line 125
    if-ne p0, v1, :cond_6

    .line 126
    .line 127
    :goto_2
    return-object v1

    .line 128
    :cond_6
    :goto_3
    new-instance p0, Lne0/e;

    .line 129
    .line 130
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 131
    .line 132
    invoke-direct {p0, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 133
    .line 134
    .line 135
    return-object p0

    .line 136
    :cond_7
    new-instance p0, La8/r0;

    .line 137
    .line 138
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 139
    .line 140
    .line 141
    throw p0
.end method
