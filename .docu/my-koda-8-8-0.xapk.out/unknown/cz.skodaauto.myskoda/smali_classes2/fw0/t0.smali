.class public final Lfw0/t0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lfw0/e1;


# instance fields
.field public final a:I

.field public final b:Lzv0/c;

.field public c:I

.field public d:Law0/c;


# direct methods
.method public constructor <init>(ILzv0/c;)V
    .locals 1

    .line 1
    const-string v0, "client"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput p1, p0, Lfw0/t0;->a:I

    .line 10
    .line 11
    iput-object p2, p0, Lfw0/t0;->b:Lzv0/c;

    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final a(Lkw0/c;Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p2, Lfw0/s0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lfw0/s0;

    .line 7
    .line 8
    iget v1, v0, Lfw0/s0;->f:I

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
    iput v1, v0, Lfw0/s0;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lfw0/s0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lfw0/s0;-><init>(Lfw0/t0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lfw0/s0;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lfw0/s0;->f:I

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_2

    .line 34
    .line 35
    if-ne v2, v4, :cond_1

    .line 36
    .line 37
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 42
    .line 43
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 44
    .line 45
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    throw p0

    .line 49
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    iget-object p2, p0, Lfw0/t0;->d:Law0/c;

    .line 53
    .line 54
    if-eqz p2, :cond_3

    .line 55
    .line 56
    invoke-static {p2, v3}, Lvy0/e0;->j(Lvy0/b0;Ljava/util/concurrent/CancellationException;)V

    .line 57
    .line 58
    .line 59
    :cond_3
    iget p2, p0, Lfw0/t0;->c:I

    .line 60
    .line 61
    iget v2, p0, Lfw0/t0;->a:I

    .line 62
    .line 63
    if-ge p2, v2, :cond_7

    .line 64
    .line 65
    add-int/2addr p2, v4

    .line 66
    iput p2, p0, Lfw0/t0;->c:I

    .line 67
    .line 68
    iget-object p2, p0, Lfw0/t0;->b:Lzv0/c;

    .line 69
    .line 70
    iget-object p2, p2, Lzv0/c;->k:Lkw0/e;

    .line 71
    .line 72
    iget-object v2, p1, Lkw0/c;->d:Ljava/lang/Object;

    .line 73
    .line 74
    iput v4, v0, Lfw0/s0;->f:I

    .line 75
    .line 76
    invoke-virtual {p2, p1, v2, v0}, Lyw0/d;->a(Ljava/lang/Object;Ljava/lang/Object;Lrx0/c;)Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object p2

    .line 80
    if-ne p2, v1, :cond_4

    .line 81
    .line 82
    return-object v1

    .line 83
    :cond_4
    :goto_1
    instance-of p1, p2, Law0/c;

    .line 84
    .line 85
    if-eqz p1, :cond_5

    .line 86
    .line 87
    move-object v3, p2

    .line 88
    check-cast v3, Law0/c;

    .line 89
    .line 90
    :cond_5
    if-eqz v3, :cond_6

    .line 91
    .line 92
    iput-object v3, p0, Lfw0/t0;->d:Law0/c;

    .line 93
    .line 94
    return-object v3

    .line 95
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 96
    .line 97
    new-instance p1, Ljava/lang/StringBuilder;

    .line 98
    .line 99
    const-string v0, "Failed to execute send pipeline. Expected [HttpClientCall], but received "

    .line 100
    .line 101
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 105
    .line 106
    .line 107
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object p1

    .line 111
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 112
    .line 113
    .line 114
    move-result-object p1

    .line 115
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 116
    .line 117
    .line 118
    throw p0

    .line 119
    :cond_7
    new-instance p0, Laq/c;

    .line 120
    .line 121
    new-instance p1, Ljava/lang/StringBuilder;

    .line 122
    .line 123
    const-string p2, "Max send count "

    .line 124
    .line 125
    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 126
    .line 127
    .line 128
    invoke-virtual {p1, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 129
    .line 130
    .line 131
    const-string p2, " exceeded. Consider increasing the property maxSendCount if more is required."

    .line 132
    .line 133
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 134
    .line 135
    .line 136
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 137
    .line 138
    .line 139
    move-result-object p1

    .line 140
    const-string p2, "message"

    .line 141
    .line 142
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 143
    .line 144
    .line 145
    const/4 p2, 0x2

    .line 146
    invoke-direct {p0, p1, p2}, Laq/c;-><init>(Ljava/lang/String;I)V

    .line 147
    .line 148
    .line 149
    throw p0
.end method
