.class public final Lyy0/d0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/i;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:Lyy0/i;


# direct methods
.method public synthetic constructor <init>(Lyy0/i;II)V
    .locals 0

    .line 1
    iput p3, p0, Lyy0/d0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lyy0/d0;->f:Lyy0/i;

    .line 4
    .line 5
    iput p2, p0, Lyy0/d0;->e:I

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Lyy0/d0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    instance-of v0, p2, Lyy0/h0;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    move-object v0, p2

    .line 11
    check-cast v0, Lyy0/h0;

    .line 12
    .line 13
    iget v1, v0, Lyy0/h0;->e:I

    .line 14
    .line 15
    const/high16 v2, -0x80000000

    .line 16
    .line 17
    and-int v3, v1, v2

    .line 18
    .line 19
    if-eqz v3, :cond_0

    .line 20
    .line 21
    sub-int/2addr v1, v2

    .line 22
    iput v1, v0, Lyy0/h0;->e:I

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    new-instance v0, Lyy0/h0;

    .line 26
    .line 27
    invoke-direct {v0, p0, p2}, Lyy0/h0;-><init>(Lyy0/d0;Lkotlin/coroutines/Continuation;)V

    .line 28
    .line 29
    .line 30
    :goto_0
    iget-object p2, v0, Lyy0/h0;->d:Ljava/lang/Object;

    .line 31
    .line 32
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 33
    .line 34
    iget v2, v0, Lyy0/h0;->e:I

    .line 35
    .line 36
    const/4 v3, 0x1

    .line 37
    if-eqz v2, :cond_2

    .line 38
    .line 39
    if-ne v2, v3, :cond_1

    .line 40
    .line 41
    iget-object p0, v0, Lyy0/h0;->g:Ljava/lang/Object;

    .line 42
    .line 43
    :try_start_0
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Lzy0/a; {:try_start_0 .. :try_end_0} :catch_0

    .line 44
    .line 45
    .line 46
    goto :goto_2

    .line 47
    :catch_0
    move-exception p1

    .line 48
    goto :goto_1

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
    new-instance p2, Ljava/lang/Object;

    .line 61
    .line 62
    invoke-direct {p2}, Ljava/lang/Object;-><init>()V

    .line 63
    .line 64
    .line 65
    new-instance v2, Lkotlin/jvm/internal/d0;

    .line 66
    .line 67
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 68
    .line 69
    .line 70
    :try_start_1
    iget-object v4, p0, Lyy0/d0;->f:Lyy0/i;

    .line 71
    .line 72
    new-instance v5, Lyy0/j0;

    .line 73
    .line 74
    iget p0, p0, Lyy0/d0;->e:I

    .line 75
    .line 76
    invoke-direct {v5, v2, p0, p1, p2}, Lyy0/j0;-><init>(Lkotlin/jvm/internal/d0;ILyy0/j;Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    iput-object p2, v0, Lyy0/h0;->g:Ljava/lang/Object;

    .line 80
    .line 81
    iput v3, v0, Lyy0/h0;->e:I

    .line 82
    .line 83
    invoke-interface {v4, v5, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object p0
    :try_end_1
    .catch Lzy0/a; {:try_start_1 .. :try_end_1} :catch_1

    .line 87
    if-ne p0, v1, :cond_3

    .line 88
    .line 89
    goto :goto_3

    .line 90
    :catch_1
    move-exception p1

    .line 91
    move-object p0, p2

    .line 92
    :goto_1
    iget-object p2, p1, Lzy0/a;->d:Ljava/lang/Object;

    .line 93
    .line 94
    if-ne p2, p0, :cond_4

    .line 95
    .line 96
    :cond_3
    :goto_2
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 97
    .line 98
    :goto_3
    return-object v1

    .line 99
    :cond_4
    throw p1

    .line 100
    :pswitch_0
    new-instance v0, Lkotlin/jvm/internal/d0;

    .line 101
    .line 102
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 103
    .line 104
    .line 105
    iget-object v1, p0, Lyy0/d0;->f:Lyy0/i;

    .line 106
    .line 107
    check-cast v1, Lbn0/f;

    .line 108
    .line 109
    new-instance v2, Lpp0/p;

    .line 110
    .line 111
    iget p0, p0, Lyy0/d0;->e:I

    .line 112
    .line 113
    invoke-direct {v2, v0, p0, p1}, Lpp0/p;-><init>(Lkotlin/jvm/internal/d0;ILyy0/j;)V

    .line 114
    .line 115
    .line 116
    invoke-virtual {v1, v2, p2}, Lbn0/f;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object p0

    .line 120
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 121
    .line 122
    if-ne p0, p1, :cond_5

    .line 123
    .line 124
    goto :goto_4

    .line 125
    :cond_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 126
    .line 127
    :goto_4
    return-object p0

    .line 128
    nop

    .line 129
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
