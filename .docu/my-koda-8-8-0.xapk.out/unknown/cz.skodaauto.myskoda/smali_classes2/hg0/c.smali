.class public final Lhg0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lhg0/g;


# direct methods
.method public synthetic constructor <init>(Lhg0/g;I)V
    .locals 0

    .line 1
    iput p2, p0, Lhg0/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lhg0/c;->e:Lhg0/g;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Lhg0/c;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lhg0/c;->e:Lhg0/g;

    .line 4
    .line 5
    const/4 v1, 0x1

    .line 6
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 7
    .line 8
    packed-switch v0, :pswitch_data_0

    .line 9
    .line 10
    .line 11
    check-cast p1, Lun0/b;

    .line 12
    .line 13
    iget-object v0, p0, Lhg0/g;->j:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 14
    .line 15
    iget-boolean p1, p1, Lun0/b;->b:Z

    .line 16
    .line 17
    const/4 v3, 0x0

    .line 18
    if-eqz p1, :cond_2

    .line 19
    .line 20
    invoke-virtual {v0, v3, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;->compareAndSet(ZZ)Z

    .line 21
    .line 22
    .line 23
    move-result p1

    .line 24
    if-eqz p1, :cond_1

    .line 25
    .line 26
    iget-object p1, p0, Lhg0/g;->k:Lhg0/e;

    .line 27
    .line 28
    if-eqz p1, :cond_0

    .line 29
    .line 30
    invoke-virtual {p1}, Ljava/util/TimerTask;->cancel()Z

    .line 31
    .line 32
    .line 33
    :cond_0
    new-instance v4, Ljava/util/Timer;

    .line 34
    .line 35
    invoke-direct {v4}, Ljava/util/Timer;-><init>()V

    .line 36
    .line 37
    .line 38
    new-instance v5, Lhg0/e;

    .line 39
    .line 40
    invoke-direct {v5, p0, v3}, Lhg0/e;-><init>(Ljava/lang/Object;I)V

    .line 41
    .line 42
    .line 43
    const-wide/16 v6, 0x0

    .line 44
    .line 45
    const-wide/16 v8, 0x1388

    .line 46
    .line 47
    invoke-virtual/range {v4 .. v9}, Ljava/util/Timer;->schedule(Ljava/util/TimerTask;JJ)V

    .line 48
    .line 49
    .line 50
    iput-object v5, p0, Lhg0/g;->k:Lhg0/e;

    .line 51
    .line 52
    :cond_1
    iget-object p1, p0, Lhg0/g;->a:Ldg0/a;

    .line 53
    .line 54
    iget-object p1, p1, Ldg0/a;->d:Lyy0/k1;

    .line 55
    .line 56
    iget-object p1, p1, Lyy0/k1;->d:Lyy0/n1;

    .line 57
    .line 58
    invoke-interface {p1}, Lyy0/n1;->c()Ljava/util/List;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    invoke-static {p1}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    check-cast p1, Ldg0/b;

    .line 67
    .line 68
    sget-object v0, Ldg0/b;->d:Ldg0/b;

    .line 69
    .line 70
    if-ne p1, v0, :cond_4

    .line 71
    .line 72
    iget-object p1, p0, Lhg0/g;->f:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 73
    .line 74
    invoke-virtual {p1, v1, v3}, Ljava/util/concurrent/atomic/AtomicBoolean;->compareAndSet(ZZ)Z

    .line 75
    .line 76
    .line 77
    invoke-static {p0, p2}, Lhg0/g;->a(Lhg0/g;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 82
    .line 83
    if-ne p0, p1, :cond_4

    .line 84
    .line 85
    move-object v2, p0

    .line 86
    goto :goto_0

    .line 87
    :cond_2
    sget-object p1, Lhg0/g;->l:Lcom/google/android/gms/location/LocationRequest;

    .line 88
    .line 89
    invoke-virtual {v0, v1, v3}, Ljava/util/concurrent/atomic/AtomicBoolean;->compareAndSet(ZZ)Z

    .line 90
    .line 91
    .line 92
    move-result p1

    .line 93
    if-eqz p1, :cond_4

    .line 94
    .line 95
    iget-object p1, p0, Lhg0/g;->k:Lhg0/e;

    .line 96
    .line 97
    if-eqz p1, :cond_3

    .line 98
    .line 99
    invoke-virtual {p1}, Ljava/util/TimerTask;->cancel()Z

    .line 100
    .line 101
    .line 102
    :cond_3
    const/4 p1, 0x0

    .line 103
    iput-object p1, p0, Lhg0/g;->k:Lhg0/e;

    .line 104
    .line 105
    :cond_4
    :goto_0
    return-object v2

    .line 106
    :pswitch_0
    check-cast p1, Ldg0/b;

    .line 107
    .line 108
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 109
    .line 110
    .line 111
    move-result p1

    .line 112
    if-eqz p1, :cond_6

    .line 113
    .line 114
    if-ne p1, v1, :cond_5

    .line 115
    .line 116
    sget-object p1, Lhg0/g;->l:Lcom/google/android/gms/location/LocationRequest;

    .line 117
    .line 118
    invoke-virtual {p0}, Lhg0/g;->c()V

    .line 119
    .line 120
    .line 121
    goto :goto_1

    .line 122
    :cond_5
    new-instance p0, La8/r0;

    .line 123
    .line 124
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 125
    .line 126
    .line 127
    throw p0

    .line 128
    :cond_6
    invoke-static {p0, p2}, Lhg0/g;->a(Lhg0/g;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object p0

    .line 132
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 133
    .line 134
    if-ne p0, p1, :cond_7

    .line 135
    .line 136
    move-object v2, p0

    .line 137
    :cond_7
    :goto_1
    return-object v2

    .line 138
    nop

    .line 139
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
