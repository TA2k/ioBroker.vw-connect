.class public final synthetic Lh2/n2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lvy0/b0;

.field public final synthetic f:Lm1/t;


# direct methods
.method public synthetic constructor <init>(Lm1/t;Lvy0/b0;I)V
    .locals 0

    .line 1
    iput p3, p0, Lh2/n2;->d:I

    iput-object p1, p0, Lh2/n2;->f:Lm1/t;

    iput-object p2, p0, Lh2/n2;->e:Lvy0/b0;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lvy0/b0;Lm1/t;I)V
    .locals 0

    .line 2
    iput p3, p0, Lh2/n2;->d:I

    iput-object p1, p0, Lh2/n2;->e:Lvy0/b0;

    iput-object p2, p0, Lh2/n2;->f:Lm1/t;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lh2/n2;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lh2/x2;

    .line 7
    .line 8
    const/16 v1, 0x8

    .line 9
    .line 10
    iget-object v2, p0, Lh2/n2;->f:Lm1/t;

    .line 11
    .line 12
    const/4 v3, 0x0

    .line 13
    invoke-direct {v0, v2, v3, v1}, Lh2/x2;-><init>(Lm1/t;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    const/4 v1, 0x3

    .line 17
    iget-object p0, p0, Lh2/n2;->e:Lvy0/b0;

    .line 18
    .line 19
    invoke-static {p0, v3, v3, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 20
    .line 21
    .line 22
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    return-object p0

    .line 25
    :pswitch_0
    new-instance v0, Lh2/x2;

    .line 26
    .line 27
    const/4 v1, 0x7

    .line 28
    iget-object v2, p0, Lh2/n2;->f:Lm1/t;

    .line 29
    .line 30
    const/4 v3, 0x0

    .line 31
    invoke-direct {v0, v2, v3, v1}, Lh2/x2;-><init>(Lm1/t;Lkotlin/coroutines/Continuation;I)V

    .line 32
    .line 33
    .line 34
    const/4 v1, 0x3

    .line 35
    iget-object p0, p0, Lh2/n2;->e:Lvy0/b0;

    .line 36
    .line 37
    invoke-static {p0, v3, v3, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 38
    .line 39
    .line 40
    goto :goto_0

    .line 41
    :pswitch_1
    new-instance v0, Lh2/x2;

    .line 42
    .line 43
    const/4 v1, 0x6

    .line 44
    iget-object v2, p0, Lh2/n2;->f:Lm1/t;

    .line 45
    .line 46
    const/4 v3, 0x0

    .line 47
    invoke-direct {v0, v2, v3, v1}, Lh2/x2;-><init>(Lm1/t;Lkotlin/coroutines/Continuation;I)V

    .line 48
    .line 49
    .line 50
    const/4 v1, 0x3

    .line 51
    iget-object p0, p0, Lh2/n2;->e:Lvy0/b0;

    .line 52
    .line 53
    invoke-static {p0, v3, v3, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 54
    .line 55
    .line 56
    goto :goto_0

    .line 57
    :pswitch_2
    iget-object v0, p0, Lh2/n2;->f:Lm1/t;

    .line 58
    .line 59
    invoke-virtual {v0}, Lm1/t;->d()Z

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    if-nez v1, :cond_0

    .line 64
    .line 65
    const/4 p0, 0x0

    .line 66
    goto :goto_1

    .line 67
    :cond_0
    new-instance v1, Lh2/x2;

    .line 68
    .line 69
    const/4 v2, 0x2

    .line 70
    const/4 v3, 0x0

    .line 71
    invoke-direct {v1, v0, v3, v2}, Lh2/x2;-><init>(Lm1/t;Lkotlin/coroutines/Continuation;I)V

    .line 72
    .line 73
    .line 74
    const/4 v0, 0x3

    .line 75
    iget-object p0, p0, Lh2/n2;->e:Lvy0/b0;

    .line 76
    .line 77
    invoke-static {p0, v3, v3, v1, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 78
    .line 79
    .line 80
    const/4 p0, 0x1

    .line 81
    :goto_1
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    return-object p0

    .line 86
    :pswitch_3
    iget-object v0, p0, Lh2/n2;->f:Lm1/t;

    .line 87
    .line 88
    invoke-virtual {v0}, Lm1/t;->b()Z

    .line 89
    .line 90
    .line 91
    move-result v1

    .line 92
    if-nez v1, :cond_1

    .line 93
    .line 94
    const/4 p0, 0x0

    .line 95
    goto :goto_2

    .line 96
    :cond_1
    new-instance v1, Lh2/x2;

    .line 97
    .line 98
    const/4 v2, 0x3

    .line 99
    const/4 v3, 0x0

    .line 100
    invoke-direct {v1, v0, v3, v2}, Lh2/x2;-><init>(Lm1/t;Lkotlin/coroutines/Continuation;I)V

    .line 101
    .line 102
    .line 103
    const/4 v0, 0x3

    .line 104
    iget-object p0, p0, Lh2/n2;->e:Lvy0/b0;

    .line 105
    .line 106
    invoke-static {p0, v3, v3, v1, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 107
    .line 108
    .line 109
    const/4 p0, 0x1

    .line 110
    :goto_2
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 111
    .line 112
    .line 113
    move-result-object p0

    .line 114
    return-object p0

    .line 115
    :pswitch_4
    new-instance v0, Lh2/x2;

    .line 116
    .line 117
    const/4 v1, 0x1

    .line 118
    iget-object v2, p0, Lh2/n2;->f:Lm1/t;

    .line 119
    .line 120
    const/4 v3, 0x0

    .line 121
    invoke-direct {v0, v2, v3, v1}, Lh2/x2;-><init>(Lm1/t;Lkotlin/coroutines/Continuation;I)V

    .line 122
    .line 123
    .line 124
    const/4 v1, 0x3

    .line 125
    iget-object p0, p0, Lh2/n2;->e:Lvy0/b0;

    .line 126
    .line 127
    invoke-static {p0, v3, v3, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 128
    .line 129
    .line 130
    goto :goto_0

    .line 131
    :pswitch_5
    new-instance v0, Lh2/x2;

    .line 132
    .line 133
    const/4 v1, 0x0

    .line 134
    iget-object v2, p0, Lh2/n2;->f:Lm1/t;

    .line 135
    .line 136
    const/4 v3, 0x0

    .line 137
    invoke-direct {v0, v2, v3, v1}, Lh2/x2;-><init>(Lm1/t;Lkotlin/coroutines/Continuation;I)V

    .line 138
    .line 139
    .line 140
    const/4 v1, 0x3

    .line 141
    iget-object p0, p0, Lh2/n2;->e:Lvy0/b0;

    .line 142
    .line 143
    invoke-static {p0, v3, v3, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 144
    .line 145
    .line 146
    goto :goto_0

    .line 147
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
