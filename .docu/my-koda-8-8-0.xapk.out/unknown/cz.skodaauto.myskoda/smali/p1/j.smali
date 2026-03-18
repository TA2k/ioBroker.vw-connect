.class public final synthetic Lp1/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lp1/v;

.field public final synthetic f:Lvy0/b0;


# direct methods
.method public synthetic constructor <init>(Lp1/v;Lvy0/b0;I)V
    .locals 0

    .line 1
    iput p3, p0, Lp1/j;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lp1/j;->e:Lp1/v;

    .line 4
    .line 5
    iput-object p2, p0, Lp1/j;->f:Lvy0/b0;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lp1/j;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lp1/j;->e:Lp1/v;

    .line 7
    .line 8
    invoke-virtual {v0}, Lp1/v;->d()Z

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    if-eqz v1, :cond_0

    .line 13
    .line 14
    new-instance v1, Lp1/k;

    .line 15
    .line 16
    const/4 v2, 0x1

    .line 17
    const/4 v3, 0x0

    .line 18
    invoke-direct {v1, v0, v3, v2}, Lp1/k;-><init>(Lp1/v;Lkotlin/coroutines/Continuation;I)V

    .line 19
    .line 20
    .line 21
    const/4 v0, 0x3

    .line 22
    iget-object p0, p0, Lp1/j;->f:Lvy0/b0;

    .line 23
    .line 24
    invoke-static {p0, v3, v3, v1, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 25
    .line 26
    .line 27
    const/4 p0, 0x1

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    const/4 p0, 0x0

    .line 30
    :goto_0
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0

    .line 35
    :pswitch_0
    iget-object v0, p0, Lp1/j;->e:Lp1/v;

    .line 36
    .line 37
    invoke-virtual {v0}, Lp1/v;->b()Z

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    if-eqz v1, :cond_1

    .line 42
    .line 43
    new-instance v1, Lp1/k;

    .line 44
    .line 45
    const/4 v2, 0x0

    .line 46
    const/4 v3, 0x0

    .line 47
    invoke-direct {v1, v0, v3, v2}, Lp1/k;-><init>(Lp1/v;Lkotlin/coroutines/Continuation;I)V

    .line 48
    .line 49
    .line 50
    const/4 v0, 0x3

    .line 51
    iget-object p0, p0, Lp1/j;->f:Lvy0/b0;

    .line 52
    .line 53
    invoke-static {p0, v3, v3, v1, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 54
    .line 55
    .line 56
    const/4 p0, 0x1

    .line 57
    goto :goto_1

    .line 58
    :cond_1
    const/4 p0, 0x0

    .line 59
    :goto_1
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    return-object p0

    .line 64
    :pswitch_1
    iget-object v0, p0, Lp1/j;->e:Lp1/v;

    .line 65
    .line 66
    invoke-virtual {v0}, Lp1/v;->d()Z

    .line 67
    .line 68
    .line 69
    move-result v1

    .line 70
    if-eqz v1, :cond_2

    .line 71
    .line 72
    new-instance v1, Lp1/k;

    .line 73
    .line 74
    const/4 v2, 0x1

    .line 75
    const/4 v3, 0x0

    .line 76
    invoke-direct {v1, v0, v3, v2}, Lp1/k;-><init>(Lp1/v;Lkotlin/coroutines/Continuation;I)V

    .line 77
    .line 78
    .line 79
    const/4 v0, 0x3

    .line 80
    iget-object p0, p0, Lp1/j;->f:Lvy0/b0;

    .line 81
    .line 82
    invoke-static {p0, v3, v3, v1, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 83
    .line 84
    .line 85
    const/4 p0, 0x1

    .line 86
    goto :goto_2

    .line 87
    :cond_2
    const/4 p0, 0x0

    .line 88
    :goto_2
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    return-object p0

    .line 93
    :pswitch_2
    iget-object v0, p0, Lp1/j;->e:Lp1/v;

    .line 94
    .line 95
    invoke-virtual {v0}, Lp1/v;->b()Z

    .line 96
    .line 97
    .line 98
    move-result v1

    .line 99
    if-eqz v1, :cond_3

    .line 100
    .line 101
    new-instance v1, Lp1/k;

    .line 102
    .line 103
    const/4 v2, 0x0

    .line 104
    const/4 v3, 0x0

    .line 105
    invoke-direct {v1, v0, v3, v2}, Lp1/k;-><init>(Lp1/v;Lkotlin/coroutines/Continuation;I)V

    .line 106
    .line 107
    .line 108
    const/4 v0, 0x3

    .line 109
    iget-object p0, p0, Lp1/j;->f:Lvy0/b0;

    .line 110
    .line 111
    invoke-static {p0, v3, v3, v1, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 112
    .line 113
    .line 114
    const/4 p0, 0x1

    .line 115
    goto :goto_3

    .line 116
    :cond_3
    const/4 p0, 0x0

    .line 117
    :goto_3
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    return-object p0

    .line 122
    nop

    .line 123
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
