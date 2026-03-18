.class public final Lvp/z2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lvp/f4;

.field public final synthetic f:Lvp/d3;


# direct methods
.method public constructor <init>(Lvp/d3;Lvp/f4;I)V
    .locals 0

    .line 1
    iput p3, p0, Lvp/z2;->d:I

    .line 2
    .line 3
    packed-switch p3, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p2, p0, Lvp/z2;->e:Lvp/f4;

    .line 10
    .line 11
    iput-object p1, p0, Lvp/z2;->f:Lvp/d3;

    .line 12
    .line 13
    return-void

    .line 14
    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 15
    .line 16
    .line 17
    iput-object p2, p0, Lvp/z2;->e:Lvp/f4;

    .line 18
    .line 19
    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    iput-object p1, p0, Lvp/z2;->f:Lvp/d3;

    .line 23
    .line 24
    return-void

    .line 25
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final run()V
    .locals 6

    .line 1
    iget v0, p0, Lvp/z2;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lvp/z2;->f:Lvp/d3;

    .line 7
    .line 8
    iget-object v1, v0, Lvp/d3;->h:Lvp/c0;

    .line 9
    .line 10
    iget-object v2, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v2, Lvp/g1;

    .line 13
    .line 14
    if-nez v1, :cond_0

    .line 15
    .line 16
    iget-object p0, v2, Lvp/g1;->i:Lvp/p0;

    .line 17
    .line 18
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 19
    .line 20
    .line 21
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 22
    .line 23
    const-string v0, "Failed to send consent settings to service"

    .line 24
    .line 25
    invoke-virtual {p0, v0}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    :try_start_0
    iget-object p0, p0, Lvp/z2;->e:Lvp/f4;

    .line 30
    .line 31
    invoke-interface {v1, p0}, Lvp/c0;->O(Lvp/f4;)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0}, Lvp/d3;->n0()V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 35
    .line 36
    .line 37
    goto :goto_0

    .line 38
    :catch_0
    move-exception p0

    .line 39
    iget-object v0, v2, Lvp/g1;->i:Lvp/p0;

    .line 40
    .line 41
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 42
    .line 43
    .line 44
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 45
    .line 46
    const-string v1, "Failed to send consent settings to the service"

    .line 47
    .line 48
    invoke-virtual {v0, p0, v1}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    :goto_0
    return-void

    .line 52
    :pswitch_0
    iget-object v0, p0, Lvp/z2;->f:Lvp/d3;

    .line 53
    .line 54
    iget-object v1, v0, Lvp/d3;->h:Lvp/c0;

    .line 55
    .line 56
    iget-object v2, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 57
    .line 58
    check-cast v2, Lvp/g1;

    .line 59
    .line 60
    if-nez v1, :cond_1

    .line 61
    .line 62
    iget-object p0, v2, Lvp/g1;->i:Lvp/p0;

    .line 63
    .line 64
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 65
    .line 66
    .line 67
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 68
    .line 69
    const-string v0, "Discarding data. Failed to send app launch"

    .line 70
    .line 71
    invoke-virtual {p0, v0}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    goto :goto_3

    .line 75
    :cond_1
    :try_start_1
    iget-object p0, p0, Lvp/z2;->e:Lvp/f4;

    .line 76
    .line 77
    iget-object v3, v2, Lvp/g1;->g:Lvp/h;

    .line 78
    .line 79
    sget-object v4, Lvp/z;->b1:Lvp/y;

    .line 80
    .line 81
    const/4 v5, 0x0

    .line 82
    invoke-virtual {v3, v5, v4}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 83
    .line 84
    .line 85
    move-result v3

    .line 86
    if-eqz v3, :cond_2

    .line 87
    .line 88
    invoke-virtual {v0, v1, v5, p0}, Lvp/d3;->s0(Lvp/c0;Loo/a;Lvp/f4;)V

    .line 89
    .line 90
    .line 91
    goto :goto_1

    .line 92
    :catch_1
    move-exception p0

    .line 93
    goto :goto_2

    .line 94
    :cond_2
    :goto_1
    invoke-interface {v1, p0}, Lvp/c0;->J(Lvp/f4;)V

    .line 95
    .line 96
    .line 97
    invoke-virtual {v2}, Lvp/g1;->n()Lvp/j0;

    .line 98
    .line 99
    .line 100
    move-result-object v3

    .line 101
    invoke-virtual {v3}, Lvp/j0;->f0()Z

    .line 102
    .line 103
    .line 104
    iget-object v3, v2, Lvp/g1;->g:Lvp/h;

    .line 105
    .line 106
    invoke-virtual {v3, v5, v4}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 107
    .line 108
    .line 109
    invoke-virtual {v0, v1, v5, p0}, Lvp/d3;->s0(Lvp/c0;Loo/a;Lvp/f4;)V

    .line 110
    .line 111
    .line 112
    invoke-virtual {v0}, Lvp/d3;->n0()V
    :try_end_1
    .catch Landroid/os/RemoteException; {:try_start_1 .. :try_end_1} :catch_1

    .line 113
    .line 114
    .line 115
    goto :goto_3

    .line 116
    :goto_2
    iget-object v0, v2, Lvp/g1;->i:Lvp/p0;

    .line 117
    .line 118
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 119
    .line 120
    .line 121
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 122
    .line 123
    const-string v1, "Failed to send app launch to the service"

    .line 124
    .line 125
    invoke-virtual {v0, p0, v1}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 126
    .line 127
    .line 128
    :goto_3
    return-void

    .line 129
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
