.class public final synthetic La0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;ZI)V
    .locals 0

    .line 1
    iput p3, p0, La0/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, La0/b;->f:Ljava/lang/Object;

    .line 4
    .line 5
    iput-boolean p2, p0, La0/b;->e:Z

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 4

    .line 1
    iget v0, p0, La0/b;->d:I

    .line 2
    .line 3
    const/4 v1, 0x4

    .line 4
    const/4 v2, 0x0

    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, La0/b;->f:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Lu/y;

    .line 11
    .line 12
    iget-boolean p0, p0, La0/b;->e:Z

    .line 13
    .line 14
    iput-boolean p0, v0, Lu/y;->J:Z

    .line 15
    .line 16
    if-eqz p0, :cond_1

    .line 17
    .line 18
    iget p0, v0, Lu/y;->O:I

    .line 19
    .line 20
    if-eq p0, v1, :cond_0

    .line 21
    .line 22
    iget p0, v0, Lu/y;->O:I

    .line 23
    .line 24
    const/4 v1, 0x5

    .line 25
    if-ne p0, v1, :cond_1

    .line 26
    .line 27
    :cond_0
    invoke-virtual {v0, v2}, Lu/y;->K(Z)V

    .line 28
    .line 29
    .line 30
    :cond_1
    return-void

    .line 31
    :pswitch_0
    iget-object v0, p0, La0/b;->f:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast v0, Lb81/d;

    .line 34
    .line 35
    iget-boolean p0, p0, La0/b;->e:Z

    .line 36
    .line 37
    iget-object v0, v0, Lb81/d;->f:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast v0, La8/f0;

    .line 40
    .line 41
    sget-object v1, Lw7/w;->a:Ljava/lang/String;

    .line 42
    .line 43
    iget-object v0, v0, La8/f0;->d:La8/i0;

    .line 44
    .line 45
    iget-boolean v1, v0, La8/i0;->r1:Z

    .line 46
    .line 47
    if-ne v1, p0, :cond_2

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_2
    iput-boolean p0, v0, La8/i0;->r1:Z

    .line 51
    .line 52
    iget-object v0, v0, La8/i0;->q:Le30/v;

    .line 53
    .line 54
    new-instance v1, La8/x;

    .line 55
    .line 56
    const/4 v2, 0x1

    .line 57
    invoke-direct {v1, v2, p0}, La8/x;-><init>(IZ)V

    .line 58
    .line 59
    .line 60
    const/16 p0, 0x17

    .line 61
    .line 62
    invoke-virtual {v0, p0, v1}, Le30/v;->e(ILw7/j;)V

    .line 63
    .line 64
    .line 65
    :goto_0
    return-void

    .line 66
    :pswitch_1
    iget-object v0, p0, La0/b;->f:Ljava/lang/Object;

    .line 67
    .line 68
    check-cast v0, La0/e;

    .line 69
    .line 70
    iget-boolean p0, p0, La0/b;->e:Z

    .line 71
    .line 72
    iget-boolean v3, v0, La0/e;->a:Z

    .line 73
    .line 74
    if-ne v3, p0, :cond_3

    .line 75
    .line 76
    goto :goto_1

    .line 77
    :cond_3
    iput-boolean p0, v0, La0/e;->a:Z

    .line 78
    .line 79
    if-eqz p0, :cond_4

    .line 80
    .line 81
    iget-boolean p0, v0, La0/e;->b:Z

    .line 82
    .line 83
    if-eqz p0, :cond_5

    .line 84
    .line 85
    iget-object p0, v0, La0/e;->c:Lu/m;

    .line 86
    .line 87
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 88
    .line 89
    .line 90
    new-instance v3, Lrx/b;

    .line 91
    .line 92
    invoke-direct {v3, p0, v1}, Lrx/b;-><init>(Ljava/lang/Object;I)V

    .line 93
    .line 94
    .line 95
    invoke-static {v3}, Llp/uf;->b(Ly4/i;)Ly4/k;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    invoke-static {p0}, Lk0/h;->d(Lcom/google/common/util/concurrent/ListenableFuture;)Lcom/google/common/util/concurrent/ListenableFuture;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    new-instance v1, La0/d;

    .line 104
    .line 105
    invoke-direct {v1, v0, v2}, La0/d;-><init>(Ljava/lang/Object;I)V

    .line 106
    .line 107
    .line 108
    iget-object v3, v0, La0/e;->d:Lj0/h;

    .line 109
    .line 110
    invoke-interface {p0, v3, v1}, Lcom/google/common/util/concurrent/ListenableFuture;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 111
    .line 112
    .line 113
    iput-boolean v2, v0, La0/e;->b:Z

    .line 114
    .line 115
    goto :goto_1

    .line 116
    :cond_4
    new-instance p0, Lb0/l;

    .line 117
    .line 118
    const-string v1, "The camera control has became inactive."

    .line 119
    .line 120
    invoke-direct {p0, v1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 121
    .line 122
    .line 123
    iget-object v1, v0, La0/e;->g:Ly4/h;

    .line 124
    .line 125
    if-eqz v1, :cond_5

    .line 126
    .line 127
    invoke-virtual {v1, p0}, Ly4/h;->d(Ljava/lang/Throwable;)Z

    .line 128
    .line 129
    .line 130
    const/4 p0, 0x0

    .line 131
    iput-object p0, v0, La0/e;->g:Ly4/h;

    .line 132
    .line 133
    :cond_5
    :goto_1
    return-void

    .line 134
    nop

    .line 135
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
