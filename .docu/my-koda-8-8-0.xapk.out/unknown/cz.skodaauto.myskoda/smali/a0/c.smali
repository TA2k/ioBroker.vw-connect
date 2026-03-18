.class public final synthetic La0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:La0/e;

.field public final synthetic f:Ly4/h;


# direct methods
.method public synthetic constructor <init>(La0/e;Ly4/h;I)V
    .locals 0

    .line 1
    iput p3, p0, La0/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, La0/c;->e:La0/e;

    .line 4
    .line 5
    iput-object p2, p0, La0/c;->f:Ly4/h;

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
    .locals 3

    .line 1
    iget v0, p0, La0/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x1

    .line 7
    iget-object v1, p0, La0/c;->e:La0/e;

    .line 8
    .line 9
    iput-boolean v0, v1, La0/e;->b:Z

    .line 10
    .line 11
    new-instance v0, Lb0/l;

    .line 12
    .line 13
    const-string v2, "Camera2CameraControl was updated with new options."

    .line 14
    .line 15
    invoke-direct {v0, v2}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    iget-object v2, v1, La0/e;->g:Ly4/h;

    .line 19
    .line 20
    if-eqz v2, :cond_0

    .line 21
    .line 22
    invoke-virtual {v2, v0}, Ly4/h;->d(Ljava/lang/Throwable;)Z

    .line 23
    .line 24
    .line 25
    const/4 v0, 0x0

    .line 26
    iput-object v0, v1, La0/e;->g:Ly4/h;

    .line 27
    .line 28
    :cond_0
    iget-object p0, p0, La0/c;->f:Ly4/h;

    .line 29
    .line 30
    iput-object p0, v1, La0/e;->g:Ly4/h;

    .line 31
    .line 32
    iget-boolean p0, v1, La0/e;->a:Z

    .line 33
    .line 34
    if-eqz p0, :cond_1

    .line 35
    .line 36
    iget-object p0, v1, La0/e;->c:Lu/m;

    .line 37
    .line 38
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 39
    .line 40
    .line 41
    new-instance v0, Lrx/b;

    .line 42
    .line 43
    const/4 v2, 0x4

    .line 44
    invoke-direct {v0, p0, v2}, Lrx/b;-><init>(Ljava/lang/Object;I)V

    .line 45
    .line 46
    .line 47
    invoke-static {v0}, Llp/uf;->b(Ly4/i;)Ly4/k;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    invoke-static {p0}, Lk0/h;->d(Lcom/google/common/util/concurrent/ListenableFuture;)Lcom/google/common/util/concurrent/ListenableFuture;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    new-instance v0, La0/d;

    .line 56
    .line 57
    const/4 v2, 0x0

    .line 58
    invoke-direct {v0, v1, v2}, La0/d;-><init>(Ljava/lang/Object;I)V

    .line 59
    .line 60
    .line 61
    iget-object v2, v1, La0/e;->d:Lj0/h;

    .line 62
    .line 63
    invoke-interface {p0, v2, v0}, Lcom/google/common/util/concurrent/ListenableFuture;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 64
    .line 65
    .line 66
    const/4 p0, 0x0

    .line 67
    iput-boolean p0, v1, La0/e;->b:Z

    .line 68
    .line 69
    :cond_1
    return-void

    .line 70
    :pswitch_0
    const/4 v0, 0x1

    .line 71
    iget-object v1, p0, La0/c;->e:La0/e;

    .line 72
    .line 73
    iput-boolean v0, v1, La0/e;->b:Z

    .line 74
    .line 75
    new-instance v0, Lb0/l;

    .line 76
    .line 77
    const-string v2, "Camera2CameraControl was updated with new options."

    .line 78
    .line 79
    invoke-direct {v0, v2}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    iget-object v2, v1, La0/e;->g:Ly4/h;

    .line 83
    .line 84
    if-eqz v2, :cond_2

    .line 85
    .line 86
    invoke-virtual {v2, v0}, Ly4/h;->d(Ljava/lang/Throwable;)Z

    .line 87
    .line 88
    .line 89
    const/4 v0, 0x0

    .line 90
    iput-object v0, v1, La0/e;->g:Ly4/h;

    .line 91
    .line 92
    :cond_2
    iget-object p0, p0, La0/c;->f:Ly4/h;

    .line 93
    .line 94
    iput-object p0, v1, La0/e;->g:Ly4/h;

    .line 95
    .line 96
    iget-boolean p0, v1, La0/e;->a:Z

    .line 97
    .line 98
    if-eqz p0, :cond_3

    .line 99
    .line 100
    iget-object p0, v1, La0/e;->c:Lu/m;

    .line 101
    .line 102
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 103
    .line 104
    .line 105
    new-instance v0, Lrx/b;

    .line 106
    .line 107
    const/4 v2, 0x4

    .line 108
    invoke-direct {v0, p0, v2}, Lrx/b;-><init>(Ljava/lang/Object;I)V

    .line 109
    .line 110
    .line 111
    invoke-static {v0}, Llp/uf;->b(Ly4/i;)Ly4/k;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    invoke-static {p0}, Lk0/h;->d(Lcom/google/common/util/concurrent/ListenableFuture;)Lcom/google/common/util/concurrent/ListenableFuture;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    new-instance v0, La0/d;

    .line 120
    .line 121
    const/4 v2, 0x0

    .line 122
    invoke-direct {v0, v1, v2}, La0/d;-><init>(Ljava/lang/Object;I)V

    .line 123
    .line 124
    .line 125
    iget-object v2, v1, La0/e;->d:Lj0/h;

    .line 126
    .line 127
    invoke-interface {p0, v2, v0}, Lcom/google/common/util/concurrent/ListenableFuture;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 128
    .line 129
    .line 130
    const/4 p0, 0x0

    .line 131
    iput-boolean p0, v1, La0/e;->b:Z

    .line 132
    .line 133
    :cond_3
    return-void

    .line 134
    nop

    .line 135
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
