.class public final synthetic Lu/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lrn/i;


# direct methods
.method public synthetic constructor <init>(Lrn/i;I)V
    .locals 0

    .line 1
    iput p2, p0, Lu/v;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lu/v;->e:Lrn/i;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 3

    .line 1
    iget v0, p0, Lu/v;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lu/v;->e:Lrn/i;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Lb81/b;

    .line 11
    .line 12
    iget-object v0, v0, Lb81/b;->f:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v0, Lu/y;

    .line 15
    .line 16
    iget v0, v0, Lu/y;->O:I

    .line 17
    .line 18
    const/16 v1, 0x9

    .line 19
    .line 20
    const/4 v2, 0x0

    .line 21
    if-eq v0, v1, :cond_0

    .line 22
    .line 23
    iget-object p0, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast p0, Lb81/b;

    .line 26
    .line 27
    iget-object p0, p0, Lb81/b;->f:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast p0, Lu/y;

    .line 30
    .line 31
    iget v0, p0, Lu/y;->O:I

    .line 32
    .line 33
    invoke-static {v0}, Lu/w;->p(I)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    const-string v1, "Camera skip reopen at state: "

    .line 38
    .line 39
    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    invoke-virtual {p0, v0, v2}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 44
    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_0
    iget-object v0, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast v0, Lb81/b;

    .line 50
    .line 51
    iget-object v0, v0, Lb81/b;->f:Ljava/lang/Object;

    .line 52
    .line 53
    check-cast v0, Lu/y;

    .line 54
    .line 55
    const-string v1, "Camera onError timeout, reopen it."

    .line 56
    .line 57
    invoke-virtual {v0, v1, v2}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 58
    .line 59
    .line 60
    iget-object v0, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast v0, Lb81/b;

    .line 63
    .line 64
    iget-object v0, v0, Lb81/b;->f:Ljava/lang/Object;

    .line 65
    .line 66
    check-cast v0, Lu/y;

    .line 67
    .line 68
    const/16 v1, 0x8

    .line 69
    .line 70
    invoke-virtual {v0, v1}, Lu/y;->G(I)V

    .line 71
    .line 72
    .line 73
    iget-object p0, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 74
    .line 75
    check-cast p0, Lb81/b;

    .line 76
    .line 77
    iget-object p0, p0, Lb81/b;->f:Ljava/lang/Object;

    .line 78
    .line 79
    check-cast p0, Lu/y;

    .line 80
    .line 81
    iget-object p0, p0, Lu/y;->k:Lu/x;

    .line 82
    .line 83
    invoke-virtual {p0}, Lu/x;->b()V

    .line 84
    .line 85
    .line 86
    :goto_0
    return-void

    .line 87
    :pswitch_0
    iget-object v0, p0, Lrn/i;->f:Ljava/lang/Object;

    .line 88
    .line 89
    check-cast v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 90
    .line 91
    const/4 v1, 0x1

    .line 92
    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;->getAndSet(Z)Z

    .line 93
    .line 94
    .line 95
    move-result v0

    .line 96
    if-eqz v0, :cond_1

    .line 97
    .line 98
    goto :goto_1

    .line 99
    :cond_1
    iget-object v0, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 100
    .line 101
    check-cast v0, Lb81/b;

    .line 102
    .line 103
    iget-object v0, v0, Lb81/b;->f:Ljava/lang/Object;

    .line 104
    .line 105
    check-cast v0, Lu/y;

    .line 106
    .line 107
    iget-object v0, v0, Lu/y;->f:Lj0/h;

    .line 108
    .line 109
    new-instance v1, Lu/v;

    .line 110
    .line 111
    const/4 v2, 0x1

    .line 112
    invoke-direct {v1, p0, v2}, Lu/v;-><init>(Lrn/i;I)V

    .line 113
    .line 114
    .line 115
    invoke-virtual {v0, v1}, Lj0/h;->execute(Ljava/lang/Runnable;)V

    .line 116
    .line 117
    .line 118
    :goto_1
    return-void

    .line 119
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
