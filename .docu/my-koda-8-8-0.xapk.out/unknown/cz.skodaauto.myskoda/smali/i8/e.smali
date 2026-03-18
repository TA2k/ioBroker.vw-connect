.class public final Li8/e;
.super La8/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Handler$Callback;


# instance fields
.field public A:I

.field public B:Ll9/e;

.field public C:Ll9/g;

.field public D:Ll9/c;

.field public E:Ll9/c;

.field public F:I

.field public final G:Landroid/os/Handler;

.field public final H:La8/f0;

.field public final I:Lb81/d;

.field public J:Z

.field public K:Z

.field public L:Lt7/o;

.field public M:J

.field public N:J

.field public final v:Lrb0/a;

.field public final w:Lz7/e;

.field public x:Li8/a;

.field public final y:Li8/d;

.field public z:Z


# direct methods
.method public constructor <init>(La8/f0;Landroid/os/Looper;)V
    .locals 2

    .line 1
    sget-object v0, Li8/d;->e1:Lhu/q;

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    invoke-direct {p0, v1}, La8/f;-><init>(I)V

    .line 5
    .line 6
    .line 7
    iput-object p1, p0, Li8/e;->H:La8/f0;

    .line 8
    .line 9
    if-nez p2, :cond_0

    .line 10
    .line 11
    const/4 p1, 0x0

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    new-instance p1, Landroid/os/Handler;

    .line 14
    .line 15
    invoke-direct {p1, p2, p0}, Landroid/os/Handler;-><init>(Landroid/os/Looper;Landroid/os/Handler$Callback;)V

    .line 16
    .line 17
    .line 18
    :goto_0
    iput-object p1, p0, Li8/e;->G:Landroid/os/Handler;

    .line 19
    .line 20
    iput-object v0, p0, Li8/e;->y:Li8/d;

    .line 21
    .line 22
    new-instance p1, Lrb0/a;

    .line 23
    .line 24
    const/16 p2, 0x8

    .line 25
    .line 26
    invoke-direct {p1, p2}, Lrb0/a;-><init>(I)V

    .line 27
    .line 28
    .line 29
    iput-object p1, p0, Li8/e;->v:Lrb0/a;

    .line 30
    .line 31
    new-instance p1, Lz7/e;

    .line 32
    .line 33
    const/4 p2, 0x1

    .line 34
    invoke-direct {p1, p2}, Lz7/e;-><init>(I)V

    .line 35
    .line 36
    .line 37
    iput-object p1, p0, Li8/e;->w:Lz7/e;

    .line 38
    .line 39
    new-instance p1, Lb81/d;

    .line 40
    .line 41
    const/4 v0, 0x0

    .line 42
    invoke-direct {p1, p2, v0}, Lb81/d;-><init>(IZ)V

    .line 43
    .line 44
    .line 45
    iput-object p1, p0, Li8/e;->I:Lb81/d;

    .line 46
    .line 47
    const-wide p1, -0x7fffffffffffffffL    # -4.9E-324

    .line 48
    .line 49
    .line 50
    .line 51
    .line 52
    iput-wide p1, p0, Li8/e;->N:J

    .line 53
    .line 54
    iput-wide p1, p0, Li8/e;->M:J

    .line 55
    .line 56
    return-void
.end method


# virtual methods
.method public final B(Lt7/o;)I
    .locals 3

    .line 1
    iget-object v0, p1, Lt7/o;->n:Ljava/lang/String;

    .line 2
    .line 3
    const-string v1, "application/x-media3-cues"

    .line 4
    .line 5
    invoke-static {v0, v1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    iget-object v1, p1, Lt7/o;->n:Ljava/lang/String;

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    if-nez v0, :cond_2

    .line 13
    .line 14
    iget-object p0, p0, Li8/e;->y:Li8/d;

    .line 15
    .line 16
    check-cast p0, Lhu/q;

    .line 17
    .line 18
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 19
    .line 20
    .line 21
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast p0, Lwe0/b;

    .line 24
    .line 25
    invoke-virtual {p0, p1}, Lwe0/b;->i(Lt7/o;)Z

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    if-nez p0, :cond_2

    .line 30
    .line 31
    const-string p0, "application/cea-608"

    .line 32
    .line 33
    invoke-static {v1, p0}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result p0

    .line 37
    if-nez p0, :cond_2

    .line 38
    .line 39
    const-string p0, "application/x-mp4-cea-608"

    .line 40
    .line 41
    invoke-static {v1, p0}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result p0

    .line 45
    if-nez p0, :cond_2

    .line 46
    .line 47
    const-string p0, "application/cea-708"

    .line 48
    .line 49
    invoke-static {v1, p0}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result p0

    .line 53
    if-eqz p0, :cond_0

    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_0
    invoke-static {v1}, Lt7/d0;->k(Ljava/lang/String;)Z

    .line 57
    .line 58
    .line 59
    move-result p0

    .line 60
    if-eqz p0, :cond_1

    .line 61
    .line 62
    const/4 p0, 0x1

    .line 63
    invoke-static {p0, v2, v2, v2}, La8/f;->f(IIII)I

    .line 64
    .line 65
    .line 66
    move-result p0

    .line 67
    return p0

    .line 68
    :cond_1
    invoke-static {v2, v2, v2, v2}, La8/f;->f(IIII)I

    .line 69
    .line 70
    .line 71
    move-result p0

    .line 72
    return p0

    .line 73
    :cond_2
    :goto_0
    iget p0, p1, Lt7/o;->O:I

    .line 74
    .line 75
    if-nez p0, :cond_3

    .line 76
    .line 77
    const/4 p0, 0x4

    .line 78
    goto :goto_1

    .line 79
    :cond_3
    const/4 p0, 0x2

    .line 80
    :goto_1
    invoke-static {p0, v2, v2, v2}, La8/f;->f(IIII)I

    .line 81
    .line 82
    .line 83
    move-result p0

    .line 84
    return p0
.end method

.method public final D()V
    .locals 3

    .line 1
    iget-object v0, p0, Li8/e;->L:Lt7/o;

    .line 2
    .line 3
    iget-object v0, v0, Lt7/o;->n:Ljava/lang/String;

    .line 4
    .line 5
    const-string v1, "application/cea-608"

    .line 6
    .line 7
    invoke-static {v0, v1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-nez v0, :cond_1

    .line 12
    .line 13
    iget-object v0, p0, Li8/e;->L:Lt7/o;

    .line 14
    .line 15
    iget-object v0, v0, Lt7/o;->n:Ljava/lang/String;

    .line 16
    .line 17
    const-string v1, "application/x-mp4-cea-608"

    .line 18
    .line 19
    invoke-static {v0, v1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-nez v0, :cond_1

    .line 24
    .line 25
    iget-object v0, p0, Li8/e;->L:Lt7/o;

    .line 26
    .line 27
    iget-object v0, v0, Lt7/o;->n:Ljava/lang/String;

    .line 28
    .line 29
    const-string v1, "application/cea-708"

    .line 30
    .line 31
    invoke-static {v0, v1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    if-eqz v0, :cond_0

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_0
    const/4 v0, 0x0

    .line 39
    goto :goto_1

    .line 40
    :cond_1
    :goto_0
    const/4 v0, 0x1

    .line 41
    :goto_1
    new-instance v1, Ljava/lang/StringBuilder;

    .line 42
    .line 43
    const-string v2, "Legacy decoding is disabled, can\'t handle "

    .line 44
    .line 45
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    iget-object p0, p0, Li8/e;->L:Lt7/o;

    .line 49
    .line 50
    iget-object p0, p0, Lt7/o;->n:Ljava/lang/String;

    .line 51
    .line 52
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    const-string p0, " samples (expected application/x-media3-cues)."

    .line 56
    .line 57
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    invoke-static {p0, v0}, Lw7/a;->i(Ljava/lang/String;Z)V

    .line 65
    .line 66
    .line 67
    return-void
.end method

.method public final E()J
    .locals 4

    .line 1
    iget v0, p0, Li8/e;->F:I

    .line 2
    .line 3
    const/4 v1, -0x1

    .line 4
    const-wide v2, 0x7fffffffffffffffL

    .line 5
    .line 6
    .line 7
    .line 8
    .line 9
    if-ne v0, v1, :cond_0

    .line 10
    .line 11
    return-wide v2

    .line 12
    :cond_0
    iget-object v0, p0, Li8/e;->D:Ll9/c;

    .line 13
    .line 14
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    iget v0, p0, Li8/e;->F:I

    .line 18
    .line 19
    iget-object v1, p0, Li8/e;->D:Ll9/c;

    .line 20
    .line 21
    invoke-virtual {v1}, Ll9/c;->k()I

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    if-lt v0, v1, :cond_1

    .line 26
    .line 27
    return-wide v2

    .line 28
    :cond_1
    iget-object v0, p0, Li8/e;->D:Ll9/c;

    .line 29
    .line 30
    iget p0, p0, Li8/e;->F:I

    .line 31
    .line 32
    invoke-virtual {v0, p0}, Ll9/c;->i(I)J

    .line 33
    .line 34
    .line 35
    move-result-wide v0

    .line 36
    return-wide v0
.end method

.method public final F(J)J
    .locals 2

    .line 1
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 2
    .line 3
    .line 4
    .line 5
    .line 6
    cmp-long v0, p1, v0

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 v0, 0x0

    .line 13
    :goto_0
    invoke-static {v0}, Lw7/a;->j(Z)V

    .line 14
    .line 15
    .line 16
    iget-wide v0, p0, La8/f;->n:J

    .line 17
    .line 18
    sub-long/2addr p1, v0

    .line 19
    return-wide p1
.end method

.method public final G()V
    .locals 7

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Li8/e;->z:Z

    .line 3
    .line 4
    iget-object v1, p0, Li8/e;->L:Lt7/o;

    .line 5
    .line 6
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    iget-object v2, p0, Li8/e;->y:Li8/d;

    .line 10
    .line 11
    check-cast v2, Lhu/q;

    .line 12
    .line 13
    iget-object v2, v2, Lhu/q;->e:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v2, Lwe0/b;

    .line 16
    .line 17
    iget-object v3, v1, Lt7/o;->n:Ljava/lang/String;

    .line 18
    .line 19
    iget v4, v1, Lt7/o;->K:I

    .line 20
    .line 21
    if-eqz v3, :cond_3

    .line 22
    .line 23
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 24
    .line 25
    .line 26
    move-result v5

    .line 27
    const/4 v6, -0x1

    .line 28
    sparse-switch v5, :sswitch_data_0

    .line 29
    .line 30
    .line 31
    :goto_0
    move v0, v6

    .line 32
    goto :goto_1

    .line 33
    :sswitch_0
    const-string v0, "application/cea-708"

    .line 34
    .line 35
    invoke-virtual {v3, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    if-nez v0, :cond_0

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_0
    const/4 v0, 0x2

    .line 43
    goto :goto_1

    .line 44
    :sswitch_1
    const-string v5, "application/cea-608"

    .line 45
    .line 46
    invoke-virtual {v3, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v5

    .line 50
    if-nez v5, :cond_2

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :sswitch_2
    const-string v0, "application/x-mp4-cea-608"

    .line 54
    .line 55
    invoke-virtual {v3, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result v0

    .line 59
    if-nez v0, :cond_1

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_1
    const/4 v0, 0x0

    .line 63
    :cond_2
    :goto_1
    packed-switch v0, :pswitch_data_0

    .line 64
    .line 65
    .line 66
    goto :goto_2

    .line 67
    :pswitch_0
    new-instance v0, Lm9/g;

    .line 68
    .line 69
    iget-object v1, v1, Lt7/o;->q:Ljava/util/List;

    .line 70
    .line 71
    invoke-direct {v0, v4, v1}, Lm9/g;-><init>(ILjava/util/List;)V

    .line 72
    .line 73
    .line 74
    goto :goto_3

    .line 75
    :pswitch_1
    new-instance v0, Lm9/c;

    .line 76
    .line 77
    invoke-direct {v0, v3, v4}, Lm9/c;-><init>(Ljava/lang/String;I)V

    .line 78
    .line 79
    .line 80
    goto :goto_3

    .line 81
    :cond_3
    :goto_2
    invoke-virtual {v2, v1}, Lwe0/b;->i(Lt7/o;)Z

    .line 82
    .line 83
    .line 84
    move-result v0

    .line 85
    if-eqz v0, :cond_4

    .line 86
    .line 87
    invoke-virtual {v2, v1}, Lwe0/b;->f(Lt7/o;)Ll9/j;

    .line 88
    .line 89
    .line 90
    move-result-object v0

    .line 91
    new-instance v1, Li8/b;

    .line 92
    .line 93
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 94
    .line 95
    .line 96
    move-result-object v2

    .line 97
    invoke-virtual {v2}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object v2

    .line 101
    const-string v3, "Decoder"

    .line 102
    .line 103
    invoke-virtual {v2, v3}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    invoke-direct {v1, v0}, Li8/b;-><init>(Ll9/j;)V

    .line 107
    .line 108
    .line 109
    move-object v0, v1

    .line 110
    :goto_3
    iput-object v0, p0, Li8/e;->B:Ll9/e;

    .line 111
    .line 112
    iget-wide v1, p0, La8/f;->o:J

    .line 113
    .line 114
    invoke-interface {v0, v1, v2}, Lz7/c;->d(J)V

    .line 115
    .line 116
    .line 117
    return-void

    .line 118
    :cond_4
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 119
    .line 120
    const-string v0, "Attempted to create decoder for unsupported MIME type: "

    .line 121
    .line 122
    invoke-static {v0, v3}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 123
    .line 124
    .line 125
    move-result-object v0

    .line 126
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 127
    .line 128
    .line 129
    throw p0

    .line 130
    nop

    .line 131
    :sswitch_data_0
    .sparse-switch
        0x37713300 -> :sswitch_2
        0x5d578071 -> :sswitch_1
        0x5d578432 -> :sswitch_0
    .end sparse-switch

    .line 132
    .line 133
    .line 134
    .line 135
    .line 136
    .line 137
    .line 138
    .line 139
    .line 140
    .line 141
    .line 142
    .line 143
    .line 144
    .line 145
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final H(Lv7/c;)V
    .locals 3

    .line 1
    iget-object v0, p1, Lv7/c;->a:Lhr/x0;

    .line 2
    .line 3
    iget-object p0, p0, Li8/e;->H:La8/f0;

    .line 4
    .line 5
    iget-object v1, p0, La8/f0;->d:La8/i0;

    .line 6
    .line 7
    iget-object v1, v1, La8/i0;->q:Le30/v;

    .line 8
    .line 9
    new-instance v2, La8/d0;

    .line 10
    .line 11
    invoke-direct {v2, v0}, La8/d0;-><init>(Lhr/x0;)V

    .line 12
    .line 13
    .line 14
    const/16 v0, 0x1b

    .line 15
    .line 16
    invoke-virtual {v1, v0, v2}, Le30/v;->e(ILw7/j;)V

    .line 17
    .line 18
    .line 19
    iget-object p0, p0, La8/f0;->d:La8/i0;

    .line 20
    .line 21
    iput-object p1, p0, La8/i0;->s1:Lv7/c;

    .line 22
    .line 23
    iget-object p0, p0, La8/i0;->q:Le30/v;

    .line 24
    .line 25
    new-instance v1, La8/t;

    .line 26
    .line 27
    const/4 v2, 0x2

    .line 28
    invoke-direct {v1, p1, v2}, La8/t;-><init>(Ljava/lang/Object;I)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {p0, v0, v1}, Le30/v;->e(ILw7/j;)V

    .line 32
    .line 33
    .line 34
    return-void
.end method

.method public final I()V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-object v0, p0, Li8/e;->C:Ll9/g;

    .line 3
    .line 4
    const/4 v1, -0x1

    .line 5
    iput v1, p0, Li8/e;->F:I

    .line 6
    .line 7
    iget-object v1, p0, Li8/e;->D:Ll9/c;

    .line 8
    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    invoke-virtual {v1}, Lz7/f;->n()V

    .line 12
    .line 13
    .line 14
    iput-object v0, p0, Li8/e;->D:Ll9/c;

    .line 15
    .line 16
    :cond_0
    iget-object v1, p0, Li8/e;->E:Ll9/c;

    .line 17
    .line 18
    if-eqz v1, :cond_1

    .line 19
    .line 20
    invoke-virtual {v1}, Lz7/f;->n()V

    .line 21
    .line 22
    .line 23
    iput-object v0, p0, Li8/e;->E:Ll9/c;

    .line 24
    .line 25
    :cond_1
    return-void
.end method

.method public final handleMessage(Landroid/os/Message;)Z
    .locals 2

    .line 1
    iget v0, p1, Landroid/os/Message;->what:I

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-ne v0, v1, :cond_0

    .line 5
    .line 6
    iget-object p1, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p1, Lv7/c;

    .line 9
    .line 10
    invoke-virtual {p0, p1}, Li8/e;->H(Lv7/c;)V

    .line 11
    .line 12
    .line 13
    return v1

    .line 14
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 15
    .line 16
    invoke-direct {p0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 17
    .line 18
    .line 19
    throw p0
.end method

.method public final k()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "TextRenderer"

    .line 2
    .line 3
    return-object p0
.end method

.method public final m()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Li8/e;->K:Z

    .line 2
    .line 3
    return p0
.end method

.method public final o()Z
    .locals 6

    .line 1
    iget-object v0, p0, Li8/e;->L:Lt7/o;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    goto :goto_0

    .line 7
    :cond_0
    iget-object v0, v0, Lt7/o;->n:Ljava/lang/String;

    .line 8
    .line 9
    const-string v2, "application/x-media3-cues"

    .line 10
    .line 11
    invoke-static {v0, v2}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_2

    .line 16
    .line 17
    iget-object v0, p0, Li8/e;->x:Li8/a;

    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 20
    .line 21
    .line 22
    iget-wide v2, p0, Li8/e;->M:J

    .line 23
    .line 24
    invoke-interface {v0, v2, v3}, Li8/a;->d(J)J

    .line 25
    .line 26
    .line 27
    move-result-wide v2

    .line 28
    const-wide/high16 v4, -0x8000000000000000L

    .line 29
    .line 30
    cmp-long v0, v2, v4

    .line 31
    .line 32
    if-eqz v0, :cond_1

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_1
    :try_start_0
    iget-object p0, p0, La8/f;->l:Lh8/y0;

    .line 36
    .line 37
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 38
    .line 39
    .line 40
    invoke-interface {p0}, Lh8/y0;->c()V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 41
    .line 42
    .line 43
    return v1

    .line 44
    :cond_2
    iget-boolean v0, p0, Li8/e;->K:Z

    .line 45
    .line 46
    if-nez v0, :cond_6

    .line 47
    .line 48
    iget-boolean v0, p0, Li8/e;->J:Z

    .line 49
    .line 50
    if-eqz v0, :cond_5

    .line 51
    .line 52
    iget-object v0, p0, Li8/e;->D:Ll9/c;

    .line 53
    .line 54
    iget-wide v2, p0, Li8/e;->M:J

    .line 55
    .line 56
    if-eqz v0, :cond_3

    .line 57
    .line 58
    invoke-virtual {v0}, Ll9/c;->k()I

    .line 59
    .line 60
    .line 61
    move-result v4

    .line 62
    if-lez v4, :cond_3

    .line 63
    .line 64
    invoke-virtual {v0}, Ll9/c;->k()I

    .line 65
    .line 66
    .line 67
    move-result v4

    .line 68
    sub-int/2addr v4, v1

    .line 69
    invoke-virtual {v0, v4}, Ll9/c;->i(I)J

    .line 70
    .line 71
    .line 72
    move-result-wide v4

    .line 73
    cmp-long v0, v4, v2

    .line 74
    .line 75
    if-lez v0, :cond_3

    .line 76
    .line 77
    goto :goto_0

    .line 78
    :cond_3
    iget-object v0, p0, Li8/e;->E:Ll9/c;

    .line 79
    .line 80
    iget-wide v2, p0, Li8/e;->M:J

    .line 81
    .line 82
    if-eqz v0, :cond_4

    .line 83
    .line 84
    invoke-virtual {v0}, Ll9/c;->k()I

    .line 85
    .line 86
    .line 87
    move-result v4

    .line 88
    if-lez v4, :cond_4

    .line 89
    .line 90
    invoke-virtual {v0}, Ll9/c;->k()I

    .line 91
    .line 92
    .line 93
    move-result v4

    .line 94
    sub-int/2addr v4, v1

    .line 95
    invoke-virtual {v0, v4}, Ll9/c;->i(I)J

    .line 96
    .line 97
    .line 98
    move-result-wide v4

    .line 99
    cmp-long v0, v4, v2

    .line 100
    .line 101
    if-lez v0, :cond_4

    .line 102
    .line 103
    goto :goto_0

    .line 104
    :cond_4
    iget-object p0, p0, Li8/e;->C:Ll9/g;

    .line 105
    .line 106
    if-nez p0, :cond_6

    .line 107
    .line 108
    :cond_5
    :goto_0
    return v1

    .line 109
    :catch_0
    :cond_6
    const/4 p0, 0x0

    .line 110
    return p0
.end method

.method public final p()V
    .locals 7

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-object v0, p0, Li8/e;->L:Lt7/o;

    .line 3
    .line 4
    const-wide v1, -0x7fffffffffffffffL    # -4.9E-324

    .line 5
    .line 6
    .line 7
    .line 8
    .line 9
    iput-wide v1, p0, Li8/e;->N:J

    .line 10
    .line 11
    new-instance v3, Lv7/c;

    .line 12
    .line 13
    sget-object v4, Lhr/x0;->h:Lhr/x0;

    .line 14
    .line 15
    iget-wide v5, p0, Li8/e;->M:J

    .line 16
    .line 17
    invoke-virtual {p0, v5, v6}, Li8/e;->F(J)J

    .line 18
    .line 19
    .line 20
    invoke-direct {v3, v4}, Lv7/c;-><init>(Ljava/util/List;)V

    .line 21
    .line 22
    .line 23
    iget-object v4, p0, Li8/e;->G:Landroid/os/Handler;

    .line 24
    .line 25
    if-eqz v4, :cond_0

    .line 26
    .line 27
    const/4 v5, 0x1

    .line 28
    invoke-virtual {v4, v5, v3}, Landroid/os/Handler;->obtainMessage(ILjava/lang/Object;)Landroid/os/Message;

    .line 29
    .line 30
    .line 31
    move-result-object v3

    .line 32
    invoke-virtual {v3}, Landroid/os/Message;->sendToTarget()V

    .line 33
    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    invoke-virtual {p0, v3}, Li8/e;->H(Lv7/c;)V

    .line 37
    .line 38
    .line 39
    :goto_0
    iput-wide v1, p0, Li8/e;->M:J

    .line 40
    .line 41
    iget-object v1, p0, Li8/e;->B:Ll9/e;

    .line 42
    .line 43
    if-eqz v1, :cond_1

    .line 44
    .line 45
    invoke-virtual {p0}, Li8/e;->I()V

    .line 46
    .line 47
    .line 48
    iget-object v1, p0, Li8/e;->B:Ll9/e;

    .line 49
    .line 50
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 51
    .line 52
    .line 53
    invoke-interface {v1}, Lz7/c;->b()V

    .line 54
    .line 55
    .line 56
    iput-object v0, p0, Li8/e;->B:Ll9/e;

    .line 57
    .line 58
    const/4 v0, 0x0

    .line 59
    iput v0, p0, Li8/e;->A:I

    .line 60
    .line 61
    :cond_1
    return-void
.end method

.method public final r(JZ)V
    .locals 2

    .line 1
    iput-wide p1, p0, Li8/e;->M:J

    .line 2
    .line 3
    iget-object p1, p0, Li8/e;->x:Li8/a;

    .line 4
    .line 5
    if-eqz p1, :cond_0

    .line 6
    .line 7
    invoke-interface {p1}, Li8/a;->clear()V

    .line 8
    .line 9
    .line 10
    :cond_0
    new-instance p1, Lv7/c;

    .line 11
    .line 12
    sget-object p2, Lhr/x0;->h:Lhr/x0;

    .line 13
    .line 14
    iget-wide v0, p0, Li8/e;->M:J

    .line 15
    .line 16
    invoke-virtual {p0, v0, v1}, Li8/e;->F(J)J

    .line 17
    .line 18
    .line 19
    invoke-direct {p1, p2}, Lv7/c;-><init>(Ljava/util/List;)V

    .line 20
    .line 21
    .line 22
    iget-object p2, p0, Li8/e;->G:Landroid/os/Handler;

    .line 23
    .line 24
    if-eqz p2, :cond_1

    .line 25
    .line 26
    const/4 p3, 0x1

    .line 27
    invoke-virtual {p2, p3, p1}, Landroid/os/Handler;->obtainMessage(ILjava/lang/Object;)Landroid/os/Message;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    invoke-virtual {p1}, Landroid/os/Message;->sendToTarget()V

    .line 32
    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_1
    invoke-virtual {p0, p1}, Li8/e;->H(Lv7/c;)V

    .line 36
    .line 37
    .line 38
    :goto_0
    const/4 p1, 0x0

    .line 39
    iput-boolean p1, p0, Li8/e;->J:Z

    .line 40
    .line 41
    iput-boolean p1, p0, Li8/e;->K:Z

    .line 42
    .line 43
    const-wide p2, -0x7fffffffffffffffL    # -4.9E-324

    .line 44
    .line 45
    .line 46
    .line 47
    .line 48
    iput-wide p2, p0, Li8/e;->N:J

    .line 49
    .line 50
    iget-object p2, p0, Li8/e;->L:Lt7/o;

    .line 51
    .line 52
    if-eqz p2, :cond_3

    .line 53
    .line 54
    iget-object p2, p2, Lt7/o;->n:Ljava/lang/String;

    .line 55
    .line 56
    const-string p3, "application/x-media3-cues"

    .line 57
    .line 58
    invoke-static {p2, p3}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    move-result p2

    .line 62
    if-nez p2, :cond_3

    .line 63
    .line 64
    iget p2, p0, Li8/e;->A:I

    .line 65
    .line 66
    if-eqz p2, :cond_2

    .line 67
    .line 68
    invoke-virtual {p0}, Li8/e;->I()V

    .line 69
    .line 70
    .line 71
    iget-object p2, p0, Li8/e;->B:Ll9/e;

    .line 72
    .line 73
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 74
    .line 75
    .line 76
    invoke-interface {p2}, Lz7/c;->b()V

    .line 77
    .line 78
    .line 79
    const/4 p2, 0x0

    .line 80
    iput-object p2, p0, Li8/e;->B:Ll9/e;

    .line 81
    .line 82
    iput p1, p0, Li8/e;->A:I

    .line 83
    .line 84
    invoke-virtual {p0}, Li8/e;->G()V

    .line 85
    .line 86
    .line 87
    return-void

    .line 88
    :cond_2
    invoke-virtual {p0}, Li8/e;->I()V

    .line 89
    .line 90
    .line 91
    iget-object p1, p0, Li8/e;->B:Ll9/e;

    .line 92
    .line 93
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 94
    .line 95
    .line 96
    invoke-interface {p1}, Lz7/c;->flush()V

    .line 97
    .line 98
    .line 99
    iget-wide p2, p0, La8/f;->o:J

    .line 100
    .line 101
    invoke-interface {p1, p2, p3}, Lz7/c;->d(J)V

    .line 102
    .line 103
    .line 104
    :cond_3
    return-void
.end method

.method public final w([Lt7/o;JJLh8/b0;)V
    .locals 0

    .line 1
    const/4 p2, 0x0

    .line 2
    aget-object p1, p1, p2

    .line 3
    .line 4
    iput-object p1, p0, Li8/e;->L:Lt7/o;

    .line 5
    .line 6
    iget-object p1, p1, Lt7/o;->n:Ljava/lang/String;

    .line 7
    .line 8
    const-string p2, "application/x-media3-cues"

    .line 9
    .line 10
    invoke-static {p1, p2}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result p1

    .line 14
    const/4 p2, 0x1

    .line 15
    if-nez p1, :cond_1

    .line 16
    .line 17
    invoke-virtual {p0}, Li8/e;->D()V

    .line 18
    .line 19
    .line 20
    iget-object p1, p0, Li8/e;->B:Ll9/e;

    .line 21
    .line 22
    if-eqz p1, :cond_0

    .line 23
    .line 24
    iput p2, p0, Li8/e;->A:I

    .line 25
    .line 26
    return-void

    .line 27
    :cond_0
    invoke-virtual {p0}, Li8/e;->G()V

    .line 28
    .line 29
    .line 30
    return-void

    .line 31
    :cond_1
    iget-object p1, p0, Li8/e;->L:Lt7/o;

    .line 32
    .line 33
    iget p1, p1, Lt7/o;->L:I

    .line 34
    .line 35
    if-ne p1, p2, :cond_2

    .line 36
    .line 37
    new-instance p1, Li8/c;

    .line 38
    .line 39
    invoke-direct {p1}, Li8/c;-><init>()V

    .line 40
    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_2
    new-instance p1, Lbn/c;

    .line 44
    .line 45
    const/4 p2, 0x1

    .line 46
    invoke-direct {p1, p2}, Lbn/c;-><init>(I)V

    .line 47
    .line 48
    .line 49
    :goto_0
    iput-object p1, p0, Li8/e;->x:Li8/a;

    .line 50
    .line 51
    return-void
.end method

.method public final y(JJ)V
    .locals 18

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-wide/from16 v2, p1

    .line 4
    .line 5
    iget-boolean v0, v1, La8/f;->q:Z

    .line 6
    .line 7
    const/4 v4, 0x1

    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    iget-wide v5, v1, Li8/e;->N:J

    .line 11
    .line 12
    const-wide v7, -0x7fffffffffffffffL    # -4.9E-324

    .line 13
    .line 14
    .line 15
    .line 16
    .line 17
    cmp-long v0, v5, v7

    .line 18
    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    cmp-long v0, v2, v5

    .line 22
    .line 23
    if-ltz v0, :cond_0

    .line 24
    .line 25
    invoke-virtual {v1}, Li8/e;->I()V

    .line 26
    .line 27
    .line 28
    iput-boolean v4, v1, Li8/e;->K:Z

    .line 29
    .line 30
    :cond_0
    iget-boolean v0, v1, Li8/e;->K:Z

    .line 31
    .line 32
    if-eqz v0, :cond_1

    .line 33
    .line 34
    goto/16 :goto_10

    .line 35
    .line 36
    :cond_1
    iget-object v0, v1, Li8/e;->L:Lt7/o;

    .line 37
    .line 38
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 39
    .line 40
    .line 41
    iget-object v0, v0, Lt7/o;->n:Ljava/lang/String;

    .line 42
    .line 43
    const-string v5, "application/x-media3-cues"

    .line 44
    .line 45
    invoke-static {v0, v5}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v0

    .line 49
    iget-object v5, v1, Li8/e;->G:Landroid/os/Handler;

    .line 50
    .line 51
    const/4 v6, 0x4

    .line 52
    const/4 v7, -0x4

    .line 53
    iget-object v8, v1, Li8/e;->I:Lb81/d;

    .line 54
    .line 55
    const/4 v9, 0x0

    .line 56
    if-eqz v0, :cond_a

    .line 57
    .line 58
    iget-object v0, v1, Li8/e;->x:Li8/a;

    .line 59
    .line 60
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 61
    .line 62
    .line 63
    iget-boolean v0, v1, Li8/e;->J:Z

    .line 64
    .line 65
    if-eqz v0, :cond_2

    .line 66
    .line 67
    goto/16 :goto_1

    .line 68
    .line 69
    :cond_2
    iget-object v0, v1, Li8/e;->w:Lz7/e;

    .line 70
    .line 71
    invoke-virtual {v1, v8, v0, v9}, La8/f;->x(Lb81/d;Lz7/e;I)I

    .line 72
    .line 73
    .line 74
    move-result v8

    .line 75
    if-eq v8, v7, :cond_3

    .line 76
    .line 77
    goto/16 :goto_1

    .line 78
    .line 79
    :cond_3
    invoke-virtual {v0, v6}, Lkq/d;->c(I)Z

    .line 80
    .line 81
    .line 82
    move-result v6

    .line 83
    if-eqz v6, :cond_4

    .line 84
    .line 85
    iput-boolean v4, v1, Li8/e;->J:Z

    .line 86
    .line 87
    goto :goto_1

    .line 88
    :cond_4
    invoke-virtual {v0}, Lz7/e;->p()V

    .line 89
    .line 90
    .line 91
    iget-object v6, v0, Lz7/e;->h:Ljava/nio/ByteBuffer;

    .line 92
    .line 93
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 94
    .line 95
    .line 96
    iget-wide v11, v0, Lz7/e;->j:J

    .line 97
    .line 98
    invoke-virtual {v6}, Ljava/nio/ByteBuffer;->array()[B

    .line 99
    .line 100
    .line 101
    move-result-object v7

    .line 102
    invoke-virtual {v6}, Ljava/nio/ByteBuffer;->arrayOffset()I

    .line 103
    .line 104
    .line 105
    move-result v8

    .line 106
    invoke-virtual {v6}, Ljava/nio/Buffer;->limit()I

    .line 107
    .line 108
    .line 109
    move-result v6

    .line 110
    iget-object v10, v1, Li8/e;->v:Lrb0/a;

    .line 111
    .line 112
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 113
    .line 114
    .line 115
    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    .line 116
    .line 117
    .line 118
    move-result-object v10

    .line 119
    invoke-virtual {v10, v7, v8, v6}, Landroid/os/Parcel;->unmarshall([BII)V

    .line 120
    .line 121
    .line 122
    invoke-virtual {v10, v9}, Landroid/os/Parcel;->setDataPosition(I)V

    .line 123
    .line 124
    .line 125
    const-class v6, Landroid/os/Bundle;

    .line 126
    .line 127
    invoke-virtual {v6}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 128
    .line 129
    .line 130
    move-result-object v6

    .line 131
    invoke-virtual {v10, v6}, Landroid/os/Parcel;->readBundle(Ljava/lang/ClassLoader;)Landroid/os/Bundle;

    .line 132
    .line 133
    .line 134
    move-result-object v6

    .line 135
    invoke-virtual {v10}, Landroid/os/Parcel;->recycle()V

    .line 136
    .line 137
    .line 138
    const-string v7, "c"

    .line 139
    .line 140
    invoke-virtual {v6, v7}, Landroid/os/Bundle;->getParcelableArrayList(Ljava/lang/String;)Ljava/util/ArrayList;

    .line 141
    .line 142
    .line 143
    move-result-object v7

    .line 144
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 145
    .line 146
    .line 147
    new-instance v10, Ll9/a;

    .line 148
    .line 149
    new-instance v8, Lj9/d;

    .line 150
    .line 151
    const/4 v13, 0x6

    .line 152
    invoke-direct {v8, v13}, Lj9/d;-><init>(I)V

    .line 153
    .line 154
    .line 155
    invoke-static {}, Lhr/h0;->o()Lhr/e0;

    .line 156
    .line 157
    .line 158
    move-result-object v13

    .line 159
    :goto_0
    invoke-interface {v7}, Ljava/util/List;->size()I

    .line 160
    .line 161
    .line 162
    move-result v14

    .line 163
    if-ge v9, v14, :cond_5

    .line 164
    .line 165
    invoke-interface {v7, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-result-object v14

    .line 169
    check-cast v14, Landroid/os/Bundle;

    .line 170
    .line 171
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 172
    .line 173
    .line 174
    invoke-virtual {v8, v14}, Lj9/d;->apply(Ljava/lang/Object;)Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    move-result-object v14

    .line 178
    invoke-virtual {v13, v14}, Lhr/b0;->a(Ljava/lang/Object;)V

    .line 179
    .line 180
    .line 181
    add-int/lit8 v9, v9, 0x1

    .line 182
    .line 183
    goto :goto_0

    .line 184
    :cond_5
    invoke-virtual {v13}, Lhr/e0;->i()Lhr/x0;

    .line 185
    .line 186
    .line 187
    move-result-object v15

    .line 188
    const-string v7, "d"

    .line 189
    .line 190
    invoke-virtual {v6, v7}, Landroid/os/BaseBundle;->getLong(Ljava/lang/String;)J

    .line 191
    .line 192
    .line 193
    move-result-wide v13

    .line 194
    invoke-direct/range {v10 .. v15}, Ll9/a;-><init>(JJLjava/util/List;)V

    .line 195
    .line 196
    .line 197
    invoke-virtual {v0}, Lz7/e;->m()V

    .line 198
    .line 199
    .line 200
    iget-object v0, v1, Li8/e;->x:Li8/a;

    .line 201
    .line 202
    invoke-interface {v0, v10, v2, v3}, Li8/a;->c(Ll9/a;J)Z

    .line 203
    .line 204
    .line 205
    move-result v9

    .line 206
    :goto_1
    iget-object v0, v1, Li8/e;->x:Li8/a;

    .line 207
    .line 208
    iget-wide v6, v1, Li8/e;->M:J

    .line 209
    .line 210
    invoke-interface {v0, v6, v7}, Li8/a;->d(J)J

    .line 211
    .line 212
    .line 213
    move-result-wide v6

    .line 214
    const-wide/high16 v10, -0x8000000000000000L

    .line 215
    .line 216
    cmp-long v0, v6, v10

    .line 217
    .line 218
    if-nez v0, :cond_6

    .line 219
    .line 220
    iget-boolean v8, v1, Li8/e;->J:Z

    .line 221
    .line 222
    if-eqz v8, :cond_6

    .line 223
    .line 224
    if-nez v9, :cond_6

    .line 225
    .line 226
    iput-boolean v4, v1, Li8/e;->K:Z

    .line 227
    .line 228
    :cond_6
    if-eqz v0, :cond_7

    .line 229
    .line 230
    cmp-long v0, v6, v2

    .line 231
    .line 232
    if-gtz v0, :cond_7

    .line 233
    .line 234
    move v9, v4

    .line 235
    :cond_7
    if-eqz v9, :cond_9

    .line 236
    .line 237
    iget-object v0, v1, Li8/e;->x:Li8/a;

    .line 238
    .line 239
    invoke-interface {v0, v2, v3}, Li8/a;->a(J)Lhr/h0;

    .line 240
    .line 241
    .line 242
    move-result-object v0

    .line 243
    iget-object v6, v1, Li8/e;->x:Li8/a;

    .line 244
    .line 245
    invoke-interface {v6, v2, v3}, Li8/a;->b(J)J

    .line 246
    .line 247
    .line 248
    move-result-wide v6

    .line 249
    new-instance v8, Lv7/c;

    .line 250
    .line 251
    invoke-virtual {v1, v6, v7}, Li8/e;->F(J)J

    .line 252
    .line 253
    .line 254
    invoke-direct {v8, v0}, Lv7/c;-><init>(Ljava/util/List;)V

    .line 255
    .line 256
    .line 257
    if-eqz v5, :cond_8

    .line 258
    .line 259
    invoke-virtual {v5, v4, v8}, Landroid/os/Handler;->obtainMessage(ILjava/lang/Object;)Landroid/os/Message;

    .line 260
    .line 261
    .line 262
    move-result-object v0

    .line 263
    invoke-virtual {v0}, Landroid/os/Message;->sendToTarget()V

    .line 264
    .line 265
    .line 266
    goto :goto_2

    .line 267
    :cond_8
    invoke-virtual {v1, v8}, Li8/e;->H(Lv7/c;)V

    .line 268
    .line 269
    .line 270
    :goto_2
    iget-object v0, v1, Li8/e;->x:Li8/a;

    .line 271
    .line 272
    invoke-interface {v0, v6, v7}, Li8/a;->e(J)V

    .line 273
    .line 274
    .line 275
    :cond_9
    iput-wide v2, v1, Li8/e;->M:J

    .line 276
    .line 277
    return-void

    .line 278
    :cond_a
    invoke-virtual {v1}, Li8/e;->D()V

    .line 279
    .line 280
    .line 281
    iput-wide v2, v1, Li8/e;->M:J

    .line 282
    .line 283
    iget-object v0, v1, Li8/e;->E:Ll9/c;

    .line 284
    .line 285
    const-string v10, "Subtitle decoding failed. streamFormat="

    .line 286
    .line 287
    const-string v11, "TextRenderer"

    .line 288
    .line 289
    const/4 v12, 0x0

    .line 290
    if-nez v0, :cond_c

    .line 291
    .line 292
    iget-object v0, v1, Li8/e;->B:Ll9/e;

    .line 293
    .line 294
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 295
    .line 296
    .line 297
    invoke-interface {v0, v2, v3}, Ll9/e;->a(J)V

    .line 298
    .line 299
    .line 300
    :try_start_0
    iget-object v0, v1, Li8/e;->B:Ll9/e;

    .line 301
    .line 302
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 303
    .line 304
    .line 305
    invoke-interface {v0}, Lz7/c;->c()Ljava/lang/Object;

    .line 306
    .line 307
    .line 308
    move-result-object v0

    .line 309
    check-cast v0, Ll9/c;

    .line 310
    .line 311
    iput-object v0, v1, Li8/e;->E:Ll9/c;
    :try_end_0
    .catch Ll9/f; {:try_start_0 .. :try_end_0} :catch_0

    .line 312
    .line 313
    goto :goto_4

    .line 314
    :catch_0
    move-exception v0

    .line 315
    new-instance v2, Ljava/lang/StringBuilder;

    .line 316
    .line 317
    invoke-direct {v2, v10}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 318
    .line 319
    .line 320
    iget-object v3, v1, Li8/e;->L:Lt7/o;

    .line 321
    .line 322
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 323
    .line 324
    .line 325
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 326
    .line 327
    .line 328
    move-result-object v2

    .line 329
    invoke-static {v11, v2, v0}, Lw7/a;->p(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 330
    .line 331
    .line 332
    new-instance v0, Lv7/c;

    .line 333
    .line 334
    sget-object v2, Lhr/x0;->h:Lhr/x0;

    .line 335
    .line 336
    iget-wide v6, v1, Li8/e;->M:J

    .line 337
    .line 338
    invoke-virtual {v1, v6, v7}, Li8/e;->F(J)J

    .line 339
    .line 340
    .line 341
    invoke-direct {v0, v2}, Lv7/c;-><init>(Ljava/util/List;)V

    .line 342
    .line 343
    .line 344
    if-eqz v5, :cond_b

    .line 345
    .line 346
    invoke-virtual {v5, v4, v0}, Landroid/os/Handler;->obtainMessage(ILjava/lang/Object;)Landroid/os/Message;

    .line 347
    .line 348
    .line 349
    move-result-object v0

    .line 350
    invoke-virtual {v0}, Landroid/os/Message;->sendToTarget()V

    .line 351
    .line 352
    .line 353
    goto :goto_3

    .line 354
    :cond_b
    invoke-virtual {v1, v0}, Li8/e;->H(Lv7/c;)V

    .line 355
    .line 356
    .line 357
    :goto_3
    invoke-virtual {v1}, Li8/e;->I()V

    .line 358
    .line 359
    .line 360
    iget-object v0, v1, Li8/e;->B:Ll9/e;

    .line 361
    .line 362
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 363
    .line 364
    .line 365
    invoke-interface {v0}, Lz7/c;->b()V

    .line 366
    .line 367
    .line 368
    iput-object v12, v1, Li8/e;->B:Ll9/e;

    .line 369
    .line 370
    iput v9, v1, Li8/e;->A:I

    .line 371
    .line 372
    invoke-virtual {v1}, Li8/e;->G()V

    .line 373
    .line 374
    .line 375
    goto/16 :goto_10

    .line 376
    .line 377
    :cond_c
    :goto_4
    iget v0, v1, La8/f;->k:I

    .line 378
    .line 379
    const/4 v13, 0x2

    .line 380
    if-eq v0, v13, :cond_d

    .line 381
    .line 382
    goto/16 :goto_10

    .line 383
    .line 384
    :cond_d
    iget-object v0, v1, Li8/e;->D:Ll9/c;

    .line 385
    .line 386
    if-eqz v0, :cond_e

    .line 387
    .line 388
    invoke-virtual {v1}, Li8/e;->E()J

    .line 389
    .line 390
    .line 391
    move-result-wide v14

    .line 392
    move v0, v9

    .line 393
    :goto_5
    cmp-long v14, v14, v2

    .line 394
    .line 395
    if-gtz v14, :cond_f

    .line 396
    .line 397
    iget v0, v1, Li8/e;->F:I

    .line 398
    .line 399
    add-int/2addr v0, v4

    .line 400
    iput v0, v1, Li8/e;->F:I

    .line 401
    .line 402
    invoke-virtual {v1}, Li8/e;->E()J

    .line 403
    .line 404
    .line 405
    move-result-wide v14

    .line 406
    move v0, v4

    .line 407
    goto :goto_5

    .line 408
    :cond_e
    move v0, v9

    .line 409
    :cond_f
    iget-object v14, v1, Li8/e;->E:Ll9/c;

    .line 410
    .line 411
    if-eqz v14, :cond_10

    .line 412
    .line 413
    invoke-virtual {v14, v6}, Lkq/d;->c(I)Z

    .line 414
    .line 415
    .line 416
    move-result v15

    .line 417
    if-eqz v15, :cond_12

    .line 418
    .line 419
    if-nez v0, :cond_10

    .line 420
    .line 421
    invoke-virtual {v1}, Li8/e;->E()J

    .line 422
    .line 423
    .line 424
    move-result-wide v14

    .line 425
    const-wide v16, 0x7fffffffffffffffL

    .line 426
    .line 427
    .line 428
    .line 429
    .line 430
    cmp-long v14, v14, v16

    .line 431
    .line 432
    if-nez v14, :cond_10

    .line 433
    .line 434
    iget v14, v1, Li8/e;->A:I

    .line 435
    .line 436
    if-ne v14, v13, :cond_11

    .line 437
    .line 438
    invoke-virtual {v1}, Li8/e;->I()V

    .line 439
    .line 440
    .line 441
    iget-object v14, v1, Li8/e;->B:Ll9/e;

    .line 442
    .line 443
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 444
    .line 445
    .line 446
    invoke-interface {v14}, Lz7/c;->b()V

    .line 447
    .line 448
    .line 449
    iput-object v12, v1, Li8/e;->B:Ll9/e;

    .line 450
    .line 451
    iput v9, v1, Li8/e;->A:I

    .line 452
    .line 453
    invoke-virtual {v1}, Li8/e;->G()V

    .line 454
    .line 455
    .line 456
    :cond_10
    :goto_6
    move-object v15, v8

    .line 457
    goto :goto_7

    .line 458
    :cond_11
    invoke-virtual {v1}, Li8/e;->I()V

    .line 459
    .line 460
    .line 461
    iput-boolean v4, v1, Li8/e;->K:Z

    .line 462
    .line 463
    goto :goto_6

    .line 464
    :cond_12
    move-object v15, v8

    .line 465
    iget-wide v7, v14, Lz7/f;->f:J

    .line 466
    .line 467
    cmp-long v7, v7, v2

    .line 468
    .line 469
    if-gtz v7, :cond_14

    .line 470
    .line 471
    iget-object v0, v1, Li8/e;->D:Ll9/c;

    .line 472
    .line 473
    if-eqz v0, :cond_13

    .line 474
    .line 475
    invoke-virtual {v0}, Lz7/f;->n()V

    .line 476
    .line 477
    .line 478
    :cond_13
    invoke-virtual {v14, v2, v3}, Ll9/c;->e(J)I

    .line 479
    .line 480
    .line 481
    move-result v0

    .line 482
    iput v0, v1, Li8/e;->F:I

    .line 483
    .line 484
    iput-object v14, v1, Li8/e;->D:Ll9/c;

    .line 485
    .line 486
    iput-object v12, v1, Li8/e;->E:Ll9/c;

    .line 487
    .line 488
    move v0, v4

    .line 489
    :cond_14
    :goto_7
    if-eqz v0, :cond_19

    .line 490
    .line 491
    iget-object v0, v1, Li8/e;->D:Ll9/c;

    .line 492
    .line 493
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 494
    .line 495
    .line 496
    iget-object v0, v1, Li8/e;->D:Ll9/c;

    .line 497
    .line 498
    invoke-virtual {v0, v2, v3}, Ll9/c;->e(J)I

    .line 499
    .line 500
    .line 501
    move-result v0

    .line 502
    if-eqz v0, :cond_17

    .line 503
    .line 504
    iget-object v7, v1, Li8/e;->D:Ll9/c;

    .line 505
    .line 506
    invoke-virtual {v7}, Ll9/c;->k()I

    .line 507
    .line 508
    .line 509
    move-result v7

    .line 510
    if-nez v7, :cond_15

    .line 511
    .line 512
    goto :goto_8

    .line 513
    :cond_15
    const/4 v7, -0x1

    .line 514
    if-ne v0, v7, :cond_16

    .line 515
    .line 516
    iget-object v0, v1, Li8/e;->D:Ll9/c;

    .line 517
    .line 518
    invoke-virtual {v0}, Ll9/c;->k()I

    .line 519
    .line 520
    .line 521
    move-result v7

    .line 522
    sub-int/2addr v7, v4

    .line 523
    invoke-virtual {v0, v7}, Ll9/c;->i(I)J

    .line 524
    .line 525
    .line 526
    move-result-wide v7

    .line 527
    goto :goto_9

    .line 528
    :cond_16
    iget-object v7, v1, Li8/e;->D:Ll9/c;

    .line 529
    .line 530
    sub-int/2addr v0, v4

    .line 531
    invoke-virtual {v7, v0}, Ll9/c;->i(I)J

    .line 532
    .line 533
    .line 534
    move-result-wide v7

    .line 535
    goto :goto_9

    .line 536
    :cond_17
    :goto_8
    iget-object v0, v1, Li8/e;->D:Ll9/c;

    .line 537
    .line 538
    iget-wide v7, v0, Lz7/f;->f:J

    .line 539
    .line 540
    :goto_9
    invoke-virtual {v1, v7, v8}, Li8/e;->F(J)J

    .line 541
    .line 542
    .line 543
    new-instance v0, Lv7/c;

    .line 544
    .line 545
    iget-object v7, v1, Li8/e;->D:Ll9/c;

    .line 546
    .line 547
    invoke-virtual {v7, v2, v3}, Ll9/c;->f(J)Ljava/util/List;

    .line 548
    .line 549
    .line 550
    move-result-object v2

    .line 551
    invoke-direct {v0, v2}, Lv7/c;-><init>(Ljava/util/List;)V

    .line 552
    .line 553
    .line 554
    if-eqz v5, :cond_18

    .line 555
    .line 556
    invoke-virtual {v5, v4, v0}, Landroid/os/Handler;->obtainMessage(ILjava/lang/Object;)Landroid/os/Message;

    .line 557
    .line 558
    .line 559
    move-result-object v0

    .line 560
    invoke-virtual {v0}, Landroid/os/Message;->sendToTarget()V

    .line 561
    .line 562
    .line 563
    goto :goto_a

    .line 564
    :cond_18
    invoke-virtual {v1, v0}, Li8/e;->H(Lv7/c;)V

    .line 565
    .line 566
    .line 567
    :cond_19
    :goto_a
    iget v0, v1, Li8/e;->A:I

    .line 568
    .line 569
    if-ne v0, v13, :cond_1a

    .line 570
    .line 571
    goto/16 :goto_10

    .line 572
    .line 573
    :cond_1a
    :goto_b
    :try_start_1
    iget-boolean v0, v1, Li8/e;->J:Z

    .line 574
    .line 575
    if-nez v0, :cond_22

    .line 576
    .line 577
    iget-object v0, v1, Li8/e;->C:Ll9/g;

    .line 578
    .line 579
    if-nez v0, :cond_1c

    .line 580
    .line 581
    iget-object v0, v1, Li8/e;->B:Ll9/e;

    .line 582
    .line 583
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 584
    .line 585
    .line 586
    invoke-interface {v0}, Lz7/c;->f()Ljava/lang/Object;

    .line 587
    .line 588
    .line 589
    move-result-object v0

    .line 590
    check-cast v0, Ll9/g;

    .line 591
    .line 592
    if-nez v0, :cond_1b

    .line 593
    .line 594
    goto/16 :goto_10

    .line 595
    .line 596
    :cond_1b
    iput-object v0, v1, Li8/e;->C:Ll9/g;

    .line 597
    .line 598
    goto :goto_c

    .line 599
    :catch_1
    move-exception v0

    .line 600
    goto :goto_e

    .line 601
    :cond_1c
    :goto_c
    iget v2, v1, Li8/e;->A:I

    .line 602
    .line 603
    if-ne v2, v4, :cond_1d

    .line 604
    .line 605
    iput v6, v0, Lkq/d;->e:I

    .line 606
    .line 607
    iget-object v2, v1, Li8/e;->B:Ll9/e;

    .line 608
    .line 609
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 610
    .line 611
    .line 612
    invoke-interface {v2, v0}, Lz7/c;->e(Ll9/g;)V

    .line 613
    .line 614
    .line 615
    iput-object v12, v1, Li8/e;->C:Ll9/g;

    .line 616
    .line 617
    iput v13, v1, Li8/e;->A:I

    .line 618
    .line 619
    return-void

    .line 620
    :cond_1d
    invoke-virtual {v1, v15, v0, v9}, La8/f;->x(Lb81/d;Lz7/e;I)I

    .line 621
    .line 622
    .line 623
    move-result v2

    .line 624
    const/4 v3, -0x4

    .line 625
    if-ne v2, v3, :cond_20

    .line 626
    .line 627
    invoke-virtual {v0, v6}, Lkq/d;->c(I)Z

    .line 628
    .line 629
    .line 630
    move-result v2

    .line 631
    if-eqz v2, :cond_1e

    .line 632
    .line 633
    iput-boolean v4, v1, Li8/e;->J:Z

    .line 634
    .line 635
    iput-boolean v9, v1, Li8/e;->z:Z

    .line 636
    .line 637
    goto :goto_d

    .line 638
    :cond_1e
    iget-object v2, v15, Lb81/d;->f:Ljava/lang/Object;

    .line 639
    .line 640
    check-cast v2, Lt7/o;

    .line 641
    .line 642
    if-nez v2, :cond_1f

    .line 643
    .line 644
    goto :goto_10

    .line 645
    :cond_1f
    iget-wide v7, v2, Lt7/o;->s:J

    .line 646
    .line 647
    iput-wide v7, v0, Ll9/g;->m:J

    .line 648
    .line 649
    invoke-virtual {v0}, Lz7/e;->p()V

    .line 650
    .line 651
    .line 652
    iget-boolean v2, v1, Li8/e;->z:Z

    .line 653
    .line 654
    invoke-virtual {v0, v4}, Lkq/d;->c(I)Z

    .line 655
    .line 656
    .line 657
    move-result v7

    .line 658
    xor-int/2addr v7, v4

    .line 659
    and-int/2addr v2, v7

    .line 660
    iput-boolean v2, v1, Li8/e;->z:Z

    .line 661
    .line 662
    :goto_d
    iget-boolean v2, v1, Li8/e;->z:Z

    .line 663
    .line 664
    if-nez v2, :cond_1a

    .line 665
    .line 666
    iget-object v2, v1, Li8/e;->B:Ll9/e;

    .line 667
    .line 668
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 669
    .line 670
    .line 671
    invoke-interface {v2, v0}, Lz7/c;->e(Ll9/g;)V

    .line 672
    .line 673
    .line 674
    iput-object v12, v1, Li8/e;->C:Ll9/g;
    :try_end_1
    .catch Ll9/f; {:try_start_1 .. :try_end_1} :catch_1

    .line 675
    .line 676
    goto :goto_b

    .line 677
    :cond_20
    const/4 v0, -0x3

    .line 678
    if-ne v2, v0, :cond_1a

    .line 679
    .line 680
    goto :goto_10

    .line 681
    :goto_e
    new-instance v2, Ljava/lang/StringBuilder;

    .line 682
    .line 683
    invoke-direct {v2, v10}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 684
    .line 685
    .line 686
    iget-object v3, v1, Li8/e;->L:Lt7/o;

    .line 687
    .line 688
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 689
    .line 690
    .line 691
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 692
    .line 693
    .line 694
    move-result-object v2

    .line 695
    invoke-static {v11, v2, v0}, Lw7/a;->p(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 696
    .line 697
    .line 698
    new-instance v0, Lv7/c;

    .line 699
    .line 700
    sget-object v2, Lhr/x0;->h:Lhr/x0;

    .line 701
    .line 702
    iget-wide v6, v1, Li8/e;->M:J

    .line 703
    .line 704
    invoke-virtual {v1, v6, v7}, Li8/e;->F(J)J

    .line 705
    .line 706
    .line 707
    invoke-direct {v0, v2}, Lv7/c;-><init>(Ljava/util/List;)V

    .line 708
    .line 709
    .line 710
    if-eqz v5, :cond_21

    .line 711
    .line 712
    invoke-virtual {v5, v4, v0}, Landroid/os/Handler;->obtainMessage(ILjava/lang/Object;)Landroid/os/Message;

    .line 713
    .line 714
    .line 715
    move-result-object v0

    .line 716
    invoke-virtual {v0}, Landroid/os/Message;->sendToTarget()V

    .line 717
    .line 718
    .line 719
    goto :goto_f

    .line 720
    :cond_21
    invoke-virtual {v1, v0}, Li8/e;->H(Lv7/c;)V

    .line 721
    .line 722
    .line 723
    :goto_f
    invoke-virtual {v1}, Li8/e;->I()V

    .line 724
    .line 725
    .line 726
    iget-object v0, v1, Li8/e;->B:Ll9/e;

    .line 727
    .line 728
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 729
    .line 730
    .line 731
    invoke-interface {v0}, Lz7/c;->b()V

    .line 732
    .line 733
    .line 734
    iput-object v12, v1, Li8/e;->B:Ll9/e;

    .line 735
    .line 736
    iput v9, v1, Li8/e;->A:I

    .line 737
    .line 738
    invoke-virtual {v1}, Li8/e;->G()V

    .line 739
    .line 740
    .line 741
    :cond_22
    :goto_10
    return-void
.end method
