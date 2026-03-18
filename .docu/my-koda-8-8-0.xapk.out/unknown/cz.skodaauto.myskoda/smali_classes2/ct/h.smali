.class public final Lct/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lzs/g;


# instance fields
.field public final synthetic a:I

.field public b:Z

.field public c:Z

.field public d:Lzs/c;

.field public final e:Lzs/e;


# direct methods
.method public synthetic constructor <init>(Lzs/e;I)V
    .locals 0

    .line 1
    iput p2, p0, Lct/h;->a:I

    .line 2
    .line 3
    const/4 p2, 0x0

    .line 4
    iput-boolean p2, p0, Lct/h;->b:Z

    .line 5
    .line 6
    iput-boolean p2, p0, Lct/h;->c:Z

    .line 7
    .line 8
    iput-object p1, p0, Lct/h;->e:Lzs/e;

    .line 9
    .line 10
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 11
    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final b(Ljava/lang/String;)Lzs/g;
    .locals 3

    .line 1
    iget v0, p0, Lct/h;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-boolean v0, p0, Lct/h;->b:Z

    .line 7
    .line 8
    if-nez v0, :cond_0

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    iput-boolean v0, p0, Lct/h;->b:Z

    .line 12
    .line 13
    iget-object v0, p0, Lct/h;->e:Lzs/e;

    .line 14
    .line 15
    check-cast v0, Llp/e0;

    .line 16
    .line 17
    iget-object v1, p0, Lct/h;->d:Lzs/c;

    .line 18
    .line 19
    iget-boolean v2, p0, Lct/h;->c:Z

    .line 20
    .line 21
    invoke-virtual {v0, v1, p1, v2}, Llp/e0;->c(Lzs/c;Ljava/lang/Object;Z)V

    .line 22
    .line 23
    .line 24
    return-object p0

    .line 25
    :cond_0
    new-instance p0, Lzs/b;

    .line 26
    .line 27
    const-string p1, "Cannot encode a second value in the ValueEncoderContext"

    .line 28
    .line 29
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    throw p0

    .line 33
    :pswitch_0
    iget-boolean v0, p0, Lct/h;->b:Z

    .line 34
    .line 35
    if-nez v0, :cond_1

    .line 36
    .line 37
    const/4 v0, 0x1

    .line 38
    iput-boolean v0, p0, Lct/h;->b:Z

    .line 39
    .line 40
    iget-object v0, p0, Lct/h;->e:Lzs/e;

    .line 41
    .line 42
    check-cast v0, Lkp/f;

    .line 43
    .line 44
    iget-object v1, p0, Lct/h;->d:Lzs/c;

    .line 45
    .line 46
    iget-boolean v2, p0, Lct/h;->c:Z

    .line 47
    .line 48
    invoke-virtual {v0, v1, p1, v2}, Lkp/f;->c(Lzs/c;Ljava/lang/Object;Z)V

    .line 49
    .line 50
    .line 51
    return-object p0

    .line 52
    :cond_1
    new-instance p0, Lzs/b;

    .line 53
    .line 54
    const-string p1, "Cannot encode a second value in the ValueEncoderContext"

    .line 55
    .line 56
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    throw p0

    .line 60
    :pswitch_1
    iget-boolean v0, p0, Lct/h;->b:Z

    .line 61
    .line 62
    if-nez v0, :cond_2

    .line 63
    .line 64
    const/4 v0, 0x1

    .line 65
    iput-boolean v0, p0, Lct/h;->b:Z

    .line 66
    .line 67
    iget-object v0, p0, Lct/h;->e:Lzs/e;

    .line 68
    .line 69
    check-cast v0, Ljp/n0;

    .line 70
    .line 71
    iget-object v1, p0, Lct/h;->d:Lzs/c;

    .line 72
    .line 73
    iget-boolean v2, p0, Lct/h;->c:Z

    .line 74
    .line 75
    invoke-virtual {v0, v1, p1, v2}, Ljp/n0;->c(Lzs/c;Ljava/lang/Object;Z)V

    .line 76
    .line 77
    .line 78
    return-object p0

    .line 79
    :cond_2
    new-instance p0, Lzs/b;

    .line 80
    .line 81
    const-string p1, "Cannot encode a second value in the ValueEncoderContext"

    .line 82
    .line 83
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    throw p0

    .line 87
    :pswitch_2
    iget-boolean v0, p0, Lct/h;->b:Z

    .line 88
    .line 89
    if-nez v0, :cond_3

    .line 90
    .line 91
    const/4 v0, 0x1

    .line 92
    iput-boolean v0, p0, Lct/h;->b:Z

    .line 93
    .line 94
    iget-object v0, p0, Lct/h;->e:Lzs/e;

    .line 95
    .line 96
    check-cast v0, Lct/f;

    .line 97
    .line 98
    iget-object v1, p0, Lct/h;->d:Lzs/c;

    .line 99
    .line 100
    iget-boolean v2, p0, Lct/h;->c:Z

    .line 101
    .line 102
    invoke-virtual {v0, v1, p1, v2}, Lct/f;->h(Lzs/c;Ljava/lang/Object;Z)V

    .line 103
    .line 104
    .line 105
    return-object p0

    .line 106
    :cond_3
    new-instance p0, Lzs/b;

    .line 107
    .line 108
    const-string p1, "Cannot encode a second value in the ValueEncoderContext"

    .line 109
    .line 110
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 111
    .line 112
    .line 113
    throw p0

    .line 114
    nop

    .line 115
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final c(Z)Lzs/g;
    .locals 3

    .line 1
    iget v0, p0, Lct/h;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-boolean v0, p0, Lct/h;->b:Z

    .line 7
    .line 8
    if-nez v0, :cond_0

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    iput-boolean v0, p0, Lct/h;->b:Z

    .line 12
    .line 13
    iget-object v0, p0, Lct/h;->e:Lzs/e;

    .line 14
    .line 15
    check-cast v0, Llp/e0;

    .line 16
    .line 17
    iget-object v1, p0, Lct/h;->d:Lzs/c;

    .line 18
    .line 19
    iget-boolean v2, p0, Lct/h;->c:Z

    .line 20
    .line 21
    invoke-virtual {v0, v1, p1, v2}, Llp/e0;->h(Lzs/c;IZ)V

    .line 22
    .line 23
    .line 24
    return-object p0

    .line 25
    :cond_0
    new-instance p0, Lzs/b;

    .line 26
    .line 27
    const-string p1, "Cannot encode a second value in the ValueEncoderContext"

    .line 28
    .line 29
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    throw p0

    .line 33
    :pswitch_0
    iget-boolean v0, p0, Lct/h;->b:Z

    .line 34
    .line 35
    if-nez v0, :cond_1

    .line 36
    .line 37
    const/4 v0, 0x1

    .line 38
    iput-boolean v0, p0, Lct/h;->b:Z

    .line 39
    .line 40
    iget-object v0, p0, Lct/h;->e:Lzs/e;

    .line 41
    .line 42
    check-cast v0, Lkp/f;

    .line 43
    .line 44
    iget-object v1, p0, Lct/h;->d:Lzs/c;

    .line 45
    .line 46
    iget-boolean v2, p0, Lct/h;->c:Z

    .line 47
    .line 48
    invoke-virtual {v0, v1, p1, v2}, Lkp/f;->h(Lzs/c;IZ)V

    .line 49
    .line 50
    .line 51
    return-object p0

    .line 52
    :cond_1
    new-instance p0, Lzs/b;

    .line 53
    .line 54
    const-string p1, "Cannot encode a second value in the ValueEncoderContext"

    .line 55
    .line 56
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    throw p0

    .line 60
    :pswitch_1
    iget-boolean v0, p0, Lct/h;->b:Z

    .line 61
    .line 62
    if-nez v0, :cond_2

    .line 63
    .line 64
    const/4 v0, 0x1

    .line 65
    iput-boolean v0, p0, Lct/h;->b:Z

    .line 66
    .line 67
    iget-object v0, p0, Lct/h;->e:Lzs/e;

    .line 68
    .line 69
    check-cast v0, Ljp/n0;

    .line 70
    .line 71
    iget-object v1, p0, Lct/h;->d:Lzs/c;

    .line 72
    .line 73
    iget-boolean v2, p0, Lct/h;->c:Z

    .line 74
    .line 75
    invoke-virtual {v0, v1, p1, v2}, Ljp/n0;->h(Lzs/c;IZ)V

    .line 76
    .line 77
    .line 78
    return-object p0

    .line 79
    :cond_2
    new-instance p0, Lzs/b;

    .line 80
    .line 81
    const-string p1, "Cannot encode a second value in the ValueEncoderContext"

    .line 82
    .line 83
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    throw p0

    .line 87
    :pswitch_2
    iget-boolean v0, p0, Lct/h;->b:Z

    .line 88
    .line 89
    if-nez v0, :cond_3

    .line 90
    .line 91
    const/4 v0, 0x1

    .line 92
    iput-boolean v0, p0, Lct/h;->b:Z

    .line 93
    .line 94
    iget-object v0, p0, Lct/h;->e:Lzs/e;

    .line 95
    .line 96
    check-cast v0, Lct/f;

    .line 97
    .line 98
    iget-object v1, p0, Lct/h;->d:Lzs/c;

    .line 99
    .line 100
    iget-boolean v2, p0, Lct/h;->c:Z

    .line 101
    .line 102
    invoke-virtual {v0, v1, p1, v2}, Lct/f;->c(Lzs/c;IZ)V

    .line 103
    .line 104
    .line 105
    return-object p0

    .line 106
    :cond_3
    new-instance p0, Lzs/b;

    .line 107
    .line 108
    const-string p1, "Cannot encode a second value in the ValueEncoderContext"

    .line 109
    .line 110
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 111
    .line 112
    .line 113
    throw p0

    .line 114
    nop

    .line 115
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
