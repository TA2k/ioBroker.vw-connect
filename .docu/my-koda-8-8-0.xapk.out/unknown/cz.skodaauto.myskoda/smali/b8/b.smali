.class public final synthetic Lb8/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lw7/j;
.implements Lbb/w;
.implements Lgs/e;
.implements Lc1/w;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lb8/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lb8/a;Lh8/s;Lh8/x;Ljava/io/IOException;Z)V
    .locals 0

    .line 2
    const/4 p1, 0x0

    iput p1, p0, Lb8/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public a(Lbb/v;Lbb/x;Z)V
    .locals 0

    .line 1
    iget p0, p0, Lb8/b;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-interface {p1}, Lbb/v;->b()V

    .line 7
    .line 8
    .line 9
    return-void

    .line 10
    :pswitch_0
    invoke-interface {p1}, Lbb/v;->a()V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :pswitch_1
    invoke-interface {p1, p2}, Lbb/v;->e(Lbb/x;)V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :pswitch_2
    invoke-interface {p1, p2}, Lbb/v;->c(Lbb/x;)V

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    :pswitch_3
    invoke-interface {p1, p2}, Lbb/v;->d(Lbb/x;)V

    .line 23
    .line 24
    .line 25
    return-void

    .line 26
    nop

    .line 27
    :pswitch_data_0
    .packed-switch 0x17
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public b(F)F
    .locals 1

    .line 1
    const p0, 0x3eba2e8c

    .line 2
    .line 3
    .line 4
    cmpg-float p0, p1, p0

    .line 5
    .line 6
    const/high16 v0, 0x40f20000    # 7.5625f

    .line 7
    .line 8
    if-gez p0, :cond_0

    .line 9
    .line 10
    mul-float/2addr v0, p1

    .line 11
    mul-float/2addr v0, p1

    .line 12
    return v0

    .line 13
    :cond_0
    const p0, 0x3f3a2e8c

    .line 14
    .line 15
    .line 16
    cmpg-float p0, p1, p0

    .line 17
    .line 18
    if-gez p0, :cond_1

    .line 19
    .line 20
    const p0, 0x3f0ba2e9

    .line 21
    .line 22
    .line 23
    sub-float/2addr p1, p0

    .line 24
    mul-float/2addr v0, p1

    .line 25
    mul-float/2addr v0, p1

    .line 26
    const/high16 p0, 0x3f400000    # 0.75f

    .line 27
    .line 28
    add-float/2addr v0, p0

    .line 29
    return v0

    .line 30
    :cond_1
    const p0, 0x3f68ba2f

    .line 31
    .line 32
    .line 33
    cmpg-float p0, p1, p0

    .line 34
    .line 35
    if-gez p0, :cond_2

    .line 36
    .line 37
    const p0, 0x3f51745d

    .line 38
    .line 39
    .line 40
    sub-float/2addr p1, p0

    .line 41
    mul-float/2addr v0, p1

    .line 42
    mul-float/2addr v0, p1

    .line 43
    const/high16 p0, 0x3f700000    # 0.9375f

    .line 44
    .line 45
    add-float/2addr v0, p0

    .line 46
    return v0

    .line 47
    :cond_2
    const p0, 0x3f745d17

    .line 48
    .line 49
    .line 50
    sub-float/2addr p1, p0

    .line 51
    mul-float/2addr v0, p1

    .line 52
    mul-float/2addr v0, p1

    .line 53
    const/high16 p0, 0x3f7c0000    # 0.984375f

    .line 54
    .line 55
    add-float/2addr v0, p0

    .line 56
    return v0
.end method

.method public e(Lin/z1;)Ljava/lang/Object;
    .locals 3

    .line 1
    new-instance p0, Lbu/b;

    .line 2
    .line 3
    const-class v0, Lbu/a;

    .line 4
    .line 5
    invoke-static {v0}, Lgs/s;->a(Ljava/lang/Class;)Lgs/s;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-virtual {p1, v0}, Lin/z1;->c(Lgs/s;)Ljava/util/Set;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    sget-object v0, Lbu/c;->f:Lbu/c;

    .line 14
    .line 15
    if-nez v0, :cond_1

    .line 16
    .line 17
    const-class v1, Lbu/c;

    .line 18
    .line 19
    monitor-enter v1

    .line 20
    :try_start_0
    sget-object v0, Lbu/c;->f:Lbu/c;

    .line 21
    .line 22
    if-nez v0, :cond_0

    .line 23
    .line 24
    new-instance v0, Lbu/c;

    .line 25
    .line 26
    const/4 v2, 0x0

    .line 27
    invoke-direct {v0, v2}, Lbu/c;-><init>(I)V

    .line 28
    .line 29
    .line 30
    sput-object v0, Lbu/c;->f:Lbu/c;

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :catchall_0
    move-exception p0

    .line 34
    goto :goto_1

    .line 35
    :cond_0
    :goto_0
    monitor-exit v1

    .line 36
    goto :goto_2

    .line 37
    :goto_1
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 38
    throw p0

    .line 39
    :cond_1
    :goto_2
    invoke-direct {p0, p1, v0}, Lbu/b;-><init>(Ljava/util/Set;Lbu/c;)V

    .line 40
    .line 41
    .line 42
    return-object p0
.end method

.method public invoke(Ljava/lang/Object;)V
    .locals 0

    .line 1
    iget p0, p0, Lb8/b;->d:I

    .line 2
    .line 3
    check-cast p1, Lb8/j;

    .line 4
    .line 5
    packed-switch p0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    return-void

    .line 12
    :pswitch_0
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :pswitch_1
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    return-void

    .line 20
    :pswitch_2
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    :pswitch_3
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 25
    .line 26
    .line 27
    return-void

    .line 28
    :pswitch_4
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 29
    .line 30
    .line 31
    return-void

    .line 32
    :pswitch_5
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 33
    .line 34
    .line 35
    return-void

    .line 36
    :pswitch_6
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 37
    .line 38
    .line 39
    return-void

    .line 40
    :pswitch_7
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 41
    .line 42
    .line 43
    return-void

    .line 44
    :pswitch_8
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 45
    .line 46
    .line 47
    return-void

    .line 48
    :pswitch_9
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 49
    .line 50
    .line 51
    return-void

    .line 52
    :pswitch_a
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 53
    .line 54
    .line 55
    return-void

    .line 56
    :pswitch_b
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 57
    .line 58
    .line 59
    return-void

    .line 60
    :pswitch_c
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 61
    .line 62
    .line 63
    return-void

    .line 64
    :pswitch_d
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 65
    .line 66
    .line 67
    return-void

    .line 68
    :pswitch_e
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 69
    .line 70
    .line 71
    return-void

    .line 72
    :pswitch_f
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 73
    .line 74
    .line 75
    return-void

    .line 76
    :pswitch_10
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 77
    .line 78
    .line 79
    return-void

    .line 80
    :pswitch_11
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 81
    .line 82
    .line 83
    return-void

    .line 84
    :pswitch_12
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 85
    .line 86
    .line 87
    return-void

    .line 88
    :pswitch_13
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 89
    .line 90
    .line 91
    return-void

    .line 92
    :pswitch_14
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 93
    .line 94
    .line 95
    return-void

    .line 96
    :pswitch_15
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 97
    .line 98
    .line 99
    const/4 p0, 0x1

    .line 100
    iput p0, p1, Lb8/j;->w:I

    .line 101
    .line 102
    return-void

    .line 103
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
