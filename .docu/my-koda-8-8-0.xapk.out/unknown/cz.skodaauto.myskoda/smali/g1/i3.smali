.class public final Lg1/i3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Laq/f;
.implements Lo8/p;
.implements Lo8/q;


# instance fields
.field public final synthetic d:I

.field public e:J

.field public f:Ljava/lang/Object;


# direct methods
.method public constructor <init>()V
    .locals 2

    const/4 v0, 0x3

    iput v0, p0, Lg1/i3;->d:I

    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const-wide/16 v0, 0x0

    .line 12
    iput-wide v0, p0, Lg1/i3;->e:J

    return-void
.end method

.method public synthetic constructor <init>(JLjava/lang/Object;I)V
    .locals 0

    .line 1
    iput p4, p0, Lg1/i3;->d:I

    iput-wide p1, p0, Lg1/i3;->e:J

    iput-object p3, p0, Lg1/i3;->f:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;JI)V
    .locals 0

    .line 2
    iput p4, p0, Lg1/i3;->d:I

    iput-object p1, p0, Lg1/i3;->f:Ljava/lang/Object;

    iput-wide p2, p0, Lg1/i3;->e:J

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Lo8/p;J)V
    .locals 2

    const/16 v0, 0x8

    iput v0, p0, Lg1/i3;->d:I

    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    iput-object p1, p0, Lg1/i3;->f:Ljava/lang/Object;

    .line 9
    invoke-interface {p1}, Lo8/p;->getPosition()J

    move-result-wide v0

    cmp-long p1, v0, p2

    if-ltz p1, :cond_0

    const/4 p1, 0x1

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    invoke-static {p1}, Lw7/a;->c(Z)V

    .line 10
    iput-wide p2, p0, Lg1/i3;->e:J

    return-void
.end method

.method public constructor <init>(Lto/a;)V
    .locals 1

    const/4 v0, 0x6

    iput v0, p0, Lg1/i3;->d:I

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    iput-object p1, p0, Lg1/i3;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lu01/b0;)V
    .locals 2

    const/4 v0, 0x1

    iput v0, p0, Lg1/i3;->d:I

    const-string v0, "source"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 5
    iput-object p1, p0, Lg1/i3;->f:Ljava/lang/Object;

    const-wide/32 v0, 0x40000

    .line 6
    iput-wide v0, p0, Lg1/i3;->e:J

    return-void
.end method


# virtual methods
.method public a(IZ)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lg1/i3;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lo8/p;

    .line 4
    .line 5
    const/4 p2, 0x1

    .line 6
    invoke-interface {p0, p1, p2}, Lo8/p;->a(IZ)Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method

.method public b([BIIZ)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lg1/i3;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lo8/p;

    .line 4
    .line 5
    const/4 p2, 0x0

    .line 6
    invoke-interface {p0, p1, p2, p3, p4}, Lo8/p;->b([BIIZ)Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method

.method public c(Lo8/c0;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lg1/i3;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lo8/q;

    .line 4
    .line 5
    new-instance v1, Lw8/c;

    .line 6
    .line 7
    invoke-direct {v1, p0, p1, p1}, Lw8/c;-><init>(Lg1/i3;Lo8/c0;Lo8/c0;)V

    .line 8
    .line 9
    .line 10
    invoke-interface {v0, v1}, Lo8/q;->c(Lo8/c0;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public e()V
    .locals 0

    .line 1
    iget-object p0, p0, Lg1/i3;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lo8/p;

    .line 4
    .line 5
    invoke-interface {p0}, Lo8/p;->e()V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public f([BIIZ)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lg1/i3;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lo8/p;

    .line 4
    .line 5
    const/4 p2, 0x0

    .line 6
    invoke-interface {p0, p1, p2, p3, p4}, Lo8/p;->f([BIIZ)Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method

.method public getLength()J
    .locals 4

    .line 1
    iget-object v0, p0, Lg1/i3;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lo8/p;

    .line 4
    .line 5
    invoke-interface {v0}, Lo8/p;->getLength()J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    iget-wide v2, p0, Lg1/i3;->e:J

    .line 10
    .line 11
    sub-long/2addr v0, v2

    .line 12
    return-wide v0
.end method

.method public getPosition()J
    .locals 4

    .line 1
    iget-object v0, p0, Lg1/i3;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lo8/p;

    .line 4
    .line 5
    invoke-interface {v0}, Lo8/p;->getPosition()J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    iget-wide v2, p0, Lg1/i3;->e:J

    .line 10
    .line 11
    sub-long/2addr v0, v2

    .line 12
    return-wide v0
.end method

.method public h()J
    .locals 4

    .line 1
    iget-object v0, p0, Lg1/i3;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lo8/p;

    .line 4
    .line 5
    invoke-interface {v0}, Lo8/p;->h()J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    iget-wide v2, p0, Lg1/i3;->e:J

    .line 10
    .line 11
    sub-long/2addr v0, v2

    .line 12
    return-wide v0
.end method

.method public i(I)V
    .locals 0

    .line 1
    iget-object p0, p0, Lg1/i3;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lo8/p;

    .line 4
    .line 5
    invoke-interface {p0, p1}, Lo8/p;->i(I)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public j(I)I
    .locals 0

    .line 1
    iget-object p0, p0, Lg1/i3;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lo8/p;

    .line 4
    .line 5
    invoke-interface {p0, p1}, Lo8/p;->j(I)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public k([BII)I
    .locals 0

    .line 1
    iget-object p0, p0, Lg1/i3;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lo8/p;

    .line 4
    .line 5
    invoke-interface {p0, p1, p2, p3}, Lo8/p;->k([BII)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public m()V
    .locals 0

    .line 1
    iget-object p0, p0, Lg1/i3;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lo8/q;

    .line 4
    .line 5
    invoke-interface {p0}, Lo8/q;->m()V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public n(I)V
    .locals 0

    .line 1
    iget-object p0, p0, Lg1/i3;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lo8/p;

    .line 4
    .line 5
    invoke-interface {p0, p1}, Lo8/p;->n(I)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public o([BII)V
    .locals 0

    .line 1
    iget-object p0, p0, Lg1/i3;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lo8/p;

    .line 4
    .line 5
    invoke-interface {p0, p1, p2, p3}, Lo8/p;->o([BII)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public onFailure(Ljava/lang/Exception;)V
    .locals 2

    .line 1
    iget p1, p0, Lg1/i3;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    :pswitch_0
    iget-object p1, p0, Lg1/i3;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p1, Lrn/i;

    .line 9
    .line 10
    iget-wide v0, p0, Lg1/i3;->e:J

    .line 11
    .line 12
    iget-object p0, p1, Lrn/i;->g:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p0, Ljava/util/concurrent/atomic/AtomicLong;

    .line 15
    .line 16
    invoke-virtual {p0, v0, v1}, Ljava/util/concurrent/atomic/AtomicLong;->set(J)V

    .line 17
    .line 18
    .line 19
    return-void

    .line 20
    :pswitch_1
    iget-object p1, p0, Lg1/i3;->f:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast p1, Lb81/d;

    .line 23
    .line 24
    iget-wide v0, p0, Lg1/i3;->e:J

    .line 25
    .line 26
    iget-object p0, p1, Lb81/d;->f:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast p0, Ljava/util/concurrent/atomic/AtomicLong;

    .line 29
    .line 30
    invoke-virtual {p0, v0, v1}, Ljava/util/concurrent/atomic/AtomicLong;->set(J)V

    .line 31
    .line 32
    .line 33
    return-void

    .line 34
    :pswitch_2
    iget-object p1, p0, Lg1/i3;->f:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast p1, Lb81/b;

    .line 37
    .line 38
    iget-wide v0, p0, Lg1/i3;->e:J

    .line 39
    .line 40
    iget-object p0, p1, Lb81/b;->f:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast p0, Ljava/util/concurrent/atomic/AtomicLong;

    .line 43
    .line 44
    invoke-virtual {p0, v0, v1}, Ljava/util/concurrent/atomic/AtomicLong;->set(J)V

    .line 45
    .line 46
    .line 47
    return-void

    .line 48
    nop

    .line 49
    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_2
        :pswitch_0
        :pswitch_1
    .end packed-switch
.end method

.method public p(Lp3/t;F)J
    .locals 5

    .line 1
    iget-wide v0, p1, Lp3/t;->c:J

    .line 2
    .line 3
    iget-wide v2, p1, Lp3/t;->g:J

    .line 4
    .line 5
    invoke-static {v0, v1, v2, v3}, Ld3/b;->g(JJ)J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    iget-wide v2, p0, Lg1/i3;->e:J

    .line 10
    .line 11
    invoke-static {v2, v3, v0, v1}, Ld3/b;->h(JJ)J

    .line 12
    .line 13
    .line 14
    move-result-wide v0

    .line 15
    iput-wide v0, p0, Lg1/i3;->e:J

    .line 16
    .line 17
    iget-object p1, p0, Lg1/i3;->f:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast p1, Lg1/w1;

    .line 20
    .line 21
    if-nez p1, :cond_0

    .line 22
    .line 23
    invoke-static {v0, v1}, Ld3/b;->d(J)F

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    invoke-virtual {p0, v0, v1}, Lg1/i3;->w(J)F

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    invoke-static {v0}, Ljava/lang/Math;->abs(F)F

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    :goto_0
    cmpl-float v0, v0, p2

    .line 37
    .line 38
    if-ltz v0, :cond_4

    .line 39
    .line 40
    if-nez p1, :cond_1

    .line 41
    .line 42
    iget-wide v0, p0, Lg1/i3;->e:J

    .line 43
    .line 44
    invoke-static {v0, v1}, Ld3/b;->d(J)F

    .line 45
    .line 46
    .line 47
    move-result p1

    .line 48
    invoke-static {v0, v1, p1}, Ld3/b;->b(JF)J

    .line 49
    .line 50
    .line 51
    move-result-wide v0

    .line 52
    invoke-static {v0, v1, p2}, Ld3/b;->i(JF)J

    .line 53
    .line 54
    .line 55
    move-result-wide p1

    .line 56
    iget-wide v0, p0, Lg1/i3;->e:J

    .line 57
    .line 58
    invoke-static {v0, v1, p1, p2}, Ld3/b;->g(JJ)J

    .line 59
    .line 60
    .line 61
    move-result-wide p0

    .line 62
    return-wide p0

    .line 63
    :cond_1
    iget-wide v0, p0, Lg1/i3;->e:J

    .line 64
    .line 65
    invoke-virtual {p0, v0, v1}, Lg1/i3;->w(J)F

    .line 66
    .line 67
    .line 68
    move-result v0

    .line 69
    iget-wide v1, p0, Lg1/i3;->e:J

    .line 70
    .line 71
    invoke-virtual {p0, v1, v2}, Lg1/i3;->w(J)F

    .line 72
    .line 73
    .line 74
    move-result v1

    .line 75
    invoke-static {v1}, Ljava/lang/Math;->signum(F)F

    .line 76
    .line 77
    .line 78
    move-result v1

    .line 79
    mul-float/2addr v1, p2

    .line 80
    sub-float/2addr v0, v1

    .line 81
    iget-wide v1, p0, Lg1/i3;->e:J

    .line 82
    .line 83
    sget-object p0, Lg1/w1;->e:Lg1/w1;

    .line 84
    .line 85
    const/16 p2, 0x20

    .line 86
    .line 87
    const-wide v3, 0xffffffffL

    .line 88
    .line 89
    .line 90
    .line 91
    .line 92
    if-ne p1, p0, :cond_2

    .line 93
    .line 94
    and-long/2addr v1, v3

    .line 95
    :goto_1
    long-to-int v1, v1

    .line 96
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 97
    .line 98
    .line 99
    move-result v1

    .line 100
    goto :goto_2

    .line 101
    :cond_2
    shr-long/2addr v1, p2

    .line 102
    goto :goto_1

    .line 103
    :goto_2
    if-ne p1, p0, :cond_3

    .line 104
    .line 105
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 106
    .line 107
    .line 108
    move-result p0

    .line 109
    int-to-long p0, p0

    .line 110
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 111
    .line 112
    .line 113
    move-result v0

    .line 114
    int-to-long v0, v0

    .line 115
    shl-long/2addr p0, p2

    .line 116
    and-long/2addr v0, v3

    .line 117
    or-long/2addr p0, v0

    .line 118
    return-wide p0

    .line 119
    :cond_3
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 120
    .line 121
    .line 122
    move-result p0

    .line 123
    int-to-long p0, p0

    .line 124
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 125
    .line 126
    .line 127
    move-result v0

    .line 128
    int-to-long v0, v0

    .line 129
    shl-long/2addr p0, p2

    .line 130
    and-long/2addr v0, v3

    .line 131
    or-long/2addr p0, v0

    .line 132
    return-wide p0

    .line 133
    :cond_4
    const-wide p0, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 134
    .line 135
    .line 136
    .line 137
    .line 138
    return-wide p0
.end method

.method public q(II)Lo8/i0;
    .locals 0

    .line 1
    iget-object p0, p0, Lg1/i3;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lo8/q;

    .line 4
    .line 5
    invoke-interface {p0, p1, p2}, Lo8/q;->q(II)Lo8/i0;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public r(I)V
    .locals 4

    .line 1
    const/16 v0, 0x40

    .line 2
    .line 3
    if-lt p1, v0, :cond_1

    .line 4
    .line 5
    iget-object p0, p0, Lg1/i3;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lg1/i3;

    .line 8
    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    sub-int/2addr p1, v0

    .line 12
    invoke-virtual {p0, p1}, Lg1/i3;->r(I)V

    .line 13
    .line 14
    .line 15
    :cond_0
    return-void

    .line 16
    :cond_1
    iget-wide v0, p0, Lg1/i3;->e:J

    .line 17
    .line 18
    const-wide/16 v2, 0x1

    .line 19
    .line 20
    shl-long/2addr v2, p1

    .line 21
    not-long v2, v2

    .line 22
    and-long/2addr v0, v2

    .line 23
    iput-wide v0, p0, Lg1/i3;->e:J

    .line 24
    .line 25
    return-void
.end method

.method public read([BII)I
    .locals 0

    .line 1
    iget-object p0, p0, Lg1/i3;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lo8/p;

    .line 4
    .line 5
    invoke-interface {p0, p1, p2, p3}, Lt7/g;->read([BII)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public readFully([BII)V
    .locals 0

    .line 1
    iget-object p0, p0, Lg1/i3;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lo8/p;

    .line 4
    .line 5
    invoke-interface {p0, p1, p2, p3}, Lo8/p;->readFully([BII)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public s(I)I
    .locals 4

    .line 1
    iget-object v0, p0, Lg1/i3;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lg1/i3;

    .line 4
    .line 5
    const/16 v1, 0x40

    .line 6
    .line 7
    const-wide/16 v2, 0x1

    .line 8
    .line 9
    if-nez v0, :cond_1

    .line 10
    .line 11
    if-lt p1, v1, :cond_0

    .line 12
    .line 13
    iget-wide p0, p0, Lg1/i3;->e:J

    .line 14
    .line 15
    invoke-static {p0, p1}, Ljava/lang/Long;->bitCount(J)I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0

    .line 20
    :cond_0
    iget-wide v0, p0, Lg1/i3;->e:J

    .line 21
    .line 22
    shl-long p0, v2, p1

    .line 23
    .line 24
    sub-long/2addr p0, v2

    .line 25
    and-long/2addr p0, v0

    .line 26
    invoke-static {p0, p1}, Ljava/lang/Long;->bitCount(J)I

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    return p0

    .line 31
    :cond_1
    if-ge p1, v1, :cond_2

    .line 32
    .line 33
    iget-wide v0, p0, Lg1/i3;->e:J

    .line 34
    .line 35
    shl-long p0, v2, p1

    .line 36
    .line 37
    sub-long/2addr p0, v2

    .line 38
    and-long/2addr p0, v0

    .line 39
    invoke-static {p0, p1}, Ljava/lang/Long;->bitCount(J)I

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    return p0

    .line 44
    :cond_2
    sub-int/2addr p1, v1

    .line 45
    invoke-virtual {v0, p1}, Lg1/i3;->s(I)I

    .line 46
    .line 47
    .line 48
    move-result p1

    .line 49
    iget-wide v0, p0, Lg1/i3;->e:J

    .line 50
    .line 51
    invoke-static {v0, v1}, Ljava/lang/Long;->bitCount(J)I

    .line 52
    .line 53
    .line 54
    move-result p0

    .line 55
    add-int/2addr p0, p1

    .line 56
    return p0
.end method

.method public t()V
    .locals 1

    .line 1
    iget-object v0, p0, Lg1/i3;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lg1/i3;

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    new-instance v0, Lg1/i3;

    .line 8
    .line 9
    invoke-direct {v0}, Lg1/i3;-><init>()V

    .line 10
    .line 11
    .line 12
    iput-object v0, p0, Lg1/i3;->f:Ljava/lang/Object;

    .line 13
    .line 14
    :cond_0
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 3

    .line 1
    iget v0, p0, Lg1/i3;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    iget-object v0, p0, Lg1/i3;->f:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v0, Lg1/i3;

    .line 14
    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    iget-wide v0, p0, Lg1/i3;->e:J

    .line 18
    .line 19
    invoke-static {v0, v1}, Ljava/lang/Long;->toBinaryString(J)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 25
    .line 26
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 27
    .line 28
    .line 29
    iget-object v1, p0, Lg1/i3;->f:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast v1, Lg1/i3;

    .line 32
    .line 33
    invoke-virtual {v1}, Lg1/i3;->toString()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    const-string v1, "xx"

    .line 41
    .line 42
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    iget-wide v1, p0, Lg1/i3;->e:J

    .line 46
    .line 47
    invoke-static {v1, v2}, Ljava/lang/Long;->toBinaryString(J)Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    :goto_0
    return-object p0

    .line 59
    :pswitch_data_0
    .packed-switch 0x3
        :pswitch_0
    .end packed-switch
.end method

.method public u(I)Z
    .locals 4

    .line 1
    const/16 v0, 0x40

    .line 2
    .line 3
    if-lt p1, v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lg1/i3;->t()V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lg1/i3;->f:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Lg1/i3;

    .line 11
    .line 12
    sub-int/2addr p1, v0

    .line 13
    invoke-virtual {p0, p1}, Lg1/i3;->u(I)Z

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    return p0

    .line 18
    :cond_0
    iget-wide v0, p0, Lg1/i3;->e:J

    .line 19
    .line 20
    const-wide/16 v2, 0x1

    .line 21
    .line 22
    shl-long p0, v2, p1

    .line 23
    .line 24
    and-long/2addr p0, v0

    .line 25
    const-wide/16 v0, 0x0

    .line 26
    .line 27
    cmp-long p0, p0, v0

    .line 28
    .line 29
    if-eqz p0, :cond_1

    .line 30
    .line 31
    const/4 p0, 0x1

    .line 32
    return p0

    .line 33
    :cond_1
    const/4 p0, 0x0

    .line 34
    return p0
.end method

.method public v(IZ)V
    .locals 9

    .line 1
    const/16 v0, 0x40

    .line 2
    .line 3
    if-lt p1, v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lg1/i3;->t()V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lg1/i3;->f:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Lg1/i3;

    .line 11
    .line 12
    sub-int/2addr p1, v0

    .line 13
    invoke-virtual {p0, p1, p2}, Lg1/i3;->v(IZ)V

    .line 14
    .line 15
    .line 16
    return-void

    .line 17
    :cond_0
    iget-wide v0, p0, Lg1/i3;->e:J

    .line 18
    .line 19
    const-wide/high16 v2, -0x8000000000000000L

    .line 20
    .line 21
    and-long/2addr v2, v0

    .line 22
    const-wide/16 v4, 0x0

    .line 23
    .line 24
    cmp-long v2, v2, v4

    .line 25
    .line 26
    const/4 v3, 0x0

    .line 27
    const/4 v4, 0x1

    .line 28
    if-eqz v2, :cond_1

    .line 29
    .line 30
    move v2, v4

    .line 31
    goto :goto_0

    .line 32
    :cond_1
    move v2, v3

    .line 33
    :goto_0
    const-wide/16 v5, 0x1

    .line 34
    .line 35
    shl-long v7, v5, p1

    .line 36
    .line 37
    sub-long/2addr v7, v5

    .line 38
    and-long v5, v0, v7

    .line 39
    .line 40
    not-long v7, v7

    .line 41
    and-long/2addr v0, v7

    .line 42
    shl-long/2addr v0, v4

    .line 43
    or-long/2addr v0, v5

    .line 44
    iput-wide v0, p0, Lg1/i3;->e:J

    .line 45
    .line 46
    if-eqz p2, :cond_2

    .line 47
    .line 48
    invoke-virtual {p0, p1}, Lg1/i3;->z(I)V

    .line 49
    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_2
    invoke-virtual {p0, p1}, Lg1/i3;->r(I)V

    .line 53
    .line 54
    .line 55
    :goto_1
    if-nez v2, :cond_4

    .line 56
    .line 57
    iget-object p1, p0, Lg1/i3;->f:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast p1, Lg1/i3;

    .line 60
    .line 61
    if-eqz p1, :cond_3

    .line 62
    .line 63
    goto :goto_2

    .line 64
    :cond_3
    return-void

    .line 65
    :cond_4
    :goto_2
    invoke-virtual {p0}, Lg1/i3;->t()V

    .line 66
    .line 67
    .line 68
    iget-object p0, p0, Lg1/i3;->f:Ljava/lang/Object;

    .line 69
    .line 70
    check-cast p0, Lg1/i3;

    .line 71
    .line 72
    invoke-virtual {p0, v3, v2}, Lg1/i3;->v(IZ)V

    .line 73
    .line 74
    .line 75
    return-void
.end method

.method public w(J)F
    .locals 2

    .line 1
    iget-object p0, p0, Lg1/i3;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lg1/w1;

    .line 4
    .line 5
    sget-object v0, Lg1/w1;->e:Lg1/w1;

    .line 6
    .line 7
    if-ne p0, v0, :cond_0

    .line 8
    .line 9
    const/16 p0, 0x20

    .line 10
    .line 11
    shr-long p0, p1, p0

    .line 12
    .line 13
    :goto_0
    long-to-int p0, p0

    .line 14
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    return p0

    .line 19
    :cond_0
    const-wide v0, 0xffffffffL

    .line 20
    .line 21
    .line 22
    .line 23
    .line 24
    and-long p0, p1, v0

    .line 25
    .line 26
    goto :goto_0
.end method

.method public x(I)Z
    .locals 10

    .line 1
    const/16 v0, 0x40

    .line 2
    .line 3
    if-lt p1, v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lg1/i3;->t()V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lg1/i3;->f:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Lg1/i3;

    .line 11
    .line 12
    sub-int/2addr p1, v0

    .line 13
    invoke-virtual {p0, p1}, Lg1/i3;->x(I)Z

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    return p0

    .line 18
    :cond_0
    const-wide/16 v0, 0x1

    .line 19
    .line 20
    shl-long v2, v0, p1

    .line 21
    .line 22
    iget-wide v4, p0, Lg1/i3;->e:J

    .line 23
    .line 24
    and-long v6, v4, v2

    .line 25
    .line 26
    const-wide/16 v8, 0x0

    .line 27
    .line 28
    cmp-long p1, v6, v8

    .line 29
    .line 30
    const/4 v6, 0x1

    .line 31
    const/4 v7, 0x0

    .line 32
    if-eqz p1, :cond_1

    .line 33
    .line 34
    move p1, v6

    .line 35
    goto :goto_0

    .line 36
    :cond_1
    move p1, v7

    .line 37
    :goto_0
    not-long v8, v2

    .line 38
    and-long/2addr v4, v8

    .line 39
    iput-wide v4, p0, Lg1/i3;->e:J

    .line 40
    .line 41
    sub-long/2addr v2, v0

    .line 42
    and-long v0, v4, v2

    .line 43
    .line 44
    not-long v2, v2

    .line 45
    and-long/2addr v2, v4

    .line 46
    invoke-static {v2, v3, v6}, Ljava/lang/Long;->rotateRight(JI)J

    .line 47
    .line 48
    .line 49
    move-result-wide v2

    .line 50
    or-long/2addr v0, v2

    .line 51
    iput-wide v0, p0, Lg1/i3;->e:J

    .line 52
    .line 53
    iget-object v0, p0, Lg1/i3;->f:Ljava/lang/Object;

    .line 54
    .line 55
    check-cast v0, Lg1/i3;

    .line 56
    .line 57
    if-eqz v0, :cond_3

    .line 58
    .line 59
    invoke-virtual {v0, v7}, Lg1/i3;->u(I)Z

    .line 60
    .line 61
    .line 62
    move-result v0

    .line 63
    if-eqz v0, :cond_2

    .line 64
    .line 65
    const/16 v0, 0x3f

    .line 66
    .line 67
    invoke-virtual {p0, v0}, Lg1/i3;->z(I)V

    .line 68
    .line 69
    .line 70
    :cond_2
    iget-object p0, p0, Lg1/i3;->f:Ljava/lang/Object;

    .line 71
    .line 72
    check-cast p0, Lg1/i3;

    .line 73
    .line 74
    invoke-virtual {p0, v7}, Lg1/i3;->x(I)Z

    .line 75
    .line 76
    .line 77
    :cond_3
    return p1
.end method

.method public y()V
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    iput-wide v0, p0, Lg1/i3;->e:J

    .line 4
    .line 5
    iget-object p0, p0, Lg1/i3;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lg1/i3;

    .line 8
    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    invoke-virtual {p0}, Lg1/i3;->y()V

    .line 12
    .line 13
    .line 14
    :cond_0
    return-void
.end method

.method public z(I)V
    .locals 4

    .line 1
    const/16 v0, 0x40

    .line 2
    .line 3
    if-lt p1, v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lg1/i3;->t()V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lg1/i3;->f:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Lg1/i3;

    .line 11
    .line 12
    sub-int/2addr p1, v0

    .line 13
    invoke-virtual {p0, p1}, Lg1/i3;->z(I)V

    .line 14
    .line 15
    .line 16
    return-void

    .line 17
    :cond_0
    iget-wide v0, p0, Lg1/i3;->e:J

    .line 18
    .line 19
    const-wide/16 v2, 0x1

    .line 20
    .line 21
    shl-long/2addr v2, p1

    .line 22
    or-long/2addr v0, v2

    .line 23
    iput-wide v0, p0, Lg1/i3;->e:J

    .line 24
    .line 25
    return-void
.end method
