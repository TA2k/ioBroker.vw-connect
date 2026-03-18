.class public final Lt3/n;
.super Lt3/e1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic i:I


# direct methods
.method public constructor <init>(III)V
    .locals 4

    .line 1
    iput p3, p0, Lt3/n;->i:I

    .line 2
    .line 3
    packed-switch p3, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Lt3/e1;-><init>()V

    .line 7
    .line 8
    .line 9
    int-to-long v0, p1

    .line 10
    const/16 p1, 0x20

    .line 11
    .line 12
    shl-long/2addr v0, p1

    .line 13
    int-to-long p1, p2

    .line 14
    const-wide v2, 0xffffffffL

    .line 15
    .line 16
    .line 17
    .line 18
    .line 19
    and-long/2addr p1, v2

    .line 20
    or-long/2addr p1, v0

    .line 21
    invoke-virtual {p0, p1, p2}, Lt3/e1;->v0(J)V

    .line 22
    .line 23
    .line 24
    return-void

    .line 25
    :pswitch_0
    invoke-direct {p0}, Lt3/e1;-><init>()V

    .line 26
    .line 27
    .line 28
    int-to-long v0, p1

    .line 29
    const/16 p1, 0x20

    .line 30
    .line 31
    shl-long/2addr v0, p1

    .line 32
    int-to-long p1, p2

    .line 33
    const-wide v2, 0xffffffffL

    .line 34
    .line 35
    .line 36
    .line 37
    .line 38
    and-long/2addr p1, v2

    .line 39
    or-long/2addr p1, v0

    .line 40
    invoke-virtual {p0, p1, p2}, Lt3/e1;->v0(J)V

    .line 41
    .line 42
    .line 43
    return-void

    .line 44
    :pswitch_1
    invoke-direct {p0}, Lt3/e1;-><init>()V

    .line 45
    .line 46
    .line 47
    int-to-long v0, p1

    .line 48
    const/16 p1, 0x20

    .line 49
    .line 50
    shl-long/2addr v0, p1

    .line 51
    int-to-long p1, p2

    .line 52
    const-wide v2, 0xffffffffL

    .line 53
    .line 54
    .line 55
    .line 56
    .line 57
    and-long/2addr p1, v2

    .line 58
    or-long/2addr p1, v0

    .line 59
    invoke-virtual {p0, p1, p2}, Lt3/e1;->v0(J)V

    .line 60
    .line 61
    .line 62
    return-void

    .line 63
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method private final B0(JFLay0/k;)V
    .locals 0

    .line 1
    return-void
.end method

.method private final C0(JFLay0/k;)V
    .locals 0

    .line 1
    return-void
.end method

.method private final E0(JFLay0/k;)V
    .locals 0

    .line 1
    return-void
.end method


# virtual methods
.method public final a0(Lt3/a;)I
    .locals 0

    .line 1
    iget p0, p0, Lt3/n;->i:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/high16 p0, -0x80000000

    .line 7
    .line 8
    return p0

    .line 9
    :pswitch_0
    const/high16 p0, -0x80000000

    .line 10
    .line 11
    return p0

    .line 12
    :pswitch_1
    const/high16 p0, -0x80000000

    .line 13
    .line 14
    return p0

    .line 15
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final l0(JFLay0/k;)V
    .locals 0

    .line 1
    iget p0, p0, Lt3/n;->i:I

    .line 2
    .line 3
    return-void
.end method
