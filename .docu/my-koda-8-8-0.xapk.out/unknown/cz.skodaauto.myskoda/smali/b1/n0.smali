.class public final Lb1/n0;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lkotlin/jvm/internal/n;


# direct methods
.method public constructor <init>(ILay0/k;)V
    .locals 0

    .line 1
    iput p1, p0, Lb1/n0;->f:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p2, Lkotlin/jvm/internal/n;

    .line 7
    .line 8
    iput-object p2, p0, Lb1/n0;->g:Lkotlin/jvm/internal/n;

    .line 9
    .line 10
    const/4 p1, 0x1

    .line 11
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :pswitch_0
    check-cast p2, Lkotlin/jvm/internal/n;

    .line 16
    .line 17
    iput-object p2, p0, Lb1/n0;->g:Lkotlin/jvm/internal/n;

    .line 18
    .line 19
    const/4 p1, 0x1

    .line 20
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lb1/n0;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lt4/l;

    .line 7
    .line 8
    iget-wide v0, p1, Lt4/l;->a:J

    .line 9
    .line 10
    const/16 p1, 0x20

    .line 11
    .line 12
    shr-long/2addr v0, p1

    .line 13
    long-to-int v0, v0

    .line 14
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    iget-object p0, p0, Lb1/n0;->g:Lkotlin/jvm/internal/n;

    .line 19
    .line 20
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    check-cast p0, Ljava/lang/Number;

    .line 25
    .line 26
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    int-to-long v0, p0

    .line 31
    shl-long p0, v0, p1

    .line 32
    .line 33
    const/4 v0, 0x0

    .line 34
    int-to-long v0, v0

    .line 35
    const-wide v2, 0xffffffffL

    .line 36
    .line 37
    .line 38
    .line 39
    .line 40
    and-long/2addr v0, v2

    .line 41
    or-long/2addr p0, v0

    .line 42
    new-instance v0, Lt4/j;

    .line 43
    .line 44
    invoke-direct {v0, p0, p1}, Lt4/j;-><init>(J)V

    .line 45
    .line 46
    .line 47
    return-object v0

    .line 48
    :pswitch_0
    check-cast p1, Lt4/l;

    .line 49
    .line 50
    iget-wide v0, p1, Lt4/l;->a:J

    .line 51
    .line 52
    const/16 p1, 0x20

    .line 53
    .line 54
    shr-long/2addr v0, p1

    .line 55
    long-to-int v0, v0

    .line 56
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    iget-object p0, p0, Lb1/n0;->g:Lkotlin/jvm/internal/n;

    .line 61
    .line 62
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    check-cast p0, Ljava/lang/Number;

    .line 67
    .line 68
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 69
    .line 70
    .line 71
    move-result p0

    .line 72
    int-to-long v0, p0

    .line 73
    shl-long p0, v0, p1

    .line 74
    .line 75
    const/4 v0, 0x0

    .line 76
    int-to-long v0, v0

    .line 77
    const-wide v2, 0xffffffffL

    .line 78
    .line 79
    .line 80
    .line 81
    .line 82
    and-long/2addr v0, v2

    .line 83
    or-long/2addr p0, v0

    .line 84
    new-instance v0, Lt4/j;

    .line 85
    .line 86
    invoke-direct {v0, p0, p1}, Lt4/j;-><init>(J)V

    .line 87
    .line 88
    .line 89
    return-object v0

    .line 90
    nop

    .line 91
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
