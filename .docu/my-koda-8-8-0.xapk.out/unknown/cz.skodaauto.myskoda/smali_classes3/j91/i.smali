.class public final synthetic Lj91/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Lt2/b;


# direct methods
.method public synthetic constructor <init>(ZLt2/b;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Lj91/i;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Lj91/i;->e:Z

    iput-object p2, p0, Lj91/i;->f:Lt2/b;

    return-void
.end method

.method public synthetic constructor <init>(ZLt2/b;I)V
    .locals 0

    .line 2
    const/4 p3, 0x0

    iput p3, p0, Lj91/i;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Lj91/i;->e:Z

    iput-object p2, p0, Lj91/i;->f:Lt2/b;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lj91/i;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 11
    .line 12
    .line 13
    move-result p2

    .line 14
    and-int/lit8 v0, p2, 0x3

    .line 15
    .line 16
    const/4 v1, 0x2

    .line 17
    const/4 v2, 0x1

    .line 18
    const/4 v3, 0x0

    .line 19
    if-eq v0, v1, :cond_0

    .line 20
    .line 21
    move v0, v2

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    move v0, v3

    .line 24
    :goto_0
    and-int/2addr p2, v2

    .line 25
    check-cast p1, Ll2/t;

    .line 26
    .line 27
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 28
    .line 29
    .line 30
    move-result p2

    .line 31
    if-eqz p2, :cond_2

    .line 32
    .line 33
    iget-boolean p2, p0, Lj91/i;->e:Z

    .line 34
    .line 35
    iget-object p0, p0, Lj91/i;->f:Lt2/b;

    .line 36
    .line 37
    if-eqz p2, :cond_1

    .line 38
    .line 39
    const p2, -0x33aabf55    # -5.5902892E7f

    .line 40
    .line 41
    .line 42
    invoke-virtual {p1, p2}, Ll2/t;->Y(I)V

    .line 43
    .line 44
    .line 45
    new-instance p2, Lzb/w;

    .line 46
    .line 47
    const/4 v0, 0x0

    .line 48
    invoke-direct {p2, p0, v0}, Lzb/w;-><init>(Lt2/b;I)V

    .line 49
    .line 50
    .line 51
    const p0, 0x6a0b2753

    .line 52
    .line 53
    .line 54
    invoke-static {p0, p1, p2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    const/4 p2, 0x6

    .line 59
    invoke-static {p0, p1, p2}, Lkp/u8;->a(Lt2/b;Ll2/o;I)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {p1, v3}, Ll2/t;->q(Z)V

    .line 63
    .line 64
    .line 65
    goto :goto_1

    .line 66
    :cond_1
    const p2, -0x33a9b31c    # -5.6177552E7f

    .line 67
    .line 68
    .line 69
    invoke-virtual {p1, p2}, Ll2/t;->Y(I)V

    .line 70
    .line 71
    .line 72
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 73
    .line 74
    .line 75
    move-result-object p2

    .line 76
    invoke-virtual {p0, p1, p2}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    invoke-virtual {p1, v3}, Ll2/t;->q(Z)V

    .line 80
    .line 81
    .line 82
    goto :goto_1

    .line 83
    :cond_2
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 84
    .line 85
    .line 86
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 87
    .line 88
    return-object p0

    .line 89
    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 90
    .line 91
    .line 92
    const/16 p2, 0x31

    .line 93
    .line 94
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 95
    .line 96
    .line 97
    move-result p2

    .line 98
    iget-boolean v0, p0, Lj91/i;->e:Z

    .line 99
    .line 100
    iget-object p0, p0, Lj91/i;->f:Lt2/b;

    .line 101
    .line 102
    invoke-static {v0, p0, p1, p2}, Llp/pb;->a(ZLt2/b;Ll2/o;I)V

    .line 103
    .line 104
    .line 105
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 106
    .line 107
    return-object p0

    .line 108
    nop

    .line 109
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
