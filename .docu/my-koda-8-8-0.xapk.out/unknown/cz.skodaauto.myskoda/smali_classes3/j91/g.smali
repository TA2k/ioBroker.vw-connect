.class public final synthetic Lj91/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:J

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(JLt2/b;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Lj91/g;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-wide p1, p0, Lj91/g;->e:J

    iput-object p3, p0, Lj91/g;->f:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(JLt2/b;I)V
    .locals 0

    .line 2
    const/4 p4, 0x0

    iput p4, p0, Lj91/g;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-wide p1, p0, Lj91/g;->e:J

    iput-object p3, p0, Lj91/g;->f:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Li2/l0;JI)V
    .locals 0

    .line 3
    const/4 p4, 0x2

    iput p4, p0, Lj91/g;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lj91/g;->f:Ljava/lang/Object;

    iput-wide p2, p0, Lj91/g;->e:J

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lj91/g;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lj91/g;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Li2/l0;

    .line 9
    .line 10
    check-cast p1, Ll2/o;

    .line 11
    .line 12
    check-cast p2, Ljava/lang/Integer;

    .line 13
    .line 14
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    const/4 p2, 0x1

    .line 18
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 19
    .line 20
    .line 21
    move-result p2

    .line 22
    iget-wide v1, p0, Lj91/g;->e:J

    .line 23
    .line 24
    invoke-static {v0, v1, v2, p1, p2}, Lj2/i;->a(Li2/l0;JLl2/o;I)V

    .line 25
    .line 26
    .line 27
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    return-object p0

    .line 30
    :pswitch_0
    iget-object v0, p0, Lj91/g;->f:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast v0, Lt2/b;

    .line 33
    .line 34
    check-cast p1, Ll2/o;

    .line 35
    .line 36
    check-cast p2, Ljava/lang/Integer;

    .line 37
    .line 38
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 39
    .line 40
    .line 41
    move-result p2

    .line 42
    and-int/lit8 v1, p2, 0x3

    .line 43
    .line 44
    const/4 v2, 0x2

    .line 45
    const/4 v3, 0x1

    .line 46
    if-eq v1, v2, :cond_0

    .line 47
    .line 48
    move v1, v3

    .line 49
    goto :goto_1

    .line 50
    :cond_0
    const/4 v1, 0x0

    .line 51
    :goto_1
    and-int/2addr p2, v3

    .line 52
    check-cast p1, Ll2/t;

    .line 53
    .line 54
    invoke-virtual {p1, p2, v1}, Ll2/t;->O(IZ)Z

    .line 55
    .line 56
    .line 57
    move-result p2

    .line 58
    if-eqz p2, :cond_1

    .line 59
    .line 60
    sget-object p2, Lh2/p1;->a:Ll2/e0;

    .line 61
    .line 62
    iget-wide v1, p0, Lj91/g;->e:J

    .line 63
    .line 64
    invoke-static {v1, v2}, Le3/s;->d(J)F

    .line 65
    .line 66
    .line 67
    move-result p0

    .line 68
    invoke-static {v1, v2, p0}, Le3/s;->b(JF)J

    .line 69
    .line 70
    .line 71
    move-result-wide v1

    .line 72
    invoke-static {v1, v2, p2}, Lf2/m0;->s(JLl2/e0;)Ll2/t1;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    new-instance p2, Ld71/d;

    .line 77
    .line 78
    const/16 v1, 0x17

    .line 79
    .line 80
    invoke-direct {p2, v0, v1}, Ld71/d;-><init>(Lt2/b;I)V

    .line 81
    .line 82
    .line 83
    const v0, -0x3d03378b

    .line 84
    .line 85
    .line 86
    invoke-static {v0, p1, p2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 87
    .line 88
    .line 89
    move-result-object p2

    .line 90
    const/16 v0, 0x38

    .line 91
    .line 92
    invoke-static {p0, p2, p1, v0}, Ll2/b;->a(Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 93
    .line 94
    .line 95
    goto :goto_2

    .line 96
    :cond_1
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 97
    .line 98
    .line 99
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 100
    .line 101
    return-object p0

    .line 102
    :pswitch_1
    iget-object v0, p0, Lj91/g;->f:Ljava/lang/Object;

    .line 103
    .line 104
    check-cast v0, Lt2/b;

    .line 105
    .line 106
    check-cast p1, Ll2/o;

    .line 107
    .line 108
    check-cast p2, Ljava/lang/Integer;

    .line 109
    .line 110
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 111
    .line 112
    .line 113
    const/16 p2, 0x31

    .line 114
    .line 115
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 116
    .line 117
    .line 118
    move-result p2

    .line 119
    iget-wide v1, p0, Lj91/g;->e:J

    .line 120
    .line 121
    invoke-static {v1, v2, v0, p1, p2}, Llp/ob;->a(JLt2/b;Ll2/o;I)V

    .line 122
    .line 123
    .line 124
    goto :goto_0

    .line 125
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
