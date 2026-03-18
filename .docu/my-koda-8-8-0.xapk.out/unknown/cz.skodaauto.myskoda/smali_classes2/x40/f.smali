.class public final synthetic Lx40/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lx2/s;

.field public final synthetic f:I


# direct methods
.method public synthetic constructor <init>(Lx2/s;II)V
    .locals 0

    .line 1
    iput p3, p0, Lx40/f;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lx40/f;->e:Lx2/s;

    .line 4
    .line 5
    iput p2, p0, Lx40/f;->f:I

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lx40/f;->d:I

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
    iget p2, p0, Lx40/f;->f:I

    .line 14
    .line 15
    or-int/lit8 p2, p2, 0x1

    .line 16
    .line 17
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 18
    .line 19
    .line 20
    move-result p2

    .line 21
    iget-object p0, p0, Lx40/f;->e:Lx2/s;

    .line 22
    .line 23
    invoke-static {p0, p1, p2}, Lz70/l;->I(Lx2/s;Ll2/o;I)V

    .line 24
    .line 25
    .line 26
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 27
    .line 28
    return-object p0

    .line 29
    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 30
    .line 31
    .line 32
    iget p2, p0, Lx40/f;->f:I

    .line 33
    .line 34
    or-int/lit8 p2, p2, 0x1

    .line 35
    .line 36
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 37
    .line 38
    .line 39
    move-result p2

    .line 40
    iget-object p0, p0, Lx40/f;->e:Lx2/s;

    .line 41
    .line 42
    invoke-static {p0, p1, p2}, Lz70/l;->I(Lx2/s;Ll2/o;I)V

    .line 43
    .line 44
    .line 45
    goto :goto_0

    .line 46
    :pswitch_1
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 47
    .line 48
    .line 49
    iget p2, p0, Lx40/f;->f:I

    .line 50
    .line 51
    or-int/lit8 p2, p2, 0x1

    .line 52
    .line 53
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 54
    .line 55
    .line 56
    move-result p2

    .line 57
    iget-object p0, p0, Lx40/f;->e:Lx2/s;

    .line 58
    .line 59
    invoke-static {p0, p1, p2}, Lxk0/h;->T(Lx2/s;Ll2/o;I)V

    .line 60
    .line 61
    .line 62
    goto :goto_0

    .line 63
    :pswitch_2
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 64
    .line 65
    .line 66
    iget p2, p0, Lx40/f;->f:I

    .line 67
    .line 68
    or-int/lit8 p2, p2, 0x1

    .line 69
    .line 70
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 71
    .line 72
    .line 73
    move-result p2

    .line 74
    iget-object p0, p0, Lx40/f;->e:Lx2/s;

    .line 75
    .line 76
    invoke-static {p0, p1, p2}, Lxf0/i0;->C(Lx2/s;Ll2/o;I)V

    .line 77
    .line 78
    .line 79
    goto :goto_0

    .line 80
    :pswitch_3
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 81
    .line 82
    .line 83
    iget p2, p0, Lx40/f;->f:I

    .line 84
    .line 85
    or-int/lit8 p2, p2, 0x1

    .line 86
    .line 87
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 88
    .line 89
    .line 90
    move-result p2

    .line 91
    iget-object p0, p0, Lx40/f;->e:Lx2/s;

    .line 92
    .line 93
    invoke-static {p0, p1, p2}, Lx40/a;->t(Lx2/s;Ll2/o;I)V

    .line 94
    .line 95
    .line 96
    goto :goto_0

    .line 97
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
