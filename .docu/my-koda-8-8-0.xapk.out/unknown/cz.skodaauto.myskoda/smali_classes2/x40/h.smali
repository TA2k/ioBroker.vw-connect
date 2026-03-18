.class public final synthetic Lx40/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/a;

.field public final synthetic f:Lw40/l;


# direct methods
.method public synthetic constructor <init>(Lay0/a;Lw40/l;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Lx40/h;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lx40/h;->e:Lay0/a;

    iput-object p2, p0, Lx40/h;->f:Lw40/l;

    return-void
.end method

.method public synthetic constructor <init>(Lw40/l;Lay0/a;I)V
    .locals 0

    .line 2
    const/4 p3, 0x0

    iput p3, p0, Lx40/h;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lx40/h;->f:Lw40/l;

    iput-object p2, p0, Lx40/h;->e:Lay0/a;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lx40/h;->d:I

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
    if-eq v0, v1, :cond_0

    .line 19
    .line 20
    move v0, v2

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 v0, 0x0

    .line 23
    :goto_0
    and-int/2addr p2, v2

    .line 24
    move-object v5, p1

    .line 25
    check-cast v5, Ll2/t;

    .line 26
    .line 27
    invoke-virtual {v5, p2, v0}, Ll2/t;->O(IZ)Z

    .line 28
    .line 29
    .line 30
    move-result p1

    .line 31
    if-eqz p1, :cond_1

    .line 32
    .line 33
    new-instance p1, Lp4/a;

    .line 34
    .line 35
    const/16 p2, 0x1d

    .line 36
    .line 37
    iget-object v0, p0, Lx40/h;->e:Lay0/a;

    .line 38
    .line 39
    iget-object p0, p0, Lx40/h;->f:Lw40/l;

    .line 40
    .line 41
    invoke-direct {p1, p2, v0, p0}, Lp4/a;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    const p0, -0x3a50fcd6

    .line 45
    .line 46
    .line 47
    invoke-static {p0, v5, p1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 48
    .line 49
    .line 50
    move-result-object v4

    .line 51
    const/16 v6, 0x180

    .line 52
    .line 53
    const/4 v7, 0x3

    .line 54
    const/4 v1, 0x0

    .line 55
    const-wide/16 v2, 0x0

    .line 56
    .line 57
    invoke-static/range {v1 .. v7}, Lxf0/i0;->t(Lx2/s;JLt2/b;Ll2/o;II)V

    .line 58
    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_1
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 62
    .line 63
    .line 64
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 65
    .line 66
    return-object p0

    .line 67
    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 68
    .line 69
    .line 70
    const/4 p2, 0x1

    .line 71
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 72
    .line 73
    .line 74
    move-result p2

    .line 75
    iget-object v0, p0, Lx40/h;->f:Lw40/l;

    .line 76
    .line 77
    iget-object p0, p0, Lx40/h;->e:Lay0/a;

    .line 78
    .line 79
    invoke-static {v0, p0, p1, p2}, Lx40/a;->n(Lw40/l;Lay0/a;Ll2/o;I)V

    .line 80
    .line 81
    .line 82
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 83
    .line 84
    return-object p0

    .line 85
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
