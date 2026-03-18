.class public final synthetic Lxf0/r1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lxf0/i0;


# direct methods
.method public synthetic constructor <init>(Lxf0/i0;I)V
    .locals 0

    .line 1
    iput p2, p0, Lxf0/r1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lxf0/r1;->e:Lxf0/i0;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lxf0/r1;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 8
    .line 9
    .line 10
    move-result p2

    .line 11
    packed-switch v0, :pswitch_data_0

    .line 12
    .line 13
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
    iget-object p0, p0, Lxf0/r1;->e:Lxf0/i0;

    .line 34
    .line 35
    check-cast p0, Lxf0/k1;

    .line 36
    .line 37
    iget-object v4, p0, Lxf0/k1;->k:Lay0/a;

    .line 38
    .line 39
    sget-object v2, Lxf0/t1;->h:Lxf0/q3;

    .line 40
    .line 41
    const/16 v6, 0x30

    .line 42
    .line 43
    const/4 v7, 0x4

    .line 44
    const v1, 0x7f080291

    .line 45
    .line 46
    .line 47
    const/4 v3, 0x0

    .line 48
    invoke-static/range {v1 .. v7}, Lxf0/t1;->b(ILxf0/q3;Lx2/s;Lay0/a;Ll2/o;II)V

    .line 49
    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_1
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 53
    .line 54
    .line 55
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    return-object p0

    .line 58
    :pswitch_0
    and-int/lit8 v0, p2, 0x3

    .line 59
    .line 60
    const/4 v1, 0x2

    .line 61
    const/4 v2, 0x1

    .line 62
    if-eq v0, v1, :cond_2

    .line 63
    .line 64
    move v0, v2

    .line 65
    goto :goto_2

    .line 66
    :cond_2
    const/4 v0, 0x0

    .line 67
    :goto_2
    and-int/2addr p2, v2

    .line 68
    move-object v5, p1

    .line 69
    check-cast v5, Ll2/t;

    .line 70
    .line 71
    invoke-virtual {v5, p2, v0}, Ll2/t;->O(IZ)Z

    .line 72
    .line 73
    .line 74
    move-result p1

    .line 75
    if-eqz p1, :cond_3

    .line 76
    .line 77
    sget-object v2, Lxf0/t1;->h:Lxf0/q3;

    .line 78
    .line 79
    iget-object p0, p0, Lxf0/r1;->e:Lxf0/i0;

    .line 80
    .line 81
    check-cast p0, Lxf0/l1;

    .line 82
    .line 83
    iget v1, p0, Lxf0/l1;->k:I

    .line 84
    .line 85
    const/16 v6, 0x30

    .line 86
    .line 87
    const/16 v7, 0xc

    .line 88
    .line 89
    const/4 v3, 0x0

    .line 90
    const/4 v4, 0x0

    .line 91
    invoke-static/range {v1 .. v7}, Lxf0/t1;->b(ILxf0/q3;Lx2/s;Lay0/a;Ll2/o;II)V

    .line 92
    .line 93
    .line 94
    goto :goto_3

    .line 95
    :cond_3
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 96
    .line 97
    .line 98
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 99
    .line 100
    return-object p0

    .line 101
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
