.class public final Lvv/x0;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lx2/s;

.field public final synthetic h:Lay0/o;


# direct methods
.method public synthetic constructor <init>(Lx2/s;Lay0/o;I)V
    .locals 0

    .line 1
    iput p3, p0, Lvv/x0;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lvv/x0;->g:Lx2/s;

    .line 4
    .line 5
    iput-object p2, p0, Lvv/x0;->h:Lay0/o;

    .line 6
    .line 7
    const/4 p1, 0x2

    .line 8
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lvv/x0;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v5, p1

    .line 7
    check-cast v5, Ll2/o;

    .line 8
    .line 9
    check-cast p2, Ljava/lang/Number;

    .line 10
    .line 11
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 12
    .line 13
    .line 14
    move-result p1

    .line 15
    and-int/lit8 p1, p1, 0xb

    .line 16
    .line 17
    const/4 p2, 0x2

    .line 18
    if-ne p1, p2, :cond_1

    .line 19
    .line 20
    move-object p1, v5

    .line 21
    check-cast p1, Ll2/t;

    .line 22
    .line 23
    invoke-virtual {p1}, Ll2/t;->A()Z

    .line 24
    .line 25
    .line 26
    move-result p2

    .line 27
    if-nez p2, :cond_0

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 31
    .line 32
    .line 33
    goto :goto_1

    .line 34
    :cond_1
    :goto_0
    const/4 v6, 0x0

    .line 35
    const/4 v7, 0x6

    .line 36
    iget-object v1, p0, Lvv/x0;->g:Lx2/s;

    .line 37
    .line 38
    const/4 v2, 0x0

    .line 39
    const/4 v3, 0x0

    .line 40
    iget-object v4, p0, Lvv/x0;->h:Lay0/o;

    .line 41
    .line 42
    invoke-static/range {v1 .. v7}, Llp/dc;->a(Lx2/s;Lvv/n0;Lxf0/b2;Lay0/o;Ll2/o;II)V

    .line 43
    .line 44
    .line 45
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 46
    .line 47
    return-object p0

    .line 48
    :pswitch_0
    move-object v4, p1

    .line 49
    check-cast v4, Ll2/o;

    .line 50
    .line 51
    check-cast p2, Ljava/lang/Number;

    .line 52
    .line 53
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 54
    .line 55
    .line 56
    move-result p1

    .line 57
    and-int/lit8 p1, p1, 0xb

    .line 58
    .line 59
    const/4 p2, 0x2

    .line 60
    if-ne p1, p2, :cond_3

    .line 61
    .line 62
    move-object p1, v4

    .line 63
    check-cast p1, Ll2/t;

    .line 64
    .line 65
    invoke-virtual {p1}, Ll2/t;->A()Z

    .line 66
    .line 67
    .line 68
    move-result p2

    .line 69
    if-nez p2, :cond_2

    .line 70
    .line 71
    goto :goto_2

    .line 72
    :cond_2
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 73
    .line 74
    .line 75
    goto :goto_3

    .line 76
    :cond_3
    :goto_2
    const/4 v5, 0x0

    .line 77
    const/4 v6, 0x6

    .line 78
    iget-object v0, p0, Lvv/x0;->g:Lx2/s;

    .line 79
    .line 80
    const/4 v1, 0x0

    .line 81
    const/4 v2, 0x0

    .line 82
    iget-object v3, p0, Lvv/x0;->h:Lay0/o;

    .line 83
    .line 84
    invoke-static/range {v0 .. v6}, Llp/dc;->a(Lx2/s;Lvv/n0;Lxf0/b2;Lay0/o;Ll2/o;II)V

    .line 85
    .line 86
    .line 87
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 88
    .line 89
    return-object p0

    .line 90
    nop

    .line 91
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
