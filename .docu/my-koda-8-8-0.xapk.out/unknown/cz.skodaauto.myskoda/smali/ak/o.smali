.class public final synthetic Lak/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(IILay0/k;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Lak/o;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Lak/o;->e:I

    iput-object p3, p0, Lak/o;->g:Ljava/lang/Object;

    iput p2, p0, Lak/o;->f:I

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;III)V
    .locals 0

    .line 2
    iput p4, p0, Lak/o;->d:I

    iput-object p1, p0, Lak/o;->g:Ljava/lang/Object;

    iput p2, p0, Lak/o;->e:I

    iput p3, p0, Lak/o;->f:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lak/o;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lak/o;->g:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lay0/a;

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
    iget p2, p0, Lak/o;->e:I

    .line 18
    .line 19
    or-int/lit8 p2, p2, 0x1

    .line 20
    .line 21
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 22
    .line 23
    .line 24
    move-result p2

    .line 25
    iget p0, p0, Lak/o;->f:I

    .line 26
    .line 27
    invoke-static {p2, p0, v0, p1}, Lvb0/a;->b(IILay0/a;Ll2/o;)V

    .line 28
    .line 29
    .line 30
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 31
    .line 32
    return-object p0

    .line 33
    :pswitch_0
    iget-object v0, p0, Lak/o;->g:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast v0, Ljava/util/List;

    .line 36
    .line 37
    check-cast p1, Ll2/o;

    .line 38
    .line 39
    check-cast p2, Ljava/lang/Integer;

    .line 40
    .line 41
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 42
    .line 43
    .line 44
    iget p2, p0, Lak/o;->f:I

    .line 45
    .line 46
    or-int/lit8 p2, p2, 0x1

    .line 47
    .line 48
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 49
    .line 50
    .line 51
    move-result p2

    .line 52
    iget p0, p0, Lak/o;->e:I

    .line 53
    .line 54
    invoke-static {v0, p0, p1, p2}, Li91/j0;->t0(Ljava/util/List;ILl2/o;I)V

    .line 55
    .line 56
    .line 57
    goto :goto_0

    .line 58
    :pswitch_1
    iget-object v0, p0, Lak/o;->g:Ljava/lang/Object;

    .line 59
    .line 60
    check-cast v0, Lay0/k;

    .line 61
    .line 62
    check-cast p1, Ll2/o;

    .line 63
    .line 64
    check-cast p2, Ljava/lang/Integer;

    .line 65
    .line 66
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 67
    .line 68
    .line 69
    iget p2, p0, Lak/o;->f:I

    .line 70
    .line 71
    or-int/lit8 p2, p2, 0x1

    .line 72
    .line 73
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 74
    .line 75
    .line 76
    move-result p2

    .line 77
    iget p0, p0, Lak/o;->e:I

    .line 78
    .line 79
    invoke-static {p0, v0, p1, p2}, Lbk/a;->w(ILay0/k;Ll2/o;I)V

    .line 80
    .line 81
    .line 82
    goto :goto_0

    .line 83
    :pswitch_2
    iget-object v0, p0, Lak/o;->g:Ljava/lang/Object;

    .line 84
    .line 85
    check-cast v0, Lnd/b;

    .line 86
    .line 87
    check-cast p1, Ll2/o;

    .line 88
    .line 89
    check-cast p2, Ljava/lang/Integer;

    .line 90
    .line 91
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 92
    .line 93
    .line 94
    iget p2, p0, Lak/o;->f:I

    .line 95
    .line 96
    or-int/lit8 p2, p2, 0x1

    .line 97
    .line 98
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 99
    .line 100
    .line 101
    move-result p2

    .line 102
    iget p0, p0, Lak/o;->e:I

    .line 103
    .line 104
    invoke-static {v0, p0, p1, p2}, Lak/a;->o(Lnd/b;ILl2/o;I)V

    .line 105
    .line 106
    .line 107
    goto :goto_0

    .line 108
    nop

    .line 109
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
