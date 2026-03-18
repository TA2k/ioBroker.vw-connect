.class public final synthetic Li40/k2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:I

.field public final synthetic g:I


# direct methods
.method public synthetic constructor <init>(IIII)V
    .locals 0

    .line 1
    iput p4, p0, Li40/k2;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Li40/k2;->e:I

    iput p2, p0, Li40/k2;->f:I

    iput p3, p0, Li40/k2;->g:I

    return-void
.end method

.method public synthetic constructor <init>(IIIII)V
    .locals 0

    .line 2
    iput p5, p0, Li40/k2;->d:I

    iput p1, p0, Li40/k2;->e:I

    iput p2, p0, Li40/k2;->f:I

    iput p3, p0, Li40/k2;->g:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Li40/k2;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ll2/o;

    .line 7
    .line 8
    check-cast p2, Ljava/lang/Integer;

    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    iget p2, p0, Li40/k2;->g:I

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
    iget v0, p0, Li40/k2;->e:I

    .line 22
    .line 23
    iget p0, p0, Li40/k2;->f:I

    .line 24
    .line 25
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 26
    .line 27
    invoke-static {v0, p0, p2, p1, v1}, Lxf0/y1;->o(IIILl2/o;Lx2/s;)V

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
    move-object v4, p1

    .line 34
    check-cast v4, Ll2/o;

    .line 35
    .line 36
    check-cast p2, Ljava/lang/Integer;

    .line 37
    .line 38
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 39
    .line 40
    .line 41
    const/4 p1, 0x1

    .line 42
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 43
    .line 44
    .line 45
    move-result v3

    .line 46
    iget v0, p0, Li40/k2;->e:I

    .line 47
    .line 48
    iget v1, p0, Li40/k2;->f:I

    .line 49
    .line 50
    iget v2, p0, Li40/k2;->g:I

    .line 51
    .line 52
    sget-object v5, Lx2/p;->b:Lx2/p;

    .line 53
    .line 54
    invoke-static/range {v0 .. v5}, Lpr0/e;->a(IIIILl2/o;Lx2/s;)V

    .line 55
    .line 56
    .line 57
    goto :goto_0

    .line 58
    :pswitch_1
    check-cast p1, Ll2/o;

    .line 59
    .line 60
    check-cast p2, Ljava/lang/Integer;

    .line 61
    .line 62
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 63
    .line 64
    .line 65
    iget p2, p0, Li40/k2;->g:I

    .line 66
    .line 67
    or-int/lit8 p2, p2, 0x1

    .line 68
    .line 69
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 70
    .line 71
    .line 72
    move-result p2

    .line 73
    iget v0, p0, Li40/k2;->e:I

    .line 74
    .line 75
    iget p0, p0, Li40/k2;->f:I

    .line 76
    .line 77
    invoke-static {v0, p0, p1, p2}, Li40/m2;->d(IILl2/o;I)V

    .line 78
    .line 79
    .line 80
    goto :goto_0

    .line 81
    :pswitch_2
    check-cast p1, Ll2/o;

    .line 82
    .line 83
    check-cast p2, Ljava/lang/Integer;

    .line 84
    .line 85
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 86
    .line 87
    .line 88
    const/4 p2, 0x1

    .line 89
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 90
    .line 91
    .line 92
    move-result p2

    .line 93
    iget v0, p0, Li40/k2;->e:I

    .line 94
    .line 95
    iget v1, p0, Li40/k2;->f:I

    .line 96
    .line 97
    iget p0, p0, Li40/k2;->g:I

    .line 98
    .line 99
    invoke-static {v0, v1, p0, p1, p2}, Li40/m2;->a(IIILl2/o;I)V

    .line 100
    .line 101
    .line 102
    goto :goto_0

    .line 103
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
