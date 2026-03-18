.class public final synthetic Ld90/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:I


# direct methods
.method public synthetic constructor <init>(III)V
    .locals 0

    .line 1
    iput p3, p0, Ld90/i;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Ld90/i;->e:I

    iput p2, p0, Ld90/i;->f:I

    return-void
.end method

.method public synthetic constructor <init>(IIII)V
    .locals 0

    .line 2
    iput p4, p0, Ld90/i;->d:I

    iput p1, p0, Ld90/i;->e:I

    iput p2, p0, Ld90/i;->f:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ld90/i;->d:I

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
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    const/4 p2, 0x1

    .line 14
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 15
    .line 16
    .line 17
    move-result p2

    .line 18
    iget v0, p0, Ld90/i;->e:I

    .line 19
    .line 20
    iget p0, p0, Ld90/i;->f:I

    .line 21
    .line 22
    invoke-static {v0, p0, p1, p2}, Li40/m2;->b(IILl2/o;I)V

    .line 23
    .line 24
    .line 25
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 26
    .line 27
    return-object p0

    .line 28
    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 29
    .line 30
    .line 31
    const/4 p2, 0x1

    .line 32
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 33
    .line 34
    .line 35
    move-result p2

    .line 36
    iget v0, p0, Ld90/i;->e:I

    .line 37
    .line 38
    iget p0, p0, Ld90/i;->f:I

    .line 39
    .line 40
    invoke-static {v0, p0, p1, p2}, Li40/q;->g(IILl2/o;I)V

    .line 41
    .line 42
    .line 43
    goto :goto_0

    .line 44
    :pswitch_1
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 45
    .line 46
    .line 47
    iget p2, p0, Ld90/i;->f:I

    .line 48
    .line 49
    or-int/lit8 p2, p2, 0x1

    .line 50
    .line 51
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 52
    .line 53
    .line 54
    move-result p2

    .line 55
    iget p0, p0, Ld90/i;->e:I

    .line 56
    .line 57
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 58
    .line 59
    invoke-static {p0, p2, p1, v0}, Ldl0/e;->i(IILl2/o;Lx2/s;)V

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
    iget p2, p0, Ld90/i;->f:I

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
    iget p0, p0, Ld90/i;->e:I

    .line 75
    .line 76
    invoke-static {p0, p2, p1}, Ljp/bg;->a(IILl2/o;)V

    .line 77
    .line 78
    .line 79
    goto :goto_0

    .line 80
    nop

    .line 81
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
