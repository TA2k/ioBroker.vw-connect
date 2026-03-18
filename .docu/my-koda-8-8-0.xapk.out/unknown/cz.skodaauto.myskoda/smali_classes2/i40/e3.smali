.class public final synthetic Li40/e3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:F

.field public final synthetic f:I


# direct methods
.method public synthetic constructor <init>(FII)V
    .locals 0

    .line 1
    iput p3, p0, Li40/e3;->d:I

    iput p1, p0, Li40/e3;->e:F

    iput p2, p0, Li40/e3;->f:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(IFI)V
    .locals 0

    .line 2
    const/4 p3, 0x0

    iput p3, p0, Li40/e3;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Li40/e3;->f:I

    iput p2, p0, Li40/e3;->e:F

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Li40/e3;->d:I

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
    iget p2, p0, Li40/e3;->f:I

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
    iget p0, p0, Li40/e3;->e:F

    .line 22
    .line 23
    invoke-static {p0, p2, p1}, Llp/bf;->d(FILl2/o;)V

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
    iget p2, p0, Li40/e3;->f:I

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
    iget p0, p0, Li40/e3;->e:F

    .line 41
    .line 42
    invoke-static {p0, p2, p1}, Llp/bf;->c(FILl2/o;)V

    .line 43
    .line 44
    .line 45
    goto :goto_0

    .line 46
    :pswitch_1
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 47
    .line 48
    .line 49
    iget p2, p0, Li40/e3;->f:I

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
    iget p0, p0, Li40/e3;->e:F

    .line 58
    .line 59
    invoke-static {p0, p2, p1}, Llp/bf;->b(FILl2/o;)V

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
    iget p2, p0, Li40/e3;->f:I

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
    iget p0, p0, Li40/e3;->e:F

    .line 75
    .line 76
    invoke-static {p0, p2, p1}, Llp/bf;->a(FILl2/o;)V

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
    const/4 p2, 0x1

    .line 84
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 85
    .line 86
    .line 87
    move-result p2

    .line 88
    iget v0, p0, Li40/e3;->f:I

    .line 89
    .line 90
    iget p0, p0, Li40/e3;->e:F

    .line 91
    .line 92
    invoke-static {v0, p0, p1, p2}, Li40/f3;->f(IFLl2/o;I)V

    .line 93
    .line 94
    .line 95
    goto :goto_0

    .line 96
    nop

    .line 97
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
