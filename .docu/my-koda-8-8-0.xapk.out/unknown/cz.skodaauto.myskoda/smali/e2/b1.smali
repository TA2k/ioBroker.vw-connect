.class public final synthetic Le2/b1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lt4/c;

.field public final synthetic f:Ll2/b1;


# direct methods
.method public synthetic constructor <init>(Lt4/c;Ll2/b1;I)V
    .locals 0

    .line 1
    iput p3, p0, Le2/b1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Le2/b1;->e:Lt4/c;

    .line 4
    .line 5
    iput-object p2, p0, Le2/b1;->f:Ll2/b1;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Le2/b1;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    iget-object v2, p0, Le2/b1;->f:Ll2/b1;

    .line 6
    .line 7
    iget-object p0, p0, Le2/b1;->e:Lt4/c;

    .line 8
    .line 9
    packed-switch v0, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    check-cast p1, Lg4/l0;

    .line 13
    .line 14
    const-string v0, "textLayoutResult"

    .line 15
    .line 16
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    iget-object p1, p1, Lg4/l0;->b:Lg4/o;

    .line 20
    .line 21
    const/4 v0, 0x0

    .line 22
    invoke-virtual {p1, v0}, Lg4/o;->b(I)F

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    invoke-virtual {p1, v0}, Lg4/o;->f(I)F

    .line 27
    .line 28
    .line 29
    move-result p1

    .line 30
    sub-float/2addr v3, p1

    .line 31
    invoke-interface {p0, v3}, Lt4/c;->o0(F)F

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    new-instance p1, Lt4/f;

    .line 36
    .line 37
    invoke-direct {p1, p0}, Lt4/f;-><init>(F)V

    .line 38
    .line 39
    .line 40
    invoke-interface {v2, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    return-object v1

    .line 44
    :pswitch_0
    check-cast p1, Lt4/h;

    .line 45
    .line 46
    iget-wide v3, p1, Lt4/h;->a:J

    .line 47
    .line 48
    invoke-static {v3, v4}, Lt4/h;->c(J)F

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    invoke-interface {p0, v0}, Lt4/c;->Q(F)I

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    iget-wide v3, p1, Lt4/h;->a:J

    .line 57
    .line 58
    invoke-static {v3, v4}, Lt4/h;->b(J)F

    .line 59
    .line 60
    .line 61
    move-result p1

    .line 62
    invoke-interface {p0, p1}, Lt4/c;->Q(F)I

    .line 63
    .line 64
    .line 65
    move-result p0

    .line 66
    int-to-long v3, v0

    .line 67
    const/16 p1, 0x20

    .line 68
    .line 69
    shl-long/2addr v3, p1

    .line 70
    int-to-long p0, p0

    .line 71
    const-wide v5, 0xffffffffL

    .line 72
    .line 73
    .line 74
    .line 75
    .line 76
    and-long/2addr p0, v5

    .line 77
    or-long/2addr p0, v3

    .line 78
    new-instance v0, Lt4/l;

    .line 79
    .line 80
    invoke-direct {v0, p0, p1}, Lt4/l;-><init>(J)V

    .line 81
    .line 82
    .line 83
    invoke-interface {v2, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    return-object v1

    .line 87
    :pswitch_1
    check-cast p1, Lay0/a;

    .line 88
    .line 89
    new-instance v0, Laj0/c;

    .line 90
    .line 91
    const/16 v1, 0x13

    .line 92
    .line 93
    invoke-direct {v0, p1, v1}, Laj0/c;-><init>(Lay0/a;I)V

    .line 94
    .line 95
    .line 96
    new-instance p1, Le2/b1;

    .line 97
    .line 98
    const/4 v1, 0x1

    .line 99
    invoke-direct {p1, p0, v2, v1}, Le2/b1;-><init>(Lt4/c;Ll2/b1;I)V

    .line 100
    .line 101
    .line 102
    sget-object p0, Le1/v0;->a:Ld4/z;

    .line 103
    .line 104
    new-instance p0, Landroidx/compose/foundation/MagnifierElement;

    .line 105
    .line 106
    sget-object v1, Le1/f1;->a:Le1/f1;

    .line 107
    .line 108
    invoke-direct {p0, v0, p1, v1}, Landroidx/compose/foundation/MagnifierElement;-><init>(Laj0/c;Le2/b1;Le1/f1;)V

    .line 109
    .line 110
    .line 111
    return-object p0

    .line 112
    nop

    .line 113
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
