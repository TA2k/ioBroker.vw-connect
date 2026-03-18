.class public final La7/t1;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lay0/n;

.field public final synthetic h:J

.field public final synthetic i:La7/a2;


# direct methods
.method public constructor <init>(IJLa7/a2;Lay0/n;)V
    .locals 0

    const/4 p1, 0x0

    iput p1, p0, La7/t1;->f:I

    .line 1
    iput-object p4, p0, La7/t1;->i:La7/a2;

    iput-wide p2, p0, La7/t1;->h:J

    iput-object p5, p0, La7/t1;->g:Lay0/n;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method

.method public constructor <init>(Lay0/n;JLa7/a2;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, La7/t1;->f:I

    .line 2
    iput-object p1, p0, La7/t1;->g:Lay0/n;

    iput-wide p2, p0, La7/t1;->h:J

    iput-object p4, p0, La7/t1;->i:La7/a2;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, La7/t1;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ll2/o;

    .line 7
    .line 8
    check-cast p2, Ljava/lang/Number;

    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 11
    .line 12
    .line 13
    move-result p2

    .line 14
    and-int/lit8 p2, p2, 0x3

    .line 15
    .line 16
    const/4 v0, 0x2

    .line 17
    if-ne p2, v0, :cond_1

    .line 18
    .line 19
    move-object p2, p1

    .line 20
    check-cast p2, Ll2/t;

    .line 21
    .line 22
    invoke-virtual {p2}, Ll2/t;->A()Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-nez v0, :cond_0

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 30
    .line 31
    .line 32
    goto :goto_2

    .line 33
    :cond_1
    :goto_0
    sget-object p2, La7/v1;->d:La7/v1;

    .line 34
    .line 35
    check-cast p1, Ll2/t;

    .line 36
    .line 37
    const v0, 0x227c4e56

    .line 38
    .line 39
    .line 40
    invoke-virtual {p1, v0}, Ll2/t;->Z(I)V

    .line 41
    .line 42
    .line 43
    const v0, -0x20ad3f64

    .line 44
    .line 45
    .line 46
    invoke-virtual {p1, v0}, Ll2/t;->Z(I)V

    .line 47
    .line 48
    .line 49
    iget-object v0, p1, Ll2/t;->a:Leb/j0;

    .line 50
    .line 51
    instance-of v0, v0, Ly6/b;

    .line 52
    .line 53
    if-eqz v0, :cond_3

    .line 54
    .line 55
    invoke-virtual {p1}, Ll2/t;->W()V

    .line 56
    .line 57
    .line 58
    iget-boolean v0, p1, Ll2/t;->S:Z

    .line 59
    .line 60
    if-eqz v0, :cond_2

    .line 61
    .line 62
    invoke-virtual {p1, p2}, Ll2/t;->l(Lay0/a;)V

    .line 63
    .line 64
    .line 65
    goto :goto_1

    .line 66
    :cond_2
    invoke-virtual {p1}, Ll2/t;->m0()V

    .line 67
    .line 68
    .line 69
    :goto_1
    new-instance p2, Lt4/h;

    .line 70
    .line 71
    iget-wide v0, p0, La7/t1;->h:J

    .line 72
    .line 73
    invoke-direct {p2, v0, v1}, Lt4/h;-><init>(J)V

    .line 74
    .line 75
    .line 76
    sget-object v0, La7/i1;->y:La7/i1;

    .line 77
    .line 78
    invoke-static {v0, p2, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 79
    .line 80
    .line 81
    sget-object p2, La7/i1;->z:La7/i1;

    .line 82
    .line 83
    iget-object v0, p0, La7/t1;->i:La7/a2;

    .line 84
    .line 85
    invoke-static {p2, v0, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 86
    .line 87
    .line 88
    const/4 p2, 0x1

    .line 89
    const/4 v0, 0x0

    .line 90
    iget-object p0, p0, La7/t1;->g:Lay0/n;

    .line 91
    .line 92
    invoke-static {v0, p0, p1, p2, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->v(ILay0/n;Ll2/t;ZZ)V

    .line 93
    .line 94
    .line 95
    invoke-virtual {p1, v0}, Ll2/t;->q(Z)V

    .line 96
    .line 97
    .line 98
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 99
    .line 100
    return-object p0

    .line 101
    :cond_3
    invoke-static {}, Ll2/b;->l()V

    .line 102
    .line 103
    .line 104
    const/4 p0, 0x0

    .line 105
    throw p0

    .line 106
    :pswitch_0
    move-object v5, p1

    .line 107
    check-cast v5, Ll2/o;

    .line 108
    .line 109
    check-cast p2, Ljava/lang/Number;

    .line 110
    .line 111
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 112
    .line 113
    .line 114
    iget-object v4, p0, La7/t1;->g:Lay0/n;

    .line 115
    .line 116
    const/4 v0, 0x1

    .line 117
    iget-wide v1, p0, La7/t1;->h:J

    .line 118
    .line 119
    iget-object v3, p0, La7/t1;->i:La7/a2;

    .line 120
    .line 121
    invoke-static/range {v0 .. v5}, Lis0/b;->a(IJLa7/a2;Lay0/n;Ll2/o;)V

    .line 122
    .line 123
    .line 124
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 125
    .line 126
    return-object p0

    .line 127
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
