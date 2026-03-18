.class public final Lb1/f;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lb1/f;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lb1/f;->g:Ljava/lang/Object;

    .line 4
    .line 5
    const/4 p1, 0x3

    .line 6
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Lb1/f;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v1, p1

    .line 7
    check-cast v1, Lvv/m0;

    .line 8
    .line 9
    move-object v8, p2

    .line 10
    check-cast v8, Ll2/o;

    .line 11
    .line 12
    check-cast p3, Ljava/lang/Number;

    .line 13
    .line 14
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 15
    .line 16
    .line 17
    move-result p1

    .line 18
    const-string p2, "$this$CodeBlock"

    .line 19
    .line 20
    invoke-static {v1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    and-int/lit8 p2, p1, 0xe

    .line 24
    .line 25
    if-nez p2, :cond_1

    .line 26
    .line 27
    move-object p2, v8

    .line 28
    check-cast p2, Ll2/t;

    .line 29
    .line 30
    invoke-virtual {p2, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result p2

    .line 34
    if-eqz p2, :cond_0

    .line 35
    .line 36
    const/4 p2, 0x4

    .line 37
    goto :goto_0

    .line 38
    :cond_0
    const/4 p2, 0x2

    .line 39
    :goto_0
    or-int/2addr p1, p2

    .line 40
    :cond_1
    and-int/lit8 p2, p1, 0x5b

    .line 41
    .line 42
    const/16 p3, 0x12

    .line 43
    .line 44
    if-ne p2, p3, :cond_3

    .line 45
    .line 46
    move-object p2, v8

    .line 47
    check-cast p2, Ll2/t;

    .line 48
    .line 49
    invoke-virtual {p2}, Ll2/t;->A()Z

    .line 50
    .line 51
    .line 52
    move-result p3

    .line 53
    if-nez p3, :cond_2

    .line 54
    .line 55
    goto :goto_1

    .line 56
    :cond_2
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 57
    .line 58
    .line 59
    goto :goto_2

    .line 60
    :cond_3
    :goto_1
    iget-object p0, p0, Lb1/f;->g:Ljava/lang/Object;

    .line 61
    .line 62
    move-object v2, p0

    .line 63
    check-cast v2, Ljava/lang/String;

    .line 64
    .line 65
    const/4 v7, 0x0

    .line 66
    and-int/lit8 v9, p1, 0xe

    .line 67
    .line 68
    const/4 v3, 0x0

    .line 69
    const/4 v4, 0x0

    .line 70
    const/4 v5, 0x0

    .line 71
    const/4 v6, 0x0

    .line 72
    invoke-static/range {v1 .. v9}, Lvv/l0;->c(Lvv/m0;Ljava/lang/String;Lx2/s;Lay0/k;IZILl2/o;I)V

    .line 73
    .line 74
    .line 75
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 76
    .line 77
    return-object p0

    .line 78
    :pswitch_0
    check-cast p1, Lc1/r1;

    .line 79
    .line 80
    check-cast p2, Ll2/o;

    .line 81
    .line 82
    check-cast p3, Ljava/lang/Number;

    .line 83
    .line 84
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 85
    .line 86
    .line 87
    check-cast p2, Ll2/t;

    .line 88
    .line 89
    const p1, 0x38f969d6

    .line 90
    .line 91
    .line 92
    invoke-virtual {p2, p1}, Ll2/t;->Y(I)V

    .line 93
    .line 94
    .line 95
    iget-object p0, p0, Lb1/f;->g:Ljava/lang/Object;

    .line 96
    .line 97
    check-cast p0, Lc1/a0;

    .line 98
    .line 99
    const/4 p1, 0x0

    .line 100
    invoke-virtual {p2, p1}, Ll2/t;->q(Z)V

    .line 101
    .line 102
    .line 103
    return-object p0

    .line 104
    :pswitch_1
    check-cast p1, Lt3/s0;

    .line 105
    .line 106
    check-cast p2, Lt3/p0;

    .line 107
    .line 108
    check-cast p3, Lt4/a;

    .line 109
    .line 110
    iget-wide v0, p3, Lt4/a;->a:J

    .line 111
    .line 112
    invoke-interface {p2, v0, v1}, Lt3/p0;->L(J)Lt3/e1;

    .line 113
    .line 114
    .line 115
    move-result-object p2

    .line 116
    iget p3, p2, Lt3/e1;->d:I

    .line 117
    .line 118
    iget v0, p2, Lt3/e1;->e:I

    .line 119
    .line 120
    new-instance v1, Lb1/e;

    .line 121
    .line 122
    iget-object p0, p0, Lb1/f;->g:Ljava/lang/Object;

    .line 123
    .line 124
    check-cast p0, Lb1/d0;

    .line 125
    .line 126
    const/4 v2, 0x0

    .line 127
    invoke-direct {v1, v2, p2, p0}, Lb1/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 128
    .line 129
    .line 130
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 131
    .line 132
    invoke-interface {p1, p3, v0, p0, v1}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 133
    .line 134
    .line 135
    move-result-object p0

    .line 136
    return-object p0

    .line 137
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
