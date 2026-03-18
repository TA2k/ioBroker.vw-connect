.class public final synthetic Lf20/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:I

.field public final synthetic h:I


# direct methods
.method public synthetic constructor <init>(Lx2/s;Lay0/a;III)V
    .locals 0

    .line 1
    iput p5, p0, Lf20/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lf20/b;->e:Lx2/s;

    .line 4
    .line 5
    iput-object p2, p0, Lf20/b;->f:Lay0/a;

    .line 6
    .line 7
    iput p3, p0, Lf20/b;->g:I

    .line 8
    .line 9
    iput p4, p0, Lf20/b;->h:I

    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lf20/b;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    packed-switch v0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    iget p2, p0, Lf20/b;->g:I

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
    iget-object v0, p0, Lf20/b;->e:Lx2/s;

    .line 22
    .line 23
    iget-object v1, p0, Lf20/b;->f:Lay0/a;

    .line 24
    .line 25
    iget p0, p0, Lf20/b;->h:I

    .line 26
    .line 27
    invoke-static {v0, v1, p1, p2, p0}, Luz/k0;->Y(Lx2/s;Lay0/a;Ll2/o;II)V

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
    iget p2, p0, Lf20/b;->g:I

    .line 34
    .line 35
    or-int/lit8 p2, p2, 0x1

    .line 36
    .line 37
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 38
    .line 39
    .line 40
    move-result p2

    .line 41
    iget-object v0, p0, Lf20/b;->e:Lx2/s;

    .line 42
    .line 43
    iget-object v1, p0, Lf20/b;->f:Lay0/a;

    .line 44
    .line 45
    iget p0, p0, Lf20/b;->h:I

    .line 46
    .line 47
    invoke-static {v0, v1, p1, p2, p0}, Lpr0/a;->b(Lx2/s;Lay0/a;Ll2/o;II)V

    .line 48
    .line 49
    .line 50
    goto :goto_0

    .line 51
    :pswitch_1
    iget p2, p0, Lf20/b;->g:I

    .line 52
    .line 53
    or-int/lit8 p2, p2, 0x1

    .line 54
    .line 55
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 56
    .line 57
    .line 58
    move-result p2

    .line 59
    iget-object v0, p0, Lf20/b;->e:Lx2/s;

    .line 60
    .line 61
    iget-object v1, p0, Lf20/b;->f:Lay0/a;

    .line 62
    .line 63
    iget p0, p0, Lf20/b;->h:I

    .line 64
    .line 65
    invoke-static {v0, v1, p1, p2, p0}, Lot0/a;->c(Lx2/s;Lay0/a;Ll2/o;II)V

    .line 66
    .line 67
    .line 68
    goto :goto_0

    .line 69
    :pswitch_2
    iget p2, p0, Lf20/b;->g:I

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
    iget-object v0, p0, Lf20/b;->e:Lx2/s;

    .line 78
    .line 79
    iget-object v1, p0, Lf20/b;->f:Lay0/a;

    .line 80
    .line 81
    iget p0, p0, Lf20/b;->h:I

    .line 82
    .line 83
    invoke-static {v0, v1, p1, p2, p0}, Lo90/b;->i(Lx2/s;Lay0/a;Ll2/o;II)V

    .line 84
    .line 85
    .line 86
    goto :goto_0

    .line 87
    :pswitch_3
    iget p2, p0, Lf20/b;->g:I

    .line 88
    .line 89
    or-int/lit8 p2, p2, 0x1

    .line 90
    .line 91
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 92
    .line 93
    .line 94
    move-result p2

    .line 95
    iget-object v0, p0, Lf20/b;->e:Lx2/s;

    .line 96
    .line 97
    iget-object v1, p0, Lf20/b;->f:Lay0/a;

    .line 98
    .line 99
    iget p0, p0, Lf20/b;->h:I

    .line 100
    .line 101
    invoke-static {v0, v1, p1, p2, p0}, Lna0/a;->e(Lx2/s;Lay0/a;Ll2/o;II)V

    .line 102
    .line 103
    .line 104
    goto :goto_0

    .line 105
    :pswitch_4
    iget p2, p0, Lf20/b;->g:I

    .line 106
    .line 107
    or-int/lit8 p2, p2, 0x1

    .line 108
    .line 109
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 110
    .line 111
    .line 112
    move-result p2

    .line 113
    iget-object v0, p0, Lf20/b;->e:Lx2/s;

    .line 114
    .line 115
    iget-object v1, p0, Lf20/b;->f:Lay0/a;

    .line 116
    .line 117
    iget p0, p0, Lf20/b;->h:I

    .line 118
    .line 119
    invoke-static {v0, v1, p1, p2, p0}, Llp/se;->d(Lx2/s;Lay0/a;Ll2/o;II)V

    .line 120
    .line 121
    .line 122
    goto :goto_0

    .line 123
    :pswitch_5
    iget p2, p0, Lf20/b;->g:I

    .line 124
    .line 125
    or-int/lit8 p2, p2, 0x1

    .line 126
    .line 127
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 128
    .line 129
    .line 130
    move-result p2

    .line 131
    iget-object v0, p0, Lf20/b;->e:Lx2/s;

    .line 132
    .line 133
    iget-object v1, p0, Lf20/b;->f:Lay0/a;

    .line 134
    .line 135
    iget p0, p0, Lf20/b;->h:I

    .line 136
    .line 137
    invoke-static {v0, v1, p1, p2, p0}, Lf20/a;->b(Lx2/s;Lay0/a;Ll2/o;II)V

    .line 138
    .line 139
    .line 140
    goto :goto_0

    .line 141
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
