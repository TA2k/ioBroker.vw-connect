.class public final synthetic Lbl/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/a;

.field public final synthetic f:Lx2/s;

.field public final synthetic g:I


# direct methods
.method public synthetic constructor <init>(Lay0/a;Lx2/s;II)V
    .locals 0

    .line 1
    iput p4, p0, Lbl/g;->d:I

    iput-object p1, p0, Lbl/g;->e:Lay0/a;

    iput-object p2, p0, Lbl/g;->f:Lx2/s;

    iput p3, p0, Lbl/g;->g:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;Lay0/a;II)V
    .locals 0

    .line 2
    const/4 p3, 0x7

    iput p3, p0, Lbl/g;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lbl/g;->f:Lx2/s;

    iput-object p2, p0, Lbl/g;->e:Lay0/a;

    iput p4, p0, Lbl/g;->g:I

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;Lay0/a;IIB)V
    .locals 0

    .line 3
    iput p4, p0, Lbl/g;->d:I

    iput-object p1, p0, Lbl/g;->f:Lx2/s;

    iput-object p2, p0, Lbl/g;->e:Lay0/a;

    iput p3, p0, Lbl/g;->g:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lbl/g;->d:I

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
    const/4 p2, 0x7

    .line 14
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 15
    .line 16
    .line 17
    move-result p2

    .line 18
    iget-object v0, p0, Lbl/g;->f:Lx2/s;

    .line 19
    .line 20
    iget-object v1, p0, Lbl/g;->e:Lay0/a;

    .line 21
    .line 22
    iget p0, p0, Lbl/g;->g:I

    .line 23
    .line 24
    invoke-static {v0, v1, p1, p2, p0}, Lv50/a;->U(Lx2/s;Lay0/a;Ll2/o;II)V

    .line 25
    .line 26
    .line 27
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    return-object p0

    .line 30
    :pswitch_0
    iget p2, p0, Lbl/g;->g:I

    .line 31
    .line 32
    or-int/lit8 p2, p2, 0x1

    .line 33
    .line 34
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 35
    .line 36
    .line 37
    move-result p2

    .line 38
    iget-object v0, p0, Lbl/g;->e:Lay0/a;

    .line 39
    .line 40
    iget-object p0, p0, Lbl/g;->f:Lx2/s;

    .line 41
    .line 42
    invoke-static {p2, v0, p1, p0}, Lo90/b;->e(ILay0/a;Ll2/o;Lx2/s;)V

    .line 43
    .line 44
    .line 45
    goto :goto_0

    .line 46
    :pswitch_1
    iget p2, p0, Lbl/g;->g:I

    .line 47
    .line 48
    or-int/lit8 p2, p2, 0x1

    .line 49
    .line 50
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 51
    .line 52
    .line 53
    move-result p2

    .line 54
    iget-object v0, p0, Lbl/g;->e:Lay0/a;

    .line 55
    .line 56
    iget-object p0, p0, Lbl/g;->f:Lx2/s;

    .line 57
    .line 58
    invoke-static {p2, v0, p1, p0}, Lo50/e;->a(ILay0/a;Ll2/o;Lx2/s;)V

    .line 59
    .line 60
    .line 61
    goto :goto_0

    .line 62
    :pswitch_2
    iget p2, p0, Lbl/g;->g:I

    .line 63
    .line 64
    or-int/lit8 p2, p2, 0x1

    .line 65
    .line 66
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 67
    .line 68
    .line 69
    move-result p2

    .line 70
    iget-object v0, p0, Lbl/g;->e:Lay0/a;

    .line 71
    .line 72
    iget-object p0, p0, Lbl/g;->f:Lx2/s;

    .line 73
    .line 74
    invoke-static {p2, v0, p1, p0}, Ln70/a;->M(ILay0/a;Ll2/o;Lx2/s;)V

    .line 75
    .line 76
    .line 77
    goto :goto_0

    .line 78
    :pswitch_3
    iget p2, p0, Lbl/g;->g:I

    .line 79
    .line 80
    or-int/lit8 p2, p2, 0x1

    .line 81
    .line 82
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 83
    .line 84
    .line 85
    move-result p2

    .line 86
    iget-object v0, p0, Lbl/g;->e:Lay0/a;

    .line 87
    .line 88
    iget-object p0, p0, Lbl/g;->f:Lx2/s;

    .line 89
    .line 90
    invoke-static {p2, v0, p1, p0}, Ln70/a;->k(ILay0/a;Ll2/o;Lx2/s;)V

    .line 91
    .line 92
    .line 93
    goto :goto_0

    .line 94
    :pswitch_4
    iget p2, p0, Lbl/g;->g:I

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
    iget-object v0, p0, Lbl/g;->e:Lay0/a;

    .line 103
    .line 104
    iget-object p0, p0, Lbl/g;->f:Lx2/s;

    .line 105
    .line 106
    invoke-static {p2, v0, p1, p0}, Liz/c;->a(ILay0/a;Ll2/o;Lx2/s;)V

    .line 107
    .line 108
    .line 109
    goto :goto_0

    .line 110
    :pswitch_5
    iget p2, p0, Lbl/g;->g:I

    .line 111
    .line 112
    or-int/lit8 p2, p2, 0x1

    .line 113
    .line 114
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 115
    .line 116
    .line 117
    move-result p2

    .line 118
    iget-object v0, p0, Lbl/g;->e:Lay0/a;

    .line 119
    .line 120
    iget-object p0, p0, Lbl/g;->f:Lx2/s;

    .line 121
    .line 122
    invoke-static {p2, v0, p1, p0}, Lha0/b;->b(ILay0/a;Ll2/o;Lx2/s;)V

    .line 123
    .line 124
    .line 125
    goto :goto_0

    .line 126
    :pswitch_6
    iget p2, p0, Lbl/g;->g:I

    .line 127
    .line 128
    or-int/lit8 p2, p2, 0x1

    .line 129
    .line 130
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 131
    .line 132
    .line 133
    move-result p2

    .line 134
    iget-object v0, p0, Lbl/g;->e:Lay0/a;

    .line 135
    .line 136
    iget-object p0, p0, Lbl/g;->f:Lx2/s;

    .line 137
    .line 138
    invoke-static {p2, v0, p1, p0}, Lbl/a;->a(ILay0/a;Ll2/o;Lx2/s;)V

    .line 139
    .line 140
    .line 141
    goto :goto_0

    .line 142
    nop

    .line 143
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
