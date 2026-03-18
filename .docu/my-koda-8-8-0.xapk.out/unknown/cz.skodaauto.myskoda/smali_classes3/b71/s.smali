.class public final synthetic Lb71/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Z

.field public final synthetic h:I


# direct methods
.method public synthetic constructor <init>(ILay0/a;Lx2/s;ZI)V
    .locals 0

    .line 1
    const/4 p5, 0x3

    iput p5, p0, Lb71/s;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Lb71/s;->h:I

    iput-object p2, p0, Lb71/s;->f:Lay0/a;

    iput-object p3, p0, Lb71/s;->e:Lx2/s;

    iput-boolean p4, p0, Lb71/s;->g:Z

    return-void
.end method

.method public synthetic constructor <init>(ILx2/s;Lay0/a;ZI)V
    .locals 0

    .line 2
    const/4 p5, 0x4

    iput p5, p0, Lb71/s;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Lb71/s;->h:I

    iput-object p2, p0, Lb71/s;->e:Lx2/s;

    iput-object p3, p0, Lb71/s;->f:Lay0/a;

    iput-boolean p4, p0, Lb71/s;->g:Z

    return-void
.end method

.method public synthetic constructor <init>(Lay0/a;Lx2/s;ZI)V
    .locals 1

    .line 3
    const/4 v0, 0x2

    iput v0, p0, Lb71/s;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lb71/s;->f:Lay0/a;

    iput-object p2, p0, Lb71/s;->e:Lx2/s;

    iput-boolean p3, p0, Lb71/s;->g:Z

    iput p4, p0, Lb71/s;->h:I

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;Lay0/a;ZI)V
    .locals 1

    .line 4
    const/4 v0, 0x1

    iput v0, p0, Lb71/s;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lb71/s;->e:Lx2/s;

    iput-object p2, p0, Lb71/s;->f:Lay0/a;

    iput-boolean p3, p0, Lb71/s;->g:Z

    iput p4, p0, Lb71/s;->h:I

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;ZLay0/a;II)V
    .locals 0

    .line 5
    iput p5, p0, Lb71/s;->d:I

    iput-object p1, p0, Lb71/s;->e:Lx2/s;

    iput-boolean p2, p0, Lb71/s;->g:Z

    iput-object p3, p0, Lb71/s;->f:Lay0/a;

    iput p4, p0, Lb71/s;->h:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Lb71/s;->d:I

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
    iget p2, p0, Lb71/s;->h:I

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
    iget-object v0, p0, Lb71/s;->f:Lay0/a;

    .line 22
    .line 23
    iget-object v1, p0, Lb71/s;->e:Lx2/s;

    .line 24
    .line 25
    iget-boolean p0, p0, Lb71/s;->g:Z

    .line 26
    .line 27
    invoke-static {p2, v0, p1, v1, p0}, Lz61/a;->b(ILay0/a;Ll2/o;Lx2/s;Z)V

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
    move-object v3, p1

    .line 34
    check-cast v3, Ll2/o;

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
    move-result v1

    .line 46
    iget v0, p0, Lb71/s;->h:I

    .line 47
    .line 48
    iget-object v2, p0, Lb71/s;->f:Lay0/a;

    .line 49
    .line 50
    iget-object v4, p0, Lb71/s;->e:Lx2/s;

    .line 51
    .line 52
    iget-boolean v5, p0, Lb71/s;->g:Z

    .line 53
    .line 54
    invoke-static/range {v0 .. v5}, Lxf0/i0;->h(IILay0/a;Ll2/o;Lx2/s;Z)V

    .line 55
    .line 56
    .line 57
    goto :goto_0

    .line 58
    :pswitch_1
    move-object v3, p1

    .line 59
    check-cast v3, Ll2/o;

    .line 60
    .line 61
    check-cast p2, Ljava/lang/Integer;

    .line 62
    .line 63
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 64
    .line 65
    .line 66
    const/4 p1, 0x1

    .line 67
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    iget v0, p0, Lb71/s;->h:I

    .line 72
    .line 73
    iget-object v2, p0, Lb71/s;->f:Lay0/a;

    .line 74
    .line 75
    iget-object v4, p0, Lb71/s;->e:Lx2/s;

    .line 76
    .line 77
    iget-boolean v5, p0, Lb71/s;->g:Z

    .line 78
    .line 79
    invoke-static/range {v0 .. v5}, Li91/j0;->T(IILay0/a;Ll2/o;Lx2/s;Z)V

    .line 80
    .line 81
    .line 82
    goto :goto_0

    .line 83
    :pswitch_2
    check-cast p1, Ll2/o;

    .line 84
    .line 85
    check-cast p2, Ljava/lang/Integer;

    .line 86
    .line 87
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 88
    .line 89
    .line 90
    iget p2, p0, Lb71/s;->h:I

    .line 91
    .line 92
    or-int/lit8 p2, p2, 0x1

    .line 93
    .line 94
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 95
    .line 96
    .line 97
    move-result p2

    .line 98
    iget-object v0, p0, Lb71/s;->f:Lay0/a;

    .line 99
    .line 100
    iget-object v1, p0, Lb71/s;->e:Lx2/s;

    .line 101
    .line 102
    iget-boolean p0, p0, Lb71/s;->g:Z

    .line 103
    .line 104
    invoke-static {p2, v0, p1, v1, p0}, Li91/j0;->b0(ILay0/a;Ll2/o;Lx2/s;Z)V

    .line 105
    .line 106
    .line 107
    goto :goto_0

    .line 108
    :pswitch_3
    check-cast p1, Ll2/o;

    .line 109
    .line 110
    check-cast p2, Ljava/lang/Integer;

    .line 111
    .line 112
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 113
    .line 114
    .line 115
    iget p2, p0, Lb71/s;->h:I

    .line 116
    .line 117
    or-int/lit8 p2, p2, 0x1

    .line 118
    .line 119
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 120
    .line 121
    .line 122
    move-result p2

    .line 123
    iget-object v0, p0, Lb71/s;->f:Lay0/a;

    .line 124
    .line 125
    iget-object v1, p0, Lb71/s;->e:Lx2/s;

    .line 126
    .line 127
    iget-boolean p0, p0, Lb71/s;->g:Z

    .line 128
    .line 129
    invoke-static {p2, v0, p1, v1, p0}, Lkp/o;->c(ILay0/a;Ll2/o;Lx2/s;Z)V

    .line 130
    .line 131
    .line 132
    goto :goto_0

    .line 133
    :pswitch_4
    check-cast p1, Ll2/o;

    .line 134
    .line 135
    check-cast p2, Ljava/lang/Integer;

    .line 136
    .line 137
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 138
    .line 139
    .line 140
    iget p2, p0, Lb71/s;->h:I

    .line 141
    .line 142
    or-int/lit8 p2, p2, 0x1

    .line 143
    .line 144
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 145
    .line 146
    .line 147
    move-result p2

    .line 148
    iget-object v0, p0, Lb71/s;->f:Lay0/a;

    .line 149
    .line 150
    iget-object v1, p0, Lb71/s;->e:Lx2/s;

    .line 151
    .line 152
    iget-boolean p0, p0, Lb71/s;->g:Z

    .line 153
    .line 154
    invoke-static {p2, v0, p1, v1, p0}, Lb71/a;->k(ILay0/a;Ll2/o;Lx2/s;Z)V

    .line 155
    .line 156
    .line 157
    goto :goto_0

    .line 158
    nop

    .line 159
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
