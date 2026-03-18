.class public final synthetic Ls60/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Lx2/s;

.field public final synthetic g:Lay0/a;

.field public final synthetic h:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Lx2/s;Lay0/a;II)V
    .locals 0

    .line 1
    iput p5, p0, Ls60/w;->d:I

    iput-object p1, p0, Ls60/w;->e:Ljava/lang/String;

    iput-object p2, p0, Ls60/w;->f:Lx2/s;

    iput-object p3, p0, Ls60/w;->g:Lay0/a;

    iput p4, p0, Ls60/w;->h:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;Ljava/lang/String;Lay0/a;III)V
    .locals 0

    .line 2
    iput p6, p0, Ls60/w;->d:I

    iput-object p1, p0, Ls60/w;->f:Lx2/s;

    iput-object p2, p0, Ls60/w;->e:Ljava/lang/String;

    iput-object p3, p0, Ls60/w;->g:Lay0/a;

    iput p5, p0, Ls60/w;->h:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Ls60/w;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v4, p1

    .line 7
    check-cast v4, Ll2/o;

    .line 8
    .line 9
    check-cast p2, Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    const/4 p1, 0x1

    .line 15
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 16
    .line 17
    .line 18
    move-result v5

    .line 19
    iget-object v1, p0, Ls60/w;->f:Lx2/s;

    .line 20
    .line 21
    iget-object v2, p0, Ls60/w;->e:Ljava/lang/String;

    .line 22
    .line 23
    iget-object v3, p0, Ls60/w;->g:Lay0/a;

    .line 24
    .line 25
    iget v6, p0, Ls60/w;->h:I

    .line 26
    .line 27
    invoke-static/range {v1 .. v6}, Lxf0/y1;->b(Lx2/s;Ljava/lang/String;Lay0/a;Ll2/o;II)V

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
    check-cast p1, Ll2/o;

    .line 34
    .line 35
    check-cast p2, Ljava/lang/Integer;

    .line 36
    .line 37
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 38
    .line 39
    .line 40
    iget p2, p0, Ls60/w;->h:I

    .line 41
    .line 42
    or-int/lit8 p2, p2, 0x1

    .line 43
    .line 44
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 45
    .line 46
    .line 47
    move-result p2

    .line 48
    iget-object v0, p0, Ls60/w;->e:Ljava/lang/String;

    .line 49
    .line 50
    iget-object v1, p0, Ls60/w;->f:Lx2/s;

    .line 51
    .line 52
    iget-object p0, p0, Ls60/w;->g:Lay0/a;

    .line 53
    .line 54
    invoke-static {v0, v1, p0, p1, p2}, Lxf0/r0;->e(Ljava/lang/String;Lx2/s;Lay0/a;Ll2/o;I)V

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
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 63
    .line 64
    .line 65
    iget p2, p0, Ls60/w;->h:I

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
    iget-object v0, p0, Ls60/w;->e:Ljava/lang/String;

    .line 74
    .line 75
    iget-object v1, p0, Ls60/w;->f:Lx2/s;

    .line 76
    .line 77
    iget-object p0, p0, Ls60/w;->g:Lay0/a;

    .line 78
    .line 79
    invoke-static {v0, v1, p0, p1, p2}, Lxf0/r0;->d(Ljava/lang/String;Lx2/s;Lay0/a;Ll2/o;I)V

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
    iget p2, p0, Ls60/w;->h:I

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
    iget-object v0, p0, Ls60/w;->e:Ljava/lang/String;

    .line 99
    .line 100
    iget-object v1, p0, Ls60/w;->f:Lx2/s;

    .line 101
    .line 102
    iget-object p0, p0, Ls60/w;->g:Lay0/a;

    .line 103
    .line 104
    invoke-static {v0, v1, p0, p1, p2}, Lxf0/r0;->a(Ljava/lang/String;Lx2/s;Lay0/a;Ll2/o;I)V

    .line 105
    .line 106
    .line 107
    goto :goto_0

    .line 108
    :pswitch_3
    move-object v3, p1

    .line 109
    check-cast v3, Ll2/o;

    .line 110
    .line 111
    check-cast p2, Ljava/lang/Integer;

    .line 112
    .line 113
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 114
    .line 115
    .line 116
    const/4 p1, 0x1

    .line 117
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 118
    .line 119
    .line 120
    move-result v4

    .line 121
    iget-object v0, p0, Ls60/w;->f:Lx2/s;

    .line 122
    .line 123
    iget-object v1, p0, Ls60/w;->e:Ljava/lang/String;

    .line 124
    .line 125
    iget-object v2, p0, Ls60/w;->g:Lay0/a;

    .line 126
    .line 127
    iget v5, p0, Ls60/w;->h:I

    .line 128
    .line 129
    invoke-static/range {v0 .. v5}, Ls60/a;->m(Lx2/s;Ljava/lang/String;Lay0/a;Ll2/o;II)V

    .line 130
    .line 131
    .line 132
    goto :goto_0

    .line 133
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
