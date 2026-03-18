.class public final synthetic Ld00/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lc00/y0;

.field public final synthetic f:Ld00/a;


# direct methods
.method public synthetic constructor <init>(Lc00/y0;Ld00/a;I)V
    .locals 0

    .line 1
    iput p3, p0, Ld00/h;->d:I

    iput-object p1, p0, Ld00/h;->e:Lc00/y0;

    iput-object p2, p0, Ld00/h;->f:Ld00/a;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lc00/y0;Ld00/a;II)V
    .locals 0

    .line 2
    iput p4, p0, Ld00/h;->d:I

    iput-object p1, p0, Ld00/h;->e:Lc00/y0;

    iput-object p2, p0, Ld00/h;->f:Ld00/a;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Ld00/h;->d:I

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
    iget-object v0, p0, Ld00/h;->e:Lc00/y0;

    .line 19
    .line 20
    iget-object p0, p0, Ld00/h;->f:Ld00/a;

    .line 21
    .line 22
    invoke-static {v0, p0, p1, p2}, Ld00/o;->d(Lc00/y0;Ld00/a;Ll2/o;I)V

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
    iget-object v0, p0, Ld00/h;->e:Lc00/y0;

    .line 37
    .line 38
    iget-object p0, p0, Ld00/h;->f:Ld00/a;

    .line 39
    .line 40
    invoke-static {v0, p0, p1, p2}, Ld00/o;->t(Lc00/y0;Ld00/a;Ll2/o;I)V

    .line 41
    .line 42
    .line 43
    goto :goto_0

    .line 44
    :pswitch_1
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 45
    .line 46
    .line 47
    move-result p2

    .line 48
    and-int/lit8 v0, p2, 0x3

    .line 49
    .line 50
    const/4 v1, 0x2

    .line 51
    const/4 v2, 0x0

    .line 52
    const/4 v3, 0x1

    .line 53
    if-eq v0, v1, :cond_0

    .line 54
    .line 55
    move v0, v3

    .line 56
    goto :goto_1

    .line 57
    :cond_0
    move v0, v2

    .line 58
    :goto_1
    and-int/2addr p2, v3

    .line 59
    check-cast p1, Ll2/t;

    .line 60
    .line 61
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 62
    .line 63
    .line 64
    move-result p2

    .line 65
    if-eqz p2, :cond_1

    .line 66
    .line 67
    iget-object p2, p0, Ld00/h;->e:Lc00/y0;

    .line 68
    .line 69
    iget-object p0, p0, Ld00/h;->f:Ld00/a;

    .line 70
    .line 71
    invoke-static {p2, p0, p1, v2}, Ld00/o;->d(Lc00/y0;Ld00/a;Ll2/o;I)V

    .line 72
    .line 73
    .line 74
    goto :goto_2

    .line 75
    :cond_1
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 76
    .line 77
    .line 78
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 79
    .line 80
    return-object p0

    .line 81
    :pswitch_2
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 82
    .line 83
    .line 84
    move-result p2

    .line 85
    and-int/lit8 v0, p2, 0x3

    .line 86
    .line 87
    const/4 v1, 0x2

    .line 88
    const/4 v2, 0x0

    .line 89
    const/4 v3, 0x1

    .line 90
    if-eq v0, v1, :cond_2

    .line 91
    .line 92
    move v0, v3

    .line 93
    goto :goto_3

    .line 94
    :cond_2
    move v0, v2

    .line 95
    :goto_3
    and-int/2addr p2, v3

    .line 96
    check-cast p1, Ll2/t;

    .line 97
    .line 98
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 99
    .line 100
    .line 101
    move-result p2

    .line 102
    if-eqz p2, :cond_3

    .line 103
    .line 104
    iget-object p2, p0, Ld00/h;->e:Lc00/y0;

    .line 105
    .line 106
    iget-object p0, p0, Ld00/h;->f:Ld00/a;

    .line 107
    .line 108
    invoke-static {p2, p0, p1, v2}, Ld00/o;->t(Lc00/y0;Ld00/a;Ll2/o;I)V

    .line 109
    .line 110
    .line 111
    goto :goto_4

    .line 112
    :cond_3
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 113
    .line 114
    .line 115
    :goto_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 116
    .line 117
    return-object p0

    .line 118
    nop

    .line 119
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
