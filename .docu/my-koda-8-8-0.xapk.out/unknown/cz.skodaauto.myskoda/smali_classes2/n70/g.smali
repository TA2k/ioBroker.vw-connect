.class public final synthetic Ln70/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lm70/l;

.field public final synthetic f:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lm70/l;Lay0/k;)V
    .locals 1

    .line 1
    const/4 v0, 0x2

    iput v0, p0, Ln70/g;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ln70/g;->e:Lm70/l;

    iput-object p2, p0, Ln70/g;->f:Lay0/k;

    return-void
.end method

.method public synthetic constructor <init>(Lm70/l;Lay0/k;II)V
    .locals 0

    .line 2
    iput p4, p0, Ln70/g;->d:I

    iput-object p1, p0, Ln70/g;->e:Lm70/l;

    iput-object p2, p0, Ln70/g;->f:Lay0/k;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Ln70/g;->d:I

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
    move-result p2

    .line 14
    and-int/lit8 v0, p2, 0x3

    .line 15
    .line 16
    const/4 v1, 0x2

    .line 17
    const/4 v2, 0x0

    .line 18
    const/4 v3, 0x1

    .line 19
    if-eq v0, v1, :cond_0

    .line 20
    .line 21
    move v0, v3

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    move v0, v2

    .line 24
    :goto_0
    and-int/2addr p2, v3

    .line 25
    move-object v7, p1

    .line 26
    check-cast v7, Ll2/t;

    .line 27
    .line 28
    invoke-virtual {v7, p2, v0}, Ll2/t;->O(IZ)Z

    .line 29
    .line 30
    .line 31
    move-result p1

    .line 32
    if-eqz p1, :cond_2

    .line 33
    .line 34
    iget-object p1, p0, Ln70/g;->e:Lm70/l;

    .line 35
    .line 36
    iget-object p1, p1, Lm70/l;->g:Ll70/h;

    .line 37
    .line 38
    if-nez p1, :cond_1

    .line 39
    .line 40
    const p0, 0x588216f5

    .line 41
    .line 42
    .line 43
    invoke-virtual {v7, p0}, Ll2/t;->Y(I)V

    .line 44
    .line 45
    .line 46
    :goto_1
    invoke-virtual {v7, v2}, Ll2/t;->q(Z)V

    .line 47
    .line 48
    .line 49
    goto :goto_2

    .line 50
    :cond_1
    const p2, 0x588216f6

    .line 51
    .line 52
    .line 53
    invoke-virtual {v7, p2}, Ll2/t;->Y(I)V

    .line 54
    .line 55
    .line 56
    new-instance p2, Li50/j;

    .line 57
    .line 58
    const/16 v0, 0x11

    .line 59
    .line 60
    iget-object p0, p0, Ln70/g;->f:Lay0/k;

    .line 61
    .line 62
    invoke-direct {p2, p0, p1, v0}, Li50/j;-><init>(Lay0/k;Ljava/lang/Enum;I)V

    .line 63
    .line 64
    .line 65
    const p0, -0x1de188e2

    .line 66
    .line 67
    .line 68
    invoke-static {p0, v7, p2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 69
    .line 70
    .line 71
    move-result-object v6

    .line 72
    const/16 v8, 0x180

    .line 73
    .line 74
    const/4 v9, 0x3

    .line 75
    const/4 v3, 0x0

    .line 76
    const-wide/16 v4, 0x0

    .line 77
    .line 78
    invoke-static/range {v3 .. v9}, Lxf0/i0;->t(Lx2/s;JLt2/b;Ll2/o;II)V

    .line 79
    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_2
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 83
    .line 84
    .line 85
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 86
    .line 87
    return-object p0

    .line 88
    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 89
    .line 90
    .line 91
    const/4 p2, 0x1

    .line 92
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 93
    .line 94
    .line 95
    move-result p2

    .line 96
    iget-object v0, p0, Ln70/g;->e:Lm70/l;

    .line 97
    .line 98
    iget-object p0, p0, Ln70/g;->f:Lay0/k;

    .line 99
    .line 100
    invoke-static {v0, p0, p1, p2}, Ln70/a;->V(Lm70/l;Lay0/k;Ll2/o;I)V

    .line 101
    .line 102
    .line 103
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 104
    .line 105
    return-object p0

    .line 106
    :pswitch_1
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 107
    .line 108
    .line 109
    const/4 p2, 0x1

    .line 110
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 111
    .line 112
    .line 113
    move-result p2

    .line 114
    iget-object v0, p0, Ln70/g;->e:Lm70/l;

    .line 115
    .line 116
    iget-object p0, p0, Ln70/g;->f:Lay0/k;

    .line 117
    .line 118
    invoke-static {v0, p0, p1, p2}, Ln70/a;->s(Lm70/l;Lay0/k;Ll2/o;I)V

    .line 119
    .line 120
    .line 121
    goto :goto_3

    .line 122
    nop

    .line 123
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
