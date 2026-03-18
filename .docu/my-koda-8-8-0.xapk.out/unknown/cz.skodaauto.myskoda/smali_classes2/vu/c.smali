.class public final synthetic Lvu/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lvu/l;

.field public final synthetic f:Lvu/i;


# direct methods
.method public synthetic constructor <init>(Lvu/l;Lvu/i;I)V
    .locals 0

    .line 1
    iput p3, p0, Lvu/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lvu/c;->e:Lvu/l;

    .line 4
    .line 5
    iput-object p2, p0, Lvu/c;->f:Lvu/i;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lvu/c;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 8
    .line 9
    .line 10
    move-result p2

    .line 11
    packed-switch v0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    and-int/lit8 v0, p2, 0x3

    .line 15
    .line 16
    const/4 v1, 0x2

    .line 17
    const/4 v2, 0x1

    .line 18
    const/4 v3, 0x0

    .line 19
    if-eq v0, v1, :cond_0

    .line 20
    .line 21
    move v0, v2

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    move v0, v3

    .line 24
    :goto_0
    and-int/2addr p2, v2

    .line 25
    check-cast p1, Ll2/t;

    .line 26
    .line 27
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 28
    .line 29
    .line 30
    move-result p2

    .line 31
    if-eqz p2, :cond_2

    .line 32
    .line 33
    iget-object p2, p0, Lvu/c;->e:Lvu/l;

    .line 34
    .line 35
    iget-object p2, p2, Lvu/l;->x:Ll2/b1;

    .line 36
    .line 37
    invoke-interface {p2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object p2

    .line 41
    check-cast p2, Lay0/o;

    .line 42
    .line 43
    if-nez p2, :cond_1

    .line 44
    .line 45
    const p0, 0x3820be9a

    .line 46
    .line 47
    .line 48
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 49
    .line 50
    .line 51
    :goto_1
    invoke-virtual {p1, v3}, Ll2/t;->q(Z)V

    .line 52
    .line 53
    .line 54
    goto :goto_2

    .line 55
    :cond_1
    const v0, -0x7a0f75b9

    .line 56
    .line 57
    .line 58
    invoke-virtual {p1, v0}, Ll2/t;->Y(I)V

    .line 59
    .line 60
    .line 61
    iget-object p0, p0, Lvu/c;->f:Lvu/i;

    .line 62
    .line 63
    check-cast p0, Lvu/h;

    .line 64
    .line 65
    iget-object p0, p0, Lvu/h;->a:Lzj0/c;

    .line 66
    .line 67
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    invoke-interface {p2, p0, p1, v0}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    goto :goto_1

    .line 75
    :cond_2
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
    :pswitch_0
    and-int/lit8 v0, p2, 0x3

    .line 82
    .line 83
    const/4 v1, 0x2

    .line 84
    const/4 v2, 0x1

    .line 85
    const/4 v3, 0x0

    .line 86
    if-eq v0, v1, :cond_3

    .line 87
    .line 88
    move v0, v2

    .line 89
    goto :goto_3

    .line 90
    :cond_3
    move v0, v3

    .line 91
    :goto_3
    and-int/2addr p2, v2

    .line 92
    check-cast p1, Ll2/t;

    .line 93
    .line 94
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 95
    .line 96
    .line 97
    move-result p2

    .line 98
    if-eqz p2, :cond_5

    .line 99
    .line 100
    iget-object p2, p0, Lvu/c;->e:Lvu/l;

    .line 101
    .line 102
    iget-object p2, p2, Lvu/l;->w:Ll2/b1;

    .line 103
    .line 104
    invoke-interface {p2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object p2

    .line 108
    check-cast p2, Lay0/o;

    .line 109
    .line 110
    if-nez p2, :cond_4

    .line 111
    .line 112
    const p0, 0x2e4533ce

    .line 113
    .line 114
    .line 115
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 116
    .line 117
    .line 118
    :goto_4
    invoke-virtual {p1, v3}, Ll2/t;->q(Z)V

    .line 119
    .line 120
    .line 121
    goto :goto_5

    .line 122
    :cond_4
    const v0, 0x438e9e93

    .line 123
    .line 124
    .line 125
    invoke-virtual {p1, v0}, Ll2/t;->Y(I)V

    .line 126
    .line 127
    .line 128
    iget-object p0, p0, Lvu/c;->f:Lvu/i;

    .line 129
    .line 130
    check-cast p0, Lvu/g;

    .line 131
    .line 132
    iget-object p0, p0, Lvu/g;->a:Lqu/a;

    .line 133
    .line 134
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 135
    .line 136
    .line 137
    move-result-object v0

    .line 138
    invoke-interface {p2, p0, p1, v0}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    goto :goto_4

    .line 142
    :cond_5
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 143
    .line 144
    .line 145
    :goto_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 146
    .line 147
    return-object p0

    .line 148
    nop

    .line 149
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
