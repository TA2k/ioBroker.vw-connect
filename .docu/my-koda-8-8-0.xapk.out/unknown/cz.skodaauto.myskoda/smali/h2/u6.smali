.class public final Lh2/u6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/n;


# direct methods
.method public synthetic constructor <init>(ILay0/n;)V
    .locals 0

    .line 1
    iput p1, p0, Lh2/u6;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Lh2/u6;->e:Lay0/n;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lh2/u6;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Li2/e1;

    .line 7
    .line 8
    check-cast p2, Ll2/o;

    .line 9
    .line 10
    check-cast p3, Ljava/lang/Number;

    .line 11
    .line 12
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 13
    .line 14
    .line 15
    move-result p1

    .line 16
    and-int/lit8 p3, p1, 0x11

    .line 17
    .line 18
    const/16 v0, 0x10

    .line 19
    .line 20
    const/4 v1, 0x0

    .line 21
    const/4 v2, 0x1

    .line 22
    if-eq p3, v0, :cond_0

    .line 23
    .line 24
    move p3, v2

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    move p3, v1

    .line 27
    :goto_0
    and-int/2addr p1, v2

    .line 28
    check-cast p2, Ll2/t;

    .line 29
    .line 30
    invoke-virtual {p2, p1, p3}, Ll2/t;->O(IZ)Z

    .line 31
    .line 32
    .line 33
    move-result p1

    .line 34
    if-eqz p1, :cond_1

    .line 35
    .line 36
    iget-object p0, p0, Lh2/u6;->e:Lay0/n;

    .line 37
    .line 38
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    invoke-interface {p0, p2, p1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_1
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 47
    .line 48
    .line 49
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 50
    .line 51
    return-object p0

    .line 52
    :pswitch_0
    check-cast p1, Lk1/t;

    .line 53
    .line 54
    check-cast p2, Ll2/o;

    .line 55
    .line 56
    check-cast p3, Ljava/lang/Number;

    .line 57
    .line 58
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 59
    .line 60
    .line 61
    move-result p1

    .line 62
    and-int/lit8 p3, p1, 0x11

    .line 63
    .line 64
    const/16 v0, 0x10

    .line 65
    .line 66
    const/4 v1, 0x0

    .line 67
    const/4 v2, 0x1

    .line 68
    if-eq p3, v0, :cond_2

    .line 69
    .line 70
    move p3, v2

    .line 71
    goto :goto_2

    .line 72
    :cond_2
    move p3, v1

    .line 73
    :goto_2
    and-int/2addr p1, v2

    .line 74
    check-cast p2, Ll2/t;

    .line 75
    .line 76
    invoke-virtual {p2, p1, p3}, Ll2/t;->O(IZ)Z

    .line 77
    .line 78
    .line 79
    move-result p1

    .line 80
    if-eqz p1, :cond_3

    .line 81
    .line 82
    iget-object p0, p0, Lh2/u6;->e:Lay0/n;

    .line 83
    .line 84
    invoke-static {p0, p2, v1}, Lh2/wa;->c(Lay0/n;Ll2/o;I)V

    .line 85
    .line 86
    .line 87
    goto :goto_3

    .line 88
    :cond_3
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 89
    .line 90
    .line 91
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 92
    .line 93
    return-object p0

    .line 94
    :pswitch_1
    check-cast p1, Li2/e1;

    .line 95
    .line 96
    check-cast p2, Ll2/o;

    .line 97
    .line 98
    check-cast p3, Ljava/lang/Number;

    .line 99
    .line 100
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 101
    .line 102
    .line 103
    move-result p1

    .line 104
    and-int/lit8 p3, p1, 0x11

    .line 105
    .line 106
    const/16 v0, 0x10

    .line 107
    .line 108
    const/4 v1, 0x0

    .line 109
    const/4 v2, 0x1

    .line 110
    if-eq p3, v0, :cond_4

    .line 111
    .line 112
    move p3, v2

    .line 113
    goto :goto_4

    .line 114
    :cond_4
    move p3, v1

    .line 115
    :goto_4
    and-int/2addr p1, v2

    .line 116
    check-cast p2, Ll2/t;

    .line 117
    .line 118
    invoke-virtual {p2, p1, p3}, Ll2/t;->O(IZ)Z

    .line 119
    .line 120
    .line 121
    move-result p1

    .line 122
    if-eqz p1, :cond_5

    .line 123
    .line 124
    iget-object p0, p0, Lh2/u6;->e:Lay0/n;

    .line 125
    .line 126
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 127
    .line 128
    .line 129
    move-result-object p1

    .line 130
    invoke-interface {p0, p2, p1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    goto :goto_5

    .line 134
    :cond_5
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 135
    .line 136
    .line 137
    :goto_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 138
    .line 139
    return-object p0

    .line 140
    nop

    .line 141
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
