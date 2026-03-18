.class public final synthetic Lal/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Llh/g;


# direct methods
.method public synthetic constructor <init>(Llh/g;I)V
    .locals 0

    .line 1
    iput p2, p0, Lal/k;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lal/k;->e:Llh/g;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lal/k;->d:I

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
    iget-object p0, p0, Lal/k;->e:Llh/g;

    .line 34
    .line 35
    iget-boolean p0, p0, Llh/g;->e:Z

    .line 36
    .line 37
    if-eqz p0, :cond_1

    .line 38
    .line 39
    const p0, -0x20b0bf63

    .line 40
    .line 41
    .line 42
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 43
    .line 44
    .line 45
    invoke-static {v3, v2, p1, v3}, Ldk/b;->e(IILl2/o;Z)V

    .line 46
    .line 47
    .line 48
    :goto_1
    invoke-virtual {p1, v3}, Ll2/t;->q(Z)V

    .line 49
    .line 50
    .line 51
    goto :goto_2

    .line 52
    :cond_1
    const p0, -0x20e9a735

    .line 53
    .line 54
    .line 55
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 56
    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_2
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 60
    .line 61
    .line 62
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 63
    .line 64
    return-object p0

    .line 65
    :pswitch_0
    and-int/lit8 v0, p2, 0x3

    .line 66
    .line 67
    const/4 v1, 0x2

    .line 68
    const/4 v2, 0x1

    .line 69
    const/4 v3, 0x0

    .line 70
    if-eq v0, v1, :cond_3

    .line 71
    .line 72
    move v0, v2

    .line 73
    goto :goto_3

    .line 74
    :cond_3
    move v0, v3

    .line 75
    :goto_3
    and-int/2addr p2, v2

    .line 76
    check-cast p1, Ll2/t;

    .line 77
    .line 78
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 79
    .line 80
    .line 81
    move-result p2

    .line 82
    if-eqz p2, :cond_5

    .line 83
    .line 84
    iget-object p0, p0, Lal/k;->e:Llh/g;

    .line 85
    .line 86
    iget-boolean p0, p0, Llh/g;->e:Z

    .line 87
    .line 88
    if-eqz p0, :cond_4

    .line 89
    .line 90
    const p0, 0x43dc7c8

    .line 91
    .line 92
    .line 93
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 94
    .line 95
    .line 96
    invoke-static {p1}, Lzb/b;->r(Ll2/o;)Lay0/a;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    sget-object p2, Lal/a;->f:Lt2/b;

    .line 101
    .line 102
    const/16 v0, 0x30

    .line 103
    .line 104
    invoke-static {p0, p2, p1, v0}, Lzb/b;->f(Lay0/a;Lay0/n;Ll2/o;I)V

    .line 105
    .line 106
    .line 107
    :goto_4
    invoke-virtual {p1, v3}, Ll2/t;->q(Z)V

    .line 108
    .line 109
    .line 110
    goto :goto_5

    .line 111
    :cond_4
    const p0, 0x3f8de1e

    .line 112
    .line 113
    .line 114
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 115
    .line 116
    .line 117
    goto :goto_4

    .line 118
    :cond_5
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 119
    .line 120
    .line 121
    :goto_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 122
    .line 123
    return-object p0

    .line 124
    nop

    .line 125
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
