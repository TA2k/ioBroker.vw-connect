.class public final synthetic Ly61/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh70/o;

.field public final synthetic f:Ly61/g;

.field public final synthetic g:Lt2/b;


# direct methods
.method public synthetic constructor <init>(Lh70/o;Ly61/g;Lt2/b;I)V
    .locals 0

    .line 1
    iput p4, p0, Ly61/e;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ly61/e;->e:Lh70/o;

    .line 4
    .line 5
    iput-object p2, p0, Ly61/e;->f:Ly61/g;

    .line 6
    .line 7
    iput-object p3, p0, Ly61/e;->g:Lt2/b;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Ly61/e;->d:I

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
    if-eq v0, v1, :cond_0

    .line 19
    .line 20
    move v0, v2

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 v0, 0x0

    .line 23
    :goto_0
    and-int/2addr p2, v2

    .line 24
    check-cast p1, Ll2/t;

    .line 25
    .line 26
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 27
    .line 28
    .line 29
    move-result p2

    .line 30
    if-eqz p2, :cond_1

    .line 31
    .line 32
    sget-object p2, Ly61/a;->a:Ll2/e0;

    .line 33
    .line 34
    iget-object v0, p0, Ly61/e;->e:Lh70/o;

    .line 35
    .line 36
    invoke-virtual {p2, v0}, Ll2/e0;->a(Ljava/lang/Object;)Ll2/t1;

    .line 37
    .line 38
    .line 39
    move-result-object p2

    .line 40
    sget-object v0, Lc71/e;->a:Ll2/e0;

    .line 41
    .line 42
    iget-object v1, p0, Ly61/e;->f:Ly61/g;

    .line 43
    .line 44
    iget-object v1, v1, Ly61/g;->a:Lc71/g;

    .line 45
    .line 46
    invoke-virtual {v0, v1}, Ll2/e0;->a(Ljava/lang/Object;)Ll2/t1;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    filled-new-array {p2, v0}, [Ll2/t1;

    .line 51
    .line 52
    .line 53
    move-result-object p2

    .line 54
    new-instance v0, Ld71/d;

    .line 55
    .line 56
    const/16 v1, 0x19

    .line 57
    .line 58
    iget-object p0, p0, Ly61/e;->g:Lt2/b;

    .line 59
    .line 60
    invoke-direct {v0, p0, v1}, Ld71/d;-><init>(Lt2/b;I)V

    .line 61
    .line 62
    .line 63
    const p0, -0x146bbc6e

    .line 64
    .line 65
    .line 66
    invoke-static {p0, p1, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    const/16 v0, 0x38

    .line 71
    .line 72
    invoke-static {p2, p0, p1, v0}, Ll2/b;->b([Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 73
    .line 74
    .line 75
    goto :goto_1

    .line 76
    :cond_1
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 77
    .line 78
    .line 79
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 80
    .line 81
    return-object p0

    .line 82
    :pswitch_0
    and-int/lit8 v0, p2, 0x3

    .line 83
    .line 84
    const/4 v1, 0x2

    .line 85
    const/4 v2, 0x1

    .line 86
    if-eq v0, v1, :cond_2

    .line 87
    .line 88
    move v0, v2

    .line 89
    goto :goto_2

    .line 90
    :cond_2
    const/4 v0, 0x0

    .line 91
    :goto_2
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
    if-eqz p2, :cond_3

    .line 99
    .line 100
    new-instance p2, Ly61/e;

    .line 101
    .line 102
    const/4 v0, 0x1

    .line 103
    iget-object v1, p0, Ly61/e;->e:Lh70/o;

    .line 104
    .line 105
    iget-object v2, p0, Ly61/e;->f:Ly61/g;

    .line 106
    .line 107
    iget-object p0, p0, Ly61/e;->g:Lt2/b;

    .line 108
    .line 109
    invoke-direct {p2, v1, v2, p0, v0}, Ly61/e;-><init>(Lh70/o;Ly61/g;Lt2/b;I)V

    .line 110
    .line 111
    .line 112
    const p0, 0x352f1052

    .line 113
    .line 114
    .line 115
    invoke-static {p0, p1, p2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    const/4 p2, 0x6

    .line 120
    invoke-static {p0, p1, p2}, Ld71/e;->a(Lt2/b;Ll2/o;I)V

    .line 121
    .line 122
    .line 123
    goto :goto_3

    .line 124
    :cond_3
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 125
    .line 126
    .line 127
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 128
    .line 129
    return-object p0

    .line 130
    nop

    .line 131
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
