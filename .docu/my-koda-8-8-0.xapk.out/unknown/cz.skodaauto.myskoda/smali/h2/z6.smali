.class public final Lh2/z6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Z

.field public final synthetic g:Li1/l;

.field public final synthetic h:Lh2/eb;

.field public final synthetic i:Le3/n0;


# direct methods
.method public synthetic constructor <init>(ZZLi1/l;Lh2/eb;Le3/n0;I)V
    .locals 0

    .line 1
    iput p6, p0, Lh2/z6;->d:I

    .line 2
    .line 3
    iput-boolean p1, p0, Lh2/z6;->e:Z

    .line 4
    .line 5
    iput-boolean p2, p0, Lh2/z6;->f:Z

    .line 6
    .line 7
    iput-object p3, p0, Lh2/z6;->g:Li1/l;

    .line 8
    .line 9
    iput-object p4, p0, Lh2/z6;->h:Lh2/eb;

    .line 10
    .line 11
    iput-object p5, p0, Lh2/z6;->i:Le3/n0;

    .line 12
    .line 13
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    iget v0, p0, Lh2/z6;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ll2/o;

    .line 7
    .line 8
    check-cast p2, Ljava/lang/Number;

    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

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
    move-object v7, p1

    .line 25
    check-cast v7, Ll2/t;

    .line 26
    .line 27
    invoke-virtual {v7, p2, v0}, Ll2/t;->O(IZ)Z

    .line 28
    .line 29
    .line 30
    move-result p1

    .line 31
    if-eqz p1, :cond_1

    .line 32
    .line 33
    sget-object v1, Lh2/hb;->a:Lh2/hb;

    .line 34
    .line 35
    iget-object v6, p0, Lh2/z6;->i:Le3/n0;

    .line 36
    .line 37
    const v8, 0x6d80c00

    .line 38
    .line 39
    .line 40
    iget-boolean v2, p0, Lh2/z6;->e:Z

    .line 41
    .line 42
    iget-boolean v3, p0, Lh2/z6;->f:Z

    .line 43
    .line 44
    iget-object v4, p0, Lh2/z6;->g:Li1/l;

    .line 45
    .line 46
    iget-object v5, p0, Lh2/z6;->h:Lh2/eb;

    .line 47
    .line 48
    invoke-virtual/range {v1 .. v8}, Lh2/hb;->a(ZZLi1/l;Lh2/eb;Le3/n0;Ll2/o;I)V

    .line 49
    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_1
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 53
    .line 54
    .line 55
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    return-object p0

    .line 58
    :pswitch_0
    check-cast p1, Ll2/o;

    .line 59
    .line 60
    check-cast p2, Ljava/lang/Number;

    .line 61
    .line 62
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 63
    .line 64
    .line 65
    move-result p2

    .line 66
    and-int/lit8 v0, p2, 0x3

    .line 67
    .line 68
    const/4 v1, 0x2

    .line 69
    const/4 v2, 0x1

    .line 70
    if-eq v0, v1, :cond_2

    .line 71
    .line 72
    move v0, v2

    .line 73
    goto :goto_2

    .line 74
    :cond_2
    const/4 v0, 0x0

    .line 75
    :goto_2
    and-int/2addr p2, v2

    .line 76
    move-object v10, p1

    .line 77
    check-cast v10, Ll2/t;

    .line 78
    .line 79
    invoke-virtual {v10, p2, v0}, Ll2/t;->O(IZ)Z

    .line 80
    .line 81
    .line 82
    move-result p1

    .line 83
    if-eqz p1, :cond_3

    .line 84
    .line 85
    sget-object v1, Lh2/v6;->a:Lh2/v6;

    .line 86
    .line 87
    const/high16 v11, 0x6000000

    .line 88
    .line 89
    const/16 v12, 0xc8

    .line 90
    .line 91
    iget-boolean v2, p0, Lh2/z6;->e:Z

    .line 92
    .line 93
    iget-boolean v3, p0, Lh2/z6;->f:Z

    .line 94
    .line 95
    iget-object v4, p0, Lh2/z6;->g:Li1/l;

    .line 96
    .line 97
    const/4 v5, 0x0

    .line 98
    iget-object v6, p0, Lh2/z6;->h:Lh2/eb;

    .line 99
    .line 100
    iget-object v7, p0, Lh2/z6;->i:Le3/n0;

    .line 101
    .line 102
    const/4 v8, 0x0

    .line 103
    const/4 v9, 0x0

    .line 104
    invoke-virtual/range {v1 .. v12}, Lh2/v6;->a(ZZLi1/l;Lx2/s;Lh2/eb;Le3/n0;FFLl2/o;II)V

    .line 105
    .line 106
    .line 107
    goto :goto_3

    .line 108
    :cond_3
    invoke-virtual {v10}, Ll2/t;->R()V

    .line 109
    .line 110
    .line 111
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 112
    .line 113
    return-object p0

    .line 114
    nop

    .line 115
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
