.class public final synthetic Lxf0/j2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:F

.field public final synthetic f:F

.field public final synthetic g:F

.field public final synthetic h:F

.field public final synthetic i:F

.field public final synthetic j:J


# direct methods
.method public synthetic constructor <init>(FFFFFJI)V
    .locals 0

    .line 1
    iput p8, p0, Lxf0/j2;->d:I

    .line 2
    .line 3
    iput p1, p0, Lxf0/j2;->e:F

    .line 4
    .line 5
    iput p2, p0, Lxf0/j2;->f:F

    .line 6
    .line 7
    iput p3, p0, Lxf0/j2;->g:F

    .line 8
    .line 9
    iput p4, p0, Lxf0/j2;->h:F

    .line 10
    .line 11
    iput p5, p0, Lxf0/j2;->i:F

    .line 12
    .line 13
    iput-wide p6, p0, Lxf0/j2;->j:J

    .line 14
    .line 15
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 16
    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    iget v0, p0, Lxf0/j2;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v1, p1

    .line 7
    check-cast v1, Lg3/d;

    .line 8
    .line 9
    const-string p1, "$this$onDrawBehind"

    .line 10
    .line 11
    invoke-static {v1, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    new-instance v2, Lg3/h;

    .line 15
    .line 16
    iget p1, p0, Lxf0/j2;->e:F

    .line 17
    .line 18
    invoke-interface {v1, p1}, Lt4/c;->w0(F)F

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    iget p1, p0, Lxf0/j2;->f:F

    .line 23
    .line 24
    invoke-interface {v1, p1}, Lt4/c;->w0(F)F

    .line 25
    .line 26
    .line 27
    move-result p1

    .line 28
    iget v0, p0, Lxf0/j2;->g:F

    .line 29
    .line 30
    invoke-interface {v1, v0}, Lt4/c;->w0(F)F

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    const/4 v4, 0x2

    .line 35
    new-array v4, v4, [F

    .line 36
    .line 37
    const/4 v5, 0x0

    .line 38
    aput p1, v4, v5

    .line 39
    .line 40
    const/4 p1, 0x1

    .line 41
    aput v0, v4, p1

    .line 42
    .line 43
    iget p1, p0, Lxf0/j2;->h:F

    .line 44
    .line 45
    invoke-interface {v1, p1}, Lt4/c;->w0(F)F

    .line 46
    .line 47
    .line 48
    move-result p1

    .line 49
    new-instance v7, Le3/j;

    .line 50
    .line 51
    new-instance v0, Landroid/graphics/DashPathEffect;

    .line 52
    .line 53
    invoke-direct {v0, v4, p1}, Landroid/graphics/DashPathEffect;-><init>([FF)V

    .line 54
    .line 55
    .line 56
    invoke-direct {v7, v0}, Le3/j;-><init>(Landroid/graphics/DashPathEffect;)V

    .line 57
    .line 58
    .line 59
    const/16 v8, 0xe

    .line 60
    .line 61
    const/4 v4, 0x0

    .line 62
    const/4 v6, 0x0

    .line 63
    invoke-direct/range {v2 .. v8}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 64
    .line 65
    .line 66
    iget p1, p0, Lxf0/j2;->i:F

    .line 67
    .line 68
    invoke-interface {v1, p1}, Lt4/c;->w0(F)F

    .line 69
    .line 70
    .line 71
    move-result p1

    .line 72
    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 73
    .line 74
    .line 75
    move-result v0

    .line 76
    int-to-long v3, v0

    .line 77
    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 78
    .line 79
    .line 80
    move-result p1

    .line 81
    int-to-long v5, p1

    .line 82
    const/16 p1, 0x20

    .line 83
    .line 84
    shl-long/2addr v3, p1

    .line 85
    const-wide v7, 0xffffffffL

    .line 86
    .line 87
    .line 88
    .line 89
    .line 90
    and-long/2addr v5, v7

    .line 91
    or-long v8, v3, v5

    .line 92
    .line 93
    const-wide/16 v6, 0x0

    .line 94
    .line 95
    const/16 v11, 0xe6

    .line 96
    .line 97
    move-object v10, v2

    .line 98
    iget-wide v2, p0, Lxf0/j2;->j:J

    .line 99
    .line 100
    const-wide/16 v4, 0x0

    .line 101
    .line 102
    invoke-static/range {v1 .. v11}, Lg3/d;->j0(Lg3/d;JJJJLg3/e;I)V

    .line 103
    .line 104
    .line 105
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 106
    .line 107
    return-object p0

    .line 108
    :pswitch_0
    check-cast p1, Lb3/d;

    .line 109
    .line 110
    const-string v0, "$this$drawWithCache"

    .line 111
    .line 112
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    new-instance v1, Lxf0/j2;

    .line 116
    .line 117
    const/4 v9, 0x1

    .line 118
    iget v2, p0, Lxf0/j2;->e:F

    .line 119
    .line 120
    iget v3, p0, Lxf0/j2;->f:F

    .line 121
    .line 122
    iget v4, p0, Lxf0/j2;->g:F

    .line 123
    .line 124
    iget v5, p0, Lxf0/j2;->h:F

    .line 125
    .line 126
    iget v6, p0, Lxf0/j2;->i:F

    .line 127
    .line 128
    iget-wide v7, p0, Lxf0/j2;->j:J

    .line 129
    .line 130
    invoke-direct/range {v1 .. v9}, Lxf0/j2;-><init>(FFFFFJI)V

    .line 131
    .line 132
    .line 133
    new-instance p0, Law/o;

    .line 134
    .line 135
    const/4 v0, 0x5

    .line 136
    invoke-direct {p0, v0, v1}, Law/o;-><init>(ILay0/k;)V

    .line 137
    .line 138
    .line 139
    invoke-virtual {p1, p0}, Lb3/d;->b(Lay0/k;)Lb3/g;

    .line 140
    .line 141
    .line 142
    move-result-object p0

    .line 143
    return-object p0

    .line 144
    nop

    .line 145
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
