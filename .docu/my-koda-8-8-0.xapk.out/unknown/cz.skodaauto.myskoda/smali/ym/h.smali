.class public final Lym/h;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;

.field public final synthetic k:I

.field public final synthetic l:I

.field public final synthetic m:I


# direct methods
.method public synthetic constructor <init>(Lum/a;Lay0/a;Lx2/s;Lt3/k;IIII)V
    .locals 0

    .line 1
    iput p8, p0, Lym/h;->f:I

    iput-object p1, p0, Lym/h;->g:Ljava/lang/Object;

    iput-object p2, p0, Lym/h;->h:Ljava/lang/Object;

    iput-object p3, p0, Lym/h;->i:Ljava/lang/Object;

    iput-object p4, p0, Lym/h;->j:Ljava/lang/Object;

    iput p5, p0, Lym/h;->k:I

    iput p6, p0, Lym/h;->l:I

    iput p7, p0, Lym/h;->m:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method

.method public constructor <init>(Lvv/m0;Lvv/g0;Ljava/util/List;ILt2/b;II)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lym/h;->f:I

    .line 2
    iput-object p1, p0, Lym/h;->g:Ljava/lang/Object;

    iput-object p2, p0, Lym/h;->h:Ljava/lang/Object;

    iput-object p3, p0, Lym/h;->i:Ljava/lang/Object;

    iput p4, p0, Lym/h;->k:I

    iput-object p5, p0, Lym/h;->j:Ljava/lang/Object;

    iput p6, p0, Lym/h;->l:I

    iput p7, p0, Lym/h;->m:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Lym/h;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v6, p1

    .line 7
    check-cast v6, Ll2/o;

    .line 8
    .line 9
    check-cast p2, Ljava/lang/Number;

    .line 10
    .line 11
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 12
    .line 13
    .line 14
    iget-object p1, p0, Lym/h;->g:Ljava/lang/Object;

    .line 15
    .line 16
    move-object v1, p1

    .line 17
    check-cast v1, Lvv/m0;

    .line 18
    .line 19
    iget-object p1, p0, Lym/h;->h:Ljava/lang/Object;

    .line 20
    .line 21
    move-object v2, p1

    .line 22
    check-cast v2, Lvv/g0;

    .line 23
    .line 24
    iget-object p1, p0, Lym/h;->i:Ljava/lang/Object;

    .line 25
    .line 26
    move-object v3, p1

    .line 27
    check-cast v3, Ljava/util/List;

    .line 28
    .line 29
    iget-object p1, p0, Lym/h;->j:Ljava/lang/Object;

    .line 30
    .line 31
    move-object v5, p1

    .line 32
    check-cast v5, Lt2/b;

    .line 33
    .line 34
    iget p1, p0, Lym/h;->l:I

    .line 35
    .line 36
    or-int/lit8 p1, p1, 0x1

    .line 37
    .line 38
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 39
    .line 40
    .line 41
    move-result v7

    .line 42
    iget v8, p0, Lym/h;->m:I

    .line 43
    .line 44
    iget v4, p0, Lym/h;->k:I

    .line 45
    .line 46
    invoke-static/range {v1 .. v8}, Lvv/x;->a(Lvv/m0;Lvv/g0;Ljava/util/List;ILt2/b;Ll2/o;II)V

    .line 47
    .line 48
    .line 49
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 50
    .line 51
    return-object p0

    .line 52
    :pswitch_0
    move-object v4, p1

    .line 53
    check-cast v4, Ll2/o;

    .line 54
    .line 55
    check-cast p2, Ljava/lang/Number;

    .line 56
    .line 57
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 58
    .line 59
    .line 60
    iget-object p1, p0, Lym/h;->g:Ljava/lang/Object;

    .line 61
    .line 62
    move-object v0, p1

    .line 63
    check-cast v0, Lum/a;

    .line 64
    .line 65
    iget-object p1, p0, Lym/h;->h:Ljava/lang/Object;

    .line 66
    .line 67
    move-object v1, p1

    .line 68
    check-cast v1, Lay0/a;

    .line 69
    .line 70
    iget-object p1, p0, Lym/h;->i:Ljava/lang/Object;

    .line 71
    .line 72
    move-object v2, p1

    .line 73
    check-cast v2, Lx2/s;

    .line 74
    .line 75
    iget-object p1, p0, Lym/h;->j:Ljava/lang/Object;

    .line 76
    .line 77
    move-object v3, p1

    .line 78
    check-cast v3, Lt3/k;

    .line 79
    .line 80
    iget p1, p0, Lym/h;->k:I

    .line 81
    .line 82
    or-int/lit8 p1, p1, 0x1

    .line 83
    .line 84
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 85
    .line 86
    .line 87
    move-result v5

    .line 88
    iget p1, p0, Lym/h;->l:I

    .line 89
    .line 90
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 91
    .line 92
    .line 93
    move-result v6

    .line 94
    iget v7, p0, Lym/h;->m:I

    .line 95
    .line 96
    invoke-static/range {v0 .. v7}, Lcom/google/android/gms/internal/measurement/z3;->a(Lum/a;Lay0/a;Lx2/s;Lt3/k;Ll2/o;III)V

    .line 97
    .line 98
    .line 99
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 100
    .line 101
    return-object p0

    .line 102
    :pswitch_1
    move-object v4, p1

    .line 103
    check-cast v4, Ll2/o;

    .line 104
    .line 105
    check-cast p2, Ljava/lang/Number;

    .line 106
    .line 107
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 108
    .line 109
    .line 110
    iget-object p1, p0, Lym/h;->g:Ljava/lang/Object;

    .line 111
    .line 112
    move-object v0, p1

    .line 113
    check-cast v0, Lum/a;

    .line 114
    .line 115
    iget-object p1, p0, Lym/h;->h:Ljava/lang/Object;

    .line 116
    .line 117
    move-object v1, p1

    .line 118
    check-cast v1, Lay0/a;

    .line 119
    .line 120
    iget-object p1, p0, Lym/h;->i:Ljava/lang/Object;

    .line 121
    .line 122
    move-object v2, p1

    .line 123
    check-cast v2, Lx2/s;

    .line 124
    .line 125
    iget-object p1, p0, Lym/h;->j:Ljava/lang/Object;

    .line 126
    .line 127
    move-object v3, p1

    .line 128
    check-cast v3, Lt3/k;

    .line 129
    .line 130
    iget p1, p0, Lym/h;->k:I

    .line 131
    .line 132
    or-int/lit8 p1, p1, 0x1

    .line 133
    .line 134
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 135
    .line 136
    .line 137
    move-result v5

    .line 138
    iget p1, p0, Lym/h;->l:I

    .line 139
    .line 140
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 141
    .line 142
    .line 143
    move-result v6

    .line 144
    iget v7, p0, Lym/h;->m:I

    .line 145
    .line 146
    invoke-static/range {v0 .. v7}, Lcom/google/android/gms/internal/measurement/z3;->a(Lum/a;Lay0/a;Lx2/s;Lt3/k;Ll2/o;III)V

    .line 147
    .line 148
    .line 149
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 150
    .line 151
    return-object p0

    .line 152
    nop

    .line 153
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
