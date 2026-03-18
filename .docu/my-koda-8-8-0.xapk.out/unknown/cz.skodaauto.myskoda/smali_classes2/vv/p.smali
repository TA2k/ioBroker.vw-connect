.class public final Lvv/p;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic f:Lvv/g0;

.field public final synthetic g:Lvv/f0;

.field public final synthetic h:Lvv/m0;

.field public final synthetic i:I

.field public final synthetic j:I


# direct methods
.method public constructor <init>(Lvv/g0;Lvv/f0;Lvv/m0;II)V
    .locals 0

    .line 1
    iput-object p1, p0, Lvv/p;->f:Lvv/g0;

    .line 2
    .line 3
    iput-object p2, p0, Lvv/p;->g:Lvv/f0;

    .line 4
    .line 5
    iput-object p3, p0, Lvv/p;->h:Lvv/m0;

    .line 6
    .line 7
    iput p4, p0, Lvv/p;->i:I

    .line 8
    .line 9
    iput p5, p0, Lvv/p;->j:I

    .line 10
    .line 11
    const/4 p1, 0x3

    .line 12
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 13
    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    check-cast p1, Ljava/lang/Number;

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    check-cast p2, Ll2/o;

    .line 8
    .line 9
    check-cast p3, Ljava/lang/Number;

    .line 10
    .line 11
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 12
    .line 13
    .line 14
    move-result p3

    .line 15
    const/4 v0, 0x0

    .line 16
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    and-int/lit8 v2, p3, 0xe

    .line 21
    .line 22
    if-nez v2, :cond_1

    .line 23
    .line 24
    move-object v2, p2

    .line 25
    check-cast v2, Ll2/t;

    .line 26
    .line 27
    invoke-virtual {v2, p1}, Ll2/t;->e(I)Z

    .line 28
    .line 29
    .line 30
    move-result v2

    .line 31
    if-eqz v2, :cond_0

    .line 32
    .line 33
    const/4 v2, 0x4

    .line 34
    goto :goto_0

    .line 35
    :cond_0
    const/4 v2, 0x2

    .line 36
    :goto_0
    or-int/2addr p3, v2

    .line 37
    :cond_1
    and-int/lit8 p3, p3, 0x5b

    .line 38
    .line 39
    const/16 v2, 0x12

    .line 40
    .line 41
    if-ne p3, v2, :cond_3

    .line 42
    .line 43
    move-object p3, p2

    .line 44
    check-cast p3, Ll2/t;

    .line 45
    .line 46
    invoke-virtual {p3}, Ll2/t;->A()Z

    .line 47
    .line 48
    .line 49
    move-result v2

    .line 50
    if-nez v2, :cond_2

    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_2
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 54
    .line 55
    .line 56
    goto/16 :goto_2

    .line 57
    .line 58
    :cond_3
    :goto_1
    iget-object p3, p0, Lvv/p;->f:Lvv/g0;

    .line 59
    .line 60
    invoke-virtual {p3}, Ljava/lang/Enum;->ordinal()I

    .line 61
    .line 62
    .line 63
    move-result p3

    .line 64
    iget v2, p0, Lvv/p;->i:I

    .line 65
    .line 66
    iget-object v3, p0, Lvv/p;->h:Lvv/m0;

    .line 67
    .line 68
    iget-object v4, p0, Lvv/p;->g:Lvv/f0;

    .line 69
    .line 70
    if-eqz p3, :cond_5

    .line 71
    .line 72
    const/4 p0, 0x1

    .line 73
    if-eq p3, p0, :cond_4

    .line 74
    .line 75
    check-cast p2, Ll2/t;

    .line 76
    .line 77
    const p0, -0x48cb2cad

    .line 78
    .line 79
    .line 80
    invoke-virtual {p2, p0}, Ll2/t;->Z(I)V

    .line 81
    .line 82
    .line 83
    invoke-virtual {p2, v0}, Ll2/t;->q(Z)V

    .line 84
    .line 85
    .line 86
    goto :goto_2

    .line 87
    :cond_4
    check-cast p2, Ll2/t;

    .line 88
    .line 89
    const p0, -0x48cb2ccd

    .line 90
    .line 91
    .line 92
    invoke-virtual {p2, p0}, Ll2/t;->Z(I)V

    .line 93
    .line 94
    .line 95
    iget-object p0, v4, Lvv/f0;->e:Lay0/k;

    .line 96
    .line 97
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 98
    .line 99
    .line 100
    invoke-interface {p0, v3}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    check-cast p0, Lvv/d1;

    .line 105
    .line 106
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 107
    .line 108
    .line 109
    const p1, 0x5d44829f

    .line 110
    .line 111
    .line 112
    invoke-virtual {p2, p1}, Ll2/t;->Z(I)V

    .line 113
    .line 114
    .line 115
    iget-object p0, p0, Lvv/d1;->a:Lt2/b;

    .line 116
    .line 117
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 118
    .line 119
    .line 120
    move-result-object p1

    .line 121
    invoke-virtual {p0, p1, p2, v1}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    invoke-virtual {p2, v0}, Ll2/t;->q(Z)V

    .line 125
    .line 126
    .line 127
    invoke-virtual {p2, v0}, Ll2/t;->q(Z)V

    .line 128
    .line 129
    .line 130
    goto :goto_2

    .line 131
    :cond_5
    check-cast p2, Ll2/t;

    .line 132
    .line 133
    const p3, -0x48cb2d2e

    .line 134
    .line 135
    .line 136
    invoke-virtual {p2, p3}, Ll2/t;->Z(I)V

    .line 137
    .line 138
    .line 139
    iget-object p3, v4, Lvv/f0;->d:Lay0/k;

    .line 140
    .line 141
    invoke-static {p3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 142
    .line 143
    .line 144
    invoke-interface {p3, v3}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object p3

    .line 148
    check-cast p3, Lvv/h0;

    .line 149
    .line 150
    iget p0, p0, Lvv/p;->j:I

    .line 151
    .line 152
    add-int/2addr p0, p1

    .line 153
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 154
    .line 155
    .line 156
    const p1, 0x7559ec41

    .line 157
    .line 158
    .line 159
    invoke-virtual {p2, p1}, Ll2/t;->Z(I)V

    .line 160
    .line 161
    .line 162
    iget-object p1, p3, Lvv/h0;->a:Lt2/b;

    .line 163
    .line 164
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 165
    .line 166
    .line 167
    move-result-object p3

    .line 168
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 169
    .line 170
    .line 171
    move-result-object p0

    .line 172
    invoke-virtual {p1, p3, p0, p2, v1}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    invoke-virtual {p2, v0}, Ll2/t;->q(Z)V

    .line 176
    .line 177
    .line 178
    invoke-virtual {p2, v0}, Ll2/t;->q(Z)V

    .line 179
    .line 180
    .line 181
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 182
    .line 183
    return-object p0
.end method
