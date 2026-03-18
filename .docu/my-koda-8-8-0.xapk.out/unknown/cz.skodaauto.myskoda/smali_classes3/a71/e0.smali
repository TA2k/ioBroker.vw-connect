.class public final synthetic La71/e0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Landroidx/lifecycle/x;ZII)V
    .locals 0

    .line 1
    const/4 p3, 0x6

    iput p3, p0, La71/e0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, La71/e0;->g:Ljava/lang/Object;

    iput-boolean p2, p0, La71/e0;->e:Z

    iput p4, p0, La71/e0;->f:I

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;ZII)V
    .locals 0

    .line 2
    iput p4, p0, La71/e0;->d:I

    iput-object p1, p0, La71/e0;->g:Ljava/lang/Object;

    iput-boolean p2, p0, La71/e0;->e:Z

    iput p3, p0, La71/e0;->f:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(ZLh71/a;I)V
    .locals 1

    .line 3
    const/4 v0, 0x0

    iput v0, p0, La71/e0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, La71/e0;->e:Z

    iput-object p2, p0, La71/e0;->g:Ljava/lang/Object;

    iput p3, p0, La71/e0;->f:I

    return-void
.end method

.method public synthetic constructor <init>(ZLlx0/e;II)V
    .locals 0

    .line 4
    iput p4, p0, La71/e0;->d:I

    iput-boolean p1, p0, La71/e0;->e:Z

    iput-object p2, p0, La71/e0;->g:Ljava/lang/Object;

    iput p3, p0, La71/e0;->f:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, La71/e0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, La71/e0;->g:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Landroidx/lifecycle/x;

    .line 9
    .line 10
    check-cast p1, Ll2/o;

    .line 11
    .line 12
    check-cast p2, Ljava/lang/Integer;

    .line 13
    .line 14
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    const/4 p2, 0x1

    .line 18
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 19
    .line 20
    .line 21
    move-result p2

    .line 22
    iget-boolean v1, p0, La71/e0;->e:Z

    .line 23
    .line 24
    iget p0, p0, La71/e0;->f:I

    .line 25
    .line 26
    invoke-static {v0, v1, p1, p2, p0}, Lxf0/y1;->m(Landroidx/lifecycle/x;ZLl2/o;II)V

    .line 27
    .line 28
    .line 29
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    return-object p0

    .line 32
    :pswitch_0
    iget-object v0, p0, La71/e0;->g:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v0, Lm1/t;

    .line 35
    .line 36
    check-cast p1, Ll2/o;

    .line 37
    .line 38
    check-cast p2, Ljava/lang/Integer;

    .line 39
    .line 40
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 41
    .line 42
    .line 43
    iget p2, p0, La71/e0;->f:I

    .line 44
    .line 45
    or-int/lit8 p2, p2, 0x1

    .line 46
    .line 47
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 48
    .line 49
    .line 50
    move-result p2

    .line 51
    iget-boolean p0, p0, La71/e0;->e:Z

    .line 52
    .line 53
    invoke-static {v0, p0, p1, p2}, Lcom/google/android/gms/internal/measurement/i5;->a(Lm1/t;ZLl2/o;I)V

    .line 54
    .line 55
    .line 56
    goto :goto_0

    .line 57
    :pswitch_1
    iget-object v0, p0, La71/e0;->g:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast v0, Lt2/b;

    .line 60
    .line 61
    check-cast p1, Ll2/o;

    .line 62
    .line 63
    check-cast p2, Ljava/lang/Integer;

    .line 64
    .line 65
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 66
    .line 67
    .line 68
    iget p2, p0, La71/e0;->f:I

    .line 69
    .line 70
    or-int/lit8 p2, p2, 0x1

    .line 71
    .line 72
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 73
    .line 74
    .line 75
    move-result p2

    .line 76
    iget-boolean p0, p0, La71/e0;->e:Z

    .line 77
    .line 78
    invoke-static {p0, v0, p1, p2}, Llp/pb;->d(ZLt2/b;Ll2/o;I)V

    .line 79
    .line 80
    .line 81
    goto :goto_0

    .line 82
    :pswitch_2
    iget-object v0, p0, La71/e0;->g:Ljava/lang/Object;

    .line 83
    .line 84
    check-cast v0, Lh50/v;

    .line 85
    .line 86
    check-cast p1, Ll2/o;

    .line 87
    .line 88
    check-cast p2, Ljava/lang/Integer;

    .line 89
    .line 90
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 91
    .line 92
    .line 93
    iget p2, p0, La71/e0;->f:I

    .line 94
    .line 95
    or-int/lit8 p2, p2, 0x1

    .line 96
    .line 97
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 98
    .line 99
    .line 100
    move-result p2

    .line 101
    iget-boolean p0, p0, La71/e0;->e:Z

    .line 102
    .line 103
    invoke-static {v0, p0, p1, p2}, Li50/s;->g(Lh50/v;ZLl2/o;I)V

    .line 104
    .line 105
    .line 106
    goto :goto_0

    .line 107
    :pswitch_3
    iget-object v0, p0, La71/e0;->g:Ljava/lang/Object;

    .line 108
    .line 109
    check-cast v0, Lay0/n;

    .line 110
    .line 111
    check-cast p1, Ll2/o;

    .line 112
    .line 113
    check-cast p2, Ljava/lang/Integer;

    .line 114
    .line 115
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 116
    .line 117
    .line 118
    iget p2, p0, La71/e0;->f:I

    .line 119
    .line 120
    or-int/lit8 p2, p2, 0x1

    .line 121
    .line 122
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 123
    .line 124
    .line 125
    move-result p2

    .line 126
    iget-boolean p0, p0, La71/e0;->e:Z

    .line 127
    .line 128
    invoke-static {p0, v0, p1, p2}, Ljp/ub;->b(ZLay0/n;Ll2/o;I)V

    .line 129
    .line 130
    .line 131
    goto :goto_0

    .line 132
    :pswitch_4
    iget-object v0, p0, La71/e0;->g:Ljava/lang/Object;

    .line 133
    .line 134
    check-cast v0, Lay0/k;

    .line 135
    .line 136
    check-cast p1, Ll2/o;

    .line 137
    .line 138
    check-cast p2, Ljava/lang/Integer;

    .line 139
    .line 140
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 141
    .line 142
    .line 143
    iget p2, p0, La71/e0;->f:I

    .line 144
    .line 145
    or-int/lit8 p2, p2, 0x1

    .line 146
    .line 147
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 148
    .line 149
    .line 150
    move-result p2

    .line 151
    iget-boolean p0, p0, La71/e0;->e:Z

    .line 152
    .line 153
    invoke-static {p0, v0, p1, p2}, Lal/a;->k(ZLay0/k;Ll2/o;I)V

    .line 154
    .line 155
    .line 156
    goto :goto_0

    .line 157
    :pswitch_5
    iget-object v0, p0, La71/e0;->g:Ljava/lang/Object;

    .line 158
    .line 159
    check-cast v0, Lh71/a;

    .line 160
    .line 161
    check-cast p1, Ll2/o;

    .line 162
    .line 163
    check-cast p2, Ljava/lang/Integer;

    .line 164
    .line 165
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 166
    .line 167
    .line 168
    iget p2, p0, La71/e0;->f:I

    .line 169
    .line 170
    or-int/lit8 p2, p2, 0x1

    .line 171
    .line 172
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 173
    .line 174
    .line 175
    move-result p2

    .line 176
    iget-boolean p0, p0, La71/e0;->e:Z

    .line 177
    .line 178
    invoke-static {p0, v0, p1, p2}, La71/s0;->f(ZLh71/a;Ll2/o;I)V

    .line 179
    .line 180
    .line 181
    goto/16 :goto_0

    .line 182
    .line 183
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
