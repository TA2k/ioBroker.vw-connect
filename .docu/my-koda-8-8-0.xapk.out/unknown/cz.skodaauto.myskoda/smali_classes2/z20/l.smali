.class public final Lz20/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# static fields
.field public static final e:Lz20/l;

.field public static final f:Lz20/l;

.field public static final g:Lz20/l;


# instance fields
.field public final synthetic d:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lz20/l;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lz20/l;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lz20/l;->e:Lz20/l;

    .line 8
    .line 9
    new-instance v0, Lz20/l;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-direct {v0, v1}, Lz20/l;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lz20/l;->f:Lz20/l;

    .line 16
    .line 17
    new-instance v0, Lz20/l;

    .line 18
    .line 19
    const/4 v1, 0x2

    .line 20
    invoke-direct {v0, v1}, Lz20/l;-><init>(I)V

    .line 21
    .line 22
    .line 23
    sput-object v0, Lz20/l;->g:Lz20/l;

    .line 24
    .line 25
    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lz20/l;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget p0, p0, Lz20/l;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lz4/e;

    .line 7
    .line 8
    const-string p0, "$this$constrainAs"

    .line 9
    .line 10
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p1, Lz4/e;->c:Lz4/f;

    .line 14
    .line 15
    iget-object v0, p0, Lz4/f;->d:Lz4/h;

    .line 16
    .line 17
    iget-object v1, p0, Lz4/f;->e:Lz4/g;

    .line 18
    .line 19
    iget-object v2, p0, Lz4/f;->f:Lz4/h;

    .line 20
    .line 21
    iget-object p0, p0, Lz4/f;->g:Lz4/g;

    .line 22
    .line 23
    const/4 v3, 0x0

    .line 24
    int-to-float v3, v3

    .line 25
    iget-object v4, p1, Lz4/e;->d:Ly7/k;

    .line 26
    .line 27
    invoke-virtual {v4, v0, v3, v3}, Ly7/k;->a(Lz4/h;FF)V

    .line 28
    .line 29
    .line 30
    iget-object v0, p1, Lz4/e;->f:Ly7/k;

    .line 31
    .line 32
    invoke-virtual {v0, v2, v3, v3}, Ly7/k;->a(Lz4/h;FF)V

    .line 33
    .line 34
    .line 35
    iget-object v0, p1, Lz4/e;->b:Ld5/f;

    .line 36
    .line 37
    new-instance v2, Ld5/e;

    .line 38
    .line 39
    const/high16 v4, 0x3f000000    # 0.5f

    .line 40
    .line 41
    invoke-direct {v2, v4}, Ld5/e;-><init>(F)V

    .line 42
    .line 43
    .line 44
    const-string v5, "hRtlBias"

    .line 45
    .line 46
    invoke-virtual {v0, v5, v2}, Ld5/b;->D(Ljava/lang/String;Ld5/c;)V

    .line 47
    .line 48
    .line 49
    iget-object v2, p1, Lz4/e;->e:Ly41/a;

    .line 50
    .line 51
    invoke-virtual {v2, v1, v3, v3}, Ly41/a;->b(Lz4/g;FF)V

    .line 52
    .line 53
    .line 54
    iget-object p1, p1, Lz4/e;->g:Ly41/a;

    .line 55
    .line 56
    invoke-virtual {p1, p0, v3, v3}, Ly41/a;->b(Lz4/g;FF)V

    .line 57
    .line 58
    .line 59
    new-instance p0, Ld5/e;

    .line 60
    .line 61
    invoke-direct {p0, v4}, Ld5/e;-><init>(F)V

    .line 62
    .line 63
    .line 64
    const-string p1, "vBias"

    .line 65
    .line 66
    invoke-virtual {v0, p1, p0}, Ld5/b;->D(Ljava/lang/String;Ld5/c;)V

    .line 67
    .line 68
    .line 69
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 70
    .line 71
    return-object p0

    .line 72
    :pswitch_0
    check-cast p1, Lz4/e;

    .line 73
    .line 74
    const-string p0, "$this$constrainAs"

    .line 75
    .line 76
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    iget-object p0, p1, Lz4/e;->c:Lz4/f;

    .line 80
    .line 81
    iget-object v0, p0, Lz4/f;->d:Lz4/h;

    .line 82
    .line 83
    iget-object v1, p0, Lz4/f;->e:Lz4/g;

    .line 84
    .line 85
    iget-object v2, p0, Lz4/f;->f:Lz4/h;

    .line 86
    .line 87
    iget-object p0, p0, Lz4/f;->g:Lz4/g;

    .line 88
    .line 89
    const/4 v3, 0x0

    .line 90
    int-to-float v3, v3

    .line 91
    iget-object v4, p1, Lz4/e;->d:Ly7/k;

    .line 92
    .line 93
    invoke-virtual {v4, v0, v3, v3}, Ly7/k;->a(Lz4/h;FF)V

    .line 94
    .line 95
    .line 96
    iget-object v0, p1, Lz4/e;->f:Ly7/k;

    .line 97
    .line 98
    invoke-virtual {v0, v2, v3, v3}, Ly7/k;->a(Lz4/h;FF)V

    .line 99
    .line 100
    .line 101
    iget-object v0, p1, Lz4/e;->b:Ld5/f;

    .line 102
    .line 103
    new-instance v2, Ld5/e;

    .line 104
    .line 105
    const/high16 v4, 0x3f000000    # 0.5f

    .line 106
    .line 107
    invoke-direct {v2, v4}, Ld5/e;-><init>(F)V

    .line 108
    .line 109
    .line 110
    const-string v5, "hRtlBias"

    .line 111
    .line 112
    invoke-virtual {v0, v5, v2}, Ld5/b;->D(Ljava/lang/String;Ld5/c;)V

    .line 113
    .line 114
    .line 115
    iget-object v2, p1, Lz4/e;->e:Ly41/a;

    .line 116
    .line 117
    invoke-virtual {v2, v1, v3, v3}, Ly41/a;->b(Lz4/g;FF)V

    .line 118
    .line 119
    .line 120
    iget-object p1, p1, Lz4/e;->g:Ly41/a;

    .line 121
    .line 122
    invoke-virtual {p1, p0, v3, v3}, Ly41/a;->b(Lz4/g;FF)V

    .line 123
    .line 124
    .line 125
    new-instance p0, Ld5/e;

    .line 126
    .line 127
    invoke-direct {p0, v4}, Ld5/e;-><init>(F)V

    .line 128
    .line 129
    .line 130
    const-string p1, "vBias"

    .line 131
    .line 132
    invoke-virtual {v0, p1, p0}, Ld5/b;->D(Ljava/lang/String;Ld5/c;)V

    .line 133
    .line 134
    .line 135
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 136
    .line 137
    return-object p0

    .line 138
    :pswitch_1
    check-cast p1, Lz4/e;

    .line 139
    .line 140
    const-string p0, "$this$constrainAs"

    .line 141
    .line 142
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 143
    .line 144
    .line 145
    iget-object p0, p1, Lz4/e;->e:Ly41/a;

    .line 146
    .line 147
    iget-object v0, p1, Lz4/e;->c:Lz4/f;

    .line 148
    .line 149
    iget-object v1, v0, Lz4/f;->e:Lz4/g;

    .line 150
    .line 151
    const/4 v2, 0x0

    .line 152
    const/4 v3, 0x6

    .line 153
    invoke-static {p0, v1, v2, v3}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 154
    .line 155
    .line 156
    iget-object p0, p1, Lz4/e;->d:Ly7/k;

    .line 157
    .line 158
    iget-object p1, v0, Lz4/f;->d:Lz4/h;

    .line 159
    .line 160
    invoke-static {p0, p1, v2, v3}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 161
    .line 162
    .line 163
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 164
    .line 165
    return-object p0

    .line 166
    nop

    .line 167
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
