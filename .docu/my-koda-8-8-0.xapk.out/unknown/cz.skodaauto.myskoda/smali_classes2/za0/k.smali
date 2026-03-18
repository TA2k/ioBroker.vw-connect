.class public final synthetic Lza0/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:J

.field public final synthetic e:Lza0/q;

.field public final synthetic f:Lya0/a;

.field public final synthetic g:Lyl/l;


# direct methods
.method public synthetic constructor <init>(JLza0/q;Lya0/a;Lyl/l;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lza0/k;->d:J

    .line 5
    .line 6
    iput-object p3, p0, Lza0/k;->e:Lza0/q;

    .line 7
    .line 8
    iput-object p4, p0, Lza0/k;->f:Lya0/a;

    .line 9
    .line 10
    iput-object p5, p0, Lza0/k;->g:Lyl/l;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    check-cast p1, Lf7/s;

    .line 2
    .line 3
    check-cast p2, Ll2/o;

    .line 4
    .line 5
    check-cast p3, Ljava/lang/Integer;

    .line 6
    .line 7
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    const-string p3, "$this$Row"

    .line 11
    .line 12
    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    sget-object p1, Ly6/o;->a:Ly6/o;

    .line 16
    .line 17
    invoke-static {p1}, Lkp/p7;->b(Ly6/q;)Ly6/q;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    sget p3, Lza0/q;->k:F

    .line 22
    .line 23
    const/4 v0, 0x2

    .line 24
    int-to-float v0, v0

    .line 25
    div-float/2addr p3, v0

    .line 26
    const/4 v0, 0x0

    .line 27
    const/16 v1, 0xe

    .line 28
    .line 29
    invoke-static {p1, p3, v0, v0, v1}, Lkp/n7;->c(Ly6/q;FFFI)Ly6/q;

    .line 30
    .line 31
    .line 32
    move-result-object v3

    .line 33
    sget-wide v0, Lza0/q;->h:J

    .line 34
    .line 35
    iget-wide v4, p0, Lza0/k;->d:J

    .line 36
    .line 37
    invoke-static {v4, v5, v0, v1}, Lt4/h;->a(JJ)Z

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    iget-object v2, p0, Lza0/k;->e:Lza0/q;

    .line 42
    .line 43
    move-wide v0, v4

    .line 44
    iget-object v4, p0, Lza0/k;->f:Lya0/a;

    .line 45
    .line 46
    const/4 p3, 0x0

    .line 47
    if-eqz p1, :cond_0

    .line 48
    .line 49
    check-cast p2, Ll2/t;

    .line 50
    .line 51
    const p0, 0x1363d83a

    .line 52
    .line 53
    .line 54
    invoke-virtual {p2, p0}, Ll2/t;->Y(I)V

    .line 55
    .line 56
    .line 57
    const/16 p0, 0x200

    .line 58
    .line 59
    invoke-virtual {v2, v3, v4, p2, p0}, Lza0/q;->l(Ly6/q;Lya0/a;Ll2/o;I)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {p2, p3}, Ll2/t;->q(Z)V

    .line 63
    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_0
    sget-wide v5, Lza0/q;->i:J

    .line 67
    .line 68
    invoke-static {v0, v1, v5, v6}, Lt4/h;->a(JJ)Z

    .line 69
    .line 70
    .line 71
    move-result p1

    .line 72
    iget-object v5, p0, Lza0/k;->g:Lyl/l;

    .line 73
    .line 74
    if-eqz p1, :cond_1

    .line 75
    .line 76
    move-object v6, p2

    .line 77
    check-cast v6, Ll2/t;

    .line 78
    .line 79
    const p0, 0x1363e113

    .line 80
    .line 81
    .line 82
    invoke-virtual {v6, p0}, Ll2/t;->Y(I)V

    .line 83
    .line 84
    .line 85
    const/16 v7, 0x1000

    .line 86
    .line 87
    invoke-virtual/range {v2 .. v7}, Lza0/q;->o(Ly6/q;Lya0/a;Lyl/l;Ll2/o;I)V

    .line 88
    .line 89
    .line 90
    invoke-virtual {v6, p3}, Ll2/t;->q(Z)V

    .line 91
    .line 92
    .line 93
    goto :goto_0

    .line 94
    :cond_1
    sget-wide p0, Lza0/q;->g:J

    .line 95
    .line 96
    invoke-static {v0, v1, p0, p1}, Lt4/h;->a(JJ)Z

    .line 97
    .line 98
    .line 99
    move-result p0

    .line 100
    if-eqz p0, :cond_2

    .line 101
    .line 102
    move-object v6, p2

    .line 103
    check-cast v6, Ll2/t;

    .line 104
    .line 105
    const p0, 0x1363ed14

    .line 106
    .line 107
    .line 108
    invoke-virtual {v6, p0}, Ll2/t;->Y(I)V

    .line 109
    .line 110
    .line 111
    const/16 v7, 0x1000

    .line 112
    .line 113
    invoke-virtual/range {v2 .. v7}, Lza0/q;->j(Ly6/q;Lya0/a;Lyl/l;Ll2/o;I)V

    .line 114
    .line 115
    .line 116
    invoke-virtual {v6, p3}, Ll2/t;->q(Z)V

    .line 117
    .line 118
    .line 119
    goto :goto_0

    .line 120
    :cond_2
    sget-wide p0, Lza0/q;->j:J

    .line 121
    .line 122
    invoke-static {v0, v1, p0, p1}, Lt4/h;->a(JJ)Z

    .line 123
    .line 124
    .line 125
    move-result p0

    .line 126
    if-eqz p0, :cond_3

    .line 127
    .line 128
    move-object v6, p2

    .line 129
    check-cast v6, Ll2/t;

    .line 130
    .line 131
    const p0, 0x1363f8f7

    .line 132
    .line 133
    .line 134
    invoke-virtual {v6, p0}, Ll2/t;->Y(I)V

    .line 135
    .line 136
    .line 137
    const/16 v7, 0x1000

    .line 138
    .line 139
    invoke-virtual/range {v2 .. v7}, Lza0/q;->f(Ly6/q;Lya0/a;Lyl/l;Ll2/o;I)V

    .line 140
    .line 141
    .line 142
    invoke-virtual {v6, p3}, Ll2/t;->q(Z)V

    .line 143
    .line 144
    .line 145
    goto :goto_0

    .line 146
    :cond_3
    check-cast p2, Ll2/t;

    .line 147
    .line 148
    const p0, 0x58c8934f

    .line 149
    .line 150
    .line 151
    invoke-virtual {p2, p0}, Ll2/t;->Y(I)V

    .line 152
    .line 153
    .line 154
    invoke-virtual {p2, p3}, Ll2/t;->q(Z)V

    .line 155
    .line 156
    .line 157
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 158
    .line 159
    return-object p0
.end method
