.class public Lwz0/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lvz0/r;
.implements Ltz0/d;
.implements Ltz0/b;


# instance fields
.field public final a:Ljava/util/ArrayList;

.field public final b:Lvz0/d;

.field public final c:Lay0/k;

.field public final d:Lvz0/k;

.field public e:Ljava/lang/String;

.field public f:Ljava/lang/String;

.field public final synthetic g:I

.field public h:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lvz0/d;Lay0/k;C)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    new-instance p3, Ljava/util/ArrayList;

    invoke-direct {p3}, Ljava/util/ArrayList;-><init>()V

    iput-object p3, p0, Lwz0/s;->a:Ljava/util/ArrayList;

    .line 3
    iput-object p1, p0, Lwz0/s;->b:Lvz0/d;

    .line 4
    iput-object p2, p0, Lwz0/s;->c:Lay0/k;

    .line 5
    iget-object p1, p1, Lvz0/d;->a:Lvz0/k;

    .line 6
    iput-object p1, p0, Lwz0/s;->d:Lvz0/k;

    return-void
.end method

.method public constructor <init>(Lvz0/d;Lay0/k;I)V
    .locals 0

    iput p3, p0, Lwz0/s;->g:I

    packed-switch p3, :pswitch_data_0

    const-string p3, "json"

    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p3, "nodeConsumer"

    invoke-static {p2, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 p3, 0x0

    .line 7
    invoke-direct {p0, p1, p2, p3}, Lwz0/s;-><init>(Lvz0/d;Lay0/k;C)V

    .line 8
    const-string p1, "primitive"

    .line 9
    iget-object p0, p0, Lwz0/s;->a:Ljava/util/ArrayList;

    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-void

    .line 10
    :pswitch_0
    const-string p3, "json"

    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p3, "nodeConsumer"

    invoke-static {p2, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 p3, 0x0

    .line 11
    invoke-direct {p0, p1, p2, p3}, Lwz0/s;-><init>(Lvz0/d;Lay0/k;C)V

    .line 12
    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Lwz0/s;->h:Ljava/lang/Object;

    return-void

    .line 13
    :pswitch_1
    const-string p3, "json"

    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p3, "nodeConsumer"

    invoke-static {p2, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 p3, 0x0

    .line 14
    invoke-direct {p0, p1, p2, p3}, Lwz0/s;-><init>(Lvz0/d;Lay0/k;C)V

    .line 15
    new-instance p1, Ljava/util/LinkedHashMap;

    invoke-direct {p1}, Ljava/util/LinkedHashMap;-><init>()V

    iput-object p1, p0, Lwz0/s;->h:Ljava/lang/Object;

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V
    .locals 1

    .line 1
    iget v0, p0, Lwz0/s;->g:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, p1, p2, p3, p4}, Lwz0/s;->F(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    return-void

    .line 10
    :pswitch_0
    const-string v0, "descriptor"

    .line 11
    .line 12
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    const-string v0, "serializer"

    .line 16
    .line 17
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    if-nez p4, :cond_0

    .line 21
    .line 22
    iget-object v0, p0, Lwz0/s;->d:Lvz0/k;

    .line 23
    .line 24
    iget-boolean v0, v0, Lvz0/k;->e:Z

    .line 25
    .line 26
    if-eqz v0, :cond_1

    .line 27
    .line 28
    :cond_0
    invoke-virtual {p0, p1, p2, p3, p4}, Lwz0/s;->F(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    :cond_1
    return-void

    .line 32
    nop

    .line 33
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public final B(I)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lwz0/s;->L()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Ljava/lang/String;

    .line 6
    .line 7
    const-string v1, "tag"

    .line 8
    .line 9
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    invoke-static {p1}, Lvz0/o;->a(Ljava/lang/Number;)Lvz0/e0;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    invoke-virtual {p0, v0, p1}, Lwz0/s;->M(Ljava/lang/String;Lvz0/n;)V

    .line 21
    .line 22
    .line 23
    return-void
.end method

.method public final C(Lsz0/g;ID)V
    .locals 1

    .line 1
    const-string v0, "descriptor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, p1, p2}, Lwz0/s;->K(Lsz0/g;I)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    invoke-virtual {p0, p1, p3, p4}, Lwz0/s;->G(Ljava/lang/Object;D)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public final D(Lqz0/a;Ljava/lang/Object;)V
    .locals 4

    .line 1
    const-string v0, "serializer"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lwz0/s;->a:Ljava/util/ArrayList;

    .line 7
    .line 8
    invoke-static {v0}, Lmx0/q;->U(Ljava/util/List;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iget-object v1, p0, Lwz0/s;->b:Lvz0/d;

    .line 13
    .line 14
    if-nez v0, :cond_1

    .line 15
    .line 16
    invoke-interface {p1}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    iget-object v2, v1, Lvz0/d;->b:Lwq/f;

    .line 21
    .line 22
    invoke-static {v0, v2}, Lwz0/p;->f(Lsz0/g;Lwq/f;)Lsz0/g;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    invoke-interface {v0}, Lsz0/g;->getKind()Lkp/y8;

    .line 27
    .line 28
    .line 29
    move-result-object v2

    .line 30
    instance-of v2, v2, Lsz0/f;

    .line 31
    .line 32
    if-nez v2, :cond_0

    .line 33
    .line 34
    invoke-interface {v0}, Lsz0/g;->getKind()Lkp/y8;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    sget-object v2, Lsz0/j;->b:Lsz0/j;

    .line 39
    .line 40
    if-ne v0, v2, :cond_1

    .line 41
    .line 42
    :cond_0
    new-instance v0, Lwz0/s;

    .line 43
    .line 44
    iget-object p0, p0, Lwz0/s;->c:Lay0/k;

    .line 45
    .line 46
    const/4 v2, 0x0

    .line 47
    invoke-direct {v0, v1, p0, v2}, Lwz0/s;-><init>(Lvz0/d;Lay0/k;I)V

    .line 48
    .line 49
    .line 50
    invoke-virtual {v0, p1, p2}, Lwz0/s;->D(Lqz0/a;Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    return-void

    .line 54
    :cond_1
    iget-object v0, v1, Lvz0/d;->a:Lvz0/k;

    .line 55
    .line 56
    instance-of v2, p1, Luz0/b;

    .line 57
    .line 58
    if-eqz v2, :cond_2

    .line 59
    .line 60
    iget-object v0, v0, Lvz0/k;->j:Lvz0/a;

    .line 61
    .line 62
    sget-object v3, Lvz0/a;->d:Lvz0/a;

    .line 63
    .line 64
    if-eq v0, v3, :cond_6

    .line 65
    .line 66
    goto :goto_0

    .line 67
    :cond_2
    iget-object v0, v0, Lvz0/k;->j:Lvz0/a;

    .line 68
    .line 69
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 70
    .line 71
    .line 72
    move-result v0

    .line 73
    if-eqz v0, :cond_6

    .line 74
    .line 75
    const/4 v3, 0x1

    .line 76
    if-eq v0, v3, :cond_4

    .line 77
    .line 78
    const/4 v1, 0x2

    .line 79
    if-ne v0, v1, :cond_3

    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_3
    new-instance p0, La8/r0;

    .line 83
    .line 84
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 85
    .line 86
    .line 87
    throw p0

    .line 88
    :cond_4
    invoke-interface {p1}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 89
    .line 90
    .line 91
    move-result-object v0

    .line 92
    invoke-interface {v0}, Lsz0/g;->getKind()Lkp/y8;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    sget-object v3, Lsz0/k;->b:Lsz0/k;

    .line 97
    .line 98
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 99
    .line 100
    .line 101
    move-result v3

    .line 102
    if-nez v3, :cond_5

    .line 103
    .line 104
    sget-object v3, Lsz0/k;->e:Lsz0/k;

    .line 105
    .line 106
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 107
    .line 108
    .line 109
    move-result v0

    .line 110
    if-eqz v0, :cond_6

    .line 111
    .line 112
    :cond_5
    :goto_0
    invoke-interface {p1}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 113
    .line 114
    .line 115
    move-result-object v0

    .line 116
    invoke-static {v0, v1}, Lwz0/p;->i(Lsz0/g;Lvz0/d;)Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object v0

    .line 120
    goto :goto_2

    .line 121
    :cond_6
    :goto_1
    const/4 v0, 0x0

    .line 122
    :goto_2
    if-eqz v2, :cond_9

    .line 123
    .line 124
    move-object v1, p1

    .line 125
    check-cast v1, Luz0/b;

    .line 126
    .line 127
    if-eqz p2, :cond_8

    .line 128
    .line 129
    invoke-static {v1, p0, p2}, Ljp/lg;->c(Luz0/b;Ltz0/d;Ljava/lang/Object;)Lqz0/a;

    .line 130
    .line 131
    .line 132
    move-result-object v1

    .line 133
    if-eqz v0, :cond_7

    .line 134
    .line 135
    invoke-static {p1, v1, v0}, Lwz0/p;->e(Lqz0/a;Lqz0/a;Ljava/lang/String;)V

    .line 136
    .line 137
    .line 138
    invoke-interface {v1}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 139
    .line 140
    .line 141
    move-result-object p1

    .line 142
    invoke-interface {p1}, Lsz0/g;->getKind()Lkp/y8;

    .line 143
    .line 144
    .line 145
    move-result-object p1

    .line 146
    invoke-static {p1}, Lwz0/p;->h(Lkp/y8;)V

    .line 147
    .line 148
    .line 149
    :cond_7
    move-object p1, v1

    .line 150
    goto :goto_3

    .line 151
    :cond_8
    new-instance p0, Ljava/lang/StringBuilder;

    .line 152
    .line 153
    const-string p1, "Value for serializer "

    .line 154
    .line 155
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 156
    .line 157
    .line 158
    invoke-interface {v1}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 159
    .line 160
    .line 161
    move-result-object p1

    .line 162
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 163
    .line 164
    .line 165
    const-string p1, " should always be non-null. Please report issue to the kotlinx.serialization tracker."

    .line 166
    .line 167
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 168
    .line 169
    .line 170
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 171
    .line 172
    .line 173
    move-result-object p0

    .line 174
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 175
    .line 176
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 177
    .line 178
    .line 179
    move-result-object p0

    .line 180
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 181
    .line 182
    .line 183
    throw p1

    .line 184
    :cond_9
    :goto_3
    if-eqz v0, :cond_a

    .line 185
    .line 186
    invoke-interface {p1}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 187
    .line 188
    .line 189
    move-result-object v1

    .line 190
    invoke-interface {v1}, Lsz0/g;->h()Ljava/lang/String;

    .line 191
    .line 192
    .line 193
    move-result-object v1

    .line 194
    iput-object v0, p0, Lwz0/s;->e:Ljava/lang/String;

    .line 195
    .line 196
    iput-object v1, p0, Lwz0/s;->f:Ljava/lang/String;

    .line 197
    .line 198
    :cond_a
    invoke-interface {p1, p0, p2}, Lqz0/a;->serialize(Ltz0/d;Ljava/lang/Object;)V

    .line 199
    .line 200
    .line 201
    return-void
.end method

.method public final E(Ljava/lang/String;)V
    .locals 2

    .line 1
    const-string v0, "value"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lwz0/s;->L()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    check-cast v0, Ljava/lang/String;

    .line 11
    .line 12
    const-string v1, "tag"

    .line 13
    .line 14
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-static {p1}, Lvz0/o;->b(Ljava/lang/String;)Lvz0/e0;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    invoke-virtual {p0, v0, p1}, Lwz0/s;->M(Ljava/lang/String;Lvz0/n;)V

    .line 22
    .line 23
    .line 24
    return-void
.end method

.method public final F(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V
    .locals 1

    .line 1
    const-string v0, "descriptor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "serializer"

    .line 7
    .line 8
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0, p1, p2}, Lwz0/s;->K(Lsz0/g;I)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    iget-object p2, p0, Lwz0/s;->a:Ljava/util/ArrayList;

    .line 16
    .line 17
    invoke-virtual {p2, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    invoke-super {p0, p3, p4}, Ltz0/d;->g(Lqz0/a;Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    return-void
.end method

.method public final G(Ljava/lang/Object;D)V
    .locals 4

    .line 1
    check-cast p1, Ljava/lang/String;

    .line 2
    .line 3
    const-string v0, "tag"

    .line 4
    .line 5
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-static {p2, p3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    invoke-static {v0}, Lvz0/o;->a(Ljava/lang/Number;)Lvz0/e0;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    invoke-virtual {p0, p1, v0}, Lwz0/s;->M(Ljava/lang/String;Lvz0/n;)V

    .line 17
    .line 18
    .line 19
    iget-object v0, p0, Lwz0/s;->d:Lvz0/k;

    .line 20
    .line 21
    iget-boolean v0, v0, Lvz0/k;->h:Z

    .line 22
    .line 23
    if-nez v0, :cond_1

    .line 24
    .line 25
    invoke-static {p2, p3}, Ljava/lang/Math;->abs(D)D

    .line 26
    .line 27
    .line 28
    move-result-wide v0

    .line 29
    const-wide v2, 0x7fefffffffffffffL    # Double.MAX_VALUE

    .line 30
    .line 31
    .line 32
    .line 33
    .line 34
    cmpg-double v0, v0, v2

    .line 35
    .line 36
    if-gtz v0, :cond_0

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_0
    invoke-static {p2, p3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 40
    .line 41
    .line 42
    move-result-object p2

    .line 43
    invoke-virtual {p0}, Lwz0/s;->J()Lvz0/n;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    const-string p3, "output"

    .line 52
    .line 53
    invoke-static {p0, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    new-instance p3, Lwz0/l;

    .line 57
    .line 58
    invoke-static {p2, p1, p0}, Lwz0/p;->t(Ljava/lang/Number;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    const/4 p1, 0x1

    .line 63
    invoke-direct {p3, p0, p1}, Lwz0/l;-><init>(Ljava/lang/String;I)V

    .line 64
    .line 65
    .line 66
    throw p3

    .line 67
    :cond_1
    :goto_0
    return-void
.end method

.method public final H(Ljava/lang/Object;F)V
    .locals 2

    .line 1
    check-cast p1, Ljava/lang/String;

    .line 2
    .line 3
    const-string v0, "tag"

    .line 4
    .line 5
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-static {p2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    invoke-static {v0}, Lvz0/o;->a(Ljava/lang/Number;)Lvz0/e0;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    invoke-virtual {p0, p1, v0}, Lwz0/s;->M(Ljava/lang/String;Lvz0/n;)V

    .line 17
    .line 18
    .line 19
    iget-object v0, p0, Lwz0/s;->d:Lvz0/k;

    .line 20
    .line 21
    iget-boolean v0, v0, Lvz0/k;->h:Z

    .line 22
    .line 23
    if-nez v0, :cond_1

    .line 24
    .line 25
    invoke-static {p2}, Ljava/lang/Math;->abs(F)F

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    const v1, 0x7f7fffff    # Float.MAX_VALUE

    .line 30
    .line 31
    .line 32
    cmpg-float v0, v0, v1

    .line 33
    .line 34
    if-gtz v0, :cond_0

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    invoke-static {p2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 38
    .line 39
    .line 40
    move-result-object p2

    .line 41
    invoke-virtual {p0}, Lwz0/s;->J()Lvz0/n;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    const-string v0, "output"

    .line 50
    .line 51
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    new-instance v0, Lwz0/l;

    .line 55
    .line 56
    invoke-static {p2, p1, p0}, Lwz0/p;->t(Ljava/lang/Number;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    const/4 p1, 0x1

    .line 61
    invoke-direct {v0, p0, p1}, Lwz0/l;-><init>(Ljava/lang/String;I)V

    .line 62
    .line 63
    .line 64
    throw v0

    .line 65
    :cond_1
    :goto_0
    return-void
.end method

.method public final I(Ljava/lang/Object;Lsz0/g;)Ltz0/d;
    .locals 1

    .line 1
    check-cast p1, Ljava/lang/String;

    .line 2
    .line 3
    const-string v0, "tag"

    .line 4
    .line 5
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string v0, "inlineDescriptor"

    .line 9
    .line 10
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    invoke-static {p2}, Lwz0/c0;->a(Lsz0/g;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    new-instance p2, Lwz0/b;

    .line 20
    .line 21
    invoke-direct {p2, p0, p1}, Lwz0/b;-><init>(Lwz0/s;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    return-object p2

    .line 25
    :cond_0
    invoke-interface {p2}, Lsz0/g;->isInline()Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-eqz v0, :cond_1

    .line 30
    .line 31
    sget-object v0, Lvz0/o;->a:Luz0/f0;

    .line 32
    .line 33
    invoke-virtual {p2, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    if-eqz v0, :cond_1

    .line 38
    .line 39
    new-instance v0, Lwz0/b;

    .line 40
    .line 41
    invoke-direct {v0, p0, p1, p2}, Lwz0/b;-><init>(Lwz0/s;Ljava/lang/String;Lsz0/g;)V

    .line 42
    .line 43
    .line 44
    return-object v0

    .line 45
    :cond_1
    iget-object p2, p0, Lwz0/s;->a:Ljava/util/ArrayList;

    .line 46
    .line 47
    invoke-virtual {p2, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    return-object p0
.end method

.method public J()Lvz0/n;
    .locals 1

    .line 1
    iget v0, p0, Lwz0/s;->g:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lvz0/f;

    .line 7
    .line 8
    iget-object p0, p0, Lwz0/s;->h:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Ljava/util/ArrayList;

    .line 11
    .line 12
    invoke-direct {v0, p0}, Lvz0/f;-><init>(Ljava/util/List;)V

    .line 13
    .line 14
    .line 15
    return-object v0

    .line 16
    :pswitch_0
    new-instance v0, Lvz0/a0;

    .line 17
    .line 18
    iget-object p0, p0, Lwz0/s;->h:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Ljava/util/LinkedHashMap;

    .line 21
    .line 22
    invoke-direct {v0, p0}, Lvz0/a0;-><init>(Ljava/util/Map;)V

    .line 23
    .line 24
    .line 25
    return-object v0

    .line 26
    :pswitch_1
    iget-object p0, p0, Lwz0/s;->h:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast p0, Lvz0/n;

    .line 29
    .line 30
    if-eqz p0, :cond_0

    .line 31
    .line 32
    return-object p0

    .line 33
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 34
    .line 35
    const-string v0, "Primitive element has not been recorded. Is call to .encodeXxx is missing in serializer?"

    .line 36
    .line 37
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    throw p0

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final K(Lsz0/g;I)Ljava/lang/String;
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget v0, p0, Lwz0/s;->g:I

    .line 7
    .line 8
    packed-switch v0, :pswitch_data_0

    .line 9
    .line 10
    .line 11
    const-string v0, "descriptor"

    .line 12
    .line 13
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "json"

    .line 17
    .line 18
    iget-object v1, p0, Lwz0/s;->b:Lvz0/d;

    .line 19
    .line 20
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    invoke-static {p1, v1}, Lwz0/p;->o(Lsz0/g;Lvz0/d;)V

    .line 24
    .line 25
    .line 26
    invoke-interface {p1, p2}, Lsz0/g;->e(I)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    goto :goto_0

    .line 31
    :pswitch_0
    const-string v0, "descriptor"

    .line 32
    .line 33
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    invoke-static {p2}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    :goto_0
    const-string p2, "nestedName"

    .line 41
    .line 42
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    iget-object p0, p0, Lwz0/s;->a:Ljava/util/ArrayList;

    .line 46
    .line 47
    invoke-static {p0}, Lmx0/q;->U(Ljava/util/List;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    check-cast p0, Ljava/lang/String;

    .line 52
    .line 53
    return-object p1

    .line 54
    nop

    .line 55
    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_0
    .end packed-switch
.end method

.method public final L()Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object p0, p0, Lwz0/s;->a:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-interface {p0}, Ljava/util/Collection;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    invoke-static {p0}, Ljp/k1;->h(Ljava/util/List;)I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0

    .line 18
    :cond_0
    new-instance p0, Lqz0/h;

    .line 19
    .line 20
    const-string v0, "No tag in stack for requested element"

    .line 21
    .line 22
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    throw p0
.end method

.method public M(Ljava/lang/String;Lvz0/n;)V
    .locals 1

    .line 1
    iget v0, p0, Lwz0/s;->g:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string v0, "key"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "element"

    .line 12
    .line 13
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-static {p1}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 17
    .line 18
    .line 19
    move-result p1

    .line 20
    iget-object p0, p0, Lwz0/s;->h:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast p0, Ljava/util/ArrayList;

    .line 23
    .line 24
    invoke-virtual {p0, p1, p2}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    return-void

    .line 28
    :pswitch_0
    const-string v0, "key"

    .line 29
    .line 30
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    const-string v0, "element"

    .line 34
    .line 35
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    iget-object p0, p0, Lwz0/s;->h:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast p0, Ljava/util/LinkedHashMap;

    .line 41
    .line 42
    invoke-interface {p0, p1, p2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    return-void

    .line 46
    :pswitch_1
    const-string v0, "key"

    .line 47
    .line 48
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    const-string v0, "element"

    .line 52
    .line 53
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    const-string v0, "primitive"

    .line 57
    .line 58
    if-ne p1, v0, :cond_1

    .line 59
    .line 60
    iget-object p1, p0, Lwz0/s;->h:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast p1, Lvz0/n;

    .line 63
    .line 64
    if-nez p1, :cond_0

    .line 65
    .line 66
    iput-object p2, p0, Lwz0/s;->h:Ljava/lang/Object;

    .line 67
    .line 68
    iget-object p0, p0, Lwz0/s;->c:Lay0/k;

    .line 69
    .line 70
    invoke-interface {p0, p2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    return-void

    .line 74
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 75
    .line 76
    const-string p1, "Primitive element was already recorded. Does call to .encodeXxx happen more than once?"

    .line 77
    .line 78
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    throw p0

    .line 82
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 83
    .line 84
    const-string p1, "This output can only consume primitives with \'primitive\' tag"

    .line 85
    .line 86
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    throw p0

    .line 90
    nop

    .line 91
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final a(Lsz0/g;)Ltz0/b;
    .locals 5

    .line 1
    const-string v0, "descriptor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lwz0/s;->a:Ljava/util/ArrayList;

    .line 7
    .line 8
    invoke-static {v0}, Lmx0/q;->U(Ljava/util/List;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    if-nez v0, :cond_0

    .line 13
    .line 14
    iget-object v0, p0, Lwz0/s;->c:Lay0/k;

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    new-instance v0, Lw81/c;

    .line 18
    .line 19
    const/16 v1, 0x14

    .line 20
    .line 21
    invoke-direct {v0, p0, v1}, Lw81/c;-><init>(Ljava/lang/Object;I)V

    .line 22
    .line 23
    .line 24
    :goto_0
    invoke-interface {p1}, Lsz0/g;->getKind()Lkp/y8;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    sget-object v2, Lsz0/k;->c:Lsz0/k;

    .line 29
    .line 30
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    iget-object v3, p0, Lwz0/s;->b:Lvz0/d;

    .line 35
    .line 36
    if-nez v2, :cond_6

    .line 37
    .line 38
    instance-of v2, v1, Lsz0/d;

    .line 39
    .line 40
    if-eqz v2, :cond_1

    .line 41
    .line 42
    goto :goto_2

    .line 43
    :cond_1
    sget-object v2, Lsz0/k;->d:Lsz0/k;

    .line 44
    .line 45
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v1

    .line 49
    if-eqz v1, :cond_5

    .line 50
    .line 51
    const/4 v1, 0x0

    .line 52
    invoke-interface {p1, v1}, Lsz0/g;->g(I)Lsz0/g;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    iget-object v2, v3, Lvz0/d;->b:Lwq/f;

    .line 57
    .line 58
    invoke-static {v1, v2}, Lwz0/p;->f(Lsz0/g;Lwq/f;)Lsz0/g;

    .line 59
    .line 60
    .line 61
    move-result-object v1

    .line 62
    invoke-interface {v1}, Lsz0/g;->getKind()Lkp/y8;

    .line 63
    .line 64
    .line 65
    move-result-object v2

    .line 66
    instance-of v4, v2, Lsz0/f;

    .line 67
    .line 68
    if-nez v4, :cond_4

    .line 69
    .line 70
    sget-object v4, Lsz0/j;->b:Lsz0/j;

    .line 71
    .line 72
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result v2

    .line 76
    if-eqz v2, :cond_2

    .line 77
    .line 78
    goto :goto_1

    .line 79
    :cond_2
    iget-object v2, v3, Lvz0/d;->a:Lvz0/k;

    .line 80
    .line 81
    iget-boolean v2, v2, Lvz0/k;->d:Z

    .line 82
    .line 83
    if-eqz v2, :cond_3

    .line 84
    .line 85
    new-instance v1, Lwz0/s;

    .line 86
    .line 87
    const/4 v2, 0x2

    .line 88
    invoke-direct {v1, v3, v0, v2}, Lwz0/s;-><init>(Lvz0/d;Lay0/k;I)V

    .line 89
    .line 90
    .line 91
    goto :goto_3

    .line 92
    :cond_3
    invoke-static {v1}, Lwz0/p;->b(Lsz0/g;)Lwz0/l;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    throw p0

    .line 97
    :cond_4
    :goto_1
    new-instance v1, Lwz0/w;

    .line 98
    .line 99
    const-string v2, "nodeConsumer"

    .line 100
    .line 101
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    const/4 v2, 0x1

    .line 105
    invoke-direct {v1, v3, v0, v2}, Lwz0/s;-><init>(Lvz0/d;Lay0/k;I)V

    .line 106
    .line 107
    .line 108
    const/4 v0, 0x1

    .line 109
    iput-boolean v0, v1, Lwz0/w;->j:Z

    .line 110
    .line 111
    goto :goto_3

    .line 112
    :cond_5
    new-instance v1, Lwz0/s;

    .line 113
    .line 114
    const/4 v2, 0x1

    .line 115
    invoke-direct {v1, v3, v0, v2}, Lwz0/s;-><init>(Lvz0/d;Lay0/k;I)V

    .line 116
    .line 117
    .line 118
    goto :goto_3

    .line 119
    :cond_6
    :goto_2
    new-instance v1, Lwz0/s;

    .line 120
    .line 121
    const/4 v2, 0x2

    .line 122
    invoke-direct {v1, v3, v0, v2}, Lwz0/s;-><init>(Lvz0/d;Lay0/k;I)V

    .line 123
    .line 124
    .line 125
    :goto_3
    iget-object v0, p0, Lwz0/s;->e:Ljava/lang/String;

    .line 126
    .line 127
    if-eqz v0, :cond_a

    .line 128
    .line 129
    instance-of v2, v1, Lwz0/w;

    .line 130
    .line 131
    if-eqz v2, :cond_8

    .line 132
    .line 133
    move-object v2, v1

    .line 134
    check-cast v2, Lwz0/w;

    .line 135
    .line 136
    const-string v3, "key"

    .line 137
    .line 138
    invoke-static {v0}, Lvz0/o;->b(Ljava/lang/String;)Lvz0/e0;

    .line 139
    .line 140
    .line 141
    move-result-object v0

    .line 142
    invoke-virtual {v2, v3, v0}, Lwz0/w;->M(Ljava/lang/String;Lvz0/n;)V

    .line 143
    .line 144
    .line 145
    iget-object v0, p0, Lwz0/s;->f:Ljava/lang/String;

    .line 146
    .line 147
    if-nez v0, :cond_7

    .line 148
    .line 149
    invoke-interface {p1}, Lsz0/g;->h()Ljava/lang/String;

    .line 150
    .line 151
    .line 152
    move-result-object v0

    .line 153
    :cond_7
    invoke-static {v0}, Lvz0/o;->b(Ljava/lang/String;)Lvz0/e0;

    .line 154
    .line 155
    .line 156
    move-result-object p1

    .line 157
    const-string v0, "value"

    .line 158
    .line 159
    invoke-virtual {v2, v0, p1}, Lwz0/w;->M(Ljava/lang/String;Lvz0/n;)V

    .line 160
    .line 161
    .line 162
    goto :goto_4

    .line 163
    :cond_8
    iget-object v2, p0, Lwz0/s;->f:Ljava/lang/String;

    .line 164
    .line 165
    if-nez v2, :cond_9

    .line 166
    .line 167
    invoke-interface {p1}, Lsz0/g;->h()Ljava/lang/String;

    .line 168
    .line 169
    .line 170
    move-result-object v2

    .line 171
    :cond_9
    invoke-static {v2}, Lvz0/o;->b(Ljava/lang/String;)Lvz0/e0;

    .line 172
    .line 173
    .line 174
    move-result-object p1

    .line 175
    invoke-virtual {v1, v0, p1}, Lwz0/s;->M(Ljava/lang/String;Lvz0/n;)V

    .line 176
    .line 177
    .line 178
    :goto_4
    const/4 p1, 0x0

    .line 179
    iput-object p1, p0, Lwz0/s;->e:Ljava/lang/String;

    .line 180
    .line 181
    iput-object p1, p0, Lwz0/s;->f:Ljava/lang/String;

    .line 182
    .line 183
    :cond_a
    return-object v1
.end method

.method public final b(Lsz0/g;)V
    .locals 1

    .line 1
    const-string v0, "descriptor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p1, p0, Lwz0/s;->a:Ljava/util/ArrayList;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/util/ArrayList;->isEmpty()Z

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    if-nez p1, :cond_0

    .line 13
    .line 14
    invoke-virtual {p0}, Lwz0/s;->L()Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    :cond_0
    iget-object p1, p0, Lwz0/s;->c:Lay0/k;

    .line 18
    .line 19
    invoke-virtual {p0}, Lwz0/s;->J()Lvz0/n;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    invoke-interface {p1, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    return-void
.end method

.method public final c()Lwq/f;
    .locals 0

    .line 1
    iget-object p0, p0, Lwz0/s;->b:Lvz0/d;

    .line 2
    .line 3
    iget-object p0, p0, Lvz0/d;->b:Lwq/f;

    .line 4
    .line 5
    return-object p0
.end method

.method public final d(D)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Lwz0/s;->L()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {p0, v0, p1, p2}, Lwz0/s;->G(Ljava/lang/Object;D)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final e(Lsz0/g;)Z
    .locals 1

    .line 1
    const-string v0, "descriptor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lwz0/s;->d:Lvz0/k;

    .line 7
    .line 8
    iget-boolean p0, p0, Lvz0/k;->a:Z

    .line 9
    .line 10
    return p0
.end method

.method public final f(B)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lwz0/s;->L()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Ljava/lang/String;

    .line 6
    .line 7
    const-string v1, "tag"

    .line 8
    .line 9
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-static {p1}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    invoke-static {p1}, Lvz0/o;->a(Ljava/lang/Number;)Lvz0/e0;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    invoke-virtual {p0, v0, p1}, Lwz0/s;->M(Ljava/lang/String;Lvz0/n;)V

    .line 21
    .line 22
    .line 23
    return-void
.end method

.method public final h(Luz0/f1;IC)V
    .locals 1

    .line 1
    const-string v0, "descriptor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, p1, p2}, Lwz0/s;->K(Lsz0/g;I)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    invoke-static {p3}, Ljava/lang/String;->valueOf(C)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p2

    .line 14
    invoke-static {p2}, Lvz0/o;->b(Ljava/lang/String;)Lvz0/e0;

    .line 15
    .line 16
    .line 17
    move-result-object p2

    .line 18
    invoke-virtual {p0, p1, p2}, Lwz0/s;->M(Ljava/lang/String;Lvz0/n;)V

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method public final i(Lsz0/g;I)V
    .locals 2

    .line 1
    const-string v0, "enumDescriptor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lwz0/s;->L()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    check-cast v0, Ljava/lang/String;

    .line 11
    .line 12
    const-string v1, "tag"

    .line 13
    .line 14
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-interface {p1, p2}, Lsz0/g;->e(I)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    invoke-static {p1}, Lvz0/o;->b(Ljava/lang/String;)Lvz0/e0;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    invoke-virtual {p0, v0, p1}, Lwz0/s;->M(Ljava/lang/String;Lvz0/n;)V

    .line 26
    .line 27
    .line 28
    return-void
.end method

.method public final j(Lsz0/g;)Ltz0/d;
    .locals 3

    .line 1
    const-string v0, "descriptor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lwz0/s;->a:Ljava/util/ArrayList;

    .line 7
    .line 8
    invoke-static {v0}, Lmx0/q;->U(Ljava/util/List;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    if-eqz v0, :cond_1

    .line 13
    .line 14
    iget-object v0, p0, Lwz0/s;->e:Ljava/lang/String;

    .line 15
    .line 16
    if-eqz v0, :cond_0

    .line 17
    .line 18
    invoke-interface {p1}, Lsz0/g;->h()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    iput-object v0, p0, Lwz0/s;->f:Ljava/lang/String;

    .line 23
    .line 24
    :cond_0
    invoke-virtual {p0}, Lwz0/s;->L()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    invoke-virtual {p0, v0, p1}, Lwz0/s;->I(Ljava/lang/Object;Lsz0/g;)Ltz0/d;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0

    .line 33
    :cond_1
    new-instance v0, Lwz0/s;

    .line 34
    .line 35
    iget-object v1, p0, Lwz0/s;->c:Lay0/k;

    .line 36
    .line 37
    const/4 v2, 0x0

    .line 38
    iget-object p0, p0, Lwz0/s;->b:Lvz0/d;

    .line 39
    .line 40
    invoke-direct {v0, p0, v1, v2}, Lwz0/s;-><init>(Lvz0/d;Lay0/k;I)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {v0, p1}, Lwz0/s;->j(Lsz0/g;)Ltz0/d;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    return-object p0
.end method

.method public final k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V
    .locals 1

    .line 1
    const-string v0, "descriptor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "serializer"

    .line 7
    .line 8
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0, p1, p2}, Lwz0/s;->K(Lsz0/g;I)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    iget-object p2, p0, Lwz0/s;->a:Ljava/util/ArrayList;

    .line 16
    .line 17
    invoke-virtual {p2, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    invoke-virtual {p0, p3, p4}, Lwz0/s;->D(Lqz0/a;Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    return-void
.end method

.method public final l(Luz0/f1;I)Ltz0/d;
    .locals 1

    .line 1
    const-string v0, "descriptor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, p1, p2}, Lwz0/s;->K(Lsz0/g;I)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    invoke-virtual {p1, p2}, Luz0/n0;->g(I)Lsz0/g;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    invoke-virtual {p0, v0, p1}, Lwz0/s;->I(Ljava/lang/Object;Lsz0/g;)Ltz0/d;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0
.end method

.method public final m(J)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lwz0/s;->L()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Ljava/lang/String;

    .line 6
    .line 7
    const-string v1, "tag"

    .line 8
    .line 9
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-static {p1, p2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    invoke-static {p1}, Lvz0/o;->a(Ljava/lang/Number;)Lvz0/e0;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    invoke-virtual {p0, v0, p1}, Lwz0/s;->M(Ljava/lang/String;Lvz0/n;)V

    .line 21
    .line 22
    .line 23
    return-void
.end method

.method public final n(IILsz0/g;)V
    .locals 1

    .line 1
    const-string v0, "descriptor"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, p3, p1}, Lwz0/s;->K(Lsz0/g;I)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 11
    .line 12
    .line 13
    move-result-object p2

    .line 14
    invoke-static {p2}, Lvz0/o;->a(Ljava/lang/Number;)Lvz0/e0;

    .line 15
    .line 16
    .line 17
    move-result-object p2

    .line 18
    invoke-virtual {p0, p1, p2}, Lwz0/s;->M(Ljava/lang/String;Lvz0/n;)V

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method public final o(Lsz0/g;IB)V
    .locals 1

    .line 1
    const-string v0, "descriptor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, p1, p2}, Lwz0/s;->K(Lsz0/g;I)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    invoke-static {p3}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 11
    .line 12
    .line 13
    move-result-object p2

    .line 14
    invoke-static {p2}, Lvz0/o;->a(Ljava/lang/Number;)Lvz0/e0;

    .line 15
    .line 16
    .line 17
    move-result-object p2

    .line 18
    invoke-virtual {p0, p1, p2}, Lwz0/s;->M(Ljava/lang/String;Lvz0/n;)V

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method public final p()V
    .locals 2

    .line 1
    iget-object v0, p0, Lwz0/s;->a:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-static {v0}, Lmx0/q;->U(Ljava/util/List;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Ljava/lang/String;

    .line 8
    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    iget-object p0, p0, Lwz0/s;->c:Lay0/k;

    .line 12
    .line 13
    sget-object v0, Lvz0/x;->INSTANCE:Lvz0/x;

    .line 14
    .line 15
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    sget-object v1, Lvz0/x;->INSTANCE:Lvz0/x;

    .line 20
    .line 21
    invoke-virtual {p0, v0, v1}, Lwz0/s;->M(Ljava/lang/String;Lvz0/n;)V

    .line 22
    .line 23
    .line 24
    return-void
.end method

.method public final q(Lsz0/g;I)Ltz0/b;
    .locals 0

    .line 1
    const-string p2, "descriptor"

    .line 2
    .line 3
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, p1}, Lwz0/s;->a(Lsz0/g;)Ltz0/b;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0
.end method

.method public final r(S)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lwz0/s;->L()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Ljava/lang/String;

    .line 6
    .line 7
    const-string v1, "tag"

    .line 8
    .line 9
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-static {p1}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    invoke-static {p1}, Lvz0/o;->a(Ljava/lang/Number;)Lvz0/e0;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    invoke-virtual {p0, v0, p1}, Lwz0/s;->M(Ljava/lang/String;Lvz0/n;)V

    .line 21
    .line 22
    .line 23
    return-void
.end method

.method public final s(Z)V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lwz0/s;->L()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Ljava/lang/String;

    .line 6
    .line 7
    const-string v1, "tag"

    .line 8
    .line 9
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    sget-object v1, Lvz0/o;->a:Luz0/f0;

    .line 17
    .line 18
    new-instance v1, Lvz0/u;

    .line 19
    .line 20
    const/4 v2, 0x0

    .line 21
    const/4 v3, 0x0

    .line 22
    invoke-direct {v1, p1, v2, v3}, Lvz0/u;-><init>(Ljava/lang/Object;ZLsz0/g;)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p0, v0, v1}, Lwz0/s;->M(Ljava/lang/String;Lvz0/n;)V

    .line 26
    .line 27
    .line 28
    return-void
.end method

.method public final t(Lsz0/g;IF)V
    .locals 1

    .line 1
    const-string v0, "descriptor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, p1, p2}, Lwz0/s;->K(Lsz0/g;I)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    invoke-virtual {p0, p1, p3}, Lwz0/s;->H(Ljava/lang/Object;F)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public final u(F)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Lwz0/s;->L()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {p0, v0, p1}, Lwz0/s;->H(Ljava/lang/Object;F)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final v(C)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lwz0/s;->L()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Ljava/lang/String;

    .line 6
    .line 7
    const-string v1, "tag"

    .line 8
    .line 9
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-static {p1}, Ljava/lang/String;->valueOf(C)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    invoke-static {p1}, Lvz0/o;->b(Ljava/lang/String;)Lvz0/e0;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    invoke-virtual {p0, v0, p1}, Lwz0/s;->M(Ljava/lang/String;Lvz0/n;)V

    .line 21
    .line 22
    .line 23
    return-void
.end method

.method public final w(Luz0/f1;IS)V
    .locals 1

    .line 1
    const-string v0, "descriptor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, p1, p2}, Lwz0/s;->K(Lsz0/g;I)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    invoke-static {p3}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    .line 11
    .line 12
    .line 13
    move-result-object p2

    .line 14
    invoke-static {p2}, Lvz0/o;->a(Ljava/lang/Number;)Lvz0/e0;

    .line 15
    .line 16
    .line 17
    move-result-object p2

    .line 18
    invoke-virtual {p0, p1, p2}, Lwz0/s;->M(Ljava/lang/String;Lvz0/n;)V

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method public final x(Lsz0/g;ILjava/lang/String;)V
    .locals 1

    .line 1
    const-string v0, "descriptor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "value"

    .line 7
    .line 8
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0, p1, p2}, Lwz0/s;->K(Lsz0/g;I)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    invoke-static {p3}, Lvz0/o;->b(Ljava/lang/String;)Lvz0/e0;

    .line 16
    .line 17
    .line 18
    move-result-object p2

    .line 19
    invoke-virtual {p0, p1, p2}, Lwz0/s;->M(Ljava/lang/String;Lvz0/n;)V

    .line 20
    .line 21
    .line 22
    return-void
.end method

.method public final y(Lsz0/g;IZ)V
    .locals 2

    .line 1
    const-string v0, "descriptor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, p1, p2}, Lwz0/s;->K(Lsz0/g;I)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    invoke-static {p3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 11
    .line 12
    .line 13
    move-result-object p2

    .line 14
    sget-object p3, Lvz0/o;->a:Luz0/f0;

    .line 15
    .line 16
    new-instance p3, Lvz0/u;

    .line 17
    .line 18
    const/4 v0, 0x0

    .line 19
    const/4 v1, 0x0

    .line 20
    invoke-direct {p3, p2, v0, v1}, Lvz0/u;-><init>(Ljava/lang/Object;ZLsz0/g;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p0, p1, p3}, Lwz0/s;->M(Ljava/lang/String;Lvz0/n;)V

    .line 24
    .line 25
    .line 26
    return-void
.end method

.method public final z(Lsz0/g;IJ)V
    .locals 1

    .line 1
    const-string v0, "descriptor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, p1, p2}, Lwz0/s;->K(Lsz0/g;I)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    invoke-static {p3, p4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 11
    .line 12
    .line 13
    move-result-object p2

    .line 14
    invoke-static {p2}, Lvz0/o;->a(Ljava/lang/Number;)Lvz0/e0;

    .line 15
    .line 16
    .line 17
    move-result-object p2

    .line 18
    invoke-virtual {p0, p1, p2}, Lwz0/s;->M(Ljava/lang/String;Lvz0/n;)V

    .line 19
    .line 20
    .line 21
    return-void
.end method
