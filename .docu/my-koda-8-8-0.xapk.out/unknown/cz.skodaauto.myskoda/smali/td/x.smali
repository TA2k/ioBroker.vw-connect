.class public final Ltd/x;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Ljd/b;

.field public final e:Lt90/c;

.field public final f:Lt10/k;

.field public final g:Ltd/h;

.field public final h:Lyy0/c2;

.field public final i:Lyy0/l1;

.field public final j:Lyy0/l1;

.field public k:Ljava/lang/String;

.field public l:Ljava/lang/String;

.field public m:Ljava/util/List;


# direct methods
.method public constructor <init>(Ljava/util/List;Ljd/b;Lt90/c;Lt10/k;)V
    .locals 2

    .line 1
    const-string v0, "initialSelection"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p2, p0, Ltd/x;->d:Ljd/b;

    .line 10
    .line 11
    iput-object p3, p0, Ltd/x;->e:Lt90/c;

    .line 12
    .line 13
    iput-object p4, p0, Ltd/x;->f:Lt10/k;

    .line 14
    .line 15
    sget-object p2, Ltd/h;->a:Ltd/h;

    .line 16
    .line 17
    iput-object p2, p0, Ltd/x;->g:Ltd/h;

    .line 18
    .line 19
    sget-object p2, Ltd/t;->e:Ltd/t;

    .line 20
    .line 21
    invoke-static {p2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 22
    .line 23
    .line 24
    move-result-object p2

    .line 25
    iput-object p2, p0, Ltd/x;->h:Lyy0/c2;

    .line 26
    .line 27
    new-instance p3, Llb0/y;

    .line 28
    .line 29
    const/16 p4, 0xb

    .line 30
    .line 31
    invoke-direct {p3, p4, p2, p0}, Llb0/y;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 35
    .line 36
    .line 37
    move-result-object p4

    .line 38
    new-instance v0, Llc/q;

    .line 39
    .line 40
    sget-object v1, Llc/a;->c:Llc/c;

    .line 41
    .line 42
    invoke-direct {v0, v1}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    sget-object v1, Lyy0/u1;->b:Lyy0/w1;

    .line 46
    .line 47
    invoke-static {p3, p4, v1, v0}, Lyy0/u;->F(Lyy0/i;Lvy0/b0;Lyy0/v1;Ljava/lang/Object;)Lyy0/l1;

    .line 48
    .line 49
    .line 50
    move-result-object p3

    .line 51
    iput-object p3, p0, Ltd/x;->i:Lyy0/l1;

    .line 52
    .line 53
    new-instance p3, Lag/r;

    .line 54
    .line 55
    const/16 p4, 0xf

    .line 56
    .line 57
    invoke-direct {p3, p2, p4}, Lag/r;-><init>(Lyy0/c2;I)V

    .line 58
    .line 59
    .line 60
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 61
    .line 62
    .line 63
    move-result-object p2

    .line 64
    sget-object p4, Ltd/r;->a:Ltd/r;

    .line 65
    .line 66
    invoke-static {p3, p2, v1, p4}, Lyy0/u;->F(Lyy0/i;Lvy0/b0;Lyy0/v1;Ljava/lang/Object;)Lyy0/l1;

    .line 67
    .line 68
    .line 69
    move-result-object p2

    .line 70
    iput-object p2, p0, Ltd/x;->j:Lyy0/l1;

    .line 71
    .line 72
    invoke-static {}, Ljava/time/LocalDate;->now()Ljava/time/LocalDate;

    .line 73
    .line 74
    .line 75
    move-result-object p2

    .line 76
    const-wide/16 p3, 0x28

    .line 77
    .line 78
    invoke-virtual {p2, p3, p4}, Ljava/time/LocalDate;->minusDays(J)Ljava/time/LocalDate;

    .line 79
    .line 80
    .line 81
    move-result-object p3

    .line 82
    const-string p4, "minusDays(...)"

    .line 83
    .line 84
    invoke-static {p3, p4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    sget-object p4, Ljava/time/format/DateTimeFormatter;->ISO_DATE:Ljava/time/format/DateTimeFormatter;

    .line 88
    .line 89
    invoke-virtual {p2, p4}, Ljava/time/LocalDate;->format(Ljava/time/format/DateTimeFormatter;)Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object p2

    .line 93
    const-string v0, "format(...)"

    .line 94
    .line 95
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    invoke-virtual {p3, p4}, Ljava/time/LocalDate;->format(Ljava/time/format/DateTimeFormatter;)Ljava/lang/String;

    .line 99
    .line 100
    .line 101
    move-result-object p3

    .line 102
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 103
    .line 104
    .line 105
    iput-object p3, p0, Ltd/x;->k:Ljava/lang/String;

    .line 106
    .line 107
    iput-object p2, p0, Ltd/x;->l:Ljava/lang/String;

    .line 108
    .line 109
    sget-object p2, Lmx0/s;->d:Lmx0/s;

    .line 110
    .line 111
    iput-object p2, p0, Ltd/x;->m:Ljava/util/List;

    .line 112
    .line 113
    check-cast p1, Ljava/lang/Iterable;

    .line 114
    .line 115
    new-instance p2, Ljava/util/ArrayList;

    .line 116
    .line 117
    const/16 p3, 0xa

    .line 118
    .line 119
    invoke-static {p1, p3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 120
    .line 121
    .line 122
    move-result p3

    .line 123
    invoke-direct {p2, p3}, Ljava/util/ArrayList;-><init>(I)V

    .line 124
    .line 125
    .line 126
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 127
    .line 128
    .line 129
    move-result-object p1

    .line 130
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 131
    .line 132
    .line 133
    move-result p3

    .line 134
    const/4 p4, 0x0

    .line 135
    if-eqz p3, :cond_2

    .line 136
    .line 137
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object p3

    .line 141
    check-cast p3, Lki/i;

    .line 142
    .line 143
    instance-of v0, p3, Lki/f;

    .line 144
    .line 145
    if-eqz v0, :cond_0

    .line 146
    .line 147
    new-instance p3, Lpd/y;

    .line 148
    .line 149
    const-string v0, "ALL_SUBSCRIPTION"

    .line 150
    .line 151
    invoke-direct {p3, p4, v0}, Lpd/y;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 152
    .line 153
    .line 154
    goto :goto_1

    .line 155
    :cond_0
    instance-of p4, p3, Lki/h;

    .line 156
    .line 157
    if-eqz p4, :cond_1

    .line 158
    .line 159
    new-instance p4, Lpd/y;

    .line 160
    .line 161
    check-cast p3, Lki/h;

    .line 162
    .line 163
    iget-object p3, p3, Lki/h;->b:Ljava/lang/String;

    .line 164
    .line 165
    const-string v0, "VEHICLE"

    .line 166
    .line 167
    invoke-direct {p4, p3, v0}, Lpd/y;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 168
    .line 169
    .line 170
    move-object p3, p4

    .line 171
    :goto_1
    invoke-virtual {p2, p3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 172
    .line 173
    .line 174
    goto :goto_0

    .line 175
    :cond_1
    new-instance p0, La8/r0;

    .line 176
    .line 177
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 178
    .line 179
    .line 180
    throw p0

    .line 181
    :cond_2
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 182
    .line 183
    .line 184
    move-result-object p1

    .line 185
    new-instance p3, Lr60/t;

    .line 186
    .line 187
    const/16 v0, 0x10

    .line 188
    .line 189
    invoke-direct {p3, v0, p0, p2, p4}, Lr60/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 190
    .line 191
    .line 192
    const/4 p0, 0x3

    .line 193
    invoke-static {p1, p4, p4, p3, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 194
    .line 195
    .line 196
    return-void
.end method


# virtual methods
.method public final a(Z)V
    .locals 4

    .line 1
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v1, Lc/m;

    .line 6
    .line 7
    const/16 v2, 0x8

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    invoke-direct {v1, p0, p1, v3, v2}, Lc/m;-><init>(Ljava/lang/Object;ZLkotlin/coroutines/Continuation;I)V

    .line 11
    .line 12
    .line 13
    const/4 p0, 0x3

    .line 14
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 15
    .line 16
    .line 17
    return-void
.end method
