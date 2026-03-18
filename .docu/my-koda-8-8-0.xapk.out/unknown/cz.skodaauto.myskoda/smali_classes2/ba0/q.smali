.class public final Lba0/q;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lko0/f;

.field public final i:Lz90/a;

.field public final j:Lz90/b;

.field public final k:Lz90/t;

.field public final l:Ltr0/b;

.field public final m:Lij0/a;

.field public final n:Lrq0/f;

.field public final o:Lz90/l;

.field public final p:Lz90/x;


# direct methods
.method public constructor <init>(Lz90/h;Lko0/f;Lz90/a;Lz90/b;Lz90/t;Ltr0/b;Lij0/a;Lrq0/f;Lz90/l;Lz90/x;)V
    .locals 7

    .line 1
    new-instance v0, Lba0/l;

    .line 2
    .line 3
    const/4 v5, 0x0

    .line 4
    const/4 v6, 0x0

    .line 5
    const/4 v1, 0x0

    .line 6
    const/4 v2, 0x0

    .line 7
    const/4 v3, 0x0

    .line 8
    const/4 v4, 0x0

    .line 9
    invoke-direct/range {v0 .. v6}, Lba0/l;-><init>(Lba0/k;Lql0/g;ZZZZ)V

    .line 10
    .line 11
    .line 12
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 13
    .line 14
    .line 15
    iput-object p2, p0, Lba0/q;->h:Lko0/f;

    .line 16
    .line 17
    iput-object p3, p0, Lba0/q;->i:Lz90/a;

    .line 18
    .line 19
    iput-object p4, p0, Lba0/q;->j:Lz90/b;

    .line 20
    .line 21
    iput-object p5, p0, Lba0/q;->k:Lz90/t;

    .line 22
    .line 23
    iput-object p6, p0, Lba0/q;->l:Ltr0/b;

    .line 24
    .line 25
    iput-object p7, p0, Lba0/q;->m:Lij0/a;

    .line 26
    .line 27
    iput-object p8, p0, Lba0/q;->n:Lrq0/f;

    .line 28
    .line 29
    move-object/from16 p2, p9

    .line 30
    .line 31
    iput-object p2, p0, Lba0/q;->o:Lz90/l;

    .line 32
    .line 33
    move-object/from16 p2, p10

    .line 34
    .line 35
    iput-object p2, p0, Lba0/q;->p:Lz90/x;

    .line 36
    .line 37
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 38
    .line 39
    .line 40
    move-result-object p2

    .line 41
    move-object p3, p2

    .line 42
    check-cast p3, Lba0/l;

    .line 43
    .line 44
    invoke-virtual {p1}, Lz90/h;->invoke()Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    check-cast p1, Laa0/j;

    .line 49
    .line 50
    if-eqz p1, :cond_3

    .line 51
    .line 52
    iget-object p2, p1, Laa0/j;->a:Ljava/lang/String;

    .line 53
    .line 54
    iget-object p4, p1, Laa0/j;->b:Ljava/lang/String;

    .line 55
    .line 56
    iget-object v0, p1, Laa0/j;->c:Ljava/lang/String;

    .line 57
    .line 58
    iget-object v1, p1, Laa0/j;->d:Ljava/time/OffsetDateTime;

    .line 59
    .line 60
    invoke-static {v1}, Lvo/a;->g(Ljava/time/OffsetDateTime;)Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    const-string v2, " | "

    .line 65
    .line 66
    invoke-static {v0, v2, v1}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    iget-object p1, p1, Laa0/j;->e:Ljava/util/ArrayList;

    .line 71
    .line 72
    new-instance v1, Ljava/util/ArrayList;

    .line 73
    .line 74
    const/16 v2, 0xa

    .line 75
    .line 76
    invoke-static {p1, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 77
    .line 78
    .line 79
    move-result v2

    .line 80
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 81
    .line 82
    .line 83
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 84
    .line 85
    .line 86
    move-result-object p1

    .line 87
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 88
    .line 89
    .line 90
    move-result v2

    .line 91
    if-eqz v2, :cond_2

    .line 92
    .line 93
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v2

    .line 97
    check-cast v2, Laa0/d;

    .line 98
    .line 99
    instance-of v3, v2, Laa0/g;

    .line 100
    .line 101
    if-eqz v3, :cond_0

    .line 102
    .line 103
    new-instance v2, Lba0/j;

    .line 104
    .line 105
    const v3, 0x7f0802b8

    .line 106
    .line 107
    .line 108
    sget-object v4, Laa0/e;->d:Laa0/e;

    .line 109
    .line 110
    const v5, 0x7f121532

    .line 111
    .line 112
    .line 113
    invoke-direct {v2, v5, v3, v4}, Lba0/j;-><init>(IILaa0/e;)V

    .line 114
    .line 115
    .line 116
    goto :goto_1

    .line 117
    :cond_0
    instance-of v2, v2, Laa0/a;

    .line 118
    .line 119
    if-eqz v2, :cond_1

    .line 120
    .line 121
    new-instance v2, Lba0/j;

    .line 122
    .line 123
    const v3, 0x7f0803ad

    .line 124
    .line 125
    .line 126
    sget-object v4, Laa0/e;->e:Laa0/e;

    .line 127
    .line 128
    const v5, 0x7f121534

    .line 129
    .line 130
    .line 131
    invoke-direct {v2, v5, v3, v4}, Lba0/j;-><init>(IILaa0/e;)V

    .line 132
    .line 133
    .line 134
    :goto_1
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 135
    .line 136
    .line 137
    goto :goto_0

    .line 138
    :cond_1
    new-instance p0, La8/r0;

    .line 139
    .line 140
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 141
    .line 142
    .line 143
    throw p0

    .line 144
    :cond_2
    new-instance p1, Lba0/k;

    .line 145
    .line 146
    invoke-direct {p1, p2, p4, v0, v1}, Lba0/k;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/ArrayList;)V

    .line 147
    .line 148
    .line 149
    :goto_2
    move-object p4, p1

    .line 150
    goto :goto_3

    .line 151
    :cond_3
    const/4 p1, 0x0

    .line 152
    goto :goto_2

    .line 153
    :goto_3
    const/4 p1, 0x0

    .line 154
    const/16 p2, 0x3e

    .line 155
    .line 156
    const/4 v0, 0x0

    .line 157
    const/4 v1, 0x0

    .line 158
    const/4 v2, 0x0

    .line 159
    const/4 v3, 0x0

    .line 160
    move/from16 p9, p1

    .line 161
    .line 162
    move/from16 p10, p2

    .line 163
    .line 164
    move-object p5, v0

    .line 165
    move p6, v1

    .line 166
    move p7, v2

    .line 167
    move p8, v3

    .line 168
    invoke-static/range {p3 .. p10}, Lba0/l;->a(Lba0/l;Lba0/k;Lql0/g;ZZZZI)Lba0/l;

    .line 169
    .line 170
    .line 171
    move-result-object p1

    .line 172
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 173
    .line 174
    .line 175
    return-void
.end method
