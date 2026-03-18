.class public abstract Lfb/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "Schedulers"

    .line 2
    .line 3
    invoke-static {v0}, Leb/w;->f(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lfb/i;->a:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method public static a(Lmb/s;Leb/j;Ljava/util/List;)V
    .locals 2

    .line 1
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-lez v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 11
    .line 12
    .line 13
    move-result-wide v0

    .line 14
    invoke-interface {p2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 19
    .line 20
    .line 21
    move-result p2

    .line 22
    if-eqz p2, :cond_0

    .line 23
    .line 24
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p2

    .line 28
    check-cast p2, Lmb/o;

    .line 29
    .line 30
    iget-object p2, p2, Lmb/o;->a:Ljava/lang/String;

    .line 31
    .line 32
    invoke-virtual {p0, v0, v1, p2}, Lmb/s;->g(JLjava/lang/String;)I

    .line 33
    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    return-void
.end method

.method public static b(Leb/b;Landroidx/work/impl/WorkDatabase;Ljava/util/List;)V
    .locals 8

    .line 1
    if-eqz p2, :cond_4

    .line 2
    .line 3
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    goto/16 :goto_2

    .line 10
    .line 11
    :cond_0
    invoke-virtual {p1}, Landroidx/work/impl/WorkDatabase;->x()Lmb/s;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    invoke-virtual {p1}, Lla/u;->c()V

    .line 16
    .line 17
    .line 18
    :try_start_0
    iget-object v1, v0, Lmb/s;->a:Lla/u;

    .line 19
    .line 20
    new-instance v2, Lm40/e;

    .line 21
    .line 22
    const/16 v3, 0xe

    .line 23
    .line 24
    invoke-direct {v2, v3}, Lm40/e;-><init>(I)V

    .line 25
    .line 26
    .line 27
    const/4 v3, 0x0

    .line 28
    const/4 v4, 0x1

    .line 29
    invoke-static {v1, v4, v3, v2}, Ljp/ue;->f(Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    check-cast v1, Ljava/util/List;

    .line 34
    .line 35
    iget-object v2, p0, Leb/b;->d:Leb/j;

    .line 36
    .line 37
    invoke-static {v0, v2, v1}, Lfb/i;->a(Lmb/s;Leb/j;Ljava/util/List;)V

    .line 38
    .line 39
    .line 40
    iget v2, p0, Leb/b;->k:I

    .line 41
    .line 42
    iget-object v5, v0, Lmb/s;->a:Lla/u;

    .line 43
    .line 44
    new-instance v6, Lac/g;

    .line 45
    .line 46
    const/4 v7, 0x6

    .line 47
    invoke-direct {v6, v2, v7}, Lac/g;-><init>(II)V

    .line 48
    .line 49
    .line 50
    invoke-static {v5, v4, v3, v6}, Ljp/ue;->f(Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v2

    .line 54
    check-cast v2, Ljava/util/List;

    .line 55
    .line 56
    iget-object p0, p0, Leb/b;->d:Leb/j;

    .line 57
    .line 58
    invoke-static {v0, p0, v2}, Lfb/i;->a(Lmb/s;Leb/j;Ljava/util/List;)V

    .line 59
    .line 60
    .line 61
    invoke-interface {v2, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    .line 62
    .line 63
    .line 64
    iget-object p0, v0, Lmb/s;->a:Lla/u;

    .line 65
    .line 66
    new-instance v0, Lm40/e;

    .line 67
    .line 68
    const/16 v1, 0x11

    .line 69
    .line 70
    invoke-direct {v0, v1}, Lm40/e;-><init>(I)V

    .line 71
    .line 72
    .line 73
    invoke-static {p0, v4, v3, v0}, Ljp/ue;->f(Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    check-cast p0, Ljava/util/List;

    .line 78
    .line 79
    invoke-virtual {p1}, Lla/u;->q()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 80
    .line 81
    .line 82
    invoke-virtual {p1}, Lla/u;->g()V

    .line 83
    .line 84
    .line 85
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 86
    .line 87
    .line 88
    move-result p1

    .line 89
    if-lez p1, :cond_2

    .line 90
    .line 91
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 92
    .line 93
    .line 94
    move-result p1

    .line 95
    new-array p1, p1, [Lmb/o;

    .line 96
    .line 97
    invoke-interface {v2, p1}, Ljava/util/List;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object p1

    .line 101
    check-cast p1, [Lmb/o;

    .line 102
    .line 103
    invoke-interface {p2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 104
    .line 105
    .line 106
    move-result-object v0

    .line 107
    :cond_1
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 108
    .line 109
    .line 110
    move-result v1

    .line 111
    if-eqz v1, :cond_2

    .line 112
    .line 113
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object v1

    .line 117
    check-cast v1, Lfb/g;

    .line 118
    .line 119
    invoke-interface {v1}, Lfb/g;->e()Z

    .line 120
    .line 121
    .line 122
    move-result v2

    .line 123
    if-eqz v2, :cond_1

    .line 124
    .line 125
    invoke-interface {v1, p1}, Lfb/g;->a([Lmb/o;)V

    .line 126
    .line 127
    .line 128
    goto :goto_0

    .line 129
    :cond_2
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 130
    .line 131
    .line 132
    move-result p1

    .line 133
    if-lez p1, :cond_4

    .line 134
    .line 135
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 136
    .line 137
    .line 138
    move-result p1

    .line 139
    new-array p1, p1, [Lmb/o;

    .line 140
    .line 141
    invoke-interface {p0, p1}, Ljava/util/List;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object p0

    .line 145
    check-cast p0, [Lmb/o;

    .line 146
    .line 147
    invoke-interface {p2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 148
    .line 149
    .line 150
    move-result-object p1

    .line 151
    :cond_3
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 152
    .line 153
    .line 154
    move-result p2

    .line 155
    if-eqz p2, :cond_4

    .line 156
    .line 157
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object p2

    .line 161
    check-cast p2, Lfb/g;

    .line 162
    .line 163
    invoke-interface {p2}, Lfb/g;->e()Z

    .line 164
    .line 165
    .line 166
    move-result v0

    .line 167
    if-nez v0, :cond_3

    .line 168
    .line 169
    invoke-interface {p2, p0}, Lfb/g;->a([Lmb/o;)V

    .line 170
    .line 171
    .line 172
    goto :goto_1

    .line 173
    :catchall_0
    move-exception p0

    .line 174
    invoke-virtual {p1}, Lla/u;->g()V

    .line 175
    .line 176
    .line 177
    throw p0

    .line 178
    :cond_4
    :goto_2
    return-void
.end method
