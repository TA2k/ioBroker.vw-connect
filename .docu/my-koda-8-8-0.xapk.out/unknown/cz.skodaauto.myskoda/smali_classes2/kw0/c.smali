.class public final Lkw0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Low0/z;

.field public b:Low0/s;

.field public final c:Low0/n;

.field public d:Ljava/lang/Object;

.field public e:Lvy0/z1;

.field public final f:Lvw0/d;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Low0/z;

    .line 5
    .line 6
    invoke-direct {v0}, Low0/z;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lkw0/c;->a:Low0/z;

    .line 10
    .line 11
    sget-object v0, Low0/s;->b:Low0/s;

    .line 12
    .line 13
    iput-object v0, p0, Lkw0/c;->b:Low0/s;

    .line 14
    .line 15
    new-instance v0, Low0/n;

    .line 16
    .line 17
    const/4 v1, 0x0

    .line 18
    invoke-direct {v0, v1}, Low0/n;-><init>(I)V

    .line 19
    .line 20
    .line 21
    iput-object v0, p0, Lkw0/c;->c:Low0/n;

    .line 22
    .line 23
    sget-object v0, Lmw0/b;->a:Lmw0/b;

    .line 24
    .line 25
    iput-object v0, p0, Lkw0/c;->d:Ljava/lang/Object;

    .line 26
    .line 27
    invoke-static {}, Lvy0/e0;->f()Lvy0/z1;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    iput-object v0, p0, Lkw0/c;->e:Lvy0/z1;

    .line 32
    .line 33
    new-instance v0, Lvw0/d;

    .line 34
    .line 35
    invoke-direct {v0}, Lvw0/d;-><init>()V

    .line 36
    .line 37
    .line 38
    iput-object v0, p0, Lkw0/c;->f:Lvw0/d;

    .line 39
    .line 40
    return-void
.end method


# virtual methods
.method public final a(Lzw0/a;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lkw0/c;->f:Lvw0/d;

    .line 2
    .line 3
    if-eqz p1, :cond_0

    .line 4
    .line 5
    sget-object v0, Lkw0/g;->a:Lvw0/a;

    .line 6
    .line 7
    invoke-virtual {p0, v0, p1}, Lvw0/d;->e(Lvw0/a;Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    return-void

    .line 11
    :cond_0
    sget-object p1, Lkw0/g;->a:Lvw0/a;

    .line 12
    .line 13
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    const-string v0, "key"

    .line 17
    .line 18
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {p0}, Lvw0/d;->c()Ljava/util/Map;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-interface {p0, p1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    return-void
.end method

.method public final b(Low0/s;)V
    .locals 1

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lkw0/c;->b:Low0/s;

    .line 7
    .line 8
    return-void
.end method

.method public final c(Lkw0/c;)V
    .locals 8

    .line 1
    const-string v0, "builder"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p1, Lkw0/c;->b:Low0/s;

    .line 7
    .line 8
    iput-object v0, p0, Lkw0/c;->b:Low0/s;

    .line 9
    .line 10
    iget-object v0, p1, Lkw0/c;->d:Ljava/lang/Object;

    .line 11
    .line 12
    iput-object v0, p0, Lkw0/c;->d:Ljava/lang/Object;

    .line 13
    .line 14
    iget-object v0, p1, Lkw0/c;->f:Lvw0/d;

    .line 15
    .line 16
    sget-object v1, Lkw0/g;->a:Lvw0/a;

    .line 17
    .line 18
    invoke-virtual {v0, v1}, Lvw0/d;->d(Lvw0/a;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    check-cast v1, Lzw0/a;

    .line 23
    .line 24
    invoke-virtual {p0, v1}, Lkw0/c;->a(Lzw0/a;)V

    .line 25
    .line 26
    .line 27
    iget-object v1, p1, Lkw0/c;->a:Low0/z;

    .line 28
    .line 29
    iget-object v2, p0, Lkw0/c;->a:Low0/z;

    .line 30
    .line 31
    const-string v3, "<this>"

    .line 32
    .line 33
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    const-string v4, "url"

    .line 37
    .line 38
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    iget-object v4, v1, Low0/z;->d:Low0/b0;

    .line 42
    .line 43
    iput-object v4, v2, Low0/z;->d:Low0/b0;

    .line 44
    .line 45
    iget-object v4, v1, Low0/z;->a:Ljava/lang/String;

    .line 46
    .line 47
    const-string v5, "<set-?>"

    .line 48
    .line 49
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    iput-object v4, v2, Low0/z;->a:Ljava/lang/String;

    .line 53
    .line 54
    iget v4, v1, Low0/z;->c:I

    .line 55
    .line 56
    invoke-virtual {v2, v4}, Low0/z;->e(I)V

    .line 57
    .line 58
    .line 59
    iget-object v4, v1, Low0/z;->h:Ljava/util/List;

    .line 60
    .line 61
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    iput-object v4, v2, Low0/z;->h:Ljava/util/List;

    .line 65
    .line 66
    iget-object v4, v1, Low0/z;->e:Ljava/lang/String;

    .line 67
    .line 68
    iput-object v4, v2, Low0/z;->e:Ljava/lang/String;

    .line 69
    .line 70
    iget-object v4, v1, Low0/z;->f:Ljava/lang/String;

    .line 71
    .line 72
    iput-object v4, v2, Low0/z;->f:Ljava/lang/String;

    .line 73
    .line 74
    new-instance v4, Low0/n;

    .line 75
    .line 76
    const/4 v6, 0x1

    .line 77
    invoke-direct {v4, v6}, Low0/n;-><init>(I)V

    .line 78
    .line 79
    .line 80
    iget-object v6, v1, Low0/z;->i:Low0/n;

    .line 81
    .line 82
    invoke-static {v4, v6}, Llp/mc;->a(Lvw0/k;Lvw0/k;)V

    .line 83
    .line 84
    .line 85
    iput-object v4, v2, Low0/z;->i:Low0/n;

    .line 86
    .line 87
    new-instance v6, Lj1/a;

    .line 88
    .line 89
    const/16 v7, 0x17

    .line 90
    .line 91
    invoke-direct {v6, v4, v7}, Lj1/a;-><init>(Ljava/lang/Object;I)V

    .line 92
    .line 93
    .line 94
    iput-object v6, v2, Low0/z;->j:Lj1/a;

    .line 95
    .line 96
    iget-object v4, v1, Low0/z;->g:Ljava/lang/String;

    .line 97
    .line 98
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    iput-object v4, v2, Low0/z;->g:Ljava/lang/String;

    .line 102
    .line 103
    iget-boolean v1, v1, Low0/z;->b:Z

    .line 104
    .line 105
    iput-boolean v1, v2, Low0/z;->b:Z

    .line 106
    .line 107
    iget-object v1, v2, Low0/z;->h:Ljava/util/List;

    .line 108
    .line 109
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    iput-object v1, v2, Low0/z;->h:Ljava/util/List;

    .line 113
    .line 114
    iget-object v1, p0, Lkw0/c;->c:Low0/n;

    .line 115
    .line 116
    iget-object p1, p1, Lkw0/c;->c:Low0/n;

    .line 117
    .line 118
    invoke-static {v1, p1}, Llp/mc;->a(Lvw0/k;Lvw0/k;)V

    .line 119
    .line 120
    .line 121
    iget-object p0, p0, Lkw0/c;->f:Lvw0/d;

    .line 122
    .line 123
    invoke-static {p0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    const-string p1, "other"

    .line 127
    .line 128
    invoke-static {v0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 129
    .line 130
    .line 131
    invoke-virtual {v0}, Lvw0/d;->c()Ljava/util/Map;

    .line 132
    .line 133
    .line 134
    move-result-object p1

    .line 135
    invoke-interface {p1}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 136
    .line 137
    .line 138
    move-result-object p1

    .line 139
    check-cast p1, Ljava/lang/Iterable;

    .line 140
    .line 141
    invoke-static {p1}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 142
    .line 143
    .line 144
    move-result-object p1

    .line 145
    check-cast p1, Ljava/lang/Iterable;

    .line 146
    .line 147
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 148
    .line 149
    .line 150
    move-result-object p1

    .line 151
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 152
    .line 153
    .line 154
    move-result v1

    .line 155
    if-eqz v1, :cond_0

    .line 156
    .line 157
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object v1

    .line 161
    check-cast v1, Lvw0/a;

    .line 162
    .line 163
    const-string v2, "null cannot be cast to non-null type io.ktor.util.AttributeKey<kotlin.Any>"

    .line 164
    .line 165
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 166
    .line 167
    .line 168
    invoke-virtual {v0, v1}, Lvw0/d;->b(Lvw0/a;)Ljava/lang/Object;

    .line 169
    .line 170
    .line 171
    move-result-object v2

    .line 172
    invoke-virtual {p0, v1, v2}, Lvw0/d;->e(Lvw0/a;Ljava/lang/Object;)V

    .line 173
    .line 174
    .line 175
    goto :goto_0

    .line 176
    :cond_0
    return-void
.end method
