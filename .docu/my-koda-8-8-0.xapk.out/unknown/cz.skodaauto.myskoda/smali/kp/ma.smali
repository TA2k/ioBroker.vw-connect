.class public final Lkp/ma;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkp/ja;


# instance fields
.field public final a:Lgs/o;

.field public final b:Lkp/ia;


# direct methods
.method public constructor <init>(Landroid/content/Context;Lkp/ia;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lkp/ma;->b:Lkp/ia;

    .line 5
    .line 6
    sget-object p2, Lpn/a;->e:Lpn/a;

    .line 7
    .line 8
    invoke-static {p1}, Lrn/r;->b(Landroid/content/Context;)V

    .line 9
    .line 10
    .line 11
    invoke-static {}, Lrn/r;->a()Lrn/r;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    invoke-virtual {p1, p2}, Lrn/r;->c(Lrn/l;)Lrn/p;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    sget-object p2, Lpn/a;->d:Ljava/util/Set;

    .line 20
    .line 21
    new-instance v0, Lon/c;

    .line 22
    .line 23
    const-string v1, "json"

    .line 24
    .line 25
    invoke-direct {v0, v1}, Lon/c;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-interface {p2, v0}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result p2

    .line 32
    if-eqz p2, :cond_0

    .line 33
    .line 34
    new-instance p2, Lgs/o;

    .line 35
    .line 36
    new-instance v0, Ljp/wg;

    .line 37
    .line 38
    const/4 v1, 0x2

    .line 39
    invoke-direct {v0, p1, v1}, Ljp/wg;-><init>(Lrn/p;I)V

    .line 40
    .line 41
    .line 42
    invoke-direct {p2, v0}, Lgs/o;-><init>(Lgt/b;)V

    .line 43
    .line 44
    .line 45
    :cond_0
    new-instance p2, Lgs/o;

    .line 46
    .line 47
    new-instance v0, Ljp/wg;

    .line 48
    .line 49
    const/4 v1, 0x3

    .line 50
    invoke-direct {v0, p1, v1}, Ljp/wg;-><init>(Lrn/p;I)V

    .line 51
    .line 52
    .line 53
    invoke-direct {p2, v0}, Lgs/o;-><init>(Lgt/b;)V

    .line 54
    .line 55
    .line 56
    iput-object p2, p0, Lkp/ma;->a:Lgs/o;

    .line 57
    .line 58
    return-void
.end method


# virtual methods
.method public final a(Lvp/y1;)V
    .locals 6

    .line 1
    iget-object v0, p0, Lkp/ma;->b:Lkp/ia;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lkp/ma;->a:Lgs/o;

    .line 7
    .line 8
    invoke-virtual {p0}, Lgs/o;->get()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Lrn/q;

    .line 13
    .line 14
    const-class v1, Lkp/l7;

    .line 15
    .line 16
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    sget-object v0, Lkp/pa;->f:Lkp/pa;

    .line 20
    .line 21
    iget-object v2, p1, Lvp/y1;->e:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v2, Lil/g;

    .line 24
    .line 25
    iget-object v3, p1, Lvp/y1;->f:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast v3, Ljp/uf;

    .line 28
    .line 29
    const/4 v4, 0x0

    .line 30
    invoke-static {v4}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 31
    .line 32
    .line 33
    move-result-object v4

    .line 34
    iput-object v4, v3, Ljp/uf;->h:Ljava/lang/Object;

    .line 35
    .line 36
    iget-object p1, p1, Lvp/y1;->f:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast p1, Ljp/uf;

    .line 39
    .line 40
    sget-object v3, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 41
    .line 42
    iput-object v3, p1, Ljp/uf;->f:Ljava/lang/Object;

    .line 43
    .line 44
    new-instance v3, Lkp/l9;

    .line 45
    .line 46
    invoke-direct {v3, p1}, Lkp/l9;-><init>(Ljp/uf;)V

    .line 47
    .line 48
    .line 49
    iput-object v3, v2, Lil/g;->e:Ljava/lang/Object;

    .line 50
    .line 51
    :try_start_0
    invoke-static {}, Lkp/pa;->b()V

    .line 52
    .line 53
    .line 54
    new-instance p1, Lkp/l7;

    .line 55
    .line 56
    invoke-direct {p1, v2}, Lkp/l7;-><init>(Lil/g;)V

    .line 57
    .line 58
    .line 59
    new-instance v2, Lil/g;

    .line 60
    .line 61
    const/4 v3, 0x6

    .line 62
    invoke-direct {v2, v3}, Lil/g;-><init>(I)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {v0, v2}, Lkp/pa;->a(Lat/a;)V

    .line 66
    .line 67
    .line 68
    new-instance v0, Ljava/util/HashMap;

    .line 69
    .line 70
    iget-object v3, v2, Lil/g;->e:Ljava/lang/Object;

    .line 71
    .line 72
    check-cast v3, Ljava/util/HashMap;

    .line 73
    .line 74
    invoke-direct {v0, v3}, Ljava/util/HashMap;-><init>(Ljava/util/Map;)V

    .line 75
    .line 76
    .line 77
    new-instance v3, Ljava/util/HashMap;

    .line 78
    .line 79
    iget-object v4, v2, Lil/g;->f:Ljava/lang/Object;

    .line 80
    .line 81
    check-cast v4, Ljava/util/HashMap;

    .line 82
    .line 83
    invoke-direct {v3, v4}, Ljava/util/HashMap;-><init>(Ljava/util/Map;)V

    .line 84
    .line 85
    .line 86
    iget-object v2, v2, Lil/g;->g:Ljava/lang/Object;

    .line 87
    .line 88
    check-cast v2, Lkp/e;

    .line 89
    .line 90
    new-instance v4, Ljava/io/ByteArrayOutputStream;

    .line 91
    .line 92
    invoke-direct {v4}, Ljava/io/ByteArrayOutputStream;-><init>()V
    :try_end_0
    .catch Ljava/io/UnsupportedEncodingException; {:try_start_0 .. :try_end_0} :catch_1

    .line 93
    .line 94
    .line 95
    :try_start_1
    new-instance v5, Lkp/f;

    .line 96
    .line 97
    invoke-direct {v5, v4, v0, v3, v2}, Lkp/f;-><init>(Ljava/io/ByteArrayOutputStream;Ljava/util/HashMap;Ljava/util/HashMap;Lzs/d;)V

    .line 98
    .line 99
    .line 100
    invoke-virtual {v0, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v0

    .line 104
    check-cast v0, Lzs/d;

    .line 105
    .line 106
    if-eqz v0, :cond_0

    .line 107
    .line 108
    invoke-interface {v0, p1, v5}, Lzs/a;->a(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 109
    .line 110
    .line 111
    goto :goto_0

    .line 112
    :cond_0
    new-instance p1, Lzs/b;

    .line 113
    .line 114
    invoke-static {v1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object v0

    .line 118
    const-string v1, "No encoder for "

    .line 119
    .line 120
    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 121
    .line 122
    .line 123
    move-result-object v0

    .line 124
    invoke-direct {p1, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 125
    .line 126
    .line 127
    throw p1
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_0

    .line 128
    :catch_0
    :goto_0
    :try_start_2
    invoke-virtual {v4}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    .line 129
    .line 130
    .line 131
    move-result-object p1
    :try_end_2
    .catch Ljava/io/UnsupportedEncodingException; {:try_start_2 .. :try_end_2} :catch_1

    .line 132
    new-instance v0, Lon/a;

    .line 133
    .line 134
    sget-object v1, Lon/d;->e:Lon/d;

    .line 135
    .line 136
    const/4 v2, 0x0

    .line 137
    invoke-direct {v0, p1, v1, v2}, Lon/a;-><init>(Ljava/lang/Object;Lon/d;Lon/b;)V

    .line 138
    .line 139
    .line 140
    new-instance p1, Lj9/d;

    .line 141
    .line 142
    const/16 v1, 0x19

    .line 143
    .line 144
    invoke-direct {p1, v1}, Lj9/d;-><init>(I)V

    .line 145
    .line 146
    .line 147
    invoke-virtual {p0, v0, p1}, Lrn/q;->a(Lon/a;Lon/g;)V

    .line 148
    .line 149
    .line 150
    return-void

    .line 151
    :catch_1
    move-exception p0

    .line 152
    new-instance p1, Ljava/lang/UnsupportedOperationException;

    .line 153
    .line 154
    const-string v0, "Failed to covert logging to UTF-8 byte array"

    .line 155
    .line 156
    invoke-direct {p1, v0, p0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 157
    .line 158
    .line 159
    throw p1
.end method
