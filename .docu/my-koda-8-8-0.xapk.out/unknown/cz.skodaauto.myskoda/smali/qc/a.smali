.class public final Lqc/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lqc/a;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lqc/a;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lqc/a;->a:Lqc/a;

    .line 7
    .line 8
    return-void
.end method

.method public static a(Ljava/lang/String;Ljava/lang/String;Lay0/k;Lay0/k;Lzb/s0;I)V
    .locals 6

    .line 1
    and-int/lit8 v0, p5, 0x2

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    move-object p1, v1

    .line 7
    :cond_0
    and-int/lit8 v0, p5, 0x4

    .line 8
    .line 9
    if-eqz v0, :cond_1

    .line 10
    .line 11
    move-object p2, v1

    .line 12
    :cond_1
    and-int/lit8 v0, p5, 0x8

    .line 13
    .line 14
    if-eqz v0, :cond_2

    .line 15
    .line 16
    move-object p3, v1

    .line 17
    :cond_2
    and-int/lit8 p5, p5, 0x10

    .line 18
    .line 19
    if-eqz p5, :cond_3

    .line 20
    .line 21
    move-object p4, v1

    .line 22
    :cond_3
    const-string p5, "uriString"

    .line 23
    .line 24
    invoke-static {p0, p5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    new-instance p5, Ljava/net/URI;

    .line 28
    .line 29
    invoke-direct {p5, p0}, Ljava/net/URI;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {p5}, Ljava/net/URI;->getScheme()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    const-string v2, "getScheme(...)"

    .line 37
    .line 38
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    const-string v3, "http"

    .line 42
    .line 43
    invoke-virtual {v0, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v4

    .line 47
    const-string v5, "https"

    .line 48
    .line 49
    if-nez v4, :cond_4

    .line 50
    .line 51
    invoke-virtual {v0, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    move-result v0

    .line 55
    if-eqz v0, :cond_5

    .line 56
    .line 57
    :cond_4
    if-eqz p3, :cond_5

    .line 58
    .line 59
    invoke-interface {p3, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    return-void

    .line 63
    :cond_5
    invoke-virtual {p5}, Ljava/net/URI;->getScheme()Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object p3

    .line 67
    invoke-static {p3, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    invoke-virtual {p3, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    move-result v0

    .line 74
    if-nez v0, :cond_6

    .line 75
    .line 76
    invoke-virtual {p3, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    move-result p3

    .line 80
    if-eqz p3, :cond_7

    .line 81
    .line 82
    :cond_6
    if-eqz p4, :cond_7

    .line 83
    .line 84
    invoke-virtual {p4, p0}, Lzb/s0;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    return-void

    .line 88
    :cond_7
    invoke-virtual {p5}, Ljava/net/URI;->getScheme()Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object p3

    .line 92
    invoke-static {p3, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    const-string p4, "charging"

    .line 96
    .line 97
    invoke-virtual {p3, p4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    move-result p3

    .line 101
    if-eqz p3, :cond_8

    .line 102
    .line 103
    invoke-virtual {p5}, Ljava/net/URI;->getHost()Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object p3

    .line 107
    const-string p4, "getHost(...)"

    .line 108
    .line 109
    invoke-static {p3, p4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    const-string p4, "pdf"

    .line 113
    .line 114
    invoke-virtual {p3, p4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 115
    .line 116
    .line 117
    move-result p3

    .line 118
    if-eqz p3, :cond_8

    .line 119
    .line 120
    invoke-virtual {p5}, Ljava/net/URI;->getPath()Ljava/lang/String;

    .line 121
    .line 122
    .line 123
    move-result-object p3

    .line 124
    const-string p4, "getPath(...)"

    .line 125
    .line 126
    invoke-static {p3, p4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 127
    .line 128
    .line 129
    const-string p4, "/tariffdetails"

    .line 130
    .line 131
    invoke-virtual {p3, p4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 132
    .line 133
    .line 134
    move-result p3

    .line 135
    if-eqz p3, :cond_8

    .line 136
    .line 137
    if-eqz p1, :cond_8

    .line 138
    .line 139
    if-eqz p2, :cond_8

    .line 140
    .line 141
    invoke-interface {p2, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    return-void

    .line 145
    :cond_8
    sget-object p1, Lgi/b;->g:Lgi/b;

    .line 146
    .line 147
    new-instance p2, Lod0/d;

    .line 148
    .line 149
    const/16 p3, 0x9

    .line 150
    .line 151
    invoke-direct {p2, p0, p3}, Lod0/d;-><init>(Ljava/lang/String;I)V

    .line 152
    .line 153
    .line 154
    sget-object p0, Lgi/a;->e:Lgi/a;

    .line 155
    .line 156
    const-class p3, Lqc/a;

    .line 157
    .line 158
    invoke-virtual {p3}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 159
    .line 160
    .line 161
    move-result-object p3

    .line 162
    const/16 p4, 0x24

    .line 163
    .line 164
    invoke-static {p3, p4}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 165
    .line 166
    .line 167
    move-result-object p4

    .line 168
    const/16 p5, 0x2e

    .line 169
    .line 170
    invoke-static {p5, p4, p4}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 171
    .line 172
    .line 173
    move-result-object p4

    .line 174
    invoke-virtual {p4}, Ljava/lang/String;->length()I

    .line 175
    .line 176
    .line 177
    move-result p5

    .line 178
    if-nez p5, :cond_9

    .line 179
    .line 180
    goto :goto_0

    .line 181
    :cond_9
    const-string p3, "Kt"

    .line 182
    .line 183
    invoke-static {p4, p3}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 184
    .line 185
    .line 186
    move-result-object p3

    .line 187
    :goto_0
    invoke-static {p3, p0, p1, v1, p2}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 188
    .line 189
    .line 190
    return-void
.end method
