.class public final Lh2/y1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lgy0/j;

.field public final b:Lh2/e8;

.field public final c:Li2/e0;

.field public final d:Lh2/g2;

.field public final e:Ljava/lang/String;

.field public final f:Ljava/lang/String;

.field public final g:Ljava/lang/String;

.field public final h:Ljava/lang/String;

.field public i:Ljava/lang/Long;

.field public j:Ljava/lang/Long;


# direct methods
.method public constructor <init>(Lgy0/j;Lh2/e8;Li2/e0;Lh2/g2;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/y1;->a:Lgy0/j;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/y1;->b:Lh2/e8;

    .line 7
    .line 8
    iput-object p3, p0, Lh2/y1;->c:Li2/e0;

    .line 9
    .line 10
    iput-object p4, p0, Lh2/y1;->d:Lh2/g2;

    .line 11
    .line 12
    iput-object p5, p0, Lh2/y1;->e:Ljava/lang/String;

    .line 13
    .line 14
    iput-object p6, p0, Lh2/y1;->f:Ljava/lang/String;

    .line 15
    .line 16
    iput-object p7, p0, Lh2/y1;->g:Ljava/lang/String;

    .line 17
    .line 18
    iput-object p8, p0, Lh2/y1;->h:Ljava/lang/String;

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final a(Li2/y;ILjava/util/Locale;)Ljava/lang/String;
    .locals 6

    .line 1
    const/4 v0, 0x1

    .line 2
    if-nez p1, :cond_0

    .line 3
    .line 4
    iget-object p1, p0, Lh2/y1;->c:Li2/e0;

    .line 5
    .line 6
    iget-object p1, p1, Li2/e0;->a:Ljava/lang/String;

    .line 7
    .line 8
    sget-object p2, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 9
    .line 10
    invoke-virtual {p1, p2}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    const-string p2, "toUpperCase(...)"

    .line 15
    .line 16
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    invoke-static {p1, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    array-length p2, p1

    .line 28
    invoke-static {p1, p2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    iget-object p0, p0, Lh2/y1;->e:Ljava/lang/String;

    .line 33
    .line 34
    invoke-static {p0, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    return-object p0

    .line 39
    :cond_0
    iget v1, p1, Li2/y;->d:I

    .line 40
    .line 41
    iget-wide v2, p1, Li2/y;->g:J

    .line 42
    .line 43
    iget-object p1, p0, Lh2/y1;->a:Lgy0/j;

    .line 44
    .line 45
    invoke-virtual {p1, v1}, Lgy0/j;->i(I)Z

    .line 46
    .line 47
    .line 48
    move-result v4

    .line 49
    const/4 v5, 0x2

    .line 50
    if-nez v4, :cond_1

    .line 51
    .line 52
    iget p2, p1, Lgy0/h;->d:I

    .line 53
    .line 54
    invoke-static {p2, p3}, Lh2/v0;->a(ILjava/util/Locale;)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p2

    .line 58
    iget p1, p1, Lgy0/h;->e:I

    .line 59
    .line 60
    invoke-static {p1, p3}, Lh2/v0;->a(ILjava/util/Locale;)Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object p1

    .line 64
    filled-new-array {p2, p1}, [Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    invoke-static {p1, v5}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object p1

    .line 72
    array-length p2, p1

    .line 73
    invoke-static {p1, p2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object p1

    .line 77
    iget-object p0, p0, Lh2/y1;->f:Ljava/lang/String;

    .line 78
    .line 79
    invoke-static {p0, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    return-object p0

    .line 84
    :cond_1
    iget-object p1, p0, Lh2/y1;->b:Lh2/e8;

    .line 85
    .line 86
    invoke-interface {p1, v1}, Lh2/e8;->a(I)Z

    .line 87
    .line 88
    .line 89
    move-result v1

    .line 90
    if-eqz v1, :cond_8

    .line 91
    .line 92
    invoke-interface {p1, v2, v3}, Lh2/e8;->b(J)Z

    .line 93
    .line 94
    .line 95
    move-result p1

    .line 96
    if-nez p1, :cond_2

    .line 97
    .line 98
    goto :goto_2

    .line 99
    :cond_2
    if-ne p2, v0, :cond_4

    .line 100
    .line 101
    iget-object p1, p0, Lh2/y1;->j:Ljava/lang/Long;

    .line 102
    .line 103
    if-eqz p1, :cond_3

    .line 104
    .line 105
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    .line 106
    .line 107
    .line 108
    move-result-wide v0

    .line 109
    goto :goto_0

    .line 110
    :cond_3
    const-wide v0, 0x7fffffffffffffffL

    .line 111
    .line 112
    .line 113
    .line 114
    .line 115
    :goto_0
    cmp-long p1, v2, v0

    .line 116
    .line 117
    if-gtz p1, :cond_6

    .line 118
    .line 119
    :cond_4
    if-ne p2, v5, :cond_7

    .line 120
    .line 121
    iget-object p1, p0, Lh2/y1;->i:Ljava/lang/Long;

    .line 122
    .line 123
    if-eqz p1, :cond_5

    .line 124
    .line 125
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    .line 126
    .line 127
    .line 128
    move-result-wide p1

    .line 129
    goto :goto_1

    .line 130
    :cond_5
    const-wide/high16 p1, -0x8000000000000000L

    .line 131
    .line 132
    :goto_1
    cmp-long p1, v2, p1

    .line 133
    .line 134
    if-gez p1, :cond_7

    .line 135
    .line 136
    :cond_6
    iget-object p0, p0, Lh2/y1;->h:Ljava/lang/String;

    .line 137
    .line 138
    return-object p0

    .line 139
    :cond_7
    const-string p0, ""

    .line 140
    .line 141
    return-object p0

    .line 142
    :cond_8
    :goto_2
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 143
    .line 144
    .line 145
    move-result-object p1

    .line 146
    const/4 p2, 0x0

    .line 147
    iget-object v1, p0, Lh2/y1;->d:Lh2/g2;

    .line 148
    .line 149
    invoke-virtual {v1, p1, p3, p2}, Lh2/g2;->a(Ljava/lang/Long;Ljava/util/Locale;Z)Ljava/lang/String;

    .line 150
    .line 151
    .line 152
    move-result-object p1

    .line 153
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 154
    .line 155
    .line 156
    move-result-object p1

    .line 157
    invoke-static {p1, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object p1

    .line 161
    array-length p2, p1

    .line 162
    invoke-static {p1, p2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    move-result-object p1

    .line 166
    iget-object p0, p0, Lh2/y1;->g:Ljava/lang/String;

    .line 167
    .line 168
    invoke-static {p0, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 169
    .line 170
    .line 171
    move-result-object p0

    .line 172
    return-object p0
.end method
